package networkcore

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

var ErrPathUnavailable = errors.New("kernel endpoint path unavailable")
var ErrNoRoute = errors.New("kernel reports no endpoint route")

// Path deliberately matches the existing session path fields. A consumer using
// unscoped lookup must compare this, not the new scoped route-entry metadata.
// Values are private network metadata and must not appear in exported errors.
type Path struct {
	InterfaceIndex int
	InterfaceName  string
	Gateway        netip.Addr
	GatewayZone    int
	Direct         bool
	Source         netip.Addr
	SourceZone     int
}

// ScopedPath is an observed route, never proof of ownership or incarnation.
// Flags contains only stable route-class bits; changing counters/link addresses
// are excluded. Host/cloned route transitions conservatively change identity.
type ScopedPath struct {
	Path
	Prefix netip.Prefix
	Flags  int
}

var sequence atomic.Uint64
var otherQueryReplies atomic.Uint64 // Private characterization counter; no metadata.
var interfaceName = regexp.MustCompile(`^[a-z][a-z0-9]{0,14}$`)

const stableFlags = unix.RTF_HOST | unix.RTF_GATEWAY | unix.RTF_IFSCOPE |
	unix.RTF_STATIC | unix.RTF_CLONING | unix.RTF_PRCLONING |
	unix.RTF_WASCLONED | unix.RTF_LLINFO

// One allocator must serve EVERY route query in a worker process. A second
// package-local counter would collide through AF_ROUTE's broadcast delivery.
func allocateSequence(counter *atomic.Uint64) (int, error) {
	for {
		current := counter.Load()
		if current >= 0x7fffffff {
			return 0, ErrPathUnavailable
		}
		if counter.CompareAndSwap(current, current+1) {
			return int(current + 1), nil
		}
	}
}

// EndpointRoute preserves the current session observer's unscoped decoding
// contract: source may be absent and selected-prefix metadata is not required.
func EndpointRoute(ctx context.Context, destination netip.Addr) (Path, error) {
	result, err := query(ctx, destination, 0, false)
	return result.Path, err
}

// ScopedRoute is deliberately stricter. Missing source, noncanonical or
// uncovered destination/mask, implicit unscoped primary routes and wrong scope
// are refused. Native evidence must characterize refusals before relaxing them.
func ScopedRoute(ctx context.Context, destination netip.Addr, scope int) (ScopedPath, error) {
	if scope < 1 || scope > 65535 || destination.IsUnspecified() || destination.IsMulticast() {
		return ScopedPath{}, ErrPathUnavailable
	}
	return query(ctx, destination, scope, true)
}

func query(ctx context.Context, destination netip.Addr, scope int, strict bool) (ScopedPath, error) {
	if ctx == nil || ctx.Err() != nil || !destination.IsValid() || destination.Zone() != "" || destination.Is4In6() || scope < 0 || scope > 65535 {
		return ScopedPath{}, ErrPathUnavailable
	}
	seq, err := allocateSequence(&sequence)
	if err != nil {
		return ScopedPath{}, err
	}
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return ScopedPath{}, ErrPathUnavailable
	}
	defer unix.Close(fd)
	unix.CloseOnExec(fd)
	if unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 100000}) != nil ||
		unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &unix.Timeval{Usec: 100000}) != nil {
		return ScopedPath{}, ErrPathUnavailable
	}
	addrs := make([]route.Addr, unix.RTAX_MAX)
	if destination.Is4() {
		addrs[unix.RTAX_DST] = &route.Inet4Addr{IP: destination.As4()}
	} else {
		addrs[unix.RTAX_DST] = &route.Inet6Addr{IP: destination.As16()}
	}
	addrs[unix.RTAX_IFP] = &route.LinkAddr{}
	request := &route.RouteMessage{Version: unix.RTM_VERSION, Type: unix.RTM_GET,
		ID: uintptr(os.Getpid()), Seq: seq, Index: scope, Addrs: addrs}
	if scope != 0 {
		request.Flags = unix.RTF_IFSCOPE
	}
	data, err := request.Marshal()
	if err != nil || ctx.Err() != nil {
		return ScopedPath{}, ErrPathUnavailable
	}
	deadline := time.Now().Add(2 * time.Second)
	if n, err := unix.Write(fd, data); err != nil || n != len(data) {
		return ScopedPath{}, ErrPathUnavailable
	}
	buffer := make([]byte, 64*1024)
	for tries := 0; tries < 128 && ctx.Err() == nil && time.Now().Before(deadline); tries++ {
		n, err := unix.Read(fd, buffer)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil || n <= 0 || n == len(buffer) {
			return ScopedPath{}, ErrPathUnavailable
		}
		messages, err := route.ParseRIB(route.RIBTypeRoute, buffer[:n])
		if err != nil {
			return ScopedPath{}, ErrPathUnavailable
		}
		for _, message := range messages {
			reply, ok := message.(*route.RouteMessage)
			if !ok || !sameRequest(request, reply) {
				if ok && reply.ID == request.ID && reply.Type == request.Type && reply.Seq != request.Seq {
					otherQueryReplies.Add(1)
				}
				continue
			}
			if ctx.Err() != nil || !time.Now().Before(deadline) {
				return ScopedPath{}, ErrPathUnavailable
			}
			if errors.Is(reply.Err, unix.ESRCH) {
				return ScopedPath{}, ErrNoRoute
			}
			result, err := decode(destination, scope, strict, reply, net.InterfaceByIndex)
			if ctx.Err() != nil || !time.Now().Before(deadline) {
				return ScopedPath{}, ErrPathUnavailable
			}
			return result, err
		}
	}
	return ScopedPath{}, ErrPathUnavailable
}

func sameRequest(request, reply *route.RouteMessage) bool {
	return reply != nil && reply.Version == request.Version && reply.Type == request.Type &&
		reply.ID == request.ID && reply.Seq == request.Seq
}

func routeIP(value route.Addr) (netip.Addr, int) {
	switch value := value.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(value.IP), 0
	case *route.Inet6Addr:
		return netip.AddrFrom16(value.IP), value.ZoneID
	default:
		return netip.Addr{}, 0
	}
}

func decode(destination netip.Addr, scope int, strict bool, reply *route.RouteMessage, lookup func(int) (*net.Interface, error)) (ScopedPath, error) {
	if reply == nil || reply.Err != nil || reply.Flags&unix.RTF_UP == 0 ||
		reply.Flags&(unix.RTF_REJECT|unix.RTF_BLACKHOLE|unix.RTF_CONDEMNED|unix.RTF_DEAD) != 0 || len(reply.Addrs) <= unix.RTAX_IFA {
		return ScopedPath{}, ErrPathUnavailable
	}
	index := reply.Index
	if link, ok := reply.Addrs[unix.RTAX_IFP].(*route.LinkAddr); ok {
		if index == 0 {
			index = link.Index
		} else if link.Index != 0 && index != link.Index {
			return ScopedPath{}, ErrPathUnavailable
		}
	}
	if index <= 0 || (scope != 0 && index != scope) {
		return ScopedPath{}, ErrPathUnavailable
	}
	iface, err := lookup(index)
	if err != nil || iface == nil || iface.Index != index || iface.Flags&net.FlagUp == 0 || !interfaceName.MatchString(iface.Name) {
		return ScopedPath{}, ErrPathUnavailable
	}
	path := Path{InterfaceIndex: index, InterfaceName: iface.Name, Direct: reply.Flags&unix.RTF_GATEWAY == 0}
	path.Gateway, path.GatewayZone = routeIP(reply.Addrs[unix.RTAX_GATEWAY])
	path.Source, path.SourceZone = routeIP(reply.Addrs[unix.RTAX_IFA])
	if !validPath(destination, path) {
		return ScopedPath{}, ErrPathUnavailable
	}
	if !strict {
		// EndpointRoute exposes Path only. Scoped characterization can inspect
		// these flags without mistaking compatibility decoding for admission.
		prefix, _ := selectedPrefix(destination, index, reply)
		return ScopedPath{Path: path, Prefix: prefix, Flags: reply.Flags & stableFlags}, nil
	}
	if scope == 0 || index > 65535 || reply.Flags&unix.RTF_IFSCOPE == 0 ||
		!path.Source.IsValid() || path.Source.IsUnspecified() || path.Source.Is4In6() ||
		(path.Gateway.IsValid() && (path.Gateway.IsUnspecified() || path.Gateway.Is4In6())) {
		return ScopedPath{}, ErrPathUnavailable
	}
	if path.Direct {
		link, ok := reply.Addrs[unix.RTAX_GATEWAY].(*route.LinkAddr)
		if !ok || (link.Index != 0 && link.Index != index) {
			return ScopedPath{}, ErrPathUnavailable
		}
	}
	prefix, err := selectedPrefix(destination, index, reply)
	if err != nil {
		return ScopedPath{}, err
	}
	return ScopedPath{Path: path, Prefix: prefix, Flags: reply.Flags & stableFlags}, nil
}

// Preserve the existing unscoped observer's address semantics. Strict source
// presence and unspecified/mapped checks belong to ScopedRoute above.
func validPath(destination netip.Addr, path Path) bool {
	if !path.Direct && (!path.Gateway.IsValid() || path.Gateway.IsUnspecified()) {
		return false
	}
	for _, value := range []struct {
		address netip.Addr
		zone    int
	}{{path.Gateway, path.GatewayZone}, {path.Source, path.SourceZone}} {
		if !value.address.IsValid() {
			if value.zone != 0 {
				return false
			}
			continue
		}
		if value.address.Zone() != "" || value.address.BitLen() != destination.BitLen() || value.address.IsMulticast() || value.zone < 0 {
			return false
		}
		if value.address.IsLinkLocalUnicast() {
			if value.zone != path.InterfaceIndex {
				return false
			}
		} else if value.zone != 0 {
			return false
		}
	}
	return true
}

func selectedPrefix(destination netip.Addr, index int, reply *route.RouteMessage) (netip.Prefix, error) {
	selected, zone := routeIP(reply.Addrs[unix.RTAX_DST])
	if !selected.IsValid() || selected.Is4In6() || selected.BitLen() != destination.BitLen() ||
		selected.IsMulticast() || (zone != 0 && (!selected.IsLinkLocalUnicast() || zone != index)) {
		return netip.Prefix{}, ErrPathUnavailable
	}
	bits := selected.BitLen()
	if mask := reply.Addrs[unix.RTAX_NETMASK]; mask != nil {
		value, maskZone := routeIP(mask)
		if !value.IsValid() || value.BitLen() != bits || maskZone != 0 {
			return netip.Prefix{}, ErrPathUnavailable
		}
		ones, width := net.IPMask(value.AsSlice()).Size()
		if width != bits || (reply.Flags&unix.RTF_HOST != 0 && ones != bits) {
			return netip.Prefix{}, ErrPathUnavailable
		}
		bits = ones
	} else if reply.Flags&unix.RTF_HOST == 0 {
		// A missing mask is not silently interpreted as a default route.
		return netip.Prefix{}, ErrPathUnavailable
	}
	prefix := netip.PrefixFrom(selected, bits)
	if prefix.Masked() != prefix || !prefix.Contains(destination) {
		return netip.Prefix{}, ErrPathUnavailable
	}
	return prefix, nil
}
