package session

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// AF_ROUTE messages can reach other private query sockets in this process.
// Do not reuse a reply correlation sequence during its lifetime.
var endpointRouteSequence atomic.Uint64

// RTM_GET only: no routing table mutation, shell, localized command output,
// whole-system RIB dump or profile metadata in argv. Each private socket has
// a short read timeout and a shared caller deadline; unrelated events cannot
// keep the query alive indefinitely.
func nativeEndpointPath(ctx context.Context, address netip.Addr) (endpointPath, error) {
	failure := errors.New("kernel endpoint route query failed")
	if !address.IsValid() || address.Zone() != "" || address.Is4In6() {
		return endpointPath{}, failure
	}
	sequence := endpointRouteSequence.Add(1)
	if sequence > 0x7fffffff {
		return endpointPath{}, failure
	}
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return endpointPath{}, failure
	}
	defer unix.Close(fd)
	unix.CloseOnExec(fd)
	if unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 100000}) != nil ||
		unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &unix.Timeval{Usec: 100000}) != nil {
		return endpointPath{}, failure
	}
	addrs := make([]route.Addr, unix.RTAX_MAX)
	if address.Is4() {
		addrs[unix.RTAX_DST] = &route.Inet4Addr{IP: address.As4()}
	} else {
		addrs[unix.RTAX_DST] = &route.Inet6Addr{IP: address.As16()}
	}
	addrs[unix.RTAX_IFP] = &route.LinkAddr{}
	request := &route.RouteMessage{Version: unix.RTM_VERSION, Type: unix.RTM_GET, ID: uintptr(os.Getpid()), Seq: int(sequence), Addrs: addrs}
	data, err := request.Marshal()
	if err != nil || ctx.Err() != nil {
		return endpointPath{}, failure
	}
	if n, err := unix.Write(fd, data); err != nil || n != len(data) {
		return endpointPath{}, failure
	}
	deadline := time.Now().Add(2 * time.Second)
	buffer := make([]byte, 64*1024)
	for attempts := 0; attempts < 128 && ctx.Err() == nil && time.Now().Before(deadline); attempts++ {
		n, err := unix.Read(fd, buffer)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil || n == 0 || n == len(buffer) {
			return endpointPath{}, failure
		}
		messages, err := route.ParseRIB(route.RIBTypeRoute, buffer[:n])
		if err != nil {
			return endpointPath{}, failure
		}
		for _, message := range messages {
			reply, ok := message.(*route.RouteMessage)
			if !ok || reply.Type != unix.RTM_GET || reply.ID != request.ID || reply.Seq != request.Seq {
				continue
			}
			return decodeEndpointPath(address, reply)
		}
	}
	return endpointPath{}, failure
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

func decodeEndpointPath(address netip.Addr, reply *route.RouteMessage) (endpointPath, error) {
	failure := errors.New("kernel endpoint route is unavailable")
	if reply.Err != nil || reply.Flags&unix.RTF_UP == 0 || reply.Flags&(unix.RTF_REJECT|unix.RTF_BLACKHOLE|unix.RTF_CONDEMNED|unix.RTF_DEAD) != 0 || len(reply.Addrs) <= unix.RTAX_IFA {
		return endpointPath{}, failure
	}
	index := reply.Index
	if link, ok := reply.Addrs[unix.RTAX_IFP].(*route.LinkAddr); ok {
		if index == 0 {
			index = link.Index
		} else if link.Index != 0 && index != link.Index {
			return endpointPath{}, failure
		}
	}
	iface, err := net.InterfaceByIndex(index)
	if err != nil || iface.Flags&net.FlagUp == 0 {
		return endpointPath{}, failure
	}
	path := endpointPath{InterfaceIndex: index, InterfaceName: iface.Name, Direct: reply.Flags&unix.RTF_GATEWAY == 0}
	path.Gateway, path.GatewayZone = routeIP(reply.Addrs[unix.RTAX_GATEWAY])
	path.Source, path.SourceZone = routeIP(reply.Addrs[unix.RTAX_IFA])
	// A direct route uses a link gateway; its changing ARP/NDP hardware
	// address is not a gateway identity and must not cause false disconnects.
	if !validEndpointPath(address, path) {
		return endpointPath{}, failure
	}
	return path, nil
}
