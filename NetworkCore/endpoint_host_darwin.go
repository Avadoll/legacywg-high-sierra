package networkcore

import (
	"context"
	"net/netip"
	"os"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// ScopedHost describes only a single numeric host escape on an already
// captured interface. It cannot express a default/prefix route or a command.
// This is private worker network metadata, never a user-facing IPC DTO.
// Callers must journal ownership before mutation and serialize all effects.
type ScopedHost struct {
	Destination netip.Addr
	Path        Path
}

func routeAddress(address netip.Addr, zone int) route.Addr {
	if address.Is4() {
		return &route.Inet4Addr{IP: address.As4()}
	}
	return &route.Inet6Addr{IP: address.As16(), ZoneID: zone}
}

func (host ScopedHost) valid() bool {
	dst, path := host.Destination, host.Path
	if !dst.IsValid() || dst.Zone() != "" || dst.Is4In6() || dst.IsUnspecified() || dst.IsMulticast() || dst.IsLinkLocalUnicast() || dst.IsLoopback() || dst.String() == "255.255.255.255" ||
		path.InterfaceIndex < 1 || path.InterfaceIndex > 65535 || !interfaceName.MatchString(path.InterfaceName) ||
		!path.Source.IsValid() || path.Source.IsUnspecified() || path.Source.Is4In6() || !validPath(dst, path) {
		return false
	}
	return !path.Direct || (!path.Gateway.IsValid() && path.GatewayZone == 0)
}

// Matches requires the exact static host entry; a borrowed prefix, cloned
// neighbor or implicit primary/default is never ownership evidence.
func (host ScopedHost) Matches(snapshot ScopedPath) bool {
	const flags = unix.RTF_HOST | unix.RTF_STATIC | unix.RTF_IFSCOPE
	want := flags
	if !host.Path.Direct {
		want |= unix.RTF_GATEWAY
	}
	observedFlags := snapshot.Flags
	// nd6_rtrequest annotates direct IPv6 host routes with LLINFO, even
	// when our acknowledged route is STATIC rather than a cloned neighbor.
	// Keep the exception local to IPv6 direct routes; cloned routes remain
	// refused. This is not ownership evidence without the committed journal.
	if host.Destination.Is6() && host.Path.Direct {
		observedFlags &^= unix.RTF_LLINFO
	}
	return host.valid() && snapshot.Path == host.Path &&
		snapshot.Prefix == netip.PrefixFrom(host.Destination, host.Destination.BitLen()) && observedFlags == want
}

// ObserveScopedHost returns a validated best-match observation. A false exact
// match permits callers to refuse borrowing/overwriting somebody else's route.
// It does not authorize deletion, prove incarnation, or enumerate a RIB.
func ObserveScopedHost(ctx context.Context, host ScopedHost) (ScopedPath, error) {
	if !host.valid() {
		return ScopedPath{}, ErrPathUnavailable
	}
	return query(ctx, host.Destination, host.Path.InterfaceIndex, false)
}

// ChangeScopedHost performs one typed RTM_ADD or RTM_DELETE. There is no change,
// replace, flush or fallback operation. An error is ambiguous to ownership:
// callers must retain their journal and re-observe, never delete on error.
// A successful acknowledgment still requires a fresh strict route observation.
func ChangeScopedHost(ctx context.Context, host ScopedHost, add bool) error {
	if ctx == nil || ctx.Err() != nil || !host.valid() || os.Geteuid() != 0 {
		return ErrPathUnavailable
	}
	seq, err := allocateSequence(&sequence)
	if err != nil {
		return err
	}
	addresses := make([]route.Addr, unix.RTAX_MAX)
	addresses[unix.RTAX_DST] = routeAddress(host.Destination, 0)
	addresses[unix.RTAX_IFP] = &route.LinkAddr{Index: host.Path.InterfaceIndex, Name: host.Path.InterfaceName}
	addresses[unix.RTAX_IFA] = routeAddress(host.Path.Source, host.Path.SourceZone)
	flags := unix.RTF_UP | unix.RTF_HOST | unix.RTF_STATIC | unix.RTF_IFSCOPE
	if host.Path.Direct {
		addresses[unix.RTAX_GATEWAY] = &route.LinkAddr{Index: host.Path.InterfaceIndex}
	} else {
		flags |= unix.RTF_GATEWAY
		addresses[unix.RTAX_GATEWAY] = routeAddress(host.Path.Gateway, host.Path.GatewayZone)
	}
	kind := unix.RTM_DELETE
	if add {
		kind = unix.RTM_ADD
	}
	reply, err := exchange(ctx, &route.RouteMessage{Version: unix.RTM_VERSION, Type: kind,
		ID: uintptr(os.Getpid()), Seq: seq, Index: host.Path.InterfaceIndex, Flags: flags, Addrs: addresses})
	if err != nil || reply.Err != nil {
		return ErrPathUnavailable
	}
	return nil
}
