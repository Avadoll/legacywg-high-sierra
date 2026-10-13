// Developer-only route admission experiment. Does not enter the product.
package main

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
	"golang.zx2c4.com/wireguard/device"
)

type kernelPath struct {
	index       int
	name        string
	source      netip.Addr
	sourceZone  int
	gateway     netip.Addr
	gatewayZone int
	direct      bool
	scoped      bool
}

// Routing replies may be broadcast to multiple open AF_ROUTE sockets.
// Observers/opening checks must not consume another concurrent query's reply.
// Refuse exhaustion instead of reusing a sequence in this process.
var fixtureRouteSequence atomic.Uint64
var fixtureOtherQueryReplies atomic.Uint64

func kernelIP(value route.Addr) (netip.Addr, int) {
	switch value := value.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(value.IP), 0
	case *route.Inet6Addr:
		return netip.AddrFrom16(value.IP), value.ZoneID
	}
	return netip.Addr{}, 0
}

// The same RTM_GET wire format as the production unscoped observer, with
// RTF_IFSCOPE/rtm_index as defined by Apple's High Sierra-era rtsock.c.
// Never dumps the RIB, mutates a route or exports identities. One private
// socket, 100ms timeouts, 2s overall limit, <=128 unrelated reads / 64KiB.
func queryKernelPath(ctx context.Context, address netip.Addr, scope int) (kernelPath, error) {
	failure := errors.New("fixture kernel path unavailable")
	if ctx.Err() != nil || !address.IsValid() || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || scope < 0 || scope > 65535 {
		return kernelPath{}, failure
	}
	sequence := fixtureRouteSequence.Add(1)
	if sequence > 0x7fffffff {
		return kernelPath{}, failure
	}
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return kernelPath{}, failure
	}
	defer unix.Close(fd)
	unix.CloseOnExec(fd)
	if unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 100000}) != nil || unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &unix.Timeval{Usec: 100000}) != nil {
		return kernelPath{}, failure
	}
	addrs := make([]route.Addr, unix.RTAX_MAX)
	if address.Is4() {
		addrs[unix.RTAX_DST] = &route.Inet4Addr{IP: address.As4()}
	} else {
		addrs[unix.RTAX_DST] = &route.Inet6Addr{IP: address.As16()}
	}
	addrs[unix.RTAX_IFP] = &route.LinkAddr{}
	request := &route.RouteMessage{Version: unix.RTM_VERSION, Type: unix.RTM_GET, ID: uintptr(os.Getpid()), Seq: int(sequence), Index: scope, Addrs: addrs}
	if scope != 0 {
		request.Flags = unix.RTF_IFSCOPE
	}
	data, err := request.Marshal()
	if err != nil || ctx.Err() != nil {
		return kernelPath{}, failure
	}
	if n, err := unix.Write(fd, data); err != nil || n != len(data) {
		return kernelPath{}, failure
	}
	deadline := time.Now().Add(2 * time.Second)
	buffer := make([]byte, 64*1024)
	for tries := 0; tries < 128 && ctx.Err() == nil && time.Now().Before(deadline); tries++ {
		n, err := unix.Read(fd, buffer)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil || n == 0 || n == len(buffer) {
			return kernelPath{}, failure
		}
		messages, err := route.ParseRIB(route.RIBTypeRoute, buffer[:n])
		if err != nil {
			return kernelPath{}, failure
		}
		for _, message := range messages {
			reply, ok := message.(*route.RouteMessage)
			if !ok || reply.Type != request.Type || reply.ID != request.ID || reply.Seq != request.Seq {
				if ok && reply.Type == request.Type && reply.ID == request.ID && reply.Seq != request.Seq {
					fixtureOtherQueryReplies.Add(1)
				}
				continue
			}
			if ctx.Err() != nil || reply.Err != nil || reply.Flags&unix.RTF_UP == 0 || reply.Flags&(unix.RTF_REJECT|unix.RTF_BLACKHOLE|unix.RTF_CONDEMNED|unix.RTF_DEAD) != 0 || len(reply.Addrs) <= unix.RTAX_IFA {
				return kernelPath{}, failure
			}
			index := reply.Index
			if link, ok := reply.Addrs[unix.RTAX_IFP].(*route.LinkAddr); ok {
				if index == 0 {
					index = link.Index
				} else if link.Index != 0 && index != link.Index {
					return kernelPath{}, failure
				}
			}
			if index <= 0 || (scope != 0 && index != scope) {
				return kernelPath{}, failure
			}
			iface, err := net.InterfaceByIndex(index)
			if err != nil || iface.Flags&net.FlagUp == 0 {
				return kernelPath{}, failure
			}
			path := kernelPath{index: index, name: iface.Name, direct: reply.Flags&unix.RTF_GATEWAY == 0, scoped: reply.Flags&unix.RTF_IFSCOPE != 0}
			path.gateway, path.gatewayZone = kernelIP(reply.Addrs[unix.RTAX_GATEWAY])
			path.source, path.sourceZone = kernelIP(reply.Addrs[unix.RTAX_IFA])
			if !path.direct && (!path.gateway.IsValid() || path.gateway.IsUnspecified()) {
				return kernelPath{}, failure
			}
			for _, value := range []struct {
				address netip.Addr
				zone    int
			}{{path.gateway, path.gatewayZone}, {path.source, path.sourceZone}} {
				if !value.address.IsValid() {
					if value.zone != 0 {
						return kernelPath{}, failure
					}
					continue
				}
				if value.address.BitLen() != address.BitLen() || value.address.IsMulticast() || value.address.IsUnspecified() || value.zone < 0 {
					return kernelPath{}, failure
				}
				if value.address.IsLinkLocalUnicast() {
					if value.zone != index {
						return kernelPath{}, failure
					}
				} else if value.zone != 0 {
					return kernelPath{}, failure
				}
			}
			return path, nil
		}
	}
	return kernelPath{}, failure
}

// Admission uses the exact captured route, current interface identity and
// source membership before and after opening. This is a bounded observation,
// not an atomic lifetime/generation guard or proof against index reuse.
func admitPath(ctx context.Context, remote, local netip.Addr, before kernelPath) error {
	failure := errors.New("fixture scoped admission refused")
	iface, err := net.InterfaceByIndex(before.index)
	if err != nil || iface.Name != before.name || iface.Flags&net.FlagUp == 0 || !before.scoped {
		return failure
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return failure
	}
	found := false
	for _, value := range addresses {
		p, err := netip.ParsePrefix(value.String())
		if err == nil && p.Addr() == local {
			found = true
		}
	}
	if !found {
		return failure
	}
	after, err := queryKernelPath(ctx, remote, before.index)
	if err != nil || after != before || ctx.Err() != nil {
		return failure
	}
	return nil
}

func admittedFactory(local, remote netip.Addr, before kernelPath) func(uint16) (net.PacketConn, error) {
	return func(port uint16) (net.PacketConn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := admitPath(ctx, remote, local, before); err != nil {
			return nil, err
		}
		socket, err := socketPort(local, before.index, port)
		if err != nil {
			return nil, err
		}
		if err := admitPath(ctx, remote, local, before); err != nil {
			socket.Close()
			return nil, err
		}
		return socket, nil
	}
}

type scopedObserver struct {
	cancel     context.CancelFunc
	done       chan struct{}
	lost       chan struct{}
	lostAt     time.Time // Published by closing lost; read only after that event.
	downFailed atomic.Bool
}

// A developer-only bounded poll, not a packet-level fail-closed guard.
// Loss latches before stopping the official device; the old Bind may never
// reopen even if the route reappears. A new connection needs a new admission
// context. Socket interface scoping remains active throughout the poll gap.
func observeScopedPath(local, remote netip.Addr, before kernelPath, bind *packetBind, engine *device.Device) *scopedObserver {
	ctx, cancel := context.WithCancel(context.Background())
	observer := &scopedObserver{cancel: cancel, done: make(chan struct{}), lost: make(chan struct{})}
	go func() {
		defer close(observer.done)
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				check, stop := context.WithTimeout(ctx, 2*time.Second)
				err := admitPath(check, remote, local, before)
				stop()
				if ctx.Err() != nil {
					return
				}
				if err == nil {
					continue
				}
				bind.refused.Store(true)
				if engine.Down() != nil {
					observer.downFailed.Store(true)
				}
				observer.lostAt = time.Now()
				close(observer.lost)
				return
			}
		}
	}()
	return observer
}

func (observer *scopedObserver) stop() bool {
	observer.cancel()
	select {
	case <-observer.done:
		return !observer.downFailed.Load()
	case <-time.After(3 * time.Second):
		return false
	}
}
