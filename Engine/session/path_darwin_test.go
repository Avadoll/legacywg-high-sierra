package session

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	configcore "legacywg/ConfigCore"
)

func TestNativeEndpointRouteQuery(t *testing.T) {
	for _, text := range []string{"127.0.0.1", "::1"} {
		t.Run(text, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			address := netip.MustParseAddr(text)
			path, err := nativeEndpointPath(ctx, address)
			if err != nil || path.InterfaceName != "lo0" || path.InterfaceIndex <= 0 {
				t.Fatal("kernel loopback path unavailable", err)
			}
			if verifyEndpointPaths(ctx, map[netip.Addr]endpointPath{address: path}, nativeEndpointPath) != nil {
				t.Fatal("stable native route identity changed")
			}
		})
	}
}

func TestKernelEndpointRouteRejectsUnsafeReplies(t *testing.T) {
	iface, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal("native loopback interface unavailable")
	}
	address := netip.MustParseAddr("127.0.0.1")
	for _, flag := range []int{0, unix.RTF_UP | unix.RTF_REJECT, unix.RTF_UP | unix.RTF_BLACKHOLE, unix.RTF_UP | unix.RTF_DEAD, unix.RTF_UP | unix.RTF_CONDEMNED} {
		reply := &route.RouteMessage{Index: iface.Index, Flags: flag, Addrs: make([]route.Addr, unix.RTAX_MAX)}
		if _, err := decodeEndpointPath(address, reply); err == nil {
			t.Fatal("unusable route flags accepted")
		}
	}
	reply := &route.RouteMessage{Index: iface.Index, Flags: unix.RTF_UP | unix.RTF_GATEWAY, Addrs: make([]route.Addr, unix.RTAX_MAX)}
	if _, err := decodeEndpointPath(address, reply); err == nil {
		t.Fatal("missing gateway accepted")
	}
	reply.Flags = unix.RTF_UP
	reply.Addrs[unix.RTAX_IFP] = &route.LinkAddr{Index: iface.Index + 1}
	if _, err := decodeEndpointPath(address, reply); err == nil {
		t.Fatal("conflicting interface indices accepted")
	}
}

func TestNativeCurrentEndpointMonitorFollowsKernelLoopbackPath(t *testing.T) {
	initial := netip.MustParseAddrPort("127.0.0.1:1234")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	before, err := nativeEndpointPath(ctx, initial.Addr())
	if err != nil {
		t.Fatal("native baseline path missing")
	}
	raw := "public_key=a\nendpoint=127.0.0.2:4321\n"
	config := &configcore.Config{Peers: []configcore.Peer{{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("198.18.89.0/24")}}}}
	check, err := newCurrentPathCheck(config, "public_key=a\n", []netip.AddrPort{initial}, map[netip.Addr]endpointPath{initial.Addr(): before}, 65535, func() (string, error) { return raw, nil }, nativeEndpointPath)
	if err != nil || check.verify(ctx) != nil {
		t.Fatal("native roamed loopback kernel path not followed")
	}
}
