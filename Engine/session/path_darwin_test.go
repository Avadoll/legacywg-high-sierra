package session

import (
	"context"
	"net/netip"
	"testing"
	"time"

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
