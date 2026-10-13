package session

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func testPath() endpointPath {
	return endpointPath{InterfaceIndex: 4, InterfaceName: "en0", Gateway: netip.MustParseAddr("192.0.2.1"), Source: netip.MustParseAddr("192.0.2.2")}
}

func TestEndpointPathCaptureDeduplicatesAddresses(t *testing.T) {
	calls := 0
	endpoint := netip.MustParseAddrPort("192.0.2.99:1234")
	paths, err := captureEndpointPaths(context.Background(), []netip.AddrPort{endpoint, netip.AddrPortFrom(endpoint.Addr(), 4321), {}}, func(context.Context, netip.Addr) (endpointPath, error) { calls++; return testPath(), nil })
	if err != nil || len(paths) != 1 || calls != 1 {
		t.Fatal("endpoint address query was not bounded/deduplicated")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = captureEndpointPaths(ctx, []netip.AddrPort{endpoint}, func(context.Context, netip.Addr) (endpointPath, error) {
		t.Fatal("canceled capture queried kernel")
		return endpointPath{}, nil
	})
	if err == nil {
		t.Fatal("canceled capture accepted")
	}
}

func TestEndpointPathChangesCannotBeAccepted(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.99")
	before := testPath()
	original := map[netip.Addr]endpointPath{address: before}
	changes := map[string]endpointPath{}
	path := before
	path.InterfaceIndex++
	changes["interface reuse"] = path
	path = before
	path.InterfaceName = "en1"
	changes["other interface"] = path
	path = before
	path.Gateway = netip.MustParseAddr("192.0.2.3")
	changes["gateway"] = path
	path = before
	path.Source = netip.MustParseAddr("192.0.2.4")
	changes["DHCP source"] = path
	path = before
	path.Direct = true
	changes["directness"] = path
	for name, path := range changes {
		t.Run(name, func(t *testing.T) {
			if verifyEndpointPaths(context.Background(), original, func(context.Context, netip.Addr) (endpointPath, error) { return path, nil }) == nil {
				t.Fatal("changed kernel path accepted")
			}
		})
	}
	if verifyEndpointPaths(context.Background(), original, func(context.Context, netip.Addr) (endpointPath, error) { return before, nil }) != nil {
		t.Fatal("unchanged path refused")
	}
	err := verifyEndpointPaths(context.Background(), original, func(context.Context, netip.Addr) (endpointPath, error) {
		return endpointPath{}, errors.New("private-endpoint-marker")
	})
	if err == nil || strings.Contains(err.Error(), "marker") || strings.Contains(err.Error(), address.String()) {
		t.Fatal("private route metadata leaked")
	}
}

func TestEndpointPathIPv6Scope(t *testing.T) {
	address := netip.MustParseAddr("2001:db8::99")
	path := endpointPath{InterfaceIndex: 4, InterfaceName: "en0", Gateway: netip.MustParseAddr("fe80::1"), GatewayZone: 4, Source: netip.MustParseAddr("2001:db8::2")}
	if !validEndpointPath(address, path) {
		t.Fatal("scoped IPv6 gateway refused")
	}
	path.GatewayZone = 5
	if validEndpointPath(address, path) {
		t.Fatal("foreign gateway scope accepted")
	}
	path.GatewayZone = 0
	if validEndpointPath(address, path) {
		t.Fatal("missing link-local scope accepted")
	}
	path.Gateway = netip.MustParseAddr("192.0.2.1")
	if validEndpointPath(address, path) {
		t.Fatal("cross-family gateway accepted")
	}
	path.Gateway = netip.Addr{}
	path.Direct = true
	if !validEndpointPath(address, path) {
		t.Fatal("direct IPv6 path refused")
	}
}

func TestPathWatchStopsWithoutLeavingWaitingGoroutine(t *testing.T) {
	watch := startPathWatch(map[netip.Addr]endpointPath{}, func(context.Context, netip.Addr) (endpointPath, error) {
		t.Fatal("empty path queried")
		return endpointPath{}, nil
	})
	if watch.close() != nil || watch.close() != nil {
		t.Fatal("monitor close was not idempotent")
	}
	select {
	case <-watch.lost:
	case <-time.After(time.Second):
		t.Fatal("session observer cannot finish on stop")
	}
}

func TestPathWatchSignalsUnavailableRoute(t *testing.T) {
	watch := startPathWatch(map[netip.Addr]endpointPath{netip.MustParseAddr("192.0.2.99"): testPath()}, func(context.Context, netip.Addr) (endpointPath, error) {
		return endpointPath{}, errors.New("unavailable")
	})
	defer watch.close()
	select {
	case <-watch.lost:
	case <-time.After(5 * time.Second):
		t.Fatal("lost endpoint route was not signaled")
	}
}
