package session

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	configcore "legacywg/ConfigCore"
)

func TestCurrentEndpointDecoderCorrelatesPeerOrderAndRefusesUnsafeMetadata(t *testing.T) {
	indices := map[string]int{"a": 0, "b": 1}
	raw := "public_key=b\nendpoint=[2001:db8::2]:4321\npublic_key=a\nendpoint=192.0.2.99:1234\n"
	endpoints, err := readCurrentEndpoints(raw, indices)
	if err != nil || endpoints[0] != netip.MustParseAddrPort("192.0.2.99:1234") || endpoints[1] != netip.MustParseAddrPort("[2001:db8::2]:4321") {
		t.Fatal("private peer order not preserved")
	}
	for _, bad := range []string{
		"public_key=foreign\nendpoint=192.0.2.99:1234\n",
		"public_key=a\npublic_key=a\npublic_key=b\n",
		"endpoint=192.0.2.99:1234\npublic_key=a\npublic_key=b\n",
		"public_key=a\nendpoint=192.0.2.99:1234\nendpoint=192.0.2.98:1234\npublic_key=b\n",
		"public_key=a\n", strings.Repeat("x", 128*1024+1),
	} {
		if _, err := readCurrentEndpoints(bad, indices); err == nil {
			t.Fatal("unsafe current peer records accepted")
		}
	}
	for _, endpoint := range []string{"192.0.2.99:0", "example.invalid:1234", "[fe80::1%en0]:1234", "[::ffff:192.0.2.99]:1234", "0.0.0.0:1234", "224.0.0.1:1234"} {
		if _, err := readCurrentEndpoints("public_key=a\nendpoint="+endpoint+"\npublic_key=b\n", indices); err == nil {
			t.Fatal("unsafe endpoint accepted")
		}
	}
}

func fixtureCurrentCheck(t *testing.T) (*currentPathCheck, *string) {
	t.Helper()
	first, second := netip.MustParseAddrPort("192.0.2.99:1234"), netip.MustParseAddrPort("192.0.2.100:1235")
	raw := "public_key=a\nendpoint=" + first.String() + "\npublic_key=b\nendpoint=" + second.String() + "\n"
	config := &configcore.Config{Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")}, Peers: []configcore.Peer{{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}, {AllowedIPs: []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/64")}}}}
	check, err := newCurrentPathCheck(config, "public_key=a\npublic_key=b\n", []netip.AddrPort{first, second}, map[netip.Addr]endpointPath{first.Addr(): testPath(), second.Addr(): testPath()}, 9, func() (string, error) { return raw, nil }, func(context.Context, netip.Addr) (endpointPath, error) { return testPath(), nil })
	if err != nil {
		t.Fatal("monitor initialization failed")
	}
	return check, &raw
}

func TestCurrentEndpointMonitorFollowsRoamedDestinationAndItsOwnLaterRouteLoss(t *testing.T) {
	check, raw := fixtureCurrentCheck(t)
	if check.verify(context.Background()) != nil {
		t.Fatal("initial state refused")
	}
	*raw = "public_key=b\nendpoint=192.0.2.100:1235\npublic_key=a\nendpoint=192.0.2.98:2345\n"
	queried := map[netip.Addr]bool{}
	check.lookup = func(_ context.Context, address netip.Addr) (endpointPath, error) {
		queried[address] = true
		return testPath(), nil
	}
	if check.verify(context.Background()) != nil || !queried[netip.MustParseAddr("192.0.2.98")] || queried[netip.MustParseAddr("192.0.2.99")] {
		t.Fatal("monitor did not follow current authenticated endpoint")
	}
	check.lookup = func(_ context.Context, address netip.Addr) (endpointPath, error) {
		path := testPath()
		if address == netip.MustParseAddr("192.0.2.98") {
			path.InterfaceIndex = 9
			path.InterfaceName = "utun9"
		}
		return path, nil
	}
	if check.verify(context.Background()) == nil {
		t.Fatal("roamed destination routed into own tunnel was accepted")
	}
}

func TestCurrentEndpointMonitorRejectsOverlapMissingPeersAndPathChanges(t *testing.T) {
	for _, endpoint := range []string{"10.0.0.88:1234", "[2001:db8:1::2]:1234"} {
		check, raw := fixtureCurrentCheck(t)
		*raw = "public_key=a\nendpoint=" + endpoint + "\npublic_key=b\nendpoint=192.0.2.100:1235\n"
		check.lookup = func(context.Context, netip.Addr) (endpointPath, error) {
			t.Fatal("overlap queried kernel")
			return endpointPath{}, nil
		}
		if check.verify(context.Background()) == nil {
			t.Fatal("roaming into AllowedIPs accepted")
		}
	}
	for _, path := range []endpointPath{func() endpointPath { p := testPath(); p.Gateway = netip.MustParseAddr("192.0.2.3"); return p }(), func() endpointPath { p := testPath(); p.Source = netip.MustParseAddr("192.0.2.4"); return p }()} {
		check, _ := fixtureCurrentCheck(t)
		check.lookup = func(context.Context, netip.Addr) (endpointPath, error) { return path, nil }
		if check.verify(context.Background()) == nil {
			t.Fatal("changed current endpoint path accepted")
		}
	}
	check, raw := fixtureCurrentCheck(t)
	*raw = "public_key=a\npublic_key=b\nendpoint=192.0.2.100:1235\n"
	if check.verify(context.Background()) == nil {
		t.Fatal("configured endpoint disappearance accepted")
	}
}

func TestCurrentEndpointMonitorDeduplicatesAndCancelsWithoutMetadataLeak(t *testing.T) {
	check, raw := fixtureCurrentCheck(t)
	*raw = "public_key=a\nendpoint=192.0.2.99:1234\npublic_key=b\nendpoint=192.0.2.99:2345\n"
	calls := 0
	check.lookup = func(context.Context, netip.Addr) (endpointPath, error) { calls++; return testPath(), nil }
	if check.verify(context.Background()) != nil || calls != 1 {
		t.Fatal("shared endpoint path not deduplicated")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	check.read = func() (string, error) { t.Fatal("canceled monitor read engine"); return "", nil }
	if check.verify(ctx) == nil {
		t.Fatal("canceled monitor accepted")
	}
	check.read = func() (string, error) { return "", errors.New("private-key-endpoint-marker") }
	err := check.verify(context.Background())
	if err == nil || strings.Contains(err.Error(), "marker") || strings.Contains(err.Error(), "192.0.2") {
		t.Fatal("private engine metadata leaked")
	}
}

func TestPassivePeerEstablishesBaselineOnlyOutsideTunnel(t *testing.T) {
	config := &configcore.Config{Peers: []configcore.Peer{{AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}}}
	raw := "public_key=a\n"
	check, err := newCurrentPathCheck(config, "public_key=a\n", []netip.AddrPort{{}}, nil, 9, func() (string, error) { return raw, nil }, func(context.Context, netip.Addr) (endpointPath, error) { return testPath(), nil })
	if err != nil || check.verify(context.Background()) != nil {
		t.Fatal("pending passive peer refused")
	}
	raw = "public_key=a\nendpoint=192.0.2.99:1234\n"
	if check.verify(context.Background()) != nil || !check.have[0] {
		t.Fatal("authenticated passive endpoint not captured")
	}
	raw = "public_key=a\n"
	if check.verify(context.Background()) == nil {
		t.Fatal("learned passive endpoint disappeared silently")
	}
}
