package networkcore

import (
	configcore "legacywg/ConfigCore"
	"net/netip"
	"testing"
)

func TestRoutingPolicy(t *testing.T) {
	for _, test := range []struct {
		name          string
		routes        []string
		v4, v6, block bool
	}{
		{"full v4", []string{"0.0.0.0/0"}, true, false, true},
		{"split", []string{"10.0.0.0/8"}, false, false, false},
		{"dual stack", []string{"0.0.0.0/0", "::/0"}, true, true, false},
		{"two halves", []string{"0.0.0.0/1", "128.0.0.0/1"}, true, false, true},
		{"four quarters", []string{"0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"}, true, false, true},
		{"incomplete", []string{"0.0.0.0/1", "128.0.0.0/2"}, false, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			peer := configcore.Peer{Endpoint: &configcore.Endpoint{Host: "vpn.example.test", Port: 51820}}
			for _, route := range test.routes {
				peer.AllowedIPs = append(peer.AllowedIPs, netip.MustParsePrefix(route))
			}
			config := &configcore.Config{Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24"), netip.MustParsePrefix("fd00::2/64")}, Peers: []configcore.Peer{peer}}
			plan, err := Build(config, true)
			if err != nil {
				t.Fatal(err)
			}
			if plan.FullIPv4 != test.v4 || plan.FullIPv6 != test.v6 || plan.RequireIPv6Block != test.block || !plan.RequireBootstrapDNS {
				t.Fatal("incorrect routing policy")
			}
			config.Addresses[0] = netip.MustParsePrefix("192.0.2.2/24")
			if plan.Addresses[0].String() != "10.0.0.2/24" {
				t.Fatal("plan aliases mutable config")
			}
		})
	}
}

func TestUnsafePlanRejected(t *testing.T) {
	config := &configcore.Config{Addresses: []netip.Prefix{netip.MustParsePrefix("10.0.0.2/24")}, Peers: []configcore.Peer{{Endpoint: &configcore.Endpoint{Host: "192.0.2.1", Port: 51820}, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("::/0")}}}}
	if _, err := Build(config, true); err == nil {
		t.Fatal("IPv6 full tunnel without address accepted")
	}
	config.Peers[0].Endpoint = nil
	if _, err := Build(config, true); err == nil {
		t.Fatal("outgoing plan without endpoint accepted")
	}
}
