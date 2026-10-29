package session

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	configcore "legacywg/ConfigCore"
)

func TestResearchFullIntentAndBootstrap(t *testing.T) {
	text := strings.Replace(splitProfile(), "198.18.0.2/32", "0.0.0.0/0", 1)
	text = strings.Replace(text, "Address=", "DNS=198.18.0.2\nAddress=", 1)
	text = strings.Replace(text, "127.0.0.1", "vpn.example.invalid", 1)
	config, err := configcore.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	defer config.Destroy()
	endpoints, err := CheckCapabilities(config)
	if err != nil {
		t.Fatal("bounded full intent refused", err)
	}
	endpoints, err = resolveEndpoints(context.Background(), config, endpoints, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.8")}, nil
	})
	if err != nil || endpoints[0].String() != "192.0.2.8:51820" {
		t.Fatal("full endpoint bootstrap refused", err)
	}
	routes := sessionRoutes(config)
	if len(routes) != 4 {
		t.Fatal("full routes or IPv6 sink missing")
	}
	for _, prefix := range routes {
		if prefix.Bits() != 1 {
			t.Fatal("system default replacement requested")
		}
	}
}

func TestResearchFullRefusesMissingDNSAndMultiplePeers(t *testing.T) {
	text := strings.Replace(splitProfile(), "198.18.0.2/32", "0.0.0.0/0", 1)
	config, err := configcore.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	defer config.Destroy()
	if _, err := CheckCapabilities(config); err == nil {
		t.Fatal("full mode silently uses system DNS")
	}
	config.DNS = []netip.Addr{netip.MustParseAddr("198.18.0.2")}
	config.Peers = append(config.Peers, configcore.Peer{})
	if _, err := CheckCapabilities(config); err == nil {
		t.Fatal("unsupported full multiple-peer topology accepted")
	}
}
