package session

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	configcore "legacywg/ConfigCore"
)

func hostnameConfig(t *testing.T) *configcore.Config {
	t.Helper()
	config, err := configcore.Parse([]byte(strings.Replace(splitProfile(), "127.0.0.1", "vpn.example.test", 1)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(config.Destroy)
	return config
}

func TestHostnameValidationHasNoResolverSideEffects(t *testing.T) {
	config := hostnameConfig(t)
	endpoints, err := CheckCapabilities(config)
	if err != nil || len(endpoints) != 1 || endpoints[0].IsValid() {
		t.Fatal("pure hostname validation must defer resolution", err)
	}
}

func TestResolvedEndpointSelection(t *testing.T) {
	for name, item := range map[string]struct {
		answers []string
		want    string
	}{
		"ipv4 preferred": {[]string{"2001:db8::1", "192.0.2.1"}, "192.0.2.1:51820"},
		"ipv6 only":      {[]string{"2001:db8::1"}, "[2001:db8::1]:51820"},
		"mapped ipv4":    {[]string{"::ffff:192.0.2.1"}, "192.0.2.1:51820"},
		"reject overlap": {[]string{"198.18.0.2"}, ""},
		"skip unsafe":    {[]string{"0.0.0.0", "224.0.0.1", "fe80::1", "198.18.0.2", "192.0.2.1"}, "192.0.2.1:51820"},
		"zoned ipv6":     {[]string{"fe80::1%en0"}, ""},
		"empty":          {nil, ""},
	} {
		t.Run(name, func(t *testing.T) {
			config := hostnameConfig(t)
			endpoints, _ := CheckCapabilities(config)
			got, err := resolveEndpoints(context.Background(), config, endpoints, func(context.Context, string) ([]netip.Addr, error) {
				answers := make([]netip.Addr, len(item.answers))
				for i, answer := range item.answers {
					answers[i] = netip.MustParseAddr(answer)
				}
				return answers, nil
			})
			if item.want == "" {
				if err == nil {
					t.Fatal("unsafe endpoint accepted")
				}
			} else if err != nil || got[0].String() != item.want {
				t.Fatal("unexpected endpoint selection", err)
			}
		})
	}
}

func TestResolutionBoundsAndPrivateErrors(t *testing.T) {
	config := hostnameConfig(t)
	for name, lookup := range map[string]endpointLookup{
		"timeout": func(ctx context.Context, _ string) ([]netip.Addr, error) { <-ctx.Done(); return nil, ctx.Err() },
		"private error": func(context.Context, string) ([]netip.Addr, error) {
			return nil, errors.New("private endpoint metadata")
		},
		"answer limit": func(context.Context, string) ([]netip.Addr, error) { return make([]netip.Addr, 33), nil },
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer cancel()
			endpoints, _ := CheckCapabilities(config)
			if _, err := resolveEndpoints(ctx, config, endpoints, lookup); err == nil || strings.Contains(err.Error(), "private endpoint") {
				t.Fatal("unbounded resolution or leaked resolver metadata")
			}
		})
	}
}

func TestResolutionChecksOtherPeersAndDeduplicatesNames(t *testing.T) {
	config := hostnameConfig(t)
	config.Peers = append(config.Peers, configcore.Peer{
		Endpoint:   &configcore.Endpoint{Host: "vpn.example.test", Port: 51821},
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	})
	calls := 0
	endpoints, err := resolveEndpoints(context.Background(), config, make([]netip.AddrPort, 2), func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("203.0.113.1")}, nil
	})
	if err != nil || calls != 1 || endpoints[0].String() != "203.0.113.1:51820" || endpoints[1].String() != "203.0.113.1:51821" {
		t.Fatal("cross-peer overlap or duplicate name resolution", err)
	}
}
