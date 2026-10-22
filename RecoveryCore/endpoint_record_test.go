package recoverycore

import (
	"bytes"
	"net/netip"
	"testing"
)

func fixtureEndpointSpec(six bool) endpointRouteSpec {
	spec := endpointRouteSpec{Destination: netip.MustParseAddr("198.18.111.130"), Interface: "en42", Index: 42, Source: netip.MustParseAddr("198.18.111.129"), Gateway: netip.MustParseAddr("198.18.111.1")}
	if six {
		spec.Destination = netip.MustParseAddr("2001:db8:111::130")
		spec.Source = netip.MustParseAddr("2001:db8:111::129")
		spec.Gateway = netip.MustParseAddr("fe80::1")
		spec.GatewayZone = 42
	}
	return spec
}

func TestEndpointRecordCanonicalAndConservativeTransitions(t *testing.T) {
	record, err := newEndpointRouteRecord("00000000-0000-0000-0000-000000000001", "0123456789abcdef0123456789abcdef", []endpointRouteSpec{fixtureEndpointSpec(false), fixtureEndpointSpec(true)})
	if err != nil {
		t.Fatal("valid route plan refused")
	}
	for _, phase := range []endpointRoutePhase{endpointAddIntent, endpointInstalled, endpointRemoveIntent, endpointRemoved} {
		next, err := record.advance(0, phase)
		if err != nil || !endpointTransition(record, next) || record.Routes[0].Phase == next.Routes[0].Phase {
			t.Fatal("route transition or immutable copy failed")
		}
		record = next
		data, err := encodeEndpointRoutes(record)
		if err != nil {
			t.Fatal("encode failed")
		}
		decoded, err := decodeEndpointRoutes(data)
		if err != nil || decoded.Routes[0] != record.Routes[0] || decoded.Routes[1] != record.Routes[1] {
			t.Fatal("canonical round trip failed")
		}
		for _, bad := range [][]byte{append(append([]byte(nil), data...), data...), bytes.Replace(data, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(data, []byte(`"version":1`), []byte(`"extra":0,"version":1`), 1), bytes.Replace(data, []byte(`"index":42`), []byte(`"index":65536`), 1)} {
			if _, err := decodeEndpointRoutes(bad); err == nil {
				t.Fatal("ambiguous/corrupt route record accepted")
			}
		}
	}
	if _, err := record.advance(0, endpointInstalled); err == nil {
		t.Fatal("removed ownership revived")
	}
	if _, err := record.advance(1, endpointInstalled); err == nil {
		t.Fatal("addition confirmation skipped intent")
	}
	changed := record
	changed.Routes = append([]endpointRouteEntry(nil), record.Routes...)
	changed.Routes[1].Spec.Index++
	if endpointTransition(record, changed) {
		t.Fatal("route identity changed")
	}
}

func TestEndpointRecordRefusesUnsafePlans(t *testing.T) {
	for name, change := range map[string]func(*endpointRouteSpec){
		"default":                func(s *endpointRouteSpec) { s.Destination = netip.IPv4Unspecified() },
		"mapped":                 func(s *endpointRouteSpec) { s.Destination = netip.MustParseAddr("::ffff:198.18.111.130") },
		"multicast":              func(s *endpointRouteSpec) { s.Destination = netip.MustParseAddr("224.0.0.1") },
		"link local destination": func(s *endpointRouteSpec) { s.Destination = netip.MustParseAddr("169.254.1.2") },
		"loopback destination":   func(s *endpointRouteSpec) { s.Destination = netip.MustParseAddr("127.0.0.1") },
		"wrong family":           func(s *endpointRouteSpec) { s.Source = netip.MustParseAddr("2001:db8::2") },
		"bad interface":          func(s *endpointRouteSpec) { s.Interface = "en0;id" },
		"bad zone":               func(s *endpointRouteSpec) { s.GatewayZone = 42 },
		"direct with gateway":    func(s *endpointRouteSpec) { s.Direct = true },
		"gateway missing":        func(s *endpointRouteSpec) { s.Gateway = netip.Addr{} },
		"missing source":         func(s *endpointRouteSpec) { s.Source = netip.Addr{} },
	} {
		t.Run(name, func(t *testing.T) {
			spec := fixtureEndpointSpec(false)
			change(&spec)
			if spec.valid() {
				t.Fatal("unsafe host accepted")
			}
		})
	}
	for _, specs := range [][]endpointRouteSpec{nil, {fixtureEndpointSpec(false), fixtureEndpointSpec(false)}} {
		if _, err := newEndpointRouteRecord("00000000-0000-0000-0000-000000000001", "0123456789abcdef0123456789abcdef", specs); err == nil {
			t.Fatal("empty/duplicate route plan accepted")
		}
	}
}
