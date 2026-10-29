package session

import (
	"context"
	"errors"
	"net"
	"net/netip"

	configcore "legacywg/ConfigCore"
)

type endpointLookup func(context.Context, string) ([]netip.Addr, error)

func systemLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	// The pinned Go implementation uses libc on Darwin, even with CGO_ENABLED=0.
	// The root helper supplies a fixed environment without resolver overrides.
	return (&net.Resolver{}).LookupNetIP(ctx, "ip", host)
}

func resolveEndpoints(ctx context.Context, config *configcore.Config, endpoints []netip.AddrPort, lookup endpointLookup) ([]netip.AddrPort, error) {
	cache := make(map[string]netip.Addr)
	for index, peer := range config.Peers {
		if peer.Endpoint == nil || endpoints[index].IsValid() {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, errors.New("endpoint resolution timed out")
		}
		host := peer.Endpoint.Host
		address, found := cache[host]
		if !found {
			answers, err := lookup(ctx, host)
			if ctx.Err() != nil {
				return nil, errors.New("endpoint resolution timed out")
			}
			if err != nil || len(answers) == 0 || len(answers) > 32 {
				return nil, errors.New("endpoint name could not be resolved")
			}
			// Prefer IPv4 when both families are available; preserve native order
			// within a family. IPv6-only names are supported. This is one chosen
			// address, not a promise of reachability or automatic fallback.
			for _, ipv4 := range []bool{true, false} {
				for _, candidate := range answers {
					candidate = candidate.Unmap()
					if !candidate.IsValid() || candidate.Is4() != ipv4 || candidate.IsUnspecified() || candidate.IsMulticast() || candidate.Zone() != "" || candidate.IsLinkLocalUnicast() {
						continue
					}
					overlaps := false
					for _, other := range config.Peers {
						for _, route := range other.AllowedIPs {
							overlaps = overlaps || (!fullMode(config) && route.Contains(candidate))
						}
					}
					if !overlaps {
						address = candidate
						break
					}
				}
				if address.IsValid() {
					break
				}
			}
			if !address.IsValid() {
				return nil, errors.New("endpoint has no usable address outside tunnel routes")
			}
			cache[host] = address
		}
		endpoints[index] = netip.AddrPortFrom(address, peer.Endpoint.Port)
	}
	return endpoints, nil
}
