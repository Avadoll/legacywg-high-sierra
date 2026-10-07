// Package networkcore builds a side-effect-free network intent. It never
// claims that routes, DNS or a firewall policy have been installed.
package networkcore

import (
	"errors"
	configcore "legacywg/ConfigCore"
	"net/netip"
)

type Plan struct {
	Addresses           []netip.Prefix
	Routes              []netip.Prefix
	DNS                 []netip.Addr
	Endpoints           []configcore.Endpoint
	FullIPv4            bool
	FullIPv6            bool
	RequireIPv6Block    bool
	RequireBootstrapDNS bool
	Protected           bool
}

// Build refuses a protected full IPv6 route with no local IPv6 address. The
// executor must refuse protected IPv4-only full tunnels until IPv6 blocking
// has been demonstrated on the target platform.
func Build(config *configcore.Config, protected bool) (*Plan, error) {
	if config == nil || len(config.Addresses) == 0 || len(config.Peers) == 0 {
		return nil, errors.New("validated profile required")
	}
	plan := &Plan{Addresses: append([]netip.Prefix(nil), config.Addresses...), DNS: append([]netip.Addr(nil), config.DNS...), Protected: protected}
	seen := map[netip.Prefix]bool{}
	for _, peer := range config.Peers {
		if peer.Endpoint != nil {
			plan.Endpoints = append(plan.Endpoints, *peer.Endpoint)
			if _, err := netip.ParseAddr(peer.Endpoint.Host); err != nil {
				plan.RequireBootstrapDNS = true
			}
		}
		for _, prefix := range peer.AllowedIPs {
			prefix = prefix.Masked()
			if seen[prefix] {
				continue
			}
			seen[prefix] = true
			plan.Routes = append(plan.Routes, prefix)
		}
	}
	if len(plan.Endpoints) == 0 {
		return nil, errors.New("outgoing client requires at least one Endpoint")
	}
	// Full coverage can also be represented by two /1 routes, or by a more
	// fragmented set. Collapse covered sibling prefixes without enumerating IPs.
	plan.FullIPv4 = covers(netip.MustParsePrefix("0.0.0.0/0"), plan.Routes)
	plan.FullIPv6 = covers(netip.MustParsePrefix("::/0"), plan.Routes)
	plan.RequireIPv6Block = protected && plan.FullIPv4 && !plan.FullIPv6
	if protected && plan.FullIPv6 {
		hasIPv6 := false
		for _, address := range plan.Addresses {
			hasIPv6 = hasIPv6 || address.Addr().Is6()
		}
		if !hasIPv6 {
			return nil, errors.New("full IPv6 tunnel requires an IPv6 interface address")
		}
	}
	return plan, nil
}

func covers(target netip.Prefix, routes []netip.Prefix) bool {
	contained := []netip.Prefix{}
	for _, route := range routes {
		if route.Addr().BitLen() != target.Addr().BitLen() {
			continue
		}
		if route.Bits() <= target.Bits() && route.Contains(target.Addr()) {
			return true
		}
		if target.Contains(route.Addr()) {
			contained = append(contained, route)
		}
	}
	if len(contained) < 2 || target.Bits() == target.Addr().BitLen() {
		return false
	}
	childBits := target.Bits() + 1
	left := netip.PrefixFrom(target.Addr(), childBits)
	var rightAddress netip.Addr
	if target.Addr().Is4() {
		b := target.Addr().As4()
		b[target.Bits()/8] |= 1 << (7 - target.Bits()%8)
		rightAddress = netip.AddrFrom4(b)
	} else {
		b := target.Addr().As16()
		b[target.Bits()/8] |= 1 << (7 - target.Bits()%8)
		rightAddress = netip.AddrFrom16(b)
	}
	return covers(left, contained) && covers(netip.PrefixFrom(rightAddress, childBits), contained)
}
