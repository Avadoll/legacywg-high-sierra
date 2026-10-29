package session

import (
	"errors"
	"net/netip"

	configcore "legacywg/ConfigCore"
	networkcore "legacywg/NetworkCore"
)

// Full mode is an explicitly unprotected research connection. Its UDP sockets
// must borrow a verified scoped physical route; no default route is replaced.
func fullMode(config *configcore.Config) bool {
	plan, err := networkcore.Build(config, false)
	return err == nil && (plan.FullIPv4 || plan.FullIPv6)
}

func checkFullMode(config *configcore.Config, plan *networkcore.Plan) error {
	if !plan.FullIPv4 || len(config.Peers) != 1 || config.Peers[0].Endpoint == nil {
		return errors.New("research full tunnel requires one peer with Endpoint and full IPv4 coverage")
	}
	if len(config.DNS) == 0 {
		return errors.New("research full tunnel requires profile DNS")
	}
	return nil
}

// /1 routes supersede ordinary defaults without changing them. If the profile
// has no full IPv6 coverage, route the rest of IPv6 into our TUN, where the
// official engine drops destinations with no matching peer. More-specific
// system/LAN routes remain; this is not a firewall or a leak guarantee.
func sessionRoutes(config *configcore.Config) []netip.Prefix {
	var result []netip.Prefix
	seen := make(map[netip.Prefix]bool)
	appendRoute := func(prefix netip.Prefix) {
		prefix = prefix.Masked()
		if !seen[prefix] {
			seen[prefix] = true
			result = append(result, prefix)
		}
	}
	for _, peer := range config.Peers {
		for _, prefix := range peer.AllowedIPs {
			if prefix.Bits() != 0 {
				appendRoute(prefix)
			} else if prefix.Addr().Is4() {
				appendRoute(netip.MustParsePrefix("0.0.0.0/1"))
				appendRoute(netip.MustParsePrefix("128.0.0.0/1"))
			} else {
				appendRoute(netip.MustParsePrefix("::/1"))
				appendRoute(netip.MustParsePrefix("8000::/1"))
			}
		}
	}
	if fullMode(config) {
		appendRoute(netip.MustParsePrefix("::/1"))
		appendRoute(netip.MustParsePrefix("8000::/1"))
	}
	return result
}
