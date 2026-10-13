package session

import (
	"bufio"
	"context"
	"errors"
	"net/netip"
	"strings"

	configcore "legacywg/ConfigCore"
)

// Only configured peer identities may supply current endpoints. The official
// engine owns authenticated roaming; raw Bind source metadata is not sampled.
// All metadata stays private. Public status retains its existing DTO.
func readCurrentEndpoints(raw string, indices map[string]int) ([]netip.AddrPort, error) {
	failure := errors.New("cannot read validated current endpoints")
	if len(raw) > 128*1024 || len(indices) < 1 || len(indices) > 16 {
		return nil, failure
	}
	result := make([]netip.AddrPort, len(indices))
	seen := make([]bool, len(indices))
	seenEndpoint := make([]bool, len(indices))
	current := -1
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 1024), 4096)
	for scanner.Scan() {
		field, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		if field == "public_key" {
			index, known := indices[value]
			if !known || index < 0 || index >= len(result) || seen[index] {
				return nil, failure
			}
			current = index
			seen[index] = true
			continue
		}
		if field != "endpoint" {
			continue
		}
		if current < 0 || seenEndpoint[current] {
			return nil, failure
		}
		address, err := netip.ParseAddrPort(value)
		if err != nil || address.Port() == 0 || address.Addr().Zone() != "" || address.Addr().Is4In6() || address.Addr().IsUnspecified() || address.Addr().IsMulticast() {
			return nil, failure
		}
		result[current] = address
		seenEndpoint[current] = true
	}
	if scanner.Err() != nil {
		return nil, failure
	}
	for _, found := range seen {
		if !found {
			return nil, failure
		}
	}
	return result, nil
}

type currentPathCheck struct {
	indices  map[string]int
	initial  []netip.AddrPort
	bases    []endpointPath
	have     []bool
	blocked  []netip.Prefix
	ownIndex int
	read     func() (string, error)
	lookup   pathLookup
}

func newCurrentPathCheck(config *configcore.Config, uapi string, initial []netip.AddrPort, paths map[netip.Addr]endpointPath, ownIndex int, read func() (string, error), lookup pathLookup) (*currentPathCheck, error) {
	failure := errors.New("cannot initialize current endpoint monitor")
	indices := peerIndices(uapi)
	if len(indices) < 1 || len(indices) > 16 || len(initial) != len(indices) || len(config.Peers) != len(indices) || ownIndex <= 0 || read == nil || lookup == nil {
		return nil, failure
	}
	check := &currentPathCheck{indices: indices, initial: append([]netip.AddrPort(nil), initial...), bases: make([]endpointPath, len(indices)), have: make([]bool, len(indices)), ownIndex: ownIndex, read: read, lookup: lookup}
	for i, endpoint := range initial {
		if !endpoint.IsValid() {
			continue
		}
		path, found := paths[endpoint.Addr()]
		if !found || !validEndpointPath(endpoint.Addr(), path) || path.InterfaceIndex == ownIndex {
			return nil, failure
		}
		check.bases[i] = path
		check.have[i] = true
	}
	for _, prefix := range config.Addresses {
		check.blocked = append(check.blocked, netip.PrefixFrom(prefix.Addr(), prefix.Addr().BitLen()))
	}
	for _, peer := range config.Peers {
		for _, prefix := range peer.AllowedIPs {
			check.blocked = append(check.blocked, prefix.Masked())
		}
	}
	if len(check.blocked) > configcore.MaxCIDRs {
		return nil, failure
	}
	return check, nil
}

// Called by one monitor goroutine. Newly authenticated addresses are checked
// against the peer's original route identity, not just the old destination.
// Passive peers establish a baseline after their first authenticated endpoint
// appears. No ownership/default/PF mutation or automatic cross-path reconnect.
func (check *currentPathCheck) verify(ctx context.Context) error {
	failure := errors.New("current endpoint path changed or became unavailable")
	if ctx.Err() != nil {
		return failure
	}
	raw, err := check.read()
	if err != nil || ctx.Err() != nil {
		return failure
	}
	endpoints, err := readCurrentEndpoints(raw, check.indices)
	if err != nil {
		return failure
	}
	bases := append([]endpointPath(nil), check.bases...)
	have := append([]bool(nil), check.have...)
	queried := make(map[netip.Addr]endpointPath)
	for i, endpoint := range endpoints {
		if !endpoint.IsValid() {
			if check.initial[i].IsValid() || have[i] {
				return failure
			}
			continue
		}
		address := endpoint.Addr()
		for _, prefix := range check.blocked {
			if prefix.Contains(address) {
				return failure
			}
		}
		path, found := queried[address]
		if !found {
			if ctx.Err() != nil {
				return failure
			}
			path, err = check.lookup(ctx, address)
			if err != nil || ctx.Err() != nil || !validEndpointPath(address, path) || path.InterfaceIndex == check.ownIndex {
				return failure
			}
			queried[address] = path
		}
		if have[i] && path != bases[i] {
			return failure
		}
		bases[i] = path
		have[i] = true
	}
	check.bases = bases
	check.have = have
	return nil
}
