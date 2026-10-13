package session

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"sync"
	"time"
)

// Private kernel path identity. Never include this metadata in public status,
// diagnostics or an error. It is not proof of ownership of a route.
type endpointPath struct {
	InterfaceIndex int
	InterfaceName  string
	Gateway        netip.Addr
	GatewayZone    int
	Direct         bool
	Source         netip.Addr
	SourceZone     int
}

type pathLookup func(context.Context, netip.Addr) (endpointPath, error)

var interfaceName = regexp.MustCompile(`^[a-z][a-z0-9]{0,14}$`)

func captureEndpointPaths(ctx context.Context, endpoints []netip.AddrPort, lookup pathLookup) (map[netip.Addr]endpointPath, error) {
	if len(endpoints) > 16 {
		return nil, errors.New("endpoint path limit")
	}
	paths := make(map[netip.Addr]endpointPath)
	for _, endpoint := range endpoints {
		if !endpoint.IsValid() {
			continue
		}
		address := endpoint.Addr()
		if _, exists := paths[address]; exists {
			continue
		}
		if ctx.Err() != nil {
			return nil, errors.New("endpoint route query timed out")
		}
		path, err := lookup(ctx, address)
		if err != nil || ctx.Err() != nil || !validEndpointPath(address, path) {
			return nil, errors.New("cannot verify endpoint route")
		}
		paths[address] = path
	}
	return paths, nil
}

func validEndpointPath(address netip.Addr, path endpointPath) bool {
	if path.InterfaceIndex <= 0 || !interfaceName.MatchString(path.InterfaceName) {
		return false
	}
	if !path.Direct && (!path.Gateway.IsValid() || path.Gateway.IsUnspecified()) {
		return false
	}
	for _, scoped := range []struct {
		addr netip.Addr
		zone int
	}{{path.Gateway, path.GatewayZone}, {path.Source, path.SourceZone}} {
		if !scoped.addr.IsValid() {
			if scoped.zone != 0 {
				return false
			}
			continue
		}
		if scoped.addr.Zone() != "" || scoped.addr.BitLen() != address.BitLen() || scoped.addr.IsMulticast() || scoped.zone < 0 {
			return false
		}
		if scoped.addr.IsLinkLocalUnicast() {
			if scoped.zone != path.InterfaceIndex {
				return false
			}
		} else if scoped.zone != 0 {
			return false
		}
	}
	return true
}

func verifyEndpointPaths(ctx context.Context, original map[netip.Addr]endpointPath, lookup pathLookup) error {
	for address, before := range original {
		after, err := lookup(ctx, address)
		if err != nil || ctx.Err() != nil || !validEndpointPath(address, after) || after != before {
			return errors.New("endpoint route changed or became unavailable")
		}
	}
	return nil
}

type pathWatch struct {
	cancel context.CancelFunc
	lost   chan struct{}
	exited chan struct{}
	once   sync.Once
}

func startPathWatch(original map[netip.Addr]endpointPath, lookup pathLookup) *pathWatch {
	ctx, cancel := context.WithCancel(context.Background())
	watch := &pathWatch{cancel: cancel, lost: make(chan struct{}), exited: make(chan struct{})}
	go func() {
		defer close(watch.exited)
		defer close(watch.lost)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				check, stop := context.WithTimeout(ctx, 2*time.Second)
				err := verifyEndpointPaths(check, original, lookup)
				stop()
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					return
				}
			}
		}
	}()
	return watch
}

func (watch *pathWatch) close() error {
	watch.once.Do(watch.cancel)
	select {
	case <-watch.exited:
		return nil
	case <-time.After(3 * time.Second):
		return errors.New("endpoint monitor cleanup requires attention")
	}
}
