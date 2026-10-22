package recoverycore

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	networkcore "legacywg/NetworkCore"
)

// ProtectedTransport is the root worker's typed preparation owner. No installed
// request uses it yet. Inputs are numeric peer endpoints only; interface, source,
// gateway, PF text and filesystem paths are never supplied by the GUI.
// It does not install tunnel routes, configure DNS or claim target protection.
type ProtectedTransport struct {
	mutex    sync.Mutex
	store    *Store
	bind     *pfGuardBind
	failed   chan struct{}
	ready    bool
	finished bool
}

// PrepareProtectedTransport must precede tunnel route/DNS changes, after the
// worker has marked its newly created, configured/up utun. On an effectful
// failure it returns a non-nil owner AND an error: retain it, stop/close the
// owned tunnel and DNS, then call Disconnect explicitly. Never use Bind on an
// error. No failure path automatically restores ordinary networking.
func (store *Store) PrepareProtectedTransport(ctx context.Context, endpoints []netip.AddrPort) (*ProtectedTransport, error) {
	if ctx == nil || ctx.Err() != nil || store == nil || os.Geteuid() != 0 {
		return nil, ErrRecoveryRequired
	}
	endpoints, err := protectedEndpoints(endpoints)
	if err != nil {
		return nil, err
	}
	owner := &ProtectedTransport{store: store, failed: make(chan struct{})}
	store.mutex.Lock()
	if store.closed || store.protection != nil || store.pfTransport != nil || store.pfResidue() || store.endpointResidue() ||
		store.record.Validate() != nil || store.record.Boot != store.boot || store.record.PID != os.Getpid() || store.record.Phase != InterfaceCreated {
		store.mutex.Unlock()
		return nil, ErrRecoveryRequired
	}
	tunnel := pfInterface{store.record.Interface, store.record.InterfaceIndex}
	store.protection = owner
	store.mutex.Unlock()

	// No external effects yet. Admission failures release only our reservation.
	policy, hosts, err := captureProtectedPaths(ctx, endpoints, tunnel)
	if err != nil {
		store.mutex.Lock()
		if store.protection == owner {
			store.protection = nil
		}
		store.mutex.Unlock()
		return nil, ErrRecoveryRequired
	}
	fail := func() (*ProtectedTransport, error) {
		close(owner.failed)
		return owner, ErrRecoveryRequired
	}
	// From the first staged effect onward, the owner and journal remain pinned.
	// A caller must explicitly remove its tunnel before releasing this guard.
	if store.stageDisabledPFAnchor(ctx) != nil || store.activatePFAnchor(ctx) != nil {
		return fail()
	}
	if len(hosts) != 0 && store.installEndpointRoutes(ctx, hosts) != nil {
		return fail()
	}
	owner.bind, err = newPFScopedGuardBind(ctx, store, policy)
	if err != nil {
		return fail()
	}
	owner.ready = true
	return owner, nil
}

func protectedEndpoints(input []netip.AddrPort) ([]netip.AddrPort, error) {
	if len(input) == 0 || len(input) > maxPFReferences {
		return nil, ErrRecoveryRequired
	}
	result := append([]netip.AddrPort(nil), input...)
	for _, endpoint := range result {
		ip := endpoint.Addr()
		if !endpoint.IsValid() || endpoint.Port() == 0 || !pfNumericAddress(ip) || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return nil, ErrRecoveryRequired
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Compare(result[j]) < 0 })
	unique := result[:0]
	for _, endpoint := range result {
		if len(unique) == 0 || unique[len(unique)-1] != endpoint {
			unique = append(unique, endpoint)
		}
	}
	return unique, nil
}

func protectedSource(path networkcore.Path, ipv4 bool) (netip.Addr, error) {
	iface, err := net.InterfaceByIndex(path.InterfaceIndex)
	if err != nil || iface.Name != path.InterfaceName || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return netip.Addr{}, ErrRecoveryRequired
	}
	addresses, err := iface.Addrs()
	if err != nil || len(addresses) > 128 {
		return netip.Addr{}, ErrRecoveryRequired
	}
	var candidates []netip.Addr
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			continue
		}
		ip := prefix.Addr()
		if pfNumericAddress(ip) && ip.Is4() == ipv4 && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			candidates = append(candidates, ip)
		}
	}
	if len(candidates) == 0 {
		return netip.Addr{}, ErrRecoveryRequired
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Compare(candidates[j]) < 0 })
	selected := candidates[0]
	for _, candidate := range candidates {
		if candidate == path.Source {
			selected = candidate
			break
		}
	}
	if validatePFDatagramSource(pfInterface{path.InterfaceName, path.InterfaceIndex}, selected) != nil {
		return netip.Addr{}, ErrRecoveryRequired
	}
	return selected, nil
}

func captureProtectedPaths(ctx context.Context, endpoints []netip.AddrPort, tunnel pfInterface) (pfPolicy, []networkcore.ScopedHost, error) {
	iface, err := net.InterfaceByName(tunnel.name)
	if err != nil || iface.Index != tunnel.index || iface.Flags&net.FlagUp == 0 {
		return pfPolicy{}, nil, ErrRecoveryRequired
	}
	policy := pfPolicy{tunnel: &tunnel}
	var hosts []networkcore.ScopedHost
	seenHosts := make(map[netip.Addr]bool)
	var families [2]*pfUDPEscape
	for _, endpoint := range endpoints {
		before, err := networkcore.EndpointRoute(ctx, endpoint.Addr())
		if err != nil || before.InterfaceIndex == tunnel.index || before.InterfaceName == tunnel.name ||
			validatePFDatagramSource(pfInterface{before.InterfaceName, before.InterfaceIndex}, before.Source) != nil {
			return pfPolicy{}, nil, ErrRecoveryRequired
		}
		source, err := protectedSource(before, endpoint.Addr().Is4())
		if err != nil {
			return pfPolicy{}, nil, ErrRecoveryRequired
		}
		escape := pfUDPEscape{path: pfInterface{before.InterfaceName, before.InterfaceIndex}, source: source, endpoint: endpoint, sourcePort: 1}
		family := 0
		if endpoint.Addr().Is6() {
			family = 1
		}
		if previous := families[family]; previous != nil {
			if previous.path != escape.path || validatePFDatagramSource(previous.path, previous.source) != nil {
				return pfPolicy{}, nil, ErrRecoveryRequired
			}
			escape.source = previous.source
		} else {
			copyEscape := escape
			families[family] = &copyEscape
		}
		policy.escapes = append(policy.escapes, escape)
		if seenHosts[endpoint.Addr()] {
			continue
		}
		seenHosts[endpoint.Addr()] = true
		if scoped, err := networkcore.ScopedRoute(ctx, endpoint.Addr(), before.InterfaceIndex); err == nil {
			if scoped.Path != before {
				return pfPolicy{}, nil, ErrRecoveryRequired
			}
			// Verified pre-existing scoped paths are borrowed, never journaled.
			continue
		}
		host := networkcore.ScopedHost{Destination: endpoint.Addr(), Path: before}
		observed, err := networkcore.ObserveScopedHost(ctx, host)
		if err != nil || observed.Path != before || !observed.Prefix.IsValid() || observed.Prefix.Bits() == endpoint.Addr().BitLen() || ctx.Err() != nil {
			return pfPolicy{}, nil, ErrRecoveryRequired
		}
		hosts = append(hosts, host)
	}
	policy, err = policy.frozen()
	if err != nil || ctx.Err() != nil {
		return pfPolicy{}, nil, ErrRecoveryRequired
	}
	return policy, hosts, nil
}

// Bind exposes only the official engine interface, never the detach/recovery
// operations. Closing/Down keeps the guard active; Stop permanently retires it.
func (owner *ProtectedTransport) Bind() (conn.Bind, error) {
	owner.mutex.Lock()
	defer owner.mutex.Unlock()
	if !owner.ready || owner.finished || owner.bind == nil || owner.bind.scoped.lost.Load() {
		return nil, ErrRecoveryRequired
	}
	return owner.bind, nil
}

func (owner *ProtectedTransport) Lost() <-chan struct{} {
	if owner.bind != nil {
		return owner.bind.scoped.loss
	}
	return owner.failed // Closed before a failed constructor returns its owner.
}

// Stop retires callbacks before waiting for PF, then confirms deny-only before
// releasing ports. Close has its own bounded cleanup context even when the
// admission context expired. Ambiguous effects keep the socket and Store pins.
func (owner *ProtectedTransport) Stop(ctx context.Context) error {
	if ctx == nil {
		return ErrRecoveryRequired
	}
	owner.mutex.Lock()
	defer owner.mutex.Unlock()
	return owner.stop(ctx)
}

func (owner *ProtectedTransport) stop(ctx context.Context) error {
	owner.ready = false
	if owner.finished {
		return nil
	}
	if owner.bind == nil {
		return ErrRecoveryRequired // Preparation may have failed before activation.
	}
	owner.bind.scoped.refuse(owner.bind)
	if owner.bind.Close() != nil && owner.bind.reconcile(ctx) != nil {
		return ErrRecoveryRequired
	}
	// Close is a no-op if Open never published a lease. Prove the live deny
	// policy in that case too; an empty socket set is not a PF observation.
	proof, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	owner.bind.op.Lock()
	defer owner.bind.op.Unlock()
	return owner.bind.changePolicy(proof, pfPolicy{}, false)
}

// Disconnect is explicit release, not the path-loss/process-death policy. The
// caller must first stop its DNS process and close its own TUN/device. A live
// recorded tunnel refuses release even after Stop. No foreign route is removed.
func (owner *ProtectedTransport) Disconnect(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrRecoveryRequired
	}
	owner.mutex.Lock()
	defer owner.mutex.Unlock()
	if owner.finished {
		return nil
	}
	if owner.bind != nil && owner.stop(ctx) != nil {
		return ErrRecoveryRequired
	}
	store := owner.store
	store.mutex.Lock()
	allowed := !store.closed && store.protection == owner && interfaceGone(store.record)
	store.mutex.Unlock()
	if !allowed {
		return ErrRecoveryRequired
	}
	if owner.bind != nil && !owner.bind.detached && owner.bind.detach() != nil {
		return ErrRecoveryRequired
	}
	if store.recoverEndpointRoutes(ctx) != nil {
		return ErrRecoveryRequired
	}
	if store.pfResidue() && store.recoverPFLifecycle(ctx) != nil {
		return ErrRecoveryRequired
	}
	store.mutex.Lock()
	if store.closed || store.protection != owner || store.pfTransport != nil || store.pfResidue() || store.endpointResidue() {
		store.mutex.Unlock()
		return ErrRecoveryRequired
	}
	store.protection = nil
	store.mutex.Unlock()
	if store.Finish() != nil {
		store.mutex.Lock()
		if !store.closed {
			store.protection = owner
		}
		store.mutex.Unlock()
		return ErrRecoveryRequired
	}
	owner.finished = true
	return nil
}
