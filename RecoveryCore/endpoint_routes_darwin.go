package recoverycore

import (
	"context"
	"errors"
	"os"

	networkcore "legacywg/NetworkCore"

	"golang.org/x/sys/unix"
)

func endpointSpec(host networkcore.ScopedHost) endpointRouteSpec {
	p := host.Path
	return endpointRouteSpec{Destination: host.Destination, Interface: p.InterfaceName, Index: p.InterfaceIndex,
		Source: p.Source, SourceZone: p.SourceZone, Gateway: p.Gateway, GatewayZone: p.GatewayZone, Direct: p.Direct}
}

func (spec endpointRouteSpec) host() networkcore.ScopedHost {
	return networkcore.ScopedHost{Destination: spec.Destination, Path: networkcore.Path{
		InterfaceIndex: spec.Index, InterfaceName: spec.Interface, Source: spec.Source, SourceZone: spec.SourceZone,
		Gateway: spec.Gateway, GatewayZone: spec.GatewayZone, Direct: spec.Direct}}
}

// Route effects are permitted only while our verified enabled deny-only PF
// guard is held, with no attached socket owner. Generic PF/utun recovery must
// not lift that guard until all endpoint ownership records are resolved.
func (store *Store) endpointGuard(ctx context.Context, pfID string) error {
	if ctx == nil || ctx.Err() != nil || store.closed || store.pfTransport != nil {
		return ErrRecoveryRequired
	}
	if pending, err := store.readPF(pfTemporaryFile); err != nil || pending != nil {
		return ErrRecoveryRequired
	}
	record, err := store.readPF(pfJournalFile)
	if err != nil || record == nil || record.Phase != PFActive || record.ID != pfID || !store.pfJournalOwner(*record) || record.RulesSHA256 != pfDigest(stagedPFRule) {
		return ErrRecoveryRequired
	}
	fd, err := openPFReferences(ctx)
	if err != nil {
		return ErrRecoveryRequired
	}
	defer unix.Close(fd)
	entries, err := readPFReferences(ctx, fd)
	if err != nil {
		return ErrRecoveryRequired
	}
	owned, err := selectPFReference(*record, entries)
	if err != nil || owned == nil {
		return ErrRecoveryRequired
	}
	policy, err := readPFPolicy(ctx, record.Anchor, true)
	if err != nil || !policy.matches(*record) || policy.rules != record.RulesSHA256 || ctx.Err() != nil {
		return ErrRecoveryRequired
	}
	return nil
}

func endpointExactPresent(ctx context.Context, host networkcore.ScopedHost) (bool, error) {
	observed, err := networkcore.ObserveScopedHost(ctx, host)
	if errors.Is(err, networkcore.ErrNoRoute) {
		return false, nil
	}
	if err != nil || !observed.Prefix.IsValid() {
		return false, ErrRecoveryRequired
	}
	// A host at the same scope is preserved even if its class/path differs.
	return observed.Prefix.Bits() == host.Destination.BitLen() && observed.Flags&unix.RTF_IFSCOPE != 0, nil
}

// Install only absent exact scoped hosts captured before tunnel route changes.
// Acknowledged additions are verified before ownership is committed. An
// uncertain addition stays add_intent and is never claimed from tuple equality.
func (store *Store) installEndpointRoutes(ctx context.Context, hosts []networkcore.ScopedHost) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.closed || store.endpointResidue() {
		return ErrRecoveryRequired
	}
	pf, err := store.readPF(pfJournalFile)
	if err != nil || pf == nil || pf.PID != os.Getpid() || store.endpointGuard(ctx, pf.ID) != nil {
		return ErrRecoveryRequired
	}
	var specs []endpointRouteSpec
	for _, host := range hosts {
		specs = append(specs, endpointSpec(host))
	}
	record, err := newEndpointRouteRecord(store.boot, pf.ID, specs)
	if err != nil {
		return ErrRecoveryRequired
	}
	for _, host := range hosts {
		if validatePFDatagramSource(pfInterface{host.Path.InterfaceName, host.Path.InterfaceIndex}, host.Path.Source) != nil {
			return ErrRecoveryRequired
		}
		before, err := networkcore.EndpointRoute(ctx, host.Destination)
		if err != nil || before != host.Path {
			return ErrRecoveryRequired
		}
		observed, err := networkcore.ObserveScopedHost(ctx, host)
		if err != nil || !observed.Prefix.IsValid() || observed.Path != before || observed.Prefix.Bits() == host.Destination.BitLen() {
			return ErrRecoveryRequired
		}
	}
	if store.writeEndpointRoutes(record) != nil {
		return ErrRecoveryRequired
	}
	store.mark("endpoint_plan_committed")
	for i, host := range hosts {
		if store.endpointGuard(ctx, record.PFID) != nil {
			return ErrRecoveryRequired
		}
		present, err := endpointExactPresent(ctx, host)
		if err != nil || present {
			return ErrRecoveryRequired
		}
		next, err := record.advance(i, endpointAddIntent)
		if err != nil || store.writeEndpointRoutes(next) != nil {
			return ErrRecoveryRequired
		}
		record = next
		store.mark("endpoint_add_intent_committed")
		// Revalidate path and source after the durable intent, before sending.
		path, err := networkcore.EndpointRoute(ctx, host.Destination)
		if err != nil || path != host.Path || store.endpointGuard(ctx, record.PFID) != nil || validatePFDatagramSource(pfInterface{path.InterfaceName, path.InterfaceIndex}, path.Source) != nil {
			return ErrRecoveryRequired
		}
		if networkcore.ChangeScopedHost(ctx, host, true) != nil {
			return ErrRecoveryRequired
		}
		store.mark("endpoint_added_kernel")
		observed, err := networkcore.ScopedRoute(ctx, host.Destination, host.Path.InterfaceIndex)
		if err != nil || !host.Matches(observed) {
			return ErrRecoveryRequired
		}
		next, err = record.advance(i, endpointInstalled)
		if err != nil || store.writeEndpointRoutes(next) != nil {
			return ErrRecoveryRequired
		}
		record = next
		store.mark("endpoint_installed_committed")
	}
	return nil
}

// Reconciliation deliberately refuses an add_intent with a matching live host:
// the add acknowledgment may have been lost and tuple equality is not an
// ownership token. Unknown/replaced routes and temporary documents survive.
// Confirmed ownership is checked immediately before delete, but kernel APIs
// provide no atomic compare-delete or defense against another root writer.
func (store *Store) recoverEndpointRoutes(ctx context.Context) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.closed {
		return ErrRecoveryRequired
	}
	if temporary, err := store.readEndpointRoutes(endpointTemporaryFile); err != nil || temporary != nil {
		return ErrRecoveryRequired
	}
	record, err := store.readEndpointRoutes(endpointJournalFile)
	if err != nil {
		return ErrRecoveryRequired
	}
	if record == nil {
		return nil
	}
	if record.Boot != store.boot || (record.PID != os.Getpid() && processAlive(record.PID)) || store.endpointGuard(ctx, record.PFID) != nil {
		return ErrRecoveryRequired
	}
	for i := len(record.Routes) - 1; i >= 0; i-- {
		entry := record.Routes[i]
		host := entry.Spec.host()
		if entry.Phase == endpointRemoved {
			continue
		}
		if store.endpointGuard(ctx, record.PFID) != nil {
			return ErrRecoveryRequired
		}
		present, err := endpointExactPresent(ctx, host)
		if err != nil {
			return ErrRecoveryRequired
		}
		if entry.Phase == endpointAddIntent && present {
			return ErrRecoveryRequired
		}
		if entry.Phase == endpointInstalled || entry.Phase == endpointRemoveIntent {
			if present {
				observed, err := networkcore.ScopedRoute(ctx, host.Destination, host.Path.InterfaceIndex)
				if err != nil || !host.Matches(observed) || validatePFDatagramSource(pfInterface{host.Path.InterfaceName, host.Path.InterfaceIndex}, host.Path.Source) != nil {
					return ErrRecoveryRequired
				}
			}
			if entry.Phase == endpointInstalled {
				next, err := record.advance(i, endpointRemoveIntent)
				if err != nil || store.writeEndpointRoutes(next) != nil {
					return ErrRecoveryRequired
				}
				record = &next
				store.mark("endpoint_remove_intent_committed")
			}
			if present {
				observed, err := networkcore.ScopedRoute(ctx, host.Destination, host.Path.InterfaceIndex)
				if err != nil || !host.Matches(observed) || store.endpointGuard(ctx, record.PFID) != nil {
					return ErrRecoveryRequired
				}
				if networkcore.ChangeScopedHost(ctx, host, false) != nil {
					return ErrRecoveryRequired
				}
				store.mark("endpoint_deleted_kernel")
			}
			present, err = endpointExactPresent(ctx, host)
			if err != nil || present {
				return ErrRecoveryRequired
			}
		}
		next, err := record.advance(i, endpointRemoved)
		if err != nil || store.writeEndpointRoutes(next) != nil {
			return ErrRecoveryRequired
		}
		record = &next
		store.mark("endpoint_removed_committed")
	}
	if unix.Unlinkat(store.directory, endpointJournalFile, 0) != nil || unix.Fsync(store.directory) != nil || fullSync(store.lock) != nil {
		return ErrRecoveryRequired
	}
	store.mark("endpoint_journal_removed")
	return nil
}
