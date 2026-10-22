package recoverycore

import (
	"context"
	"net"
	"net/netip"
	"os"

	"golang.org/x/sys/unix"
)

func (store *Store) validatePFPaths(ctx context.Context, policy pfPolicy) error {
	if ctx.Err() != nil || store.closed {
		return ErrRecoveryRequired
	}
	if policy.loopback {
		iface, err := net.InterfaceByName("lo0")
		if err != nil || iface.Index < 1 || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback == 0 {
			return ErrRecoveryRequired
		}
	}
	if policy.tunnel != nil {
		if store.record.Validate() != nil || store.record.Boot != store.boot || store.record.PID != os.Getpid() || (store.record.Phase != InterfaceCreated && store.record.Phase != Configured) || store.record.Interface != policy.tunnel.name || store.record.InterfaceIndex != policy.tunnel.index {
			return ErrRecoveryRequired
		}
		iface, err := net.InterfaceByName(policy.tunnel.name)
		if err != nil || iface.Index != policy.tunnel.index || iface.Flags&net.FlagUp == 0 {
			return ErrRecoveryRequired
		}
	}
	for _, escape := range policy.escapes {
		iface, err := net.InterfaceByName(escape.path.name)
		if err != nil || iface.Index != escape.path.index || iface.Flags&net.FlagUp == 0 {
			return ErrRecoveryRequired
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return ErrRecoveryRequired
		}
		assigned := false
		for _, address := range addresses {
			var ip net.IP
			switch value := address.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if actual, ok := netip.AddrFromSlice(ip); ok && actual.Unmap() == escape.source {
				assigned = true
			}
		}
		if !assigned {
			return ErrRecoveryRequired
		}
	}
	return nil
}

func (store *Store) preparePFPolicy(ctx context.Context, record PFRecord, policy pfPolicy) (pfPolicy, string, error) {
	policy, err := policy.frozen()
	if err != nil || store.validatePFPaths(ctx, policy) != nil {
		return pfPolicy{}, "", ErrRecoveryRequired
	}
	input, err := policy.render()
	if err != nil {
		return pfPolicy{}, "", ErrRecoveryRequired
	}
	// Preview the native canonical display without any load. Disable the rule
	// optimizer for preview AND application so it cannot alter rule identity.
	canonical, err := runOwnedPF(ctx, input, "-n", "-v", "-o", "none", "-a", record.Anchor, "-f", "-")
	if err != nil {
		return pfPolicy{}, "", ErrRecoveryRequired
	}
	parsed, err := parsePFPolicy(canonical)
	if err != nil || !samePFPolicy(policy, parsed) || store.validatePFPaths(ctx, policy) != nil {
		return pfPolicy{}, "", ErrRecoveryRequired
	}
	return policy, canonical, nil
}

func (store *Store) updatePFPolicy(ctx context.Context, desired pfPolicy) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	return store.updatePFPolicyLocked(ctx, desired, nil)
}

func (store *Store) updatePFPolicyLocked(ctx context.Context, desired pfPolicy, transport *pfGuardBind) error {
	if store.pfTransport != transport {
		return ErrRecoveryRequired
	}
	if store.closed || ctx.Err() != nil || !currentPFReferenceName() {
		return ErrRecoveryRequired
	}
	if pending, err := store.readPF(pfTemporaryFile); err != nil || pending != nil {
		return ErrRecoveryRequired
	}
	record, err := store.readPF(pfJournalFile)
	if err != nil || record == nil || record.Phase != PFActive || record.PID != os.Getpid() || !store.pfJournalOwner(*record) {
		return ErrRecoveryRequired
	}
	desired, canonical, err := store.preparePFPolicy(ctx, *record, desired)
	if err != nil {
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
	before, err := readPFPolicy(ctx, record.Anchor, true)
	check, referenceErr := readPFReferences(ctx, fd)
	if err != nil || !before.matches(*record) || before.rules != record.RulesSHA256 || referenceErr != nil || !samePFReferences(entries, check) {
		return ErrRecoveryRequired
	}
	if pfDigest(canonical) == record.RulesSHA256 {
		return nil
	}
	next, err := record.BeginRuleUpdate(pfDigest(canonical))
	if err != nil || store.writePF(next) != nil {
		return ErrRecoveryRequired
	}
	record = &next
	store.mark("pf_rule_update_intent_committed")
	policyCheck, err := readPFPolicy(ctx, record.Anchor, true)
	check, referenceErr = readPFReferences(ctx, fd)
	if err != nil || policyCheck != before || referenceErr != nil || !samePFReferences(entries, check) || store.validatePFPaths(ctx, desired) != nil {
		return ErrRecoveryRequired
	}
	if err = store.changePFFilter(ctx, *record, before, entries, &desired, false); err != nil {
		return ErrRecoveryRequired
	}
	store.mark("pf_rule_update_loaded_kernel")
	after, err := readPFPolicy(ctx, record.Anchor, true)
	check, referenceErr = readPFReferences(ctx, fd)
	if err != nil || !after.matches(*record) || after.rules != record.NextRulesSHA256 || referenceErr != nil || !samePFReferences(entries, check) || store.validatePFPaths(ctx, desired) != nil {
		return ErrRecoveryRequired
	}
	next, err = record.ResolveRuleUpdate(after.rules)
	if err != nil || store.writePF(next) != nil {
		return ErrRecoveryRequired
	}
	store.mark("pf_rule_update_confirmation_committed")
	return nil
}

func (store *Store) resolvePFPolicy(ctx context.Context) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.pfTransport != nil {
		return ErrRecoveryRequired
	}
	return store.resolvePFPolicyLocked(ctx)
}

func (store *Store) resolvePFPolicyLocked(ctx context.Context) error {
	if store.closed || ctx.Err() != nil {
		return ErrRecoveryRequired
	}
	if pending, err := store.readPF(pfTemporaryFile); err != nil || pending != nil {
		return ErrRecoveryRequired
	}
	record, err := store.readPF(pfJournalFile)
	if err != nil || record == nil || record.Phase != PFRuleUpdateIntent || !store.pfJournalOwner(*record) {
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
	observed, err := readPFPolicy(ctx, record.Anchor, true)
	check, referenceErr := readPFReferences(ctx, fd)
	if err != nil || !observed.matches(*record) || referenceErr != nil || !samePFReferences(entries, check) {
		return ErrRecoveryRequired
	}
	next, err := record.ResolveRuleUpdate(observed.rules)
	if err != nil {
		return ErrRecoveryRequired
	}
	if observed.rules == record.RulesSHA256 {
		// Retire the owned inactive candidate before rolling back durable intent.
		// Active original rules stay intact; no text is reconstructed from a hash.
		if store.changePFFilter(ctx, *record, observed, entries, nil, true) != nil {
			return ErrRecoveryRequired
		}
	}
	if store.commitOwnedPF(next) != nil {
		return ErrRecoveryRequired
	}
	return nil
}
