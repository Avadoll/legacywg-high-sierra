package recoverycore

import (
	"context"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// All effects for one Store are serialized, in addition to the root directory
// flock. Competing privileged PF administrators do not participate in these
// locks; repeated observations are detection, not atomic compare-and-release.
func (store *Store) activatePFAnchor(ctx context.Context) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.closed || ctx.Err() != nil || !currentPFReferenceName() {
		return ErrRecoveryRequired
	}
	if pending, err := store.readPF(pfTemporaryFile); err != nil || pending != nil {
		return ErrRecoveryRequired
	}
	record, err := store.readPF(pfJournalFile)
	if err != nil || record == nil || !store.pfJournalOwner(*record) || record.PID != os.Getpid() || record.Phase != PFAnchorInstalled || record.RulesSHA256 != pfDigest(stagedPFRule) {
		return ErrRecoveryRequired
	}
	fd, err := openPFReferences(ctx)
	if err != nil {
		return ErrRecoveryRequired
	}
	defer unix.Close(fd)
	entries, err := readPFReferences(ctx, fd)
	if err != nil || len(entries) != 0 {
		return ErrRecoveryRequired
	}
	before, err := readDisabledPF(ctx, record.Anchor)
	if err != nil || !before.matches(*record) || before.rules != record.RulesSHA256 {
		return ErrRecoveryRequired
	}
	after := time.Now().Unix()
	next, err := record.Advance(PFReferenceIntent, after, after+5, 0)
	if err != nil || store.writePF(next) != nil {
		return ErrRecoveryRequired
	}
	record = &next
	store.mark("pf_reference_intent_committed")
	check, err := readDisabledPF(ctx, record.Anchor)
	entries, referenceErr := readPFReferences(ctx, fd)
	now := time.Now().Unix()
	if err != nil || check != before || referenceErr != nil || len(entries) != 0 || now < record.ReferenceAfter || now > record.ReferenceBefore || ctx.Err() != nil {
		return ErrRecoveryRequired
	}
	token, err := acquirePFReference(ctx, fd)
	if err != nil {
		return ErrRecoveryRequired
	}
	store.mark("pf_reference_acquired_kernel")
	entries, err = readPFReferences(ctx, fd)
	if err != nil {
		return ErrRecoveryRequired
	}
	owned, err := selectPFReference(*record, entries)
	if err != nil || owned == nil || owned.token != token {
		return ErrRecoveryRequired
	}
	policy, err := readPFPolicy(ctx, record.Anchor, true)
	if err != nil || !policy.matches(*record) || policy.rules != record.RulesSHA256 {
		return ErrRecoveryRequired
	}
	confirmed, err := readPFReferences(ctx, fd)
	if err != nil || !samePFReferences(entries, confirmed) {
		return ErrRecoveryRequired
	}
	next, err = record.Advance(PFReferenceAcquired, record.ReferenceAfter, record.ReferenceBefore, token)
	if err != nil || store.writePF(next) != nil {
		return ErrRecoveryRequired
	}
	record = &next
	store.mark("pf_reference_confirmation_committed")
	next, err = record.Advance(PFActive, record.ReferenceAfter, record.ReferenceBefore, record.Reference)
	if err != nil || store.writePF(next) != nil {
		return ErrRecoveryRequired
	}
	store.mark("pf_active_committed")
	return nil
}

func (store *Store) commitOwnedPF(record PFRecord) error {
	if !store.pfJournalOwner(record) {
		return ErrRecoveryRequired
	}
	return store.writePFForOwner(record, true)
}

// Explicit owned shutdown/dead-owner recovery, still private and not connected
// to client requests. Unknown/pending rule generations never authorize cleanup.
// On any ambiguous kernel or partial storage effect the record is retained.
func (store *Store) recoverPFLifecycle(ctx context.Context) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if store.closed || ctx.Err() != nil {
		return ErrRecoveryRequired
	}
	if pending, err := store.readPF(pfTemporaryFile); err != nil || pending != nil {
		return ErrRecoveryRequired
	}
	record, err := store.readPF(pfJournalFile)
	if err != nil || record == nil || !store.pfJournalOwner(*record) || record.RulesSHA256 != pfDigest(stagedPFRule) {
		return ErrRecoveryRequired
	}
	if store.preReferenceOwner(*record) {
		return store.finishPFAnchor(ctx, true)
	}
	if record.Phase == PFReferenceAbsent || record.Phase == PFReferenceReleased || record.Phase == PFAnchorRemovalIntent || record.Phase == PFAnchorRemoved {
		return store.finishPFAnchor(ctx, false)
	}
	if record.Phase != PFReferenceIntent && record.Phase != PFReferenceAcquired && record.Phase != PFActive && record.Phase != PFCleanupIntent {
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
	if err != nil {
		return ErrRecoveryRequired
	}
	policy, err := readPFPolicy(ctx, record.Anchor, len(entries) > 0)
	if err != nil || !policy.matches(*record) || policy.rules != record.RulesSHA256 {
		return ErrRecoveryRequired
	}
	check, err := readPFReferences(ctx, fd)
	if err != nil || !samePFReferences(entries, check) || !store.pfJournalOwner(*record) {
		return ErrRecoveryRequired
	}
	if record.Phase == PFReferenceIntent {
		phase, token := PFReferenceAbsent, uint64(0)
		if owned != nil {
			phase, token = PFReferenceAcquired, owned.token
		}
		next, err := record.Advance(phase, record.ReferenceAfter, record.ReferenceBefore, token)
		if err != nil || store.commitOwnedPF(next) != nil {
			return ErrRecoveryRequired
		}
		record = &next
		if owned == nil {
			return store.finishPFAnchor(ctx, false)
		}
	}
	if record.Phase != PFCleanupIntent {
		next, err := record.Advance(PFCleanupIntent, record.ReferenceAfter, record.ReferenceBefore, record.Reference)
		if err != nil || store.commitOwnedPF(next) != nil {
			return ErrRecoveryRequired
		}
		record = &next
	}
	store.mark("pf_reference_cleanup_intent_committed")
	// Confirm identity AND all other references immediately before scalar release.
	policyCheck, err := readPFPolicy(ctx, record.Anchor, len(entries) > 0)
	check, referenceErr := readPFReferences(ctx, fd)
	if err != nil || policyCheck != policy || referenceErr != nil || !samePFReferences(entries, check) || !store.pfJournalOwner(*record) {
		return ErrRecoveryRequired
	}
	remaining := make([]pfReference, 0, len(entries))
	for _, entry := range entries {
		if owned == nil || entry.token != owned.token {
			remaining = append(remaining, entry)
		}
	}
	if owned != nil {
		count, err := releasePFReference(ctx, fd, *owned)
		if err != nil || count != uint64(len(remaining)) {
			return ErrRecoveryRequired
		}
	}
	store.mark("pf_reference_released_kernel")
	observed, err := readPFReferences(ctx, fd)
	if err != nil || !samePFReferences(remaining, observed) {
		return ErrRecoveryRequired
	}
	post, err := readPFPolicy(ctx, record.Anchor, len(remaining) > 0)
	if err != nil || !post.matches(*record) || post.rules != record.RulesSHA256 {
		return ErrRecoveryRequired
	}
	next, err := record.Advance(PFReferenceReleased, record.ReferenceAfter, record.ReferenceBefore, record.Reference)
	if err != nil || store.commitOwnedPF(next) != nil {
		return ErrRecoveryRequired
	}
	store.mark("pf_reference_release_confirmation_committed")
	return store.finishPFAnchor(ctx, false)
}

func (store *Store) pfRemovalOwner(record PFRecord) bool {
	if !store.pfJournalOwner(record) {
		return false
	}
	return store.preReferenceOwner(record) || record.Phase == PFReferenceAbsent || record.Phase == PFReferenceReleased || record.Phase == PFAnchorRemovalIntent || record.Phase == PFAnchorRemoved
}

func (store *Store) readPFRemoval(ctx context.Context, record PFRecord, requireDisabled bool) (pfPolicySnapshot, []pfReference, error) {
	if !store.pfRemovalOwner(record) {
		return pfPolicySnapshot{}, nil, ErrRecoveryRequired
	}
	fd, err := openPFReferences(ctx)
	if err != nil {
		return pfPolicySnapshot{}, nil, ErrRecoveryRequired
	}
	defer unix.Close(fd)
	entries, err := readPFReferences(ctx, fd)
	if err != nil || ((requireDisabled || record.ReferenceAfter == 0) && len(entries) != 0) {
		return pfPolicySnapshot{}, nil, ErrRecoveryRequired
	}
	if record.ReferenceAfter > 0 {
		owned, err := selectPFReference(record, entries)
		if err != nil || owned != nil {
			return pfPolicySnapshot{}, nil, ErrRecoveryRequired
		}
	}
	policy, err := readPFPolicy(ctx, record.Anchor, len(entries) > 0)
	if err != nil {
		return pfPolicySnapshot{}, nil, ErrRecoveryRequired
	}
	check, err := readPFReferences(ctx, fd)
	if err != nil || !samePFReferences(entries, check) {
		return pfPolicySnapshot{}, nil, ErrRecoveryRequired
	}
	return policy, entries, nil
}
