package recoverycore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type pfBoundedOutput struct{ bytes.Buffer }

func (output *pfBoundedOutput) Write(data []byte) (int, error) {
	if output.Len()+len(data) > 65536 {
		return 0, ErrRecoveryRequired
	}
	return output.Buffer.Write(data)
}

// No shell, configuration path, environment override or runtime command API.
// Every caller below supplies fixed read-only arguments or this exact owned
// child load; no global load/flush/enable/disable/reference/state operation.
func runOwnedPF(ctx context.Context, input string, args ...string) (string, error) {
	if ctx.Err() != nil || os.Geteuid() != 0 {
		return "", ErrRecoveryRequired
	}
	var status unix.Stat_t
	if unix.Lstat("/sbin/pfctl", &status) != nil || status.Uid != 0 || status.Mode&unix.S_IFMT != unix.S_IFREG || status.Mode&0022 != 0 {
		return "", ErrRecoveryRequired
	}
	bounded, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, "/sbin/pfctl", args...)
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
	command.Stdin = strings.NewReader(input)
	var output, diagnostic pfBoundedOutput
	command.Stdout, command.Stderr = &output, &diagnostic
	if command.Run() != nil || bounded.Err() != nil {
		return "", ErrRecoveryRequired
	}
	// Native diagnostics and foreign policy never enter application status.
	return output.String(), nil
}

type pfDisabledSnapshot struct {
	root, recursive, nat, rules string
}

var pfStatusLine = regexp.MustCompile(`(?m)^Status:\s+(Enabled|Disabled)\b`)
var pfStateLine = regexp.MustCompile(`(?m)^\s*current entries\s+([0-9]+)\b`)

func readDisabledPF(ctx context.Context, owned string) (pfDisabledSnapshot, error) {
	if !strings.HasPrefix(owned, "com.apple/legacywg-") || !hexID.MatchString(strings.TrimPrefix(owned, "com.apple/legacywg-")) {
		return pfDisabledSnapshot{}, ErrRecoveryRequired
	}
	info, err := runOwnedPF(ctx, "", "-s", "info")
	status, count := pfStatusLine.FindAllStringSubmatch(info, -1), pfStateLine.FindAllStringSubmatch(info, -1)
	if err != nil || len(status) != 1 || len(count) != 1 || status[0][1] != "Disabled" || count[0][1] != "0" {
		return pfDisabledSnapshot{}, ErrRecoveryRequired
	}
	root, err := runOwnedPF(ctx, "", "-s", "rules")
	if err != nil || !strings.Contains(root, "anchor \"com.apple/*\" all\n") {
		return pfDisabledSnapshot{}, ErrRecoveryRequired
	}
	if _, seen, err := pfForeignView(root, owned); err != nil || seen {
		return pfDisabledSnapshot{}, ErrRecoveryRequired
	}
	recursive, err := runOwnedPF(ctx, "", "-a", "*", "-s", "rules")
	if err != nil {
		return pfDisabledSnapshot{}, ErrRecoveryRequired
	}
	foreign, _, err := pfForeignView(recursive, owned)
	if err != nil {
		return pfDisabledSnapshot{}, ErrRecoveryRequired
	}
	nat, err := runOwnedPF(ctx, "", "-s", "nat")
	if err != nil {
		return pfDisabledSnapshot{}, ErrRecoveryRequired
	}
	if _, seen, err := pfForeignView(nat, owned); err != nil || seen {
		return pfDisabledSnapshot{}, ErrRecoveryRequired
	}
	natRecursive, err := runOwnedPF(ctx, "", "-a", "*", "-s", "nat")
	if err != nil {
		return pfDisabledSnapshot{}, ErrRecoveryRequired
	}
	natForeign, _, err := pfForeignView(natRecursive, owned)
	if err != nil {
		return pfDisabledSnapshot{}, ErrRecoveryRequired
	}
	rules, err := runOwnedPF(ctx, "", "-a", owned, "-s", "rules")
	if err != nil || (rules != "" && rules != stagedPFRule) {
		return pfDisabledSnapshot{}, ErrRecoveryRequired
	}
	for _, kind := range []string{"nat", "Anchors", "Tables"} {
		text, err := runOwnedPF(ctx, "", "-a", owned, "-s", kind)
		if err != nil || strings.TrimSpace(text) != "" {
			return pfDisabledSnapshot{}, ErrRecoveryRequired
		}
	}
	info, err = runOwnedPF(ctx, "", "-s", "info")
	status, count = pfStatusLine.FindAllStringSubmatch(info, -1), pfStateLine.FindAllStringSubmatch(info, -1)
	if err != nil || len(status) != 1 || len(count) != 1 || status[0][1] != "Disabled" || count[0][1] != "0" {
		return pfDisabledSnapshot{}, ErrRecoveryRequired
	}
	return pfDisabledSnapshot{pfDigest(root), pfDigest(foreign), pfDigest(nat + "\x00" + natForeign), pfDigest(rules)}, nil
}

func (snapshot pfDisabledSnapshot) matches(record PFRecord) bool {
	return snapshot.root == record.RootSHA256 && snapshot.recursive == record.RecursiveSHA256 && snapshot.nat == record.NATSHA256
}

// Private coordinator awaiting the remaining guard/reference/path gates.
// It is compiled product source but is not called by a client request yet.
// Two observations detect ordinary changes; no userspace check/load sequence
// can claim an atomic transaction against competing privileged PF writers.
func (store *Store) stageDisabledPFAnchor(ctx context.Context) error {
	if store.closed || store.pfResidue() || ctx.Err() != nil {
		return ErrRecoveryRequired
	}
	placeholder := pfDigest("")
	record, err := NewPFRecord(store.boot, pfDigest(stagedPFRule), placeholder, placeholder, placeholder)
	if err != nil {
		return ErrRecoveryRequired
	}
	before, err := readDisabledPF(ctx, record.Anchor)
	if err != nil || before.rules != placeholder {
		return ErrRecoveryRequired
	}
	record.RootSHA256, record.RecursiveSHA256, record.NATSHA256 = before.root, before.recursive, before.nat
	if _, err = runOwnedPF(ctx, stagedPFRule, "-n", "-a", record.Anchor, "-f", "-"); err != nil || store.writePF(record) != nil {
		return ErrRecoveryRequired
	}
	store.mark("pf_install_intent_committed")
	check, err := readDisabledPF(ctx, record.Anchor)
	if err != nil || check != before {
		return ErrRecoveryRequired
	}
	if _, err = runOwnedPF(ctx, stagedPFRule, "-a", record.Anchor, "-f", "-"); err != nil {
		return ErrRecoveryRequired
	}
	store.mark("pf_anchor_loaded")
	after, err := readDisabledPF(ctx, record.Anchor)
	if err != nil || !after.matches(record) || after.rules != record.RulesSHA256 {
		return ErrRecoveryRequired
	}
	next, err := record.Advance(PFAnchorInstalled, 0, 0, 0)
	if err != nil || store.writePF(next) != nil {
		return ErrRecoveryRequired
	}
	store.mark("pf_anchor_confirmation_committed")
	return nil
}

func (store *Store) preReferenceOwner(record PFRecord) bool {
	if store.closed || record.Validate() != nil || record.Boot != store.boot || record.Reference != 0 || record.ReferenceAfter != 0 || record.ReferenceBefore != 0 {
		return false
	}
	if record.PID != os.Getpid() && !errors.Is(unix.Kill(record.PID, 0), unix.ESRCH) {
		return false
	}
	return record.Phase == PFInstallIntent || record.Phase == PFAnchorInstalled || record.Phase == PFAnchorRemovalIntent || record.Phase == PFAnchorRemoved
}

// Only this narrowly verified pre-reference cancellation may persist a dead
// owner's next phase. Existing public recovery still preserves all PF residue.
func (store *Store) commitPreReferencePF(record PFRecord) error {
	if !store.preReferenceOwner(record) {
		return ErrRecoveryRequired
	}
	return store.writePFForOwner(record, true)
}

func (store *Store) cancelDisabledPFAnchor(ctx context.Context) error {
	if store.closed || ctx.Err() != nil {
		return ErrRecoveryRequired
	}
	if pending, err := store.readPF(pfTemporaryFile); err != nil || pending != nil {
		return ErrRecoveryRequired
	}
	record, err := store.readPF(pfJournalFile)
	if err != nil || record == nil || !store.preReferenceOwner(*record) || record.RulesSHA256 != pfDigest(stagedPFRule) {
		return ErrRecoveryRequired
	}
	before, err := readDisabledPF(ctx, record.Anchor)
	if err != nil || !before.matches(*record) || (before.rules != record.RulesSHA256 && before.rules != pfDigest("")) {
		return ErrRecoveryRequired
	}
	if record.Phase != PFAnchorRemovalIntent && record.Phase != PFAnchorRemoved {
		next, err := record.Advance(PFAnchorRemovalIntent, 0, 0, 0)
		if err != nil || store.commitPreReferencePF(next) != nil {
			return ErrRecoveryRequired
		}
		record = &next
	}
	store.mark("pf_removal_intent_committed")
	check, err := readDisabledPF(ctx, record.Anchor)
	if err != nil || check != before || !store.preReferenceOwner(*record) {
		return ErrRecoveryRequired
	}
	if record.Phase == PFAnchorRemoved && check.rules != pfDigest("") {
		return ErrRecoveryRequired
	}
	if check.rules != pfDigest("") {
		if _, err = runOwnedPF(ctx, "", "-a", record.Anchor, "-f", "-"); err != nil {
			return ErrRecoveryRequired
		}
	}
	store.mark("pf_anchor_emptied")
	after, err := readDisabledPF(ctx, record.Anchor)
	if err != nil || !after.matches(*record) || after.rules != pfDigest("") || !store.preReferenceOwner(*record) {
		return ErrRecoveryRequired
	}
	if record.Phase != PFAnchorRemoved {
		next, err := record.Advance(PFAnchorRemoved, 0, 0, 0)
		if err != nil || store.commitPreReferencePF(next) != nil {
			return ErrRecoveryRequired
		}
		record = &next
	}
	// Retire only the exact confirmed document, under the same exclusive lock.
	actual, err := store.readPF(pfJournalFile)
	if err != nil || actual == nil || *actual != *record || !store.preReferenceOwner(*record) {
		return ErrRecoveryRequired
	}
	if unix.Unlinkat(store.directory, pfJournalFile, 0) != nil || unix.Fsync(store.directory) != nil || fullSync(store.lock) != nil {
		return ErrRecoveryRequired
	}
	store.mark("pf_journal_retired")
	return nil
}
