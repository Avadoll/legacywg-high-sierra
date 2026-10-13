package recoverycore

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
)

type PFPhase string

const (
	PFInstallIntent       PFPhase = "install_intent"
	PFAnchorInstalled     PFPhase = "anchor_installed"
	PFReferenceIntent     PFPhase = "reference_intent"
	PFReferenceAcquired   PFPhase = "reference_acquired"
	PFActive              PFPhase = "active"
	PFRuleUpdateIntent    PFPhase = "rule_update_intent"
	PFReferenceAbsent     PFPhase = "reference_absent"
	PFCleanupIntent       PFPhase = "cleanup_intent"
	PFReferenceReleased   PFPhase = "reference_released"
	PFAnchorRemovalIntent PFPhase = "anchor_removal_intent"
	PFAnchorRemoved       PFPhase = "anchor_removed"
)

// A record can describe only our generated child of the existing wildcard.
// It contains no rule text, endpoint, key, command, arbitrary path or global
// PF operation. Metadata is necessary evidence, not deletion authorization.
// Kernel ownership/foreign policy/lifetime checks remain mandatory separately.
type PFRecord struct {
	Version         int     `json:"version"`
	ID              string  `json:"id"`
	Boot            string  `json:"boot"`
	PID             int     `json:"pid"`
	Phase           PFPhase `json:"phase"`
	Anchor          string  `json:"anchor"`
	RulesSHA256     string  `json:"rules_sha256"`
	Generation      uint64  `json:"generation"`
	NextRulesSHA256 string  `json:"next_rules_sha256"`
	RootSHA256      string  `json:"root_sha256"`
	RecursiveSHA256 string  `json:"recursive_sha256"`
	NATSHA256       string  `json:"nat_sha256"`
	ReferenceAfter  int64   `json:"reference_after"`
	ReferenceBefore int64   `json:"reference_before"`
	Reference       uint64  `json:"reference"`
}

func hashCanonical(value string) bool {
	if len(value) != 64 {
		return false
	}
	data, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(data) == value
}

func NewPFRecord(boot, rules, root, recursive, nat string) (PFRecord, error) {
	owner, err := NewRecord(boot)
	if err != nil {
		return PFRecord{}, ErrRecoveryRequired
	}
	record := PFRecord{Version: 2, ID: owner.ID, Boot: owner.Boot, PID: owner.PID, Phase: PFInstallIntent, Anchor: "com.apple/legacywg-" + owner.ID, RulesSHA256: rules, Generation: 1, RootSHA256: root, RecursiveSHA256: recursive, NATSHA256: nat}
	if record.Validate() != nil {
		return PFRecord{}, ErrRecoveryRequired
	}
	return record, nil
}

func (record PFRecord) Validate() error {
	if record.Version != 2 || record.Generation == 0 || !hexID.MatchString(record.ID) || !bootID.MatchString(record.Boot) || record.PID < 1 || record.PID > 2147483647 || record.Anchor != "com.apple/legacywg-"+record.ID {
		return ErrRecoveryRequired
	}
	for _, hash := range []string{record.RulesSHA256, record.RootSHA256, record.RecursiveSHA256, record.NATSHA256} {
		if !hashCanonical(hash) {
			return ErrRecoveryRequired
		}
	}
	window := record.ReferenceAfter > 0 && record.ReferenceBefore >= record.ReferenceAfter && record.ReferenceBefore-record.ReferenceAfter <= 5
	noReference := record.Reference == 0 && record.ReferenceAfter == 0 && record.ReferenceBefore == 0
	if record.Phase == PFRuleUpdateIntent {
		if !hashCanonical(record.NextRulesSHA256) || record.NextRulesSHA256 == record.RulesSHA256 || record.Generation == ^uint64(0) {
			return ErrRecoveryRequired
		}
	} else if record.NextRulesSHA256 != "" {
		return ErrRecoveryRequired
	}
	switch record.Phase {
	case PFInstallIntent, PFAnchorInstalled:
		if record.ReferenceAfter != 0 || record.ReferenceBefore != 0 || record.Reference != 0 {
			return ErrRecoveryRequired
		}
	case PFReferenceIntent, PFReferenceAbsent:
		if !window || record.Reference != 0 {
			return ErrRecoveryRequired
		}
	case PFReferenceAcquired, PFActive, PFRuleUpdateIntent, PFCleanupIntent, PFReferenceReleased:
		if !window || record.Reference == 0 {
			return ErrRecoveryRequired
		}
	case PFAnchorRemovalIntent, PFAnchorRemoved:
		if !noReference && !window {
			return ErrRecoveryRequired
		}
	default:
		return ErrRecoveryRequired
	}
	return nil
}

// Intent is written before an effect; confirmation follows its verification.
// Advance itself performs no kernel operation and never releases a token.
func (record PFRecord) Advance(phase PFPhase, after, before int64, reference uint64) (PFRecord, error) {
	if record.Validate() != nil {
		return PFRecord{}, ErrRecoveryRequired
	}
	next := record
	switch {
	case record.Phase == PFInstallIntent && phase == PFAnchorInstalled:
	case record.Phase == PFAnchorInstalled && phase == PFReferenceIntent:
		next.ReferenceAfter, next.ReferenceBefore = after, before
	case record.Phase == PFReferenceIntent && phase == PFReferenceAcquired:
		next.Reference = reference
	case record.Phase == PFReferenceIntent && phase == PFReferenceAbsent:
	case record.Phase == PFReferenceAcquired && phase == PFActive:
	case (record.Phase == PFReferenceAcquired || record.Phase == PFActive) && phase == PFCleanupIntent:
	case record.Phase == PFCleanupIntent && phase == PFReferenceReleased:
	case (record.Phase == PFInstallIntent || record.Phase == PFAnchorInstalled || record.Phase == PFReferenceAbsent || record.Phase == PFReferenceReleased) && phase == PFAnchorRemovalIntent:
	case record.Phase == PFAnchorRemovalIntent && phase == PFAnchorRemoved:
	default:
		return PFRecord{}, ErrRecoveryRequired
	}
	// Irrelevant supplied identity changes may not be silently ignored.
	if phase != PFReferenceIntent && (after != record.ReferenceAfter || before != record.ReferenceBefore) {
		return PFRecord{}, ErrRecoveryRequired
	}
	if phase != PFReferenceAcquired && reference != record.Reference {
		return PFRecord{}, ErrRecoveryRequired
	}
	next.Phase = phase
	if next.Validate() != nil {
		return PFRecord{}, ErrRecoveryRequired
	}
	return next, nil
}

// Pending rules preserve both exact candidates. They authorize no kernel
// write/removal. The coordinator must observe the actual owned anchor before
// choosing confirmation/rollback; an unrelated hash is always ambiguous.
func (record PFRecord) BeginRuleUpdate(desired string) (PFRecord, error) {
	if record.Validate() != nil || record.Phase != PFActive || !hashCanonical(desired) || desired == record.RulesSHA256 || record.Generation == ^uint64(0) {
		return PFRecord{}, ErrRecoveryRequired
	}
	next := record
	next.Phase = PFRuleUpdateIntent
	next.NextRulesSHA256 = desired
	if next.Validate() != nil {
		return PFRecord{}, ErrRecoveryRequired
	}
	return next, nil
}
func (record PFRecord) ResolveRuleUpdate(observed string) (PFRecord, error) {
	if record.Validate() != nil || record.Phase != PFRuleUpdateIntent || (observed != record.RulesSHA256 && observed != record.NextRulesSHA256) {
		return PFRecord{}, ErrRecoveryRequired
	}
	next := record
	if observed == record.NextRulesSHA256 {
		next.RulesSHA256 = observed
		next.Generation++
	}
	next.NextRulesSHA256 = ""
	next.Phase = PFActive
	if next.Validate() != nil {
		return PFRecord{}, ErrRecoveryRequired
	}
	return next, nil
}

func validatePFTransition(before, next PFRecord) error {
	if before.Validate() != nil || next.Validate() != nil {
		return ErrRecoveryRequired
	}
	var expected PFRecord
	var err error
	if before.Phase == PFActive && next.Phase == PFRuleUpdateIntent {
		expected, err = before.BeginRuleUpdate(next.NextRulesSHA256)
	} else if before.Phase == PFRuleUpdateIntent && next.Phase == PFActive {
		expected, err = before.ResolveRuleUpdate(next.RulesSHA256)
	} else {
		expected, err = before.Advance(next.Phase, next.ReferenceAfter, next.ReferenceBefore, next.Reference)
	}
	if err != nil || expected != next {
		return ErrRecoveryRequired
	}
	return nil
}

func EncodePF(record PFRecord) ([]byte, error) {
	if record.Validate() != nil {
		return nil, ErrRecoveryRequired
	}
	data, err := json.Marshal(record)
	if err != nil || len(data)+1 > MaxRecordBytes {
		return nil, ErrRecoveryRequired
	}
	return append(data, '\n'), nil
}
func DecodePF(data []byte) (PFRecord, error) {
	if len(data) < 1 || len(data) > MaxRecordBytes {
		return PFRecord{}, ErrRecoveryRequired
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record PFRecord
	if decoder.Decode(&record) != nil || record.Validate() != nil {
		return PFRecord{}, ErrRecoveryRequired
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return PFRecord{}, ErrRecoveryRequired
	}
	canonical, err := EncodePF(record)
	if err != nil || !bytes.Equal(bytes.TrimSuffix(data, []byte{'\n'}), bytes.TrimSuffix(canonical, []byte{'\n'})) {
		return PFRecord{}, ErrRecoveryRequired
	}
	return record, nil
}
