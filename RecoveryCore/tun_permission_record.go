package recoverycore

import (
	"bytes"
	"encoding/json"
	"io"
)

// This metadata describes intent only. It cannot authorize a kernel operation,
// identify a reincarnated interface, adopt a PID or substitute for an owned FD.
// Storage/capability effects are implemented separately before this is usable.
type tunPermissionPhase string

const (
	tunPermissionArmed        tunPermissionPhase = "armed"
	tunPermissionEnableIntent tunPermissionPhase = "enable_intent"
	tunPermissionEnabled      tunPermissionPhase = "enabled"
	tunPermissionClearIntent  tunPermissionPhase = "clear_intent"
	tunPermissionCleared      tunPermissionPhase = "cleared"
	tunPermissionReleased     tunPermissionPhase = "released"
)

type tunPermissionRecord struct {
	Version        int                `json:"version"`
	ID             string             `json:"id"`
	SessionID      string             `json:"session_id"`
	PFID           string             `json:"pf_id"`
	Boot           string             `json:"boot"`
	PID            int                `json:"pid"`
	Interface      string             `json:"interface"`
	InterfaceIndex int                `json:"interface_index"`
	Phase          tunPermissionPhase `json:"phase"`
	Cycle          uint64             `json:"cycle"`
	PFGeneration   uint64             `json:"pf_generation"`
	RulesSHA256    string             `json:"rules_sha256"`
}

func newTUNPermissionRecord(session Record, pf PFRecord) (tunPermissionRecord, error) {
	if session.Validate() != nil || session.Phase != InterfaceCreated || pf.Validate() != nil || pf.Phase != PFActive ||
		pf.Boot != session.Boot || pf.PID != session.PID || pf.RulesSHA256 != pfDigest(stagedPFRule) {
		return tunPermissionRecord{}, ErrRecoveryRequired
	}
	nonce, err := NewRecord(session.Boot)
	if err != nil || nonce.PID != session.PID {
		return tunPermissionRecord{}, ErrRecoveryRequired
	}
	record := tunPermissionRecord{Version: 1, ID: nonce.ID, SessionID: session.ID, PFID: pf.ID,
		Boot: session.Boot, PID: session.PID, Interface: session.Interface, InterfaceIndex: session.InterfaceIndex, Phase: tunPermissionArmed}
	if record.valid() != nil {
		return tunPermissionRecord{}, ErrRecoveryRequired
	}
	return record, nil
}

func (record tunPermissionRecord) valid() error {
	if record.Version != 1 || !hexID.MatchString(record.ID) || !hexID.MatchString(record.SessionID) || !hexID.MatchString(record.PFID) ||
		!bootID.MatchString(record.Boot) || record.PID < 1 || record.PID > 2147483647 || !utunName.MatchString(record.Interface) || record.InterfaceIndex < 1 || record.InterfaceIndex > 65535 {
		return ErrRecoveryRequired
	}
	if record.Cycle == 0 {
		if (record.Phase != tunPermissionArmed && record.Phase != tunPermissionReleased) || record.PFGeneration != 0 || record.RulesSHA256 != "" {
			return ErrRecoveryRequired
		}
	} else if record.PFGeneration == 0 || record.PFGeneration == ^uint64(0) || !hashCanonical(record.RulesSHA256) || record.RulesSHA256 == pfDigest(stagedPFRule) {
		return ErrRecoveryRequired
	}
	switch record.Phase {
	case tunPermissionArmed:
		if record.Cycle != 0 {
			return ErrRecoveryRequired
		}
	case tunPermissionEnableIntent, tunPermissionEnabled, tunPermissionClearIntent, tunPermissionCleared:
		if record.Cycle == 0 {
			return ErrRecoveryRequired
		}
	case tunPermissionReleased:
	default:
		return ErrRecoveryRequired
	}
	return nil
}

func (record tunPermissionRecord) beginEnable(pf PFRecord) (tunPermissionRecord, error) {
	if record.valid() != nil || (record.Phase != tunPermissionArmed && record.Phase != tunPermissionCleared) || record.Cycle == ^uint64(0) ||
		pf.Validate() != nil || pf.Phase != PFActive || pf.ID != record.PFID || pf.Boot != record.Boot || pf.PID != record.PID ||
		pf.Generation <= record.PFGeneration || pf.Generation == ^uint64(0) || pf.RulesSHA256 == pfDigest(stagedPFRule) {
		return tunPermissionRecord{}, ErrRecoveryRequired
	}
	next := record
	next.Phase, next.Cycle = tunPermissionEnableIntent, record.Cycle+1
	next.PFGeneration, next.RulesSHA256 = pf.Generation, pf.RulesSHA256
	if next.valid() != nil {
		return tunPermissionRecord{}, ErrRecoveryRequired
	}
	return next, nil
}

func (record tunPermissionRecord) advance(phase tunPermissionPhase) (tunPermissionRecord, error) {
	if record.valid() != nil || !((record.Phase == tunPermissionEnableIntent && phase == tunPermissionEnabled) ||
		((record.Phase == tunPermissionEnableIntent || record.Phase == tunPermissionEnabled) && phase == tunPermissionClearIntent) ||
		(record.Phase == tunPermissionClearIntent && phase == tunPermissionCleared) ||
		((record.Phase == tunPermissionArmed || record.Phase == tunPermissionCleared) && phase == tunPermissionReleased)) {
		return tunPermissionRecord{}, ErrRecoveryRequired
	}
	next := record
	next.Phase = phase
	return next, next.valid()
}

func tunPermissionTransition(before, next tunPermissionRecord) bool {
	if before.valid() != nil || next.valid() != nil || before.Version != next.Version || before.ID != next.ID || before.SessionID != next.SessionID ||
		before.PFID != next.PFID || before.Boot != next.Boot || before.PID != next.PID || before.Interface != next.Interface || before.InterfaceIndex != next.InterfaceIndex {
		return false
	}
	if next.Phase == tunPermissionEnableIntent {
		return (before.Phase == tunPermissionArmed || before.Phase == tunPermissionCleared) && before.Cycle != ^uint64(0) &&
			next.Cycle == before.Cycle+1 && next.PFGeneration > before.PFGeneration
	}
	expected, err := before.advance(next.Phase)
	return err == nil && expected == next
}

func encodeTUNPermission(record tunPermissionRecord) ([]byte, error) {
	if record.valid() != nil {
		return nil, ErrRecoveryRequired
	}
	data, err := json.Marshal(record)
	if err != nil || len(data)+1 > MaxRecordBytes {
		return nil, ErrRecoveryRequired
	}
	return append(data, '\n'), nil
}

func decodeTUNPermission(data []byte) (tunPermissionRecord, error) {
	if len(data) == 0 || len(data) > MaxRecordBytes {
		return tunPermissionRecord{}, ErrRecoveryRequired
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record tunPermissionRecord
	if decoder.Decode(&record) != nil || record.valid() != nil {
		return tunPermissionRecord{}, ErrRecoveryRequired
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return tunPermissionRecord{}, ErrRecoveryRequired
	}
	canonical, err := encodeTUNPermission(record)
	if err != nil || !bytes.Equal(bytes.TrimSuffix(data, []byte{'\n'}), bytes.TrimSuffix(canonical, []byte{'\n'})) {
		return tunPermissionRecord{}, ErrRecoveryRequired
	}
	return record, nil
}
