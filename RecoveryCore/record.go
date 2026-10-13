// Package recoverycore records typed, owned changes. No recovery record can
// contain an executable command, profile, key, arbitrary path or preference.
package recoverycore

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
)

var ErrRecoveryRequired = errors.New("owned network recovery requires attention")

const MaxRecordBytes = 4096

type Phase string

const (
	Intent           Phase = "intent"
	InterfaceCreated Phase = "interface_created"
	Configured       Phase = "configured"
	RecoveryRequired Phase = "recovery_required"
)

// This version describes ephemeral utun and DNS only. It deliberately cannot
// authorize deletion of a physical route, a PF anchor or a PF enable reference.
type Record struct {
	Version        int    `json:"version"`
	ID             string `json:"id"`
	Boot           string `json:"boot"`
	PID            int    `json:"pid"`
	Phase          Phase  `json:"phase"`
	Interface      string `json:"interface"`
	InterfaceIndex int    `json:"interface_index"`
	DNSRequested   bool   `json:"dns_requested"`
}

var hexID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var bootID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var utunName = regexp.MustCompile(`^utun[0-9]{1,10}$`)

func NewRecord(boot string) (Record, error) {
	var nonce [16]byte
	if !bootID.MatchString(boot) {
		return Record{}, ErrRecoveryRequired
	}
	if _, err := rand.Read(nonce[:]); err != nil {
		return Record{}, ErrRecoveryRequired
	}
	return Record{Version: 1, ID: hex.EncodeToString(nonce[:]), Boot: boot, PID: os.Getpid(), Phase: Intent}, nil
}

func (record Record) Validate() error {
	if record.Version != 1 || !hexID.MatchString(record.ID) || !bootID.MatchString(record.Boot) || record.PID <= 0 || record.PID > 2147483647 {
		return ErrRecoveryRequired
	}
	switch record.Phase {
	case Intent:
		if record.Interface != "" || record.InterfaceIndex != 0 || record.DNSRequested {
			return ErrRecoveryRequired
		}
	case InterfaceCreated, Configured, RecoveryRequired:
		if !utunName.MatchString(record.Interface) || record.InterfaceIndex <= 0 || record.InterfaceIndex > 65535 {
			return ErrRecoveryRequired
		}
		if record.Phase == InterfaceCreated && record.DNSRequested {
			return ErrRecoveryRequired
		}
	default:
		return ErrRecoveryRequired
	}
	return nil
}

func (record Record) Advance(phase Phase, name string, index int, dns bool) (Record, error) {
	if record.Validate() != nil {
		return Record{}, ErrRecoveryRequired
	}
	next := record
	switch {
	case record.Phase == Intent && phase == InterfaceCreated:
		next.Interface, next.InterfaceIndex = name, index
	case record.Phase == InterfaceCreated && phase == Configured:
		if name != record.Interface || index != record.InterfaceIndex {
			return Record{}, ErrRecoveryRequired
		}
	case (record.Phase == InterfaceCreated || record.Phase == Configured || record.Phase == RecoveryRequired) && phase == RecoveryRequired:
		if name != record.Interface || index != record.InterfaceIndex || dns != record.DNSRequested {
			return Record{}, ErrRecoveryRequired
		}
	default:
		return Record{}, ErrRecoveryRequired
	}
	next.Phase, next.DNSRequested = phase, dns
	if next.Validate() != nil {
		return Record{}, ErrRecoveryRequired
	}
	return next, nil
}

func Encode(record Record) ([]byte, error) {
	if record.Validate() != nil {
		return nil, ErrRecoveryRequired
	}
	data, err := json.Marshal(record)
	if err != nil || len(data) > MaxRecordBytes {
		return nil, ErrRecoveryRequired
	}
	return append(data, '\n'), nil
}

func Decode(data []byte) (Record, error) {
	if len(data) == 0 || len(data) > MaxRecordBytes {
		return Record{}, ErrRecoveryRequired
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record Record
	if decoder.Decode(&record) != nil || record.Validate() != nil {
		return Record{}, ErrRecoveryRequired
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return Record{}, ErrRecoveryRequired
	}
	// Canonical encoding also rejects duplicate JSON fields and alternate
	// spellings. Unknown/corrupt/future records are preserved for attention.
	canonical, err := Encode(record)
	if err != nil || !bytes.Equal(bytes.TrimSuffix(canonical, []byte{'\n'}), bytes.TrimSuffix(data, []byte{'\n'})) {
		return Record{}, ErrRecoveryRequired
	}
	return record, nil
}
