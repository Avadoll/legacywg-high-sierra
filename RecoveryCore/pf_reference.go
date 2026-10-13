package recoverycore

import (
	"bytes"
	"encoding/binary"
	"math"
	"sort"
)

const pfReferenceOwnerName = "legacywg-worker"
const maxPFReferences = 16
const pfReferenceEntryBytes = 84

// Private kernel observations, never application status or command input.
type pfReference struct {
	token uint64
	epoch int64
	pid   int
	name  string
}

// Original projection of the packed Intel LP64 ABI from Apple XNU
// xnu-4570.71.2 bsd/net/pfvar.h. Unknown layouts or fields are refused.
func decodePFReferences(data []byte) ([]pfReference, error) {
	if len(data)%pfReferenceEntryBytes != 0 || len(data) > maxPFReferences*pfReferenceEntryBytes {
		return nil, ErrRecoveryRequired
	}
	entries := make([]pfReference, 0, len(data)/pfReferenceEntryBytes)
	for offset := 0; offset < len(data); offset += pfReferenceEntryBytes {
		row := data[offset : offset+pfReferenceEntryBytes]
		token := binary.LittleEndian.Uint64(row[:8])
		epoch := binary.LittleEndian.Uint64(row[8:16])
		pid := int32(binary.LittleEndian.Uint32(row[16:20]))
		end := bytes.IndexByte(row[20:], 0)
		if token == 0 || epoch == 0 || epoch > math.MaxInt64 || pid <= 0 || end <= 0 {
			return nil, ErrRecoveryRequired
		}
		entries = append(entries, pfReference{token, int64(epoch), int(pid), string(row[20 : 20+end])})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].token < entries[j].token })
	for i := 1; i < len(entries); i++ {
		if entries[i].token == entries[i-1].token {
			return nil, ErrRecoveryRequired
		}
	}
	return entries, nil
}

// The expected name is compiled, not taken from a path or journal. There
// must be at most one acquisition in this PID/name/bounded time window.
// A saved token with different metadata, or a second candidate, is ambiguous.
func selectPFReference(record PFRecord, entries []pfReference) (*pfReference, error) {
	if record.Validate() != nil || record.ReferenceAfter <= 0 || record.ReferenceBefore < record.ReferenceAfter {
		return nil, ErrRecoveryRequired
	}
	var candidate *pfReference
	for i := range entries {
		entry := &entries[i]
		matches := entry.pid == record.PID && entry.name == pfReferenceOwnerName && entry.epoch >= record.ReferenceAfter && entry.epoch <= record.ReferenceBefore
		if entry.pid == record.PID && !matches {
			return nil, ErrRecoveryRequired
		}
		if record.Reference != 0 && entry.token == record.Reference && !matches {
			return nil, ErrRecoveryRequired
		}
		if matches {
			if candidate != nil || (record.Reference != 0 && entry.token != record.Reference) {
				return nil, ErrRecoveryRequired
			}
			candidate = entry
		}
	}
	return candidate, nil
}

func samePFReferences(a, b []pfReference) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
