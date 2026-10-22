package recoverycore

import (
	"bytes"
	"encoding/binary"
)

// Intel LP64 projection of pinned Apple pfi_uif. The compiler comparison in
// native CI covers both legacy/modern headers independently of this decoder.
const pfInterfaceEntryBytes = 168
const maxPFInterfaces = 256

type pfInterfaceObservation struct {
	name                 string
	flags, states, rules uint32
}

func decodePFInterfaces(data []byte) ([]pfInterfaceObservation, error) {
	if len(data) == 0 || len(data)%pfInterfaceEntryBytes != 0 || len(data) > maxPFInterfaces*pfInterfaceEntryBytes {
		return nil, ErrRecoveryRequired
	}
	result := make([]pfInterfaceObservation, 0, len(data)/pfInterfaceEntryBytes)
	seen := make(map[string]bool)
	for offset := 0; offset < len(data); offset += pfInterfaceEntryBytes {
		entry := data[offset : offset+pfInterfaceEntryBytes]
		end := bytes.IndexByte(entry[:16], 0)
		if end < 1 {
			return nil, ErrRecoveryRequired
		}
		for _, value := range entry[:end] {
			if value < 33 || value > 126 {
				return nil, ErrRecoveryRequired
			}
		}
		for _, value := range entry[end:16] {
			if value != 0 {
				return nil, ErrRecoveryRequired
			}
		}
		name := string(entry[:end])
		states, rules := binary.LittleEndian.Uint32(entry[156:]), binary.LittleEndian.Uint32(entry[160:])
		if seen[name] || int32(states) < 0 || int32(rules) < 1 {
			return nil, ErrRecoveryRequired
		}
		seen[name] = true
		result = append(result, pfInterfaceObservation{name, binary.LittleEndian.Uint32(entry[152:]), states, rules})
	}
	return result, nil
}
