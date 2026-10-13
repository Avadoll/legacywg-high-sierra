package recoverycore

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func packedPFReference(token uint64, epoch uint64, pid uint32, name string) []byte {
	data := make([]byte, pfReferenceEntryBytes)
	binary.LittleEndian.PutUint64(data[:8], token)
	binary.LittleEndian.PutUint64(data[8:16], epoch)
	binary.LittleEndian.PutUint32(data[16:20], pid)
	copy(data[20:], name)
	return data
}

func TestPFReferencePackedABIRefusesMalformedAndDuplicateOwners(t *testing.T) {
	data := append(packedPFReference(456, 101, 222, "foreign worker"), packedPFReference(123, 100, 111, pfReferenceOwnerName)...)
	entries, err := decodePFReferences(data)
	if err != nil || len(entries) != 2 || entries[0].token != 123 || entries[0].pid != 111 || entries[0].name != pfReferenceOwnerName || entries[1].name != "foreign worker" {
		t.Fatal("packed scalar/name fields or stable sorting changed")
	}
	for _, bad := range [][]byte{
		data[:len(data)-1], make([]byte, 17*pfReferenceEntryBytes),
		packedPFReference(0, 100, 111, pfReferenceOwnerName), packedPFReference(123, 0, 111, pfReferenceOwnerName),
		packedPFReference(123, ^uint64(0), 111, pfReferenceOwnerName), packedPFReference(123, 100, 0, pfReferenceOwnerName),
		packedPFReference(123, 100, 0xffffffff, pfReferenceOwnerName), packedPFReference(123, 100, 111, ""),
		packedPFReference(123, 100, 111, string(bytes.Repeat([]byte{'x'}, 64))),
		append(packedPFReference(123, 100, 111, pfReferenceOwnerName), packedPFReference(123, 101, 222, "foreign")...),
	} {
		if _, err := decodePFReferences(bad); err == nil {
			t.Fatal("malformed, unbounded or repeated kernel metadata accepted")
		}
	}
}

func TestPFReferenceSelectionPreservesAmbiguity(t *testing.T) {
	record := activePFRecord(t)
	owner := pfReference{123, 101, record.PID, pfReferenceOwnerName}
	foreign := pfReference{456, 101, record.PID + 1, "foreign"}
	if selected, err := selectPFReference(record, []pfReference{owner, foreign}); err != nil || selected == nil || *selected != owner {
		t.Fatal("exact owner not distinguished from foreign reference")
	}
	if selected, err := selectPFReference(record, []pfReference{foreign}); err != nil || selected != nil {
		t.Fatal("absent recorded owner was invented")
	}
	for _, entries := range [][]pfReference{
		{{123, 101, record.PID + 1, pfReferenceOwnerName}},
		{{123, 101, record.PID, "other"}}, {{123, 99, record.PID, pfReferenceOwnerName}},
		{{123, 106, record.PID, pfReferenceOwnerName}}, {{456, 101, record.PID, pfReferenceOwnerName}},
		{owner, {789, 102, record.PID, pfReferenceOwnerName}},
	} {
		if _, err := selectPFReference(record, entries); err == nil {
			t.Fatal("changed token/PID/name/epoch or multiple candidates adopted")
		}
	}
	pending := record
	pending.Phase, pending.Reference = PFReferenceIntent, 0
	if selected, err := selectPFReference(pending, []pfReference{owner, foreign}); err != nil || selected == nil || *selected != owner {
		t.Fatal("unique lost-token intent candidate not selected")
	}
	if _, err := selectPFReference(pending, []pfReference{owner, {789, 101, record.PID, pfReferenceOwnerName}}); err == nil {
		t.Fatal("unconfirmed acquisition accepted multiple candidates")
	}
}
