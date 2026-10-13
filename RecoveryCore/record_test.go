package recoverycore

import (
	"bytes"
	"strings"
	"testing"
)

const testBoot = "01234567-89ab-cdef-0123-456789abcdef"

func TestTypedJournalTransitions(t *testing.T) {
	record, err := NewRecord(testBoot)
	if err != nil {
		t.Fatal("new intent failed")
	}
	if _, err = record.Advance(Configured, "utun1", 1, true); err == nil {
		t.Fatal("configuration without interface intent accepted")
	}
	record, err = record.Advance(InterfaceCreated, "utun1", 1, false)
	if err != nil {
		t.Fatal("interface checkpoint failed")
	}
	if _, err = record.Advance(Configured, "utun2", 1, false); err == nil {
		t.Fatal("foreign identity mutation accepted")
	}
	record, err = record.Advance(Configured, "utun1", 1, true)
	if err != nil {
		t.Fatal("configured checkpoint failed")
	}
	record, err = record.Advance(RecoveryRequired, "utun1", 1, true)
	if err != nil {
		t.Fatal("recovery checkpoint failed")
	}
	if _, err = record.Advance(InterfaceCreated, "utun1", 1, false); err == nil {
		t.Fatal("backwards checkpoint accepted")
	}
	data, err := Encode(record)
	if err != nil {
		t.Fatal("encode failed")
	}
	if decoded, err := Decode(data); err != nil || decoded != record {
		t.Fatal("canonical roundtrip failed")
	}
}

func TestJournalRejectsCommandsSecretsAmbiguityAndBounds(t *testing.T) {
	record, _ := NewRecord(testBoot)
	data, _ := Encode(record)
	bad := [][]byte{
		append(bytes.TrimSuffix(data, []byte{'\n'}), []byte("{}")...),
		[]byte(strings.Replace(string(data), `"version":1`, `"version":1,"version":1`, 1)),
		[]byte(strings.Replace(string(data), `"version":1`, `"version":1,"command":"private-marker"`, 1)),
		[]byte(strings.Replace(string(data), `"version":1`, `"version":1,"private_key":"private-marker"`, 1)),
		bytes.Repeat([]byte{'x'}, MaxRecordBytes+1), data[:len(data)/2],
		[]byte(strings.Replace(string(data), `"version":1`, `"version":2`, 1)),
		[]byte(strings.Replace(string(data), `"phase":"intent"`, `"phase":"delete_foreign_routes"`, 1)),
	}
	for _, value := range bad {
		if _, err := Decode(value); err == nil || strings.Contains(err.Error(), "marker") {
			t.Fatal("unsafe record accepted or input leaked")
		}
	}
	record.Interface = "en0"
	record.InterfaceIndex = 1
	record.Phase = InterfaceCreated
	if record.Validate() == nil {
		t.Fatal("physical interface operation allowed by utun schema")
	}
}
