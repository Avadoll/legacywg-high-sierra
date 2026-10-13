package recoverycore

import (
	"strings"
	"testing"
)

func testPFRecord(t *testing.T) PFRecord {
	t.Helper()
	hash := strings.Repeat("a", 64)
	record, err := NewPFRecord(testBoot, hash, hash, hash, hash)
	if err != nil {
		t.Fatal("typed PF record creation failed")
	}
	return record
}
func TestPFRecordStrictIdentityTransitions(t *testing.T) {
	record := testPFRecord(t)
	for _, phase := range []PFPhase{PFAnchorInstalled, PFReferenceIntent, PFReferenceAcquired, PFActive, PFCleanupIntent, PFReferenceReleased, PFAnchorRemoved} {
		after, before, reference := record.ReferenceAfter, record.ReferenceBefore, record.Reference
		if phase == PFReferenceIntent {
			after, before = 100, 105
		}
		if phase == PFReferenceAcquired {
			reference = 123
		}
		var err error
		record, err = record.Advance(phase, after, before, reference)
		if err != nil {
			t.Fatal("required PF transition refused")
		}
		data, err := EncodePF(record)
		if err != nil {
			t.Fatal("PF encoding failed")
		}
		decoded, err := DecodePF(data)
		if err != nil || decoded != record {
			t.Fatal("canonical PF record lost identity")
		}
	}
	first := testPFRecord(t)
	if _, err := first.Advance(PFActive, 100, 105, 123); err == nil {
		t.Fatal("effect phases skipped")
	}
	if _, err := first.Advance(PFAnchorInstalled, 1, 1, 0); err == nil {
		t.Fatal("unexpected owner window accepted")
	}
}
func TestPFRecordRefusesCommandsForeignNamespacesAndCorruption(t *testing.T) {
	valid := testPFRecord(t)
	for _, change := range []func(*PFRecord){
		func(r *PFRecord) { r.Anchor = "com.apple/foreign" }, func(r *PFRecord) { r.Anchor += "/child" },
		func(r *PFRecord) { r.Version = 2 }, func(r *PFRecord) { r.PID = 0 }, func(r *PFRecord) { r.Boot = "foreign-boot" },
		func(r *PFRecord) { r.RulesSHA256 = strings.Repeat("A", 64) }, func(r *PFRecord) { r.Phase = PFActive },
		func(r *PFRecord) { r.Reference = 123 }, func(r *PFRecord) { r.ReferenceBefore = 100 },
	} {
		record := valid
		change(&record)
		if record.Validate() == nil {
			t.Fatal("unsafe PF identity accepted")
		}
	}
	data, _ := EncodePF(valid)
	for _, bad := range [][]byte{
		[]byte(strings.Replace(string(data), "{", "{\"command\":\"pfctl -d\",", 1)),
		[]byte(strings.Replace(string(data), "{", "{\"version\":1,", 1)), append(append([]byte(nil), data...), []byte("{}")...),
		[]byte(strings.Repeat("x", MaxRecordBytes+1)),
	} {
		if _, err := DecodePF(bad); err == nil {
			t.Fatal("untrusted PF recovery document accepted")
		}
	}
	old, _ := NewRecord(testBoot)
	oldData, _ := Encode(old)
	if _, err := DecodePF(oldData); err == nil {
		t.Fatal("utun record interpreted as PF deletion authority")
	}
	if _, err := Decode(data); err == nil {
		t.Fatal("PF record interpreted as ephemeral utun record")
	}
}
