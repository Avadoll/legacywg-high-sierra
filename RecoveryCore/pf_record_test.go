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
	for _, phase := range []PFPhase{PFAnchorInstalled, PFReferenceIntent, PFReferenceAcquired, PFActive, PFCleanupIntent, PFReferenceReleased, PFAnchorRemovalIntent, PFAnchorRemoved} {
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
		func(r *PFRecord) { r.Version = 1 }, func(r *PFRecord) { r.PID = 0 }, func(r *PFRecord) { r.Boot = "foreign-boot" },
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

func activePFRecord(t *testing.T) PFRecord {
	t.Helper()
	record := testPFRecord(t)
	for _, phase := range []PFPhase{PFAnchorInstalled, PFReferenceIntent, PFReferenceAcquired, PFActive} {
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
			t.Fatal("active PF metadata fixture failed")
		}
	}
	return record
}

func TestPFPreReferenceCancellationDoesNotInventEnableOwnership(t *testing.T) {
	for _, start := range []PFPhase{PFInstallIntent, PFAnchorInstalled} {
		record := testPFRecord(t)
		if start == PFAnchorInstalled {
			record, _ = record.Advance(PFAnchorInstalled, 0, 0, 0)
		}
		next, err := record.Advance(PFAnchorRemovalIntent, 0, 0, 0)
		if err != nil || next.Reference != 0 {
			t.Fatal("pre-reference cancellation invented a token")
		}
		if validatePFTransition(record, next) != nil {
			t.Fatal("typed cancellation refused")
		}
		removed, err := next.Advance(PFAnchorRemoved, 0, 0, 0)
		if err != nil || removed.Reference != 0 {
			t.Fatal("pre-reference cleanup metadata failed")
		}
	}
	record := testPFRecord(t)
	record, _ = record.Advance(PFAnchorInstalled, 0, 0, 0)
	record, _ = record.Advance(PFReferenceIntent, 100, 105, 0)
	if _, err := record.Advance(PFAnchorRemovalIntent, 100, 105, 0); err == nil {
		t.Fatal("unknown acquire effect authorized anchor cleanup")
	}
	absent, err := record.Advance(PFReferenceAbsent, 100, 105, 0)
	if err != nil {
		t.Fatal("externally confirmed absence could not be recorded")
	}
	if _, err = absent.Advance(PFAnchorRemovalIntent, 100, 105, 0); err != nil {
		t.Fatal("confirmed absent reference metadata cleanup failed")
	}
}

func TestPFRuleGenerationConfirmsOnlyKnownCandidates(t *testing.T) {
	active := activePFRecord(t)
	desired := strings.Repeat("b", 64)
	pending, err := active.BeginRuleUpdate(desired)
	if err != nil || pending.Generation != active.Generation || pending.RulesSHA256 != active.RulesSHA256 {
		t.Fatal("intent overwrote active rule identity")
	}
	if validatePFTransition(active, pending) != nil {
		t.Fatal("pending update transition failed")
	}
	for _, observed := range []string{active.RulesSHA256, desired} {
		confirmed, err := pending.ResolveRuleUpdate(observed)
		if err != nil || confirmed.Phase != PFActive || confirmed.NextRulesSHA256 != "" {
			t.Fatal("known observed rules could not be resolved")
		}
		want := active.Generation
		if observed == desired {
			want++
		}
		if confirmed.Generation != want || confirmed.RulesSHA256 != observed {
			t.Fatal("confirmed rules/generation mismatch")
		}
		if validatePFTransition(pending, confirmed) != nil {
			t.Fatal("store rejected known rule generation")
		}
	}
	if _, err = pending.ResolveRuleUpdate(strings.Repeat("c", 64)); err == nil {
		t.Fatal("foreign rule hash silently adopted")
	}
	if _, err = pending.BeginRuleUpdate(strings.Repeat("c", 64)); err == nil {
		t.Fatal("pending update overwritten")
	}
	if _, err = pending.Advance(PFCleanupIntent, 100, 105, 123); err == nil {
		t.Fatal("ambiguous pending effect skipped during cleanup")
	}
	active.Generation = ^uint64(0)
	if _, err = active.BeginRuleUpdate(desired); err == nil {
		t.Fatal("generation wrapped")
	}
	pending = activePFRecord(t)
	pending.NextRulesSHA256 = desired
	if pending.Validate() == nil {
		t.Fatal("pending rules hidden in active metadata")
	}
	original := activePFRecord(t)
	changed, _ := original.BeginRuleUpdate(desired)
	changed.RootSHA256 = desired
	if validatePFTransition(original, changed) == nil {
		t.Fatal("foreign baseline changed")
	}
}
