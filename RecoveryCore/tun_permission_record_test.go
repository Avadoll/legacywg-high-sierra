package recoverycore

import (
	"bytes"
	"strings"
	"testing"
)

func permissionRecordFixture(t *testing.T) (tunPermissionRecord, PFRecord) {
	t.Helper()
	session, err := NewRecord(testBoot)
	if err != nil {
		t.Fatal("permission session fixture unavailable")
	}
	session, err = session.Advance(InterfaceCreated, "utun17", 71, false)
	if err != nil {
		t.Fatal("permission interface fixture unavailable")
	}
	pf := testPFRecord(t)
	pf.Phase, pf.ReferenceAfter, pf.ReferenceBefore, pf.Reference = PFActive, 100, 105, 123
	pf.RulesSHA256 = pfDigest(stagedPFRule)
	record, err := newTUNPermissionRecord(session, pf)
	if err != nil {
		t.Fatal("permission armed record rejected")
	}
	pf.Generation, pf.RulesSHA256 = 2, strings.Repeat("b", 64)
	return record, pf
}

func TestTUNPermissionIntentAndReopen(t *testing.T) {
	record, pf := permissionRecordFixture(t)
	check := func(next tunPermissionRecord, err error) {
		t.Helper()
		if err != nil || !tunPermissionTransition(record, next) {
			t.Fatal("required permission transition rejected")
		}
		encoded, err := encodeTUNPermission(next)
		decoded, decodeErr := decodeTUNPermission(encoded)
		if err != nil || decodeErr != nil || decoded != next {
			t.Fatal("permission canonical identity lost")
		}
		record = next
	}
	check(record.beginEnable(pf))
	check(record.advance(tunPermissionEnabled))
	check(record.advance(tunPermissionClearIntent))
	check(record.advance(tunPermissionCleared))
	if _, err := record.beginEnable(pf); err == nil {
		t.Fatal("old PF generation replay accepted")
	}
	pf.Generation = 4
	check(record.beginEnable(pf))
	// An unconfirmed enable effect must be able to proceed through clear intent.
	check(record.advance(tunPermissionClearIntent))
	check(record.advance(tunPermissionCleared))
	check(record.advance(tunPermissionReleased))
	if record.Cycle != 2 {
		t.Fatal("permission reopen cycle lost")
	}
	if _, err := record.beginEnable(pf); err == nil {
		t.Fatal("released descriptor permission reopened")
	}
}

func TestTUNPermissionRefusesSkippedEffectsAndIdentityChanges(t *testing.T) {
	armed, pf := permissionRecordFixture(t)
	if _, err := armed.advance(tunPermissionEnabled); err == nil {
		t.Fatal("enable confirmation skipped intent")
	}
	released, err := armed.advance(tunPermissionReleased)
	if err != nil || !tunPermissionTransition(armed, released) || released.Cycle != 0 {
		t.Fatal("unused armed capability cancellation rejected")
	}
	intent, err := armed.beginEnable(pf)
	if err != nil {
		t.Fatal("permission enable fixture unavailable")
	}
	if _, err := intent.advance(tunPermissionReleased); err == nil {
		t.Fatal("uncertain enable effect released without clear")
	}
	for _, change := range []func(*PFRecord){
		func(r *PFRecord) { r.ID = strings.Repeat("c", 32); r.Anchor = "com.apple/legacywg-" + r.ID },
		func(r *PFRecord) { r.Boot = "11111111-1111-1111-1111-111111111111" },
		func(r *PFRecord) { r.PID++ }, func(r *PFRecord) { r.RulesSHA256 = pfDigest(stagedPFRule) },
		func(r *PFRecord) { r.Generation = ^uint64(0) },
	} {
		other := pf
		change(&other)
		if _, err := armed.beginEnable(other); err == nil {
			t.Fatal("foreign or unusable PF admission accepted")
		}
	}
	for _, change := range []func(*tunPermissionRecord){
		func(r *tunPermissionRecord) { r.SessionID = strings.Repeat("c", 32) },
		func(r *tunPermissionRecord) { r.PFID = strings.Repeat("c", 32) },
		func(r *tunPermissionRecord) { r.ID = strings.Repeat("c", 32) },
		func(r *tunPermissionRecord) { r.PID++ }, func(r *tunPermissionRecord) { r.InterfaceIndex++ },
		func(r *tunPermissionRecord) { r.Interface = "utun18" }, func(r *tunPermissionRecord) { r.Cycle++ },
	} {
		other := intent
		change(&other)
		if tunPermissionTransition(armed, other) {
			t.Fatal("permission ownership or cycle rewrite accepted")
		}
	}
}

func TestTUNPermissionCanonicalCorruptionRefused(t *testing.T) {
	record, _ := permissionRecordFixture(t)
	valid, err := encodeTUNPermission(record)
	if err != nil {
		t.Fatal("permission encoding unavailable")
	}
	for _, data := range [][]byte{nil, bytes.Repeat([]byte{'x'}, MaxRecordBytes+1),
		append([]byte{' '}, valid...), append(append([]byte{}, valid...), []byte("{}")...),
		bytes.Replace(valid, []byte("\"armed\""), []byte("\"enabled\""), 1),
		bytes.Replace(valid, []byte("\"cycle\":0"), []byte("\"cycle\":0,\"cycle\":0"), 1),
		bytes.Replace(valid, []byte("\"version\":1"), []byte("\"version\":1,\"command\":\"id\""), 1),
		bytes.Replace(valid, []byte("utun17"), []byte("../utun17"), 1),
	} {
		if _, err := decodeTUNPermission(data); err == nil {
			t.Fatal("ambiguous permission metadata accepted")
		}
	}
}
