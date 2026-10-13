package recoverycore

import (
	"context"
	"testing"
	"time"
)

func TestRootPFRuleEnumerationForeignFilterAndNATRefused(t *testing.T) {
	requirePFRuleCI(t)
	store := realBootStore(t, ownedReferenceTestDirectory(t))
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	empty := pfDigest("")
	probe, err := NewPFRecord(store.boot, pfDigest(stagedPFRule), empty, empty, empty)
	if err != nil {
		t.Fatal("enumeration fixture identity unavailable")
	}
	before, err := readDisabledPF(ctx, probe.Anchor)
	if err != nil {
		t.Fatal("complete native baseline enumeration unavailable")
	}
	parent := "com.apple/lw-enum-ci-" + probe.ID
	child := parent + "/hidden"
	const parentRule = "anchor \"hidden\" all\n"
	var parentHash, filterHash, natHash string
	// Cleanup authority covers only our two random, separately named fixture
	// nodes. Unexpected replacement is preserved, never globally flushed.
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		p, pErr := readPFAnchorText(cleanup, parent, "rules")
		r, rErr := readPFAnchorText(cleanup, child, "rules")
		n, nErr := readPFAnchorText(cleanup, child, "nat")
		if pErr != nil || rErr != nil || nErr != nil || (parentHash != "" && pfDigest(p) != parentHash) || (filterHash != "" && pfDigest(r) != filterHash) || (natHash != "" && pfDigest(n) != natHash) {
			t.Error("changed enumeration fixture retained after cleanup refusal")
			return
		}
		if _, err := runOwnedPF(cleanup, "", "-a", child, "-f", "-"); err != nil {
			t.Error("owned enumeration child cleanup failed")
			return
		}
		if _, err := runOwnedPF(cleanup, "", "-a", parent, "-f", "-"); err != nil {
			t.Error("owned enumeration parent cleanup failed")
			return
		}
		after, err := readDisabledPF(cleanup, probe.Anchor)
		if err != nil || after != before {
			t.Error("enumerated foreign baseline not restored after fixture cleanup")
		}
	}()
	if _, err := runOwnedPF(ctx, parentRule, "-o", "none", "-a", parent, "-f", "-"); err != nil {
		t.Fatal("owned nested fixture parent setup failed")
	}
	parentText, err := readPFAnchorText(ctx, parent, "rules")
	if err != nil {
		t.Fatal("owned fixture parent confirmation failed")
	}
	parentHash = pfDigest(parentText)
	const quick = "pass out quick all flags any no state\n"
	if _, err := runOwnedPF(ctx, quick, "-o", "none", "-a", child, "-f", "-"); err != nil {
		t.Fatal("owned hidden quick-rule fixture setup failed")
	}
	filter, err := readPFAnchorText(ctx, child, "rules")
	if err != nil || filter == "" {
		t.Fatal("actual hidden quick rule not observed")
	}
	filterHash, natHash = pfDigest(filter), empty
	observations, err := enumeratePFAnchors(ctx)
	found := false
	for _, observation := range observations {
		if observation.path == child && observation.rules == filter {
			found = true
		}
	}
	if err != nil || !found {
		t.Fatal("direct kernel enumeration missed actual nested quick-rule node")
	}
	if _, _, err := pfEnumeratedDigests(observations, probe.Anchor); err == nil || store.stageDisabledPFAnchor(ctx) == nil || store.pfResidue() {
		t.Fatal("unknown nested filter policy admitted or created guard intent")
	}
	afterFilter, err := readPFAnchorText(ctx, child, "rules")
	if err != nil || afterFilter != filter || len(fixturePFReferences(t, ctx)) != 0 {
		t.Fatal("foreign filter refusal changed rule/reference")
	}
	// Deliberately replace ONLY this fixture with a known NAT rule. PF remains
	// disabled; no actual traffic, global policy or third-party node is changed.
	const natRule = "nat on lo0 inet from 198.18.99.0/24 to any -> 127.0.0.1\n"
	if _, err := runOwnedPF(ctx, natRule, "-o", "none", "-a", child, "-f", "-"); err != nil {
		t.Fatal("owned hidden NAT fixture setup failed")
	}
	filter, err = readPFAnchorText(ctx, child, "rules")
	nat, nativeErr := readPFAnchorText(ctx, child, "nat")
	if err != nil || nativeErr != nil || filter != "" || nat == "" {
		t.Fatal("actual hidden NAT replacement not observed")
	}
	filterHash, natHash = empty, pfDigest(nat)
	observations, err = enumeratePFAnchors(ctx)
	if err != nil {
		t.Fatal("hidden NAT tree enumeration failed")
	}
	if _, _, err := pfEnumeratedDigests(observations, probe.Anchor); err == nil || store.stageDisabledPFAnchor(ctx) == nil || store.pfResidue() {
		t.Fatal("unknown nested NAT policy admitted or created guard intent")
	}
	afterNAT, err := readPFAnchorText(ctx, child, "nat")
	if err != nil || afterNAT != nat || len(fixturePFReferences(t, ctx)) != 0 {
		t.Fatal("foreign NAT refusal changed rule/reference")
	}
}
