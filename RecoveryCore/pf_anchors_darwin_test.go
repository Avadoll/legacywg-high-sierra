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
	baselineTree, err := enumeratePFAnchors(ctx)
	if err != nil {
		t.Fatal("baseline kernel tree unavailable")
	}
	parent := "com.apple/lw-enum-ci-" + probe.ID
	child := parent + "/hidden"
	observeFixture := func(ctx context.Context, stage string) {
		tree, err := enumeratePFAnchors(ctx)
		parentExists, childExists := false, false
		for _, node := range tree {
			parentExists = parentExists || node.path == parent
			childExists = childExists || node.path == child
		}
		t.Logf("enumeration fixture stage=%s readable=%t parent_present=%t child_present=%t nodes=%d", stage, err == nil, parentExists, childExists, len(tree))
	}
	const parentRule = "anchor \"hidden\" all\n"
	var parentHash, filterHash, natHash string
	// Cleanup authority covers only our two random, separately named fixture
	// nodes. Unexpected replacement is preserved, never globally flushed.
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 25*time.Second)
		defer stop()
		p, pErr := readPFAnchorText(cleanup, parent, "rules")
		r, rErr := readPFAnchorText(cleanup, child, "rules")
		n, nErr := readPFAnchorText(cleanup, child, "nat")
		if pErr != nil || rErr != nil || nErr != nil || (parentHash != "" && pfDigest(p) != parentHash) || (filterHash != "" && pfDigest(r) != filterHash) || (natHash != "" && pfDigest(n) != natHash) {
			t.Error("changed enumeration fixture retained after cleanup refusal")
			return
		}
		// Drop the parent's owned reference before retiring the child; clearing
		// a referenced child first can leave empty namespace nodes behind.
		if _, err := runOwnedPF(cleanup, "", "-a", parent, "-f", "-"); err != nil {
			t.Error("owned enumeration parent cleanup failed")
			return
		}
		observeFixture(cleanup, "parent-empty-load")
		if _, err := runOwnedPF(cleanup, "", "-a", child, "-f", "-"); err != nil {
			t.Error("owned enumeration child cleanup failed")
			return
		}
		observeFixture(cleanup, "child-empty-load")
		// Fixed owned ruleset modifiers only. Never -F all/states, global scope,
		// enable/disable, or an unknown/foreign anchor cleanup operation.
		for _, path := range []string{parent, child} {
			for _, kind := range []string{"rules", "nat"} {
				if _, err := runOwnedPF(cleanup, "", "-a", path, "-F", kind); err != nil {
					t.Error("owned enumeration fixed ruleset retirement failed")
					return
				}
				stage := "parent-" + kind + "-flush"
				if path == child {
					stage = "child-" + kind + "-flush"
				}
				observeFixture(cleanup, stage)
			}
		}
		// Read otherwise hidden rule classes before any additional owned flush.
		// An unknown value is preserved; the fixture never creates these classes.
		for _, path := range []string{child, parent} {
			for _, kind := range []string{"dummynet", "Tables"} {
				text, err := runOwnedPF(cleanup, "", "-a", path, "-s", kind)
				t.Logf("enumeration fixture extra_class=%s readable=%t empty=%t", kind, err == nil, text == "")
				if err != nil || text != "" {
					t.Error("unknown fixture extra class preserved")
					return
				}
				if _, err := runOwnedPF(cleanup, "", "-a", path, "-F", kind); err != nil {
					t.Error("owned empty extra-class retirement failed")
					return
				}
				observeFixture(cleanup, "empty-extra-class-retirement")
			}
		}
		after, err := readDisabledPF(cleanup, probe.Anchor)
		// Observe possible deferred namespace retirement without changing global
		// timeouts, states, PF enabled status or foreign rules. Exact baseline
		// equality remains mandatory; expiry of this wait is a test failure.
		deadline := time.Now().Add(15 * time.Second)
		for err == nil && after != before && time.Now().Before(deadline) && cleanup.Err() == nil {
			time.Sleep(250 * time.Millisecond)
			after, err = readDisabledPF(cleanup, probe.Anchor)
		}
		if err != nil || after != before {
			t.Errorf("enumeration cleanup mismatch: readable=%t root_same=%t filter_tree_same=%t nat_tree_same=%t", err == nil, after.root == before.root, after.recursive == before.recursive, after.nat == before.nat)
			tree, treeErr := enumeratePFAnchors(cleanup)
			known := make(map[string]pfAnchorObservation)
			for _, node := range baselineTree {
				known[node.path] = node
			}
			newFixture, newOther, changedContent := 0, 0, 0
			for _, node := range tree {
				old, exists := known[node.path]
				if exists && (old.rules != node.rules || old.nat != node.nat) {
					changedContent++
				}
				if !exists && node.path != probe.Anchor {
					if node.path == parent || node.path == child {
						newFixture++
					} else {
						newOther++
					}
				}
			}
			t.Errorf("enumeration cleanup detail: tree_readable=%t baseline_nodes=%d final_nodes=%d new_fixture_nodes=%d new_other_nodes=%d changed_existing_content=%d", treeErr == nil, len(baselineTree), len(tree), newFixture, newOther, changedContent)
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
