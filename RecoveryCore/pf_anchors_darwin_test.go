package recoverycore

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func requireAbsentPFFixture(t *testing.T, tree []pfAnchorObservation, path string) {
	t.Helper()
	for _, node := range tree {
		if node.path == path || strings.HasPrefix(node.path, path+"/") {
			t.Fatal("fixture namespace already exists; preserved without mutation")
		}
	}
}

func TestRootPFRuleEmptyTransactionNamespace(t *testing.T) {
	requirePFRuleCI(t)
	if os.Getenv("LEGACYWG_PF_MIXED_DIAGNOSTIC") != "1" {
		t.Skip("isolated rejected mixed-transaction strategy experiment only")
	}
	for _, mode := range []string{"single", "multi"} {
		t.Run(mode, func(t *testing.T) {
			store := realBootStore(t, ownedReferenceTestDirectory(t))
			defer store.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			empty := pfDigest("")
			probe, err := NewPFRecord(store.boot, pfDigest(stagedPFRule), empty, empty, empty)
			if err != nil {
				t.Fatal("transaction fixture identity unavailable")
			}
			before, err := readDisabledPF(ctx, probe.Anchor)
			if err != nil {
				t.Fatal("transaction baseline unavailable")
			}
			path := "com.apple/lw-xact-ci-" + probe.ID
			tree, err := enumeratePFAnchors(ctx)
			if err != nil {
				t.Fatal("transaction fixture absence unavailable")
			}
			requireAbsentPFFixture(t, tree, path)
			helper := os.Getenv("LEGACYWG_PF_TRANSACTION_HELPER")
			if helper == "" {
				t.Fatal("transaction developer fixture unavailable")
			}
			command := exec.CommandContext(ctx, helper, path, mode)
			command.Env = []string{"GITHUB_ACTIONS=true"}
			if command.Run() != nil {
				t.Fatal("empty transaction operation failed")
			}
			after, err := readDisabledPF(ctx, probe.Anchor)
			if err != nil || after != before {
				t.Fatalf("empty %s transaction did not retire namespace: readable=%t root_same=%t filter_tree_same=%t nat_tree_same=%t", mode, err == nil, before.root == after.root, before.recursive == after.recursive, before.nat == after.nat)
			}
		})
	}
}

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
	requireAbsentPFFixture(t, baselineTree, parent)
	helper := os.Getenv("LEGACYWG_PF_NESTED_RULE_HELPER")
	if helper == "" {
		t.Fatal("explicit single-class nested fixture helper required")
	}
	runNested := func(ctx context.Context, mode string) error {
		bounded, stop := context.WithTimeout(ctx, 8*time.Second)
		defer stop()
		command := exec.CommandContext(bounded, helper, parent, mode)
		command.Env = []string{"GITHUB_ACTIONS=true"}
		return command.Run()
	}
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
		if runNested(cleanup, "clear") != nil {
			t.Error("known nested fixture single-class cleanup refused")
			return
		}
		after, err := readDisabledPF(cleanup, probe.Anchor)
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
	if runNested(ctx, "parent") != nil {
		t.Fatal("owned nested fixture parent setup failed")
	}
	parentText, err := readPFAnchorText(ctx, parent, "rules")
	if err != nil {
		t.Fatal("owned fixture parent confirmation failed")
	}
	parentHash = pfDigest(parentText)
	if runNested(ctx, "quick") != nil {
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
	if runNested(ctx, "nat") != nil {
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
