package recoverycore

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Standalone developer prototype, not the installed guard coordinator. The
// fixture owns one absent nonce leaf; exact foreign tree and final absence are
// mandatory. No relaxed production digest or cleanup assertion is introduced.
func TestRootPFRuleSingleClassRealPolicy(t *testing.T) {
	requirePFRuleCI(t)
	helper := os.Getenv("LEGACYWG_PF_SINGLE_RULE_HELPER")
	if helper == "" {
		t.Skip("explicit singleton developer helper required")
	}
	store := realBootStore(t, ownedReferenceTestDirectory(t))
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	empty := pfDigest("")
	probe, err := NewPFRecord(store.boot, pfDigest(stagedPFRule), empty, empty, empty)
	if err != nil {
		t.Fatal("singleton identity unavailable")
	}
	before, err := readDisabledPF(ctx, probe.Anchor)
	if err != nil || len(fixturePFReferences(t, ctx)) != 0 {
		t.Fatal("singleton disabled/zero-state/zero-reference baseline unavailable")
	}
	path := "com.apple/lw-rule-ci-" + probe.ID
	tree, err := enumeratePFAnchors(ctx)
	if err != nil {
		t.Fatal("singleton initial tree unavailable")
	}
	requireAbsentPFFixture(t, tree, path)
	call := func(ctx context.Context, mode string) error {
		bounded, stop := context.WithTimeout(ctx, 8*time.Second)
		defer stop()
		command := exec.CommandContext(bounded, helper, path, mode)
		command.Env = []string{"GITHUB_ACTIONS=true"}
		return command.Run()
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
		defer stop()
		if call(cleanup, "clear") != nil {
			t.Error("singleton ownership-checked cleanup refused; fixture retained")
			return
		}
		after, err := readDisabledPF(cleanup, probe.Anchor)
		if err != nil || after != before || len(fixturePFReferences(t, cleanup)) != 0 {
			t.Error("singleton exact final namespace/PF baseline not restored")
		}
	}()
	check := func(loopback bool) string {
		t.Helper()
		observations, err := enumeratePFAnchors(ctx)
		if err != nil {
			t.Fatal("singleton complete kernel observation unavailable")
		}
		var outside []pfAnchorObservation
		var rules string
		found := false
		for _, node := range observations {
			if node.path == path {
				if len(node.children) != 0 || node.nat != "" {
					t.Fatal("singleton fixture acquired unknown descendants/NAT")
				}
				found, rules = true, node.rules
				continue
			}
			// Remove only our known exact leaf from this TEST's foreign view.
			// Production baseline exclusion remains unchanged and stricter.
			children := make([]string, 0, len(node.children))
			for _, child := range node.children {
				if child != path {
					children = append(children, child)
				}
			}
			node.children = children
			outside = append(outside, node)
		}
		policy, err := parsePFPolicy(rules)
		if !found || err != nil || policy.loopback != loopback || policy.tunnel != nil || len(policy.escapes) != 0 {
			t.Fatal("singleton native policy differs from compiled fixed recipe")
		}
		filter, nat, err := pfEnumeratedDigests(outside, probe.Anchor)
		if err != nil || filter != before.recursive || nat != before.nat || len(outside) == 0 || pfDigest(outside[0].rules) != before.root || len(fixturePFReferences(t, ctx)) != 0 {
			t.Fatal("singleton rule operation changed foreign tree/root/references")
		}
		info, err := runOwnedPF(ctx, "", "-s", "info")
		status, count := pfStatusLine.FindAllStringSubmatch(info, -1), pfStateLine.FindAllStringSubmatch(info, -1)
		if err != nil || len(status) != 1 || len(count) != 1 || status[0][1] != "Disabled" || count[0][1] != "0" {
			t.Fatal("singleton changed PF enable/state baseline")
		}
		return pfDigest(rules)
	}
	if call(ctx, "deny") != nil {
		t.Fatal("singleton actual deny installation failed")
	}
	denyHash := check(false)
	if call(ctx, "rollback") != nil || check(false) != denyHash {
		t.Fatal("singleton pending loopback rollback changed active deny")
	}
	if call(ctx, "loopback") != nil {
		t.Fatal("singleton actual loopback replacement failed")
	}
	loopbackHash := check(true)
	if call(ctx, "rollback") != nil || check(true) != loopbackHash {
		t.Fatal("singleton pending deny rollback changed active loopback")
	}
	if store.pfResidue() {
		t.Fatal("standalone prototype unexpectedly wrote guard journal")
	}
}
