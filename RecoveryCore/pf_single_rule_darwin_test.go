package recoverycore

import (
	"bufio"
	"bytes"
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRootPFRuleSingleClassCodecPrimaryABI(t *testing.T) {
	requirePFRuleCI(t)
	helper := os.Getenv("LEGACYWG_PF_SINGLE_RULE_HELPER")
	if helper == "" {
		t.Skip("explicit primary ABI helper required")
	}
	anchor := "com.apple/legacywg-0123456789abcdef0123456789abcdef"
	fixtures := []struct {
		mode   string
		policy pfPolicy
	}{
		{"emit-deny", pfPolicy{}},
		{"emit-loopback", pfPolicy{loopback: true}},
		{"emit-udp4", pfPolicy{escapes: []pfUDPEscape{{path: pfInterface{"lo0", 1}, source: netip.MustParseAddr("127.0.0.1"), endpoint: netip.MustParseAddrPort("127.0.0.2:53"), sourcePort: 45120}}}},
		{"emit-udp6", pfPolicy{escapes: []pfUDPEscape{{path: pfInterface{"lo0", 1}, source: netip.MustParseAddr("::1"), endpoint: netip.MustParseAddrPort("[::2]:443"), sourcePort: 45120}}}},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.mode, func(t *testing.T) {
			frames, err := compiledPFFilterFrames(anchor, fixture.policy)
			if err != nil || len(frames) < 1 {
				t.Fatal("typed Go frame unavailable")
			}
			ctx, stop := context.WithTimeout(context.Background(), 8*time.Second)
			defer stop()
			command := exec.CommandContext(ctx, helper, anchor, fixture.mode)
			command.Env = []string{"GITHUB_ACTIONS=true"}
			var output pfBoundedOutput
			command.Stdout = &output
			if command.Run() != nil || output.Len() != pfFilterFrameSize || !bytes.Equal(output.Bytes(), frames[0][:]) {
				t.Fatal("complete Go rule frame differs from compiled primary struct")
			}
		})
	}
}

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
	if call(ctx, "unknown-operation") == nil {
		t.Fatal("singleton accepted an uncompiled operation")
	}
	afterInvalid, err := readDisabledPF(ctx, probe.Anchor)
	if err != nil || afterInvalid != before {
		t.Fatal("singleton invalid operation changed native baseline")
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
			// Fixed vocabulary only: unexpected values/rules remain private.
			known := map[string]bool{"block": true, "drop": true, "out": true, "quick": true, "all": true, "pass": true, "on": true, "lo0": true, "flags": true, "any": true, "no": true, "state": true, "rtable": true, "priority": true, "prio": true, "keep": true}
			var shape []string
			for _, token := range strings.Fields(rules) {
				if known[token] {
					shape = append(shape, token)
				} else {
					shape = append(shape, "VALUE")
				}
			}
			t.Logf("singleton native representation: found=%t parsed=%t fixed_vocabulary=%s", found, err == nil, strings.Join(shape, " "))
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
	for cycle := 0; cycle < 3; cycle++ {
		if call(ctx, "deny") != nil {
			t.Fatal("singleton actual deny installation failed")
		}
		denyHash := check(false)
		if call(ctx, "deny") == nil || check(false) != denyHash {
			t.Fatal("singleton new-install operation adopted an existing node")
		}
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
		if call(ctx, "clear") != nil {
			t.Fatal("singleton cycle clear refused")
		}
		after, err := readDisabledPF(ctx, probe.Anchor)
		if err != nil || after != before || len(fixturePFReferences(t, ctx)) != 0 {
			t.Fatal("singleton cycle did not restore exact namespace/PF baseline")
		}
	}
	for _, point := range []string{"crash-begin", "crash-rules", "crash-commit"} {
		if call(ctx, "deny") != nil {
			t.Fatal("singleton crash fixture deny installation failed")
		}
		denyHash := check(false)
		bounded, stop := context.WithTimeout(ctx, 12*time.Second)
		command := exec.CommandContext(bounded, helper, path, point)
		command.Env = []string{"GITHUB_ACTIONS=true"}
		pipe, err := command.StdoutPipe()
		if err != nil || command.Start() != nil {
			stop()
			t.Fatal("singleton crash child unavailable")
		}
		scanner := bufio.NewScanner(pipe)
		scanner.Buffer(make([]byte, 64), 64)
		reached := scanner.Scan() && scanner.Text() == "OWNED_SINGLE_RULE_CHECKPOINT"
		killed := command.Process.Kill()
		_ = command.Wait()
		stop()
		if !reached || killed != nil {
			t.Fatal("singleton actual SIGKILL checkpoint not reached")
		}
		if point == "crash-commit" {
			check(true)
		} else if check(false) != denyHash {
			t.Fatal("singleton pre-commit process death changed active deny")
		}
		// Explicit TEST fixture ownership permits retiring its inactive queue.
		// No production durable ownership/reboot claim follows from this probe.
		if call(ctx, "clear") != nil {
			t.Fatal("singleton crashed fixture cleanup refused")
		}
		after, err := readDisabledPF(ctx, probe.Anchor)
		if err != nil || after != before || len(fixturePFReferences(t, ctx)) != 0 {
			t.Fatal("singleton process death left a namespace/PF baseline difference")
		}
	}
	if store.pfResidue() {
		t.Fatal("standalone prototype unexpectedly wrote guard journal")
	}
}
