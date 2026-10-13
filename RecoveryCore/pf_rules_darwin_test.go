package recoverycore

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

func requirePFRuleCI(t *testing.T) {
	t.Helper()
	requirePFReferenceCI(t)
	if os.Getenv("LEGACYWG_PF_RULE_TESTS") != "1" {
		t.Skip("separate actual PF rule generation invocation")
	}
}

func fixturePFUDPPolicy(t *testing.T) pfPolicy {
	t.Helper()
	iface, err := net.InterfaceByName("lo0")
	if err != nil || iface.Index < 1 {
		t.Fatal("owned loopback source fixture unavailable")
	}
	return pfPolicy{escapes: []pfUDPEscape{
		{pfInterface{"lo0", iface.Index}, netip.MustParseAddr("127.0.0.1"), netip.MustParseAddrPort("127.0.0.2:53")},
		{pfInterface{"lo0", iface.Index}, netip.MustParseAddr("::1"), netip.MustParseAddrPort("[::1]:443")},
	}}
}

func TestRootPFRuleCanonicalGenerationsAndRefusals(t *testing.T) {
	requirePFRuleCI(t)
	store := realBootStore(t, ownedReferenceTestDirectory(t))
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if store.stageDisabledPFAnchor(ctx) != nil || store.activatePFAnchor(ctx) != nil {
		t.Fatal("rule generation initial owned activation failed")
	}
	initial, err := store.readPF(pfJournalFile)
	if err != nil || initial == nil {
		t.Fatal("initial generation journal missing")
	}
	entries := fixturePFReferences(t, ctx)
	desired := fixturePFUDPPolicy(t)
	if store.updatePFPolicy(ctx, desired) != nil {
		t.Fatal("actual dual-family numeric UDP generation failed")
	}
	updated, err := store.readPF(pfJournalFile)
	actual, nativeErr := readPFPolicy(ctx, initial.Anchor, true)
	if err != nil || updated == nil || updated.Generation != 2 || updated.Phase != PFActive || updated.NextRulesSHA256 != "" || updated.RulesSHA256 == initial.RulesSHA256 || nativeErr != nil || actual.rules != updated.RulesSHA256 || !actual.matches(*initial) || !samePFReferences(entries, fixturePFReferences(t, ctx)) {
		t.Fatal("actual new canonical rule hash/generation or reference preservation invalid")
	}
	if store.updatePFPolicy(ctx, desired) != nil {
		t.Fatal("identical policy did not remain a no-op")
	}
	unchanged, err := store.readPF(pfJournalFile)
	if err != nil || unchanged == nil || *unchanged != *updated {
		t.Fatal("identical rules changed generation or identity")
	}
	for _, condition := range []string{"wrong_index", "unassigned_source", "unowned_tunnel"} {
		bad, _ := desired.frozen()
		switch condition {
		case "wrong_index":
			bad.escapes[0].path.index++
		case "unassigned_source":
			bad.escapes[0].source = netip.MustParseAddr("192.0.2.201")
		case "unowned_tunnel":
			bad.tunnel = &pfInterface{"utun999999", 12}
		}
		if store.updatePFPolicy(ctx, bad) == nil {
			t.Fatal("wrong native path or unowned tunnel accepted")
		}
		record, err := store.readPF(pfJournalFile)
		policy, nativeErr := readPFPolicy(ctx, initial.Anchor, true)
		if err != nil || record == nil || *record != *updated || nativeErr != nil || policy != actual || !samePFReferences(entries, fixturePFReferences(t, ctx)) {
			t.Fatal("native path refusal changed kernel or journal")
		}
	}
	if store.updatePFPolicy(ctx, pfPolicy{loopback: true}) != nil || store.updatePFPolicy(ctx, pfPolicy{}) != nil {
		t.Fatal("loopback and deny-only rule generations failed")
	}
	final, err := store.readPF(pfJournalFile)
	if err != nil || final == nil || final.Generation != 4 || final.RulesSHA256 != initial.RulesSHA256 || final.Reference != initial.Reference {
		t.Fatal("deny-only restoration lost exact policy/owned reference")
	}
	if store.recoverPFLifecycle(ctx) != nil || store.pfResidue() || len(fixturePFReferences(t, ctx)) != 0 {
		t.Fatal("updated rule generation did not safely shut down")
	}
}

func TestRootPFRuleOwnedTunnelPolicy(t *testing.T) {
	requirePFRuleCI(t)
	store := realBootStore(t, ownedReferenceTestDirectory(t))
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if store.begin() != nil {
		t.Fatal("owned utun creation intent unavailable")
	}
	// Runs after the native device defer, before Store.Close and directory cleanup.
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if store.pfResidue() && store.recoverPFLifecycle(cleanup) != nil {
			t.Error("owned tunnel PF evidence retained after cleanup refusal")
			return
		}
		if store.Finish() != nil {
			t.Error("owned disappeared utun journal not retired")
		}
	}()
	native, err := tun.CreateTUN("utun", 1280)
	if err != nil {
		t.Fatal("owned typed-policy utun unavailable")
	}
	defer native.Close()
	name, err := native.Name()
	if err != nil || !utunName.MatchString(name) {
		t.Fatal("owned typed-policy utun identity unavailable")
	}
	command := exec.CommandContext(ctx, "/sbin/ifconfig", name, "up")
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	if command.Run() != nil {
		t.Fatal("owned typed-policy utun UP failed")
	}
	iface, err := net.InterfaceByName(name)
	if err != nil || store.MarkInterface(name, iface.Index) != nil || store.stageDisabledPFAnchor(ctx) != nil || store.activatePFAnchor(ctx) != nil {
		t.Fatal("owned typed-policy journal/interface/anchor setup failed")
	}
	policy := fixturePFUDPPolicy(t)
	policy.loopback, policy.tunnel = true, &pfInterface{name, iface.Index}
	if store.updatePFPolicy(ctx, policy) != nil {
		t.Fatal("actual journal-owned tunnel plus loopback/UDP policy failed")
	}
	record, err := store.readPF(pfJournalFile)
	if err != nil || record == nil {
		t.Fatal("journal-owned tunnel rule record missing")
	}
	observed, nativeErr := readPFPolicy(ctx, record.Anchor, true)
	if record.Generation != 2 || nativeErr != nil || observed.rules != record.RulesSHA256 {
		t.Fatal("journal-owned tunnel policy generation not observed")
	}
}

func TestRootPFRuleEffectCrashChild(t *testing.T) {
	path, stage := os.Getenv("LEGACYWG_PF_RULE_EFFECT_DIR"), os.Getenv("LEGACYWG_PF_RULE_EFFECT_STAGE")
	if path == "" || stage == "" {
		t.Skip("separate actual rule generation crash child")
	}
	requirePFRuleCI(t)
	store := realBootStore(t, path)
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if store.stageDisabledPFAnchor(ctx) != nil || store.activatePFAnchor(ctx) != nil {
		t.Fatal("actual rule crash child activation failed")
	}
	store.checkpoint = func(point string) {
		if point == stage {
			fmt.Println("OWNED_PF_RULE_CHECKPOINT")
			select {}
		}
	}
	if store.updatePFPolicy(ctx, fixturePFUDPPolicy(t)) != nil {
		t.Fatal("actual rule update failed before checkpoint")
	}
	t.Fatal("requested actual rule checkpoint not reached")
}

func TestRootPFRuleEffectCrashResolution(t *testing.T) {
	requirePFRuleCI(t)
	for _, fixture := range []struct {
		stage      string
		phase      PFPhase
		generation uint64
		newRules   bool
	}{
		{"pf_rule_update_intent_committed", PFRuleUpdateIntent, 1, false},
		{"pf_rule_update_loaded_kernel", PFRuleUpdateIntent, 1, true},
		{"pf_rule_update_confirmation_committed", PFActive, 2, true},
	} {
		t.Run(fixture.stage, func(t *testing.T) {
			path := ownedReferenceTestDirectory(t)
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRootPFRuleEffectCrashChild$", "-test.v")
			child.Env = append(os.Environ(), "LEGACYWG_PF_RULE_EFFECT_DIR="+path, "LEGACYWG_PF_RULE_EFFECT_STAGE="+fixture.stage)
			pipe, err := child.StdoutPipe()
			if err != nil || child.Start() != nil {
				t.Fatal("actual rule crash child did not start")
			}
			defer func() { _ = child.Process.Kill() }()
			scanner := bufio.NewScanner(pipe)
			reached := false
			for scanner.Scan() {
				if scanner.Text() == "OWNED_PF_RULE_CHECKPOINT" {
					reached = true
					break
				}
			}
			if !reached || child.Process.Kill() != nil {
				_ = child.Wait()
				t.Fatal("actual rule SIGKILL point not reached")
			}
			_ = child.Wait()
			store := realBootStore(t, path)
			defer store.Close()
			record, err := store.readPF(pfJournalFile)
			if err != nil || record == nil || record.PID != child.Process.Pid || record.Phase != fixture.phase || record.Generation != fixture.generation {
				t.Fatal("actual rule effect durable candidates/phase missing")
			}
			observed, err := readPFPolicy(ctx, record.Anchor, true)
			want := record.RulesSHA256
			if fixture.newRules && record.Phase == PFRuleUpdateIntent {
				want = record.NextRulesSHA256
			}
			if err != nil || observed.rules != want || !observed.matches(*record) {
				t.Fatal("actual kernel old/new rule hash differs after crash")
			}
			if record.Phase == PFRuleUpdateIntent {
				if store.resolvePFPolicy(ctx) != nil {
					t.Fatal("actual old/new hash resolution failed")
				}
				resolved, err := store.readPF(pfJournalFile)
				generation := uint64(1)
				if fixture.newRules {
					generation = 2
				}
				if err != nil || resolved == nil || resolved.Phase != PFActive || resolved.Generation != generation || resolved.RulesSHA256 != want || resolved.NextRulesSHA256 != "" || resolved.Reference != record.Reference {
					t.Fatal("rule resolution changed token or chose wrong generation")
				}
			}
			if store.recoverPFLifecycle(ctx) != nil || store.pfResidue() || len(fixturePFReferences(t, ctx)) != 0 {
				t.Fatal("actual rule crash resolution did not restore owned baseline")
			}
			after, err := readDisabledPF(ctx, record.Anchor)
			if err != nil || after.rules != pfDigest("") || !after.matches(*record) {
				t.Fatal("actual rule crash baseline not restored")
			}
		})
	}
}
