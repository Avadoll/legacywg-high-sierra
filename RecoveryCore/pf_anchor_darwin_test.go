package recoverycore

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func requirePFAnchorCI(t *testing.T) {
	t.Helper()
	requireRoot(t)
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("LEGACYWG_PF_ANCHOR_TESTS") != "1" {
		t.Skip("separate disposable native PF anchor effect invocation")
	}
	if unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}) != nil {
		t.Fatal("core dump refusal failed")
	}
}

func realBootStore(t *testing.T, path string) *Store {
	t.Helper()
	store, err := directoryStore(t, path)
	if err != nil {
		t.Fatal("owned PF effect store failed")
	}
	boot, err := unix.Sysctl("kern.bootsessionuuid")
	store.boot = strings.ToLower(strings.TrimSpace(strings.TrimRight(boot, "\x00")))
	if err != nil || !bootID.MatchString(store.boot) {
		store.Close()
		t.Fatal("native boot identity unavailable")
	}
	return store
}

func TestRootPFAnchorStageAndCancel(t *testing.T) {
	requirePFAnchorCI(t)
	store := realBootStore(t, ownedTestDirectory(t))
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if store.stageDisabledPFAnchor(ctx) != nil {
		t.Fatal("disabled journal-bound anchor staging failed")
	}
	record, err := store.readPF(pfJournalFile)
	if err != nil || record == nil || record.Phase != PFAnchorInstalled || record.Reference != 0 || record.ReferenceAfter != 0 {
		t.Fatal("anchor confirmation or no-reference identity invalid")
	}
	actual, err := readDisabledPF(ctx, record.Anchor)
	if err != nil || !actual.matches(*record) || actual.rules != pfDigest(stagedPFRule) {
		t.Fatal("actual kernel anchor differs from committed identity")
	}
	if store.reconcile() == nil || store.stageDisabledPFAnchor(ctx) == nil {
		t.Fatal("ordinary recovery or a second staging bypassed residue")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if store.cancelDisabledPFAnchor(canceled) == nil {
		t.Fatal("canceled operation accepted")
	}
	if store.cancelDisabledPFAnchor(ctx) != nil || store.pfResidue() || store.reconcile() != nil {
		t.Fatal("verified pre-reference cancellation did not restore clean store")
	}
	after, err := readDisabledPF(ctx, record.Anchor)
	if err != nil || !after.matches(*record) || after.rules != pfDigest("") {
		t.Fatal("native baseline not restored")
	}
}

func TestRootPFAnchorEffectCrashChild(t *testing.T) {
	path, stage := os.Getenv("LEGACYWG_PF_EFFECT_DIR"), os.Getenv("LEGACYWG_PF_EFFECT_STAGE")
	if path == "" || stage == "" {
		t.Skip("separate PF anchor effect crash child")
	}
	requirePFAnchorCI(t)
	store := realBootStore(t, path)
	defer store.Close()
	store.checkpoint = func(point string) {
		if point == stage {
			fmt.Println("OWNED_PF_EFFECT_CHECKPOINT")
			select {}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if store.stageDisabledPFAnchor(ctx) != nil {
		t.Fatal("crash child staging failed before checkpoint")
	}
	if store.cancelDisabledPFAnchor(ctx) != nil {
		t.Fatal("crash child cancellation failed before checkpoint")
	}
	t.Fatal("requested effect checkpoint was not reached")
}

func TestRootPFAnchorCancellationRefusesChangedRulesAndBoot(t *testing.T) {
	requirePFAnchorCI(t)
	store := realBootStore(t, ownedTestDirectory(t))
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if store.stageDisabledPFAnchor(ctx) != nil {
		t.Fatal("refusal fixture staging failed")
	}
	record, err := store.readPF(pfJournalFile)
	if err != nil || record == nil {
		t.Fatal("refusal fixture journal missing")
	}
	// Controlled replacement of ONLY this fixture's owned child. It models
	// unexpected administrator changes, not arbitrary foreign policy adoption.
	const replacement = "pass out all\n"
	if _, err := runOwnedPF(ctx, replacement, "-a", record.Anchor, "-f", "-"); err != nil {
		t.Fatal("owned changed-rule condition failed")
	}
	if store.cancelDisabledPFAnchor(ctx) == nil {
		t.Fatal("unrecorded kernel rule hash authorized cancellation")
	}
	after, err := store.readPF(pfJournalFile)
	rules, readErr := runOwnedPF(ctx, "", "-a", record.Anchor, "-s", "rules")
	if err != nil || after == nil || *after != *record || readErr != nil || rules != replacement {
		t.Fatal("changed-rule refusal modified policy or journal")
	}
	if _, err := runOwnedPF(ctx, stagedPFRule, "-a", record.Anchor, "-f", "-"); err != nil {
		t.Fatal("controlled own-rule restoration failed")
	}
	originalBoot := store.boot
	store.boot = "00000000-0000-0000-0000-000000000000"
	if store.cancelDisabledPFAnchor(ctx) == nil {
		t.Fatal("unconfirmed boot authorized cancellation")
	}
	store.boot = originalBoot
	after, err = store.readPF(pfJournalFile)
	actual, readErr := readDisabledPF(ctx, record.Anchor)
	if err != nil || after == nil || *after != *record || readErr != nil || actual.rules != record.RulesSHA256 {
		t.Fatal("boot refusal modified kernel rules or journal")
	}
	live := *record
	live.PID = os.Getppid()
	if live.PID != os.Getpid() && store.preReferenceOwner(live) {
		t.Fatal("different live owner accepted")
	}
	if store.cancelDisabledPFAnchor(ctx) != nil || store.pfResidue() {
		t.Fatal("controlled refusal fixture did not clean up")
	}
}

func TestRootPFAnchorEffectCrashRecovery(t *testing.T) {
	requirePFAnchorCI(t)
	for _, fixture := range []struct {
		stage  string
		phase  PFPhase
		loaded bool
	}{
		{"pf_install_intent_committed", PFInstallIntent, false},
		{"pf_anchor_loaded", PFInstallIntent, true},
		{"pf_removal_intent_committed", PFAnchorRemovalIntent, true},
		{"pf_anchor_emptied", PFAnchorRemovalIntent, false},
	} {
		t.Run(fixture.stage, func(t *testing.T) {
			path := ownedTestDirectory(t)
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRootPFAnchorEffectCrashChild$", "-test.v")
			child.Env = append(os.Environ(), "LEGACYWG_PF_EFFECT_DIR="+path, "LEGACYWG_PF_EFFECT_STAGE="+fixture.stage)
			pipe, err := child.StdoutPipe()
			if err != nil || child.Start() != nil {
				t.Fatal("effect crash child failed to start")
			}
			defer func() { _ = child.Process.Kill() }()
			scanner := bufio.NewScanner(pipe)
			reached := false
			for scanner.Scan() {
				if scanner.Text() == "OWNED_PF_EFFECT_CHECKPOINT" {
					reached = true
					break
				}
			}
			if !reached || child.Process.Kill() != nil {
				_ = child.Wait()
				t.Fatal("actual effect SIGKILL checkpoint was not reached")
			}
			_ = child.Wait()
			if child.ProcessState == nil || child.ProcessState.Success() {
				t.Fatal("effect child survived SIGKILL")
			}
			store := realBootStore(t, path)
			defer store.Close()
			record, err := store.readPF(pfJournalFile)
			if err != nil || record == nil || record.PID != child.Process.Pid || record.Phase != fixture.phase {
				t.Fatal("write-before-effect owner/phase not retained")
			}
			actual, err := readDisabledPF(ctx, record.Anchor)
			want := pfDigest("")
			if fixture.loaded {
				want = pfDigest(stagedPFRule)
			}
			if err != nil || !actual.matches(*record) || actual.rules != want {
				t.Fatal("real kernel state after process death differs")
			}
			if store.reconcile() == nil {
				t.Fatal("ordinary recovery adopted external PF effects")
			}
			if store.cancelDisabledPFAnchor(ctx) != nil || store.pfResidue() {
				t.Fatal("same-boot dead-owner pre-reference recovery failed")
			}
			after, err := readDisabledPF(ctx, record.Anchor)
			if err != nil || !after.matches(*record) || after.rules != pfDigest("") {
				t.Fatal("effect recovery changed native foreign baseline")
			}
		})
	}
}
