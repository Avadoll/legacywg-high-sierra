package recoverycore

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func requirePFReferenceCI(t *testing.T) {
	t.Helper()
	requireRoot(t)
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("LEGACYWG_PF_REFERENCE_TESTS") != "1" {
		t.Skip("separate disposable native journal-bound PF reference invocation")
	}
	if unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}) != nil || !currentPFReferenceName() {
		t.Fatal("fixed reference owner name or core-dump refusal failed")
	}
}

// A failed enabled-PF test must not let testing.TempDir delete its recovery
// evidence. Only successful explicit recovery retires these fixed owned files.
func ownedReferenceTestDirectory(t *testing.T) string {
	t.Helper()
	requirePFReferenceCI(t)
	path, err := os.MkdirTemp("", "legacywg-pf-lifecycle-")
	if err != nil || os.Chmod(path, 0700) != nil {
		t.Fatal("private persistent reference fixture directory unavailable")
	}
	t.Cleanup(func() {
		store := realBootStore(t, path)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if store.pfResidue() && store.recoverPFLifecycle(ctx) != nil {
			store.Close()
			t.Error("ambiguous native PF fixture evidence retained after cleanup refusal")
			return
		}
		store.Close()
		if os.Remove(filepath.Join(path, lockFile)) != nil || os.Remove(path) != nil {
			t.Error("unexpected owned fixture files retained; no recursive cleanup")
		}
	})
	return path
}

func fixturePFReferences(t *testing.T, ctx context.Context) []pfReference {
	t.Helper()
	fd, err := openPFReferences(ctx)
	if err != nil {
		t.Fatal("private native reference descriptor unavailable")
	}
	defer unix.Close(fd)
	entries, err := readPFReferences(ctx, fd)
	if err != nil {
		t.Fatal("bounded private native reference observation failed")
	}
	return entries
}

func TestRootPFReferenceActivationAndSerializedStop(t *testing.T) {
	requirePFReferenceCI(t)
	store := realBootStore(t, ownedReferenceTestDirectory(t))
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if store.stageDisabledPFAnchor(ctx) != nil {
		t.Fatal("reference activation staging failed")
	}
	results := make(chan error, 2)
	var group sync.WaitGroup
	for i := 0; i < 2; i++ {
		group.Add(1)
		go func() { defer group.Done(); results <- store.activatePFAnchor(ctx) }()
	}
	group.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("serialized activation did not produce exactly one success")
	}
	record, err := store.readPF(pfJournalFile)
	if err != nil || record == nil || record.Phase != PFActive || record.Reference == 0 {
		t.Fatal("durable actual active reference missing")
	}
	entries := fixturePFReferences(t, ctx)
	owned, err := selectPFReference(*record, entries)
	if err != nil || owned == nil || len(entries) != 1 || owned.token != record.Reference {
		t.Fatal("actual PID/name/window/token does not match journal")
	}
	policy, err := readPFPolicy(ctx, record.Anchor, true)
	if err != nil || !policy.matches(*record) || policy.rules != record.RulesSHA256 {
		t.Fatal("actual active PF policy not confirmed")
	}
	stopped, stop := context.WithCancel(ctx)
	stop()
	if store.recoverPFLifecycle(stopped) == nil || !samePFReferences(entries, fixturePFReferences(t, ctx)) {
		t.Fatal("canceled stop changed native reference ownership")
	}
	if store.reconcile() == nil || store.recoverPFLifecycle(ctx) != nil || store.pfResidue() {
		t.Fatal("explicit actual-reference shutdown failed")
	}
	after, err := readDisabledPF(ctx, record.Anchor)
	if err != nil || !after.matches(*record) || after.rules != pfDigest("") || len(fixturePFReferences(t, ctx)) != 0 {
		t.Fatal("owned stop did not restore disabled empty anchor/reference baseline")
	}
}

func TestRootPFReferenceCancellationBeforeAcquire(t *testing.T) {
	requirePFReferenceCI(t)
	store := realBootStore(t, ownedReferenceTestDirectory(t))
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if store.stageDisabledPFAnchor(ctx) != nil {
		t.Fatal("pre-acquire cancellation staging failed")
	}
	activation, stop := context.WithCancel(ctx)
	store.checkpoint = func(point string) {
		if point == "pf_reference_intent_committed" {
			stop()
		}
	}
	if store.activatePFAnchor(activation) == nil {
		t.Fatal("canceled acquire accepted")
	}
	store.checkpoint = nil
	record, err := store.readPF(pfJournalFile)
	if err != nil || record == nil || record.Phase != PFReferenceIntent || record.Reference != 0 || len(fixturePFReferences(t, ctx)) != 0 {
		t.Fatal("cancellation did not preserve unconfirmed intent without phantom token")
	}
	if store.recoverPFLifecycle(ctx) != nil || store.pfResidue() {
		t.Fatal("actual absence was not reconciled before pre-acquire cancellation")
	}
	after, err := readDisabledPF(ctx, record.Anchor)
	if err != nil || !after.matches(*record) || after.rules != pfDigest("") {
		t.Fatal("pre-acquire cancellation native baseline not restored")
	}
}

func TestRootPFReferenceEffectCrashChild(t *testing.T) {
	path, stage := os.Getenv("LEGACYWG_PF_REF_EFFECT_DIR"), os.Getenv("LEGACYWG_PF_REF_EFFECT_STAGE")
	if path == "" || stage == "" {
		t.Skip("separate actual reference crash child")
	}
	requirePFReferenceCI(t)
	store := realBootStore(t, path)
	defer store.Close()
	store.checkpoint = func(point string) {
		if point == stage {
			fmt.Println("OWNED_PF_REFERENCE_CHECKPOINT")
			select {}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if store.stageDisabledPFAnchor(ctx) != nil || store.activatePFAnchor(ctx) != nil || store.recoverPFLifecycle(ctx) != nil {
		t.Fatal("actual reference child failed before checkpoint")
	}
	t.Fatal("actual reference checkpoint not reached")
}

func TestRootPFReferenceEffectCrashRecovery(t *testing.T) {
	requirePFReferenceCI(t)
	for _, fixture := range []struct {
		stage           string
		phase           PFPhase
		kernelReference bool
		kernelRules     bool
	}{
		{"pf_reference_intent_committed", PFReferenceIntent, false, true},
		{"pf_reference_acquired_kernel", PFReferenceIntent, true, true},
		{"pf_reference_confirmation_committed", PFReferenceAcquired, true, true},
		{"pf_active_committed", PFActive, true, true},
		{"pf_reference_cleanup_intent_committed", PFCleanupIntent, true, true},
		{"pf_reference_released_kernel", PFCleanupIntent, false, true},
		{"pf_reference_release_confirmation_committed", PFReferenceReleased, false, true},
		{"pf_anchor_emptied", PFAnchorRemovalIntent, false, false},
	} {
		t.Run(fixture.stage, func(t *testing.T) {
			path := ownedReferenceTestDirectory(t)
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRootPFReferenceEffectCrashChild$", "-test.v")
			child.Env = append(os.Environ(), "LEGACYWG_PF_REF_EFFECT_DIR="+path, "LEGACYWG_PF_REF_EFFECT_STAGE="+fixture.stage)
			pipe, err := child.StdoutPipe()
			if err != nil || child.Start() != nil {
				t.Fatal("actual reference child did not start")
			}
			defer func() { _ = child.Process.Kill() }()
			scanner := bufio.NewScanner(pipe)
			reached := false
			for scanner.Scan() {
				if scanner.Text() == "OWNED_PF_REFERENCE_CHECKPOINT" {
					reached = true
					break
				}
			}
			if !reached {
				_ = child.Wait()
				t.Fatal("actual reference SIGKILL checkpoint not reached")
			}
			if competing, err := directoryStore(t, path); err == nil {
				competing.Close()
				t.Fatal("live reference owner exclusive lock bypassed")
			}
			if child.Process.Kill() != nil {
				t.Fatal("actual reference owner SIGKILL failed")
			}
			_ = child.Wait()
			if child.ProcessState == nil || child.ProcessState.Success() {
				t.Fatal("reference owner survived SIGKILL")
			}
			store := realBootStore(t, path)
			defer store.Close()
			record, err := store.readPF(pfJournalFile)
			if err != nil || record == nil || record.PID != child.Process.Pid || record.Phase != fixture.phase {
				t.Fatal("durable reference owner/phase lost at kernel crash gap")
			}
			entries := fixturePFReferences(t, ctx)
			owned, err := selectPFReference(*record, entries)
			if err != nil || (owned != nil) != fixture.kernelReference || (record.Phase == PFReferenceIntent && record.Reference != 0) {
				t.Fatal("actual surviving/missing reference not distinguished from intent")
			}
			policy, err := readPFPolicy(ctx, record.Anchor, fixture.kernelReference)
			wantRules := pfDigest("")
			if fixture.kernelRules {
				wantRules = record.RulesSHA256
			}
			if err != nil || !policy.matches(*record) || policy.rules != wantRules || store.reconcile() == nil {
				t.Fatal("native kernel policy or ordinary recovery refusal not preserved")
			}
			if store.recoverPFLifecycle(ctx) != nil || store.pfResidue() || len(fixturePFReferences(t, ctx)) != 0 {
				t.Fatal("actual dead-owner reference/anchor recovery failed")
			}
			after, err := readDisabledPF(ctx, record.Anchor)
			if err != nil || !after.matches(*record) || after.rules != pfDigest("") || store.reconcile() != nil {
				t.Fatal("actual reference crash recovery baseline not restored")
			}
		})
	}
}

type pfForeignFixture struct {
	command *exec.Cmd
	input   io.WriteCloser
	decoder *json.Decoder
}

func startForeignPFFixture(t *testing.T, ctx context.Context) *pfForeignFixture {
	t.Helper()
	path := os.Getenv("LEGACYWG_PF_FOREIGN_TEST_HELPER")
	if path == "" {
		t.Fatal("compiled foreign-reference fixture unavailable")
	}
	command := exec.CommandContext(ctx, path)
	command.Env = []string{"GITHUB_ACTIONS=true", "PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal("private foreign-reference input pipe unavailable")
	}
	output, err := command.StdoutPipe()
	if err != nil || command.Start() != nil {
		t.Fatal("private foreign-reference fixture did not start")
	}
	fixture := &pfForeignFixture{command, input, json.NewDecoder(io.LimitReader(output, 16384))}
	var ready struct {
		Ready bool  `json:"ready"`
		PID   int   `json:"pid"`
		Epoch int64 `json:"epoch"`
	}
	if fixture.decoder.Decode(&ready) != nil || !ready.Ready || ready.PID != command.Process.Pid || ready.Epoch <= 0 {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal("foreign-reference fixture owner identity invalid")
	}
	return fixture
}

func TestRootPFReferenceOtherOwnerPreserved(t *testing.T) {
	requirePFReferenceCI(t)
	store := realBootStore(t, ownedReferenceTestDirectory(t))
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if store.stageDisabledPFAnchor(ctx) != nil || store.activatePFAnchor(ctx) != nil {
		t.Fatal("other-owner preservation own activation failed")
	}
	record, err := store.readPF(pfJournalFile)
	if err != nil || record == nil {
		t.Fatal("actual own active journal missing")
	}
	other := startForeignPFFixture(t, ctx)
	otherAcquired := false
	defer func() {
		if otherAcquired && other.command.ProcessState == nil {
			// Ask the still-live independent owner to release its own value.
			// No product recovery operation is allowed to delete this reference.
			if _, err := io.WriteString(other.input, "release\n"); err == nil {
				var released struct {
					Released bool `json:"released"`
				}
				_ = other.decoder.Decode(&released)
			}
		}
		_ = other.input.Close()
		_ = other.command.Process.Kill()
		_ = other.command.Wait()
	}()
	if _, err := io.WriteString(other.input, "acquire\n"); err != nil {
		t.Fatal("other-owner acquisition pipe failed")
	}
	var acquired struct {
		Acquired bool   `json:"acquired"`
		Token    uint64 `json:"token"`
	}
	if other.decoder.Decode(&acquired) != nil || !acquired.Acquired || acquired.Token == 0 {
		t.Fatal("actual other reference acquisition unconfirmed")
	}
	otherAcquired = true
	entries := fixturePFReferences(t, ctx)
	if len(entries) != 2 {
		t.Fatal("two actual independent owner references not observed")
	}
	var foreign pfReference
	for _, entry := range entries {
		if entry.token == acquired.Token && entry.pid == other.command.Process.Pid && entry.name == "legacywg-ref" {
			foreign = entry
		}
	}
	if foreign.token == 0 {
		t.Fatal("actual other PID/name/token tuple differs")
	}
	wrong := *record
	wrong.Reference = foreign.token
	if _, err := selectPFReference(wrong, entries); err == nil || !samePFReferences(entries, fixturePFReferences(t, ctx)) {
		t.Fatal("synthetic foreign-token mismatch adopted or changed references")
	}
	if store.recoverPFLifecycle(ctx) != nil || store.pfResidue() || !samePFReferences([]pfReference{foreign}, fixturePFReferences(t, ctx)) {
		t.Fatal("own shutdown altered the other actual owner reference")
	}
	policy, err := readPFPolicy(ctx, record.Anchor, true)
	if err != nil || !policy.matches(*record) || policy.rules != pfDigest("") {
		t.Fatal("other reference did not retain Enabled PF with own anchor removed")
	}
	if _, err := io.WriteString(other.input, "release\n"); err != nil {
		t.Fatal("other owner explicit release pipe failed")
	}
	var released struct {
		Released bool `json:"released"`
	}
	if other.decoder.Decode(&released) != nil || !released.Released || other.command.Wait() != nil {
		t.Fatal("other owner explicit release unconfirmed")
	}
	policy, err = readDisabledPF(ctx, record.Anchor)
	if err != nil || !policy.matches(*record) || policy.rules != pfDigest("") || len(fixturePFReferences(t, ctx)) != 0 {
		t.Fatal("final independent-owner cleanup baseline not restored")
	}
}
