package recoverycore

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestRootPFJournalDurabilityAndPreservation(t *testing.T) {
	path := ownedTestDirectory(t)
	store, err := directoryStore(t, path)
	if err != nil {
		t.Fatal("root PF store failed")
	}
	defer store.Close()
	record := testPFRecord(t)
	if store.writePF(record) != nil {
		t.Fatal("durable PF intent failed")
	}
	read, err := store.readPF(pfJournalFile)
	if err != nil || read == nil || *read != record {
		t.Fatal("durable PF identity changed")
	}
	other, err := directoryStore(t, path)
	if err == nil {
		other.Close()
		t.Fatal("PF journal exclusive lock bypassed")
	}
	old, _ := NewRecord(testBoot)
	old.PID = 2147483647
	oldData, _ := Encode(old)
	if os.WriteFile(filepath.Join(path, journalFile), oldData, 0600) != nil {
		t.Fatal("coexisting ephemeral metadata fixture failed")
	}
	before, _ := os.ReadFile(filepath.Join(path, pfJournalFile))
	if store.reconcile() == nil || store.begin() == nil || store.Finish() == nil {
		t.Fatal("unknown PF residue did not block ordinary cleanup")
	}
	after, _ := os.ReadFile(filepath.Join(path, pfJournalFile))
	utf, _ := os.ReadFile(filepath.Join(path, journalFile))
	if !bytes.Equal(before, after) || !bytes.Equal(utf, oldData) {
		t.Fatal("PF or utun evidence removed during blocked recovery")
	}
	next, _ := record.Advance(PFAnchorInstalled, 0, 0, 0)
	if store.writePF(next) != nil {
		t.Fatal("PF confirmation commit failed")
	}
	foreign := next
	foreign.RootSHA256 = string(bytes.Repeat([]byte{'b'}, 64))
	if store.writePF(foreign) == nil {
		t.Fatal("foreign baseline adopted")
	}
	// Unknown documents stay preserved even after a boot mismatch. No kernel
	// recovery/auto-removal can be inferred merely from a stale boot field.
	store.boot = "11111111-1111-1111-1111-111111111111"
	if store.reconcile() == nil {
		t.Fatal("stale boot authorized PF document deletion")
	}
}

func TestRootPFJournalRejectsUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "acl", "mode", "hardlink", "partial"} {
		t.Run(kind, func(t *testing.T) {
			path := ownedTestDirectory(t)
			store, err := directoryStore(t, path)
			if err != nil {
				t.Fatal("PF refusal store failed")
			}
			defer store.Close()
			record := testPFRecord(t)
			data, _ := EncodePF(record)
			name := filepath.Join(path, pfJournalFile)
			foreign := filepath.Join(path, "foreign")
			if os.WriteFile(foreign, data, 0600) != nil {
				t.Fatal("foreign marker failed")
			}
			switch kind {
			case "symlink":
				err = os.Symlink(foreign, name)
			case "hardlink":
				err = os.Link(foreign, name)
			default:
				err = os.WriteFile(name, data, 0600)
			}
			if err != nil {
				t.Fatal("PF unsafe metadata fixture failed")
			}
			if kind == "acl" {
				err = exec.Command("/bin/chmod", "+a", "everyone allow read", name).Run()
			}
			if kind == "mode" {
				err = os.Chmod(name, 0644)
			}
			if kind == "partial" {
				err = os.WriteFile(name, []byte("{"), 0600)
			}
			if err != nil {
				t.Fatal("PF unsafe condition failed")
			}
			if _, err := store.readPF(pfJournalFile); err == nil {
				t.Fatal("untrusted PF document accepted")
			}
			if store.reconcile() == nil {
				t.Fatal("untrusted PF residue silently removed")
			}
			marker, err := os.ReadFile(foreign)
			if err != nil || !bytes.Equal(marker, data) {
				t.Fatal("foreign marker modified")
			}
		})
	}
}

func TestRootPFCrashChild(t *testing.T) {
	path, stage := os.Getenv("LEGACYWG_PF_JOURNAL_TEST_DIR"), os.Getenv("LEGACYWG_PF_JOURNAL_TEST_STAGE")
	if path == "" || stage == "" {
		t.Skip("separate PF metadata crash child")
	}
	requireRoot(t)
	store, err := directoryStore(t, path)
	if err != nil {
		t.Fatal("PF crash child store failed")
	}
	defer store.Close()
	if os.Getenv("LEGACYWG_PF_UPDATE_CRASH") == "1" {
		record := testPFRecord(t)
		if store.writePF(record) != nil {
			t.Fatal("PF update initial intent failed")
		}
		for _, phase := range []PFPhase{PFAnchorInstalled, PFReferenceIntent, PFReferenceAcquired, PFActive} {
			after, before, reference := record.ReferenceAfter, record.ReferenceBefore, record.Reference
			if phase == PFReferenceIntent {
				after, before = 100, 105
			}
			if phase == PFReferenceAcquired {
				reference = 123
			}
			record, err = record.Advance(phase, after, before, reference)
			if err != nil || store.writePF(record) != nil {
				t.Fatal("PF update baseline metadata failed")
			}
		}
		pending, err := record.BeginRuleUpdate(string(bytes.Repeat([]byte{'b'}, 64)))
		if err != nil {
			t.Fatal("PF pending update metadata failed")
		}
		store.checkpoint = func(current string) {
			if current == stage {
				fmt.Fprintln(os.Stdout, "READY")
				for {
					time.Sleep(time.Minute)
				}
			}
		}
		if store.writePF(pending) != nil {
			t.Fatal("PF pending update save failed")
		}
		t.Fatal("PF update checkpoint not reached")
	}
	store.checkpoint = func(current string) {
		if current == stage {
			fmt.Fprintln(os.Stdout, "READY")
			for {
				time.Sleep(time.Minute)
			}
		}
	}
	if store.writePF(testPFRecord(t)) != nil {
		t.Fatal("PF crash child intent failed")
	}
	t.Fatal("requested PF crash checkpoint not reached")
}

func TestRootPFJournalCancellationAndRuleGenerations(t *testing.T) {
	path := ownedTestDirectory(t)
	store, err := directoryStore(t, path)
	if err != nil {
		t.Fatal("PF transition store failed")
	}
	defer store.Close()
	record := testPFRecord(t)
	if store.writePF(record) != nil {
		t.Fatal("PF transition intent failed")
	}
	next, err := record.Advance(PFAnchorRemovalIntent, 0, 0, 0)
	if err != nil || store.writePF(next) != nil {
		t.Fatal("durable cancellation intent failed")
	}
	removed, err := next.Advance(PFAnchorRemoved, 0, 0, 0)
	if err != nil || store.writePF(removed) != nil {
		t.Fatal("durable no-reference cleanup confirmation failed")
	}
	if store.reconcile() == nil {
		t.Fatal("metadata confirmation alone erased kernel-effect evidence")
	}
	// A second isolated transaction exercises update confirmation/rollback.
	path2 := ownedTestDirectory(t)
	other, err := directoryStore(t, path2)
	if err != nil {
		t.Fatal("PF update store failed")
	}
	defer other.Close()
	record = testPFRecord(t)
	if other.writePF(record) != nil {
		t.Fatal("PF update intent failed")
	}
	for _, phase := range []PFPhase{PFAnchorInstalled, PFReferenceIntent, PFReferenceAcquired, PFActive} {
		after, before, reference := record.ReferenceAfter, record.ReferenceBefore, record.Reference
		if phase == PFReferenceIntent {
			after, before = 100, 105
		}
		if phase == PFReferenceAcquired {
			reference = 123
		}
		record, err = record.Advance(phase, after, before, reference)
		if err != nil || other.writePF(record) != nil {
			t.Fatal("PF update baseline save failed")
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		pending, err := record.BeginRuleUpdate(string(bytes.Repeat([]byte{'b'}, 64)))
		if err != nil || other.writePF(pending) != nil {
			t.Fatal("PF pending rule save failed")
		}
		observed := record.RulesSHA256
		if attempt == 1 {
			observed = pending.NextRulesSHA256
		}
		record, err = pending.ResolveRuleUpdate(observed)
		if err != nil || other.writePF(record) != nil {
			t.Fatal("PF rule resolution save failed")
		}
	}
	if record.Generation != 2 {
		t.Fatal("PF confirmed generation not persisted")
	}
}

func TestRootPFJournalUpdateCrashPreservesBothCandidates(t *testing.T) {
	requireRoot(t)
	for _, stage := range []string{"pf_temporary_created", "pf_temporary_synced", "pf_renamed", "pf_directory_synced"} {
		t.Run(stage, func(t *testing.T) {
			path := ownedTestDirectory(t)
			executable, err := os.Executable()
			if err != nil {
				t.Fatal("PF update executable unavailable")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "-test.run=^TestRootPFCrashChild$", "-test.v")
			command.Env = append(os.Environ(), "LEGACYWG_PF_JOURNAL_TEST_DIR="+path, "LEGACYWG_PF_JOURNAL_TEST_STAGE="+stage, "LEGACYWG_PF_UPDATE_CRASH=1")
			output, err := command.StdoutPipe()
			if err != nil {
				t.Fatal("PF update pipe failed")
			}
			if command.Start() != nil {
				t.Fatal("PF update child failed")
			}
			scanner := bufio.NewScanner(output)
			ready := false
			for scanner.Scan() {
				if scanner.Text() == "READY" {
					ready = true
					break
				}
			}
			if !ready {
				command.Wait()
				t.Fatal("PF update durable checkpoint not reached")
			}
			if command.Process.Kill() != nil {
				command.Wait()
				t.Fatal("PF update SIGKILL failed")
			}
			if command.Wait() == nil {
				t.Fatal("PF update child not killed")
			}
			store, err := directoryStore(t, path)
			if err != nil {
				t.Fatal("PF update crash lock unavailable")
			}
			defer store.Close()
			main, err := store.readPF(pfJournalFile)
			if err != nil || main == nil {
				t.Fatal("PF original/pending main metadata lost")
			}
			if stage == "pf_temporary_created" || stage == "pf_temporary_synced" {
				if main.Phase != PFActive || main.Generation != 1 {
					t.Fatal("PF active rules changed before rename")
				}
			}
			pending := main
			if stage == "pf_temporary_synced" {
				pending, err = store.readPF(pfTemporaryFile)
				if err != nil {
					t.Fatal("PF synced update intent unreadable")
				}
			}
			if stage != "pf_temporary_created" {
				if pending == nil || pending.Phase != PFRuleUpdateIntent || pending.Generation != 1 || pending.RulesSHA256 != string(bytes.Repeat([]byte{'a'}, 64)) || pending.NextRulesSHA256 != string(bytes.Repeat([]byte{'b'}, 64)) {
					t.Fatal("PF update candidate identities lost")
				}
			}
			before, err := os.ReadFile(filepath.Join(path, pfJournalFile))
			if err != nil {
				t.Fatal("PF crash main vanished")
			}
			if store.reconcile() == nil {
				t.Fatal("PF pending update auto-cleared")
			}
			after, err := os.ReadFile(filepath.Join(path, pfJournalFile))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("PF pending update evidence modified")
			}
		})
	}
}
func TestRootPFJournalCrashPreservesUnknownEffects(t *testing.T) {
	requireRoot(t)
	for _, stage := range []string{"pf_temporary_created", "pf_temporary_synced", "pf_renamed", "pf_directory_synced"} {
		t.Run(stage, func(t *testing.T) {
			path := ownedTestDirectory(t)
			executable, err := os.Executable()
			if err != nil {
				t.Fatal("PF test executable unavailable")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "-test.run=^TestRootPFCrashChild$", "-test.v")
			command.Env = append(os.Environ(), "LEGACYWG_PF_JOURNAL_TEST_DIR="+path, "LEGACYWG_PF_JOURNAL_TEST_STAGE="+stage)
			output, err := command.StdoutPipe()
			if err != nil {
				t.Fatal("PF crash pipe failed")
			}
			if command.Start() != nil {
				t.Fatal("PF crash child failed")
			}
			scanner := bufio.NewScanner(output)
			ready := false
			for scanner.Scan() {
				if scanner.Text() == "READY" {
					ready = true
					break
				}
			}
			if !ready {
				command.Wait()
				t.Fatal("PF durable checkpoint not reached")
			}
			if command.Process.Kill() != nil {
				command.Wait()
				t.Fatal("PF controlled SIGKILL failed")
			}
			if command.Wait() == nil {
				t.Fatal("PF child not killed")
			}
			store, err := directoryStore(t, path)
			if err != nil {
				t.Fatal("PF post-crash lock unavailable")
			}
			defer store.Close()
			name := pfJournalFile
			if stage == "pf_temporary_created" || stage == "pf_temporary_synced" {
				name = pfTemporaryFile
			}
			before, err := os.ReadFile(filepath.Join(path, name))
			if err != nil {
				t.Fatal("PF effect intent disappeared")
			}
			if stage != "pf_temporary_created" {
				record, err := store.readPF(name)
				if err != nil || record == nil || record.Phase != PFInstallIntent {
					t.Fatal("synced PF intent not readable")
				}
			}
			if store.reconcile() == nil || store.begin() == nil {
				t.Fatal("dead process authorized PF intent discard")
			}
			after, err := os.ReadFile(filepath.Join(path, name))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("PF effect evidence changed after crash")
			}
		})
	}
}
