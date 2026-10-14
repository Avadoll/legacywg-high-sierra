package recoverycore

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestRootPFRuleLoaderCrashChild(t *testing.T) {
	path, role, point := os.Getenv("LEGACYWG_FILTER_CRASH_DIR"), os.Getenv("LEGACYWG_FILTER_CRASH_ROLE"), os.Getenv("LEGACYWG_FILTER_CRASH_POINT")
	if path == "" || (role != "stage" && role != "remove") || point == "" {
		t.Skip("explicit journal-bound loader crash child")
	}
	requirePFRuleCI(t)
	store := realBootStore(t, path)
	defer store.Close()
	ctx, stop := context.WithTimeout(context.Background(), 45*time.Second)
	defer stop()
	if role == "remove" {
		if store.stageDisabledPFAnchor(ctx) != nil || store.activatePFAnchor(ctx) != nil {
			t.Fatal("loader removal crash fixture activation failed")
		}
	}
	store.checkpoint = func(actual string) {
		if actual == point {
			fmt.Println("OWNED_FILTER_CRASH_CHECKPOINT")
			select {}
		}
	}
	var err error
	if role == "stage" {
		err = store.stageDisabledPFAnchor(ctx)
	} else {
		err = store.recoverPFLifecycle(ctx)
	}
	if err != nil {
		t.Fatal("loader crash fixture failed before requested checkpoint")
	}
	t.Fatal("loader crash checkpoint not reached")
}

func TestRootPFRuleLoaderCrashRecovery(t *testing.T) {
	requirePFRuleCI(t)
	for _, role := range []string{"stage", "remove"} {
		for _, point := range []string{"pf_filter_transaction_begin_kernel", "pf_filter_rules_staged_kernel", "pf_filter_transaction_committed_kernel"} {
			t.Run(role+"/"+point, func(t *testing.T) {
				path := ownedReferenceTestDirectory(t)
				ctx, stop := context.WithTimeout(context.Background(), 60*time.Second)
				defer stop()
				child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRootPFRuleLoaderCrashChild$", "-test.v")
				child.Env = append(os.Environ(), "LEGACYWG_FILTER_CRASH_DIR="+path, "LEGACYWG_FILTER_CRASH_ROLE="+role, "LEGACYWG_FILTER_CRASH_POINT="+point)
				pipe, err := child.StdoutPipe()
				if err != nil || child.Start() != nil {
					t.Fatal("journal-bound loader child unavailable")
				}
				defer func() { _ = child.Process.Kill() }()
				scanner := bufio.NewScanner(pipe)
				reached := false
				for scanner.Scan() {
					if scanner.Text() == "OWNED_FILTER_CRASH_CHECKPOINT" {
						reached = true
						break
					}
				}
				if !reached || child.Process.Kill() != nil {
					_ = child.Wait()
					t.Fatal("journal-bound loader actual SIGKILL point not reached")
				}
				_ = child.Wait()
				store := realBootStore(t, path)
				defer store.Close()
				record, err := store.readPF(pfJournalFile)
				phase := PFInstallIntent
				if role == "remove" {
					phase = PFAnchorRemovalIntent
				}
				if err != nil || record == nil || record.PID != child.Process.Pid || record.Phase != phase {
					t.Fatal("loader process death lost exact durable ownership/intent")
				}
				observed, err := readDisabledPF(ctx, record.Anchor)
				want := pfDigest("")
				if role == "stage" && point == "pf_filter_transaction_committed_kernel" || role == "remove" && point != "pf_filter_transaction_committed_kernel" {
					want = record.RulesSHA256
				}
				if err != nil || !observed.matches(*record) || observed.rules != want || len(fixturePFReferences(t, ctx)) != 0 {
					t.Fatal("loader process death changed expected active policy/baselines/references")
				}
				if store.recoverPFLifecycle(ctx) != nil || store.pfResidue() {
					t.Fatal("journal-bound loader crash cleanup refused")
				}
				after, err := readDisabledPF(ctx, record.Anchor)
				tree, treeErr := enumeratePFAnchors(ctx)
				if err != nil || treeErr != nil || !after.matches(*record) || after.rules != pfDigest("") || len(fixturePFReferences(t, ctx)) != 0 {
					t.Fatal("loader crash final baseline not restored")
				}
				for _, node := range tree {
					if node.path == record.Anchor {
						t.Fatal("loader crash journal retired with retained namespace")
					}
				}
			})
		}
	}
}
