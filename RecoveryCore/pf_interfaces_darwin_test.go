package recoverycore

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

func TestRootPFRuleForeignInterfaceSkipRefused(t *testing.T) {
	requirePFRuleCI(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	store := realBootStore(t, ownedReferenceTestDirectory(t))
	defer store.Close()
	anchor := "com.apple/legacywg-0123456789abcdef0123456789abcdef"
	baseline, err := readDisabledPF(ctx, anchor)
	if err != nil || baseline.rules != pfDigest("") || len(fixturePFReferences(t, ctx)) != 0 {
		t.Fatal("foreign skip fixture requires unchanged disabled baseline")
	}
	// Owned by this harness, deliberately outside the Store's interface owner.
	// No real foreign/physical interface flag is modified by the experiment.
	foreign, err := tun.CreateTUN("utun", 1280)
	if err != nil {
		t.Fatal("foreign skip controlled interface unavailable")
	}
	defer foreign.Close()
	name, err := foreign.Name()
	if err != nil {
		t.Fatal("foreign skip controlled identity unavailable")
	}
	fd, err := openPFReferences(ctx)
	if err != nil {
		t.Fatal("foreign skip fixture descriptor unavailable")
	}
	defer unix.Close(fd)
	flagged := false
	defer func() {
		if flagged {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if fixtureChangeOwnSkip(cleanup, fd, foreign, false) != nil {
				t.Error("controlled foreign flag cleanup refused")
			}
		}
	}()
	entries, err := readPFInterfaces(ctx)
	found := false
	for _, entry := range entries {
		if entry.name == name {
			found = entry.flags == 0 && entry.states == 0 && entry.rules == 1
		}
	}
	if err != nil || !found || requireUnskippedPFInterfaces(ctx) != nil {
		t.Fatal("complete read-only interface observation differs from fresh own fixture")
	}
	if fixtureChangeOwnSkip(ctx, fd, foreign, true) != nil {
		t.Fatal("controlled foreign skip flag unavailable")
	}
	flagged = true
	if !t.Run("skip_observed_and_policy_refused", func(t *testing.T) {
		entries, err := readPFInterfaces(ctx)
		found := false
		for _, entry := range entries {
			if entry.name == name {
				found = entry.flags == fixturePFSkip && entry.states == 0 && entry.rules == 1
			}
		}
		if err != nil || !found || requireUnskippedPFInterfaces(ctx) == nil {
			t.Fatal("foreign skip not observed or unexpectedly admitted")
		}
		if _, err := readDisabledPF(ctx, anchor); err == nil {
			t.Fatal("disabled-policy baseline claimed filterability with foreign skip")
		}
		if store.stageDisabledPFAnchor(ctx) == nil || store.pfResidue() {
			t.Fatal("foreign skip did not refuse before own journal/policy effects")
		}
		observed, err := fixtureReadPFInterface(ctx, fd, name)
		if err != nil || observed != (fixturePFInterface{fixturePFSkip, 0, 1}) || len(fixturePFReferences(t, ctx)) != 0 {
			t.Fatal("foreign skip refusal changed flag/reference ownership")
		}
	}) {
		return
	}
	if fixtureChangeOwnSkip(ctx, fd, foreign, false) != nil {
		t.Fatal("controlled foreign skip clear failed")
	}
	flagged = false
	t.Run("original_baseline_preserved", func(t *testing.T) {
		after, err := readDisabledPF(ctx, anchor)
		if err != nil || after != baseline || store.pfResidue() || len(fixturePFReferences(t, ctx)) != 0 {
			t.Fatal("foreign skip refusal changed policy/journal/reference baseline")
		}
	})
}
