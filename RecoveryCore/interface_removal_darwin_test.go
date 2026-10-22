package recoverycore

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRootPFRuleAwaitOwnedInterfaceRemoval(t *testing.T) {
	f := newProtectedFixture(t)
	original := f.store.record
	raw, err := f.tunnel.File().SyscallConn()
	if err != nil {
		t.Fatal("interface removal descriptor unavailable")
	}
	lease := -1
	var duplicateErr error
	if raw.Control(func(fd uintptr) { lease, duplicateErr = unix.FcntlInt(fd, unix.F_DUPFD_CLOEXEC, 0) }) != nil || duplicateErr != nil || lease < 0 {
		t.Fatal("interface removal controlled descriptor hold failed")
	}
	defer func() {
		if lease >= 0 {
			_ = unix.Close(lease)
		}
	}()
	if f.tunnel.Close() != nil || f.store.Finish() == nil {
		t.Fatal("immediate Finish ignored the actually live leased interface")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if !t.Run("canceled_wait_preserves_journal", func(t *testing.T) {
		if f.store.FinishAfterClose(canceled) == nil || f.store.closed {
			t.Fatal("canceled interface wait released journal ownership")
		}
		record, err := f.store.read(journalFile)
		if err != nil || record == nil || *record != original {
			t.Fatal("canceled interface wait changed the journal")
		}
	}) {
		return
	}
	result := make(chan error, 1)
	go func() { result <- f.store.FinishAfterClose(context.Background()) }()
	joined := false
	defer func() {
		if !joined {
			select {
			case <-result:
			case <-time.After(4 * time.Second):
				t.Error("interface removal waiter did not join")
			}
		}
	}()
	if !t.Run("live_descriptor_does_not_release", func(t *testing.T) {
		select {
		case <-result:
			joined = true
			t.Fatal("post-close wait completed while original interface was held")
		case <-time.After(120 * time.Millisecond):
		}
		if admittedInterfaceNameAbsent(original.Interface) {
			t.Fatal("controlled descriptor did not hold the original interface")
		}
	}) {
		return
	}
	if unix.Close(lease) != nil {
		t.Fatal("interface removal controlled lease release failed")
	}
	lease = -1
	t.Run("actual_removal_finishes_journal", func(t *testing.T) {
		select {
		case err := <-result:
			joined = true
			if err != nil || !f.store.closed || !admittedInterfaceNameAbsent(original.Interface) || f.store.FinishAfterClose(context.Background()) != nil {
				t.Fatal("confirmed native disappearance did not finish idempotently")
			}
		case <-time.After(4 * time.Second):
			t.Fatal("native interface removal wait exceeded its bound")
		}
	})
}
