package recoverycore

import (
	"context"
	"time"
)

// Closing Darwin's utun control socket starts an asynchronous interface detach.
// Wait only for observation; never delete/down an interface or relax identity.
// A live same-name/index replacement remains refused for the whole bound.
func (store *Store) awaitInterfaceRemoval(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrRecoveryRequired
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if bounded.Err() != nil {
			return ErrRecoveryRequired
		}
		store.mutex.Lock()
		closed, record := store.closed, store.record
		store.mutex.Unlock()
		if closed {
			return nil
		}
		if record.Validate() != nil {
			return ErrRecoveryRequired
		}
		if interfaceGone(record) {
			return nil
		}
		select {
		case <-bounded.Done():
			return ErrRecoveryRequired
		case <-ticker.C:
		}
	}
}

// FinishAfterClose is for callers that have closed their own device. Finish
// remains a strict immediate check, including its final identity/record checks.
// Waiting does not authorize generic release of protected/PF/route ownership.
func (store *Store) FinishAfterClose(ctx context.Context) error {
	store.mutex.Lock()
	if store.closed {
		store.mutex.Unlock()
		return nil
	}
	forbidden := store.protection != nil || store.pfResidue() || store.endpointResidue()
	store.mutex.Unlock()
	if forbidden || store.awaitInterfaceRemoval(ctx) != nil {
		return ErrRecoveryRequired
	}
	return store.Finish()
}
