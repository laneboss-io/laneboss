//go:build linux

package admin

import (
	"context"
	"testing"
	"time"
)

// TestCodexAuthDuringOpenGate exercises the exact helper lock
// handoff used while a Codex child can already reach its lane socket after the
// native release and before the durable opened transition. The ordinary gate
// remains held throughout both controls; only operationMu is lent.
func TestCodexAuthDuringOpenGate(t *testing.T) {
	manager := &leaseManager{}

	openCtx, finishOpen := manager.lockHelperOperation(context.Background(), false)
	noLendCtx, cancelNoLend := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancelNoLend()
	noLendAcquired := make(chan struct{})
	go func() {
		_, release := manager.lockHelperOperation(noLendCtx, true)
		release()
		close(noLendAcquired)
	}()
	select {
	case <-noLendAcquired:
		finishOpen()
		t.Fatal("metadata authentication acquired open_gate state without its lock handoff")
	case <-noLendCtx.Done():
	}

	// The timed-out negative-control waiter is still blocked on operationMu.
	resume := lendCredentialOperation(openCtx, &manager.operationMu)
	select {
	case <-noLendAcquired:
	case <-time.After(time.Second):
		resume()
		finishOpen()
		t.Fatal("negative-control metadata waiter was not collectable")
	}
	resume()
	finishOpen()

	openCtx, finishOpen = manager.lockHelperOperation(context.Background(), false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	acquired := make(chan struct{})
	go func() {
		_, release := manager.lockHelperOperation(ctx, true)
		defer release()
		if manager.helperMu.TryLock() {
			manager.helperMu.Unlock()
			acquired <- struct{}{}
			return
		}
		close(acquired)
	}()
	resume = lendCredentialOperation(openCtx, &manager.operationMu)
	select {
	case <-acquired:
	case <-ctx.Done():
		resume()
		finishOpen()
		t.Fatalf("Codex identity self reached helper frame receive timeout: %v", ctx.Err())
	}
	resume()
	finishOpen()
}
