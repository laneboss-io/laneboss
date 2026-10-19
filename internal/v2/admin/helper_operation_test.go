package admin

import (
	"context"
	"testing"
	"time"
)

// This tests the merged lock protocol only. Native authentication and the
// worker's live descriptor guard retain their separate Linux canaries.
func TestHelperMetadataLockHandoff(t *testing.T) {
	manager := &leaseManager{}
	ctx, finish := manager.lockHelperOperation(context.Background(), false)
	if manager.helperMu.TryLock() {
		manager.helperMu.Unlock()
		finish()
		t.Fatal("ordinary helper request did not retain its canonical gate")
	}
	resume := lendCredentialOperation(ctx, &manager.operationMu)
	acquired := make(chan func(), 1)
	go func() {
		_, release := manager.lockHelperOperation(context.Background(), true)
		acquired <- release
	}()
	select {
	case release := <-acquired:
		if manager.helperMu.TryLock() {
			manager.helperMu.Unlock()
			release()
			resume()
			finish()
			t.Fatal("metadata reader released the pending request's canonical gate")
		}
		release()
	case <-time.After(time.Second):
		// Recover the deliberately blocked control before failing, so this
		// test never strands a goroutine or returns a locked executor thread.
		resume()
		finish()
		select {
		case release := <-acquired:
			release()
		case <-time.After(time.Second):
			t.Fatal("metadata lock control could not collect its waiter")
		}
		t.Fatal("credential metadata reader stayed blocked on the worker's canonical helper gate")
	}
	resume()
	if manager.operationMu.TryLock() {
		manager.operationMu.Unlock()
		finish()
		t.Fatal("credential operation resumed without regaining its state lock")
	}
	finish()
	if !manager.helperMu.TryLock() {
		t.Fatal("completed helper request retained its canonical gate")
	}
	manager.helperMu.Unlock()
	if !manager.operationMu.TryLock() {
		t.Fatal("completed helper request retained its state lock")
	}
	manager.operationMu.Unlock()
}
