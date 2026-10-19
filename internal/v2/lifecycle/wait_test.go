package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestAwaitReceiptCancel(t *testing.T) {
	f := newFixture(t)
	request := api.LoopRequest{Target: f.target, ExpectedGeneration: f.child.Generation, BackoffMS: 100}
	scope := f.scope("lane.loop", request, f.parent)
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	f.store.receiptAwaited = make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := f.store.AwaitReceipt(ctx, scope, key); finished <- err }()
	select {
	case <-f.store.receiptAwaited:
	case <-time.After(time.Second):
		t.Fatal("receipt wait never reached its pending channel")
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("receipt wait ignored cancellation: %v", err)
		}
	case <-time.After(time.Second):
		// Release the model's real channel on a failing control as well.
		fixtureRetainedReply(f, scope, api.Operation{ID: "released-operation", LifeID: f.target.LifeID, Run: f.target.Run, Status: "succeeded"})
		t.Fatal("receipt wait ignored cancellation")
	}
	retained, err := f.store.LookupReceipt(context.Background(), scope, key)
	if err != nil || retained.Reply != nil || len(f.store.transactions) != 0 {
		t.Fatalf("cancelled receipt wait published a reply: %v", err)
	}
}

func TestAwaitReceiptCancelled(t *testing.T) {
	f := newFixture(t)
	request := api.LoopRequest{Target: f.target, ExpectedGeneration: f.child.Generation, BackoffMS: 100}
	scope := f.scope("lane.loop", request, f.parent)
	fixtureRetainedReply(f, scope, api.Operation{ID: "completed-operation", LifeID: f.target.LifeID, Run: f.target.Run, Status: "succeeded"})
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := f.store.AwaitReceipt(ctx, scope, key)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled receipt wait returned retained success: %v", err)
	}
}
