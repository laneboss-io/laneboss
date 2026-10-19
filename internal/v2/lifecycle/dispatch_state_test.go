package lifecycle

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestDispatchReceiptStates(t *testing.T) {
	f := newFixture(t)
	request := api.StopRequest{Target: f.target, ExpectedGeneration: f.child.Generation, Reason: f.blob("dispatch-state", "task", []byte("one invocation"))}
	scope := f.scope("lane.stop", request, f.parent)
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	receipt, err := f.store.LookupReceipt(context.Background(), scope, key)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := f.store.OwnsMutation(context.Background(), scope, key, receipt.Operation.ID)
	if err != nil || !owned {
		t.Fatalf("fresh invocation lost its reserved pending receipt: %v", err)
	}
	retry := scope
	retry.Frame = &fixtureFrame{raw: append([]byte{}, scope.Frame.Bytes()...)}
	owned, err = f.store.OwnsMutation(context.Background(), retry, key, receipt.Operation.ID)
	if err != nil || owned {
		t.Fatalf("same connection retry acquired the original invocation: %v", err)
	}
	fixtureRetainedReply(f, scope, receipt.Operation)
	owned, err = f.store.OwnsMutation(context.Background(), scope, key, receipt.Operation.ID)
	if err != nil || owned {
		t.Fatalf("completed reply retained pending invocation ownership: %v", err)
	}
}

func TestLaunchReplayOtherInvocation(t *testing.T) {
	f := newLaunchFixture(t)
	f.store.receiptAwaited = make(chan struct{}, 1)
	retry := f.scope
	retry.Frame = &fixtureFrame{raw: append([]byte{}, f.scope.Frame.Bytes()...)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	type result struct {
		operation api.Operation
		found     bool
		err       error
	}
	finished := make(chan result, 1)
	go func() {
		operation, found, err := f.service.launchReplay(ctx, retry)
		finished <- result{operation, found, err}
	}()
	select {
	case <-f.store.receiptAwaited:
	case <-finished:
		t.Fatal("launch retry skipped its protected wait")
	case <-ctx.Done():
		t.Fatal("launch retry never reached receipt await")
	}
	operation, err := f.service.LaneStart(context.Background(), f.scope, f.request)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-finished:
		if got.err != nil || !got.found || got.operation != operation || f.store.reservationCalls != 1 {
			t.Fatalf("launch retry replaced its owner's retained reply: %v", got.err)
		}
	case <-ctx.Done():
		t.Fatal("launch retry did not wake on the retained reply")
	}
}

func TestCommitNeedsReservation(t *testing.T) {
	f := newFixture(t)
	f.ended()
	review := fixtureReview(f)
	f.add("lane.reviewed", review, f.target.Run, "service", f.parent)
	request := api.MarkRequest{Target: f.target, ExpectedGeneration: f.child.Generation, State: "accepted", Review: review}
	scope := f.prepareScope("lane.mark", request, f.parent)
	event, err := f.service.event(scope, f.child, "lane.state", api.StateEvent{From: f.child.State, To: "accepted", Generation: f.child.Generation + 1, ReviewID: review.ID}, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.service.commitLifecycle(context.Background(), scope, f.child, []api.Event{event}, nil)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || typed.Message != "mutation has no dispatcher reservation" || len(f.store.transactions) != 0 {
		t.Fatalf("public mutation committed without its dispatcher reservation: %v", err)
	}
}
