package lifecycle

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type dispatchAttemptKey struct{}
type dispatchAttempt struct{ id api.ID }

type dispatchStore struct {
	*fixtureStore
	owners  map[string]*dispatchAttempt
	done    map[string]chan struct{}
	awaited chan struct{}
}

func dispatchContext(t *testing.T) context.Context {
	t.Helper()
	return context.WithValue(context.Background(), dispatchAttemptKey{}, &dispatchAttempt{id: launchIDForTest()})
}

func (store *dispatchStore) ReserveRequest(ctx context.Context, request api.RequestReservation) (api.MutationReceipt, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	scope := request.Scope
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	domain := fixtureReceiptKey(scope, key)
	if prior, ok := store.receipts[domain]; ok {
		if !receiptMatches(scope, key, prior) {
			return api.MutationReceipt{}, launchConflict()
		}
		return prior, nil
	}
	var original api.Request
	if api.DecodeObject(request.RawRequest, &original) != nil || !reflect.DeepEqual(original, scope.Request) {
		return api.MutationReceipt{}, launchConflict()
	}
	attempt, ok := ctx.Value(dispatchAttemptKey{}).(*dispatchAttempt)
	if !ok {
		return api.MutationReceipt{}, launchConflict()
	}
	op := api.Operation{ID: launchIDForTest(), Status: "pending"}
	receipt := api.MutationReceipt{Config: scope.Config, Actor: scope.Actor, Key: key, PolicyGeneration: scope.PolicyGeneration,
		Operation: op, RawRequest: append([]byte{}, request.RawRequest...)}
	store.receipts[domain], store.operations[op.ID] = receipt, op
	store.owners[domain], store.done[domain] = attempt, make(chan struct{})
	return receipt, nil
}

func (store *dispatchStore) OwnsMutation(ctx context.Context, scope api.Scope, key api.RequestKey, operation api.ID) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	domain := fixtureReceiptKey(scope, key)
	receipt, ok := store.receipts[domain]
	if !ok || !receiptMatches(scope, key, receipt) || receipt.Operation.ID != operation {
		return false, launchConflict()
	}
	attempt, _ := ctx.Value(dispatchAttemptKey{}).(*dispatchAttempt)
	return attempt != nil && store.owners[domain] == attempt && receipt.Reply == nil, nil
}

func (store *dispatchStore) AwaitReceipt(ctx context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	store.mu.Lock()
	store.awaitCalls++
	done := store.done[fixtureReceiptKey(scope, key)]
	store.mu.Unlock()
	select {
	case store.awaited <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
		return api.MutationReceipt{}, ctx.Err()
	case <-done:
		return store.LookupReceipt(ctx, scope, key)
	}
}

func (store *dispatchStore) Transact(ctx context.Context, tx api.Transaction) (api.Commit, error) {
	commit, err := store.fixtureStore.Transact(ctx, tx)
	if err != nil {
		return api.Commit{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := api.RequestKey{Method: tx.Scope.Request.Method, IdempotencyKey: tx.Scope.Request.IdempotencyKey, RequestSHA256: tx.Scope.Request.RequestSHA256}
	if done := store.done[fixtureReceiptKey(tx.Scope, key)]; done != nil && commit.Reply != nil {
		select {
		case <-done:
		default:
			close(done)
		}
	}
	return commit, nil
}

func preReserveMutation(t *testing.T, f *fixture, scope *api.Scope) (context.Context, *dispatchStore, api.MutationReceipt) {
	t.Helper()
	store := &dispatchStore{fixtureStore: f.store, owners: map[string]*dispatchAttempt{}, done: map[string]chan struct{}{}, awaited: make(chan struct{}, 1)}
	f.service.deps.Store = store
	ctx := dispatchContext(t)
	raw, err := json.Marshal(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Frame = &fixtureFrame{raw: raw}
	receipt, err := store.ReserveRequest(ctx, api.RequestReservation{Scope: *scope, RawRequest: raw, Deadline: "2030-01-02T03:05:05Z"})
	if err != nil || receipt.Reply != nil || !validID(receipt.Operation.ID) {
		t.Fatalf("dispatcher fixture failed to reserve a pending operation: %v", err)
	}
	return ctx, store, receipt
}

func TestFreshMutationReceipt(t *testing.T) {
	for _, method := range []string{"stop", "mark"} {
		t.Run(method, func(t *testing.T) {
			f := newFixture(t)
			f.ended()
			var scope api.Scope
			var invoke func(context.Context) (api.Operation, error)
			if method == "stop" {
				lane := f.child
				lane.State = "running"
				f.store.lanes[lane.LifeID] = lane
				request := api.StopRequest{Target: f.target, ExpectedGeneration: lane.Generation, Reason: f.blob("dispatch-reason", "task", []byte("stop this retained run"))}
				scope = f.prepareScope("lane.stop", request, f.parent)
				invoke = func(ctx context.Context) (api.Operation, error) { return f.service.LaneStop(ctx, scope, request) }
			} else {
				review := fixtureReview(f)
				f.add("lane.reviewed", review, f.target.Run, "service", f.parent)
				request := api.MarkRequest{Target: f.target, ExpectedGeneration: f.child.Generation, State: "accepted", Review: review}
				scope = f.prepareScope("lane.mark", request, f.parent)
				invoke = func(ctx context.Context) (api.Operation, error) { return f.service.LaneMark(ctx, scope, request) }
			}
			owner, store, reserved := preReserveMutation(t, f, &scope)
			ctx, cancel := context.WithTimeout(owner, time.Second)
			defer cancel()
			operation, err := invoke(ctx)
			if err != nil || store.awaitCalls != 0 || len(store.transactions) != 1 {
				t.Fatalf("fresh dispatcher reservation waited for itself: %v", err)
			}
			if operation.ID != reserved.Operation.ID {
				t.Fatal("fresh mutation replaced its reserved operation")
			}
		})
	}
}

func TestPendingMutationRetry(t *testing.T) {
	f := newFixture(t)
	f.ended()
	lane := f.child
	lane.State = "running"
	f.store.lanes[lane.LifeID] = lane
	request := api.StopRequest{Target: f.target, ExpectedGeneration: lane.Generation, Reason: f.blob("retry-reason", "task", []byte("one retained stop"))}
	scope := f.prepareScope("lane.stop", request, f.parent)
	owner, store, _ := preReserveMutation(t, f, &scope)
	ctx, cancel := context.WithTimeout(dispatchContext(t), time.Second)
	defer cancel()
	type result struct {
		operation api.Operation
		err       error
	}
	finished := make(chan result, 1)
	go func() {
		operation, err := f.service.LaneStop(ctx, scope, request)
		finished <- result{operation, err}
	}()
	select {
	case <-store.awaited:
	case <-finished:
		t.Fatal("another executor's pending receipt bypassed await")
	case <-ctx.Done():
		t.Fatal("pending retry never reached its actual await")
	}
	f.service.mu.Lock()
	held := f.service.gates[f.target.LifeID] != nil
	f.service.mu.Unlock()
	if held {
		t.Fatal("pending retry held the life gate")
	}
	owner, stopOwner := context.WithTimeout(owner, time.Second)
	defer stopOwner()
	operation, err := f.service.LaneStop(owner, scope, request)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-finished:
		if result.err != nil || result.operation.ID != operation.ID || len(store.transactions) != 1 {
			t.Fatalf("pending retry did not replay its owner's result: %v", result.err)
		}
	case <-ctx.Done():
		t.Fatal("pending retry did not wake after owner completion")
	}
}

type dispatchAbsentStore struct{ api.StateStore }

func TestPendingDispatchAbsent(t *testing.T) {
	f := newFixture(t)
	request := api.StopRequest{Target: f.target, ExpectedGeneration: f.child.Generation, Reason: f.blob("absent-dispatch", "task", []byte("retain unknown ownership"))}
	scope := f.prepareScope("lane.stop", request, f.parent)
	owner, store, _ := preReserveMutation(t, f, &scope)
	f.service.deps.Store = dispatchAbsentStore{StateStore: store}
	ctx, cancel := context.WithTimeout(owner, time.Second)
	defer cancel()
	_, _, err := f.service.lookupReply(ctx, scope)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeNotImplemented || typed.Owner != "lb-v2-service" || store.awaitCalls != 0 || len(store.transactions) != 0 {
		t.Fatalf("unknown dispatcher ownership was treated as execution authority: %v", err)
	}
}
