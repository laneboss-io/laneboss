package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type failedCalls struct {
	*launchFixtureStore
	calls int
}

func (store *failedCalls) FailPlan(ctx context.Context, tx api.Transaction, jobs []api.PlanCleanup) (api.Commit, error) {
	store.calls++
	return store.launchFixtureStore.FailPlan(ctx, tx, jobs)
}

func TestFailPreflight(t *testing.T) {
	for _, mode := range []string{"valid", "absent"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			if _, err := f.service.PlanLaunch(context.Background(), scope, request); err != nil {
				t.Fatal(err)
			}
			record = f.store.plans[record.Reservation.ID]
			if mode == "absent" {
				delete(f.store.metadata, launchObjectID(record.Reservation.ID, "result-credential-slot"))
			}
			store := &failedCalls{launchFixtureStore: f.store}
			f.service.deps.Store = store
			execution := &planExecution{service: f.service, scope: scope, lease: request.Lease, record: record}
			original := problem(api.CodeForbidden, "original planning refusal", "Retain the same allocation.")
			err := execution.failPlan(context.Background(), original)
			if mode == "absent" {
				if !errors.Is(err, original) || err == original || store.calls != 0 || len(f.store.failedWrites) != 0 || !reflect.DeepEqual(f.store.plans[record.Reservation.ID], record) {
					t.Fatalf("failed plan skipped its shared preflight: %v", err)
				}
				return
			}
			if err != original || store.calls != 1 || len(f.store.failedWrites) != 1 {
				t.Fatalf("shared failure port did not commit the original batch: %v", err)
			}
			write := f.store.failedWrites[0]
			if api.ValidateFailedPlanWrite(write.Transaction, write.Cleanup) != nil || api.ValidateTransactionShape(write.Transaction) == nil {
				t.Fatal("failed plan escaped the shared atomic writer boundary")
			}
		})
	}
}

func TestCleanupOwner(t *testing.T) {
	original := &api.Error{Code: api.CodeUnavailable, Message: "protected store unavailable", Retryable: true}
	got := cleanupIssue(original)
	want := *original
	want.Owner = "lb-v2-service"
	if !reflect.DeepEqual(*got, want) || original.Owner != "" || got == original {
		t.Fatal("cleanup lost the protected store error provenance")
	}
	owned := api.NotImplemented("stage-owner", "original producer")
	if cleanupIssue(owned) != owned {
		t.Fatal("cleanup replaced an existing dependency owner")
	}
}

type loopReply struct {
	*loopStore
	t        *testing.T
	mutation string
}

func (store loopReply) ReserveLaunch(ctx context.Context, scope api.Scope, request api.LaunchReservationRequest) (api.LaunchReservation, error) {
	r, err := store.loopStore.ReserveLaunch(ctx, scope, request)
	if err != nil {
		return r, err
	}
	r = launchClone(store.t, r)
	switch store.mutation {
	case "configured-by":
		r.Loop.ConfiguredBy.ID = "foreign-configurator"
	case "level":
		r.Level--
	case "role":
		r.Role = "foreign-role"
	case "previous-turn":
		r.Loop.PreviousLogicalTurnID = "foreign-turn"
	}
	return r, nil
}

func TestLoopReply(t *testing.T) {
	f, store, scope, target := readyLoop(t)
	f.service.deps.Store = loopReply{loopStore: store, t: t, mutation: "configured-by"}
	_, err := f.service.ReserveLoop(context.Background(), scope, target)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || len(store.ends) != 1 {
		t.Fatalf("loop accepted a foreign writer response: %v", err)
	}
}

func TestLoopReplyPins(t *testing.T) {
	for _, mutation := range []string{"level", "role", "previous-turn"} {
		t.Run(mutation, func(t *testing.T) {
			f, store, scope, target := readyLoop(t)
			f.service.deps.Store = loopReply{loopStore: store, t: t, mutation: mutation}
			_, err := f.service.ReserveLoop(context.Background(), scope, target)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity || len(store.ends) != 1 {
				t.Fatalf("loop accepted a returned %s pin: %v", mutation, err)
			}
		})
	}
}

func TestLoopClaim(t *testing.T) {
	f, _, scheduler, target := readyLoop(t)
	r, err := f.service.ReserveLoop(context.Background(), scheduler, target)
	if err != nil {
		t.Fatal(err)
	}
	scope, request := f.claim(t, f.store.plans[r.ID])
	request.Lease = launchClone(t, request.Lease)
	request.Lease.Record.Effect.Context.LogicalTurnID = "foreign-turn"
	f.store.effects[request.Lease.Record.Effect.ID] = request.Lease.Record
	execution := &planExecution{service: f.service, scope: scope, lease: request.Lease, record: f.store.plans[r.ID]}
	if err := execution.checkClaim(context.Background()); err == nil {
		t.Fatal("loop claim lost its original logical turn")
	}
}
