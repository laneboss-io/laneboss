//go:build linux

package service

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestCaptureWorkerRunLifetime(t *testing.T) {
	f, reservation, effect := scopePlanningFixture(t)
	clock := &planReconcileClock{}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.Deps.Clock = clock
	var err error
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	state := &planningPolicyStore{Service: f.State, effect: effect.ID}
	planner := successfulScopePlanner(t, state, f, effect)
	scope := f.Execution
	claim, err := f.State.ClaimEffect(ctx, scope, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: scope.Actor.ID,
		Deadline: api.Timestamp(clock.Now().Add(30 * time.Second).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.PlanLaunch(ctx, scope, api.LaunchPlanRequest{Lease: claim})
	if err != nil {
		t.Fatal("real planner did not reach capture issuance", err)
	}
	worker, err := f.State.WorkerLease(ctx, scope, plan.Capture.WorkerLeaseID)
	if err != nil {
		t.Fatal(err)
	}
	planningEnd, err := time.Parse(time.RFC3339Nano, string(claim.ExpiresAt))
	if err != nil {
		t.Fatal(err)
	}
	captureEnd, err := time.Parse(time.RFC3339Nano, string(worker.ExpiresAt))
	if err != nil || !captureEnd.After(planningEnd.Add(time.Duration(plan.Budget.WallMS)*time.Millisecond)) {
		t.Fatal("capture worker expires before the authorized run and drain after planning", err)
	}
	clock.advance(31 * time.Second)
	freshScope := scope
	freshScope.Actor.ID = fx.ID(t)
	fresh, err := f.State.ClaimEffect(ctx, freshScope, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: claim.Record.Generation, ClaimantID: freshScope.Actor.ID,
		Deadline: api.Timestamp(clock.Now().Add(30 * time.Second).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := planner.PlanLaunch(ctx, freshScope, api.LaunchPlanRequest{Lease: fresh})
	if err != nil || !reflect.DeepEqual(replayed, plan) {
		t.Fatal("reclaim replaced the original capture producer", err)
	}
	again, err := f.State.WorkerLease(ctx, freshScope, worker.ID)
	if err != nil || !reflect.DeepEqual(again, worker) || !captureEnd.After(clock.Now()) || reservation.ID != plan.Reservation.ID {
		t.Fatal("reclaim renewed or expired the independently retained capture job", err)
	}
	if _, err := planner.PlanLaunch(ctx, scope, api.LaunchPlanRequest{Lease: claim}); err == nil {
		t.Fatal("longer capture lifetime renewed a stale planner's mutation authority")
	}
}
