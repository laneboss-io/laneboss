//go:build linux

package service

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestExpiredAgentPrepareKeepsParentOwner(t *testing.T) {
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
	state := &planningPolicyStore{Service: f.State, effect: effect.ID}
	planner := successfulScopePlanner(t, state, f, effect)
	host := launchServer(t, f)
	host.deps.Store, host.deps.Clock = state, clock
	launcher := &agentOwnerLauncher{state: state}
	host.runtime = api.RuntimeServices{Store: state, LaunchPlanner: planner, Helper: &admin.Service{}, Worker: state.sourcePorts, Launcher: launcher}
	t.Cleanup(func() {
		if err := host.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx := context.Background()
	scope := api.Scope{Config: f.Deps.Config, Actor: api.Actor{Kind: "service", ID: fx.ID(t)}, Source: "worker", PolicyGeneration: reservation.PolicyGeneration}
	parent, err := state.ClaimEffect(ctx, scope, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: scope.Actor.ID,
		Deadline: api.Timestamp(clock.Now().Add(30 * time.Second).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.PlanLaunch(ctx, scope, api.LaunchPlanRequest{Lease: parent})
	if err != nil {
		t.Fatal(err)
	}
	record, err := state.LaunchPlan(ctx, scope, reservation.ID)
	if err != nil || record.Phase != "spec_retained" {
		t.Fatal("prepare recovery did not retain its original sealed plan", err)
	}
	_, child, err := host.prepareAgent(ctx, scope, parent, record, host.runtime)
	if err != nil {
		t.Fatal(err)
	}
	foreign := child.Record.Effect
	request := *foreign.HelperPrepare
	request.PreparedSpecID = fx.ID(t)
	foreign.HelperPrepare = &request
	if owned, err := retainedAgentPrepare(ctx, state, scope, foreign); owned || err == nil {
		t.Fatal("foreign prepare selectors acquired the planning owner's deferral", err)
	} else {
		codeIs(t, err, api.CodeIntegrity)
	}
	clock.advance(31 * time.Second)
	pending, err := state.PendingEffects(ctx, api.CursorRequest{Limit: 200})
	found := false
	for _, queued := range pending {
		found = found || queued.ID == child.Record.Effect.ID
	}
	if err != nil || !found {
		t.Fatal("expired prepare child was not in the real startup/outbox inventory", err)
	}
	if result := host.reconcileEffect(ctx, child.Record.Effect, make(effectRetries)); result != attemptNext || host.fault != nil {
		t.Fatal("expired agent prepare escaped its parent and faulted generic reconciliation", host.fault)
	}
	actual, err := state.Effect(ctx, scope, child.Record.Effect.ID)
	if err != nil || !reflect.DeepEqual(actual, child.Record) {
		t.Fatal("generic reconciliation stole or completed the parent's prepare child", err)
	}
	scope.Actor.ID = fx.ID(t)
	parent, err = state.ClaimEffect(ctx, scope, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: parent.Record.Generation, ClaimantID: scope.Actor.ID,
		Deadline: api.Timestamp(clock.Now().Add(30 * time.Second).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	prepared, recovered, err := host.prepareAgent(ctx, scope, parent, record, host.runtime)
	if err != nil || recovered.ClaimID == child.ClaimID || recovered.Record.Generation <= child.Record.Generation {
		t.Fatal("original planning owner could not reclaim the unchanged prepare stage", err)
	}
	if _, err := host.bindAgent(api.WithEffectLease(ctx, parent), scope, parent, recovered, record, plan, prepared); err != nil {
		t.Fatal("recovered owner could not reach the real bound transition", err)
	}
	if err := host.completePreparedChild(ctx, scope, recovered, prepared); err != nil {
		t.Fatal(err)
	}
	bound, err := state.LaunchPlan(ctx, scope, reservation.ID)
	if err != nil || bound.Phase != "bound" {
		t.Fatal("parent recovery did not retain its bound launch", err)
	}
	if verified, err := state.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !verified.OK {
		t.Fatal("prepare recovery damaged the real store journal", err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	if owned, err := retainedAgentPrepare(ctx, state, scope, child.Record.Effect); owned || err == nil {
		t.Fatal("closed authoritative storage became a successful ownership deferral", err)
	}
}
