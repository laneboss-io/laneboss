//go:build linux

package service

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// The hook observes the plan produced by lifecycle; it never supplies one or
// replaces a writer response. The real writer validates and publishes it.
func (s *planningPolicyStore) Transact(ctx context.Context, tx api.Transaction) (api.Commit, error) {
	if s.planWriteHook != nil {
		for _, record := range tx.Writes.LaunchPlans {
			if record.Phase == "planned" && record.Plan != nil {
				s.planWriteHook(*record.Plan)
			}
		}
	}
	return s.Service.Transact(ctx, tx)
}

func TestHelperPlanWrite(t *testing.T) {
	for _, driver := range []api.Driver{api.DriverClaudock, api.DriverCodex} {
		t.Run(string(driver), func(t *testing.T) { helperPlanWrite(t, driver) })
	}
}

func helperPlanWrite(t *testing.T, driver api.Driver) {
	f, reservation, effect := scopeDriverFixture(t, 0, driver)
	state := &planningPolicyStore{Service: f.State, effect: effect.ID}
	planner := scopePlanSetup(t, state, f, effect, nil, func(p *successfulPlanPorts) {
		p.profileMode = "helper"
	})
	checked := false
	state.planWriteHook = func(plan api.LaunchPlan) {
		if err := api.ValidateLaunchPlan(plan); err != nil {
			t.Fatal("constructed plan failed its shape check before publication", err)
		}
		checked = true
		t.Log("actual constructed plan passes ValidateLaunchPlan before the real writer")
	}
	host := launchServer(t, f)
	host.deps.Store = state
	host.runtime = api.RuntimeServices{Store: state, LaunchPlanner: planner, Helper: &agentOwnerHelper{state: state},
		Worker: state.sourcePorts, Launcher: &agentOwnerLauncher{state: state}}
	t.Cleanup(func() {
		if err := host.Close(); err != nil {
			t.Error(err)
		}
	})
	claimant, err := wire.NewID()
	if err != nil {
		t.Fatal(err)
	}
	scope := api.Scope{Config: f.Deps.Config, Actor: api.Actor{Kind: "service", ID: claimant}, Source: "worker"}
	lease, err := state.ClaimEffect(context.Background(), scope, api.EffectClaimRequest{EffectID: effect.ID,
		ExpectedGeneration: 1, ClaimantID: scope.Actor.ID, Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	attempt := &effectAttempt{server: host, kind: "PlanLaunch"}
	ctx := api.WithHelperReasonObserver(context.Background(), attempt.observeHelperReason)
	outcome, err := host.runEffect(ctx, scope, lease)
	if err != nil || !checked || outcome.LaunchPlan == nil || outcome.Process == nil {
		t.Fatal("installed helper profile did not publish and open its actual plan", attempt.errorReason(err), err)
	}
	want := "codex-api"
	if driver == api.DriverClaudock {
		want = "claudock-helper"
	}
	if outcome.LaunchPlan.Runner.Slot.Mode != want {
		t.Fatal("broker did not issue the selected driver's public mode")
	}
	if _, err := state.CompleteEffect(ctx, scope, outcome); err != nil {
		t.Fatal("real planning parent did not complete", err)
	}
	operation, err := state.Operation(ctx, f.Execution, reservation.OperationID)
	if err != nil || operation.Status != "succeeded" || operation.Error != nil {
		t.Fatal("real operation did not retain its opened completion", err)
	}
}
