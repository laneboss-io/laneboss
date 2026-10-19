//go:build linux

package service

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/policy"
	"laneboss.io/laneboss/internal/v2/secrets"
	"laneboss.io/laneboss/internal/v2/secrets/native"
	"laneboss.io/laneboss/internal/v2/secrets/testdir"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
	"laneboss.io/laneboss/internal/v2/templates"
)

// The observer calls the real planner and stops only after validating its
// complete retained output. Native prepare/open is a later boundary: completing
// the PlanLaunch effect there would require an opened plan and actual process.
type observeSuccessfulPlanning struct {
	api.LaunchPlanner
	state *planningPolicyStore
	stop  context.CancelFunc
}

func TestLaunchOperationPointLookup(t *testing.T) {
	f, request := sourcedPromptFixture(t)
	ctx := context.Background()
	view, err := f.State.BeginRead(ctx, f.Execution)
	if err != nil {
		t.Fatal(err)
	}
	scope := f.Execution
	scope.ReadView = view
	actual, err := f.State.LaunchPlanForOperation(ctx, scope, f.Reservation.OperationID)
	if err != nil || actual.Reservation.ID != request.ReservationID || actual.Reservation.OriginalRequest != f.Reservation.OriginalRequest {
		t.Fatal("operation point lookup lost its exact protected launch reservation", err)
	}
	missing, err := f.State.LaunchPlanForOperation(ctx, scope, fx.ID(t))
	codeIs(t, err, api.CodeNotFound)
	if missing.Reservation.ID != "" {
		t.Fatal("operation lookup returned a plan for an absent operation")
	}
	borrowed := scope
	borrowed.Actor.ID = fx.ID(t)
	foreign, err := f.State.LaunchPlanForOperation(ctx, borrowed, f.Reservation.OperationID)
	if err == nil || foreign.Reservation.ID != "" {
		t.Fatal("operation lookup accepted a borrowed read view")
	}
	if err := view.Close(); err != nil {
		t.Fatal(err)
	}
	foreign, err = f.State.LaunchPlanForOperation(ctx, scope, f.Reservation.OperationID)
	if err == nil || foreign.Reservation.ID != "" {
		t.Fatal("operation lookup accepted a closed read view")
	}
}

func TestPlanningReclaimedClaimRefused(t *testing.T) {
	f, reservation, effect := scopePlanningFixture(t)
	ctx := context.Background()
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	clock := &planReconcileClock{}
	f.Deps.Clock = clock
	var err error
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal(err)
	}
	old, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1,
		ClaimantID: f.Execution.Actor.ID, Deadline: api.Timestamp(clock.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(2 * time.Minute)
	freshScope := f.Execution
	freshScope.Actor.ID = fx.ID(t)
	fresh, err := f.State.ClaimEffect(ctx, freshScope, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: old.Record.Generation,
		ClaimantID: freshScope.Actor.ID, Deadline: api.Timestamp(clock.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
	if err != nil || fresh.ClaimID == old.ClaimID || fresh.Record.Generation <= old.Record.Generation {
		t.Fatal("actual reclaim did not replace the expired attempt", err)
	}
	claim := api.PlanningClaim(reservation.ID, old)
	renderer, err := templates.New(templates.Dependencies{Store: f.State, Policy: &policy.Service{}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	briefing, err := renderer.LaunchBriefing(ctx, f.Execution, api.LaunchPromptRequest{ReservationID: reservation.ID, Lease: old})
	codeIs(t, err, api.CodeConflict)
	if briefing.Markdown.ID != "" {
		t.Fatal("template retained a prompt under an actually reclaimed lease")
	}
	authority, err := admin.CheckLaunchPlanningAuthority(ctx, f.State, f.Deps.Config, claim)
	codeIs(t, err, api.CodeConflict)
	if authority.Reservation.ID != "" {
		t.Fatal("administrator accepted an actually reclaimed lease")
	}
	backend, err := native.New(native.Dependencies{Directory: testdir.New(t), KeyHandle: fx.ID(t), Config: f.Deps.Config, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Error(err)
		}
	})
	broker, err := secrets.New(secrets.Dependencies{Backend: backend, Store: f.State, Human: planningCredentialBoundary{}, ProjectionIdentity: planningCredentialBoundary{},
		Config: f.Deps.Config, ServiceScope: f.Execution, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	slot, err := broker.AcquireLaunch(ctx, api.LaunchProfileRequest{Claim: claim, HelperLeaseID: fx.ID(t), Target: reservation.Target, Grant: f.Ceiling.Profiles[0]})
	codeIs(t, err, api.CodeConflict)
	if slot.ID != "" {
		t.Fatal("credentials returned a slot under an actually reclaimed lease")
	}
	injection, err := broker.InjectLaunch(ctx, api.LaunchInjectionRequest{Claim: claim, HelperLeaseID: fx.ID(t), Target: reservation.Target, Grants: []api.SecretGrant{}})
	codeIs(t, err, api.CodeConflict)
	if len(injection.SlotIDs) != 0 {
		t.Fatal("credentials returned material under an actually reclaimed lease")
	}
	current, err := f.State.Effect(ctx, freshScope, effect.ID)
	if err != nil || !reflect.DeepEqual(current, fresh.Record) {
		t.Fatal("stale consumers changed the actual replacement claim", err)
	}
}

func (o *observeSuccessfulPlanning) PlanLaunch(ctx context.Context, scope api.Scope, request api.LaunchPlanRequest) (api.LaunchPlan, error) {
	plan, err := o.LaunchPlanner.PlanLaunch(ctx, scope, request)
	if err != nil {
		o.state.planningErr = err
		return plan, err
	}
	if err := api.ValidateLaunchPlan(plan); err != nil {
		return api.LaunchPlan{}, err
	}
	current, err := o.state.Effect(ctx, scope, request.Lease.Record.Effect.ID)
	if err != nil {
		return api.LaunchPlan{}, err
	}
	if !reflect.DeepEqual(current, request.Lease.Record) {
		return api.LaunchPlan{}, serviceError(api.CodeIntegrity, "planning completed after losing its actual durable lease")
	}
	o.state.planned, o.state.planningLease = &plan, request.Lease
	o.stop()
	return plan, nil
}

func TestPlanningCalleeClaimControls(t *testing.T) {
	f, request := sourcedPromptFixture(t)
	// A second real public admission/reservation in the same store proves
	// foreign selection is refused even when that effect and claim exist.
	other := fx.NewIn(t, f.State, f.Deps)
	f.State = other.State
	other.Reserve(t)
	ctx := context.Background()
	renderer, err := templates.New(templates.Dependencies{Store: f.State, Policy: &policy.Service{}, Clock: fx.Clock{}})
	if err != nil {
		t.Fatal(err)
	}
	backend, err := native.New(native.Dependencies{Directory: testdir.New(t), KeyHandle: fx.ID(t), Config: f.Deps.Config, Clock: fx.Clock{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Error(err)
		}
	})
	broker, err := secrets.New(secrets.Dependencies{Backend: backend, Store: f.State, Config: f.Deps.Config,
		ServiceScope: f.Execution, Human: planningCredentialBoundary{}, Clock: fx.Clock{}, ProjectionIdentity: planningCredentialBoundary{}})
	if err != nil {
		t.Fatal(err)
	}
	grant := f.Record.Inputs.Grants.Profiles[0]
	grant.Provider = "component-provider" // Pass the profile shape gate to exercise claim authentication.
	for _, mutation := range []string{"stale_generation", "foreign_reservation_effect", "foreign_claim_id"} {
		t.Run(mutation, func(t *testing.T) {
			selected := request
			switch mutation {
			case "stale_generation":
				selected.Lease.Record.Generation--
			case "foreign_claim_id":
				selected.Lease.ClaimID = fx.ID(t)
			case "foreign_reservation_effect":
				selected.Lease = other.Claim
			}
			claim := api.PlanningClaim(request.ReservationID, selected.Lease)
			briefing, err := renderer.LaunchBriefing(ctx, f.Execution, selected)
			if err == nil || briefing.Markdown.ID != "" {
				t.Fatal("template accepted a foreign or stale planning claim")
			}
			record, err := admin.CheckLaunchPlanningAuthority(ctx, f.State, f.Deps.Config, claim)
			codeIs(t, err, api.CodeConflict)
			if record.Reservation.ID != "" {
				t.Fatal("administrator returned authority for a refused planning claim")
			}
			slot, err := broker.AcquireLaunch(ctx, api.LaunchProfileRequest{Claim: claim, HelperLeaseID: fx.ID(t), Target: f.Reservation.Target, Grant: grant})
			codeIs(t, err, api.CodeConflict)
			if slot.ID != "" {
				t.Fatal("credentials returned a slot for a refused planning claim")
			}
			injection, err := broker.InjectLaunch(ctx, api.LaunchInjectionRequest{Claim: claim, HelperLeaseID: fx.ID(t), Target: f.Reservation.Target, Grants: []api.SecretGrant{}})
			codeIs(t, err, api.CodeConflict)
			if len(injection.SlotIDs) != 0 {
				t.Fatal("credentials returned material for a refused planning claim")
			}
		})
	}
	current, err := f.State.Effect(ctx, f.Execution, request.Lease.Record.Effect.ID)
	if err != nil || !reflect.DeepEqual(current, request.Lease.Record) {
		t.Fatal("claim controls changed the live durable attempt", err)
	}
}
