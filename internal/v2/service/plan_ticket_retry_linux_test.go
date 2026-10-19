//go:build linux

package service

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestPlanLaunchDeferredTicketReclaim(t *testing.T) {
	for _, ttl := range []time.Duration{time.Hour, 10 * time.Second} {
		t.Run(ttl.String(), func(t *testing.T) {
			f, reservation, effect := scopePlanningFixtureTicketTTL(t, ttl)
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
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			state := &planningPolicyStore{Service: f.State, effect: effect.ID, stop: cancel}
			planner := successfulScopePlanner(t, state, f, effect)
			claims := &planReconcileStore{Service: f.State, effect: effect.ID, clock: clock, shortFirst: true, stop: cancel}
			var issued api.GrantSet
			var firstTicketReads int
			state.sourcePorts.afterSources = func() error {
				if issued.ID != "" {
					return nil
				}
				// Admission, protected ticket reads, deterministic issuance and
				// actual admin source verification have all succeeded. Only the
				// external source port defers; no authority step is replaced.
				issued, err = f.State.Grants(ctx, reservation.GrantSetID)
				if err != nil {
					t.Fatal(err)
				}
				firstTicketReads = len(state.tickets)
				if firstTicketReads < 4 || len(claims.claims) != 1 {
					t.Fatal("deferral did not follow the actual ticket and issuance steps")
				}
				clock.advance(31 * time.Second)
				return &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-admin", Message: "component source temporarily unavailable", Retryable: true}
			}
			host := fixtureServer(t)
			host.options.Config, host.deps.Store, host.deps.Clock = f.Deps.Config, claims, clock
			host.runtime = api.RuntimeServices{Store: claims, LaunchPlanner: &observeSuccessfulPlanning{LaunchPlanner: planner, state: state, stop: cancel},
				Helper: &admin.Service{}, Worker: &dataworker.Service{}, Launcher: &healthLauncher{}}
			host.reconcileLoop(ctx)
			if host.fault != nil || errors.Is(ctx.Err(), context.DeadlineExceeded) || state.planned == nil {
				t.Fatal("deferred ticket operation did not advance under its reclaimed planning effect", host.fault, state.planningErr)
			}
			if len(claims.claims) != 2 || claims.claims[0].ClaimID == claims.claims[1].ClaimID ||
				claims.claims[0].Record.ClaimantID == claims.claims[1].Record.ClaimantID || len(state.tickets) <= firstTicketReads {
				t.Fatal("retry did not recheck the consumed ticket under a fresh actual claimant")
			}
			for _, claim := range claims.claims {
				if !bytes.Equal(fx.JSON(t, claim.Record.Effect), fx.JSON(t, effect)) {
					t.Fatal("reclaim changed the original effect, operation or reservation")
				}
			}
			retained, err := f.State.LaunchPlan(context.Background(), f.Execution, reservation.ID)
			if err != nil || retained.Phase != "spec_retained" || retained.Plan == nil || retained.Handoff == nil ||
				!reflect.DeepEqual(retained.Reservation, reservation) || !reflect.DeepEqual(retained.Inputs.Grants, issued) {
				t.Fatal("retry reissued grants or lost its original reservation and completed plan", err)
			}
			receipt, err := f.State.LaunchReceipt(context.Background(), f.Execution, api.LaunchReceiptRequest{ReservationID: reservation.ID})
			if err != nil || !bytes.Equal(receipt.RawRequest, f.Raw) {
				t.Fatal("retry changed the original receipt bytes", err)
			}
			old := claims.claims[0]
			staleScope := f.Execution
			staleScope.Actor.ID = old.Record.ClaimantID
			_, err = planner.PlanLaunch(context.Background(), staleScope, api.LaunchPlanRequest{Lease: old})
			codeIs(t, err, api.CodeConflict)
			if err := host.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Defer only after the real planner has retained every stage and its spec.
// Reclaim must revalidate authority without producing any replacement stage.
type deferRetainedTicketPlan struct {
	api.LaunchPlanner
	t      *testing.T
	state  *planningPolicyStore
	clock  *planReconcileClock
	before api.LaunchPlanRecord
}

func (p *deferRetainedTicketPlan) PlanLaunch(ctx context.Context, scope api.Scope, request api.LaunchPlanRequest) (api.LaunchPlan, error) {
	plan, err := p.LaunchPlanner.PlanLaunch(ctx, scope, request)
	if err != nil || p.before.Reservation.ID != "" {
		return plan, err
	}
	p.before, err = p.state.LaunchPlan(ctx, scope, plan.Reservation.ID)
	if err != nil || p.before.Phase != "spec_retained" || p.before.Plan == nil || p.before.Handoff == nil {
		p.t.Fatal("deferral did not follow actual completed stage retention", err)
	}
	p.clock.advance(31 * time.Second)
	return api.LaunchPlan{}, &api.Error{Code: api.CodeUnavailable, Owner: "lb-v2-admin", Message: "component handoff temporarily unavailable", Retryable: true}
}

func TestPlanLaunchDeferredRetainedStages(t *testing.T) {
	f, reservation, effect := scopePlanningFixtureTicketTTL(t, 10*time.Second)
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
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	state := &planningPolicyStore{Service: f.State, effect: effect.ID, stop: cancel}
	planner := successfulScopePlanner(t, state, f, effect)
	deferred := &deferRetainedTicketPlan{LaunchPlanner: planner, t: t, state: state, clock: clock}
	claims := &planReconcileStore{Service: f.State, effect: effect.ID, clock: clock, stop: cancel}
	host := fixtureServer(t)
	host.options.Config, host.deps.Store, host.deps.Clock = f.Deps.Config, claims, clock
	host.runtime = api.RuntimeServices{Store: claims, LaunchPlanner: &observeSuccessfulPlanning{LaunchPlanner: deferred, state: state, stop: cancel},
		Helper: &admin.Service{}, Worker: &dataworker.Service{}, Launcher: &healthLauncher{}}
	host.reconcileLoop(ctx)
	if host.fault != nil || errors.Is(ctx.Err(), context.DeadlineExceeded) || state.planned == nil || len(claims.claims) != 2 ||
		claims.claims[0].Record.ClaimantID == claims.claims[1].Record.ClaimantID || len(state.tickets) < 10 {
		t.Fatal("retained-stage retry did not revalidate the ticket under a fresh claimant", host.fault, state.planningErr)
	}
	after, err := f.State.LaunchPlan(context.Background(), f.Execution, reservation.ID)
	if err != nil || !reflect.DeepEqual(after, deferred.before) || !reflect.DeepEqual(*state.planned, *deferred.before.Plan) || len(state.credentialClaims) != 2 {
		t.Fatal("retry replaced retained grants, materialization, prompt, slot, injection, capture or spec", err)
	}
	turn, err := f.State.Turn(context.Background(), f.Execution, reservation.Target, effect.Context.LogicalTurnID)
	if err != nil || turn.Generation != 2 || turn.GuidanceID == "" || turn.Task != f.Start.Task {
		t.Fatal("retry changed the completed guidance turn", err)
	}
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
}
