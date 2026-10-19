//go:build linux

package service

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/guidance"
	"laneboss.io/laneboss/internal/v2/judge"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// Component input only. The separate root canary measures native identity.
type loopSeed struct{ stamp api.InstalledScheduler }

func (p *loopSeed) VerifyScheduler(ctx context.Context) (api.InstalledScheduler, error) {
	return p.stamp, ctx.Err()
}

func loopSetup(t *testing.T) (*fx.Fixture, api.Scope, api.LoopTurnSelector) {
	t.Helper()
	f := fx.ControlledChild(t)
	f.Opened(t)
	f.Ended(t)
	pick := loopScene(t, f)
	peer := &loopSeed{stamp: api.InstalledScheduler{Config: f.Deps.Config, Actor: api.Actor{Kind: "scheduler", ID: fx.ID(t)},
		CapabilityID: fx.ID(t), CapabilityGeneration: 1, InstallationGeneration: 1, BootID: "component-loop", PolicyGeneration: 1, ExpiresAt: fx.Expiry()}}
	scope, err := api.BindSchedulerScope(context.Background(), peer, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return f, scope, pick
}

func loopScene(t *testing.T, f *fx.Fixture) api.LoopTurnSelector {
	t.Helper()
	ctx := context.Background()
	setting := api.LoopRequest{Target: f.Reservation.Target, ExpectedGeneration: f.Lane.Generation, Enabled: true, IdleMessage: &f.Lane.Task, BackoffMS: 1}
	f.Admit(t, "lane.loop", setting)
	next := f.Lane
	next.Generation++
	event := f.Event(t, "lane.loop", setting)
	event.Actor, event.RequestedBy, event.OperationID, event.RequestID = f.Human.Actor, f.Human.Actor, "", f.Human.Request.RequestID
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Human, RawRequest: f.Raw,
		Compare: []api.Compare{{Kind: api.CompareLane, ID: next.LifeID, Generation: f.Lane.Generation}},
		Writes:  api.StateWrites{Lanes: []api.Lane{next}}, Events: []api.Event{event},
		Reply: &api.RPCReply{Result: fx.JSON(t, api.Operation{ID: f.Receipt.Operation.ID, Status: "succeeded", LifeID: next.LifeID, Run: next.Run})}}); err != nil {
		t.Fatal(err)
	}
	f.Lane = next
	page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: next.LifeID, Run: next.Run})
	if err != nil {
		t.Fatal(err)
	}
	pick := api.LoopTurnSelector{Target: f.Reservation.Target, ExpectedGeneration: next.Generation, PreviousLaunchID: next.LaunchID, CancellationEpoch: next.CancellationEpoch}
	for _, row := range page.Events {
		if row.Kind == "lane.loop" {
			pick.SettingEventID, pick.SettingSeq, pick.SettingOperationID = row.ID, row.Seq, row.OperationID
		}
		if row.Kind == "lane.ended" {
			pick.EndEventID, pick.EndSeq = row.ID, row.Seq
		}
	}
	return pick
}

func loopInputs(t *testing.T) (*fx.Fixture, api.LaunchPromptRequest) {
	t.Helper()
	ctx := context.Background()
	f, scope, pick := loopSetup(t)
	r, err := f.State.ReserveLaunch(ctx, scope, api.LaunchReservationRequest{Loop: &pick})
	if err != nil {
		t.Fatal(err)
	}
	f.Reservation = r
	f.Record, err = f.State.LaunchPlan(ctx, f.Execution, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	f.Claim, err = f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: r.Loop.PlanEffectID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()})
	if err != nil {
		t.Fatal(err)
	}
	return f, api.LaunchPromptRequest{ReservationID: r.ID, Lease: f.Claim}
}

func TestLoopInputs(t *testing.T) {
	f, request := loopInputs(t)
	ctx := context.Background()
	resolver, err := grants.New(grants.Dependencies{Config: f.Deps.Config, Store: f.State, Worker: &dataworker.Service{}, Clock: f.Deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.Resolve(ctx, f.Execution, api.GrantResolveRequest{ReservationID: f.Reservation.ID})
	if err != nil {
		t.Fatal("loop cannot resolve its fresh retained grant snapshot", err)
	}
	fresh, err := f.State.Grants(ctx, f.Reservation.GrantSetID)
	if err != nil || !reflect.DeepEqual(fresh, resolved) || fresh.Generation != f.Reservation.Loop.GrantGeneration {
		t.Fatal("loop resolver replaced its frozen snapshot", err)
	}
	previous, err := f.State.LaunchBinding(ctx, f.Reservation.PreviousLaunchID)
	if err != nil {
		t.Fatal(err)
	}
	old, err := f.State.LaunchPlan(ctx, f.Execution, previous.Recovery.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	inputs := *old.Inputs
	inputs.Grants, inputs.Sources.ReservationID = fresh, f.Reservation.ID
	next := f.Record
	next.Phase, next.Inputs, next.Generation = "sourced", &inputs, next.Generation+1
	cause := f.Intent(t, api.InternalLaunchPlan)
	cause.LogicalTurnID = f.Reservation.Loop.LogicalTurnID
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause,
		Writes:  api.StateWrites{LaunchPlans: []api.LaunchPlanRecord{next}},
		Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: f.Reservation.ID, Generation: f.Record.Generation}, {Kind: api.CompareGrants, ID: fresh.ID, Generation: fresh.Generation}},
		Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: f.Lane.LifeID, Epoch: f.Lane.CancellationEpoch}}}}); err != nil {
		t.Fatal("loop could not retain sourced inputs", err)
	}
	f.Record = next
	installPlanningOrg(t, f)
	input, err := f.State.LaunchBriefingInput(ctx, f.Execution, request)
	if err != nil || input.Lane == nil || input.Lane.Task != *f.Reservation.Loop.Setting.IdleMessage || input.Lane.BudgetRemaining != f.Reservation.Loop.BudgetRemaining || input.Lane.Session != f.Reservation.Loop.PreviousSession {
		t.Fatal("loop prompt lost exact task, budget or private history", err)
	}
	selector, err := guidance.New(guidance.Dependencies{Store: f.State, Judge: &judge.Service{}, Clock: f.Deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selector.LaunchGuidance(ctx, f.Execution, request); err != nil {
		t.Fatal("loop guidance could not retain its exact turn", err)
	}
	turn, err := f.State.Turn(ctx, f.Execution, f.Reservation.Target, f.Reservation.Loop.LogicalTurnID)
	if err != nil || turn.Trigger.Kind != "loop" || len(turn.MailIDs) != 0 || len(turn.Trigger.MailIDs) != 0 || turn.Trigger.CausingRun != f.Reservation.Loop.Selector.Target.Run ||
		!reflect.DeepEqual(turn.Trigger.CausingSeqs, []api.Sequence{f.Reservation.Loop.Selector.SettingSeq, f.Reservation.Loop.Selector.EndSeq}) {
		t.Fatal("loop turn lost its exact setting/end cause", err)
	}
	foreign := f.Execution
	foreign.Request = f.Human.Request
	if loaded, err := lstate.Load(ctx, f.State, f.Deps.Config, foreign, f.Reservation.ID); err == nil {
		if err := loaded.Close(); err != nil {
			t.Error(err)
		}
		t.Fatal("loop accepted a fabricated public request")
	}
}
