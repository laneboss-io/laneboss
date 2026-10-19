//go:build linux

package store_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/store"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// This source models the private producer for writer tests. Native producer
// authentication has its own Linux canary; labels cannot bind this source.
type loopPeer struct {
	value api.InstalledScheduler
	err   error
}

func (p *loopPeer) VerifyScheduler(ctx context.Context) (api.InstalledScheduler, error) {
	if err := ctx.Err(); err != nil {
		return api.InstalledScheduler{}, err
	}
	return p.value, p.err
}

func loopReady(t *testing.T, changes ...func(*api.LoopRequest)) (*fx.Fixture, *loopPeer, api.Scope, api.LoopTurnSelector) {
	t.Helper()
	f := fx.ControlledChild(t)
	f.Opened(t)
	f.Ended(t)
	setting := api.LoopRequest{Target: f.Reservation.Target, ExpectedGeneration: f.Lane.Generation, Enabled: true, IdleMessage: &f.Lane.Task, BackoffMS: 1}
	for _, change := range changes {
		if change != nil {
			change(&setting)
		}
	}
	f.Admit(t, "lane.loop", setting)
	next := f.Lane
	next.Generation++
	event := f.Event(t, "lane.loop", setting)
	event.Actor, event.RequestedBy = f.Human.Actor, f.Human.Actor
	event.OperationID, event.RequestID = "", f.Human.Request.RequestID
	_, err := f.State.Transact(context.Background(), api.Transaction{Scope: f.Human, RawRequest: f.Raw,
		Compare: []api.Compare{{Kind: api.CompareLane, ID: next.LifeID, Generation: f.Lane.Generation}},
		Writes:  api.StateWrites{Lanes: []api.Lane{next}}, Events: []api.Event{event},
		Reply: &api.RPCReply{Result: fx.JSON(t, api.Operation{ID: f.Receipt.Operation.ID, Status: "succeeded", LifeID: next.LifeID, Run: next.Run})}})
	if err != nil {
		t.Fatal("real loop setting failed", err)
	}
	f.Lane = next
	page, err := f.State.Events(context.Background(), f.Execution, api.EventTailRequest{LifeID: next.LifeID, Run: next.Run})
	if err != nil {
		t.Fatal(err)
	}
	selector := api.LoopTurnSelector{Target: f.Reservation.Target, ExpectedGeneration: next.Generation, CancellationEpoch: next.CancellationEpoch, PreviousLaunchID: next.LaunchID}
	for _, row := range page.Events {
		if row.Kind == "lane.loop" {
			selector.SettingEventID, selector.SettingSeq, selector.SettingOperationID = row.ID, row.Seq, row.OperationID
		}
		if row.Kind == "lane.ended" {
			selector.EndEventID, selector.EndSeq = row.ID, row.Seq
		}
	}
	p := &loopPeer{value: api.InstalledScheduler{Config: f.Deps.Config, Actor: api.Actor{Kind: "scheduler", ID: fx.ID(t)}, CapabilityID: fx.ID(t), CapabilityGeneration: 1, InstallationGeneration: 1, BootID: "loop-test-boot", PolicyGeneration: 1, ExpiresAt: fx.Expiry()}}
	scope, err := api.BindSchedulerScope(context.Background(), p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return f, p, scope, selector
}

func TestLoopWrite(t *testing.T) {
	f, _, scope, selector := loopReady(t)
	first, err := f.State.ReserveLaunch(context.Background(), scope, api.LaunchReservationRequest{Loop: &selector})
	if err != nil {
		t.Fatal("private loop writer refused actual setting and end", err)
	}
	if first.Loop == nil || first.RequestedBy != scope.Actor || first.Target.Run != selector.Target.Run+1 || first.Loop.ConfiguredBy != f.Human.Actor || first.Loop.BudgetRemaining != f.Lane.BudgetRemaining {
		t.Fatal("loop lost actual scheduler, configurator, run or budget")
	}
	if err := api.ValidateLaunchReservation(first); err != nil {
		t.Fatal(err)
	}
	second, err := f.State.ReserveLaunch(context.Background(), scope, api.LaunchReservationRequest{Loop: &selector})
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("loop replay created another reservation", err)
	}
	effects, err := f.State.PendingEffects(context.Background(), api.CursorRequest{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, effect := range effects {
		if effect.PlanLaunch != nil && effect.PlanLaunch.ReservationID == first.ID {
			count++
			if effect.Context.RequestedBy != scope.Actor || effect.Context.LogicalTurnID != first.Loop.LogicalTurnID {
				t.Fatal("loop effect borrowed another requester")
			}
		}
	}
	if count != 1 {
		t.Fatal("loop did not retain exactly one planning effect", count)
	}
	if result, err := f.State.Verify(context.Background(), api.VerifyRequest{Scope: "all"}); err != nil || !result.OK {
		t.Fatal("loop damaged real-store integrity", err)
	}
}

func TestLoopFences(t *testing.T) {
	for _, cell := range []string{"stale", "foreign", "epoch", "revoked", "missing", "early", "disabled", "budget", "policy", "nonquiet", "parent"} {
		t.Run(cell, func(t *testing.T) {
			var change func(*api.LoopRequest)
			if cell == "early" {
				change = func(setting *api.LoopRequest) { setting.BackoffMS = 3600000 }
			} else if cell == "disabled" {
				change = func(setting *api.LoopRequest) {
					setting.Enabled, setting.IdleMessage, setting.BackoffMS = false, nil, 0
				}
			}
			f, p, scope, selector := loopReady(t, change)
			before, err := f.State.LaunchInventory(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			switch cell {
			case "stale":
				selector.ExpectedGeneration++
			case "foreign":
				selector.EndEventID = fx.ID(t)
			case "epoch":
				selector.CancellationEpoch++
			case "revoked":
				p.err = &api.Error{Code: api.CodeForbidden, Message: "producer revoked"}
			case "missing":
				selector.SettingEventID = fx.ID(t)
			case "budget":
				lane := f.Lane
				lane.BudgetRemaining.WallMS = 0
				f.Replace(t, "lane", lane.LifeID, lane.Generation, lane)
			case "policy":
				policy, err := f.State.Policy(context.Background(), f.Execution)
				if err != nil {
					t.Fatal(err)
				}
				policy.Generation++
				policy.SHA256 = ""
				raw, err := api.CanonicalJSON(fx.JSON(t, policy))
				if err != nil {
					t.Fatal(err)
				}
				policy.SHA256 = fx.Digest(raw)
				f.Replace(t, "policy", api.ID(f.Deps.Config), policy.Generation, policy)
			case "nonquiet":
				measured := f.Observation(t, "exited")
				one, exit := uint64(1), 0
				measured.Observation.Survivors, measured.Observation.ExitCode = &one, &exit
				if err := f.State.RecordLaunchObservation(context.Background(), f.Lane.LaunchID, measured); err != nil {
					t.Fatal(err)
				}
			case "parent":
				parent, err := f.State.Lane(context.Background(), f.Execution, api.LifeRef{LifeID: f.Lane.ParentLifeID})
				if err != nil {
					t.Fatal(err)
				}
				parent.State, parent.Generation = "accepted", parent.Generation+1
				f.Replace(t, "lane", parent.LifeID, parent.Generation, parent)
			}
			_, err = f.State.ReserveLaunch(context.Background(), scope, api.LaunchReservationRequest{Loop: &selector})
			if err == nil {
				t.Fatal("loop accepted " + cell)
			}
			code := api.CodeConflict
			if cell == "revoked" || cell == "parent" {
				code = api.CodeForbidden
			} else if cell == "nonquiet" {
				code = api.CodeContainmentUnknown
			}
			launchCode(t, err, code)
			after, err := f.State.LaunchInventory(context.Background())
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("refused loop changed reservations", err)
			}
		})
	}
}

func TestLoopInput(t *testing.T) {
	f, _, scope, selector := loopReady(t)
	r, err := f.State.ReserveLaunch(context.Background(), scope, api.LaunchReservationRequest{Loop: &selector})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := f.State.LaunchReceipt(context.Background(), f.Execution, api.LaunchReceiptRequest{ReservationID: r.ID})
	if err != nil || receipt.Actor != scope.Actor || receipt.Operation.ID != r.OperationID || receipt.Reply == nil {
		t.Fatal("loop lost its private durable receipt", err)
	}
	loaded, err := lstate.Load(context.Background(), f.State, f.Deps.Config, f.Execution, r.ID)
	if err != nil {
		t.Fatal("loop canonical input cannot be loaded", err)
	}
	if loaded.Request.Method != "" || !reflect.DeepEqual(loaded.Record.Reservation, r) {
		t.Fatal("loop was interpreted as a public request")
	}
	if err := loaded.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLoopReopen(t *testing.T) {
	f, _, scope, selector := loopReady(t)
	ctx := context.Background()
	first, err := f.State.ReserveLaunch(ctx, scope, api.LaunchReservationRequest{Loop: &selector})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.State.Close(); err != nil {
		t.Fatal(err)
	}
	f.State, err = store.New(f.Deps)
	if err != nil {
		t.Fatal("loop could not recover its original private receipt", err)
	}
	again, err := f.State.ReserveLaunch(ctx, scope, api.LaunchReservationRequest{Loop: &selector})
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatal("restart lost the exact causal-end claim", err)
	}
	page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: first.Target.LifeID, Run: first.Target.Run})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range page.Events {
		if event.Kind == "loop.reserved" {
			count++
			if err := api.ValidateLoopReservedEvent(event, first); err != nil {
				t.Fatal(err)
			}
		}
	}
	if count != 1 {
		t.Fatal("restart appended another loop reservation", count)
	}
	if result, err := f.State.Verify(ctx, api.VerifyRequest{Scope: "all"}); err != nil || !result.OK {
		t.Fatal("recovered loop failed integrity", err)
	}
}

func TestLoopRace(t *testing.T) {
	f, _, scope, selector := loopReady(t)
	f.Admit(t, "lane.turn", api.TurnRequest{Target: selector.Target, ExpectedGeneration: f.Lane.Generation,
		IdleMessage: &f.Lane.Task, MailIDs: []api.ID{}, Budget: f.Lane.BudgetRemaining})
	manual := f.ReservationRequest(t)
	type attempt struct {
		r   api.LaunchReservation
		err error
	}
	start := make(chan struct{})
	results := make(chan attempt, 2)
	go func() {
		<-start
		r, err := f.State.ReserveLaunch(context.Background(), scope, api.LaunchReservationRequest{Loop: &selector})
		results <- attempt{r, err}
	}()
	go func() {
		<-start
		r, err := f.State.ReserveLaunch(context.Background(), f.Human, manual)
		results <- attempt{r, err}
	}()
	close(start)
	winners := 0
	for i := 0; i < 2; i++ {
		result := <-results
		if result.err == nil {
			winners++
			if result.r.Target != (api.LifeRef{LifeID: selector.Target.LifeID, Run: selector.Target.Run + 1}) {
				t.Fatal("race selected another next run")
			}
		} else {
			launchCode(t, result.err, api.CodeConflict)
		}
	}
	if winners != 1 {
		t.Fatal("manual turn and loop did not have exactly one winner", winners)
	}
	plans, err := f.State.LaunchInventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, plan := range plans {
		if plan.Reservation.Target.LifeID == selector.Target.LifeID && plan.Reservation.Target.Run == selector.Target.Run+1 {
			count++
		}
	}
	if count != 1 {
		t.Fatal("race left competing next-run reservations", count)
	}
}
