//go:build linux

package grants

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

type delegationWorker struct{ api.DataWorker }

func TestRetainedStarterSealedRealStore(t *testing.T) {
	f := fx.ControlledChild(t)
	f.Opened(t)
	ctx := context.Background()
	parentLane, err := f.State.Lane(ctx, f.Execution, api.LifeRef{LifeID: f.Lane.ParentLifeID})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := f.State.LaunchBinding(ctx, parentLane.LaunchID)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := f.State.LaunchPlan(ctx, f.Execution, binding.Recovery.PlanID)
	if err != nil || plan.Plan == nil {
		t.Fatal(err)
	}
	parent := *f
	parent.Lane, parent.Binding, parent.Record, parent.Reservation, parent.Plan, parent.Prepared = parentLane, binding, plan, plan.Reservation, *plan.Plan, binding.Prepared
	effect, err := f.State.Effect(ctx, f.Execution, plan.Handoff.Cause.EffectID)
	if err != nil || effect.Outcome == nil || effect.Outcome.Process == nil {
		t.Fatal(err)
	}
	parent.Process = *effect.Outcome.Process
	parent.Ended(t)
	service, err := New(Dependencies{Config: f.Deps.Config, Store: f.State, Worker: &delegationWorker{}, Clock: f.Deps.Clock})
	if err != nil {
		t.Fatal(err)
	}
	state := &lstate.State{Scope: f.Execution, Record: f.Record}
	for _, lifecycle := range []string{"accepted", "merged", "abandoned", "lost"} {
		before, err := f.State.Lane(ctx, f.Execution, api.LifeRef{LifeID: parentLane.LifeID})
		if err != nil {
			t.Fatal(err)
		}
		next := before
		next.State = lifecycle
		next.Generation++
		cause := parent.Intent(t, api.InternalLifecycleEffect)
		cause.ID = fx.ID(t)
		if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Lanes: []api.Lane{next}}, Compare: []api.Compare{{Kind: api.CompareLane, ID: next.LifeID, Generation: before.Generation}}, Events: []api.Event{parent.Event(t, "lane.state", api.StateEvent{From: before.State, To: next.State, Generation: next.Generation})}}); err != nil {
			t.Fatal(err)
		}
		err = service.retainedStarter(ctx, state, f.Lane)
		if lifecycle == "lost" {
			if err == nil {
				t.Fatal("lost ancestor borrowed a prior successful lease")
			}
			continue
		}
		if err != nil {
			t.Fatal("terminal authentic ancestor lost sealed prior scope", lifecycle, err)
		}
	}
}
