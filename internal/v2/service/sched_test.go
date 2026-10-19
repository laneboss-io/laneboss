//go:build linux

package service

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/lifecycle"
)

// Only the outside observation is a component input. Scheduler selection,
// lifecycle eligibility, reservation and the store's journal are real.
type loopObserver struct {
	api.Launcher
	end api.ProcessObservation
}

func (o *loopObserver) Observe(ctx context.Context, handle api.ProcessHandle) (api.ProcessObservation, error) {
	if err := ctx.Err(); err != nil {
		return api.ProcessObservation{}, err
	}
	if handle != o.end.Handle {
		return api.ProcessObservation{}, serviceError(api.CodeForbidden, "component observation selected another process")
	}
	return o.end, nil
}

func TestSchedDue(t *testing.T) {
	f, scope, pick := loopSetup(t)
	ctx := context.Background()
	page, err := f.State.Events(ctx, f.Execution, api.EventTailRequest{LifeID: pick.Target.LifeID, Run: pick.Target.Run})
	if err != nil {
		t.Fatal(err)
	}
	var end api.RunEndEvent
	for _, event := range page.Events {
		if event.ID == pick.EndEventID {
			if err := api.DecodeObject(event.Payload, &end); err != nil {
				t.Fatal(err)
			}
		}
	}
	coordinator, err := lifecycle.New(lifecycle.Dependencies{Store: f.State, Identity: &authFixture{}, Clock: f.Deps.Clock, Launcher: &loopObserver{end: end.Observation}})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{options: Options{Config: f.Deps.Config}, deps: Dependencies{Store: f.State, Clock: f.Deps.Clock}, controller: f.Execution.Actor.ID}
	if err := s.reserveDueLoops(ctx, scope, coordinator); err != nil {
		t.Fatal("scheduler did not dispatch a due durable loop", err)
	}
	if err := s.reserveDueLoops(ctx, scope, coordinator); err != nil {
		t.Fatal("scheduler replay failed", err)
	}
	plans, err := f.State.LaunchInventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, plan := range plans {
		if plan.Reservation.Loop == nil {
			continue
		}
		count++
		if plan.Reservation.Loop.Selector != pick || plan.Reservation.RequestedBy != scope.Actor {
			t.Fatal("scheduler reserved a different durable cause")
		}
	}
	if count != 1 {
		t.Fatal("scheduler did not create exactly one loop", count)
	}
}
