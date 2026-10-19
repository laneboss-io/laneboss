package watchdog

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type automaticJournal struct{ *journalStore }

func (m *automaticJournal) Lanes(_ context.Context, scope api.Scope, request api.ListRequest) (api.LanePage, error) {
	m.check(scope)
	if request.Limit < 1 || request.Limit > 200 || request.Cursor != "" {
		m.t.Fatal("automatic scan lost its bounded inventory")
	}
	return api.LanePage{Lanes: []api.Lane{m.lane}}, nil
}

func automaticPass(t *testing.T, s *Service) error {
	t.Helper()
	driver, ok := any(s).(interface{ ReconcileAutomatic(context.Context) error })
	if !ok {
		t.Fatal("watchdog has no installed automatic dispatcher")
	}
	return driver.ReconcileAutomatic(context.Background())
}

func TestAutomaticDurableWait(t *testing.T) {
	r, state, probe := newJournal(t)
	r.s.deps.Store = &automaticJournal{state}
	room := r.broker.rooms["profile-b"]
	room.Available = false
	r.broker.rooms["profile-b"] = room
	if _, err := r.s.ObserveLimit(context.Background(), r.signal); err != nil {
		t.Fatal(err)
	}
	before := state.lane
	for i := 0; i < 2; i++ {
		restartService(t, r)
		if err := automaticPass(t, r.s); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(before, state.lane) || state.writeCalls != 1 || len(probe.requests) != 0 {
		t.Fatal("automatic restart reset its durable wait or dispatched early")
	}
	r.clock.at = r.clock.at.Add(5 * time.Second)
	room.Available = true
	r.broker.rooms["profile-b"] = room
	if err := automaticPass(t, r.s); err != nil {
		t.Fatal(err)
	}
	if state.writeCalls != 2 || len(probe.requests) != 1 || probe.requests[0].IntentID != r.s.intentID(r.signal.Target) {
		t.Fatal("restored room did not dispatch the original continuation once")
	}
	if err := r.s.Cancel(context.Background(), r.signal.Target); err != nil {
		t.Fatal(err)
	}
	if err := automaticPass(t, r.s); err != nil {
		t.Fatal(err)
	}
	if len(probe.requests) != 1 {
		t.Fatal("automatic dispatcher revived a cancelled continuation")
	}
}

func TestAutomaticCompletedRun(t *testing.T) {
	r, state, probe := newJournal(t)
	r.s.deps.Store = &automaticJournal{state}
	r.addEvent("lane.ended", api.RunEndEvent{LaunchID: state.lane.LaunchID, Reason: "exit", Observation: r.launcher.observation, BudgetRemaining: state.lane.BudgetRemaining})
	if err := automaticPass(t, r.s); err != nil {
		t.Fatal(err)
	}
	if len(probe.requests) != 1 || state.writeCalls != 1 || r.broker.acquireCalls != 0 {
		t.Fatal("automatic classifier did not submit one retained handoff without acquiring a loose slot")
	}
}

func TestFramedRun(t *testing.T) {
	r, state, probe := newJournal(t)
	r.s.deps.Store = &automaticJournal{state}
	var frame api.CaptureRecord
	if err := json.Unmarshal(r.store.events[2].Payload, &frame); err != nil {
		t.Fatal(err)
	}
	r.store.events[2].Kind = "capture.framed"
	raw := frame
	raw.ID, raw.Coverage = "raw-source", "partial"
	r.addEvent("capture.appended", raw)
	r.addEvent("lane.ended", api.RunEndEvent{LaunchID: state.lane.LaunchID, Reason: "exit", Observation: r.launcher.observation, BudgetRemaining: state.lane.BudgetRemaining})
	if err := automaticPass(t, r.s); err != nil {
		t.Fatal("derived provider frames were not consumed", err)
	}
	if len(probe.requests) != 1 || state.writeCalls != 1 || r.broker.acquireCalls != 0 {
		t.Fatal("framed run did not submit its one fenced continuation")
	}
}
