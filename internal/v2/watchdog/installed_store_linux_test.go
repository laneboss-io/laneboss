//go:build linux

package watchdog

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// These are real-store integration regressions, with explicit component
// launch/capture receipts. They do not claim native confinement or vendor auth.
func TestInstalledWatchdogReads(t *testing.T) {
	f := fx.Ready(t, true)
	f.Opened(t)
	f.Ended(t)
	r := newRig(t)
	r.s.deps.Config, r.s.deps.Store = f.Deps.Config, f.State
	ctx := context.Background()
	t.Run("current-life", func(t *testing.T) {
		lane, err := r.s.currentLane(ctx, f.Reservation.Target)
		if err != nil || lane.LifeID != f.Lane.LifeID || lane.Run != f.Lane.Run {
			t.Fatal("installed watchdog cannot read its actual current life", err)
		}
	})
	t.Run("whole-life-events", func(t *testing.T) {
		events, err := r.s.events(ctx, f.Lane.LifeID)
		if err != nil || len(events) == 0 {
			t.Fatal("installed watchdog cannot read the actual life journal", err)
		}
		found := false
		for _, event := range events {
			found = found || event.Kind == "lane.ended" && event.Run == f.Lane.Run
		}
		if !found {
			t.Fatal("installed watchdog lost its committed run end")
		}
	})
	t.Run("exact-bytes", func(t *testing.T) {
		if data, err := r.s.blob(ctx, f.Lane.Task, api.MaxFrameBytes); err != nil || int64(len(data)) != f.Lane.Task.Bytes {
			t.Fatal("installed watchdog cannot verify actual task bytes", err)
		}
	})
	t.Run("foreign-config", func(t *testing.T) {
		scope := r.s.readScope()
		scope.Config += "-foreign"
		if _, err := f.State.Lane(ctx, scope, f.Reservation.Target); err == nil {
			t.Fatal("watchdog read crossed its configuration")
		}
	})
	t.Run("public-relabel", func(t *testing.T) {
		scope := f.LaneScope(t)
		scope.Actor = r.s.readScope().Actor
		scope.Source = "watchdog"
		if _, err := f.State.Events(ctx, scope, api.EventTailRequest{LifeID: f.Lane.LifeID}); err == nil {
			t.Fatal("public endpoint borrowed internal watchdog journal authority")
		}
	})
}

func TestInstalledWaitJournal(t *testing.T) {
	f := fx.ReadyUsage(t)
	usage := fx.UsageWindow(t, f, "100")
	r := newRig(t)
	s := r.s
	s.deps.Config, s.deps.Store, s.deps.Clock = f.Deps.Config, f.State, f.Deps.Clock
	signal := r.signal
	signal.Target = f.Reservation.Target
	// A journal-boundary fixture, never an outside usage/authentication proof.
	signal.UsageEvidence = &usage
	origin := api.Event{OperationID: f.Reservation.OperationID, RequestID: f.Reservation.RequestID, RequestedBy: f.Reservation.RequestedBy}
	plan := assessment{Signal: signal, Lane: f.Lane, Grants: f.Plan.Inputs.Grants, Cause: origin}
	op, err := s.recordIntent(context.Background(), plan, signal, 0, 0)
	if err != nil {
		t.Fatal("real store could not retain the watchdog wait and actual operation", err)
	}
	intent, found, err := s.intent(context.Background(), signal.Target)
	if err != nil || !found || intent.Status != "waiting" || intent.OperationID != op.ID || intent.Swap.OperationID != op.ID ||
		op.ID == origin.OperationID || op.ID == s.internal(api.InternalProfileContinue, f.Lane, signal.Target, 1, origin).ID || op.Status != "succeeded" {
		t.Fatal("wait borrowed its launch/internal identity or lost the stamped operation", err)
	}
	before := f.Lane
	after, err := s.currentLane(context.Background(), signal.Target)
	if err != nil {
		t.Fatal(err)
	}
	after.Generation, after.State, after.LastSeq = before.Generation, before.State, before.LastSeq
	if !reflect.DeepEqual(before, after) {
		t.Fatal("journal changed the retained task, counters, history or budget")
	}
	// An early restart must preserve the exact wait and operation, not retry it.
	if _, err := s.Reconcile(context.Background(), signal.Target); err == nil {
		t.Fatal("restart dispatched before the durable backoff")
	} else {
		requireCode(t, err, api.CodeUnavailable)
	}
	if err := s.Cancel(context.Background(), signal.Target); err != nil {
		t.Fatal("real wait cancellation failed", err)
	}
	cancelled, found, err := s.intent(context.Background(), signal.Target)
	if err != nil || !found || cancelled.Status != "cancelled" || cancelled.OperationID == op.ID {
		t.Fatal("cancellation did not retain its own real operation", err)
	}
	if _, err := s.ObserveLimit(context.Background(), signal); err == nil {
		t.Fatal("cancelled wait replayed its old signal")
	} else {
		requireCode(t, err, api.CodeCancelled)
	}
}

func TestInstalledJournalRejectsForeignRun(t *testing.T) {
	f := fx.ReadyUsage(t)
	usage := fx.UsageWindow(t, f, "100")
	r := newRig(t)
	s := r.s
	s.deps.Config, s.deps.Store, s.deps.Clock = f.Deps.Config, f.State, f.Deps.Clock
	signal := r.signal
	signal.Target, signal.UsageEvidence = f.Reservation.Target, &usage
	signal.Target.Run++
	origin := api.Event{OperationID: f.Reservation.OperationID, RequestID: f.Reservation.RequestID, RequestedBy: f.Reservation.RequestedBy}
	before, err := s.currentLane(context.Background(), f.Reservation.Target)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.recordIntent(context.Background(), assessment{Signal: signal, Lane: before, Grants: f.Plan.Inputs.Grants, Cause: origin}, signal, 0, 0)
	if err == nil {
		t.Fatal("real watchdog journal accepted a foreign causing run")
	}
	after, readErr := s.currentLane(context.Background(), f.Reservation.Target)
	if readErr != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("refused foreign run changed the actual life", readErr)
	}
}
