//go:build linux

package store_test

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func TestWriterOpenPolicy(t *testing.T) {
	f := fx.Ready(t, true)
	ctx := context.Background()
	// The component helper observation is retained through the real store;
	// this fixture does not execute a process or claim installed acceptance.
	if err := f.State.RecordLaunchObservation(ctx, f.Reservation.LaunchID, f.Observation(t, "running")); err != nil {
		t.Fatal("open observation setup failed", err)
	}
	lane, record := f.Lane, f.Record
	lane.Generation++
	lane.State, lane.Containment = "running", "running"
	record.Generation++
	record.Phase = "opened"
	cause := f.Intent(t, api.InternalHelperOpen)
	input := api.Transaction{Scope: f.Execution, Internal: &cause,
		Writes:  api.StateWrites{Lanes: []api.Lane{lane}, LaunchPlans: []api.LaunchPlanRecord{record}},
		Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: record.Reservation.ID, Generation: f.Record.Generation}},
		Guards:  []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: lane.LifeID, Epoch: lane.CancellationEpoch}}}}
	first, err := f.State.Transact(ctx, input)
	if err != nil {
		t.Fatal("fresh open lost its current policy stamp", err)
	}
	publishFixturePolicy(t, f)
	replay, err := f.State.Transact(ctx, input)
	if err != nil || !replay.Replayed || replay.LastSeq != first.LastSeq || replay.Operation.ID != first.Operation.ID {
		t.Fatal("policy change invalidated exact committed replay", err)
	}
	// A new invocation cannot reuse the old approved generation or its stamp.
	fresh := input
	nextCause := cause
	nextCause.ID = fx.ID(t)
	fresh.Internal = &nextCause
	if _, err := f.State.Transact(ctx, fresh); err == nil {
		t.Fatal("fresh open reused an old approved policy")
	} else {
		launchCode(t, err, api.CodeInvalid)
	}
}
