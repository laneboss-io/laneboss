//go:build linux

package admin_test

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func continuationReviewFixture(t *testing.T) (*fx.Fixture, api.LaunchPlanRecord, api.ID) {
	t.Helper()
	f := fx.New(t)
	second := f.Ceiling.Profiles[0]
	second.ID, second.ProfileID = fx.ID(t), fx.ID(t)
	f.Ceiling.Profiles = append(append([]api.ProfileGrant{}, f.Ceiling.Profiles...), second)
	f.Replace(t, "grants", f.Ceiling.ID, f.Ceiling.Generation, f.Ceiling)
	f.Start.Grants.Profiles[0].ExpiresAt = f.Start.Grants.Data[0].ExpiresAt
	delegation := f.Start.Grants.Profiles[0]
	delegation.ParentGrantID, delegation.ProfileID = second.ID, second.ProfileID
	f.Start.Grants.Profiles = append(f.Start.Grants.Profiles, delegation)
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	sourced := f.SourceTransaction(t)
	issued := sourced.Writes.Grants[0]
	issued.Profiles[1].ID = fx.ID(t)
	issued.Profiles[1].ExpiresAt = delegation.ExpiresAt
	sourced.Writes.Grants[0] = issued
	sourced.Writes.LaunchPlans[0].Inputs.Grants = issued
	sourced.Events = []api.Event{f.Event(t, "grants.issued", api.GrantEvent{GrantSet: issued})}
	if _, err := f.State.Transact(context.Background(), sourced); err != nil {
		t.Fatal("could not issue both actual reserved profiles", err)
	}
	f.Record = sourced.Writes.LaunchPlans[0]
	f.BuildPlan(t, true)
	f.Spec(t)
	f.Bind(t)
	ctx := context.Background()
	data := f.CaptureData(t, []byte("review continuation captured input "+string(fx.ID(t))))
	captured, err := f.State.AppendCapture(ctx, f.Worker, f.AppendRequest(t, &data, false))
	if err != nil {
		t.Fatal(err)
	}
	evidence := f.Retain(t, "manifest", []byte("review eligibility "+string(fx.ID(t))), f.Execution.Actor, f.Reservation.Target.LifeID)
	f.Opened(t)
	f.Ended(t)
	from, to := f.Plan.Inputs.Grants.Profiles[0], f.Plan.Inputs.Grants.Profiles[1]
	eligible := api.ProfileEligibility{ID: fx.ID(t), Compatible: true, Reason: "component retained eligibility", Evidence: evidence, CheckedAt: fx.Expiry(), ExpiresAt: fx.Expiry(),
		Request: api.ProfileEligibilityRequest{Target: f.Reservation.Target, GrantSetID: f.Reservation.GrantSetID, FromGrantID: from.ID, ToGrantID: to.ID,
			Driver: f.Lane.Session.Driver, Model: f.Lane.Model, Session: f.Lane.Session, HistoryID: f.Lane.Session.HistoryID}}
	cause := f.Intent(t, api.InternalProfileContinue)
	cause.EffectID, cause.CauseOperationID, cause.CauseRequestID = fx.ID(t), fx.ID(t), fx.ID(t)
	cause.RequestedBy, cause.LogicalTurnID = api.Actor{Kind: "watchdog", ID: fx.ID(t)}, f.Lane.LogicalTurnID
	swap := api.ProfileSwap{ProfileGrantID: to.ID, EligibilityID: eligible.ID, ExpectedGeneration: f.Lane.Generation, CancellationEpoch: f.Lane.CancellationEpoch,
		FromProfileID: from.ProfileID, ToProfileID: to.ProfileID, CausingRun: f.Lane.Run, ContinuationRun: f.Lane.Run + 1, LogicalTurnID: f.Lane.LogicalTurnID, OperationID: cause.CauseOperationID,
		Limit: api.LimitSignal{Target: f.Reservation.Target, Kind: "quota", ProfileID: from.ProfileID, Provider: "component-provider", CaptureID: captured.RecordID, CaptureSHA256: data.SHA256, AdapterVersion: "component-v1", ObservedAt: fx.Expiry()},
		Room:  api.Room{ProfileID: to.ProfileID, Available: true, CheckedAt: fx.Expiry(), ExpiresAt: fx.Expiry(), Evidence: evidence, Reason: "component room"}}
	slot := f.Plan.Runner.Slot
	slot.ID, slot.LeaseID, slot.ProfileGrantID, slot.ProfileID = fx.ID(t), fx.ID(t), to.ID, to.ProfileID
	intent := api.ContinuationIntent{ID: fx.ID(t), Target: f.Reservation.Target, LogicalTurnID: f.Lane.LogicalTurnID, ExpectedGeneration: f.Lane.Generation,
		CancellationEpoch: f.Lane.CancellationEpoch, Generation: 1, Status: "pending", Swap: swap, Eligibility: eligible, Slot: &slot, OperationID: cause.CauseOperationID}
	effect := api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID, Context: &cause, Swap: &swap}
	if _, err := f.State.Transact(ctx, api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Continuations: []api.ContinuationIntent{intent}}, Effects: []api.Effect{effect}}); err != nil {
		t.Fatal("could not retain real continuation intent", err)
	}
	if _, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: effect.ID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: fx.Expiry()}); err != nil {
		t.Fatal(err)
	}
	claimed, err := f.State.ClaimContinuation(ctx, f.Execution, api.ContinuationClaimRequest{Intent: cause, Request: api.ContinuationRequest{IntentID: intent.ID, Swap: swap}})
	if err != nil {
		t.Fatal("actual continuation claim failed", err)
	}
	r, err := f.State.ReserveLaunch(ctx, f.Execution, api.LaunchReservationRequest{OperationID: claimed.OperationID, ContinuationID: claimed.ID,
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: f.Lane.LifeID, Epoch: f.Lane.CancellationEpoch}}}})
	if err != nil {
		t.Fatal("actual continuation reservation failed", err)
	}
	record, err := f.State.LaunchPlan(ctx, f.Execution, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	return f, record, to.ID
}

func TestRevContSwappedProfile(t *testing.T) {
	if reviewAsNonroot(t) {
		return
	}
	f, record, want := continuationReviewFixture(t)
	selected, err := admin.ReviewRetainedProfile(context.Background(), f.State, f.Execution, record)
	if err != nil || selected != want || selected == f.Lane.ProfileGrantID {
		t.Fatal("retained source selection used the old lane profile instead of its actual claimed swap", err)
	}
	foreign := record
	foreign.Reservation.OperationID = fx.ID(t)
	if selected, err := admin.ReviewRetainedProfile(context.Background(), f.State, f.Execution, foreign); err == nil || selected != "" {
		t.Fatal("continuation selector accepted an original input owned by another operation", err)
	}
}
