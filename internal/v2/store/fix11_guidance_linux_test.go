//go:build linux

package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

func guidanceFixture(t *testing.T) (*fx.Fixture, api.GuidanceReservationRequest) {
	t.Helper()
	f := fx.Ready(t, true)
	f.Human = f.LaneScope(t)
	f.Admit(t, "guidance.select", api.GuidanceRequest{Target: f.Reservation.Target, LogicalTurnID: f.Lane.LogicalTurnID, Task: f.Lane.Task})
	page, err := f.State.DecisionCandidates(context.Background(), f.Human, api.DecisionQuery{Target: f.Reservation.Target, Kind: "binding", Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	return f, api.GuidanceReservationRequest{AttemptID: fx.ID(t), Target: f.Reservation.Target, LogicalTurnID: f.Lane.LogicalTurnID, ExpectedTask: f.Lane.Task, ExpectedTurnGeneration: 1, CancellationEpoch: f.Lane.CancellationEpoch, PolicyGeneration: 1, CandidateSnapshotID: page.SnapshotID, MaxCostMicros: 100, Deadline: api.Timestamp(time.Now().Add(4 * time.Second).UTC().Format(time.RFC3339Nano))}
}

func guidanceCompletion(t *testing.T, f *fx.Fixture, r api.GuidanceReservation) api.Transaction {
	t.Helper()
	result := api.Guidance{ID: fx.ID(t), Target: r.Target, LogicalTurnID: r.LogicalTurnID, Task: r.Task, PolicyGeneration: r.PolicyGeneration, CandidateSnapshotID: r.CandidateSnapshotID, ReservationID: r.ID, AsOf: fx.Expiry(), Items: append([]api.GuidanceItem{}, r.BindingItems...), JudgmentIDs: []api.ID{}, Status: "empty"}
	cause := api.InternalIntent{ID: fx.ID(t), Kind: api.InternalGuidanceComplete, Config: f.Deps.Config, Actor: f.Execution.Actor, RequestedBy: r.RequestedBy, CauseOperationID: r.OwnerOperationID, CauseRequestID: r.OwnerRequestID, Target: r.Target, LogicalTurnID: r.LogicalTurnID, CancellationEpoch: r.CancellationEpoch}
	event := f.Event(t, "guidance.selected", result)
	event.RequestedBy = r.RequestedBy
	return api.Transaction{Scope: f.Execution, Internal: &cause, Writes: api.StateWrites{Guidance: []api.GuidanceSelection{{ReservationID: r.ID, ClaimID: r.ClaimID, AttemptID: r.OwnerAttemptID, ExpectedGeneration: 1, Result: result}}}, Events: []api.Event{event}, Compare: []api.Compare{{Kind: api.CompareGuidance, ID: r.ID, Generation: 1}}, Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}}
}

func TestGuidanceOneWinner(t *testing.T) {
	f, request := guidanceFixture(t)
	requests := make([]api.GuidanceReservationRequest, 8)
	for i := range requests {
		requests[i] = request
		requests[i].AttemptID = fx.ID(t)
	}
	type result struct {
		Claim api.GuidanceReservation
		Err   error
	}
	results := make(chan result, 8)
	var workers sync.WaitGroup
	for _, request := range requests {
		workers.Add(1)
		go func(request api.GuidanceReservationRequest) {
			defer workers.Done()
			claim, err := f.State.ReserveGuidance(context.Background(), f.Human, request)
			results <- result{claim, err}
		}(request)
	}
	workers.Wait()
	close(results)
	winners := 0
	var original api.GuidanceReservation
	for result := range results {
		if result.Err != nil {
			t.Fatal("guidance atomic reservation failed", result.Err)
		}
		if result.Claim.Acquired {
			winners++
			original = result.Claim
		}
	}
	if winners != 1 {
		t.Fatal("guidance reservation did not grant exactly one evaluation owner")
	}
	retry, err := f.State.ReserveGuidance(context.Background(), f.Human, request)
	if err != nil || retry.Acquired || retry.ID != original.ID || retry.Deadline != original.Deadline {
		t.Fatal("guidance observer acquired or reset the existing claim", err)
	}
	input := guidanceCompletion(t, f, original)
	if _, err := f.State.Transact(context.Background(), input); err != nil {
		t.Fatal("guidance owner completion failed", err)
	}
	completed, err := f.State.AwaitGuidance(context.Background(), f.Human, api.GuidanceAwaitRequest{ReservationID: original.ID, Deadline: request.Deadline})
	if err != nil || completed.Acquired || completed.Status != "completed" || completed.Result == nil {
		t.Fatal("guidance loser did not await the actual completed selection", err)
	}
	if replay, err := f.State.Transact(context.Background(), input); err != nil || !replay.Replayed {
		t.Fatal("guidance completion did not replay one commit", err)
	}
}

func TestGuidanceOwnerFences(t *testing.T) {
	for _, fault := range []string{"attempt", "operation", "requester", "claim", "missing_cas", "missing_epoch", "early_recovery"} {
		t.Run(fault, func(t *testing.T) {
			f, request := guidanceFixture(t)
			r, err := f.State.ReserveGuidance(context.Background(), f.Human, request)
			if err != nil {
				t.Fatal(err)
			}
			input := guidanceCompletion(t, f, r)
			switch fault {
			case "attempt":
				input.Writes.Guidance[0].AttemptID = fx.ID(t)
			case "operation":
				input.Internal.CauseOperationID = fx.ID(t)
			case "requester":
				input.Internal.RequestedBy.ID = fx.ID(t)
				input.Events[0].RequestedBy = input.Internal.RequestedBy
			case "claim":
				input.Writes.Guidance[0].ClaimID = fx.ID(t)
			case "missing_cas":
				input.Compare = nil
			case "missing_epoch":
				input.Guards = nil
			case "early_recovery":
				input.Internal.Kind = api.InternalGuidanceRecover
				input.Writes.Guidance[0].Result.Status = "unavailable"
				input.Writes.Guidance[0].Result.Notice = "interrupted"
				input.Events[0].Payload = fx.JSON(t, input.Writes.Guidance[0].Result)
			}
			if _, err := f.State.Transact(context.Background(), input); err == nil {
				t.Fatal("guidance completion accepted foreign " + fault)
			}
		})
	}
}

func TestGuidanceInterruptedRecovery(t *testing.T) {
	f, request := guidanceFixture(t)
	claim, err := f.State.ReserveGuidance(context.Background(), f.Human, request)
	if err != nil {
		t.Fatal(err)
	}
	claim.Acquired = false
	claim.ReservedAt = api.Timestamp(time.Now().Add(-6 * time.Second).UTC().Format(time.RFC3339Nano))
	claim.Deadline = api.Timestamp(time.Now().Add(-2 * time.Second).UTC().Format(time.RFC3339Nano))
	// A closed-store expiry fixture advances retained clock evidence for this
	// recovery component case; no second evaluator or provider is supplied.
	f.Replace(t, "guidance", claim.ID, 1, claim)
	if err := f.State.RecoverGuidance(context.Background()); err != nil {
		t.Fatal("expired guidance recovery failed", err)
	}
	read, err := f.State.GuidanceReservation(context.Background(), f.Human, claim.Target, claim.LogicalTurnID)
	if err != nil || read.Result == nil || read.Result.Status != "unavailable" || read.Result.WeightedScore != nil || len(read.Result.JudgmentIDs) != 0 || read.OwnerAttemptID != claim.OwnerAttemptID {
		t.Fatal("interrupted guidance was rejudged or lost its owner", err)
	}
	if err := f.State.RecoverGuidance(context.Background()); err != nil {
		t.Fatal("completed guidance recovery did not remain quiescent", err)
	}
}

func TestGuidanceMeasuredScoreGate(t *testing.T) {
	t.Run("nonbinding_item", func(t *testing.T) {
		f, request := guidanceFixture(t)
		claim, err := f.State.ReserveGuidance(context.Background(), f.Human, request)
		if err != nil {
			t.Fatal(err)
		}
		input := guidanceCompletion(t, f, claim)
		item := api.GuidanceItem{DecisionID: fx.ID(t), Weight: 1,
			Source: api.SourceRef{ID: claim.Task.ID, Path: "task.md", SHA256: claim.Task.SHA256, Generation: 1}}
		input.Writes.Guidance[0].Result.Items = append(input.Writes.Guidance[0].Result.Items, item)
		input.Events[0].Payload = fx.JSON(t, input.Writes.Guidance[0].Result)
		var decoded api.Guidance
		if err := wire.Decode(input.Events[0].Payload, &decoded); err != nil {
			t.Fatal("nonbinding guidance fixture is not schema-valid", err)
		}
		if err := api.ValidateTransactionShape(input); err != nil {
			t.Fatal("nonbinding guidance fixture has invalid transaction shape", err)
		}
		if err := api.ValidateGuidanceCompletion(claim, input.Writes.Guidance[0], *input.Internal, time.Now()); err != nil {
			t.Fatal("nonbinding guidance fixture lost its current owner", err)
		}
		if _, err := f.State.Transact(context.Background(), input); err == nil {
			t.Fatal("unscored guidance accepted a nonbinding historical item")
		} else {
			launchCode(t, err, api.CodeForbidden)
		}
		if _, err := f.State.Transact(context.Background(), guidanceCompletion(t, f, claim)); err != nil {
			t.Fatal("binding-only guidance control failed", err)
		}
		completed, err := f.State.GuidanceReservation(context.Background(), f.Human, claim.Target, claim.LogicalTurnID)
		if err != nil || completed.Status != "completed" || completed.Result == nil || len(completed.Result.Items) != len(claim.BindingItems) {
			t.Fatal("binding-only guidance control lost its actual completion", err)
		}
	})
	t.Run("missing_judgment", func(t *testing.T) {
		f, request := guidanceFixture(t)
		claim, err := f.State.ReserveGuidance(context.Background(), f.Human, request)
		if err != nil {
			t.Fatal(err)
		}
		input := guidanceCompletion(t, f, claim)
		input.Writes.Guidance[0].Result.Status = "scored"
		input.Events[0].Payload = fx.JSON(t, input.Writes.Guidance[0].Result)
		if _, err := f.State.Transact(context.Background(), input); err == nil {
			t.Fatal("guidance accepted a score without measured judgment provenance")
		} else {
			launchCode(t, err, api.CodeIntegrity)
		}
		if _, err := f.State.Transact(context.Background(), guidanceCompletion(t, f, claim)); err != nil {
			t.Fatal("unscored guidance control failed", err)
		}
	})
}

func TestGuidanceAwaitDeadline(t *testing.T) {
	t.Run("claim_deadline", func(t *testing.T) {
		f, request := guidanceFixture(t)
		claim, err := f.State.ReserveGuidance(context.Background(), f.Human, request)
		if err != nil {
			t.Fatal(err)
		}
		claim.Acquired = false
		claim.ReservedAt = api.Timestamp(time.Now().Add(-6 * time.Second).UTC().Format(time.RFC3339Nano))
		claim.Deadline = api.Timestamp(time.Now().Add(-2 * time.Second).UTC().Format(time.RFC3339Nano))
		f.Replace(t, "guidance", claim.ID, 1, claim)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, err = f.State.AwaitGuidance(ctx, f.Human, api.GuidanceAwaitRequest{ReservationID: claim.ID, Deadline: fx.Expiry()})
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeDeadline {
			t.Fatal("guidance await reset its retained claim deadline", err)
		}
	})
}
