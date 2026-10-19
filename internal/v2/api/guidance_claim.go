package api

import (
	"reflect"
	"time"
)

type GuidanceAwaitRequest struct {
	ReservationID ID
	Deadline      Timestamp
}

func validGuidanceSelection(tx Transaction, selection GuidanceSelection) bool {
	cause := tx.Internal
	if cause == nil || cause.Kind != InternalGuidanceComplete && cause.Kind != InternalGuidanceRecover ||
		!launchID(selection.ReservationID) || !launchID(selection.ClaimID) || !launchID(selection.AttemptID) || selection.ExpectedGeneration != 1 ||
		selection.Result.ReservationID != selection.ReservationID || selection.Result.Target != cause.Target || selection.Result.LogicalTurnID != cause.LogicalTurnID ||
		selection.Result.Status != "scored" && selection.Result.Status != "empty" && selection.Result.Status != "unavailable" {
		return false
	}
	cas, epoch := false, false
	for _, compare := range tx.Compare {
		cas = cas || compare.Kind == CompareGuidance && compare.ID == selection.ReservationID && compare.Generation == selection.ExpectedGeneration
	}
	for _, guard := range tx.Guards {
		epoch = epoch || guard.Cancellation != nil && guard.Cancellation.LifeID == cause.Target.LifeID && guard.Cancellation.Epoch == cause.CancellationEpoch
	}
	return cas && epoch
}

func ValidateGuidanceReservation(r GuidanceReservation) error {
	start, startErr := time.Parse(time.RFC3339Nano, string(r.ReservedAt))
	deadline, deadlineErr := time.Parse(time.RFC3339Nano, string(r.Deadline))
	owner := r.OwnerKey.Method == "guidance.select" && r.LaunchReservationID == "" && r.LaunchEffectID == "" && r.MaxCostMicros > 0
	if launchID(r.LaunchReservationID) && launchID(r.LaunchEffectID) {
		owner = (r.OwnerKey.Method == "lane.start" || r.OwnerKey.Method == "lane.adopt" || r.OwnerKey.Method == "lane.resume" || r.OwnerKey.Method == "lane.turn") && r.MaxCostMicros >= 0
		if r.OwnerKey.Method == "loop.reserved" {
			owner = r.OwnerKey.IdempotencyKey == r.LaunchReservationID && r.RequestedBy.Kind == "scheduler" &&
				r.RequestedBy.LifeID == "" && r.RequestedBy.Level == 0 && r.RequestedBy.Role == "" && r.MaxCostMicros >= 0
		}
	}
	if !bindingConfigName.MatchString(r.Config) || !launchID(r.ID) || !launchID(r.Target.LifeID) || r.Target.Run == 0 || !launchID(r.LogicalTurnID) || !launchBlob(r.Task, "task") ||
		!launchGeneration(r.PolicyGeneration) || !launchGeneration(r.TurnGeneration) || !launchID(r.CandidateSnapshotID) || !launchID(r.ClaimID) ||
		!launchID(r.OwnerAttemptID) || !launchID(r.OwnerOperationID) || !launchID(r.OwnerRequestID) || !launchID(r.RequestedBy.ID) ||
		!owner || !launchID(r.OwnerKey.IdempotencyKey) || !bindingDigest.MatchString(string(r.OwnerKey.RequestSHA256)) ||
		r.CancellationEpoch > launchMaxInteger || r.MaxCostMicros > launchMaxInteger ||
		startErr != nil || deadlineErr != nil || !start.Before(deadline) || deadline.Sub(start) > 5*time.Second {
		return launchInvalid("guidance claim lacks its retained owner and total deadline")
	}
	for _, item := range r.BindingItems {
		if !item.Binding || !launchID(item.DecisionID) {
			return launchInvalid("guidance claim lost its binding snapshot")
		}
	}
	switch r.Status {
	case "pending":
		if r.Generation != 1 || r.Result != nil {
			return launchInvalid("pending guidance claim carries a result")
		}
	case "completed":
		if r.Generation != 2 || r.Result == nil || r.Acquired {
			return launchInvalid("completed guidance claim lacks one final result")
		}
		result := r.Result
		if result.ReservationID != r.ID || result.Target != r.Target || result.LogicalTurnID != r.LogicalTurnID || result.Task != r.Task ||
			result.PolicyGeneration != r.PolicyGeneration || result.CandidateSnapshotID != r.CandidateSnapshotID ||
			result.Status != "scored" && result.Status != "empty" && result.Status != "unavailable" {
			return launchInvalid("guidance result differs from its retained turn")
		}
		for _, required := range r.BindingItems {
			found := false
			for _, item := range result.Items {
				found = found || reflect.DeepEqual(item, required)
			}
			if !found {
				return launchInvalid("guidance result omitted a binding item")
			}
		}
	default:
		return launchInvalid("unknown guidance reservation status")
	}
	return nil
}

func GuidanceCanEvaluate(request GuidanceReservationRequest, r GuidanceReservation, now time.Time) bool {
	deadline, err := time.Parse(time.RFC3339Nano, string(r.Deadline))
	return r.Acquired && r.Status == "pending" && r.MaxCostMicros > 0 && r.OwnerAttemptID == request.AttemptID &&
		r.Target == request.Target && r.LogicalTurnID == request.LogicalTurnID && r.Task == request.ExpectedTask &&
		r.PolicyGeneration == request.PolicyGeneration && r.CandidateSnapshotID == request.CandidateSnapshotID &&
		r.TurnGeneration == request.ExpectedTurnGeneration && r.CancellationEpoch == request.CancellationEpoch && r.MaxCostMicros == request.MaxCostMicros &&
		err == nil && now.Before(deadline) && ValidateGuidanceReservation(r) == nil
}

func ValidateGuidanceCompletion(r GuidanceReservation, selection GuidanceSelection, cause InternalIntent, now time.Time) error {
	if err := ValidateGuidanceReservation(r); err != nil {
		return err
	}
	deadline, _ := time.Parse(time.RFC3339Nano, string(r.Deadline))
	if r.Status != "pending" || selection.ReservationID != r.ID || selection.ClaimID != r.ClaimID || selection.ExpectedGeneration != r.Generation ||
		selection.AttemptID != r.OwnerAttemptID || cause.Actor.Kind != "service" || !launchID(cause.Actor.ID) ||
		cause.Config != r.Config || cause.RequestedBy != r.RequestedBy || cause.CauseOperationID != r.OwnerOperationID || cause.CauseRequestID != r.OwnerRequestID ||
		cause.Target != r.Target || cause.LogicalTurnID != r.LogicalTurnID || cause.CancellationEpoch != r.CancellationEpoch {
		return launchInvalid("guidance completion differs from its one owner claim")
	}
	switch cause.Kind {
	case InternalGuidanceComplete:
		if !now.Before(deadline) {
			return launchInvalid("expired guidance owner cannot complete")
		}
	case InternalGuidanceRecover:
		if now.Before(deadline) || selection.Result.Status != "unavailable" || len(selection.Result.JudgmentIDs) != 0 ||
			selection.Result.JudgmentID != "" || selection.Result.WeightedScore != nil || selection.Result.Notice == "" ||
			!reflect.DeepEqual(selection.Result.Items, r.BindingItems) {
			return launchInvalid("guidance recovery must finish unavailable without rejudging")
		}
	default:
		return launchInvalid("unrelated guidance completion emitter")
	}
	done := r
	done.Status, done.Generation, done.Acquired, done.Result = "completed", 2, false, &selection.Result
	return ValidateGuidanceReservation(done)
}
