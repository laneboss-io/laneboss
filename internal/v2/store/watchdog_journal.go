package store

import (
	"context"
	"database/sql"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func watchdogJournal(input api.Transaction) bool {
	return watchdogReader(input.Scope) && input.Internal != nil &&
		(input.Internal.Kind == api.InternalProfileContinue || input.Internal.Kind == api.InternalProfileCancel)
}

// The original causing operation remains in InternalIntent. A watchdog
// journal owns a distinct operation, chosen once by the writer and returned
// from its immutable internal_commit on replay. It cannot replace a launch's
// already completed receipt or alias the internal intent identity.
func (s *Service) stampWatchdogJournal(ctx context.Context, db queryer, input api.Transaction, operation api.ID) (api.Transaction, string, error) {
	if len(input.Writes.Continuations) != 1 || len(input.Effects) != 0 {
		return input, "", fault(api.CodeInvalid, "watchdog journal requires one continuation and no executable effects")
	}
	intent := input.Writes.Continuations[0]
	if intent.OperationID != "" || intent.Swap.OperationID != "" || intent.Target != input.Internal.Target ||
		input.Internal.Kind == api.InternalProfileContinue && intent.LogicalTurnID != input.Internal.LogicalTurnID || intent.ExpectedGeneration != intent.Swap.ExpectedGeneration ||
		intent.CancellationEpoch != intent.Swap.CancellationEpoch || intent.CancellationEpoch != input.Internal.CancellationEpoch ||
		input.Internal.Kind == api.InternalProfileContinue && intent.Slot != nil {
		return input, "", fault(api.CodeInvalid, "watchdog journal changed its single continuation fence or preassigned an operation")
	}
	status := "succeeded"
	if input.Internal.Kind == api.InternalProfileCancel {
		if intent.Status != "cancelled" {
			return input, "", fault(api.CodeInvalid, "watchdog cancellation requires a cancelled intent")
		}
	} else {
		switch intent.Status {
		case "pending":
			status = "pending"
		case "waiting":
		default:
			return input, "", fault(api.CodeInvalid, "watchdog selection has no waiting or pending phase")
		}
	}
	var lane api.Lane
	if err := storedProjection(ctx, db, "lane", intent.Target.LifeID, &lane); err != nil {
		return input, "", err
	}
	if intent.Swap.Limit.Target != intent.Target || intent.Swap.CausingRun != intent.Target.Run || intent.Swap.ContinuationRun != intent.Target.Run+1 {
		return input, "", fault(api.CodeInvalid, "watchdog journal changed its causing or continued run")
	}
	if input.Internal.Kind == api.InternalProfileContinue && (lane.Run != intent.Target.Run || lane.LogicalTurnID != intent.LogicalTurnID || lane.CancellationEpoch != intent.CancellationEpoch || lane.Cleaned) {
		return input, "", fault(api.CodeConflict, "watchdog journal belongs to a stale run, turn or cancellation epoch")
	}
	laneCAS, intentCAS, grantsCAS, epochGuard := false, false, false, false
	for _, compare := range input.Compare {
		laneCAS = laneCAS || compare.Kind == api.CompareLane && compare.ID == lane.LifeID && compare.Generation == lane.Generation
		intentCAS = intentCAS || compare.Kind == api.CompareContinuation && compare.ID == intent.ID && compare.Generation+1 == intent.Generation
		if compare.Kind == api.CompareGrants && compare.ID == lane.GrantSetID {
			var grants api.GrantSet
			if err := storedProjection(ctx, db, "grants", lane.GrantSetID, &grants); err != nil {
				return input, "", err
			}
			grantsCAS = compare.Generation == grants.Generation
		}
	}
	for _, guard := range input.Guards {
		epochGuard = epochGuard || guard.Cancellation != nil && guard.Cancellation.LifeID == lane.LifeID && guard.Cancellation.Epoch == lane.CancellationEpoch
	}
	if !laneCAS || !intentCAS || !epochGuard || input.Internal.Kind == api.InternalProfileContinue && !grantsCAS {
		return input, "", fault(api.CodeConflict, "watchdog journal lacks its actual life, grants, continuation or cancellation comparison")
	}
	if input.Internal.Kind == api.InternalProfileCancel {
		var prior api.ContinuationIntent
		if err := storedProjection(ctx, db, "continuation", intent.ID, &prior); err != nil {
			return input, "", err
		}
		if prior.Target != intent.Target || prior.LogicalTurnID != intent.LogicalTurnID ||
			prior.Status != "waiting" && prior.Status != "pending" && prior.Status != "claimed" ||
			!sameValue(prior.Slot, intent.Slot) || lane.Run != intent.Target.Run && !(prior.Status == "claimed" && lane.Run == intent.Target.Run+1) {
			return input, "", fault(api.CodeConflict, "watchdog cancellation lost its existing claim or retained slot")
		}
	}
	if len(input.Writes.Lanes) == 1 {
		next := input.Writes.Lanes[0]
		if next.LifeID != lane.LifeID || next.Generation != lane.Generation+1 || intent.ExpectedGeneration != next.Generation || intent.CancellationEpoch != next.CancellationEpoch {
			return input, "", fault(api.CodeConflict, "watchdog journal life revision differs from its actual fence")
		}
		before, after := lane, next
		after.Generation, after.State, after.LastSeq, after.CancellationEpoch = before.Generation, before.State, before.LastSeq, before.CancellationEpoch
		if !sameValue(before, after) || input.Internal.Kind == api.InternalProfileContinue && (next.State != "profile_wait" || next.CancellationEpoch != lane.CancellationEpoch) ||
			input.Internal.Kind == api.InternalProfileCancel && next.CancellationEpoch != lane.CancellationEpoch+1 {
			return input, "", fault(api.CodeConflict, "watchdog journal changed retained task, budget, history or cancellation semantics")
		}
	} else if len(input.Writes.Lanes) != 0 || input.Internal.Kind != api.InternalProfileCancel || intent.ExpectedGeneration != lane.Generation || intent.CancellationEpoch != lane.CancellationEpoch {
		return input, "", fault(api.CodeConflict, "watchdog journal lost its actual life fence")
	}
	intent.OperationID, intent.Swap.OperationID = operation, operation
	input.Writes.Continuations = []api.ContinuationIntent{intent}
	return input, status, nil
}

func (s *Service) watchdogOperationEvent(ctx context.Context, tx *sql.Tx, input api.Transaction, operation *api.Operation, now api.Timestamp, digest api.Digest) (api.Sequence, error) {
	var head api.Sequence
	if err := tx.QueryRowContext(ctx, "SELECT coalesce(max(seq),0) FROM events").Scan(&head); err != nil {
		return 0, err
	}
	id, err := wire.NewID()
	if err != nil {
		return 0, err
	}
	operation.FirstSeq, operation.LastSeq = head+1, head+1
	data, err := canonicalValue(api.OperationEvent{Operation: *operation, RequestSHA256: digest})
	if err != nil {
		return 0, err
	}
	kind := api.EventKind("operation.completed")
	if operation.Status == "pending" {
		kind = "operation.accepted"
	}
	event := api.Event{Schema: api.SchemaVersion, ID: id, Config: s.deps.Config, Kind: kind, Origin: "service",
		Actor: input.Scope.Actor, RequestedBy: input.Internal.RequestedBy, RequestID: input.Internal.CauseRequestID,
		OperationID: operation.ID, LifeID: operation.LifeID, Run: operation.Run, LogicalTurnID: input.Internal.LogicalTurnID,
		StarterChain: []api.ID{}, RequestedAt: now, ObservedAt: now}
	event.Payload = data
	return appendPrivateEvent(ctx, tx, event, now)
}
