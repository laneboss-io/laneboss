package watchdog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// The identity selects the causing run, not a capture, selected profile, wall
// clock or cancellation epoch. Re-observation cannot mint another claim for
// the same run, even if its caller changes one of those inputs.
func (s *Service) intentID(target api.LifeRef) api.ID {
	return s.journalID(target, "continuation")
}

func (s *Service) journalID(target api.LifeRef, purpose string) api.ID {
	data := []byte(s.deps.Config + "\x00" + string(target.LifeID) + "\x00" + fmt.Sprint(target.Run) + "\x00" + purpose)
	return api.ID("wd-" + string(digest(data)))
}

func (s *Service) intent(ctx context.Context, target api.LifeRef) (api.ContinuationIntent, bool, error) {
	id := s.intentID(target)
	intent, err := s.deps.Store.ContinuationIntent(ctx, s.readScope(), id)
	if err != nil {
		var typed *api.Error
		if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
			return api.ContinuationIntent{}, false, nil
		}
		return api.ContinuationIntent{}, false, err
	}
	if intent.ID != id || intent.Target != target || intent.Generation == 0 || intent.ExpectedGeneration == 0 ||
		uint64(intent.Generation) >= maxExactInteger || !validID.MatchString(string(intent.LogicalTurnID)) ||
		!validID.MatchString(string(intent.OperationID)) {
		return api.ContinuationIntent{}, false, problem(api.CodeIntegrity, "stored continuation has invalid identity or generation")
	}
	switch intent.Status {
	case "cancelled":
	case "waiting", "pending", "claimed", "completed":
		if !reflect.DeepEqual(intent.Swap.Limit.Target, target) || intent.Swap.CausingRun != target.Run ||
			intent.Swap.FromProfileID != intent.Swap.Limit.ProfileID ||
			intent.Swap.ContinuationRun != target.Run+1 || intent.Swap.LogicalTurnID != intent.LogicalTurnID ||
			intent.Swap.ExpectedGeneration != intent.ExpectedGeneration ||
			intent.Swap.CancellationEpoch != intent.CancellationEpoch || intent.Swap.OperationID != intent.OperationID {
			return api.ContinuationIntent{}, false, problem(api.CodeIntegrity, "stored continuation changed its run, turn, epoch or operation")
		}
		if err := checkSignal(intent.Swap.Limit); err != nil {
			return api.ContinuationIntent{}, false, err
		}
	default:
		return api.ContinuationIntent{}, false, problem(api.CodeIntegrity, "stored continuation has an unknown status")
	}
	return intent, true, nil
}

func (s *Service) resumeIntent(ctx context.Context, intent api.ContinuationIntent) (api.Operation, error) {
	if intent.Status == "cancelled" {
		return api.Operation{}, problem(api.CodeCancelled, "durable watchdog intent is cancelled")
	}
	// A claimed intent may already own a slot or a prepared gate. Recovery
	// submits the identical request to lifecycle's claim reconciler; it must
	// never reassess and acquire a second slot here.
	if intent.Status == "completed" {
		return s.recordedOperation(ctx, intent)
	}
	lane, err := s.currentLane(ctx, intent.Target)
	if err != nil {
		return api.Operation{}, err
	}
	if lane.CancellationEpoch != intent.CancellationEpoch {
		return api.Operation{}, problem(api.CodeCancelled, "continuation epoch was revoked by current life control")
	}
	if lane.LifeID != intent.Target.LifeID ||
		lane.LogicalTurnID != intent.LogicalTurnID || lane.Cleaned {
		return api.Operation{}, problem(api.CodeConflict, "continuation no longer belongs to the current run and turn")
	}
	events, err := s.events(ctx, intent.Target.LifeID)
	if err != nil {
		return api.Operation{}, err
	}
	if err := controlError(events, intent.Target, intent.LogicalTurnID); err != nil {
		return api.Operation{}, err
	}
	if intent.Status == "claimed" {
		if lane.Run != intent.Target.Run && lane.Run != intent.Target.Run+1 {
			return api.Operation{}, problem(api.CodeConflict, "claimed continuation is outside its recorded run pair")
		}
		if _, err := s.recordedOperation(ctx, intent); err != nil {
			return api.Operation{}, err
		}
		return s.continueIntent(ctx, intent, lane.PolicyGeneration)
	}
	if lane.Run != intent.Target.Run {
		return api.Operation{}, problem(api.CodeConflict, "continuation is outside its causing run")
	}
	// A waiting intent owns no selected handoff. Backoff must finish before
	// fresh planning advances the life policy and commits a matching intent.
	if intent.Status == "waiting" {
		return s.reassess(ctx, intent.Target, intent.Generation, intent.OperationID)
	}
	policy, err := s.policyForLane(ctx, lane)
	if err != nil {
		return api.Operation{}, err
	}
	generation, err := api.PolicyGenerationFor(api.PolicyNewLaunch, policy.Generation, lane.PolicyGeneration)
	if err != nil {
		return api.Operation{}, err
	}
	if generation != lane.PolicyGeneration {
		return s.reassess(ctx, intent.Target, intent.Generation, intent.OperationID)
	}
	if lane.Run != intent.Target.Run || lane.Generation != intent.ExpectedGeneration {
		return api.Operation{}, problem(api.CodeConflict, "life generation changed after continuation preparation")
	}
	if err := eligibleLane(lane, intent.Target); err != nil {
		return api.Operation{}, err
	}
	// Read the operation before the final authority/clock checks. A slow
	// operation lookup must not extend a pending room or eligibility receipt.
	if _, err := s.recordedOperation(ctx, intent); err != nil {
		return api.Operation{}, err
	}
	receipt := intent.Eligibility
	request := receipt.Request
	if !receipt.Compatible || !intent.Swap.Room.Available || receipt.ID != intent.Swap.EligibilityID || request.Target != intent.Target ||
		request.GrantSetID != lane.GrantSetID || request.FromGrantID != lane.ProfileGrantID ||
		request.ToGrantID != intent.Swap.ProfileGrantID || request.Driver != lane.Session.Driver ||
		request.Model != lane.Model || request.Session != lane.Session || request.HistoryID != lane.Session.HistoryID ||
		!validID.MatchString(string(intent.Swap.ToProfileID)) || intent.Swap.ToProfileID == intent.Swap.FromProfileID {
		return api.Operation{}, problem(api.CodeIntegrity, "continuation eligibility differs from its retained life and profile choice")
	}
	// Pending means no slot handoff has been claimed yet. A lost reply or
	// restart does not extend either outside receipt's lifetime. Claimed
	// recovery above must instead reconcile its already-owned slot/gate.
	grant, err := s.pendingGrant(ctx, lane, intent)
	if err != nil {
		return api.Operation{}, err
	}
	usageObserved, err := s.pendingUsageObservation(ctx, lane, intent)
	if err != nil {
		return api.Operation{}, err
	}
	now := s.deps.Clock.Now()
	if usageObserved.After(now) {
		return api.Operation{}, problem(api.CodeIntegrity, "retained usage observation is in the future")
	}
	if err := validateRoom(intent.Swap.Room, grant, now); err != nil {
		if errors.Is(err, errReceiptStale) {
			return s.reassess(ctx, intent.Target, intent.Generation, intent.OperationID)
		}
		return api.Operation{}, err
	}
	if err := validateEligibility(receipt, request, now); err != nil {
		if errors.Is(err, errReceiptStale) {
			return s.reassess(ctx, intent.Target, intent.Generation, intent.OperationID)
		}
		return api.Operation{}, err
	}
	if now.Sub(usageObserved) > 30*time.Second {
		return s.reassess(ctx, intent.Target, intent.Generation, intent.OperationID)
	}
	return s.continueIntent(ctx, intent, lane.PolicyGeneration)
}

func (s *Service) continueIntent(ctx context.Context, intent api.ContinuationIntent, policy api.Generation) (api.Operation, error) {
	scope := s.readScope()
	scope.PolicyGeneration = policy
	request := api.ContinuationRequest{
		IntentID: intent.ID, Swap: intent.Swap,
	}
	operation, err := s.deps.Lifecycle.Continue(ctx, scope, request)
	if err != nil {
		return api.Operation{}, err
	}
	// Continue may have advanced the durable phase before returning. Only
	// that retained phase can justify a succeeded result; a pending receipt
	// or an internal intent ID is never an alternate completion rule.
	current, found, err := s.intent(ctx, intent.Target)
	if err != nil {
		return api.Operation{}, err
	}
	if !found || current.Generation < intent.Generation {
		return api.Operation{}, problem(api.CodeIntegrity, "continuation reply lost its durable intent")
	}
	if current.Status == "cancelled" {
		return api.Operation{}, problem(api.CodeCancelled, "continuation was cancelled during lifecycle handoff")
	}
	if err := api.ValidateContinuationOperation(current, request, operation); err != nil {
		return api.Operation{}, err
	}
	if err := checkOperation(operation, intent.Target); err != nil {
		return api.Operation{}, err
	}
	// A successful call is a lifecycle operation receipt, not an invented
	// watchdog.swapped event. Lifecycle must commit the measured handoff and
	// actual launch with that event before the product can claim a swap.
	return operation, nil
}

func (s *Service) recordedOperation(ctx context.Context, intent api.ContinuationIntent) (api.Operation, error) {
	operation, err := s.deps.Store.Operation(ctx, s.readScope(), intent.OperationID)
	if err != nil {
		return api.Operation{}, err
	}
	if intent.Status == "waiting" {
		// A wait is a journal acknowledgement, not a launch operation.
		if operation.ID != intent.OperationID {
			return api.Operation{}, problem(api.CodeIntegrity, "waiting replay returned another journal operation")
		}
	} else {
		// Freeze the request from this observation's claim, then compare the
		// fresh retained intent with that request and its store-stamped receipt.
		// Comparing the earlier snapshot with itself would allow a replacement
		// operation to reach lifecycle. Keep these reads before the final
		// pending authority/clock checks so they cannot extend receipt expiry.
		retained, err := s.deps.Store.ContinuationIntent(ctx, s.readScope(), intent.ID)
		if err != nil {
			return api.Operation{}, err
		}
		if retained.Status == "cancelled" {
			return api.Operation{}, problem(api.CodeCancelled, "continuation was cancelled before lifecycle handoff")
		}
		if err := api.ValidateContinuationOperation(retained, api.ContinuationRequest{IntentID: intent.ID, Swap: intent.Swap}, operation); err != nil {
			return api.Operation{}, err
		}
	}
	if err := checkOperation(operation, intent.Target); err != nil {
		return api.Operation{}, err
	}
	return operation, nil
}

func checkOperation(operation api.Operation, target api.LifeRef) error {
	if !validID.MatchString(string(operation.ID)) || operation.LifeID != target.LifeID ||
		(operation.Run != target.Run && operation.Run != target.Run+1) ||
		operation.FirstSeq == 0 || operation.LastSeq < operation.FirstSeq {
		return problem(api.CodeIntegrity, "continuation has no matching durable operation receipt")
	}
	switch operation.Status {
	case "pending", "running", "succeeded":
		if operation.Error == nil {
			return nil
		}
	case "failed", "cancelled":
		if operation.Error != nil {
			return operation.Error
		}
	}
	return problem(api.CodeIntegrity, "continuation operation has an inconsistent outcome")
}

func (s *Service) recordIntent(ctx context.Context, plan assessment, signal api.LimitSignal, generation api.Generation, previous int64) (api.Operation, error) {
	// A reassessment may have measured a fresh outside usage window. Retain its
	// exact committed reference while preserving the causing capture and run.
	signal = plan.Signal
	lane := plan.Lane
	lane.Generation++
	lane.State = "profile_wait"
	intent := api.ContinuationIntent{
		ID: s.intentID(signal.Target), Target: signal.Target, LogicalTurnID: lane.LogicalTurnID,
		ExpectedGeneration: lane.Generation, CancellationEpoch: lane.CancellationEpoch,
		Generation: generation + 1, Status: "waiting",
		Swap: api.ProfileSwap{FromProfileID: signal.ProfileID, CausingRun: signal.Target.Run,
			ContinuationRun: signal.Target.Run + 1, LogicalTurnID: lane.LogicalTurnID, Limit: signal,
			ExpectedGeneration: lane.Generation, CancellationEpoch: lane.CancellationEpoch},
	}
	if plan.Swap != nil && plan.Eligibility != nil {
		intent.Status, intent.Swap, intent.Eligibility = "pending", *plan.Swap, *plan.Eligibility
		intent.Swap.ExpectedGeneration = lane.Generation
	}
	cause := s.internal(api.InternalProfileContinue, lane, signal.Target, generation+1, plan.Cause)
	events := []api.Event{}
	appendEvent := func(kind api.EventKind, payload api.WatchdogEvent) error {
		event, err := s.event(lane, cause, kind, payload)
		if err != nil {
			return err
		}
		events = append(events, event)
		return nil
	}
	if generation == 0 {
		if err := appendEvent("watchdog.limit", api.WatchdogEvent{
			Signal: &signal, Reason: "validated_provider_limit", BudgetRemaining: lane.BudgetRemaining,
		}); err != nil {
			return api.Operation{}, err
		}
	}
	if intent.Status == "waiting" {
		delay, err := nextBackoff(previous)
		if err != nil {
			return api.Operation{}, err
		}
		if err := appendEvent("watchdog.waiting", api.WatchdogEvent{
			Signal: &signal, Reason: "no_eligible_profile_room", RetryAfterMS: delay, BudgetRemaining: lane.BudgetRemaining,
		}); err != nil {
			return api.Operation{}, err
		}
	}
	transaction := api.Transaction{
		Scope: s.readScope(), Internal: &cause,
		Compare: []api.Compare{
			{Kind: api.CompareLane, ID: lane.LifeID, Generation: plan.Lane.Generation},
			{Kind: api.CompareGrants, ID: plan.Grants.ID, Generation: plan.Grants.Generation},
			{Kind: api.CompareContinuation, ID: intent.ID, Generation: generation},
		},
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: lane.LifeID, Epoch: lane.CancellationEpoch}}},
		Writes: api.StateWrites{Lanes: []api.Lane{lane}, Continuations: []api.ContinuationIntent{intent}}, Events: events,
	}
	commit, err := s.transact(ctx, transaction)
	if err != nil {
		return api.Operation{}, err
	}
	if err := checkOperation(commit.Operation, signal.Target); err != nil {
		return api.Operation{}, err
	}
	stored, found, err := s.intent(ctx, signal.Target)
	if err != nil {
		return api.Operation{}, err
	}
	if found && stored.Status == "cancelled" {
		return s.resumeIntent(ctx, stored)
	}
	if !found || stored.Generation < intent.Generation || !reflect.DeepEqual(stored.Swap.Limit, signal) {
		return api.Operation{}, problem(api.CodeIntegrity, "continuation commit did not retain its intent and stamped operation")
	}
	if stored.Generation == intent.Generation && (stored.OperationID != commit.Operation.ID ||
		stored.ExpectedGeneration != intent.ExpectedGeneration || stored.CancellationEpoch != intent.CancellationEpoch) {
		return api.Operation{}, problem(api.CodeIntegrity, "continuation commit changed its generation or operation binding")
	}
	if found && intent.Status == "pending" {
		receipt := commit.Operation
		if stored.Status == "completed" {
			// A completed read-back may be newer than the commit response.
			// Read that same committed operation's actual final result.
			receipt, err = s.deps.Store.Operation(ctx, s.readScope(), commit.Operation.ID)
			if err != nil {
				return api.Operation{}, err
			}
		}
		if err := api.ValidateContinuationOperation(stored, api.ContinuationRequest{IntentID: stored.ID, Swap: stored.Swap}, receipt); err != nil {
			return api.Operation{}, err
		}
	}
	// The scheduler may have advanced this intent between commit and read-back.
	// Recover the newer durable phase, never overwrite it with the old plan.
	if stored.Status == "waiting" {
		return s.recordedOperation(ctx, stored)
	}
	return s.resumeIntent(ctx, stored)
}

func (s *Service) internal(kind api.InternalKind, lane api.Lane, target api.LifeRef, generation api.Generation, origin api.Event) api.InternalIntent {
	actor := s.readScope().Actor
	requestedBy := origin.RequestedBy
	if requestedBy.Kind == "" {
		requestedBy = actor
	}
	return api.InternalIntent{
		ID: s.journalID(target, fmt.Sprintf("%s/%d", kind, generation)), Kind: kind,
		Config: s.deps.Config, Actor: actor, RequestedBy: requestedBy,
		CauseOperationID: origin.OperationID, CauseRequestID: origin.RequestID,
		Target: target, LogicalTurnID: lane.LogicalTurnID, CancellationEpoch: lane.CancellationEpoch,
	}
}

func (s *Service) event(lane api.Lane, cause api.InternalIntent, kind api.EventKind, payload api.WatchdogEvent) (api.Event, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return api.Event{}, problem(api.CodeIntegrity, "watchdog event could not be encoded")
	}
	return api.Event{
		Schema: api.SchemaVersion, ID: s.journalID(cause.Target, "event/"+string(cause.ID)+"/"+string(kind)), Config: s.deps.Config, Kind: kind, Origin: "service",
		Actor: cause.Actor, RequestedBy: cause.RequestedBy, RequestID: cause.CauseRequestID,
		LifeID: lane.LifeID, Run: cause.Target.Run, LogicalTurnID: lane.LogicalTurnID,
		ParentLifeID: lane.ParentLifeID, RootLifeID: lane.RootLifeID,
		StarterChain: append([]api.ID{}, lane.StarterChain...), StarterEventSeq: lane.StarterEventSeq,
		ObservedAt: api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano)), Payload: data,
	}, nil
}

func (s *Service) cancelIntent(ctx context.Context, target api.LifeRef) error {
	lane, err := s.currentLane(ctx, target)
	if err != nil {
		return err
	}
	if lane.LifeID != target.LifeID {
		return problem(api.CodeConflict, "cancellation target is a stale life or run")
	}
	prior, found, err := s.intent(ctx, target)
	if err != nil {
		return err
	}
	if found && (prior.Status == "cancelled" || prior.Status == "completed") {
		return nil
	}
	if lane.Run != target.Run && !(found && prior.Status == "claimed" && lane.Run == target.Run+1) {
		return problem(api.CodeConflict, "cancellation target is a stale life or run")
	}
	if !found {
		return nil
	}
	if lane.Generation == 0 || uint64(lane.Generation) >= maxExactInteger ||
		uint64(lane.CancellationEpoch) >= maxExactInteger || !validID.MatchString(string(lane.LogicalTurnID)) {
		return problem(api.CodeIntegrity, "cancellation life generation or turn is invalid")
	}
	if lane.CancellationEpoch < prior.CancellationEpoch {
		return problem(api.CodeIntegrity, "cancellation intent has a future life epoch")
	}
	if lane.CancellationEpoch > prior.CancellationEpoch && lane.State == "profile_wait" && lane.Run == target.Run {
		return problem(api.CodeConflict, "manual control advanced the epoch without settling profile_wait")
	}
	oldGeneration, oldEpoch := lane.Generation, lane.CancellationEpoch
	var laneWrites []api.Lane
	if lane.CancellationEpoch == prior.CancellationEpoch && lane.Run == target.Run {
		lane.Generation++
		lane.CancellationEpoch++
		if lane.State == "profile_wait" {
			lane.State = "verifying"
		}
		laneWrites = []api.Lane{lane}
	}
	// Manual control may already have advanced the epoch. Cancel the live
	// claim under that current fence without advancing the life a second time.
	intent := prior
	intent.Status, intent.ExpectedGeneration, intent.CancellationEpoch = "cancelled", lane.Generation, lane.CancellationEpoch
	intent.Generation = prior.Generation + 1
	intent.Swap.ExpectedGeneration, intent.Swap.CancellationEpoch = lane.Generation, lane.CancellationEpoch
	// Operation IDs are assigned by the store, never guessed from Internal.ID
	// or copied from the earlier selection operation.
	intent.OperationID, intent.Swap.OperationID = "", ""
	// This interface has no caller Scope. It records watchdog's cancellation
	// action, not a fabricated manual caller. Lifecycle records the actual
	// stop/resume/revocation requester in its own atomic control transaction.
	cause := s.internal(api.InternalProfileCancel, lane, target, intent.Generation, api.Event{})
	event, err := s.event(lane, cause, "watchdog.cancelled", api.WatchdogEvent{
		Reason: "continuation_cancelled", BudgetRemaining: lane.BudgetRemaining,
	})
	if err != nil {
		return err
	}
	transaction := api.Transaction{
		Scope: s.readScope(), Internal: &cause,
		Compare: []api.Compare{
			{Kind: api.CompareLane, ID: target.LifeID, Generation: oldGeneration},
			{Kind: api.CompareContinuation, ID: intent.ID, Generation: prior.Generation},
		},
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: target.LifeID, Epoch: oldEpoch}}},
		Writes: api.StateWrites{Lanes: laneWrites, Continuations: []api.ContinuationIntent{intent}},
		Events: []api.Event{event},
	}
	commit, err := s.transact(ctx, transaction)
	if err != nil {
		return err
	}
	if err := checkOperation(commit.Operation, target); err != nil {
		return err
	}
	stored, present, err := s.intent(ctx, target)
	if err != nil {
		return err
	}
	if !present || stored.Status != "cancelled" || stored.CancellationEpoch != lane.CancellationEpoch ||
		stored.OperationID != commit.Operation.ID || stored.Swap.OperationID != commit.Operation.ID ||
		stored.ExpectedGeneration != lane.Generation || stored.Swap.ExpectedGeneration != lane.Generation ||
		stored.Swap.CancellationEpoch != lane.CancellationEpoch {
		return problem(api.CodeIntegrity, "cancellation was not durably retained")
	}
	return nil
}
