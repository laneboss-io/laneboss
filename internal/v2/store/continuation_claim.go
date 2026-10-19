package store

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type continuationClaim struct {
	Planning         bool
	Input            api.ContinuationClaimRequest
	ClaimID          api.ID
	ClaimantID       api.ID
	Generation       api.Generation
	EffectGeneration api.Generation
	Original         []byte
}

func (s *Service) claimContinuation(ctx context.Context, scope api.Scope, request api.ContinuationClaimRequest) (result api.ContinuationIntent, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return result, err
	}
	if !internalScope(scope) || request.Intent.Kind != api.InternalProfileContinue || request.Intent.Actor != scope.Actor || request.Intent.Config != scope.Config || request.Intent.RequestedBy.Kind != "service" && request.Intent.RequestedBy.Kind != "scheduler" && request.Intent.RequestedBy.Kind != "watchdog" {
		return result, fault(api.CodeForbidden, "continuation requires its authentic internal stage")
	}
	effect, err := effectRow(ctx, s.db, request.Intent.EffectID)
	if err != nil {
		return result, err
	}
	if effect.ClaimID == "" || effect.ClaimantID != scope.Actor.ID || effect.Outcome != nil || !future(effect.ClaimExpiresAt, s.deps.Clock.Now()) || effect.Effect.Swap == nil ||
		!sameValue(*effect.Effect.Swap, request.Request.Swap) || effect.Effect.Context.RequestedBy != request.Intent.RequestedBy || effect.Effect.OperationID != request.Intent.CauseOperationID || effect.Effect.Context.CauseRequestID != request.Intent.CauseRequestID || effect.Effect.Context.Target != request.Intent.Target || effect.Effect.Context.LogicalTurnID != request.Intent.LogicalTurnID {
		return result, fault(api.CodeConflict, "continuation has no current original swap claim")
	}
	if err := storedProjection(ctx, s.db, "continuation", request.Request.IntentID, &result); err != nil {
		return result, err
	}
	var previous continuationClaim
	err = storedProjection(ctx, s.db, "continuation_claim", result.ID, &previous)
	if err == nil {
		before, after := previous.Input, request
		before.Intent.ID, after.Intent.ID = "", ""
		before.Intent.Actor, after.Intent.Actor = api.Actor{}, api.Actor{}
		if !sameValue(before, after) {
			return result, fault(api.CodeConflict, "continuation claim retry changed its causal inputs")
		}
		if previous.ClaimID == effect.ClaimID && previous.EffectGeneration == effect.Generation && previous.ClaimantID == scope.Actor.ID {
			return result, nil
		}
		if result.Status != "claimed" {
			return result, fault(api.CodeConflict, "continuation is no longer claimable")
		}
		var lane api.Lane
		if err := storedProjection(ctx, s.db, "lane", result.Target.LifeID, &lane); err != nil {
			return result, err
		}
		if err := s.continuationFence(ctx, s.db, lane, result); err != nil {
			return result, err
		}
		previous.ClaimID, previous.ClaimantID, previous.EffectGeneration, previous.Generation = effect.ClaimID, scope.Actor.ID, effect.Generation, previous.Generation+1
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return result, err
		}
		defer finish(tx, &resultErr)
		if err := put(ctx, tx, "continuation_claim", result.ID, previous.Generation, previous); err != nil {
			return result, err
		}
		if err := tx.Commit(); err != nil {
			return result, err
		}
		return result, nil
	}
	if !absent(err) {
		return result, err
	}
	if result.Status != "pending" && result.Status != "ready" || result.OperationID != effect.Effect.OperationID || !sameValue(result.Swap, request.Request.Swap) || result.Target != request.Intent.Target || result.CancellationEpoch != request.Intent.CancellationEpoch {
		return result, fault(api.CodeConflict, "continuation intent changed before claim")
	}
	var lane api.Lane
	if err := storedProjection(ctx, s.db, "lane", result.Target.LifeID, &lane); err != nil {
		return result, err
	}
	if err := s.continuationFence(ctx, s.db, lane, result); err != nil {
		return result, err
	}
	original, err := canonicalValue(request)
	if err != nil {
		return result, err
	}
	if len(original) > api.MaxFrameBytes {
		return result, wire.Invalid("continuation input exceeds retained frame bound")
	}
	result.Status, result.Generation = "claimed", result.Generation+1
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	if err := put(ctx, tx, "continuation", result.ID, result.Generation, result); err != nil {
		return result, err
	}
	if err := put(ctx, tx, "continuation_claim", result.ID, 1, continuationClaim{Input: request, ClaimID: effect.ClaimID, ClaimantID: scope.Actor.ID, Generation: 1, EffectGeneration: effect.Generation, Original: original}); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	s.notifyChanged()
	return result, nil
}

func (s *Service) continuationFence(ctx context.Context, db queryer, lane api.Lane, intent api.ContinuationIntent) error {
	return s.contFence(ctx, db, lane, intent, true)
}

func (s *Service) contFence(ctx context.Context, db queryer, lane api.Lane, intent api.ContinuationIntent, slot bool) error {
	var policy api.EffectivePolicy
	if err := storedProjection(ctx, db, "policy", api.ID(s.deps.Config), &policy); err != nil {
		return err
	}
	if policy.Generation != lane.PolicyGeneration {
		return fault(api.CodeConflict, "continuation policy generation changed")
	}
	swap, eligible := intent.Swap, intent.Eligibility
	if intent.Target.Run != lane.Run || intent.ExpectedGeneration != lane.Generation || intent.CancellationEpoch != lane.CancellationEpoch || intent.LogicalTurnID != lane.LogicalTurnID ||
		swap.ExpectedGeneration != lane.Generation || swap.CancellationEpoch != lane.CancellationEpoch || swap.CausingRun != lane.Run || swap.ContinuationRun != lane.Run+1 || swap.LogicalTurnID != lane.LogicalTurnID ||
		swap.EligibilityID != eligible.ID || !eligible.Compatible || !future(eligible.ExpiresAt, s.deps.Clock.Now()) || eligible.Request.Target != intent.Target || eligible.Request.Session != lane.Session ||
		eligible.Request.HistoryID != lane.Session.HistoryID || eligible.Request.GrantSetID != lane.GrantSetID || eligible.Request.ToGrantID != swap.ProfileGrantID ||
		eligible.Request.Driver != lane.Session.Driver || eligible.Request.Model != lane.Model || !swap.Room.Available || swap.Room.ProfileID != swap.ToProfileID || !future(swap.Room.ExpiresAt, s.deps.Clock.Now()) ||
		slot && intent.Slot == nil || intent.Slot != nil && (intent.Slot.ProfileGrantID != swap.ProfileGrantID || intent.Slot.ProfileID != swap.ToProfileID || !future(intent.Slot.ExpiresAt, s.deps.Clock.Now())) {
		return fault(api.CodeConflict, "continuation claim, eligibility, slot or logical-turn fence changed")
	}
	var grants api.GrantSet
	if err := storedProjection(ctx, db, "grants", lane.GrantSetID, &grants); err != nil {
		return err
	}
	from, to := false, false
	fromPaid, toPaid := false, false
	for _, profile := range grants.Profiles {
		if profile.ID == eligible.Request.FromGrantID && profile.ProfileID == swap.FromProfileID {
			from, fromPaid = true, profile.Paid
		}
		if profile.ID == eligible.Request.ToGrantID && profile.ProfileID == swap.ToProfileID && future(profile.ExpiresAt, s.deps.Clock.Now()) {
			to, toPaid = true, profile.Paid
		}
	}
	if grants.Revoked || !future(grants.ExpiresAt, s.deps.Clock.Now()) || !from || !to || !fromPaid && toPaid {
		return fault(api.CodeForbidden, "continuation cannot widen grants or select a paid fallback")
	}
	metadata, _, err := objectRow(ctx, db, eligible.Evidence.ID)
	if err != nil {
		return err
	}
	if metadata.Ref != eligible.Evidence {
		return fault(api.CodeIntegrity, "continuation eligibility lost its retained evidence")
	}
	prior, err := s.launchBinding(ctx, db, lane.LaunchID)
	if err != nil {
		return err
	}
	if prior.Recovery == nil || prior.Recovery.Capture.Status != "registered" {
		return fault(api.CodeForbidden, "continuation requires registered primary capture")
	}
	var eventData []byte
	if err := db.QueryRowContext(ctx, "SELECT data FROM events WHERE json_extract(data,'$.kind') IN ('capture.appended','capture.framed') AND json_extract(data,'$.payload.id')=?", string(swap.Limit.CaptureID)).Scan(&eventData); err != nil {
		return fault(api.CodeForbidden, "continuation limit has no retained primary capture")
	}
	var event api.Event
	if err := wire.Decode(eventData, &event); err != nil {
		return err
	}
	var captured api.CaptureRecord
	if err := wire.Decode(event.Payload, &captured); err != nil {
		return err
	}
	if !captured.Primary || captured.BindingID != prior.Recovery.Capture.ID || captured.Target != intent.Target || captured.Data.SHA256 != swap.Limit.CaptureSHA256 || swap.Limit.Target != intent.Target {
		return fault(api.CodeForbidden, "continuation limit differs from the original captured run")
	}
	return nil
}

// Continue is a typed in-process operation, not a public RPC frame. Retain
// exactly the canonical bytes of its actual ClaimContinuation input, including
// the original requester and swap. Never manufacture a human request envelope.
func (s *Service) reserveInternalContinuation(ctx context.Context, scope api.Scope, request api.LaunchReservationRequest) (result api.LaunchReservation, resultErr error) {
	if scope.Actor.Kind == "watchdog" {
		return s.reserveWatch(ctx, scope, request)
	}
	if !internalScope(scope) || scope.Request.Method != "" {
		return result, fault(api.CodeForbidden, "internal continuation cannot borrow a public request")
	}
	var claim continuationClaim
	if err := storedProjection(ctx, s.db, "continuation_claim", request.ContinuationID, &claim); err != nil {
		return result, err
	}
	if claim.Input.Intent.CauseOperationID != request.OperationID || claim.ClaimantID != scope.Actor.ID {
		return result, fault(api.CodeForbidden, "continuation reservation belongs to another operation or actor")
	}
	effect, err := effectRow(ctx, s.db, claim.Input.Intent.EffectID)
	if err != nil {
		return result, err
	}
	if effect.ClaimID != claim.ClaimID || effect.Generation != claim.EffectGeneration || effect.ClaimantID != scope.Actor.ID || effect.Outcome != nil || !future(effect.ClaimExpiresAt, s.deps.Clock.Now()) {
		return result, fault(api.CodeConflict, "continuation swap claim expired or changed")
	}
	var owner launchOwner
	err = storedProjection(ctx, s.db, "launch_operation", request.OperationID, &owner)
	if err == nil {
		if !sameValue(owner.Request, request) || owner.Actor != claim.Input.Intent.RequestedBy {
			return result, fault(api.CodeIdempotencyConflict, "continuation reservation retry changed its input")
		}
		var saved api.LaunchPlanRecord
		if err := storedProjection(ctx, s.db, "launch_plan", owner.ReservationID, &saved); err != nil {
			return result, err
		}
		if err := s.checkLaunchBytes(ctx, s.db, saved); err != nil {
			return result, err
		}
		return saved.Reservation, nil
	}
	if !absent(err) {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	var policy api.EffectivePolicy
	if err := storedProjection(ctx, tx, "policy", api.ID(scope.Config), &policy); err != nil {
		return result, err
	}
	if scope.PolicyGeneration != policy.Generation {
		return result, fault(api.CodeConflict, "continuation policy changed")
	}
	intent := claim.Input.Intent
	result = api.LaunchReservation{Config: scope.Config, Mode: "continue", OperationID: request.OperationID, RequestID: intent.CauseRequestID, RequestSHA256: api.Digest(hash(claim.Original)), RequestedBy: intent.RequestedBy, PolicyGeneration: policy.Generation, StarterChain: []api.ID{}}
	for _, id := range []*api.ID{&result.ID, &result.LaunchID, &result.SpecID} {
		*id, err = wire.NewID()
		if err != nil {
			return result, err
		}
	}
	if err := s.reserveContinuation(ctx, tx, scope, request, &result); err != nil {
		return result, err
	}
	result.Authority = api.LaunchAuthority{Kind: "starter", ID: result.PreviousLaunchID}
	if err := s.guards(ctx, tx, api.Transaction{Scope: scope, Guards: request.Guards}, result.OperationID); err != nil {
		return result, err
	}
	serviceActor := api.Actor{Kind: "service", ID: s.storeID}
	objectID, err := wire.NewID()
	if err != nil {
		return result, err
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))
	result.OriginalRequest, err = s.retain(ctx, tx, api.Scope{Config: scope.Config, Actor: serviceActor}, api.ObjectWrite{ObjectKey: objectID, Class: "launch_request", Bytes: claim.Original, SHA256: api.Digest(hash(claim.Original)), Origin: "service", ACL: api.ObjectACL{Config: scope.Config, Owner: serviceActor, LifeID: result.Target.LifeID, Audience: "owner", Generation: 1}}, result.OperationID, now)
	if err != nil {
		return result, err
	}
	if err := api.ValidateLaunchReservation(result); err != nil {
		return result, err
	}
	if err := put(ctx, tx, "launch_plan", result.ID, 1, api.LaunchPlanRecord{Reservation: result, Generation: 1, Phase: "reserved"}); err != nil {
		return result, err
	}
	if err := put(ctx, tx, "launch_operation", result.OperationID, 1, launchOwner{Request: request, ReservationID: result.ID, Actor: result.RequestedBy}); err != nil {
		return result, err
	}
	effectID, err := wire.NewID()
	if err != nil {
		return result, err
	}
	intentID, err := wire.NewID()
	if err != nil {
		return result, err
	}
	cause := api.InternalIntent{ID: intentID, Kind: api.InternalLaunchPlan, Config: scope.Config, Actor: serviceActor, RequestedBy: result.RequestedBy, CauseOperationID: result.OperationID, CauseRequestID: result.RequestID, EffectID: effectID, Target: result.Target, CancellationEpoch: result.CancellationEpoch, LogicalTurnID: intent.LogicalTurnID}
	if err := insertLaunchEffect(ctx, tx, api.Effect{ID: effectID, OperationID: result.OperationID, Context: &cause, PlanLaunch: &api.LaunchPlanEffect{ReservationID: result.ID}}); err != nil {
		return result, err
	}
	var operationData []byte
	var operation api.Operation
	if err := tx.QueryRowContext(ctx, "SELECT data FROM operations WHERE id=?", string(result.OperationID)).Scan(&operationData); err != nil {
		return result, err
	}
	if err := wire.Decode(operationData, &operation); err != nil {
		return result, err
	}
	if operation.Status != "pending" && operation.Status != "running" {
		return result, fault(api.CodeConflict, "continuation operation is no longer pending")
	}
	operation.Status, operation.LifeID, operation.Run = "pending", result.Target.LifeID, result.Target.Run
	operationData, err = json.Marshal(operation)
	if err != nil {
		return result, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE operations SET data=? WHERE id=?", operationData, string(operation.ID)); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	s.notifyChanged()
	return result, nil
}
