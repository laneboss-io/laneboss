package store

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Caller holds the sole writer. This is the consumed-once reservation, not
// an execution lease or a credential receipt. Only its PlanLaunch effect's
// live claim may subsequently acquire and persist the selected slot.
func (s *Service) reserveWatch(ctx context.Context, scope api.Scope, q api.LaunchReservationRequest) (r api.LaunchReservation, resultErr error) {
	if !watchdogReader(scope) {
		return r, fault(api.CodeForbidden, "continuation needs its private watchdog reader")
	}
	var i api.ContinuationIntent
	if err := storedProjection(ctx, s.db, "continuation", q.ContinuationID, &i); err != nil {
		return r, err
	}
	if i.OperationID != q.OperationID || i.Swap.OperationID != q.OperationID || i.ID != q.ContinuationID {
		return r, fault(api.CodeConflict, "continuation operation or identity changed")
	}
	var owner launchOwner
	err := storedProjection(ctx, s.db, "launch_operation", q.OperationID, &owner)
	if err == nil {
		if owner.Actor != scope.Actor || !sameValue(owner.Request, q) || i.Status != "claimed" && i.Status != "completed" {
			return r, fault(api.CodeConflict, "continuation replay changed its claim or requester")
		}
		var saved api.LaunchPlanRecord
		if err := storedProjection(ctx, s.db, "launch_plan", owner.ReservationID, &saved); err != nil {
			return r, err
		}
		if err := s.checkLaunchBytes(ctx, s.db, saved); err != nil {
			return r, err
		}
		return saved.Reservation, nil
	}
	if !absent(err) {
		return r, err
	}
	if i.Status != "pending" || i.Slot != nil {
		return r, fault(api.CodeConflict, "continuation has no unconsumed pending selection")
	}
	if err := s.dispatchAllowed(ctx, s.db); err != nil {
		return r, err
	}
	var lane api.Lane
	if err := storedProjection(ctx, s.db, "lane", i.Target.LifeID, &lane); err != nil {
		return r, err
	}
	if scope.PolicyGeneration != lane.PolicyGeneration {
		return r, fault(api.CodeConflict, "continuation policy changed")
	}
	if err := s.contFence(ctx, s.db, lane, i, false); err != nil {
		return r, err
	}
	var op api.Operation
	var opOwner string
	var raw []byte
	if err := s.db.QueryRowContext(ctx, "SELECT principal,data FROM operations WHERE id=?", string(q.OperationID)).Scan(&opOwner, &raw); err != nil {
		return r, err
	}
	if err := wire.Decode(raw, &op); err != nil {
		return r, err
	}
	if opOwner != principal(scope) || op.LifeID != i.Target.LifeID || op.Run != i.Target.Run || op.Status != "pending" || op.Error != nil {
		return r, fault(api.CodeForbidden, "continuation has no matching pending journal operation")
	}
	var eventRaw []byte
	if err := s.db.QueryRowContext(ctx, "SELECT data FROM events WHERE json_extract(data,'$.operation_id')=? ORDER BY seq LIMIT 1", string(q.OperationID)).Scan(&eventRaw); err != nil {
		return r, err
	}
	var event api.Event
	if err := wire.Decode(eventRaw, &event); err != nil {
		return r, err
	}
	if event.Config != scope.Config || event.Actor != scope.Actor || event.LifeID != i.Target.LifeID || event.Run != i.Target.Run || event.Origin != "service" {
		return r, fault(api.CodeForbidden, "continuation journal lost its actual causal requester")
	}
	input := api.ContinuationRequest{IntentID: i.ID, Swap: i.Swap}
	original, err := canonicalValue(input)
	if err != nil {
		return r, err
	}
	r = api.LaunchReservation{Config: scope.Config, Mode: "continue", OperationID: q.OperationID,
		RequestID: event.RequestID, RequestSHA256: api.Digest(hash(original)), RequestedBy: scope.Actor,
		PolicyGeneration: lane.PolicyGeneration, StarterChain: []api.ID{}}
	for _, id := range []*api.ID{&r.ID, &r.LaunchID, &r.SpecID} {
		*id, err = wire.NewID()
		if err != nil {
			return r, err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r, err
	}
	defer finish(tx, &resultErr)
	if err := s.guards(ctx, tx, api.Transaction{Scope: scope, Guards: q.Guards}, q.OperationID); err != nil {
		return r, err
	}
	if err := s.reserveRetainedLife(ctx, tx, scope, i.Target, i.ExpectedGeneration, lane.BudgetRemaining, &r); err != nil {
		return r, err
	}
	r.Authority = api.LaunchAuthority{Kind: "starter", ID: r.PreviousLaunchID}
	objectID, err := wire.NewID()
	if err != nil {
		return r, err
	}
	actor := api.Actor{Kind: "service", ID: s.storeID}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))
	r.OriginalRequest, err = s.retain(ctx, tx, api.Scope{Config: scope.Config, Actor: actor}, api.ObjectWrite{ObjectKey: objectID,
		Class: "launch_request", Bytes: original, SHA256: api.Digest(hash(original)), Origin: "service",
		ACL: api.ObjectACL{Config: scope.Config, Owner: actor, LifeID: r.Target.LifeID, Audience: "owner", Generation: 1}}, q.OperationID, now)
	if err != nil {
		return r, err
	}
	if err := api.ValidateLaunchReservation(r); err != nil {
		return r, err
	}
	effectID, err := wire.NewID()
	if err != nil {
		return r, err
	}
	causeID, err := wire.NewID()
	if err != nil {
		return r, err
	}
	cause := api.InternalIntent{ID: causeID, Kind: api.InternalLaunchPlan, Config: scope.Config, Actor: actor, RequestedBy: scope.Actor,
		CauseOperationID: q.OperationID, CauseRequestID: r.RequestID, EffectID: effectID, Target: r.Target,
		CancellationEpoch: r.CancellationEpoch, LogicalTurnID: i.LogicalTurnID}
	if err := insertLaunchEffect(ctx, tx, api.Effect{ID: effectID, OperationID: q.OperationID, Context: &cause, PlanLaunch: &api.LaunchPlanEffect{ReservationID: r.ID}}); err != nil {
		return r, err
	}
	i.Status, i.Generation = "claimed", i.Generation+1
	claim := continuationClaim{Planning: true, Input: api.ContinuationClaimRequest{Intent: api.InternalIntent{
		ID: causeID, Kind: api.InternalProfileContinue, Config: scope.Config, Actor: scope.Actor, RequestedBy: scope.Actor,
		CauseOperationID: q.OperationID, CauseRequestID: r.RequestID, Target: i.Target, EffectID: effectID,
		CancellationEpoch: i.CancellationEpoch, LogicalTurnID: i.LogicalTurnID}, Request: input},
		ClaimantID: scope.Actor.ID, Generation: 1, Original: original}
	for _, row := range []struct {
		kind  string
		id    api.ID
		gen   api.Generation
		value any
	}{
		{"continuation", i.ID, i.Generation, i}, {"continuation_claim", i.ID, 1, claim},
		{"launch_plan", r.ID, 1, api.LaunchPlanRecord{Reservation: r, Generation: 1, Phase: "reserved"}},
		{"launch_operation", q.OperationID, 1, launchOwner{Request: q, ReservationID: r.ID, Actor: scope.Actor}},
	} {
		if err := put(ctx, tx, row.kind, row.id, row.gen, row.value); err != nil {
			return r, err
		}
	}
	op.Run = r.Target.Run
	raw, err = json.Marshal(op)
	if err != nil {
		return r, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE operations SET data=? WHERE id=?", raw, string(op.ID)); err != nil {
		return r, err
	}
	if err := tx.Commit(); err != nil {
		return r, err
	}
	s.notifyChanged()
	return r, nil
}
