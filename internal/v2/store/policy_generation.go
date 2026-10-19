package store

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func (s *Service) PolicyAt(ctx context.Context, scope api.Scope, generation api.Generation) (api.EffectivePolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.EffectivePolicy{}, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return api.EffectivePolicy{}, err
	}
	return s.policyAt(ctx, s.db, generation)
}

func (s *Service) policyAt(ctx context.Context, db readDatabase, generation api.Generation) (api.EffectivePolicy, error) {
	var current api.EffectivePolicy
	if err := storedProjection(ctx, db, "policy", api.ID(s.deps.Config), &current); err != nil {
		return current, err
	}
	if generation == 0 || generation > current.Generation {
		return api.EffectivePolicy{}, fault(api.CodeConflict, "policy generation is not an approved retained snapshot")
	}
	rows, err := db.QueryContext(ctx, "SELECT data,sha256 FROM projection_history WHERE kind='policy' AND id=? AND json_extract(data,'$.generation')=? ORDER BY seq", s.deps.Config, uint64(generation))
	if err != nil {
		return api.EffectivePolicy{}, err
	}
	defer rows.Close()
	var result api.EffectivePolicy
	found := false
	for rows.Next() {
		var data []byte
		var digest string
		var policy api.EffectivePolicy
		if err := rows.Scan(&data, &digest); err != nil {
			return result, err
		}
		if hash(data) != digest || decodeStored(data, &policy) != nil || policy.Generation != generation || !wire.ValidDigest(string(policy.SHA256)) || found && !sameValue(result, policy) {
			return api.EffectivePolicy{}, fault(api.CodeIntegrity, "approved policy history is ambiguous or corrupt")
		}
		result, found = policy, true
	}
	if err := rows.Err(); err != nil {
		return result, err
	}
	if !found {
		return result, fault(api.CodeNotFound, "approved policy snapshot is absent")
	}
	return result, nil
}

func (s *Service) validatePolicyRefresh(ctx context.Context, db queryer, input api.Transaction) error {
	if len(input.Writes.Lanes) != 1 || len(input.Events) != 1 {
		return fault(api.CodeForbidden, "policy refresh requires one lane and one policy event")
	}
	next, event := input.Writes.Lanes[0], input.Events[0]
	var before api.Lane
	var current api.EffectivePolicy
	var payload api.PolicyAdvanceEvent
	if err := storedProjection(ctx, db, "lane", next.LifeID, &before); err != nil {
		return err
	}
	if err := storedProjection(ctx, db, "policy", api.ID(s.deps.Config), &current); err != nil {
		return err
	}
	var err error
	current, err = s.storedRolePolicy(ctx, db, current, before)
	if err != nil {
		return err
	}
	if err := wire.Decode(event.Payload, &payload); err != nil {
		return err
	}
	request := api.PolicyAdvanceRequest{Target: api.LifeRef{LifeID: before.LifeID, Run: before.Run}, ExpectedLaneGeneration: before.Generation, FromGeneration: before.PolicyGeneration, ToGeneration: current.Generation, CancellationEpoch: before.CancellationEpoch}
	if event.Origin != "service" || event.LifeID != before.LifeID || event.Run != before.Run || input.Internal.Target != request.Target || input.Internal.CancellationEpoch != before.CancellationEpoch {
		return fault(api.CodeForbidden, "policy refresh event differs from the current life")
	}
	var actual api.Sequence
	if err := db.QueryRowContext(ctx, "SELECT coalesce(max(seq),0)+1 FROM events").Scan(&actual); err != nil {
		return err
	}
	if next.LastSeq != actual {
		return fault(api.CodeForbidden, "policy refresh sequence differs from its actual journal head")
	}
	// LastSeq is stamped by the store coordinator; it must not change any
	// other projection field or historical launch/grant byte.
	return api.ValidatePolicyAdvance(before, request, current, api.PolicyAdvanceReceipt{Changed: true, Lane: next, Event: payload, EventID: event.ID, CommittedSeq: next.LastSeq})
}

func (s *Service) RefreshLanePolicy(ctx context.Context, scope api.Scope, request api.PolicyAdvanceRequest) (api.PolicyAdvanceReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result api.PolicyAdvanceReceipt
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return result, err
	}
	requestedBy := scope.Actor
	var parent, parentRequest, parentTurn api.ID
	if !internalScope(scope) || scope.Actor.Kind != "service" {
		// The policy component calls this port with its original admitted lane
		// frame. Resolve that parent before constructing the internal writer.
		if scope.Actor.Kind != "lane" || scope.Request.Method != "policy.evaluate" || scope.Actor.LifeID != request.Target.LifeID {
			return result, fault(api.CodeForbidden, "policy refresh requires the bound service coordinator")
		}
		if err := verifyProjectionFrame(ctx, scope, "policy.evaluate"); err != nil {
			return result, err
		}
		retained, err := s.lookupReceipt(ctx, s.db, scope, requestKey(scope.Request))
		if err != nil {
			return result, err
		}
		if retained.Reply != nil || retained.Deferred != nil || retained.Actor != scope.Actor {
			return result, fault(api.CodeConflict, "policy refresh has no pending original evaluation")
		}
		var input api.PolicyEvaluateRequest
		if err := api.DecodeObject(scope.Request.Params, &input); err != nil {
			return result, err
		}
		if input.Target != request.Target || input.LogicalTurnID == "" {
			return result, fault(api.CodeForbidden, "policy refresh target differs from its original evaluation")
		}
		parent, parentRequest, parentTurn = retained.Operation.ID, scope.Request.RequestID, input.LogicalTurnID
		scope = api.Scope{Config: scope.Config, Actor: api.Actor{Kind: "service", ID: "lb-v2-policy"}, Source: "service", PolicyGeneration: scope.PolicyGeneration}
	}
	var before api.Lane
	var current api.EffectivePolicy
	var grants api.GrantSet
	if err := storedProjection(ctx, s.db, "lane", request.Target.LifeID, &before); err != nil {
		return result, err
	}
	if parentTurn != "" && parentTurn != before.LogicalTurnID {
		return result, fault(api.CodeConflict, "policy refresh original turn changed")
	}
	if err := storedProjection(ctx, s.db, "policy", api.ID(s.deps.Config), &current); err != nil {
		return result, err
	}
	var err error
	current, err = s.storedRolePolicy(ctx, s.db, current, before)
	if err != nil {
		return result, err
	}
	if err := storedProjection(ctx, s.db, "grants", before.GrantSetID, &grants); err != nil {
		return result, err
	}
	if grants.Revoked || grants.LifeID != before.LifeID || !future(grants.ExpiresAt, s.deps.Clock.Now()) {
		return result, fault(api.CodeForbidden, "policy refresh lacks current life grants")
	}
	result.Lane = before
	if before.PolicyGeneration == current.Generation {
		return result, api.ValidatePolicyAdvance(before, request, current, result)
	}
	if err := s.db.QueryRowContext(ctx, "SELECT coalesce(max(seq),0)+1 FROM events").Scan(&result.CommittedSeq); err != nil {
		return result, err
	}
	result.EventID, err = wire.NewID()
	if err != nil {
		return result, err
	}
	result.Changed = true
	result.Lane.Generation++
	result.Lane.PolicyGeneration = current.Generation
	result.Lane.LastSeq = result.CommittedSeq
	result.Event = api.PolicyAdvanceEvent{FromGeneration: before.PolicyGeneration, ToGeneration: current.Generation, LaneGeneration: result.Lane.Generation, PolicySHA256: current.SHA256, GrantSetID: before.GrantSetID}
	if err := api.ValidatePolicyAdvance(before, request, current, result); err != nil {
		return api.PolicyAdvanceReceipt{}, err
	}
	payload, err := json.Marshal(result.Event)
	if err != nil {
		return api.PolicyAdvanceReceipt{}, err
	}
	id, err := wire.NewID()
	if err != nil {
		return api.PolicyAdvanceReceipt{}, err
	}
	cause := api.InternalIntent{ID: id, Kind: api.InternalPolicyRefresh, Config: scope.Config, Actor: scope.Actor, RequestedBy: requestedBy, Target: request.Target, CancellationEpoch: request.CancellationEpoch, CauseOperationID: parent, CauseRequestID: parentRequest}
	event := api.Event{Schema: api.SchemaVersion, ID: result.EventID, Config: scope.Config, Kind: "lane.policy", Actor: scope.Actor, RequestedBy: requestedBy, LifeID: before.LifeID, Run: before.Run, LogicalTurnID: before.LogicalTurnID, Origin: "service", Payload: payload, StarterChain: append([]api.ID{}, before.StarterChain...)}
	commit, err := s.transactInternal(ctx, api.Transaction{Scope: scope, Internal: &cause, Writes: api.StateWrites{Lanes: []api.Lane{result.Lane}}, Events: []api.Event{event}, Compare: []api.Compare{{Kind: api.CompareLane, ID: before.LifeID, Generation: before.Generation}}, Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: before.LifeID, Epoch: before.CancellationEpoch}}}})
	if err != nil {
		return api.PolicyAdvanceReceipt{}, err
	}
	if commit.LastSeq != result.CommittedSeq {
		return api.PolicyAdvanceReceipt{}, fault(api.CodeIntegrity, "policy refresh lost its actual committed head")
	}
	return result, nil
}
