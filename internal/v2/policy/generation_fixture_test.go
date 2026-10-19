package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"laneboss.io/laneboss/internal/v2/api"
)

// Test-only protected ports. These validate and apply the actual narrow DTO
// transaction, but do not claim a production store lock, native peer or D6.
func (s *testStore) PolicyAt(_ context.Context, scope api.Scope, generation api.Generation) (api.EffectivePolicy, error) {
	s.historyReads = append(s.historyReads, generation)
	if s.historyErr != nil {
		return api.EffectivePolicy{}, s.historyErr
	}
	if scope.Config != s.org.Config || generation == 0 || generation > scope.PolicyGeneration {
		return api.EffectivePolicy{}, forbiddenTarget()
	}
	policy, found := s.policyHistory[generation]
	if !found {
		return api.EffectivePolicy{}, &api.Error{Code: api.CodeNotFound}
	}
	return copyPolicy(policy), nil
}

func (s *testStore) RefreshLanePolicy(ctx context.Context, scope api.Scope, request api.PolicyAdvanceRequest) (api.PolicyAdvanceReceipt, error) {
	s.advanceRequests = append(s.advanceRequests, request)
	if s.advanceErr != nil {
		return api.PolicyAdvanceReceipt{}, s.advanceErr
	}
	owner, err := s.LookupReceipt(ctx, scope, testScopeKey(scope))
	if err != nil {
		return api.PolicyAdvanceReceipt{}, err
	}
	if owner.Reply != nil || scope.PolicyGeneration != s.policy.Generation || request.ExpectedLaneGeneration != s.lane.Generation ||
		request.CancellationEpoch != s.lane.CancellationEpoch || request.FromGeneration != s.lane.PolicyGeneration ||
		request.ToGeneration != s.policy.Generation || request.Target != (api.LifeRef{LifeID: s.lane.LifeID, Run: s.lane.Run}) {
		return api.PolicyAdvanceReceipt{}, conflict("fixture policy refresh lost its current fence")
	}
	before := s.lane
	if before.PolicyGeneration == s.policy.Generation {
		return api.PolicyAdvanceReceipt{Lane: before}, nil
	}
	after := before
	after.Generation++
	after.PolicyGeneration, after.LastSeq = s.policy.Generation, s.seq+1
	payload := api.PolicyAdvanceEvent{FromGeneration: before.PolicyGeneration, ToGeneration: after.PolicyGeneration,
		LaneGeneration: after.Generation, PolicySHA256: s.policy.SHA256, GrantSetID: before.GrantSetID}
	receipt := api.PolicyAdvanceReceipt{Changed: true, Lane: after, Event: payload,
		EventID: api.ID(fmt.Sprintf("policy-refresh-%d", s.seq+1)), CommittedSeq: s.seq + 1}
	if err := api.ValidatePolicyAdvance(before, request, s.policy, receipt); err != nil {
		return api.PolicyAdvanceReceipt{}, err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return api.PolicyAdvanceReceipt{}, err
	}
	actor := api.Actor{Kind: "service", ID: "lb-v2-policy"}
	event := api.Event{Schema: api.SchemaVersion, ID: receipt.EventID, Config: scope.Config, Kind: "lane.policy",
		Actor: actor, RequestedBy: scope.Actor, LifeID: before.LifeID, Run: before.Run, Seq: receipt.CommittedSeq,
		Origin: "service", OperationID: owner.Operation.ID, RequestID: scope.Request.RequestID, Payload: raw}
	cause := api.InternalIntent{ID: receipt.EventID, Kind: api.InternalPolicyRefresh, Config: scope.Config,
		Actor: actor, RequestedBy: scope.Actor, CauseRequestID: scope.Request.RequestID, CauseOperationID: owner.Operation.ID,
		Target: request.Target, CancellationEpoch: request.CancellationEpoch}
	tx := api.Transaction{Scope: api.Scope{Config: scope.Config, Actor: actor}, Internal: &cause, Writes: api.StateWrites{Lanes: []api.Lane{after}},
		Events: []api.Event{event}, Compare: []api.Compare{{Kind: api.CompareLane, ID: before.LifeID, Generation: before.Generation}},
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: before.LifeID, Epoch: before.CancellationEpoch}}}}
	if err := api.ValidateTransactionShape(tx); err != nil {
		return api.PolicyAdvanceReceipt{}, err
	}
	s.lane, s.seq, s.policyTx = after, receipt.CommittedSeq, tx
	s.policyEvents = append(s.policyEvents, event)
	if s.alterAdvance != nil {
		s.alterAdvance(&receipt)
	}
	return receipt, nil
}
