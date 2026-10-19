package store

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

// The policy module retains generated input under the real admitted public
// operation. This port accepts no new RPC, public write or caller-selected
// component authority; all owner/cause/target facts are joined under the lock.
func (s *Service) policyRetentionScope(ctx context.Context, scope api.Scope, request api.RetainObjectRequest) (api.Scope, error) {
	if err := s.readScope(ctx, scope); err != nil {
		return api.Scope{}, err
	}
	if err := verifyProjectionFrame(ctx, scope, "policy.evaluate"); err != nil {
		return api.Scope{}, err
	}
	i, o := request.Intent, request.Object
	if scope.Request.Proof != nil || i.Kind != api.InternalObjectRetain || i.Actor != (api.Actor{Kind: "service", ID: "lb-v2-policy"}) || i.RequestedBy != scope.Actor || i.Config != scope.Config || i.CauseRequestID != scope.Request.RequestID || i.EffectID != "" ||
		o.Class != "judge_request" || o.Origin != "service" || o.ACL.Config != scope.Config || o.ACL.Owner != scope.Actor || o.ACL.LifeID != i.Target.LifeID || o.ACL.Audience != "owner" || o.ACL.Generation != 1 || len(o.ACL.Participants) != 0 {
		return api.Scope{}, fault(api.CodeForbidden, "policy retention changed its original component or principal")
	}
	receipt, err := s.lookupReceipt(ctx, s.db, scope, requestKey(scope.Request))
	if err != nil {
		return api.Scope{}, err
	}
	if receipt.Reply != nil || receipt.Actor != scope.Actor || receipt.Config != scope.Config || receipt.Operation.ID != i.CauseOperationID || receipt.Key != requestKey(scope.Request) {
		return api.Scope{}, fault(api.CodeForbidden, "policy retention has no matching pending causal operation")
	}
	var input api.PolicyEvaluateRequest
	if err := api.DecodeObject(scope.Request.Params, &input); err != nil {
		return api.Scope{}, err
	}
	if input.Target != i.Target || input.LogicalTurnID != i.LogicalTurnID || scope.Actor.Kind == "lane" && scope.Actor.LifeID != i.Target.LifeID {
		return api.Scope{}, fault(api.CodeForbidden, "policy retention target differs from its admitted request")
	}
	var lane api.Lane
	var policy api.EffectivePolicy
	if err := storedProjection(ctx, s.db, "lane", i.Target.LifeID, &lane); err != nil {
		return api.Scope{}, err
	}
	if err := storedProjection(ctx, s.db, "policy", api.ID(scope.Config), &policy); err != nil {
		return api.Scope{}, err
	}
	if lane.Cleaned || lane.Run != i.Target.Run || lane.LogicalTurnID != i.LogicalTurnID || policy.Generation != scope.PolicyGeneration || i.CancellationEpoch != 0 && i.CancellationEpoch != lane.CancellationEpoch {
		return api.Scope{}, fault(api.CodeConflict, "policy retention life, turn or generation changed")
	}
	task := false
	for _, ref := range o.InputRefs {
		metadata, _, err := objectRow(ctx, s.db, ref.ID)
		if err != nil {
			return api.Scope{}, err
		}
		visible, err := s.visibleObject(ctx, s.db, scope, metadata)
		if err != nil {
			return api.Scope{}, err
		}
		if metadata.Ref != ref || !visible {
			return api.Scope{}, fault(api.CodeForbidden, "policy retention input is absent or not visible")
		}
		task = task || ref == lane.Task
	}
	if !task {
		return api.Scope{}, fault(api.CodeForbidden, "policy retention omitted its actual retained task")
	}
	return api.Scope{Config: scope.Config, Actor: i.Actor, Source: "service", PolicyGeneration: scope.PolicyGeneration}, nil
}
