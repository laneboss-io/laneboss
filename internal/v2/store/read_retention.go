package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func publicProjectionMethod(method api.Method) bool {
	return method == "brief.start" || method == "brief.render" || method == "config.read"
}

// Called under the store writer lock by the component-only retention port.
// A read frame has no public mutation reservation. Its output receives a real
// internal causal operation derived from that exact authenticated read instead.
func (s *Service) retainReadProjection(ctx context.Context, scope api.Scope, request api.RetainObjectRequest) (api.BlobRef, error) {
	var empty api.BlobRef
	if err := s.readScope(ctx, scope); err != nil {
		return empty, err
	}
	if err := verifyProjectionFrame(ctx, scope, scope.Request.Method); err != nil {
		return empty, err
	}
	if !publicProjectionMethod(scope.Request.Method) || scope.Actor.Kind != "lane" && scope.Actor.Kind != "human" || scope.Request.Proof != nil {
		return empty, fault(api.CodeForbidden, "read projection has no authenticated read-only parent")
	}
	intent, object := request.Intent, request.Object
	owner := api.Methods[scope.Request.Method].Owner
	if intent.Kind != api.InternalObjectRetain || intent.Config != scope.Config || intent.Actor != (api.Actor{Kind: "service", ID: api.ID(owner)}) || intent.RequestedBy != scope.Actor || intent.CauseRequestID != scope.Request.RequestID || intent.CauseOperationID != "" || intent.EffectID != "" ||
		object.Origin != "service" || object.ACL.Config != scope.Config || object.ACL.Owner != scope.Actor || object.ACL.Generation != 1 || len(object.ACL.Participants) != 0 {
		return empty, fault(api.CodeForbidden, "read projection changed its component, principal or causal frame")
	}
	wantClass := "prompt"
	if scope.Request.Method == "config.read" {
		wantClass = "policy"
	}
	if object.Class != wantClass || object.ACL.Audience != "owner" && object.ACL.Audience != "life" || len(object.InputRefs) == 0 || object.ACL.LifeID != intent.Target.LifeID {
		return empty, fault(api.CodeForbidden, "read projection class, audience or retained input inventory differs")
	}
	if object.Class == "policy" && object.ACL.Audience != "owner" || object.Class == "prompt" && (intent.Target.LifeID == "" && object.ACL.Audience != "owner" || intent.Target.LifeID != "" && object.ACL.Audience != "life") {
		return empty, fault(api.CodeForbidden, "read projection audience differs from its actual target")
	}
	if scope.Actor.Kind == "lane" && (intent.Target.LifeID != scope.Actor.LifeID || object.ACL.LifeID != scope.Actor.LifeID) {
		return empty, fault(api.CodeForbidden, "read projection selected a foreign life")
	}
	var policy api.EffectivePolicy
	if err := storedProjection(ctx, s.db, "policy", api.ID(scope.Config), &policy); err != nil {
		return empty, err
	}
	if policy.Generation != scope.PolicyGeneration {
		return empty, fault(api.CodeConflict, "read projection policy changed before retention")
	}
	if intent.Target.LifeID != "" {
		var lane api.Lane
		if err := storedProjection(ctx, s.db, "lane", intent.Target.LifeID, &lane); err != nil {
			return empty, err
		}
		if lane.Cleaned || intent.Target.Run != 0 && intent.Target.Run != lane.Run || intent.LogicalTurnID != "" && intent.LogicalTurnID != lane.LogicalTurnID || intent.CancellationEpoch != 0 && intent.CancellationEpoch != lane.CancellationEpoch {
			return empty, fault(api.CodeConflict, "read projection life, turn or epoch changed")
		}
		if object.Class == "prompt" {
			assigned := false
			for _, ref := range object.InputRefs {
				assigned = assigned || ref == lane.Task
			}
			if !assigned {
				return empty, fault(api.CodeForbidden, "briefing retention omitted the actual assigned task")
			}
		}
	}
	for _, ref := range object.InputRefs {
		metadata, _, err := objectRow(ctx, s.db, ref.ID)
		if err != nil {
			return empty, err
		}
		visible, err := s.visibleObject(ctx, s.db, scope, metadata)
		if err != nil {
			return empty, err
		}
		if metadata.Ref != ref || !visible {
			return empty, fault(api.CodeForbidden, "read projection input is absent or not visible")
		}
	}
	id, err := api.ReadProjectionOperationID(scope, object)
	if err != nil {
		return empty, err
	}
	intent.ID = id
	intent.CauseOperationID = intent.ID
	internal := api.Scope{Config: scope.Config, Actor: intent.Actor, Source: "service", PolicyGeneration: scope.PolicyGeneration}
	if _, err := s.transactInternal(ctx, api.Transaction{Scope: internal, Internal: &intent, Writes: api.StateWrites{Objects: []api.ObjectWrite{object}}}); err != nil {
		return empty, err
	}
	metadata, _, err := objectRow(ctx, s.db, object.ObjectKey)
	if err != nil {
		return empty, err
	}
	return metadata.Ref, nil
}
