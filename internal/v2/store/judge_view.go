package store

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func (s *Service) JudgeView(ctx context.Context, scope api.Scope) (api.ConfigView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result api.ConfigView
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return result, err
	}
	if scope.Actor.Kind != "lane" && scope.Actor.Kind != "human" {
		return result, fault(api.CodeForbidden, "judge projection requires a current lane or verified human")
	}
	if err := verifyProjectionFrame(ctx, scope, "judge.list"); err != nil {
		return result, err
	}
	db, err := s.reader(scope)
	if err != nil {
		return result, err
	}
	var policy api.EffectivePolicy
	if err := storedProjection(ctx, db, "policy", api.ID(s.deps.Config), &policy); err != nil {
		return result, err
	}
	if policy.Generation != scope.PolicyGeneration || policy.Generation == 0 {
		return result, fault(api.CodeConflict, "judge projection policy generation changed")
	}
	judge, err := api.ResolveJudgeConfig(policy.Judge)
	if err != nil {
		return result, err
	}
	if scope.Actor.Kind == "lane" {
		var lane api.Lane
		if err := storedProjection(ctx, db, "lane", scope.Actor.LifeID, &lane); err != nil {
			return result, err
		}
		if lane.Level != scope.Actor.Level || lane.Role != scope.Actor.Role {
			return result, fault(api.CodeForbidden, "judge projection differs from its authenticated role")
		}
		policy, err = s.storedRolePolicy(ctx, db, policy, lane)
		if err != nil {
			return result, err
		}
		if lane.Cleaned || lane.Level != policy.Context.Level || lane.Role != policy.Context.Role {
			return result, fault(api.CodeConflict, "judge projection policy belongs to a different current role")
		}
	}
	if len(policy.Sources) == 0 {
		return result, fault(api.CodePrerequisite, "approved judge policy has no retained source inventory")
	}
	var org api.OrgSnapshot
	if err := storedProjection(ctx, db, "org", api.ID(s.deps.Config), &org); err != nil {
		return result, err
	}
	if org.Config != s.deps.Config || org.Ref.OrgID != api.ID(s.deps.Config) || org.Ref.Generation == 0 {
		return result, fault(api.CodeIntegrity, "judge projection org inventory differs from its configuration")
	}
	inputs := []api.BlobRef{}
	for _, source := range policy.Sources {
		found := false
		for _, file := range org.Sources {
			if file.Source != source {
				continue
			}
			metadata, _, err := objectRow(ctx, db, file.Content.ID)
			if err != nil {
				return result, err
			}
			if metadata.Ref != file.Content || !objectVisible(scope, metadata.ACL) || source.Generation != org.Ref.Generation {
				return result, fault(api.CodeIntegrity, "judge projection source is not its authorized committed content")
			}
			inputs = append(inputs, file.Content)
			found = true
			break
		}
		if !found {
			return result, fault(api.CodeIntegrity, "judge policy source is outside the approved org inventory")
		}
	}
	view := api.JudgeView{Schema: "laneboss.judge-view.v2", Config: s.deps.Config, PolicyGeneration: policy.Generation, PolicySHA256: policy.SHA256, Context: policy.Context, Judge: judge, Sources: append([]api.SourceRef{}, policy.Sources...)}
	data, err := json.Marshal(view)
	if err != nil {
		return result, err
	}
	key := api.ID(hash([]byte(scope.Config + ":" + principal(scope) + ":" + string(scope.Request.RequestID) + ":" + hash(data))))
	actor := api.Actor{Kind: "service", ID: "lb-v2-judge"}
	internal := api.Scope{Config: scope.Config, Actor: actor, Source: "service", PolicyGeneration: policy.Generation}
	cause := api.InternalIntent{ID: api.ID("view-" + string(key)), Kind: api.InternalObjectRetain, Config: scope.Config, Actor: actor, RequestedBy: scope.Actor, CauseRequestID: scope.Request.RequestID}
	object := api.ObjectWrite{ObjectKey: key, Class: "policy", Bytes: data, SHA256: api.Digest(hash(data)), Origin: "service", InputRefs: inputs,
		ACL: api.ObjectACL{Config: scope.Config, Owner: scope.Actor, LifeID: scope.Actor.LifeID, Audience: "owner", Generation: 1, Participants: []api.ID{}}}
	// This internal operation is derived from the authenticated read frame and
	// retained atomically with the projection. No public mutation is invented.
	if _, err := s.transactInternal(ctx, api.Transaction{Scope: internal, Internal: &cause, Writes: api.StateWrites{Objects: []api.ObjectWrite{object}}}); err != nil {
		return result, err
	}
	metadata, retained, err := objectRow(ctx, s.db, key)
	if err != nil {
		return result, err
	}
	if metadata.Ref.SHA256 != object.SHA256 || string(retained) != string(data) {
		return result, fault(api.CodeIntegrity, "judge projection readback differs from approved policy bytes")
	}
	return api.ConfigView{Generation: org.Ref.Generation, Sources: append([]api.SourceRef{}, policy.Sources...), Projection: metadata.Ref, Warnings: []string{}}, nil
}

// Keep strict read-frame validation separate from any mutation reservation.
func verifyProjectionFrame(ctx context.Context, scope api.Scope, method api.Method) error {
	if scope.Request.Method != method || scope.Request.Config != scope.Config || !wire.ValidID(string(scope.Request.RequestID)) || scope.Frame == nil || scope.Connection == nil {
		return fault(api.CodeUnauthenticated, "protected read projection lacks its exact authenticated frame")
	}
	if err := scope.Frame.Verify(ctx, scope.Connection); err != nil {
		return err
	}
	var frame api.Request
	if err := json.Unmarshal(scope.Frame.Bytes(), &frame); err != nil || !sameValue(frame, scope.Request) {
		return fault(api.CodeIntegrity, "protected read projection frame differs from authenticated request")
	}
	return nil
}
