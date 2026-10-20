package identity

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) HumanEnroll(ctx context.Context, scope api.Scope, request api.HumanAccessRequest) (api.HumanAdmission, error) {
	var result api.HumanAdmission
	if err := s.mutationScope(ctx, scope, "human.enroll", request); err != nil {
		return result, err
	}
	if scope.Actor.Kind != "human" || scope.Request.Proof == nil {
		return result, refusal(api.CodeForbidden, "enrollment changes require the enrolled human's own proof")
	}
	store, ok := s.deps.Store.(api.HumanAdmissionStore)
	if !ok {
		return result, api.NotImplemented("lb-v2-service", "human invitation and approval store")
	}
	target, err := s.deps.Store.AuthorizationTarget(ctx, scope, scope.Request)
	if err != nil {
		return result, err
	}
	if _, err := s.CheckProof(ctx, scope, *scope.Request.Proof, target); err != nil {
		return result, err
	}
	proposed, err := store.PrepareHumanChange(ctx, scope, request)
	if err != nil {
		return result, err
	}
	reply, err := json.Marshal(proposed)
	if err != nil {
		return result, err
	}
	public := proposed
	public.Token = ""
	payload, err := json.Marshal(public)
	if err != nil {
		return result, err
	}
	id, err := newID()
	if err != nil {
		return result, err
	}
	event := api.Event{Schema: api.SchemaVersion, ID: id, Config: scope.Config, Kind: "human.enrollment",
		Actor: scope.Actor, RequestedBy: scope.Actor, Origin: "service", StarterChain: []api.ID{}, Payload: payload}
	commit, err := s.deps.Store.Transact(ctx, api.Transaction{Scope: scope, RawRequest: scope.Frame.Bytes(),
		Reply: &api.RPCReply{Result: reply}, Writes: api.StateWrites{HumanChanges: []api.HumanAdmission{proposed}},
		Events: []api.Event{event}, Guards: []api.TransactionGuard{{Proof: &api.ProofUse{Proof: *scope.Request.Proof, Target: target}}}})
	if err != nil {
		return result, err
	}
	if commit.Reply == nil || commit.Reply.Error != nil || commit.Operation.Status != "succeeded" || commit.LastSeq == 0 {
		return result, refusal(api.CodeIntegrity, "human enrollment action lacks its committed receipt")
	}
	if err := strictObject(commit.Reply.Result, &result); err != nil {
		return api.HumanAdmission{}, err
	}
	return result, nil
}

func (s *Service) HumanPending(ctx context.Context, scope api.Scope, _ api.Empty) (api.HumanPendingPage, error) {
	if err := s.Authorize(ctx, scope, scope.Request); err != nil {
		return api.HumanPendingPage{}, err
	}
	store, ok := s.deps.Store.(api.HumanAdmissionStore)
	if !ok {
		return api.HumanPendingPage{}, api.NotImplemented("lb-v2-service", "pending human registrations")
	}
	return store.PendingHumans(ctx, scope)
}
