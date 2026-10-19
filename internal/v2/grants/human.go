package grants

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func (s *Service) humanBinding(ctx context.Context, scope api.Scope) error {
	if nilInterface(scope.Connection) || !manifest.ValidID(scope.Connection.ID()) {
		return refused("human operation requires its live authenticated connection")
	}
	binding := scope.Connection.Binding()
	if binding.Class != api.EndpointHuman || binding.Config != scope.Config ||
		binding.EndpointGeneration != scope.EndpointGeneration || binding.ContractRevision != api.ContractRevision {
		return refused("human connection binding does not match this operation")
	}
	peer := scope.Connection.Peer()
	if nilInterface(peer) {
		return refused("human connection has no verified peer")
	}
	return peer.Alive(ctx)
}

func (s *Service) humanRead(ctx context.Context, scope api.Scope) error {
	if err := s.humanBinding(ctx, scope); err != nil {
		return err
	}
	authority, err := scope.Connection.ReadAuthority(ctx)
	if err != nil {
		return err
	}
	if authority.Config != scope.Config || authority.PrincipalID != scope.Actor.ID ||
		authority.EndpointGeneration != scope.EndpointGeneration || !manifest.ValidID(authority.SessionID) ||
		!manifest.ValidID(authority.CredentialID) {
		return refused("human read session is not bound to this principal and endpoint")
	}
	if _, err := manifest.Expiry(authority.ExpiresAt, s.deps.Clock.Now()); err != nil {
		return err
	}
	_, err = manifest.Expiry(authority.IdleExpiresAt, s.deps.Clock.Now())
	return err
}

// This only prepares a guard. The authoritative store must consume it in the
// same transaction as the real result/effect; preflight never spends a nonce.
func (s *Service) humanMutation(ctx context.Context, scope api.Scope, method api.Method, input any) (api.TransactionGuard, error) {
	var zero api.TransactionGuard
	if err := s.humanBinding(ctx, scope); err != nil {
		return zero, err
	}
	request := scope.Request
	if request.Protocol != api.Protocol || request.Schema != api.SchemaVersion || request.Config != scope.Config ||
		request.Method != method || !manifest.ValidID(request.RequestID) || !manifest.ValidID(request.IdempotencyKey) ||
		len(request.RequestID) < 22 || len(request.IdempotencyKey) < 22 || request.Proof == nil || nilInterface(scope.Frame) {
		return zero, refused("human mutation lacks its exact proof-bound request and frame")
	}
	if err := scope.Frame.Verify(ctx, scope.Connection); err != nil {
		return zero, err
	}
	var framed api.Request
	if err := api.DecodeObject(scope.Frame.Bytes(), &framed); err != nil || !reflect.DeepEqual(framed, request) {
		return zero, refused("human operation differs from its authenticated request frame")
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return zero, integrity("cannot encode human mutation input")
	}
	expected, err := api.CanonicalJSON(raw)
	if err != nil {
		return zero, err
	}
	actual, err := api.CanonicalJSON(request.Params)
	if err != nil || !bytes.Equal(expected, actual) {
		return zero, refused("human operation params differ from the verified intent")
	}
	digest, err := api.RequestDigest(request)
	if err != nil || request.RequestSHA256 != digest || request.Proof.RequestSHA256 != digest {
		return zero, refused("human operation proof has a different intent digest")
	}
	if _, err := manifest.Expiry(request.Proof.ExpiresAt, s.deps.Clock.Now()); err != nil {
		return zero, err
	}
	if nilInterface(s.deps.Human) {
		return zero, &api.Error{Code: api.CodePrerequisite, Message: "human verifier is not wired into grants",
			Instead: "Wire the authenticated identity verifier in assembly before human mutations.", Owner: "lb-v2-integrate"}
	}
	target, err := s.deps.Store.AuthorizationTarget(ctx, scope, request)
	if err != nil {
		return zero, hideGrant(err)
	}
	if target.Method != method || target.RequestSHA256 != digest || !manifest.ValidID(target.TargetID) {
		return zero, integrity("human authorization target differs from this request")
	}
	verified, err := s.deps.Human.CheckProof(ctx, scope, *request.Proof, target)
	if err != nil {
		return zero, err
	}
	if verified.Ref != *request.Proof || verified.Config != scope.Config || verified.PrincipalID != scope.Actor.ID ||
		verified.EndpointClass != api.EndpointHuman || verified.EndpointGeneration != scope.EndpointGeneration ||
		verified.Target != target || verified.ConsumedBy != "" || !manifest.ValidID(verified.CredentialID) || !manifest.ValidID(verified.NonceID) {
		return zero, refused("human verifier returned mismatched or consumed proof facts")
	}
	return api.TransactionGuard{Proof: &api.ProofUse{Proof: verified.Ref, Target: target}}, nil
}
