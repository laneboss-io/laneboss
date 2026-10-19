package identity

import (
	"bytes"
	"context"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// SessionReadback is a constructor-only identity capability, never a public
// store read/RPC. ReadSessionCommit resolves the exact verified frame's durable
// request key and loads its receipt, current session/enrollment and consumed
// proof together under the store's read lock. It returns owned snapshot bytes.
// It must not require or grant a general connection ReadAuthority. There is no
// caller-selected session ID and no fallback to the public ReadSession method.
type SessionReadback interface {
	ReadSessionCommit(context.Context, api.Scope) (SessionCommit, error)
}

type SessionCommit struct {
	Receipt    api.MutationReceipt
	Session    api.StoredReadSession
	Enrollment api.HumanEnrollment
	Proof      api.VerifiedHumanProof
}

// FinalizeHumanSession is the private dispatch hook for human.session receipt
// replay, including a commit whose first connection bind failed. Dispatch must
// finalize before reporting success, and must preserve a finalization error
// separately from the immutable successful mutation receipt. No new RPC exists.
func (s *Service) FinalizeHumanSession(ctx context.Context, scope api.Scope) (api.HumanSession, error) {
	return s.finalizeHumanSession(ctx, scope, nil)
}

func (s *Service) finalizeHumanSession(ctx context.Context, scope api.Scope, expected *api.HumanSession) (api.HumanSession, error) {
	var empty api.HumanSession
	if err := s.mutationScope(ctx, scope, "human.session", api.HumanSessionRequest{}); err != nil {
		return empty, err
	}
	if scope.Actor.Kind != "human" || scope.Request.Proof == nil {
		return empty, refusal(api.CodeUnauthenticated, "session finalization requires its authenticated human proof request")
	}
	if nilDependency(s.deps.Sessions) {
		return empty, api.NotImplemented("lb-v2-service", "private committed session read-back")
	}
	snapshot, err := s.deps.Sessions.ReadSessionCommit(ctx, scope)
	if err != nil {
		return empty, err
	}
	receipt := snapshot.Receipt
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	committed, stampErr := utcTime(receipt.RecordedAt)
	now := s.deps.Clock.Now()
	if receipt.Config != scope.Config || receipt.Actor != scope.Actor || receipt.Key != key ||
		receipt.PolicyGeneration != scope.PolicyGeneration || !bytes.Equal(receipt.RawRequest, scope.Frame.Bytes()) ||
		!validID(receipt.Operation.ID) || receipt.Operation.Status != "succeeded" || receipt.Operation.Error != nil ||
		receipt.Deferred != nil || receipt.Reply == nil || receipt.Reply.Error != nil || len(receipt.Reply.Result) == 0 ||
		receipt.FirstSeq == 0 || receipt.LastSeq < receipt.FirstSeq || receipt.Operation.FirstSeq != receipt.FirstSeq || receipt.Operation.LastSeq != receipt.LastSeq ||
		stampErr != nil || committed.After(now) {
		return empty, refusal(api.CodeIntegrity, "session read-back differs from its exact committed request")
	}
	var retained api.HumanSession
	if err := strictObject(receipt.Reply.Result, &retained); err != nil {
		return empty, refusal(api.CodeIntegrity, "committed session reply has invalid shape")
	}
	if expected != nil && retained != *expected {
		return empty, refusal(api.CodeIntegrity, "session read-back differs from the completed reply")
	}
	expires, expiryErr := utcTime(retained.ExpiresAt)
	idle, idleErr := utcTime(retained.IdleExpiresAt)
	if !validID(retained.ID) || retained.Config != scope.Config || snapshot.Session.Generation != 1 ||
		expiryErr != nil || idleErr != nil || idle.After(expires) || expires.After(committed.Add(30*time.Minute)) || idle.After(committed.Add(5*time.Minute)) {
		return empty, refusal(api.CodeUnauthenticated, "session finalization is not the current initial session revision")
	}
	enrollment, proof := snapshot.Enrollment, snapshot.Proof
	if enrollment.Config != scope.Config || enrollment.PrincipalID != scope.Actor.ID || enrollment.Generation == 0 {
		return empty, refusal(api.CodeUnauthenticated, "session principal enrollment is no longer current")
	}
	if err := originPolicy(enrollment.Origin, enrollment.RPID); err != nil {
		return empty, err
	}
	if err := api.ValidateHumanEnrollments(scope.Config, []api.HumanEnrollment{enrollment}); err != nil {
		return empty, err
	}
	target, err := s.deps.Store.AuthorizationTarget(ctx, scope, scope.Request)
	if err != nil {
		return empty, err
	}
	if err := validateIntent(target); err != nil {
		return empty, err
	}
	verified, verifiedErr := utcTime(proof.VerifiedAt)
	proofExpiry, proofErr := utcTime(proof.Ref.ExpiresAt)
	if proof.Ref != *scope.Request.Proof || !validID(proof.Ref.ID) || proof.Ref.RequestSHA256 != target.RequestSHA256 ||
		proof.Target != target || target.Method != "human.session" || target.RequestSHA256 != key.RequestSHA256 ||
		proof.Config != scope.Config || proof.PrincipalID != scope.Actor.ID || proof.EndpointClass != api.EndpointHuman || proof.EndpointGeneration != scope.EndpointGeneration ||
		proof.ConsumedBy != receipt.Operation.ID || !validID(proof.CredentialID) || !validID(proof.NonceID) || !validID(proof.ConnectionID) ||
		!validID(proof.AssertionEvidence.ID) || !validDigest(proof.AssertionEvidence.SHA256) || proof.AssertionEvidence.Class != "artifact" ||
		proof.AssertionEvidence.Bytes <= 0 || proof.AssertionEvidence.Bytes > api.MaxFrameBytes || verifiedErr != nil || proofErr != nil ||
		verified.After(committed) || !committed.Before(proofExpiry) || !verified.Before(proofExpiry) || proofExpiry.After(verified.Add(120*time.Second)) ||
		proof.Ref.SimulatedPresence != proof.SimulatedPresence || retained.SimulatedPresence != proof.SimulatedPresence ||
		receipt.SimulatedPresence != proof.SimulatedPresence || receipt.Operation.SimulatedPresence != proof.SimulatedPresence {
		return empty, refusal(api.CodeUnauthenticated, "session has no matching durable proof consumption")
	}
	found := false
	for _, credential := range enrollment.Credentials {
		if credential.ID == proof.CredentialID && !credential.Revoked && credential.Generation > 0 && credential.SimulatedPresence == proof.SimulatedPresence {
			found = true
		}
	}
	if !found {
		return empty, refusal(api.CodeUnauthenticated, "session credential is no longer enrolled")
	}
	return s.bindReadSession(ctx, scope, retained, proof, snapshot.Session)
}
