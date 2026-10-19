package approval

import (
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func approvalFromProof(now time.Time, scope api.Scope, operation api.ID, change api.ChangeRequest, facts api.VerifiedHumanProof) (api.ChangeApproval, error) {
	if now.IsZero() {
		return api.ChangeApproval{}, integrity("approval requires a service-clock instant")
	}
	target := api.HumanChallengeRequest{Method: scope.Request.Method, TargetID: change.ID,
		RequestSHA256: scope.Request.RequestSHA256, BaseGeneration: change.BaseGeneration}
	if scope.Request.Proof == nil || facts.Ref != *scope.Request.Proof || facts.Config != scope.Config ||
		facts.SimulatedPresence != facts.Ref.SimulatedPresence ||
		facts.PrincipalID != scope.Actor.ID || facts.EndpointClass != api.EndpointHuman ||
		facts.EndpointGeneration != scope.EndpointGeneration || facts.Target != target ||
		!validID(facts.CredentialID) || !validID(facts.NonceID) || !validID(facts.ConnectionID) ||
		!validBlob(facts.AssertionEvidence) || facts.AssertionEvidence.Class != "artifact" ||
		facts.AssertionEvidence.Bytes < 1 || facts.AssertionEvidence.Bytes > api.MaxFrameBytes || facts.ConsumedBy != "" {
		return api.ChangeApproval{}, forbidden("human proof facts do not authorize this exact approval")
	}
	verified, err := timestamp(facts.VerifiedAt)
	if err != nil || verified.After(now) {
		return api.ChangeApproval{}, forbidden("human assertion has an invalid verification time")
	}
	proofExpiry, err := timestamp(facts.Ref.ExpiresAt)
	if err != nil || !now.Before(proofExpiry) || !verified.Before(proofExpiry) || proofExpiry.Sub(verified) > 120*time.Second {
		return api.ChangeApproval{}, forbidden("human confirmation expired before approval")
	}
	created, err := timestamp(change.CreatedAt)
	if err != nil || verified.Before(created) {
		return api.ChangeApproval{}, forbidden("human confirmation predates the staged change")
	}
	stageExpiry, err := timestamp(change.ExpiresAt)
	if err != nil {
		return api.ChangeApproval{}, err
	}
	if !now.Before(stageExpiry) {
		return api.ChangeApproval{}, forbidden("staged change expired before approval")
	}
	expires := now.Add(10 * time.Minute)
	if stageExpiry.Before(expires) {
		expires = stageExpiry
	}
	result := api.ChangeApproval{SimulatedPresence: facts.SimulatedPresence, ID: stableID(operation, "approval"), ChangeID: change.ID,
		RequesterLifeID: change.Requester.LifeID, ApproverKeyID: facts.CredentialID, NonceID: facts.NonceID,
		ManifestSHA256: change.ManifestSHA256, BaseGeneration: change.BaseGeneration,
		ApprovedAt: api.Timestamp(now.UTC().Format(time.RFC3339Nano)), ExpiresAt: api.Timestamp(expires.UTC().Format(time.RFC3339Nano))}
	if err := ValidateApprovalBinding(now, change, result); err != nil {
		return api.ChangeApproval{}, err
	}
	return result, nil
}
