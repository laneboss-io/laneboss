package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// This checks the identity component's atomic evidence handoff, not an
// assertion's cryptographic validity. Store commit must authenticate the bound
// identity producer, original frame and current enrollment/challenge/counter.
func validAssertionEvidence(tx Transaction) bool {
	if tx.Scope.Actor.Kind != "human" || tx.Scope.Actor.ID == "" || tx.Scope.Config == "" ||
		tx.Scope.EndpointGeneration == 0 || len(tx.Writes.Proofs) != 1 || len(tx.Writes.Objects) != 1 ||
		len(tx.Writes.Challenges) != 1 || len(tx.Writes.Counters) != 1 || len(tx.Guards) != 0 ||
		tx.Reply == nil || tx.Reply.Error != nil {
		return false
	}
	var request HumanConfirmRequest
	if DecodeObject(tx.Scope.Request.Params, &request) != nil || request.ChallengeID == "" || request.CredentialID == "" {
		return false
	}
	proof, object := tx.Writes.Proofs[0], tx.Writes.Objects[0]
	ref, acl := proof.AssertionEvidence, object.ACL
	if proof.Config != tx.Scope.Config || proof.PrincipalID != tx.Scope.Actor.ID ||
		proof.SimulatedPresence != proof.Ref.SimulatedPresence ||
		proof.EndpointClass != EndpointHuman || proof.EndpointGeneration != tx.Scope.EndpointGeneration ||
		proof.ConnectionID == "" || proof.CredentialID != request.CredentialID || proof.NonceID != request.ChallengeID ||
		proof.Ref.ID == "" || proof.VerifiedAt == "" || proof.ConsumedBy != "" ||
		ref.ID == "" || object.ObjectKey != ref.ID || ref.Class != "artifact" || object.Class != ref.Class ||
		ref.Bytes < 1 || ref.Bytes > MaxFrameBytes || int64(len(object.Bytes)) != ref.Bytes || object.SHA256 != ref.SHA256 ||
		object.Origin != "identity" || len(object.InputRefs) != 0 {
		return false
	}
	if acl.Config != tx.Scope.Config || acl.Owner != tx.Scope.Actor || acl.Audience != "private" ||
		acl.LifeID != "" || len(acl.Participants) != 0 || acl.Generation != 1 {
		return false
	}
	// The private evidence is the exact encoding of the typed assertion that
	// identity verified. ClientDataJSON, authenticator data and signature bytes
	// survive this encoding unchanged; a self-consistent unrelated blob refuses.
	verified, err := json.Marshal(request)
	if err != nil || !bytes.Equal(object.Bytes, verified) {
		return false
	}
	sum := sha256.Sum256(object.Bytes)
	if ref.SHA256 != Digest(hex.EncodeToString(sum[:])) {
		return false
	}
	challenge, counter := tx.Writes.Challenges[0], tx.Writes.Counters[0]
	if !challenge.Consumed || challenge.Generation == 0 || challenge.PrincipalID != tx.Scope.Actor.ID ||
		challenge.EndpointClass != EndpointHuman || challenge.EndpointGeneration != tx.Scope.EndpointGeneration ||
		challenge.Challenge.Config != tx.Scope.Config || challenge.Challenge.ID != request.ChallengeID ||
		proof.Target != (HumanChallengeRequest{Method: challenge.Challenge.Method, TargetID: challenge.Challenge.TargetID,
			RequestSHA256: challenge.Challenge.RequestSHA256, BaseGeneration: challenge.Challenge.BaseGeneration}) ||
		proof.Ref.RequestSHA256 != challenge.Challenge.RequestSHA256 || proof.Ref.ExpiresAt != challenge.Challenge.ExpiresAt ||
		counter.CredentialID != request.CredentialID || counter.ExpectedGeneration == 0 {
		return false
	}
	var reply ProofRef
	if DecodeObject(tx.Reply.Result, &reply) != nil || reply != proof.Ref || len(tx.Events) != 1 || tx.Events[0].Kind != "human.confirmed" {
		return false
	}
	var eventProof ProofRef
	return DecodeObject(tx.Events[0].Payload, &eventProof) == nil && eventProof == proof.Ref &&
		tx.Events[0].Config == tx.Scope.Config && tx.Events[0].Actor == tx.Scope.Actor
}
