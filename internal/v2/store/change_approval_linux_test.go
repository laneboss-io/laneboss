//go:build linux

package store

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func changeApprovalFixture(t *testing.T) (*Service, api.Transaction, api.ID) {
	t.Helper()
	s, _, proposal := changeFixture(t)
	if _, err := s.Transact(context.Background(), proposal); err != nil {
		t.Fatal(err)
	}
	change := proposal.Writes.Changes[0]
	scope := cacheHuman(t, s, api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: testID(t)}})
	request := api.ChangeApproveRequest{ChangeID: change.ID, ManifestSHA256: change.ManifestSHA256, BaseGeneration: 1}
	scope.Request = testRequest(t, "org.change.approve", request)
	now := s.deps.Clock.Now().UTC()
	proof := api.ProofRef{ID: testID(t), RequestSHA256: scope.Request.RequestSHA256, ExpiresAt: api.Timestamp(now.Add(time.Minute).Format(time.RFC3339Nano))}
	scope.Request.Proof = &proof
	scope.Frame = &archFrame{raw: enrollmentJSON(t, scope.Request)}
	authority, err := scope.Connection.ReadAuthority(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	target := api.HumanChallengeRequest{Method: scope.Request.Method, TargetID: change.ID, RequestSHA256: scope.Request.RequestSHA256, BaseGeneration: 1}
	facts := api.VerifiedHumanProof{Ref: proof, Config: scope.Config, PrincipalID: scope.Actor.ID, CredentialID: authority.CredentialID, NonceID: testID(t), ConnectionID: scope.Connection.ID(), EndpointClass: api.EndpointHuman, EndpointGeneration: scope.EndpointGeneration, Target: target, VerifiedAt: api.Timestamp(now.Format(time.RFC3339Nano)), AssertionEvidence: change.Reason}
	fixtureProjection(t, s, "proof", proof.ID, 1, facts)
	approved := api.ChangeApproval{ID: testID(t), ChangeID: change.ID, RequesterLifeID: change.Requester.LifeID, ApproverKeyID: facts.CredentialID, NonceID: facts.NonceID, ManifestSHA256: change.ManifestSHA256, BaseGeneration: 1, ApprovedAt: facts.VerifiedAt, ExpiresAt: api.Timestamp(now.Add(5 * time.Minute).Format(time.RFC3339Nano))}
	event := api.Event{Schema: api.SchemaVersion, ID: testID(t), Config: scope.Config, Kind: "org.change.approved", Actor: scope.Actor, RequestedBy: scope.Actor, Origin: "service", StarterChain: []api.ID{}, Payload: enrollmentJSON(t, api.ChangeEvent{Change: change, Approval: &approved, Reason: "component verified proof handoff"})}
	return s, api.Transaction{Scope: scope, RawRequest: scope.Frame.Bytes(), Compare: []api.Compare{{Kind: api.CompareOrg, ID: change.OrgID, Generation: 1}, {Kind: api.CompareApproval, ID: approved.ID}}, Guards: []api.TransactionGuard{{Proof: &api.ProofUse{Proof: proof, Target: target}}}, Writes: api.StateWrites{Approvals: []api.ChangeApproval{approved}}, Events: []api.Event{event}, Reply: &api.RPCReply{Result: enrollmentJSON(t, approved)}}, proof.ID
}

func TestChangeApprovalAtomic(t *testing.T) {
	s, tx, proof := changeApprovalFixture(t)
	ctx := context.Background()
	commit, err := s.Transact(ctx, tx)
	if err != nil {
		t.Fatal("real-store approval refused its exact verified proof handoff", err)
	}
	var use api.ProofUseReceipt
	if err := storedProjection(ctx, s.db, "proof_use", proof, &use); err != nil || use.OperationID != commit.Operation.ID {
		t.Fatal("approval did not atomically consume its actual proof", err)
	}
	again, err := s.Transact(ctx, tx)
	if err != nil || !again.Replayed || again.LastSeq != commit.LastSeq {
		t.Fatal("approval replay consumed or appended twice", err)
	}
	second := tx
	second.Scope.Request = testRequest(t, "org.change.approve", api.ChangeApproveRequest{ChangeID: tx.Writes.Approvals[0].ChangeID, ManifestSHA256: tx.Writes.Approvals[0].ManifestSHA256, BaseGeneration: 1})
	second.Scope.Request.Proof = tx.Scope.Request.Proof
	second.Scope.Frame = &archFrame{raw: enrollmentJSON(t, second.Scope.Request)}
	second.RawRequest = second.Scope.Frame.Bytes()
	if _, err := s.Transact(ctx, second); err == nil {
		t.Fatal("new request reused a consumed approval proof")
	}
}

func TestChangeApprovalFences(t *testing.T) {
	for _, defect := range []string{"missing_event", "wrong_key", "wrong_nonce", "presence", "stale_base", "missing_proof"} {
		t.Run(defect, func(t *testing.T) {
			s, tx, proof := changeApprovalFixture(t)
			switch defect {
			case "missing_event":
				tx.Events = nil
			case "wrong_key":
				tx.Writes.Approvals[0].ApproverKeyID = testID(t)
			case "wrong_nonce":
				tx.Writes.Approvals[0].NonceID = testID(t)
			case "presence":
				tx.Writes.Approvals[0].SimulatedPresence = true
			case "stale_base":
				tx.Compare[0].Generation++
			case "missing_proof":
				tx.Guards = nil
			}
			if _, err := s.Transact(context.Background(), tx); err == nil {
				t.Fatal("approval accepted " + defect)
			}
			var facts api.VerifiedHumanProof
			if err := storedProjection(context.Background(), s.db, "proof", proof, &facts); err != nil || facts.ConsumedBy != "" {
				t.Fatal("refused approval consumed a proof", err)
			}
		})
	}
}
