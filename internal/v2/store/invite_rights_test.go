//go:build linux

package store

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func inviteApprover(t *testing.T, s *Service, owner api.Scope) (api.HumanEnrollment, api.HumanAdmission) {
	t.Helper()
	r := api.HumanAccessRequest{Action: "invite", Role: "human", CanApprove: true}
	invite, err := inviteCommit(t, s, inviteScope(t, s, owner, r), r)
	if err != nil {
		t.Fatal("approving human invitation failed", err)
	}
	install, pending := inviteRegister(t, s, invite)
	return install.Enrollment, inviteDecision(t, s, owner, pending, "approve")
}

func TestInviteLastApprover(t *testing.T) {
	for _, mode := range []string{"sole", "ordinary", "pending", "revoked", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			s, owner, _ := sessionFixture(t)
			ctx := context.Background()
			switch mode {
			case "ordinary":
				_, pending := inviteRegister(t, s, inviteNew(t, s, owner))
				inviteDecision(t, s, owner, pending, "approve")
			case "pending":
				r := api.HumanAccessRequest{Action: "invite", Role: "human", CanApprove: true}
				invite, err := inviteCommit(t, s, inviteScope(t, s, owner, r), r)
				if err != nil {
					t.Fatal(err)
				}
				inviteRegister(t, s, invite)
			case "revoked":
				_, backup := inviteApprover(t, s, owner)
				r := api.HumanAccessRequest{Action: "revoke", PrincipalID: backup.PrincipalID, ExpectedGeneration: backup.EnrollmentGeneration}
				if _, err := inviteCommit(t, s, inviteScope(t, s, owner, r), r); err != nil {
					t.Fatal("revoking one of two approvers failed", err)
				}
			case "legacy":
				if _, err := s.db.ExecContext(ctx, "DELETE FROM projections WHERE kind='human_rights' AND id=?", string(owner.Actor.ID)); err != nil {
					t.Fatal(err)
				}
			}
			canApprove, err := humanApproveRight(ctx, s.db, owner.Actor.ID)
			if err != nil || !canApprove {
				t.Fatal("remaining approver positive control failed", err)
			}
			r := api.HumanAccessRequest{Action: "revoke", PrincipalID: owner.Actor.ID, ExpectedGeneration: 1}
			scope := inviteScope(t, s, owner, r)
			_, err = inviteCommit(t, s, scope, r)
			expectCode(t, err, api.CodeForbidden)
			var current api.HumanEnrollment
			if err := storedProjection(ctx, s.db, "enrollment", owner.Actor.ID, &current); err != nil || current.Generation != 1 || current.Credentials[0].Revoked {
				t.Fatal("refused last-approver revocation changed its enrollment", err)
			}
			var proof api.VerifiedHumanProof
			if err := storedProjection(ctx, s.db, "proof", scope.Request.Proof.ID, &proof); err != nil || proof.ConsumedBy != "" {
				t.Fatal("refused last-approver revocation consumed its proof", err)
			}
		})
	}
}

func TestInviteApproverHandoff(t *testing.T) {
	s, owner, _ := sessionFixture(t)
	enrollment, _ := inviteApprover(t, s, owner)
	backup := inviteReader(t, s, enrollment)
	r := api.HumanAccessRequest{Action: "revoke", PrincipalID: owner.Actor.ID, ExpectedGeneration: 1}
	if _, err := inviteCommit(t, s, inviteScope(t, s, backup, r), r); err != nil {
		t.Fatal("active backup could not take over from the first approver", err)
	}
	canApprove, err := humanApproveRight(context.Background(), s.db, backup.Actor.ID)
	if err != nil || !canApprove {
		t.Fatal("handoff lost the backup's approval right", err)
	}
	r = api.HumanAccessRequest{Action: "revoke", PrincipalID: backup.Actor.ID, ExpectedGeneration: enrollment.Generation}
	_, err = inviteCommit(t, s, inviteScope(t, s, backup, r), r)
	expectCode(t, err, api.CodeForbidden)
}

func TestInviteApproverWriter(t *testing.T) {
	s, owner, _ := sessionFixture(t)
	_, backup := inviteApprover(t, s, owner)
	ctx := context.Background()
	r := api.HumanAccessRequest{Action: "revoke", PrincipalID: owner.Actor.ID, ExpectedGeneration: 1}
	scope := inviteScope(t, s, owner, r)
	proposed, err := s.PrepareHumanChange(ctx, scope, r)
	if err != nil {
		t.Fatal("two-approver preflight control failed", err)
	}
	target, err := s.authorizationTarget(ctx, s.db, scope, scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	event := api.Event{Schema: api.SchemaVersion, ID: testID(t), Config: scope.Config,
		Kind: "human.enrollment", Actor: scope.Actor, RequestedBy: scope.Actor, Origin: "service",
		StarterChain: []api.ID{}, Payload: enrollmentJSON(t, proposed)}
	input := api.Transaction{Scope: scope, RawRequest: scope.Frame.Bytes(),
		Reply:  &api.RPCReply{Result: enrollmentJSON(t, proposed)},
		Writes: api.StateWrites{HumanChanges: []api.HumanAdmission{proposed}}, Events: []api.Event{event},
		Guards: []api.TransactionGuard{{Proof: &api.ProofUse{Proof: *scope.Request.Proof, Target: target}}}}
	// Change a different enrollment after successful preflight. Its independent
	// generation cannot fence this stale proposal; the writer must recount.
	r = api.HumanAccessRequest{Action: "revoke", PrincipalID: backup.PrincipalID, ExpectedGeneration: backup.EnrollmentGeneration}
	if _, err := inviteCommit(t, s, inviteScope(t, s, owner, r), r); err != nil {
		t.Fatal("revoking the spare approver failed", err)
	}
	_, err = s.Transact(ctx, input)
	expectCode(t, err, api.CodeForbidden)
	var current api.HumanEnrollment
	if err := storedProjection(ctx, s.db, "enrollment", owner.Actor.ID, &current); err != nil || current.Generation != 1 || current.Credentials[0].Revoked {
		t.Fatal("writer accepted a stale last-approver revocation", err)
	}
	var proof api.VerifiedHumanProof
	if err := storedProjection(ctx, s.db, "proof", scope.Request.Proof.ID, &proof); err != nil || proof.ConsumedBy != "" {
		t.Fatal("writer refusal did not roll back human proof consumption", err)
	}
}
