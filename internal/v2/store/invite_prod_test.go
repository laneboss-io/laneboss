//go:build linux && !laneboss_e2e_authenticator

package store

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestInvitePolicyAtApproval(t *testing.T) {
	s, owner, _ := sessionFixture(t)
	invitePort(t, s)
	install, pending := inviteRegister(t, s, inviteNew(t, s, owner))
	// Model an existing marked pending DTO from a dedicated test build.
	// It is not in the active startup inventory and must be checked again by
	// the real production activation transaction, under the writer lock.
	credential := &install.Enrollment.Credentials[0]
	credential.ID = api.InvitedCredentialID(credential.RawCredentialID)
	credential.AAGUID = api.SoftwareAuthenticatorAAGUID
	credential.AttestationMarker = api.SoftwareAuthenticatorAttestationMarker
	credential.SimulatedPresence = true
	fixtureProjection(t, s, "pending_human", pending.ID, 1, install)
	r := api.HumanAccessRequest{Action: "approve", InviteID: pending.ID, Fingerprint: pending.Fingerprint, ExpectedGeneration: pending.Generation}
	scope := inviteScope(t, s, owner, r)
	_, err := inviteCommit(t, s, scope, r)
	expectCode(t, err, api.CodeForbidden)
	all, err := s.HumanEnrollments(context.Background(), s.deps.Config)
	if err != nil || len(all) != 1 {
		t.Fatal("production activation admitted a marked pending credential", err)
	}
	var proof api.VerifiedHumanProof
	if err := storedProjection(context.Background(), s.db, "proof", scope.Request.Proof.ID, &proof); err != nil || proof.ConsumedBy != "" {
		t.Fatal("refused activation consumed the approving human's proof", err)
	}
}
