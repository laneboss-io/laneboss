//go:build linux

package store

import (
	"context"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func TestInviteBaselineFences(t *testing.T) {
	for _, mode := range []string{"receipt-config", "ceremony", "journal", "generation", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			s, owner, _ := sessionFixture(t)
			enrollment, _ := inviteApprover(t, s, owner)
			backup := inviteReader(t, s, enrollment)
			ctx := context.Background()
			r := api.HumanAccessRequest{Action: "revoke", PrincipalID: owner.Actor.ID, ExpectedGeneration: 1}
			scope := inviteScope(t, s, backup, r)
			proposed, err := s.PrepareHumanChange(ctx, scope, r)
			if err != nil {
				t.Fatal("baseline handoff preflight control failed", err)
			}
			var decoded api.HumanAdmission
			if err := wire.Decode(enrollmentJSON(t, proposed), &decoded); err != nil {
				t.Fatal("baseline handoff returned an invalid public reply", err)
			}
			var raw []byte
			if err := s.db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='enrollment_receipt' AND json_extract(data,'$.PrincipalID')=?", string(owner.Actor.ID)).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var receipt api.EnrollmentReceipt
			if err := decodeStored(raw, &receipt); err != nil {
				t.Fatal(err)
			}
			var challenge api.EnrollmentChallenge
			if err := storedProjection(ctx, s.db, "enrollment_challenge", receipt.ChallengeID, &challenge); err != nil {
				t.Fatal(err)
			}
			event, err := authorityEvent(ctx, s.db, receipt.OperationID, "blob.committed", receipt.Evidence.ID)
			if err != nil || proposed.InviterID != receipt.PrincipalID || proposed.CreatedAt != event.RecordedAt || proposed.ExpiresAt != challenge.ExpiresAt {
				t.Fatal("baseline reply differs from its retained ceremony provenance", err)
			}
			switch mode {
			case "receipt-config":
				receipt.Config = "foreign-config"
			case "ceremony":
				challenge.Consumed = false
				fixtureProjection(t, s, "enrollment_challenge", challenge.ID, 2, challenge)
			case "journal":
				receipt.EventID = testID(t)
			case "generation":
				receipt.Generation++
			case "duplicate":
				receipt.CeremonyID = testID(t)
			}
			fixtureProjection(t, s, "enrollment_receipt", receipt.CeremonyID, 1, receipt)
			_, err = inviteCommit(t, s, scope, r)
			expectCode(t, err, api.CodeIntegrity)
			var proof api.VerifiedHumanProof
			if err := storedProjection(ctx, s.db, "proof", scope.Request.Proof.ID, &proof); err != nil || proof.ConsumedBy != "" {
				t.Fatal("refused baseline transition consumed its human proof", err)
			}
		})
	}
}
