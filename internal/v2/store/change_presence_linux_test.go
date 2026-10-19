//go:build linux

package store

import (
	"context"
	"encoding/json"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// These are already verified component authority records. Tagged identity tests
// separately exercise signed software ceremonies; this does not prove a person.
func TestChangePublicationPresence(t *testing.T) {
	for _, authority := range []string{"approval", "pending_operation"} {
		t.Run(authority, func(t *testing.T) {
			s, _, tx := deferredChangeFixture(t)
			ctx := context.Background()
			if authority == "approval" {
				var approved api.ChangeApproval
				if err := storedProjection(ctx, s.db, "approval", tx.Effects[0].ApplyChange.ApprovalID, &approved); err != nil {
					t.Fatal(err)
				}
				approved.SimulatedPresence = true
				fixtureProjection(t, s, "approval", approved.ID, 1, approved)
			} else {
				receipt, err := s.LookupReceipt(ctx, tx.Scope, tx.Deferred.Key)
				if err != nil {
					t.Fatal(err)
				}
				receipt.Operation.SimulatedPresence = true
				if _, err := s.db.Exec("UPDATE operations SET data=? WHERE id=?", enrollmentJSON(t, receipt.Operation), string(receipt.Operation.ID)); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := s.Transact(ctx, tx); err != nil {
				t.Fatal(err)
			}
			scope, lease, request := publicationClaim(t, s, tx)
			actual, err := s.PublishChange(ctx, scope, request)
			if err != nil || !actual.SimulatedPresence {
				t.Fatal("canonical publication dropped consumed simulated authority", err)
			}
			commit, err := s.CompleteEffect(ctx, scope, publicationOutcome(t, tx, lease, actual))
			if err != nil || !commit.Operation.SimulatedPresence {
				t.Fatal("publication completion lost simulated operation provenance", err)
			}
			var returned api.ChangeReceipt
			if json.Unmarshal(commit.Reply.Result, &returned) != nil || !returned.SimulatedPresence {
				t.Fatal("final deferred publication reply was upgraded to physical presence")
			}
		})
	}
}
