//go:build linux

package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestPresenceWriteFences(t *testing.T) {
	for _, kind := range []string{"ticket", "session", "approval", "application"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := testStore(t)
			ctx := context.Background()
			// An already-approved authority DTO isolates propagation. This is
			// neither a software authenticator nor a registration substitute.
			approval := api.ChangeApproval{ID: testID(t), SimulatedPresence: true}
			fixtureProjection(t, s, "approval", approval.ID, 1, approval)
			input := api.Transaction{Guards: []api.TransactionGuard{{Approval: &api.ApprovalUse{ApprovalID: approval.ID}}}}
			switch kind {
			case "ticket":
				input.Writes.Tickets = []api.Ticket{{SimulatedPresence: true}}
			case "session":
				input.Writes.ReadSessions = []api.StoredReadSession{{Session: api.HumanSession{SimulatedPresence: true}}}
			case "approval":
				input.Writes.Approvals = []api.ChangeApproval{{SimulatedPresence: true}}
			case "application":
				input.Writes.Applications = []api.ChangeReceipt{{ApprovalID: approval.ID, SimulatedPresence: true}}
			}
			if marked, err := s.transactionPresence(ctx, s.db, input); err != nil || !marked {
				t.Fatal("retained presence propagation control failed", err)
			}
			switch kind {
			case "ticket":
				input.Writes.Tickets[0].SimulatedPresence = false
			case "session":
				input.Writes.ReadSessions[0].Session.SimulatedPresence = false
			case "approval":
				input.Writes.Approvals[0].SimulatedPresence = false
			case "application":
				input.Writes.Applications[0].SimulatedPresence = false
			}
			if _, err := s.transactionPresence(ctx, s.db, input); err == nil {
				t.Fatal("presence propagation accepted dropped " + kind)
			}
		})
	}
}

func TestPendingPresenceSurvives(t *testing.T) {
	t.Run("pending_operation", func(t *testing.T) {
		s, _ := testStore(t)
		input := testTransaction(t)
		raw, err := json.Marshal(input.Scope.Request)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := s.ReserveRequest(context.Background(), api.RequestReservation{Scope: input.Scope, RawRequest: raw, Deadline: api.Timestamp(time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano))})
		if err != nil {
			t.Fatal(err)
		}
		// Install a previously verified mark into this component's pending
		// operation, then finish the same request without another proof.
		operation := receipt.Operation
		operation.SimulatedPresence = true
		data, err := json.Marshal(operation)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.ExecContext(context.Background(), "UPDATE operations SET data=? WHERE id=?", data, string(operation.ID)); err != nil {
			t.Fatal(err)
		}
		commit, err := s.Transact(context.Background(), input)
		if err != nil || !commit.Operation.SimulatedPresence {
			t.Fatal("pending operation completion dropped retained simulated presence", err)
		}
	})
}

func TestPresenceEvolution(t *testing.T) {
	t.Run("retained_mark", func(t *testing.T) {
		before := api.Operation{ID: testID(t), Status: "pending", SimulatedPresence: true}
		after := before
		after.SimulatedPresence = false
		if validOperationEvolution(enrollmentJSON(t, after), enrollmentJSON(t, before)) {
			t.Fatal("operation evolution erased retained simulated presence")
		}
		if !validOperationEvolution(enrollmentJSON(t, before), enrollmentJSON(t, before)) {
			t.Fatal("unchanged operation presence control failed")
		}
	})
}
