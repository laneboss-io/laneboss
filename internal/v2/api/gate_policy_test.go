package api

import (
	"context"
	"errors"
	"testing"
)

type gatePolicyModel struct {
	current map[string]EffectivePolicy
	err     error
	calls   int
}

func (m *gatePolicyModel) CurrentApprovedPolicy(_ context.Context, scope Scope) (EffectivePolicy, error) {
	m.calls++
	if m.err != nil {
		return EffectivePolicy{}, m.err
	}
	policy, ok := m.current[scope.Config]
	if !ok {
		return EffectivePolicy{}, &Error{Code: CodeNotFound}
	}
	return policy, nil
}

func gatePolicyForTest(t *testing.T, tx Transaction, generation Generation) Transaction {
	t.Helper()
	source := &gatePolicyModel{current: map[string]EffectivePolicy{tx.Scope.Config: {Generation: generation}}}
	bound, err := BindCurrentLaunchPolicy(context.Background(), source, tx)
	if err != nil || source.calls != 1 {
		t.Fatalf("current launch policy was not read: %v", err)
	}
	return bound
}

func gateTransaction(t *testing.T, kind InternalKind) Transaction {
	t.Helper()
	p := launchFixture(t)
	r, binding := p.Reservation, launchFixtureBinding(t, p)
	phase := "bound"
	if kind == InternalHelperOpen {
		phase = "opened"
	}
	cause := InternalIntent{ID: "gate-intent", Kind: kind, Config: r.Config, Target: r.Target,
		Actor: Actor{Kind: "service", ID: "gate-service"}, RequestedBy: r.RequestedBy, CauseOperationID: r.OperationID,
		CauseRequestID: r.RequestID, EffectID: ID("gate-" + string(kind)), CancellationEpoch: r.CancellationEpoch, LogicalTurnID: "logical-turn"}
	record := LaunchPlanRecord{Reservation: r, Generation: 4, Phase: phase, Inputs: &p.Inputs, Plan: &p, Handoff: &binding.Recovery.Handoff}
	lane := Lane{LifeID: r.Target.LifeID, Run: r.Target.Run, Generation: r.Generation, GrantSetID: r.GrantSetID, LaunchID: r.LaunchID,
		Level: r.Level, Role: r.Role, Session: p.Runner.Session}
	return Transaction{Scope: Scope{Config: r.Config, Actor: cause.Actor, PolicyGeneration: r.PolicyGeneration}, Internal: &cause,
		Writes:  StateWrites{LaunchPlans: []LaunchPlanRecord{record}, IdentityBindings: []LaunchBindingRequest{binding}, Lanes: []Lane{lane}},
		Compare: []Compare{{Kind: CompareLaunchPlan, ID: r.ID, Generation: 3}, {Kind: CompareLane, ID: r.Target.LifeID, Generation: r.BaseGeneration}},
		Guards:  []TransactionGuard{{Cancellation: &CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}}
}

func requireGateInvalid(t *testing.T, err error, diagnostic string) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != CodeInvalid {
		t.Fatalf("%s: %v", diagnostic, err)
	}
}

func TestGatePolicy(t *testing.T) {
	for _, row := range []struct {
		name string
		kind InternalKind
	}{{"prepare", InternalHelperPrepare}, {"open", InternalHelperOpen}} {
		t.Run(row.name+"_old", func(t *testing.T) {
			tx := gateTransaction(t, row.kind)
			old := tx.Writes.LaunchPlans[0].Reservation.PolicyGeneration
			current := gatePolicyForTest(t, tx, old)
			if err := ValidateTransactionShape(current); err != nil {
				t.Fatal(err)
			}
			// Scope remains historical; only the protected head read advances.
			stale := gatePolicyForTest(t, tx, old+1)
			requireGateInvalid(t, ValidateTransactionShape(stale), "launch policy gate was bypassed")
		})
		t.Run(row.name+"_missing", func(t *testing.T) {
			tx := gateTransaction(t, row.kind)
			requireGateInvalid(t, ValidateTransactionShape(tx), "launch policy stamp was omitted")
		})
	}
	t.Run("reuse", func(t *testing.T) {
		prepared := gateTransaction(t, InternalHelperPrepare)
		prepared = gatePolicyForTest(t, prepared, prepared.Scope.PolicyGeneration)
		opened := gateTransaction(t, InternalHelperOpen)
		opened.launchPolicy = prepared.launchPolicy
		requireGateInvalid(t, ValidateTransactionShape(opened), "prepare policy stamp was reused for opening")
	})
	t.Run("source", func(t *testing.T) {
		tx := gateTransaction(t, InternalHelperOpen)
		sentinel := errors.New("approved policy unavailable")
		source := &gatePolicyModel{err: sentinel}
		if _, err := BindCurrentLaunchPolicy(context.Background(), source, tx); !errors.Is(err, sentinel) || source.calls != 1 {
			t.Fatalf("approved policy source failure was hidden: %v", err)
		}
	})
}

func TestTurnEvent(t *testing.T) {
	for _, emitter := range []string{"public", "open", "mail"} {
		t.Run(emitter, func(t *testing.T) {
			var tx Transaction
			switch emitter {
			case "public":
				tx = catalogTransaction(t, "lane.turn")
			case "open":
				tx = gateTransaction(t, InternalHelperOpen)
				tx = gatePolicyForTest(t, tx, tx.Scope.PolicyGeneration)
			case "mail":
				cause := InternalIntent{ID: "mail-intent", Kind: InternalMailDeliver, Config: "demo", Actor: Actor{Kind: "service", ID: "mail-service"}, Target: LifeRef{LifeID: "life", Run: 1}, LogicalTurnID: "logical-turn"}
				tx = Transaction{Scope: Scope{Config: "demo"}, Internal: &cause, Guards: []TransactionGuard{{Cancellation: &CancellationCheck{LifeID: "life", Epoch: 1}}}}
			}
			target := LifeRef{LifeID: tx.Scope.Actor.LifeID, Run: 1}
			if tx.Internal != nil {
				target = tx.Internal.Target
			}
			tx.Events = []Event{{Kind: "lane.turn", LifeID: target.LifeID, Run: target.Run, LogicalTurnID: "logical-turn"}}
			if err := ValidateTransactionShape(tx); err != nil {
				t.Fatal(err)
			}
			tx.Events[0].LogicalTurnID = ""
			requireGateInvalid(t, ValidateTransactionShape(tx), "turn event omitted logical turn identity")
		})
	}
}
