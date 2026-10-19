package api

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestPolicyUse(t *testing.T) {
	for _, row := range []struct {
		name     string
		use      PolicyUse
		expected Generation
	}{
		{"evaluation", PolicyNewEvaluation, 4}, {"selection", PolicyNewSelection, 4}, {"launch", PolicyNewLaunch, 4},
		{"replay", PolicyExactReplay, 3}, {"retained", PolicyRetainedSelection, 3},
	} {
		t.Run(row.name, func(t *testing.T) {
			actual, err := PolicyGenerationFor(row.use, 4, 3)
			if err != nil || actual != row.expected {
				t.Fatalf("policy use selected the wrong generation: got=%d want=%d err=%v", actual, row.expected, err)
			}
		})
	}
	if _, err := PolicyGenerationFor(PolicyExactReplay, 4, 5); err == nil {
		t.Fatal("future receipt policy was accepted")
	}
}

func TestPolicyReplay(t *testing.T) {
	p := launchFixture(t)
	scope := Scope{Config: "demo", Actor: p.Reservation.RequestedBy, PolicyGeneration: 4, Request: Request{Method: "guidance.select", IdempotencyKey: "retained-key", RequestSHA256: p.Reservation.RequestSHA256}}
	r := MutationReceipt{Config: scope.Config, Actor: scope.Actor, PolicyGeneration: 3, Key: RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}}
	actual, err := PolicyGenerationForReplay(scope, EffectivePolicy{Generation: 4}, r)
	if err != nil || actual != 3 {
		t.Fatalf("mid-turn policy apply blocked exact replay: generation=%d err=%v", actual, err)
	}
	r.Key.RequestSHA256 = launchFixtureBlob("different-request", "task").SHA256
	_, err = PolicyGenerationForReplay(scope, EffectivePolicy{Generation: 4}, r)
	requireLaunchInvalid(t, err, "policy replay ignored its retained request binding")
}

func policyAdvanceFixture(t *testing.T) (Lane, PolicyAdvanceRequest, EffectivePolicy, PolicyAdvanceReceipt) {
	t.Helper()
	p := launchFixture(t)
	before := Lane{LifeID: p.Reservation.Target.LifeID, Run: 1, Generation: 7, PolicyGeneration: 3, CancellationEpoch: 1, State: "running", GrantSetID: p.Reservation.GrantSetID, LastSeq: 12}
	current := EffectivePolicy{Generation: 4, SHA256: launchFixtureBlob("current-policy", "manifest").SHA256}
	request := PolicyAdvanceRequest{Target: p.Reservation.Target, ExpectedLaneGeneration: 7, FromGeneration: 3, ToGeneration: 4, CancellationEpoch: 1}
	after := before
	after.Generation, after.PolicyGeneration, after.LastSeq = 8, 4, 20
	event := PolicyAdvanceEvent{FromGeneration: 3, ToGeneration: 4, LaneGeneration: 8, PolicySHA256: current.SHA256, GrantSetID: before.GrantSetID}
	return before, request, current, PolicyAdvanceReceipt{Changed: true, Lane: after, Event: event, EventID: "policy-event", CommittedSeq: 20}
}

func TestPolicyAdvance(t *testing.T) {
	b, r, p, a := policyAdvanceFixture(t)
	if err := ValidatePolicyAdvance(b, r, p, a); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"pin", "event", "epoch", "cas"} {
		t.Run(fault, func(t *testing.T) {
			b, r, p, a := policyAdvanceFixture(t)
			switch fault {
			case "pin":
				a.Lane.GrantSetID = "widened-grants"
			case "event":
				a.Event.ToGeneration = 3
			case "epoch":
				r.CancellationEpoch++
			case "cas":
				r.ExpectedLaneGeneration--
			}
			requireLaunchInvalid(t, ValidatePolicyAdvance(b, r, p, a), "lane policy advance escaped its narrow CAS update")
		})
	}
	b.PolicyGeneration, r.FromGeneration = 4, 4
	if err := ValidatePolicyAdvance(b, r, p, PolicyAdvanceReceipt{Lane: b}); err != nil {
		t.Fatal(err)
	}
}

func TestLaunchPolicyCurrent(t *testing.T) {
	p := launchFixture(t)
	current := EffectivePolicy{Generation: p.Reservation.PolicyGeneration}
	if err := ValidateLaunchPolicyCurrent(p.Reservation, p.Inputs.Grants, current); err != nil {
		t.Fatal(err)
	}
	current.Generation++
	var typed *Error
	if err := ValidateLaunchPolicyCurrent(p.Reservation, p.Inputs.Grants, current); !errors.As(err, &typed) || typed.Code != CodeConflict {
		t.Fatalf("stale unopened launch escaped current policy recheck: %v", err)
	}
	p.Reservation.PolicyGeneration, p.Inputs.Grants.PolicyGeneration = current.Generation, current.Generation
	if err := ValidateLaunchPolicyCurrent(p.Reservation, p.Inputs.Grants, current); err != nil {
		t.Fatalf("current continuation policy was refused: %v", err)
	}
}

func TestPolicyAdvanceWrite(t *testing.T) {
	b, _, _, a := policyAdvanceFixture(t)
	payload, err := json.Marshal(a.Event)
	if err != nil {
		t.Fatal(err)
	}
	cause := InternalIntent{ID: "policy-refresh", Kind: InternalPolicyRefresh, Config: "demo", Actor: Actor{Kind: "service", ID: "policy"}, Target: LifeRef{LifeID: b.LifeID, Run: b.Run}, CancellationEpoch: b.CancellationEpoch}
	tx := Transaction{Scope: Scope{Config: "demo"}, Internal: &cause, Writes: StateWrites{Lanes: []Lane{a.Lane}}, Events: []Event{{Kind: "lane.policy", Payload: payload}},
		Compare: []Compare{{Kind: CompareLane, ID: b.LifeID, Generation: b.Generation}}, Guards: []TransactionGuard{{Cancellation: &CancellationCheck{LifeID: b.LifeID, Epoch: b.CancellationEpoch}}}}
	if err := ValidateTransactionShape(tx); err != nil {
		t.Fatal(err)
	}
	tx.Compare = nil
	var typed *Error
	if err := ValidateTransactionShape(tx); !errors.As(err, &typed) || typed.Code != CodeInvalid {
		t.Fatalf("policy refresh omitted lane CAS: %v", err)
	}
}
