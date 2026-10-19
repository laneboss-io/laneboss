package policy

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// This models the approved projection arriving from the store. The public E2E
// separately performs actual file-backed D6 applies while its workers stay live.
func nextFixturePolicy(t *testing.T, f *fixture) {
	t.Helper()
	f.scope.PolicyGeneration++
	f.store.policy.Generation++
	f.store.policy.Rules[0].Text += " Apply the newly approved responsibility."
	f.seal(t)
}

func TestPolicyCurrentEvaluation(t *testing.T) {
	f := newFixture(t, sourceRule("ordinary"))
	f.evaluate(t)
	before, launch, grants, turn := f.store.lane, f.store.launch, f.store.grants, f.store.turn
	nextFixturePolicy(t, f)
	f.judge.probability = 1
	for _, method := range []string{"policy.get", "config.read", "config.validate"} {
		if err := readFixture(f, method); err != nil {
			t.Fatalf("historical launch pin blocked a current policy read: %v", err)
		}
	}
	if !reflect.DeepEqual(f.store.lane, before) || len(f.store.advanceRequests) != 0 || len(f.store.policyEvents) != 0 {
		t.Fatal("policy read refreshed the lane's recorded projection")
	}
	decision, err := f.evaluateOnce(context.Background())
	if err != nil || decision.PolicyGeneration != f.scope.PolicyGeneration || decision.Result != "refuse" ||
		decision.CacheOf != "" || decision.SkipID != "" || len(f.judge.requests) != 2 ||
		f.judge.requests[1].Context.PolicyGeneration != f.scope.PolicyGeneration ||
		f.judge.requests[1].Rules[0].Text != f.store.policy.Rules[0].Text {
		t.Fatalf("fresh policy evaluation did not use the current approved generation: %v", err)
	}
	if len(f.store.advanceRequests) != 1 || len(f.store.policyEvents) != 1 {
		t.Fatal("fresh policy evaluation omitted its one protected lane refresh")
	}
	request := f.store.advanceRequests[0]
	if request.ExpectedLaneGeneration != before.Generation || request.CancellationEpoch != before.CancellationEpoch ||
		request.FromGeneration != before.PolicyGeneration || request.ToGeneration != f.scope.PolicyGeneration {
		t.Fatal("lane policy refresh used a stale life fence")
	}
	want := before
	want.Generation++
	want.PolicyGeneration, want.LastSeq = f.scope.PolicyGeneration, f.store.policyEvents[0].Seq
	if !reflect.DeepEqual(f.store.lane, want) || !reflect.DeepEqual(f.store.launch, launch) ||
		!reflect.DeepEqual(f.store.grants, grants) || !reflect.DeepEqual(f.store.turn, turn) {
		t.Fatal("policy refresh rewrote historical launch/grants or unrelated live state")
	}
	var advance api.PolicyAdvanceEvent
	if api.DecodeObject(f.store.policyEvents[0].Payload, &advance) != nil ||
		advance != (api.PolicyAdvanceEvent{FromGeneration: before.PolicyGeneration, ToGeneration: f.scope.PolicyGeneration,
			LaneGeneration: want.Generation, PolicySHA256: f.store.policy.SHA256, GrantSetID: before.GrantSetID}) {
		t.Fatal("policy refresh event did not retain the exact generation change")
	}
	if err := api.ValidateTransactionShape(f.store.policyTx); err != nil {
		t.Fatalf("policy refresh lost its internal CAS/cancellation write: %v", err)
	}
	cached := f.evaluate(t)
	if cached.CacheOf != decision.ID || len(f.store.advanceRequests) != 1 || len(f.store.policyEvents) != 1 || len(f.judge.requests) != 2 {
		t.Fatal("current policy cache rejudged or repeated its lane refresh")
	}
}

func TestPolicyHistoricalReplay(t *testing.T) {
	f := newFixture(t, sourceRule("ordinary"))
	first := f.evaluate(t)
	before := f.store.lane
	objects, reads := len(f.store.uploads), f.store.policyReads
	nextFixturePolicy(t, f)
	// Fresh preflight is intentionally unavailable; retained history remains real.
	f.store.policyErr = api.NotImplemented("fixture", "fresh policy preflight")
	replayed, err := f.service.PolicyEvaluate(context.Background(), f.scope, f.request)
	if err != nil || !reflect.DeepEqual(replayed, first) || len(f.store.historyReads) != 1 ||
		f.store.historyReads[0] != first.PolicyGeneration || f.store.policyReads != reads ||
		len(f.judge.requests) != 1 || len(f.store.uploads) != objects || len(f.store.events) != 1 ||
		len(f.store.advanceRequests) != 0 || !reflect.DeepEqual(f.store.lane, before) {
		t.Fatalf("exact policy replay lost its retained generation or performed fresh work: %v", err)
	}
	f.store.launch.Revoked = true
	_, err = f.service.PolicyEvaluate(context.Background(), f.scope, f.request)
	wantCode(t, err, api.CodeForbidden)
	if len(f.store.historyReads) != 1 {
		t.Fatal("revoked current authority reached policy history")
	}
}

func TestHumanPreviewKeepsLaneProjection(t *testing.T) {
	f := newFixture(t, sourceRule("ordinary"))
	nextFixturePolicy(t, f)
	f.scope.Actor, f.scope.LaunchID = api.Actor{Kind: "human", ID: "preview-reader"}, ""
	f.judge.probability = 1
	before, launch, grants, turn := f.store.lane, f.store.launch, f.store.grants, f.store.turn
	decision, err := f.evaluateOnce(context.Background())
	if err != nil || !decision.AuditComplete || decision.PolicyGeneration != f.scope.PolicyGeneration ||
		decision.Result != "refuse" || len(f.judge.requests) != 1 || len(f.judge.scopes) != 1 ||
		f.judge.scopes[0].Actor != f.scope.Actor || f.judge.requests[0].Context.PolicyGeneration != f.scope.PolicyGeneration {
		t.Fatalf("human preview did not judge current policy under its own authority: %v", err)
	}
	if len(f.store.advanceRequests) != 0 || len(f.store.policyEvents) != 0 ||
		!reflect.DeepEqual(f.store.lane, before) || !reflect.DeepEqual(f.store.launch, launch) ||
		!reflect.DeepEqual(f.store.grants, grants) || !reflect.DeepEqual(f.store.turn, turn) {
		t.Fatal("human preview refreshed the target lane policy projection")
	}
}

func TestPolicyReplayBinding(t *testing.T) {
	for _, name := range []string{"config", "actor", "key", "digest"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, sourceRule("ordinary"))
			f.evaluate(t)
			receipt := f.store.receipts[testDomain(f.scope, testScopeKey(f.scope))]
			switch name {
			case "config":
				receipt.Config = "foreign"
			case "actor":
				receipt.Actor.ID = "foreign"
			case "key":
				receipt.Key.IdempotencyKey = "foreign-key"
			case "digest":
				receipt.Key.RequestSHA256 = digestBytes([]byte("foreign intent"))
			}
			_, err := f.service.replayPolicy(context.Background(), f.scope, receipt)
			wantCode(t, err, api.CodeInvalid)
			if len(f.store.historyReads) != 0 {
				t.Fatal("foreign replay binding reached retained policy history")
			}
		})
	}
}

func TestPolicyReplayHistoryRefusals(t *testing.T) {
	for _, name := range []string{"future", "unknown", "generation", "hash", "reply", "missing-port"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, sourceRule("ordinary"))
			f.evaluate(t)
			domain := testDomain(f.scope, testScopeKey(f.scope))
			receipt := f.store.receipts[domain]
			code := api.CodeIntegrity
			switch name {
			case "future":
				receipt.PolicyGeneration = f.scope.PolicyGeneration + 1
				code = api.CodeInvalid
			case "unknown":
				delete(f.store.policyHistory, receipt.PolicyGeneration)
				code = api.CodeNotFound
			case "generation", "hash":
				policy := f.store.policyHistory[receipt.PolicyGeneration]
				if name == "generation" {
					policy.Generation++
				} else {
					policy.SHA256 = digestBytes([]byte("different policy"))
				}
				f.store.policyHistory[receipt.PolicyGeneration] = policy
			case "reply":
				var decision api.PolicyDecision
				if err := json.Unmarshal(receipt.Reply.Result, &decision); err != nil {
					t.Fatal(err)
				}
				decision.PolicyGeneration++
				raw, err := json.Marshal(decision)
				if err != nil {
					t.Fatal(err)
				}
				receipt.Reply = &api.RPCReply{Result: raw}
			case "missing-port":
				f.store.historyErr = api.NotImplemented("lb-v2-service", "store.PolicyAt")
				code = api.CodeNotImplemented
			}
			f.store.receipts[domain] = receipt
			_, err := f.service.PolicyEvaluate(context.Background(), f.scope, f.request)
			wantCode(t, err, code)
			if len(f.judge.requests) != 1 || len(f.store.advanceRequests) != 0 || len(f.store.events) != 1 {
				t.Fatal("invalid historical replay started new work")
			}
		})
	}
}

func TestPolicyAdvanceReceiptRefusals(t *testing.T) {
	for _, name := range []string{"pin", "event", "cas", "epoch", "unchanged"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, sourceRule("ordinary"))
			nextFixturePolicy(t, f)
			f.store.alterAdvance = func(receipt *api.PolicyAdvanceReceipt) {
				switch name {
				case "pin":
					receipt.Lane.GrantSetID = "widened-grants"
				case "event":
					receipt.Event.ToGeneration--
				case "cas":
					receipt.Lane.Generation++
				case "epoch":
					receipt.Lane.CancellationEpoch++
				case "unchanged":
					receipt.Changed = false
				}
			}
			decision, err := f.evaluateOnce(context.Background())
			wantCode(t, err, api.CodeInvalid)
			if decision.ID != "" || len(f.judge.fits) != 0 || len(f.store.events) != 0 || len(f.store.advanceRequests) != 1 {
				t.Fatal("invalid policy advance receipt reached judgment or success")
			}
		})
	}
}

func TestPolicyAdvancePortFailure(t *testing.T) {
	for _, code := range []api.ErrorCode{api.CodeConflict, api.CodeNotImplemented} {
		f := newFixture(t, sourceRule("ordinary"))
		nextFixturePolicy(t, f)
		refusal := &api.Error{Code: code, Owner: "lb-v2-service", Message: "policy refresh unavailable",
			Instead: "Reconcile the current protected lane policy projection."}
		f.store.advanceErr = refusal
		_, err := f.evaluateOnce(context.Background())
		if err != refusal || len(f.judge.fits) != 0 || len(f.store.events) != 0 || len(f.store.policyEvents) != 0 {
			t.Fatalf("policy refresh failure became judgment or success: %v", err)
		}
	}
}

func TestPolicyAdvanceFence(t *testing.T) {
	f := newFixture(t, sourceRule("ordinary"))
	before := f.store.lane
	nextFixturePolicy(t, f)
	_, err := f.evaluateOnce(context.Background())
	if err != nil || len(f.store.advanceRequests) != 1 ||
		f.store.advanceRequests[0].ExpectedLaneGeneration != before.Generation ||
		f.store.advanceRequests[0].CancellationEpoch != before.CancellationEpoch {
		t.Fatalf("lane policy refresh used a stale life fence: %v", err)
	}
}
