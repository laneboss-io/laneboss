package policy

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client"
)

func testFrameForScope(t *testing.T, scope *api.Scope) {
	t.Helper()
	raw, err := json.Marshal(scope.Request)
	if err != nil {
		t.Fatal(err)
	}
	scope.Frame = testFrame(raw)
}

func TestForeignPolicyReceipt(t *testing.T) {
	for _, row := range []struct {
		name  string
		alter func(*api.MutationReceipt)
	}{
		{"config", func(r *api.MutationReceipt) { r.Config = "foreign" }},
		{"principal", func(r *api.MutationReceipt) { r.Actor.ID = "foreign" }},
		{"life", func(r *api.MutationReceipt) { r.Actor.LifeID = "foreign" }},
		{"kind", func(r *api.MutationReceipt) { r.Actor.Kind = "human" }},
		{"method", func(r *api.MutationReceipt) { r.Key.Method = "judge.ask" }},
		{"key", func(r *api.MutationReceipt) { r.Key.IdempotencyKey = "foreign" }},
		{"digest", func(r *api.MutationReceipt) { r.Key.RequestSHA256 = digestBytes([]byte("foreign")) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newFixture(t, sourceRule("ordinary"))
			f.store.alterReceipt = row.alter
			_, err := f.evaluateOnce(context.Background())
			wantCode(t, err, api.CodeIntegrity)
			if len(f.judge.requests)+len(f.store.uploads)+len(f.store.events) != 0 {
				t.Fatal("foreign receipt performed policy work")
			}
		})
	}
}

func TestReceiptDomainBoundaries(t *testing.T) {
	f := newFixture(t, sourceRule("ordinary"))
	f.evaluate(t)
	key := testScopeKey(f.scope)
	for _, mutate := range []func(*api.Scope, *api.RequestKey){
		func(s *api.Scope, _ *api.RequestKey) { s.Config = "different" },
		func(s *api.Scope, _ *api.RequestKey) { s.Actor.Kind = "human" },
		func(s *api.Scope, _ *api.RequestKey) { s.Actor.ID = "different" },
		func(s *api.Scope, _ *api.RequestKey) { s.Actor.LifeID = "different" },
		func(_ *api.Scope, k *api.RequestKey) { k.Method = "judge.ask" },
		func(_ *api.Scope, k *api.RequestKey) { k.IdempotencyKey = "different" },
	} {
		scope, changed := f.scope, key
		mutate(&scope, &changed)
		_, err := f.store.LookupReceipt(context.Background(), scope, changed)
		wantCode(t, err, api.CodeNotFound)
	}
	changed := key
	changed.RequestSHA256 = digestBytes([]byte("changed intent"))
	_, err := f.store.LookupReceipt(context.Background(), f.scope, changed)
	wantCode(t, err, api.CodeIdempotencyConflict)
	stored := f.store.receipts[testDomain(f.scope, key)]
	if stored.Config != f.scope.Config || stored.Actor != f.scope.Actor || stored.Key != key {
		t.Fatal("fixture rebuilt rather than retained original receipt facts")
	}
}

func TestProofBeforePolicyReplay(t *testing.T) {
	for _, row := range []struct {
		name   string
		lane   bool
		mutate func(*api.Scope)
		code   api.ErrorCode
	}{
		{"lane-proof", true, func(s *api.Scope) {
			s.Request.Proof = &api.ProofRef{ID: "human-proof", RequestSHA256: s.Request.RequestSHA256}
		}, api.CodeForbidden},
		{"missing-human", false, func(s *api.Scope) { s.Connection, s.ReadAuthority = nil, nil }, api.CodeForbidden},
		{"bad-id", false, func(s *api.Scope) {
			s.Request.Proof = &api.ProofRef{ID: "bad.id", RequestSHA256: s.Request.RequestSHA256}
		}, api.CodeInvalid},
		{"wrong-digest", false, func(s *api.Scope) {
			s.Request.Proof = &api.ProofRef{ID: "human-proof", RequestSHA256: digestBytes([]byte("different"))}
		}, api.CodeInvalid},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newFixture(t, sourceRule("ordinary"))
			if !row.lane {
				f.scope.Actor, f.scope.LaunchID = api.Actor{Kind: "human", ID: "reader"}, ""
			}
			f.evaluate(t)
			lookups, uses := f.store.lookups, f.store.proofUses
			row.mutate(&f.scope)
			testFrameForScope(t, &f.scope)
			_, err := f.service.PolicyEvaluate(context.Background(), f.scope, f.request)
			wantCode(t, err, row.code)
			if f.store.lookups != lookups || f.store.proofUses != uses || len(f.store.events) != 1 {
				t.Fatal("invalid proof reached replay or changed committed state")
			}
		})
	}
}

func TestHumanPolicyGuardAndReplay(t *testing.T) {
	f := newFixture(t, sourceRule("ordinary"))
	f.scope.Actor, f.scope.LaunchID = api.Actor{Kind: "human", ID: "reader"}, ""
	first := f.evaluate(t)
	if len(f.store.lastTx.Guards) != 0 || f.store.proofUses != 0 || f.store.lastTx.Scope.Actor != f.scope.Actor ||
		f.store.lastTx.Scope.ReadAuthority == nil || f.store.lastTx.Scope.ReadAuthority.ConnectionID != f.scope.Connection.ID() {
		t.Fatal("human preview did not retain its live session without consuming a proof")
	}
	targets := f.store.targets
	f.store.policyErr = api.NotImplemented("fixture", "preflight after completed reply")
	replayed, err := f.service.PolicyEvaluate(context.Background(), f.scope, f.request)
	if err != nil || !reflect.DeepEqual(replayed, first) || f.store.targets != targets || f.store.proofUses != 0 || len(f.store.events) != 1 {
		t.Fatalf("completed human receipt revalidated or consumed its proof again: %v", err)
	}
	f.store.policyErr = nil
	key, err := client.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	f.scope.Request.IdempotencyKey = key
	testFrameForScope(t, &f.scope)
	f.store.receipts[testDomain(f.scope, testScopeKey(f.scope))] = api.MutationReceipt{
		Config: f.scope.Config, Key: testScopeKey(f.scope), Actor: f.scope.Actor,
		Operation: api.Operation{ID: "next-operation", Status: "running"}, RawRequest: f.scope.Frame.Bytes()}
	_, err = f.service.PolicyEvaluate(context.Background(), f.scope, f.request)
	if err != nil || len(f.store.events) != 2 || f.store.proofUses != 0 {
		t.Fatalf("fresh preview on the verified session failed: %v", err)
	}
	f.clock.now = f.clock.now.Add(6 * time.Minute)
	_, err = f.service.PolicyEvaluate(context.Background(), f.scope, f.request)
	wantCode(t, err, api.CodeForbidden)
	if f.store.proofUses != 0 || len(f.store.events) != 2 {
		t.Fatal("expired human session replay changed committed state")
	}
}

func TestHumanPolicyTargetGuard(t *testing.T) {
	f := newFixture(t, sourceRule("ordinary"))
	f.scope.Actor, f.scope.LaunchID = api.Actor{Kind: "human", ID: "reader"}, ""
	if err := f.prepare(); err != nil {
		t.Fatal(err)
	}
	f.scope.Connection.(*testReadConnection).authority.PrincipalID = "different-human"
	_, err := f.service.PolicyEvaluate(context.Background(), f.scope, f.request)
	if len(f.judge.requests)+len(f.store.uploads)+len(f.store.events)+f.store.retentions != 0 {
		t.Fatal("mismatched proof target performed policy work")
	}
	wantCode(t, err, api.CodeForbidden)
}

func TestDefaultJudgeSpelling(t *testing.T) {
	f := newFixture(t, sourceRule("ordinary"))
	f.store.policy.Judge.Provider, f.store.policy.Judge.Model = "", ""
	f.seal(t)
	result, err := f.evaluateOnce(context.Background())
	if err != nil || result.Result != "allow" || len(result.Rules) != 1 || result.Rules[0].Probability == nil || len(f.judge.requests) != 1 {
		t.Fatalf("default judge spelling did not produce a scored allow: %v", err)
	}
	if f.judge.requests[0].Config.Provider != api.DefaultJudgeProvider || f.judge.requests[0].Config.Model != api.DefaultJudgeModel ||
		f.judge.requests[0].Config.DeploymentSHA256 != f.store.policy.Judge.DeploymentSHA256 {
		t.Fatal("default judge spelling lost its approved provider/model/pins")
	}
}

func TestScopedJudgeRefusal(t *testing.T) {
	for _, row := range []struct {
		name, phase string
		code        api.ErrorCode
	}{
		{"fit", "fit", api.CodeForbidden},
		{"evaluate", "evaluate", api.CodeForbidden},
		{"fit-invalid", "fit", api.CodeInvalid},
		{"evaluate-invalid", "evaluate", api.CodeInvalid},
		{"fit-not-found", "fit", api.CodeNotFound},
		{"evaluate-not-found", "evaluate", api.CodeNotFound},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newFixture(t, sourceRule("ordinary"))
			refusal := &api.Error{Code: row.code, Message: "scope, request or approved provider differs",
				Instead: "Repair the approved judge request or provider configuration.", Owner: "lb-v2-judge"}
			if row.phase == "fit" {
				f.judge.fitErr = refusal
			} else {
				f.judge.evalErr = refusal
			}
			decision, err := f.evaluateOnce(context.Background())
			wantCode(t, err, row.code)
			if err != refusal || decision.ID != "" || len(f.store.events) != 0 || len(f.judge.fits) != 1 ||
				(row.phase == "fit" && len(f.judge.requests) != 0) || (row.phase == "evaluate" && len(f.judge.requests) != 1) {
				t.Fatal("scoped judge refusal became an unscored policy allow or lost its exact typed error")
			}
		})
	}
}

func TestHumanSessionBeforeReplay(t *testing.T) {
	for _, row := range []struct {
		name string
		edit func(*testReadConnection)
	}{
		{"closed", func(c *testReadConnection) { c.closed = true }},
		{"revoked", func(c *testReadConnection) { c.revoked = true }},
		{"connection", func(c *testReadConnection) { c.authority.ConnectionID = "another-connection" }},
		{"principal", func(c *testReadConnection) { c.authority.PrincipalID = "another-human" }},
		{"config", func(c *testReadConnection) { c.authority.Config = "another-config" }},
		{"endpoint", func(c *testReadConnection) { c.authority.EndpointGeneration++ }},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newFixture(t, sourceRule("ordinary"))
			f.scope.Actor, f.scope.LaunchID = api.Actor{Kind: "human", ID: "reader"}, ""
			f.evaluate(t)
			lookups := f.store.lookups
			row.edit(f.scope.Connection.(*testReadConnection))
			_, err := f.service.PolicyEvaluate(context.Background(), f.scope, f.request)
			wantCode(t, err, api.CodeForbidden)
			if f.store.lookups != lookups || len(f.store.events) != 1 {
				t.Fatal("stale or borrowed human session reached replay")
			}
		})
	}
}
