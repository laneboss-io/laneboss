package watchdog

import (
	"context"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func (r *testRig) advancePolicy() {
	r.store.policyHistory = map[api.Generation]api.EffectivePolicy{r.store.policy.Generation: r.store.policy}
	r.store.policy.Generation++
	r.store.policy.SHA256 = digest([]byte("new approved fixture policy"))
}

func TestFreshPolicy(t *testing.T) {
	r := newRig(t)
	before, turn, launch, grants := r.store.lane, r.store.turn, r.store.launch, r.store.grants
	r.advancePolicy()
	plan, err := r.s.assess(context.Background(), r.signal)
	if err != nil || plan.Swap == nil || plan.Lane.PolicyGeneration != r.store.policy.Generation ||
		plan.Lane.Generation != before.Generation+1 || plan.Swap.ExpectedGeneration != plan.Lane.Generation || len(r.store.policyRefreshes) != 1 {
		t.Fatal("fresh continuation did not refresh current policy before its fences", err)
	}
	if !reflect.DeepEqual(r.store.turn, turn) || !reflect.DeepEqual(r.store.launch, launch) || !reflect.DeepEqual(r.store.grants, grants) ||
		r.store.policyHistory[turn.PolicyGeneration].Generation != turn.PolicyGeneration {
		t.Fatal("current policy refresh rewrote historical turn, launch or issued grants")
	}
	r.noEffects()
}

func TestPolicyRefreshReceipt(t *testing.T) {
	r := newRig(t)
	r.advancePolicy()
	r.store.policyReply = func(receipt api.PolicyAdvanceReceipt) api.PolicyAdvanceReceipt {
		receipt.Lane.BudgetRemaining.SpendMicros++
		return receipt
	}
	_, err := r.s.assess(context.Background(), r.signal)
	requireCode(t, err, api.CodeInvalid)
	if !reflect.DeepEqual(r.broker.checked, []api.ID{"profile-a", "profile-b"}) || len(r.store.policyRefreshes) != 1 {
		t.Fatal("policy-advance receipt was not checked after corroborated profile selection")
	}
	r.noEffects()
}

func TestPolicyHistory(t *testing.T) {
	r := newRig(t)
	r.advancePolicy()
	history := r.store.policyHistory[r.store.turn.PolicyGeneration]
	history.Generation++
	r.store.policyHistory[r.store.turn.PolicyGeneration] = history
	_, err := r.s.assess(context.Background(), r.signal)
	requireCode(t, err, api.CodeIntegrity)
	r.noEffects()
}

func TestRetainedPolicyReplay(t *testing.T) {
	r, store, probe := newJournal(t)
	operation, err := r.s.ObserveLimit(context.Background(), r.signal)
	if err != nil {
		t.Fatal(err)
	}
	id := probe.requests[0].IntentID
	intent := store.intents[id]
	intent.Status = "completed"
	store.intents[id] = intent
	operation.Status = "succeeded"
	store.operations[operation.ID] = operation
	turn, launch := store.turn, store.launch
	r.advancePolicy()
	replayed, err := r.s.Reconcile(context.Background(), r.signal.Target)
	if err != nil || replayed != operation || len(probe.requests) != 1 || len(store.policyRefreshes) != 0 ||
		!reflect.DeepEqual(turn, store.turn) || !reflect.DeepEqual(launch, store.launch) {
		t.Fatal("receipt replay refreshed or replaced its retained policy snapshot", err)
	}
}

func TestFreshPolicyExclusion(t *testing.T) {
	r := newRig(t)
	r.advancePolicy()
	r.store.policy.ProfileExclusions = []api.ID{"profile-b"}
	plan, err := r.s.assess(context.Background(), r.signal)
	if err != nil || plan.Swap != nil || !reflect.DeepEqual(r.broker.checked, []api.ID{"profile-a"}) {
		t.Fatal("fresh continuation used historical profile exclusions", err)
	}
	r.noEffects()
}
