package lifecycle

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func (store *fixtureStore) PolicyAt(_ context.Context, _ api.Scope, generation api.Generation) (api.EffectivePolicy, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	policy, ok := store.policyHistory[generation]
	if !ok {
		return api.EffectivePolicy{}, launchMissing()
	}
	return policy, nil
}

func (store *fixtureStore) RefreshLanePolicy(_ context.Context, scope api.Scope, request api.PolicyAdvanceRequest) (api.PolicyAdvanceReceipt, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.policyRefreshes++
	before, ok := store.lanes[request.Target.LifeID]
	if !ok || !treeVisible(scope, before) || scope.PolicyGeneration != store.policy.Generation ||
		before.Generation != request.ExpectedLaneGeneration || before.CancellationEpoch != request.CancellationEpoch {
		return api.PolicyAdvanceReceipt{}, launchConflict()
	}
	receipt := api.PolicyAdvanceReceipt{Lane: before}
	if before.PolicyGeneration != store.policy.Generation {
		receipt.Changed = true
		receipt.EventID = launchIDForTest()
		receipt.CommittedSeq = store.seq + 1
		receipt.Lane.Generation++
		receipt.Lane.PolicyGeneration = store.policy.Generation
		receipt.Lane.LastSeq = receipt.CommittedSeq
		receipt.Event = api.PolicyAdvanceEvent{FromGeneration: before.PolicyGeneration, ToGeneration: store.policy.Generation,
			LaneGeneration: receipt.Lane.Generation, PolicySHA256: store.policy.SHA256, GrantSetID: before.GrantSetID}
	}
	if err := api.ValidatePolicyAdvance(before, request, store.policy, receipt); err != nil {
		return api.PolicyAdvanceReceipt{}, err
	}
	if receipt.Changed {
		raw, err := json.Marshal(receipt.Event)
		if err != nil {
			return api.PolicyAdvanceReceipt{}, err
		}
		store.seq++
		store.lanes[before.LifeID] = receipt.Lane
		stamp := api.Timestamp(fixtureClock{}.Now().Format(time.RFC3339Nano))
		store.events = append(store.events, api.Event{Schema: api.SchemaVersion, ID: receipt.EventID, Config: scope.Config, Kind: "lane.policy", Origin: "service", RecordedAt: stamp, ObservedAt: stamp, RequestedAt: stamp, LogicalTurnID: before.LogicalTurnID,
			Actor: api.Actor{Kind: "service", ID: "policy-coordinator"}, RequestedBy: scope.Actor, RequestID: launchIDForTest(), OperationID: launchIDForTest(),
			LifeID: before.LifeID, Run: before.Run, ParentLifeID: before.ParentLifeID, RootLifeID: before.RootLifeID, StarterChain: append([]api.ID{}, before.StarterChain...),
			StarterEventSeq: before.StarterEventSeq, Seq: store.seq, Payload: raw})
	}
	return receipt, nil
}

func advanceFixturePolicy(f *fixture) {
	f.t.Helper()
	f.store.policyHistory[f.store.policy.Generation] = f.store.policy
	f.store.policy.Generation++
	raw, err := json.Marshal(f.store.policy)
	if err != nil {
		f.t.Fatal(err)
	}
	f.store.policy.SHA256 = digestOf(raw)
	f.store.policyHistory[f.store.policy.Generation] = f.store.policy
}

func TestPolicyFreshFence(t *testing.T) {
	f := newLaunchFixture(t)
	_, lane := f.endedPlan(t)
	oldGrants := launchClone(t, f.store.grants[lane.GrantSetID])
	oldBinding := launchClone(t, f.store.bindings[lane.LaunchID])
	advanceFixturePolicy(f.fixture)
	request := api.ResumeRequest{Target: api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}, ExpectedGeneration: lane.Generation,
		Message: f.fixture.blob("new-policy-input", "task", []byte("fresh work under current policy")), Budget: lane.BudgetRemaining}
	scope := f.fixture.scope("lane.resume", request, f.parent)
	scope.PolicyGeneration = f.store.policy.Generation
	validated, validationErr := f.service.revalidate(context.Background(), scope, lane)
	if validationErr != nil || !reflect.DeepEqual(validated, oldGrants) {
		t.Fatalf("current revalidation rewrote historical issuance: %v", validationErr)
	}
	_, err := f.service.LaneResume(context.Background(), scope, request)
	if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict || f.store.lanes[lane.LifeID].PolicyGeneration != f.store.policy.Generation ||
		f.store.lanes[lane.LifeID].Generation != lane.Generation+1 {
		t.Fatalf("fresh policy did not refresh before taking the launch fence: %v", err)
	}
	request.ExpectedGeneration = f.store.lanes[lane.LifeID].Generation
	scope = f.fixture.scope("lane.resume", request, f.parent)
	scope.PolicyGeneration = f.store.policy.Generation
	operation, err := f.service.LaneResume(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	var reservation api.LaunchPlanRecord
	for _, candidate := range f.store.plans {
		if candidate.Reservation.OperationID == operation.ID {
			reservation = candidate
		}
	}
	internal, planRequest := f.claim(t, reservation)
	plan, err := f.service.PlanLaunch(context.Background(), internal, planRequest)
	if err != nil || plan.Reservation.PolicyGeneration != f.store.policy.Generation || plan.Inputs.Grants.PolicyGeneration != f.store.policy.Generation ||
		plan.Inputs.Grants.ID == oldGrants.ID || !reflect.DeepEqual(f.store.grants[oldGrants.ID], oldGrants) || !reflect.DeepEqual(f.store.bindings[lane.LaunchID], oldBinding) {
		t.Fatalf("fresh launch reused or rewrote historical authority: %v", err)
	}
}

func TestPolicyReceiptReplay(t *testing.T) {
	for _, mode := range []string{"retained", "unknown", "future", "foreign"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			operation, _ := f.reserve(t)
			advanceFixturePolicy(f.fixture)
			key := api.RequestKey{Method: f.scope.Request.Method, IdempotencyKey: f.scope.Request.IdempotencyKey, RequestSHA256: f.scope.Request.RequestSHA256}
			if mode != "retained" {
				receipt := f.store.receipts[fixtureReceiptKey(f.scope, key)]
				if mode == "unknown" {
					delete(f.store.policyHistory, receipt.PolicyGeneration)
				} else if mode == "foreign" {
					wrong := f.store.policyHistory[receipt.PolicyGeneration]
					wrong.Generation++
					f.store.policyHistory[receipt.PolicyGeneration] = wrong
				} else {
					receipt.PolicyGeneration = f.store.policy.Generation + 1
				}
				f.store.receipts[fixtureReceiptKey(f.scope, key)] = receipt
			}
			scope := f.scope
			scope.PolicyGeneration = f.store.policy.Generation
			// authorize also validates completed receipts through lookupReply.
			// Exercise the launch-specific boundary directly as well, so that
			// removing its own policy check cannot hide behind that earlier gate.
			direct, found, directErr := f.service.launchReplay(context.Background(), scope)
			if mode == "retained" {
				if directErr != nil || !found || !reflect.DeepEqual(direct, operation) || f.store.policyRefreshes != 0 || f.store.reservationCalls != 1 {
					t.Fatalf("exact receipt replay was reevaluated after policy advance: direct: %v", directErr)
				}
			} else {
				want := api.CodeInvalid
				if mode == "unknown" {
					want = api.CodeNotFound
				} else if mode == "foreign" {
					want = api.CodeIntegrity
				}
				if typed, ok := directErr.(*api.Error); !ok || typed.Code != want || !found {
					t.Fatalf("unknown or future receipt policy authorized replay: direct: %v", directErr)
				}
			}
			replay, err := f.service.LaneStart(context.Background(), scope, f.request)
			if mode == "retained" {
				if err != nil || !reflect.DeepEqual(replay, operation) || f.store.policyRefreshes != 0 || f.store.reservationCalls != 1 {
					t.Fatalf("exact receipt replay was reevaluated after policy advance: %v", err)
				}
			} else if err == nil {
				t.Fatal("unknown or future receipt policy authorized replay")
			}
		})
	}
}

func TestPolicyErrorReplay(t *testing.T) {
	for _, mode := range []string{"retained", "unknown", "future"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			f.reserve(t)
			advanceFixturePolicy(f.fixture)
			key := api.RequestKey{Method: f.scope.Request.Method, IdempotencyKey: f.scope.Request.IdempotencyKey, RequestSHA256: f.scope.Request.RequestSHA256}
			receipt := f.store.receipts[fixtureReceiptKey(f.scope, key)]
			retainedError := problem(api.CodeUnavailable, "retained launch failed", "Reconcile the original operation.")
			receipt.Reply = &api.RPCReply{Error: retainedError}
			if mode == "unknown" {
				delete(f.store.policyHistory, receipt.PolicyGeneration)
			} else if mode == "future" {
				receipt.PolicyGeneration = f.store.policy.Generation + 1
			}
			f.store.receipts[fixtureReceiptKey(f.scope, key)] = receipt
			scope := f.scope
			scope.PolicyGeneration = f.store.policy.Generation
			// Keep error receipts covered at the same launchReplay boundary;
			// the public authorization check must not mask a missing local gate.
			_, found, directErr := f.service.launchReplay(context.Background(), scope)
			if mode == "retained" {
				if directErr != retainedError || !found || f.store.reservationCalls != 1 || f.store.policyRefreshes != 0 {
					t.Fatalf("retained error replay changed its original decision: direct: %v", directErr)
				}
			} else {
				want := api.CodeInvalid
				if mode == "unknown" {
					want = api.CodeNotFound
				}
				if typed, ok := directErr.(*api.Error); !ok || typed.Code != want || !found || directErr == retainedError {
					t.Fatalf("error receipt bypassed retained policy validation: direct: %v", directErr)
				}
			}
			_, err := f.service.LaneStart(context.Background(), scope, f.request)
			if mode == "retained" {
				if err != retainedError || f.store.reservationCalls != 1 || f.store.policyRefreshes != 0 {
					t.Fatalf("retained error replay changed its original decision: %v", err)
				}
			} else if err == nil || err == retainedError {
				t.Fatal("error receipt bypassed retained policy validation")
			}
		})
	}
}

func TestPolicyContinueTurn(t *testing.T) {
	for _, mode := range []string{"retained", "future"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			previous, lane := f.endedPlan(t)
			advanceFixturePolicy(f.fixture)
			scope := api.Scope{Config: "example", Actor: api.Actor{Kind: "watchdog", ID: "watchdog"}, Source: "watchdog", PolicyGeneration: f.store.policy.Generation}
			lane, err := f.service.refreshLaunchPolicy(context.Background(), scope, lane)
			if err != nil {
				t.Fatal(err)
			}
			scope, request, _ := f.continuation(t, lane)
			if mode == "future" {
				turn := f.store.turns[lane.LogicalTurnID]
				turn.PolicyGeneration = f.store.policy.Generation + 1
				f.store.turns[lane.LogicalTurnID] = turn
			}
			operation, err := f.service.Continue(context.Background(), scope, request)
			if err != nil {
				t.Fatal(err)
			}
			var record api.LaunchPlanRecord
			for _, candidate := range f.store.plans {
				if candidate.Reservation.OperationID == operation.ID {
					record = candidate
				}
			}
			internal, planRequest := f.claim(t, record)
			plan, err := f.service.PlanLaunch(context.Background(), internal, planRequest)
			if mode == "future" {
				if err == nil {
					t.Fatal("future turn policy authorized retained selection")
				}
				return
			}
			if err != nil || plan.Runner.Prompt != previous.Runner.Prompt || plan.Reservation.PolicyGeneration != f.store.policy.Generation || f.ports.calls["guidance"] != 1 {
				t.Fatalf("current continuation lost its retained turn selection: %v", err)
			}
		})
	}
}

func TestPolicySealedAndOpened(t *testing.T) {
	for _, opened := range []bool{false, true} {
		name := "sealed"
		if opened {
			name = "opened"
		}
		t.Run(name, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			plan, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err != nil {
				t.Fatal(err)
			}
			if opened {
				f.bindPrepared(t, scope, request, plan)
				current := f.store.plans[record.Reservation.ID]
				current.Phase = "opened"
				current.Generation++
				f.store.plans[record.Reservation.ID] = current
			}
			before := launchClone(t, f.ports.calls)
			advanceFixturePolicy(f.fixture)
			currentScope := scope
			currentScope.PolicyGeneration = f.store.policy.Generation
			replayed, err := f.service.PlanLaunch(context.Background(), currentScope, request)
			if opened {
				if err != nil || !reflect.DeepEqual(replayed, plan) || f.ports.calls["allocate"] != before["allocate"] || f.ports.calls["acquire"] != before["acquire"] || f.ports.calls["grants"] != before["grants"] {
					t.Fatalf("opened recovery did not retain its historical binding: %v", err)
				}
			} else if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict || f.ports.calls["grants"] != before["grants"] || f.store.plans[record.Reservation.ID].Plan.Reservation.PolicyGeneration != plan.Reservation.PolicyGeneration {
				t.Fatalf("old sealed plan crossed its current policy fence: %v", err)
			}
		})
	}
}
