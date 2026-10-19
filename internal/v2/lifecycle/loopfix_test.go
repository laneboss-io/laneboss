package lifecycle

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func readyLoop(t *testing.T) (*launchFixture, *loopStore, api.Scope, api.LifeRef) {
	t.Helper()
	f := newLaunchFixture(t)
	_, lane := f.endedPlan(t)
	target := api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}
	idle := f.blob(launchIDForTest(), "task", []byte("execute this retained loop input\n"))
	setting := api.LoopRequest{Target: target, ExpectedGeneration: lane.Generation, Enabled: true, IdleMessage: &idle, BackoffMS: 100}
	if _, err := f.service.LaneLoop(context.Background(), f.fixture.scope("lane.loop", setting, f.parent), setting); err != nil {
		t.Fatal(err)
	}
	clock := &movingClock{now: fixtureClock{}.Now().Add(time.Second)}
	f.service.deps.Clock = clock
	source := &loopSource{identity: api.InstalledScheduler{Config: "example", Actor: api.Actor{Kind: "scheduler", ID: "installed-loop"},
		CapabilityID: launchIDForTest(), CapabilityGeneration: 1, InstallationGeneration: 1, BootID: "fixture-boot",
		PolicyGeneration: f.store.policy.Generation, ExpiresAt: api.Timestamp(clock.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))}}
	scope, err := api.BindSchedulerScope(context.Background(), source, clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	store := &loopStore{launchFixtureStore: f.store, source: source, clock: clock, ends: map[api.ID]api.ID{}, checkScope: true}
	f.service.deps.Store = store
	return f, store, scope, target
}

func TestLoopReserve(t *testing.T) {
	for _, mode := range []string{"valid", "forged", "revoked", "early", "disabled", "policy"} {
		t.Run(mode, func(t *testing.T) {
			f, store, scope, target := readyLoop(t)
			switch mode {
			case "forged":
				store.checkScope = false
				store.source.identity.CapabilityID = "stale-capability"
			case "revoked":
				store.source.err = api.NotImplemented("lb-v2-identity", "revoked fixture scheduler")
			case "early":
				f.service.deps.Clock.(*movingClock).now = fixtureClock{}.Now()
			case "disabled":
				lane := f.store.lanes[target.LifeID]
				setting := api.LoopRequest{Target: target, ExpectedGeneration: lane.Generation, BackoffMS: 100}
				if _, err := f.service.LaneLoop(context.Background(), f.fixture.scope("lane.loop", setting, f.parent), setting); err != nil {
					t.Fatal(err)
				}
			case "policy":
				f.store.policy.Generation++
			}
			reads := store.source.reads
			before, effects := len(f.store.plans), len(f.store.effects)
			r, err := f.service.ReserveLoop(context.Background(), scope, target)
			if mode != "valid" {
				if err == nil || len(f.store.plans) != before || len(f.store.effects) != effects || len(store.ends) != 0 || mode != "policy" && store.calls != 0 ||
					mode == "forged" && store.source.reads == reads {
					t.Fatalf("loop reservation crossed its private current fence: %s: %v", mode, err)
				}
				return
			}
			if err != nil || r.Loop == nil || r.RequestedBy != scope.Actor || r.OriginalRequest.Class != "manifest" ||
				len(f.store.plans) != before+1 || len(f.store.effects) != effects+1 || r.Loop.LogicalTurnID == r.Loop.PreviousLogicalTurnID {
				t.Fatalf("loop did not reserve its real causal outbox: %v", err)
			}
			got, err := f.service.ReserveLoop(context.Background(), scope, target)
			if err != nil || !reflect.DeepEqual(got, r) || len(f.store.plans) != before+1 || len(store.ends) != 1 {
				t.Fatalf("loop retry replaced its original reservation: %v", err)
			}
			lane := f.store.lanes[target.LifeID]
			lane.CancellationEpoch++
			f.store.lanes[lane.LifeID] = lane
			if _, err := store.ReserveLaunch(context.Background(), scope, api.LaunchReservationRequest{Loop: &r.Loop.Selector}); err == nil || len(f.store.plans) != before+1 {
				t.Fatal("loop writer replay ignored its current epoch")
			}
		})
	}
}

func TestLoopEndPins(t *testing.T) {
	for _, mode := range []string{"continuation", "launch", "budget"} {
		t.Run(mode, func(t *testing.T) {
			f, _, _, target := readyLoop(t)
			lane := f.store.lanes[target.LifeID]
			end := api.RunEndEvent{LaunchID: lane.LaunchID, Reason: "exit", BudgetRemaining: lane.BudgetRemaining,
				Observation: f.launcher.observation}
			switch mode {
			case "continuation":
				end.ProfileContinuation = true
			case "launch":
				end.LaunchID = "foreign-launch"
			case "budget":
				end.BudgetRemaining.WallMS++
			}
			if loopEndMatches(&end, lane) {
				t.Fatalf("loop end accepted a changed %s pin", mode)
			}
		})
	}
}

func TestLoopOpenedGenerationAdvance(t *testing.T) {
	f, _, scheduler, target := readyLoop(t)
	r, err := f.service.ReserveLoop(context.Background(), scheduler, target)
	if err != nil {
		t.Fatal(err)
	}
	scope, request := f.claim(t, f.store.plans[r.ID])
	plan, err := f.service.PlanLaunch(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	f.bindPrepared(t, scope, request, plan)
	if _, err := f.store.Transact(context.Background(), openFixtureTransaction(t, f)); err != nil {
		t.Fatal(err)
	}
	lane := f.store.lanes[target.LifeID]
	lane.Generation++
	f.store.lanes[target.LifeID] = lane
	if _, err := f.service.PlanLaunch(context.Background(), scope, request); err != nil {
		t.Fatalf("opened replay rejected an in-place generation advance: %v", err)
	}
}

func TestLoopPlan(t *testing.T) {
	f, _, scheduler, target := readyLoop(t)
	r, err := f.service.ReserveLoop(context.Background(), scheduler, target)
	if err != nil {
		t.Fatal(err)
	}
	scope, request := f.claim(t, f.store.plans[r.ID])
	plan, err := f.service.PlanLaunch(context.Background(), scope, request)
	if err != nil || api.ValidateLaunchPlan(plan) != nil || plan.Budget != r.Loop.BudgetRemaining ||
		plan.Runner.Session != r.Loop.PreviousSession || plan.Data.Home.Home != r.Loop.PreviousHome.Home ||
		plan.Inputs.Grants.Generation != r.Loop.GrantGeneration {
		t.Fatalf("loop planner lost its retained causal pins: %v", err)
	}
	var prompt launchPrompt
	if err := api.DecodeObject(f.store.blobs[plan.Runner.Prompt.ID], &prompt); err != nil || prompt.Task != string(f.store.blobs[r.Loop.Setting.IdleMessage.ID]) || prompt.Message != "" || len(prompt.Mail) != 0 {
		t.Fatalf("loop planner did not render its exact idle task: %v", err)
	}
	f.bindPrepared(t, scope, request, plan)
	if _, err := f.store.Transact(context.Background(), openFixtureTransaction(t, f)); err != nil {
		t.Fatal(err)
	}
	got, err := f.service.PlanLaunch(context.Background(), scope, request)
	if err != nil || !reflect.DeepEqual(got, plan) || f.ports.calls["runner-turn"] != 1 || f.ports.calls["acquire"] != 2 {
		t.Fatalf("loop replay replaced its original resources: %v", err)
	}
	found := false
	for _, event := range f.store.events {
		if event.Kind == "lane.turn" && event.OperationID == r.OperationID {
			found = true
			if err := api.ValidateLoopTurnEvent(event, r); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !found {
		t.Fatal("loop open lost its scheduler turn audit")
	}
}

func TestLoopManifest(t *testing.T) {
	for _, mode := range []string{"turn", "effect", "bytes"} {
		t.Run(mode, func(t *testing.T) {
			f, _, scheduler, target := readyLoop(t)
			r, err := f.service.ReserveLoop(context.Background(), scheduler, target)
			if err != nil {
				t.Fatal(err)
			}
			scope, request := f.claim(t, f.store.plans[r.ID])
			execution := &planExecution{service: f.service, scope: scope, lease: request.Lease, record: f.store.plans[r.ID], input: launchInput{turn: r.Loop.LogicalTurnID}}
			raw := append([]byte{}, f.store.blobs[r.OriginalRequest.ID]...)
			switch mode {
			case "turn":
				execution.input.turn = "foreign-turn"
			case "effect":
				execution.lease.Record.Effect.ID = "foreign-effect"
			case "bytes":
				var value map[string]any
				if err := json.Unmarshal(raw, &value); err != nil {
					t.Fatal(err)
				}
				value["logical_turn_id"] = "foreign-turn"
				raw, err = json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := execution.loopInput(raw); err == nil {
				t.Fatal("loop planner accepted a replaced manifest claim")
			}
		})
	}
}

func TestLoopReplayPins(t *testing.T) {
	for _, mutation := range []string{"manifest", "session", "budget", "task", "turn"} {
		t.Run(mutation, func(t *testing.T) {
			f, _, scheduler, target := readyLoop(t)
			r, err := f.service.ReserveLoop(context.Background(), scheduler, target)
			if err != nil {
				t.Fatal(err)
			}
			scope, request := f.claim(t, f.store.plans[r.ID])
			plan, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err != nil {
				t.Fatal(err)
			}
			f.bindPrepared(t, scope, request, plan)
			if _, err := f.store.Transact(context.Background(), openFixtureTransaction(t, f)); err != nil {
				t.Fatal(err)
			}
			lane := f.store.lanes[target.LifeID]
			foreign := f.blob(launchIDForTest(), "task", []byte("foreign loop task"))
			switch mutation {
			case "manifest":
				raw := append([]byte{}, f.store.blobs[r.OriginalRequest.ID]...)
				raw[0] ^= 1
				f.store.blobs[r.OriginalRequest.ID] = raw
			case "session":
				lane.Session.ID = "foreign-session"
			case "budget":
				lane.BudgetRemaining.WallMS++
			case "task":
				lane.Task = foreign
			case "turn":
				turn := f.store.turns[r.Loop.LogicalTurnID]
				turn.Task = foreign
				f.store.turns[r.Loop.LogicalTurnID] = turn
			}
			f.store.lanes[target.LifeID] = lane
			_, err = f.service.PlanLaunch(context.Background(), scope, request)
			if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeIntegrity {
				t.Fatalf("opened replay accepted a changed %s pin: %v", mutation, err)
			}
		})
	}
}

func TestLoopBudgetFence(t *testing.T) {
	f, store, scope, target := readyLoop(t)
	lane := f.store.lanes[target.LifeID]
	lane.BudgetRemaining = api.Budget{}
	f.store.lanes[target.LifeID] = lane
	_, err := f.service.ReserveLoop(context.Background(), scope, target)
	if err == nil || store.calls != 0 {
		t.Fatalf("loop accepted an invalid remaining budget: %v", err)
	}
}

func TestLoopFence(t *testing.T) {
	f, store, scope, target := readyLoop(t)
	r, err := f.service.ReserveLoop(context.Background(), scope, target)
	if err != nil {
		t.Fatal(err)
	}
	before, effects := len(f.store.plans), len(f.store.effects)
	f.store.fences[target.LifeID]++
	if _, err := store.ReserveLaunch(context.Background(), scope, api.LaunchReservationRequest{Loop: &r.Loop.Selector}); err == nil || len(f.store.plans) != before || len(f.store.effects) != effects {
		t.Fatal("loop replay lost its protected cancellation fence")
	}
}
