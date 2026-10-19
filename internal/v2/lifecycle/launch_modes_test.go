package lifecycle

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestLaunchAdopt(t *testing.T) {
	f := newLaunchFixture(t)
	legacy := api.AdoptionManifest{Schema: "laneboss.adoption.v2", SourceVersion: "fixture-legacy-1",
		Workspace: api.Workspace{ID: "legacy-workspace", ProjectID: f.request.ProjectID, LogicalCWD: "/work/main"},
		Session: api.Session{ID: "legacy-session", Driver: f.request.Driver, VendorID: "legacy-vendor-session",
			VendorVersion: "vendor-pin-2", HomeID: "legacy-home", HistoryID: "legacy-history", LogicalCWD: "/work/main"},
		PrivateHistory: f.fixture.blob(launchIDForTest(), "artifact", []byte("legacy private history bytes\n")),
		Quiescence:     f.fixture.blob(launchIDForTest(), "artifact", []byte("fixture legacy quiescence receipt\n"))}
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	manifest := f.fixture.blob(launchIDForTest(), "manifest", encoded)
	request := api.AdoptRequest{Lane: f.request.Lane, Level: f.request.Level, Role: f.request.Role,
		Task: f.request.Task, ProfileGrantID: f.request.ProfileGrantID, Driver: f.request.Driver,
		Model: f.request.Model, Effort: f.request.Effort, Budget: f.request.Budget, Grants: f.request.Grants,
		ExpectedPolicyGeneration: f.request.ExpectedPolicyGeneration, ImportManifest: manifest}
	scope := f.fixture.scope("lane.adopt", request, f.parent)
	operation, err := f.service.LaneAdopt(context.Background(), scope, request)
	if err != nil || operation.Status != "pending" || operation.Run != 1 {
		t.Fatalf("adoption did not reserve a new private life: %v", err)
	}
	var record api.LaunchPlanRecord
	for _, candidate := range f.store.plans {
		if candidate.Reservation.OperationID == operation.ID {
			record = candidate
		}
	}
	internal, planRequest := f.claim(t, record)
	plan, err := f.service.PlanLaunch(context.Background(), internal, planRequest)
	if err != nil || plan.Reservation.Mode != "adopt" || plan.Runner.Session.VendorID != legacy.Session.VendorID ||
		plan.Runner.Home.ID == legacy.Session.HomeID || plan.Runner.Session.HomeID != plan.Data.Home.Home.ID ||
		plan.Runner.Session.HistoryID != plan.Data.Home.Home.HistoryID || f.ports.calls["runner-resume"] != 1 {
		t.Fatalf("adoption replaced vendor identity or trusted legacy storage IDs: %v", err)
	}
}

type launchContinuationBroker struct {
	*launchFixturePorts
	eligibility api.ProfileEligibility
	room        api.Room
}

func (broker *launchContinuationBroker) Eligibility(_ context.Context, request api.ProfileEligibilityRequest) (api.ProfileEligibility, error) {
	if request != broker.eligibility.Request {
		return api.ProfileEligibility{}, launchConflict()
	}
	return broker.eligibility, nil
}

func (broker *launchContinuationBroker) Room(_ context.Context, grant api.ProfileGrant) (api.Room, error) {
	if grant.ProfileID != broker.room.ProfileID {
		return api.Room{}, launchConflict()
	}
	return broker.room, nil
}

func (f *launchFixture) continuation(t *testing.T, lane api.Lane) (api.Scope, api.ContinuationRequest, api.ProfileGrant) {
	t.Helper()
	grants := f.store.grants[lane.GrantSetID]
	from := grants.Profiles[0]
	if len(grants.Profiles) != 2 {
		t.Fatal("fixture continuation has no original delegated replacement")
	}
	to := grants.Profiles[1]
	eligibility := api.ProfileEligibility{ID: launchIDForTest(), Compatible: true,
		Request: api.ProfileEligibilityRequest{Target: api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}, GrantSetID: lane.GrantSetID,
			FromGrantID: from.ID, ToGrantID: to.ID, Driver: lane.Session.Driver, Model: lane.Model, Session: lane.Session, HistoryID: lane.Session.HistoryID},
		Evidence:  f.fixture.blob(launchIDForTest(), "artifact", []byte(string(from.ProfileID)+" to "+string(to.ProfileID))),
		CheckedAt: "2030-01-02T03:04:05Z", ExpiresAt: "2031-01-01T00:00:00Z"}
	room := api.Room{ProfileID: to.ProfileID, Available: true, CheckedAt: eligibility.CheckedAt, ExpiresAt: eligibility.ExpiresAt,
		Evidence: f.fixture.blob(launchIDForTest(), "artifact", []byte("fixture room for "+string(to.ProfileID)))}
	f.service.deps.Credentials = &launchContinuationBroker{launchFixturePorts: f.ports, eligibility: eligibility, room: room}
	swap := api.ProfileSwap{OperationID: launchIDForTest(), EligibilityID: eligibility.ID, ExpectedGeneration: lane.Generation,
		CancellationEpoch: lane.CancellationEpoch, ProfileGrantID: to.ID, FromProfileID: from.ProfileID, ToProfileID: to.ProfileID,
		CausingRun: lane.Run, ContinuationRun: lane.Run + 1, LogicalTurnID: lane.LogicalTurnID,
		Limit: api.LimitSignal{Target: eligibility.Request.Target, ProfileID: from.ProfileID, Provider: from.Provider}, Room: room}
	request := api.ContinuationRequest{IntentID: launchIDForTest(), Swap: swap}
	f.store.continuations[request.IntentID] = api.ContinuationIntent{ID: request.IntentID, Target: swap.Limit.Target,
		OperationID: swap.OperationID, LogicalTurnID: lane.LogicalTurnID, ExpectedGeneration: lane.Generation, CancellationEpoch: lane.CancellationEpoch,
		Generation: 1, Status: "pending", Eligibility: eligibility, Swap: swap}
	f.store.operations[swap.OperationID] = api.Operation{ID: swap.OperationID, Status: "pending", LifeID: lane.LifeID, Run: lane.Run}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	f.store.continuationFrames = map[api.ID][]byte{request.IntentID: encoded}
	f.store.continuationRequestIDs = map[api.ID]api.ID{request.IntentID: launchIDForTest()}
	return api.Scope{Config: "example", Actor: api.Actor{Kind: "watchdog", ID: "watchdog"}, Source: "watchdog",
		PolicyGeneration: f.store.policy.Generation}, request, to
}

func TestPlanContinuation(t *testing.T) {
	for _, retainedSlot := range []bool{false, true} {
		name := "new-slot"
		if retainedSlot {
			name = "retained-slot"
		}
		t.Run(name, func(t *testing.T) {
			f := newLaunchFixture(t)
			previous, lane := f.endedPlan(t)
			lane.Counters = api.TaskCounters{Failures: 2, Retries: 3}
			f.store.lanes[lane.LifeID] = lane
			scope, request, profile := f.continuation(t, lane)
			operation, err := f.service.Continue(context.Background(), scope, request)
			if err != nil || operation.Status != "pending" || operation.LifeID != lane.LifeID || operation.Run != lane.Run+1 {
				t.Fatalf("continuation did not retain the next pending operation: %v", err)
			}
			replay, err := f.service.Continue(context.Background(), scope, request)
			if err != nil || !reflect.DeepEqual(replay, operation) {
				t.Fatalf("continuation retry issued a replacement operation: %v", err)
			}
			var record api.LaunchPlanRecord
			for _, candidate := range f.store.plans {
				if candidate.Reservation.OperationID == operation.ID {
					record = candidate
				}
			}
			internal, planRequest := f.claim(t, record)
			if retainedSlot {
				if _, issued := f.store.grants[record.Reservation.GrantSetID]; issued {
					t.Fatal("retained slot fixture issued fresh grants before planning")
				}
				slot, err := f.ports.Acquire(context.Background(), record.Reservation.Target, profile)
				if err != nil {
					t.Fatal(err)
				}
				intent := f.store.continuations[request.IntentID]
				intent.Slot = &slot
				f.store.continuations[request.IntentID] = intent
			}
			plan, err := f.service.PlanLaunch(context.Background(), internal, planRequest)
			if err != nil || plan.Reservation.Mode != "continue" || plan.Runner.Prompt != previous.Runner.Prompt ||
				plan.Runner.Session != lane.Session || plan.Budget != lane.BudgetRemaining || plan.Data.Home != previous.Data.Home ||
				plan.Runner.Slot.ProfileGrantID != profile.ID || f.ports.calls["guidance"] != 1 || f.ports.calls["briefing"] != 1 ||
				f.ports.calls["acquire"] != 2 || f.store.lanes[lane.LifeID].Counters != lane.Counters {
				t.Fatalf("continuation reset the turn, prompt, history, slot or budget: %v", err)
			}
			kept := f.store.continuations[request.IntentID]
			if kept.Slot == nil || *kept.Slot != plan.Runner.Slot {
				t.Fatal("planner lost the acquired slot before injection")
			}
			if _, err := f.service.PlanLaunch(context.Background(), internal, planRequest); err != nil || f.ports.calls["acquire"] != 2 {
				t.Fatalf("continuation restart acquired a replacement slot: %v", err)
			}
		})
	}
}

func TestSlotGrantFence(t *testing.T) {
	for _, mode := range []string{"valid", "absent", "epoch", "intent", "binding", "grant"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, lane := f.endedPlan(t)
			scope, request, profile := f.continuation(t, lane)
			operation, err := f.service.Continue(context.Background(), scope, request)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "absent" {
				delete(f.store.fences, lane.LifeID)
			} else if mode == "epoch" {
				f.store.fences[lane.LifeID]++
			} else if mode == "intent" {
				intent := f.store.continuations[request.IntentID]
				intent.Status = "cancelled"
				f.store.continuations[intent.ID] = intent
			} else if mode == "binding" {
				changed := lane
				changed.LaunchID = "foreign-launch"
				f.store.lanes[lane.LifeID] = changed
			} else if mode == "grant" {
				grants := f.store.grants[lane.GrantSetID]
				grants.Revoked = true
				f.store.grants[grants.ID] = grants
			}
			target := api.LifeRef{LifeID: operation.LifeID, Run: operation.Run}
			slot, err := f.ports.Acquire(context.Background(), target, profile)
			if mode == "valid" {
				if err != nil || slot.ProfileGrantID != profile.ID || slot.ProfileID != profile.ProfileID || f.ports.slots[target] != slot {
					t.Fatalf("retained slot lost its actual continuation authority: %v", err)
				}
			} else if typed, ok := err.(*api.Error); !ok || typed.Code != api.CodeConflict || f.ports.slots[target].ID != "" {
				t.Fatalf("retained slot bypassed its original fence: %s: %v", mode, err)
			}
		})
	}
}

func TestPlanRetainedPins(t *testing.T) {
	for _, fault := range []string{"binding", "runtime", "home", "capture"} {
		t.Run(fault, func(t *testing.T) {
			f := newLaunchFixture(t)
			previous, lane := f.endedPlan(t)
			message := f.fixture.blob(launchIDForTest(), "task", []byte("retained input\n"))
			request := api.ResumeRequest{Target: previous.Reservation.Target, ExpectedGeneration: lane.Generation, Message: message, Budget: lane.BudgetRemaining}
			scope := f.fixture.scope("lane.resume", request, f.parent)
			operation, err := f.service.LaneResume(context.Background(), scope, request)
			if err != nil {
				t.Fatal(err)
			}
			var record api.LaunchPlanRecord
			for _, candidate := range f.store.plans {
				if candidate.Reservation.OperationID == operation.ID {
					record = candidate
				}
			}
			if fault == "binding" {
				delete(f.store.bindings, lane.LaunchID)
			}
			if fault == "runtime" {
				f.ports.sourceHook = func(sources *api.LaunchSources) {
					sources.Runtime.Executable.SHA256 = digestOf([]byte("unsupported upgrade"))
				}
			}
			if fault == "home" {
				f.ports.dataHook = func(data *api.LaunchData) { data.Home.RootID = "replacement-home" }
			}
			if fault == "capture" {
				f.ports.failStage, f.ports.failure = "reconcile-capture", api.NotImplemented("capture-owner", "actual original capture reconciliation")
			}
			internal, planRequest := f.claim(t, record)
			_, err = f.service.PlanLaunch(context.Background(), internal, planRequest)
			if fault == "runtime" && f.ports.calls["acquire"] != 1 {
				t.Fatal("retained launch accepted changed private recovery pins before credential access")
			}
			if fault == "home" && f.ports.calls["acquire"] != 1 {
				t.Fatal("invalid retained pins acquired another credential")
			}
			if err == nil {
				t.Fatal("retained launch accepted changed private recovery pins")
			}
			if fault != "capture" && f.ports.calls["acquire"] != 1 {
				t.Fatal("invalid retained pins acquired another credential")
			}
		})
	}
}
