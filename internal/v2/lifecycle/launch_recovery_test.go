package lifecycle

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// Model the owning service's post-plan commit from a nonexecuting helper
// receipt. The planner never receives a caller-supplied pre-resolved binding.
func (f *launchFixture) bindPrepared(t *testing.T, scope api.Scope, request api.LaunchPlanRequest, plan api.LaunchPlan) api.Lane {
	t.Helper()
	record := f.store.plans[plan.Reservation.ID]
	if record.Handoff == nil {
		t.Fatal("fixture cannot prepare before the retained spec")
	}
	cause := *request.Lease.Record.Effect.Context
	cause.Kind, cause.ID, cause.EffectID = api.InternalHelperPrepare, launchIDForTest(), launchIDForTest()
	prepare := api.HelperLaunchRequest{Cause: cause, LeaseID: plan.Lease.ID, PreparedSpecID: record.Handoff.Spec.ID, SpecSHA256: record.Handoff.SpecSHA256}
	f.store.effects[cause.EffectID] = api.EffectRecord{Effect: api.Effect{ID: cause.EffectID, OperationID: cause.CauseOperationID,
		Context: &cause, HelperPrepare: &prepare}, Generation: 1, State: api.EffectPending}
	prepareClaim, err := f.store.ClaimEffect(context.Background(), scope, api.EffectClaimRequest{EffectID: cause.EffectID,
		ExpectedGeneration: 1, ClaimantID: scope.Actor.ID, Deadline: request.Lease.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.service.deps.Sources.(api.Helper).Prepare(context.Background(), prepare)
	if err != nil {
		t.Fatal(err)
	}
	var recovery api.LaunchRecovery
	if err := api.DecodeObject(f.store.blobs[launchObjectID(plan.Reservation.ID, "recovery")], &recovery); err != nil {
		t.Fatal(err)
	}
	r := plan.Reservation
	input, err := f.ports.original(r)
	if err != nil {
		t.Fatal(err)
	}
	lane := api.Lane{Task: input.Task, LifeID: r.Target.LifeID, Name: input.Lane, Run: r.Target.Run, Generation: r.Generation,
		LaunchID: r.LaunchID, ParentLifeID: r.ParentLifeID, RootLifeID: r.RootLifeID, StarterChain: r.StarterChain,
		StarterEventSeq: r.StarterEventSeq, CancellationEpoch: r.CancellationEpoch, BudgetRemaining: plan.Budget,
		Level: r.Level, Role: r.Role, Model: input.Model, Effort: input.Effort, ProfileGrantID: input.ProfileGrantID,
		GrantSetID: r.GrantSetID, PolicyGeneration: r.PolicyGeneration, LogicalTurnID: cause.LogicalTurnID,
		State: "preparing", Workspace: plan.Data.Workspace, Session: plan.Runner.Session}
	binding := api.LaunchBindingRequest{Record: api.LaunchRecord{Kind: "agent", ID: r.LaunchID, Config: r.Config, Target: r.Target,
		ParentLifeID: r.ParentLifeID, RootLifeID: r.RootLifeID, StarterChain: r.StarterChain, StarterEventSeq: r.StarterEventSeq,
		Actor:      api.Actor{Kind: "lane", ID: launchIDForTest(), LifeID: r.Target.LifeID, Level: r.Level, Role: r.Role},
		UIDLeaseID: plan.Lease.ID, HostUID: plan.Lease.UID, ContainmentID: plan.Lease.ContainmentID,
		ProcessGeneration: prepared.ProcessGeneration, GrantSetID: r.GrantSetID, GrantsSHA256: plan.Inputs.Grants.SHA256,
		PolicyGeneration: r.PolicyGeneration, EndpointGeneration: plan.Lease.EndpointGeneration}, Prepared: prepared, Recovery: &recovery}
	execution := &planExecution{service: f.service, scope: scope, lease: request.Lease, record: record,
		input: launchInput{turn: cause.LogicalTurnID}}
	identity, err := execution.event("identity.bound", binding.Record)
	if err != nil {
		t.Fatal(err)
	}
	events := []api.Event{identity}
	if r.Target.Run == 1 {
		kind := api.EventKind("lane.created")
		if r.Mode == "adopt" {
			kind = "lane.adopted"
		}
		payload := fixtureLaunchEvent(lane, r.LaunchID)
		payload.GrantsSHA256 = plan.Inputs.Grants.SHA256
		payload.Prompt, payload.BoundaryBackend, payload.EndpointGeneration = plan.Runner.Prompt, plan.Inputs.Sources.Runtime.Backend, plan.Lease.EndpointGeneration
		created, err := execution.event(kind, payload)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, created)
	}
	record.Phase, record.Generation = "bound", record.Generation+1
	turn := api.TurnSnapshot{Target: r.Target, LogicalTurnID: cause.LogicalTurnID, Task: input.Task,
		Prompt: &plan.Runner.Prompt, Generation: 1, PolicyGeneration: r.PolicyGeneration, Status: "prepared", MailIDs: []api.ID{}}
	_, err = f.store.Transact(context.Background(), api.Transaction{Scope: scope, Internal: &cause,
		Writes: api.StateWrites{LaunchPlans: []api.LaunchPlanRecord{record}, Lanes: []api.Lane{lane}, Turns: []api.TurnSnapshot{turn},
			IdentityBindings: []api.LaunchBindingRequest{binding}}, Events: events,
		Compare: []api.Compare{{Kind: api.CompareLaunchPlan, ID: r.ID, Generation: record.Generation - 1},
			{Kind: api.CompareLane, ID: r.Target.LifeID, Generation: r.BaseGeneration}},
		Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}})
	if err != nil {
		t.Fatal(err)
	}
	retained := f.store.bindings[r.LaunchID]
	if err := api.ValidateLaunchBindingPlan(retained, plan); err != nil {
		t.Fatal(err)
	}
	f.retainProjection(t, plan, retained, prepareClaim)
	return lane
}

func (f *launchFixture) endedPlan(t *testing.T) (api.LaunchPlan, api.Lane) {
	t.Helper()
	_, record := f.reserve(t)
	scope, request := f.claim(t, record)
	plan, err := f.service.PlanLaunch(context.Background(), scope, request)
	if err != nil {
		t.Fatal(err)
	}
	lane := f.bindPrepared(t, scope, request, plan)
	// An observed vendor mapping is run output. It does not rewrite the
	// pre-execution spec or invent another private history.
	sessionBytes, err := json.Marshal(struct{ SessionID api.ID }{SessionID: launchIDForTest()})
	if err != nil {
		t.Fatal(err)
	}
	sessionCapture := f.fixture.blob(launchIDForTest(), "capture", sessionBytes)
	lane.Session.VendorID = string(sessionCapture.SHA256)
	lane.State = "verifying"
	f.store.lanes[lane.LifeID] = lane
	zero, exit := uint64(0), 0
	observation := api.ProcessObservation{Handle: api.ProcessHandle{ID: launchIDForTest(), Target: plan.Reservation.Target,
		ContainmentID: plan.Lease.ContainmentID, Generation: f.store.bindings[plan.Reservation.LaunchID].Prepared.ProcessGeneration},
		State: "exited", Survivors: &zero, ExitCode: &exit, PromptStatus: "completed", ObservedAt: "2030-01-02T03:04:05Z"}
	f.launcher.observation = observation
	f.fixture.addTo(lane, "lane.ended", api.RunEndEvent{LaunchID: lane.LaunchID, Reason: "exit", Observation: observation,
		BudgetRemaining: lane.BudgetRemaining}, "service", f.parent)
	return plan, lane
}

func TestPlanLaunchRecovery(t *testing.T) {
	for _, fault := range []string{"valid", "missing", "request", "home", "capture", "spec", "uncommitted", "prepared", "kind", "level", "role"} {
		t.Run(fault, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			plan, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err != nil {
				t.Fatal(err)
			}
			f.bindPrepared(t, scope, request, plan)
			binding := launchClone(t, f.store.bindings[plan.Reservation.LaunchID])
			switch fault {
			case "missing":
				delete(f.store.bindings, plan.Reservation.LaunchID)
			case "request":
				binding.Recovery.OriginalRequest.ID = "foreign-request"
			case "home":
				binding.Recovery.Home.RootID = "foreign-home"
			case "capture":
				binding.Recovery.Capture.ID = "foreign-capture"
			case "spec":
				binding.Recovery.Handoff.SpecSHA256 = digestOf([]byte("foreign-spec"))
			case "uncommitted":
				binding.Identity.CommittedSeq = 0
			case "prepared":
				binding.Prepared.ProcessGeneration = "foreign-process"
			case "kind":
				binding.Record.Kind = ""
			case "level":
				binding.Record.Actor.Level++
			case "role":
				binding.Record.Actor.Role = "reviewer"
			}
			if fault == "kind" || fault == "level" || fault == "role" {
				// Isolate the reserved pin from the independent record digest gate.
				encoded, err := json.Marshal(binding.Record)
				if err != nil {
					t.Fatal(err)
				}
				canonical, err := api.CanonicalJSON(encoded)
				if err != nil {
					t.Fatal(err)
				}
				binding.Identity.RecordSHA256 = digestOf(canonical)
			}
			if fault != "missing" {
				f.store.bindings[plan.Reservation.LaunchID] = binding
			}
			before := launchClone(t, f.ports.calls)
			second, err := f.service.PlanLaunch(context.Background(), scope, request)
			if fault == "valid" {
				if err != nil || !reflect.DeepEqual(second, plan) {
					t.Fatalf("restart did not validate the actual retained binding: %v", err)
				}
			} else if err == nil {
				t.Fatal("restart accepted a missing or mismatched retained launch binding")
			}
			for _, stage := range []string{"allocate", "materialize", "acquire", "runner-start", "capture", "prepare"} {
				if f.ports.calls[stage] != before[stage] {
					t.Fatalf("binding recovery re-executed the %s stage", stage)
				}
			}
		})
	}
}

func TestPlanLaunchMissingStage(t *testing.T) {
	for _, fault := range []string{"allocation", "materialization", "prompt", "home", "spool"} {
		t.Run(fault, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			plan, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "allocation":
				delete(f.store.effects, launchObjectID(record.Reservation.ID, "allocate-effect"))
			case "materialization":
				stage := f.store.dataStages[record.Reservation.ID]
				delete(f.store.effects, stage.Worker.EffectID)
			case "prompt":
				delete(f.store.blobs, plan.Runner.Prompt.ID)
			case "home":
				delete(f.ports.storage, plan.Lease.ID)
			case "spool":
				delete(f.ports.captures, plan.Capture.ID)
			}
			_, err = f.service.PlanLaunch(context.Background(), scope, request)
			if err == nil || f.ports.calls["allocate"] != 1 || f.ports.calls["materialize"] != 1 ||
				f.ports.calls["acquire"] != 1 || f.ports.calls["capture"] != 1 {
				t.Fatalf("restart recreated missing measured launch resources: %v", err)
			}
		})
	}
}

func TestPlanChildErrors(t *testing.T) {
	for _, stage := range []string{"allocate", "materialize"} {
		t.Run(stage, func(t *testing.T) {
			f := newLaunchFixture(t)
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			primary := api.NotImplemented("actual-stage-owner", "actual "+stage)
			f.ports.failStage, f.ports.failure = stage, primary
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err != primary {
				t.Fatalf("child stage replaced its actual failure: %v", err)
			}
			_, err = f.service.PlanLaunch(context.Background(), scope, request)
			if err != primary || f.ports.calls[stage] != 1 {
				t.Fatalf("child stage replay repeated its retained failed effect: %v", err)
			}
		})
	}
}

func TestPlanLaunchLostOutcome(t *testing.T) {
	f := newLaunchFixture(t)
	_, record := f.reserve(t)
	scope, request := f.claim(t, record)
	f.store.completeErr = &api.Error{Code: api.CodeUnavailable, Message: "fixture lost allocation acknowledgement"}
	_, err := f.service.PlanLaunch(context.Background(), scope, request)
	if err != f.store.completeErr || len(f.ports.allocations) != 1 || f.ports.calls["materialize"] != 0 {
		t.Fatalf("lost allocation acknowledgement advanced the plan: %v", err)
	}
	original := f.ports.allocations[record.Reservation.ID]
	f.store.completeErr = nil
	plan, err := f.service.PlanLaunch(context.Background(), scope, request)
	if err != nil || plan.Lease != original || len(f.ports.allocations) != 1 || f.ports.calls["allocate"] != 2 {
		t.Fatalf("allocation recovery replaced its original journal identity: %v", err)
	}
}

func TestPlanRetainedRuns(t *testing.T) {
	for _, mode := range []string{"resume", "turn"} {
		t.Run(mode, func(t *testing.T) {
			f := newLaunchFixture(t)
			previous, lane := f.endedPlan(t)
			priorGrants := launchClone(t, f.store.grants[lane.GrantSetID])
			priorBinding := launchClone(t, f.store.bindings[lane.LaunchID])
			edited := append(append([]byte{}, f.ports.workspaceBytes[lane.Workspace.ID]...), []byte("private edits after first run\n")...)
			f.ports.workspaceBytes[lane.Workspace.ID] = edited
			message := f.fixture.blob(launchIDForTest(), "task", []byte("retained run input\n"))
			var operation api.Operation
			var err error
			if mode == "resume" {
				request := api.ResumeRequest{Target: previous.Reservation.Target, ExpectedGeneration: lane.Generation,
					Message: message, Budget: lane.BudgetRemaining}
				scope := f.fixture.scope("lane.resume", request, f.parent)
				operation, err = f.service.LaneResume(context.Background(), scope, request)
			} else {
				request := api.TurnRequest{Target: previous.Reservation.Target, ExpectedGeneration: lane.Generation,
					MailIDs: []api.ID{}, IdleMessage: &message, Budget: lane.BudgetRemaining}
				scope := f.fixture.scope("lane.turn", request, f.parent)
				operation, err = f.service.LaneTurn(context.Background(), scope, request)
			}
			if err != nil || operation.Status != "pending" || operation.LifeID != lane.LifeID || operation.Run != lane.Run+1 {
				t.Fatalf("retained public launch did not reserve the next run: %v", err)
			}
			var reserved api.LaunchPlanRecord
			for _, record := range f.store.plans {
				if record.Reservation.OperationID == operation.ID {
					reserved = record
				}
			}
			scope, request := f.claim(t, reserved)
			plan, err := f.service.PlanLaunch(context.Background(), scope, request)
			if err != nil || plan.Reservation.PreviousLaunchID != previous.Reservation.LaunchID ||
				plan.Data.Home != previous.Data.Home || plan.Data.Workspace.ID != previous.Data.Workspace.ID ||
				plan.Runner.Session != lane.Session || plan.Budget != lane.BudgetRemaining {
				t.Fatalf("retained planner replaced the task's private session or budget: %v", err)
			}
			// Fix 11 requires a fresh current-policy grant snapshot. Issuance
			// identity may advance without replacing private task state.
			if plan.Reservation.GrantSetID == priorGrants.ID || plan.Inputs.Grants.ID != plan.Reservation.GrantSetID ||
				plan.Inputs.Grants.PolicyGeneration != f.store.policy.Generation ||
				!reflect.DeepEqual(f.store.grants[priorGrants.ID], priorGrants) || !reflect.DeepEqual(f.store.bindings[lane.LaunchID], priorBinding) {
				t.Fatal("fresh retained launch rewrote historical authority")
			}
			if plan.Data.Workspace.Snapshot.SHA256 != digestOf(append([]byte("snapshot\x00"), edited...)) {
				t.Fatal("retained materialization recopied the initial project over private edits")
			}
			var prompt launchPrompt
			if err := api.DecodeObject(f.store.blobs[plan.Runner.Prompt.ID], &prompt); err != nil || prompt.Message != string(f.store.blobs[message.ID]) {
				t.Fatalf("retained planner changed the exact follow-up bytes: %v", err)
			}
		})
	}
}

func TestCheckCaptureGap(t *testing.T) {
	f := newFixture(t)
	fixtureActiveRun(f)
	gap := api.CaptureGap{BindingID: "capture-binding", Target: f.target, Stream: "stdout", StartOffset: 21,
		Reason: "actual producer disappeared", ObservedAt: "2030-01-02T03:04:05Z"}
	f.add("capture.gap", gap, f.target.Run, "service", f.parent)
	exit := 17
	f.launcher.observation.ExitCode = &exit
	observed, err := f.service.LaneCheck(context.Background(), f.scope("lane.check", f.target, f.parent), f.target)
	if err != nil || observed.ExitCode == nil || *observed.ExitCode != exit {
		t.Fatalf("check erased the actual failed exit: %v", err)
	}
	found := false
	for _, event := range f.store.events {
		if event.Kind == "capture.closed" {
			t.Fatal("process end fabricated capture EOF")
		}
		if event.Kind == "capture.gap" {
			var retained api.CaptureGap
			if err := api.DecodeObject(event.Payload, &retained); err != nil || !reflect.DeepEqual(retained, gap) {
				t.Fatalf("process end rewrote the actual capture failure: %v", err)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("process end erased the actual capture failure")
	}
}
