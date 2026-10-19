package watchdog

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// These are complete shape-valid retained DTOs, not native launch, capture or
// D6 attestations. Their hashes are computed from the actual fixture bytes.
func (r *testRig) fix10Launch() {
	lane := r.store.lane
	lane.RootLifeID = lane.LifeID
	lane.Session.VendorVersion = "fixture-vendor-1"
	source := api.ProjectLaunchSource{EnrollmentID: "project-enrollment", Generation: 1, ProjectID: "project-one", GrantID: "main-data",
		Object: r.addClassBlob("source-object", []byte("fixture source manifest\n"), "manifest"), Base: string(digest([]byte("fixture base"))), HistoryScope: "reachable"}
	lane.Workspace.ProjectID, lane.Workspace.Base, lane.Workspace.Branch = source.ProjectID, source.Base, "lane/"+string(lane.LifeID)
	lane.Workspace.Snapshot = r.addClassBlob("workspace-snapshot", []byte("fixture workspace manifest\n"), "manifest")
	r.store.lane = lane
	r.store.grants.Data = []api.DataGrant{{ID: source.GrantID, SourceObjectID: source.Object.ID, SourceSHA256: source.Object.SHA256,
		RelativePath: ".", Destination: "/work/main", Delivery: "copy", Access: "rw", HistoryScope: source.HistoryScope, ExpiresAt: r.store.grants.ExpiresAt}}
	r.grants.grants = r.store.grants
	r.broker.eligibility.Request.Session = lane.Session
	requestBytes, err := json.Marshal(api.ResumeRequest{Target: api.LifeRef{LifeID: lane.LifeID, Run: lane.Run - 1},
		ExpectedGeneration: lane.Generation - 1, Message: lane.Task, Budget: lane.BudgetRemaining})
	if err != nil {
		r.t.Fatal(err)
	}
	original := r.addClassBlob("original-request", requestBytes, "launch_request")
	reservation := api.LaunchReservation{ID: "reservation-one", Config: r.store.launch.Config, Mode: "resume", Level: lane.Level, Role: lane.Role,
		Driver: lane.Session.Driver, Authority: api.LaunchAuthority{Kind: "starter", ID: "previous-launch"},
		Target: r.signal.Target, LaunchID: lane.LaunchID, SpecID: "spec-one", GrantSetID: lane.GrantSetID,
		Generation: lane.Generation, BaseGeneration: lane.Generation - 1, CancellationEpoch: lane.CancellationEpoch, PolicyGeneration: lane.PolicyGeneration,
		RootLifeID: lane.RootLifeID, PreviousLaunchID: "previous-launch", OperationID: r.store.events[0].OperationID, RequestID: r.store.events[0].RequestID,
		RequestSHA256: original.SHA256, OriginalRequest: original, RequestedBy: r.store.events[0].RequestedBy}
	executable := api.Executable{ID: "runtime-claudock", Version: "fixture-wrapper-1", SHA256: digest([]byte("fixture wrapper bytes"))}
	runtime := api.LaunchRuntime{EnrollmentID: "runtime-enrollment", Generation: 1, Backend: "linux-bwrap-landlock", Driver: lane.Session.Driver,
		Executable: executable, Manifest: r.addClassBlob("runtime-manifest", []byte("fixture runtime manifest\n"), "manifest")}
	lease := api.HelperLease{ID: "helper-lease", UID: 12001, GID: 12001, ContainmentID: r.launcher.handle.ContainmentID, EndpointGeneration: 1}
	home := api.PrivateHomeBinding{LifeID: lane.LifeID, RootID: "home-root", Generation: 1,
		Home: api.PrivateHome{ID: lane.Session.HomeID, WorkspaceID: lane.Workspace.ID, VendorDirectory: ".vendor", HistoryID: lane.Session.HistoryID}}
	materialization := api.Materialization{GrantSetID: lane.GrantSetID,
		Manifest: r.addClassBlob("materialization", []byte("fixture materialization\n"), "manifest"),
		Objects: []api.MaterializedObject{{GrantID: source.GrantID, SourceIdentity: "source-identity", DestinationIdentity: "workspace-identity",
			SnapshotSHA256: lane.Workspace.Snapshot.SHA256, WorkspaceID: lane.Workspace.ID}}}
	slot := api.CredentialSlot{ID: "source-slot", LeaseID: "source-slot-lease", ProfileGrantID: lane.ProfileGrantID, ProfileID: r.signal.ProfileID, ExpiresAt: r.store.grants.ExpiresAt}
	runner := api.RunnerPlan{Driver: lane.Session.Driver, Executable: executable, Argv: []string{"runtime-claudock", "fixture"}, CWD: lane.Session.LogicalCWD,
		Prompt: r.addClassBlob("launch-prompt", []byte("fixture prompt\n"), "prompt"), Home: home.Home, Slot: slot, Session: lane.Session, AdapterVersion: r.signal.AdapterVersion}
	supervisor := api.Executable{ID: "capture-supervisor", Version: "fixture-supervisor-1", SHA256: digest([]byte("fixture supervisor bytes"))}
	capture := api.CaptureBinding{ID: "capture-binding", Config: reservation.Config, ReservationID: reservation.ID, Target: r.signal.Target, LaunchID: lane.LaunchID,
		HelperLeaseID: lease.ID, OperationID: reservation.OperationID, RequestID: reservation.RequestID, RequestedBy: reservation.RequestedBy, Generation: 1,
		Status: "registered", WorkerLeaseID: "capture-lease", EffectID: "capture-effect", ProducerID: "capture-producer", ProducerGeneration: "producer-generation", BootID: "fixture-boot",
		Supervisor: &supervisor, Streams: []api.CaptureStreamBinding{{ID: "stream-out", Stream: "stdout", PipeID: "pipe-out"}, {ID: "stream-err", Stream: "stderr", PipeID: "pipe-err"}}}
	grants := r.store.grants
	grants.Profiles = append([]api.ProfileGrant{}, grants.Profiles...)
	plan := api.LaunchPlan{Reservation: reservation, Inputs: api.LaunchInputs{Grants: grants, Sources: api.LaunchSources{ReservationID: reservation.ID, Project: source, Runtime: runtime}},
		Lease: lease, Data: api.LaunchData{ReservationID: reservation.ID, Target: r.signal.Target, LeaseID: lease.ID, Source: source, Workspace: lane.Workspace, Home: home, Materialization: materialization},
		Runner: runner, Injection: api.Injection{Target: r.signal.Target, SlotIDs: []api.ID{slot.ID}, Outcome: "prepared"}, Budget: lane.BudgetRemaining, Capture: capture}
	r.store.plan = api.LaunchPlanRecord{Reservation: reservation, Generation: 1, Phase: "opened", Inputs: &plan.Inputs, Plan: &plan}
	r.retainFix10Binding()
	r.capture(func(c *api.CaptureRecord) { c.BindingID = capture.ID })
	r.store.captureState = api.CaptureState{Binding: capture, Generation: 1, LastSeq: r.store.events[2].Seq,
		Positions: []api.CapturePosition{{StreamID: "stream-out", NextOffset: int64(len(r.store.blobs["capture-bytes"])), EOF: true}, {StreamID: "stream-err", NextOffset: 0, EOF: true}}}
	var event api.LaunchEvent
	if err := json.Unmarshal(r.store.events[0].Payload, &event); err != nil {
		r.t.Fatal(err)
	}
	event.Lane, event.Task, event.GrantSetID, event.GrantsSHA256, event.PolicyGeneration = lane, lane.Task, grants.ID, grants.SHA256, lane.PolicyGeneration
	payload, err := json.Marshal(event)
	if err != nil {
		r.t.Fatal(err)
	}
	r.store.events[0].Payload = payload
}

func (r *testRig) canonicalFixture(value any) ([]byte, api.Digest) {
	r.t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		r.t.Fatal(err)
	}
	canonical, err := api.CanonicalJSON(encoded)
	if err != nil {
		r.t.Fatal(err)
	}
	return canonical, digest(canonical)
}

func (r *testRig) retainFix10Binding() {
	r.t.Helper()
	plan := r.store.plan.Plan
	reservation := plan.Reservation
	spec := api.LaunchSpec{Kind: "agent", PlanID: reservation.ID, Capture: &plan.Capture, ID: reservation.SpecID, Target: reservation.Target, LaunchID: reservation.LaunchID,
		Backend: plan.Inputs.Sources.Runtime.Backend, UIDLeaseID: plan.Lease.ID, Workspace: plan.Data.Workspace, Materialization: plan.Data.Materialization,
		Grants: plan.Inputs.Grants, Runner: &plan.Runner, Injection: plan.Injection, Budget: plan.Budget, EndpointGeneration: plan.Lease.EndpointGeneration,
		RuntimeManifest: plan.Inputs.Sources.Runtime.Manifest, PolicyGeneration: reservation.PolicyGeneration}
	specBytes, specHash := r.canonicalFixture(spec)
	ref := r.addClassBlob("retained-spec", specBytes, "launch_spec")
	handoff := api.PreparedSpecHandoff{Config: reservation.Config, Spec: spec, Original: ref, SpecSHA256: specHash, OperationID: reservation.OperationID, RequestID: reservation.RequestID,
		Cause: api.InternalIntent{ID: "register-intent", Kind: api.InternalHelperRegister, Config: reservation.Config, Actor: api.Actor{Kind: "service", ID: "service"},
			RequestedBy: reservation.RequestedBy, CauseOperationID: reservation.OperationID, CauseRequestID: reservation.RequestID, EffectID: "register-effect", Target: reservation.Target, CancellationEpoch: reservation.CancellationEpoch}}
	launch := r.store.launch
	launch.Kind, launch.RootLifeID = "agent", reservation.RootLifeID
	launch.Actor = api.Actor{Kind: "lane", ID: "agent-principal", LifeID: reservation.Target.LifeID, Level: reservation.Level, Role: reservation.Role}
	launch.UIDLeaseID, launch.HostUID, launch.EndpointGeneration = plan.Lease.ID, plan.Lease.UID, plan.Lease.EndpointGeneration
	r.store.launch = launch
	_, recordHash := r.canonicalFixture(launch)
	r.store.binding = api.LaunchBindingRequest{Record: launch,
		Prepared: api.PreparedLaunch{ID: "prepared-one", SpecSHA256: specHash, Target: reservation.Target, ContainmentID: launch.ContainmentID,
			ProcessGeneration: launch.ProcessGeneration, EndpointGeneration: launch.EndpointGeneration, GateID: "gate-one"},
		Identity: api.IdentityCommit{LaunchID: launch.ID, EventID: "identity-event", CommittedSeq: 1, RecordSHA256: recordHash},
		Recovery: &api.LaunchRecovery{PlanID: reservation.ID, OriginalRequest: reservation.OriginalRequest, Handoff: handoff, Home: plan.Data.Home, Capture: plan.Capture}}
	r.store.plan.Handoff = &handoff
}

func refusedFixtureCapture(capture api.CaptureBinding) api.CaptureBinding {
	capture.Status, capture.Streams = "refused", nil
	capture.WorkerLeaseID, capture.EffectID, capture.ProducerID, capture.ProducerGeneration, capture.BootID, capture.Supervisor = "", "", "", "", "", nil
	capture.RefusalPolicy = &api.CaptureRefusalPolicy{Allowed: true, PolicyGeneration: 3, ApprovalID: "d6-capture-exception"}
	capture.Refusal = api.NotImplemented("capture-owner", "capture unavailable")
	capture.Refusal.OperationID = capture.OperationID
	return capture
}

func TestFix10Operation(t *testing.T) {
	for _, state := range []string{"pending", "running", "completed"} {
		t.Run(state, func(t *testing.T) {
			r, store, probe := newJournal(t)
			probe.before = func() {
				id := probe.requests[len(probe.requests)-1].IntentID
				intent := store.intents[id]
				op := store.operations[intent.OperationID]
				if state == "completed" {
					intent.Status = "completed"
					intent.Generation++
					op.Status = "succeeded"
				} else {
					op.Status = state
				}
				store.intents[id], store.operations[op.ID] = intent, op
			}
			op, err := r.s.ObserveLimit(context.Background(), r.signal)
			if err != nil || len(probe.requests) != 1 || op.ID != probe.requests[0].Swap.OperationID || op.ID == store.transactions[0].Internal.ID {
				t.Fatal("shared operation was not retained through the actual durable phase", err)
			}
			if state == "completed" && op.Status != "succeeded" {
				t.Fatal("completed phase lost its result")
			}
		})
	}
	for _, fault := range []string{"returned-id", "intent-id", "pending-success", "claimed-success", "swapped-operation"} {
		t.Run(fault, func(t *testing.T) {
			r, store, probe := newJournal(t)
			faultApplied := false
			inject := func() {
				id := r.s.intentID(r.signal.Target)
				intent := store.intents[id]
				op := store.operations[intent.OperationID]
				switch fault {
				case "returned-id":
					op.ID = "other-operation"
				case "intent-id":
					op.ID = store.transactions[0].Internal.ID
				case "pending-success":
					op.Status = "succeeded"
				case "claimed-success":
					intent.Status = "claimed"
					intent.Generation++
					op.Status = "succeeded"
				case "swapped-operation":
					intent.Status = "claimed"
					intent.Generation++
					intent.OperationID, intent.Swap.OperationID = "replacement-operation", "replacement-operation"
					op.ID = intent.OperationID
				}
				store.intents[id] = intent
				store.operations[intent.OperationID] = op
				faultApplied = true
			}
			calls := 1
			if fault == "swapped-operation" {
				// Replace the stored claim while its original operation is read,
				// before dispatch. Retain the original operation record so that
				// validating only the earlier snapshot cannot detect this fault.
				store.onOperation = inject
				calls = 0
			} else {
				probe.before = inject
			}
			_, err := r.s.ObserveLimit(context.Background(), r.signal)
			requireCode(t, err, api.CodeInvalid)
			if !faultApplied || store.writeCalls != 1 || len(probe.requests) != calls || r.broker.acquireCalls != 0 {
				t.Fatal("operation refusal changed its claim or acquired a slot")
			}
		})
	}
}

func TestFix10SelectionReceipt(t *testing.T) {
	r, store, probe := newJournal(t)
	store.after = func() {
		for id, op := range store.operations {
			op.Status = "succeeded"
			store.operations[id] = op
		}
	}
	// The durable receipt itself must agree with pending, even if the commit
	// reply still carries the original pending snapshot.
	_, err := r.s.ObserveLimit(context.Background(), r.signal)
	requireCode(t, err, api.CodeInvalid)
	if len(probe.requests) != 0 {
		t.Fatal("completed pending receipt reached lifecycle")
	}
}

func TestFix10LaunchPins(t *testing.T) {
	for _, fault := range []string{"level", "role", "driver"} {
		t.Run(fault, func(t *testing.T) {
			r := newRig(t)
			lane := r.store.lane
			switch fault {
			case "level":
				lane.Level++
			case "role":
				lane.Role = "reviewer"
			case "driver":
				lane.Session.Driver = api.DriverCodex
			}
			_, err := r.s.launchContext(context.Background(), lane, r.store.launch)
			requireCode(t, err, api.CodeIntegrity)
			r.noEffects()
		})
	}
	for _, fault := range []string{"capture-missing", "eof", "position", "refused"} {
		t.Run(fault, func(t *testing.T) {
			r := newRig(t)
			if fault == "refused" {
				capture := refusedFixtureCapture(r.store.plan.Plan.Capture)
				r.store.plan.Plan.Capture = capture
				r.store.plan.Plan.CapturePolicy = &api.EffectivePolicy{Generation: r.store.lane.PolicyGeneration, AllowCaptureRefusal: true, CaptureRefusalApprovalID: capture.RefusalPolicy.ApprovalID}
				r.retainFix10Binding()
				r.store.captureState.Binding, r.store.captureState.Positions = capture, nil
				_, err := r.s.launchContext(context.Background(), r.store.lane, r.store.launch)
				if err != capture.Refusal {
					t.Fatal("approved capture refusal authorized continuation or lost its actual refusal", err)
				}
			} else {
				switch fault {
				case "capture-missing":
					r.store.captureState.Binding.ID = "other-capture"
				case "eof":
					r.store.captureState.Positions[0].EOF = false
				case "position":
					r.store.captureState.Positions = r.store.captureState.Positions[:1]
				}
				_, err := r.s.launchContext(context.Background(), r.store.lane, r.store.launch)
				if fault == "capture-missing" {
					requireCode(t, err, api.CodeNotFound)
				} else {
					requireCode(t, err, api.CodeIntegrity)
				}
			}
			r.noEffects()
		})
	}
	r := newRig(t)
	if err := api.ValidateLaunchPlanRecord(r.store.plan); err != nil {
		t.Fatal("fixture plan is not valid", err)
	}
	if err := api.ValidateLaunchBindingPlan(r.store.binding, *r.store.plan.Plan); err != nil {
		t.Fatal("fixture binding is not valid", err)
	}
	before := r.store.lane
	plan, err := r.s.assess(context.Background(), r.signal)
	if err != nil || plan.Swap == nil || !reflect.DeepEqual(before, r.store.lane) {
		t.Fatal("registered capture and pinned launch were refused or changed", err)
	}
	// The private workspace remains the same while its task edits advance
	// the snapshot beyond the launch plan's initial materialization.
	r.store.lane.Workspace.Snapshot = r.addClassBlob("post-run-snapshot", []byte("updated workspace snapshot\n"), "manifest")
	if _, err := r.s.launchContext(context.Background(), r.store.lane, r.store.launch); err != nil {
		t.Fatal("task edits invalidated stable workspace identity", err)
	}
	r.noEffects()
}

func TestFix10RefusedEvent(t *testing.T) {
	r := newRig(t)
	capture := refusedFixtureCapture(r.store.plan.Plan.Capture)
	if err := api.ValidateCaptureBinding(capture); err != nil {
		t.Fatal(err)
	}
	r.addEvent("capture.refused", capture)
	r.addEvent("watchdog.waiting", api.WatchdogEvent{Signal: &r.signal, RetryAfterMS: 5000})
	_, err := r.s.Reconcile(context.Background(), r.signal.Target)
	if !reflect.DeepEqual(err, capture.Refusal) {
		t.Fatal("refused capture became backoff or lost its owning refusal", err)
	}
	if len(r.broker.checked) != 0 {
		t.Fatal("refused capture polled room")
	}
	r.noEffects()

	r, store, probe := newJournal(t)
	if _, err := r.s.ObserveLimit(context.Background(), r.signal); err != nil {
		t.Fatal(err)
	}
	r.addEvent("capture.refused", refusedFixtureCapture(r.store.plan.Plan.Capture))
	_, err = r.s.Reconcile(context.Background(), r.signal.Target)
	requireCode(t, err, api.CodeNotImplemented)
	if len(probe.requests) != 1 || store.writeCalls != 1 {
		t.Fatal("pending recovery bypassed capture refusal")
	}
}

func TestFix10StoreStamp(t *testing.T) {
	for _, fault := range []string{"intent", "swap", "both", "commit-success"} {
		t.Run(fault, func(t *testing.T) {
			r, store, probe := newJournal(t)
			if fault == "commit-success" {
				store.replyOperation = func(op api.Operation) api.Operation { op.Status = "succeeded"; return op }
			} else {
				store.after = func() {
					id := r.s.intentID(r.signal.Target)
					intent := store.intents[id]
					if fault == "intent" || fault == "both" {
						intent.OperationID = "foreign-operation"
					}
					if fault == "swap" || fault == "both" {
						intent.Swap.OperationID = "foreign-operation"
					}
					store.intents[id] = intent
				}
			}
			_, err := r.s.ObserveLimit(context.Background(), r.signal)
			if fault == "commit-success" {
				requireCode(t, err, api.CodeInvalid)
			} else {
				requireCode(t, err, api.CodeIntegrity)
			}
			if len(probe.requests) != 0 || store.writeCalls != 1 || r.broker.acquireCalls != 0 {
				t.Fatal("invalid store-stamped receipt reached a continuation")
			}
			written := store.transactions[0].Writes.Continuations[0]
			if written.OperationID != "" || written.Swap.OperationID != "" {
				t.Fatal("watchdog supplied an operation instead of retaining the store stamp")
			}
		})
	}
}

func TestFix10OperationLookupClock(t *testing.T) {
	r, store, probe := newJournal(t)
	probe.err = problem(api.CodeDeadline, "handoff interrupted")
	_, err := r.s.ObserveLimit(context.Background(), r.signal)
	requireCode(t, err, api.CodeDeadline)
	probe.err = nil
	store.onOperation = func() { r.clock.at = r.clock.at.Add(31 * time.Second) }
	_, err = r.s.Reconcile(context.Background(), r.signal.Target)
	requireCode(t, err, api.CodeIntegrity)
	if len(probe.requests) != 1 || store.writeCalls != 1 || r.broker.acquireCalls != 0 {
		t.Fatal("operation lookup extended expired pending evidence")
	}
}
