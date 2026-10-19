package identity

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// These fixtures exercise the identity consumer and the real API validators.
// They do not resolve protected enrollment, allocate a helper, or stand in for
// the installed launched-lane gate. The caller's tuple and retained store
// objects are independent byte copies so changing one cannot change the other.
func cloneLaunchValue[T any](t *testing.T, value T) T {
	t.Helper()
	var result T
	if err := json.Unmarshal(launchJSON(t, value), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func launchJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func launchBlob(t *testing.T, id api.ID, class string, value any) api.BlobRef {
	t.Helper()
	raw, err := api.CanonicalJSON(launchJSON(t, value))
	if err != nil {
		t.Fatal(err)
	}
	return api.BlobRef{ID: id, Class: class, Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
}

func fixtureLaunchPlan(t *testing.T, record api.LaunchRecord, drivers ...api.Driver) api.LaunchPlan {
	t.Helper()
	driver, vendorDirectory := api.DriverCodex, ".codex"
	if len(drivers) != 0 {
		driver = drivers[0]
	}
	if driver == api.DriverClaudock {
		vendorDirectory = ".claude"
	}
	slotMode := "codex-file"
	if driver == api.DriverClaudock {
		slotMode = "claudock-headless"
	}
	source := api.ProjectLaunchSource{EnrollmentID: "project-enrollment", Generation: 1,
		ProjectID: "project", GrantID: "main-data", Base: strings.Repeat("a", 40), HistoryScope: "reachable",
		Object: launchBlob(t, "source", "manifest", map[string]string{"tree": "private-source"})}
	executable := api.Executable{ID: api.ID(string(driver) + "-runtime"), SHA256: digestBytes([]byte("pinned runtime fixture")), Version: "fixture-v1"}
	runtime := api.LaunchRuntime{EnrollmentID: "runtime-enrollment", Generation: 1, Backend: "linux-bwrap-landlock",
		Driver: driver, Executable: executable, Manifest: launchBlob(t, "runtime", "manifest", executable)}
	grants := api.GrantSet{ID: record.GrantSetID, LifeID: record.Target.LifeID, ParentLifeID: record.ParentLifeID,
		SHA256: record.GrantsSHA256, Generation: 1, PolicyGeneration: record.PolicyGeneration, ExpiresAt: "2100-01-01T00:00:00Z",
		Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{},
		Data: []api.DataGrant{{ID: source.GrantID, SourceObjectID: source.Object.ID, SourceSHA256: source.Object.SHA256,
			RelativePath: ".", Destination: "/work/main", Access: "rw", Delivery: "copy",
			HistoryScope: source.HistoryScope, ExpiresAt: "2100-01-01T00:00:00Z"}},
		Profiles: []api.ProfileGrant{{ID: "profile-grant", ProfileID: "profile", Driver: driver, ExpiresAt: "2100-01-01T00:00:00Z"}}}
	var rootTicket api.ID
	if record.ParentLifeID == "" {
		rootTicket = "issued-ticket"
	}
	request := api.Request{Protocol: api.Protocol, Schema: api.SchemaVersion, Config: record.Config, Method: "lane.start",
		RequestID: "original-launch-request", IdempotencyKey: "original-launch-retry-key", Params: launchJSON(t, api.StartRequest{
			Lane: "child", ProjectID: source.ProjectID, Level: record.Actor.Level, Role: record.Actor.Role, Driver: runtime.Driver,
			Task: launchBlob(t, "task", "task", "launch fixture task"), RootTicketID: rootTicket,
			Budget: api.Budget{WallMS: 1000, Processes: 4}, ExpectedPolicyGeneration: record.PolicyGeneration,
			Grants: api.GrantRequest{Resources: []api.ResourceDelegation{}, Data: []api.DataGrantRequest{}, Secrets: []api.SecretDelegation{},
				Profiles: []api.ProfileDelegation{}, Network: []api.NetworkDelegation{}, Channels: []api.ChannelDelegation{}}})}
	if record.Target.Run > 1 {
		request.Method = "lane.resume"
		request.Params = launchJSON(t, api.ResumeRequest{Target: api.LifeRef{LifeID: record.Target.LifeID, Run: record.Target.Run - 1},
			ExpectedGeneration: 1, Message: launchBlob(t, "follow-up", "task", "resume fixture task"), Budget: api.Budget{WallMS: 1000, Processes: 4}})
	}
	digest, err := api.RequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	request.RequestSHA256 = digest
	if record.Target.Run > 1 && record.ParentLifeID == "" {
		// This is the retained reference to the original consumed proof, not
		// a fresh proof issued by this fixture or reused by BindLaunch.
		request.Proof = &api.ProofRef{ID: "consumed-launch-proof", RequestSHA256: digest, ExpiresAt: "2100-01-01T00:00:00Z"}
	}
	reservation := api.LaunchReservation{ID: "reservation", Config: record.Config, Mode: "start", Target: record.Target,
		Level: record.Actor.Level, Role: record.Actor.Role, Driver: driver,
		Authority: api.LaunchAuthority{Kind: "ticket", ID: rootTicket},
		LaunchID:  record.ID, SpecID: "launch-spec", GrantSetID: record.GrantSetID, Generation: 1,
		CancellationEpoch: 1, PolicyGeneration: record.PolicyGeneration, ParentLifeID: record.ParentLifeID,
		RootLifeID: record.RootLifeID, StarterChain: append([]api.ID{}, record.StarterChain...), StarterEventSeq: record.StarterEventSeq,
		OperationID: "original-operation", RequestID: request.RequestID, RequestSHA256: digest,
		RequestedBy:     api.Actor{Kind: "human", ID: "original-human"},
		OriginalRequest: launchBlob(t, "original-frame", "launch_request", request)}
	if record.ParentLifeID != "" {
		reservation.RequestedBy = api.Actor{Kind: "lane", ID: "parent-principal", LifeID: record.ParentLifeID,
			Level: record.Actor.Level + 1, Role: "supervisor"}
		reservation.Authority = api.LaunchAuthority{Kind: "starter", ID: "parent-launch"}
	}
	if record.Target.Run > 1 {
		reservation.Mode, reservation.BaseGeneration, reservation.Generation, reservation.PreviousLaunchID = "resume", 1, 2, "previous-launch"
		reservation.Authority = api.LaunchAuthority{Kind: "proof", ID: "consumed-launch-proof"}
		if reservation.RequestedBy.Kind == "lane" {
			reservation.Authority = api.LaunchAuthority{Kind: "starter", ID: "parent-launch"}
		}
	}
	lease := api.HelperLease{ID: record.UIDLeaseID, UID: record.HostUID, GID: record.HostUID,
		ContainmentID: record.ContainmentID, EndpointGeneration: record.EndpointGeneration}
	workspace := api.Workspace{ID: "workspace", ProjectID: source.ProjectID, Base: source.Base,
		Branch: "lane/" + string(record.Target.LifeID), LogicalCWD: "/work/main",
		Snapshot: launchBlob(t, "snapshot", "manifest", map[string]string{"tree": "private-workspace"})}
	home := api.PrivateHomeBinding{LifeID: record.Target.LifeID, RootID: "private-root", Generation: 1,
		Home: api.PrivateHome{ID: "private-home", WorkspaceID: workspace.ID, HistoryID: "private-history", VendorDirectory: vendorDirectory}}
	materialization := api.Materialization{GrantSetID: grants.ID, Manifest: launchBlob(t, "materialized", "manifest", workspace),
		Objects: []api.MaterializedObject{{GrantID: source.GrantID, SourceIdentity: "source-identity", DestinationIdentity: "work-identity",
			SnapshotSHA256: workspace.Snapshot.SHA256, WorkspaceID: workspace.ID}}}
	runner := api.RunnerPlan{Driver: runtime.Driver, Executable: executable, Argv: []string{string(executable.ID), "fixture"},
		CWD: workspace.LogicalCWD, Home: home.Home, EnvironmentNames: []string{}, AdapterVersion: "fixture-v1", Prompt: launchBlob(t, "prompt", "prompt", request.Params),
		Slot: api.CredentialSlot{ID: "slot", ProfileGrantID: "profile-grant", ProfileID: "profile", Mode: slotMode, LeaseID: "credential-lease", ExpiresAt: "2100-01-01T00:00:00Z"},
		Session: api.Session{ID: "session", Driver: runtime.Driver, VendorVersion: "fixture-vendor-v2", VendorID: "retained-vendor-session",
			HomeID: home.Home.ID, HistoryID: home.Home.HistoryID, LogicalCWD: workspace.LogicalCWD}}
	refusal := api.NotImplemented("lb-v2-admin", "capture fixture disposition")
	refusal.OperationID = reservation.OperationID
	capture := api.CaptureBinding{ID: "capture", Config: record.Config, ReservationID: reservation.ID, Target: record.Target,
		LaunchID: record.ID, HelperLeaseID: lease.ID, OperationID: reservation.OperationID, RequestID: reservation.RequestID,
		RequestedBy: reservation.RequestedBy, Generation: 1, Status: "refused", Streams: []api.CaptureStreamBinding{}, Refusal: refusal,
		RefusalPolicy: &api.CaptureRefusalPolicy{Allowed: true, PolicyGeneration: reservation.PolicyGeneration, ApprovalID: "capture-approval"}}
	return api.LaunchPlan{Reservation: reservation, Inputs: api.LaunchInputs{Grants: grants,
		Sources: api.LaunchSources{ReservationID: reservation.ID, Project: source, Runtime: runtime}}, Lease: lease,
		Data: api.LaunchData{ReservationID: reservation.ID, Target: record.Target, LeaseID: lease.ID,
			Source: source, Workspace: workspace, Home: home, Materialization: materialization},
		Runner: runner, Injection: api.Injection{Target: record.Target, SlotIDs: []api.ID{runner.Slot.ID},
			TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}, Outcome: "prepared"},
		Budget: api.Budget{WallMS: 1000, Processes: 4}, Capture: capture,
		CapturePolicy: &api.EffectivePolicy{Generation: reservation.PolicyGeneration, AllowCaptureRefusal: true, CaptureRefusalApprovalID: "capture-approval"}}
}

func plannedFixtureBinding(t *testing.T, record api.LaunchRecord, plan api.LaunchPlan) api.LaunchBindingRequest {
	t.Helper()
	r := plan.Reservation
	spec := api.LaunchSpec{Kind: "agent", ID: r.SpecID, PlanID: r.ID, Capture: &plan.Capture,
		Target: r.Target, LaunchID: record.ID, UIDLeaseID: plan.Lease.ID, Backend: plan.Inputs.Sources.Runtime.Backend,
		Workspace: plan.Data.Workspace, Materialization: plan.Data.Materialization, Grants: plan.Inputs.Grants,
		Runner: &plan.Runner, Injection: plan.Injection, Budget: plan.Budget, EndpointGeneration: record.EndpointGeneration,
		RuntimeManifest: plan.Inputs.Sources.Runtime.Manifest, PolicyGeneration: record.PolicyGeneration}
	var decoded api.LaunchSpec
	if err := api.DecodeObject(launchJSON(t, spec), &decoded); err != nil {
		t.Fatalf("fixture setup: launch spec does not have the complete wire shape: %v", err)
	}
	original := launchBlob(t, "original-spec", "launch_spec", spec)
	handoff := api.PreparedSpecHandoff{Config: record.Config, Spec: spec, Original: original, SpecSHA256: original.SHA256,
		OperationID: r.OperationID, RequestID: r.RequestID,
		Cause: api.InternalIntent{ID: "register-intent", Kind: api.InternalHelperRegister, Config: record.Config,
			Actor: api.Actor{Kind: "service", ID: "installed-service"}, RequestedBy: r.RequestedBy, Target: r.Target,
			CauseOperationID: r.OperationID, CauseRequestID: r.RequestID, EffectID: "register-effect", CancellationEpoch: r.CancellationEpoch}}
	return api.LaunchBindingRequest{Record: record, Prepared: api.PreparedLaunch{ID: "prepared-gate", GateID: "gate",
		Target: record.Target, SpecSHA256: original.SHA256, ContainmentID: record.ContainmentID,
		ProcessGeneration: record.ProcessGeneration, EndpointGeneration: record.EndpointGeneration},
		Identity: api.IdentityCommit{LaunchID: record.ID, EventID: "identity-event", CommittedSeq: 7,
			RecordSHA256: launchBlob(t, "record", "manifest", record).SHA256},
		Recovery: &api.LaunchRecovery{PlanID: r.ID, OriginalRequest: r.OriginalRequest, Handoff: handoff, Home: plan.Data.Home, Capture: plan.Capture}}
}

func retainFixturePlan(t *testing.T, store *fixtureStore, binding api.LaunchBindingRequest) {
	t.Helper()
	plan := fixtureLaunchPlan(t, binding.Record)
	retainCustomPlan(t, store, binding, plan)
}

func retainCustomPlan(t *testing.T, store *fixtureStore, binding api.LaunchBindingRequest, plan api.LaunchPlan) {
	t.Helper()
	retained := cloneLaunchValue(t, binding)
	plan = cloneLaunchValue(t, plan)
	store.binding, store.grants = &retained, &plan.Inputs.Grants
	store.plan = &api.LaunchPlanRecord{Reservation: plan.Reservation, Generation: 4, Phase: "bound",
		Inputs: &plan.Inputs, Plan: &plan, Handoff: &retained.Recovery.Handoff}
	store.lane.Generation, store.lane.CancellationEpoch = plan.Reservation.Generation, plan.Reservation.CancellationEpoch
	store.lane.Session = plan.Runner.Session
	if plan.CapturePolicy != nil {
		policy := cloneLaunchValue(t, *plan.CapturePolicy)
		store.policy = &policy
	}
	store.events = &api.EventPage{Complete: true, Events: []api.Event{{Schema: api.SchemaVersion,
		ID: binding.Identity.EventID, Seq: binding.Identity.CommittedSeq, Kind: "identity.bound", Config: binding.Record.Config,
		Actor: binding.Recovery.Handoff.Cause.Actor, RequestedBy: plan.Reservation.RequestedBy,
		RequestID: plan.Reservation.RequestID, OperationID: plan.Reservation.OperationID, LifeID: binding.Record.Target.LifeID,
		Run: binding.Record.Target.Run, Payload: launchJSON(t, binding.Record)}}}
	retainProjection(t, store, retained, plan)
}

func TestLaunchPlanReadFixture(t *testing.T) {
	for _, rule := range []string{"valid", "child", "claudock", "opened", "restart", "plan-gap", "event-gap", "binding-gap", "resume", "registered"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			if rule == "resume" {
				store.record.Target.Run, store.lane.Run = 2, 2
			}
			if rule == "child" {
				store.record.ParentLifeID, store.record.RootLifeID = "parent-life", "parent-life"
				store.record.StarterChain, store.record.StarterEventSeq = []api.ID{"parent-life"}, 3
				store.lane.ParentLifeID, store.lane.RootLifeID = store.record.ParentLifeID, store.record.RootLifeID
				store.lane.StarterChain, store.lane.StarterEventSeq = append([]api.ID{}, store.record.StarterChain...), store.record.StarterEventSeq
			}
			driver := api.DriverCodex
			if rule == "claudock" {
				driver = api.DriverClaudock
			}
			plan := fixtureLaunchPlan(t, store.record, driver)
			if rule == "registered" {
				capture := &plan.Capture
				capture.Status, capture.Refusal = "registered", nil
				capture.RefusalPolicy, plan.CapturePolicy = nil, nil
				capture.WorkerLeaseID, capture.EffectID, capture.ProducerID = "capture-worker", "capture-effect", "capture-producer"
				capture.ProducerGeneration, capture.BootID = "kernel-generation", "boot"
				capture.Supervisor = &api.Executable{ID: "supervisor", SHA256: digestBytes([]byte("fixed supervisor")), Version: "fixture-v1"}
				capture.Streams = []api.CaptureStreamBinding{{ID: "stdout", Stream: "stdout", PipeID: "pipe-out"}, {ID: "stderr", Stream: "stderr", PipeID: "pipe-err"}}
			}
			request := plannedFixtureBinding(t, store.record, plan)
			retainCustomPlan(t, store, request, plan)
			sentinel := api.NotImplemented("lb-v2-service", "retained launch dependency")
			switch rule {
			case "opened":
				store.plan.Phase = "opened"
				store.lane.Generation++
			case "restart":
				var err error
				s, err = New(s.deps)
				if err != nil {
					t.Fatal(err)
				}
			case "plan-gap":
				store.planErr = sentinel
			case "event-gap":
				store.eventErr = sentinel
			case "binding-gap":
				store.err = sentinel
			}
			permit, err := s.BindLaunch(context.Background(), request)
			if strings.HasSuffix(rule, "-gap") {
				if !errors.Is(err, sentinel) || permit != (api.LaunchPermit{}) {
					t.Fatalf("fixture check: launch dependency refusal was replaced: %v", err)
				}
				return
			}
			if err != nil || permit.PreparedID != request.Prepared.ID || permit.RecordSHA256 != request.Identity.RecordSHA256 ||
				permit.CommittedSeq != request.Identity.CommittedSeq || store.planReads != 1 || store.planID != request.Recovery.PlanID ||
				store.planScope.Actor != request.Recovery.Handoff.Cause.Actor || store.planScope.Actor == plan.Reservation.RequestedBy ||
				store.planScope.Config != request.Record.Config || store.eventQuery.Since != request.Identity.CommittedSeq-1 {
				t.Fatalf("fixture check: retained plan and committed event were not read: %v", err)
			}
		})
	}
}

func TestLaunchRecoveryFixture(t *testing.T) {
	for _, rule := range []string{"missing", "reservation", "request", "path", "executable", "argv", "budget", "capture", "history", "digest"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			request := fixtureLaunchBinding(t, store.record)
			retainFixturePlan(t, store, request)
			switch rule {
			case "missing":
				request.Recovery = nil
			case "reservation":
				request.Recovery.PlanID = "foreign-reservation"
			case "request":
				request.Recovery.OriginalRequest.ID = "foreign-request"
			case "path":
				request.Recovery.Home.RootID = "/caller/home"
			case "executable":
				request.Recovery.Handoff.Spec.Runner.Executable.ID = "/caller/executable"
			case "argv":
				request.Recovery.Handoff.Spec.Runner.Argv = []string{"caller-command"}
			case "budget":
				request.Recovery.Handoff.Spec.Budget.WallMS++
			case "capture":
				request.Recovery.Capture.ID = "foreign-capture"
			case "history":
				request.Recovery.Home.Home.HistoryID = "shared-history"
			case "digest":
				request.Recovery.Handoff.SpecSHA256 = digestBytes([]byte("changed spec"))
			}
			permit, err := s.BindLaunch(context.Background(), request)
			fixtureCode(t, err, api.CodeConflict)
			if permit != (api.LaunchPermit{}) {
				t.Fatal("fixture check: changed recovery returned a permit")
			}
		})
	}
}

func TestLaunchPlanGuardsFixture(t *testing.T) {
	for _, rule := range []string{"missing-recovery", "missing-plan", "revision", "phase", "reservation", "handoff", "causal-service", "prepared-spec", "home-path", "executable", "capture", "epoch", "generation", "grants", "policy"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			request := fixtureLaunchBinding(t, store.record)
			retainFixturePlan(t, store, request)
			want := api.CodeIntegrity
			switch rule {
			case "missing-recovery":
				store.binding.Recovery = nil
			case "missing-plan":
				store.plan.Plan, store.plan.Handoff, store.plan.Inputs, store.plan.Phase = nil, nil, nil, "reserved"
			case "revision":
				store.plan.Generation, want = 0, api.CodeInvalid
			case "phase":
				store.plan.Phase = "spec_retained"
			case "reservation":
				store.plan.Reservation.ID = "foreign-reservation"
				store.plan.Plan.Reservation.ID = store.plan.Reservation.ID
				store.plan.Plan.Inputs.Sources.ReservationID = store.plan.Reservation.ID
				store.plan.Plan.Data.ReservationID = store.plan.Reservation.ID
				store.plan.Plan.Capture.ReservationID = store.plan.Reservation.ID
				store.plan.Inputs = &store.plan.Plan.Inputs
				other := plannedFixtureBinding(t, store.record, *store.plan.Plan)
				store.plan.Handoff = &other.Recovery.Handoff
			case "handoff":
				other := cloneLaunchValue(t, *store.plan.Handoff)
				other.Cause.ID = "another-register-intent"
				store.plan.Handoff = &other
			case "causal-service":
				store.binding.Recovery.Handoff.Cause.Actor = store.plan.Reservation.RequestedBy
			case "prepared-spec":
				store.binding.Prepared.SpecSHA256 = digestBytes([]byte("foreign prepared spec"))
				request.Prepared = store.binding.Prepared
				want = api.CodeInvalid
			case "home-path":
				store.plan.Plan.Data.Home.RootID = "/caller/home"
				want = api.CodeInvalid
			case "executable":
				store.plan.Plan.Runner.Executable.ID = "caller-executable"
				want = api.CodeInvalid
			case "capture":
				store.plan.Plan.Capture.Refusal.Code = api.CodeIntegrity
				want = api.CodeInvalid
			case "epoch":
				store.lane.CancellationEpoch++
				want = api.CodeConflict
			case "generation":
				store.lane.Generation--
				want = api.CodeConflict
			case "grants":
				changed := cloneLaunchValue(t, *store.grants)
				changed.Generation++
				store.grants, want = &changed, api.CodeForbidden
			case "policy":
				store.policy, want = &api.EffectivePolicy{Generation: store.record.PolicyGeneration + 1}, api.CodeConflict
			}
			permit, err := s.BindLaunch(context.Background(), request)
			fixtureCode(t, err, want)
			if permit != (api.LaunchPermit{}) {
				t.Fatal("fixture check: invalid retained launch returned a permit")
			}
		})
	}
}

func TestIdentityEventFixture(t *testing.T) {
	for _, rule := range []string{"missing", "sequence", "id", "kind", "config", "operation", "requester", "target", "payload", "actor"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			request := fixtureLaunchBinding(t, store.record)
			retainFixturePlan(t, store, request)
			event := &store.events.Events[0]
			switch rule {
			case "missing":
				store.events.Events = nil
			case "sequence":
				event.Seq++
			case "id":
				event.ID = "foreign-event"
			case "kind":
				event.Kind = "identity.revoked"
			case "config":
				event.Config = "other"
			case "operation":
				event.OperationID = "foreign-operation"
			case "requester":
				event.RequestedBy = api.Actor{Kind: "service", ID: "different-requester"}
			case "actor":
				event.Actor.ID = "another-service"
			case "target":
				event.Run++
			case "payload":
				other := store.record
				other.EndpointGeneration++
				event.Payload = launchJSON(t, other)
			}
			permit, err := s.BindLaunch(context.Background(), request)
			fixtureCode(t, err, api.CodeIntegrity)
			if permit != (api.LaunchPermit{}) {
				t.Fatal("fixture check: uncommitted identity event returned a permit")
			}
		})
	}
}

func TestBindingShapeFixture(t *testing.T) {
	_, store, _ := serviceFixture(t)
	request := fixtureLaunchBinding(t, store.record)
	if err := validateBindingRequest(request); err != nil {
		t.Fatal(err)
	}
	request.Prepared.GateID = ""
	errorCode(t, validateBindingRequest(request), api.CodeInvalid)
}

func TestCurrentCallerFixture(t *testing.T) {
	for _, rule := range []string{"current", "source-label", "endpoint", "worker-class", "human-class", "principal", "policy", "legacy-kind", "worker-kind"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			scope := fixtureRequest(t, fixtureLaneScope(t, s, store, 5), "identity.self", api.Empty{})
			connection := scope.Connection.(*fixtureConnection)
			before := scope.Actor
			want := api.CodeUnauthenticated
			switch rule {
			case "source-label":
				scope.Source = "worker"
			case "endpoint":
				connection.binding.EndpointGeneration++
			case "worker-class":
				connection.binding.Class, connection.binding.WorkerLeaseID = api.EndpointWorker, "capture-worker"
				want = api.CodeNotImplemented
			case "human-class":
				connection.binding = fixtureHumanBinding()
				store.enrollment = &api.HumanEnrollment{Config: scope.Config, PrincipalID: "human-principal", Generation: 1}
			case "principal":
				scope.Actor.ID = "claimed-principal"
				before = scope.Actor
			case "policy":
				store.policy = &api.EffectivePolicy{Generation: scope.PolicyGeneration + 1}
				want = api.CodeConflict
			case "legacy-kind":
				store.record.Kind = ""
			case "worker-kind":
				store.record.Kind = "worker"
			}
			err := s.Authorize(context.Background(), scope, scope.Request)
			if rule == "current" || rule == "source-label" {
				if err != nil || scope.Actor != before || scope.Connection != connection || scope.Frame.(*fixtureFrame).verifies != 1 {
					t.Fatalf("fixture check: actual caller or frame was replaced: %v", err)
				}
				return
			}
			fixtureCode(t, err, want)
			if scope.Actor != before || scope.Connection != connection {
				t.Fatal("fixture check: refused caller was relabelled")
			}
		})
	}
}

func TestWorkerBindingGapFixture(t *testing.T) {
	s, store, _ := serviceFixture(t)
	binding := fixtureHumanBinding()
	binding.Class, binding.LaunchID, binding.WorkerLeaseID = api.EndpointWorker, store.record.ID, "worker-lease"
	target := store.record.Target
	binding.Target = &target
	connection := fixtureUnboundConnection(t, binding)
	peer := &fixturePeer{facts: api.PeerFacts{HostPID: 42, HostUID: 1234, HostGID: 1234, ProcessGeneration: "worker-kernel"}}
	s.deps.Peers = &fixturePeers{peer: peer}
	scope, err := s.Authenticate(context.Background(), connection)
	errorCode(t, err, api.CodeNotImplemented)
	if !reflect.DeepEqual(scope, api.Scope{}) || connection.closes != 1 || peer.closes != 1 {
		t.Fatal("fixture check: worker gap reinterpreted authority or retained its connection")
	}
}

func TestLaunchRevocationGapFixture(t *testing.T) {
	s, store, _ := serviceFixture(t)
	before := cloneLaunchValue(t, store.record)
	err := s.RevokeLaunch(context.Background(), store.record.ID)
	errorCode(t, err, api.CodeNotImplemented)
	if !reflect.DeepEqual(before, store.record) || store.transaction != nil {
		t.Fatal("fixture check: revocation without a cause changed stored authority")
	}
	store.err = api.NotImplemented("lb-v2-service", "revocation dependency")
	if err := s.RevokeLaunch(context.Background(), store.record.ID); !errors.Is(err, store.err) {
		t.Fatal("fixture check: revocation dependency refusal was replaced")
	}
}

func TestLaunchGrantExpiryFixture(t *testing.T) {
	for _, rule := range []string{"expired", "revoked"} {
		t.Run(rule, func(t *testing.T) {
			s, store, _ := serviceFixture(t)
			request := fixtureLaunchBinding(t, store.record)
			retainFixturePlan(t, store, request)
			changed := cloneLaunchValue(t, *store.grants)
			if rule == "expired" {
				changed.ExpiresAt = timestamp(s.deps.Clock.Now().Add(-time.Second))
			} else {
				changed.Revoked = true
			}
			store.grants = &changed
			permit, err := s.BindLaunch(context.Background(), request)
			fixtureCode(t, err, api.CodeForbidden)
			if permit != (api.LaunchPermit{}) {
				t.Fatal("fixture check: stale grants returned a permit")
			}
		})
	}
}
