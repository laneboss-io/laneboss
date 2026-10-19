package dashboard

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

// These records retain the actual HTTP resume input and synthetic launch
// outputs for the projection fixture. No helper, process or model runs here.
type fixtureReviewResume struct {
	Scope     api.Scope
	Before    api.Lane
	Request   api.ResumeRequest
	Operation api.Operation
}

type fixtureReviewLaunch struct {
	Record         api.LaunchPlanRecord
	Binding        api.LaunchBindingRequest
	ReservationRef api.BlobRef
	EnrollmentRef  api.BlobRef
	RecordRef      api.BlobRef
	BindingRef     api.BlobRef
}

func (m *memHarness) fixtureReviewJSON(t *testing.T, id api.ID, class string, value any) api.BlobRef {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = api.CanonicalJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return m.putBlob(id, class, raw)
}

// Follow the API launch/review fixtures: bind the retained request, enrolled
// project/runtime, private session, capture and exact canonical recovery spec.
// The fixture's shared validators stay active; this does not implement any
// production StateStore launch port or bypass the HTTP mark dispatcher.
func (m *memHarness) fixtureRetainReviewLaunch(t *testing.T, lane api.Lane) *fixtureReviewLaunch {
	t.Helper()
	resume := m.reviewResume
	if resume == nil || resume.Scope.Frame == nil || resume.Scope.Request.Proof == nil ||
		!m.consumed[resume.Scope.Request.Proof.ID] || resume.Request.Target.LifeID != lane.LifeID ||
		resume.Request.Target.Run+1 != lane.Run || resume.Before.Generation != resume.Request.ExpectedGeneration ||
		resume.Operation.Run != lane.Run || resume.Operation.Status != "succeeded" {
		t.Fatal("fixture launch lacks the retained successful resume")
	}
	scope, before := resume.Scope, resume.Before
	reservationRequest := api.LaunchReservationRequest{OperationID: resume.Operation.ID,
		Guards: []api.TransactionGuard{
			{Cancellation: &api.CancellationCheck{LifeID: lane.LifeID, Epoch: before.CancellationEpoch}},
			{Proof: &api.ProofUse{Proof: *scope.Request.Proof, Target: api.HumanChallengeRequest{
				Method: scope.Request.Method, TargetID: lane.LifeID, RequestSHA256: scope.Request.RequestSHA256,
				BaseGeneration: before.Generation}}}}}
	if err := api.ValidateLaunchReservationRequest(scope, reservationRequest); err != nil {
		t.Fatalf("fixture launch request: %v", err)
	}
	original := m.putBlob("fixture-resume-request", "launch_request", scope.Frame.Bytes())
	r := api.LaunchReservation{ID: "fixture-reservation", Config: scope.Config, Mode: "resume", Level: before.Level,
		Role: before.Role, Driver: before.Session.Driver, Authority: api.LaunchAuthority{Kind: "proof", ID: scope.Request.Proof.ID},
		Target: api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}, LaunchID: "fixture-launch-2", SpecID: "fixture-spec",
		GrantSetID: "fixture-grants", Generation: before.Generation + 1, BaseGeneration: before.Generation,
		CancellationEpoch: before.CancellationEpoch, PolicyGeneration: scope.PolicyGeneration, ParentLifeID: before.ParentLifeID,
		RootLifeID: before.RootLifeID, StarterChain: append([]api.ID{}, before.StarterChain...), StarterEventSeq: before.StarterEventSeq,
		OperationID: resume.Operation.ID, RequestID: scope.Request.RequestID, RequestSHA256: scope.Request.RequestSHA256,
		RequestedBy: scope.Actor, OriginalRequest: original, PreviousLaunchID: before.LaunchID}
	if err := api.ValidateLaunchReservation(r); err != nil {
		t.Fatalf("fixture launch reservation: %v", err)
	}
	reservationRef := m.fixtureReviewJSON(t, "fixture-reservation-record", "manifest", r)
	source := api.ProjectLaunchSource{EnrollmentID: "fixture-project-enrollment", Generation: 1,
		ProjectID: "fixture-project", GrantID: "fixture-main-data", Base: strings.Repeat("a", 40), HistoryScope: "tree",
		Object: m.fixtureReviewJSON(t, "fixture-project-source", "manifest", map[string]string{"schema": "fixture.project", "tree": "empty"})}
	runtimeBytes := m.putBlob("fixture-runtime-bytes", "manifest", []byte("synthetic runtime executable"))
	executable := api.Executable{ID: "fixture-runtime", SHA256: runtimeBytes.SHA256, Version: "fixture-v1"}
	supervisorBytes := m.putBlob("fixture-supervisor-bytes", "manifest", []byte("synthetic capture supervisor"))
	supervisor := api.Executable{ID: "fixture-supervisor", SHA256: supervisorBytes.SHA256, Version: "fixture-v1"}
	runtimeManifest := m.fixtureReviewJSON(t, "fixture-runtime-manifest", "manifest", api.RuntimeManifest{
		Schema: "laneboss.runtime.v2", Generation: 1, Artifact: executable, Bootstrap: supervisor,
		Objects: []api.RuntimeObject{}, Bindings: []api.InstalledBinding{}})
	runtime := api.LaunchRuntime{EnrollmentID: "fixture-runtime-enrollment", Generation: 1,
		Backend: "linux-bwrap-landlock", Driver: r.Driver, Executable: executable, Manifest: runtimeManifest}
	enrollment := api.LaunchEnrollment{Schema: "laneboss.launch-enrollment.v2", Config: r.Config, Generation: 1,
		Projects: []api.ProjectEnrollment{{ID: source.EnrollmentID, Generation: source.Generation, ProjectID: source.ProjectID,
			Object: source.Object, Base: source.Base, HistoryScope: source.HistoryScope}},
		Runtimes: []api.LaunchRuntime{runtime}, Supervisor: &supervisor}
	if err := api.ValidateLaunchEnrollment(enrollment, r.Config, runtimeManifest); err != nil {
		t.Fatalf("fixture launch enrollment: %v", err)
	}
	enrollmentRef := m.fixtureReviewJSON(t, "fixture-source-enrollment", "manifest", enrollment)
	const expires = api.Timestamp("2100-01-01T00:00:00Z")
	grants := api.GrantSet{ID: r.GrantSetID, LifeID: lane.LifeID, ParentLifeID: r.ParentLifeID, Generation: 1,
		PolicyGeneration: r.PolicyGeneration, ExpiresAt: expires, Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{},
		Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{},
		Data: []api.DataGrant{{ID: source.GrantID, SourceObjectID: source.Object.ID, SourceSHA256: source.Object.SHA256,
			RelativePath: ".", Destination: "/work/main", Delivery: "copy", Access: "rw", HistoryScope: source.HistoryScope, ExpiresAt: expires}},
		Profiles: []api.ProfileGrant{{ID: "fixture-profile-grant", ProfileID: "fixture-profile", Driver: r.Driver, ExpiresAt: expires}}}
	grants.SHA256 = m.fixtureReviewJSON(t, "fixture-grant-source", "manifest", grants).SHA256
	lease := api.HelperLease{ID: "fixture-helper", UID: 12001, GID: 12001, ContainmentID: "fixture-containment", EndpointGeneration: 1}
	workspace := api.Workspace{ID: "fixture-workspace", ProjectID: source.ProjectID, Base: source.Base,
		Branch: "lane/" + string(lane.LifeID), LogicalCWD: "/work/main",
		Snapshot: m.fixtureReviewJSON(t, "fixture-review-snapshot", "manifest", map[string]any{
			"schema": "fixture.workspace", "target": r.Target, "source": source.Object})}
	home := api.PrivateHomeBinding{LifeID: lane.LifeID, RootID: "fixture-home-root", Generation: 1,
		Home: api.PrivateHome{ID: "fixture-home", WorkspaceID: workspace.ID, VendorDirectory: ".fixture", HistoryID: "fixture-history"}}
	materialization := api.Materialization{GrantSetID: grants.ID,
		Manifest: m.fixtureReviewJSON(t, "fixture-materialization", "manifest", workspace),
		Objects: []api.MaterializedObject{{GrantID: source.GrantID, SourceIdentity: "fixture-source-inode",
			DestinationIdentity: "fixture-destination-inode", SnapshotSHA256: workspace.Snapshot.SHA256, WorkspaceID: workspace.ID}}}
	slot := api.CredentialSlot{ID: "fixture-slot", ProfileGrantID: "fixture-profile-grant", ProfileID: "fixture-profile",
		Mode: "fixture", LeaseID: "fixture-credential-lease", ExpiresAt: expires}
	session := lane.Session
	session.HomeID, session.HistoryID, session.LogicalCWD = home.Home.ID, home.Home.HistoryID, workspace.LogicalCWD
	session.VendorID, session.VendorVersion = "fixture-vendor-session", executable.Version
	runner := api.RunnerPlan{Driver: r.Driver, Executable: executable, Argv: []string{"fixture-runtime", "fixture"},
		CWD: workspace.LogicalCWD, EnvironmentNames: []string{}, Prompt: resume.Request.Message,
		Home: home.Home, Slot: slot, Session: session, AdapterVersion: "fixture-v1"}
	capture := api.CaptureBinding{ID: "fixture-capture", Config: r.Config, ReservationID: r.ID, Target: r.Target,
		LaunchID: r.LaunchID, HelperLeaseID: lease.ID, OperationID: r.OperationID, RequestID: r.RequestID, RequestedBy: r.RequestedBy,
		Generation: 1, Status: "registered", WorkerLeaseID: "fixture-capture-lease", EffectID: "fixture-capture-effect",
		ProducerID: "fixture-capture-producer", ProducerGeneration: "fixture-kernel", BootID: "fixture-boot", Supervisor: &supervisor,
		Streams: []api.CaptureStreamBinding{{ID: "stdout", Stream: "stdout", PipeID: "stdout-pipe"}, {ID: "stderr", Stream: "stderr", PipeID: "stderr-pipe"}}}
	plan := api.LaunchPlan{Reservation: r, Inputs: api.LaunchInputs{Grants: grants,
		Sources: api.LaunchSources{ReservationID: r.ID, Project: source, Runtime: runtime}}, Lease: lease,
		Data: api.LaunchData{ReservationID: r.ID, Target: r.Target, LeaseID: lease.ID, Source: source,
			Workspace: workspace, Home: home, Materialization: materialization}, Runner: runner,
		Injection: api.Injection{Target: r.Target, SlotIDs: []api.ID{slot.ID}, TaskSecretNames: []string{},
			TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}, Outcome: "prepared"},
		Budget: resume.Request.Budget, Capture: capture}
	spec := api.LaunchSpec{Kind: "agent", PlanID: r.ID, ID: r.SpecID, Target: r.Target, LaunchID: r.LaunchID,
		Backend: runtime.Backend, UIDLeaseID: lease.ID, Workspace: workspace, Materialization: materialization,
		Grants: grants, Runner: &runner, Injection: plan.Injection, Budget: plan.Budget, EndpointGeneration: lease.EndpointGeneration,
		RuntimeManifest: runtimeManifest, PolicyGeneration: r.PolicyGeneration, Capture: &capture}
	specRef := m.fixtureReviewJSON(t, "fixture-original-spec", "launch_spec", spec)
	handoff := api.PreparedSpecHandoff{Config: r.Config, Spec: spec, OperationID: r.OperationID, RequestID: r.RequestID,
		SpecSHA256: specRef.SHA256, Original: specRef, Cause: api.InternalIntent{ID: "fixture-register-intent", Kind: api.InternalHelperRegister,
			Config: r.Config, Actor: api.Actor{Kind: "service", ID: "fixture-service"}, RequestedBy: r.RequestedBy,
			CauseOperationID: r.OperationID, CauseRequestID: r.RequestID, EffectID: "fixture-register-effect",
			Target: r.Target, CancellationEpoch: r.CancellationEpoch}}
	record := api.LaunchPlanRecord{Reservation: r, Generation: 4, Phase: "bound", Inputs: &plan.Inputs, Plan: &plan, Handoff: &handoff}
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		t.Fatalf("fixture launch plan: %v", err)
	}
	identity := api.LaunchRecord{Kind: "agent", ID: r.LaunchID, Config: r.Config, Target: r.Target,
		ParentLifeID: r.ParentLifeID, RootLifeID: r.RootLifeID, StarterChain: r.StarterChain, StarterEventSeq: r.StarterEventSeq,
		Actor:      api.Actor{Kind: "lane", ID: "fixture-lane-principal", LifeID: lane.LifeID, Level: r.Level, Role: r.Role},
		UIDLeaseID: lease.ID, HostUID: lease.UID, ProcessGeneration: "fixture-gate-generation", ContainmentID: lease.ContainmentID,
		GrantSetID: grants.ID, GrantsSHA256: grants.SHA256, PolicyGeneration: r.PolicyGeneration, EndpointGeneration: lease.EndpointGeneration}
	identityRef := m.fixtureReviewJSON(t, "fixture-identity-record", "manifest", identity)
	identityEvent := api.Event{Schema: 2, ID: "fixture-identity-event", Kind: "identity.bound", Config: r.Config,
		Origin: "service", LifeID: lane.LifeID, Run: lane.Run, Actor: handoff.Cause.Actor, RequestedBy: r.RequestedBy,
		RequestID: r.RequestID, OperationID: r.OperationID, Payload: append([]byte(nil), m.blobs[identityRef.ID]...)}
	m.appendEvent(identityEvent)
	binding := api.LaunchBindingRequest{Record: identity,
		Prepared: api.PreparedLaunch{ID: "fixture-prepared", SpecSHA256: specRef.SHA256, Target: r.Target,
			ContainmentID: lease.ContainmentID, ProcessGeneration: identity.ProcessGeneration,
			EndpointGeneration: lease.EndpointGeneration, GateID: "fixture-gate"},
		Identity: api.IdentityCommit{LaunchID: r.LaunchID, EventID: identityEvent.ID,
			CommittedSeq: m.events[len(m.events)-1].Seq, RecordSHA256: identityRef.SHA256},
		Recovery: &api.LaunchRecovery{PlanID: r.ID, OriginalRequest: r.OriginalRequest, Handoff: handoff, Home: home, Capture: capture}}
	if err := api.ValidateLaunchBindingPlan(binding, plan); err != nil {
		t.Fatalf("fixture launch recovery: %v", err)
	}
	m.reviewLaunch = &fixtureReviewLaunch{Record: record, Binding: binding, ReservationRef: reservationRef, EnrollmentRef: enrollmentRef,
		RecordRef:  m.fixtureReviewJSON(t, "fixture-launch-plan", "manifest", record),
		BindingRef: m.fixtureReviewJSON(t, "fixture-launch-binding", "manifest", binding)}
	lane.LaunchID, lane.GrantSetID, lane.PolicyGeneration = r.LaunchID, r.GrantSetID, r.PolicyGeneration
	lane.Workspace, lane.Session = workspace, session
	m.lanes[lane.LifeID] = lane
	return m.reviewLaunch
}

func (m *memHarness) checkFixtureReviewBytes(t *testing.T, receipt api.ReviewReceipt) {
	t.Helper()
	launch := m.reviewLaunch
	if launch == nil || receipt.Evidence == nil {
		t.Fatal("fixture review omitted retained launch evidence")
	}
	for id, ref := range m.blobRefs {
		raw, exists := m.blobs[id]
		sum := sha256.Sum256(raw)
		if !exists || ref.Bytes != int64(len(raw)) || ref.SHA256 != api.Digest(hex.EncodeToString(sum[:])) {
			t.Fatalf("fixture review object bytes differ from their reference: %s", id)
		}
	}
	r := launch.Record.Reservation
	if !bytes.Equal(m.blobs[r.OriginalRequest.ID], m.reviewResume.Scope.Frame.Bytes()) {
		t.Fatal("fixture review lost original resume bytes")
	}
	var reservation api.LaunchReservation
	var record api.LaunchPlanRecord
	var binding api.LaunchBindingRequest
	var enrollment api.LaunchEnrollment
	for _, object := range []struct {
		ref api.BlobRef
		out any
	}{{launch.ReservationRef, &reservation}, {launch.RecordRef, &record},
		{launch.BindingRef, &binding}, {launch.EnrollmentRef, &enrollment}} {
		if err := api.DecodeObject(m.blobs[object.ref.ID], object.out); err != nil {
			t.Fatalf("fixture review retained object cannot be decoded: %v", err)
		}
	}
	if !reflect.DeepEqual(reservation, r) || !reflect.DeepEqual(record, launch.Record) ||
		!reflect.DeepEqual(binding, launch.Binding) {
		t.Fatal("fixture review changed a retained launch or recovery record")
	}
	plan := record.Plan
	if plan == nil || binding.Recovery == nil {
		t.Fatal("fixture review omitted retained plan or recovery")
	}
	source := plan.Inputs.Sources.Project
	if len(enrollment.Projects) != 1 || len(enrollment.Runtimes) != 1 ||
		enrollment.Projects[0] != (api.ProjectEnrollment{ID: source.EnrollmentID, Generation: source.Generation,
			ProjectID: source.ProjectID, Object: source.Object, Base: source.Base, HistoryScope: source.HistoryScope}) ||
		enrollment.Runtimes[0] != plan.Inputs.Sources.Runtime {
		t.Fatal("fixture review sources differ from retained enrollment")
	}
	if err := api.ValidateLaunchPlanRecord(record); err != nil {
		t.Fatalf("fixture retained plan: %v", err)
	}
	if err := api.ValidateLaunchBindingPlan(binding, *plan); err != nil {
		t.Fatalf("fixture retained recovery: %v", err)
	}
	subject := receipt.Evidence.Subject
	if subject.Target != r.Target || subject.LaunchID != r.LaunchID || subject.Snapshot != plan.Data.Workspace.Snapshot ||
		subject.SessionID != plan.Runner.Session.ID || subject.CaptureBindingID != binding.Recovery.Capture.ID ||
		!reflect.DeepEqual(subject.Streams, binding.Recovery.Capture.Streams) ||
		subject.Generation != m.lanes[r.Target.LifeID].Generation {
		t.Fatal("fixture review subject differs from retained launch")
	}
	identityFound, endFound := false, false
	for _, event := range m.events {
		if event.ID == binding.Identity.EventID && event.Seq == binding.Identity.CommittedSeq && event.Kind == "identity.bound" &&
			event.Actor == binding.Recovery.Handoff.Cause.Actor && event.OperationID == r.OperationID && event.RequestedBy == r.RequestedBy {
			identityFound = true
		}
		if event.ID == subject.EndEventID && event.Seq == subject.EndSeq && event.Kind == "lane.ended" &&
			event.LifeID == r.Target.LifeID && event.Run == r.Target.Run {
			var ended api.RunEndEvent
			if err := api.DecodeObject(event.Payload, &ended); err != nil {
				t.Fatal(err)
			}
			endFound = ended.LaunchID == r.LaunchID && ended.Observation.State == "exited" &&
				ended.Observation.ExitCode != nil && *ended.Observation.ExitCode == 0 &&
				ended.Observation.Survivors != nil && *ended.Observation.Survivors == 0
		}
	}
	if !identityFound || !endFound {
		t.Fatal("fixture review omitted retained identity or end event")
	}
}
