package linux

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// These metadata controls exercise validators, not an installed launch. They
// advance the retained shapes in order, supply no host workspace/home path and
// never return a successful Prepare/Launch or advertise production readiness.
// Real reservation, enrollment, worker and kernel receipts remain E2E inputs.
func metaBlob(name, class string) api.BlobRef {
	ref := fixtureBlob(name)
	ref.Class = class
	return ref
}

func metaJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := api.CanonicalJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func metaHandoff(t *testing.T, spec api.LaunchSpec, cause api.InternalIntent) (api.PreparedSpecHandoff, []byte) {
	t.Helper()
	original := metaJSON(t, spec)
	digest := digestBytes(original)
	return api.PreparedSpecHandoff{Cause: cause, Config: cause.Config, Spec: spec,
		Original:   api.BlobRef{ID: "retained-spec", Class: "launch_spec", SHA256: digest, Bytes: int64(len(original))},
		SpecSHA256: digest, OperationID: cause.CauseOperationID, RequestID: cause.CauseRequestID}, original
}

func planMeta(t *testing.T) (api.LaunchPlanRecord, []byte) {
	t.Helper()
	return planMetaForDriver(t, api.DriverCodex)
}

func planMetaForDriver(t *testing.T, driver api.Driver) (api.LaunchPlanRecord, []byte) {
	t.Helper()
	r := api.LaunchReservation{ID: "reservation", Config: "demo", Mode: "start", Target: api.LifeRef{LifeID: "child-life", Run: 1},
		Level: 5, Role: "supervisor", Driver: driver, Authority: api.LaunchAuthority{Kind: "ticket", ID: "root-ticket"},
		LaunchID: "launch-agent", SpecID: "spec-agent", GrantSetID: "child-grants", Generation: 1,
		CancellationEpoch: 2, PolicyGeneration: 3, RootLifeID: "child-life", StarterChain: []api.ID{},
		OperationID: "operation", RequestID: "request",
		RequestedBy: api.Actor{Kind: "human", ID: "starter"}}
	budget := api.Budget{WallMS: 1000, CPUSeconds: 1, MemoryBytes: 1 << 20, DiskBytes: 1 << 20, Processes: 8}
	r.OriginalRequest, r.RequestSHA256 = reservationInput(t, r, budget)
	record := api.LaunchPlanRecord{Reservation: r, Generation: 1, Phase: "reserved"}
	check := func() {
		t.Helper()
		if err := api.ValidateLaunchPlanRecord(record); err != nil {
			t.Fatal("metadata stage", record.Phase, err)
		}
	}
	check()
	project := api.ProjectLaunchSource{EnrollmentID: "project-entry", Generation: 1, ProjectID: "project", GrantID: "main-data",
		Object: metaBlob("source-object", "manifest"), Base: strings.Repeat("a", 40), HistoryScope: "reachable"}
	runtime := api.LaunchRuntime{EnrollmentID: "runtime-entry", Generation: 1, Backend: backendName, Driver: r.Driver,
		Executable: api.Executable{ID: "driver", Version: "fixture-v1", SHA256: metaBlob("driver-bytes", "runtime").SHA256},
		Manifest:   metaBlob("enrolled-runtime", "manifest")}
	grants := api.GrantSet{ID: r.GrantSetID, LifeID: r.Target.LifeID, Generation: 1, PolicyGeneration: r.PolicyGeneration,
		SHA256: metaBlob("grant-bytes", "manifest").SHA256, ExpiresAt: "2100-01-01T00:00:00Z",
		Resources: []api.ResourceGrant{}, Secrets: []api.SecretGrant{}, Network: []api.NetworkGrant{}, Channels: []api.ChannelGrant{},
		Data: []api.DataGrant{{ID: project.GrantID, SourceObjectID: project.Object.ID, SourceSHA256: project.Object.SHA256,
			RelativePath: ".", Access: "rw", Delivery: "copy", Destination: "/work/main", HistoryScope: project.HistoryScope,
			ExpiresAt: "2100-01-01T00:00:00Z"}},
		Profiles: []api.ProfileGrant{{ID: "profile-grant", ProfileID: "profile", Driver: runtime.Driver, ExpiresAt: "2100-01-01T00:00:00Z"}}}
	inputs := api.LaunchInputs{Grants: grants, Sources: api.LaunchSources{ReservationID: r.ID, Project: project, Runtime: runtime}}
	record.Inputs, record.Phase, record.Generation = &inputs, "sourced", 2
	check()
	lease := api.HelperLease{ID: "lease", UID: 12001, GID: 12001, ContainmentID: "containment", EndpointGeneration: 4}
	workspace := api.Workspace{ID: "workspace", ProjectID: project.ProjectID, Base: project.Base,
		Branch: "lane/" + string(r.Target.LifeID), LogicalCWD: "/work/main", Snapshot: metaBlob("workspace-bytes", "manifest")}
	vendorDirectory, program := ".codex", "/usr/bin/codex"
	if r.Driver == api.DriverClaudock {
		vendorDirectory, program = ".claude", "/usr/bin/claudock"
	}
	home := api.PrivateHomeBinding{LifeID: r.Target.LifeID, RootID: "private-root", Generation: 1,
		Home: api.PrivateHome{ID: "home", WorkspaceID: workspace.ID, VendorDirectory: vendorDirectory, HistoryID: "history"}}
	materialization := api.Materialization{GrantSetID: grants.ID, Manifest: metaBlob("materialization", "manifest"),
		Objects: []api.MaterializedObject{{GrantID: project.GrantID, SourceIdentity: "source-inode", DestinationIdentity: "private-inode",
			WorkspaceID: workspace.ID, SnapshotSHA256: workspace.Snapshot.SHA256}}}
	slot := api.CredentialSlot{ID: "slot", LeaseID: "slot-lease", ProfileGrantID: "profile-grant", ProfileID: "profile",
		Mode: "fixture", ExpiresAt: "2100-01-01T00:00:00Z"}
	runner := api.RunnerPlan{Driver: r.Driver, Executable: runtime.Executable, Argv: []string{program, "fixture"},
		CWD: workspace.LogicalCWD, Home: home.Home, Slot: slot, Prompt: metaBlob("prompt", "prompt"),
		EnvironmentNames: []string{}, InnerSandbox: "off", AdapterVersion: "fixture-v1",
		Session: api.Session{ID: "session", Driver: runtime.Driver, VendorVersion: runtime.Executable.Version,
			HomeID: home.Home.ID, HistoryID: home.Home.HistoryID, LogicalCWD: workspace.LogicalCWD}}
	supervisor := api.Executable{ID: "capture-supervisor", Version: "fixture-v1", SHA256: fixtureBlob("capture-bytes").SHA256}
	capture := api.CaptureBinding{ID: "capture", Config: r.Config, ReservationID: r.ID, Target: r.Target,
		LaunchID: r.LaunchID, HelperLeaseID: lease.ID, OperationID: r.OperationID, RequestID: r.RequestID,
		RequestedBy: r.RequestedBy, Generation: 1, Status: "registered", WorkerLeaseID: "capture-lease", EffectID: "capture-effect",
		ProducerID: "capture-producer", ProducerGeneration: "capture-generation", BootID: "boot", Supervisor: &supervisor,
		Streams: []api.CaptureStreamBinding{{ID: "stdout", Stream: "stdout", PipeID: "pipe-out"}, {ID: "stderr", Stream: "stderr", PipeID: "pipe-err"}}}
	plan := api.LaunchPlan{Reservation: r, Inputs: inputs, Lease: lease,
		Data: api.LaunchData{ReservationID: r.ID, Target: r.Target, LeaseID: lease.ID, Source: project,
			Workspace: workspace, Home: home, Materialization: materialization}, Runner: runner,
		Injection: api.Injection{Target: r.Target, SlotIDs: []api.ID{slot.ID}, Outcome: "prepared",
			TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, GrantIDs: []api.ID{}, SourceVersions: []string{}},
		Budget: budget, Capture: capture}
	record.DataStageID = "materialize-stage"
	record.Plan, record.Phase, record.Generation = &plan, "planned", 3
	check()
	spec := api.LaunchSpec{Kind: "agent", PlanID: r.ID, ID: r.SpecID, LaunchID: r.LaunchID, Target: r.Target,
		Backend: runtime.Backend, UIDLeaseID: lease.ID, Workspace: workspace, Materialization: materialization,
		Grants: grants, Runner: &runner, Injection: plan.Injection, Budget: plan.Budget, Capture: &capture,
		EndpointGeneration: lease.EndpointGeneration, PolicyGeneration: r.PolicyGeneration, RuntimeManifest: runtime.Manifest}
	cause := api.InternalIntent{ID: "register", Kind: api.InternalHelperRegister, Config: r.Config,
		Actor: api.Actor{Kind: "service", ID: "service"}, RequestedBy: r.RequestedBy, Target: r.Target,
		CauseOperationID: r.OperationID, CauseRequestID: r.RequestID, EffectID: "register-effect", CancellationEpoch: r.CancellationEpoch}
	handoff, raw := metaHandoff(t, spec, cause)
	record.Handoff, record.Phase, record.Generation = &handoff, "spec_retained", 4
	check()
	return record, raw
}

func runtimeMeta(record api.LaunchPlanRecord) api.ResolvedRuntime {
	plan, h := record.Plan, record.Handoff
	artifact := api.Executable{ID: "release", Version: "fixture-v1", SHA256: fixtureBlob("release-bytes").SHA256}
	object := api.RuntimeObject{ID: plan.Runner.Executable.ID, RootID: "runtime-root", Role: "runner",
		RelativePath: "bin/codex", Content: metaBlob("driver-bytes", "runtime"), Mode: 0555}
	if plan.Reservation.Driver == api.DriverClaudock {
		object.RelativePath = "bin/claudock"
	}
	target := plan.Reservation.Target
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision,
		Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: h.Config, Class: api.EndpointLane,
		InstallationGeneration: 1, EndpointGeneration: plan.Lease.EndpointGeneration, ServiceUID: 12000, ServiceGID: 12000,
		Socket: "/run/laneboss/lane.sock", ArtifactSHA256: artifact.SHA256, ServiceVersion: artifact.Version,
		Backend: backendName, LaunchID: plan.Reservation.LaunchID, Target: &target}
	return api.ResolvedRuntime{Workspace: plan.Data.Workspace, Home: plan.Data.Home.Home,
		SpecReceipt: api.PreparedSpecReceipt{SpecID: h.Spec.ID, Config: h.Config, Target: h.Spec.Target,
			LeaseID: h.Spec.UIDLeaseID, SpecSHA256: h.SpecSHA256, RuntimeManifest: h.Spec.RuntimeManifest, OperationID: h.OperationID},
		Manifest: api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: artifact, Bootstrap: artifact,
			Objects: []api.RuntimeObject{object}, Bindings: []api.InstalledBinding{endpoint}}}
}

func TestAgentPlanMetadata(t *testing.T) {
	record, raw := planMeta(t)
	h := *record.Handoff
	if err := validateAgentHandoff(h.Spec, h, raw, record); err != nil {
		t.Fatal("retained agent metadata control:", err)
	}
	for name, change := range map[string]func(*api.LaunchSpec){
		"reservation": func(s *api.LaunchSpec) { s.PlanID = "foreign" },
		"executable":  func(s *api.LaunchSpec) { s.Runner.Executable.ID = "caller-executable" },
		"argv":        func(s *api.LaunchSpec) { s.Runner.Argv[0] = "/caller/executable" },
		"cwd":         func(s *api.LaunchSpec) { s.Runner.CWD = "/caller/work" },
		"home":        func(s *api.LaunchSpec) { s.Runner.Home.ID = "shared-home" },
		"manifest":    func(s *api.LaunchSpec) { s.RuntimeManifest.ID = "caller-manifest" },
		"policy":      func(s *api.LaunchSpec) { s.PolicyGeneration++ },
		"grants":      func(s *api.LaunchSpec) { s.Grants.Generation++ },
		"budget":      func(s *api.LaunchSpec) { s.Budget.WallMS++ },
		"capture":     func(s *api.LaunchSpec) { s.Capture = nil },
	} {
		t.Run(name, func(t *testing.T) {
			r, _ := planMeta(t)
			var changed api.LaunchSpec
			if err := api.DecodeObject(metaJSON(t, r.Handoff.Spec), &changed); err != nil {
				t.Fatal(err)
			}
			change(&changed)
			// A replay may present internally consistent new bytes. The original
			// retained plan must still decide, before helper registration.
			handoff, bytes := metaHandoff(t, changed, r.Handoff.Cause)
			if validateAgentHandoff(changed, handoff, bytes, r) == nil {
				t.Fatal("changed agent input escaped the retained plan")
			}
		})
	}
}

func TestAgentRuntimePins(t *testing.T) {
	r, _ := planMeta(t)
	runtime := runtimeMeta(r)
	if err := validateRuntime(*r.Handoff, runtime); err != nil {
		t.Fatal("enrolled runtime shape control:", err)
	}
	if err := validateAgentRuntime(*r.Plan, runtime); err != nil {
		t.Fatal("private storage and executable control:", err)
	}
	for name, change := range map[string]func(*api.ResolvedRuntime){
		"home":       func(r *api.ResolvedRuntime) { r.Home.ID = "shared-home" },
		"workspace":  func(r *api.ResolvedRuntime) { r.Workspace.ID = "foreign-workspace" },
		"executable": func(r *api.ResolvedRuntime) { r.Manifest.Objects[0].ID = "foreign-executable" },
		"bytes":      func(r *api.ResolvedRuntime) { r.Manifest.Objects[0].Content.SHA256 = fixtureBlob("other").SHA256 },
		"mode":       func(r *api.ResolvedRuntime) { r.Manifest.Objects[0].Mode = 0444 },
		"duplicate":  func(r *api.ResolvedRuntime) { r.Manifest.Objects = append(r.Manifest.Objects, r.Manifest.Objects[0]) },
	} {
		t.Run(name, func(t *testing.T) {
			runtime := runtimeMeta(r)
			change(&runtime)
			if validateAgentRuntime(*r.Plan, runtime) == nil {
				t.Fatal("foreign runtime executable or private storage was admitted")
			}
		})
	}
	for _, hostPath := range []string{"/caller/runtime", "../escape"} {
		runtime := runtimeMeta(r)
		object := &runtime.Manifest.Objects[0]
		object.RelativePath = hostPath
		if validateRuntime(*r.Handoff, runtime) == nil {
			t.Fatal("caller runtime path was admitted")
		}
	}
}

func TestAgentGrantExpiry(t *testing.T) {
	r, _ := planMeta(t)
	spec := r.Handoff.Spec
	if err := validateSpec(spec, spec.RuntimeManifest, time.Now()); err != nil {
		t.Fatal("current agent grants metadata control:", err)
	}
	spec.Grants.ExpiresAt = "2000-01-01T00:00:00Z"
	if validateSpec(spec, spec.RuntimeManifest, time.Now()) == nil {
		t.Fatal("expired agent grants were admitted")
	}
}

func TestAgentStageCause(t *testing.T) {
	r, _ := planMeta(t)
	base := r.Handoff.Cause
	base.Kind, base.ID, base.EffectID = api.InternalHelperPrepare, "prepare", "prepare-effect"
	if err := validateStageCause(context.Background(), base, base.Kind, *r.Handoff); err != nil {
		t.Fatal("distinct prepare-stage cause control:", err)
	}
	for name, change := range map[string]func(*api.InternalIntent){
		"requester": func(c *api.InternalIntent) { c.RequestedBy.ID = "foreign" },
		"request":   func(c *api.InternalIntent) { c.CauseRequestID = "foreign" },
		"operation": func(c *api.InternalIntent) { c.CauseOperationID = "foreign" },
		"config":    func(c *api.InternalIntent) { c.Config = "other" },
		"actor":     func(c *api.InternalIntent) { c.Actor.Kind = "lane" },
		"epoch":     func(c *api.InternalIntent) { c.CancellationEpoch++ },
		"intent":    func(c *api.InternalIntent) { c.ID = r.Handoff.Cause.ID },
		"effect":    func(c *api.InternalIntent) { c.EffectID = r.Handoff.Cause.EffectID },
		"target":    func(c *api.InternalIntent) { c.Target.Run++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			change(&changed)
			if validateStageCause(context.Background(), changed, base.Kind, *r.Handoff) == nil {
				t.Fatal("helper stage changed requester, claim or cancellation fence")
			}
		})
	}
}

func TestPlanOpenCause(t *testing.T) {
	r, _ := planMeta(t)
	handoff := *r.Handoff
	parent := handoff.Cause
	parent.Kind, parent.ID = api.InternalLaunchPlan, "planning-cause"
	record := api.EffectRecord{State: api.EffectClaimed, Generation: 2, ClaimID: "current-claim", ClaimantID: "current-executor", ClaimExpiresAt: "2100-01-01T00:00:00Z",
		Effect: api.Effect{ID: parent.EffectID, OperationID: parent.CauseOperationID, Context: &parent,
			PlanLaunch: &api.LaunchPlanEffect{ReservationID: handoff.Spec.PlanID}}}
	lease := api.EffectLease{Record: record, ClaimID: record.ClaimID, ExpiresAt: record.ClaimExpiresAt}
	open := parent
	open.Kind, open.ID, open.Actor = api.InternalHelperOpen, "open-cause", api.Actor{Kind: "service", ID: record.ClaimantID}
	ctx := api.WithEffectLease(context.Background(), lease)
	if err := validateStageCause(ctx, open, api.InternalHelperOpen, handoff); err != nil {
		t.Fatal("live parent planning claim cannot own its native open", err)
	}
	for _, fault := range []string{"missing", "pending", "claim", "expiry", "plan", "context", "actor", "prepare"} {
		t.Run(fault, func(t *testing.T) {
			selected, cause, kind := lease, open, api.InternalHelperOpen
			selected.Record.Effect = lease.Record.Effect
			input := parent
			selected.Record.Effect.Context = &input
			switch fault {
			case "pending":
				selected.Record.State = api.EffectPending
			case "claim":
				selected.ClaimID = "foreign-claim"
			case "expiry":
				selected.ExpiresAt, selected.Record.ClaimExpiresAt = "2000-01-01T00:00:00Z", "2000-01-01T00:00:00Z"
			case "plan":
				selected.Record.Effect.PlanLaunch = &api.LaunchPlanEffect{ReservationID: "foreign-plan"}
			case "context":
				input.CauseRequestID = "foreign-request"
			case "actor":
				cause.Actor.ID = "foreign-executor"
			case "prepare":
				cause.Kind, kind = api.InternalHelperPrepare, api.InternalHelperPrepare
			}
			attemptCtx := api.WithEffectLease(context.Background(), selected)
			if fault == "missing" {
				attemptCtx = context.Background()
			}
			if validateStageCause(attemptCtx, cause, kind, handoff) == nil {
				t.Fatal("open accepted a missing, stale or foreign planning claim")
			}
		})
	}
}

// Generic controls retain the service's real owning refusal. Only the explicit
// retained fixture above implements successful metadata reads and their errors.
func metaControls(t *testing.T) *fixtureControls {
	t.Helper()
	r, bytes := planMeta(t)
	return &fixtureControls{handoff: *r.Handoff, original: bytes}
}

func TestAgentPlanLookup(t *testing.T) {
	r, _ := planMeta(t)
	if err := validatePlanSelector(r, r.Reservation.ID); err != nil {
		t.Fatal("retained selector metadata control:", err)
	}
	if validatePlanSelector(r, "foreign") == nil {
		t.Fatal("foreign reservation escaped the plan lookup")
	}
	record, err := readAgentPlan(context.Background(), metaControls(t), r.Reservation.ID)
	requireCode(t, err, api.CodeNotImplemented)
	if record.Plan != nil || record.Handoff != nil {
		t.Fatal("failed plan read fabricated retained data")
	}
	_, err = readAgentPlan(context.Background(), metaControls(t), "")
	requireCode(t, err, api.CodeInvalid)
}

func TestPreparePhase(t *testing.T) {
	r, _ := planMeta(t)
	if err := validatePreparePhase(r); err != nil {
		t.Fatal("retained preparation phase control:", err)
	}
	for _, phase := range []string{"reserved", "sourced", "planned", "bound", "opened", "failed", "unknown"} {
		r.Phase = phase
		if validatePreparePhase(r) == nil {
			t.Fatal("agent phase allowed another prepared gate")
		}
	}
}

func TestAgentPreparePlanGate(t *testing.T) {
	source := retainedMeta(t)
	helper := &helperTripwire{}
	launcher, err := New(Dependencies{Helper: helper, RuntimeManifest: source.handoff.Spec.RuntimeManifest, Controls: source})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := launcher.Prepare(context.Background(), source.handoff.Spec)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Owner != "lb-v2-admin" || typed.Code != api.CodeNotImplemented ||
		helper.calls != 1 || len(source.reads) != 1 || prepared.ID != "" {
		t.Fatal("agent prepare did not consume the retained plan before registration")
	}
	for _, fault := range []string{"changed", "expired", "claim", "missing", "foreign", "record", "phase"} {
		t.Run(fault, func(t *testing.T) {
			source := retainedMeta(t)
			spec := source.handoff.Spec
			if fault == "changed" {
				spec.Budget.WallMS++
				source.handoff, source.original = metaHandoff(t, spec, source.handoff.Cause)
			} else if fault == "expired" {
				spec.Grants.ExpiresAt = "2000-01-01T00:00:00Z"
			} else if fault == "claim" {
				source.planErr = errors.New("current plan claim is gone")
			} else if fault == "missing" {
				source.planErr = api.NotImplemented("lb-v2-service", "service.Plan")
			} else if fault == "foreign" {
				source.record, source.foreign = foreignMeta(t), true
			} else if fault == "record" {
				source.record.Generation = 0
			} else if fault == "phase" {
				source.record.Phase = "bound"
			}
			helper := &helperTripwire{}
			launcher, err := New(Dependencies{Helper: helper, RuntimeManifest: spec.RuntimeManifest, Controls: source})
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := launcher.Prepare(context.Background(), spec)
			if err == nil || helper.calls != 0 || prepared.ID != "" {
				t.Fatal("agent plan refusal reached helper registration")
			}
			if source.planErr != nil && err != source.planErr {
				t.Fatal("prepare replaced the original plan source error")
			}
		})
	}
}

func TestAgentLostRecovery(t *testing.T) {
	// Use the existing rejected worker protocol tuple as an agent claim. No
	// successful binding or launched process is fabricated for this refusal.
	source, prepared, permit := committedFixture(t)
	source.binding.Record.Kind = "agent"
	source.binding.Record.Actor.Kind = "lane"
	digest, err := canonicalDigest(source.binding.Record)
	if err != nil {
		t.Fatal(err)
	}
	source.binding.Identity.RecordSHA256, permit.RecordSHA256 = digest, digest
	source.open.Permit = permit
	helper := &helperTripwire{}
	launcher, err := New(Dependencies{Helper: helper, RuntimeManifest: source.handoff.Spec.RuntimeManifest, Controls: source})
	if err != nil {
		t.Fatal(err)
	}
	process, err := launcher.Launch(context.Background(), prepared, permit)
	if err == nil || helper.calls != 0 || process.ID != "" {
		t.Fatal("missing agent recovery reached a helper gate")
	}
	requireCode(t, err, api.CodeIntegrity)
}

func TestLaunchRecordDigest(t *testing.T) {
	source, prepared, permit := committedFixture(t)
	if err := validateIdentity(prepared, permit, source.binding); err != nil {
		t.Fatal("retained worker identity shape control:", err)
	}
	record := &source.binding.Record
	record.PolicyGeneration++
	if validateIdentity(prepared, permit, source.binding) == nil {
		t.Fatal("changed committed record escaped its JCS digest")
	}
}

// This is a validator tuple only, never a ControlSource.Binding reply or a
// successful helper receipt. Installed acceptance must obtain these fields
// from real Prepare and the atomic identity.bound transaction instead.
func bindingMeta(t *testing.T, record api.LaunchPlanRecord) api.LaunchBindingRequest {
	t.Helper()
	p, r := record.Plan, record.Reservation
	launch := api.LaunchRecord{Kind: "agent", ID: r.LaunchID, Config: r.Config, Target: r.Target, ParentLifeID: r.ParentLifeID,
		RootLifeID: r.RootLifeID, StarterChain: r.StarterChain, StarterEventSeq: r.StarterEventSeq,
		Actor:      api.Actor{ID: "child-principal", Kind: "lane", LifeID: r.Target.LifeID, Level: r.Level, Role: r.Role},
		UIDLeaseID: p.Lease.ID, HostUID: p.Lease.UID, ContainmentID: p.Lease.ContainmentID,
		ProcessGeneration: "prepared-generation", GrantSetID: p.Inputs.Grants.ID, GrantsSHA256: p.Inputs.Grants.SHA256,
		PolicyGeneration: r.PolicyGeneration, EndpointGeneration: p.Lease.EndpointGeneration}
	digest, err := canonicalDigest(launch)
	if err != nil {
		t.Fatal(err)
	}
	return api.LaunchBindingRequest{Record: launch,
		Prepared: api.PreparedLaunch{ID: "prepared-agent", GateID: "agent-gate", Target: r.Target,
			SpecSHA256: record.Handoff.SpecSHA256, ContainmentID: launch.ContainmentID,
			ProcessGeneration: launch.ProcessGeneration, EndpointGeneration: launch.EndpointGeneration},
		Identity: api.IdentityCommit{LaunchID: r.LaunchID, EventID: "bound-event", CommittedSeq: 9, RecordSHA256: digest},
		Recovery: &api.LaunchRecovery{PlanID: r.ID, OriginalRequest: r.OriginalRequest, Handoff: *record.Handoff,
			Home: p.Data.Home, Capture: p.Capture}}
}

type bindingChange func(*api.LaunchBindingRequest, *api.LaunchPlanRecord)

func TestAgentBindingMetadata(t *testing.T) {
	for _, phase := range []string{"bound", "opened"} {
		r, _ := planMeta(t)
		r.Phase = phase
		binding := bindingMeta(t, r)
		if err := validateAgentBinding(binding, r, r.Handoff.Spec.RuntimeManifest); err != nil {
			t.Fatal("retained recovery shape control:", err)
		}
	}
	for name, change := range map[string]bindingChange{
		"missing": func(b *api.LaunchBindingRequest, r *api.LaunchPlanRecord) { b.Recovery = nil },
		"request": func(b *api.LaunchBindingRequest, r *api.LaunchPlanRecord) { b.Recovery.OriginalRequest.ID = "foreign" },
		"home":    func(b *api.LaunchBindingRequest, r *api.LaunchPlanRecord) { b.Recovery.Home.RootID = "shared" },
		"capture": func(b *api.LaunchBindingRequest, r *api.LaunchPlanRecord) { b.Recovery.Capture.ID = "foreign" },
		"intent": func(b *api.LaunchBindingRequest, r *api.LaunchPlanRecord) {
			b.Recovery.Handoff.Cause.ID = "new-register"
		},
		"phase":  func(b *api.LaunchBindingRequest, r *api.LaunchPlanRecord) { r.Phase = "spec_retained" },
		"policy": func(b *api.LaunchBindingRequest, r *api.LaunchPlanRecord) { b.Record.PolicyGeneration++ },
		"grants": func(b *api.LaunchBindingRequest, r *api.LaunchPlanRecord) {
			b.Record.GrantsSHA256 = fixtureBlob("other").SHA256
		},
		"digest": func(b *api.LaunchBindingRequest, r *api.LaunchPlanRecord) {
			b.Identity.RecordSHA256 = fixtureBlob("other").SHA256
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, _ := planMeta(t)
			r.Phase = "bound"
			binding := bindingMeta(t, r)
			change(&binding, &r)
			if validateAgentBinding(binding, r, r.Handoff.Spec.RuntimeManifest) == nil {
				t.Fatal("agent recovery changed retained request, home, capture or phase")
			}
		})
	}
}

func TestAgentCaptureDisposition(t *testing.T) {
	plan := refusedPlanMeta(t)
	for _, code := range []api.ErrorCode{api.CodeNotImplemented, api.CodeUnavailable, api.CodeUnsupported} {
		plan.Capture.Refusal.Code = code
		if err := api.ValidateLaunchPlan(plan); err != nil {
			t.Fatal("explicit refused capture shape control:", err)
		}
	}
	for _, code := range []api.ErrorCode{api.CodeIntegrity, api.CodeForbidden, api.CodeUnauthenticated, api.CodeContainmentUnknown} {
		plan.Capture.Refusal.Code = code
		if api.ValidateLaunchPlan(plan) == nil {
			t.Fatal("capture guard failure became a launch fallback")
		}
	}
}

type refusedControls struct {
	ControlSource
	err error
}

func (c refusedControls) Handoff(context.Context, api.LaunchSpec) (api.PreparedSpecHandoff, error) {
	return api.PreparedSpecHandoff{}, c.err
}

func (c refusedControls) Binding(context.Context, api.ID) (api.LaunchBindingRequest, error) {
	return api.LaunchBindingRequest{}, c.err
}

func (c refusedControls) Observe(context.Context, api.ProcessHandle) (api.HelperObserveRequest, error) {
	return api.HelperObserveRequest{}, c.err
}

func (c refusedControls) Stop(context.Context, api.ProcessHandle, string) (api.HelperStopRequest, error) {
	return api.HelperStopRequest{}, c.err
}

func (c refusedControls) Abort(context.Context, api.PreparedLaunch) (api.HelperAbortRequest, error) {
	return api.HelperAbortRequest{}, c.err
}

func (c refusedControls) Release(context.Context, api.ID, api.ProcessObservation) (api.HelperReleaseRequest, error) {
	return api.HelperReleaseRequest{}, c.err
}

func TestServiceRefusalsPropagate(t *testing.T) {
	_, prepared, permit := committedFixture(t)
	process := api.ProcessHandle{ID: "process", Target: prepared.Target,
		ContainmentID: prepared.ContainmentID, Generation: prepared.ProcessGeneration}
	zero, exit := uint64(0), 0
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	observation := api.ProcessObservation{Handle: process, State: "exited", Survivors: &zero,
		ExitCode: &exit, PromptStatus: "completed", ObservedAt: api.Timestamp(stamp)}
	for _, code := range []api.ErrorCode{api.CodeNotImplemented, api.CodeForbidden, api.CodeCancelled, api.CodeConflict, api.CodeNotFound} {
		err := &api.Error{Code: code, Owner: "lb-v2-service", Message: "retained claim refusal", Instead: "Reconcile the original claim."}
		helper := &helperTripwire{}
		launcher, newErr := New(Dependencies{Helper: helper, RuntimeManifest: fixtureSpec().RuntimeManifest,
			Controls: refusedControls{err: err}})
		if newErr != nil {
			t.Fatal(newErr)
		}
		_, prepareErr := launcher.Prepare(context.Background(), fixtureSpec())
		_, launchErr := launcher.Launch(context.Background(), prepared, permit)
		observed, observeErr := launcher.Observe(context.Background(), process)
		stopped, stopErr := launcher.Stop(context.Background(), process, "bounded stop")
		abortErr := launcher.Abort(context.Background(), prepared)
		releaseErr := launcher.Collect(context.Background(), "lease", observation)
		for _, actual := range []error{prepareErr, launchErr, observeErr, stopErr, abortErr, releaseErr} {
			if actual != err {
				t.Fatal("service claim refusal was replaced or swallowed")
			}
		}
		if helper.calls != 0 || observed.State != "unknown" || stopped.State != "unknown" ||
			observed.Survivors != nil || stopped.Survivors != nil {
			t.Fatal("service claim refusal invented helper work or quiescence")
		}
	}
}
