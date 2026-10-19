package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func launchFixtureBlob(id ID, class string) BlobRef {
	data := []byte("fixture bytes for " + string(id))
	sum := sha256.Sum256(data)
	return BlobRef{ID: id, Class: class, Bytes: int64(len(data)), SHA256: Digest(hex.EncodeToString(sum[:]))}
}

func launchFixture(t *testing.T) LaunchPlan {
	t.Helper()
	original := launchFixtureBlob("original-request", "launch_request")
	r := LaunchReservation{ID: "reservation-one", Config: "demo", Mode: "start", Level: 5, Role: "supervisor", Driver: DriverCodex,
		Authority: LaunchAuthority{Kind: "ticket", ID: "root-ticket"}, Target: LifeRef{LifeID: "life-child", Run: 1},
		LaunchID: "launch-one", SpecID: "spec-one", GrantSetID: "child-grants", Generation: 1, CancellationEpoch: 1, PolicyGeneration: 3,
		RootLifeID: "life-child", StarterChain: []ID{}, StarterEventSeq: 0, OperationID: "operation-one", RequestID: "request-one",
		RequestSHA256: original.SHA256, RequestedBy: Actor{Kind: "human", ID: "human-one"}, OriginalRequest: original}
	source := ProjectLaunchSource{EnrollmentID: "project-enrollment", Generation: 1, ProjectID: "project-one", GrantID: "main-data",
		Object: launchFixtureBlob("source-object", "manifest"), Base: strings.Repeat("a", 40), HistoryScope: "reachable"}
	executable := Executable{ID: "runtime-codex", SHA256: launchFixtureBlob("runtime-bytes", "manifest").SHA256, Version: "fixture-v1"}
	runtime := LaunchRuntime{EnrollmentID: "runtime-enrollment", Generation: 2, Backend: "linux-bwrap-landlock",
		Driver: DriverCodex, Executable: executable, Manifest: launchFixtureBlob("runtime-manifest", "manifest")}
	grants := GrantSet{ID: "child-grants", LifeID: r.Target.LifeID, SHA256: launchFixtureBlob("grants", "manifest").SHA256,
		Generation: 1, PolicyGeneration: r.PolicyGeneration, ExpiresAt: "2100-01-01T00:00:00Z", Resources: []ResourceGrant{},
		Data: []DataGrant{{ID: source.GrantID, SourceObjectID: source.Object.ID, SourceSHA256: source.Object.SHA256,
			RelativePath: ".", Destination: "/work/main", Delivery: "copy", Access: "rw", HistoryScope: source.HistoryScope,
			ExpiresAt: "2100-01-01T00:00:00Z"}}, Secrets: []SecretGrant{}, Network: []NetworkGrant{}, Channels: []ChannelGrant{},
		Profiles: []ProfileGrant{{ID: "profile-grant", ProfileID: "profile-one", Driver: DriverCodex, ExpiresAt: "2100-01-01T00:00:00Z"}}}
	lease := HelperLease{ID: "helper-lease", UID: 12001, GID: 12001, ContainmentID: "containment-one", EndpointGeneration: 1}
	workspace := Workspace{ID: "workspace-one", ProjectID: source.ProjectID, Base: source.Base, Branch: "lane/life-child",
		LogicalCWD: "/work/main", Snapshot: launchFixtureBlob("workspace-snapshot", "manifest")}
	home := PrivateHomeBinding{LifeID: r.Target.LifeID, RootID: "home-root", Generation: 1,
		Home: PrivateHome{ID: "home-one", WorkspaceID: workspace.ID, VendorDirectory: ".codex", HistoryID: "history-one"}}
	materialization := Materialization{GrantSetID: grants.ID, Manifest: launchFixtureBlob("materialization", "manifest"),
		Objects: []MaterializedObject{{GrantID: source.GrantID, SourceIdentity: "source-inode", DestinationIdentity: "destination-inode",
			SnapshotSHA256: workspace.Snapshot.SHA256, WorkspaceID: workspace.ID}}}
	slot := CredentialSlot{ID: "slot-one", ProfileGrantID: "profile-grant", ProfileID: "profile-one", Mode: "fixture",
		LeaseID: "credential-lease", ExpiresAt: "2100-01-01T00:00:00Z"}
	runner := RunnerPlan{Driver: DriverCodex, Executable: executable, Argv: []string{"runtime-codex", "fixture"},
		CWD: workspace.LogicalCWD, EnvironmentNames: []string{}, Prompt: launchFixtureBlob("prompt-one", "prompt"), Home: home.Home, Slot: slot,
		Session: Session{ID: "session-one", Driver: DriverCodex, VendorVersion: executable.Version, HomeID: home.Home.ID,
			HistoryID: home.Home.HistoryID, LogicalCWD: workspace.LogicalCWD}, AdapterVersion: "fixture-v1"}
	supervisor := Executable{ID: "capture-supervisor", SHA256: launchFixtureBlob("supervisor-bytes", "manifest").SHA256, Version: "fixture-v1"}
	capture := CaptureBinding{ID: "capture-binding", Config: r.Config, ReservationID: r.ID, Target: r.Target, LaunchID: r.LaunchID,
		HelperLeaseID: lease.ID, OperationID: r.OperationID, RequestID: r.RequestID, RequestedBy: r.RequestedBy, Generation: 1,
		Status: "registered", WorkerLeaseID: "capture-lease", EffectID: "capture-effect", ProducerID: "capture-producer",
		ProducerGeneration: "kernel-generation-one", BootID: "boot-one", Supervisor: &supervisor,
		Streams: []CaptureStreamBinding{{ID: "stream-out", Stream: "stdout", PipeID: "pipe-out"}, {ID: "stream-err", Stream: "stderr", PipeID: "pipe-err"}}}
	return LaunchPlan{Reservation: r, Inputs: LaunchInputs{Grants: grants, Sources: LaunchSources{ReservationID: r.ID, Project: source, Runtime: runtime}},
		Lease: lease, Data: LaunchData{ReservationID: r.ID, Target: r.Target, LeaseID: lease.ID, Source: source,
			Workspace: workspace, Home: home, Materialization: materialization}, Runner: runner,
		Injection: Injection{Target: r.Target, SlotIDs: []ID{slot.ID}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{},
			GrantIDs: []ID{}, SourceVersions: []string{}, Outcome: "prepared"},
		Budget: Budget{WallMS: 1000, CPUSeconds: 1, MemoryBytes: 1 << 20, Processes: 10, DiskBytes: 1 << 20}, Capture: capture}
}

func launchFixtureSpec(plan LaunchPlan) LaunchSpec {
	return LaunchSpec{Kind: "agent", PlanID: plan.Reservation.ID, Capture: &plan.Capture, ID: plan.Reservation.SpecID,
		Target: plan.Reservation.Target, LaunchID: plan.Reservation.LaunchID, Backend: plan.Inputs.Sources.Runtime.Backend,
		UIDLeaseID: plan.Lease.ID, Workspace: plan.Data.Workspace, Materialization: plan.Data.Materialization,
		Grants: plan.Inputs.Grants, Runner: &plan.Runner, Injection: plan.Injection, Budget: plan.Budget,
		EndpointGeneration: plan.Lease.EndpointGeneration, RuntimeManifest: plan.Inputs.Sources.Runtime.Manifest,
		PolicyGeneration: plan.Reservation.PolicyGeneration}
}

func launchFixtureHash(t *testing.T, value any) ([]byte, Digest) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	return canonical, Digest(hex.EncodeToString(sum[:]))
}

func launchFixtureBinding(t *testing.T, plan LaunchPlan) LaunchBindingRequest {
	t.Helper()
	r, spec := plan.Reservation, launchFixtureSpec(plan)
	original, digest := launchFixtureHash(t, spec)
	handoff := PreparedSpecHandoff{Config: r.Config, Spec: spec, OperationID: r.OperationID, RequestID: r.RequestID, SpecSHA256: digest,
		Original: BlobRef{ID: "original-spec", Class: "launch_spec", Bytes: int64(len(original)), SHA256: digest},
		Cause: InternalIntent{ID: "register-intent", Kind: InternalHelperRegister, Config: r.Config, Actor: Actor{Kind: "service", ID: "service-one"},
			RequestedBy: r.RequestedBy, CauseOperationID: r.OperationID, CauseRequestID: r.RequestID, EffectID: "register-effect",
			Target: r.Target, CancellationEpoch: r.CancellationEpoch}}
	record := LaunchRecord{Kind: "agent", ID: r.LaunchID, Config: r.Config, Target: r.Target, RootLifeID: r.RootLifeID, StarterChain: r.StarterChain,
		StarterEventSeq: r.StarterEventSeq, Actor: Actor{Kind: "lane", ID: "principal-child", LifeID: r.Target.LifeID, Level: 5, Role: "supervisor"},
		UIDLeaseID: plan.Lease.ID, HostUID: plan.Lease.UID, ProcessGeneration: "gate-generation", ContainmentID: plan.Lease.ContainmentID,
		GrantSetID: plan.Inputs.Grants.ID, GrantsSHA256: plan.Inputs.Grants.SHA256, PolicyGeneration: r.PolicyGeneration, EndpointGeneration: plan.Lease.EndpointGeneration}
	_, recordDigest := launchFixtureHash(t, record)
	return LaunchBindingRequest{Record: record,
		Prepared: PreparedLaunch{ID: "prepared-one", SpecSHA256: digest, Target: r.Target, ContainmentID: record.ContainmentID,
			ProcessGeneration: record.ProcessGeneration, EndpointGeneration: record.EndpointGeneration, GateID: "gate-one"},
		Identity: IdentityCommit{LaunchID: r.LaunchID, EventID: "identity-event", CommittedSeq: 10, RecordSHA256: recordDigest},
		Recovery: &LaunchRecovery{PlanID: r.ID, OriginalRequest: r.OriginalRequest, Handoff: handoff, Home: plan.Data.Home, Capture: plan.Capture}}
}

func requireLaunchInvalid(t *testing.T, err error, diagnostic string) {
	t.Helper()
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != CodeInvalid || typed.Owner != "lb-v2-integrate" {
		t.Fatalf("%s: expected typed invalid_request, got %v", diagnostic, err)
	}
}

func TestLaunchReservationShape(t *testing.T) {
	for _, mode := range []string{"start", "adopt", "resume", "turn", "continue"} {
		t.Run(mode, func(t *testing.T) {
			r := launchFixture(t).Reservation
			r.Mode = mode
			if mode != "start" && mode != "adopt" {
				r.Target.Run, r.BaseGeneration, r.Generation, r.PreviousLaunchID = 2, 1, 2, "previous-launch"
				r.Authority = LaunchAuthority{Kind: "proof", ID: "human-proof"}
				if mode == "continue" {
					r.Authority = LaunchAuthority{Kind: "starter", ID: r.PreviousLaunchID}
				}
			}
			if err := ValidateLaunchReservation(r); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("child_ancestry", func(t *testing.T) {
		r := launchFixture(t).Reservation
		r.ParentLifeID, r.RootLifeID, r.StarterChain, r.StarterEventSeq = "parent-life", "root-life", []ID{"root-life", "parent-life"}, 5
		r.RequestedBy = Actor{Kind: "lane", ID: "parent-principal", LifeID: "parent-life", Level: 6, Role: "supervisor"}
		r.Authority = LaunchAuthority{Kind: "starter", ID: "parent-launch"}
		if err := ValidateLaunchReservation(r); err != nil {
			t.Fatal(err)
		}
	})
	for _, principal := range []string{"service", "scheduler", "watchdog"} {
		t.Run("continue_"+principal, func(t *testing.T) {
			r := launchFixture(t).Reservation
			r.Mode, r.Target.Run, r.BaseGeneration, r.Generation, r.PreviousLaunchID = "continue", 2, 1, 2, "previous-launch"
			r.RequestedBy = Actor{Kind: principal, ID: ID(principal + "-one")}
			r.Authority = LaunchAuthority{Kind: "starter", ID: r.PreviousLaunchID}
			if err := ValidateLaunchReservation(r); err != nil {
				t.Fatal(err)
			}
		})
	}
	for name, change := range map[string]func(*LaunchReservation){
		"child_path":      func(r *LaunchReservation) { r.Target.LifeID = "../caller-child" },
		"new_base":        func(r *LaunchReservation) { r.BaseGeneration = 1 },
		"new_run":         func(r *LaunchReservation) { r.Target.Run = 2 },
		"reused_id":       func(r *LaunchReservation) { r.SpecID = r.LaunchID },
		"missing_request": func(r *LaunchReservation) { r.OriginalRequest = BlobRef{} },
		"unknown_mode":    func(r *LaunchReservation) { r.Mode = "replace" },
		"foreign_root":    func(r *LaunchReservation) { r.RootLifeID = "foreign-life" },
		"root_sequence":   func(r *LaunchReservation) { r.StarterEventSeq = 5 },
		"child_sequence": func(r *LaunchReservation) {
			r.ParentLifeID, r.RootLifeID, r.StarterChain = "parent-life", "root-life", []ID{"root-life", "parent-life"}
		},
		"chain_order": func(r *LaunchReservation) {
			r.ParentLifeID, r.RootLifeID, r.StarterChain, r.StarterEventSeq = "parent-life", "root-life", []ID{"parent-life", "root-life"}, 5
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := launchFixture(t).Reservation
			change(&r)
			requireLaunchInvalid(t, ValidateLaunchReservation(r), "invalid reservation accepted")
		})
	}
}

func TestLaunchPlanShape(t *testing.T) {
	for _, driver := range []Driver{DriverCodex, DriverClaudock} {
		p := launchFixture(t)
		p.Reservation.Driver = driver
		p.Inputs.Sources.Runtime.Driver, p.Inputs.Grants.Profiles[0].Driver, p.Runner.Driver, p.Runner.Session.Driver = driver, driver, driver, driver
		if driver == DriverClaudock {
			p.Runner.Session.VendorVersion = "fixture-claude-v2"
		}
		if err := ValidateLaunchPlan(p); err != nil {
			t.Fatal(err)
		}
	}
	for name, change := range map[string]func(*LaunchPlan){
		"grant_child":      func(p *LaunchPlan) { p.Inputs.Grants.LifeID = "foreign-child" },
		"grant_policy":     func(p *LaunchPlan) { p.Inputs.Grants.PolicyGeneration++ },
		"project_object":   func(p *LaunchPlan) { p.Inputs.Grants.Data[0].SourceObjectID = "foreign-object" },
		"workspace_path":   func(p *LaunchPlan) { p.Data.Workspace.LogicalCWD = "/caller/work" },
		"workspace_branch": func(p *LaunchPlan) { p.Data.Workspace.Branch = "caller-branch" },
		"home_life":        func(p *LaunchPlan) { p.Data.Home.LifeID = "foreign-life" },
		"home_path":        func(p *LaunchPlan) { p.Data.Home.Home.VendorDirectory = "../../shared" },
		"materialization":  func(p *LaunchPlan) { p.Data.Materialization.GrantSetID = "foreign-grants" },
		"runtime":          func(p *LaunchPlan) { p.Runner.Executable.ID = "caller-runtime" },
		"history":          func(p *LaunchPlan) { p.Runner.Session.HistoryID = "shared-history" },
		"vendor_version":   func(p *LaunchPlan) { p.Runner.Session.VendorVersion = "" },
		"profile":          func(p *LaunchPlan) { p.Runner.Slot.ProfileGrantID = "foreign-profile" },
		"capture_missing":  func(p *LaunchPlan) { p.Capture = CaptureBinding{} },
		"capture_launch":   func(p *LaunchPlan) { p.Capture.LaunchID = "foreign-launch" },
	} {
		t.Run(name, func(t *testing.T) {
			p := launchFixture(t)
			change(&p)
			requireLaunchInvalid(t, ValidateLaunchPlan(p), "invalid launch plan accepted")
		})
	}
}

func TestLaunchEnrollmentShape(t *testing.T) {
	p := launchFixture(t)
	project := p.Inputs.Sources.Project
	base := LaunchEnrollment{Schema: "laneboss.launch-enrollment.v2", Config: p.Reservation.Config, Generation: 1,
		Projects: []ProjectEnrollment{{ID: project.EnrollmentID, Generation: project.Generation, ProjectID: project.ProjectID,
			Object: project.Object, Base: project.Base, HistoryScope: project.HistoryScope}},
		Runtimes: []LaunchRuntime{p.Inputs.Sources.Runtime}, Supervisor: p.Capture.Supervisor}
	if err := ValidateLaunchEnrollment(base, base.Config, p.Inputs.Sources.Runtime.Manifest); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"config", "duplicate_project", "duplicate_driver", "manifest", "host_path", "third_driver"} {
		t.Run(fault, func(t *testing.T) {
			encoded, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			var changed LaunchEnrollment
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "config":
				changed.Config = "other"
			case "duplicate_project":
				changed.Projects = append(changed.Projects, changed.Projects[0])
			case "duplicate_driver":
				changed.Runtimes = append(changed.Runtimes, changed.Runtimes[0])
			case "manifest":
				changed.Runtimes[0].Manifest.ID = "other-manifest"
			case "host_path":
				changed.Projects[0].Object.ID = "/caller/project"
			case "third_driver":
				changed.Runtimes[0].Driver = "shell"
			}
			requireLaunchInvalid(t, ValidateLaunchEnrollment(changed, base.Config, p.Inputs.Sources.Runtime.Manifest), "untrusted launch enrollment accepted")
		})
	}
}

func TestLaunchInputReservation(t *testing.T) {
	p := launchFixture(t)
	if err := validateLaunchInputs(p.Reservation, p.Inputs); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"grant_id", "child", "policy"} {
		t.Run(fault, func(t *testing.T) {
			changed := launchFixture(t)
			switch fault {
			case "grant_id":
				changed.Inputs.Grants.ID = "other-grants"
			case "child":
				changed.Inputs.Grants.LifeID = "other-child"
			case "policy":
				changed.Inputs.Grants.PolicyGeneration++
			}
			requireLaunchInvalid(t, validateLaunchInputs(changed.Reservation, changed.Inputs), "launch inputs escaped their reservation")
		})
	}
}

func TestAgentSpecPlanBinding(t *testing.T) {
	p := launchFixture(t)
	if err := ValidateAgentLaunchSpec(launchFixtureSpec(p), p); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*LaunchSpec){
		"plan":    func(s *LaunchSpec) { s.PlanID = "foreign-reservation" },
		"runtime": func(s *LaunchSpec) { s.RuntimeManifest.ID = "caller-runtime" },
		"capture": func(s *LaunchSpec) { s.Capture = nil },
		"budget":  func(s *LaunchSpec) { s.Budget.WallMS++ },
		"backend": func(s *LaunchSpec) { s.Backend = "darwin-seatbelt" },
	} {
		t.Run(name, func(t *testing.T) {
			s := launchFixtureSpec(p)
			change(&s)
			requireLaunchInvalid(t, ValidateAgentLaunchSpec(s, p), "spec escaped its retained plan")
		})
	}
}

func TestLaunchRecoveryBinding(t *testing.T) {
	p := launchFixture(t)
	if err := ValidateLaunchBindingPlan(launchFixtureBinding(t, p), p); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*LaunchBindingRequest){
		"missing": func(b *LaunchBindingRequest) { b.Recovery = nil },
		"request": func(b *LaunchBindingRequest) { b.Recovery.OriginalRequest.ID = "other-request" },
		"home":    func(b *LaunchBindingRequest) { b.Recovery.Home.RootID = "new-home" },
		"capture": func(b *LaunchBindingRequest) { b.Recovery.Capture.ID = "other-capture" },
		"spec_digest": func(b *LaunchBindingRequest) {
			b.Recovery.Handoff.SpecSHA256 = launchFixtureBlob("other-spec", "manifest").SHA256
		},
		"prepared": func(b *LaunchBindingRequest) { b.Prepared.ID = b.Record.ID },
		"record_digest": func(b *LaunchBindingRequest) {
			b.Identity.RecordSHA256 = launchFixtureBlob("other-record", "manifest").SHA256
		},
		"uncommitted": func(b *LaunchBindingRequest) { b.Identity.CommittedSeq = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			b := launchFixtureBinding(t, p)
			change(&b)
			requireLaunchInvalid(t, ValidateLaunchBindingPlan(b, p), "recovery escaped its committed binding")
		})
	}
}

func TestLaunchPlanPhases(t *testing.T) {
	p := launchFixture(t)
	handoff := launchFixtureBinding(t, p).Recovery.Handoff
	for _, phase := range []string{"reserved", "sourced", "planned", "spec_retained", "bound", "opened", "failed"} {
		t.Run(phase, func(t *testing.T) {
			r := LaunchPlanRecord{Reservation: p.Reservation, Generation: 1, Phase: phase}
			if phase != "reserved" && phase != "failed" {
				r.Inputs = &p.Inputs
			}
			if phase == "planned" || phase == "spec_retained" || phase == "bound" || phase == "opened" {
				r.Plan = &p
			}
			if phase == "spec_retained" || phase == "bound" || phase == "opened" {
				r.Handoff = &handoff
			}
			if phase == "failed" {
				r.Error = NotImplemented("lb-v2-lifecycle", "fixture")
			}
			if err := ValidateLaunchPlanRecord(r); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, phase := range []string{"sourced", "planned", "spec_retained", "bound", "opened", "failed", "unknown"} {
		t.Run("incomplete_"+phase, func(t *testing.T) {
			r := LaunchPlanRecord{Reservation: p.Reservation, Generation: 1, Phase: phase}
			requireLaunchInvalid(t, ValidateLaunchPlanRecord(r), "incomplete launch phase accepted")
		})
	}
	t.Run("handoff_required", func(t *testing.T) {
		r := LaunchPlanRecord{Reservation: p.Reservation, Generation: 3, Phase: "bound", Inputs: &p.Inputs, Plan: &p}
		requireLaunchInvalid(t, ValidateLaunchPlanRecord(r), "bound launch omitted its retained handoff")
	})
}

func TestLaunchSelectorShapes(t *testing.T) {
	for name, destination := range map[string]any{"reservation": &LaunchReservationRequest{}, "grants": &GrantResolveRequest{}, "sources": &LaunchSourceRequest{}, "data": &LaunchDataRequest{}} {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(destination)
			if err != nil {
				t.Fatal(err)
			}
			if err := DecodeObject(encoded, destination); err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"child_id", "workspace_path", "executable"} {
				fields[field] = json.RawMessage(`"caller-choice"`)
				bad, err := json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
				requireLaunchInvalidJSON(t, bad, destination)
				delete(fields, field)
			}
		})
	}
}

func requireLaunchInvalidJSON(t *testing.T, data []byte, destination any) {
	t.Helper()
	var typed *Error
	if err := DecodeObject(data, destination); !errors.As(err, &typed) || typed.Code != CodeInvalid {
		t.Fatalf("launch selector accepted caller authority fields: %v", err)
	}
}

func TestLaunchPlanWriteAuthority(t *testing.T) {
	p := launchFixture(t)
	intent := InternalIntent{ID: "plan-intent", Kind: InternalLaunchPlan, Config: p.Reservation.Config, Target: p.Reservation.Target,
		Actor: Actor{Kind: "service", ID: "service-one"}, RequestedBy: p.Reservation.RequestedBy, CauseOperationID: p.Reservation.OperationID,
		CauseRequestID: p.Reservation.RequestID, EffectID: "plan-effect", CancellationEpoch: p.Reservation.CancellationEpoch}
	record := LaunchPlanRecord{Reservation: p.Reservation, Generation: 2, Phase: "planned", Inputs: &p.Inputs, Plan: &p}
	tx := Transaction{Scope: Scope{Config: intent.Config}, Internal: &intent,
		Writes: StateWrites{LaunchPlans: []LaunchPlanRecord{record}}, Compare: []Compare{{Kind: CompareLaunchPlan, ID: p.Reservation.ID, Generation: 1}},
		Guards: []TransactionGuard{{Cancellation: &CancellationCheck{LifeID: p.Reservation.Target.LifeID, Epoch: p.Reservation.CancellationEpoch}}}}
	if err := ValidateTransactionShape(tx); err != nil {
		t.Fatal(err)
	}
	withoutCAS := tx
	withoutCAS.Compare = nil
	if ValidateTransactionShape(withoutCAS) == nil {
		t.Fatal("launch plan write omitted its reservation CAS")
	}
	withoutEpoch := tx
	withoutEpoch.Guards = nil
	if ValidateTransactionShape(withoutEpoch) == nil {
		t.Fatal("launch plan write omitted its cancellation fence")
	}
	bad := tx
	bad.Writes.Policy = &EffectivePolicy{}
	if ValidateTransactionShape(bad) == nil {
		t.Fatal("launch planner wrote policy outside its authority")
	}
	bad = tx
	bad.Internal = &InternalIntent{ID: "other-intent", Kind: InternalObjectRetain, Config: intent.Config}
	if ValidateTransactionShape(bad) == nil {
		t.Fatal("unrelated worker wrote launch plans")
	}
	// The public write catalog remains closed even when the record is valid.
	bad = tx
	bad.Internal = nil
	bad.Scope.Request.Method = "lane.start"
	result, err := json.Marshal(Operation{ID: "operation-one", Status: "pending"})
	if err != nil {
		t.Fatal(err)
	}
	bad.Reply = &RPCReply{Result: result}
	if ValidateTransactionShape(bad) == nil {
		t.Fatal("public transaction wrote store-issued launch plans")
	}
	if EventSchemas["capture.bound"] != reflect.TypeFor[CaptureBinding]() || EventSchemas["launch.planned"] != reflect.TypeFor[LaunchPlanRecord]() {
		t.Fatal("launch and capture events lost their typed payloads")
	}
}

func TestLaunchBoundTransaction(t *testing.T) {
	p := launchFixture(t)
	binding := launchFixtureBinding(t, p)
	r := p.Reservation
	cause := InternalIntent{ID: "prepare-intent", Kind: InternalHelperPrepare, Config: r.Config, Target: r.Target,
		Actor: Actor{Kind: "service", ID: "service-one"}, RequestedBy: r.RequestedBy, CauseOperationID: r.OperationID,
		CauseRequestID: r.RequestID, EffectID: "prepare-effect", CancellationEpoch: r.CancellationEpoch}
	record := LaunchPlanRecord{Reservation: r, Generation: 4, Phase: "bound", Inputs: &p.Inputs, Plan: &p, Handoff: &binding.Recovery.Handoff}
	projection := Lane{LifeID: r.Target.LifeID, Run: r.Target.Run, Generation: r.Generation, GrantSetID: r.GrantSetID, LaunchID: r.LaunchID,
		Level: r.Level, Role: r.Role, Session: p.Runner.Session}
	tx := Transaction{Scope: Scope{Config: r.Config}, Internal: &cause,
		Writes:  StateWrites{LaunchPlans: []LaunchPlanRecord{record}, IdentityBindings: []LaunchBindingRequest{binding}, Lanes: []Lane{projection}},
		Compare: []Compare{{Kind: CompareLaunchPlan, ID: r.ID, Generation: 3}, {Kind: CompareLane, ID: r.Target.LifeID, Generation: r.BaseGeneration}},
		Guards:  []TransactionGuard{{Cancellation: &CancellationCheck{LifeID: r.Target.LifeID, Epoch: r.CancellationEpoch}}}}
	tx = gatePolicyForTest(t, tx, p.Reservation.PolicyGeneration)
	if err := ValidateTransactionShape(tx); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"identity", "lane", "life_cas", "foreign_recovery", "no_plan_bind", "no_plan_lane", "role", "legacy_kind", "event"} {
		t.Run(fault, func(t *testing.T) {
			changed := tx
			switch fault {
			case "identity":
				changed.Writes.IdentityBindings = nil
			case "lane":
				changed.Writes.Lanes = nil
			case "life_cas":
				changed.Compare = changed.Compare[:1]
			case "foreign_recovery":
				other := launchFixtureBinding(t, p)
				other.Recovery.OriginalRequest.ID = "foreign-request"
				changed.Writes.IdentityBindings = []LaunchBindingRequest{other}
			case "no_plan_bind":
				changed.Writes.LaunchPlans = nil
				changed.Writes.Lanes = nil
			case "no_plan_lane":
				changed.Writes.LaunchPlans = nil
				changed.Writes.IdentityBindings = nil
			case "role", "legacy_kind":
				other := launchFixtureBinding(t, p)
				if fault == "role" {
					other.Record.Actor.Role = "executor"
				} else {
					other.Record.Kind = ""
				}
				_, other.Identity.RecordSHA256 = launchFixtureHash(t, other.Record)
				changed.Writes.IdentityBindings = []LaunchBindingRequest{other}
			case "event":
				changed.Writes = StateWrites{}
				changed.Events = []Event{{Kind: "lane.created", LifeID: r.Target.LifeID, Run: r.Target.Run}}
			}
			var typed *Error
			if err := ValidateTransactionShape(changed); !errors.As(err, &typed) || typed.Code != CodeInvalid {
				t.Fatalf("bound launch omitted its atomic ready binding: %v", err)
			}
		})
	}
}
