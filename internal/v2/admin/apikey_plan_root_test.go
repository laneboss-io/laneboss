//go:build linux && laneboss_root_canary

package admin

import (
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// Supply complete synthetic comparison authority to the real journal readers.
// The kernel launch, credential holding and process observations are measured
// separately; none of these metadata fields supplies a successful observation.
func keyPlan(t *testing.T, record *leaseRecord, runtime api.BlobRef, executable api.Executable) api.CredentialProjectionRequest {
	t.Helper()
	a := &record.LaunchAllocations[0]
	a.Reservation.Driver, a.Inputs.Sources.Runtime.Driver = api.DriverClaudock, api.DriverClaudock
	a.Inputs.Sources.Runtime.Manifest, a.Inputs.Sources.Runtime.Executable = runtime, executable
	expires := api.Timestamp(time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))
	slot := api.CredentialSlot{ID: "key-slot", ProfileGrantID: "key-grant", ProfileID: "key-profile", Mode: "claude-api-key", LeaseID: "key-lease", ExpiresAt: expires}
	a.Inputs.Grants.Profiles = []api.ProfileGrant{{ID: slot.ProfileGrantID, ProfileID: slot.ProfileID, Driver: api.DriverClaudock, ExpiresAt: expires}}
	a.Inputs.Grants.SHA256 = ""
	grants, err := canonicalValue(a.Inputs.Grants)
	if err != nil {
		t.Fatal(err)
	}
	a.Inputs.Grants.SHA256 = digestBytes(grants)
	r := a.Reservation
	home := record.Storage.Binding.Home
	source := a.Inputs.Sources.Project
	task := []byte("# API key lane\n")
	ref := func(id api.ID, class string, data []byte) api.BlobRef {
		return api.BlobRef{ID: id, Class: class, Bytes: int64(len(data)), SHA256: digestBytes(data)}
	}
	workspace := api.Workspace{ID: record.Storage.Binding.WorkspaceID, ProjectID: source.ProjectID, Base: source.Base,
		Branch: "lane/" + string(r.Target.LifeID), LogicalCWD: "/work/main", Snapshot: ref("key-snapshot", "manifest", task)}
	material := api.Materialization{GrantSetID: a.Inputs.Grants.ID, Manifest: ref("key-material", "manifest", task),
		Objects: []api.MaterializedObject{{GrantID: source.GrantID, WorkspaceID: workspace.ID, SnapshotSHA256: workspace.Snapshot.SHA256,
			SourceIdentity: string(source.Object.ID), DestinationIdentity: record.Storage.Directories[0].Device + ":" + record.Storage.Directories[0].Inode}}}
	runner := api.RunnerPlan{Driver: api.DriverClaudock, Slot: slot, Home: home.Home, Executable: executable,
		Argv: []string{"/runtime/key-vendor", "key-vendor"}, EnvironmentNames: []string{"ANTHROPIC_API_KEY"}, CWD: "/work/main",
		Prompt: ref("key-prompt", "prompt", task), AdapterVersion: "key-canary",
		Session: api.Session{ID: "key-session", Driver: api.DriverClaudock, VendorVersion: executable.Version,
			HomeID: home.Home.ID, HistoryID: home.Home.HistoryID, LogicalCWD: "/work/main"}}
	cause := record.Request.Cause
	cause.ID, cause.Kind, cause.EffectID = "key-register", api.InternalHelperRegister, "key-register-effect"
	capture, _ := capturePlanFixture()
	capture.Reservation, capture.Request.ReservationID, capture.Request.HelperLeaseID = r, r.ID, record.Lease.ID
	capture.Request.Cause = cause
	capture.Request.Cause.Kind = api.InternalLaunchPlan
	capture.Worker.Target, capture.Worker.OperationID, capture.Worker.EffectID = r.Target, r.OperationID, cause.EffectID
	capture.Worker.RuntimeManifest, capture.Worker.GrantSetID = runtime, r.GrantSetID
	capture.Policy.Generation = r.PolicyGeneration
	disposition, err := refusedCaptureBinding(capture, record.Lease)
	if err != nil {
		t.Fatal(err)
	}
	record.Captures = []captureJournal{{Registration: capture, Binding: disposition}}
	plan := api.LaunchPlan{Reservation: r, Inputs: a.Inputs, Lease: record.Lease, Runner: runner, Budget: record.Request.Budget,
		Data: api.LaunchData{ReservationID: r.ID, Target: r.Target, LeaseID: record.Lease.ID, Source: source,
			Workspace: workspace, Home: home, Materialization: material}, Capture: disposition, CapturePolicy: &capture.Policy,
		Injection: api.Injection{Target: r.Target, SlotIDs: []api.ID{slot.ID}, GrantIDs: []api.ID{}, SourceVersions: []string{},
			TaskSecretNames: []string{}, TaskSecretFileNames: []string{}, Outcome: "prepared"}}
	spec := api.LaunchSpec{ID: r.SpecID, Kind: "agent", PlanID: r.ID, LaunchID: r.LaunchID, Target: r.Target, UIDLeaseID: record.Lease.ID,
		Backend: "linux-bwrap-landlock", RuntimeManifest: runtime, Budget: plan.Budget, Runner: &runner, Capture: &disposition,
		Workspace: workspace, Materialization: material, Grants: a.Inputs.Grants, Injection: plan.Injection,
		EndpointGeneration: record.Lease.EndpointGeneration, PolicyGeneration: r.PolicyGeneration}
	canonical, err := canonicalValue(spec)
	if err != nil {
		t.Fatal(err)
	}
	handoff := api.PreparedSpecHandoff{Config: r.Config, Cause: cause, OperationID: r.OperationID, RequestID: r.RequestID, Spec: spec,
		SpecSHA256: digestBytes(canonical), Original: ref("key-spec-bytes", "launch_spec", canonical)}
	record.Spec = &specRegistration{Plan: &plan, Handoff: handoff, Original: canonical}
	record.SpecReceipt = &api.PreparedSpecReceipt{SpecID: spec.ID, Config: r.Config, Target: r.Target, LeaseID: record.Lease.ID,
		SpecSHA256: handoff.SpecSHA256, RuntimeManifest: runtime, OperationID: r.OperationID}
	prepare := cause
	prepare.ID, prepare.Kind, prepare.EffectID = "key-prepare", api.InternalHelperPrepare, "key-prepare-effect"
	job := api.HelperLaunchRequest{Cause: prepare, LeaseID: record.Lease.ID, PreparedSpecID: spec.ID, SpecSHA256: handoff.SpecSHA256}
	record.Gate = &gateJournal{Request: job, State: "preparing", Prepared: api.PreparedLaunch{ID: "key-prepared", GateID: "key-gate",
		Target: r.Target, SpecSHA256: handoff.SpecSHA256, ContainmentID: record.Lease.ContainmentID, EndpointGeneration: record.Lease.EndpointGeneration}}
	claim := api.EffectLease{ClaimID: "key-claim", ExpiresAt: expires, Record: api.EffectRecord{State: api.EffectClaimed, Generation: 1,
		ClaimID: "key-claim", ClaimantID: prepare.Actor.ID, ClaimExpiresAt: expires, Effect: api.Effect{ID: prepare.EffectID,
			OperationID: prepare.CauseOperationID, Context: &prepare, HelperPrepare: &job}}}
	return api.CredentialProjectionRequest{Cause: prepare, Claim: claim, Handoff: handoff, Lease: record.Lease, Home: home}
}

func keyOpen(t *testing.T, record *leaseRecord) {
	t.Helper()
	plan, prepared := record.Spec.Plan, record.Gate.Prepared
	r := plan.Reservation
	launch := api.LaunchRecord{Kind: "agent", ID: r.LaunchID, Config: r.Config, Target: r.Target, RootLifeID: r.RootLifeID,
		StarterChain: r.StarterChain, StarterEventSeq: r.StarterEventSeq,
		Actor:      api.Actor{Kind: "lane", ID: "key-principal", LifeID: r.Target.LifeID, Level: r.Level, Role: r.Role},
		UIDLeaseID: record.Lease.ID, HostUID: record.Lease.UID, ContainmentID: record.Lease.ContainmentID,
		ProcessGeneration: prepared.ProcessGeneration, EndpointGeneration: prepared.EndpointGeneration,
		GrantSetID: plan.Inputs.Grants.ID, GrantsSHA256: plan.Inputs.Grants.SHA256, PolicyGeneration: r.PolicyGeneration}
	canonical, err := canonicalValue(launch)
	if err != nil {
		t.Fatal(err)
	}
	commit := api.IdentityCommit{LaunchID: launch.ID, EventID: "key-identity", RecordSHA256: digestBytes(canonical), CommittedSeq: 1}
	binding := api.LaunchBindingRequest{Record: launch, Prepared: prepared, Identity: commit,
		Recovery: &api.LaunchRecovery{PlanID: r.ID, OriginalRequest: r.OriginalRequest, Handoff: record.Spec.Handoff,
			Home: plan.Data.Home, Capture: plan.Capture}}
	cause := record.Gate.Request.Cause
	cause.ID, cause.Kind, cause.EffectID = "key-open", api.InternalHelperOpen, "key-open-effect"
	permit := api.LaunchPermit{LaunchID: launch.ID, PreparedID: prepared.ID, RecordSHA256: commit.RecordSHA256, CommittedSeq: commit.CommittedSeq}
	request := api.HelperOpenRequest{Cause: cause, Prepared: prepared, Permit: permit, OperationID: r.OperationID, EffectID: cause.EffectID}
	record.Gate.Permit, record.Gate.State = &permit, "opening"
	record.Gate.Open = &gateOpenRegistration{Request: request, Binding: binding, Policy: *plan.CapturePolicy}
}
