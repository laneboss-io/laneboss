package linux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type helperTripwire struct{ calls int }

func (h *helperTripwire) Allocate(context.Context, api.HelperLeaseRequest) (api.HelperLease, error) {
	h.calls++
	return api.HelperLease{}, api.NotImplemented("lb-v2-admin", "Allocate")
}

func (h *helperTripwire) Prepare(context.Context, api.HelperLaunchRequest) (api.PreparedLaunch, error) {
	h.calls++
	return api.PreparedLaunch{}, api.NotImplemented("lb-v2-admin", "Prepare")
}

func (h *helperTripwire) Release(context.Context, api.HelperReleaseRequest) (api.ReleaseReceipt, error) {
	h.calls++
	return api.ReleaseReceipt{}, api.NotImplemented("lb-v2-admin", "Release")
}

func (h *helperTripwire) RegisterSpec(context.Context, api.PreparedSpecHandoff) (api.PreparedSpecReceipt, error) {
	h.calls++
	return api.PreparedSpecReceipt{}, api.NotImplemented("lb-v2-admin", "RegisterSpec")
}

func (h *helperTripwire) ResolveRuntime(context.Context, api.PreparedSpecHandoff) (api.ResolvedRuntime, error) {
	h.calls++
	return api.ResolvedRuntime{}, api.NotImplemented("lb-v2-admin", "ResolveRuntime")
}

func (h *helperTripwire) ResolveLaunchSources(context.Context, api.LaunchSourceRequest) (api.LaunchSources, error) {
	h.calls++
	return api.LaunchSources{}, api.NotImplemented("lb-v2-admin", "ResolveLaunchSources")
}

func (h *helperTripwire) ResolveLaunchStorage(context.Context, api.LaunchDataRequest) (api.LaunchStorage, error) {
	h.calls++
	return api.LaunchStorage{}, api.NotImplemented("lb-v2-admin", "ResolveLaunchStorage")
}

func (h *helperTripwire) OpenLaunchDataStorage(context.Context, api.StorageProjectionRequest) (api.StorageProjection, error) {
	h.calls++
	return api.StorageProjection{}, api.NotImplemented("lb-v2-admin", "OpenLaunchDataStorage")
}

func (h *helperTripwire) RegisterCapture(context.Context, api.CaptureRegistrationRequest) (api.CaptureBinding, error) {
	h.calls++
	return api.CaptureBinding{}, api.NotImplemented("lb-v2-admin", "RegisterCapture")
}

func (h *helperTripwire) ReconcileCapture(context.Context, api.CaptureBinding) (api.CaptureBinding, error) {
	h.calls++
	return api.CaptureBinding{}, api.NotImplemented("lb-v2-admin", "ReconcileCapture")
}

func (h *helperTripwire) OpenGate(context.Context, api.HelperOpenRequest) (api.ProcessHandle, error) {
	h.calls++
	return api.ProcessHandle{}, api.NotImplemented("lb-v2-admin", "OpenGate")
}

func (h *helperTripwire) ObserveGate(context.Context, api.HelperObserveRequest) (api.ProcessObservation, error) {
	h.calls++
	return api.ProcessObservation{}, api.NotImplemented("lb-v2-admin", "ObserveGate")
}

func (h *helperTripwire) StopGate(context.Context, api.HelperStopRequest) (api.ProcessObservation, error) {
	h.calls++
	return api.ProcessObservation{}, api.NotImplemented("lb-v2-admin", "StopGate")
}

func (h *helperTripwire) AbortGate(context.Context, api.HelperAbortRequest) (api.AbortReceipt, error) {
	h.calls++
	return api.AbortReceipt{}, api.NotImplemented("lb-v2-admin", "AbortGate")
}

func (h *helperTripwire) ReconcileGate(context.Context, api.HelperReconcileRequest) (api.LaunchReconciliation, error) {
	h.calls++
	return api.LaunchReconciliation{}, api.NotImplemented("lb-v2-admin", "ReconcileGate")
}

func (h *helperTripwire) InspectCredentialTransfer(context.Context, api.CredentialTransfer) ([]api.CredentialDescriptorFact, error) {
	h.calls++
	return nil, api.NotImplemented("lb-v2-admin", "InspectCredentialTransfer")
}

func (h *helperTripwire) ProjectCredentials(context.Context, api.CredentialTransfer) (api.CredentialProjectionReceipt, error) {
	h.calls++
	return api.CredentialProjectionReceipt{}, api.NotImplemented("lb-v2-admin", "ProjectCredentials")
}

func (h *helperTripwire) ObserveCredentials(context.Context, api.ID) (api.CredentialProjectionReceipt, error) {
	h.calls++
	return api.CredentialProjectionReceipt{}, api.NotImplemented("lb-v2-admin", "ObserveCredentials")
}

func (h *helperTripwire) WithdrawCredentials(context.Context, api.CredentialProjectionRecord) (api.CredentialWithdrawalReceipt, error) {
	h.calls++
	return api.CredentialWithdrawalReceipt{}, api.NotImplemented("lb-v2-admin", "WithdrawCredentials")
}

func (h *helperTripwire) CollectCredentialRefresh(context.Context, api.CredentialProjectionRecord) (api.CredentialRefresh, error) {
	h.calls++
	return api.CredentialRefresh{}, api.NotImplemented("lb-v2-admin", "CollectCredentialRefresh")
}

func (h *helperTripwire) RegisterContainment(context.Context, api.ContainmentBinding) error {
	h.calls++
	return api.NotImplemented("lb-v2-admin", "RegisterContainment")
}

func (h *helperTripwire) ResolveContainment(context.Context, api.PeerFacts, api.InstalledBinding) (api.ContainmentBinding, error) {
	h.calls++
	return api.ContainmentBinding{}, api.NotImplemented("lb-v2-admin", "ResolveContainment")
}

func (h *helperTripwire) RevokeContainment(context.Context, api.ID) error {
	h.calls++
	return api.NotImplemented("lb-v2-admin", "RevokeContainment")
}

var _ api.HelperControl = (*helperTripwire)(nil)

func fixtureBlob(name string) api.BlobRef {
	hash := sha256.Sum256([]byte(name))
	return api.BlobRef{ID: api.ID(name), SHA256: api.Digest(hex.EncodeToString(hash[:])),
		Bytes: int64(len(name)), Class: "runtime"}
}

func fixtureSpec() api.LaunchSpec {
	manifest := fixtureBlob("runtime-manifest")
	budget := api.Budget{WallMS: 1000, MemoryBytes: 1024 * 1024, DiskBytes: 1024 * 1024, Processes: 8}
	grants := api.GrantSet{ID: "grants", LifeID: "life", Generation: 1,
		PolicyGeneration: 1, SHA256: fixtureBlob("grants").SHA256}
	return api.LaunchSpec{ID: "spec", Kind: "worker", Target: api.LifeRef{LifeID: "life", Run: 1},
		LaunchID: "launch", Backend: backendName, UIDLeaseID: "lease", EndpointGeneration: 1,
		PolicyGeneration: 1, RuntimeManifest: manifest, Budget: budget, Grants: grants,
		Workspace:       api.Workspace{ID: "workspace", LogicalCWD: "/work/main"},
		Materialization: api.Materialization{GrantSetID: grants.ID, Manifest: fixtureBlob("materialized")},
		Injection:       api.Injection{Target: api.LifeRef{LifeID: "life", Run: 1}, Outcome: "ready"},
		Worker: &api.WorkerPlan{Schema: "laneboss.worker-plan.v2", Kind: "test", GrantSetID: grants.ID,
			Budget: budget, Input: fixtureBlob("input"), Argv: []string{"/usr/bin/tool"},
			Executable: api.Executable{ID: "exe", SHA256: fixtureBlob("exe").SHA256, Version: "1"}},
	}
}

func requireCode(t *testing.T, err error, code api.ErrorCode) {
	t.Helper()
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("expected typed %s, got %v", code, err)
	}
}

func TestLauncherClosesMissingTransport(t *testing.T) {
	helper := &helperTripwire{}
	spec := fixtureSpec()
	s, err := New(Dependencies{Helper: helper, RuntimeManifest: spec.RuntimeManifest})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSpec(spec, spec.RuntimeManifest, time.Now()); err != nil {
		t.Fatal("positive metadata control:", err)
	}
	prepared, err := s.Prepare(context.Background(), spec)
	requireCode(t, err, api.CodeNotImplemented)
	if prepared.ID != "" || prepared.GateID != "" {
		t.Fatal("incomplete prepare invented a gate")
	}
	process := api.ProcessHandle{ID: "process", Target: spec.Target, ContainmentID: "run", Generation: "generation"}
	observed, err := s.Observe(context.Background(), process)
	requireCode(t, err, api.CodeNotImplemented)
	if observed.State != "unknown" || observed.Survivors != nil || observed.ExitCode != nil {
		t.Fatal("unknown containment invented zero or exit")
	}
	stopped, err := s.Stop(context.Background(), process, "stop")
	requireCode(t, err, api.CodeNotImplemented)
	if stopped.Survivors != nil || stopped.State != "unknown" {
		t.Fatal("incomplete stop claimed success")
	}
	zero := uint64(0)
	err = s.Collect(context.Background(), "lease", api.ProcessObservation{
		Handle: process, State: "exited", Survivors: &zero})
	requireCode(t, err, api.CodeNotImplemented)
	requireCode(t, s.Collect(context.Background(), "lease", observed), api.CodeContainmentUnknown)
	requireCode(t, s.Abort(context.Background(), prepared), api.CodeNotImplemented)
	if helper.calls != 0 {
		t.Fatal("unverified control contacted privileged helper")
	}
}

func TestPrepareRejectsNetworkNoLease(t *testing.T) {
	spec := fixtureSpec()
	spec.Grants.Network = []api.NetworkGrant{{ID: "network", EndpointID: "endpoint", Mode: "internet"}}
	s, err := New(Dependencies{Helper: &helperTripwire{}, RuntimeManifest: spec.RuntimeManifest})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Prepare(context.Background(), spec)
	var prerequisite *PrerequisiteError
	if !errors.As(err, &prerequisite) || prerequisite.Check != "controlled_egress" {
		t.Fatal("networked prepare did not require controlled egress")
	}
	requireCode(t, err, api.CodePrerequisite)
}

func TestMetadataRefusesInvalidAuthority(t *testing.T) {
	mutations := []func(*api.LaunchSpec){
		func(s *api.LaunchSpec) { s.Grants.Revoked = true },
		func(s *api.LaunchSpec) { s.Grants.LifeID = "other-life" },
		func(s *api.LaunchSpec) { s.Grants.ExpiresAt = "2000-01-01T00:00:00Z" },
		func(s *api.LaunchSpec) { s.PolicyGeneration++ },
		func(s *api.LaunchSpec) { s.Materialization.GrantSetID = "other-grants" },
		func(s *api.LaunchSpec) { s.Worker.GrantSetID = "other-grants" },
		func(s *api.LaunchSpec) { s.Worker.Argv = []string{"relative"} },
		func(s *api.LaunchSpec) { s.Workspace.LogicalCWD = "/work/main/../other" },
		func(s *api.LaunchSpec) { s.Worker.Executable.SHA256 = "not-a-digest" },
		func(s *api.LaunchSpec) { s.Kind = "agent" },
		func(s *api.LaunchSpec) { s.Injection.Target.Run++ },
		func(s *api.LaunchSpec) { s.Budget.MemoryBytes = 0 },
	}
	for index, mutate := range mutations {
		spec := fixtureSpec()
		mutate(&spec)
		if err := validateSpec(spec, fixtureSpec().RuntimeManifest, time.Now()); err == nil {
			t.Fatalf("metadata mutation %d was accepted", index)
		}
	}
}

func TestPermitAndConstructorChecks(t *testing.T) {
	_, err := New(Dependencies{RuntimeManifest: fixtureBlob("runtime")})
	requireCode(t, err, api.CodePrerequisite)
	_, err = New(Dependencies{Helper: &helperTripwire{}})
	requireCode(t, err, api.CodeIntegrity)
	s := &Service{}
	_, err = s.Launch(context.Background(), api.PreparedLaunch{}, api.LaunchPermit{})
	requireCode(t, err, api.CodeInvalid)
	prepared := api.PreparedLaunch{ID: "prepared", SpecSHA256: fixtureBlob("spec").SHA256,
		Target: api.LifeRef{LifeID: "life", Run: 1}, GateID: "gate", ContainmentID: "containment",
		EndpointGeneration: 1, ProcessGeneration: "generation"}
	permit := api.LaunchPermit{PreparedID: prepared.ID, LaunchID: "launch",
		CommittedSeq: 1, RecordSHA256: fixtureBlob("record").SHA256}
	_, err = s.Launch(context.Background(), prepared, permit)
	requireCode(t, err, api.CodeNotImplemented)
	permit.PreparedID = "other"
	_, err = s.Launch(context.Background(), prepared, permit)
	requireCode(t, err, api.CodeInvalid)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.Prepare(ctx, fixtureSpec())
	requireCode(t, err, api.CodeCancelled)
}

func TestAgentPlansUseTwoDrivers(t *testing.T) {
	for _, driver := range []api.Driver{api.DriverClaudock, api.DriverCodex} {
		spec := fixtureSpec()
		executable := spec.Worker.Executable
		spec.Kind, spec.Worker = "agent", nil
		spec.Grants.Profiles = []api.ProfileGrant{{ID: "profile-grant", ProfileID: "profile", Driver: driver}}
		spec.Runner = &api.RunnerPlan{Driver: driver, Executable: executable,
			Argv: []string{"/usr/bin/driver"}, CWD: spec.Workspace.LogicalCWD,
			Prompt: fixtureBlob("prompt"), InnerSandbox: "off", AdapterVersion: "1",
			Home: api.PrivateHome{ID: "home", WorkspaceID: spec.Workspace.ID, HistoryID: "history"},
			Slot: api.CredentialSlot{ID: "slot", LeaseID: "slot-lease", ProfileGrantID: "profile-grant", ProfileID: "profile"}}
		spec.Runner.Session = api.Session{ID: "session", Driver: driver, HomeID: "home",
			HistoryID: "history", LogicalCWD: spec.Workspace.LogicalCWD}
		spec.Injection.SlotIDs = []api.ID{spec.Runner.Slot.ID}
		spec.Injection.Outcome = "prepared"
		if err := validateSpec(spec, spec.RuntimeManifest, time.Now()); err != nil {
			t.Fatal("supported driver metadata control:", err)
		}
		spec.Runner.Session.HistoryID = "other-history"
		requireCode(t, validateSpec(spec, spec.RuntimeManifest, time.Now()), api.CodeInvalid)
		spec.Runner.Session.HistoryID = "history"
		spec.Runner.Driver = api.Driver("generic")
		requireCode(t, validateSpec(spec, spec.RuntimeManifest, time.Now()), api.CodeForbidden)
	}
}

func TestDraftThreeWorkerPlans(t *testing.T) {
	for _, kind := range []string{"test", "import", "export", "archive", "render", "box_run",
		"channel", "owner_sheet", "gateway"} {
		spec := fixtureSpec()
		spec.Worker.Kind = kind
		if kind == "channel" {
			spec.Worker.Argv = channelArgv("channel-lease")
			spec.Worker.Input.Class = "channel_input"
		}
		if err := validateSpec(spec, spec.RuntimeManifest, time.Now()); err != nil {
			t.Fatal("supported worker metadata control:", err)
		}
	}
	spec := fixtureSpec()
	spec.Worker.Schema = "laneboss.worker.v2"
	requireCode(t, validateSpec(spec, spec.RuntimeManifest, time.Now()), api.CodeInvalid)
	spec = fixtureSpec()
	spec.Worker.Kind = "unregistered"
	requireCode(t, validateSpec(spec, spec.RuntimeManifest, time.Now()), api.CodeInvalid)
}

func TestBackendRejectsOldLabel(t *testing.T) {
	spec := fixtureSpec()
	if err := validateSpec(spec, spec.RuntimeManifest, time.Now()); err != nil {
		t.Fatal("selected backend control:", err)
	}
	for _, name := range []string{"linux", "darwin-seatbelt", ""} {
		spec.Backend = name
		requireCode(t, validateSpec(spec, spec.RuntimeManifest, time.Now()), api.CodeUnsupported)
	}
}
