package linux

import (
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func secretReviewSpec() api.LaunchSpec {
	spec := fixtureSpec()
	spec.Grants.Secrets = []api.SecretGrant{
		{ID: "env-grant", Name: "token", SourceHandle: "source-env", Version: "v1", Delivery: "env", Target: "TASK_TOKEN"},
		{ID: "file-grant", Name: "file", SourceHandle: "source-file", Version: "v2", Delivery: "file", Target: "tokens/selected"},
	}
	spec.Injection.GrantIDs = []api.ID{"env-grant", "file-grant"}
	spec.Injection.SourceVersions = []string{"v1", "v2"}
	spec.Injection.TaskSecretNames = []string{"TASK_TOKEN"}
	spec.Injection.TaskSecretFileNames = []string{"tokens/selected"}
	return spec
}

func agentReviewSpec() api.LaunchSpec {
	spec := fixtureSpec()
	executable := spec.Worker.Executable
	spec.Kind, spec.Worker = "agent", nil
	spec.Grants.Profiles = []api.ProfileGrant{{ID: "profile-grant", ProfileID: "profile", Driver: api.DriverCodex}}
	spec.Runner = &api.RunnerPlan{Driver: api.DriverCodex, Executable: executable,
		Argv: []string{"/usr/bin/driver"}, CWD: spec.Workspace.LogicalCWD,
		Prompt: fixtureBlob("prompt"), InnerSandbox: "off", AdapterVersion: "1",
		Home: api.PrivateHome{ID: "home", WorkspaceID: spec.Workspace.ID, HistoryID: "history"},
		Slot: api.CredentialSlot{ID: "slot", LeaseID: "slot-lease", ProfileGrantID: "profile-grant", ProfileID: "profile"}}
	spec.Injection.SlotIDs = []api.ID{"slot"}
	spec.Injection.Outcome = "prepared"
	return spec
}

func TestInjectionGrantCorrelation(t *testing.T) {
	control := secretReviewSpec()
	if err := validateSpec(control, control.RuntimeManifest, time.Now()); err != nil {
		t.Fatal("complete injection metadata control:", err)
	}
	for _, change := range []func(*api.LaunchSpec){
		func(s *api.LaunchSpec) { s.Injection.Outcome = "failed" },
		func(s *api.LaunchSpec) { s.Injection.GrantIDs[0] = "ungranted" },
		func(s *api.LaunchSpec) { s.Injection.SourceVersions[0] = "stale" },
		func(s *api.LaunchSpec) { s.Injection.SourceVersions = s.Injection.SourceVersions[:1] },
		func(s *api.LaunchSpec) { s.Injection.SlotIDs = []api.ID{"unexpected-slot"} },
		func(s *api.LaunchSpec) { s.Grants.Secrets[0].ExpiresAt = "2000-01-01T00:00:00Z" },
		func(s *api.LaunchSpec) { s.Injection.TaskSecretNames[0] = "HOME"; s.Grants.Secrets[0].Target = "HOME" },
		func(s *api.LaunchSpec) {
			s.Injection.TaskSecretNames[0] = "LD_PRELOAD"
			s.Grants.Secrets[0].Target = "LD_PRELOAD"
		},
		func(s *api.LaunchSpec) {
			s.Injection.TaskSecretFileNames[0] = "../escape"
			s.Grants.Secrets[1].Target = "../escape"
		},
		func(s *api.LaunchSpec) {
			s.Injection.TaskSecretFileNames[0] = "/absolute"
			s.Grants.Secrets[1].Target = "/absolute"
		},
	} {
		spec := secretReviewSpec()
		change(&spec)
		if err := validateSpec(spec, spec.RuntimeManifest, time.Now()); err == nil {
			t.Fatal("unready, stale, ungranted or unsafe injection was admitted")
		}
	}
	agent := agentReviewSpec()
	if err := validateSpec(agent, agent.RuntimeManifest, time.Now()); err != nil {
		t.Fatal("run-slot correlation control:", err)
	}
	agent.Injection.SlotIDs = nil
	if validateSpec(agent, agent.RuntimeManifest, time.Now()) == nil {
		t.Fatal("runner slot omitted from injection was admitted")
	}
}

func TestLaunchBudgetsAndNetworkModes(t *testing.T) {
	for _, change := range []func(*api.LaunchSpec){
		func(s *api.LaunchSpec) { s.Budget.SpendMicros = -1; s.Worker.Budget = s.Budget },
		func(s *api.LaunchSpec) { s.Budget.DiskBytes = 0; s.Worker.Budget = s.Budget },
		func(s *api.LaunchSpec) {
			s.Grants.Network = []api.NetworkGrant{{ID: "net", EndpointID: "endpoint", Mode: "egress"}}
		},
		func(s *api.LaunchSpec) {
			s.Grants.Network = []api.NetworkGrant{{EndpointID: "endpoint", Mode: "internet"}}
		},
	} {
		spec := fixtureSpec()
		change(&spec)
		if validateSpec(spec, spec.RuntimeManifest, time.Now()) == nil {
			t.Fatal("invalid launch budget or network grant was admitted")
		}
	}
	spec := agentReviewSpec()
	spec.Grants.Profiles[0].Paid = true
	if validateSpec(spec, spec.RuntimeManifest, time.Now()) == nil {
		t.Fatal("paid profile admitted with zero spend")
	}
	spec.Budget.SpendMicros = 1
	if err := validateSpec(spec, spec.RuntimeManifest, time.Now()); err != nil {
		t.Fatal("bounded paid-profile metadata control:", err)
	}
	spec.Runner.InnerSandbox = "unregistered"
	if validateSpec(spec, spec.RuntimeManifest, time.Now()) == nil {
		t.Fatal("arbitrary inner sandbox mode was admitted")
	}
}

func TestOfflineNetworkLeaseFields(t *testing.T) {
	spec := fixtureSpec()
	if err := validateNetwork(spec, api.NetworkLease{}); err != nil {
		t.Fatal("offline zero-lease control:", err)
	}
	for _, lease := range []api.NetworkLease{{NamespaceID: "namespace"}, {GrantSetID: "grants"},
		{EndpointIDs: []api.ID{"endpoint"}}, {Generation: 1}, {PolicySHA256: fixtureBlob("policy").SHA256},
		{ExpiresAt: "2100-01-01T00:00:00Z"}} {
		if validateNetwork(spec, lease) == nil {
			t.Fatal("offline launch retained hidden network lease fields")
		}
	}
}

func TestProcessObservationContract(t *testing.T) {
	handle := api.ProcessHandle{ID: "process", Target: fixtureSpec().Target, ContainmentID: "containment", Generation: "generation"}
	now := api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
	zero, one := uint64(0), uint64(1)
	exit, sig, outside := 0, 9, int(int64(2147483648))
	base := api.ProcessObservation{Handle: handle, State: "running", Survivors: &one, PromptStatus: "not_written", ObservedAt: now}
	if err := validateObservation(handle, base, false); err != nil {
		t.Fatal("running observation control:", err)
	}
	for _, change := range []func(*api.ProcessObservation){
		func(o *api.ProcessObservation) { o.PromptStatus = "invalid" },
		func(o *api.ProcessObservation) { o.ExitCode = &exit },
		func(o *api.ProcessObservation) { o.Signal = &sig },
	} {
		observed := base
		change(&observed)
		if validateObservation(handle, observed, false) == nil {
			t.Fatal("running observation carried a false exit or prompt enum")
		}
	}
	base.State, base.Survivors, base.ExitCode = "exited", &zero, &exit
	if err := validateObservation(handle, base, true); err != nil {
		t.Fatal("known exited observation control:", err)
	}
	for _, change := range []func(*api.ProcessObservation){
		func(o *api.ProcessObservation) { o.ExitCode = nil },
		func(o *api.ProcessObservation) { o.Signal = &sig },
		func(o *api.ProcessObservation) { o.ExitCode = &outside },
		func(o *api.ProcessObservation) { o.ExitCode = nil; o.Signal = &outside },
	} {
		observed := base
		change(&observed)
		if validateObservation(handle, observed, true) == nil {
			t.Fatal("exit/signal exclusivity or signed range was not checked")
		}
	}
}

func TestAbortRequiresUnopenedGate(t *testing.T) {
	_, prepared, _ := committedFixture(t)
	zero := uint64(0)
	now := api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
	request := api.HelperAbortRequest{LeaseID: "lease", PreparedID: prepared.ID}
	base := api.AbortReceipt{ID: "receipt", LeaseID: "lease", PreparedID: prepared.ID, ObservedAt: now,
		Quiescence: api.ProcessObservation{State: "prepared", Survivors: &zero, PromptStatus: "not_written", ObservedAt: now,
			Handle: api.ProcessHandle{Target: prepared.Target, ContainmentID: prepared.ContainmentID, Generation: prepared.ProcessGeneration}}}
	if err := validateAborted(request, prepared, base); err != nil {
		t.Fatal("nonexecuting receipt shape control:", err)
	}
	exit, sig := 0, 9
	for _, change := range []func(*api.AbortReceipt){
		func(r *api.AbortReceipt) { r.Quiescence.State = "exited" },
		func(r *api.AbortReceipt) { r.Quiescence.ExitCode = &exit },
		func(r *api.AbortReceipt) { r.Quiescence.Signal = &sig },
		func(r *api.AbortReceipt) { r.Quiescence.Handle.Generation = "different" },
		func(r *api.AbortReceipt) { r.AgentExecuted = true },
	} {
		receipt := base
		change(&receipt)
		if validateAborted(request, prepared, receipt) == nil {
			t.Fatal("abort admitted an executed, exited or different process generation")
		}
	}
}

func TestInstalledProbeKeepsHost(t *testing.T) {
	// Protocol-shape checks only; this fixture does not call Service.Probe or
	// advertise a working installed backend to another component.
	host := api.IsolationCapabilities{Backend: backendName, Kernel: "6.8.0", LandlockABI: 3,
		Checks: []api.Capability{{Name: "cgroup_v2_mount", Available: true}}}
	measured := api.IsolationCapabilities{Backend: backendName, Kernel: host.Kernel, LandlockABI: host.LandlockABI, Available: true}
	for _, name := range []string{"bwrap_options", "namespace_boundary", "seccomp_deny_filter", "uid_pool",
		"cgroup_containment", "controlled_egress", "runtime_projection", "capture_pipes", "launch_gate"} {
		evidence := fixtureBlob(name)
		measured.Checks = append(measured.Checks, api.Capability{Name: name, Available: true, Evidence: &evidence})
	}
	if err := validateInstalledProbe(host, measured); err != nil {
		t.Fatal("complete probe shape control:", err)
	}
	merged := mergeInstalledProbe(host, measured)
	if len(merged.Checks) != len(measured.Checks)+1 || merged.Checks[0] != host.Checks[0] {
		t.Fatal("current host prerequisite was discarded")
	}
	host.Checks[0].Available = false
	if validateInstalledProbe(host, measured) == nil {
		t.Fatal("installed helper evidence overrode a failed host prerequisite")
	}
}
