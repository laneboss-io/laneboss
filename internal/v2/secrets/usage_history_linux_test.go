package secrets

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	fx "laneboss.io/laneboss/internal/v2/store/testfx"
)

// The single writer issues all job, identity, acknowledgement and completion
// rows. A real owned cat process supplies bytes/exit and its process group is
// counted after wait. Connection/containment are post-authentication fixtures;
// this does not authenticate a native confined worker or vendor.
func TestUsageCompletedMetadataAfterExpiry(t *testing.T) {
	ctx := context.Background()
	f := fx.New(t)
	f.Start.Driver, f.Ceiling.Profiles[0].Driver = api.DriverClaudock, api.DriverClaudock
	f.Ceiling.SHA256 = ""
	var err error
	f.Ceiling.SHA256, err = manifest.HashValue(f.Ceiling)
	if err != nil {
		t.Fatal(err)
	}
	f.Replace(t, "grants", f.Ceiling.ID, f.Ceiling.Generation, f.Ceiling)
	f.Admit(t, "lane.start", f.Start)
	f.Reserve(t)
	f.Source(t)
	f.BuildPlanForIdentity(t, true, uint32(os.Geteuid())+1, uint32(os.Getegid())+1)
	f.Spec(t)
	f.Bind(t)
	f.Opened(t)
	selected := f.Plan.Inputs.Grants.Profiles[0]
	input := api.UsageCredentialInput{Schema: "laneboss.usage-input.v1", ProfileGeneration: 1, VendorProfile: string(selected.ProfileID),
		Source: api.SecretGrant{ID: fx.ID(t), Name: "usage-login", SourceHandle: fx.ID(t), Version: "v1", Delivery: "file", Target: "login.json", ExpiresAt: fx.Expiry()},
		Request: api.UsageWindowRequest{Target: f.Reservation.Target, LaunchID: f.Reservation.LaunchID, OperationID: f.Reservation.OperationID, ProfileGrantID: selected.ID, ProfileID: selected.ProfileID, Provider: selected.Provider,
			Executable: f.Plan.Runner.Executable, RuntimeManifest: f.Plan.Inputs.Sources.Runtime.Manifest, AdapterVersion: f.Plan.Runner.AdapterVersion}}
	job, err := f.State.PrepareUsageJob(ctx, f.Execution, input)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := f.State.ClaimEffect(ctx, f.Execution, api.EffectClaimRequest{EffectID: job.Lease.EffectID, ExpectedGeneration: 1, ClaimantID: f.Execution.Actor.ID, Deadline: job.Lease.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "/usr/bin/cat")
	command.Env = []string{}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var output bytes.Buffer
	command.Stdout = &output
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		if !waited {
			if err := command.Process.Kill(); err != nil {
				t.Error(err)
			}
			if err := command.Wait(); err == nil {
				t.Error("killed fixture unexpectedly exited successfully")
			}
		}
	})
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(command.Process.Pid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(stat[strings.LastIndex(string(stat), ")")+2:]))
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(fields) < 20 {
		t.Fatal("cannot measure owned metadata child generation", err)
	}
	generation := strings.TrimSpace(string(boot)) + ":" + fields[19]
	allocation := api.HelperLease{ID: fx.ID(t), UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), ContainmentID: fx.ID(t), EndpointGeneration: 1}
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", Protocol: api.Protocol, APISchema: api.SchemaVersion, ContractRevision: api.ContractRevision, Config: f.Deps.Config, Class: api.EndpointWorker,
		InstallationGeneration: 1, EndpointGeneration: 1, ServiceUID: uint32(os.Geteuid()) + 1000, ServiceGID: uint32(os.Getegid()) + 1000, Socket: "/runtime/laneboss-worker.sock", Backend: "linux-bwrap-landlock",
		ArtifactSHA256: job.Runtime.Executable.SHA256, ServiceVersion: job.Runtime.Executable.Version, LaunchID: job.LaunchID, Target: &job.Lease.Target, WorkerLeaseID: job.Lease.ID}
	injection := api.Injection{Target: job.Lease.Target, Outcome: "prepared", SlotIDs: []api.ID{fx.ID(t)}, GrantIDs: []api.ID{input.Source.ID}, SourceVersions: []string{input.Source.Version}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}}
	handoff, err := f.State.UsageHandoff(ctx, f.Execution, claim, allocation, endpoint, injection)
	if err != nil {
		t.Fatal(err)
	}
	prepared := api.PreparedLaunch{ID: fx.ID(t), GateID: fx.ID(t), Target: job.Lease.Target, ContainmentID: allocation.ContainmentID, EndpointGeneration: 1, SpecSHA256: handoff.SpecSHA256, ProcessGeneration: generation}
	binding, err := f.State.BindUsageWorker(ctx, f.Execution, claim, prepared)
	if err != nil {
		t.Fatal(err)
	}
	facts := api.PeerFacts{HostUID: allocation.UID, HostGID: allocation.GID, HostPID: command.Process.Pid, ProcessGeneration: generation, ContainmentID: allocation.ContainmentID}
	principal, err := f.State.WorkerBinding(ctx, endpoint, facts)
	if err != nil {
		t.Fatal(err)
	}
	source := []byte("PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC\nowned\tplan\tcurrent\t100\t" + time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano) + "\n")
	if _, err := stdin.Write(source); err != nil {
		t.Fatal(err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	err = command.Wait()
	waited = true
	if err != nil || command.ProcessState == nil || !bytes.Equal(output.Bytes(), source) {
		t.Fatal("owned usage child did not produce its measured output", err)
	}
	observed := api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
	connection := &fx.Connection{Identity: fx.ID(t), Endpoint: endpoint, Verified: &fx.Peer{FactsValue: facts}}
	scope := api.Scope{Config: f.Deps.Config, Actor: binding.Record.Actor, LaunchID: binding.Record.ID, EndpointGeneration: 1, PolicyGeneration: 1, Connection: connection, Frame: &fx.Frame{Raw: []byte("post-authentication completion consumer frame")}}
	result := UsageCommandResult{Raw: output.Bytes(), ExitCode: command.ProcessState.ExitCode(), ObservedAt: observed}
	encoded, err := api.CanonicalJSON(fx.JSON(t, result))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := f.State.WorkerResult(ctx, scope, api.WorkerResultSubmission{LeaseID: job.Lease.ID, ExpectedGeneration: principal.Lease.Generation, InputSHA256: job.Lease.Input.SHA256, Result: encoded})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := f.State.RetainObject(ctx, f.Execution, api.RetainObjectRequest{Intent: job.Cause, Object: api.ObjectWrite{ObjectKey: fx.ID(t), Class: "usage_raw", Bytes: source, SHA256: fx.Digest(source), Origin: "service",
		ACL: api.ObjectACL{Config: f.Deps.Config, Owner: job.Actor, LifeID: job.Lease.Target.LifeID, Audience: "service", Generation: 1}, InputRefs: []api.BlobRef{job.Lease.Input, receipt.Result}}})
	if err != nil {
		t.Fatal(err)
	}
	survivors := usageGroupMembers(t, command.Process.Pid)
	if survivors != 0 {
		t.Fatal("owned metadata child has surviving process-group members")
	}
	exit := command.ProcessState.ExitCode()
	end := api.ProcessObservation{Handle: api.ProcessHandle{ID: binding.Record.ID, Target: job.Lease.Target, ContainmentID: allocation.ContainmentID, Generation: generation}, State: "exited", ExitCode: &exit, Survivors: &survivors, ObservedAt: api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))}
	if err := f.State.RecordUsageRetirement(ctx, f.Execution, job.ID, end); err != nil {
		t.Fatal(err)
	}
	expiry, err := time.Parse(time.RFC3339Nano, string(job.Lease.ExpiresAt))
	if err != nil {
		t.Fatal(err)
	}
	service := &Service{deps: Dependencies{Config: f.Deps.Config, Store: f.State, ServiceScope: f.Execution, Clock: &clockFixture{now: expiry.Add(time.Second)}}}
	if _, err := f.State.WorkerBinding(ctx, endpoint, facts); err != nil {
		t.Fatal("retained live-time mapping fixture unexpectedly changed before historical read", err)
	}
	if err := service.usageProducer(ctx, principal, observed, raw); err != nil {
		t.Fatal("completed metadata could not authenticate after worker expiry", err)
	}
	for _, fault := range []string{"identity", "claim", "raw"} {
		changed, ref := principal, raw
		switch fault {
		case "identity":
			changed.Record.UIDLeaseID = fx.ID(t)
		case "claim":
			changed.Claim.Record.Generation++
		case "raw":
			ref.SHA256 = fx.Digest([]byte("foreign raw"))
		}
		if err := service.usageProducer(ctx, changed, observed, ref); err == nil {
			t.Fatal("historical metadata accepted changed original facts", fault)
		}
	}
	if err := api.ValidateWorkerPrincipal(principal, endpoint, facts, api.WorkerInputRead, service.deps.Clock.Now()); err == nil {
		t.Fatal("historical metadata granted live expired authority")
	}
}

func usageGroupMembers(t *testing.T, group int) uint64 {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	var count uint64
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		raw, err := os.ReadFile("/proc/" + entry.Name() + "/stat")
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal("cannot inventory owned process group", err)
		}
		fields := strings.Fields(string(raw[strings.LastIndex(string(raw), ")")+2:]))
		if len(fields) < 3 {
			t.Fatal("cannot parse process-group inventory")
		}
		pgid, err := strconv.Atoi(fields[2])
		if err != nil {
			t.Fatal(err)
		}
		if pgid == group {
			count++
		}
	}
	return count
}
