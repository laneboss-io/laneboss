//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

func cleanupHolder(t *testing.T, group string, lease api.HelperLease, boot string) (*exec.Cmd, *os.File, string) {
	t.Helper()
	cgroup, err := os.Open(group)
	if err != nil {
		t.Fatal(err)
	}
	defer cgroup.Close()
	holdRead, holdWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer holdRead.Close()
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		holdWrite.Close()
		t.Fatal(err)
	}
	defer readyRead.Close()
	command := exec.Command("/proc/self/exe", "archive-cg-hold")
	command.Env = []string{}
	command.ExtraFiles = []*os.File{holdRead, readyWrite}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: lease.UID, Gid: lease.GID, Groups: []uint32{}}, UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
	if err := command.Start(); err != nil {
		holdWrite.Close()
		readyWrite.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := holdWrite.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error(err)
		}
		if command.ProcessState == nil {
			if err := command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Error(err)
			}
			if err := command.Wait(); err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Error(err)
				}
			}
		}
	})
	if err := readyWrite.Close(); err != nil {
		t.Fatal(err)
	}
	if err := readyRead.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var ready [1]byte
	if _, err := io.ReadFull(readyRead, ready[:]); err != nil || ready[0] != 1 {
		t.Fatal("cleanup cgroup holder did not become ready")
	}
	generation, err := processGeneration(command.Process.Pid, boot)
	if err != nil {
		t.Fatal(err)
	}
	return command, holdWrite, generation
}

func cleanupWorkerSeal(t *testing.T, b installation, p leaseRecord, group api.ID) *archiveWorker {
	t.Helper()
	r := archiveClaimFixture()
	r.Job.Lease.ID = api.ID(string(p.Lease.ID) + "-aj")
	r.Job.Plan.Argv = append([]string{}, r.Job.Plan.Argv...)
	r.Job.Plan.Argv[len(r.Job.Plan.Argv)-1] = string(r.Job.Lease.ID)
	r.Job.Intent = p.Archive.Intent
	r.Job.Lease.Target, r.Job.Freeze = r.Job.Intent.Request.Target, freezeRef(t, p.Archive.Freeze)
	r.Claim.Record.Effect.Context.Target = r.Job.Lease.Target
	r.Claim.Record.Effect.Context.CancellationEpoch = r.Job.Intent.CancellationEpoch
	r.Job.Plan.Budget = p.Request.Budget
	input := archivejob.Input{Schema: "laneboss.archive-input.v2", JobID: r.Job.ID, Intent: r.Job.Intent, Freeze: r.Job.Freeze, ReceiptID: "archive-receipt", StoreID: "archive-store", Budget: r.Job.Plan.Budget}
	inputBytes := encodeLaunchFixture(t, input)
	r.Job.Lease.Input = api.BlobRef{ID: "archive-input", Class: "archive_input", Bytes: int64(len(inputBytes)), SHA256: digestBytes(inputBytes)}
	r.Job.Plan.Input = r.Job.Lease.Input
	r.Claim.Record.Effect.Worker = &r.Job.Plan
	lease := api.HelperLease{ID: api.ID(string(p.Lease.ID) + "-worker"), ContainmentID: group, UID: b.Lanes[1].UID, GID: b.Lanes[1].GID, EndpointGeneration: b.Generation}
	registration := testSpecRegistration(lease)
	spec := registration.Handoff.Spec
	r.Job.Lease.RuntimeManifest = spec.RuntimeManifest
	spec.PlanID, spec.LaunchID, spec.Target = r.Job.ID, r.LaunchID, r.Job.Lease.Target
	spec.Injection.Target = spec.Target
	spec.Grants.ID, spec.Grants.LifeID = r.Job.Lease.GrantSetID, spec.Target.LifeID
	spec.Worker, spec.Materialization.GrantSetID, spec.Materialization.Manifest = &r.Job.Plan, spec.Grants.ID, r.Job.Freeze
	cause := *r.Claim.Record.Effect.Context
	cause.Kind, cause.Actor = api.InternalHelperRegister, api.Actor{Kind: "service", ID: r.Claim.Record.ClaimantID}
	registration.Handoff.Cause, registration.Handoff.Spec = cause, spec
	registration.Handoff.OperationID, registration.Handoff.RequestID = cause.CauseOperationID, cause.CauseRequestID
	registration.Original = encodeLaunchFixture(t, spec)
	canonical, err := api.CanonicalJSON(registration.Original)
	if err != nil {
		t.Fatal(err)
	}
	registration.Handoff.Original.Bytes, registration.Handoff.Original.SHA256 = int64(len(registration.Original)), digestBytes(registration.Original)
	registration.Handoff.SpecSHA256 = digestBytes(canonical)
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: b.Config, Class: api.EndpointWorker, InstallationGeneration: b.Generation, EndpointGeneration: b.Generation, ServiceUID: b.Service.UID, ServiceGID: b.Service.GID, Socket: "/runtime/laneboss-worker.sock", ArtifactSHA256: b.Artifact.SHA256, ServiceVersion: b.Release.Version, Backend: "linux-bwrap-landlock", LaunchID: r.LaunchID, Target: &spec.Target, WorkerLeaseID: r.Job.Lease.ID}
	if err := validateArchiveSeal(archiveSeal{Reg: r, Spec: registration, Endpoint: endpoint, Input: inputBytes}, b, true); err != nil {
		t.Fatal(err)
	}
	return &archiveWorker{Reg: r, Lease: lease, State: "registered", Created: gateTimestamp(), Spec: &registration, Endpoint: &endpoint, Input: inputBytes}
}

func cleanupWorker(t *testing.T, b installation, p leaseRecord, group api.ID, path string) *archiveWorker {
	t.Helper()
	w := cleanupWorkerSeal(t, b, p, group)
	command, hold, generation := cleanupHolder(t, path, w.Lease, p.BootID)
	if err := hold.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	live := &nativeGate{command: command, state: command.ProcessState, done: make(chan struct{}), released: true}
	close(live.done)
	w.State = "exited"
	w.Gate = &dataGate{Prepared: api.PreparedLaunch{ID: "archive-prepared", GateID: "archive-gate", Target: w.Reg.Job.Lease.Target, ContainmentID: group, ProcessGeneration: generation, SpecSHA256: w.Spec.Handoff.SpecSHA256}, PID: command.Process.Pid, State: "ended"}
	child := archiveChild(p, *w)
	resources := &linuxResources{binding: b}
	observation, err := measureArchiveNative(context.Background(), live, archiveHandle(*w), func() error { return resources.Quiescent(context.Background(), child) })
	if err != nil {
		t.Fatal(err)
	}
	w.Observation = &observation
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
	return w
}
