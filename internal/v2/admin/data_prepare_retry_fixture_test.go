//go:build linux && laneboss_root_canary

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
)

// This canary measures native preparation/retry and filesystem ownership.
// The separate copy child runs the actual fixed dataworker under its reserved
// UID/cgroup. Bootstrap/acknowledgement metadata are explicit fixtures; this
// does not certify the complete service's identity/result protocol.
func workerStorageRetry(t *testing.T, ctx context.Context, m *leaseManager, reg dataReg) {
	t.Helper()
	parent, index, err := m.findData(reg.Request)
	if err != nil {
		t.Fatal(err)
	}
	job := parent.DataJobs[index]
	lease, token := job.Lease, job.Projection.OpenToken
	starts := &storageStartRecorder{leaseStorage: m.store, manager: m}
	m.store = starts
	if lease.UID == parent.Lease.UID || lease.GID == parent.Lease.GID {
		t.Fatal("two native slots were not reserved")
	}
	child := dataChild(parent, job)
	if err := m.resources.Quiescent(ctx, child); err != nil {
		t.Fatal(err)
	}
	groupPath := filepath.Join(m.binding.cgroupPath(), string(lease.ContainmentID))
	if err := os.Remove(groupPath); err != nil {
		t.Fatal(err)
	}
	_, err = m.prepareData(ctx, reg)
	var refused *api.Error
	if !errors.As(err, &refused) || refused.Code != api.CodeContainmentUnknown || api.HelperReason(err) != "cgroup_open" {
		t.Fatal("missing native containment did not defer preparation", err)
	}
	if starts.barriers != 0 {
		t.Fatal("pre-spawn refusal crossed the durable native-start barrier")
	}
	parent, index, err = m.findData(reg.Request)
	if err != nil {
		t.Fatal(err)
	}
	interrupted := parent.DataJobs[index]
	if interrupted.Gate == nil || interrupted.Gate.PID != 0 || interrupted.Gate.Prepared.ProcessGeneration != "" {
		t.Fatal("pre-spawn refusal acquired an unexplained native lifetime")
	}
	preparedID, gateID := interrupted.Gate.Prepared.ID, interrupted.Gate.Prepared.GateID
	uncertain := interrupted
	gate := *interrupted.Gate
	gate.State = "preparing"
	uncertain.Gate = &gate
	if _, err := m.resumeDataPreparation(ctx, parent, uncertain); !errors.As(err, &refused) || refused.Code != api.CodeContainmentUnknown || api.HelperReason(err) != "data_retry" {
		t.Fatal("legacy or crossed-start preparation was treated as unstarted", err)
	}
	child.Phase = "reserved"
	if err := m.resources.Ensure(ctx, child); err != nil {
		t.Fatal(err)
	}
	workerStorageLiveControl(t, ctx, m, reg, child)
	projection, err := m.openData(ctx, reg)
	if err != nil || projection.OpenToken != token {
		t.Fatal("deferred prepare retry could not resume its original held roots", err)
	}
	closeProc, err := mountHelperProc(m.binding.runtimePath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeProc(); err != nil {
			t.Error(err)
		}
	}()
	prepared, err := m.prepareData(ctx, reg)
	if err != nil {
		t.Fatal("repaired native preparation could not resume", err)
	}
	if starts.barriers != 1 {
		t.Fatal("native start did not retain its pre-creation barrier exactly once")
	}
	parent, index, err = m.findData(reg.Request)
	if err != nil {
		t.Fatal(err)
	}
	job = parent.DataJobs[index]
	if job.Lease != lease || job.Projection.OpenToken != token || prepared.ID != preparedID || prepared.GateID != gateID || prepared.ProcessGeneration == "" {
		t.Fatal("deferred native prepare replaced its reserved slot, gate or token")
	}
	live := m.gates[lease.ID]
	if live == nil {
		t.Fatal("native prepare did not retain its wait owner")
	}
	if err := live.Close(); err != nil {
		t.Fatal(err)
	}
	cleanup, done := context.WithTimeout(ctx, 5*time.Second)
	defer done()
	if _, err := live.Stop(cleanup, dataHandle(job)); err != nil {
		t.Fatal(err)
	}
	if err := m.waitContainmentEmpty(cleanup, dataChild(parent, job)); err != nil {
		t.Fatal(err)
	}
	if err := m.resources.Quiescent(cleanup, dataChild(parent, job)); err != nil {
		t.Fatal(err)
	}
	pins := m.dataPins[token]
	input, err := sealedBootstrap(storageCopyInput{Job: job, Boot: m.bootID, Manifest: pins.manifest})
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	resultRead, resultWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer resultRead.Close()
	defer resultWrite.Close()
	group, err := os.Open(filepath.Join(m.binding.cgroupPath(), string(lease.ContainmentID)))
	if err != nil {
		t.Fatal(err)
	}
	defer group.Close()
	command := exec.CommandContext(ctx, m.binding.binaryPath(), "-test.run=^TestWorkerLaunchNative$", "-test.v", "--", "worker-copy")
	command.Env = []string{}
	command.ExtraFiles = []*os.File{input, pins.roots[0], pins.roots[1], pins.roots[2], resultWrite}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: lease.UID, Gid: lease.GID, Groups: []uint32{}}, UseCgroupFD: true, CgroupFD: int(group.Fd())}
	output, err := command.CombinedOutput()
	resultWrite.Close()
	if err != nil {
		t.Fatalf("actual worker-UID copy failed: %v\n%s", err, output)
	}
	raw, err := io.ReadAll(io.LimitReader(resultRead, api.MaxFrameBytes+1))
	if err != nil {
		t.Fatal(err)
	}
	var result api.LaunchData
	if api.DecodeObject(raw, &result) != nil || result.ReservationID != reg.Reservation.ID || result.LeaseID != parent.Lease.ID || result.Workspace.Snapshot.SHA256 != digestBytes(pins.manifest) {
		t.Fatal("copy child did not produce its actual bound materialization")
	}
	if err := m.resources.Quiescent(cleanup, dataChild(parent, job)); err != nil {
		t.Fatal(err)
	}
	if err := m.returnData(ctx, parent, job, pins.manifest); err != nil {
		t.Fatal(err)
	}
	if err := m.syncLaunchStorage(ctx, &parent, false); err != nil {
		t.Fatal("returned storage does not belong to the agent's original slot", err)
	}
	resolved, err := m.resolveStorage(ctx, launchStorageQuery{Request: api.LaunchDataRequest{ReservationID: reg.Reservation.ID, GrantSetID: reg.Reservation.GrantSetID, LeaseID: parent.Lease.ID}, Reservation: reg.Reservation})
	if err != nil || !reflect.DeepEqual(resolved, job.Projection.Storage) {
		t.Fatal("returned tree changed its original lease binding", err)
	}
	for _, item := range parent.Storage.Directories {
		var info unix.Stat_t
		if unix.Lstat(filepath.Join(laneStagePath(m.binding, parent.Lease.ID), string(item.ID)), &info) != nil || info.Uid != parent.Lease.UID || info.Gid != parent.Lease.GID || info.Mode&07777 != 0700 {
			t.Fatal("storage child retained the other reserved slot's ownership")
		}
	}
}

type storageStartRecorder struct {
	leaseStorage
	manager  *leaseManager
	barriers int
}

func (s *storageStartRecorder) Save(record leaseRecord) error {
	if err := s.leaseStorage.Save(record); err != nil {
		return err
	}
	for _, job := range record.DataJobs {
		if job.State == "preparing" && job.Gate != nil && job.Gate.State == "preparing" {
			if err := s.manager.resources.Quiescent(context.Background(), dataChild(record, job)); err != nil {
				return err
			}
			s.barriers++
		}
	}
	return nil
}

type storageCopyInput struct {
	Job      dataJob
	Boot     string
	Manifest []byte
}
type storageCopyBootstrap struct {
	api.WorkerBootstrap
	input     storageCopyInput
	principal api.WorkerPrincipal
	result    *os.File
	results   api.Sequence
}
type storageCopyClock struct{}

func (storageCopyClock) Now() time.Time { return time.Now() }

func (s *storageCopyBootstrap) WorkerInput(ctx context.Context, scope api.Scope, request api.WorkerInputRequest) (api.WorkerJobInput, error) {
	if err := ctx.Err(); err != nil {
		return api.WorkerJobInput{}, err
	}
	w := s.input.Job.Reg.Worker
	if scope.Actor != s.principal.Record.Actor || request.LeaseID != w.ID {
		return api.WorkerJobInput{}, failure(api.CodeForbidden, "copy fixture received another worker")
	}
	return api.WorkerJobInput{Schema: "laneboss.worker-input.v2", StageID: s.principal.StageID, LeaseID: w.ID, Kind: w.Kind, OperationID: w.OperationID, EffectID: w.EffectID, Input: w.Input, Bytes: s.input.Job.Input}, nil
}
func (s *storageCopyBootstrap) WorkerResult(ctx context.Context, scope api.Scope, request api.WorkerResultSubmission) (api.WorkerResultReceipt, error) {
	if err := ctx.Err(); err != nil {
		return api.WorkerResultReceipt{}, err
	}
	w := s.input.Job.Reg.Worker
	if scope.Actor != s.principal.Record.Actor || request.LeaseID != w.ID || request.InputSHA256 != w.Input.SHA256 || request.ExpectedGeneration != w.Generation {
		return api.WorkerResultReceipt{}, failure(api.CodeForbidden, "copy fixture result changed its input")
	}
	if n, err := s.result.Write(request.Result); err != nil || n != len(request.Result) {
		return api.WorkerResultReceipt{}, failure(api.CodeIntegrity, "copy fixture result write failed")
	}
	s.results++
	return api.WorkerResultReceipt{LeaseID: w.ID, StageID: s.principal.StageID, Generation: w.Generation + 1, CommittedSeq: s.results, Result: api.BlobRef{ID: api.ID(digestBytes(request.Result)[:32]), Class: "worker_result", SHA256: digestBytes(request.Result), Bytes: int64(len(request.Result))}}, nil
}

func workerStorageHold(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatal("UID survivor control did not drop root")
	}
	release, ready := os.NewFile(3, "hold-release"), os.NewFile(4, "hold-ready")
	defer release.Close()
	defer ready.Close()
	if _, err := ready.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	var signal [1]byte
	if _, err := io.ReadFull(release, signal[:]); err != nil || signal[0] != 1 {
		t.Fatal("UID survivor control lost its release", err)
	}
}

func workerStorageLiveControl(t *testing.T, ctx context.Context, m *leaseManager, reg dataReg, child leaseRecord) {
	t.Helper()
	releaseRead, releaseWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer releaseRead.Close()
	defer releaseWrite.Close()
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyRead.Close()
	defer readyWrite.Close()
	group, err := os.Open(filepath.Join(m.binding.cgroupPath(), string(child.Lease.ContainmentID)))
	if err != nil {
		t.Fatal(err)
	}
	defer group.Close()
	command := exec.CommandContext(ctx, m.binding.binaryPath(), "-test.run=^TestWorkerLaunchNative$", "-test.v", "--", "worker-hold")
	command.Env, command.ExtraFiles = []string{}, []*os.File{releaseRead, readyWrite}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: child.Lease.UID, Gid: child.Lease.GID, Groups: []uint32{}}, UseCgroupFD: true, CgroupFD: int(group.Fd())}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if command.ProcessState == nil {
			command.Process.Kill()
			command.Wait()
		}
	}()
	readyWrite.Close()
	if err := readyRead.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var signal [1]byte
	if _, err := io.ReadFull(readyRead, signal[:]); err != nil || signal[0] != 1 {
		t.Fatal("UID survivor control did not become live", err)
	}
	_, blocked := m.openData(ctx, reg)
	if _, err := releaseWrite.Write(signal[:]); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
	var refusal *api.Error
	if !errors.As(blocked, &refusal) || refusal.Code != api.CodeContainmentUnknown || api.HelperReason(blocked) != "cgroup_population" {
		t.Fatal("preparation retry did not refuse the actual surviving worker UID", blocked)
	}
	parent, index, err := m.findData(reg.Request)
	if err != nil || parent.DataJobs[index].State != "preparing" {
		t.Fatal("refused live UID recovery changed the retained attempt", err)
	}
}

func workerStorageCopy(t *testing.T) {
	t.Helper()
	control := os.NewFile(3, "copy-fixture")
	defer control.Close()
	raw, err := io.ReadAll(io.LimitReader(control, api.MaxFrameBytes+1))
	if err != nil {
		t.Fatal(err)
	}
	var input storageCopyInput
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	job, reg := input.Job, input.Job.Reg
	if uint32(os.Geteuid()) != job.Lease.UID || uint32(os.Getegid()) != job.Lease.GID || job.Lease.UID == 0 {
		t.Fatal("copy did not run as its reserved worker UID")
	}
	process := input.Boot + ":" + strconv.Itoa(os.Getpid())
	record := api.LaunchRecord{Kind: "worker", ID: reg.LaunchID, Config: reg.Reservation.Config, Target: reg.Worker.Target, Actor: api.Actor{Kind: "worker", ID: "copy-fixture-principal"}, UIDLeaseID: job.Lease.ID, HostUID: job.Lease.UID, ContainmentID: job.Lease.ContainmentID, ProcessGeneration: process, GrantSetID: reg.Grants.ID, GrantsSHA256: reg.Grants.SHA256, PolicyGeneration: reg.Reservation.PolicyGeneration, EndpointGeneration: job.Lease.EndpointGeneration}
	intent := job.Spec.Handoff.Cause
	claim := api.EffectLease{ClaimID: reg.ClaimID, ExpiresAt: reg.ClaimExpires, Record: api.EffectRecord{Effect: api.Effect{ID: reg.Worker.EffectID, OperationID: reg.Worker.OperationID, Context: &intent, Worker: &reg.Plan}, State: api.EffectClaimed, Generation: reg.ClaimGeneration, ClaimID: reg.ClaimID, ClaimantID: reg.ParentActor.ID, ClaimExpiresAt: reg.ClaimExpires}}
	principal := api.WorkerPrincipal{StageID: reg.Request.StageID, Lease: reg.Worker, Record: record, Endpoint: *job.Endpoint, Peer: api.PeerFacts{HostUID: job.Lease.UID, HostGID: job.Lease.GID, HostPID: os.Getpid(), ContainmentID: job.Lease.ContainmentID, ProcessGeneration: process}, BootID: input.Boot, AllocationGeneration: job.Projection.Generation, Claim: claim, CancellationEpoch: reg.Reservation.CancellationEpoch}
	result := os.NewFile(7, "copy-result")
	defer result.Close()
	bootstrap := &storageCopyBootstrap{input: input, principal: principal, result: result}
	roots := make([]*os.Root, 3)
	for i := range roots {
		roots[i], err = os.OpenRoot("/proc/self/fd/" + strconv.Itoa(4+i))
		if err != nil {
			t.Fatal(err)
		}
		defer roots[i].Close()
	}
	var body dataInput
	if err := api.DecodeObject(job.Input, &body); err != nil {
		t.Fatal(err)
	}
	_, err = dataworker.RunMaterialization(context.Background(), dataworker.MaterializationJob{Principal: principal, Scope: api.Scope{Config: record.Config, Actor: record.Actor, LaunchID: record.ID, EndpointGeneration: record.EndpointGeneration}, Bootstrap: bootstrap, Source: roots[0], Workspace: roots[1], Home: roots[2], Clock: storageCopyClock{}, Read: func(ctx context.Context, request api.BlobReadRequest) (api.BlobChunk, error) {
		if err := ctx.Err(); err != nil {
			return api.BlobChunk{}, err
		}
		if request.ObjectID != body.Source.Object.ID && request.ObjectID != body.Output.ID || request.Offset < 0 || request.Offset > int64(len(input.Manifest)) || request.Limit < 1 {
			return api.BlobChunk{}, failure(api.CodeForbidden, "copy read escaped its manifests")
		}
		end := min(int64(len(input.Manifest)), request.Offset+int64(request.Limit))
		data := append([]byte(nil), input.Manifest[request.Offset:end]...)
		return api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: data, SHA256: digestBytes(data)}, nil
	}})
	if err != nil {
		t.Fatal("fixed dataworker refused the actual worker-UID copy", err)
	}
}
