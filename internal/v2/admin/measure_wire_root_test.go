//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

type measureWireInput struct {
	Binding installation
	Query   dataMeasure
}

// The installed native kit runs the real materialization owner and worker
// before these additional service-UID requests. No helper/store double is used.
func TestMaterializationDirtyWire(t *testing.T) {
	if os.Args[len(os.Args)-1] == "measure-wire-client" {
		measureWireClient(t)
		return
	}
	workerLaunchCanary(t, false, measureDirtyCanary)
}

func measureDirtyCanary(t *testing.T, ctx context.Context, m *leaseManager, reg dataReg, runtime api.BlobRef, executable api.Executable) {
	materializationStageRun(t, ctx, m, reg, runtime, executable, true)
	p, err := m.find(reg.Request.AgentLeaseID)
	if err != nil || len(p.DataJobs) != 1 {
		t.Fatal("real materialization did not retain one data job", err)
	}
	job := p.DataJobs[0]
	if job.Result == nil || p.Storage.Workspace == nil || p.Storage.Workspace.Phase != "published" {
		t.Fatal("real materialization did not publish its measured workspace")
	}
	output, err := canonicalValue(job.Result.Data)
	if err != nil || digestBytes(output) != job.Result.ResultReceipt.Result.SHA256 {
		t.Fatal("wire replay cannot reconstruct the acknowledged output", err)
	}
	q := dataMeasure{Reg: job.Reg, Receipt: job.Result.ResultReceipt, Output: output, Manifest: m.dataPins[job.Projection.OpenToken].manifest}
	input, err := sealedBootstrap(measureWireInput{m.binding, q})
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	lock, err := os.OpenFile(filepath.Join(m.binding.statePath(), "lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	m.storeLock = lock
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: m.binding.socketPath(), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err := listener.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var optionErr error
	if err := raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }); err != nil || optionErr != nil {
		t.Fatal(err, optionErr)
	}
	if err := errors.Join(os.Chown(m.binding.socketPath(), 0, int(m.binding.Service.GID)), os.Chmod(m.binding.socketPath(), 0660)); err != nil {
		t.Fatal(err)
	}
	group, err := os.Open(filepath.Join("/sys/fs/cgroup/system.slice", "laneboss-service@"+m.binding.Config+".service"))
	if err != nil {
		t.Fatal(err)
	}
	defer group.Close()
	hold, release, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	defer release.Close()
	diagnostics, sink, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer diagnostics.Close()
	previous := os.Stderr
	os.Stderr = sink
	defer func() { os.Stderr = previous; sink.Close() }()
	var journal bytes.Buffer
	finished := make(chan error, 1)
	go func() {
		for i := range 3 {
			connection, err := listener.AcceptUnix()
			if err != nil {
				finished <- fmt.Errorf("helper wire step %d: %w", i, err)
				return
			}
			err = serveHelperConnectionWithJournal(ctx, connection, m.binding, m, &journal)
			var typed *api.Error
			if i == 0 && err != nil || i > 0 && (!errors.As(err, &typed) || i == 1 && typed.Code != api.CodeForbidden || i == 2 && api.HelperReason(err) != "reply_transport") {
				finished <- fmt.Errorf("helper wire step %d: %w", i, err)
				return
			}
		}
		finished <- nil
	}()
	command := exec.CommandContext(ctx, m.binding.binaryPath(), "-test.run=^TestMaterializationDirtyWire$", "-test.v", "--", "measure-wire-client")
	command.Env, command.ExtraFiles = []string{}, []*os.File{input, hold}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: m.binding.Service.UID, Gid: m.binding.Service.GID, Groups: []uint32{}}, UseCgroupFD: true, CgroupFD: int(group.Fd())}
	var clientOutput bytes.Buffer
	command.Stdout, command.Stderr = &clientOutput, &clientOutput
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	serveErr := <-finished
	if err := release.Close(); err != nil {
		t.Error(err)
	}
	clientErr := command.Wait()
	os.Stderr = previous
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	diagnostic, err := io.ReadAll(diagnostics)
	if serveErr != nil || clientErr != nil || err != nil || !bytes.Contains(clientOutput.Bytes(), []byte("--- PASS: TestMaterializationDirtyWire ")) {
		t.Fatalf("real measurement wire failed: helper=%v client=%v read=%v\n%s", serveErr, clientErr, err, clientOutput.Bytes())
	}
	// The successful wire measurement must support a real dirty archive.
	work := filepath.Join(storageBase(m.binding, p), string(p.Storage.Binding.WorkspaceID))
	want := []byte("wire-measured dirty archive bytes\n")
	if err := os.WriteFile(filepath.Join(work, "dirty.txt"), want, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(filepath.Join(work, "dirty.txt"), int(p.Lease.UID), int(p.Lease.GID)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.collectData(ctx, job.Lease.ID); err != nil {
		t.Fatal(err)
	}
	res := p.LaunchAllocations[0].Reservation
	intent := archivejob.Intent{OperationID: "measure-dirty", Request: api.ArchiveRequest{Target: res.Target, ExpectedGeneration: 3}, CancellationEpoch: res.CancellationEpoch, EndEventID: "measure-ended", EndSeq: 9}
	lane := api.Lane{LifeID: res.Target.LifeID, Run: res.Target.Run, Generation: 3, CancellationEpoch: res.CancellationEpoch, LaunchID: res.LaunchID, Workspace: api.Workspace{ID: p.Storage.Binding.WorkspaceID}}
	header, err := m.freezeArchive(ctx, archiveQuery{Intent: intent, Lane: lane})
	if err != nil {
		t.Fatal("wire-measured workspace could not freeze its dirty archive", err)
	}
	found := false
	for _, ref := range header.Objects {
		if ref.SHA256 == digestBytes(want) && ref.Bytes == int64(len(want)) {
			found = true
		}
	}
	if !found {
		t.Fatal("actual dirty archive omitted the wire-measured workspace bytes")
	}
	var facts struct {
		Stage         string `json:"stage"`
		Code          string `json:"code"`
		RefusalReason string `json:"refusal_reason"`
	}
	if err := json.Unmarshal(diagnostic, &facts); err != nil || facts.Stage != "response_write" || facts.Code != "forbidden" || facts.RefusalReason != "materialization_claim" {
		t.Fatalf("failed data_measure reply lost its original guard: %s (%v)", diagnostic, err)
	}
	if !bytes.Contains(journal.Bytes(), []byte(`"method":"data_measure","code":"unavailable","reason":"reply_transport"`)) {
		t.Fatal("wire control did not exercise the actual failed reply transport")
	}
	t.Log("real helper measurement and replay; expired claim refused; closed reply retains guard; dirty archive bytes retained")
}

func measureWireClient(t *testing.T) {
	input := os.NewFile(3, "measure-input")
	defer input.Close()
	var seed measureWireInput
	if err := json.NewDecoder(input).Decode(&seed); err != nil {
		t.Fatal(err)
	}
	s := &Service{binding: seed.Binding, deps: Dependencies{Config: seed.Binding.Config, ServiceUID: seed.Binding.Service.UID}}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var result api.LaunchDataResult
	if err := s.call(ctx, "data_measure", seed.Query, &result); err != nil || result.ResultReceipt != seed.Query.Receipt {
		t.Fatal("real helper refused its original measured result", err)
	}
	seed.Query.Reg.ClaimExpires = api.Timestamp(time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano))
	var typed *api.Error
	if err := s.call(ctx, "data_measure", seed.Query, &result); !errors.As(err, &typed) || typed.Code != api.CodeForbidden || typed.Message != "native workspace materialization claim or grants expired" {
		t.Fatal("expired measurement claim escaped the actual helper check", err)
	}
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: seed.Binding.socketPath(), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.CloseRead(); err != nil {
		t.Fatal(err)
	}
	params, err := EncodeWire(seed.Query)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := randomID("mw-")
	if err != nil {
		t.Fatal(err)
	}
	request := helperRequest{Protocol: helperProtocol, Revision: api.ContractRevision, Config: seed.Binding.Config, Generation: seed.Binding.Generation, ArtifactSHA256: seed.Binding.Artifact.SHA256, Nonce: nonce, Method: "data_measure", Params: params}
	if err := writeFrame(connection, request); err != nil {
		t.Fatal(err)
	}
	hold := os.NewFile(4, "measure-hold")
	defer hold.Close()
	var one [1]byte
	if n, err := hold.Read(one[:]); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatal("measurement client lost its helper lifetime barrier", err)
	}
}
