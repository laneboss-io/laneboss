//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func init() { materializationCanaryDriver = materializationStageCanary }

func TestMaterializationNative(t *testing.T) { TestWorkerLaunchNative(t) }

func TestMaterializationNativeCopies(t *testing.T) { TestWorkerLaunchNative(t) }

func TestMaterializationTaskPeaks(t *testing.T) {
	for trial := 0; trial < 20; trial++ {
		t.Run("trial-"+strconv.Itoa(trial), func(t *testing.T) { TestWorkerLaunchNative(t) })
	}
}

type materializationCanaryFrame struct {
	Method string
	Input  json.RawMessage
}

type materializationCanaryReply struct{ Error *api.Error }

func materializationStageCanary(t *testing.T, ctx context.Context, m *leaseManager, data dataReg, runtime api.BlobRef, executable api.Executable) {
	materializationStageRun(t, ctx, m, data, runtime, executable, strings.HasPrefix(t.Name(), "TestMaterializationTaskPeaks"))
}

// onlyData leaves the measured workspace intact for a subsequent native
// consumer, before the optional capture-corruption control damages its spool.
func materializationStageRun(t *testing.T, ctx context.Context, m *leaseManager, data dataReg, runtime api.BlobRef, executable api.Executable, onlyData bool) {
	t.Helper()
	t.Cleanup(func() { archiveCanaryCollect(t, m) })
	parent, err := m.find(data.Request.AgentLeaseID)
	if err != nil {
		t.Fatal(err)
	}
	reserved := parent
	reserved.Phase = "reserved"
	if err := m.resources.Ensure(ctx, reserved); err != nil {
		t.Fatal(err)
	}
	servicePath := filepath.Join("/run/laneboss-v2/services", m.binding.Config)
	if err := os.MkdirAll(servicePath, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(servicePath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(os.Chown(servicePath, int(m.binding.Service.UID), int(m.binding.Service.GID)), os.Chmod(servicePath, 0700)); err != nil {
		t.Fatal(err)
	}
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion,
		Config: m.binding.Config, Class: api.EndpointHuman, ServiceUID: m.binding.Service.UID, ServiceGID: m.binding.Service.GID,
		Socket: filepath.Join(servicePath, "human.sock"), Backend: "linux-bwrap-landlock", ServiceVersion: m.binding.Release.Version,
		ArtifactSHA256: executable.SHA256, InstallationGeneration: m.binding.Generation, EndpointGeneration: m.binding.Generation}
	endpoint.MappedServiceUID, endpoint.MappedServiceGID, err = wire.NamespaceServiceIDs()
	if err != nil {
		t.Fatal(err)
	}
	workerCanaryJSON(t, filepath.Join("/etc/laneboss-v2/bindings", m.binding.Config+".json"), endpoint, 0444)
	closeProc, err := mountHelperProc(m.binding.runtimePath())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeProc(); err != nil {
			t.Error(err)
		}
	}()
	lock, err := os.OpenFile(filepath.Join(m.binding.statePath(), "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	m.storeLock = lock
	if err := errors.Join(os.Chown(m.binding.runtimePath(), 0, int(m.binding.Service.GID)), os.Chmod(m.binding.runtimePath(), 0750)); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: m.binding.socketPath(), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	rawSocket, err := listener.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var socketErr error
	if err := rawSocket.Control(func(fd uintptr) { socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }); err != nil || socketErr != nil {
		t.Fatal(err, socketErr)
	}
	if err := errors.Join(os.Chown(m.binding.socketPath(), 0, int(m.binding.Service.GID)), os.Chmod(m.binding.socketPath(), 0660)); err != nil {
		t.Fatal(err)
	}
	var journalMu sync.Mutex
	counts := map[string]int{}
	finished := make(chan error, 1)
	go func() {
		for {
			connection, err := listener.AcceptUnix()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					finished <- nil
				} else {
					finished <- err
				}
				return
			}
			var journal bytes.Buffer
			callErr := serveHelperConnectionWithJournal(ctx, connection, m.binding, m, &journal)
			decoder := json.NewDecoder(&journal)
			for {
				var entry struct {
					Method string `json:"method"`
					Code   string `json:"code"`
					Reason string `json:"reason"`
				}
				if err := decoder.Decode(&entry); errors.Is(err, io.EOF) {
					break
				} else if err != nil {
					finished <- err
					return
				}
				journalMu.Lock()
				counts[entry.Method+":"+entry.Code]++
				journalMu.Unlock()
				if entry.Method == "register_capture" {
					t.Log("native capture helper journal: " + entry.Code + " " + entry.Reason)
				}
			}
			if errors.Is(callErr, errHelperJournal) {
				finished <- callErr
				return
			}
		}
	}()
	defer func() {
		listener.Close()
		if err := <-finished; err != nil {
			t.Error(err)
		}
	}()
	serviceGroup, err := os.Open(filepath.Join("/sys/fs/cgroup/system.slice", "laneboss-service@"+m.binding.Config+".service"))
	if err != nil {
		t.Fatal(err)
	}
	defer serviceGroup.Close()
	metadata, err := sealedBootstrap(struct {
		Binding      api.InstalledBinding
		Agent        api.HelperLease
		Runtime      api.BlobRef
		RuntimeBytes []byte
		Budget       api.Budget
		TaskPeakOnly bool
		WithCopies   bool
	}{endpoint, parent.Lease, runtime, archiveCanaryRuntime(t, m), parent.Request.Budget, onlyData, t.Name() == "TestMaterializationNativeCopies"})
	if err != nil {
		t.Fatal(err)
	}
	defer metadata.Close()
	requests, requestWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer requests.Close()
	replies, replyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer replyWrite.Close()
	command := exec.CommandContext(ctx, m.binding.binaryPath(), "-test.run=^TestMaterializationNativeStoreClient$", "-test.v", "--", "materialization-store-client")
	command.Env, command.ExtraFiles = []string{"HOME=" + servicePath, "TMPDIR=" + servicePath}, []*os.File{metadata, requestWrite, replies}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: m.binding.Service.UID, Gid: m.binding.Service.GID, Groups: []uint32{}}, UseCgroupFD: true, CgroupFD: int(serviceGroup.Fd())}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	requestWrite.Close()
	replies.Close()
	decoder, encoder := json.NewDecoder(requests), json.NewEncoder(replyWrite)
	for {
		var frame materializationCanaryFrame
		if err := decoder.Decode(&frame); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		callErr := materializationCanaryControl(t, ctx, m, &parent, frame)
		if callErr != nil {
			t.Logf("native materialization control %s failed: %v", frame.Method, callErr)
		}
		var reply materializationCanaryReply
		if callErr != nil {
			var typed *api.Error
			if errors.As(callErr, &typed) {
				reply.Error = typed
			} else {
				reply.Error = failure(api.CodeIntegrity, "native canary control failed")
			}
		}
		if err := encoder.Encode(reply); err != nil {
			t.Fatal(err)
		}
	}
	workerErr := command.Wait()
	materializationCanaryResources(t, m)
	if workerErr != nil || !bytes.Contains(output.Bytes(), []byte("--- PASS: TestMaterializationNativeStoreClient ")) {
		t.Fatalf("native materialization owner failed: %v\n%s", workerErr, output.Bytes())
	}
	journalMu.Lock()
	prepared, opened := counts["data_prepare:ok"], counts["data_gate:ok"]
	journalMu.Unlock()
	if prepared != 1 || opened != 1 {
		t.Fatal("native canary did not journal successful data_prepare and data_gate", prepared, opened)
	}
	t.Log(output.String())
}

func materializationCanaryResources(t *testing.T, m *leaseManager) {
	t.Helper()
	records, err := m.records()
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		for _, job := range record.DataJobs {
			native, ok := m.gates[job.Lease.ID].(*nativeGate)
			if !ok {
				continue
			}
			group, err := os.Open(filepath.Join(m.binding.cgroupPath(), string(job.Lease.ContainmentID)))
			if err != nil {
				t.Fatal(err)
			}
			after := readNativeCgroupSnapshot(int(group.Fd()))
			peakFile, peakErr := os.Open(filepath.Join(m.binding.cgroupPath(), string(job.Lease.ContainmentID), "pids.peak"))
			if peakErr == nil {
				peakBytes, readErr := io.ReadAll(io.LimitReader(peakFile, 64))
				closeErr := peakFile.Close()
				peak, parseErr := strconv.ParseUint(strings.TrimSpace(string(peakBytes)), 10, 32)
				if readErr != nil || closeErr != nil || parseErr != nil || peak == 0 {
					t.Fatal("cannot measure native worker task peak")
				}
				t.Logf("native worker task peak: tasks=%d limit=%d", peak, job.Reg.Plan.Budget.Processes)
			} else if !errors.Is(peakErr, os.ErrNotExist) {
				t.Fatal("cannot open native worker task peak")
			}
			if err := group.Close(); err != nil {
				t.Fatal(err)
			}
			t.Log("native worker resource facts: " + native.cgroupBefore.facts(after))
			if !native.cgroupBefore.pidsMax.known || !after.pidsMax.known || after.pidsMax.value != native.cgroupBefore.pidsMax.value {
				t.Error("native worker exhausted its unchanged process ceiling")
			}
		}
	}
}

func materializationCanaryControl(t *testing.T, ctx context.Context, m *leaseManager, parent *leaseRecord, frame materializationCanaryFrame) error {
	switch frame.Method {
	case "collect-copies":
		var id api.ID
		if err := json.Unmarshal(frame.Input, &id); err != nil {
			return err
		}
		return materializationCopyCollection(t, ctx, m, parent.Lease.ID, id)
	case "verify-copies":
		var id api.ID
		if err := json.Unmarshal(frame.Input, &id); err != nil {
			return err
		}
		return materializationCopyViews(t, ctx, m, parent.Lease.ID, id)
	case "source":
		var source struct {
			Stage      api.LaunchDataStage
			Allocation api.HelperLeaseRequest
			Policy     api.EffectivePolicy
			Objects    []struct {
				Ref  api.BlobRef
				Data []byte
			}
		}
		if err := decodeStrict(frame.Input, &source); err != nil {
			return err
		}
		parent.Request = source.Allocation
		parent.LaunchAllocations = []launchAllocation{{Request: source.Allocation, Reservation: source.Stage.Reservation, Inputs: source.Stage.Inputs, Policy: source.Policy}}
		parent.Storage.Binding.ReservationID, parent.Storage.Binding.Target = source.Stage.Reservation.ID, source.Stage.Reservation.Target
		parent.Storage.Binding.Home.LifeID = source.Stage.Reservation.Target.LifeID
		parent.Storage.Binding.Home.Home.VendorDirectory = ".codex"
		if err := m.save(*parent); err != nil {
			return err
		}
		enrollment := api.LaunchEnrollment{Schema: "laneboss.launch-enrollment.v2", Config: m.binding.Config, Generation: 1,
			Projects: []api.ProjectEnrollment{{ID: source.Stage.Inputs.Sources.Project.EnrollmentID, Generation: 1, ProjectID: source.Stage.Inputs.Sources.Project.ProjectID, Object: source.Stage.Inputs.Sources.Project.Object, Base: source.Stage.Inputs.Sources.Project.Base, HistoryScope: "tree"}}, Runtimes: []api.LaunchRuntime{source.Stage.Inputs.Sources.Runtime}}
		var runtime api.RuntimeManifest
		if err := api.DecodeObject(archiveCanaryRuntime(t, m), &runtime); err != nil {
			return err
		}
		enrollment.Supervisor = &runtime.Bootstrap
		enrollmentBytes, err := json.Marshal(enrollment)
		if err != nil {
			return err
		}
		base := filepath.Join(filepath.Dir(m.binding.binaryPath()), "runtime", m.binding.Config)
		workerCanaryWrite(t, filepath.Join(base, "launch-enrollment.json"), enrollmentBytes, 0444)
		catalogPath := filepath.Join("/etc/laneboss-v2/boot", m.binding.Config+".json")
		catalogBytes, err := readProtected(catalogPath, api.MaxFrameBytes)
		if err != nil {
			return err
		}
		var catalog bootCatalog
		if err := api.DecodeObject(catalogBytes, &catalog); err != nil {
			return err
		}
		catalog.LaunchEnrollmentFile = filepath.Join(base, "launch-enrollment.json")
		catalog.LaunchEnrollment = &api.BlobRef{ID: "native-launch-enrollment", Class: "manifest", Bytes: int64(len(enrollmentBytes)), SHA256: digestBytes(enrollmentBytes)}
		workerCanaryJSON(t, catalogPath, catalog, 0444)
		objects := []dataCacheCanaryObject{}
		for _, object := range source.Objects {
			objects = append(objects, dataCacheCanaryObject{Ref: object.Ref, Data: object.Data})
		}
		input := filepath.Join(privateTestDir(t), "source-input.json")
		var sourceCacheLimit uint64
		if t.Name() == "TestMaterializationNativeCopies" {
			sourceCacheLimit = parent.Request.Budget.DiskBytes
		}
		workerCanaryJSON(t, input, struct {
			Enrollment       []byte                  `json:"enrollment"`
			Objects          []dataCacheCanaryObject `json:"objects"`
			DataGrants       []api.DataGrant         `json:"data_grants"`
			SourceCacheLimit uint64                  `json:"source_cache_limit,omitempty"`
		}{enrollmentBytes, objects, source.Stage.Inputs.Grants.Data, sourceCacheLimit}, 0600)
		command := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "testdata/source_cache_canary.py", input, m.binding.statePath())
		command.Env = []string{}
		if output, err := command.CombinedOutput(); err != nil || !bytes.Contains(output, []byte("source-cache:changed")) {
			for _, diagnostic := range []string{"source content is absent from the protected initial inventory", "source content pin differs", "source tree path escapes its protected root", "invalid source directory", "invalid source file", "unexpected fields", "source cache contains unexpected entries", "KeyError", "FileNotFoundError", "PermissionError", "TypeError"} {
				if bytes.Contains(output, []byte(diagnostic)) {
					t.Log("source-cache diagnostic:", diagnostic)
				}
			}
			return failure(api.CodeIntegrity, "native source installation failed")
		}
		return nil
	case "interrupt", "repair":
		var request api.StorageProjectionRequest
		if frame.Method == "interrupt" {
			if err := decodeStrict(frame.Input, &request); err != nil {
				return err
			}
		} else {
			var selected api.LaunchDataRequest
			if err := decodeStrict(frame.Input, &selected); err != nil {
				return err
			}
			record, err := m.find(selected.LeaseID)
			if err != nil || len(record.DataJobs) != 1 {
				return failure(api.CodeIntegrity, "retry lost original native data job")
			}
			request = record.DataJobs[0].Reg.Request
		}
		record, index, err := m.findData(request)
		if err != nil {
			return err
		}
		child := dataChild(record, record.DataJobs[index])
		if frame.Method == "interrupt" {
			return os.Remove(filepath.Join(m.binding.cgroupPath(), string(child.Lease.ContainmentID)))
		}
		child.Phase = "reserved"
		return m.resources.Ensure(ctx, child)
	case "capture":
		var binding api.CaptureBinding
		if err := decodeStrict(frame.Input, &binding); err != nil {
			return err
		}
		record, err := m.find(binding.HelperLeaseID)
		if err != nil {
			return err
		}
		if err := m.requireActive(record, storageReady); err != nil {
			return err
		}
		live, ok := m.captures[binding.ID].(*nativeCapture)
		if !ok || len(record.Captures) != 1 || record.Captures[0].Binding.ID != binding.ID {
			return failure(api.CodeIntegrity, "native capture lost its original producer")
		}
		stdout, stderr, err := live.TakeWriters(ctx)
		if err != nil {
			return err
		}
		if err := m.verifyCaptureSpool(ctx, record, record.Captures[0]); err != nil {
			return err
		}
		payload := []byte("native capture after storage return\n")
		checkpoint, err := live.spool.OpenFile("marker", os.O_RDONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		defer checkpoint.Close()
		if err := unix.Flock(int(checkpoint.Fd()), unix.LOCK_EX); err != nil {
			return err
		}
		for _, file := range []*os.File{stdout, stderr} {
			if n, err := file.Write(payload); err != nil || n != len(payload) {
				return failure(api.CodeIntegrity, "native capture pipe did not accept its actual input")
			}
		}
		snapshotErr := m.verifyCaptureSpool(ctx, record, record.Captures[0])
		var pending *api.Error
		if !errors.As(snapshotErr, &pending) || pending.Code != api.CodeUnavailable || !pending.Retryable {
			return failure(api.CodeIntegrity, "native snapshot did not defer its in-progress checkpoint")
		}
		if err := unix.Flock(int(checkpoint.Fd()), unix.LOCK_UN); err != nil {
			return err
		}
		snapshotContext, cancelSnapshot := context.WithTimeout(ctx, 3*time.Second)
		defer cancelSnapshot()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			err := m.verifyCaptureSpool(snapshotContext, record, record.Captures[0])
			if err == nil {
				break
			}
			if !api.CaptureSnapshotPending(err) {
				return err
			}
			select {
			case <-snapshotContext.Done():
				return snapshotContext.Err()
			case <-ticker.C:
			}
		}
		for _, file := range []*os.File{stdout, stderr} {
			if err := file.Close(); err != nil {
				return err
			}
		}
		observation, err := live.gate.Stop(ctx, api.ProcessHandle{})
		if err != nil {
			return err
		}
		if err := live.cleanExit(observation); err != nil {
			return err
		}
		marker, err := readSpool(live.spool, binding)
		if err != nil {
			return err
		}
		for _, position := range marker.Positions {
			if position.Bytes != int64(len(payload)) || position.SHA256 != digestBytes(payload) || !position.PipeEOF {
				return failure(api.CodeIntegrity, "native capture spool lost its actual bytes or EOF")
			}
		}
		damaged, err := live.spool.OpenFile("stdout", os.O_WRONLY|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		if n, err := damaged.WriteAt([]byte{'X'}, 0); err != nil || n != 1 {
			damaged.Close()
			return failure(api.CodeIntegrity, "cannot install actual capture corruption control")
		}
		if err := errors.Join(damaged.Sync(), damaged.Close()); err != nil {
			return err
		}
		corruptErr := m.verifyCaptureSpool(ctx, record, record.Captures[0])
		var corrupted *api.Error
		if !errors.As(corruptErr, &corrupted) || corrupted.Code != api.CodeIntegrity {
			return failure(api.CodeIntegrity, "capture checkpoint hid actual committed spool corruption")
		}
		t.Log("native capture checkpoint: live update deferred; committed corruption refused")
		if err := live.Close(); err != nil {
			return err
		}
		if err := live.spool.Close(); err != nil {
			return err
		}
		t.Log("native capture registered after return; measured spool bytes and EOF")
		return nil
	case "verify":
		var result api.LaunchDataResult
		if err := decodeStrict(frame.Input, &result); err != nil {
			return err
		}
		record, index, found, err := m.dataByLease(result.Observation.Handle.ID)
		if err != nil {
			return err
		}
		if !found {
			record, err = m.find(parent.Lease.ID)
			if err != nil || len(record.DataJobs) != 1 {
				return failure(api.CodeIntegrity, "native measurement lost its retained job")
			}
			index = 0
		}
		job := record.DataJobs[index]
		if job.Result == nil || job.Result.StageID != result.StageID || job.State != "measured" {
			return failure(api.CodeIntegrity, "native job did not retain its actual measurement")
		}
		if err := m.syncLaunchStorage(ctx, &record, false); err != nil {
			return err
		}
		return nil
	}
	return failure(api.CodeInvalid, "unknown native materialization canary control")
}
