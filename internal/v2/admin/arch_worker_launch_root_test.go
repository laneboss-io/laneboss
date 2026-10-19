//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

// Reuse only the real installed native kit. This branch starts a distinct-UID
// client with a real SQLite store and identity service; no worker store double
// participates in the archive canary.
func TestArchiveLaunchNative(t *testing.T) { TestWorkerLaunchNative(t) }

func TestArchiveFixtureNative(t *testing.T) { workerLaunchCanary(t, false, archiveLaunchCanary) }

func archiveLaunchCanary(t *testing.T, ctx context.Context, m *leaseManager, data dataReg, runtime api.BlobRef, executable api.Executable) {
	t.Helper()
	var costMu sync.Mutex
	costs := map[string]time.Duration{}
	counts := map[string]int{}
	ctx = context.WithValue(ctx, archiveCostKey{}, func(stage string, elapsed time.Duration) {
		costMu.Lock()
		defer costMu.Unlock()
		costs[stage] += elapsed
		counts[stage]++
	})
	t.Cleanup(func() { archiveCanaryCollect(t, m) })
	parent, err := m.find(data.Request.AgentLeaseID)
	if err != nil {
		t.Fatal(err)
	}
	reserved := parent
	reserved.Phase = "reserved"
	if err := m.resources.Ensure(ctx, reserved); err != nil {
		t.Fatal("native archive parent setup failed", err)
	}
	if strings.Split(t.Name(), "/")[0] == "TestArchiveFixtureNative" {
		for i := range 12 {
			name := filepath.Join(storageBase(m.binding, parent), string(parent.Storage.Directories[0].ID), "fixture-"+strconv.Itoa(i))
			if err := os.WriteFile(name, []byte("retained native fixture bytes "+strconv.Itoa(i)+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(name, int(parent.Lease.UID), int(parent.Lease.GID)); err != nil {
				t.Fatal(err)
			}
		}
	}
	servicePath := filepath.Join("/run/laneboss-v2/services", m.binding.Config)
	for _, directory := range []string{filepath.Dir(servicePath), servicePath} {
		if err := os.MkdirAll(directory, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Dir(servicePath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(os.Chown(servicePath, int(m.binding.Service.UID), int(m.binding.Service.GID)), os.Chmod(servicePath, 0700)); err != nil {
		t.Fatal(err)
	}
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion, Config: m.binding.Config, Class: api.EndpointHuman, ServiceUID: m.binding.Service.UID, ServiceGID: m.binding.Service.GID, Socket: filepath.Join(servicePath, "human.sock"), Backend: "linux-bwrap-landlock", ServiceVersion: m.binding.Release.Version, ArtifactSHA256: m.binding.Artifact.SHA256, InstallationGeneration: m.binding.Generation, EndpointGeneration: m.binding.Generation}
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
			if err := serveHelperConnectionWithJournal(ctx, connection, m.binding, m, &journal); errors.Is(err, errHelperJournal) {
				finished <- err
				return
			}
			logArchiveCost(t, journal.Bytes())
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
		Reservation  api.LaunchReservation
		Parent       api.HelperLease
		Storage      api.LaunchStorage
		Runtime      api.BlobRef
		Executable   api.Executable
		Boot         string
		Directory    string
		RuntimeBytes []byte
		Budget       api.Budget
	}{endpoint, data.Reservation, parent.Lease, parent.Storage.Binding, runtime, executable, m.bootID, servicePath, archiveCanaryRuntime(t, m), parent.Request.Budget})
	if err != nil {
		t.Fatal(err)
	}
	defer metadata.Close()
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyRead.Close()
	defer readyWrite.Close()
	ackRead, ackWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ackRead.Close()
	defer ackWrite.Close()
	clientTest, clientMode := "TestArchiveNativeStoreClient", "archive-store-client"
	if strings.Split(t.Name(), "/")[0] == "TestReviewLaunchNative" {
		clientTest, clientMode = "TestReviewNativeStoreClient", "review-store-client"
	}
	if strings.Split(t.Name(), "/")[0] == "TestNativeChildLaunch" {
		clientTest, clientMode = "TestNativeChildStoreClient", "test-store-client"
	}
	if strings.Split(t.Name(), "/")[0] == "TestCheckLaunchNative" {
		clientTest, clientMode = "TestCheckNativeStoreClient", "check-store-client"
	}
	command := exec.CommandContext(ctx, m.binding.binaryPath(), "-test.run=^"+clientTest+"$", "-test.v", "--", clientMode)
	command.Env, command.ExtraFiles = []string{"HOME=" + servicePath, "TMPDIR=" + servicePath}, []*os.File{metadata, readyWrite, ackRead}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: m.binding.Service.UID, Gid: m.binding.Service.GID, Groups: []uint32{}}, UseCgroupFD: true, CgroupFD: int(serviceGroup.Fd())}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	readyWrite.Close()
	ackRead.Close()
	if err := readyRead.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var lane api.Lane
	inputDecoder := json.NewDecoder(readyRead)
	if err := inputDecoder.Decode(&lane); err != nil {
		command.Wait()
		t.Fatalf("real archive store did not provide its ended fixture: %v\n%s", err, output.Bytes())
	}
	if _, _, err := descriptorReferences(ctx, command.Process.Pid, nil); err != nil {
		ackWrite.Close()
		command.Wait()
		t.Fatal("native archive helper cannot inspect its actual service child", err)
	}
	if clientMode == "check-store-client" {
		var actual struct {
			Reservation api.LaunchReservation
			Inputs      api.LaunchInputs
			Request     api.HelperLeaseRequest
		}
		if err := inputDecoder.Decode(&actual); err != nil {
			t.Fatal("native child allocation enrollment is unavailable", err)
		}
		parent.Request = actual.Request
		parent.LaunchAllocations[0].Reservation, parent.LaunchAllocations[0].Inputs, parent.LaunchAllocations[0].Request = actual.Reservation, actual.Inputs, actual.Request
		parent.Storage.Binding.ReservationID = actual.Reservation.ID
	}
	archiveCanaryRetarget(t, m, parent, lane)
	if clientMode == "test-store-client" {
		// The post-run freeze must measure a real candidate file owned by the
		// original lane UID. The later worker receives its immutable bytes.
		path := filepath.Join(storageBase(m.binding, parent), string(lane.Workspace.ID), "candidate-source.txt")
		content, err := randomID("actual-candidate-")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, int(parent.Lease.UID), int(parent.Lease.GID)); err != nil {
			t.Fatal(err)
		}
	}
	if clientMode == "review-store-client" || clientMode == "check-store-client" {
		requirementsPath := filepath.Join("/etc/laneboss-v2/review", m.binding.Config+".json")
		if err := os.MkdirAll(filepath.Dir(requirementsPath), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Dir(requirementsPath), 0755); err != nil {
			t.Fatal(err)
		}
		names := []string{"unit"}
		if clientMode == "check-store-client" {
			names = []string{"snapshot-integrity"}
		}
		workerCanaryJSON(t, requirementsPath, map[string]any{"schema": "laneboss.review-requirements.v2", "config": m.binding.Config, "policy_generation": 1, "projects": []any{map[string]any{"project_id": lane.Workspace.ProjectID, "checks": names}}}, 0644)
		t.Cleanup(func() {
			if err := os.Remove(requirementsPath); err != nil {
				t.Error(err)
			}
		})
	}
	if n, err := ackWrite.Write([]byte{1}); err != nil || n != 1 {
		t.Fatal(err)
	}
	witnessed := make(chan error, 1)
	go func() {
		var prepared api.Lane
		if err := inputDecoder.Decode(&prepared); err != nil {
			witnessed <- err
			return
		}
		archiveCanaryNamespaceWitness(t, m)
		_, err := ackWrite.Write([]byte{1})
		witnessed <- err
	}()
	err = command.Wait()
	costMu.Lock()
	t.Logf("archive_fence: calls=%d tree_ms=%.3f refs_ms=%.3f ns_ms=%.3f fd_ms=%.3f", counts["references"], float64(costs["tree"].Microseconds())/1000, float64(costs["references"].Microseconds())/1000, float64(costs["namespaces"].Microseconds())/1000, float64(costs["descriptors"].Microseconds())/1000)
	costMu.Unlock()
	if witnessErr := <-witnessed; err == nil && witnessErr != nil {
		t.Fatal("native prepared fixture was not observed", witnessErr)
	}
	if err != nil || !bytes.Contains(output.Bytes(), []byte("--- PASS: "+clientTest+" ")) {
		archiveCanaryNamespaceWitness(t, m)
		t.Fatalf("real store/identity/native archive client failed: %v\n%s", err, output.Bytes())
	}
	logArchiveCost(t, output.Bytes())
	t.Log("real SQLite identity permit opened the original native archive gate; replay and missing-source controls refused")
}

func logArchiveCost(t *testing.T, output []byte) {
	t.Helper()
	for _, line := range strings.Split(string(output), "\n") {
		result := strings.Contains(line, `"event":"archive_result"`) ||
			strings.Contains(line, `"event":"worker_timing"`) && strings.Contains(line, `"stage":"result_`)
		helper := strings.Contains(line, `"event":"helper_timing"`) && strings.Contains(line, `"stage":"turn"`)
		if result || helper || strings.Contains(line, "native TestChild:") || strings.Contains(line, `"event":"worker_cost"`) || strings.Contains(line, "archive_fence:") || strings.Contains(line, "archive_phase:") || strings.Contains(line, "archive_total:") || strings.Contains(line, "native test and export measured:") {
			t.Log(line)
		}
	}
}

// Diagnose a failed prerequisite without excluding any process or namespace
// from the production scan. Only ownership categories and verdicts are logged.
func archiveCanaryNamespaceWitness(t *testing.T, m *leaseManager) {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Log("namespace witness: process inventory unavailable")
		return
	}
	pins := map[storageInode]*os.File{}
	defer func() {
		for _, file := range pins {
			file.Close()
		}
	}()
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		tasks, err := os.ReadDir(filepath.Join("/proc", entry.Name(), "task"))
		if err != nil {
			continue
		}
		for _, task := range tasks {
			file, err := os.Open(filepath.Join("/proc", entry.Name(), "task", task.Name(), "ns/mnt"))
			if err != nil {
				continue
			}
			var info unix.Stat_t
			if unix.Fstat(int(file.Fd()), &info) != nil {
				file.Close()
				continue
			}
			key := storageInode{Device: uint64(info.Dev), Inode: info.Ino}
			if pins[key] == nil {
				pins[key] = file
			} else {
				file.Close()
			}
		}
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		_, retained, err := scopedDescriptorReferences(context.Background(), pid, nil, pins, nil)
		if err != nil {
			t.Logf("namespace witness: descriptor observation refused: %v", err)
			continue
		}
		if !retained {
			continue
		}
		kind := "other-process"
		if pid == 1 {
			kind = "service-manager"
		}
		if pid == os.Getpid() {
			kind = "current-helper"
		}
		file, err := os.Open(filepath.Join("/proc", entry.Name(), "exe"))
		if err == nil {
			if verifyExecutableFile(file, m.binding.Artifact) == nil && kind == "other-process" {
				kind = "matched-test-artifact"
				var owner unix.Stat_t
				if unix.Stat(filepath.Join("/proc", entry.Name()), &owner) == nil {
					if owner.Uid == m.binding.Service.UID {
						kind = "service-client"
					} else if owner.Uid != 0 {
						kind = "worker-bootstrap"
					}
				}
			}
			file.Close()
		}
		t.Logf("namespace witness: retained mount namespace owner=%s", kind)
	}
}

func archiveCanaryRuntime(t *testing.T, m *leaseManager) []byte {
	t.Helper()
	raw, err := readProtected(filepath.Join(filepath.Dir(m.binding.binaryPath()), "runtime", m.binding.Config, "manifest.json"), api.MaxFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func archiveCanaryRetarget(t *testing.T, m *leaseManager, parent leaseRecord, lane api.Lane) {
	t.Helper()
	target := api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}
	base := storageBase(m.binding, parent)
	before := parent.Storage.Binding.WorkspaceID
	if err := os.Rename(filepath.Join(base, string(before)), filepath.Join(base, string(lane.Workspace.ID))); err != nil {
		t.Fatal(err)
	}
	parent.Storage.Directories[0].ID = lane.Workspace.ID
	parent.Storage.Binding.Target, parent.Storage.Binding.WorkspaceID = target, lane.Workspace.ID
	parent.Storage.Binding.Home.LifeID = lane.LifeID
	parent.Storage.Binding.Home.Home.WorkspaceID = lane.Workspace.ID
	parent.Request.LifeID, parent.Request.Cause.Target, parent.Request.Cause.CancellationEpoch = lane.LifeID, target, lane.CancellationEpoch
	for i := range parent.LaunchAllocations {
		a := &parent.LaunchAllocations[i]
		a.Request = parent.Request
		a.Reservation.Target, a.Reservation.RootLifeID, a.Reservation.LaunchID, a.Reservation.CancellationEpoch = target, lane.RootLifeID, lane.LaunchID, lane.CancellationEpoch
		a.Reservation.ParentLifeID, a.Reservation.StarterChain, a.Reservation.StarterEventSeq = lane.ParentLifeID, append([]api.ID{}, lane.StarterChain...), lane.StarterEventSeq
		a.Inputs.Grants.LifeID = lane.LifeID
	}
	if err := m.save(parent); err != nil {
		t.Fatal("native ended fixture did not retain its actual storage", err)
	}
}

func archiveCanaryCollect(t *testing.T, m *leaseManager) {
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, gate := range m.gates {
		if err := gate.Close(); err != nil {
			t.Error(err)
			return
		}
		if _, err := gate.Stop(cleanup, api.ProcessHandle{}); err != nil {
			t.Error(err)
			return
		}
	}
	records, err := m.records()
	if err != nil {
		t.Error(err)
		return
	}
	var reviews []leaseRecord
	for _, record := range records {
		raw, err := json.Marshal(record)
		if err != nil {
			t.Error(err)
			return
		}
		var inventory struct {
			Reviews []*archiveJournal `json:"reviews"`
		}
		if err := json.Unmarshal(raw, &inventory); err != nil {
			t.Error(err)
			return
		}
		for _, journal := range inventory.Reviews {
			view := record
			view.Archive = journal
			reviews = append(reviews, view)
		}
	}
	records = append(records, reviews...)
	for _, record := range records {
		if record.Archive != nil && record.Archive.Worker != nil {
			worker := record.Archive.Worker
			if worker.Collected {
				retirement := record.Archive.Retirement
				if retirement == nil || retirement.Proof == nil || retirement.Proof.Release == nil || worker.Observation == nil || worker.Observation.Survivors == nil || *worker.Observation.Survivors != 0 {
					t.Error("collected archive lacks its measured retirement")
				}
				group := filepath.Join(m.binding.cgroupPath(), string(worker.Lease.ContainmentID))
				if _, err := os.Lstat(group); !errors.Is(err, os.ErrNotExist) {
					t.Error("collected archive retained its native containment", err)
				}
				continue
			}
			if err := m.waitContainmentEmpty(cleanup, archiveChild(record, *record.Archive.Worker)); err != nil {
				t.Error(err)
			}
		}
	}
}
