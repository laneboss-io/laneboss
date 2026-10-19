//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
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
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func init() {
	if len(os.Args) == 7 && os.Args[1] == "admin-lane-gate-service" {
		os.Exit(laneGateServiceFixture(os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6]))
	}
}

// This distinct-UID peer proves native transport, not lifecycle authorization.
// It must receive the exact CLI request from the lane UID and emit a correlated
// strict response. A setup failure cannot produce its success observation.
func laneGateServiceFixture(path, config, life, uidWord, gidWord string) int {
	uid, uidErr := strconv.ParseUint(uidWord, 10, 32)
	gid, gidErr := strconv.ParseUint(gidWord, 10, 32)
	if uidErr != nil || gidErr != nil || os.Geteuid() == 0 {
		return 131
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return 132
	}
	defer listener.Close()
	if os.Chmod(path, 0666) != nil || listener.SetDeadline(time.Now().Add(20*time.Second)) != nil {
		return 133
	}
	ready := os.NewFile(3, "lane-service-ready")
	defer ready.Close()
	if n, err := ready.Write([]byte{1}); err != nil || n != 1 {
		return 134
	}
	connection, err := listener.AcceptUnix()
	if err != nil {
		return 135
	}
	defer connection.Close()
	peer, err := wire.PeerCredentials(connection)
	if err != nil || peer.PID <= 1 || peer.UID != uint32(uid) || peer.GID != uint32(gid) ||
		connection.SetDeadline(time.Now().Add(5*time.Second)) != nil {
		return 136
	}
	raw, err := wire.ReadFrame(connection)
	if err != nil {
		return 137
	}
	request, err := wire.DecodeRequest(raw)
	var target api.LifeRef
	if err != nil || request.Config != config || request.Method != "lane.status" || wire.Decode(request.Params, &target) != nil ||
		target.LifeID != api.ID(life) || target.Run != 1 {
		return 138
	}
	if n, err := ready.Write([]byte{2}); err != nil || n != 1 {
		return 141
	}
	ref := api.BlobRef{ID: "lane-gate-fixture-task", SHA256: digestBytes(request.Params), Bytes: int64(len(request.Params)), Class: "task"}
	lane := api.Lane{LifeID: target.LifeID, Run: target.Run, RootLifeID: target.LifeID, LaunchID: target.LifeID,
		Name: string(request.RequestID), State: "running", Generation: 1, PolicyGeneration: 1, Level: 3, Role: "executor",
		StarterChain: []api.ID{}, Task: ref, Session: api.Session{Driver: api.DriverCodex},
		Workspace: api.Workspace{Snapshot: ref}, LastSeq: 1}
	result, err := json.Marshal(lane)
	if err != nil || wire.ValidateResult(request.Method, result) != nil {
		return 139
	}
	response, err := json.Marshal(api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion,
		RequestID: request.RequestID, LastSeq: 1, Result: result})
	if err != nil || wire.WriteFrame(connection, response) != nil {
		return 140
	}
	return 0
}

// Run in the installed disposable fixture's exclusive root control unit.
// The shared production mount composer and actual native gate exercise the
// enrolled CLI, UID/cgroup/user/PID namespaces, Landlock/seccomp and release.
// This component has no credential authority: startConfinedGate must refuse
// that absence. The separate native endpoint run does not claim projection or
// capture approval; the composed installed E2E owns those measurements.
func TestInstalledLaneGateEndpoint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if os.Geteuid() != 0 {
		t.Fatal("installed lane gate requires the disposable root integration kit")
	}
	binding := installedGateBinding(t)
	state, err := os.OpenRoot(binding.statePath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Error(err)
		}
	})
	lock, err := state.OpenFile("lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lock.Close(); err != nil {
			t.Error(err)
		}
	})
	var lockInfo unix.Stat_t
	if unix.Fstat(int(lock.Fd()), &lockInfo) != nil || lockInfo.Uid != 0 || lockInfo.Mode&unix.S_IFMT != unix.S_IFREG ||
		lockInfo.Mode&07777 != 0600 || lockInfo.Nlink != 1 || unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		t.Fatal("installed lane gate requires its safe exclusive helper lock")
	}
	closeProc, err := mountHelperProc(binding.runtimePath())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := closeProc(); err != nil {
			t.Error(err)
		}
	})
	bootBytes, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	boot := strings.TrimSpace(string(bootBytes))
	catalogBytes, err := readProtected(filepath.Join("/etc/laneboss-v2/boot", binding.Config+".json"), api.MaxFrameBytes)
	if err != nil {
		t.Fatal(err)
	}
	var catalog bootCatalog
	if err := decodeStrict(catalogBytes, &catalog); err != nil {
		t.Fatal(err)
	}
	manifest, err := loadInstalledRuntime(ctx, binding, catalog.RuntimeManifest)
	if err != nil {
		t.Fatal(err)
	}
	executablePath := ""
	for _, object := range manifest.Objects {
		if object.ID == manifest.Bootstrap.ID && object.Content.SHA256 == binding.Artifact.SHA256 {
			executablePath = nativeRuntimeTarget(object)
		}
	}
	if executablePath == "" || len(manifest.Bindings) != 0 || len(binding.Lanes) == 0 {
		t.Fatal("installed lane gate lacks its exact enrolled CLI runtime")
	}
	id, err := randomID("lane-gate-")
	if err != nil {
		t.Fatal(err)
	}
	cgroupID, err := randomID("lane-gate-cg-")
	if err != nil {
		t.Fatal(err)
	}
	lease := api.HelperLease{ID: id, ContainmentID: cgroupID, UID: binding.Lanes[0].UID, GID: binding.Lanes[0].GID, EndpointGeneration: binding.Generation}
	target := api.LifeRef{LifeID: id, Run: 1}
	registration, _ := capturePlanFixture()
	registration.Reservation.Config, registration.Reservation.Target, registration.Reservation.RootLifeID = binding.Config, target, id
	registration.Reservation.LaunchID = id
	registration.Request.Cause.Config, registration.Request.Cause.Target = binding.Config, target
	registration.Request.HelperLeaseID, registration.Worker.Target = lease.ID, target
	capture, err := refusedCaptureBinding(registration, lease)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := newLaunchStorage(launchAllocation{Reservation: registration.Reservation}, lease)
	if err != nil {
		t.Fatal(err)
	}
	request := testAllocation()
	request.Config, request.Cause.Config, request.LifeID, request.Cause.Target.LifeID = binding.Config, binding.Config, id, id
	request.Budget.MemoryBytes, request.Budget.Processes, request.Budget.CPUSeconds, request.Budget.WallMS = 256<<20, 32, 5, 10000
	spec := api.LaunchSpec{Kind: "agent", LaunchID: id, Target: target, UIDLeaseID: lease.ID, EndpointGeneration: lease.EndpointGeneration,
		Backend: "linux-bwrap-landlock", RuntimeManifest: catalog.RuntimeManifest, Budget: request.Budget,
		Runner: &api.RunnerPlan{Driver: api.DriverCodex, Executable: manifest.Bootstrap, CWD: "/work/main",
			Argv: []string{executablePath, "lane", "status", "--config", binding.Config, "--life", string(id), "--run", "1"}}}
	record := leaseRecord{Lease: lease, Request: request, Phase: "reserved", BootID: boot, Storage: &storage,
		Gate: &gateJournal{Prepared: api.PreparedLaunch{ID: id, GateID: id}},
		Spec: &specRegistration{Handoff: api.PreparedSpecHandoff{Spec: spec}, Plan: &api.LaunchPlan{Capture: capture, CapturePolicy: &registration.Policy}}}
	resources := &linuxResources{binding: binding}
	manager := &leaseManager{binding: binding, bootID: boot, resources: resources}
	resources.manager = manager
	refused, refusal := manager.startConfinedGate(ctx, record)
	var typed *api.Error
	if refused != nil || !errors.As(refusal, &typed) || typed.Code != api.CodeUnavailable || typed.Message != "native credential projection receiver is not bound" {
		t.Fatal("acceptance: native gate omitted its credential receiver barrier")
	}
	if err := resources.Ensure(ctx, record); err != nil {
		t.Fatal(err)
	}
	record.Phase = "active"
	if err := manager.syncLaunchStorage(ctx, &record, true); err != nil {
		t.Fatal(err)
	}
	service, err := workerServiceBinding(binding)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(filepath.Dir(service.Socket), "lanes")
	if err := os.Mkdir(base, 0700); err == nil {
		if err := os.Chown(base, int(service.ServiceUID), int(service.ServiceGID)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if t.Failed() {
				return
			}
			if err := os.Remove(base); err != nil {
				t.Error(err)
			}
		})
	} else if !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	stage, err := randomID("lb-v2-serve2-lane-peer-")
	if err != nil {
		t.Fatal(err)
	}
	stagePath := filepath.Join("/run", string(stage))
	if err := createLaneStage(stagePath, service.ServiceGID); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(stagePath)
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	peerBinary := filepath.Join(stagePath, "peer")
	if err := os.WriteFile(peerBinary, self, 0555); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(peerBinary)
	if err := os.Chmod(peerBinary, 0555); err != nil {
		t.Fatal(err)
	}
	retained, err := os.ReadFile(peerBinary)
	if err != nil || digestBytes(retained) != digestBytes(self) {
		t.Fatal("lane peer executable read-back differs", err)
	}
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readyRead.Close()
	defer readyWrite.Close()
	socketPath := filepath.Join(base, string(id)+".sock")
	peer := exec.CommandContext(ctx, peerBinary, "admin-lane-gate-service", socketPath, binding.Config, string(id),
		strconv.FormatUint(uint64(lease.UID), 10), strconv.FormatUint(uint64(lease.GID), 10))
	peer.Env, peer.ExtraFiles = []string{}, []*os.File{readyWrite}
	peer.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: service.ServiceUID, Gid: service.ServiceGID, Groups: []uint32{}}}
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	peerWaited := false
	t.Cleanup(func() {
		if !peerWaited {
			cancel()
			if err := peer.Wait(); err != nil && !t.Failed() {
				t.Error("lane peer failed during collection", err)
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
		t.Fatal("installed lane peer did not create its actual endpoint", err)
	}
	network, err := newEmptyNetworkNamespace(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := network.Close(); err != nil {
			t.Error(err)
		}
	})
	var netInfo unix.Stat_t
	if err := unix.Fstat(int(network.Fd()), &netInfo); err != nil {
		t.Fatal(err)
	}
	manager.networks = map[api.ID]*namespaceOwner{lease.ID: {file: network}}
	record.Network = &networkJournal{Phase: "ready", Device: strconv.FormatUint(uint64(netInfo.Dev), 10), Inode: strconv.FormatUint(netInfo.Ino, 10)}
	_, mounts, err := manager.gateMounts(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, mount := range mounts {
			if err := mount.file.Close(); err != nil {
				t.Error(err)
			}
		}
	}()
	mounts, err = manager.appendLaneEndpointMounts(ctx, record, mounts)
	if err != nil {
		t.Fatal(err)
	}
	stdin, prompt := promptInputFixture(t, []byte("native lane endpoint prompt\n"))
	token, err := randomID("lane-endpoint-release-")
	if err != nil {
		t.Fatal(err)
	}
	discard, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer discard.Close()
	payload := gatePayload{stdin: stdin, Prompt: &prompt, Config: binding.Config, Mode: "prepared-gate", GateID: id, Token: string(token),
		UID: lease.UID, GID: lease.GID, Argv: spec.Runner.Argv, CWD: spec.Runner.CWD, Budget: request.Budget, Environment: []string{}}
	gate, err := startNativeGate(ctx, binding, record, payload, mounts, discard, discard, nil, network, boot)
	if err != nil {
		t.Fatal("acceptance: lane gate could not prepare its exact endpoint projections", err)
	}
	t.Cleanup(func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if err := gate.Close(); err != nil {
			t.Error(err)
			return
		}
		if _, err := gate.Stop(cleanup, api.ProcessHandle{}); err != nil {
			t.Error(err)
			return
		}
		if err := manager.waitContainmentEmpty(cleanup, record); err != nil {
			t.Error(err)
			return
		}
		if t.Failed() {
			return // Preserve failed native containment and private storage.
		}
		if err := resources.Remove(cleanup, record); err != nil {
			t.Error(err)
			return
		}
		storageBase := filepath.Join("/var/lib/laneboss-v2/lanes", binding.Config, string(lease.ID))
		for _, item := range record.Storage.Directories {
			if err := os.Remove(filepath.Join(storageBase, string(item.ID))); err != nil {
				t.Error(err)
				return
			}
		}
		if err := os.Remove(storageBase); err != nil {
			t.Error(err)
		}
	})
	assertGateClosed(t, readyRead, "acceptance: lane CLI contacted its service before gate release")
	if err := gate.Release(); err != nil {
		t.Fatal(err)
	}
	if err := readyRead.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(readyRead, ready[:]); err != nil || ready[0] != 2 {
		t.Fatal("acceptance: lane service did not receive the exact credentialed CLI request", err)
	}
	observation, err := gate.Stop(ctx, api.ProcessHandle{})
	if err != nil || observation.State != "exited" || observation.ExitCode == nil || *observation.ExitCode != 0 {
		t.Fatal("acceptance: installed lane CLI did not consume its service response through the sealed binding", err)
	}
	peerErr := peer.Wait()
	peerWaited = true
	if peerErr != nil {
		t.Fatal("acceptance: lane service did not receive the exact credentialed CLI request", peerErr)
	}
}
