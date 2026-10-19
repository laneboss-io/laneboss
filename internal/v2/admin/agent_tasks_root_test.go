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
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func init() {
	if len(os.Args) == 6 && os.Args[1] == "agent-task-service" {
		os.Exit(agentTaskService(os.Args[2], os.Args[3], os.Args[4], os.Args[5]))
	}
}

// The RPC response is a narrow component peer; its UID check and the shipped
// fixture, CLI, native bootstrap, inherited projections and 16-task cgroup are
// real. This does not stand in for the installed identity/store acceptance.
func agentTaskService(socket, config, life, laneUID string) int {
	uid, err := strconv.ParseUint(laneUID, 10, 32)
	if err != nil || os.Geteuid() == 0 {
		return 81
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return 82
	}
	defer listener.Close()
	if os.Chmod(socket, 0666) != nil || listener.SetDeadline(time.Now().Add(35*time.Second)) != nil {
		return 83
	}
	ready := os.NewFile(3, "agent-peer-ready")
	if _, err := ready.Write([]byte{1}); err != nil {
		return 84
	}
	ready.Close()
	connection, err := listener.AcceptUnix()
	if err != nil {
		return 85
	}
	defer connection.Close()
	peer, err := wire.PeerCredentials(connection)
	if err != nil || peer.UID != uint32(uid) || connection.SetDeadline(time.Now().Add(10*time.Second)) != nil {
		return 86
	}
	raw, err := wire.ReadFrame(connection)
	if err != nil {
		return 87
	}
	request, err := wire.DecodeRequest(raw)
	if err != nil || request.Method != "identity.self" || request.Config != config {
		return 88
	}
	scope := api.Scope{Config: config, Actor: api.Actor{Kind: "lane", ID: api.ID(life), LifeID: api.ID(life), Level: 5, Role: "executor"},
		LaunchID: api.ID(life), EndpointGeneration: 1, PolicyGeneration: 1, Source: "lane"}
	result, err := json.Marshal(scope)
	if err != nil || wire.ValidateResult(request.Method, result) != nil {
		return 89
	}
	response, err := json.Marshal(api.Response{Protocol: api.Protocol, Schema: api.SchemaVersion, RequestID: request.RequestID, LastSeq: 1, Result: result})
	if err != nil || wire.WriteFrame(connection, response) != nil {
		return 90
	}
	return 0
}

func TestAgentFixtureTaskBudgetNative(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("agent task canary requires disposable Linux root")
	}
	if os.Args[len(os.Args)-1] == "agent-task-unit" {
		agentTaskUnit(t, os.Args[len(os.Args)-2])
		return
	}
	directory, err := os.MkdirTemp("/run", "lb-agent-tasks-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	workerCanaryWrite(t, filepath.Join(directory, "canary"), self, 0555)
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	repo := filepath.Clean(filepath.Join(cwd, "../../.."))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for name, pkg := range map[string]string{"cli": "./cmd/laneboss", "fixture": "./cmd/laneboss/serve-fixture"} {
		command := exec.CommandContext(ctx, "go", "build", "-tags=laneboss_partial,laneboss_e2e_authenticator", "-o", filepath.Join(directory, name), pkg)
		command.Dir = repo
		command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOCACHE=/private/tmp/lb-shared-gocache")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("agent task canary build failed: %v\n%s", err, output)
		}
	}
	id, err := randomID("tasks-")
	if err != nil {
		t.Fatal(err)
	}
	config := string(id[:23])
	args := []string{"--quiet", "--wait", "--pipe", "--collect", "--unit=laneboss-helper@" + config + ".service"}
	args = append(args, workerCanaryProperties(t, config)...)
	args = append(args, "--property=RuntimeMaxSec=110s", filepath.Join(directory, "canary"), "-test.run=^TestAgentFixtureTaskBudgetNative$", "-test.v", "--", config, "agent-task-unit")
	command := exec.CommandContext(ctx, "/usr/bin/systemd-run", args...)
	command.Env = []string{}
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: TestAgentFixtureTaskBudgetNative")) {
		t.Fatalf("agent/CLI task canary failed under the shipped helper properties: %v\n%s", err, output)
	}
	for _, line := range strings.Split(string(output), "\n") {
		if _, facts, found := strings.Cut(line, "agent task facts: "); found {
			t.Log("agent task facts: " + facts)
		}
	}
}

func agentTaskUnit(t *testing.T, config string) {
	workerCanaryMounts(t)
	accounts := workerCanaryAccounts(t)
	m, _, _ := dataOpenNativeFixture(t, dataOpenFixtureOptions{Config: config, Service: accounts[0], Lanes: accounts[1:]})
	workerCanaryCgroups(t, m)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cli, err := os.ReadFile(filepath.Join(filepath.Dir(self), "cli"))
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile(filepath.Join(filepath.Dir(self), "fixture"))
	if err != nil {
		t.Fatal(err)
	}
	m.binding.Artifact.Bytes, m.binding.Artifact.SHA256 = int64(len(cli)), digestBytes(cli)
	m.binding.Release.Artifacts = []api.ReleaseArtifact{m.binding.Artifact}
	executable := api.Executable{ID: "cli", SHA256: digestBytes(cli), Version: m.binding.Release.Version}
	manifest := api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: executable, Bootstrap: executable,
		Objects: []api.RuntimeObject{{ID: "cli", Role: "bootstrap", RootID: "root", RelativePath: "bootstrap", Mode: 0555,
			Content: api.BlobRef{ID: "cli-bytes", Class: "artifact", Bytes: int64(len(cli)), SHA256: digestBytes(cli)}},
			{ID: "fixture", Role: "agent", RootID: "root", RelativePath: "fixture", Mode: 0555,
				Content: api.BlobRef{ID: "fixture-bytes", Class: "artifact", Bytes: int64(len(fixture)), SHA256: digestBytes(fixture)}}}, Bindings: []api.InstalledBinding{}}
	raw, err := canonicalValue(manifest)
	if err != nil {
		t.Fatal(err)
	}
	ref := api.BlobRef{ID: "agent-task-runtime", Class: "manifest", Bytes: int64(len(raw)), SHA256: digestBytes(raw)}
	base := filepath.Join(filepath.Dir(m.binding.binaryPath()), "runtime", config)
	for _, path := range []string{filepath.Join(base, "root"), filepath.Dir(bindingPath(config)), "/etc/laneboss-v2/boot", "/etc/laneboss-v2/bindings", m.binding.runtimePath()} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	workerCanaryWrite(t, m.binding.binaryPath(), cli, 0555)
	workerCanaryWrite(t, filepath.Join(base, "root/bootstrap"), cli, 0555)
	workerCanaryWrite(t, filepath.Join(base, "root/fixture"), fixture, 0555)
	workerCanaryWrite(t, filepath.Join(base, "manifest.json"), raw, 0444)
	workerCanaryJSON(t, filepath.Join(base, "roots.json"), []enrolledRoot{{ID: "root", Path: filepath.Join(base, "root")}}, 0444)
	workerCanaryJSON(t, bindingPath(config), m.binding, 0644)
	workerCanaryJSON(t, filepath.Join("/etc/laneboss-v2/boot", config+".json"), bootCatalog{Schema: "laneboss.boot-catalog.v2", Revision: api.ContractRevision, Config: config,
		Files: []enrolledFile{}, Directories: []enrolledDirectory{}, Accounts: []account{}, RuntimeFile: filepath.Join(base, "manifest.json"), RuntimeManifest: ref,
		RuntimeRoots: []enrolledRoot{{ID: "root", Path: filepath.Join(base, "root")}}}, 0444)
	for _, tree := range []string{"/usr/lib/laneboss-v2", "/etc/laneboss-v2"} {
		if err := filepath.WalkDir(tree, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return os.Chmod(path, 0755)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	m.bootID = strings.TrimSpace(string(boot))
	serviceBase := filepath.Join("/run/laneboss-v2/services", config)
	for _, path := range []string{filepath.Dir(serviceBase), serviceBase, filepath.Join(serviceBase, "lanes")} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Dir(serviceBase), 0755); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{serviceBase, filepath.Join(serviceBase, "lanes")} {
		if err := errors.Join(os.Chown(path, int(m.binding.Service.UID), int(m.binding.Service.GID)), os.Chmod(path, 0700)); err != nil {
			t.Fatal(err)
		}
	}
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion,
		Config: config, Class: api.EndpointHuman, ServiceUID: m.binding.Service.UID, ServiceGID: m.binding.Service.GID, Socket: filepath.Join(serviceBase, "human.sock"),
		Backend: "linux-bwrap-landlock", ServiceVersion: m.binding.Release.Version, ArtifactSHA256: digestBytes(cli), InstallationGeneration: m.binding.Generation, EndpointGeneration: m.binding.Generation}
	workerCanaryJSON(t, filepath.Join("/etc/laneboss-v2/bindings", config+".json"), endpoint, 0444)
	closeProc, err := mountHelperProc(m.binding.runtimePath())
	if err != nil {
		t.Fatal(err)
	}
	defer closeProc()
	for _, driver := range []api.Driver{api.DriverCodex, api.DriverClaudock} {
		t.Run(string(driver), func(t *testing.T) { agentTaskRun(t, m, ref, self, serviceBase, driver) })
	}
}

func agentTaskRun(t *testing.T, m *leaseManager, runtimeRef api.BlobRef, self, serviceBase string, driver api.Driver) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	id, err := randomID("")
	if err != nil {
		t.Fatal(err)
	}
	lease := api.HelperLease{ID: id, ContainmentID: id, UID: m.binding.Lanes[0].UID, GID: m.binding.Lanes[0].GID, EndpointGeneration: 1}
	request := testAllocation()
	request.Config, request.Cause.Config, request.LifeID, request.Cause.Target = m.binding.Config, m.binding.Config, id, api.LifeRef{LifeID: id, Run: 1}
	request.RuntimeManifestID = runtimeRef.ID
	request.Budget = api.Budget{WallMS: 60000, CPUSeconds: 30, MemoryBytes: 268435456, Processes: 16, DiskBytes: 33554432, Currency: "USD"}
	record := leaseRecord{Lease: lease, Request: request, Phase: "reserved", BootID: m.bootID,
		Spec: &specRegistration{Handoff: api.PreparedSpecHandoff{Spec: api.LaunchSpec{Kind: "agent", LaunchID: id, Target: request.Cause.Target, UIDLeaseID: id,
			EndpointGeneration: 1, Backend: "linux-bwrap-landlock", RuntimeManifest: runtimeRef, Runner: &api.RunnerPlan{Driver: driver}}}}}
	resources := &linuxResources{binding: m.binding, manager: m}
	m.resources = resources
	if err := resources.Ensure(ctx, record); err != nil {
		t.Fatal(err)
	}
	record.Phase = "active"
	peerRead, peerWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer peerRead.Close()
	socket := filepath.Join(serviceBase, "lanes", string(id)+".sock")
	peer := exec.CommandContext(ctx, self, "agent-task-service", socket, m.binding.Config, string(id), strconv.FormatUint(uint64(lease.UID), 10))
	peer.Env, peer.ExtraFiles = []string{}, []*os.File{peerWrite}
	peer.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: m.binding.Service.UID, Gid: m.binding.Service.GID, Groups: []uint32{}}}
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	peerWrite.Close()
	peerWaited := false
	defer func() {
		if !peerWaited {
			cancel()
			peer.Wait()
		}
	}()
	peerRead.SetReadDeadline(time.Now().Add(5 * time.Second))
	var ready [1]byte
	if _, err := io.ReadFull(peerRead, ready[:]); err != nil || ready[0] != 1 {
		waitErr := peer.Wait()
		peerWaited = true
		t.Fatalf("agent task service peer did not become ready: read=%v wait=%v", err, waitErr)
	}
	_, mounts, err := m.gateMounts(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	work := privateTestDir(t)
	if err := os.Chmod(filepath.Dir(work), 0755); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(os.Chown(work, int(lease.UID), int(lease.GID)), os.Chmod(work, 0700)); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/work/main", "/home/lane"} {
		mount, err := pinNativeMount(work, target, true, true, true, lease.UID, lease.GID)
		if err != nil {
			t.Fatal(err)
		}
		mounts = append(mounts, mount)
	}
	mounts, err = m.appendLaneEndpointMounts(ctx, record, mounts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, mount := range mounts {
			mount.file.Close()
		}
	}()
	stdin, prompt := promptInputFixture(t, []byte("task-budget native prompt\n"))
	defer stdin.Close()
	stdout, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdout.Close()
	defer output.Close()
	stderr, err := os.OpenFile(filepath.Join(work, "native.stderr"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	group := filepath.Join(m.binding.cgroupPath(), string(lease.ContainmentID))
	readCount := func(name string) uint64 {
		raw, err := os.ReadFile(filepath.Join(group, name))
		if err != nil {
			t.Fatal("agent task cgroup measurement unavailable", err)
		}
		value, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	if readCount("pids.max") != 16 {
		t.Fatal("agent task canary changed its installed 16-task budget")
	}
	beforeRaw, err := os.ReadFile(filepath.Join(group, "pids.events"))
	before, valid := parseNativeEvents(beforeRaw)
	if err != nil || !valid {
		t.Fatal("agent task event baseline unavailable", err)
	}
	token, err := randomID("release-")
	if err != nil {
		t.Fatal(err)
	}
	argv := []string{"/runtime/fixture", "--config", m.binding.Config, "--client", wire.LaneClientPath, "--binding", wire.LaneBindingPath,
		"--challenge", string(id), "--life", string(id), "--run", "1", "--mode", "lifecycle", "--driver", string(driver),
		"--session", string(id), "--home", string(id), "--history", string(id), "--vendor-session", string(id), "--model", "fixture-model", "--effort", "high", "--wait-ms", "60000"}
	payload := gatePayload{Config: m.binding.Config, Mode: "prepared-gate", GateID: id, Token: string(token), UID: lease.UID, GID: lease.GID,
		Argv: argv, CWD: "/work/main", Environment: agentEnvironment(driver), Budget: request.Budget, stdin: stdin, Prompt: &prompt}
	gate, err := startNativeGate(ctx, m.binding, record, payload, mounts, output, stderr, nil, nil, m.bootID)
	if err != nil {
		raw, readErr := os.ReadFile(stderr.Name())
		if readErr != nil {
			t.Fatal("cannot read retained native setup diagnostics", readErr)
		}
		if match := regexp.MustCompile(`Can't find source path ([^\n]+)`).FindSubmatch(raw); len(match) == 2 {
			category := "other"
			for _, known := range []string{"/proc/self/fd/", "/dev/", "/proc/"} {
				if bytes.Contains(match[1], []byte(known)) {
					category = known
				}
			}
			t.Logf("native mount source facts: category=%s fd_tokens=%v", category, regexp.MustCompile(`/proc/self/fd/[0-9]+`).FindAllString(string(match[1]), -1))
		}
		t.Fatal("agent task bootstrap did not reach its real prepared gate", err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	if m.gates == nil {
		m.gates = make(map[api.ID]ownedGate)
	}
	m.gates[lease.ID] = gate
	defer func() {
		gate.Close()
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if _, err := gate.Stop(cleanup, api.ProcessHandle{}); err != nil {
			t.Error(err)
			return
		}
		if err := m.waitContainmentEmpty(cleanup, record); err != nil {
			t.Error(err)
			return
		}
		if !t.Failed() {
			if err := resources.Remove(cleanup, record); err != nil {
				t.Error(err)
			}
		}
	}()
	if err := gate.Release(); err != nil {
		t.Fatal(err)
	}
	stdout.SetReadDeadline(time.Now().Add(20 * time.Second))
	var observed map[string]any
	decodeErr := json.NewDecoder(stdout).Decode(&observed)
	afterRaw, eventErr := os.ReadFile(filepath.Join(group, "pids.events"))
	after, valid := parseNativeEvents(afterRaw)
	peak := readCount("pids.peak")
	if decodeErr != nil || eventErr != nil || !valid || after["max"] != before["max"] || peak > 16 || observed["type"] != "serve.session" {
		t.Fatalf("agent and actual CLI failed their shared budget: decode=%v events=%v pids_peak=%d max_delta=%d", decodeErr, eventErr, peak, after["max"]-before["max"])
	}
	if err := peer.Wait(); err != nil {
		t.Fatal("actual CLI did not complete its native service exchange", err)
	}
	peerWaited = true
	observation, err := gate.Observe(ctx, api.ProcessHandle{})
	if err != nil || observation.State != "running" {
		t.Fatal("fixture was not still running after its CLI completed", err)
	}
	t.Logf("agent task facts: driver=%s pids_peak=%d pids_max=16 max_delta=0 cli_exchange=complete fixture=running", driver, peak)
}
