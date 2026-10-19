//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	linuxunit "laneboss.io/laneboss/packaging/v2/linux"
)

// Only durable service metadata is a fixture. The production helper handler,
// authenticated unprivileged client, sealed projected files, native bootstrap,
// pidfds, namespaces, cgroups, allocation flock and guard protocol are real.
// This does not claim a full installed service or materialization completion.
type workerCanaryStore struct {
	api.StateStore
	Binding   api.LaunchBindingRequest
	Principal api.WorkerPrincipal
}

func (s *workerCanaryStore) LaunchBinding(_ context.Context, id api.ID) (api.LaunchBindingRequest, error) {
	if id != s.Binding.Record.ID {
		return api.LaunchBindingRequest{}, failure(api.CodeNotFound, "canary has no such committed worker")
	}
	return s.Binding, nil
}

func (s *workerCanaryStore) WorkerBinding(_ context.Context, endpoint api.InstalledBinding, peer api.PeerFacts) (api.WorkerPrincipal, error) {
	if !reflect.DeepEqual(endpoint, s.Principal.Endpoint) || peer != s.Principal.Peer {
		return api.WorkerPrincipal{}, failure(api.CodeUnauthenticated, "canary principal differs from the independently measured native worker")
	}
	return s.Principal, nil
}

type workerCanaryInput struct {
	Binding  installation
	Store    workerCanaryStore
	Mode     string
	DataOpen *dataReg
}

func TestWorkerLaunchNative(t *testing.T) {
	workerLaunchCanary(t, false)
}

var materializationCanaryDriver func(*testing.T, context.Context, *leaseManager, dataReg, api.BlobRef, api.Executable)

func workerLaunchCanary(t *testing.T, retry bool, drivers ...func(*testing.T, context.Context, *leaseManager, dataReg, api.BlobRef, api.Executable)) {
	if os.Args[len(os.Args)-1] == "worker-copy" {
		workerStorageCopy(t)
		return
	}
	if os.Args[len(os.Args)-1] == "worker-hold" {
		workerStorageHold(t)
		return
	}
	if os.Geteuid() != 0 && os.Args[len(os.Args)-1] != "worker-client" {
		t.Fatal("worker handoff canary requires the disposable root Linux step")
	}
	if os.Args[len(os.Args)-1] == "worker-client" {
		workerCanaryClient(t)
		return
	}
	if os.Args[len(os.Args)-1] != "worker-root" {
		workerCanaryReapPrior(t)
		self, err := os.ReadFile("/proc/self/exe")
		if err != nil {
			t.Fatal(err)
		}
		id, err := randomID("worker-")
		if err != nil {
			t.Fatal(err)
		}
		config := string(id[:23])
		directory, err := os.MkdirTemp("/run", "lb-v2-serve2-worker-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(directory)
		binary := filepath.Join(directory, "canary")
		workerCanaryWrite(t, binary, self, 0555)
		cwd := workerCanarySources(t, directory)
		properties := workerCanaryProperties(t, config)
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		args := []string{"--quiet", "--wait", "--pipe", "--unit=laneboss-helper@" + config + ".service"}
		args = append(args, properties...)
		args = append(args, "--property=RuntimeMaxSec=80s", "--property=WorkingDirectory="+cwd,
			binary, "-test.run=^"+t.Name()+"$", "-test.v", "--", config, "worker-root")
		command := exec.CommandContext(ctx, "/usr/bin/systemd-run", args...)
		command.Env = []string{}
		command.WaitDelay = 3 * time.Second
		output, err := command.CombinedOutput()
		if err != nil || !bytes.Contains(output, []byte("--- PASS: "+t.Name()+" ")) {
			workerCanaryUnitResult(t, config)
			t.Fatalf("real helper worker handoff child failed: %v\n%s", err, output)
		}
		// Preserve the child's measured observations in the retained transcript.
		t.Log(string(output))
		logArchiveCost(t, output)
		if t.Name() == "TestMaterializationNative" {
			if !bytes.Contains(output, []byte(`{"event":"worker_exit","status":"exit_0","stderr":"none"}`)) {
				t.Fatal("successful native materialization lost its measured worker exit journal")
			}
			t.Log("native worker journal: exit_0 stderr=none")
			if !bytes.Contains(output, []byte("native capture registered after return; measured spool bytes and EOF")) {
				t.Fatal("native materialization did not reach capture registration and actual pipe EOF")
			}
			t.Log("native capture: registered after return; spool bytes and EOF verified")
			for _, line := range strings.Split(string(output), "\n") {
				if _, facts, found := strings.Cut(line, "native worker resource facts: "); found {
					t.Log("native worker resource facts: " + facts)
				}
			}
		}
		for _, line := range strings.Split(string(output), "\n") {
			if _, fact, found := strings.Cut(line, "native worker task peak: "); found {
				t.Log("native worker task peak: " + fact)
			}
			if strings.Contains(line, "native worker resource facts:") && strings.HasPrefix(t.Name(), "TestMaterializationTaskPeaks") {
				t.Log(strings.TrimSpace(line))
			}
		}
		return
	}
	workerCanaryMounts(t)
	t.Log("canary phase: private mounts ready")
	accounts := workerCanaryAccounts(t)
	m, reg, cacheInput := dataOpenNativeFixture(t, dataOpenFixtureOptions{Config: os.Args[len(os.Args)-2], Service: accounts[0], Lanes: accounts[1:]})
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-B", "testdata/source_cache_canary.py", cacheInput, m.binding.statePath())
	command.Env = []string{}
	if output, err := command.CombinedOutput(); err != nil || string(output) != "source-cache:changed\n" {
		t.Fatal("worker canary could not install its approved source cache", err)
	}
	t.Log("canary phase: source cache ready")
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	m.binding.Artifact.Bytes, m.binding.Artifact.SHA256 = int64(len(self)), digestBytes(self)
	m.binding.Release.Artifacts = []api.ReleaseArtifact{m.binding.Artifact}
	executable := api.Executable{ID: "artifact", Version: m.binding.Release.Version, SHA256: m.binding.Artifact.SHA256}
	manifest := api.RuntimeManifest{Schema: "laneboss.runtime.v2", Generation: 1, Artifact: executable, Bootstrap: executable,
		Objects: []api.RuntimeObject{{ID: executable.ID, Role: "bootstrap", RootID: "root", RelativePath: "bootstrap", Mode: 0555,
			Content: api.BlobRef{ID: "bootstrap-bytes", Class: "artifact", Bytes: int64(len(self)), SHA256: digestBytes(self)}}}, Bindings: []api.InstalledBinding{}}
	libraries := workerCanaryLibraries(t, &manifest)
	runtimeBytes, err := canonicalValue(manifest)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRef := api.BlobRef{ID: "canary-runtime", Class: "manifest", Bytes: int64(len(runtimeBytes)), SHA256: digestBytes(runtimeBytes)}
	base := filepath.Join(filepath.Dir(m.binding.binaryPath()), "runtime", m.binding.Config)
	for _, directory := range []string{filepath.Dir(bindingPath(m.binding.Config)), filepath.Join("/etc/laneboss-v2", "boot"), filepath.Join("/etc/laneboss-v2", "bindings"), filepath.Join(base, "root"), m.binding.runtimePath()} {
		if err := os.MkdirAll(directory, 0755); err != nil {
			t.Fatal(err)
		}
	}
	workerCanaryWrite(t, m.binding.binaryPath(), self, 0555)
	workerCanaryWrite(t, filepath.Join(base, "root", "bootstrap"), self, 0555)
	for relative, content := range libraries {
		path := filepath.Join(base, "root", relative)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		workerCanaryWrite(t, path, content, 0555)
	}
	workerCanaryWrite(t, filepath.Join(base, "manifest.json"), runtimeBytes, 0444)
	workerCanaryJSON(t, filepath.Join(base, "roots.json"), []enrolledRoot{{ID: "root", Path: filepath.Join(base, "root")}}, 0444)
	workerCanaryJSON(t, bindingPath(m.binding.Config), m.binding, 0644)
	workerCanaryJSON(t, filepath.Join("/etc/laneboss-v2/boot", m.binding.Config+".json"), bootCatalog{Schema: "laneboss.boot-catalog.v2", Revision: api.ContractRevision, Config: m.binding.Config,
		Files: []enrolledFile{}, Directories: []enrolledDirectory{}, Accounts: []account{},
		RuntimeFile: filepath.Join(base, "manifest.json"), RuntimeManifest: runtimeRef, RuntimeRoots: []enrolledRoot{{ID: "root", Path: filepath.Join(base, "root")}}}, 0444)
	// These directories are installer fixtures, created before the real helper
	// starts in production. Give them their declared modes despite UMask=0077.
	for _, tree := range []string{"/usr/lib/laneboss-v2", "/etc/laneboss-v2"} {
		if err := filepath.WalkDir(tree, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
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
	parent, err := m.find(reg.Request.AgentLeaseID)
	if err != nil {
		t.Fatal(err)
	}
	parent.BootID = m.bootID
	parent.Request.RuntimeManifestID = runtimeRef.ID
	parent.Request.Budget.MemoryBytes, parent.Request.Budget.Processes, parent.Request.Budget.WallMS = 256<<20, 64, 30000
	if name := strings.Split(t.Name(), "/")[0]; name == "TestArchiveLaunchNative" || name == "TestArchiveFixtureNative" || name == "TestReviewLaunchNative" || name == "TestNativeChildLaunch" || name == "TestCheckLaunchNative" {
		parent.Request.Budget.CPUSeconds, parent.Request.Budget.DiskBytes, parent.Request.Budget.Currency = 10, 4<<20, "USD"
	} else if retry || strings.HasPrefix(t.Name(), "TestMaterialization") {
		// Match the installed serve fixture's declared task ceilings.
		parent.Request.Budget = api.Budget{WallMS: 60000, CPUSeconds: 30, MemoryBytes: 268435456, Processes: 16, DiskBytes: 33554432, Currency: "USD"}
	}
	if t.Name() == "TestMaterializationNativeCopies" {
		// Two independent 65 MiB views plus the main project must fit the
		// explicit test allocation; no installed default is changed.
		parent.Request.Budget.DiskBytes = 256 << 20
	}
	parent.LaunchAllocations[0].Request = parent.Request
	parent.LaunchAllocations[0].Inputs.Sources.Runtime.Manifest = runtimeRef
	parent.LaunchAllocations[0].Inputs.Sources.Runtime.Executable = executable
	reg.Inputs = parent.LaunchAllocations[0].Inputs
	reg.Worker.RuntimeManifest, reg.Plan.Executable = runtimeRef, executable
	reg.Plan.Budget = parent.Request.Budget
	// The allocation effect retains the planner's stable author. Its live
	// executor is a different service claimant, as in the installed outbox.
	original := parent.Request
	live := original
	live.Cause.Actor.ID = "native-allocation-claimant"
	authority := launchAuthority{Record: api.LaunchPlanRecord{Reservation: parent.LaunchAllocations[0].Reservation, Inputs: &reg.Inputs},
		Claim: api.EffectRecord{Effect: api.Effect{HelperAllocate: &original}}, Policy: parent.LaunchAllocations[0].Policy}
	parent.LaunchAllocations[0] = launchAllocationForAuthority(authority, live)
	parent.Request = parent.LaunchAllocations[0].Request
	if err := m.save(parent); err != nil {
		t.Fatal(err)
	}
	workerCanaryCgroups(t, m)
	t.Log("canary phase: control group ready")
	for _, directory := range []string{"/var/lib/laneboss-v2/lanes", filepath.Dir(laneStagePath(m.binding, parent.Lease.ID))} {
		if err := os.Chmod(directory, 0755); err != nil {
			t.Fatal(err)
		}
	}
	resources := &linuxResources{binding: m.binding, manager: m}
	m.resources = resources
	if len(drivers) == 1 {
		drivers[0](t, ctx, m, reg, runtimeRef, executable)
		return
	}
	if strings.HasPrefix(t.Name(), "TestMaterialization") {
		if materializationCanaryDriver == nil {
			t.Fatal("materialization integration canary is not built")
		}
		materializationCanaryDriver(t, ctx, m, reg, runtimeRef, executable)
		return
	}
	if strings.Split(t.Name(), "/")[0] == "TestArchiveLaunchNative" || strings.Split(t.Name(), "/")[0] == "TestReviewLaunchNative" {
		archiveLaunchCanary(t, ctx, m, reg, runtimeRef, executable)
		return
	}
	workerCanaryServe(t, ctx, m, workerCanaryStore{}, reg)
	parent, index, err := m.findData(reg.Request)
	if err != nil {
		t.Fatal(err)
	}
	job := parent.DataJobs[index]
	t.Cleanup(func() {
		if err := m.dataPins[job.Projection.OpenToken].close(); err != nil {
			t.Error(err)
		}
	})
	outputRef := api.BlobRef{ID: "worker-output", Class: "manifest", Bytes: 1, SHA256: digestBytes([]byte("fixture output reference"))}
	if retry {
		manifest := m.dataPins[job.Projection.OpenToken].manifest
		outputRef.Bytes, outputRef.SHA256 = int64(len(manifest)), digestBytes(manifest)
	}
	input, err := canonicalValue(dataInput{Schema: "laneboss.materialize-input.v2", StageID: reg.Request.StageID, Reservation: reg.Reservation,
		Source: reg.Inputs.Sources.Project, Storage: job.Projection, Grants: reg.Grants, Budget: reg.Plan.Budget,
		Output: outputRef})
	if err != nil {
		t.Fatal(err)
	}
	reg.Worker.Input = api.BlobRef{ID: "worker-input", Class: "materialize_input", Bytes: int64(len(input)), SHA256: digestBytes(input)}
	reg.Worker.ConsumedBy, reg.Plan.Input = reg.LaunchID, reg.Worker.Input
	servicePath := filepath.Join("/run/laneboss-v2/services", m.binding.Config)
	for _, directory := range []string{filepath.Dir(servicePath), servicePath, filepath.Join(servicePath, "workers")} {
		if err := os.MkdirAll(directory, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(filepath.Dir(servicePath), 0755); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{servicePath, filepath.Join(servicePath, "workers")} {
		if err := errors.Join(os.Chown(directory, int(m.binding.Service.UID), int(m.binding.Service.GID)), os.Chmod(directory, 0700)); err != nil {
			t.Fatal(err)
		}
	}
	endpoint := api.InstalledBinding{Schema: "laneboss.binding.v2", ContractRevision: api.ContractRevision, Protocol: api.Protocol, APISchema: api.SchemaVersion,
		Config: m.binding.Config, Class: api.EndpointHuman, ServiceUID: m.binding.Service.UID, ServiceGID: m.binding.Service.GID, Socket: filepath.Join(servicePath, "human.sock"),
		Backend: "linux-bwrap-landlock", ServiceVersion: m.binding.Release.Version, ArtifactSHA256: m.binding.Artifact.SHA256, InstallationGeneration: m.binding.Generation, EndpointGeneration: m.binding.Generation}
	workerCanaryJSON(t, filepath.Join("/etc/laneboss-v2/bindings", m.binding.Config+".json"), endpoint, 0444)
	socket, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(servicePath, "workers", string(reg.Worker.ID)+".sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	if err := errors.Join(os.Chown(socket.Addr().String(), int(m.binding.Service.UID), int(m.binding.Service.GID)), os.Chmod(socket.Addr().String(), 0666)); err != nil {
		t.Fatal(err)
	}
	endpoint.Class, endpoint.Socket, endpoint.LaunchID, endpoint.Target, endpoint.WorkerLeaseID = api.EndpointWorker, "/runtime/laneboss-worker.sock", reg.LaunchID, &reg.Worker.Target, reg.Worker.ID
	spec := api.LaunchSpec{ID: "worker-spec", Kind: "worker", PlanID: reg.Reservation.ID, Worker: &reg.Plan, LaunchID: reg.LaunchID, Target: reg.Worker.Target,
		UIDLeaseID: job.Lease.ID, Backend: endpoint.Backend, EndpointGeneration: job.Lease.EndpointGeneration, PolicyGeneration: reg.Reservation.PolicyGeneration,
		RuntimeManifest: runtimeRef, Budget: reg.Plan.Budget, Grants: reg.Grants, Materialization: api.Materialization{GrantSetID: reg.Grants.ID, Objects: []api.MaterializedObject{}},
		Injection: api.Injection{Target: reg.Worker.Target, Outcome: "prepared", SlotIDs: []api.ID{}, GrantIDs: []api.ID{}, SourceVersions: []string{}, TaskSecretNames: []string{}, TaskSecretFileNames: []string{}}}
	originalBytes, err := canonicalValue(spec)
	if err != nil {
		t.Fatal(err)
	}
	cause := parent.Request.Cause
	cause.Kind, cause.EffectID, cause.CauseOperationID, cause.CauseRequestID, cause.CancellationEpoch = api.InternalHelperRegister, reg.Worker.EffectID, reg.Reservation.OperationID, reg.Reservation.RequestID, reg.Reservation.CancellationEpoch
	handoff := api.PreparedSpecHandoff{Cause: cause, Config: m.binding.Config, Spec: spec, SpecSHA256: digestBytes(originalBytes), OperationID: reg.Reservation.OperationID, RequestID: reg.Reservation.RequestID,
		Original: api.BlobRef{ID: "worker-spec-bytes", Class: "launch_spec", Bytes: int64(len(originalBytes)), SHA256: digestBytes(originalBytes)}}
	if _, err := m.registerData(ctx, dataSeal{Reg: reg, Spec: specRegistration{Handoff: handoff, Original: originalBytes}, Endpoint: endpoint, Input: input}); err != nil {
		t.Fatal("real worker registration failed", err)
	}
	if retry {
		workerStorageRetry(t, ctx, m, reg)
		return
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
		t.Fatal("real confined worker preparation failed", err)
	}
	t.Cleanup(func() {
		gate := m.gates[job.Lease.ID]
		if err := gate.Close(); err != nil {
			t.Error(err)
			return
		}
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		if _, err := gate.Stop(cleanup, api.ProcessHandle{}); err != nil {
			t.Error(err)
			return
		}
		if err := m.waitContainmentEmpty(cleanup, dataChild(parent, job)); err != nil {
			t.Error(err)
		}
	})
	native, err := m.dataNative(ctx, reg)
	if err != nil {
		t.Fatal(err)
	}
	record := api.LaunchRecord{Kind: "worker", ID: reg.LaunchID, Config: m.binding.Config, Actor: api.Actor{Kind: "worker", ID: "native-job-principal"}, Target: reg.Worker.Target,
		StarterChain: append([]api.ID{}, reg.Reservation.StarterChain...),
		UIDLeaseID:   job.Lease.ID, HostUID: job.Lease.UID, ContainmentID: job.Lease.ContainmentID, ProcessGeneration: prepared.ProcessGeneration,
		GrantSetID: reg.Grants.ID, GrantsSHA256: reg.Grants.SHA256, PolicyGeneration: reg.Reservation.PolicyGeneration, EndpointGeneration: prepared.EndpointGeneration}
	binding := api.LaunchBindingRequest{Record: record, Prepared: prepared, Identity: api.IdentityCommit{LaunchID: record.ID, EventID: "canary-bound", RecordSHA256: digestBytes(mustCanaryJSON(t, record)), CommittedSeq: 7}}
	store := workerCanaryStore{Binding: binding, Principal: api.WorkerPrincipal{StageID: reg.Request.StageID, Lease: reg.Worker, Record: record, Endpoint: endpoint,
		Peer: native.Peer, BootID: m.bootID, AllocationGeneration: job.Projection.Generation, CancellationEpoch: reg.Reservation.CancellationEpoch}}
	workerCanaryServe(t, ctx, m, store)
}

// Consume the shipped template, including implicit seccomp hardening and the
// exact capability ceiling. Only ExecStart/Type are supplied by systemd-run.
func workerCanaryProperties(t *testing.T, config string) []string {
	t.Helper()
	var properties []string
	var writable []string
	service := false
	for _, line := range strings.Split(linuxunit.HelperTemplate(), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			service = line == "[Service]"
		}
		if !service || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok || name == "ExecStart" || name == "Type" {
			continue
		}
		value = strings.ReplaceAll(value, "%i", config)
		value = strings.ReplaceAll(value, "@CRED@", CredentialRuntimeDirectory(config))
		if name == "ReadWritePaths" {
			writable = append(writable, strings.Fields(value)...)
			continue
		}
		properties = append(properties, "--property="+name+"="+value)
	}
	for _, path := range append([]string{"/etc/laneboss-v2", "/usr/lib/laneboss-v2", "/run/laneboss-v2"}, writable...) {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	return append(properties, "--property=ReadWritePaths="+strings.Join(writable, " "))
}

// PrivateTmp/ProtectHome must not hide test inputs. Stage the real
// installer source files in /run, retaining their normal relative layout.
func workerCanarySources(t *testing.T, directory string) string {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("native worker canary cannot find its source module")
		}
		root = parent
	}
	for _, relative := range []string{"internal/v2/admin/" + "testdata/source_cache_canary.py", "scripts/v2-admin/boot.py", "scripts/v2-admin/runtime_deps.py", "scripts/v2-admin/runtime_files.py"} {
		raw, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(directory, "source", relative)
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			t.Fatal(err)
		}
		workerCanaryWrite(t, target, raw, 0444)
	}
	return filepath.Join(directory, "source/internal/v2/admin")
}

// Keep failed fixture units long enough to read the kernel/systemd exit facts.
// Only this canary's named result fields are emitted, never unit settings or
// process arguments. This observation cannot turn a failed assertion into a pass.
func workerCanaryUnitResult(t *testing.T, config string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "laneboss-helper@"+config+".service", "--property=Result,ExecMainCode,ExecMainStatus,SubState,MemoryPeak,MemoryMax,OOMPolicy")
	command.Env = []string{}
	output, err := command.Output()
	if err != nil {
		t.Log("native fixture exit observation: unavailable")
		return
	}
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "Result", "ExecMainCode", "ExecMainStatus", "SubState", "MemoryPeak", "MemoryMax", "OOMPolicy":
			t.Logf("native fixture exit observation: %s=%s", key, value)
		}
	}
	journal := exec.CommandContext(ctx, "/usr/bin/journalctl", "--unit=laneboss-helper@"+config+".service", "--no-pager", "--output=cat", "--lines=30")
	journal.Env = []string{}
	data, journalErr := journal.Output()
	message := strings.ToLower(string(data))
	t.Logf("native unit journal: read=%t oom=%t stopping=%t killed=%t",
		journalErr == nil, strings.Contains(message, "oom") || strings.Contains(message, "out of memory"),
		strings.Contains(message, "stopping"), strings.Contains(message, "killed"))
}

func mustCanaryJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := canonicalValue(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func workerCanaryWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func workerCanaryJSON(t *testing.T, path string, value any, mode os.FileMode) {
	t.Helper()
	workerCanaryWrite(t, path, mustCanaryJSON(t, value), mode)
}

func workerCanaryMounts(t *testing.T) {
	t.Helper()
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/etc/laneboss-v2", "/usr/lib/laneboss-v2", "/var/lib/laneboss-v2", "/run/laneboss-v2"} {
		if err := os.MkdirAll(path, 0755); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mount("tmpfs", path, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"); err != nil {
			t.Fatal(err)
		}
		// The private subprocess's namespace owns and collects these mounts.
	}
}

// A timed-out parent must not strand this lane's earlier disposable unit.
// Select only this fixture's root-owned staged executable and fixed helper
// control cgroup, then stop the observed process through its original pidfd.
// No command-line pattern, PID-only signal or unrelated unit is selected.
func workerCanaryReapPrior(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 || pid == os.Getpid() {
			continue
		}
		path, err := os.Readlink("/proc/" + entry.Name() + "/exe")
		if err != nil || !strings.HasPrefix(path, "/run/lb-v2-serve2-worker-") || filepath.Base(path) != "canary" {
			continue
		}
		membership, err := cgroupMembership(pid)
		if err != nil {
			continue // A vanished process owns no live fixture to collect.
		}
		config, err := helperControlConfig(membership)
		if err != nil || !strings.HasPrefix(config, "worker-") {
			continue
		}
		var staged unix.Stat_t
		if unix.Lstat(path, &staged) != nil || staged.Uid != 0 || staged.Mode&unix.S_IFMT != unix.S_IFREG || staged.Mode&07777 != 0555 {
			t.Fatal("prior worker canary executable lost its protected identity")
		}
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			t.Fatal("cannot pin prior worker canary for collection")
		}
		var executing unix.Stat_t
		if unix.Stat("/proc/"+entry.Name()+"/exe", &executing) != nil || executing.Dev != staged.Dev || executing.Ino != staged.Ino {
			unix.Close(fd)
			t.Fatal("prior worker canary changed while its lifetime was pinned")
		}
		err = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		count, pollErr := unix.Poll(poll, 5000)
		closeErr := unix.Close(fd)
		if err != nil || pollErr != nil || count != 1 || poll[0].Revents&unix.POLLIN == 0 || closeErr != nil {
			t.Fatal("prior worker canary did not reach measured collection")
		}
	}
}

func workerCanaryAccounts(t *testing.T) []account {
	t.Helper()
	var accounts []account
	for _, name := range []string{"nobody", "daemon", "bin", "sys"} {
		entry, err := user.Lookup(name)
		if err != nil {
			t.Fatal("worker canary requires its locked noninteractive system accounts")
		}
		uid, uidErr := strconv.ParseUint(entry.Uid, 10, 32)
		gid, gidErr := strconv.ParseUint(entry.Gid, 10, 32)
		if uidErr != nil || gidErr != nil {
			t.Fatal("worker canary system account is not numeric")
		}
		account := account{Name: name, UID: uint32(uid), GID: uint32(gid)}
		if err := checkAccount(account); err != nil {
			t.Fatal("worker canary system account failed its real installation check", err)
		}
		accounts = append(accounts, account)
	}
	return accounts
}

// The ordinary test binary may use the system dynamic loader. Enroll the
// actual loader/libc bytes as runtime objects so both ordinary and static
// builds exercise the identical bootstrap instead of skipping either one.
func workerCanaryLibraries(t *testing.T, manifest *api.RuntimeManifest) map[string][]byte {
	t.Helper()
	binary, err := elf.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer binary.Close()
	paths := []string{}
	for _, program := range binary.Progs {
		if program.Type == elf.PT_INTERP {
			raw, err := io.ReadAll(program.Open())
			if err != nil {
				t.Fatal(err)
			}
			paths = append(paths, strings.TrimRight(string(raw), "\x00"))
		}
	}
	names, err := binary.ImportedLibraries()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		found := ""
		for _, directory := range []string{"/lib/x86_64-linux-gnu", "/lib/aarch64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu"} {
			candidate := filepath.Join(directory, name)
			if _, err := os.Stat(candidate); err == nil {
				found = candidate
				break
			}
		}
		if found == "" {
			t.Fatal("native worker canary cannot enroll a required system library")
		}
		paths = append(paths, found)
	}
	contents := map[string][]byte{}
	for i, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		relative := strings.TrimPrefix(path, "/")
		contents[relative] = content
		id := api.ID("library-" + strconv.Itoa(i))
		manifest.Objects = append(manifest.Objects, api.RuntimeObject{ID: id, Role: "library", RootID: "root", RelativePath: relative, Mode: 0555,
			Content: api.BlobRef{ID: id, Class: "artifact", Bytes: int64(len(content)), SHA256: digestBytes(content)}})
	}
	return contents
}

func workerCanaryCgroups(t *testing.T, m *leaseManager) {
	t.Helper()
	original, err := cgroupMembership(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Dir(m.binding.cgroupPath())
	service := filepath.Join("/sys/fs/cgroup/system.slice", "laneboss-service@"+m.binding.Config+".service")
	if original != strings.TrimPrefix(helper, "/sys/fs/cgroup") {
		parts := strings.Split(strings.Trim(original, "/"), "/")
		t.Fatalf("worker canary unit mismatch: system_slice=%t helper_unit=%t config_match=%t control=%t depth=%d", strings.HasPrefix(original, "/system.slice/"),
			strings.Contains(original, "laneboss-helper@"), strings.Contains(original, m.binding.Config), strings.HasSuffix(original, "/control"), len(parts))
	}
	if err := os.Mkdir(service, 0755); err != nil {
		t.Fatal(err)
	}
	if err := setupCgroups(m.binding); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		entries, err := os.ReadDir(m.binding.cgroupPath())
		if err != nil {
			t.Error(err)
			return
		}
		for _, entry := range entries {
			if entry.IsDir() {
				if err := os.Remove(filepath.Join(m.binding.cgroupPath(), entry.Name())); err != nil {
					t.Error(err)
				}
			}
		}
		for _, path := range []string{m.binding.cgroupPath(), service} {
			if err := os.Remove(path); err != nil {
				t.Error(err)
			}
		}
	})
}

func workerCanaryServe(t *testing.T, ctx context.Context, m *leaseManager, store workerCanaryStore, dataOpen ...dataReg) {
	t.Helper()
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
	closeMetadata, err := startCredentialMetadata(ctx, m.binding, m)
	if err != nil {
		t.Fatal("worker canary could not start its authenticated metadata endpoint", err)
	}
	defer func() {
		if err := closeMetadata(); err != nil {
			t.Error(err)
		}
	}()
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
		t.Fatal("worker canary listener could not enable native credentials", err, optionErr)
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
	modes := []string{"current", "enclosed", "metadata-worker", "metadata-attempt", "foreign", "stale", "foreign-prepared", "closed", "closed-state", "input", "endpoint", "lock"}
	var open *dataReg
	if len(dataOpen) == 1 {
		open = &dataOpen[0]
		modes = []string{"data-open"}
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			input, err := sealedBootstrap(workerCanaryInput{Binding: m.binding, Store: store, Mode: mode, DataOpen: open})
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			requestRead, requestWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer requestRead.Close()
			defer requestWrite.Close()
			ackRead, ackWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer ackRead.Close()
			defer ackWrite.Close()
			lockResult := make(chan error, 1)
			if mode == "lock" {
				go func() {
					var signal [1]byte
					_, err := io.ReadFull(requestRead, signal[:])
					if err == nil {
						err = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
					}
					if err == nil {
						_, err = ackWrite.Write(signal[:])
					}
					lockResult <- err
				}()
			}
			name := strings.Split(t.Name(), "/")[0]
			command := exec.CommandContext(ctx, m.binding.binaryPath(), "-test.run=^"+name+"$", "-test.v", "--", "worker-client")
			command.Env, command.ExtraFiles = []string{}, []*os.File{input, requestWrite, ackRead}
			command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: m.binding.Service.UID, Gid: m.binding.Service.GID, Groups: []uint32{}}, UseCgroupFD: true, CgroupFD: int(serviceGroup.Fd())}
			output, err := command.CombinedOutput()
			requestWrite.Close()
			if mode == "lock" {
				if lockErr := <-lockResult; lockErr != nil {
					t.Error("native lock-loss control could not execute", lockErr)
				}
				if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			}
			if err != nil || !bytes.Contains(output, []byte("--- PASS: "+name+" ")) {
				t.Fatalf("real unprivileged handoff client failed: %v\n%s", err, output)
			}
		})
	}
}

func workerCanaryClient(t *testing.T) {
	t.Helper()
	input := os.NewFile(3, "canary-metadata")
	raw, err := io.ReadAll(input)
	if err != nil {
		t.Fatal(err)
	}
	var seeded workerCanaryInput
	if err := json.Unmarshal(raw, &seeded); err != nil {
		t.Fatal(err)
	}
	store := seeded.Store
	s := &Service{binding: seeded.Binding, deps: Dependencies{Config: seeded.Binding.Config, ServiceUID: seeded.Binding.Service.UID, Store: &store}}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if seeded.Mode == "data-open" {
		if seeded.DataOpen == nil {
			t.Fatal("native data open has no retained registration")
		}
		var opened, replay api.StorageProjection
		if err := s.call(ctx, "data_open", dataCopyOpenRequest{Registration: *seeded.DataOpen, Copies: []dataCopyPayload{}}, &opened); err != nil {
			t.Fatal("staged allocation data_open through the real helper failed", err)
		}
		if opened.OpenToken == "" || opened.StageID != seeded.DataOpen.Request.StageID {
			t.Fatal("native data open lost its original stage or token")
		}
		if err := s.call(ctx, "data_open", dataCopyOpenRequest{Registration: *seeded.DataOpen, Copies: []dataCopyPayload{}}, &replay); err != nil || !reflect.DeepEqual(opened, replay) {
			t.Fatal("native data open retry changed its actual retained projection", err)
		}
		return
	}
	id := store.Binding.Prepared.ID
	if seeded.Mode == "metadata-worker" || seeded.Mode == "metadata-attempt" {
		workerCanaryMetadata(t, ctx, s, id, seeded.Mode)
		return
	}
	if seeded.Mode == "enclosed" {
		err := s.WithWorkerLaunch(ctx, store.Binding.Prepared, func(held context.Context) error {
			guard, err := s.AcquireWorkerLaunch(held, s.deps.Config, id)
			if err != nil {
				return err
			}
			if err := guard.Check(held); err != nil {
				return errors.Join(err, guard.Close())
			}
			if err := guard.Close(); err != nil {
				return err
			}
			if err := guard.Check(held); err == nil {
				return failure(api.CodeIntegrity, "closed worker borrow retained authority")
			}
			if err := s.workerSession(held).check(held); err != nil {
				return err
			}
			var ticket containmentTicket
			if err := s.call(held, "containment", containmentQuery{LeaseID: store.Binding.Record.UIDLeaseID, Opened: true}, &ticket); err != nil {
				return err
			}
			if ticket.Lease.ID != store.Binding.Record.UIDLeaseID || ticket.WorkerLeaseID != store.Principal.Lease.ID || ticket.StageID != store.Principal.StageID {
				return failure(api.CodeIntegrity, "worker transaction substituted its prepared containment")
			}
			return nil
		})
		if err != nil {
			t.Fatal("worker borrow close released its enclosing native transaction", err)
		}
		return
	}
	if seeded.Mode == "foreign" {
		store.Principal.Lease.ID = "foreign-lease"
	}
	if seeded.Mode == "stale" {
		store.Principal.Lease.Generation++
	}
	if seeded.Mode == "foreign-prepared" {
		id = "stale-prepared"
	}
	guard, err := s.AcquireWorkerLaunch(ctx, s.deps.Config, id)
	if seeded.Mode == "foreign" || seeded.Mode == "stale" || seeded.Mode == "foreign-prepared" {
		if err == nil || guard != nil {
			t.Fatal("foreign or stale lease acquired a real helper worker guard")
		}
		return
	}
	if err != nil {
		t.Fatal("real helper worker launch acquisition failed", err)
	}
	defer func() {
		if err := guard.Close(); err != nil && seeded.Mode != "lock" {
			t.Error(err)
		}
	}()
	if guard.Input() == nil || guard.Endpoint() == nil || guard.Peer() == nil || guard.Authority().Binding.Prepared != store.Binding.Prepared {
		t.Fatal("real helper omitted its retained worker handoff")
	}
	if err := guard.Check(ctx); err != nil {
		t.Fatal("real helper baseline check failed", err)
	}
	facts, err := guard.Peer().Facts(ctx)
	if err != nil || facts != store.Principal.Peer {
		t.Fatal("worker peer was not the independently measured live bootstrap", err)
	}
	switch seeded.Mode {
	case "current":
		return
	case "closed":
		if err := guard.Close(); err != nil {
			t.Fatal(err)
		}
	case "closed-state":
		native := guard.(*workerLaunchGuard)
		native.mu.Lock()
		native.closed = true
		native.mu.Unlock()
		err := guard.Check(ctx)
		native.mu.Lock()
		native.closed = false
		native.mu.Unlock()
		if err == nil {
			t.Fatal("closed worker guard accepted its otherwise live retained handles")
		}
		return
	case "input", "endpoint":
		file := guard.Input()
		if seeded.Mode == "endpoint" {
			file = guard.Endpoint()
		}
		info, err := file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		content := make([]byte, info.Size())
		if _, err := file.ReadAt(content, 0); err != nil {
			t.Fatal(err)
		}
		replacement, err := sealedBootstrap(json.RawMessage(content))
		if err != nil {
			t.Fatal(err)
		}
		defer replacement.Close()
		if err := replacement.Chmod(0444); err != nil {
			t.Fatal(err)
		}
		view, err := os.Open("/proc/self/fd/" + strconv.Itoa(int(replacement.Fd())))
		if err != nil {
			t.Fatal(err)
		}
		defer view.Close()
		actual := make([]byte, len(content))
		if _, err := view.ReadAt(actual, 0); err != nil || !bytes.Equal(actual, content) {
			t.Fatal("descriptor replacement control changed its bytes")
		}
		if err := unix.Dup3(int(view.Fd()), int(file.Fd()), unix.O_CLOEXEC); err != nil {
			t.Fatal(err)
		}
	case "lock":
		request, ack := os.NewFile(4, "canary-lock-request"), os.NewFile(5, "canary-lock-ack")
		if _, err := request.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		var signal [1]byte
		if _, err := io.ReadFull(ack, signal[:]); err != nil {
			t.Fatal(err)
		}
	}
	if err := guard.Check(ctx); err == nil {
		t.Fatal("worker handoff accepted a closed guard, changed descriptor identity or missing native lock")
	}
}

// Use the production authenticated metadata socket. Its allowlist must reject
// a real prepared worker before transferring any rights, and the normal client
// must forward an explicit attempt so invalid authority cannot disappear.
func workerCanaryMetadata(t *testing.T, ctx context.Context, service *Service, prepared api.ID, mode string) {
	t.Helper()
	if mode == "metadata-attempt" {
		ctx = api.WithEffectLease(ctx, api.EffectLease{})
		var observed api.CredentialProjectionReceipt
		err := service.call(ctx, "credential_projection_observe_id", struct{ ProjectionID api.ID }{"metadata-projection"}, &observed)
		var refused *api.Error
		if !errors.As(err, &refused) || refused.Code != api.CodeForbidden || refused.Message != "native helper received an invalid explicit effect attempt" {
			t.Fatal("metadata client discarded its explicit effect attempt", err)
		}
		return
	}
	connection, err := net.DialTimeout("unix", service.binding.credentialMetadataPath(), 2*time.Second)
	if err != nil {
		t.Fatal("authenticated metadata endpoint was unavailable", err)
	}
	defer connection.Close()
	stop, err := bindHelperCall(ctx, connection)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	peer, err := pinPeer(connection.(*net.UnixConn), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer closePeer(peer)
	nonce, err := randomID("metadata-")
	if err != nil {
		t.Fatal(err)
	}
	params, err := json.Marshal(workerLaunchQuery{PreparedID: prepared})
	if err != nil {
		t.Fatal(err)
	}
	request := helperRequest{Protocol: helperProtocol, Revision: api.ContractRevision, Config: service.binding.Config, Generation: service.binding.Generation,
		ArtifactSHA256: service.binding.Artifact.SHA256, Nonce: nonce, Method: "worker_launch", Params: params}
	if err := writeFrame(connection, request); err != nil {
		t.Fatal(err)
	}
	raw, err := readUnixFrame(connection.(*net.UnixConn), peer)
	if err != nil {
		t.Fatal("metadata endpoint did not refuse worker launch before descriptor transfer", err)
	}
	var result api.Empty
	err = workerResponse(raw, nonce, &result)
	var refused *api.Error
	if !errors.As(err, &refused) || refused.Code != api.CodeForbidden || refused.Message != "credential metadata endpoint refuses state-changing operations" {
		t.Fatal("metadata endpoint admitted a worker launch", err)
	}
}
