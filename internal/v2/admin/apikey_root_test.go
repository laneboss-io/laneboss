//go:build linux && laneboss_root_canary

package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

func init() {
	if len(os.Args) == 2 && os.Args[1] == "key-env-control" {
		if _, err := os.Stdout.WriteString("control\n"); err != nil {
			os.Exit(89)
		}
		var hold [1]byte
		if n, err := os.Stdin.Read(hold[:]); n != 0 || !errors.Is(err, io.EOF) {
			os.Exit(90)
		}
		os.Exit(0)
	}
	if len(os.Args) != 2 || os.Args[1] != "key-vendor" {
		return
	}
	count := 0
	for _, item := range os.Environ() {
		if name, _, ok := strings.Cut(item, "="); ok && name == "ANTHROPIC_API_KEY" {
			count++
		}
	}
	if count != 1 || os.Getenv("ANTHROPIC_API_KEY") == "" {
		os.Stdout.WriteString("unset\n")
		os.Exit(86)
	}
	if _, err := os.Stdout.WriteString("set\n"); err != nil {
		os.Exit(87)
	}
	var hold [1]byte
	if n, err := os.Stdin.Read(hold[:]); n != 0 || !errors.Is(err, io.EOF) {
		os.Exit(88)
	}
	os.Exit(0)
}

// Enrollment/slot authority is synthetic. The installed helper properties,
// artifact/runtime pins, cgroup, fixed bootstrap, isolation, sealed copies,
// final exec and withdrawal are the product paths. No provider is contacted.
func TestAPIKeyNativeDeliveryCanary(t *testing.T) {
	workerLaunchCanary(t, false, keyLaunch)
	t.Log("key canary verified vendor environ once and its selected private read-only store; argv, earlier environments and journals clear; store removed on withdrawal")
}

type keyStoreInput struct {
	Config   string
	Path     string
	Metadata json.RawMessage
}

func keyLaunch(t *testing.T, ctx context.Context, m *leaseManager, data dataReg, runtime api.BlobRef, executable api.Executable) {
	t.Helper()
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatal(err)
	}
	canary := []byte("sk-ant-" + hex.EncodeToString(entropy[:]))
	clear(entropy[:])
	defer clear(canary)
	keyScannerControls(t, ctx, m, canary)
	record, err := m.find(data.Request.AgentLeaseID)
	if err != nil {
		t.Fatal(err)
	}
	reserved := record
	reserved.Phase = "reserved"
	if err := m.resources.Ensure(ctx, reserved); err != nil {
		t.Fatal("key native containment unavailable", err)
	}
	closeProc, err := mountHelperProc(m.binding.runtimePath())
	if err != nil {
		t.Fatal(err)
	}
	procLive := true
	defer func() {
		if procLive {
			if err := closeProc(); err != nil {
				t.Error(err)
			}
		}
	}()
	base := storageBase(m.binding, record)
	work := filepath.Join(base, string(record.Storage.Directories[0].ID))
	workerCanaryWrite(t, filepath.Join(work, "key-task"), []byte("# API key lane\n"), 0444)
	record.Storage.Binding.Home.Home.VendorDirectory = ".claude"
	request := keyPlan(t, &record, runtime, executable)
	spec, home := request.Handoff.Spec, request.Home
	slot, expires := spec.Runner.Slot, spec.Runner.Slot.ExpiresAt
	targets, err := api.CredentialTargets(request, time.Now())
	if err != nil {
		t.Fatal("API key kind refused before native launch", err)
	}
	if len(targets) != 1 || targets[0].Delivery != "file" || targets[0].RelativePath != claudock.KeyStorePath || targets[0].EnvironmentName != "ANTHROPIC_API_KEY" {
		t.Fatal("API key differs from its selected private store target")
	}
	for _, name := range []string{"ANTHROPIC_API_KEY", "CLAUDE_OTHER"} {
		if manifest.SecretTarget("env", name) == nil {
			t.Fatal("reserved task grant accepted")
		}
		bad := request
		bad.Handoff.Spec.Grants.Secrets = []api.SecretGrant{{ID: "key-task", SourceHandle: "key-source", Version: "v1", Delivery: "env", Target: name, ExpiresAt: expires}}
		bad.Handoff.Spec.Injection.GrantIDs, bad.Handoff.Spec.Injection.SourceVersions = []api.ID{"key-task"}, []string{"v1"}
		if _, err := api.CredentialTargets(bad, time.Now()); err == nil {
			t.Fatal("reserved task projection accepted")
		}
	}
	if err := m.save(record); err != nil {
		t.Fatal(err)
	}
	_, mounts, err := m.gateMounts(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, mount := range mounts {
			mount.file.Close()
		}
	}()
	// workerLaunchCanary installs the same root-owned release artifact used
	// by TestArchiveLaunchNative. Its test entry also supplies the vendor.
	vendor := m.binding.binaryPath()
	if err := verifyExecutable(vendor, m.binding.Artifact); err != nil {
		t.Fatal("key canary shared installed artifact failed verification", err)
	}
	file, err := os.Open(vendor)
	if err != nil {
		t.Fatal(err)
	}
	mounts = append(mounts, &nativeMount{file: file, target: "/runtime/key-vendor", executable: true})
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	stdin, finish, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	defer finish.Close()
	// Test logs and observations are not helper journal objects. Keep them
	// outside fileLeaseStore's closed state inventory and include them in scans.
	evidence := filepath.Join(m.binding.runtimePath(), "key-evidence")
	if err := os.Mkdir(evidence, 0700); err != nil {
		t.Fatal(err)
	}
	journal, err := os.OpenFile(filepath.Join(evidence, "key-helper.log"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	token, err := randomID("key-gate-")
	if err != nil {
		t.Fatal(err)
	}
	payload := gatePayload{Config: m.binding.Config, Mode: "prepared-gate", GateID: "key-gate", Token: string(token),
		UID: record.Lease.UID, GID: record.Lease.GID, CWD: "/work/main", Argv: spec.Runner.Argv, Environment: agentEnvironment(api.DriverClaudock, slot.Mode),
		Budget: spec.Budget, CredentialRequired: true, PreparedID: "key-prepared", SpecSHA256: request.Handoff.SpecSHA256, stdin: stdin}
	gate, err := startNativeGate(ctx, m.binding, record, payload, mounts, write, journal, nil, nil, m.bootID)
	if err != nil {
		stderr, readErr := io.ReadAll(io.NewSectionReader(journal, 0, 8192))
		if readErr != nil || bytes.Contains(stderr, canary) {
			t.Fatal("key launch stderr is unreadable or contains material")
		}
		t.Logf("bwrap stderr: %s", stderr)
		t.Fatal("key installed native launch failed", err)
	}
	native := gate.(*nativeGate)
	m.gates = map[api.ID]ownedGate{record.Lease.ID: gate}
	t.Cleanup(func() { archiveCanaryCollect(t, m) })
	record.Gate.Prepared.ProcessGeneration = gate.Generation()
	record.Gate.State, record.Gate.PID = "prepared", gate.PID()
	request.Prepared = record.Gate.Prepared
	if err := m.save(record); err != nil {
		entries, readErr := os.ReadDir(m.binding.statePath())
		if readErr != nil {
			t.Fatal("key failure inventory is unreadable", readErr)
		}
		for _, entry := range entries {
			if entry.Name() == "key-helper.log" || entry.Name() == "key-evidence" {
				t.Logf("helper state failure object=%s directory=%t", entry.Name(), entry.IsDir())
			}
		}
		t.Fatal(err)
	}
	root, err := os.Open(filepath.Join(base, string(home.RootID)))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	fd, err := unix.MemfdCreate("key-input", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	input := os.NewFile(uintptr(fd), "key-input")
	defer input.Close()
	if n, err := input.Write(canary); err != nil || n != len(canary) {
		t.Fatal("key source write failed")
	}
	sourceID, _, err := credentialObject(input)
	if err != nil {
		t.Fatal(err)
	}
	parent, name, err := credentialParent(root, targets[0].RelativePath, record.Lease.UID, record.Lease.GID, 0700)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	fd, err = reserveCredentialFile(parent, name, targets[0].FileMode)
	if err != nil {
		t.Fatal(err)
	}
	writer := os.NewFile(uintptr(fd), "key-store-copy")
	if err := copyKeyStore(ctx, input, writer, int64(len(canary))); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fchown(fd, int(record.Lease.UID), int(record.Lease.GID)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	heldFile, err := dataFile(parent, name, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	heldID, st, err := credentialObject(heldFile)
	if err != nil || heldID == sourceID || st.Uid != record.Lease.UID || st.Nlink != 1 || st.Mode&07777 != 0600 {
		t.Fatal("key holding is not a distinct private single-link store")
	}
	authority := api.CredentialProjectionAuthority{ID: "key-projection", Generation: 1, Request: request, Targets: targets,
		Sources: []api.CredentialSourceVersion{{Key: slot.ID, Generation: 1, Version: "v1"}}}
	held := &heldCredentials{home: root, record: api.CredentialProjectionRecord{Authority: authority, Generation: 1, State: "reserved"},
		files: []*os.File{heldFile}, sources: []string{sourceID}, sourceHandles: []*os.File{input}, destinations: []storageInode{{Device: uint64(st.Dev), Inode: st.Ino}}}
	m.credentials = &credentialRuntime{manager: m, held: map[api.ID]*heldCredentials{authority.ID: held}}
	if err := m.credentials.readOnlyView(ctx, record, targets[0], heldFile); err != nil {
		t.Fatal(err)
	}
	receipt, err := m.credentials.measure(ctx, held)
	if err != nil {
		t.Fatal("key private store holding could not be measured", err)
	}
	held.record.Generation, held.record.State, held.record.Receipt = receipt.Generation, "held", &receipt
	record.Credentials = &credentialJournal{State: "held", Record: &held.record}
	if err := m.save(record); err != nil {
		t.Fatal(err)
	}
	keyProcScan(t, m, record, canary, 0, evidence, "closed")
	delivery, err := m.prepareCredentialExec(ctx, record)
	if err != nil {
		t.Fatal("key sealed exec handoff failed", err)
	}
	for _, export := range delivery.exports {
		fact, err := credentialDescriptor(export, true)
		if err != nil || fact.OwnerUID != 0 || fact.Links != 0 || !fact.ReadOnly || !fact.CloseOnExec || fact.ObjectID == heldID {
			t.Fatal("key final handoff lost root ownership or distinct seals")
		}
	}
	if err := m.deliverCredentialExec(ctx, record, delivery); err != nil {
		t.Fatal(err)
	}
	if err := delivery.close(); err != nil {
		t.Fatal(err)
	}
	keyProcScan(t, m, record, canary, 0, evidence, "delivered")
	keyOpen(t, &record)
	if err := m.save(record); err != nil {
		t.Fatal(err)
	}
	if err := gate.Release(); err != nil {
		t.Fatal(err)
	}
	if err := read.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var verdict [4]byte
	if _, err := io.ReadFull(read, verdict[:]); err != nil || string(verdict[:]) != "set\n" {
		t.Fatal("key vendor did not report set")
	}
	if err := m.awaitCredentialGate(ctx, record); err != nil {
		t.Fatal("key vendor exec proof failed", err)
	}
	keyProcScan(t, m, record, canary, native.innerPID, evidence, "vendor")
	if err := native.innerLifetime(m.bootID); err != nil {
		t.Fatal(err)
	}
	view := "/proc/" + strconv.Itoa(native.innerPID) + "/root"
	keyLiveStoreScan(t, canary, view+"/home/lane", heldFile)
	keyDiskScan(t, canary, "lane-live", true, view+"/work/main", view+"/history",
		view+"/tmp", view+"/run/lane", view+"/dev/shm")
	if err := native.innerLifetime(m.bootID); err != nil {
		t.Fatal(err)
	}
	workerCanaryWrite(t, filepath.Join(evidence, "vendor.log"), verdict[:], 0600)
	keyStoreRun(t, ctx, m, held.record, canary, evidence)
	if err := finish.Close(); err != nil {
		t.Fatal(err)
	}
	observation, err := gate.Stop(ctx, api.ProcessHandle{})
	if err != nil || observation.State != "exited" || observation.ExitCode == nil || *observation.ExitCode != 0 {
		t.Fatal("key vendor did not exit cleanly", err)
	}
	record.Gate.State = "opened"
	if err := m.save(record); err != nil {
		t.Fatal(err)
	}
	projection := held.record
	projection.State, projection.Generation = "withdrawing", projection.Generation+1
	stop := request.Cause
	stop.ID, stop.Kind, stop.EffectID = "key-stop", api.InternalHelperRelease, "key-stop-effect"
	projection.Fence = &api.CredentialWithdrawalRequest{ProjectionID: authority.ID, ExpectedGeneration: held.record.Generation, Cause: stop, Reason: "cancelled"}
	record.Credentials = &credentialJournal{State: "withdrawing", Record: &projection}
	if err := m.save(record); err != nil {
		t.Fatal(err)
	}
	withdrawal, err := m.credentials.withdraw(ctx, projection)
	if err != nil || !withdrawal.RotationRequired || withdrawal.AgentExecuted == nil || !*withdrawal.AgentExecuted {
		t.Fatal("key stop lost its rotation-required receipt", err)
	}
	if _, err := os.Lstat(filepath.Join(base, string(home.RootID), claudock.KeyStorePath)); !os.IsNotExist(err) {
		t.Fatal("lane end retained its private API key store")
	}
	if held.releaseScan == nil || !reflect.DeepEqual(held.releaseScan.Authority, projection.Authority) || held.releaseScan.Cause != projection.Fence.Cause {
		t.Fatal("native key withdrawal omitted its exact value-free release scan")
	}
	for _, count := range []*uint64{withdrawal.HelperDescriptors, withdrawal.ProjectedFiles, withdrawal.EnvironmentBuffers, withdrawal.OpenGates, withdrawal.Observation.Survivors} {
		if count == nil || *count != 0 {
			t.Fatal("key stop retained a credential or process")
		}
	}
	workerCanaryJSON(t, filepath.Join(evidence, "withdrawal.json"), withdrawal, 0600)
	keyStoreRun(t, ctx, m, projection, canary, evidence)
	// Process argv/environments were measured while alive. After quiescence,
	// collect the helper's virtual procfs before scanning all runtime files.
	if err := closeProc(); err != nil {
		t.Fatal(err)
	}
	procLive = false
	keyDiskScan(t, canary, "helper-state", false, m.binding.statePath())
	keyDiskScan(t, canary, "lane", true, base)
	keyDiskScan(t, canary, "runtime", false, m.binding.runtimePath())
	keyDiskScan(t, canary, "evidence", true, evidence)
	journalSync := exec.CommandContext(ctx, "/usr/bin/journalctl", "--sync")
	journalSync.Env = []string{}
	if err := journalSync.Run(); err != nil {
		t.Fatal("journal query failed: place=sync")
	}
	for _, role := range []string{"service", "helper"} {
		command := exec.CommandContext(ctx, "/usr/bin/journalctl", "--quiet", "--no-pager", "--output=cat", "--unit=laneboss-"+role+"@"+m.binding.Config+".service")
		command.Env = []string{}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("journal query failed: place=%s", role)
		}
		if err := keyJournalScan(output, canary); err != nil {
			t.Fatalf("%s: place=%s", err, role)
		}
		workerCanaryWrite(t, filepath.Join(evidence, role+".journal"), output, 0600)
	}
	keyDiskScan(t, canary, "evidence-journals", true, evidence)
	t.Log("key canary: vendor environment exactly once; earlier environments, all lane argv, state, evidence, SQLite, journals and lane files clear; rotation required")
}

// The exact selected slot is expected while live. Every other file is still
// scanned by the unchanged scanner; withdrawal scans the entire home again.
func keyLiveStoreScan(t *testing.T, key []byte, home string, held *os.File) {
	t.Helper()
	selected := filepath.Join(home, claudock.KeyStorePath)
	count := 0
	err := filepath.WalkDir(home, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if path != selected {
			return keyDiskScanResult(t, key, "live-home", true, path)
		}
		info, err := os.Lstat(path)
		original, statErr := held.Stat()
		if err != nil || statErr != nil || !os.SameFile(info, original) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errors.New("live key store differs from the selected private inode")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		defer clear(data)
		actual, err := claudock.DecodeKeyStore(data)
		defer clear(actual)
		if err != nil || !bytes.Equal(actual, key) {
			return errors.New("live store lost its selected slot key")
		}
		count++
		return nil
	})
	if err != nil || count != 1 {
		t.Fatal("live home did not contain exactly its selected private store", err)
	}
}

func keyStoreRun(t *testing.T, ctx context.Context, m *leaseManager, projection api.CredentialProjectionRecord, canary []byte, evidence string) {
	t.Helper()
	path := filepath.Join("/run/laneboss-v2/services", m.binding.Config)
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(os.Chown(path, int(m.binding.Service.UID), int(m.binding.Service.GID)), os.Chmod(path, 0700)); err != nil {
		t.Fatal(err)
	}
	input, err := sealedBootstrap(keyStoreInput{Config: m.binding.Config, Path: path, Metadata: mustCanaryJSON(t, projection)})
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	group, err := os.Open(filepath.Join("/sys/fs/cgroup/system.slice", "laneboss-service@"+m.binding.Config+".service"))
	if err != nil {
		t.Fatal(err)
	}
	defer group.Close()
	command := exec.CommandContext(ctx, m.binding.binaryPath(), "key-store")
	command.Env, command.ExtraFiles = []string{}, []*os.File{input}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: m.binding.Service.UID, Gid: m.binding.Service.GID, Groups: []uint32{}}, UseCgroupFD: true, CgroupFD: int(group.Fd())}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	stdin, finish, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	defer finish.Close()
	command.Stdin, command.Stdout, command.Stderr = stdin, write, write
	if err := command.Start(); err != nil {
		t.Fatal("key service metadata start failed", err)
	}
	t.Cleanup(func() {
		if command.ProcessState == nil {
			if err := command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Error(err)
			}
			if err := command.Wait(); err != nil {
				t.Error("key service required forced collection")
			}
		}
	})
	if err := read.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var output [7]byte
	if _, err := io.ReadFull(read, output[:]); err != nil || string(output[:]) != "stored\n" {
		t.Fatal("key service metadata retention failed")
	}
	keyReadProc(t, command.Process.Pid, canary, 0, evidence, "service-"+projection.State)
	// Journald resolves the sender's UID/cgroup from this actual service PID.
	// Flush while that producer is still alive on its stdin lifetime gate;
	// a detached logger that has already exited loses those native facts.
	journalSync := exec.CommandContext(ctx, "/usr/bin/journalctl", "--sync")
	journalSync.Env = []string{}
	if err := journalSync.Run(); err != nil {
		t.Fatal("journal query failed: place=service-sync")
	}
	if err := finish.Close(); err != nil {
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal("key service metadata exit failed", err)
	}
	workerCanaryWrite(t, filepath.Join(evidence, "service-"+projection.State+".log"), output[:], 0600)
	database, err := os.ReadFile(filepath.Join(path, "state.sqlite"))
	if err != nil || !bytes.HasPrefix(database, []byte("SQLite format 3")) || bytes.Contains(database, canary) {
		t.Fatal("key database scan failed or found material")
	}
	keyDiskScan(t, canary, "sqlite", false, path)
}

func keyProcScan(t *testing.T, m *leaseManager, record leaseRecord, canary []byte, vendor int, evidence, phase string) {
	t.Helper()
	group := filepath.Join(m.binding.cgroupPath(), string(record.Lease.ContainmentID))
	seen := map[int]bool{os.Getpid(): true}
	if err := filepath.WalkDir(group, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || entry.Name() != "cgroup.procs" {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, word := range strings.Fields(string(data)) {
			pid, err := strconv.Atoi(word)
			if err != nil {
				return err
			}
			seen[pid] = true
		}
		return nil
	}); err != nil || len(seen) < 3 {
		t.Fatal("key process inventory incomplete", err)
	}
	found := 0
	for pid := range seen {
		if keyReadProc(t, pid, canary, vendor, evidence, phase) {
			found++
		}
	}
	if vendor != 0 && found != 1 {
		t.Fatal("key vendor absent from native process inventory")
	}
}

func keyReadProc(t *testing.T, pid int, canary []byte, vendor int, evidence, phase string) bool {
	t.Helper()
	argv, isVendor, err := keyProcessScan(pid, canary, vendor)
	if err != nil {
		t.Fatal(err)
	}
	workerCanaryWrite(t, filepath.Join(evidence, phase+"-"+strconv.Itoa(pid)+".argv"), argv, 0600)
	return isVendor
}

func keyProcessScan(pid int, canary []byte, vendor int) ([]byte, bool, error) {
	proc := "/proc/" + strconv.Itoa(pid)
	argv, err := os.ReadFile(proc + "/cmdline")
	if err != nil || bytes.Contains(argv, canary) {
		return nil, false, errors.New("key argv scan failed or found material")
	}
	environment, err := os.ReadFile(proc + "/environ")
	if err != nil {
		return nil, false, errors.New("key environment inventory unavailable")
	}
	count, names := 0, 0
	for _, item := range bytes.Split(environment, []byte{0}) {
		if bytes.HasPrefix(item, []byte("ANTHROPIC_API_KEY=")) {
			names++
			if bytes.Equal(item, append([]byte("ANTHROPIC_API_KEY="), canary...)) {
				count++
			}
		}
	}
	leaked := bytes.Contains(environment, canary)
	clear(environment)
	if pid == vendor {
		if count != 1 || names != 1 {
			return nil, false, errors.New("key vendor environment is missing, changed or duplicated")
		}
		return argv, true, nil
	}
	if leaked || names != 0 {
		return nil, false, errors.New("key reached an earlier process environment")
	}
	return argv, false, nil
}

func keyDiskScan(t *testing.T, canary []byte, scope string, strict bool, roots ...string) {
	t.Helper()
	if err := keyDiskScanResult(t, canary, scope, strict, roots...); err != nil {
		t.Fatal(err)
	}
}

func keyDiskScanResult(t *testing.T, canary []byte, scope string, strict bool, roots ...string) error {
	t.Helper()
	total := 0
	for index, root := range roots {
		count := 0
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(root, path)
			if err != nil || bytes.Contains([]byte(relative), canary) {
				return errors.New("key inventory path is unreadable or contains material")
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			kind := keyFileType(info.Mode())
			switch kind {
			case "regular":
				file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
				if err != nil {
					return fmt.Errorf("key regular read failed: path=%s type=regular: %w", relative, err)
				}
				actual, statErr := file.Stat()
				if statErr != nil || !actual.Mode().IsRegular() || !os.SameFile(info, actual) {
					return errors.Join(file.Close(), fmt.Errorf("key regular input changed: path=%s type=regular", relative))
				}
				data, readErr := io.ReadAll(file)
				if err := errors.Join(readErr, file.Close()); err != nil {
					return fmt.Errorf("key regular read failed: path=%s type=regular: %w", relative, err)
				}
				count++
				if bytes.Contains(data, canary) {
					return errors.New("key found in persistent file bytes")
				}
			case "symlink":
				target, err := os.Readlink(path)
				if err != nil {
					return fmt.Errorf("key link read failed: path=%s type=symlink: %w", relative, err)
				}
				if bytes.Contains([]byte(target), canary) {
					return errors.New("key found in symlink target text")
				}
				t.Logf("key scan entry: scope=%s path=%s type=symlink target=%q followed=false", scope, relative, target)
			case "socket", "FIFO", "device":
				reason := map[string]string{"socket": "endpoint has no regular file bytes", "FIFO": "pipe has no persistent file bytes", "device": "device is a kernel interface"}[kind]
				t.Logf("key scan entry: scope=%s path=%s type=%s searchable=false reason=%s", scope, relative, kind, reason)
				if strict {
					return fmt.Errorf("key protected scope contains a non-searchable entry: path=%s type=%s", relative, kind)
				}
			default:
				return fmt.Errorf("key file inventory has an unsearched entry: path=%s type=%s", relative, kind)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("key disk scan failed: scope=%s root=%d: %w", scope, index, err)
		}
		total += count
		t.Logf("key disk scan: scope=%s root=%d files=%d", scope, index, count)
	}
	if total == 0 {
		return fmt.Errorf("key disk scan had no regular files: scope=%s", scope)
	}
	return nil
}

func keyFileType(mode os.FileMode) string {
	switch {
	case mode.IsRegular():
		return "regular"
	case mode.IsDir():
		return "directory"
	case mode&os.ModeSymlink != 0:
		return "symlink"
	case mode&os.ModeSocket != 0:
		return "socket"
	case mode&os.ModeNamedPipe != 0:
		return "FIFO"
	case mode&os.ModeDevice != 0:
		return "device"
	default:
		return "unknown"
	}
}
