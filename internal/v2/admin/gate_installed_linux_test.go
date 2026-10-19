//go:build linux && laneboss_gate_integration

package admin

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func installedGateBinding(t *testing.T) installation {
	t.Helper()
	membership, err := cgroupMembership(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	config, err := helperControlConfig(membership)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := loadInstallation(config)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

// Run only in the disposable gate-integration fixture's root helper unit,
// after the installed accounts, artifact/runtime and delegated controllers
// exist. Missing prerequisites fail; they never skip or fabricate readiness.
// This is an actual native-bootstrap test, not a real vendor/profile launch.
func TestInstalledNativeClosedGate(t *testing.T) {
	installedNativeClosedGate(t, false)
}

func installedNativeClosedGate(t *testing.T, credentials bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if os.Geteuid() != 0 {
		t.Fatal("installed native gate fixture requires its isolated root unit")
	}
	binding := installedGateBinding(t)
	if err := verifyExecutable(binding.binaryPath(), binding.Artifact); err != nil {
		t.Fatal(err)
	}
	state, err := os.OpenRoot(binding.statePath())
	if err != nil {
		t.Fatal("cannot pin installed native fixture state")
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Error("cannot close installed native fixture state")
		}
	})
	lock, err := state.OpenFile("lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		t.Fatal("cannot pin installed native fixture helper lock")
	}
	t.Cleanup(func() {
		if err := lock.Close(); err != nil {
			t.Error("cannot close installed native fixture helper lock")
		}
	})
	var lockStat unix.Stat_t
	if unix.Fstat(int(lock.Fd()), &lockStat) != nil || lockStat.Uid != 0 || lockStat.Mode&unix.S_IFMT != unix.S_IFREG || lockStat.Mode&07777 != 0600 || lockStat.Nlink != 1 ||
		unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		t.Fatal("installed native fixture requires its safe exclusive helper lock")
	}
	closeProc, err := mountHelperProc(binding.runtimePath())
	if err != nil {
		t.Fatal("installed native fixture could not set up production pristine procfs")
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
	id, err := randomID("native-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	cgroupID, err := randomID("native-fixture-cg-")
	if err != nil {
		t.Fatal(err)
	}
	lease := api.HelperLease{ID: id, UID: binding.Lanes[0].UID, GID: binding.Lanes[0].GID, ContainmentID: cgroupID, EndpointGeneration: binding.Generation}
	request := testAllocation()
	request.Config, request.Cause.Config, request.LifeID, request.Cause.Target.LifeID = binding.Config, binding.Config, id, id
	request.Budget.MemoryBytes, request.Budget.Processes, request.Budget.CPUSeconds, request.Budget.WallMS = 256<<20, 32, 5, 10000
	record := leaseRecord{Lease: lease, Request: request, Phase: "reserved", BootID: boot,
		Spec: &specRegistration{Handoff: api.PreparedSpecHandoff{Spec: api.LaunchSpec{RuntimeManifest: catalog.RuntimeManifest}}}}
	resources := &linuxResources{binding: binding}
	m := &leaseManager{binding: binding, bootID: boot, resources: resources}
	resources.manager = m
	if err := resources.Ensure(ctx, record); err != nil {
		t.Fatal(err)
	}
	record.Phase = "active"
	_, mounts, err := m.gateMounts(ctx, record)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, mount := range mounts {
			mount.file.Close()
		}
	}()
	canaryPath := "/proc/self/exe"
	if credentials {
		root, err := os.MkdirTemp("/run", "lb-v2-serve2-exec-")
		if err != nil {
			t.Fatal(err)
		}
		// This is a public immutable executable, not a credential directory.
		if err := os.Chmod(root, 0755); err != nil {
			t.Fatal(err)
		}
		canaryPath = filepath.Join(root, "vendor")
		self, err := os.ReadFile("/proc/self/exe")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(canaryPath, self, 0555); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(canaryPath, 0555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if t.Failed() {
				return
			}
			if err := os.Remove(canaryPath); err != nil {
				t.Error(err)
				return
			}
			if err := os.Remove(root); err != nil {
				t.Error(err)
			}
		})
	}
	canary, err := os.Open(canaryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer canary.Close()
	mounts = append(mounts, &nativeMount{file: canary, target: "/runtime/native-canary", executable: true})
	laneDir := func(prefix string) string {
		directory, err := os.MkdirTemp("/run", prefix)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(directory, int(lease.UID), int(lease.GID)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if !t.Failed() {
				if err := os.RemoveAll(directory); err != nil {
					t.Error(err)
				}
			}
		})
		return directory
	}
	work := laneDir("lb-gate-work-")
	workMount, err := pinNativeMount(work, "/work/main", true, true, true, lease.UID, lease.GID)
	if err != nil {
		t.Fatal(err)
	}
	mounts = append(mounts, workMount)
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	discard, err := os.CreateTemp(privateTestDir(t), "gate-stderr-")
	if err != nil {
		t.Fatal(err)
	}
	defer discard.Close()
	token, err := randomID("native-canary-")
	if err != nil {
		t.Fatal(err)
	}
	payload := gatePayload{Config: binding.Config, Mode: "prepared-gate", GateID: id, Token: string(token), UID: lease.UID, GID: lease.GID,
		Argv: []string{"/runtime/native-canary", "admin-gate-native-canary", string(token)}, Environment: []string{}, CWD: "/work/main", Budget: request.Budget}
	var finish *os.File
	if credentials {
		homeDir := laneDir("lb-gate-home-")
		finish = credentialExecCanary(t, m, &record, &payload, homeDir)
		home, err := pinNativeMount(homeDir, "/home/lane", true, true, true, lease.UID, lease.GID)
		if err != nil {
			t.Fatal(err)
		}
		mounts = append(mounts, home)
	}
	gate, err := startNativeGate(ctx, binding, record, payload, mounts, write, discard, nil, nil, boot)
	if err != nil {
		data, readErr := os.ReadFile(discard.Name())
		t.Logf("bootstrap stderr read=%t", readErr == nil)
		fdText := regexp.MustCompile(`/proc/(self|[0-9]+)/fd/([0-9]+)`).FindSubmatch(data)
		if len(fdText) == 3 {
			fd, parseErr := strconv.Atoi(string(fdText[2]))
			index := fd - 6
			t.Logf("unresolved fd: parsed=%t fd=%d mount_index=%d in_range=%t",
				parseErr == nil, fd, index, index >= 0 && index < len(mounts))
		}
		t.Logf("source failure: proc=%t denied=%t missing=%t bad_fd=%t",
			strings.Contains(string(data), "/proc/"), strings.Contains(string(data), "Permission denied"),
			strings.Contains(string(data), "No such file or directory"), strings.Contains(string(data), "Bad file descriptor"))
		matched := false
		for index, mount := range mounts {
			link, linkErr := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(mount.file.Fd())))
			if linkErr != nil || !strings.Contains(string(data), link) {
				continue
			}
			matched = true
			_, statErr := mount.file.Stat()
			errno := "other"
			if strings.Contains(string(data), "Permission denied") {
				errno = "EACCES"
			} else if strings.Contains(string(data), "No such file or directory") {
				errno = "ENOENT"
			}
			t.Logf("unresolved source: index=%d directory=%t executable=%t writable=%t held=%t errno=%s",
				index, mount.directory, mount.executable, mount.writable, statErr == nil, errno)
		}
		t.Logf("bootstrap source matched=%t", matched)
		t.Fatal(err)
	}
	t.Cleanup(func() {
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
		if err := m.waitContainmentEmpty(cleanup, record); err != nil {
			t.Error(err)
			return
		}
		if t.Failed() {
			return
		} // Keep the failed fixture's kernel containment.
		if err := resources.Remove(cleanup, record); err != nil {
			t.Error(err)
		}
	})
	if gate.(*nativeGate).cgroupFD != -1 {
		t.Fatal("acceptance: native gate retained a borrowed cgroup descriptor number")
	}
	if _, err := os.Lstat(filepath.Join(work, "executed")); !os.IsNotExist(err) {
		t.Fatal("acceptance: confined canary executed before native release")
	}
	assertGateClosed(t, read, "acceptance: confined executable wrote before the committed release descriptor")
	if credentials {
		m.gates = map[api.ID]ownedGate{lease.ID: gate}
		delivery, err := m.prepareCredentialExec(ctx, record)
		if err != nil {
			t.Fatal("credential exec canary could not prepare its actual held input", err)
		}
		defer delivery.close()
		if err := m.deliverCredentialExec(ctx, record, delivery); err != nil {
			t.Fatal("credential exec canary could not transfer its actual input", err)
		}
	}
	if err := gate.Release(); err != nil {
		t.Fatal(err)
	}
	if err := read.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, len(token))
	if _, err := io.ReadFull(read, actual); err != nil || string(actual) != string(token) {
		if credentials {
			observation, observeErr := gate.Observe(ctx, api.ProcessHandle{})
			if observeErr == nil && observation.ExitCode != nil && (*observation.ExitCode == 87 || *observation.ExitCode == 88) {
				t.Fatalf("acceptance: native credential vendor refused PID1 or inherited descriptors: code=%d", *observation.ExitCode)
			}
		}
		t.Fatalf("native released canary did not run: %v", err)
	}
	if credentials {
		observeCredentialCanary(t, ctx, m, record)
		if err := finish.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := gate.Release(); err == nil {
		t.Fatal("acceptance: installed native release was reusable")
	}
	if _, err := gate.Stop(ctx, api.ProcessHandle{}); err != nil {
		t.Fatal(err)
	}
	bytes, err := os.ReadFile(filepath.Join(work, "executed"))
	if err != nil || string(bytes) != string(token) {
		t.Fatal("native canary filesystem read-back differs")
	}
}
