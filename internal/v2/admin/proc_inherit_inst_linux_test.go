//go:build linux && laneboss_gate_integration

package admin

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func init() {
	if len(os.Args) != 3 || os.Args[1] != "admin-inherited-proc-canary" {
		return
	}
	real, effective, saved := unix.Getresuid()
	groups, err := os.Getgroups()
	if err != nil || real == 0 || real != effective || real != saved || len(groups) != 0 {
		os.Exit(77)
	}
	// Descriptors are independently pinned by the root fixture. Compare the
	// actual child namespace, rather than returning the parent's expectation.
	var expected, actual unix.Stat_t
	if unix.Fstat(3, &expected) != nil || unix.Stat("/proc/self/ns/mnt", &actual) != nil || expected.Dev != actual.Dev || expected.Ino != actual.Ino {
		os.Exit(78)
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(4, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		os.Exit(79)
	}
	flags := uint64(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	if uint64(fs.Flags)&flags != flags || uint64(fs.Flags)&unix.MS_RDONLY != 0 {
		os.Exit(80)
	}
	var root unix.Statx_t
	if unix.Statx(4, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &root) != nil || root.Mask&unix.STATX_MNT_ID == 0 {
		os.Exit(81)
	}
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		os.Exit(81)
	}
	id, found := strconv.FormatUint(root.Mnt_id, 10), false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if fields[1] == id {
			// A hidden child mount defeats the fully visible procfs premise.
			os.Exit(81)
		}
		if fields[0] == id {
			if found || fields[3] != "/" || !strings.Contains(line, " - proc ") {
				os.Exit(81)
			}
			found = true
		}
	}
	if !found {
		os.Exit(81)
	}
	if err := unix.Fstatat(4, "sys", &actual, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		os.Exit(82)
	}
	if unix.Close(3) != nil || unix.Close(4) != nil {
		os.Exit(83)
	}
	if n, err := os.Stdout.WriteString(os.Args[2]); err != nil || n != len(os.Args[2]) {
		os.Exit(84)
	}
	os.Exit(0)
}

// Run only in TestInstalledPristineProc's unchanged root unit, after its
// production mount setup. The exact credential/cgroup constructor and locked
// retained-netns launcher must preserve the helper's mount namespace. No
// namespace/proc descriptors enter the later bwrap or vendor canary.
func testInstalledProcInheritance(t *testing.T, binding installation, executable string) {
	t.Helper()
	namespace, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal("cannot pin installed mount namespace for its inheritance canary")
	}
	defer namespace.Close()
	wrongNamespace, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal("cannot pin the namespace negative control")
	}
	defer wrongNamespace.Close()
	proc, err := os.Open(filepath.Join(binding.runtimePath(), "proc"))
	if err != nil {
		t.Fatal("cannot pin the production pristine procfs for its inheritance canary")
	}
	defer proc.Close()
	wrongFS, err := os.Open("/run")
	if err != nil {
		t.Fatal("cannot pin the non-proc filesystem negative control")
	}
	defer wrongFS.Close()
	membership, err := cgroupMembership(os.Getpid())
	if err != nil {
		t.Fatal("cannot observe the installed proc canary's cgroup")
	}
	cgroup, err := os.Open(filepath.Join("/sys/fs/cgroup", membership))
	if err != nil {
		t.Fatal("cannot pin the installed proc canary's cgroup")
	}
	defer cgroup.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	network, err := newEmptyNetworkNamespace(ctx)
	if err != nil {
		t.Fatal("cannot create the production retained-netns inheritance fixture")
	}
	defer network.Close()
	token, err := randomID("proc-inheritance-")
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range []struct {
		name      string
		namespace *os.File
		proc      *os.File
		exit      int
	}{
		{"namespace-control", wrongNamespace, proc, 78},
		{"filesystem-control", namespace, wrongFS, 79},
		{"candidate", namespace, proc, 0},
	} {
		t.Run(sample.name, func(t *testing.T) {
			command := exec.CommandContext(ctx, executable, "admin-inherited-proc-canary", string(token))
			command.Env, command.Dir = []string{}, "/"
			command.ExtraFiles = []*os.File{sample.namespace, sample.proc}
			command.SysProcAttr = nativeGateAttributes(binding.Lanes[0].UID, binding.Lanes[0].GID, int(cgroup.Fd()))
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			lifetime := newNativeSpawnLifetime()
			if err := startInNetworkNamespacePinned(command, network, lifetime); err != nil {
				t.Fatal("installed proc inheritance canary failed before native exec")
			}
			waitErr := command.Wait()
			lifetime.observedWait(command.ProcessState)
			select {
			case <-lifetime.threadDone:
			case <-time.After(3 * time.Second):
				t.Fatal("installed proc inheritance creator did not observe actual child exit")
			}
			var exited *exec.ExitError
			if ctx.Err() != nil || command.ProcessState == nil || command.ProcessState.ExitCode() != sample.exit ||
				waitErr != nil && !errors.As(waitErr, &exited) || (waitErr == nil) != (sample.exit == 0) || stderr.Len() != 0 {
				stage := "wait_unavailable"
				if command.ProcessState != nil {
					stage = procInheritanceStage(command.ProcessState.ExitCode())
				}
				t.Fatalf("acceptance: native launch did not inherit the measured pristine procfs or its deciding control (stage=%s)", stage)
			}
			if sample.exit == 0 && stdout.String() != string(token) || sample.exit != 0 && stdout.Len() != 0 {
				t.Fatal("acceptance: native proc inheritance canary invented its success output")
			}
		})
		if t.Failed() {
			return
		}
	}
}

func procInheritanceStage(code int) string {
	switch code {
	case 0:
		return "complete"
	case 77:
		return "credentials"
	case 78:
		return "mount_namespace"
	case 79:
		return "proc_filesystem"
	case 80:
		return "proc_flags"
	case 81:
		return "mount_visibility"
	case 82:
		return "proc_subset"
	case 83:
		return "descriptor_close"
	case 84:
		return "canary_output"
	default:
		return "other"
	}
}
