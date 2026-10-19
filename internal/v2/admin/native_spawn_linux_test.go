//go:build linux

package admin

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func TestNativeSpawnDiagnostic(t *testing.T) {
	private, err := randomID("private-spawn-")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		cause error
		name  string
	}{
		{unix.EPERM, "EPERM"}, {unix.EACCES, "EACCES"}, {unix.ENOSYS, "ENOSYS"},
		{unix.EINVAL, "EINVAL"}, {unix.EBADF, "EBADF"}, {unix.EBUSY, "EBUSY"},
		{unix.EOPNOTSUPP, "EOPNOTSUPP"}, {unix.EAGAIN, "EAGAIN"}, {unix.ENOMEM, "ENOMEM"},
		{unix.ENOENT, "ENOENT"}, {unix.ENOEXEC, "ENOEXEC"}, {unix.ENOTDIR, "ENOTDIR"},
		{unix.ELOOP, "ELOOP"}, {unix.EFAULT, "EFAULT"}, {unix.EMFILE, "EMFILE"}, {unix.ENFILE, "ENFILE"},
		{unix.Errno(0), "other"}, {unix.Errno(4095), "other"}, {errors.New(string(private)), "other"},
	} {
		t.Run(entry.name, func(t *testing.T) {
			wrapped := fmt.Errorf("%s: %w", private, &os.PathError{Op: string(private), Path: "/" + string(private), Err: &os.SyscallError{Syscall: string(private), Err: entry.cause}})
			failure := nativeGateCreationFailure(wrapped, unix.EINVAL)
			var typed *api.Error
			want := "kernel refused confined gate creation (spawn errno=" + entry.name + "; clone3 size-zero=EINVAL (argument validation reached))"
			if !errors.As(failure, &typed) || typed.Owner != "lb-v2-admin" || typed.Code != api.CodePrerequisite || typed.Message != want {
				t.Fatal("native spawn refusal lost its safe errno or operation scope")
			}
			if strings.Contains(failure.Error(), string(private)) {
				t.Fatal("acceptance: native spawn refusal disclosed private wrapped text")
			}
		})
	}
	for _, cause := range []unix.Errno{unix.EPERM, unix.EACCES, unix.ENOSYS, unix.EINVAL, unix.Errno(0), unix.Errno(4095)} {
		failure := nativeGateCreationFailure(unix.EBADF, cause)
		var typed *api.Error
		if !errors.As(failure, &typed) || typed.Code != api.CodePrerequisite || !strings.Contains(typed.Message, "spawn errno=EBADF; clone3 size-zero="+nativeSpawnErrno(cause)) ||
			strings.Contains(typed.Message, "argument validation reached") != (cause == unix.EINVAL) {
			t.Fatal("acceptance: clone3 entry observation was lost or overstated")
		}
	}
}

func TestNativeClone3Probe(t *testing.T) {
	for _, cause := range []unix.Errno{unix.EPERM, unix.ENOSYS, unix.EINVAL} {
		calls := 0
		observed := probeNativeClone3(func(trap, a1, a2, a3 uintptr) (uintptr, uintptr, unix.Errno) {
			calls++
			if trap != unix.SYS_CLONE3 || a1 != 0 || a2 != 0 || a3 != 0 {
				t.Fatal("acceptance: clone3 diagnostic lost its null pointer and zero size")
			}
			return ^uintptr(0), 0, cause
		})
		if calls != 1 || observed != cause {
			t.Fatal("acceptance: clone3 diagnostic ignored its actual syscall result")
		}
	}
}

func TestNativeSpawnMissing(t *testing.T) {
	private, err := randomID("missing-executable-")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(privateTestDir(t), string(private)), string(private))
	cmd.Env = []string{}
	err = startInNetworkNamespace(cmd, nil)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodePrerequisite || !strings.Contains(typed.Message, "spawn errno=ENOENT;") || !strings.Contains(typed.Message, "clone3 size-zero=") {
		t.Fatal("acceptance: actual failed spawn lost its safe creation diagnostic")
	}
	if cmd.Process != nil || strings.Contains(err.Error(), string(private)) {
		t.Fatal("acceptance: failed spawn created a process or disclosed its executable")
	}
	if !strings.Contains(typed.Message, "helper CAP_SETUID=") || !strings.Contains(typed.Message, "helper nnp=") || !strings.Contains(typed.Message, "cgroup=not-requested") {
		t.Fatal("acceptance: actual failed spawn lost its read-only setup observations")
	}
	if !strings.Contains(typed.Message, "process CAP_SETUID CapEff=") || !strings.Contains(typed.Message, ", CapPrm=") || !strings.Contains(typed.Message, ", CapBnd=") {
		t.Fatal("acceptance: actual failed spawn lost its independent main-thread observation")
	}
}

func TestNativeClone3Entry(t *testing.T) {
	// This is a real, noncreating syscall observation. A missing/filtered entry
	// remains a refusal category; it is never evidence of native containment.
	observed := probeNativeClone3(unix.RawSyscall)
	if observed != unix.EINVAL && observed != unix.ENOSYS && observed != unix.EPERM && observed != unix.EACCES {
		t.Fatal("native size-zero clone3 probe did not produce a supported refusal category")
	}
	if observed == unix.EINVAL && nativeSpawnErrno(observed) != "EINVAL" {
		t.Fatal("native clone3 validation observation lost its errno")
	}
}

func TestNativeSpawnCgroupFD(t *testing.T) {
	private, err := randomID("missing-cgroup-executable-")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(privateTestDir(t), string(private)), string(private))
	cmd.Env = []string{}
	cgroupFD := missingNativeCgroupFD(t)
	cmd.SysProcAttr = nativeGateAttributes(uint32(os.Geteuid()), uint32(os.Getegid()), cgroupFD)
	attr := cmd.SysProcAttr
	if !attr.UseCgroupFD || attr.CgroupFD != cgroupFD || attr.Credential == nil || attr.Credential.Uid != uint32(os.Geteuid()) || attr.Credential.Gid != uint32(os.Getegid()) ||
		attr.Credential.Groups == nil || len(attr.Credential.Groups) != 0 || attr.Credential.NoSetGroups || attr.Cloneflags != 0 || attr.Unshareflags != 0 || len(attr.AmbientCaps) != 0 {
		t.Fatal("acceptance: native creation lost atomic cgroup placement or credential dropping")
	}
	// This is the production constructor and a real syscall, with an invalid
	// cgroup FD. It must fail at clone3 before credentials or exec. Even a
	// weakened constructor encounters a missing executable, never test code.
	err = startInNetworkNamespace(cmd, nil)
	want := "EBADF"
	switch probeNativeClone3(unix.RawSyscall) {
	case unix.EINVAL:
	case unix.ENOSYS:
		want = "ENOSYS"
	case unix.EPERM:
		want = "EPERM"
	case unix.EACCES:
		want = "EACCES"
	default:
		t.Fatal("native cgroup spawn control could not classify clone3 entry")
	}
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodePrerequisite || !strings.Contains(typed.Message, "spawn errno="+want+";") || cmd.Process != nil {
		t.Fatal("acceptance: invalid cgroup FD did not refuse native creation at clone3")
	}
	if strings.Contains(err.Error(), string(private)) {
		t.Fatal("acceptance: cgroup creation refusal disclosed private executable data")
	}
	if !strings.Contains(typed.Message, "cgroup=unavailable(EBADF)") {
		t.Fatal("acceptance: failed spawn did not inspect its original cgroup descriptor")
	}
}

func missingNativeCgroupFD(t *testing.T) int {
	t.Helper()
	// A negative int becomes an out-of-range uint64 in Go's clone_args and
	// would test EINVAL instead of FD lookup. Keep the value in kernel int
	// range and establish that this descriptor is actually absent.
	const fd = 1<<31 - 1
	if _, err := unix.FcntlInt(fd, unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatal("native cgroup refusal fixture could not establish an absent FD")
	}
	return fd
}

func TestNativeSpawnSuccess(t *testing.T) {
	token, err := randomID("spawn-output-")
	if err != nil {
		t.Fatal(err)
	}
	// Reuse the actual descriptor-test vendor's exact-byte output/EOF canary.
	// This is a component spawn, not an installed containment assertion.
	cmd := exec.Command("/proc/self/exe", "admin-gate-descriptor-vendor", string(token))
	cmd.Env = []string{}
	var output bytes.Buffer
	cmd.Stdout = &output
	if err := startInNetworkNamespace(cmd, nil); err != nil {
		t.Fatal("native success control failed to start its real canary")
	}
	if err := cmd.Wait(); err != nil || !cmd.ProcessState.Success() || output.String() != string(token) {
		t.Fatal("acceptance: native creation reported success without the real canary output and exit")
	}
}
