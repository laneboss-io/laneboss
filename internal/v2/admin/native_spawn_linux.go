//go:build linux

package admin

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func nativeGateAttributes(uid, gid uint32, cgroupFD int) *syscall.SysProcAttr {
	// CLONE_INTO_CGROUP is mandatory. There is no fork-then-migrate fallback.
	return &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}, UseCgroupFD: true, CgroupFD: cgroupFD}
}

// cmd.Start combines clone3(CLONE_INTO_CGROUP), child credential/FD setup and
// execve. Its error does not identify which of those operations failed. Never
// label every Start error a clone3 or user-namespace refusal, or expose the
// wrapped PathError, which can contain private executable/argument data.
func nativeGateCreationError(err error, attr *syscall.SysProcAttr) error {
	return failure(api.CodePrerequisite, nativeGateCreationMessage(err, probeNativeClone3(unix.RawSyscall))+"; "+nativeCapabilityFacts(unix.Capget)+"; "+nativeMainCapabilityFacts()+"; "+nativeThreadFacts()+"; "+nativeCgroupFacts(attr))
}

type nativeClone3Call func(trap, a1, a2, a3 uintptr) (uintptr, uintptr, unix.Errno)

func probeNativeClone3(call nativeClone3Call) unix.Errno {
	// A zero struct size is below CLONE_ARGS_SIZE_VER0. The kernel must reject
	// it before reading arguments or creating any task. This tests syscall
	// entry only: EINVAL reaches validation; ENOSYS can mean absent or filtered.
	// No valid clone, namespace, cgroup or credential operation is attempted.
	_, _, errno := call(unix.SYS_CLONE3, 0, 0, 0)
	return errno
}

func nativeGateCreationFailure(err error, probe unix.Errno) error {
	return failure(api.CodePrerequisite, nativeGateCreationMessage(err, probe))
}

func nativeGateCreationMessage(err error, probe unix.Errno) string {
	entry := nativeSpawnErrno(probe)
	if probe == unix.EINVAL {
		entry = "EINVAL (argument validation reached)"
	}
	return "kernel refused confined gate creation (spawn errno=" + nativeSpawnErrno(err) + "; clone3 size-zero=" + entry + ")"
}

func nativeSpawnErrno(err error) string {
	var errno unix.Errno
	if !errors.As(err, &errno) {
		return "other"
	}
	switch errno {
	case unix.EPERM:
		return "EPERM"
	case unix.EACCES:
		return "EACCES"
	case unix.ENOSYS:
		return "ENOSYS"
	case unix.EINVAL:
		return "EINVAL"
	case unix.EBADF:
		return "EBADF"
	case unix.EBUSY:
		return "EBUSY"
	case unix.EOPNOTSUPP:
		return "EOPNOTSUPP"
	case unix.EAGAIN:
		return "EAGAIN"
	case unix.ENOMEM:
		return "ENOMEM"
	case unix.ENOENT:
		return "ENOENT"
	case unix.ENOEXEC:
		return "ENOEXEC"
	case unix.ENOTDIR:
		return "ENOTDIR"
	case unix.ELOOP:
		return "ELOOP"
	case unix.EFAULT:
		return "EFAULT"
	case unix.EMFILE:
		return "EMFILE"
	case unix.ENFILE:
		return "ENFILE"
	default:
		// Unknown, zero and non-errno errors never disclose arbitrary text.
		return "other"
	}
}
