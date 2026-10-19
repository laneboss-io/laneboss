//go:build linux

package linux

import (
	"encoding/binary"
	"errors"
	"runtime"

	"golang.org/x/sys/unix"
)

func auditArchitecture() (uint32, error) {
	switch runtime.GOARCH {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64, nil
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64, nil
	default:
		return 0, errors.New("seccomp architecture is not supported")
	}
}

// denyFilter is a syscall blacklist. The default is ALLOW. Ordinary binaries,
// compiler output, shells, file/network clients and process creation require
// no executable or syscall registration. Nested namespace creation and host
// kernel/process-management interfaces are denied even after a renamed exec.
func denyFilter() ([]unix.SockFilter, error) {
	architecture, err := auditArchitecture()
	if err != nil {
		return nil, err
	}
	load := uint16(unix.BPF_LD | unix.BPF_W | unix.BPF_ABS)
	jump := uint16(unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K)
	ret := uint16(unix.BPF_RET | unix.BPF_K)
	filter := []unix.SockFilter{
		{Code: load, K: 4}, // struct seccomp_data.arch
		{Code: jump, Jt: 1, K: architecture},
		{Code: ret, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: load, K: 0}, // struct seccomp_data.nr
	}
	if runtime.GOARCH == "amd64" {
		// x32 uses the same audit arch but different syscall numbers.
		filter = append(filter,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, Jf: 1, K: 0x40000000},
			unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_KILL_PROCESS})
	}
	for _, number := range []uint32{
		unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT,
		unix.SYS_OPEN_TREE, unix.SYS_MOVE_MOUNT, unix.SYS_MOUNT_SETATTR,
		unix.SYS_FSOPEN, unix.SYS_FSCONFIG, unix.SYS_FSMOUNT, unix.SYS_FSPICK,
		unix.SYS_SETNS, unix.SYS_UNSHARE, unix.SYS_PTRACE,
		unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
		unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_USERFAULTFD,
		unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_NAME_TO_HANDLE_AT,
		unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY,
		unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD, unix.SYS_REBOOT,
		unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
		unix.SYS_SWAPON, unix.SYS_SWAPOFF,
	} {
		filter = append(filter, unix.SockFilter{Code: jump, Jf: 1, K: number},
			unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)})
	}
	// clone3's flags live behind a user pointer, which classic BPF cannot read.
	// ENOSYS invokes the ordinary clone fallback in libc. Plain fork/threads
	// remain available; only clone's namespace bits are rejected.
	filter = append(filter,
		unix.SockFilter{Code: jump, Jf: 1, K: unix.SYS_CLONE3},
		unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)},
		unix.SockFilter{Code: jump, Jf: 3, K: unix.SYS_CLONE},
		unix.SockFilter{Code: load, K: 16},
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, Jf: 1,
			K: unix.CLONE_NEWUSER | unix.CLONE_NEWNS | unix.CLONE_NEWNET | unix.CLONE_NEWIPC |
				unix.CLONE_NEWUTS | unix.CLONE_NEWPID | unix.CLONE_NEWCGROUP | unix.CLONE_PTRACE},
		unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		unix.SockFilter{Code: ret, K: unix.SECCOMP_RET_ALLOW})
	return filter, nil
}

// bwrap consumes a packed array of native struct sock_filter, not SockFprog.
// Supported amd64/arm64 artifacts are little endian; the explicit encoding
// avoids Go padding or unsafe-slice assumptions in the retained input bytes.
func filterBytes(filter []unix.SockFilter) []byte {
	data := make([]byte, len(filter)*8)
	for index, instruction := range filter {
		entry := data[index*8:]
		binary.LittleEndian.PutUint16(entry, instruction.Code)
		entry[2], entry[3] = instruction.Jt, instruction.Jf
		binary.LittleEndian.PutUint32(entry[4:], instruction.K)
	}
	return data
}
