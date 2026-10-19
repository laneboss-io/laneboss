//go:build linux

package admin

import (
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// These are read-only failure observations, never prerequisites that return a
// successful launch or evidence of confinement. Only fixed names and verdicts
// escape: no UID, PID, cgroup path, controller value or capability bitmap.
func nativeCapabilityFacts(get func(*unix.CapUserHeader, *unix.CapUserData) error) string {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := get(&header, &data[0]); err != nil {
		return "helper capabilities=" + nativeFactError(err)
	}
	return "helper CAP_SETUID=" + nativeCapabilityBit(data[0].Effective, unix.CAP_SETUID) +
		", CAP_SETGID=" + nativeCapabilityBit(data[0].Effective, unix.CAP_SETGID) +
		", CAP_SYS_ADMIN=" + nativeCapabilityBit(data[0].Effective, unix.CAP_SYS_ADMIN)
}

func nativeCapabilityBit(bits uint32, capability uint) string {
	if bits&(uint32(1)<<capability) != 0 {
		return "present"
	}
	return "absent"
}

func nativeThreadFacts() string {
	nnp, nnpErr := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	seccomp, seccompErr := unix.PrctlRetInt(unix.PR_GET_SECCOMP, 0, 0, 0, 0)
	return "helper nnp=" + nativeThreadMode(nnp, nnpErr, false) + ", seccomp=" + nativeThreadMode(seccomp, seccompErr, true)
}

func nativeThreadMode(value int, err error, seccomp bool) string {
	if err != nil {
		return nativeFactError(err)
	}
	if seccomp {
		switch value {
		case 0:
			return "none"
		case 1:
			return "strict"
		case 2:
			return "filter"
		}
	} else {
		switch value {
		case 0:
			return "off"
		case 1:
			return "on"
		}
	}
	return "unrecognized"
}

func nativeCgroupFacts(attr *syscall.SysProcAttr) string {
	if attr == nil || !attr.UseCgroupFD {
		return "cgroup=not-requested"
	}
	fd := attr.CgroupFD
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return "cgroup=" + nativeFactError(err)
	}
	if info.Mode&unix.S_IFMT != unix.S_IFDIR {
		return "cgroup=not-directory"
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return "cgroup=" + nativeFactError(err)
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return "cgroup=not-cgroup-v2"
	}
	domain, domainErr := readNativeCgroupControl(fd, "cgroup.type")
	subtree, subtreeErr := readNativeCgroupControl(fd, "cgroup.subtree_control")
	processes, processesErr := readNativeCgroupControl(fd, "cgroup.procs")
	return "cgroup=v2, type=" + nativeCgroupValue(domain, domainErr, true) +
		", subtree=" + nativeCgroupValue(subtree, subtreeErr, false) +
		", processes=" + nativeCgroupValue(processes, processesErr, false) +
		", procs-open=" + nativeCgroupWriteOpen(fd)
}

func nativeCgroupValue(value string, err error, domain bool) string {
	if err != nil {
		return nativeFactError(err)
	}
	if domain {
		switch value {
		case "domain", "threaded", "domain threaded", "domain invalid":
			return value
		default:
			return "unrecognized"
		}
	}
	if value == "" {
		return "empty"
	}
	return "nonempty"
}

func readNativeCgroupControl(fd int, name string) (string, error) {
	child, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(child), "spawn-cgroup-control")
	data, readErr := io.ReadAll(io.LimitReader(file, 4097))
	closeErr := file.Close()
	if readErr != nil {
		return "", readErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if len(data) > 4096 {
		return "", io.ErrShortBuffer
	}
	return strings.TrimSpace(string(data)), nil
}

func nativeCgroupWriteOpen(fd int) string {
	// Opening without O_TRUNC/O_CREAT and closing performs no cgroup write.
	// Openability does not prove attach permissions or migration authority.
	child, err := unix.Openat(fd, "cgroup.procs", unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nativeFactError(err)
	}
	if err := unix.Close(child); err != nil {
		return nativeFactError(err)
	}
	return "openable"
}

func nativeFactError(err error) string {
	return "unavailable(" + nativeSpawnErrno(err) + ")"
}
