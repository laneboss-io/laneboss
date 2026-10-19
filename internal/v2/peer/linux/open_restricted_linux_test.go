//go:build linux

package linux

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestCgroupRestricted(t *testing.T) {
	if os.Args[len(os.Args)-1] != "peer-openat2-refused" {
		command := exec.Command("/proc/self/exe", "-test.run=^TestCgroupRestricted$", "--", "peer-openat2-refused")
		command.Env = []string{}
		if err := command.Run(); err != nil {
			t.Fatal("acceptance: peer cgroup open failed under actual openat2 EPERM")
		}
		return
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jf: 1, K: unix.SYS_OPENAT2},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	result, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(filter)
	if errno != 0 || result != 0 {
		t.Fatal("peer open restriction fixture could not install its actual filter")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, "/sys/fs/cgroup", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC})
	if fd >= 0 {
		unix.Close(fd)
	}
	if !errors.Is(err, unix.EPERM) {
		t.Fatal("peer open restriction fixture did not measure EPERM")
	}
	process, err := readProcess(os.Getpid(), uint32(os.Getuid()), uint32(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	fd, identity, err := openGroup(process.group)
	if err != nil {
		t.Fatal("acceptance: peer cgroup open failed under actual openat2 EPERM")
	}
	defer unix.Close(fd)
	var info unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &info) != nil || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || identity.device != uint64(info.Dev) || identity.inode != info.Ino {
		t.Fatal("peer cgroup walk did not retain its actual cgroup-v2 inode")
	}
}
