//go:build linux

package linux

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// This small interpreter checks branch offsets independently of serialization.
// Kernel installation and a real unshare(0) control run in kernel_linux_test.
func evaluateFilter(t *testing.T, code []unix.SockFilter, number, architecture, flags uint32) uint32 {
	t.Helper()
	var accumulator uint32
	for pc := 0; pc < len(code); pc++ {
		instruction := code[pc]
		switch instruction.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			switch instruction.K {
			case 0:
				accumulator = number
			case 4:
				accumulator = architecture
			case 16:
				accumulator = flags
			default:
				t.Fatal("unexpected filter load")
			}
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K,
			unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K,
			unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			match := accumulator == instruction.K
			if instruction.Code == unix.BPF_JMP|unix.BPF_JGE|unix.BPF_K {
				match = accumulator >= instruction.K
			}
			if instruction.Code == unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K {
				match = accumulator&instruction.K != 0
			}
			if match {
				pc += int(instruction.Jt)
			} else {
				pc += int(instruction.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return instruction.K
		default:
			t.Fatal("unexpected filter instruction")
		}
	}
	t.Fatal("filter fell off the program")
	return 0
}

func TestSeccompIsADenyList(t *testing.T) {
	filter, err := denyFilter()
	if err != nil {
		t.Fatal(err)
	}
	architecture, err := auditArchitecture()
	if err != nil {
		t.Fatal(err)
	}
	for _, number := range []uint32{unix.SYS_READ, unix.SYS_WRITE, unix.SYS_OPENAT,
		unix.SYS_EXECVE, unix.SYS_SOCKET, unix.SYS_GETPID, unix.SYS_CLONE, 0x3fffffff} {
		if evaluateFilter(t, filter, number, architecture, 0) != unix.SECCOMP_RET_ALLOW {
			t.Fatalf("ordinary/unknown syscall %d denied", number)
		}
	}
	for _, number := range []uint32{unix.SYS_MOUNT, unix.SYS_SETNS, unix.SYS_UNSHARE,
		unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_OPEN_BY_HANDLE_AT,
		unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_KEYCTL} {
		if evaluateFilter(t, filter, number, architecture, 0) != unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM) {
			t.Fatalf("escape syscall %d allowed", number)
		}
	}
	if evaluateFilter(t, filter, unix.SYS_CLONE, architecture, unix.CLONE_NEWUSER) != unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM) ||
		evaluateFilter(t, filter, unix.SYS_CLONE3, architecture, 0) != unix.SECCOMP_RET_ERRNO|uint32(unix.ENOSYS) ||
		evaluateFilter(t, filter, unix.SYS_READ, 0, 0) != unix.SECCOMP_RET_KILL_PROCESS {
		t.Fatal("namespace fallback or architecture gate failed")
	}
}

func TestProbeCacheScopeAndFailures(t *testing.T) {
	var cache probeCache
	calls := 0
	measure := func() (api.IsolationCapabilities, error) {
		calls++
		return api.IsolationCapabilities{LandlockABI: calls,
			Checks: []api.Capability{{Name: "measured"}}}, nil
	}
	first, err := cache.get("boot-one:artifact", measure)
	if err != nil {
		t.Fatal(err)
	}
	first.Checks[0].Name = "caller-altered"
	second, err := cache.get("boot-one:artifact", measure)
	if err != nil || calls != 1 || second.Checks[0].Name != "measured" {
		t.Fatal("cache repeated probe or leaked mutable state")
	}
	if _, err := cache.get("boot-two:artifact", measure); err != nil || calls != 2 {
		t.Fatal("new boot reused an old observation")
	}
	failed := func() (api.IsolationCapabilities, error) {
		calls++
		return api.IsolationCapabilities{}, unix.ENOENT
	}
	for i := 0; i < 2; i++ {
		if _, err := cache.get("repaired-host", failed); !errors.Is(err, unix.ENOENT) {
			t.Fatal("failed probe cause lost")
		}
	}
	if calls != 4 {
		t.Fatal("failed probe prevented administrator repair")
	}
}

func TestMountAliasesAreNotAuthority(t *testing.T) {
	plain := []mountInfo{{id: 1, target: "/", root: "/"}}
	if err := checkMounts("/fixture/work", plain, 1); err != nil {
		t.Fatal("ordinary filesystem control:", err)
	}
	for _, points := range [][]mountInfo{
		{{id: 1, target: "/", root: "/"}, {id: 2, parent: 1, target: "/fixture/work", root: "/state/private"}},
		{{id: 1, target: "/", root: "/"}, {id: 2, parent: 1, target: "/fixture/work/nested", root: "/"}},
	} {
		if err := checkMounts("/fixture/work", points, 1); err == nil {
			t.Fatal("alias/nested mount gained data authority")
		}
	}
}
