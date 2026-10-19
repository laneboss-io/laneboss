//go:build linux

package admin

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func bootstrapFilterVerdict(t *testing.T, code []unix.SockFilter, number, architecture, flags uint32) uint32 {
	t.Helper()
	var value uint32
	for pc := 0; pc < len(code); pc++ {
		instruction := code[pc]
		switch instruction.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			switch instruction.K {
			case 0:
				value = number
			case 4:
				value = architecture
			case 16:
				value = flags
			default:
				t.Fatal("unexpected bootstrap seccomp data load")
			}
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			match := value == instruction.K
			if instruction.Code == unix.BPF_JMP|unix.BPF_JGE|unix.BPF_K {
				match = value >= instruction.K
			}
			if instruction.Code == unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K {
				match = value&instruction.K != 0
			}
			if match {
				pc += int(instruction.Jt)
			} else {
				pc += int(instruction.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return instruction.K
		default:
			t.Fatal("unexpected bootstrap seccomp instruction")
		}
	}
	t.Fatal("bootstrap seccomp filter fell through")
	return 0
}

func TestUsernsFilter(t *testing.T) {
	filter, err := bootstrapSeccompFilter()
	if err != nil {
		t.Fatal(err)
	}
	architecture := uint32(unix.AUDIT_ARCH_X86_64)
	if runtime.GOARCH == "arm64" {
		architecture = unix.AUDIT_ARCH_AARCH64
	}
	for _, sample := range []struct {
		name          string
		number, flags uint32
		want          uint32
	}{
		{"unshare", unix.SYS_UNSHARE, unix.CLONE_NEWUSER, unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		{"setns", unix.SYS_SETNS, 0, unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		{"clone", unix.SYS_CLONE, unix.CLONE_NEWUSER | uint32(unix.SIGCHLD), unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		{"clone3", unix.SYS_CLONE3, 0, unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)},
		{"ordinary-clone", unix.SYS_CLONE, uint32(unix.SIGCHLD), unix.SECCOMP_RET_ALLOW},
		{"ordinary-read", unix.SYS_READ, 0, unix.SECCOMP_RET_ALLOW},
	} {
		t.Run(sample.name, func(t *testing.T) {
			if got := bootstrapFilterVerdict(t, filter, sample.number, architecture, sample.flags); got != sample.want {
				t.Fatal("acceptance: bootstrap seccomp lost the user namespace boundary or ordinary process control")
			}
		})
	}
}

func TestPristineProcMount(t *testing.T) {
	root := "1 0 0:1 / / rw - tmpfs tmpfs rw\n"
	proc := "2 1 0:2 / /witness rw,nosuid,nodev,noexec - proc proc rw\n"
	for _, sample := range []struct {
		name, data, id, path string
		want                 bool
	}{
		{"present", root + proc, "2", "/witness", true},
		{"missing", root, "2", "/witness", false},
		{"wrong-id", root + proc, "3", "/witness", false},
		{"wrong-path", root + proc, "2", "/other", false},
		{"overmounted", root + proc + "3 2 0:3 / /witness/sys ro - tmpfs tmpfs rw\n", "2", "/witness", false},
		{"duplicate", root + proc + proc, "2", "/witness", false},
		{"malformed", root + proc + "unreadable\n", "2", "/witness", false},
	} {
		t.Run(sample.name, func(t *testing.T) {
			if got := pristineProcMount([]byte(sample.data), sample.id, sample.path); got != sample.want {
				t.Fatal("acceptance: pristine procfs mount verification accepted a missing or masked view")
			}
		})
	}
}

func TestNativeUserNamespaceArgs(t *testing.T) {
	for _, network := range []bool{false, true} {
		args, _ := nativeGateArgs("userns-fixture", "prepared-gate", nil, nil, network)
		joined := strings.Join(args, "\x00")
		if strings.Contains(joined, "--disable-userns") || strings.Contains(joined, "--assert-userns-disabled") ||
			!strings.Contains(joined, "--proc\x00/proc\x00") || !strings.Contains(joined, "--remount-ro\x00/proc\x00") {
			t.Fatal("acceptance: native user namespace compatibility lost private read-only procfs or restored a sysctl write")
		}
	}
}

func TestNativeSpawnPreflight(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{false: "refused", true: "allowed"}[allow], func(t *testing.T) {
			token, err := randomID("preflight-")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "/proc/self/exe", "admin-gate-descriptor-vendor", string(token))
			command.Env = []string{}
			var stdout bytes.Buffer
			command.Stdout = &stdout
			lifetime := newNativeSpawnLifetime()
			refused, calls := errors.New("preflight refused"), 0
			startErr := startInNetworkNamespaceLifetime(command, nil, lifetime, func() error {
				calls++
				leader, err := os.Stat("/proc/self/ns/mnt")
				thread, threadErr := os.Stat("/proc/thread-self/ns/mnt")
				if err != nil || threadErr != nil || !os.SameFile(leader, thread) {
					return errors.New("preflight namespace observation unavailable")
				}
				if !allow {
					return refused
				}
				return nil
			})
			var waitErr error
			if command.Process != nil {
				waitErr = command.Wait()
				lifetime.observedWait(command.ProcessState)
			}
			select {
			case <-lifetime.threadDone:
			case <-time.After(3 * time.Second):
				t.Fatal("native preflight creator did not release after refusal or actual exit")
			}
			if calls != 1 || ctx.Err() != nil || !allow && (startErr != refused || command.Process != nil || stdout.Len() != 0) ||
				allow && (startErr != nil || waitErr != nil || stdout.String() != string(token)) {
				t.Fatal("acceptance: native spawn ignored its locked-thread preflight or invented execution")
			}
		})
	}
}

func TestNativeProcSpawnRefusal(t *testing.T) {
	command := exec.Command("/proc/self/exe", "admin-gate-descriptor-vendor", "must-not-run")
	command.Env = []string{}
	command.SysProcAttr = nativeGateAttributes(uint32(os.Geteuid()), uint32(os.Getegid()), missingNativeCgroupFD(t))
	lifetime := newNativeSpawnLifetime()
	err := startInNetworkNamespaceVerified(command, nil, lifetime, privateTestDir(t))
	var typed *api.Error
	if command.Process != nil || !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown {
		t.Fatal("acceptance: unverified pristine procfs reached native process creation")
	}
}
