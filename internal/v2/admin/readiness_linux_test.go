//go:build linux

package admin

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	if len(os.Args) != 4 || os.Args[1] != "admin-readiness-fixture" {
		return
	}
	switch os.Args[2] {
	case "bootstrap":
		// Descriptor 3 is a real ordinary file, not a sealed memfd. Exercise
		// the production failure and its deferred reason write to descriptor 5.
		if err := runFixedBootstrap(context.Background(), "readiness-fixture", "prepared-gate"); err == nil {
			os.Exit(38)
		}
	case "valid":
		if unix.Send(5, []byte(os.Args[3]), 0) != nil {
			os.Exit(39)
		}
	case "bwrap":
		if _, err := os.Stderr.WriteString("bwrap: Unknown option --" + os.Args[3] + "\n"); err != nil {
			os.Exit(39)
		}
		os.Exit(1)
	case "mount":
		if _, err := os.Stderr.WriteString("bwrap: Can't mount proc on /" + os.Args[3] + ": Read-only file system\n"); err != nil {
			os.Exit(39)
		}
		os.Exit(1)
	case "setup":
		if _, err := os.Stderr.WriteString("bwrap: Can't find source path /" + os.Args[3] + ": No such file or directory\n"); err != nil {
			os.Exit(39)
		}
		if err := unix.Close(5); err != nil {
			os.Exit(39)
		}
		time.Sleep(25 * time.Millisecond)
		os.Exit(1)
	case "mismatch":
		if unix.Send(5, []byte("foreign-"+os.Args[3]), 0) != nil {
			os.Exit(39)
		}
	case "truncated":
		if unix.Send(5, []byte(os.Args[3]+strings.Repeat("x", 1024)), 0) != nil {
			os.Exit(39)
		}
	case "deadline":
		for {
			unix.Pause()
		}
	case "signal":
		if unix.Kill(os.Getpid(), unix.SIGTERM) != nil {
			os.Exit(40)
		}
		for {
			unix.Pause()
		}
	case "eof", "closed":
	default:
		os.Exit(41)
	}
	os.Exit(37)
}

func readinessFixture(t *testing.T, mode, token string) (*net.UnixConn, *nativeGate) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("readiness socket fixture unavailable")
	}
	parent, child := os.NewFile(uintptr(pair[0]), "readiness-owner"), os.NewFile(uintptr(pair[1]), "readiness-child")
	defer parent.Close()
	defer child.Close()
	if err := unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		t.Fatal("readiness credential fixture unavailable")
	}
	connection, err := net.FileConn(parent)
	if err != nil {
		t.Fatal("readiness connection fixture unavailable")
	}
	ready := connection.(*net.UnixConn)
	discard, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal("readiness descriptor fixture unavailable")
	}
	defer discard.Close()
	cmd := exec.Command("/proc/self/exe", "admin-readiness-fixture", mode, token)
	cmd.Env, cmd.ExtraFiles = []string{}, []*os.File{discard, discard, child}
	sink, err := os.OpenFile("/dev/null", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal("readiness stderr fixture unavailable")
	}
	defer sink.Close()
	observer, err := attachBootstrapStderr(cmd, sink)
	if err != nil {
		t.Fatal("readiness stderr ownership unavailable")
	}
	if err := cmd.Start(); err != nil {
		t.Fatal("readiness child fixture did not start")
	}
	if err := child.Close(); err != nil {
		t.Fatal("readiness fixture child duplicate did not close")
	}
	pidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		if killErr := cmd.Process.Kill(); killErr != nil {
			t.Fatal("readiness fixture could not stop its unpinned child")
		}
		if err := cmd.Wait(); err == nil {
			t.Fatal("readiness fixture stop lost its actual exit")
		}
		t.Fatal("readiness child lifetime fixture unavailable")
	}
	gate := &nativeGate{command: cmd, pidfd: pidfd, innerFD: -1, done: make(chan struct{}), stderr: observer}
	go func() {
		err := cmd.Wait()
		if closeErr := observer.close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		gate.mu.Lock()
		gate.state, gate.waitErr = cmd.ProcessState, err
		close(gate.done)
		gate.mu.Unlock()
	}()
	t.Cleanup(func() {
		ready.Close()
		if err := gate.Close(); err != nil {
			t.Error("readiness fixture stop failed")
		}
		select {
		case <-gate.done:
			if err := unix.Close(pidfd); err != nil {
				t.Error("readiness fixture lifetime close failed")
			}
		case <-time.After(3 * time.Second):
			t.Error("readiness fixture child was not collected")
			if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				t.Error("readiness fixture fallback stop failed")
			}
			select {
			case <-gate.done:
				if err := unix.Close(pidfd); err != nil {
					t.Error("readiness fixture fallback lifetime close failed")
				}
			case <-time.After(3 * time.Second):
				t.Error("readiness fixture fallback wait failed")
			}
		}
	})
	if mode != "deadline" && mode != "setup" {
		select {
		case <-gate.done:
		case <-time.After(3 * time.Second):
			t.Fatal("readiness fixture did not produce its real terminal status")
		}
	}
	if err := ready.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal("readiness fixture deadline unavailable")
	}
	if mode == "closed" {
		if err := ready.Close(); err != nil {
			t.Fatal("readiness fixture could not close its reader")
		}
	}
	return ready, gate
}

func TestNativeReadiness(t *testing.T) {
	for _, sample := range []struct {
		mode   string
		kind   string
		reason string
	}{
		{"valid", "", ""}, {"eof", "read=eof", "not_reported"},
		{"deadline", "read=deadline", "not_reported"}, {"closed", "read=other", "not_reported"},
		{"mismatch", "token_mismatch", "not_reported"}, {"truncated", "truncated", "not_reported"},
		{"bootstrap", "token_mismatch", "input.seals"}, {"signal", "read=eof", "not_reported"},
		{"bwrap", "read=eof", "not_reported"}, {"mount", "read=eof", "not_reported"},
	} {
		t.Run(sample.mode, func(t *testing.T) {
			token, err := randomID("private-ready-")
			if err != nil {
				t.Fatal(err)
			}
			ready, gate := readinessFixture(t, sample.mode, string(token))
			controls, err := readNativeReadiness(ready, string(token), gate)
			if sample.kind == "" {
				if err != nil {
					t.Fatal("acceptance: exact readiness packet was refused")
				}
				messages, err := unix.ParseSocketControlMessage(controls)
				if err != nil || len(messages) != 1 {
					t.Fatal("acceptance: exact readiness lost kernel credentials")
				}
				cred, err := unix.ParseUnixCredentials(&messages[0])
				if err != nil || int(cred.Pid) != gate.command.Process.Pid || cred.Uid != uint32(os.Getuid()) || cred.Gid != uint32(os.Getgid()) {
					t.Fatal("acceptance: exact readiness credentials differ from its real child")
				}
				return
			}
			var typed *api.Error
			if len(controls) != 0 || !errors.As(err, &typed) || typed.Owner != "lb-v2-admin" || typed.Code != api.CodeContainmentUnknown {
				t.Fatal("acceptance: failed readiness packet continued toward native acceptance")
			}
			select {
			case <-gate.done:
			default:
				t.Fatal("acceptance: failed readiness did not collect its actual child")
			}
			gate.mu.Lock()
			if gate.state == nil {
				gate.mu.Unlock()
				t.Fatal("readiness fixture has no native wait status")
			}
			status, ok := gate.state.Sys().(syscall.WaitStatus)
			gate.mu.Unlock()
			wantWait := "child exited code=37"
			exitCode := 37
			if sample.mode == "bwrap" || sample.mode == "mount" {
				exitCode, wantWait = 1, "child exited code=1"
			}
			if sample.mode == "deadline" || sample.mode == "signal" {
				signal := syscall.SIGKILL
				if sample.mode == "signal" {
					signal = syscall.SIGTERM
				}
				if !ok || !status.Signaled() || status.Signal() != signal {
					t.Fatal("acceptance: readiness fixture did not retain its actual signal wait")
				}
				wantWait = "child killed signal=" + unix.SignalName(signal)
			} else if !ok || !status.Exited() || status.ExitStatus() != exitCode {
				t.Fatal("acceptance: readiness fixture did not retain its actual exit wait")
			}
			if !strings.Contains(typed.Message, sample.kind+";") || !strings.Contains(typed.Message, wantWait+";") || !strings.Contains(typed.Message, "wait_result=observed;") || !strings.Contains(typed.Message, "bootstrap_report="+sample.reason+";") || !strings.Contains(typed.Message, "stop=observed)") || strings.Contains(typed.Message, string(token)) {
				t.Fatal("acceptance: actual readiness refusal lost its case, wait, fixed reason or privacy")
			}
			if sample.mode == "bwrap" && (!strings.Contains(typed.Message, "bwrap_stderr=option_unsupported;") || !strings.Contains(typed.Message, "exit_stage_hint=bwrap_setup;")) {
				t.Fatal("acceptance: failed native bootstrap lost its actual stderr classification")
			}
			if sample.mode == "mount" && !strings.Contains(typed.Message, "bwrap_stderr=mount_failed; bwrap_mount=proc; bwrap_errno=EROFS;") {
				t.Fatal("acceptance: native readiness lost the captured mount operation and errno")
			}
		})
	}
}

func TestBootstrapReasonPrivacy(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("reason transport fixture unavailable")
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	private, err := randomID("private-reason-")
	if err != nil {
		t.Fatal(err)
	}
	if err := reportBootstrapFailure(pair[0], errors.New(string(private))); err != nil {
		t.Fatal("reason transport did not write")
	}
	data := make([]byte, 4096)
	n, err := unix.Read(pair[1], data)
	if err != nil || n == 0 || strings.Contains(string(data[:n]), string(private)) || bootstrapPacketReason(data[:n]) != "unclassified" {
		t.Fatal("acceptance: bootstrap reason transport disclosed arbitrary error data")
	}
	if bootstrapPacketReason([]byte(bootstrapFailurePrefix+string(private))) != "not_reported" {
		t.Fatal("acceptance: parent trusted an unknown bootstrap reason")
	}
}
