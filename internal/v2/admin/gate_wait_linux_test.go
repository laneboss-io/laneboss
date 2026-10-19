//go:build linux

package admin

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	if len(os.Args) != 2 {
		return
	}
	switch os.Args[1] {
	case "admin-drain-primary":
		ready, release := os.NewFile(3, "descendant-ready"), os.NewFile(4, "descendant-release")
		input, completed := os.NewFile(5, "audit-input"), os.NewFile(6, "descendant-completed")
		prefix := make([]byte, 256)
		if n, err := input.ReadAt(prefix, 0); err != nil || n != len(prefix) {
			os.Exit(71)
		}
		if n, err := os.Stderr.Write(prefix); err != nil || n != len(prefix) {
			os.Exit(72)
		}
		descendant := exec.Command("/proc/self/exe", "admin-drain-descendant")
		descendant.Env, descendant.Stderr = []string{}, os.Stderr
		descendant.ExtraFiles = []*os.File{release, input, completed}
		if err := descendant.Start(); err != nil {
			os.Exit(73)
		}
		// Private control bytes let the test pin and collect the real child.
		// No process identifier enters diagnostic output or a service receipt.
		if err := binary.Write(ready, binary.LittleEndian, int64(descendant.Process.Pid)); err != nil {
			os.Exit(74)
		}
		os.Exit(17)
	case "admin-drain-descendant":
		release, input, completed := os.NewFile(3, "descendant-release"), os.NewFile(4, "audit-input"), os.NewFile(5, "descendant-completed")
		var allow [1]byte
		if _, err := io.ReadFull(release, allow[:]); err != nil || allow[0] != 'x' {
			os.Exit(75)
		}
		if _, err := input.Seek(256, io.SeekStart); err != nil {
			os.Exit(76)
		}
		if _, err := io.Copy(os.Stderr, input); err != nil {
			os.Exit(77)
		}
		if n, err := completed.Write([]byte{'e'}); err != nil || n != 1 {
			os.Exit(78)
		}
		os.Exit(0)
	}
}

func TestNativeStderrDrain(t *testing.T) {
	for _, mode := range []string{"accepted", "refused"} {
		t.Run(mode, func(t *testing.T) {
			root := privateTestDir(t)
			capture, err := os.CreateTemp(root, "audit-")
			if err != nil {
				t.Fatal(err)
			}
			defer capture.Close()
			input, err := os.CreateTemp(root, "input-")
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			seed, err := randomID("drain-")
			if err != nil {
				t.Fatal(err)
			}
			payload := []byte(strings.Repeat(string(seed), 8192))
			if n, err := input.Write(payload); err != nil || n != len(payload) {
				t.Fatal("audit fixture input was not retained")
			}
			readyRead, readyWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer readyRead.Close()
			defer readyWrite.Close()
			releaseRead, releaseWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer releaseRead.Close()
			defer releaseWrite.Close()
			completedRead, completedWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer completedRead.Close()
			defer completedWrite.Close()
			cmd := exec.Command("/proc/self/exe", "admin-drain-primary")
			cmd.Env, cmd.ExtraFiles = []string{}, []*os.File{readyWrite, releaseRead, input, completedWrite}
			observer, err := attachBootstrapStderr(cmd, capture)
			if err != nil {
				t.Fatal(err)
			}
			defer observer.close()
			if err := cmd.Start(); err != nil {
				t.Fatal("drain fixture did not start")
			}
			pidfd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
			if err != nil {
				t.Fatal("drain fixture primary pidfd unavailable")
			}
			gate := &nativeGate{command: cmd, pidfd: pidfd, innerFD: -1, done: make(chan struct{}), stderr: observer}
			if err := gate.startWaitOwner(); err != nil {
				t.Fatal(err)
			}
			descendantFD := -1
			t.Cleanup(func() {
				if descendantFD >= 0 {
					if err := unix.PidfdSendSignal(descendantFD, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
						t.Error("drain fixture descendant stop failed")
					}
					fds := []unix.PollFd{{Fd: int32(descendantFD), Events: unix.POLLIN}}
					if count, err := unix.Poll(fds, 3000); err != nil || count != 1 || fds[0].Revents&unix.POLLIN == 0 {
						t.Error("drain fixture descendant did not end")
					}
					if err := unix.Close(descendantFD); err != nil {
						t.Error("drain fixture descendant pin did not close")
					}
				}
				if err := gate.Close(); err != nil {
					t.Error("drain fixture primary stop failed")
				}
				select {
				case <-gate.done:
				case <-time.After(3 * time.Second):
					t.Error("drain fixture copier was not collected")
				}
			})
			if err := readyRead.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var descendantPID int64
			if err := binary.Read(readyRead, binary.LittleEndian, &descendantPID); err != nil || descendantPID <= 1 {
				t.Fatal("drain fixture descendant did not start")
			}
			descendantFD, err = unix.PidfdOpen(int(descendantPID), 0)
			if err != nil {
				t.Fatal("drain fixture descendant pidfd unavailable")
			}
			select {
			case <-gate.primaryDone:
			case <-time.After(3 * time.Second):
				t.Fatal("acceptance: primary exit waited for inherited stderr EOF")
			}
			gate.mu.Lock()
			observed, observedErr := gate.primaryExited, gate.primaryErr
			gate.mu.Unlock()
			if !observed || observedErr != nil {
				t.Fatal("acceptance: primary exit waited for inherited stderr EOF")
			}
			select {
			case <-gate.done:
				t.Fatal("drain fixture did not retain a real inherited stderr writer")
			default:
			}
			observer.freeze()
			if err := capture.Close(); err != nil {
				t.Fatal(err)
			}
			gate.mu.Lock()
			gate.release, gate.token = releaseWrite, "x"
			gate.mu.Unlock()
			releaseErr := gate.Release()
			gate.mu.Lock()
			retained, consumed := gate.release == releaseWrite, gate.released
			gate.release = nil // The fixture retains its independent cleanup/release.
			gate.mu.Unlock()
			var releaseFailure *api.Error
			if !errors.As(releaseErr, &releaseFailure) || releaseFailure.Code != api.CodeContainmentUnknown || !retained || consumed {
				t.Fatal("acceptance: ended primary consumed a native release")
			}
			if mode == "refused" {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				started := time.Now()
				observation, err := gate.Stop(ctx, api.ProcessHandle{})
				cancel()
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || !strings.Contains(typed.Message, "stderr drain exceeded") || observation.State != "" || time.Since(started) > 2*nativeStderrDrainWindow {
					t.Fatal("acceptance: inherited stderr did not produce a bounded retained refusal")
				}
			}
			if _, err := releaseWrite.Write([]byte{'x'}); err != nil {
				t.Fatal(err)
			}
			if err := completedRead.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var completed [1]byte
			if _, err := io.ReadFull(completedRead, completed[:]); err != nil || completed[0] != 'e' {
				t.Fatal("acceptance: drain deadline discarded late audit bytes")
			}
			select {
			case <-gate.done:
			case <-time.After(3 * time.Second):
				t.Fatal("audit drain did not complete after real descendant exit")
			}
			actual, err := os.ReadFile(capture.Name())
			if err != nil || !bytes.Equal(actual, payload) {
				t.Fatal("acceptance: drain deadline discarded late audit bytes")
			}
			observation, err := gate.Observe(context.Background(), api.ProcessHandle{})
			if mode == "accepted" {
				if err != nil || observation.State != "exited" || observation.ExitCode == nil || *observation.ExitCode != 17 {
					t.Fatal("acceptance: clean bounded drain lost the real primary exit")
				}
			} else {
				var typed *api.Error
				if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || !strings.Contains(typed.Message, "stderr drain exceeded") {
					t.Fatal("acceptance: late EOF erased the retained drain refusal")
				}
			}
		})
	}
}

func TestNativeStderrDrainInvalid(t *testing.T) {
	cmd := exec.Command("/usr/bin/true")
	gate := &nativeGate{command: cmd, pidfd: -1, done: make(chan struct{})}
	var typed *api.Error
	if err := gate.watchPrimaryExit(); !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || cmd.Process != nil || gate.primaryDone != nil {
		t.Fatal("acceptance: invalid primary pin acquired a wait owner")
	}
}
