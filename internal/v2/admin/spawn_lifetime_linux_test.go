//go:build linux

package admin

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	if len(os.Args) != 3 || os.Args[1] != "admin-creator-lifetime" {
		return
	}
	runtime.LockOSThread()
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0); err != nil {
		os.Exit(51)
	}
	ready, release := os.NewFile(3, "creator-ready"), os.NewFile(4, "creator-release")
	if n, err := ready.WriteString(os.Args[2]); err != nil || n != len(os.Args[2]) {
		os.Exit(52)
	}
	var token [1]byte
	if _, err := io.ReadFull(release, token[:]); err != nil || token[0] != 'x' {
		os.Exit(53)
	}
	os.Exit(0)
}

func TestNativeCreatorLifetime(t *testing.T) {
	token, err := randomID("creator-")
	if err != nil {
		t.Fatal(err)
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
	cmd := exec.Command("/proc/self/exe", "admin-creator-lifetime", string(token))
	cmd.Env, cmd.ExtraFiles = []string{}, []*os.File{readyWrite, releaseRead}
	// Go installs this before exec, eliminating a child-init/creator-exit race.
	// The child also executes the same real prctl used by bwrap's policy.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	lifetime := newNativeSpawnLifetime()
	started := make(chan error, 1)
	go func() { started <- startInNetworkNamespacePinned(cmd, nil, lifetime) }()
	if err := <-started; err != nil {
		t.Fatal("creator lifetime fixture could not start")
	}
	finished := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		lifetime.observedWait(cmd.ProcessState)
		finished <- err
	}()
	waited := false
	t.Cleanup(func() {
		if !waited {
			if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) && !errors.Is(err, unix.ESRCH) {
				t.Error("creator fixture stop failed")
			}
			select {
			case <-finished:
			case <-time.After(3 * time.Second):
				t.Error("creator fixture wait was not collected")
			}
		}
	})
	if err := readyWrite.Close(); err != nil {
		t.Fatal(err)
	}
	if err := readyRead.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, len(token))
	if _, err := io.ReadFull(readyRead, actual); err != nil || string(actual) != string(token) {
		t.Fatal("acceptance: creator thread ended before its actual child")
	}
	runtime.GC()
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		if errors.Is(err, unix.ESRCH) {
			t.Fatal("acceptance: creator thread ended before its actual child")
		}
		t.Fatal("creator fixture pidfd is unavailable")
	}
	defer unix.Close(fd)
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	count, err := unix.Poll(fds, 50)
	if err != nil || count != 0 || fds[0].Revents != 0 || lifetime.fact() != "locked_present" {
		t.Fatal("acceptance: creator thread ended before its actual child")
	}
	lifetime.observedWait(nil)
	select {
	case <-lifetime.ended:
		t.Fatal("acceptance: unavailable wait released a live creator thread")
	default:
	}
	if _, err := releaseWrite.Write([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; err != nil || !cmd.ProcessState.Success() {
		t.Fatal("creator fixture lost its actual successful exit")
	}
	waited = true
	select {
	case <-lifetime.threadDone:
	case <-time.After(3 * time.Second):
		t.Fatal("acceptance: waited creator thread was not released")
	}
	if lifetime.fact() != "released" {
		t.Fatal("acceptance: waited creator thread was not released")
	}
}

func TestNativeCreatorRefusals(t *testing.T) {
	for _, lifetime := range []*nativeSpawnLifetime{nil, {}} {
		cmd := exec.Command("/usr/bin/true")
		var typed *api.Error
		err := startInNetworkNamespacePinned(cmd, nil, lifetime)
		started := cmd.Process != nil
		if started {
			if waitErr := cmd.Wait(); waitErr != nil {
				t.Fatal("refused creator fixture could not collect its unexpected child")
			}
		}
		if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || started {
			t.Fatal("acceptance: unowned native launch started a child")
		}
	}
	private, err := randomID("creator-missing-")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(filepath.Join(privateTestDir(t), string(private)))
	cmd.Env = []string{}
	lifetime := newNativeSpawnLifetime()
	var typed *api.Error
	if err := startInNetworkNamespacePinned(cmd, nil, lifetime); !errors.As(err, &typed) || typed.Code != api.CodePrerequisite ||
		!strings.Contains(typed.Message, "spawn errno=ENOENT;") || strings.Contains(typed.Message, string(private)) || cmd.Process != nil {
		t.Fatal("acceptance: owned spawn refusal lost its real failure or privacy")
	}
	select {
	case <-lifetime.threadDone:
	case <-time.After(3 * time.Second):
		t.Fatal("failed creator thread was not released")
	}
}
