//go:build linux && laneboss_root_canary

package admin

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

// Probe through a real inherited directory descriptor, so permissions on an
// unrelated ancestor cannot masquerade as withdrawal of the stage itself.
func stageTraversalProbe(t *testing.T, parent *os.File, gid uint32, allowed bool) {
	t.Helper()
	command := exec.CommandContext(collectionCanaryContext(t), "/usr/bin/cat", "/proc/self/fd/3/traversal-marker")
	command.Env, command.ExtraFiles = []string{}, []*os.File{parent}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 61002, Gid: gid, Groups: []uint32{}}}
	output, err := command.Output()
	if allowed {
		if err != nil || string(output) != "public traversal canary\n" {
			t.Fatal("stage GID traversal control was not actually readable", err)
		}
	} else {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || len(output) != 0 {
			t.Fatal("acceptance: a recycled stage GID retained traversal after withdrawal", err)
		}
	}
}

func TestStageWithdrawalParent(t *testing.T) {
	ctx := collectionCanaryContext(t)
	m, record, base := collectionLeaseFixture(t, true)
	marker := filepath.Join(base, "traversal-marker")
	if err := os.WriteFile(marker, []byte("public traversal canary\n"), 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(marker, 0444); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	stageTraversalProbe(t, parent, record.Lease.GID, true)
	live := exec.CommandContext(ctx, "/usr/bin/sleep", "30")
	live.Env = []string{}
	live.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: record.Lease.UID, Gid: record.Lease.GID, Groups: []uint32{}}}
	if err := live.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		if err := live.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Error(err)
		}
		var exited *exec.ExitError
		if err := live.Wait(); err != nil && !errors.As(err, &exited) {
			t.Error(err)
		}
	}
	t.Cleanup(stop)
	var before, after unix.Stat_t
	if err := unix.Fstat(int(parent.Fd()), &before); err != nil {
		t.Fatal(err)
	}
	err = m.retainPrivateStorage(ctx, &record)
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeContainmentUnknown || typed.Message != "lane UID still owns a live process; retain its lease" || record.Storage.Withdrawing || record.Storage.Withdrawn {
		t.Fatal("acceptance: storage withdrawal crossed a real live-UID barrier", err)
	}
	if unix.Fstat(int(parent.Fd()), &after) != nil || before.Mode != after.Mode || before.Gid != after.Gid {
		t.Fatal("refused withdrawal changed the stage parent")
	}
	stop()
	if err := m.retainPrivateStorage(ctx, &record); err != nil {
		t.Fatal("quiescent withdrawal did not complete", err)
	}
	if unix.Fstat(int(parent.Fd()), &after) != nil || after.Dev != before.Dev || after.Ino != before.Ino ||
		after.Uid != 0 || after.Gid != 0 || after.Mode&07777 != 0700 || !record.Storage.Withdrawn {
		t.Fatal("acceptance: successful withdrawal left the parent searchable by its old GID")
	}
	stageTraversalProbe(t, parent, record.Lease.GID, false)
	if err := m.retainPrivateStorage(ctx, &record); err != nil {
		t.Fatal("root-only withdrawal was not retryable", err)
	}
}
