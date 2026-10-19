//go:build linux

package boxexec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExecCancel(t *testing.T) {
	dir := t.TempDir()
	childFile := filepath.Join(dir, "child.pid")
	sleepFile := filepath.Join(dir, "sleep.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	type answer struct {
		result Result
		err    error
	}
	done := make(chan answer, 1)
	go func() {
		result, err := (ExecRunner{}).Run(ctx, Cmd{
			Name: "sh", Env: []string{"PATH=/bin:/usr/bin"},
			Args: []string{"-c", "printf '%s\\n' \"$$\" > \"$1\"; " +
				"sleep 30 & printf '%s\\n' \"$!\" > \"$2\"; wait", "sh", childFile, sleepFile},
		})
		done <- answer{result, err}
	}()
	pid, pidErr := waitPID(ctx, childFile)
	sleepPID, sleepErr := waitPID(ctx, sleepFile)
	if pidErr == nil {
		t.Cleanup(func() { stopPID(t, pid) })
	}
	if sleepErr == nil {
		t.Cleanup(func() { stopPID(t, sleepPID) })
	}
	var group, sleepGroup int
	var groupErr, sleepGroupErr error
	if pidErr == nil {
		group, groupErr = syscall.Getpgid(pid)
	}
	if sleepErr == nil {
		sleepGroup, sleepGroupErr = syscall.Getpgid(sleepPID)
	}
	started := time.Now()
	cancel()
	var got answer
	select {
	case got = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled run did not return within ten seconds")
	}
	if pidErr != nil || sleepErr != nil {
		t.Fatal("child processes did not report valid pids before cancellation")
	}
	if groupErr != nil || sleepGroupErr != nil || group != pid || sleepGroup != pid {
		t.Fatal("child and descendant were not in their own process group")
	}
	if time.Since(started) >= 10*time.Second || !errors.Is(got.err, context.Canceled) || got.result.Code != 137 {
		t.Fatalf("cancelled run: code = %d, error = %v", got.result.Code, got.err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatal("the direct child still exists after Run returned")
	}
	// A killed orphan can remain a zombie, or be mid-teardown, for a moment after Run returns: wait briefly for it.
	// A descendant that was not killed would sleep for thirty seconds, so it still fails here.
	deadline := time.Now().Add(3 * time.Second)
	for {
		live, err := livePID(sleepPID)
		if err != nil {
			t.Fatal("could not read the descendant's state")
		}
		if !live {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the descendant is still running after cancellation")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestExecPreCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := (ExecRunner{}).Run(ctx, Cmd{
		Name: "/bin/sh", Args: []string{"-c", "printf started"}, Env: []string{},
	})
	if !errors.Is(err, context.Canceled) || got.Code != -1 || len(got.Stdout) != 0 {
		t.Fatal("an already cancelled context started a child")
	}
}

func waitPID(ctx context.Context, path string) (int, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			text := strings.TrimSpace(string(data))
			if text != "" {
				pid, err := strconv.Atoi(text)
				if err != nil || pid <= 0 {
					return 0, errors.New("invalid child pid")
				}
				return pid, nil
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-ticker.C:
		}
	}
}

func livePID(pid int) (bool, error) {
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 || len(data) <= end+2 {
		return false, fmt.Errorf("invalid process state for pid %d", pid)
	}
	return data[end+2] != 'Z', nil
}

func stopPID(t *testing.T, pid int) {
	t.Helper()
	live, err := livePID(pid)
	if err != nil {
		t.Error("could not read the child process state during cleanup")
		return
	}
	if live {
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			t.Error("could not stop a child process during cleanup")
		}
	}
}
