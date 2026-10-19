//go:build linux

package admin

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRetainedNamespaceKind(t *testing.T) {
	for _, name := range []string{"mnt", "net", "pid", "user"} {
		t.Run(name, func(t *testing.T) {
			file, err := os.Open("/proc/self/ns/" + name)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			var info unix.Stat_t
			if err := unix.Fstat(int(file.Fd()), &info); err != nil {
				t.Fatal(err)
			}
			mount, err := retainedMountNamespace(file.Name(), info)
			if err != nil || mount != (name == "mnt") {
				t.Fatal("acceptance: retained namespace did not use its actual kernel family", err)
			}
			changed := info
			changed.Ino++
			if _, err := retainedMountNamespace(file.Name(), changed); err == nil {
				t.Fatal("acceptance: retained namespace accepted a changed inode")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "/usr/bin/sleep", "4")
			command.Env, command.ExtraFiles = []string{}, []*os.File{file}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
					t.Error(err)
				}
				var exited *exec.ExitError
				if err := command.Wait(); err != nil && !errors.As(err, &exited) {
					t.Error(err)
				}
			})
			_, held, err := descriptorReferences(context.Background(), command.Process.Pid, nil)
			if err != nil || held != (name == "mnt") {
				t.Fatal("acceptance: native descriptor inventory conflated namespace families", err)
			}
		})
	}
}

// A descriptor swapped for a writerless FIFO after the Statfs check must be
// refused at once; a blocking open would hang the privileged helper.
func TestRetainedNamespaceSwappedFIFO(t *testing.T) {
	path := t.TempDir() + "/swapped"
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	var info unix.Stat_t
	if err := unix.Stat(path, &info); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := retainedMountNamespace(path, info)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("acceptance: a FIFO passed as a retained namespace")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("acceptance: pinning a swapped FIFO blocked the helper")
	}
}
