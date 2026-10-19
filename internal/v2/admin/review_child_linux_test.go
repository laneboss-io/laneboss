//go:build linux

package admin_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"regexp"
	"syscall"
	"testing"
	"time"
)

// The store fixture authenticates the process's actual unprivileged UID. A
// root package run executes the same assertions in a separate real process.
func reviewAsNonroot(t *testing.T) bool {
	t.Helper()
	if os.Geteuid() != 0 {
		return false
	}
	directory, err := os.MkdirTemp("/run", "lb-review-child-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	if err := os.Chown(directory, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/proc/self/fd/3", "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.v")
	command.Env, command.ExtraFiles = []string{"HOME=" + directory, "TMPDIR=" + directory}, []*os.File{executable}
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	output, err := command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte("--- PASS: "+t.Name()+" ")) {
		t.Fatalf("nonroot review child did not execute and pass its assertions: %v\n%s", err, output)
	}
	return true
}
