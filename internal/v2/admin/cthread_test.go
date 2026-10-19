//go:build linux

package admin

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"laneboss.io/laneboss/internal/v2/api"
)

func init() {
	// Tests need the same leader reservation as the installed main package.
	runtime.LockOSThread()
	if len(os.Args) != 2 || os.Args[1] != "admin-credential-leader-guard" {
		return
	}
	if unix.Gettid() != unix.Getpid() {
		os.Exit(71)
	}
	called := false
	err := runCredentialView(func() error { called = true; return nil })
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodePrerequisite || called {
		os.Exit(72)
	}
	os.Exit(0)
}

// This deliberately invokes the worker on the actual process leader during
// child init. It cannot pass merely by being scheduled on another thread.
func TestCredLeaderGuard(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/proc/self/exe", "admin-credential-leader-guard")
	command.Env = []string{}
	if err := command.Run(); err != nil {
		t.Fatal("acceptance: credential view action ran on the process leader")
	}
}
