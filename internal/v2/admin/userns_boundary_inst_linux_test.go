//go:build linux && laneboss_gate_integration

package admin

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

func init() {
	if len(os.Args) != 3 || os.Args[1] != "admin-lane-userns-canary" {
		return
	}
	// This process is inside the real unprivileged native bwrap view. Keep
	// its creator task alive through both nested bwrap observations.
	runtime.LockOSThread()
	if os.Geteuid() == 0 || lanePrivateProc() != nil {
		os.Exit(90)
	}
	var fs unix.Statfs_t
	if unix.Statfs("/proc/sys", &fs) != nil || uint64(fs.Flags)&unix.MS_RDONLY == 0 {
		os.Exit(91)
	}
	// Try a real write-open. On an unexpected writable view, write only the
	// exact existing bytes, preserving the tunable while failing the canary.
	path := "/proc/sys/user/max_user_namespaces"
	value, err := os.ReadFile(path)
	if err != nil || len(value) == 0 {
		os.Exit(92)
	}
	fd, openErr := unix.Open(path, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if openErr == nil {
		_, writeErr := unix.Write(fd, value)
		closeErr := unix.Close(fd)
		if writeErr != nil || closeErr != nil {
			os.Exit(92)
		}
		os.Exit(93)
	}
	if !errors.Is(openErr, unix.EROFS) {
		os.Exit(92)
	}
	nested := func() (error, string) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		// This control creates a user namespace without asking for another
		// proc mount or writing a userns sysctl. Its root is read-only.
		command := exec.CommandContext(ctx, "/usr/bin/bwrap", "--die-with-parent", "--unshare-user", "--cap-drop", "ALL",
			"--ro-bind", "/", "/", "--", "/usr/bin/true")
		command.Env = []string{}
		var stderr bytes.Buffer
		command.Stderr = &stderr
		err := command.Run()
		if ctx.Err() != nil {
			return ctx.Err(), "deadline"
		}
		return err, classifyBwrapStderr(stderr.Bytes())
	}
	if err, _ := nested(); err != nil {
		os.Exit(94)
	}
	if unix.Unshare(0) != nil || !errors.Is(unix.Setns(-1, unix.CLONE_NEWUSER), unix.EBADF) {
		os.Exit(95)
	}
	if unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil || bootstrapSeccomp() != nil {
		os.Exit(96)
	}
	if !errors.Is(unix.Unshare(unix.CLONE_NEWUSER), unix.EPERM) ||
		!errors.Is(unix.Unshare(0), unix.EPERM) || !errors.Is(unix.Setns(-1, unix.CLONE_NEWUSER), unix.EPERM) {
		os.Exit(97)
	}
	if err, category := nested(); err == nil || category != "namespace_denied" {
		os.Exit(98)
	}
	if n, err := os.Stdout.WriteString(os.Args[2]); err != nil || n != len(os.Args[2]) {
		os.Exit(99)
	}
	os.Exit(0)
}
