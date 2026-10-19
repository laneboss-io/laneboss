//go:build linux

package linux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const appArmorProfilePath = "/etc/apparmor.d/laneboss-bwrap"
const appArmorSysctlPath = "/proc/sys/kernel/" +
	"apparmor_restrict_unprivileged_userns"
const unsharePath = "/usr/bin/unshare"
const truePath = "/usr/bin/true"

const appArmorProfile = "abi <abi/4.0>,\ninclude <tunables/global>\n\n" +
	"profile laneboss-bwrap /usr/bin/bwrap " +
	"flags=(unconfined) {\n  userns,\n}\n"

type namespaceCommandResult struct {
	exitCode int
	stderr   string // Bounded head, captured before interpreting any diagnostic.
	err      error
}

const namespaceStderrLimit = 8192

// os/exec writes this from one copy goroutine; Run waits for that copy before
// its caller reads data. Drain all bytes while retaining the original head.
type namespaceStderrHead struct{ data []byte }

func (head *namespaceStderrHead) Write(data []byte) (int, error) {
	keep := min(namespaceStderrLimit-len(head.data), len(data))
	head.data = append(head.data, data[:keep]...)
	return len(data), nil
}

// Only fixed availability commands reach this executor. It neither changes
// credentials nor invokes a runner, sudo, a shell or an administrator entry.
func runNamespaceCommand(ctx context.Context, path string, args []string) namespaceCommandResult {
	result := namespaceCommandResult{exitCode: -1}
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		result.err = errors.New("namespace availability must be observed by the non-root caller")
		return result
	}
	command := exec.CommandContext(ctx, path, args...)
	command.Env, command.Dir = []string{"LC_ALL=C"}, "/"
	command.WaitDelay = time.Second
	head := &namespaceStderrHead{}
	command.Stderr = head
	result.err = command.Run()
	if result.err == nil {
		result.exitCode = 0
	} else {
		var exited *exec.ExitError
		if errors.As(result.err, &exited) {
			result.exitCode = exited.ExitCode()
		}
	}
	result.err = errors.Join(result.err, ctx.Err())
	result.stderr = string(head.data)
	return result
}

// Keep executable privilege workarounds from satisfying the behavioral check.
func appArmorSystemPath(path string) (string, error) {
	resolved, err := safeSystemPath(path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return "", errors.New("ordinary non-setuid/non-setgid namespace input required")
	}
	if path != appArmorProfilePath {
		if info.Mode().Perm()&0111 == 0 {
			return "", errors.New("namespace probe executable is not executable")
		}
		_, err := unix.Getxattr(resolved, "security.capability", nil)
		if err == nil {
			return "", errors.New("file-capability namespace executable refused")
		}
		if !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
			return "", fmt.Errorf("inspect namespace executable capabilities: %w", err)
		}
	}
	return resolved, nil
}

// Dependencies are local test seams, never caller-supplied launch authority.
// Production always binds protected system inputs and actual child results.
type appArmorProbe struct {
	resolve  func(string) (string, error)
	readFile func(string) ([]byte, error)
	command  func(context.Context, string, []string) namespaceCommandResult
}

func checkAppArmorProfile(ctx context.Context) error {
	probe := appArmorProbe{resolve: appArmorSystemPath, readFile: os.ReadFile, command: runNamespaceCommand}
	return probe.check(ctx)
}

func (probe appArmorProbe) check(ctx context.Context) error {
	if probe.resolve == nil || probe.readFile == nil || probe.command == nil {
		return errors.New("AppArmor behavioral evidence source is missing")
	}
	for _, path := range []string{appArmorProfilePath, bwrapPath, unsharePath, truePath} {
		resolved, err := probe.resolve(path)
		if err != nil {
			return fmt.Errorf("AppArmor probe input ownership: %w", err)
		}
		if resolved != path {
			return errors.New("AppArmor probe inputs must not be symlinks")
		}
	}
	data, err := probe.readFile(appArmorProfilePath)
	if err != nil {
		return fmt.Errorf("read bwrap-only AppArmor profile: %w", err)
	}
	if !bytes.Equal(data, []byte(appArmorProfile)) {
		return errors.New("bwrap-only AppArmor profile differs from the installed policy")
	}
	before, err := probe.readFile(appArmorSysctlPath)
	if err != nil {
		return fmt.Errorf("read AppArmor restriction before probe: %w", err)
	}
	if strings.TrimSpace(string(before)) != "1" {
		return errors.New("AppArmor behavioral check requires actual restriction 1")
	}
	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	control := []string{"--user", "--map-root-user", "--mount", "--", truePath}
	availability := []string{"--die-with-parent", "--unshare-user", "--unshare-pid",
		"--unshare-net", "--ro-bind", "/", "/", "--", truePath}
	for index, step := range []struct {
		path string
		args []string
	}{{unsharePath, control}, {bwrapPath, availability}, {unsharePath, control}} {
		if err := probeCtx.Err(); err != nil {
			return err
		}
		observed := probe.command(probeCtx, step.path, step.args)
		if index == 1 {
			var failed []string
			if observed.exitCode != 0 {
				failed = append(failed, "expected exit 0")
			}
			if observed.err != nil {
				failed = append(failed, "command error present")
			}
			failed = append(failed, namespaceContextFailures(observed.err)...)
			if len(failed) != 0 {
				return namespaceBehaviorError("profiled bwrap namespace probe failed", failed, observed)
			}
			continue
		}
		if failed := namespaceControlFailures(observed); len(failed) != 0 {
			phase := "before bwrap"
			if index == 2 {
				phase = "after bwrap"
			}
			return namespaceBehaviorError("unprofiled mount namespace control "+phase+" must remain denied", failed, observed)
		}
	}
	if err := probeCtx.Err(); err != nil {
		return err
	}
	after, err := probe.readFile(appArmorSysctlPath)
	if err != nil {
		return fmt.Errorf("read AppArmor restriction after probe: %w", err)
	}
	if !bytes.Equal(before, after) {
		return errors.New("AppArmor restriction changed during namespace probes")
	}
	return nil
}

// unshare can fail at the namespace syscall or while configuring its user
// namespace. Recognize the operation and the permission errno together; an
// unrelated exit 1 or a permission error on another file is not a control.
func namespacePermissionDenied(stderr string) bool {
	for _, line := range strings.Split(strings.ToLower(stderr), "\n") {
		message, ok := strings.CutPrefix(strings.TrimSpace(line), "unshare: ")
		if !ok {
			continue
		}
		operation, cause, ok := strings.Cut(message, ": ")
		if !ok || cause != "operation not permitted" && cause != "permission denied" {
			continue
		}
		if operation == "unshare failed" {
			return true
		}
		target, writing := strings.CutPrefix(operation, "write failed ")
		if writing {
			switch target {
			case "/proc/self/uid_map", "/proc/self/gid_map", "/proc/self/setgroups":
				return true
			}
		}
	}
	return false
}

func namespaceControlFailures(observed namespaceCommandResult) []string {
	var failed []string
	if observed.exitCode != 1 {
		failed = append(failed, "expected exit 1")
	}
	if observed.err == nil {
		failed = append(failed, "exit error missing")
	}
	if !namespacePermissionDenied(observed.stderr) {
		failed = append(failed, "namespace permission diagnostic missing")
	}
	return append(failed, namespaceContextFailures(observed.err)...)
}

func namespaceContextFailures(err error) []string {
	var failed []string
	if errors.Is(err, context.Canceled) {
		failed = append(failed, "command canceled")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		failed = append(failed, "command timed out")
	}
	return failed
}

func namespaceBehaviorError(reason string, failed []string, observed namespaceCommandResult) error {
	// Keep observations before the wrapped cause, whose formatting can span
	// multiple lines. A first-line log must still explain the failed decision.
	return fmt.Errorf("%s (exit %d; failed conditions: %s; stderr head: %q): %w", reason, observed.exitCode,
		strings.Join(failed, ", "), observed.stderr,
		errors.Join(errors.New("required namespace behavior was not observed"), observed.err))
}
