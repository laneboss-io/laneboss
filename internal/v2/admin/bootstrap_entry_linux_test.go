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
)

func TestBootstrapEntry(t *testing.T) {
	for _, sample := range []struct {
		name   string
		args   []string
		code   int
		reason string
	}{
		{"arguments", []string{FixedBootstrapEntry}, 81, "entry.arguments"},
		{"mode", []string{FixedBootstrapEntry, "unknown", "--config", "entry-fixture"}, 81, "entry.arguments"},
		{"config", []string{FixedBootstrapEntry, "prepared-gate", "--config", "INVALID"}, 82, "entry.config"},
		{"input", []string{FixedBootstrapEntry, "prepared-gate", "--config", "entry-fixture"}, 100, "input.seals"},
		{"route", []string{FixedBootstrapEntry, "prepared-gate", "--config", "entry-fixture"}, 80, ""},
		{"route-first", []string{FixedBootstrapEntry}, 80, ""},
		{"route-stream", []string{FixedBootstrapEntry, "prepared-gate", "--config", "entry-fixture"}, 80, ""},
	} {
		t.Run(sample.name, func(t *testing.T) {
			kind := unix.SOCK_SEQPACKET
			if sample.name == "route-stream" {
				kind = unix.SOCK_STREAM
			}
			pair, err := unix.Socketpair(unix.AF_UNIX, kind|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal("entry socket fixture unavailable")
			}
			parent, child := os.NewFile(uintptr(pair[0]), "entry-owner"), os.NewFile(uintptr(pair[1]), "entry-child")
			defer parent.Close()
			defer child.Close()
			if err := unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
				t.Fatal("entry credential fixture unavailable")
			}
			connection, err := net.FileConn(parent)
			if err != nil {
				t.Fatal("entry connection fixture unavailable")
			}
			defer connection.Close()
			discard, err := os.Open("/dev/null")
			if err != nil {
				t.Fatal("entry file fixture unavailable")
			}
			defer discard.Close()
			self, err := os.Open("/proc/self/exe")
			if err != nil {
				t.Fatal("entry executable fixture unavailable")
			}
			defer self.Close()
			readyFile := child
			if sample.name == "route" || sample.name == "route-first" {
				readyFile = discard
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/proc/self/fd/6", sample.args...)
			// Match nativeGateArgs so the runtime canary reaches the real entry.
			cmd.Env, cmd.ExtraFiles = []string{"GOMAXPROCS=1"}, []*os.File{discard, discard, readyFile, self}
			uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
			if uid == 0 {
				uid, gid = 61001, 61001
			}
			cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}, NoSetGroups: os.Geteuid() != 0}}
			if err := cmd.Start(); err != nil {
				t.Fatal("entry fixture did not start after UID drop")
			}
			if err := child.Close(); err != nil {
				t.Fatal("entry child duplicate did not close")
			}
			err = cmd.Wait()
			var exited *exec.ExitError
			if ctx.Err() != nil || !errors.As(err, &exited) || cmd.ProcessState.ExitCode() != sample.code {
				t.Fatal("acceptance: actual bootstrap entry lost its distinct failure exit")
			}
			ready := connection.(*net.UnixConn)
			if err := ready.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal("entry fixture deadline unavailable")
			}
			data, controls := make([]byte, 256), make([]byte, unix.CmsgSpace(unix.SizeofUcred))
			n, oobn, flags, _, readErr := ready.ReadMsgUnix(data, controls)
			if sample.reason == "" {
				if readErr == nil {
					t.Fatal("acceptance: unavailable entry route emitted a fabricated report")
				}
				return
			}
			if readErr != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || string(data[:n]) != bootstrapFailurePrefix+sample.reason {
				t.Fatal("acceptance: early bootstrap failure did not traverse the pinned reason route")
			}
			messages, err := unix.ParseSocketControlMessage(controls[:oobn])
			if err != nil || len(messages) != 1 {
				t.Fatal("entry report did not retain its kernel credential")
			}
			cred, err := unix.ParseUnixCredentials(&messages[0])
			if err != nil || cred.Uid != uid || cred.Gid != gid || uid == 0 || int(cred.Pid) != cmd.Process.Pid {
				t.Fatal("acceptance: entry report did not originate after the actual UID drop")
			}
		})
	}
}

func TestBootstrapStageCodes(t *testing.T) {
	seen := map[int]bool{}
	for reason, code := range bootstrapStageCodes {
		if code <= 2 || seen[code] || bootstrapExitStage(code) != reason {
			t.Fatal("acceptance: bootstrap stage exit is absent, ambiguous or disconnected")
		}
		seen[code] = true
	}
	for _, reason := range bootstrapFailureReasons {
		if code, found := bootstrapStageCodes[reason]; !found || code <= 2 {
			t.Fatal("acceptance: bootstrap stage exit is absent, ambiguous or disconnected")
		}
	}
	if bootstrapExitStage(1) != "bwrap_setup" || bootstrapExitStage(2) != "go_runtime_or_init" || bootstrapExitStage(0) != "other" {
		t.Fatal("acceptance: pre-route wait stages were not distinguished")
	}
	if handled, code := RunBootstrapEntry(context.Background(), []string{"internal", "helper"}); handled || code != 0 {
		t.Fatal("acceptance: bootstrap entry intercepted an ordinary helper")
	}
	if !strings.HasPrefix(FixedBootstrapEntry, "--") {
		t.Fatal("bootstrap marker must remain an internal option")
	}
}
