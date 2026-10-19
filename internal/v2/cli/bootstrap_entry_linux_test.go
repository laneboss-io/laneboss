//go:build linux

package cli

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func init() {
	if len(os.Args) > 1 && os.Args[1] == "cli-bootstrap-entry-fixture" {
		os.Exit(RunContext(context.Background(), os.Args[2:], strings.NewReader(""), io.Discard, io.Discard))
	}
}

func TestBootstrapPrelude(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal("bootstrap CLI socket fixture unavailable")
	}
	parent, child := os.NewFile(uintptr(pair[0]), "cli-route-owner"), os.NewFile(uintptr(pair[1]), "cli-route-child")
	defer parent.Close()
	defer child.Close()
	connection, err := net.FileConn(parent)
	if err != nil {
		t.Fatal("bootstrap CLI connection fixture unavailable")
	}
	defer connection.Close()
	discard, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer discard.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "cli-bootstrap-entry-fixture", "--fixed-bootstrap", "prepared-gate", "--config", "entry-fixture")
	cmd.Env, cmd.ExtraFiles = []string{}, []*os.File{discard, discard, child}
	err = cmd.Run()
	var exited *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exited) || cmd.ProcessState.ExitCode() != 100 {
		t.Fatal("acceptance: real CLI did not dispatch the bootstrap before ordinary parsing")
	}
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}
	ready := connection.(*net.UnixConn)
	if err := ready.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 256)
	n, _, flags, _, err := ready.ReadMsgUnix(data, nil)
	if err != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || string(data[:n]) != "bootstrap-failure:input.seals" {
		t.Fatal("acceptance: real CLI bootstrap refused without its early reason packet")
	}
}
