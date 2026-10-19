//go:build linux

package admin

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

type bootstrapFileLimitObservation struct {
	Soft        uint64
	Hard        uint64
	RaiseDenied bool
}

func init() {
	if len(os.Args) != 2 || os.Args[1] != "admin-bootstrap-file-limit" {
		return
	}
	if os.Geteuid() == 0 || confineBootstrap(gatePayload{}) != nil {
		os.Exit(61)
	}
	var limit unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_NOFILE, &limit) != nil {
		os.Exit(62)
	}
	raised := unix.Rlimit{Cur: limit.Max + 1, Max: limit.Max + 1}
	err := unix.Setrlimit(unix.RLIMIT_NOFILE, &raised)
	observation := bootstrapFileLimitObservation{Soft: limit.Cur, Hard: limit.Max, RaiseDenied: errors.Is(err, unix.EPERM)}
	if json.NewEncoder(os.Stdout).Encode(observation) != nil {
		os.Exit(63)
	}
	os.Exit(0)
}

func TestBootstrapDescriptorLimit(t *testing.T) {
	executable, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer executable.Close()
	command := exec.CommandContext(readAheadContext(t), "/proc/self/fd/3", "admin-bootstrap-file-limit")
	command.Env, command.ExtraFiles = []string{}, []*os.File{executable}
	if os.Geteuid() == 0 {
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	}
	data, err := command.Output()
	var measured bootstrapFileLimitObservation
	if err != nil || json.Unmarshal(data, &measured) != nil {
		t.Fatal("native bootstrap did not report its actual descriptor limits", err)
	}
	if measured.Soft == 0 || measured.Soft > 1024 || measured.Hard == 0 || measured.Hard > 1024 || !measured.RaiseDenied {
		t.Fatalf("bootstrap descriptor inventory was not bounded: soft=%d hard=%d raise_denied=%v", measured.Soft, measured.Hard, measured.RaiseDenied)
	}
}
