//go:build linux && laneboss_root_canary

package admin

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestWalkMountCrossing(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("native walk canary requires the disposable root Linux test step")
	}
	base := privateTestDir(t)
	for _, name := range []string{"source", "alias"} {
		if err := os.Mkdir(filepath.Join(base, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "source", "record"), []byte("same-device-mount-canary"), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(readAheadContext(t), "/proc/self/exe", "admin-mount-crossing-canary", base)
	command.Env = []string{}
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
	if err := command.Run(); err != nil {
		t.Fatal("acceptance: shared walk crossed a same-device bind mount or lost its native control")
	}
}

func TestRestrictedWalk(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("native walk canary requires the disposable root Linux test step")
	}
	base := privateTestDir(t)
	for _, name := range []string{"nested", "staged"} {
		if err := os.Mkdir(filepath.Join(base, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range map[string]string{"nested/record": "restricted-walk-bytes", "outside": "denied"} {
		if err := os.WriteFile(filepath.Join(base, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.CommandContext(readAheadContext(t), "/proc/self/exe", "admin-walk-restriction-canary", base)
	command.Env = []string{}
	if err := command.Run(); err != nil {
		t.Fatal("acceptance: helper opens or Landlock failed under actual openat2 EPERM")
	}
}

func TestPrivateStageGroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("private stage traversal canary requires disposable Linux root")
	}
	// /run is root-owned and searchable; unlike TempDir, no unrelated private
	// ancestor determines the child's traversal result.
	id, err := randomID("laneboss-stage-canary-")
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join("/run", string(id))
	if err := createLaneStage(base, 61031); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(base)
	file := filepath.Join(base, "record")
	value, err := randomID("private-stage-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(value), 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0444); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file)
	probe := func(allowed uint32) {
		for _, gid := range []uint32{61031, 61032} {
			command := exec.CommandContext(readAheadContext(t), "/usr/bin/cat", file)
			command.Env = []string{}
			command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 61031, Gid: gid, Groups: []uint32{}}}
			output, err := command.Output()
			if gid == allowed && (err != nil || string(output) != string(value)) {
				t.Fatal("acceptance: lane group cannot resolve its own staged bind source")
			}
			if gid != allowed && err == nil {
				t.Fatal("acceptance: foreign group traversed private bind staging")
			}
		}
	}
	probe(61031)
	root, err := os.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := setDataParentGroup(root, 61031, 61032); err != nil {
		t.Fatal(err)
	}
	probe(61032)
	if err := setDataParentGroup(root, 61032, 61031); err != nil {
		t.Fatal(err)
	}
	probe(61031)
}

// A bounded command helper is shared by root-only canaries in this file.
