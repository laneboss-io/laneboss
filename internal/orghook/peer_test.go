package orghook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLaneBoundary(t *testing.T) {
	root := t.TempDir()
	worktree := filepath.Join(root, "worktree")
	if err := os.Mkdir(worktree, 0700); err != nil {
		t.Fatal(err)
	}
	inst := &instance{level: 3, worktree: worktree, home: filepath.Join(root, ".laneboss")}
	for _, act := range []action{
		{writes: []string{filepath.Join(root, "outside.txt")}},
		{writes: []string{filepath.Join(inst.home, "shared", "messages.txt")}},
		{commands: []command{{argv: []string{"tmux", "-S", "/tmp/example-lane", "send-keys"}, directory: worktree}}},
		{commands: []command{{argv: []string{"setsid", "laneboss"}, directory: worktree}}},
		{commands: []command{{argv: []string{"curl", "http://127.0.0.1:12345/api/messages"}, directory: worktree}}},
	} {
		reason, err := laneBoundary(act, inst, worktree, worktree)
		if err != nil || reason == "" || !strings.Contains(reason, "Instead: report up with laneboss report") {
			t.Fatal("a lane boundary bypass lacked a refusal and report route")
		}
	}
	if reason, err := laneBoundary(action{writes: []string{"allowed.txt"}}, inst, worktree, worktree); err != nil || reason != "" {
		t.Fatal("an ordinary worktree write was refused")
	}
	if err := os.Symlink(root, filepath.Join(worktree, "alias")); err != nil {
		t.Fatal(err)
	}
	if reason, err := laneBoundary(action{writes: []string{"alias/outside.txt"}}, inst, worktree, worktree); err != nil || reason == "" {
		t.Fatal("a symlink escaped the lane worktree boundary")
	}
	for _, script := range []string{"LANEBOSS_LANE=b1 true", "env LANEBOSS_ROLE=mini-b true", "nohup true"} {
		if _, err := inspectShell(script, worktree, 0); err == nil {
			t.Fatal("a lane identity assignment or detached wrapper was accepted")
		}
	}
}
