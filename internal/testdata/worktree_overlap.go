package testdata

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// WorktreeOverlapContract exercises the recorded-lane gate used by both start
// and adopt against real directories, symlinks and a linked Git worktree.
func WorktreeOverlapContract(t *testing.T, check func(string, string, []map[string]any) error) {
	t.Helper()
	root := t.TempDir()
	plain := filepath.Join(root, "plain")
	child := filepath.Join(plain, "child")
	sibling := filepath.Join(root, "plain-extra")
	repository := filepath.Join(root, "repository")
	linked := filepath.Join(root, "linked")
	for _, path := range []string{child, sibling, repository} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repository}, args...)...)
		for _, value := range os.Environ() {
			key, _, _ := strings.Cut(value, "=")
			if !strings.HasPrefix(key, "GIT_") {
				cmd.Env = append(cmd.Env, value)
			}
		}
		cmd.Env = append(cmd.Env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Git fixture %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	git("-c", "user.name=fixture", "-c", "user.email=fixture", "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "bootstrap")
	git("worktree", "add", "-q", "-b", "linked", linked, "HEAD")
	gitChild := filepath.Join(linked, "child")
	if err := os.Mkdir(gitChild, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(plain, alias); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, candidate, recorded, state string
		cleaned, sameLane, refused       bool
	}{
		{name: "plain-equal", candidate: plain, recorded: plain, refused: true},
		{name: "plain-descendant", candidate: child, recorded: plain, refused: true},
		{name: "plain-ancestor", candidate: plain, recorded: child, refused: true},
		{name: "git-descendant", candidate: gitChild, recorded: linked, refused: true},
		{name: "git-ancestor", candidate: root, recorded: linked, refused: true},
		{name: "symlink-descendant", candidate: filepath.Join(alias, "child"), recorded: plain, refused: true},
		{name: "symlink-ancestor", candidate: alias, recorded: child, refused: true},
		{name: "recorded-symlink", candidate: child, recorded: alias, refused: true},
		{name: "unrelated-prefix", candidate: sibling, recorded: plain},
		{name: "unrelated-prefix-reversed", candidate: plain, recorded: sibling},
		{name: "cleaned-equal", candidate: plain, recorded: plain, cleaned: true},
		{name: "cleaned-descendant", candidate: child, recorded: plain, cleaned: true},
		{name: "cleaned-ancestor", candidate: plain, recorded: child, cleaned: true},
		{name: "abandoned-uncleaned", candidate: child, recorded: plain, state: "abandoned", refused: true},
		{name: "merged-uncleaned", candidate: plain, recorded: child, state: "merged", refused: true},
		{name: "same-lane", candidate: child, recorded: plain, sameLane: true},
		{name: "no-recorded-worktree", candidate: plain},
		{name: "filesystem-root", candidate: string(filepath.Separator), recorded: plain, refused: true},
		{name: "new-worktree-under-symlink", candidate: filepath.Join(alias, "new"), recorded: plain, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owner := "owner"
			if tc.sameLane {
				owner = "candidate"
			}
			rows := []map[string]any{{"lane": "unassigned"}, {"lane": owner, "worktree": tc.recorded, "cleaned": tc.cleaned, "state": tc.state}}
			err := check("candidate", tc.candidate, rows)
			if !tc.refused {
				if err != nil {
					t.Fatalf("a separate, cleaned or same-lane directory was refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("an uncleaned lane's overlapping directory was allowed")
			}
			if !strings.Contains(err.Error(), "lane owner's worktree") || !strings.Contains(err.Error(), "\nInstead: pick a separate directory, or clean lane owner first") {
				t.Fatalf("the refusal must identify the owner and its recovery route: %v", err)
			}
		})
	}
}
