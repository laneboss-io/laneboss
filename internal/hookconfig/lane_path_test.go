package hookconfig

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestLanePath(t *testing.T) {
	home, cwd, state := stateRootFixture(t, false)
	writeStateConfig(t, home, []string{state}, "")
	root := filepath.Dir(cwd)
	bin := filepath.Join(root, "bin")
	child := filepath.Join(cwd, "bin")
	prefix := cwd + "-other"
	for _, path := range []string{child, prefix} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(root, "path-alias")
	if err := os.Symlink(child, alias); err != nil {
		t.Fatal(err)
	}
	safe := "/usr/bin:/bin:" + bin
	environment := []string{"HOME=" + os.Getenv("HOME"), "LANEBOSS_HOME=" + os.Getenv("LANEBOSS_HOME"),
		"LANEBOSS_STATE_HOME=" + os.Getenv("LANEBOSS_STATE_HOME"), "LANEBOSS_CONFIG=fixture",
		"CODEX_HOME=" + home, "PATH=" + safe}
	invocation := []string{"codex", "exec", CodexTrustBypass, "--disable", "plugins", "-"}
	if err := Revet(invocation, cwd, environment); err != nil {
		t.Fatalf("an ordinary effective PATH must pass full execution vetting: %v", err)
	}
	for _, item := range []struct{ name, entry string }{
		{"worktree", cwd}, {"worktree-child", child}, {"state", state},
		{"symlink", alias}, {"cleaned", cwd + "/../worktree/bin"},
		{"empty", ""}, {"relative", "."},
	} {
		t.Run(item.name, func(t *testing.T) {
			// An argv env prefix must override the safe inherited PATH.
			argv := append([]string{"env", "PATH=" + item.entry + ":" + safe}, invocation...)
			err := Revet(argv, cwd, environment)
			want := "the Codex lane's PATH contains a directory the lane can write: " + strconv.Quote(item.entry)
			if err == nil || !strings.HasPrefix(err.Error(), want+"\nInstead:") {
				t.Fatal("the effective lane-writable PATH must refuse at the PATH gate")
			}
		})
	}
	// The inverse control catches consulting the supervisor's PATH instead of
	// the effective prefix, and a shared spelling prefix is not containment.
	environment[len(environment)-1] = "PATH=" + cwd
	argv := append([]string{"env", "PATH=" + safe + ":" + prefix}, invocation...)
	if err := Revet(argv, cwd, environment); err != nil {
		t.Fatalf("a safe effective PATH must replace unsafe inheritance: %v", err)
	}
}
