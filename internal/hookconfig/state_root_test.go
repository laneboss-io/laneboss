package hookconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/guardtime"
)

func stateRootFixture(t *testing.T, custom bool) (string, string, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	org := filepath.Join(root, "org")
	home := filepath.Join(org, ".laneboss", "instances", "executor", ".codex")
	states := filepath.Join(root, "states")
	state := filepath.Join(states, "fixture")
	if custom {
		state = filepath.Join(root, "custom-store")
	}
	cwd := filepath.Join(root, "worktree")
	configuration := filepath.Join(root, "configuration")
	for _, directory := range []string{home, state, cwd, filepath.Join(root, "user")} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("LANEBOSS_CONFIG", "fixture")
	t.Setenv("LANEBOSS_HOME", configuration)
	t.Setenv("LANEBOSS_STATE_HOME", states)
	t.Setenv("HOME", filepath.Join(root, "user"))
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	text := fmt.Sprintf("schema_version=1\nname=\"fixture\"\norg_dir=%q\n", org)
	if custom {
		text += fmt.Sprintf("[state]\npath=%q\n", state)
	}
	text += "[runners.fixture]\ncommand=[\"true\",\"{brief}\"]\n"
	write(filepath.Join(configuration, "configs", "fixture", "config.toml"), []byte(text))
	write(filepath.Join(org, ".laneboss", "org.toml"), []byte("schema_version=1\nname=\"fixture\"\nlevels=[3]\n"))
	write(filepath.Join(org, ".laneboss", "L3", "roles", "executor.md"),
		[]byte("# Executor\n\n## Scope\nFixture.\n## Responsibilities\nRead.\n## Deliverable\nReport.\n## Must not\nPublish.\n"))
	write(filepath.Join(org, ".laneboss", "L3", "roles", "executor.toml"), []byte("drivers=[\"true\"]\n"))
	instance := filepath.Join(filepath.Dir(home), "instance.toml")
	write(instance, []byte("name=\"executor\"\nlevel=3\nrole=\"executor\"\n"))
	executable := filepath.Join(root, "bin", "laneboss")
	program := []byte("fixture executable bytes\n")
	write(executable, program)
	command := "fixture-org-hook"
	hooks := map[string]any{"hooks": map[string]any{"PreToolUse": []any{map[string]any{
		"matcher": "", "hooks": []any{map[string]any{"type": "command", "command": command, "timeout": guardtime.HookSeconds}},
	}}}}
	data, err := json.Marshal(hooks)
	if err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(home, "hooks.json"), data)
	marker, err := json.Marshal(RenderedHooks{Home: home, Instance: instance, SHA256: hash(data), Command: command,
		Executable: executable, ExecutableSHA256: hash(program)})
	if err != nil {
		t.Fatal(err)
	}
	write(RenderMarkerPath(home), marker)
	return home, cwd, state
}

func writeStateConfig(t *testing.T, home string, roots []string, extra string) {
	t.Helper()
	encoded, err := json.Marshal(roots)
	if err != nil {
		t.Fatal(err)
	}
	text := "[agents]\nenabled=false\n[sandbox_workspace_write]\nexclude_slash_tmp=true\nexclude_tmpdir_env_var=true\n"
	text += "writable_roots=" + string(encoded) + "\n" + extra
	if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestStateRootVetting(t *testing.T) {
	for _, custom := range []bool{false, true} {
		t.Run(fmt.Sprint("custom=", custom), func(t *testing.T) {
			home, cwd, state := stateRootFixture(t, custom)
			writeStateConfig(t, home, []string{state}, "")
			if err := VetCodex(home, cwd); err != nil {
				t.Fatalf("the exact configuration state root must pass full vetting: %v", err)
			}
			// This control proves the allowance did not change general TOML vetting.
			if err := checkConfig(filepath.Join(home, "config.toml")); err == nil {
				t.Fatal("repository and system layers must still refuse the state root")
			}
			// A passing root cannot suppress the rendered hook integrity check.
			if err := os.WriteFile(filepath.Join(home, "hooks.json"), []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := VetCodex(home, cwd); err == nil || !strings.Contains(err.Error(), "differs from its laneboss render") {
				t.Fatal("the state allowance must not skip hook vetting")
			}
		})
	}
}

func TestStateRootRefusals(t *testing.T) {
	home, cwd, state := stateRootFixture(t, false)
	parent := filepath.Dir(state)
	git, other := filepath.Join(filepath.Dir(cwd), ".git"), filepath.Join(parent, "another")
	prefix := filepath.Join(parent, "fixture-extra")
	for _, directory := range []string{git, other, prefix} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(state, alias); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		roots []string
		extra string
	}{
		{"state-and-git", []string{state, git}, ""}, {"git", []string{git}, ""},
		{"other", []string{other}, ""}, {"parent", []string{parent}, ""},
		{"prefix", []string{prefix}, ""}, {"symlink", []string{alias}, ""},
		{"dotdot", []string{state + "/../fixture"}, ""}, {"relative", []string{"fixture"}, ""},
		{"duplicate", []string{state, state}, ""}, {"empty", []string{}, ""},
		{"profile", []string{state}, fmt.Sprintf("[profiles.extra.sandbox_workspace_write]\nwritable_roots=[%q]\n", state)},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			writeStateConfig(t, home, item.roots, item.extra)
			if err := VetCodex(home, cwd); err == nil || !strings.Contains(err.Error(), "writable_roots") {
				t.Fatal("an unvetted root must retain the writable_roots refusal")
			}
		})
	}
}

func TestStateTreeAliases(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "git"} {
		t.Run(kind, func(t *testing.T) {
			home, cwd, state := stateRootFixture(t, false)
			writeStateConfig(t, home, []string{state}, "")
			if err := VetCodex(home, cwd); err != nil {
				t.Fatalf("the clean state tree must pass before its alias is added: %v", err)
			}
			target := filepath.Join(cwd, "git-canary")
			if err := os.WriteFile(target, []byte("keep\n"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(cwd, filepath.Join(state, "alias"))
			case "hardlink":
				err = os.Link(target, filepath.Join(state, "alias"))
			case "git":
				err = os.Mkdir(filepath.Join(state, ".git"), 0700)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := VetCodex(home, cwd); err == nil || !strings.Contains(err.Error(), "writable_roots") {
				t.Fatal("state aliases and Git metadata must refuse before execution")
			}
		})
	}
}
