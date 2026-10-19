//go:build darwin

package lanesandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests exercise macOS profile generation only; they never launch a
// runner, change this process's sandbox or execute a development command.
func TestDarwinProfileScope(t *testing.T) {
	root := t.TempDir()
	protected := []string{filepath.Join(root, "org", "settings.json"), filepath.Join(root, "state"), filepath.Join(root, "service", "socket")}
	profile, err := DarwinProfile(protected)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(profile, "(version 1)\n(allow default)\n") {
		t.Fatal("profile must permit ordinary operations by default")
	}
	paths, err := normalizePaths(protected)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(profile, "\n"), "\n")
	if len(lines) != len(paths)+2 {
		t.Fatal("profile added or omitted rules")
	}
	for i, path := range paths {
		want := "(deny file-write* (literal \"" + path + "\") (subpath \"" + path + "\"))"
		if lines[i+2] != want {
			t.Fatal("a write denial is missing or reaches outside its exact protected path")
		}
	}
}

func TestDarwinProfileConfiguration(t *testing.T) {
	root := t.TempDir()
	org := filepath.Join(root, "org")
	for _, instance := range []string{"executor", "reviewer"} {
		if err := os.MkdirAll(filepath.Join(org, ".laneboss", "instances", instance), 0700); err != nil {
			t.Fatal(err)
		}
	}
	c := Configuration{Home: filepath.Join(root, "config-home"), StateHome: filepath.Join(root, "state-home"), Directory: filepath.Join(root, "configuration"), StateDir: filepath.Join(root, "launcher-state"), Executable: filepath.Join(root, "bin", "laneboss"), ServiceSocketDir: filepath.Join(root, "service-socket"), Data: map[string]any{"org_dir": org}}
	for _, directory := range []string{c.Home, c.StateHome} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := ProtectedPaths(c)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := DarwinProfile(paths)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"config-home", "state-home", "configuration", "launcher-state", "bin/laneboss", "service-socket", "org/.laneboss", "org/.laneboss/instances", "org/.laneboss/org.toml", "org/.laneboss/shared/hooks", "org/.laneboss/shared/refusals"}
	for _, level := range []string{"L3", "L4", "L5", "L6"} {
		want = append(want, "org/.laneboss/"+level, "org/.laneboss/"+level+"/hooks", "org/.laneboss/"+level+"/refusals")
	}
	for _, instance := range []string{"executor", "reviewer"} {
		want = append(want, "org/.laneboss/instances/"+instance)
		for _, part := range []string{"instance.toml", ".claude", ".codex", ".claude/settings.json", ".codex/hooks.json", ".codex/config.toml", "hooks", "refusals"} {
			want = append(want, "org/.laneboss/instances/"+instance+"/"+part)
		}
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]bool{}
	for _, suffix := range want {
		for _, base := range []string{root, canonicalRoot} {
			path := filepath.Join(base, suffix)
			expected[path] = true
			if !strings.Contains(profile, "(literal \""+path+"\")") {
				t.Fatalf("configured profile omitted protected input %s", suffix)
			}
		}
	}
	if len(paths) != len(expected) || strings.Count(profile, "(deny file-write*") != len(expected) {
		t.Fatal("configured profile added paths outside the Laneboss set")
	}
	for _, path := range paths {
		if !expected[path] {
			t.Fatal("configured profile protects an unrelated location")
		}
	}
}

func TestDarwinProfileEscaping(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "quote\" backslash\\ parentheses() 雪")
	profile, err := DarwinProfile([]string{path, path})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(profile, `quote\" backslash\\ parentheses() 雪`) {
		t.Fatal("path characters were not preserved as a single quoted literal")
	}
	paths, err := normalizePaths([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(profile, "(deny file-write*") != len(paths) {
		t.Fatal("duplicate inputs produced duplicate rules")
	}
}

func TestDarwinProfileInvalidPaths(t *testing.T) {
	for _, paths := range [][]string{nil, {""}, {"relative/settings"}, {"/"}, {"/tmp/../"}, {"/tmp/settings\n(deny default)"}, {"/tmp/\xff"}} {
		if _, err := DarwinProfile(paths); err == nil {
			t.Fatalf("invalid input generated a profile: %q", paths)
		}
	}
}

func TestDarwinProfileAliases(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "org")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(alias, "future", "hooks.json")
	profile, err := DarwinProfile([]string{leaf})
	if err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{leaf, filepath.Join(real, "future", "hooks.json")} {
		if !strings.Contains(profile, "(literal \""+path+"\")") {
			t.Fatal("profile omitted a lexical or resolved location")
		}
	}
	for _, ancestor := range []string{root, alias, target, real, filepath.Join(real, "future")} {
		if strings.Contains(profile, "(subpath \""+ancestor+"\")") {
			t.Fatal("a missing protected leaf widened protection to its ancestor")
		}
	}
	dangling := filepath.Join(root, "dangling")
	if err := os.Symlink(filepath.Join(root, "absent"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := DarwinProfile([]string{dangling}); err == nil {
		t.Fatal("dangling protected links cannot silently protect their wrong lexical target")
	}
}
