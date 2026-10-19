//go:build darwin

package lanesandbox

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestClaudeOverlay(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, ".claude")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(home, "settings.json")
	input := []byte(`{"sandbox":{"enabled":true,"allowUnsandboxedCommands":false},"hooks":{"PreToolUse":[]}}`)
	if err := os.WriteFile(source, input, 0600); err != nil {
		t.Fatal(err)
	}
	data := map[string]any{"lanes": map[string]any{"sandbox": Mode}}
	seen := map[string]bool{}
	for _, argv := range [][]string{{"claude", "--settings", source, "-p"}, {"claudock", "run", "fixture", "--", "--settings=" + source, "-p"}} {
		prepared, err := ClaudeOverlay(argv, data)
		if err != nil {
			t.Fatal(err)
		}
		if err := CheckClaudeSettings(prepared); err != nil {
			t.Fatal(err)
		}
		program, args, _, err := runnerInvocation(prepared, nil)
		if err != nil {
			t.Fatal(err)
		}
		path, err := claudeSettingsPath(program, args)
		if err != nil || path == source || seen[path] || claudeDataHome(path) != home {
			t.Fatal("overlay is not isolated in the selected vendor home", err)
		}
		seen[path] = true
		actual, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var want, got map[string]any
		if err := json.Unmarshal(input, &want); err != nil {
			t.Fatal(err)
		}
		want["sandbox"].(map[string]any)["enabled"] = false
		if err := json.Unmarshal(actual, &got); err != nil || !reflect.DeepEqual(want, got) {
			t.Fatal("overlay changed fields other than sandbox.enabled", err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0444 {
			t.Fatal("overlay is not read-only", err)
		}
	}
	actual, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(actual, input) {
		t.Fatal("replacement modified the original org settings", err)
	}
}
