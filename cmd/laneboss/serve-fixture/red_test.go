//go:build linux && laneboss_root_canary && laneboss_e2e_authenticator

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Restore each old silent/ambiguous behavior only in the disposable box's
// compiler overlay. Each control must compile, reach the same namespace test,
// and fail its deciding assertion; setup/compile failures do not qualify.
func TestDirtySeqRed(t *testing.T) {
	for _, row := range []struct{ name, file, before, after, assertion, detail string }{
		{"envelope", "dirty.go", `launch.Schema == "laneboss.launch-prompt.v2"`, `launch.Schema == "laneboss.launch-prompt.v2" && false`,
			"fixture did not retain its own reached result", "dirty-result.json"},
		{"earlier-heading", "dirty.go", "bytes.LastIndex(prompt, marker)", "bytes.Index(prompt, marker)", "in-lane earlier-heading sequence failed", "dirty.prompt:"},
		{"bad-task", "dirty.go", "return fmt.Errorf(\"dirty.prompt: assigned task is not valid JSON: %w\", err)", "return nil", "in-lane bad-task sequence failed: <nil>", "FAIL"},
		{"readonly", "dirty.go", "dirty.create_tracked: %w", "creation failed: %w", "in-lane readonly sequence failed", "creation failed:"},
		{"foreign-owned", "dirty.go", "tracked, err := root.Open(input.TrackedPath)",
			"if err := root.Chmod(input.TrackedPath, info.Mode().Perm()|0200); err != nil { return err }; tracked, err := root.Open(input.TrackedPath)",
			"in-lane foreign-owned sequence failed", "chmodat README.md: operation not permitted"},
		{"plain", "dirty.go", `if f.Driver != "claudock-cli" {`, "if false {",
			"plain lifecycle touched dirty-only files", "dirty-result.json"},
		{"ordinary", "dirty.go", "if parseErr == nil && input.Schema != \"laneboss.dirty-task.v1\" ||\n\t\tparseErr != nil && !bytes.Contains(task, []byte(\"laneboss.dirty-task\")) {", "if false {",
			"plain lifecycle touched dirty-only files", "dirty-status.request.json"},
		{"restore", "main.go", "wait := time.NewTimer(time.Duration(f.WaitMS) * time.Millisecond)", "wait := time.NewTimer(0)",
			"restore host ended before its explicit stop", "fixture stop deadline expired"},
	} {
		t.Run(row.name, func(t *testing.T) {
			path, err := filepath.Abs(row.file)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(raw), row.before) != 1 {
				t.Fatal("dirty sequence control no longer selects one source site")
			}
			directory := t.TempDir()
			changed := filepath.Join(directory, row.file)
			mutant := strings.Replace(string(raw), row.before, row.after, 1)
			if err := os.WriteFile(changed, []byte(mutant), 0600); err != nil {
				t.Fatal(err)
			}
			overlay, err := json.Marshal(map[string]any{"Replace": map[string]string{path: changed}})
			if err != nil {
				t.Fatal(err)
			}
			selected := filepath.Join(directory, "overlay.json")
			if err := os.WriteFile(selected, overlay, 0600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("go", "test", "-count=1", "-tags",
				"laneboss_e2e_authenticator,laneboss_root_canary", "-overlay", selected,
				"-run", "^TestDirtyLane/"+row.name+"$", ".")
			output, err := command.CombinedOutput()
			if err == nil || !bytes.Contains(output, []byte(row.assertion)) || !bytes.Contains(output, []byte(row.detail)) ||
				bytes.Contains(output, []byte("build failed")) || bytes.Contains(output, []byte("bwrap:")) {
				t.Fatalf("sequence control missed its deciding assertion: %v\n%s", err, output)
			}
			t.Logf("RED %s: %s", row.name, row.assertion)
		})
	}
}
