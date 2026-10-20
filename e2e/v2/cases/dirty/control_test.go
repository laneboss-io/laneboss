//go:build linux

package dirtycase

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The box compiles each altered real writer and runs its deciding test. A
// compile error or an unrelated failure cannot count as a killed control.
func TestDirtyControls(t *testing.T) {
	root, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "cmd/laneboss/serve-fixture/dirty.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"bytes", "outside"} {
		t.Run(mode, func(t *testing.T) {
			mutant := string(raw)
			run, want := "^TestDirtyFiles$", "in-lane task did not append its actual nonce"
			if mode == "bytes" {
				mutant = strings.ReplaceAll(mutant, "G11 dirty tracked ", "G11 wrong tracked ")
			} else {
				run, want = "^TestDirtyOutside/parent$", "dirty task accepted a write outside lane"
				start := strings.Index(mutant, "\tif !dirtyPath(input.TrackedPath)")
				if start < 0 {
					t.Fatal("writer path guard moved")
				}
				end := strings.Index(mutant[start:], " {\n")
				if end < 0 {
					t.Fatal("writer path guard moved")
				}
				end += start
				mutant = mutant[:start] + "\tif false" + mutant[end:]
				for _, method := range []string{"Lstat", "Open", "OpenFile"} {
					for _, field := range []string{"TrackedPath", "UntrackedPath"} {
						from := "root." + method + "(input." + field
						to := "os." + method + "(filepath.Join(root.Name(), input." + field + ")"
						mutant = strings.ReplaceAll(mutant, from, to)
					}
				}
				for _, method := range []string{"OpenFile", "Remove"} {
					mutant = strings.ReplaceAll(mutant, "root."+method+"(temporary",
						"os."+method+"(filepath.Join(root.Name(), temporary)")
				}
				mutant = strings.ReplaceAll(mutant, "root.Rename(temporary, name)",
					"os.Rename(filepath.Join(root.Name(), temporary), filepath.Join(root.Name(), name))")
			}
			directory := t.TempDir()
			changed := filepath.Join(directory, "dirty.go")
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
			command := exec.Command("go", "test", "-count=1", "-tags", "laneboss_e2e_authenticator",
				"-overlay", selected, "-run", run, "./cmd/laneboss/serve-fixture")
			command.Dir = root
			output, err := command.CombinedOutput()
			if err == nil || !bytes.Contains(output, []byte(want)) || bytes.Contains(output, []byte("build failed")) {
				t.Fatalf("dirty control did not fail at its deciding assertion: %v\n%s", err, output)
			}
			t.Logf("RED %s: %s", mode, want)
		})
	}
}
