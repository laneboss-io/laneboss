package e2e_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestHarnessSliceFiles checks the restored execution path, not a live ladder.
func TestHarnessSliceFiles(t *testing.T) {
	for _, name := range []string{"installed_ladder.py", "serve_handoff.py", "ladder_ready.py", "cases/ladder/plan.json", "cases/e2e/run.sh", "readsession/main.go", "../../scripts/v2-e2e/run-installed-ladder.sh"} {
		info, err := os.Stat(name)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			t.Fatalf("8A: missing installed ladder execution file %s: %v", name, err)
		}
	}
}

func TestHarnessPython(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Fatal("harness tests require the authorized disposable Linux box")
	}
	files, err := filepath.Glob("tests/test_*.py")
	if err != nil || len(files) == 0 {
		t.Fatal("harness has no discoverable regressions", err)
	}
	for _, file := range files {
		t.Run(strings.TrimSuffix(filepath.Base(file), ".py"), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
			defer cancel()
			out := filepath.Join(t.TempDir(), "unit")
			cmd := exec.CommandContext(ctx, "python3", "unit.py", "--out", out, "--pattern", filepath.Base(file))
			output, err := cmd.CombinedOutput()
			log, logErr := os.ReadFile(filepath.Join(out, "unittest.log"))
			if err != nil || logErr != nil {
				t.Fatalf("harness regression failed: %v (log: %v)\n%s\n%s", err, logErr, output, log)
			}
			t.Logf("%s", output)
		})
	}
}
