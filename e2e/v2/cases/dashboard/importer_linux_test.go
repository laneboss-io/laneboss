//go:build linux

package dashboardcase

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Run exactly the five repaired catalog entries. A changed/ambiguous anchor,
// compile error or unrelated assertion cannot count as an executed mutant.
func TestDashboardImporterControls(t *testing.T) {
	root := filepath.Clean("../../../..")
	data, err := os.ReadFile(filepath.Join(root, "e2e/v2/cases/lifecycle/mutations.json"))
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Mutations []struct {
			ID, File, Before, After, Package, Test, Expect string
		} `json:"mutations"`
	}
	if err := json.Unmarshal(data, &catalog); err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{"check-evidence": true, "review-object-provenance": true,
		"revoke-original-cause": true, "archive-independent-readback": true, "attach-native-origin": true}
	for _, row := range catalog.Mutations {
		if !wanted[row.ID] {
			continue
		}
		delete(wanted, row.ID)
		t.Run(row.ID, func(t *testing.T) {
			dashboardGoControl(t, root, row.Package, row.Test, row.File, row.Before, row.After, row.Expect)
		})
	}
	if len(wanted) != 0 {
		t.Fatal("repaired lifecycle mutation disappeared")
	}
	for _, row := range []struct{ name, before, after string }{
		{"plan", "plan.Input != lease.Input", "false"},
		{"lease", "!reflect.DeepEqual(lease, expected)", "false"},
		{"lease-generation", "!reviewjob.CompletedGeneration(request.Lease, lease)", "false"},
	} {
		t.Run("review-"+row.name, func(t *testing.T) {
			dashboardGoControl(t, root, "./internal/v2/dataworker", "TestReviewMeasuredResult/"+row.name,
				"internal/v2/dataworker/review_stubs.go", row.before, row.after, "unmeasured review result escaped: "+row.name)
		})
	}
}

func dashboardGoControl(t *testing.T, root, pkg, test, file, before, after, diagnostic string, tags ...string) []byte {
	t.Helper()
	path, err := filepath.Abs(filepath.Join(root, file))
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil || strings.Count(string(original), before) != 1 {
		t.Fatalf("importer control anchor changed: %v", err)
	}
	mutated := []byte(strings.Replace(string(original), before, after, 1))
	directory := t.TempDir()
	mutant := filepath.Join(directory, "mutant.go")
	if err := os.WriteFile(mutant, mutated, 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"Replace": map[string]string{path: mutant}})
	if err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(directory, "overlay.json")
	if err := os.WriteFile(overlay, raw, 0600); err != nil {
		t.Fatal(err)
	}
	target := "^" + strings.ReplaceAll(test, "/", "$/^") + "$"
	args := []string{"test", "-count=1", "-vet=off"}
	if len(tags) != 0 {
		args = append(args, "-tags", tags[0])
	}
	command := exec.Command("go", append(append([]string{}, args...), "-overlay", overlay, "-run", target, pkg)...)
	command.Dir = root
	red, redErr := command.CombinedOutput()
	if redErr == nil || !strings.Contains(string(red), diagnostic) || strings.Contains(string(red), "build failed") || !strings.Contains(string(red), "--- FAIL: "+strings.Split(test, "/")[0]) {
		t.Fatalf("importer RED missed its intended assertion: %v\n%s", redErr, red)
	}
	command = exec.Command("go", append(append([]string{}, args...), "-run", target, pkg)...)
	command.Dir = root
	green, greenErr := command.CombinedOutput()
	fields := strings.Fields(string(green))
	if greenErr != nil || len(fields) < 2 || fields[0] != "ok" || fields[1] != "laneboss.io/laneboss/"+strings.TrimPrefix(pkg, "./") {
		t.Fatalf("importer GREEN failed: %v\n%s", greenErr, green)
	}
	t.Logf("test=%s source_sha256=%x mutant_sha256=%x red_exit=1 green_exit=0 diagnostic=%s", test, sha256.Sum256(original), sha256.Sum256(mutated), diagnostic)
	t.Logf("red_output=%q green_output=%q", red, green)
	record, err := json.Marshal(map[string]any{"test": test, "file": file, "before": before, "after": after, "diagnostic": diagnostic,
		"source_sha256": sha256.Sum256(original), "mutant_sha256": sha256.Sum256(mutated), "red": string(red), "green": string(green)})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func dashboardRetainControls(t *testing.T, records [][]byte) {
	t.Helper()
	raw := bytes.Join(records, []byte("\n"))
	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("native_controls=%d native_log_bytes=%d native_log_sha256=%x", len(records), len(raw), sha256.Sum256(raw))
	t.Logf("native_log_gzip_base64=%s", base64.StdEncoding.EncodeToString(compressed.Bytes()))
}
