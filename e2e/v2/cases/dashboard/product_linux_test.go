//go:build linux

package dashboardcase

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Each Go overlay changes one new product file, then executes the unchanged
// targeted test. Only the intentional mutant may fail; compilation failures
// cannot satisfy a red control. The actual source checkout stays unchanged.
func TestDashboardProductControls(t *testing.T) {
	working, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Clean(filepath.Join(working, "../../../.."))
	var retained bytes.Buffer
	controls := []struct{ pkg, test, file, before, after, diagnostic string }{
		{"service", "Open", "service/dashboard_entry.go", "ConnectionID: connection.ID()", "ConnectionID: api.ID(\"\")", "native entry lost its actual connection identity"},
		{"service", "Bootstrap", "service/dashboard_entry.go", "input.Session.Method != \"human.session\"", "input.Session.Method != \"identity.self\"", "dashboard bootstrap requires the exact redemption session intent"},
		{"service", "ExactFrame", "service/dashboard_entry.go", "!reflect.DeepEqual(retained, input)", "reflect.DeepEqual(retained, input) && false", "entry accepted bytes other than its native frame"},
		{"service", "Socket", "service/dashboard_entry.go", "os.SameFile(original, current)", "!os.SameFile(original, current)", "dashboard entry retained an owned socket"},
		{"service", "Open", "service/dashboard_entry.go", "scope.EndpointGeneration != connection.Binding().EndpointGeneration", "false", "entry accepted a changed endpoint generation"},
		{"service", "Refusal", "service/dashboard_entry.go", "ctx = context.WithValue(ctx, authenticationReplyKey{}, closeWindow)", "ctx = context.WithValue(ctx, struct{}{}, closeWindow)", "native refusal was lost before its reply"},
		{"cli", "Proxy", "cli/dashboard_entry.go", "\"installed-dashboard\", r.In.Host", "\"installed-dashboard\", \"\"", "HTTPS proxy changed the actual SSE response"},
		{"cli", "Write", "cli/dashboard_entry.go", "return os.Rename(path+\".pending\", path)", "return nil", "dashboard output changed exact bytes"},
		{"cli", "Input", "cli/dashboard_entry.go", "target.Scheme != \"https\"", "target.Scheme != \"http\"", "dashboard accepted an unpinned HTTPS origin"},
		{"assembly", "FakeScore", "assembly/dashboard_judge.go", "binary.BigEndian.Uint16(digest[:2])", "binary.LittleEndian.Uint16(digest[:2])", "fake score ignored complete request or question"},
		{"assembly", "FakeScope", "assembly/dashboard_judge.go", "original.Target != request.Context.Target", "false", "fake source accepted a foreign policy target"},
		{"assembly", "FakeEnrollment", "assembly/dashboard_judge.go", "!spec.Fake", "false", "unmarked source became an enrolled fake judge"},
		{"assembly", "FakePins", "assembly/dashboard_judge.go", "request.Config.TokenizerSHA256 != j.pin || request.Config.DeploymentSHA256 != j.pin", "false", "fake source accepted another tokenizer deployment pin"},
		{"assembly", "FakeBinding", "assembly/dashboard_judge.go", "wire.Digest(body) != object.Content.SHA256", "false", "fake source accepted bytes outside its runtime pin"},
		{"service", "ReviewPlan", "service/dashboard_review.go", "if _, err := api.WithReadAuthority(ctx, caller); err != nil", "if _, err := api.WithReadAuthority(ctx, caller); false", "native preparation accepted no human read authority"},
		{"service", "ReviewDiff", "service/dashboard_review.go", "a.Mode == b.Mode", "a.Mode != b.Mode", "review diff mistook object identity for changed content"},
		{"service", "ReviewEmpty", "service/dashboard_review.go", "ref.SHA256 != chunk.SHA256", "false", "empty frozen content accepted a different digest"},
		{"service", "ToolCoverage", "service/dashboard_review.go", "!started[id] || finished[id]", "false", "unpaired provider tool result became complete coverage"},
		{"../../e2e/v2/cases/dashboard/actor", "Provider", "../../e2e/v2/cases/dashboard/actor/events.go", "result.Exit != 0", "result.Exit == 0", "provider tool capture lost actual result or relay correlation"},
		{"../../e2e/v2/cases/dashboard/actor", "Check", "../../e2e/v2/cases/dashboard/actor/check.go", "hash(raw) != expected", "false", "fixture check accepted changed candidate bytes"},
		{"../../e2e/v2/cases/dashboard/actor", "CheckPlan", "../../e2e/v2/cases/dashboard/actor/check.go", "Input: candidate", "Input: api.BlobRef{}", "fixture check plan lost candidate, executable, grants or expected bytes"},
	}
	for index, control := range controls {
		t.Run(control.test, func(t *testing.T) {
			path := filepath.Join(root, "internal/v2", control.file)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(before), control.before) != 1 {
				t.Fatal("product red anchor is absent or ambiguous")
			}
			after := []byte(strings.Replace(string(before), control.before, control.after, 1))
			directory := t.TempDir()
			mutant := filepath.Join(directory, "mutant.go")
			if err := os.WriteFile(mutant, after, 0600); err != nil {
				t.Fatal(err)
			}
			overlay := filepath.Join(directory, "overlay.json")
			raw, err := json.Marshal(map[string]any{"Replace": map[string]string{path: mutant}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(overlay, raw, 0600); err != nil {
				t.Fatal(err)
			}
			target := "^TestDashboardEntry" + control.test + "$"
			packagePath := "./" + filepath.ToSlash(filepath.Clean(filepath.Join("internal/v2", control.pkg)))
			command := exec.Command("go", "test", "-count=1", "-vet=off", "-overlay", overlay, "-run", target, packagePath)
			command.Dir = root
			red, redErr := command.CombinedOutput()
			if redErr == nil || !strings.Contains(string(red), control.diagnostic) || strings.Contains(string(red), "build failed") || !strings.Contains(string(red), "--- FAIL: TestDashboardEntry"+control.test) {
				t.Fatalf("red missed its intended assertion: %v\n%s", redErr, red)
			}
			command = exec.Command("go", "test", "-count=1", "-vet=off", "-run", target, packagePath)
			command.Dir = root
			green, greenErr := command.CombinedOutput()
			fields := strings.Fields(string(green))
			if greenErr != nil || len(fields) < 2 || fields[0] != "ok" || fields[1] != "laneboss.io/laneboss/"+strings.TrimPrefix(packagePath, "./") {
				t.Fatalf("candidate failed after red: %v\n%s", greenErr, green)
			}
			t.Logf("control=%d test=%s red_exit=1 green_exit=0 source_sha256=%x mutant_sha256=%x mutation=%s -> %s diagnostic=%s", index+1, target, sha256.Sum256(before), sha256.Sum256(after), control.before, control.after, control.diagnostic)
			t.Log(fmt.Sprintf("red_output=%q green_output=%q", red, green))
			row, err := json.Marshal(map[string]any{"test": target, "file": control.file, "before": control.before,
				"after": control.after, "diagnostic": control.diagnostic, "source_sha256": fmt.Sprintf("%x", sha256.Sum256(before)),
				"mutant_sha256": fmt.Sprintf("%x", sha256.Sum256(after)), "red": string(red), "green": string(green)})
			if err != nil {
				t.Fatal(err)
			}
			retained.Write(row)
			retained.WriteByte('\n')
		})
	}
	if t.Failed() {
		return
	}
	directory := filepath.Join(t.TempDir(), "python-controls")
	command := exec.Command("python3", "-B", filepath.Join(root, "e2e/v2/cases/dashboard/focus.py"),
		"--source", root, "--evidence", directory)
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "PASS: dashboard focused controls") {
		t.Fatalf("Python RED/GREEN controls failed: %v\n%s", err, output)
	}
	var summary json.RawMessage
	var candidate string
	for _, line := range strings.Split(string(output), "\n") {
		var value struct {
			Summary  json.RawMessage `json:"summary"`
			Mutation struct {
				Test string `json:"test"`
			} `json:"mutation"`
			Control struct {
				Argv   []string `json:"argv"`
				Stderr string   `json:"stderr"`
			} `json:"control_output"`
		}
		if json.Unmarshal([]byte(line), &value) != nil {
			continue
		}
		if strings.HasPrefix(value.Mutation.Test, "test_test_child.") ||
			len(value.Control.Argv) > 0 && strings.HasPrefix(value.Control.Argv[len(value.Control.Argv)-1], "test_test_child.") {
			retained.WriteString(line)
			retained.WriteByte('\n')
		}
		if len(value.Summary) != 0 {
			summary = value.Summary
		}
		if len(value.Control.Argv) > 4 && value.Control.Argv[4] == "discover" {
			candidate = value.Control.Stderr
		}
	}
	var verdict struct {
		Controls int `json:"controls"`
		UnitExit int `json:"unit_exit"`
		Results  []struct {
			Red   int `json:"red_exit"`
			Green int `json:"green_exit"`
		} `json:"results"`
	}
	if json.Unmarshal(summary, &verdict) != nil || verdict.Controls < 1 || verdict.Controls != len(verdict.Results) || verdict.UnitExit != 0 || !strings.Contains(candidate, "\nOK\n") {
		t.Fatalf("Python control summary is incomplete: %s", output)
	}
	for _, result := range verdict.Results {
		if result.Red != 1 || result.Green != 0 {
			t.Fatal("Python summary credits a control without RED before GREEN")
		}
	}
	t.Logf("Python summary=%s", summary)
	t.Logf("Python candidate=%q stdout_sha256=%x", candidate, sha256.Sum256(output))
	summaryRow, err := json.Marshal(map[string]any{"summary": summary, "candidate": candidate})
	if err != nil {
		t.Fatal(err)
	}
	retained.Write(summaryRow)
	retained.WriteByte('\n')
	// Keep all Go controls and the newly added Python controls losslessly in
	// the bounded queue result. The full Python summary and output digest above
	// additionally cover the unchanged Python controls and candidate unit run.
	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(retained.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("control_log_bytes=%d control_log_sha256=%x", retained.Len(), sha256.Sum256(retained.Bytes()))
	t.Logf("control_log_gzip_base64=%s", base64.StdEncoding.EncodeToString(compressed.Bytes()))
}
