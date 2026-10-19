package approval_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// This drives the actual frozen entry through a missing-fixture failure. It
// verifies discovery, artifact correlation and atomic unreached results only;
// it does not substitute a product response or claim installed acceptance.
func TestHarnessEntry(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Fatal("approval harness execution requires the authorized Linux test box")
	}
	descriptorBytes, err := os.ReadFile("case.json")
	if err != nil {
		t.Fatal(err)
	}
	var descriptor struct {
		Schema     string   `json:"schema"`
		ID         string   `json:"id"`
		Owner      string   `json:"owner"`
		Entry      string   `json:"entry"`
		Assertions []string `json:"assertion_ids"`
	}
	if err := json.Unmarshal(descriptorBytes, &descriptor); err != nil ||
		descriptor.Schema != "laneboss.e2e-case.v2" || descriptor.ID != "approval" ||
		descriptor.Owner != "lb-v2-approval" || descriptor.Entry != "run.sh" ||
		len(descriptor.Assertions) != 1 || descriptor.Assertions[0] != "ORG-APPROVAL" {
		t.Fatalf("approval case discovery does not match the frozen harness: %v", err)
	}
	entry, err := filepath.Abs(descriptor.Entry)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	sourceBytes, err := os.ReadFile("case.py")
	if err != nil {
		t.Fatal(err)
	}
	binarySum, sourceSum := sha256.Sum256(executableBytes), sha256.Sum256(sourceBytes)
	for _, sample := range []struct {
		phase          string
		controllerWait bool
	}{{"candidate", false}, {"red", false}, {"candidate", true}, {"red", true}} {
		phase := sample.phase
		label := phase + "/missing_fixture"
		if sample.controllerWait {
			label = phase + "/missing_controller"
		}
		t.Run(label, func(t *testing.T) {
			root := approvalPrivateDir(t)
			evidence := filepath.Join(root, "evidence")
			if err := os.Mkdir(evidence, 0700); err != nil {
				t.Fatal(err)
			}
			mutation := ""
			if phase == "red" {
				mutation = "publish_exact"
			}
			contextPath, resultPath := filepath.Join(root, "context.json"), filepath.Join(root, "result.json")
			context := map[string]any{
				"schema": "laneboss.e2e-context.v2", "case_id": "approval", "phase": phase, "mutation_id": mutation,
				"binary": executable, "binary_sha256": hex.EncodeToString(binarySum[:]),
				"source_sha256": hex.EncodeToString(sourceSum[:]), "config": "case-approval",
				"binding_file": filepath.Join(root, "missing-binding.json"), "test_root": root,
				"evidence_root": evidence, "profile_grant_ids": []string{},
			}
			approvalWriteJSON(t, contextPath, context)
			expectedExit := 1
			if sample.controllerWait {
				expectedExit = 69
				approvalWriteJSON(t, filepath.Join(root, "approval-fixture.json"), map[string]any{
					"contract_revision": "v2.0-draft.4", "config": context["config"],
					"actors": map[string]any{"l6": map[string]any{}, "l5": map[string]any{}},
				})
			}
			command := exec.Command("sh", entry, "--context", contextPath, "--result", resultPath)
			output, err := command.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != expectedExit || strings.Contains(string(output), "PASS:") {
				t.Fatalf("missing fixture was reported as success: %v", err)
			}
			data, err := os.ReadFile(resultPath)
			if err != nil {
				t.Fatalf("frozen entry did not retain its atomic setup-failure result: %v", err)
			}
			var result struct {
				Schema     string `json:"schema"`
				CaseID     string `json:"case_id"`
				Phase      string `json:"phase"`
				Mutation   string `json:"mutation_id"`
				Binary     string `json:"binary_sha256"`
				Source     string `json:"source_sha256"`
				Assertions []struct {
					ID       string `json:"id"`
					Reached  bool   `json:"reached"`
					Verdict  string `json:"verdict"`
					Evidence []struct {
						Path   string `json:"path"`
						SHA256 string `json:"sha256"`
						Bytes  int    `json:"bytes"`
					} `json:"evidence"`
				} `json:"assertions"`
			}
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
			if result.Schema != "laneboss.e2e-result.v2" || result.CaseID != descriptor.ID ||
				result.Phase != phase || result.Mutation != mutation || result.Binary != context["binary_sha256"] ||
				result.Source != context["source_sha256"] || len(result.Assertions) != 1 {
				t.Fatal("harness result lost its context/artifact binding")
			}
			assertion := result.Assertions[0]
			if assertion.ID != descriptor.Assertions[0] || assertion.Reached || assertion.Verdict != "fail" || len(assertion.Evidence) == 0 {
				t.Fatal("setup failure was classified as a reached operation or lacked failure evidence")
			}
			waitRecorded := false
			for _, ref := range assertion.Evidence {
				if filepath.IsAbs(ref.Path) || strings.Contains(ref.Path, "..") {
					t.Fatal("escaping harness evidence path")
				}
				retained, err := os.ReadFile(filepath.Join(evidence, ref.Path))
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(retained)
				if len(retained) != ref.Bytes || hex.EncodeToString(sum[:]) != ref.SHA256 {
					t.Fatal("harness result references different evidence bytes")
				}
				if filepath.Base(ref.Path) == "prerequisite-wait.json" {
					var wait struct {
						Code, Owner string
						WaitFor     string `json:"wait_for"`
					}
					if err := json.Unmarshal(retained, &wait); err != nil || wait.Code != "prerequisite_missing" || wait.Owner != "lb-v2-approval" || wait.WaitFor != "installed_controller" {
						t.Fatal("missing controller did not retain its actual typed prerequisite wait", err)
					}
					waitRecorded = true
				}
			}
			if sample.controllerWait != waitRecorded {
				t.Fatal("frozen entry lost or fabricated controller-wait evidence")
			}
			leftovers, err := filepath.Glob(resultPath + ".*.tmp")
			if err != nil || len(leftovers) != 0 {
				t.Fatalf("atomic result left a temporary file: %v", err)
			}
		})
	}
}
