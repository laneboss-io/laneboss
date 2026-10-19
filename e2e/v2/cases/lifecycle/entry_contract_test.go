package lifecyclecase

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestFrozenLifecycleEntry(t *testing.T) {
	raw, err := os.ReadFile("case.json")
	if err != nil {
		t.Fatal("lifecycle is not discoverable through the frozen case manifest", err)
	}
	var manifest struct {
		Schema     string   `json:"schema"`
		ID         string   `json:"id"`
		Entry      string   `json:"entry"`
		Assertions []string `json:"assertion_ids"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != "laneboss.e2e-case.v2" || manifest.ID != "lifecycle" || manifest.Entry != "run.sh" || len(manifest.Assertions) != 1 || manifest.Assertions[0] != "LIFECYCLE-TREE" {
		t.Fatal("lifecycle manifest does not use the frozen discovery contract")
	}
	root := t.TempDir()
	contextPath, resultPath := filepath.Join(root, "context.json"), filepath.Join(root, "result.json")
	context := map[string]any{"schema": "laneboss.e2e-context.v2", "case_id": "lifecycle", "phase": "candidate", "mutation_id": "", "binary": "/missing/artifact", "binary_sha256": "", "source_sha256": "", "config": "case-lifecycle", "binding_file": filepath.Join(root, "binding.json"), "test_root": root, "evidence_root": filepath.Join(root, "evidence"), "profile_grant_ids": []string{}}
	raw, err = json.Marshal(context)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(contextPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("./run.sh", "--context", contextPath, "--result", resultPath)
	if output, err := command.CombinedOutput(); err == nil {
		t.Fatalf("missing authentic fixture was reported as acceptance: %s", output)
	}
	raw, err = os.ReadFile(resultPath)
	if err != nil {
		t.Fatal("failed prerequisite did not retain the frozen result", err)
	}
	var result struct {
		Schema     string `json:"schema"`
		Assertions []struct {
			ID      string `json:"id"`
			Reached bool   `json:"reached"`
			Verdict string `json:"verdict"`
		} `json:"assertions"`
		Collection struct {
			Quiescent bool `json:"processes_quiescent"`
			Collected bool `json:"temporary_resources_collected"`
		} `json:"collection"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Schema != "laneboss.e2e-result.v2" || len(result.Assertions) != 1 || result.Assertions[0].ID != "LIFECYCLE-TREE" || result.Assertions[0].Reached || result.Assertions[0].Verdict != "fail" || result.Collection.Quiescent || result.Collection.Collected {
		t.Fatal("missing fixture was promoted to reached, passed or collected acceptance")
	}
}
