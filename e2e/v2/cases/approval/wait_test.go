package approval_test

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestApprovalWaitAndPresence(t *testing.T) {
	root, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"wait", "presence"} {
		t.Run(mode, func(t *testing.T) {
			command := exec.Command("python3", filepath.Join(root, "testdata/wait_probe.py"), root, approvalPrivateDir(t), mode)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatal("harness observation did not run", err, string(output))
			}
			var result map[string]any
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatal(err)
			}
			if mode == "wait" {
				if result["code"] != "prerequisite_missing" || result["wait_for"] != "owner_confirmation" {
					t.Fatalf("missing owner confirmation is not a typed wait: %s", output)
				}
			} else if result["presence"] != "simulated" || result["human_approval"] != "not_proven" {
				t.Fatalf("software presence was omitted or reported as physical approval: %s", output)
			}
		})
	}
}
