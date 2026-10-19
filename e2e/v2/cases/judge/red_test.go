//go:build linux && laneboss_judge_red

package judgecase

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestJudgeNativeRed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	source, err := filepath.Abs("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	// Keep the reached failures and exact mutated/restored input bytes after
	// this Go process exits. TempDir would silently delete passing evidence.
	retained, err := os.MkdirTemp("", "lb-v2-case-judge-red-")
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(retained, "native-red")
	command := exec.CommandContext(ctx, "python3", "-B", "red_native.py", "--source", source, "--evidence", output)
	raw, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("native judge red controls: %v\n%s", err, raw)
	}
	t.Logf("retained native red evidence: %s", output)
	t.Logf("%s", raw)
	data, err := os.ReadFile(filepath.Join(output, "result.json"))
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Controls []struct {
			ID      string `json:"id"`
			Reached bool   `json:"reached"`
			Exit    int    `json:"exit"`
		}
	}
	if json.Unmarshal(data, &result) != nil || len(result.Controls) != 6 {
		t.Fatal("native red runner omitted a required reached control")
	}
	seen := map[string]bool{}
	for _, control := range result.Controls {
		if control.ID == "" || seen[control.ID] || !control.Reached || control.Exit != 1 {
			t.Fatal("native red runner returned a duplicate or unreached control")
		}
		seen[control.ID] = true
	}
	t.Log("six reached native controls were RED; every restored candidate was GREEN")
}
