package secretscase_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProducerComponents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "-I", "-B", "producer_test.py")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("secrets producer component checks failed: %v\n%s", err, output)
	}
	t.Logf("%s", output)
}

func TestInstalledControls(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	root, err := os.MkdirTemp("", "lb-v2-secret-controls-")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, "python3", "-I", "-B", "checks_install.py", "--controls", filepath.Join(root, "controls"))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("installed observer RED/GREEN controls failed: %v\n%s", err, output)
	}
	t.Logf("retained installed control inputs and outputs: %s", root)
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		var row struct {
			ID, Phase string
			Exit      int
			Input     string `json:"input_sha256"`
			Stderr    string `json:"stderr_sha256"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil || row.ID == "" || row.Input == "" || row.Stderr == "" {
			t.Fatal("installed control did not retain a complete phase record")
		}
		t.Logf("installed control %s %s=%d %s", row.ID, row.Phase, row.Exit, row.Input)
	}
	t.Logf("installed control phase-records sha256=%x", sha256.Sum256(output))
}

func TestConsumerComponents(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", "-I", "-B", "check_case.py", "--source", ".", "--unit")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("secrets consumer component checks failed: %v\n%s", err, output)
	}
	t.Logf("%s", output)
}
