package lifecyclecase

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/cli"
)

func lifecycleConfig() string {
	// Read only the binding selector; never change a live test session's
	// configuration to make a conflicting command succeed.
	if bound := os.Getenv("LANEBOSS_CONFIG"); bound != "" {
		return bound
	}
	return "example"
}

// These tests cover the actual CLI parsing entry point. The runtime case is
// run.py against the installed candidate and real contained actors.
func TestCLIRejectsForgedFile(t *testing.T) {
	for _, data := range []string{
		`{"life_id":"child","run":1,"actor":"forged"}`,
		`{"life_id":"child","run":1,"run":2}`,
		`{"life_id":"child"}`,
		`{"life_id":"child","run":null}`,
		`{"life_id":"\ud800","run":1}`,
	} {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, "request.json")
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		exit := cli.Run([]string{"lane", "status", "--config", lifecycleConfig(), "--request", path},
			strings.NewReader(""), &stdout, &stderr)
		var result api.Error
		if err := json.Unmarshal(stderr.Bytes(), &result); err != nil {
			t.Fatal("missing typed CLI failure", err)
		}
		if exit != 2 || stdout.Len() != 0 || result.Code != api.CodeInvalid {
			t.Fatal("forged request reached transport or returned success")
		}
	}
}

func TestCLIRejectsUnknownFlags(t *testing.T) {
	config := lifecycleConfig()
	for _, args := range [][]string{
		{"lane", "status", "--config", config, "--actor", "forged"},
		{"lane", "status", "--config", config, "--life", "child", "--run", "1", "extra"},
		{"lane", "start", "--config", config, "--force"},
		{"lane", "clean", "--config", config, "--force"},
		{"lane", "status", "--config", config, "--life", "child", "--life", "other"},
	} {
		var stdout, stderr bytes.Buffer
		exit := cli.Run(args, strings.NewReader(""), &stdout, &stderr)
		var result api.Error
		if err := json.Unmarshal(stderr.Bytes(), &result); err != nil {
			t.Fatal("missing typed CLI argument failure", err)
		}
		if exit != 2 || result.Code != api.CodeInvalid || stdout.Len() != 0 {
			t.Fatal("unknown or conflicting CLI arguments were admitted")
		}
	}
}
