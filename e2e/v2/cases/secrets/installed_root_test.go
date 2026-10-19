//go:build linux && laneboss_root_canary && laneboss_secret_install

package secretscase_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Explicit opt-in execution of the actual entry, never a component pass.
// queue-input records the known base; source.tar records the changed bytes.
func TestInstalledStandin(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("installed queue requires the authorized root Linux process")
	}
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	source, err := filepath.Abs(filepath.Join(directory, "../../../.."))
	if err != nil {
		t.Fatal(err)
	}
	var input struct{ BaseRevision, Scope string }
	raw, err := os.ReadFile(filepath.Join(directory, "queue-input.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]string
	if json.Unmarshal(raw, &document) != nil {
		t.Fatal("installed queue source input is invalid")
	}
	input.BaseRevision, input.Scope = document["base_revision"], document["scope"]
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(input.BaseRevision) || input.Scope == "" {
		t.Fatal("installed queue requires retained base revision provenance")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatal("installed queue requires its supplied Go toolchain")
	}
	root, err := os.MkdirTemp("/opt", "lb-v2-case-secrets-queue-")
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(root, "primary.log")
	output, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "sh", "e2e/v2/cases/secrets/QUEUE-INSTALLED.sh", source, filepath.Join(root, "evidence"))
	command.Dir = source
	command.Env = []string{"PATH=" + filepath.Dir(goTool) + ":/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C.UTF-8",
		"LB_SRC_REV=" + input.BaseRevision}
	command.Stdout, command.Stderr = output, output
	runErr := command.Run()
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	code := 0
	if runErr != nil {
		code = 1
		if exit, ok := runErr.(*exec.ExitError); ok {
			code = exit.ExitCode()
		}
	}
	result, err := json.Marshal(map[string]any{"exit": code, "source_scope": input.Scope, "primary": "primary.log"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "exit.json"), result, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("retained installed queue evidence: %s", root)
	primary, err := os.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Close()
	lines := bufio.NewScanner(primary)
	lines.Buffer(make([]byte, 4096), 1<<20)
	for lines.Scan() {
		line := lines.Text()
		var record map[string]any
		diagnostic := json.Unmarshal([]byte(line), &record) == nil && record["schema"] == "laneboss.secret-diagnostic.v1"
		if strings.HasPrefix(line, "secrets ") || diagnostic && (record["kind"] != "journal" || record["refusal"] != nil) {
			t.Log(line)
		}
	}
	if err := lines.Err(); err != nil {
		t.Fatal("installed queue could not read its retained primary output")
	}
	if runErr != nil {
		t.Fatalf("installed queue entry exited %d; preserve its evidence", code)
	}
}
