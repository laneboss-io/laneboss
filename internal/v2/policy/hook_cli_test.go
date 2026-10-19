package policy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

var hookEvidenceRoot = flag.String("lb-v2-policy-hook-evidence", "", "retained CLI hook test artifacts outside the source tree")

func hookRun(t *testing.T, ctx context.Context, directory, evidence, name string, args []string) ([]byte, error) {
	t.Helper()
	command := exec.CommandContext(ctx, "go", args...)
	command.Dir = directory
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = 10 * time.Second
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	for suffix, data := range map[string][]byte{"stdout": stdout.Bytes(), "stderr": stderr.Bytes()} {
		if writeErr := os.WriteFile(filepath.Join(evidence, name+"."+suffix), data, 0600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	exit := 0
	if err != nil {
		var exited *exec.ExitError
		if !errors.As(err, &exited) {
			t.Fatalf("CLI hook fixture command could not start: %v", err)
		}
		exit = exited.ExitCode()
	}
	record, marshalErr := json.Marshal(map[string]any{"argv": append([]string{"go"}, args...), "exit": exit,
		"timed_out": ctx.Err() != nil, "stdout": name + ".stdout", "stderr": name + ".stderr"})
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if writeErr := os.WriteFile(filepath.Join(evidence, name+".json"), record, 0600); writeErr != nil {
		t.Fatal(writeErr)
	}
	if ctx.Err() != nil {
		t.Fatal("CLI hook fixture command timed out")
	}
	if stderr.Len() != 0 && name == "test" {
		t.Fatalf("CLI hook fixture test tool wrote stderr: %s", stderr.Bytes())
	}
	return stdout.Bytes(), err
}

func TestInstalledHookExit(t *testing.T) {
	testHookCLI(t, "TestLBPolicyHookRun", "installed hook decision/exit mismatch")
}

// Fix 11 refuses raw hooks before generic file/socket handling. The child now
// drives real Run for every outcome and requires that exact typed exit 69.
func TestRawFileHookOutcome(t *testing.T) {
	testHookCLI(t, "TestLBPolicyRawFileHook", "raw file hook outcome mismatch")
}

func testHookCLI(t *testing.T, suite, failure string) {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for count := 0; count < 5; count++ {
		if info, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil && info.Mode().IsRegular() {
			break
		}
		directory = filepath.Dir(directory)
	}
	virtual := filepath.Join(directory, "internal", "v2", "cli", "lb_v2_policy_hook_test.go")
	source := filepath.Join(directory, "internal", "v2", "policy", "testdata", "cli_hook_test.go")
	if info, err := os.Stat(source); err != nil || !info.Mode().IsRegular() {
		t.Fatal("owned CLI hook test source is missing")
	}
	base := *hookEvidenceRoot
	if base == "" {
		base = filepath.Join(os.TempDir(), "lb-v2-policy-cli-evidence")
	}
	base, err = filepath.Abs(base)
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(directory, base)
	if err != nil || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
		t.Fatal("CLI hook evidence must be outside the input source")
	}
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(base)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("CLI hook evidence directory is not private")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		t.Fatal("CLI hook evidence directory belongs to another identity")
	}
	evidence, err := os.MkdirTemp(base, "lb-v2-policy-hook-")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("retained CLI hook evidence: %s", evidence)
	fixture, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	fixturePath := filepath.Join(evidence, "cli_hook_test.go")
	if err := os.WriteFile(fixturePath, fixture, 0600); err != nil {
		t.Fatal(err)
	}
	overlay, err := json.Marshal(map[string]any{"Replace": map[string]string{virtual: fixturePath}})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(evidence, "overlay.json")
	if err := os.WriteFile(file, overlay, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 120*time.Second)
	defer stop()
	binary := filepath.Join(evidence, "cli.test")
	args := []string{"test", "-c", "-trimpath", "-overlay", file, "-o", binary}
	if hookTestTags != "" {
		args = append(args, "-tags", hookTestTags)
	}
	args = append(args, "./internal/v2/cli")
	if raw, err := hookRun(t, ctx, directory, evidence, "build", args); err != nil {
		t.Fatalf("CLI hook fixture compilation failed: %v: %s", err, raw)
	}
	built, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(built)
	fixtureHash := sha256.Sum256(fixture)
	record, err := json.Marshal(map[string]any{"binary": "cli.test", "sha256": hex.EncodeToString(hash[:]),
		"bytes": len(built), "fixture": "cli_hook_test.go", "fixture_sha256": hex.EncodeToString(fixtureHash[:]),
		"overlay": "overlay.json", "tags": hookTestTags})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evidence, "binary.json"), record, 0600); err != nil {
		t.Fatal(err)
	}
	raw, runErr := hookRun(t, ctx, directory, evidence, "test", []string{"tool", "test2json", "-t", "-p",
		"laneboss.io/laneboss/internal/v2/cli", binary, "-test.v=test2json", "-test.count=1", "-test.run=^" + suite + "$"})
	t.Logf("owned CLI hook transcript:\n%s", raw)
	actual, err := os.ReadFile(binary)
	if err != nil || !bytes.Equal(actual, built) {
		t.Fatal("executed CLI hook binary changed")
	}
	if runErr != nil {
		var exited *exec.ExitError
		if !errors.As(runErr, &exited) || exited.ExitCode() != 1 {
			t.Fatalf("CLI hook fixture did not exit with an assertion failure: %v", runErr)
		}
	}
	type event struct{ Action, Test, Output, Package string }
	started, passed, failed := map[string]bool{}, map[string]bool{}, map[string]bool{}
	output := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		var item event
		if json.Unmarshal(scanner.Bytes(), &item) != nil || item.Package != "laneboss.io/laneboss/internal/v2/cli" {
			t.Fatal("CLI hook fixture did not emit test JSON")
		}
		switch item.Action {
		case "run":
			started[item.Test] = true
		case "pass":
			passed[item.Test] = true
		case "fail":
			failed[item.Test] = true
		case "skip":
			t.Fatal("CLI hook fixture skipped an outcome")
		}
		output[item.Test] += item.Output
	}
	if scanner.Err() != nil || strings.Contains(string(raw), "panic:") {
		t.Fatal("CLI hook fixture stream failed")
	}
	bad := []string{}
	for _, name := range []string{"allow", "deny", "warn", "unscored"} {
		full := suite + "/" + name
		if !started[full] {
			t.Fatal("CLI hook fixture did not reach all outcomes")
		}
		if failed[full] {
			if passed[full] {
				t.Fatal("CLI hook fixture contradicted an outcome")
			}
			if !strings.Contains(output[full], "hook exit/decision mismatch:") {
				t.Fatal("CLI hook fixture failed outside the outcome assertion")
			}
			bad = append(bad, name)
		} else if !passed[full] {
			t.Fatal("CLI hook fixture outcome is incomplete")
		}
	}
	if len(bad) != 0 {
		if runErr == nil || !failed[suite] || !failed[""] {
			t.Fatal("CLI hook fixture concealed a failing assertion")
		}
		sort.Strings(bad)
		t.Fatalf("%s: failed cases=%s", failure, strings.Join(bad, ","))
	}
	if runErr != nil || !passed[suite] || !passed[""] || failed[suite] {
		t.Fatalf("CLI hook fixture did not pass: %v", runErr)
	}
}
