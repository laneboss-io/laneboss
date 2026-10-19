//go:build linux

package grants_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// The Linux queue accepts Go packages. This entry executes the case's actual
// Python RED/candidate proof and catalog tests; it supplies no product result.
// The proof's installer validation and native socket canary require root.
func TestGrantsCaseHarness(t *testing.T) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		t.Fatal("grants case proof requires the disposable Linux root observer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	directory, err := os.MkdirTemp("", "lb-v2-case-grants-harness-")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("retained grants case proof: %s", directory)
	for _, check := range []struct {
		name string
		args []string
		pass []byte
	}{
		{"wiring", []string{"-B", "prove-wiring.py"}, []byte("PASS: grants wiring red/candidate controls")},
		{"catalog", []string{"-B", "-m", "unittest", "discover", "-s", ".", "-p", "catalog_test.py", "-v"}, []byte("\nOK\n")},
	} {
		path := filepath.Join(directory, check.name+".log")
		log, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, "python3", check.args...)
		command.Stdout, command.Stderr = log, log
		runErr := command.Run()
		closeErr := log.Close()
		output, readErr := os.ReadFile(path)
		if runErr != nil || closeErr != nil || readErr != nil || !bytes.Contains(output, check.pass) {
			t.Fatalf("actual grants %s proof failed: run=%v close=%v read=%v; transcript=%s\n%s", check.name, runErr, closeErr, readErr, path, output)
		}
		if check.name == "catalog" && (!regexp.MustCompile(`(?m)^Ran [1-9][0-9]* tests?`).Match(output) || bytes.Contains(output, []byte("skipped"))) {
			t.Fatalf("grants catalog proof ran no tests or skipped a check; transcript=%s", path)
		}
		t.Logf("actual grants %s proof passed; transcript=%s", check.name, path)
	}
}
