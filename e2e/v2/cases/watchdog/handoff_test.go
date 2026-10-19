//go:build linux

package watchdogcase_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The queue's Linux Go entry also executes the independent Python observer
// checks. No Python project code executes on the authoring machine.
func TestObserverHandoffs(t *testing.T) {
	command := exec.Command("python3", "-B", "-m", "unittest", "checks_test", "handoff_tests")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("watchdog observer/handoff tests failed: %v\n%s", err, output)
	}
	t.Logf("watchdog Python observer/handoff output: %q", output)
}

func TestProducerDelivery(t *testing.T) {
	command := exec.Command("python3", "-B", "-m", "unittest", "producer_test.Delivery")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("watchdog producer delivery failed: %v\n%s", err, output)
	}
	t.Logf("watchdog delivery output: %q", output)
}

func TestProducerG0(t *testing.T) {
	for _, check := range []struct {
		name string
		args []string
		root bool
	}{
		{"watchdog", []string{"-B", "-m", "unittest", "producer_test.G0Contract"}, true},
		{"serve", []string{"-B", "-m", "unittest", "discover", "-s", "../../../../scripts/v2-serve", "-p", "*_test.py"}, true},
	} {
		t.Run(check.name, func(t *testing.T) {
			command := exec.Command("python3", check.args...)
			if check.root {
				command = exec.Command("sudo", append([]string{"-n", "env", "PATH=" + os.Getenv("PATH"), "python3"}, check.args...)...)
			}
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("%s G0 checks failed: %v\n%s", check.name, err, output)
			}
			t.Logf("%s G0 output: %q", check.name, output)
		})
	}
}

func TestProducerUnits(t *testing.T) {
	command := exec.Command("python3", "-B", "-m", "unittest", "producer_test.Producer", "producer_test.Restart")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("watchdog producer controls failed: %v\n%s", err, output)
	}
	t.Logf("watchdog producer output: %q", output)
}

func TestProducerMutations(t *testing.T) {
	root, err := os.MkdirTemp("", "lb-v2-watchdog-red-")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("python3", "-B", "producer_red.py", "--evidence", filepath.Join(root, "controls"))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("watchdog producer mutations failed: %v\n%s", err, output)
	}
	t.Logf("watchdog mutation evidence: %s; output: %s", root, output)
}
