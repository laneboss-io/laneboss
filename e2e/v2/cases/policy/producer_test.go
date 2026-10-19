package policycase

import (
	"os/exec"
	"testing"
)

// The wrapper keeps interpreter execution on the lane's authorized Linux box.
func TestPolicyProducerControls(t *testing.T) {
	command := exec.Command("python3", "-I", "test_producer.py")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("installed policy producer controls: %v\n%s", err, output)
	}
	t.Log(string(output))
}

func TestPolicyConsumerControls(t *testing.T) {
	command := exec.Command("python3", "-I", "-m", "unittest", "discover", "-s", ".", "-p", "test_case.py")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("policy consumer controls: %v\n%s", err, output)
	}
	t.Log(string(output))
}
