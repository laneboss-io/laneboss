//go:build linux

package fixtures

import (
	"os/exec"
	"testing"
)

func TestCapRead(t *testing.T) {
	command := exec.Command("python3", "-B", "-m", "unittest", "-v", "cap_read_test")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("installed capture reader units: %v\n%s", err, output)
	}
	t.Log(string(output))
}
