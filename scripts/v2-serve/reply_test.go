package fixtures

import (
	"os/exec"
	"strings"
	"testing"
)

func TestReplyAuth(t *testing.T) {
	command := exec.Command("python3", "-B", "-m", "unittest", "-v",
		"reply_test", "api_key_canary_test", "flow_test")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("reply authentication controls: %v\n%s", err, output)
	}
	summary := strings.LastIndex(string(output), "\nRan ")
	if summary < 0 || strings.Contains(string(output), "\nRan 0 tests") {
		t.Fatalf("reply controls lack a nonempty test summary:\n%s", output)
	}
	t.Log(string(output[summary+1:]))
	t.Log(string(output))
}
