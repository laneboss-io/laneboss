//go:build linux

package admin

import (
	"os/exec"
	"strings"
	"testing"
)

func TestBootInputs(t *testing.T) {
	command := exec.Command("/usr/bin/python3", "-I", "-B", "provision_test.py")
	command.Dir = "../../../scripts/v2-admin"
	output, err := command.CombinedOutput()
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		t.Log(line)
	}
	if err != nil {
		t.Fatal("provision input regression", err)
	}
}
