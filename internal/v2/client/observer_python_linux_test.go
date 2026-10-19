//go:build linux

package client

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestOutsideObserverContract(t *testing.T) {
	script, err := filepath.Abs("../../../e2e/v2/observer_contract_test.py")
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("python3", "-I", "-B", script).CombinedOutput()
	if err != nil {
		t.Fatalf("outside observer control failed: %v\n%s", err, output)
	}
}
