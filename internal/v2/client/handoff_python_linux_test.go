//go:build linux

package client

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/client/wire"
)

func TestPythonLaneHandoff(t *testing.T) {
	script, err := filepath.Abs("../../../e2e/v2/lane_handoff_test.py")
	if err != nil {
		t.Fatal(err)
	}
	helper, err := os.ReadFile(filepath.Join(filepath.Dir(script), "lane_handoff.py"))
	if err != nil {
		t.Fatal(err)
	}
	for _, pin := range []string{"LANE_BINDING = \"" + wire.LaneBindingPath + "\"", "LANE_SOCKET = \"" + wire.LaneSocketPath + "\""} {
		if !bytes.Contains(helper, []byte(pin)) {
			t.Fatal("Python actor handoff drifted from the installed fixed projection paths")
		}
	}
	output, err := exec.Command("python3", "-I", "-B", script).CombinedOutput()
	if err != nil {
		t.Fatalf("Python descriptor control failed: %v\n%s", err, output)
	}
}
