//go:build linux && laneboss_root_canary

package dashboardcase

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The dispatcher importer owns actual systemd-scope units. Run its existing
// RED/candidate controls only on the explicitly selected Linux root test box.
func TestDashboardSharedControls(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("shared dispatcher controls require the disposable Linux root observer")
	}
	root := filepath.Clean("../../../..")
	command := exec.Command("python3", "-B", "e2e/v2/cases/grants/prove-wiring.py")
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "PASS: grants wiring red/candidate controls") {
		t.Fatalf("shared dispatcher importer controls failed: %v\n%s", err, output)
	}
	t.Logf("shared dispatcher RED/candidate output:\n%s", output)
}

func TestDashboardNativeChildLaunchControl(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("native TestChild control requires the disposable Linux root observer")
	}
	dashboardGoControl(t, "../../../..", "./internal/v2/admin", "TestNativeChildLaunch", "internal/v2/admin/review_journal.go",
		"copy.SourceOperationID = prior.Intent.OperationID", "copy.SourceOperationID = r.Job.Intent.OperationID", "archive current bytes or mode changed", "laneboss_root_canary")
}
