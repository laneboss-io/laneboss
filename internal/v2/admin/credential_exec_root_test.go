//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import (
	"context"
	"os"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestInstalledCredentialExec(t *testing.T) {
	if os.Args[len(os.Args)-1] == "agent-open-root" {
		installedNativeClosedGate(t, true)
		return
	}
	// A standalone root invocation needs the same installed runtime, accounts
	// and delegated helper control leaf as the installed-canary launcher.
	workerLaunchCanary(t, false, func(t *testing.T, _ context.Context, m *leaseManager, _ dataReg, _ api.BlobRef, _ api.Executable) {
		t.Cleanup(func() { archiveCanaryCollect(t, m) })
		installedNativeClosedGate(t, true)
	})
}
