//go:build linux && laneboss_root_canary && laneboss_gate_integration

package messagingcase

import (
	"os"
	"testing"
)

// This root canary measures actual sealed memfd/socket descriptor transfer and
// ambient-FD exclusion. It does not certify installed lane identity or drivers.
func TestItem3RootDescriptorHandoff(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("descriptor root canary requires the disposable root test kit")
	}
	TestItem3PythonDescriptorHandoff(t)
}
