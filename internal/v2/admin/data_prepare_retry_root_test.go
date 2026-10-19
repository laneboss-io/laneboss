//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin

import "testing"

func TestDataPrepareStorageRetry(t *testing.T) {
	workerLaunchCanary(t, true)
}
