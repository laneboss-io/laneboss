//go:build linux && laneboss_root_canary

package admin

import "testing"

func TestCheckLaunchNative(t *testing.T) { workerLaunchCanary(t, false, archiveLaunchCanary) }
