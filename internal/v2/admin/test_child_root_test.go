//go:build linux && laneboss_root_canary

package admin

import "testing"

func TestNativeChildLaunch(t *testing.T) { workerLaunchCanary(t, false, archiveLaunchCanary) }
