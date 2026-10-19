//go:build linux && laneboss_faults && !laneboss_e2e_authenticator

package service

import "testing"

func TestHealthBuildVariant(t *testing.T) {
	assertHealthVariant(t, "laneboss_faults", false)
}
