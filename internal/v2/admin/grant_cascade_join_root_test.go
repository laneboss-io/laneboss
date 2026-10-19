//go:build linux && laneboss_root_canary && laneboss_gate_integration

package admin_test

import (
	"laneboss.io/laneboss/internal/v2/service"
	"testing"
)

func TestGrantCascadeNative(t *testing.T) {
	naturalReleaseTest(t, "TestGrantCascadeNative", service.ExerciseGrantCascadeCanary)
}

func TestSealedDelegationNative(t *testing.T) {
	naturalReleaseTest(t, "TestSealedDelegationNative", service.ExerciseSealedDelegationCanary)
}
