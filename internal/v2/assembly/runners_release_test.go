//go:build !laneboss_partial || !laneboss_e2e_authenticator

package assembly

import "testing"

func TestReleaseRequiresRunnerPorts(t *testing.T) {
	claude, codexDriver, err := installedRunners(Installation{}, runnerDependencies{})
	if err == nil || claude != nil || codexDriver != nil {
		t.Fatal("release accepted missing runners")
	}
}
