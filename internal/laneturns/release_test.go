//go:build !laneboss_faults

package laneturns

import (
	"path/filepath"
	"testing"
)

func TestReleaseIgnoresClaimsDir(t *testing.T) {
	t.Setenv("LANEBOSS_TEST_CLAIMS_DIR", "")
	expected, err := claimRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"relative-claims", filepath.Join(t.TempDir(), "claims")} {
		t.Setenv("LANEBOSS_TEST_CLAIMS_DIR", value)
		actual, err := claimRegistry()
		if err != nil || actual != expected {
			t.Fatal("release turn claims used the test override")
		}
	}
}
