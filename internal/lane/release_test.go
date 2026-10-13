//go:build !laneboss_faults

package lane

import (
	"path/filepath"
	"testing"
)

func TestReleaseIgnoresClaimsDir(t *testing.T) {
	t.Setenv("LANEBOSS_TEST_CLAIMS_DIR", "")
	expected, err := claimsRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"relative-claims", filepath.Join(t.TempDir(), "claims")} {
		t.Setenv("LANEBOSS_TEST_CLAIMS_DIR", value)
		actual, err := claimsRegistry()
		if err != nil || actual != expected {
			t.Fatal("release claims used the test override")
		}
	}
}
