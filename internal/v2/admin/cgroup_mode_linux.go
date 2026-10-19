//go:build linux

package admin

import (
	"os"

	"laneboss.io/laneboss/internal/v2/api"
)

// Called only after the helper has checked the protected root-owned path.
// Creation modes alone are restricted by the fixed helper unit's 0077 umask.
func readableCgroup(path string) error {
	if err := os.Chmod(path, 0755); err != nil {
		return failure(api.CodePrerequisite, "cannot expose read-only lane cgroup facts")
	}
	return nil
}
