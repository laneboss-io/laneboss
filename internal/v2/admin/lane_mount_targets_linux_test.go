//go:build linux

package admin

import (
	"path/filepath"
	"testing"

	"laneboss.io/laneboss/internal/v2/client/wire"
)

func TestLaneMountTargets(t *testing.T) {
	if err := checkLaneMountTargets([]*nativeMount{{target: "/work/main"}, {target: "/runtime/enrolled-tool"}}); err != nil {
		t.Fatal("independent runtime mounts collided with lane projections", err)
	}
	for _, target := range []string{wire.LaneBindingPath, wire.LaneSocketPath, wire.LaneClientPath} {
		for _, path := range []string{target, filepath.Dir(target), target + "/nested"} {
			if err := checkLaneMountTargets([]*nativeMount{{target: path}}); err == nil {
				t.Fatal("acceptance: lane projection admitted an overlapping runtime mount")
			}
		}
	}
}
