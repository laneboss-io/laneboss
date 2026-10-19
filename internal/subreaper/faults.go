//go:build linux && laneboss_faults

package subreaper

import "laneboss.io/laneboss/internal/faults"

// Disable the actual kernel adoption, leaving caller resolution unchanged.
func disabled() (bool, error) {
	if faults.Get("lane-no-subreaper").Point == "" {
		return false, nil
	}
	return true, faults.Reach("lane-no-subreaper")
}
