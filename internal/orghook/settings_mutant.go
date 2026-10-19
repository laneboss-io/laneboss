//go:build laneboss_faults

package orghook

import "laneboss.io/laneboss/internal/faults"

// Restore the old refuse-all settings-error behavior, including read tools.
func settingsRefuseAll(reached bool) bool {
	if faults.Get("guide-settings-refuse-all").Point == "" {
		return false
	}
	if reached {
		if err := faults.Reach("guide-settings-refuse-all"); err != nil {
			panic("settings mutation marker could not be kept")
		}
	}
	return true
}
