//go:build laneboss_faults

package hookpaths

import "laneboss.io/laneboss/internal/faults"

func dropOrgJudge() bool {
	if faults.Get("judge-drop-org-source").Point == "" {
		return false
	}
	if err := faults.Reach("judge-drop-org-source"); err != nil {
		panic("judge source mutation marker could not be kept")
	}
	return true
}
