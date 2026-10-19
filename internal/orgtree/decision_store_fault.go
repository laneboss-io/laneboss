//go:build laneboss_faults

package orgtree

import "laneboss.io/laneboss/internal/faults"

func decisionStoreFaultMode() (string, error) {
	for _, point := range []string{"org-store-skip-text", "org-store-legacy-scan", "org-store-copy-nolock", "org-store-fts-double", "org-store-raw-join"} {
		if faults.Get(point).Point != "" {
			return point, faults.Reach(point)
		}
	}
	return "", nil
}

func decisionStoreCompanionFault() (bool, error) {
	const point = "org-store-companion-names"
	if faults.Get(point).Point != "" {
		return true, faults.Reach(point)
	}
	return false, nil
}
