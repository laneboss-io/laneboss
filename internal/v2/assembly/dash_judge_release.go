//go:build !laneboss_partial || !laneboss_e2e_authenticator

package assembly

import "laneboss.io/laneboss/internal/v2/api"

func dashboardPolicySource(installed Installation, actual api.ScopedJudge) (api.ScopedJudge, int64, error) {
	return actual, installed.PolicyMaxCostMicros, nil
}
