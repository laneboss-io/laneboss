//go:build !laneboss_partial || !laneboss_e2e_authenticator

package assembly

import "laneboss.io/laneboss/internal/v2/api"

func installedRunners(installed Installation, deps runnerDependencies) (api.Runner, api.Runner, error) {
	return realRunners(installed, deps)
}
