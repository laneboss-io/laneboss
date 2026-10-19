//go:build !linux && laneboss_partial && laneboss_e2e_authenticator

package assembly

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/bstate"
)

func (*initialFixtureProfiles) authenticateAPIKeyCanary(context.Context, bstate.Profile) (bool, error) {
	return false, api.NotImplemented("lb-v2-integrate", "Linux API key canary source")
}
