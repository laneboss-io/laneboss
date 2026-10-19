//go:build !laneboss_partial || !laneboss_e2e_authenticator

package assembly

import (
	"laneboss.io/laneboss/internal/v2/secrets"
	"laneboss.io/laneboss/internal/v2/service"
)

func bindInitialProfiles(_ *service.Server, _ Installation, _ *secrets.Service) error {
	return nil
}
