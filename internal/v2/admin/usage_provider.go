//go:build !linux || !laneboss_partial || !laneboss_e2e_authenticator

package admin

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) usageProvider(context.Context, api.UsageJob, api.HelperLease, bool) error {
	return nil
}
