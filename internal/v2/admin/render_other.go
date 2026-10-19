//go:build !linux

package admin

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/orgrender"
)

func (m *leaseManager) renderOrg(context.Context, orgrender.Stage) (orgrender.Result, error) {
	return orgrender.Result{}, api.NotImplemented("lb-v2-admin", "native org renderer on this platform")
}
