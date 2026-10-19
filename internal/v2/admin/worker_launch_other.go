//go:build !linux

package admin

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/identity"
)

func (*Service) AcquireWorkerLaunch(context.Context, string, api.ID) (identity.WorkerLaunchGuard, error) {
	return nil, failure(api.CodeUnsupported, "retained fixed worker descriptor handoff requires Linux")
}

func (*Service) WithWorkerLaunch(context.Context, api.PreparedLaunch, func(context.Context) error) error {
	return failure(api.CodeUnsupported, "retained fixed worker launch transaction requires Linux")
}
