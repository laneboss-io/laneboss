//go:build !linux

package admin

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) ensureNativeWorkspace(context.Context, *leaseRecord, int, dataMeasure) error {
	return failure(api.CodeUnsupported, "native workspace production requires Linux")
}
