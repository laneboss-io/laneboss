//go:build !linux

package admin

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) dispatchCaptureDrain(context.Context, string, []byte) (any, error) {
	return nil, failure(api.CodeUnsupported, "native capture drain requires Linux")
}

func (m *leaseManager) reconcileTerminalCapture(context.Context, leaseRecord, captureJournal) error {
	return failure(api.CodeUnsupported, "native terminal capture reconciliation requires Linux")
}

func (m *leaseManager) reconcileStoppedCapture(context.Context, leaseRecord, captureJournal) error {
	return failure(api.CodeUnsupported, "native stopped capture reconciliation requires Linux")
}
