//go:build !linux

package admin

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

func (m *leaseManager) startUsageGate(context.Context, leaseRecord, usageNative) (ownedGate, error) {
	return nil, failure("unsupported", "native usage gate requires Linux")
}

func (s *Service) bindUsageContainment(context.Context, usageReg) error {
	return failure("unsupported", "native usage containment requires Linux")
}

func (m *leaseManager) collectUsageHome(api.HelperLease) error {
	return failure(api.CodeUnsupported, "usage home collection requires Linux")
}

func (m *leaseManager) observeUsage(context.Context, usageReg) (api.ProcessObservation, error) {
	return api.ProcessObservation{}, failure(api.CodeUnsupported, "native usage observation requires Linux")
}
