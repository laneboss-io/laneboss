//go:build !linux

package admin

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) openJudgeCall(context.Context, judgeOpen, *api.ProcessHandle) error {
	return failure(api.CodeUnsupported, "native judge handoff requires Linux")
}

func (m *leaseManager) startJudgeGate(context.Context, leaseRecord, judgeNative) (ownedGate, error) {
	return nil, failure("unsupported", "native judge gate requires Linux")
}

func (s *Service) bindJudgeContainment(context.Context, judgeReg) error {
	return failure("unsupported", "native judge containment requires Linux")
}
