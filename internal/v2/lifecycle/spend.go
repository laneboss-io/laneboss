package lifecycle

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) checkSpend(ctx context.Context, slot api.CredentialSlot) error {
	if slot.Mode != "claude-api-key" {
		return nil
	}
	guard, ok := s.deps.Store.(api.CredentialSpendGuard)
	if !ok || absent(guard) {
		return problem(api.CodePrerequisite, "API credential balance guard is unavailable", "Enroll a tool reading through the administrator path before launching.")
	}
	_, err := guard.CheckCredentialSpend(ctx, slot)
	return failure(err)
}

func (s *Service) statusSpend(ctx context.Context, scope api.Scope, lane *api.Lane) error {
	reader, ok := s.deps.Store.(api.SpendStatusReader)
	if !ok || absent(reader) {
		return nil
	}
	balance, err := reader.LaneSpend(ctx, scope, api.LifeRef{LifeID: lane.LifeID, Run: lane.Run})
	if err != nil {
		return failure(err)
	}
	lane.CredentialSpend = balance
	return nil
}
