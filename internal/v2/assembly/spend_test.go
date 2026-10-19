package assembly

import (
	"context"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type spendRunnerStore struct {
	api.StateStore
	balances map[api.ID]api.SpendBalance
	checks   int
}

func (s *spendRunnerStore) CheckCredentialSpend(_ context.Context, slot api.CredentialSlot) (api.SpendBalance, error) {
	s.checks++
	b, ok := s.balances[slot.ProfileID]
	if !ok {
		return b, runError(api.CodePrerequisite, "API credential spend reading is missing")
	}
	if b.RemainingMicros <= b.FloorMicros {
		return b, runError(api.CodeBudget, "API credential spend floor reached")
	}
	return b, nil
}

func TestSpendRunnerDispatch(t *testing.T) {
	for _, method := range []string{"start", "resume", "turn"} {
		t.Run(method, func(t *testing.T) {
			request := enrollmentRunnerRequest()
			request.Slot.Mode = "claude-api-key"
			request.Session.Driver = api.DriverClaudock
			state := &spendRunnerStore{balances: map[api.ID]api.SpendBalance{request.Slot.ProfileID: {RemainingMicros: 5000000, FloorMicros: 5000000}}}
			vendor := &enrollmentRunnerFixture{}
			runner := guardRunnerEnrollment(vendor, Installation{}, api.DriverClaudock, runnerDependencies{Store: state})
			var err error
			switch method {
			case "start":
				_, err = runner.Start(context.Background(), request)
			case "resume":
				_, err = runner.Resume(context.Background(), request)
			case "turn":
				_, err = runner.Turn(context.Background(), request)
			}
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeBudget || state.checks != 1 || vendor.starts != 0 {
				t.Fatal("runner dispatch failed to consult the credential floor", err)
			}
		})
	}
}
