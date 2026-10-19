package lifecycle

import (
	"context"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type spendPlanStore struct {
	*launchFixtureStore
	balances map[api.ID]api.SpendBalance
	checks   int
}

func (s *spendPlanStore) CheckCredentialSpend(_ context.Context, slot api.CredentialSlot) (api.SpendBalance, error) {
	s.checks++
	b, ok := s.balances[slot.ProfileID]
	if !ok {
		return b, &api.Error{Code: api.CodePrerequisite, Message: "credential spend reading is missing"}
	}
	if b.RemainingMicros <= b.FloorMicros {
		return b, &api.Error{Code: api.CodeBudget, Message: "credential spend floor reached"}
	}
	return b, nil
}

type spendKeyBroker struct{ *launchFixturePorts }

func (p *spendKeyBroker) Acquire(ctx context.Context, target api.LifeRef, grant api.ProfileGrant) (api.CredentialSlot, error) {
	slot, err := p.launchFixturePorts.Acquire(ctx, target, grant)
	if err != nil {
		return slot, err
	}
	slot.Mode = "claude-api-key"
	p.slots[target] = slot
	return slot, nil
}

func TestSpendLifecycleLaunch(t *testing.T) {
	for _, name := range []string{"missing", "floor", "above", "capture_refused", "recovery_floor"} {
		t.Run(name, func(t *testing.T) {
			f := newLaunchFixture(t)
			f.request.Driver, f.ports.enrollment.Runtimes[0].Driver = api.DriverClaudock, api.DriverClaudock
			for i := range f.ports.delegated.Profiles {
				f.ports.delegated.Profiles[i].Driver = api.DriverClaudock
			}
			profile := f.ports.delegated.Profiles[0].ProfileID
			state := &spendPlanStore{launchFixtureStore: f.store, balances: map[api.ID]api.SpendBalance{profile: {RemainingMicros: 5000001, FloorMicros: 5000000}}}
			if name == "missing" {
				delete(state.balances, profile)
			}
			if name == "floor" {
				state.balances[profile] = api.SpendBalance{RemainingMicros: 5000000, FloorMicros: 5000000}
			}
			f.service.deps.Store = state
			f.service.deps.Credentials = &spendKeyBroker{f.ports}
			f.service.deps.Claudock = f.ports
			f.scope = f.fixture.scope("lane.start", f.request, f.parent)
			if name == "capture_refused" {
				f.ports.refuseCapture = true
				f.allowCaptureRefusal()
			}
			_, record := f.reserve(t)
			scope, request := f.claim(t, record)
			_, err := f.service.PlanLaunch(context.Background(), scope, request)
			if name == "above" || name == "recovery_floor" {
				if err != nil || state.checks == 0 {
					t.Fatal("funded API launch did not consult its balance", err)
				}
				if name == "above" {
					return
				}
				state.balances[profile] = api.SpendBalance{RemainingMicros: 5000000, FloorMicros: 5000000}
				_, err = f.service.PlanLaunch(context.Background(), scope, request)
			}
			want := api.CodeBudget
			if name == "missing" || name == "capture_refused" {
				want = api.CodePrerequisite
			}
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != want {
				t.Fatal("API launch or recovery escaped its spend gate", err)
			}
			if name != "recovery_floor" && f.store.plans[record.Reservation.ID].Handoff != nil {
				t.Fatal("refused spend gate retained an executable launch handoff")
			}
			if f.ports.calls["acquire"] != 1 {
				t.Fatal("spend refusal acquired another credential slot")
			}
		})
	}
}
