package linux

import (
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func TestAgentInjectStage(t *testing.T) {
	spec := fixtureSpec()
	spec.Kind, spec.Worker = "agent", nil
	spec.Runner = &api.RunnerPlan{Slot: api.CredentialSlot{ID: "profile-slot"}}
	spec.Injection.SlotIDs = []api.ID{spec.Runner.Slot.ID}
	spec.Injection.Outcome = "prepared"
	if err := validateInjection(spec, time.Now()); err != nil {
		t.Fatal("broker preparation cannot enter native projection", err)
	}
	spec.Injection.Outcome = "ready"
	if err := validateInjection(spec, time.Now()); err == nil {
		t.Fatal("agent preparation accepted an invented native readiness marker")
	}
}
