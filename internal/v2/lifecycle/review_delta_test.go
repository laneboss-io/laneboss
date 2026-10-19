package lifecycle

import (
	"context"
	"errors"
	"testing"

	"laneboss.io/laneboss/internal/v2/api"
)

type resolvedProfileFixture struct {
	api.GrantResolver
	profile api.ProfileGrant
}

func (r resolvedProfileFixture) ResolveProfile(context.Context, api.Scope, api.GrantResolveRequest) (api.ProfileGrant, error) {
	return r.profile, nil
}

func TestRunnerPlanFullProfile(t *testing.T) {
	resolved := api.ProfileGrant{ID: "profile-grant", ProfileID: "profile", Driver: api.DriverCodex,
		Provider: "resolved-provider", ExpiresAt: "2030-01-01T00:00:00Z"}
	s := &Service{deps: Dependencies{Grants: resolvedProfileFixture{profile: resolved}, Clock: fixtureClock{}}}
	execution := &planExecution{service: s, record: api.LaunchPlanRecord{Reservation: api.LaunchReservation{Mode: "start"}},
		input: launchInput{driver: api.DriverCodex, profile: resolved.ID, budget: api.Budget{SpendMicros: 1}}}
	inputs := api.LaunchInputs{Grants: api.GrantSet{Profiles: []api.ProfileGrant{{ID: resolved.ID, ProfileID: resolved.ProfileID,
		Driver: resolved.Driver, Provider: "retained-provider", ExpiresAt: resolved.ExpiresAt}}}}
	_, _, err := execution.runnerPlan(context.Background(), inputs, api.LaunchData{})
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeForbidden {
		t.Fatalf("mutated resolved profile reached later runner work: %v", err)
	}
}
