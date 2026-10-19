//go:build linux

package service

import (
	"context"
	"testing"
	"time"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
	"laneboss.io/laneboss/internal/v2/grants"
)

// The wrapper first runs the real resolver. It then introduces disagreement
// at the profile-return boundary while retaining the actual issued store set.
type reviewProfileResolver struct {
	*grants.Service
	mutation string
	calls    int
}

func (r *reviewProfileResolver) ResolveProfile(ctx context.Context, scope api.Scope, request api.GrantResolveRequest) (api.ProfileGrant, error) {
	profile, err := r.Service.ResolveProfile(ctx, scope, request)
	if err != nil {
		return profile, err
	}
	r.calls++
	switch r.mutation {
	case "profile":
		profile.ProfileID += "-changed"
	case "provider":
		profile.Provider += "-changed"
	case "paid":
		profile.Paid = !profile.Paid
	case "delegate":
		profile.Delegate = !profile.Delegate
	case "expiry":
		profile.ExpiresAt = api.Timestamp(time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano))
	}
	return profile, nil
}

type reviewOncePlanner struct {
	api.LaunchPlanner
	state *planningPolicyStore
	stop  context.CancelFunc
}

func (p *reviewOncePlanner) PlanLaunch(ctx context.Context, scope api.Scope, request api.LaunchPlanRequest) (api.LaunchPlan, error) {
	plan, err := p.LaunchPlanner.PlanLaunch(ctx, scope, request)
	p.state.planningErr = err
	if err == nil {
		p.state.planned = &plan
	}
	p.stop()
	return plan, err
}

func TestReviewPlannerProfileMember(t *testing.T) {
	for _, mutation := range []string{"valid", "profile", "provider", "paid", "delegate", "expiry"} {
		t.Run(mutation, func(t *testing.T) {
			f, _, effect := scopePlanningFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			state := &planningPolicyStore{Service: f.State, effect: effect.ID}
			var resolver *reviewProfileResolver
			planner := successfulScopePlannerGrants(t, state, f, effect, func(real *grants.Service) api.GrantResolver {
				resolver = &reviewProfileResolver{Service: real, mutation: mutation}
				return resolver
			})
			host := fixtureServer(t)
			host.options.Config, host.deps.Store, host.deps.Clock = f.Deps.Config, state, f.Deps.Clock
			host.runtime = api.RuntimeServices{Store: state, LaunchPlanner: &reviewOncePlanner{LaunchPlanner: planner, state: state, stop: cancel},
				Helper: &admin.Service{}, Worker: &dataworker.Service{}, Launcher: &healthLauncher{}}
			host.reconcileLoop(ctx)
			if resolver.calls != 1 || host.fault != nil {
				t.Fatal("profile comparison did not follow actual resolver and reconciliation", host.fault, state.planningErr)
			}
			if mutation == "valid" {
				if state.planningErr != nil || state.planned == nil {
					t.Fatal("real identical profile control failed", state.planningErr)
				}
			} else if state.planningErr == nil || state.planned != nil || len(state.credentialClaims) != 0 {
				t.Fatal("planner accepted a resolved profile member differing from retained grants", state.planningErr)
			}
			if err := host.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
