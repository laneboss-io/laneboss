//go:build linux

package admin

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// These test-only bridges let external-package regressions use the actual
// store (which itself imports admin) without a package import cycle.
func ReviewCurrentStage(ctx context.Context, state api.StateStore, config string, cause api.InternalIntent, kind api.InternalKind) (api.EffectRecord, error) {
	s := &Service{deps: Dependencies{Config: config, Store: state}}
	return s.currentStage(ctx, cause, kind)
}

func ReviewLaunchAuthority(ctx context.Context, state api.StateStore, config string, reservation api.ID, cause *api.InternalIntent, planning ...api.LaunchClaim) (api.LaunchPlanRecord, error) {
	s := &Service{deps: Dependencies{Config: config, Store: state}}
	authority, err := s.launchAuthority(ctx, reservation, "", cause, planning...)
	return authority.Record, err
}

func ReviewRetainedProfile(ctx context.Context, state api.StateStore, scope api.Scope, record api.LaunchPlanRecord) (api.ID, error) {
	s := &Service{deps: Dependencies{Config: scope.Config, Store: state}}
	input, err := s.retainedLaunchInput(ctx, launchAuthority{Record: record, Scope: scope})
	return input.ProfileID, err
}
