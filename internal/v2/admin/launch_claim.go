package admin

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// CheckLaunchPlanningAuthority is the read-only reservation authority check
// shared by installed launch-source adapters. It neither installs a helper nor
// resolves host paths. The durable claim, original request, operation, grants,
// policy and cancellation fence use the same launchAuthority path.
func CheckLaunchPlanningAuthority(ctx context.Context, store api.StateStore, config string, claim api.LaunchClaim) (api.LaunchPlanRecord, error) {
	s := &Service{deps: Dependencies{Store: store, Config: config}}
	authority, err := s.launchAuthority(ctx, claim.ReservationID, "", nil, claim)
	if err != nil {
		return api.LaunchPlanRecord{}, err
	}
	return authority.Record, nil
}

// CheckLaunchStageAuthority is the installed in-process stage adapter's
// preflight. It requires the caller's explicit effect lease in ctx and checks
// the same live claim and cancellation fence as the native helper client.
// It does not prepare, open, stop or release a native process.
func CheckLaunchStageAuthority(ctx context.Context, state api.StateStore, config string, cause api.InternalIntent, kind api.InternalKind) (api.EffectRecord, error) {
	s := &Service{deps: Dependencies{Store: state, Config: config}}
	return s.currentStage(ctx, cause, kind)
}
