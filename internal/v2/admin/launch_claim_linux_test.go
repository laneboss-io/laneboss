//go:build linux

package admin

import "laneboss.io/laneboss/internal/v2/api"

func fixtureLaunchClaim(store *launchFixtureStore) api.LaunchClaim {
	return api.PlanningClaim(store.plan.Reservation.ID, api.EffectLease{Record: store.claim, ClaimID: store.claim.ClaimID, ExpiresAt: store.claim.ClaimExpiresAt})
}
