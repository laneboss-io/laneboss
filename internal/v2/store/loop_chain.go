package store

import (
	"context"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// Automatic turns have no post-exit delegation lease. Every retained starter
// must still be active under the same protected policy and sealed grants.
func (s *Service) loopChain(ctx context.Context, db queryer, lane api.Lane, policy api.Generation) error {
	seen := map[api.ID]bool{}
	for {
		if seen[lane.LifeID] || len(seen) >= 4 {
			return fault(api.CodeIntegrity, "loop starter ancestry is cyclic or too deep")
		}
		seen[lane.LifeID] = true
		if lane.Cleaned {
			return fault(api.CodeForbidden, "loop starter was collected")
		}
		switch lane.State {
		case "preparing", "running", "stopping", "verifying", "idle", "profile_wait":
		default:
			return fault(api.CodeForbidden, "loop starter no longer has active delegation")
		}
		var grants api.GrantSet
		if err := storedProjection(ctx, db, "grants", lane.GrantSetID, &grants); err != nil {
			return err
		}
		if lane.PolicyGeneration != policy || grants.PolicyGeneration != policy {
			return fault(api.CodeConflict, "loop starter policy changed")
		}
		if grants.ID != lane.GrantSetID || grants.LifeID != lane.LifeID || grants.ParentLifeID != lane.ParentLifeID ||
			grants.Revoked || !future(grants.ExpiresAt, s.deps.Clock.Now()) {
			return fault(api.CodeForbidden, "loop starter grants are revoked, expired or foreign")
		}
		if err := manifest.Set(grants, s.deps.Clock.Now()); err != nil {
			return err
		}
		sealed := grants
		sealed.SHA256 = ""
		raw, err := canonicalValue(sealed)
		if err != nil {
			return err
		}
		if api.Digest(hash(raw)) != grants.SHA256 {
			return fault(api.CodeIntegrity, "loop starter grant seal changed")
		}
		if lane.ParentLifeID == "" {
			if lane.RootLifeID != lane.LifeID || len(lane.StarterChain) != 0 {
				return fault(api.CodeIntegrity, "loop root lost its authentic ancestry")
			}
			return nil
		}
		var parent api.Lane
		if err := storedProjection(ctx, db, "lane", lane.ParentLifeID, &parent); err != nil {
			return err
		}
		if parent.Level <= lane.Level || parent.Level > 6 || parent.RootLifeID != lane.RootLifeID ||
			!slices.Equal(lane.StarterChain, append(append([]api.ID{}, parent.StarterChain...), parent.LifeID)) {
			return fault(api.CodeIntegrity, "loop lost its authentic strict-lower starter edge")
		}
		lane = parent
	}
}
