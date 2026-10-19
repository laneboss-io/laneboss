package secrets

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

// Component callers now pass the actual fixture's retained selector explicitly.
// The broker still reloads Effect and the reservation; this supplies no result.
func (c *launchCase) selection(ctx context.Context) (launchSelection, error) {
	if err := ctx.Err(); err != nil {
		return launchSelection{}, err
	}
	var effect api.EffectRecord
	if err := c.store.read("effect.json", &effect); err != nil {
		return launchSelection{}, err
	}
	var storage api.LaunchStorage
	if err := c.store.read("storage.json", &storage); err != nil {
		return launchSelection{}, err
	}
	return launchSelection{Claim: api.PlanningClaim(c.store.planID, api.EffectLease{Record: effect, ClaimID: effect.ClaimID, ExpiresAt: effect.ClaimExpiresAt}), HelperLeaseID: storage.LeaseID}, nil
}

func (c *launchCase) acquire(ctx context.Context, target api.LifeRef, grant api.ProfileGrant) (api.CredentialSlot, error) {
	selection, err := c.selection(ctx)
	if err != nil {
		return api.CredentialSlot{}, err
	}
	return c.service.AcquireLaunch(ctx, api.LaunchProfileRequest{Claim: selection.Claim, HelperLeaseID: selection.HelperLeaseID, Target: target, Grant: grant})
}

func (c *launchCase) inject(ctx context.Context, target api.LifeRef, grants []api.SecretGrant) (api.Injection, error) {
	selection, err := c.selection(ctx)
	if err != nil {
		return api.Injection{}, err
	}
	return c.service.InjectLaunch(ctx, api.LaunchInjectionRequest{Claim: selection.Claim, HelperLeaseID: selection.HelperLeaseID, Target: target, Grants: grants})
}
