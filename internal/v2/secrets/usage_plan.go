package secrets

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/secrets/wire"
)

// UsageWorkerInput returns metadata from the protected enrolled profile only.
// It is an in-process composition capability, never a new socket operation.
func (s *Service) UsageWorkerInput(ctx context.Context, scope api.Scope, request api.UsageWindowRequest) (api.UsageCredentialInput, error) {
	if err := wire.Context(ctx); err != nil {
		return api.UsageCredentialInput{}, err
	}
	if err := s.usageReadScope(ctx, scope); err != nil {
		return api.UsageCredentialInput{}, err
	}
	profile, err := s.usageProfile(ctx, request)
	if err != nil {
		return api.UsageCredentialInput{}, err
	}
	return api.UsageCredentialInput{Schema: "laneboss.usage-input.v1", Request: request,
		VendorProfile: profile.Usage.VendorProfile, ProfileGeneration: profile.Generation, Source: profile.Source}, nil
}
