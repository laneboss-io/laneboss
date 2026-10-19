package secrets

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
	"testing"
)

// Existing post-authentication fixtures install a denying identity port. They
// cannot accidentally authorize a projection or masquerade as a native helper.
type deniedProjection struct{}

func (deniedProjection) AuthorizeCredentialProjection(context.Context, api.VerifiedPeer, api.CredentialProjectionRequest) (api.CredentialProjectionAuthority, error) {
	return api.CredentialProjectionAuthority{}, api.NotImplemented("lb-v2-identity", "fixture projection identity is not installed")
}
func (deniedProjection) CheckLaunchCredentials(context.Context, api.LaunchBindingRequest) (api.CredentialProjectionRecord, error) {
	return api.CredentialProjectionRecord{}, api.NotImplemented("lb-v2-identity", "fixture projection identity is not installed")
}

func TestProjectionDeps(t *testing.T) {
	s, _, _, _ := serviceFixture(t)
	deps := s.deps
	deps.ProjectionIdentity = nil
	_, err := New(deps)
	stageCode(t, err, api.CodePrerequisite)
}
