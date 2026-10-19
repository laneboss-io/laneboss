//go:build !linux

package linux

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

type Registry struct{}

func NewRegistry() (*Registry, error) {
	return nil, peerError(api.CodeUnsupported, "Linux containment registry requires Linux")
}
func (*Registry) RegisterContainment(context.Context, api.ContainmentBinding) error {
	return peerError(api.CodeUnsupported, "Linux containment registry requires Linux")
}
func (*Registry) ResolveContainment(context.Context, api.PeerFacts, api.InstalledBinding) (api.ContainmentBinding, error) {
	return api.ContainmentBinding{}, peerError(api.CodeUnsupported, "Linux containment registry requires Linux")
}
func (*Registry) RevokeContainment(context.Context, api.ID) error {
	return peerError(api.CodeUnsupported, "Linux containment registry requires Linux")
}
func (*Registry) Close() error { return nil }
