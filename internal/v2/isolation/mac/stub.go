// Package mac is owned by lb-v2-darwin.
package mac

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
)

type Dependencies struct {
	Helper          api.HelperControl
	RuntimeManifest api.BlobRef
	Controls        api.LaunchControlSource
}

type Service struct {
	deps Dependencies
}

func New(deps Dependencies) (*Service, error) {
	// TODO(lb-v2-darwin): initialize the component without a permissive fallback.
	return nil, api.NotImplemented("lb-v2-darwin", "isolation/mac.New")
}

var _ api.Launcher = (*Service)(nil)

func (s *Service) Probe(ctx context.Context) (api.IsolationCapabilities, error) {
	// TODO(lb-v2-darwin): implement Probe under the frozen contract.
	var result api.IsolationCapabilities
	return result, api.NotImplemented("lb-v2-darwin", "isolation/mac.Probe")
}

func (s *Service) Prepare(ctx context.Context, spec api.LaunchSpec) (api.PreparedLaunch, error) {
	// TODO(lb-v2-darwin): implement Prepare under the frozen contract.
	var result api.PreparedLaunch
	return result, api.NotImplemented("lb-v2-darwin", "isolation/mac.Prepare")
}

func (s *Service) Launch(ctx context.Context, prepared api.PreparedLaunch, permit api.LaunchPermit) (api.ProcessHandle, error) {
	// TODO(lb-v2-darwin): implement Launch under the frozen contract.
	var result api.ProcessHandle
	return result, api.NotImplemented("lb-v2-darwin", "isolation/mac.Launch")
}

func (s *Service) Observe(ctx context.Context, process api.ProcessHandle) (api.ProcessObservation, error) {
	// TODO(lb-v2-darwin): implement Observe under the frozen contract.
	var result api.ProcessObservation
	return result, api.NotImplemented("lb-v2-darwin", "isolation/mac.Observe")
}

func (s *Service) Stop(ctx context.Context, process api.ProcessHandle, reason string) (api.ProcessObservation, error) {
	// TODO(lb-v2-darwin): implement Stop under the frozen contract.
	var result api.ProcessObservation
	return result, api.NotImplemented("lb-v2-darwin", "isolation/mac.Stop")
}

func (s *Service) Abort(ctx context.Context, prepared api.PreparedLaunch) error {
	// TODO(lb-v2-darwin): implement Abort under the frozen contract.
	return api.NotImplemented("lb-v2-darwin", "isolation/mac.Abort")
}

func (s *Service) Collect(ctx context.Context, leaseID api.ID, observation api.ProcessObservation) error {
	// TODO(lb-v2-darwin): implement Collect under the frozen contract.
	return api.NotImplemented("lb-v2-darwin", "isolation/mac.Collect")
}
