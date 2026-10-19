package assembly

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
	"laneboss.io/laneboss/internal/v2/runner/codex"
)

type runnerDependencies struct {
	Store           api.StateStore
	Clock           api.Clock
	Sources         api.LaunchSourceResolver
	Storage         api.LaunchStorageResolver
	Grants          api.GrantResolver
	Credentials     api.CredentialBroker
	UsageWindows    api.UsageWindowSource
	Materialization api.MaterializationControl
	Capture         api.CaptureControl
}

// Construct the actual vendor adapters with the stable installed service ports.
// Their strict per-run constructors still guard every plan/capture operation;
// an absent vendor enrollment must not prevent public service health startup.
func realRunners(installed Installation, deps runnerDependencies) (api.Runner, api.Runner, error) {
	var capture func(context.Context, api.ID) (api.CaptureRecord, []byte, error)
	if source, ok := deps.Store.(interface {
		CaptureFrame(context.Context, api.ID) (api.CaptureRecord, []byte, error)
	}); ok {
		capture = source.CaptureFrame
	}
	var usageWorker func(context.Context, api.Scope, api.ID) (api.InstalledBinding, api.PeerFacts, error)
	var usageProfile func(context.Context, api.ProfileGrant) (string, error)
	if source, ok := deps.UsageWindows.(interface {
		UsageWorker(context.Context, api.Scope, api.ID) (api.InstalledBinding, api.PeerFacts, error)
		UsageProfile(context.Context, api.ProfileGrant) (string, error)
	}); ok {
		usageWorker, usageProfile = source.UsageWorker, source.UsageProfile
	}
	bindings, err := realBindings(installed, deps, claudock.Dependencies{
		Config: installed.Config, State: deps.Store, Clock: deps.Clock,
		Sources: deps.Sources, Storage: deps.Storage, Grants: deps.Grants,
		Credentials: deps.Credentials, UsageWindows: deps.UsageWindows, CaptureControl: deps.Capture,
		Capture:     capture,
		UsageWorker: usageWorker, UsageProfile: usageProfile})
	if err != nil {
		return nil, nil, err
	}
	claude, err := claudock.NewInstalled(bindings)
	if err != nil {
		if bindings.Records != nil {
			if closeErr := bindings.Records.Close(); closeErr != nil {
				return nil, nil, closeErr
			}
		}
		return nil, nil, err
	}
	boundClaude := &realRunner{Runner: claude, records: bindings.Records}
	if bindings.Records != nil {
		boundClaude.capture = &realCapture{deps: bindings, runtime: installed.RuntimeManifest}
	}
	codexDriver, err := codex.NewInstalled(codex.Dependencies{
		Store: deps.Store, Clock: deps.Clock,
		ReadScope: api.Scope{Config: installed.Config},
		Sources:   deps.Sources, Storage: deps.Storage, Materialization: deps.Materialization,
		UsageWindows: deps.UsageWindows, UsageWorker: usageWorker, UsageProfile: usageProfile})
	if err != nil {
		if closeErr := boundClaude.Close(); closeErr != nil {
			return nil, nil, closeErr
		}
		return nil, nil, err
	}
	return boundClaude, codexDriver, nil
}
