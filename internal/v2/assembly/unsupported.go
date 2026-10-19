package assembly

import (
	"context"
	"runtime"

	"laneboss.io/laneboss/internal/v2/api"
)

type unavailableLauncher struct{ backend, owner string }

func unavailablePlatform(backend, owner string) api.Launcher {
	return &unavailableLauncher{backend: backend, owner: owner}
}

func (u *unavailableLauncher) refusal() *api.Error {
	return &api.Error{Code: api.CodeUnsupported, Owner: u.owner,
		Message: "selected isolation backend is unavailable on " + runtime.GOOS,
		Instead: "Use a supported installed backend on its required operating system."}
}

func (u *unavailableLauncher) Probe(ctx context.Context) (api.IsolationCapabilities, error) {
	if err := ctx.Err(); err != nil {
		return api.IsolationCapabilities{}, err
	}
	return api.IsolationCapabilities{Backend: u.backend, Available: false,
		Checks: []api.Capability{{Name: "isolation." + u.backend, Available: false, Reason: u.refusal().Message}}}, nil
}
func (u *unavailableLauncher) Prepare(context.Context, api.LaunchSpec) (api.PreparedLaunch, error) {
	return api.PreparedLaunch{}, u.refusal()
}
func (u *unavailableLauncher) Launch(context.Context, api.PreparedLaunch, api.LaunchPermit) (api.ProcessHandle, error) {
	return api.ProcessHandle{}, u.refusal()
}
func (u *unavailableLauncher) Observe(context.Context, api.ProcessHandle) (api.ProcessObservation, error) {
	return api.ProcessObservation{}, u.refusal()
}
func (u *unavailableLauncher) Stop(context.Context, api.ProcessHandle, string) (api.ProcessObservation, error) {
	return api.ProcessObservation{}, u.refusal()
}
func (u *unavailableLauncher) Abort(context.Context, api.PreparedLaunch) error { return u.refusal() }
func (u *unavailableLauncher) Collect(context.Context, api.ID, api.ProcessObservation) error {
	return u.refusal()
}
