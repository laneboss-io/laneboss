package assembly

import (
	"context"
	"sync"

	"laneboss.io/laneboss/internal/v2/api"
)

// Installed into every launcher consumer before construction finishes.
type projectionLauncher struct {
	api.Launcher
	binder      api.CredentialProjectionBinder
	mu          sync.Mutex
	credentials api.CredentialProjectionBroker
	identity    api.CredentialProjectionIdentity
	configured  bool
	configuring bool
	attempted   bool
	bindingErr  error
}

func (l *projectionLauncher) bindRuntime(ctx context.Context, host api.ServiceHost, services api.RuntimeServices) error {
	l.mu.Lock()
	if l.configured || l.configuring || services.Launcher != l || host == nil {
		l.mu.Unlock()
		return &api.Error{Code: api.CodeConflict, Owner: "lb-v2-integrate", Message: "projection runtime binding is absent or repeated"}
	}
	l.configuring = true
	l.credentials, l.identity = services.Credentials, services.CredentialIdentity
	l.mu.Unlock()
	err := host.BindRuntime(ctx, services)
	l.mu.Lock()
	l.configuring, l.configured = false, err == nil
	l.mu.Unlock()
	return err
}

// Only this complete empty-authority materialization shape may avoid binding.
func projectionRequired(spec api.LaunchSpec) bool {
	return !(spec.Kind == "worker" && spec.Worker != nil && spec.Worker.Kind == "materialize" &&
		spec.Runner == nil && spec.Capture == nil && spec.PlanID == "" &&
		len(spec.Grants.Secrets)+len(spec.Grants.Profiles)+len(spec.Grants.Channels)+len(spec.Grants.Resources)+len(spec.Grants.Data)+len(spec.Grants.Network) == 0 &&
		len(spec.Injection.SlotIDs)+len(spec.Injection.GrantIDs)+len(spec.Injection.TaskSecretNames)+len(spec.Injection.TaskSecretFileNames)+len(spec.Injection.SourceVersions) == 0 &&
		spec.Injection.Outcome == "" && spec.Injection.Target == (api.LifeRef{}))
}

func (l *projectionLauncher) bindProjection(required bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.configured || l.binder == nil || l.credentials == nil || l.identity == nil {
		return api.NotImplemented("lb-v2-admin", "admin.BindCredentialProjection")
	}
	if !required {
		return nil
	}
	if !l.attempted {
		l.attempted = true
		l.bindingErr = l.binder.BindCredentialProjection(l.credentials, l.identity)
		if api.CredentialBindingRetryable(l.bindingErr) {
			l.attempted = false
		}
	}
	return l.bindingErr
}

func (l *projectionLauncher) Prepare(ctx context.Context, spec api.LaunchSpec) (api.PreparedLaunch, error) {
	if err := ctx.Err(); err != nil {
		return api.PreparedLaunch{}, err
	}
	if err := l.bindProjection(projectionRequired(spec)); err != nil {
		api.ObserveHelperReason(ctx, err, "cred_bind")
		return api.PreparedLaunch{}, err
	}
	return l.Launcher.Prepare(ctx, spec)
}

// Recovery has no trusted LaunchSpec here, so every Launch requires binding.
func (l *projectionLauncher) Launch(ctx context.Context, prepared api.PreparedLaunch, permit api.LaunchPermit) (api.ProcessHandle, error) {
	if err := ctx.Err(); err != nil {
		return api.ProcessHandle{}, err
	}
	if err := l.bindProjection(true); err != nil {
		api.ObserveHelperReason(ctx, err, "cred_bind")
		return api.ProcessHandle{}, err
	}
	return l.Launcher.Launch(ctx, prepared, permit)
}
