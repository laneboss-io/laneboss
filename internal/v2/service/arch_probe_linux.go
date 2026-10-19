//go:build linux && laneboss_root_canary

package service

import (
	"context"
	"path/filepath"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

type ArchiveProbe struct {
	host   *Server
	cancel context.CancelFunc
}

// OpenArchiveProbe connects the native administrator canary to the installed
// worker listener. The caller supplies the real identity service and store;
// no request, authentication verdict or worker result is synthesized here.
func OpenArchiveProbe(ctx context.Context, deps Dependencies, endpoint api.InstalledBinding) (*ArchiveProbe, error) {
	options := Options{Config: deps.Binding.Config,
		BindingFile: filepath.Join("/etc/laneboss-v2/bindings", deps.Binding.Config+".json")}
	host, err := installedServer(options, deps)
	if err != nil {
		return nil, err
	}
	host.bound = true
	workerCtx, cancel := context.WithCancel(ctx)
	if err := host.startWorkerEndpoint(workerCtx, endpoint.WorkerLeaseID, endpoint); err != nil {
		cancel()
		return nil, err
	}
	return &ArchiveProbe{host: host, cancel: cancel}, nil
}

func (p *ArchiveProbe) Close() error {
	p.cancel()
	p.host.workers.Wait()
	return p.host.fault
}

// Observe uses the same owner path as runArchive, beside the same listener.
func (p *ArchiveProbe) Observe(ctx context.Context, helper archiveHelper, job archivejob.Job, lease api.EffectLease) (api.ProcessObservation, error) {
	return p.host.observeArchive(ctx, helper, job, lease)
}

// Complete resumes the original opened job through native retirement and the
// writer's independent byte verification and committed archive receipt.
func (p *ArchiveProbe) Complete(ctx context.Context, helper api.HelperControl, scope api.Scope, lease api.EffectLease) (api.EffectOutcome, error) {
	p.host.mu.Lock()
	p.host.runtime.Helper = helper
	p.host.mu.Unlock()
	return p.host.runArchive(ctx, scope, lease)
}
