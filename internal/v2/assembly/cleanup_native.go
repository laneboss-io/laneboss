package assembly

import (
	"context"
	"sync"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/store"
)

// The store precedes the administrator client, which itself needs the store.
// Bind this private capability once, before publishing the installed server.
// Every operation calls the real administrator client and its native helper;
// an unbound capability has neither readiness nor a successful fallback.
type helperCleanupNative struct {
	mu     sync.RWMutex
	helper *admin.Service
}

var _ store.CleanupNative = (*helperCleanupNative)(nil)
var _ archivejob.Native = (*helperCleanupNative)(nil)

func (p *helperCleanupNative) bind(helper *admin.Service) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if helper == nil || p.helper != nil {
		return &api.Error{Code: api.CodeConflict, Owner: "lb-v2-integrate", Message: "cleanup native binding requires one real administrator client", Instead: "Construct a fresh installed service with its original helper."}
	}
	p.helper = helper
	return nil
}

func (p *helperCleanupNative) CleanupNativeReady() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.helper != nil
}

func (p *helperCleanupNative) client() (*admin.Service, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.helper == nil {
		return nil, api.NotImplemented("lb-v2-admin", "installed protected cleanup native ports")
	}
	return p.helper, nil
}

func (p *helperCleanupNative) ResolveCleanupWorkspace(ctx context.Context, target api.LifeRef, id api.ID) (api.CleanupWorkspace, error) {
	helper, err := p.client()
	if err != nil {
		return api.CleanupWorkspace{}, err
	}
	return helper.ResolveCleanupWorkspace(ctx, target, id)
}

func (p *helperCleanupNative) ReadWorkspaceRemoval(ctx context.Context, job api.CleanupJob) (api.WorkspaceRemoval, error) {
	helper, err := p.client()
	if err != nil {
		return api.WorkspaceRemoval{}, err
	}
	return helper.ReadWorkspaceRemoval(ctx, job)
}

func (p *helperCleanupNative) ReadCleanupWorkspace(ctx context.Context, job api.CleanupJob) (api.WorkspaceReadback, error) {
	helper, err := p.client()
	if err != nil {
		return api.WorkspaceReadback{}, err
	}
	return helper.ReadCleanupWorkspace(ctx, job)
}

func (p *helperCleanupNative) ReadCleanupRuntime(ctx context.Context, ref api.BlobRef) (api.CleanupObject, error) {
	helper, err := p.client()
	if err != nil {
		return api.CleanupObject{}, err
	}
	return helper.ReadCleanupRuntime(ctx, ref)
}

func (p *helperCleanupNative) ReadCleanupRuntimeManifest(ctx context.Context) (api.BlobRef, api.RuntimeManifest, error) {
	helper, err := p.client()
	if err != nil {
		return api.BlobRef{}, api.RuntimeManifest{}, err
	}
	return helper.ReadCleanupRuntimeManifest(ctx)
}

func (p *helperCleanupNative) FreezeArchive(ctx context.Context, intent archivejob.Intent, lane api.Lane) (archivejob.Snapshot, error) {
	helper, err := p.client()
	if err != nil {
		return archivejob.Snapshot{}, err
	}
	return helper.FreezeArchive(ctx, intent, lane)
}

func (p *helperCleanupNative) CheckArchiveFreeze(ctx context.Context, intent archivejob.Intent, frozen archivejob.Freeze) error {
	helper, err := p.client()
	if err != nil {
		return err
	}
	return helper.CheckArchiveFreeze(ctx, intent, frozen)
}
