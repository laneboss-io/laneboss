package credn

import (
	"context"
	"reflect"
	"sync"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/dataworker"
)

// Allocate before the store, bind once to the real administrator client before
// publishing the installed graph. Every read crosses the native helper port.
type Source struct {
	mu      sync.RWMutex
	helper  admin.CredentialProjectionSource
	workers *dataworker.Service
}

func New() *Source { return &Source{} }

func (p *Source) BindWorkers(workers *dataworker.Service) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if workers == nil || p.workers != nil {
		return &api.Error{Code: api.CodeConflict, Owner: "lb-v2-integrate", Message: "credential worker inventory binding is absent or repeated"}
	}
	p.workers = workers
	return nil
}

func (p *Source) BindNative(helper admin.CredentialProjectionSource) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if helper == nil || reflect.ValueOf(helper).Kind() == reflect.Pointer && reflect.ValueOf(helper).IsNil() || p.helper != nil {
		return &api.Error{Code: api.CodeConflict, Owner: "lb-v2-integrate", Message: "credential native binding requires one real administrator client"}
	}
	p.helper = helper
	return nil
}

func (p *Source) client() (admin.CredentialProjectionSource, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.helper == nil {
		return nil, &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-service", Message: "credential projection requires its installed native metadata source"}
	}
	return p.helper, nil
}

func (p *Source) ResolveCredentialProjection(ctx context.Context, scope api.Scope, request api.CredentialProjectionRequest) (api.CredentialProjectionAuthority, error) {
	helper, err := p.client()
	if err != nil {
		return api.CredentialProjectionAuthority{}, err
	}
	if request.Handoff.Spec.Kind == "worker" {
		p.mu.RLock()
		workers := p.workers
		p.mu.RUnlock()
		if workers == nil {
			return api.CredentialProjectionAuthority{}, &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-integrate", Message: "credential worker requires its installed protected inventory"}
		}
		selected, err := workers.CredentialWorkerSelection(ctx, scope, request.Handoff)
		if err != nil {
			return api.CredentialProjectionAuthority{}, err
		}
		if request.Worker == nil || selected.Lease != *request.Worker || !reflect.DeepEqual(selected.Credentials, request.WorkerCredentials) {
			return api.CredentialProjectionAuthority{}, &api.Error{Code: api.CodeForbidden, Owner: "lb-v2-integrate", Message: "credential worker differs from its installed protected selection"}
		}
	}
	return helper.ResolveCredentialProjection(ctx, scope, request)
}

func (p *Source) ObserveCredentialProjection(ctx context.Context, authority api.CredentialProjectionAuthority) (api.CredentialProjectionReceipt, error) {
	helper, err := p.client()
	if err != nil {
		return api.CredentialProjectionReceipt{}, err
	}
	return helper.ObserveCredentialProjection(ctx, authority)
}
