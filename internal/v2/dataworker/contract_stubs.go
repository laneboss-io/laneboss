// Contract draft.3 consumer stubs. These fail until the owning lane ports
// its implementation; no interface-only change is runtime acceptance.
package dataworker

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

var _ api.OrgPublisher = (*Service)(nil)

func (s *Service) PublishChange(arg0 context.Context, arg1 api.Scope, arg2 api.PublishChangeRequest) (api.ChangeReceipt, error) {
	port, ok := s.deps.Store.(interface {
		PublishChange(context.Context, api.Scope, api.PublishChangeRequest) (api.ChangeReceipt, error)
	})
	if !ok || missing(port) {
		return api.ChangeReceipt{}, &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-grants", Message: "canonical org publisher is not bound", Instead: "Bind the installed state owner's guarded publication port."}
	}
	return port.PublishChange(arg0, arg1, arg2)
}

func (s *Service) ReconcileChange(arg0 context.Context, arg1 api.Scope, arg2 api.PublishChangeRequest) (api.ChangeReceipt, error) {
	port, ok := s.deps.Store.(interface {
		ReconcileChange(context.Context, api.Scope, api.PublishChangeRequest) (api.ChangeReceipt, error)
	})
	if !ok || missing(port) {
		return api.ChangeReceipt{}, &api.Error{Code: api.CodePrerequisite, Owner: "lb-v2-grants", Message: "canonical org reconciler is not bound", Instead: "Bind the installed state owner's original-publication recovery port."}
	}
	return port.ReconcileChange(arg0, arg1, arg2)
}

func (s *Service) PublishBootstrap(arg0 context.Context, arg1 api.Scope, arg2 api.EffectLease) (api.BootstrapReceipt, error) {
	var result api.BootstrapReceipt
	return result, api.NotImplemented("lb-v2-grants", "dataworker.PublishBootstrap")
}
