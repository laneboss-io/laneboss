package admin

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// CredentialProjectionSource is the metadata-only native helper read boundary.
// It carries no descriptor or credential value through the event service.
type CredentialProjectionSource interface {
	ResolveCredentialProjection(context.Context, api.Scope, api.CredentialProjectionRequest) (api.CredentialProjectionAuthority, error)
	ObserveCredentialProjection(context.Context, api.CredentialProjectionAuthority) (api.CredentialProjectionReceipt, error)
}

type credentialSourceQuery struct {
	Actor   api.Actor
	Request api.CredentialProjectionRequest
}

var _ CredentialProjectionSource = (*Service)(nil)

func (s *Service) ResolveCredentialProjection(ctx context.Context, scope api.Scope, request api.CredentialProjectionRequest) (api.CredentialProjectionAuthority, error) {
	var observed api.CredentialProjectionAuthority
	if scope.Config != s.deps.Config || scope.Actor.Kind != "service" || !validID(scope.Actor.ID) || scope.Connection != nil || scope.Frame != nil || scope.ReadView != nil || !reflect.ValueOf(scope.Request).IsZero() || request.Handoff.Config != s.deps.Config {
		return observed, failure(api.CodeForbidden, "credential native metadata requires its private service component")
	}
	if err := api.ValidateCredentialProjectionRequest(request, time.Now()); err != nil {
		return observed, err
	}
	if err := s.call(ctx, "credential_projection_source", credentialSourceQuery{Actor: scope.Actor, Request: request}, &observed); err != nil {
		return observed, err
	}
	if observed.ID != "" || observed.Generation != 0 || !reflect.DeepEqual(observed.Request, request) {
		return api.CredentialProjectionAuthority{}, failure(api.CodeIntegrity, "native credential metadata changed its measured gate selector")
	}
	return observed, nil
}

func (s *Service) ObserveCredentialProjection(ctx context.Context, authority api.CredentialProjectionAuthority) (api.CredentialProjectionReceipt, error) {
	var observed api.CredentialProjectionReceipt
	if authority.Request.Handoff.Config != s.deps.Config || !validID(authority.ID) {
		return observed, failure(api.CodeForbidden, "credential native holding belongs to another installation")
	}
	if err := s.call(ctx, "credential_projection_observe", authority, &observed); err != nil {
		return observed, err
	}
	if err := api.ValidateCredentialHolding(authority, observed, time.Now()); err != nil {
		return api.CredentialProjectionReceipt{}, err
	}
	return observed, nil
}
