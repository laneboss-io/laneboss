package dataworker

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) CredentialWorkerSelection(ctx context.Context, scope api.Scope, handoff api.PreparedSpecHandoff) (api.CredentialWorkerSelection, error) {
	if err := checkContext(ctx); err != nil {
		return api.CredentialWorkerSelection{}, err
	}
	if scope.Config != s.deps.Config || scope.Actor.Kind != "service" || scope.Connection != nil || scope.Frame != nil || scope.ReadView != nil {
		return api.CredentialWorkerSelection{}, &api.Error{Code: api.CodeForbidden, Owner: "lb-v2-grants", Message: "credential worker inventory requires its private service scope"}
	}
	source, ok := s.deps.Store.(api.CredentialWorkerSelectionStore)
	if !ok || missing(source) {
		return api.CredentialWorkerSelection{}, api.NotImplemented("lb-v2-service", "protected credential worker selection")
	}
	first, err := source.CredentialWorkerSelection(ctx, scope, handoff)
	if err != nil {
		return first, err
	}
	live, err := source.CredentialWorkerSelection(ctx, scope, handoff)
	if err != nil {
		return api.CredentialWorkerSelection{}, err
	}
	if !reflect.DeepEqual(first, live) {
		return api.CredentialWorkerSelection{}, &api.Error{Code: api.CodeConflict, Owner: "lb-v2-grants", Message: "credential worker inventory changed during validation"}
	}
	return live, nil
}
