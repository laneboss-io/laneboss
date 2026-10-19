package dataworker

import (
	"context"
	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) TestChildScoped(ctx context.Context, scope api.Scope, request api.TestChildRequest, grants api.GrantSet) (api.Operation, error) {
	if err := checkContext(ctx); err != nil {
		return api.Operation{}, err
	}
	control, ok := s.deps.Controls.(interface {
		TestChildScoped(context.Context, api.Scope, api.TestChildRequest, api.GrantSet) (api.Operation, error)
	})
	if !ok {
		return api.Operation{}, api.NotImplemented("lb-v2-service", "native child checker coordinator")
	}
	return control.TestChildScoped(ctx, scope, request, grants)
}
