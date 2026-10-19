package service

import (
	"context"

	"laneboss.io/laneboss/internal/v2/admin"
	"laneboss.io/laneboss/internal/v2/api"
)

// This entry is absent from the public RPC catalog. Only the authenticated
// administrator listener can bind the writer's exact-reading capability.
func (s *Server) ReconcileSpend(ctx context.Context, reading api.SpendReading) (api.SpendBalance, error) {
	writer, ok := s.deps.Store.(api.SpendReconciler)
	if !ok {
		return api.SpendBalance{}, api.NotImplemented("lb-v2-store", "credential spend reconciliation")
	}
	return writer.ReconcileSpend(ctx, reading)
}

func (s *Server) ReconcileSpendFrame(ctx context.Context, endpoint api.AdminEnrollmentEndpoint, scope api.Scope, reading api.SpendReading) (api.SpendBalance, error) {
	bound, err := admin.SpendContext(ctx, endpoint, scope.Connection, scope.Frame)
	if err != nil {
		return api.SpendBalance{}, err
	}
	return s.ReconcileSpend(bound, reading)
}
