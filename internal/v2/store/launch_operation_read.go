package store

import (
	"context"
	"database/sql"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

// LaunchPlanForOperation resolves an immutable object provenance selector.
// It is an internal point lookup, never a public operation-owner override.
func (s *Service) LaunchPlanForOperation(ctx context.Context, scope api.Scope, operation api.ID) (api.LaunchPlanRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result api.LaunchPlanRecord
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return result, err
	}
	if !internalScope(scope) || scope.Actor.Kind != "service" || operation == "" {
		return result, fault(api.CodeForbidden, "launch operation lookup requires its private service reader")
	}
	db, err := s.reader(scope)
	if err != nil {
		return result, err
	}
	var raw []byte
	err = db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='launch_plan' AND json_extract(data,'$.reservation.operation_id')=?", string(operation)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return result, fault(api.CodeNotFound, "operation has no retained launch plan")
	}
	if err != nil {
		return result, err
	}
	if err := decodeStored(raw, &result); err != nil {
		return api.LaunchPlanRecord{}, err
	}
	if result.Reservation.OperationID != operation || result.Reservation.Config != scope.Config {
		return api.LaunchPlanRecord{}, fault(api.CodeIntegrity, "launch operation lookup returned a foreign reservation")
	}
	if err := s.checkLaunchBytes(ctx, db, result); err != nil {
		return api.LaunchPlanRecord{}, err
	}
	return result, nil
}
