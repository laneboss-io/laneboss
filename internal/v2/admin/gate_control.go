package admin

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

func validateProcessSelector(request api.HelperObserveRequest) error {
	if !validID(request.LeaseID) || !validID(request.Handle.ID) || !validID(request.Handle.ContainmentID) ||
		!validID(request.Handle.Target.LifeID) || request.Handle.Target.Run == 0 || request.Handle.Target.Run > 1<<53-1 || request.Handle.Generation == "" {
		return failure(api.CodeInvalid, "invalid retained process selector")
	}
	return nil
}

func (s *Service) ObserveGate(ctx context.Context, request api.HelperObserveRequest) (api.ProcessObservation, error) {
	if err := validateProcessSelector(request); err != nil {
		return api.ProcessObservation{}, err
	}
	var result api.ProcessObservation
	if err := s.call(ctx, "observe_gate", request, &result); err != nil {
		return api.ProcessObservation{}, err
	}
	if result.Handle != request.Handle || result.State != "running" && result.State != "exited" {
		return api.ProcessObservation{}, failure(api.CodeIntegrity, "helper observation substituted its process")
	}
	return result, nil
}

func (s *Service) StopGate(ctx context.Context, request api.HelperStopRequest) (api.ProcessObservation, error) {
	if err := validateProcessSelector(request.Target); err != nil {
		return api.ProcessObservation{}, err
	}
	claim, err := s.currentStage(ctx, request.Cause, api.InternalHelperStop)
	if err != nil {
		return api.ProcessObservation{}, err
	}
	if claim.Effect.Stop == nil || !reflect.DeepEqual(*claim.Effect.Stop, request.Target.Handle) {
		return api.ProcessObservation{}, failure(api.CodeForbidden, "stop differs from its retained effect")
	}
	var result api.ProcessObservation
	if err := s.call(ctx, "stop_gate", request, &result); err != nil {
		return api.ProcessObservation{}, err
	}
	if result.Handle != request.Target.Handle {
		return api.ProcessObservation{}, failure(api.CodeIntegrity, "helper stop substituted its process")
	}
	return result, nil
}

func (s *Service) ReconcileGate(ctx context.Context, request api.HelperReconcileRequest) (api.LaunchReconciliation, error) {
	if !validID(request.LeaseID) || !validID(request.LaunchID) || !validID(request.PreparedID) || !validID(request.OperationID) {
		return api.LaunchReconciliation{}, failure(api.CodeInvalid, "incomplete retained gate reconciliation selector")
	}
	var result api.LaunchReconciliation
	if err := s.call(ctx, "reconcile_gate", request, &result); err != nil {
		return api.LaunchReconciliation{}, err
	}
	if result.Prepared == nil || result.Prepared.ID != request.PreparedID || result.Observation.Handle.ID != request.LaunchID ||
		result.Process != nil && *result.Process != result.Observation.Handle || result.ConsumedPermit != nil && result.ConsumedPermit.LaunchID != request.LaunchID {
		return api.LaunchReconciliation{}, failure(api.CodeIntegrity, "helper reconciliation substituted its retained launch")
	}
	return result, nil
}
