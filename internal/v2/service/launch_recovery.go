package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

// This job is separate from pending-effect dispatch: completed/opened launches
// and registered capture producers still need reconciliation after restart.
func (s *Server) launchRecoveryLoop(ctx context.Context) {
	s.mu.Lock()
	configured, runtime := s.launchConfigured, s.runtime
	s.launchJobsActive, s.launchJobsHealthy = configured, false
	s.mu.Unlock()
	if !configured {
		return
	}
	defer func() { s.mu.Lock(); s.launchJobsActive, s.launchJobsHealthy = false, false; s.mu.Unlock() }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		err := s.reconcileLaunches(ctx, runtime)
		s.mu.Lock()
		s.launchJobsHealthy = err == nil
		s.mu.Unlock()
		if err != nil {
			if ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
				return
			}
			s.recordFault(err)
			s.journalLaunchStop(err)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Keep the typed fixed diagnostic, never Error()'s wrapper, operation IDs,
// owner selectors or recovery paths. Untyped causes use the service fallback.
func (s *Server) journalLaunchStop(cause error) {
	failure := typedError(cause)
	data, err := json.Marshal(struct {
		Event   string        `json:"event"`
		Code    api.ErrorCode `json:"code"`
		Message string        `json:"message"`
	}{"launch_recovery_stopped", failure.Code, errorDetail(failure)})
	if err == nil {
		data = append(data, '\n')
		var count int
		count, err = os.Stderr.Write(data)
		if err == nil && count != len(data) {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		s.recordFault(serviceError(api.CodeIntegrity, "launch recovery stop journal failed"))
	}
}

func (s *Server) reconcileLaunches(ctx context.Context, runtime api.RuntimeServices) error {
	control, err := s.launchStore()
	if err != nil {
		return err
	}
	records, err := control.LaunchInventory(ctx)
	if err != nil {
		return err
	}
	scope, err := s.controlScope()
	if err != nil {
		return err
	}
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if record.Plan == nil {
			continue
		} // Existing PlanLaunch/stage effects own these phases.
		plan := record.Plan
		state, err := runtime.Store.CaptureState(ctx, scope, plan.Capture.ID)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(state.Binding, plan.Capture) {
			return serviceError(api.CodeIntegrity, "capture recovery changed the retained producer or pipes")
		}
		if plan.Capture.Status == "registered" {
			// The helper owns kernel/spool verification and bounded stopping on
			// producer loss. Its typed failure is retained and propagated whole.
			actual, err := runtime.Helper.ReconcileCapture(ctx, plan.Capture)
			if err != nil {
				if api.CaptureSnapshotPending(err) {
					continue
				}
				if recorder, ok := runtime.Store.(interface {
					RecordCaptureFailure(context.Context, api.CaptureBinding, *api.Error) error
				}); ok {
					if recordErr := recorder.RecordCaptureFailure(ctx, plan.Capture, typedError(err)); recordErr != nil {
						return recordErr
					}
				}
				return err
			}
			if !reflect.DeepEqual(actual, plan.Capture) {
				return serviceError(api.CodeIntegrity, "capture reconciliation attempted to replace its producer or pipes")
			}
		}
		if record.Phase != "bound" && record.Phase != "opened" {
			continue
		}
		binding, err := runtime.Store.LaunchBinding(ctx, record.Reservation.LaunchID)
		if err != nil {
			return err
		}
		if err := api.ValidateLaunchBindingPlan(binding, *plan); err != nil {
			return err
		}
		// Read the durable stage before measuring the helper. An open may
		// finish immediately after its prepared report; that older report
		// must not be compared to a later consumed store stage.
		pending, err := control.LaunchPending(ctx, binding.Record.ID)
		if err != nil {
			return err
		}
		actual, err := runtime.Helper.ReconcileGate(ctx, api.HelperReconcileRequest{LeaseID: plan.Lease.ID, LaunchID: binding.Record.ID,
			PreparedID: binding.Prepared.ID, OperationID: record.Reservation.OperationID})
		if err != nil {
			return err
		}
		if actual.Prepared == nil || *actual.Prepared != binding.Prepared {
			return serviceError(api.CodeIntegrity, "gate recovery differs from retained prepared launch")
		}
		if (actual.Observation.State == "running" || actual.GateState == "prepared") && !binding.Record.Revoked {
			if record.Handoff == nil {
				return serviceError(api.CodeIntegrity, "lane endpoint recovery lost its retained spec")
			}
			if err := s.prepareLaneEndpoint(ctx, record.Handoff.Spec, plan.Lease); err != nil {
				return err
			}
		} else if actual.Observation.State == "exited" || binding.Record.Revoked {
			if err := s.stopLaneEndpoint(ctx, binding.Record.ID); err != nil {
				return err
			}
		}
		if pending && (actual.GateState == "prepared" || actual.GateState == "opening") && actual.Process == nil && actual.ConsumedPermit == nil &&
			(actual.Observation.State == "prepared" || actual.Observation.State == "running") {
			continue // Only the original planner's fresh authorization may open it.
		}
		if err := control.RecordLaunchObservation(ctx, binding.Record.ID, actual); err != nil {
			return err
		}
	}
	return nil
}
