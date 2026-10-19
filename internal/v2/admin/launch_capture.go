package admin

import (
	"context"
	"errors"
	"os"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type captureRegistration struct {
	Policy      api.EffectivePolicy            `json:"policy"`
	Request     api.CaptureRegistrationRequest `json:"request"`
	Reservation api.LaunchReservation          `json:"reservation"`
	Worker      api.WorkerLease                `json:"worker"`
}

type captureJournal struct {
	Registration captureRegistration   `json:"registration"`
	Binding      api.CaptureBinding    `json:"binding"`
	Native       *captureNativeJournal `json:"native,omitempty"`
}

type captureNativeJournal struct {
	Drain              *captureDrainJournal    `json:"drain,omitempty"`
	ArchiveObservation *api.ProcessObservation `json:"archive_observation,omitempty"`
	SpoolIdentity      string                  `json:"spool_identity,omitempty"`
	Phase              string                  `json:"phase"`
	Lease              api.HelperLease         `json:"lease"`
	PID                int                     `json:"pid"`
	BindingID          api.ID                  `json:"binding_id"`
}

type ownedCapture interface {
	TakeWriters(context.Context) (*os.File, *os.File, error)
	Observe(context.Context) error
	Close() error
}

func (s *Service) RegisterCapture(ctx context.Context, request api.CaptureRegistrationRequest) (api.CaptureBinding, error) {
	if err := validateCause(request.Cause, s.deps.Config, api.InternalLaunchPlan); err != nil {
		return api.CaptureBinding{}, err
	}
	if !validID(request.HelperLeaseID) || !validID(request.WorkerLeaseID) {
		return api.CaptureBinding{}, failure(api.CodeInvalid, "capture requires its helper and worker leases")
	}
	authority, err := s.launchAuthority(ctx, request.ReservationID, "", &request.Cause, request.Claim)
	if err != nil {
		return api.CaptureBinding{}, err
	}
	worker, err := s.deps.Store.WorkerLease(ctx, authority.Scope, request.WorkerLeaseID)
	if err != nil {
		return api.CaptureBinding{}, err
	}
	registration := captureRegistration{Request: request, Reservation: authority.Record.Reservation, Worker: worker, Policy: authority.Policy}
	if err := validateCaptureRegistration(registration); err != nil {
		return api.CaptureBinding{}, err
	}
	// A worker's immutable narrow input is a real retained object, not a
	// caller-selected descriptor, executable, pipe number or spool path.
	if _, err := s.readLaunchObject(ctx, authority.Scope, worker.Input, worker.OperationID, worker.Target.LifeID, true); err != nil {
		return api.CaptureBinding{}, err
	}
	var result api.CaptureBinding
	if err := s.call(ctx, "register_capture", registration, &result); err != nil {
		return result, err
	}
	if err := api.ValidateCaptureBinding(result); err != nil {
		return api.CaptureBinding{}, err
	}
	if err := api.ValidateCapturePolicy(result, authority.Policy); err != nil {
		return api.CaptureBinding{}, err
	}
	r := authority.Record.Reservation
	if result.Config != r.Config || result.ReservationID != r.ID || result.Target != r.Target || result.LaunchID != r.LaunchID ||
		result.HelperLeaseID != request.HelperLeaseID || result.OperationID != r.OperationID || result.RequestID != r.RequestID || result.RequestedBy != r.RequestedBy {
		return api.CaptureBinding{}, failure(api.CodeIntegrity, "helper capture disposition differs from its reservation")
	}
	if err := s.fenceLaunch(ctx, authority); err != nil {
		return api.CaptureBinding{}, err
	}
	return result, nil
}

func validateCaptureRegistration(registration captureRegistration) error {
	r, request, worker := registration.Reservation, registration.Request, registration.Worker
	if err := api.ValidateLaunchReservation(r); err != nil {
		return err
	}
	if err := validateCause(request.Cause, r.Config, api.InternalLaunchPlan); err != nil {
		return err
	}
	expires, err := time.Parse(time.RFC3339Nano, string(worker.ExpiresAt))
	if err != nil || !expires.After(time.Now()) || request.ReservationID != r.ID || request.Cause.Target != r.Target ||
		registration.Policy.Generation != r.PolicyGeneration ||
		request.Cause.CauseOperationID != r.OperationID || request.Cause.CauseRequestID != r.RequestID ||
		request.Cause.RequestedBy != r.RequestedBy || request.Cause.CancellationEpoch != r.CancellationEpoch ||
		worker.ID != request.WorkerLeaseID || worker.Kind != "capture_supervisor" || worker.Target != r.Target ||
		worker.OperationID != r.OperationID || worker.EffectID != request.Cause.EffectID || worker.GrantSetID != r.GrantSetID ||
		worker.Generation == 0 || !validID(worker.Input.ID) || !validDigest(worker.Input.SHA256) ||
		worker.Input.Bytes < 1 || worker.Input.Bytes > api.MaxFrameBytes || worker.Input.Class == "" || worker.ConsumedBy != "" {
		return failure(api.CodeForbidden, "capture worker is stale, consumed or foreign to the launch")
	}
	return nil
}

func (m *leaseManager) registerCapture(ctx context.Context, registration captureRegistration) (_ api.CaptureBinding, resultErr error) {
	defer helperCheck(&resultErr, "capture_registration")
	if err := validateCaptureRegistration(registration); err != nil {
		return api.CaptureBinding{}, err
	}
	record, err := m.find(registration.Request.HelperLeaseID)
	if err != nil {
		return api.CaptureBinding{}, err
	}
	if err := captureAllocationCheck(record, m.bootID); err != nil {
		return api.CaptureBinding{}, err
	}
	if err := m.requireActive(record, storageReady); err != nil {
		return api.CaptureBinding{}, err
	}
	found := false
	for _, allocation := range record.LaunchAllocations {
		if reflect.DeepEqual(allocation.Reservation, registration.Reservation) {
			found = true
			if registration.Worker.RuntimeManifest != allocation.Inputs.Sources.Runtime.Manifest || registration.Worker.Generation != record.Storage.Binding.Home.Generation {
				allowAndLog("capture_runtime_generation")
			}
		}
	}
	if !found {
		return api.CaptureBinding{}, failure(api.CodeForbidden, "capture selects a foreign helper reservation")
	}
	for _, prior := range record.Captures {
		if prior.Registration.Reservation.ID == registration.Reservation.ID {
			if !reflect.DeepEqual(prior.Registration, registration) {
				return api.CaptureBinding{}, failure(api.CodeIdempotencyConflict, "capture replay changed its retained input")
			}
			if err := m.syncLaunchStorage(ctx, &record, false); err != nil {
				return api.CaptureBinding{}, err
			}
			if prior.Native != nil {
				return m.reconcileCapture(ctx, prior.Binding)
			}
			if err := api.ValidateCapturePolicy(prior.Binding, registration.Policy); err != nil {
				return api.CaptureBinding{}, err
			}
			return prior.Binding, nil
		}
	}
	if err := m.syncLaunchStorage(ctx, &record, false); err != nil {
		return api.CaptureBinding{}, err
	}
	if err := m.resources.Quiescent(ctx, record); err != nil {
		return api.CaptureBinding{}, err
	}
	binding, attempted, err := m.registerNativeCapture(ctx, &record, registration)
	if err == nil {
		return binding, nil
	}
	var unavailable *api.Error
	if attempted || !errors.As(err, &unavailable) || unavailable.Code != api.CodeUnsupported {
		return api.CaptureBinding{}, err
	}
	// The only fallback is an unsupported enrollment before any job exists.
	// Integrity, ownership, partial startup and policy failures retain their error.
	binding, err = refusedCaptureBinding(registration, record.Lease)
	if err != nil {
		return api.CaptureBinding{}, err
	}
	refusal := *unavailable
	refusal.OperationID = registration.Reservation.OperationID
	binding.Refusal = &refusal
	record.Captures = append(record.Captures, captureJournal{Registration: registration, Binding: binding})
	if err := m.save(record); err != nil {
		return api.CaptureBinding{}, err
	}
	return binding, nil
}

func captureAllocationCheck(record leaseRecord, bootID string) error {
	check := ""
	switch {
	case record.BootID != bootID:
		check = "capture_boot"
	case record.Phase != "active":
		check = "capture_phase"
	case record.Storage == nil:
		check = "capture_storage_missing"
	case !record.Storage.Ready:
		check = "capture_storage_unready"
	}
	if check != "" {
		return api.WithHelperReason(failure(api.CodeContainmentUnknown, "capture has no current helper-owned allocation"), check)
	}
	return nil
}

func (s *Service) ReconcileCapture(ctx context.Context, binding api.CaptureBinding) (api.CaptureBinding, error) {
	if err := api.ValidateCaptureBinding(binding); err != nil {
		return api.CaptureBinding{}, err
	}
	if binding.Config != s.deps.Config {
		return api.CaptureBinding{}, failure(api.CodeForbidden, "capture belongs to another configuration")
	}
	// Read-only reconciliation uses the authenticated installed helper and
	// its exact journal. It cannot require a still-running PlanLaunch claim
	// after that operation has completed. The caller reloads CaptureState;
	// this method independently compares that whole binding with the helper.
	var result api.CaptureBinding
	if err := s.call(ctx, "reconcile_capture", binding, &result); err != nil {
		return api.CaptureBinding{}, err
	}
	if !reflect.DeepEqual(result, binding) {
		return api.CaptureBinding{}, failure(api.CodeIntegrity, "helper substituted a capture binding during reconciliation")
	}
	return result, nil
}

func refusedCaptureBinding(registration captureRegistration, lease api.HelperLease) (api.CaptureBinding, error) {
	if err := validateCaptureRegistration(registration); err != nil {
		return api.CaptureBinding{}, err
	}
	if lease.ID != registration.Request.HelperLeaseID || lease.EndpointGeneration == 0 {
		return api.CaptureBinding{}, failure(api.CodeIntegrity, "capture refusal has no matching helper allocation")
	}
	id, err := randomID("capture-")
	if err != nil {
		return api.CaptureBinding{}, err
	}
	r := registration.Reservation
	refusal := api.NotImplemented(owner, "fixed outside capture supervisor descriptor handoff")
	refusal.OperationID = r.OperationID
	binding := api.CaptureBinding{ID: id, Config: r.Config, ReservationID: r.ID, Target: r.Target, LaunchID: r.LaunchID,
		HelperLeaseID: lease.ID, OperationID: r.OperationID, RequestID: r.RequestID, RequestedBy: r.RequestedBy,
		Generation: lease.EndpointGeneration, Status: "refused", Streams: []api.CaptureStreamBinding{}, Refusal: refusal}
	binding.RefusalPolicy = &api.CaptureRefusalPolicy{Allowed: registration.Policy.AllowCaptureRefusal,
		PolicyGeneration: registration.Policy.Generation, ApprovalID: registration.Policy.CaptureRefusalApprovalID}
	if err := api.ValidateCapturePolicy(binding, registration.Policy); err != nil {
		return api.CaptureBinding{}, err
	}
	return binding, nil
}

func (m *leaseManager) reconcileCapture(ctx context.Context, binding api.CaptureBinding) (api.CaptureBinding, error) {
	if err := api.ValidateCaptureBinding(binding); err != nil {
		return api.CaptureBinding{}, err
	}
	record, err := m.find(binding.HelperLeaseID)
	if err != nil {
		return api.CaptureBinding{}, err
	}
	if record.BootID != m.bootID {
		return api.CaptureBinding{}, failure(api.CodeContainmentUnknown, "capture ownership belongs to a prior boot")
	}
	for _, prior := range record.Captures {
		if prior.Binding.ID == binding.ID {
			if !reflect.DeepEqual(prior.Binding, binding) {
				return api.CaptureBinding{}, failure(api.CodeIntegrity, "capture recovery changed its helper-owned binding")
			}
			// Retained terminal capture is read-only evidence. The normal
			// monitor must not mistake closed descriptors or withdrawn lane
			// storage for producer loss while the service drains this spool.
			// This does not discharge the job or acknowledge any byte/EOF.
			if binding.Status == "registered" && prior.Native != nil && prior.Native.ArchiveObservation != nil {
				if err := m.reconcileTerminalCapture(ctx, record, prior); err != nil {
					return api.CaptureBinding{}, err
				}
				return prior.Binding, nil
			}
			// Stop revokes acquisition immediately. Before the release stage
			// retains terminal capture, the original read-only native owner
			// still monitors its pipes; this grants no export or drain receipt.
			if record.Revoked && binding.Status == "registered" && prior.Native != nil && record.Credentials != nil && record.Credentials.Stop != nil {
				if err := m.reconcileStoppedCapture(ctx, record, prior); err != nil {
					return api.CaptureBinding{}, err
				}
				return prior.Binding, nil
			}
			if err := m.requireActive(record, storageReady); err != nil {
				return api.CaptureBinding{}, err
			}
			if binding.Status == "registered" {
				live := m.captures[binding.ID]
				if prior.Native == nil || prior.Native.Phase != "registered" || live == nil {
					return api.CaptureBinding{}, failure(api.CodeContainmentUnknown, "capture producer or pipe ownership was lost; replacement is forbidden")
				}
				if err := live.Observe(ctx); err != nil {
					return api.CaptureBinding{}, err
				}
				if err := m.verifyCaptureSpool(ctx, record, prior); err != nil {
					return api.CaptureBinding{}, err
				}
			}
			if err := m.syncLaunchStorage(ctx, &record, false); err != nil {
				return api.CaptureBinding{}, err
			}
			return prior.Binding, nil
		}
	}
	return api.CaptureBinding{}, failure(api.CodeContainmentUnknown, "capture journal is missing; a replacement pipe is not permitted")
}
