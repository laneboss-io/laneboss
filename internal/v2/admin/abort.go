package admin

import (
	"context"
	"errors"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func validateAbort(request api.HelperAbortRequest, config string) error {
	if err := validateCause(request.Cause, config, api.InternalHelperAbort); err != nil {
		return err
	}
	if !validID(request.LeaseID) || request.OperationID != request.Cause.CauseOperationID || request.EffectID != request.Cause.EffectID ||
		request.PreparedID != "" && !validID(request.PreparedID) || request.SpecSHA256 != "" && !validDigest(request.SpecSHA256) {
		return failure(api.CodeInvalid, "nonexecuting abort cause or unopened gate identity differs")
	}
	return nil
}

func validateAbortReceipt(record leaseRecord, request api.HelperAbortRequest, receipt api.AbortReceipt) error {
	observation := receipt.Quiescence
	stamp, err := time.Parse(time.RFC3339Nano, string(receipt.ObservedAt))
	issued, issuedErr := time.Parse(time.RFC3339Nano, string(record.IssuedAt))
	if !validID(receipt.ID) || receipt.LeaseID != record.Lease.ID || receipt.PreparedID != request.PreparedID || receipt.AgentExecuted ||
		observation.Handle.ID != "" || observation.Handle.Generation != "" || observation.Handle.Target != request.Cause.Target ||
		observation.Handle.ContainmentID != record.Lease.ContainmentID || observation.State != "not_started" ||
		observation.ExitCode != nil || observation.Signal != nil || observation.Survivors == nil || *observation.Survivors != 0 ||
		observation.PromptStatus != "not_written" || observation.ObservedAt != receipt.ObservedAt || err != nil || issuedErr != nil ||
		stamp.Before(issued) || stamp.After(time.Now().Add(time.Second)) {
		return failure(api.CodeIntegrity, "invalid independently measured nonexecuting abort receipt")
	}
	return nil
}

func (s *Service) AbortGate(ctx context.Context, request api.HelperAbortRequest) (api.AbortReceipt, error) {
	if err := validateAbort(request, s.deps.Config); err != nil {
		return api.AbortReceipt{}, err
	}
	claim, err := s.currentStage(ctx, request.Cause, api.InternalHelperAbort)
	if err != nil {
		return api.AbortReceipt{}, err
	}
	retained := claim.Effect.HelperAbort
	if retained != nil {
		copy := *retained
		copy.Cause.Actor = request.Cause.Actor
		retained = &copy
	}
	if retained == nil || *retained != request {
		return api.AbortReceipt{}, failure(api.CodeForbidden, "abort differs from its retained effect")
	}
	var result api.AbortReceipt
	if err := s.call(ctx, "abort", request, &result); err != nil {
		return api.AbortReceipt{}, err
	}
	comparison := leaseRecord{Lease: api.HelperLease{ID: request.LeaseID, ContainmentID: result.Quiescence.Handle.ContainmentID}, IssuedAt: "1970-01-01T00:00:00Z"}
	if err := validateAbortReceipt(comparison, request, result); err != nil {
		return api.AbortReceipt{}, err
	}
	return result, nil
}

func (m *leaseManager) abort(ctx context.Context, request api.HelperAbortRequest) (api.AbortReceipt, error) {
	if err := contextError(ctx); err != nil {
		return api.AbortReceipt{}, err
	}
	if err := validateAbort(request, m.binding.Config); err != nil {
		return api.AbortReceipt{}, err
	}
	record, err := m.find(request.LeaseID)
	if err != nil {
		return api.AbortReceipt{}, err
	}
	if record.Abort != nil && !retainedAbort(record.Abort, request, attemptClaimant(ctx, request.EffectID)) {
		return api.AbortReceipt{}, failure(api.CodeIdempotencyConflict, "changed nonexecuting abort replay")
	}
	if record.Release != nil || request.Cause.Target.LifeID != record.Request.LifeID ||
		(record.Phase != "reserved" && record.Phase != "active" && record.Phase != "aborting" && record.Phase != "aborted") {
		return api.AbortReceipt{}, failure(api.CodeConflict, "lease is not an unopened allocation")
	}
	if record.Spec == nil && request.SpecSHA256 != "" || record.Spec != nil &&
		(request.SpecSHA256 != record.SpecReceipt.SpecSHA256 || request.Cause.Target != record.SpecReceipt.Target) {
		return api.AbortReceipt{}, failure(api.CodeIntegrity, "abort differs from the registered unopened spec")
	}
	if record.BootID != m.bootID {
		return api.AbortReceipt{}, failure(api.CodeContainmentUnknown, "prior-boot abort requires administrator reconciliation")
	}
	if record.Gate != nil && (request.PreparedID != record.Gate.Prepared.ID || record.Gate.Permit != nil || record.Gate.Open != nil || record.Gate.State != "preparing" && record.Gate.State != "prepared" && record.Gate.State != "aborted") {
		return api.AbortReceipt{}, failure(api.CodeConflict, "abort cannot replace an opened or uncertain release")
	}
	containErr := m.abortPrepared(ctx, &record, request)
	fenceErr := m.fenceStopped(&record, request.Cause, "refused")
	if err := errors.Join(containErr, fenceErr); err != nil {
		return api.AbortReceipt{}, err
	}
	if err := m.withdrawProjection(ctx, &record, request.Cause, "refused"); err != nil {
		return api.AbortReceipt{}, err
	}
	if err := m.resources.Quiescent(ctx, record); err != nil {
		return api.AbortReceipt{}, err
	}
	if record.Phase == "aborted" {
		if err := m.collectPrivateStorage(ctx, &record); err != nil {
			return api.AbortReceipt{}, err
		}
		return *record.AbortReceipt, nil
	}
	if err := m.collectPrivateStorage(ctx, &record); err != nil {
		return api.AbortReceipt{}, err
	}
	if err := m.collectNetwork(ctx, &record); err != nil {
		return api.AbortReceipt{}, err
	}
	if record.AbortReceipt == nil {
		id, err := randomID("abort-")
		if err != nil {
			return api.AbortReceipt{}, err
		}
		zero := uint64(0)
		now := api.Timestamp(time.Now().UTC().Format(time.RFC3339Nano))
		record.AbortReceipt = &api.AbortReceipt{ID: id, LeaseID: record.Lease.ID, PreparedID: request.PreparedID, ObservedAt: now,
			Quiescence: api.ProcessObservation{Handle: api.ProcessHandle{Target: request.Cause.Target, ContainmentID: record.Lease.ContainmentID},
				State: "not_started", Survivors: &zero, PromptStatus: "not_written", ObservedAt: now}}
	}
	record.Phase, record.Abort = "aborting", &request
	if err := m.save(record); err != nil {
		return api.AbortReceipt{}, err
	}
	if err := m.resources.Remove(ctx, record); err != nil {
		return api.AbortReceipt{}, err
	}
	record.Phase = "aborted"
	if err := m.save(record); err != nil {
		return api.AbortReceipt{}, err
	}
	return *record.AbortReceipt, nil
}
