package service

import (
	"context"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

type archiveRetirementStore interface {
	ArchiveRecovery(context.Context, api.Scope, api.EffectLease) (archivejob.Recovery, error)
	BeginArchiveAllocation(context.Context, api.Scope, api.EffectLease) error
	RecordArchiveAllocation(context.Context, api.Scope, api.EffectLease, api.HelperLease) error
	RecordArchiveRetirement(context.Context, api.Scope, api.EffectLease, archivejob.Retirement) error
}

// Cleanup gets a bounded service-lifetime context, independent of the expired
// worker capability. It confers no new allocation, launch or data authority.
func (s *Server) retireArchive(ctx context.Context, scope api.Scope, lease api.EffectLease) (*api.ProcessObservation, error) {
	store, ok := s.deps.Store.(archiveRetirementStore)
	if !ok {
		return nil, serviceError(api.CodeContainmentUnknown, "archive retirement writer is unavailable")
	}
	state, err := store.ArchiveRecovery(ctx, scope, lease)
	if err != nil {
		return nil, err
	}
	if !state.Allocating && state.Allocation.ID == "" && !state.Handoff && state.Process.ID == "" {
		return nil, nil
	}
	proof := state.Retirement
	if proof == nil {
		s.mu.RLock()
		helper, ok := s.runtime.Helper.(archivejob.RetirementHelper)
		observer, observes := s.runtime.Helper.(archiveHelper)
		s.mu.RUnlock()
		if !ok {
			return nil, serviceError(api.CodeContainmentUnknown, "administrator must supply measured archive stop/reap/release")
		}
		cleanup, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if observes && (state.Handoff || state.Process.ID != "") {
			// Even an expired worker is observed. Retirement then reconciles
			// uncertain/running state and returns its actual release or abort.
			if _, err := observer.ObserveArchiveWorker(cleanup, state.Job, lease); err != nil && cleanup.Err() != nil {
				return nil, archiveRetirementStepError(ctx, cleanup, err)
			}
		}
		if err := s.stopWorkerEndpoint(cleanup, state.Job.Lease.ID); err != nil {
			return nil, archiveRetirementStepError(ctx, cleanup, err)
		}
		measured, err := helper.RetireArchiveWorker(cleanup, state.Job, lease)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, &api.Error{Code: api.CodeContainmentUnknown, Owner: "lb-v2-admin", Message: "original archive retirement has no complete native measurement", Instead: "Preserve the allocation and reconcile its original native retirement; never seal unknown resource state."}
		}
		if err := store.RecordArchiveRetirement(cleanup, scope, lease, measured); err != nil {
			return nil, archiveRetirementStepError(ctx, cleanup, err)
		}
		proof = &measured
	}
	if proof.Release != nil {
		observation := proof.Release.Quiescence
		return &observation, nil
	}
	return nil, nil // Explicit absence, unopened abort or boot proof is retained.
}

// A cleanup deadline has not measured retirement. Keep the original attempt
// pending through the reconciler's bounded retry delay. A joined storage error
// is still fatal; cancellation of the service itself belongs to shutdown.
func archiveRetirementStepError(parent, cleanup context.Context, err error) error {
	if parent.Err() != nil {
		return parent.Err()
	}
	if cleanup.Err() == context.DeadlineExceeded && retirementContextOnly(err) {
		return &api.Error{Code: api.CodeContainmentUnknown, Owner: "lb-v2-admin", Message: "archive retirement cleanup deadline elapsed before evidence was retained", Instead: "Retry the original native retirement with bounded backoff; preserve its allocation until the measurement is retained."}
	}
	return err
}

func retirementContextOnly(err error) bool {
	if err == context.Canceled || err == context.DeadlineExceeded {
		return true
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		children := wrapped.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !retirementContextOnly(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return retirementContextOnly(wrapped.Unwrap())
	}
	return false
}
