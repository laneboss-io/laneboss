package admin

import (
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

func validateMeasuredCleanup(job api.CleanupJob, result api.WorkspaceRemoval, now time.Time) error {
	measured, err := time.Parse(time.RFC3339Nano, string(result.After.ObservedAt))
	if err != nil || measured.IsZero() || measured.After(now) {
		return failure(api.CodeIntegrity, "cleanup result time is invalid or in the future")
	}
	return api.ValidateWorkspaceRemoval(job, result, measured)
}

// Entry and destructive calls require a currently live claim. Once the native
// result is measured, journal publication validates that original claim at the
// measured result time; scheduler or storage delay cannot undo finished work.
func (m *leaseManager) finishCleanup(p leaseRecord, job api.CleanupJob, result api.WorkspaceRemoval) (api.WorkspaceRemoval, error) {
	if err := validateMeasuredCleanup(job, result, time.Now()); err != nil {
		return api.WorkspaceRemoval{}, err
	}
	if p.Cleanup == nil {
		return api.WorkspaceRemoval{}, failure(api.CodeIntegrity, "cleanup result lost its original decision journal")
	}
	p.Cleanup.Phase, p.Cleanup.Removal = "complete", &result
	if err := m.save(p); err != nil {
		return api.WorkspaceRemoval{}, err
	}
	// Read the durable helper journal again after publication.
	p, err := m.find(p.Lease.ID)
	if err != nil {
		return api.WorkspaceRemoval{}, err
	}
	if p.Cleanup == nil || p.Cleanup.Removal == nil {
		return api.WorkspaceRemoval{}, failure(api.CodeIntegrity, "cleanup removal journal disappeared")
	}
	return *p.Cleanup.Removal, nil
}
