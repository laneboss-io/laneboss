//go:build linux

package admin

import (
	"context"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
)

func laneContainmentMatches(record leaseRecord, id api.ID) bool {
	if id == record.Lease.ID || id == record.Lease.ContainmentID || record.Spec != nil && id == record.Spec.Handoff.Spec.LaunchID {
		return true
	}
	for _, allocation := range record.LaunchAllocations {
		if id == allocation.Reservation.LaunchID || id == allocation.Reservation.ID {
			return true
		}
	}
	return false
}

// A registry revocation also invalidates the helper journal and stops the
// selected lane and its outside jobs. Errors retain all ownership for retry.
func (m *leaseManager) revokeNativeContainment(ctx context.Context, id api.ID) (matched bool, resultErr error) {
	if !validID(id) {
		return false, failure(api.CodeInvalid, "invalid native containment revocation")
	}
	finish, err := m.beginRecovery()
	if err != nil {
		return false, err
	}
	damagedErr := m.stopDamagedContainments(ctx)
	defer func() { resultErr = finish(errors.Join(damagedErr, resultErr)) }()
	return m.revokeNativeContainmentOwned(ctx, id)
}

func (m *leaseManager) revokeNativeContainmentOwned(ctx context.Context, id api.ID) (bool, error) {
	if !validID(id) {
		return false, failure(api.CodeInvalid, "invalid native containment revocation")
	}
	records, err := m.records()
	if err != nil {
		return false, err
	}
	matched := false
	var failures []error
	for _, record := range records {
		if !laneContainmentMatches(record, id) {
			continue
		}
		matched = true
		record.Revoked = true
		saveErr := m.save(record)
		var containErr error
		if record.Phase != "released" && record.Phase != "aborted" {
			containErr = m.killAndWait(ctx, record)
		}
		quietErr := m.resources.Quiescent(ctx, record)
		captureErr := m.stopCaptureJobs(ctx, record)
		_, dataErr := m.revokeData(ctx, record.Lease.ID)
		_, archiveErr := m.stopArchiveWorker(ctx, record.Lease.ID)
		dataErr = errors.Join(dataErr, archiveErr)
		// Data revocation can publish a newer parent journal. Never overwrite
		// those invalidations with the snapshot from before containment.
		current, readErr := m.find(record.Lease.ID)
		var credentialErr error
		if readErr == nil && current.Credentials != nil && current.Credentials.State != "withdrawn" {
			cause, causeErr := revokedCredentialCause(current)
			credentialErr = causeErr
			if causeErr == nil {
				credentialErr = m.fenceStopped(&current, cause, "revoked")
				if credentialErr == nil && saveErr == nil && containErr == nil && quietErr == nil && captureErr == nil && dataErr == nil {
					credentialErr = m.withdrawProjection(ctx, &current, cause, "revoked")
				}
			}
		}
		failures = append(failures, saveErr, containErr, quietErr, captureErr, dataErr, readErr, credentialErr)
	}
	dataMatched, err := m.revokeData(ctx, id)
	archiveMatched, archiveErr := m.stopArchiveWorker(ctx, id)
	return matched || dataMatched || archiveMatched, errors.Join(errors.Join(failures...), err, archiveErr)
}

func waitRevokedGate(ctx context.Context, record leaseRecord, live ownedGate, wait func() error) error {
	if live != nil {
		return stopAndWait(ctx, live, gateHandle(record), wait)
	}
	gate := record.Gate
	if gate != nil && (gate.State == "aborted" || gate.Observation != nil && validateObservation(record, *gate.Observation) == nil && gate.Observation.Handle == gateHandle(record)) {
		return wait()
	}
	return errors.Join(failure(api.CodeContainmentUnknown, "revoked lane lost its native wait owner"), wait())
}
