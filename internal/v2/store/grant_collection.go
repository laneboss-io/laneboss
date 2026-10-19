package store

import (
	"context"
	"database/sql"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
)

type grantTransportClose struct {
	Cause    api.InternalIntent
	EventID  api.ID
	LaunchID api.ID
	Receipt  api.TransportInvalidationReceipt
}

func sameStopCause(a, b api.InternalIntent) bool {
	if a.Actor.Kind != "service" || b.Actor.Kind != "service" {
		return false
	}
	a.Actor = b.Actor
	return sameValue(a, b)
}

func grantRevocationOperation(ctx context.Context, db queryer, operation api.ID) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx, "SELECT count(*) FROM receipts WHERE method='grants.revoke' AND json_extract(operation,'$.id')=?", string(operation)).Scan(&count)
	return count == 1, err
}

func (s *Service) GrantRevocationEffect(ctx context.Context, scope api.Scope, id api.ID) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return false, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return false, err
	}
	if !internalScope(scope) || scope.Actor.Kind != "service" {
		return false, fault(api.CodeForbidden, "revocation effect selection requires service authority")
	}
	record, err := effectRow(ctx, s.db, id)
	if err != nil {
		return false, err
	}
	return grantRevocationOperation(ctx, s.db, record.Effect.OperationID)
}

// Called only after the installed authenticator validates and completes its
// measured transport invalidation. The live Stop claim binds that observation
// to the already committed causal decision; no public request can stamp it.
func (s *Service) RecordGrantTransportInvalidation(ctx context.Context, scope api.Scope, lease api.EffectLease, receipt api.TransportInvalidationReceipt) (resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return err
	}
	if !internalScope(scope) || scope.Actor.Kind != "service" || lease.Record.Effect.Context == nil {
		return fault(api.CodeForbidden, "transport completion requires its live service stop")
	}
	current, err := effectRow(ctx, s.db, lease.Record.Effect.ID)
	if err != nil {
		return err
	}
	if !api.EffectLeaseClaimed(lease) || !sameValue(current, lease.Record) || current.ClaimantID != scope.Actor.ID || current.ClaimID != lease.ClaimID || current.ClaimExpiresAt != lease.ExpiresAt || !future(lease.ExpiresAt, s.deps.Clock.Now()) || current.Effect.Stop == nil {
		return fault(api.CodeConflict, "transport completion has a stale or foreign stop claim")
	}
	var lane api.Lane
	if err := storedProjection(ctx, s.db, "lane", current.Effect.Context.Target.LifeID, &lane); err != nil {
		return err
	}
	var revoked api.LaunchRevocation
	if err := storedProjection(ctx, s.db, "launch_revocation", lane.LaunchID, &revoked); err != nil {
		return err
	}
	if !sameStopCause(revoked.Cause, *current.Effect.Context) || revoked.Record.Target != current.Effect.Stop.Target || lane.CancellationEpoch != current.Effect.Context.CancellationEpoch {
		return fault(api.CodeConflict, "transport completion changed the committed revocation cause")
	}
	if err := api.ValidateTransportInvalidation(revoked, receipt); err != nil {
		return err
	}
	event, err := authorityEvent(ctx, s.db, revoked.Cause.CauseOperationID, "identity.revoked", revoked.Record.ID)
	if err != nil {
		return err
	}
	completed, err := time.Parse(time.RFC3339Nano, string(receipt.CompletedAt))
	recorded, recordedErr := time.Parse(time.RFC3339Nano, string(event.RecordedAt))
	if err != nil || recordedErr != nil || completed.Before(recorded) || completed.After(s.deps.Clock.Now()) {
		return fault(api.CodeIntegrity, "transport completion timestamp is outside its committed decision")
	}
	value := grantTransportClose{Cause: revoked.Cause, EventID: revoked.EventID, LaunchID: revoked.Record.ID, Receipt: receipt}
	var prior grantTransportClose
	err = storedProjection(ctx, s.db, "grant_transport_close", current.Effect.ID, &prior)
	if err == nil {
		if prior.Cause != value.Cause || prior.EventID != value.EventID || prior.LaunchID != value.LaunchID || api.ValidateTransportInvalidation(revoked, prior.Receipt) != nil {
			return fault(api.CodeIntegrity, "transport completion changed its original decision")
		}
		return nil
	}
	if !absent(err) {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer finish(tx, &resultErr)
	if err := put(ctx, tx, "grant_transport_close", current.Effect.ID, 1, value); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) checkGrantCollection(ctx context.Context, db queryer, record api.EffectRecord) error {
	if record.Effect.Stop == nil {
		return nil
	}
	needed, err := grantRevocationOperation(ctx, db, record.Effect.OperationID)
	if err != nil || !needed {
		return err
	}
	var lane api.Lane
	if err := storedProjection(ctx, db, "lane", record.Effect.Context.Target.LifeID, &lane); err != nil {
		return err
	}
	var closed grantTransportClose
	if err := storedProjection(ctx, db, "grant_transport_close", record.Effect.ID, &closed); err != nil {
		return fault(api.CodeUnavailable, "revocation transport invalidation is not measured complete")
	}
	var revoked api.LaunchRevocation
	if err := storedProjection(ctx, db, "launch_revocation", lane.LaunchID, &revoked); err != nil {
		return err
	}
	var endpoint api.EndpointProjection
	if err := storedProjection(ctx, db, "endpoint", lane.LaunchID, &endpoint); err != nil {
		return err
	}
	if !revoked.Record.Revoked || !endpoint.Revoked || closed.LaunchID != lane.LaunchID || closed.EventID != revoked.EventID || !sameStopCause(closed.Cause, *record.Effect.Context) {
		return fault(api.CodeIntegrity, "revocation collection lost its causal endpoint decision")
	}
	if err := api.ValidateTransportInvalidation(revoked, closed.Receipt); err != nil {
		return err
	}
	// Natural end may already own the stable release under another operation.
	// That pending job must finish before this Stop can let revocation succeed.
	var raw []byte
	err = db.QueryRowContext(ctx, `SELECT data FROM effect_states WHERE json_extract(data,'$.Effect.HelperRelease.lease_id')=?`, string(revoked.Record.UIDLeaseID)).Scan(&raw)
	if err == sql.ErrNoRows {
		return fault(api.CodeUnavailable, "revocation awaits its retained measured helper release")
	}
	if err != nil {
		return err
	}
	var release api.EffectRecord
	if err := decodeStored(raw, &release); err != nil {
		return err
	}
	if release.Effect.HelperRelease == nil || release.Effect.Context == nil || release.Effect.Context.Target != revoked.Record.Target || release.Effect.HelperRelease.Observation.Handle != *record.Effect.Stop {
		return fault(api.CodeIntegrity, "revocation selected a foreign helper release")
	}
	if release.Outcome == nil && release.Effect.OperationID == record.Effect.OperationID {
		return nil
	}
	if release.Outcome == nil || release.Outcome.Status != "succeeded" || release.Outcome.Release == nil {
		return fault(api.CodeUnavailable, "revocation awaits the original helper collection outcome")
	}
	return api.ValidateReleaseReceipt(*release.Outcome.Release)
}
