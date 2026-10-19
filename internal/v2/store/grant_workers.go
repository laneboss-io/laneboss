package store

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

type grantWorkerKey struct{}
type grantWorkerCollection struct {
	Store   *Service
	Lease   api.EffectLease
	Receipt api.ReleaseReceipt
}

func (s *Service) grantCaptureWorkers(ctx context.Context, db readDatabase, lane api.Lane) ([]api.LaunchRecord, error) {
	binding, err := s.launchBinding(ctx, db, lane.LaunchID)
	if err != nil {
		return nil, err
	}
	if binding.Recovery == nil {
		return nil, fault(api.CodeIntegrity, "grant collection lost its capture recovery binding")
	}
	capture := binding.Recovery.Capture
	if capture.Status != "registered" {
		return []api.LaunchRecord{}, nil
	}
	var worker api.WorkerLease
	if err := storedProjection(ctx, db, "worker_lease", capture.WorkerLeaseID, &worker); err != nil {
		return nil, err
	}
	if worker.Kind != "capture_supervisor" || worker.Target != capture.Target || worker.GrantSetID != lane.GrantSetID {
		return nil, fault(api.CodeIntegrity, "grant collection capture lease differs from its exact run")
	}
	records, err := projectionValues[api.LaunchRecord](ctx, db, "launch")
	if err != nil {
		return nil, err
	}
	var result []api.LaunchRecord
	for _, record := range records {
		if record.Kind == "worker" && record.Actor.Kind == "worker" && record.Actor.ID == capture.ProducerID && record.Target == worker.Target && record.GrantSetID == worker.GrantSetID {
			result = append(result, record)
		}
	}
	if len(result) != 1 {
		return nil, fault(api.CodePrerequisite, "grant collection needs the unique retained capture worker identity")
	}
	return result, nil
}

// Native release measures the capture process/UID, but does not invalidate
// service-side worker connections. Retain that last causal stage before the
// original HelperRelease is permitted to complete.
func (s *Service) RevokeCollectedGrantWorkers(ctx context.Context, scope api.Scope, lease api.EffectLease, receipt api.ReleaseReceipt) ([]api.ID, error) {
	input, ids, err := s.collectedGrantWorkerIntent(ctx, scope, lease, receipt)
	if err != nil || len(input.Events) == 0 {
		return ids, err
	}
	ctx = context.WithValue(api.WithEffectLease(ctx, lease), grantWorkerKey{}, grantWorkerCollection{s, lease, receipt})
	if _, err := s.Transact(ctx, input); err != nil {
		return nil, err
	}
	return ids, nil
}

func (s *Service) collectedGrantWorkerIntent(ctx context.Context, scope api.Scope, lease api.EffectLease, receipt api.ReleaseReceipt) (api.Transaction, []api.ID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var input api.Transaction
	if err := s.available(); err != nil {
		return input, nil, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return input, nil, err
	}
	owner, err := s.captureDrainClaim(ctx, s.db, scope, lease)
	if err != nil {
		return input, nil, err
	}
	if owner.Release == nil {
		return input, nil, fault(api.CodeForbidden, "grant worker collection requires the original helper release")
	}
	if err := measuredOutcome(lease.Record.Effect, api.EffectOutcome{Status: "succeeded", Release: &receipt}); err != nil {
		return input, nil, err
	}
	var lane api.Lane
	if err := storedProjection(ctx, s.db, "lane", owner.Cause.Target.LifeID, &lane); err != nil {
		return input, nil, err
	}
	var revoked api.LaunchRevocation
	err = storedProjection(ctx, s.db, "launch_revocation", lane.LaunchID, &revoked)
	if absent(err) {
		return input, []api.ID{}, nil
	}
	if err != nil {
		return input, nil, err
	}
	needed, err := grantRevocationOperation(ctx, s.db, revoked.Cause.CauseOperationID)
	if err != nil || !needed {
		return input, []api.ID{}, err
	}
	workers, err := s.grantCaptureWorkers(ctx, s.db, lane)
	if err != nil {
		return input, nil, err
	}
	cause := revoked.Cause
	cause.Kind, cause.ID, cause.Actor, cause.EffectID = api.InternalHelperStop, api.ID(hash([]byte(string(lease.Record.Effect.ID) + "-capture"))[:32]), scope.Actor, lease.Record.Effect.ID
	input = api.Transaction{Scope: scope, Internal: &cause, Compare: []api.Compare{{Kind: api.CompareLane, ID: lane.LifeID, Generation: lane.Generation}}, Guards: []api.TransactionGuard{{Cancellation: &api.CancellationCheck{LifeID: lane.LifeID, Epoch: lane.CancellationEpoch}}}}
	var ids []api.ID
	for _, record := range workers {
		ids = append(ids, record.ID)
		if record.Revoked {
			var prior api.LaunchRevocation
			if err := storedProjection(ctx, s.db, "launch_revocation", record.ID, &prior); err != nil {
				return input, nil, err
			}
			if prior.Cause.CauseOperationID != cause.CauseOperationID || prior.Cause.CauseRequestID != cause.CauseRequestID || prior.Cause.RequestedBy != cause.RequestedBy {
				return input, nil, fault(api.CodeIntegrity, "collected worker has a foreign revocation cause")
			}
			continue
		}
		record.Revoked = true
		raw, err := json.Marshal(record)
		if err != nil {
			return input, nil, err
		}
		input.Events = append(input.Events, api.Event{Schema: api.SchemaVersion, ID: api.ID(hash([]byte(string(cause.ID) + string(record.ID)))[:32]), Config: scope.Config, Kind: "identity.revoked", Actor: scope.Actor, RequestedBy: cause.RequestedBy, OperationID: cause.CauseOperationID, RequestID: cause.CauseRequestID, LifeID: lane.LifeID, Run: lane.Run, RootLifeID: lane.RootLifeID, ParentLifeID: lane.ParentLifeID, StarterChain: lane.StarterChain, StarterEventSeq: lane.StarterEventSeq, Origin: "service", Payload: raw})
		var endpoint api.EndpointProjection
		err = storedProjection(ctx, s.db, "endpoint", record.ID, &endpoint)
		if err == nil {
			input.Compare = append(input.Compare, api.Compare{Kind: api.CompareEndpoint, ID: record.ID, Generation: endpoint.Generation})
			endpoint.Revoked = true
			endpoint.Generation++
			input.Writes.Endpoints = append(input.Writes.Endpoints, endpoint)
		} else if !absent(err) {
			return input, nil, err
		}
	}
	return input, ids, nil
}

func workerCloseID(effect, worker api.ID) api.ID {
	return api.ID(hash([]byte(string(effect) + "-closed-" + string(worker)))[:32])
}

func (s *Service) RecordCollectedWorkerInvalidation(ctx context.Context, scope api.Scope, lease api.EffectLease, worker api.ID, receipt api.TransportInvalidationReceipt) (resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return err
	}
	owner, err := s.captureDrainClaim(ctx, s.db, scope, lease)
	if err != nil {
		return err
	}
	var revoked api.LaunchRevocation
	if err := storedProjection(ctx, s.db, "launch_revocation", worker, &revoked); err != nil {
		return err
	}
	if owner.Release == nil || revoked.Record.Kind != "worker" || revoked.Record.Target != owner.Cause.Target || revoked.Cause.EffectID != lease.Record.Effect.ID {
		return fault(api.CodeForbidden, "worker transport completion belongs to another release")
	}
	if err := api.ValidateTransportInvalidation(revoked, receipt); err != nil {
		return err
	}
	value := grantTransportClose{Cause: revoked.Cause, EventID: revoked.EventID, LaunchID: worker, Receipt: receipt}
	id := workerCloseID(lease.Record.Effect.ID, worker)
	var prior grantTransportClose
	err = storedProjection(ctx, s.db, "grant_worker_close", id, &prior)
	if err == nil {
		if prior.Cause != value.Cause || prior.EventID != value.EventID || prior.LaunchID != worker || api.ValidateTransportInvalidation(revoked, prior.Receipt) != nil {
			return fault(api.CodeIntegrity, "worker transport completion changed its retained cause")
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
	if err := put(ctx, tx, "grant_worker_close", id, 1, value); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) checkCollectedGrantWorkers(ctx context.Context, db readDatabase, effect api.Effect) error {
	if effect.HelperRelease == nil {
		return nil
	}
	var lane api.Lane
	if err := storedProjection(ctx, db, "lane", effect.Context.Target.LifeID, &lane); err != nil {
		return err
	}
	var revoked api.LaunchRevocation
	err := storedProjection(ctx, db, "launch_revocation", lane.LaunchID, &revoked)
	if absent(err) {
		return nil
	}
	if err != nil {
		return err
	}
	needed, err := grantRevocationOperation(ctx, db, revoked.Cause.CauseOperationID)
	if err != nil || !needed {
		return err
	}
	workers, err := s.grantCaptureWorkers(ctx, db, lane)
	if err != nil {
		return err
	}
	for _, worker := range workers {
		var decision api.LaunchRevocation
		if err := storedProjection(ctx, db, "launch_revocation", worker.ID, &decision); err != nil {
			return fault(api.CodeUnavailable, "grant collection awaits its capture worker revocation")
		}
		var closed grantTransportClose
		if err := storedProjection(ctx, db, "grant_worker_close", workerCloseID(effect.ID, worker.ID), &closed); err != nil {
			return fault(api.CodeUnavailable, "grant collection awaits measured capture transport close")
		}
		if !worker.Revoked || decision.Cause.CauseOperationID != revoked.Cause.CauseOperationID || closed.EventID != decision.EventID || closed.LaunchID != worker.ID || api.ValidateTransportInvalidation(decision, closed.Receipt) != nil {
			return fault(api.CodeIntegrity, "grant capture collection lost its original revocation")
		}
	}
	return nil
}
