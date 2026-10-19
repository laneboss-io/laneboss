package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func (s *Service) UsageJobForClaim(ctx context.Context, scope api.Scope, claim api.EffectLease) (api.UsageJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	stage, err := s.usageClaim(ctx, s.db, scope, claim, false)
	return stage.Job, err
}

func (s *Service) UsageGrant(ctx context.Context, scope api.Scope, grants api.GrantSet) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.usageOwner(ctx, s.db, scope); err != nil {
		return false, err
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='usage_stage' AND json_extract(data,'$.Job.grants.id')=?", string(grants.ID)).Scan(&raw)
	if absent(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var stage usageStage
	if err := decodeStored(raw, &stage); err != nil {
		return true, err
	}
	if !sameValue(stage.Job.Grants, grants) {
		return true, fault(api.CodeConflict, "usage narrow grants changed after preparation")
	}
	return true, s.usageFence(ctx, s.db, stage.Job)
}

func usageForLease(ctx context.Context, db queryer, id api.ID) (stage usageStage, err error) {
	var raw []byte
	err = db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='usage_stage' AND json_extract(data,'$.Job.lease.ID')=?", string(id)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return stage, fault(api.CodeNotFound, "usage lease has no installed stage")
	}
	if err == nil {
		err = decodeStored(raw, &stage)
	}
	return stage, err
}

func (s *Service) usagePrincipal(ctx context.Context, db queryer, endpoint api.InstalledBinding, peer api.PeerFacts, operation api.WorkerOperation) (api.WorkerPrincipal, error) {
	var empty api.WorkerPrincipal
	stage, err := usageForLease(ctx, db, endpoint.WorkerLeaseID)
	if err != nil {
		return empty, err
	}
	if err := s.usageFence(ctx, db, stage.Job); err != nil {
		return empty, err
	}
	var lease api.WorkerLease
	if err := storedProjection(ctx, db, "worker_lease", endpoint.WorkerLeaseID, &lease); err != nil {
		return empty, err
	}
	expected := stage.Job.Lease
	expected.ConsumedBy, expected.Generation = stage.Job.LaunchID, expected.Generation+1
	assigned := expected
	var ack dataAcknowledgement
	ackErr := storedProjection(ctx, db, "usage_ack", lease.ID, &ack)
	if ackErr == nil {
		expected.Generation = ack.Receipt.Generation
	} else if !absent(ackErr) {
		return empty, ackErr
	}
	if !sameValue(expected, lease) || stage.Native == nil || stage.Native.Endpoint == nil || !sameValue(*stage.Native.Endpoint, endpoint) {
		return empty, fault(api.CodeForbidden, "usage lease or endpoint differs from its actual frozen job")
	}
	binding, err := s.launchBinding(ctx, db, stage.Job.LaunchID)
	if err != nil {
		return empty, err
	}
	var current api.EndpointProjection
	if err := storedProjection(ctx, db, "endpoint", binding.Record.ID, &current); err != nil {
		return empty, err
	}
	record := binding.Record
	if current.Revoked || !sameValue(current.Binding, endpoint) || record.Revoked || record.Actor != stage.Job.Actor ||
		record.HostUID != stage.Native.Allocation.UID || peer.HostUID != record.HostUID || peer.HostGID != stage.Native.Allocation.GID ||
		record.ContainmentID != peer.ContainmentID || record.UIDLeaseID != stage.Native.Allocation.ID || record.GrantsSHA256 != stage.Job.Grants.SHA256 {
		return empty, fault(api.CodeUnauthenticated, "usage worker differs from its committed native identity")
	}
	claim, err := effectRow(ctx, db, lease.EffectID)
	if err != nil {
		return empty, err
	}
	if claim.Effect.Worker == nil || !sameValue(*claim.Effect.Worker, stage.Job.Plan) || claim.Effect.Context == nil {
		return empty, fault(api.CodeConflict, "usage worker lost its original active claim")
	}
	if claim.Outcome != nil {
		if stage.Observation == nil || claim.Outcome.Observation == nil || !sameValue(*claim.Outcome.Observation, *stage.Observation) ||
			stage.Claim.ClaimID != claim.ClaimID || claim.Generation != stage.Claim.Record.Generation+1 {
			return empty, fault(api.CodeIntegrity, "usage completed claim lost its original measured retirement")
		}
		claim = stage.Claim.Record
	}
	boot, _, found := strings.Cut(peer.ProcessGeneration, ":")
	recordBoot, _, recordFound := strings.Cut(record.ProcessGeneration, ":")
	if !found || !recordFound || boot != recordBoot || boot == "" {
		return empty, fault(api.CodeContainmentUnknown, "usage worker has another boot lifetime")
	}
	p := api.WorkerPrincipal{StageID: stage.Job.ID, Lease: assigned, Record: record, Endpoint: endpoint, Peer: peer, BootID: boot,
		AllocationGeneration: endpoint.InstallationGeneration, CancellationEpoch: stage.Job.CancellationEpoch,
		Claim: api.EffectLease{Record: claim, ClaimID: claim.ClaimID, ExpiresAt: claim.ClaimExpiresAt}}
	if err := api.ValidateWorkerPrincipal(p, endpoint, peer, operation, s.deps.Clock.Now()); err != nil {
		return empty, err
	}
	return p, nil
}

func (s *Service) usageResult(ctx context.Context, p api.WorkerPrincipal, submission api.WorkerResultSubmission) (receipt api.WorkerResultReceipt, resultErr error) {
	if submission.LeaseID != p.Lease.ID || submission.ExpectedGeneration != p.Lease.Generation || submission.InputSHA256 != p.Lease.Input.SHA256 || len(submission.Result) == 0 || len(submission.Result) > api.MaxFrameBytes {
		return receipt, fault(api.CodeConflict, "usage result changed its frozen input or generation")
	}
	var previous dataAcknowledgement
	err := storedProjection(ctx, s.db, "usage_ack", p.Lease.ID, &previous)
	if err == nil {
		if !sameValue(previous.Submission, submission) {
			return receipt, fault(api.CodeIdempotencyConflict, "usage result retry changed its exact bytes")
		}
		return previous.Receipt, api.ValidateWorkerResult(p, submission, previous.Receipt, s.deps.Clock.Now())
	}
	if !absent(err) {
		return receipt, err
	}
	var output struct {
		Raw        []byte        `json:"raw"`
		ExitCode   int           `json:"exit_code"`
		ObservedAt api.Timestamp `json:"observed_at"`
	}
	if err := api.DecodeObject(submission.Result, &output); err != nil {
		return receipt, err
	}
	observed, err := time.Parse(time.RFC3339Nano, string(output.ObservedAt))
	if err != nil || observed.After(s.deps.Clock.Now()) || len(output.Raw) == 0 || len(output.Raw) > api.MaxFrameBytes {
		return receipt, fault(api.CodeIntegrity, "usage result has no bounded actual command observation")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return receipt, err
	}
	defer finish(tx, &resultErr)
	id, err := wire.NewID()
	if err != nil {
		return receipt, err
	}
	ref, err := s.retain(context.WithValue(ctx, dataObjectKey{}, s), tx, api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: p.Claim.Record.ClaimantID}}, api.ObjectWrite{ObjectKey: id, Class: "worker_result", Bytes: submission.Result, SHA256: api.Digest(hash(submission.Result)), Origin: "service",
		ACL: api.ObjectACL{Config: s.deps.Config, Owner: p.Record.Actor, LifeID: p.Lease.Target.LifeID, Audience: "service", Generation: 1}}, p.Lease.OperationID, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
	if err != nil {
		return receipt, err
	}
	eventID, err := wire.NewID()
	if err != nil {
		return receipt, err
	}
	eventRaw, err := canonicalValue(ref)
	if err != nil {
		return receipt, err
	}
	seq, err := appendPrivateEvent(ctx, tx, api.Event{Schema: api.SchemaVersion, ID: eventID, Config: s.deps.Config, Kind: "blob.committed", Actor: p.Record.Actor, RequestedBy: p.Claim.Record.Effect.Context.RequestedBy,
		RequestID: p.Claim.Record.Effect.Context.CauseRequestID, OperationID: p.Lease.OperationID, LifeID: p.Lease.Target.LifeID, Run: p.Lease.Target.Run, Origin: "service", Payload: eventRaw}, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
	if err != nil {
		return receipt, err
	}
	receipt = api.WorkerResultReceipt{LeaseID: p.Lease.ID, StageID: p.StageID, Generation: p.Lease.Generation + 1, Result: ref, CommittedSeq: seq}
	if err := api.ValidateWorkerResult(p, submission, receipt, s.deps.Clock.Now()); err != nil {
		return receipt, err
	}
	lease := p.Lease
	lease.Generation++
	if err := put(ctx, tx, "worker_lease", lease.ID, lease.Generation, lease); err != nil {
		return receipt, err
	}
	if err := put(ctx, tx, "usage_ack", lease.ID, 1, dataAcknowledgement{Submission: submission, Receipt: receipt}); err != nil {
		return receipt, err
	}
	return receipt, tx.Commit()
}

func (s *Service) UsageOwnsEffect(ctx context.Context, scope api.Scope, effect api.Effect) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if effect.Worker == nil || effect.Worker.Kind != "usage" {
		return false, nil
	}
	if err := s.usageOwner(ctx, s.db, scope); err != nil {
		return false, err
	}
	if effect.Context == nil {
		return false, fault(api.CodeIntegrity, "usage effect has no cause")
	}
	stage, err := usageStageFor(ctx, s.db, effect.Context.ID)
	if err != nil {
		return false, err
	}
	if !sameValue(stage.Job.Plan, *effect.Worker) || stage.Job.Lease.EffectID != effect.ID {
		return false, fault(api.CodeIntegrity, "usage effect differs from its durable owner")
	}
	return true, nil
}

func (s *Service) RecordUsageRetirement(ctx context.Context, scope api.Scope, id api.ID, observation api.ProcessObservation) (resultErr error) {
	s.mu.Lock()
	if err := s.usageOwner(ctx, s.db, scope); err != nil {
		s.mu.Unlock()
		return err
	}
	stage, err := usageStageFor(ctx, s.db, id)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if stage.Native == nil || observation.Handle.ID != stage.Job.LaunchID || observation.Handle.Target != stage.Job.Lease.Target || observation.Handle.ContainmentID != stage.Native.Allocation.ContainmentID || observation.State != "exited" || observation.ExitCode == nil || observation.Survivors == nil || *observation.Survivors != 0 {
		s.mu.Unlock()
		return fault(api.CodeContainmentUnknown, "usage collection lacks its original measured quiescence")
	}
	stage.Observation = &observation
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if err = saveUsage(ctx, tx, stage); err == nil {
		err = tx.Commit()
	} else {
		err = errors.Join(err, tx.Rollback())
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	var ack dataAcknowledgement
	s.mu.RLock()
	err = storedProjection(ctx, s.db, "usage_ack", stage.Job.Lease.ID, &ack)
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	status := "succeeded"
	if *observation.ExitCode != 0 || observation.Signal != nil {
		status = "failed"
	}
	_, err = s.CompleteEffect(ctx, scope, api.EffectOutcome{EffectID: stage.Job.Lease.EffectID, ClaimID: stage.Claim.ClaimID, ExpectedGeneration: stage.Claim.Record.Generation, Status: status, Output: &ack.Receipt.Result, Observation: &observation})
	return err
}
