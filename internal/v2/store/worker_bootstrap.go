package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type dataAcknowledgement struct {
	Submission api.WorkerResultSubmission
	Receipt    api.WorkerResultReceipt
}

// WorkerBinding is a protected reverse lookup for the native identity module.
// Peer facts never create a record. Identity additionally verifies the live
// helper containment registry and the transport pins each actual writer.
func (s *Service) WorkerBinding(ctx context.Context, endpoint api.InstalledBinding, peer api.PeerFacts) (api.WorkerPrincipal, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.WorkerPrincipal{}, err
	}
	return s.dataPrincipal(ctx, s.db, endpoint, peer, api.WorkerInputRead)
}

func (s *Service) dataPrincipal(ctx context.Context, db queryer, endpoint api.InstalledBinding, peer api.PeerFacts, operation api.WorkerOperation) (api.WorkerPrincipal, error) {
	var empty api.WorkerPrincipal
	if endpoint.Class != api.EndpointWorker || endpoint.Config != s.deps.Config || !wire.ValidID(string(endpoint.WorkerLeaseID)) {
		return empty, fault(api.CodeUnauthenticated, "worker requires its protected installed endpoint")
	}
	var raw []byte
	err := db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='data_stage' AND json_extract(data,'$.Stage.Worker.ID')=?", string(endpoint.WorkerLeaseID)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		var usage api.WorkerLease
		found := storedProjection(ctx, db, "worker_lease", endpoint.WorkerLeaseID, &usage)
		if found != nil && !absent(found) {
			return empty, found
		}
		if found == nil && usage.Kind == "usage" {
			return s.usagePrincipal(ctx, db, endpoint, peer, operation)
		}
		if found == nil && usage.Kind == "test" {
			return s.reviewPrincipal(ctx, db, endpoint, peer, operation)
		}
		return s.otherWorkerPrincipal(ctx, db, endpoint, peer, operation)
	}
	if err != nil {
		return empty, err
	}
	var saved dataStageRecord
	if err := decodeStored(raw, &saved); err != nil {
		return empty, err
	}
	stage := saved.Stage
	if saved.Endpoint == nil || !sameValue(*saved.Endpoint, endpoint) {
		return empty, fault(api.CodeForbidden, "worker endpoint belongs to another frozen job")
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, db, "launch_plan", stage.Reservation.ID, &plan); err != nil {
		return empty, err
	}
	if err := s.checkDataRecord(ctx, db, plan, saved); err != nil {
		return empty, err
	}
	if err := s.currentLaunch(ctx, db, plan); err != nil {
		return empty, err
	}
	binding, err := s.launchBinding(ctx, db, stage.WorkerLaunchID)
	if err != nil {
		return empty, err
	}
	record := binding.Record
	var current api.EndpointProjection
	if err := storedProjection(ctx, db, "endpoint", record.ID, &current); err != nil {
		return empty, err
	}
	if current.Revoked || !sameValue(current.Binding, endpoint) || record.Revoked || record.Actor != saved.Actor || record.Actor.Kind != "worker" || record.Actor.Level != 0 || record.Actor.Role != "" || record.UIDLeaseID != saved.Allocation.ID || record.HostUID != saved.Allocation.UID || peer.HostGID != saved.Allocation.GID || record.ContainmentID != saved.Allocation.ContainmentID || record.GrantSetID != stage.Grants.ID || record.GrantsSHA256 != stage.Grants.SHA256 || record.PolicyGeneration != stage.Reservation.PolicyGeneration {
		return empty, fault(api.CodeUnauthenticated, "worker principal differs from its committed helper allocation")
	}
	claim, err := effectRow(ctx, db, stage.Worker.EffectID)
	if err != nil {
		return empty, err
	}
	if claim.Outcome != nil {
		var result api.LaunchDataResult
		if err := storedProjection(ctx, db, "data_measurement", stage.ID, &result); err != nil {
			return empty, err
		}
		if claim.Generation != stage.Claim.Record.Generation+1 || claim.ClaimID != stage.Claim.ClaimID || claim.ClaimantID != stage.Claim.Record.ClaimantID || s.checkDataOutcome(ctx, db, saved, result, *claim.Outcome) != nil {
			return empty, fault(api.CodeConflict, "worker completed claim differs from its original result")
		}
	} else if claim.ClaimantID != stage.Claim.Record.ClaimantID || !sameValue(claim, stage.Claim.Record) {
		return empty, fault(api.CodeConflict, "worker has no current original child claim")
	}
	boot, _, found := strings.Cut(record.ProcessGeneration, ":")
	peerBoot, _, peerFound := strings.Cut(peer.ProcessGeneration, ":")
	if !found || !peerFound || boot == "" || boot != peerBoot {
		return empty, fault(api.CodeContainmentUnknown, "worker native generation differs from the retained boot")
	}
	p := api.WorkerPrincipal{StageID: stage.ID, Lease: stage.Worker, Record: record, Endpoint: endpoint, Peer: peer, BootID: boot, AllocationGeneration: stage.Storage.Generation, Claim: stage.Claim, CancellationEpoch: stage.Reservation.CancellationEpoch}
	if err := api.ValidateWorkerPrincipal(p, endpoint, peer, operation, s.deps.Clock.Now()); err != nil {
		return empty, err
	}
	return p, nil
}

func (s *Service) dataWorkerScope(ctx context.Context, db queryer, scope api.Scope, operation api.WorkerOperation) (api.WorkerPrincipal, error) {
	if scope.Config != s.deps.Config || scope.Actor.Kind != "worker" || scope.Connection == nil || scope.Frame == nil || scope.Connection.Peer() == nil {
		return api.WorkerPrincipal{}, fault(api.CodeUnauthenticated, "worker bootstrap requires its native authenticated frame")
	}
	if err := scope.Frame.Verify(ctx, scope.Connection); err != nil {
		return api.WorkerPrincipal{}, err
	}
	if err := scope.Connection.Peer().Alive(ctx); err != nil {
		return api.WorkerPrincipal{}, err
	}
	facts, err := scope.Connection.Peer().Facts(ctx)
	if err != nil {
		return api.WorkerPrincipal{}, err
	}
	p, err := s.dataPrincipal(ctx, db, scope.Connection.Binding(), facts, operation)
	if err != nil {
		return p, err
	}
	if p.Record.Actor != scope.Actor || p.Record.ID != scope.LaunchID || p.Record.EndpointGeneration != scope.EndpointGeneration {
		return api.WorkerPrincipal{}, fault(api.CodeUnauthenticated, "worker scope differs from its own authenticated principal")
	}
	return p, nil
}

func (s *Service) WorkerInput(ctx context.Context, scope api.Scope, request api.WorkerInputRequest) (api.WorkerJobInput, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.WorkerJobInput{}, err
	}
	p, err := s.dataWorkerScope(ctx, s.db, scope, api.WorkerInputRead)
	if err != nil {
		return api.WorkerJobInput{}, err
	}
	if request.LeaseID != p.Lease.ID {
		return api.WorkerJobInput{}, fault(api.CodeForbidden, "worker cannot read another job input")
	}
	if p.Lease.Kind == "archive" {
		return s.archiveInput(ctx, s.db, p)
	}
	if p.Lease.Kind == "judge" {
		return s.judgeInput(ctx, s.db, p)
	}
	if p.Lease.Kind == "channel" {
		return s.channelInput(ctx, s.db, p)
	}
	if p.Lease.Kind == "export" || p.Lease.Kind == "test" {
		return s.reviewInput(ctx, s.db, p)
	}
	metadata, raw, err := objectRow(ctx, s.db, p.Lease.Input.ID)
	if err != nil {
		return api.WorkerJobInput{}, err
	}
	if metadata.Ref != p.Lease.Input || metadata.SourceOperationID != p.Lease.OperationID || metadata.Origin != "service" || metadata.ACL.Audience != "service" || metadata.ACL.Owner.Kind != "service" || metadata.ACL.LifeID != p.Lease.Target.LifeID {
		return api.WorkerJobInput{}, fault(api.CodeIntegrity, "worker input lost its private immutable provenance")
	}
	input := api.WorkerJobInput{Schema: "laneboss.worker-input.v2", StageID: p.StageID, LeaseID: p.Lease.ID, Kind: p.Lease.Kind, OperationID: p.Lease.OperationID, EffectID: p.Lease.EffectID, Input: p.Lease.Input, Bytes: append([]byte(nil), raw...)}
	return input, api.ValidateWorkerInput(p, input, s.deps.Clock.Now())
}

func (s *Service) WorkerResult(ctx context.Context, scope api.Scope, submission api.WorkerResultSubmission) (receipt api.WorkerResultReceipt, resultErr error) {
	started := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	archiveCost("writer_wait", time.Since(started))
	if err := s.available(); err != nil {
		return receipt, err
	}
	started = time.Now()
	p, err := s.dataWorkerScope(ctx, s.db, scope, api.WorkerResultAppend)
	archiveCost("store_scope", time.Since(started))
	if err != nil {
		return receipt, err
	}
	if p.Lease.Kind == "channel" {
		return s.channelResult(ctx, p, submission)
	}
	if p.Lease.Kind == "judge" {
		return s.judgeResult(ctx, p, submission)
	}
	if p.Lease.Kind == "usage" {
		return s.usageResult(ctx, p, submission)
	}
	if p.Lease.Kind == "export" || p.Lease.Kind == "test" {
		return s.reviewWorkerResult(ctx, p, submission)
	}
	if submission.LeaseID != p.Lease.ID {
		return receipt, fault(api.CodeForbidden, "worker cannot submit another job result")
	}
	if p.Lease.Kind == "archive" {
		return s.archiveResult(ctx, p, submission)
	}
	var previous dataAcknowledgement
	err = storedProjection(ctx, s.db, "data_ack", p.Lease.ID, &previous)
	if err == nil {
		if !sameValue(previous.Submission, submission) {
			return receipt, fault(api.CodeIdempotencyConflict, "worker result retry changed its exact bytes or input")
		}
		if err := api.ValidateWorkerResult(p, submission, previous.Receipt, s.deps.Clock.Now()); err != nil {
			return receipt, err
		}
		return previous.Receipt, nil
	}
	if !absent(err) {
		return receipt, err
	}
	if submission.ExpectedGeneration != p.Lease.Generation || submission.InputSHA256 != p.Lease.Input.SHA256 || len(submission.Result) == 0 || len(submission.Result) > api.MaxFrameBytes {
		return receipt, fault(api.CodeConflict, "worker result changed its frozen input or generation")
	}
	var saved dataStageRecord
	if err := storedProjection(ctx, s.db, "data_stage", p.StageID, &saved); err != nil {
		return receipt, err
	}
	if _, err := s.validateDataOutput(ctx, s.db, saved, submission.Result); err != nil {
		return receipt, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return receipt, err
	}
	defer finish(tx, &resultErr)
	ref, err := s.retainDataBytes(ctx, tx, saved.Stage, "worker_result", "private", append([]byte(nil), submission.Result...))
	if err != nil {
		return receipt, err
	}
	var head api.Sequence
	if err := tx.QueryRowContext(ctx, "SELECT coalesce(max(seq),0) FROM events").Scan(&head); err != nil {
		return receipt, err
	}
	receipt = api.WorkerResultReceipt{LeaseID: p.Lease.ID, StageID: p.StageID, Generation: p.Lease.Generation + 1, Result: ref, CommittedSeq: head + 1}
	if err := api.ValidateWorkerResult(p, submission, receipt, s.deps.Clock.Now()); err != nil {
		return receipt, err
	}
	id, err := wire.NewID()
	if err != nil {
		return receipt, err
	}
	if err := s.appendDataEvent(ctx, tx, saved.Stage, scope.Actor, id, "blob.committed", ref, receipt.CommittedSeq); err != nil {
		return receipt, err
	}
	lease := p.Lease
	lease.Generation++
	if err := put(ctx, tx, "worker_lease", lease.ID, lease.Generation, lease); err != nil {
		return receipt, err
	}
	if err := put(ctx, tx, "data_ack", lease.ID, 1, dataAcknowledgement{Submission: submission, Receipt: receipt}); err != nil {
		return receipt, err
	}
	if err := tx.Commit(); err != nil {
		return receipt, err
	}
	s.notifyChanged()
	return receipt, nil
}

func (s *Service) validateDataOutput(ctx context.Context, db queryer, saved dataStageRecord, raw []byte) (api.LaunchData, error) {
	var d api.LaunchData
	if err := api.DecodeObject(raw, &d); err != nil {
		return d, err
	}
	if !sameDataBytes(raw, d) {
		return d, fault(api.CodeIntegrity, "worker result must retain exact JCS LaunchData bytes")
	}
	stage, storage := saved.Stage, saved.Stage.Storage.Storage
	copies, err := api.ValidateDataCopyProjections(stage.Inputs, stage.Storage)
	if err != nil {
		return d, err
	}
	if d.ReservationID != stage.Reservation.ID || d.Target != stage.Reservation.Target || d.LeaseID != stage.AgentLeaseID || d.Source != stage.Inputs.Sources.Project || d.Home != storage.Home || d.Workspace.ID != storage.WorkspaceID || d.Workspace.ProjectID != d.Source.ProjectID || d.Workspace.Base != d.Source.Base || d.Workspace.Branch != "lane/"+string(d.Target.LifeID) || d.Workspace.LogicalCWD != "/work/main" || d.Workspace.Snapshot != saved.Output || d.Materialization.Manifest != saved.Output || d.Materialization.GrantSetID != stage.Reservation.GrantSetID || len(d.Materialization.Objects) != 1+len(copies) {
		return d, fault(api.CodeIntegrity, "worker result differs from its sealed storage, grant or source")
	}
	object := d.Materialization.Objects[0]
	if object.GrantID != d.Source.GrantID || object.WorkspaceID != storage.WorkspaceID || object.SourceIdentity != stage.Storage.SourceIdentity || object.DestinationIdentity != stage.Storage.WorkspaceIdentity || object.SnapshotSHA256 != saved.Output.SHA256 {
		return d, fault(api.CodeIntegrity, "worker result changed the opened source or destination measurement")
	}
	for i, copy := range copies {
		expected, err := copy.Receipt(storage.WorkspaceID)
		if err != nil || d.Materialization.Objects[i+1] != expected {
			return d, fault(api.CodeIntegrity, "worker result changed an opened copy projection")
		}
	}
	meta, _, err := objectRow(ctx, db, saved.Output.ID)
	if err != nil {
		return d, err
	}
	if meta.Ref != saved.Output || meta.SourceOperationID != stage.Reservation.OperationID {
		return d, fault(api.CodeIntegrity, "worker output manifest bytes changed")
	}
	return d, nil
}

func (s *Service) appendDataEvent(ctx context.Context, tx *sql.Tx, stage api.LaunchDataStage, actor api.Actor, id api.ID, kind api.EventKind, value any, seq api.Sequence) error {
	if seq == 0 || seq > 1<<53-1 {
		return fault(api.CodeIntegrity, "materialization journal sequence exhausted")
	}
	var chain string
	err := tx.QueryRowContext(ctx, "SELECT chain FROM events ORDER BY seq DESC LIMIT 1").Scan(&chain)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	r := stage.Reservation
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))
	event := api.Event{Schema: api.SchemaVersion, ID: id, Seq: seq, Config: r.Config, Kind: kind, Actor: actor, RequestedBy: r.RequestedBy, OperationID: r.OperationID, RequestID: r.RequestID, LifeID: r.Target.LifeID, Run: r.Target.Run, RootLifeID: r.RootLifeID, ParentLifeID: r.ParentLifeID, StarterChain: append([]api.ID{}, r.StarterChain...), StarterEventSeq: r.StarterEventSeq, Origin: "service", Payload: payload, RecordedAt: now, RequestedAt: now, ObservedAt: now}
	if err := wire.ValidateEvent(event); err != nil {
		return err
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO events VALUES(?,?,?,?,?,?)", uint64(seq), string(id), encoded, encoded, hash(encoded), hash(append([]byte(chain), encoded...)))
	return err
}

func (s *Service) DataReceipt(ctx context.Context, scope api.Scope, id api.ID) (api.WorkerResultReceipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	saved, err := s.loadDataStage(ctx, s.db, scope, id, false)
	if err != nil {
		return api.WorkerResultReceipt{}, err
	}
	var ack dataAcknowledgement
	if err := storedProjection(ctx, s.db, "data_ack", saved.Stage.Worker.ID, &ack); err != nil {
		return api.WorkerResultReceipt{}, err
	}
	meta, raw, err := objectRow(ctx, s.db, ack.Receipt.Result.ID)
	if err != nil {
		return api.WorkerResultReceipt{}, err
	}
	if meta.Ref != ack.Receipt.Result || !bytes.Equal(raw, ack.Submission.Result) || meta.SourceOperationID != saved.Stage.Reservation.OperationID {
		return api.WorkerResultReceipt{}, fault(api.CodeIntegrity, "worker acknowledgement lost its retained exact bytes")
	}
	return ack.Receipt, nil
}

func (s *Service) DataResult(ctx context.Context, scope api.Scope, id api.ID) (api.LaunchDataResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	saved, err := s.loadDataStage(ctx, s.db, scope, id, false)
	if err != nil {
		return api.LaunchDataResult{}, err
	}
	var result api.LaunchDataResult
	if err := storedProjection(ctx, s.db, "data_measurement", id, &result); err != nil {
		return result, err
	}
	current, err := effectRow(ctx, s.db, saved.Stage.Worker.EffectID)
	if err != nil {
		return result, err
	}
	if current.Outcome == nil {
		return api.LaunchDataResult{}, fault(api.CodeNotFound, "materialization measurement awaits its effect commit")
	}
	if err := s.checkDataOutcome(ctx, s.db, saved, result, *current.Outcome); err != nil {
		return api.LaunchDataResult{}, err
	}
	return result, nil
}

// Measurement is retained before completion; only the existing EffectStore
// atomically makes it visible as completed. A crash between these steps can
// finish the same measured effect and cannot execute another worker.
func (s *Service) CompleteMaterialization(ctx context.Context, scope api.Scope, id api.ID, result api.LaunchDataResult) (api.Commit, error) {
	if err := s.recordDataMeasurement(ctx, scope, id, result); err != nil {
		return api.Commit{}, err
	}
	stage, err := s.DataStage(ctx, scope, id)
	if err != nil {
		return api.Commit{}, err
	}
	return s.CompleteEffect(ctx, scope, api.EffectOutcome{EffectID: stage.Worker.EffectID, ClaimID: stage.Claim.ClaimID, ExpectedGeneration: stage.Claim.Record.Generation, Status: "succeeded", Output: &result.ResultReceipt.Result, Observation: &result.Observation})
}

func (s *Service) recordDataMeasurement(ctx context.Context, scope api.Scope, id api.ID, result api.LaunchDataResult) (resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	saved, err := s.loadDataStage(ctx, s.db, scope, id, false)
	if err != nil {
		return err
	}
	if scope.Actor.ID != saved.Stage.Claim.Record.ClaimantID {
		return fault(api.CodeForbidden, "materialization completion belongs to its outbox claimant")
	}
	if err := api.ValidateLaunchDataResult(saved.Stage, result); err != nil {
		return err
	}
	var ack dataAcknowledgement
	if err := storedProjection(ctx, s.db, "data_ack", saved.Stage.Worker.ID, &ack); err != nil {
		return err
	}
	if ack.Receipt != result.ResultReceipt || !sameDataBytes(ack.Submission.Result, result.Data) || result.Manifest != saved.Output {
		return fault(api.CodeIntegrity, "materialization measurement changed its actual worker acknowledgement")
	}
	var prior api.LaunchDataResult
	err = storedProjection(ctx, s.db, "data_measurement", id, &prior)
	if err == nil {
		if !sameValue(prior, result) {
			return fault(api.CodeIdempotencyConflict, "materialization measurement already differs")
		}
		return nil
	}
	if !absent(err) {
		return err
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, s.db, "launch_plan", saved.Stage.Reservation.ID, &plan); err != nil {
		return err
	}
	parent, err := effectRow(ctx, s.db, saved.Stage.ParentEffectID)
	if err != nil {
		return err
	}
	if err := s.checkDataParent(ctx, s.db, plan, parent); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer finish(tx, &resultErr)
	if err := put(ctx, tx, "data_measurement", id, 1, result); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) checkDataOutcome(ctx context.Context, db queryer, saved dataStageRecord, result api.LaunchDataResult, outcome api.EffectOutcome) error {
	if err := api.ValidateLaunchDataResult(saved.Stage, result); err != nil {
		return err
	}
	if outcome.Status != "succeeded" || outcome.Output == nil || *outcome.Output != result.ResultReceipt.Result || outcome.Observation == nil || !sameValue(*outcome.Observation, result.Observation) || outcome.ClaimID != saved.Stage.Claim.ClaimID || outcome.ExpectedGeneration != saved.Stage.Claim.Record.Generation {
		return fault(api.CodeIntegrity, "materialization effect differs from its acknowledged measured completion")
	}
	var ack dataAcknowledgement
	if err := storedProjection(ctx, db, "data_ack", saved.Stage.Worker.ID, &ack); err != nil {
		return err
	}
	if ack.Receipt != result.ResultReceipt || !sameDataBytes(ack.Submission.Result, result.Data) {
		return fault(api.CodeIntegrity, "materialization result differs from its exact committed receipt")
	}
	return nil
}

func (s *Service) validateMaterializationOutcome(ctx context.Context, db queryer, record api.EffectRecord, outcome api.EffectOutcome) error {
	if record.Effect.Worker == nil || record.Effect.Worker.Kind != "materialize" {
		return nil
	}
	var raw []byte
	if err := db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='data_stage' AND json_extract(data,'$.Stage.Worker.EffectID')=?", string(record.Effect.ID)).Scan(&raw); err != nil {
		return fault(api.CodeForbidden, "materialization effect has no original retained stage")
	}
	var saved dataStageRecord
	if err := decodeStored(raw, &saved); err != nil {
		return err
	}
	var result api.LaunchDataResult
	if err := storedProjection(ctx, db, "data_measurement", saved.Stage.ID, &result); err != nil {
		return err
	}
	return s.checkDataOutcome(ctx, db, saved, result, outcome)
}
