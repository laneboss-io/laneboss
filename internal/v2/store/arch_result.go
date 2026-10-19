package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
)

var _ archivejob.PartSink = (*Service)(nil)

// Fixed stages and durations only: no object, principal or storage selectors.
func archiveCost(stage string, elapsed time.Duration) {
	fmt.Fprintf(os.Stderr, "{\"event\":\"archive_result\",\"stage\":%q,\"elapsed_us\":%d}\n", stage, elapsed.Microseconds())
}

func (s *Service) archiveInput(ctx context.Context, db queryer, p api.WorkerPrincipal) (api.WorkerJobInput, error) {
	meta, raw, err := objectRow(ctx, db, p.Lease.Input.ID)
	if err != nil {
		return api.WorkerJobInput{}, err
	}
	if meta.Ref != p.Lease.Input || meta.SourceOperationID != p.Lease.OperationID || meta.Origin != "service" || meta.ACL.LifeID != p.Lease.Target.LifeID {
		return api.WorkerJobInput{}, fault(api.CodeIntegrity, "archive input changed its retained provenance")
	}
	input := api.WorkerJobInput{Schema: "laneboss.worker-input.v2", StageID: p.StageID, LeaseID: p.Lease.ID, Kind: "archive", OperationID: p.Lease.OperationID, EffectID: p.Lease.EffectID, Input: p.Lease.Input, Bytes: append([]byte(nil), raw...)}
	return input, api.ValidateWorkerInput(p, input, s.deps.Clock.Now())
}

func (s *Service) ArchivePart(ctx context.Context, scope api.Scope, leaseID api.ID, index uint64, data []byte) (ref api.BlobRef, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return ref, err
	}
	p, err := s.dataWorkerScope(ctx, s.db, scope, api.WorkerArchivePart)
	if err != nil {
		return ref, err
	}
	if p.Lease.Kind != "archive" || p.Lease.ID != leaseID || len(data) == 0 || len(data) > api.MaxChunkBytes || index >= 65536 {
		return ref, fault(api.CodeForbidden, "archive part is outside its current bounded worker job")
	}
	var r archiveRecord
	if err := storedProjection(ctx, s.db, "archive_job", p.Lease.OperationID, &r); err != nil {
		return ref, err
	}
	if index < uint64(len(r.Parts)) {
		meta, raw, err := objectRow(ctx, s.db, r.Parts[index].ID)
		if err != nil {
			return ref, err
		}
		if meta.Ref != r.Parts[index] || !bytes.Equal(raw, data) {
			return ref, fault(api.CodeIdempotencyConflict, "archive part retry changed its persisted bytes")
		}
		return meta.Ref, nil
	}
	if index != uint64(len(r.Parts)) || r.Ack != nil {
		return ref, fault(api.CodeConflict, "archive parts must append sequentially before result submission")
	}
	total := uint64(len(data))
	for _, part := range r.Parts {
		total += uint64(part.Bytes)
	}
	if total > r.Job.Plan.Budget.DiskBytes {
		return ref, fault(api.CodeBudget, "archive parts exceed the fixed worker disk budget")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ref, err
	}
	defer finish(tx, &resultErr)
	ref, err = s.archiveBytes(ctx, tx, r, "artifact", append([]byte(nil), data...))
	if err != nil {
		return ref, err
	}
	// Acknowledge only an independently selected SQL row, including its hash.
	meta, raw, err := objectRow(ctx, tx, ref.ID)
	if err != nil {
		return ref, err
	}
	if meta.Ref != ref || !bytes.Equal(raw, data) {
		return ref, fault(api.CodeIntegrity, "archive part failed persisted readback")
	}
	r.Parts = append(r.Parts, ref)
	if err := s.saveArchive(ctx, tx, r); err != nil {
		return ref, err
	}
	if err := tx.Commit(); err != nil {
		return ref, err
	}
	return ref, nil
}

func (s *Service) verifyArchiveBytes(ctx context.Context, db queryer, r archiveRecord, raw []byte) (archivejob.Completion, error) {
	started := time.Now()
	var result archivejob.Completion
	if api.DecodeObject(raw, &result) != nil || !sameDataBytes(raw, result) {
		return result, fault(api.CodeIntegrity, "archive completion is not its exact canonical retained bytes")
	}
	refs, f, err := s.archiveRefs(ctx, db, r)
	archiveCost("inventory", time.Since(started))
	if err != nil {
		return result, err
	}
	a := result.Receipt
	verified, err := time.Parse(time.RFC3339Nano, string(a.VerifiedAt))
	frozen, fe := time.Parse(time.RFC3339Nano, string(f.ObservedAt))
	if err != nil || fe != nil || verified.Before(frozen) || verified.After(s.deps.Clock.Now()) || a.ID != r.Input.ReceiptID || a.StoreID != s.storeID || a.LifeID != r.Lane.LifeID || a.Manifest != f.Snapshot || a.ArchiveSHA256 != result.Archive.SHA256 || a.ReadBackSHA256 != a.ArchiveSHA256 || !sameValue(result.Archive.Parts, r.Parts) {
		return result, fault(api.CodeIntegrity, "archive completion changed its reserved receipt, frozen input or persisted parts")
	}
	started = time.Now()
	meta, manifestBytes, err := objectRow(ctx, db, f.Snapshot.ID)
	if err != nil {
		return result, err
	}
	if meta.Ref != f.Snapshot {
		return result, fault(api.CodeIntegrity, "archive frozen manifest changed")
	}
	tree, err := archivejob.Manifest(manifestBytes)
	archiveCost("manifest_read", time.Since(started))
	if err != nil {
		return result, err
	}
	// Keep two bounded, independently loaded SQL objects for the interleaved
	// canonical source/archive reads. Do not walk/reload all parts per header.
	var cache [2]verifiedObject
	next := 0
	var reads time.Duration
	started = time.Now()
	digest, err := archivejob.ReadBack(ctx, result.Archive, tree, func(ctx context.Context, request api.BlobReadRequest) (api.BlobChunk, error) {
		ref, ok := refs[request.ObjectID]
		if !ok || request.Offset < 0 || request.Limit < 1 || request.Limit > api.MaxChunkBytes {
			return api.BlobChunk{}, fault(api.CodeForbidden, "archive verification read escaped its frozen inventory")
		}
		var row verifiedObject
		for _, saved := range cache {
			if saved.metadata.Ref.ID == ref.ID {
				row = saved
			}
		}
		if row.metadata.Ref.ID == "" {
			readStart := time.Now()
			meta, data, err := objectRow(ctx, db, ref.ID)
			reads += time.Since(readStart)
			if err != nil {
				return api.BlobChunk{}, err
			}
			row = verifiedObject{metadata: meta, data: data}
			cache[next] = row
			next = (next + 1) % len(cache)
		}
		if row.metadata.Ref != ref || row.metadata.ACL.Config != s.deps.Config || row.metadata.ACL.LifeID != r.Lane.LifeID || request.Offset > int64(len(row.data)) {
			return api.BlobChunk{}, fault(api.CodeIntegrity, "archive verification read changed its committed bytes")
		}
		data := append([]byte{}, row.data[request.Offset:min(int64(len(row.data)), request.Offset+int64(request.Limit))]...)
		return api.BlobChunk{ObjectID: ref.ID, Offset: request.Offset, Data: data, SHA256: api.Digest(hash(data))}, nil
	}, r.Job.Plan.Budget.DiskBytes)
	archiveCost("readback_sql", reads)
	archiveCost("readback_digest", time.Since(started)-reads)
	if err != nil {
		return result, err
	}
	if digest != a.ReadBackSHA256 {
		return result, fault(api.CodeIntegrity, "archive failed independent byte-exact verification")
	}
	return result, nil
}

// Called with the sole writer lock held by WorkerResult. The acknowledgement is
// durable before process observation, and never emits archive.verified itself.
func (s *Service) archiveResult(ctx context.Context, p api.WorkerPrincipal, submission api.WorkerResultSubmission) (receipt api.WorkerResultReceipt, resultErr error) {
	started := time.Now()
	var r archiveRecord
	if err := storedProjection(ctx, s.db, "archive_job", p.Lease.OperationID, &r); err != nil {
		return receipt, err
	}
	if r.Ack != nil {
		if !sameValue(r.Ack.Submission, submission) {
			return receipt, fault(api.CodeIdempotencyConflict, "archive result retry changed its input or bytes")
		}
		meta, raw, err := objectRow(ctx, s.db, r.Ack.Receipt.Result.ID)
		if err != nil {
			return receipt, err
		}
		if meta.Ref != r.Ack.Receipt.Result || !bytes.Equal(raw, submission.Result) {
			return receipt, fault(api.CodeIntegrity, "archive result acknowledgement lost its retained bytes")
		}
		return r.Ack.Receipt, nil
	}
	if submission.ExpectedGeneration != p.Lease.Generation || submission.InputSHA256 != p.Lease.Input.SHA256 || len(submission.Result) == 0 || len(submission.Result) > api.MaxFrameBytes {
		return receipt, fault(api.CodeConflict, "archive result changed its retained input or lease generation")
	}
	archiveCost("result_record", time.Since(started))
	if _, err := s.verifyArchiveBytes(ctx, s.db, r, submission.Result); err != nil {
		return receipt, err
	}
	started = time.Now()
	tx, err := s.db.BeginTx(ctx, nil)
	archiveCost("tx_begin", time.Since(started))
	if err != nil {
		return receipt, err
	}
	defer finish(tx, &resultErr)
	started = time.Now()
	ref, err := s.archiveBytes(ctx, tx, r, "worker_result", append([]byte(nil), submission.Result...))
	archiveCost("result_write", time.Since(started))
	if err != nil {
		return receipt, err
	}
	started = time.Now()
	event, err := s.archiveEvent(r, "blob.committed", ref)
	if err != nil {
		return receipt, err
	}
	event.Actor = p.Record.Actor
	seq, err := appendPrivateEvent(ctx, tx, event, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
	if err != nil {
		return receipt, err
	}
	receipt = api.WorkerResultReceipt{LeaseID: p.Lease.ID, StageID: p.StageID, Generation: p.Lease.Generation + 1, Result: ref, CommittedSeq: seq}
	if err := api.ValidateWorkerResult(p, submission, receipt, s.deps.Clock.Now()); err != nil {
		return receipt, err
	}
	worker := p.Lease
	worker.Generation++
	if err := put(ctx, tx, "worker_lease", worker.ID, worker.Generation, worker); err != nil {
		return receipt, err
	}
	r.Ack = &dataAcknowledgement{Submission: submission, Receipt: receipt}
	if err := s.saveArchive(ctx, tx, r); err != nil {
		return receipt, err
	}
	archiveCost("ack_write", time.Since(started))
	started = time.Now()
	if err := tx.Commit(); err != nil {
		return receipt, err
	}
	archiveCost("tx_commit", time.Since(started))
	s.notifyChanged()
	return receipt, nil
}

func (s *Service) CompleteArchive(ctx context.Context, scope api.Scope, lease api.EffectLease, observation api.ProcessObservation) (commit api.Commit, resultErr error) {
	// Native storage keeps its fence held; obtain its current measurement before
	// taking mu, then recheck SQL claim/life/policy/input fences under mu.
	job, err := s.ArchiveJob(ctx, scope, lease.Record.Effect.OperationID)
	if err != nil {
		return commit, err
	}
	s.mu.RLock()
	var prior archiveRecord
	err = storedProjection(ctx, s.db, "archive_job", job.Intent.OperationID, &prior)
	var frozen archivejob.Freeze
	if err == nil {
		_, frozen, err = s.archiveRefs(ctx, s.db, prior)
	}
	s.mu.RUnlock()
	if err != nil {
		return commit, err
	}
	if prior.Commit != nil {
		return s.replayArchive(ctx, scope, prior, lease, observation)
	}
	if s.deps.ArchiveNative == nil {
		return commit, api.NotImplemented("lb-v2-admin", "protected archive freeze recheck")
	}
	if err := s.deps.ArchiveNative.CheckArchiveFreeze(ctx, job.Intent, frozen); err != nil {
		return commit, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.archiveClaim(ctx, s.db, scope, lease)
	if err != nil {
		return commit, err
	}
	if r.Ack == nil || r.Process.ID == "" || observation.Handle != r.Process || observation.State != "exited" || observation.ExitCode == nil || *observation.ExitCode != 0 || observation.Signal != nil || observation.Survivors == nil || *observation.Survivors != 0 {
		return commit, fault(api.CodeContainmentUnknown, "archive completion lacks retained result and measured successful zero-survivor worker exit")
	}
	when, err := time.Parse(time.RFC3339Nano, string(observation.ObservedAt))
	if err != nil || when.IsZero() || when.After(s.deps.Clock.Now()) {
		return commit, fault(api.CodeContainmentUnknown, "archive worker exit has an invalid measurement time")
	}
	meta, raw, err := objectRow(ctx, s.db, r.Ack.Receipt.Result.ID)
	if err != nil {
		return commit, err
	}
	if meta.Ref != r.Ack.Receipt.Result || !bytes.Equal(raw, r.Ack.Submission.Result) {
		return commit, fault(api.CodeIntegrity, "archive result lost its independently retained bytes")
	}
	result, err := s.verifyArchiveBytes(ctx, s.db, r, raw)
	if err != nil {
		return commit, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return commit, err
	}
	defer finish(tx, &resultErr)
	outcome := api.EffectOutcome{EffectID: lease.Record.Effect.ID, ClaimID: lease.ClaimID, ExpectedGeneration: lease.Record.Generation, Status: "succeeded", Output: &r.Ack.Receipt.Result, Observation: &observation}
	event, err := s.archiveEvent(r, "archive.verified", result.Receipt)
	if err != nil {
		return commit, err
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))
	seq, err := appendPrivateEvent(ctx, tx, event, now)
	if err != nil {
		return commit, err
	}
	body, err := json.Marshal(result.Receipt)
	if err != nil {
		return commit, err
	}
	commit, err = s.finishOwnedEffect(ctx, tx, scope, lease, outcome, seq, &api.RPCReply{Result: body})
	if err != nil {
		return commit, err
	}
	r.Commit, r.Phase = &commit, "verified"
	if err := s.saveArchive(ctx, tx, r); err != nil {
		return commit, err
	}
	if err := tx.Commit(); err != nil {
		return commit, err
	}
	s.notifyChanged()
	return commit, nil
}

func (s *Service) replayArchive(ctx context.Context, scope api.Scope, r archiveRecord, lease api.EffectLease, observation api.ProcessObservation) (api.Commit, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.dataScope(ctx, s.db, scope); err != nil {
		return api.Commit{}, err
	}
	record, err := effectRow(ctx, s.db, r.Job.Lease.EffectID)
	if err != nil {
		return api.Commit{}, err
	}
	if record.Outcome == nil || record.ClaimID != lease.ClaimID || record.ClaimantID != scope.Actor.ID || record.Outcome.ExpectedGeneration != lease.Record.Generation || record.Outcome.Observation == nil || !sameValue(*record.Outcome.Observation, observation) {
		return api.Commit{}, fault(api.CodeConflict, "archive replay differs from its committed original outcome")
	}
	commit := *r.Commit
	commit.Replayed = true
	return commit, nil
}
