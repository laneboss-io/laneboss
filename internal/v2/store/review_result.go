package store

import (
	"bytes"
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

func (s *Service) reviewInput(ctx context.Context, db queryer, p api.WorkerPrincipal) (api.WorkerJobInput, error) {
	meta, raw, err := objectRow(ctx, db, p.Lease.Input.ID)
	if err != nil {
		return api.WorkerJobInput{}, err
	}
	if meta.Ref != p.Lease.Input || meta.SourceOperationID != p.Lease.OperationID || meta.Origin != "service" || meta.ACL.Owner.Kind != "service" || meta.ACL.LifeID != p.Lease.Target.LifeID || meta.ACL.Audience != "private" {
		return api.WorkerJobInput{}, fault(api.CodeIntegrity, "review input lost its original private provenance")
	}
	input := api.WorkerJobInput{Schema: "laneboss.worker-input.v2", StageID: p.StageID, LeaseID: p.Lease.ID, Kind: p.Lease.Kind, OperationID: p.Lease.OperationID, EffectID: p.Lease.EffectID, Input: p.Lease.Input, Bytes: append([]byte{}, raw...)}
	return input, api.ValidateWorkerInput(p, input, s.deps.Clock.Now())
}

func (s *Service) reviewObject(ctx context.Context, db queryer, p api.WorkerPrincipal, request api.BlobReadRequest) (api.BlobChunk, error) {
	var r reviewRecord
	if err := storedProjection(ctx, db, "review_job", p.Lease.OperationID, &r); err != nil {
		return api.BlobChunk{}, err
	}
	if r.Test != nil {
		return s.testObject(ctx, db, r, request)
	}
	refs := map[api.ID]api.BlobRef{}
	add := func(ref api.BlobRef) error {
		if prior, ok := refs[ref.ID]; ok && prior != ref {
			return fault(api.CodeIntegrity, "review input closure reused an object identity")
		}
		if len(refs) >= 4096 {
			return fault(api.CodeBudget, "review input closure exceeds its bound")
		}
		refs[ref.ID] = ref
		return nil
	}
	roots := []api.BlobRef{r.Input.Base, r.Input.Subject.Snapshot}
	if r.Preparation != nil {
		roots = append(roots, r.Preparation.Request.Candidate)
	}
	for _, root := range roots {
		meta, raw, err := objectRow(ctx, db, root.ID)
		if err != nil {
			return api.BlobChunk{}, err
		}
		if meta.Ref != root {
			return api.BlobChunk{}, fault(api.CodeIntegrity, "review tree changed its pinned bytes")
		}
		var tree api.ObjectManifest
		if api.DecodeObject(raw, &tree) != nil || manifest.Object(tree) != nil {
			return api.BlobChunk{}, fault(api.CodeIntegrity, "review object root is not an actual manifest")
		}
		if err := add(root); err != nil {
			return api.BlobChunk{}, err
		}
		for _, entry := range tree.Entries {
			for _, ref := range manifest.ContentRefs(entry) {
				if err := add(ref); err != nil {
					return api.BlobChunk{}, err
				}
			}
		}
	}
	for _, ref := range append([]api.BlobRef{r.Input.Request.Diff, r.Input.Inventory.Manifest, r.Input.Inventory.ToolRecords}, r.Input.Request.Checks...) {
		if ref.ID != "" {
			if err := add(ref); err != nil {
				return api.BlobChunk{}, err
			}
		}
	}
	for _, resolution := range r.Input.Resolutions {
		if err := add(resolution.Evidence); err != nil {
			return api.BlobChunk{}, err
		}
	}
	ref, ok := refs[request.ObjectID]
	if !ok {
		return api.BlobChunk{}, fault(api.CodeNotFound, "object is outside the original sealed review")
	}
	meta, raw, err := objectRow(ctx, db, request.ObjectID)
	if err != nil {
		return api.BlobChunk{}, err
	}
	if meta.Ref != ref || meta.ACL.Config != s.deps.Config || request.Offset < 0 || request.Offset > int64(len(raw)) || request.Limit < 1 || request.Limit > api.MaxChunkBytes {
		return api.BlobChunk{}, fault(api.CodeIntegrity, "review object changed its sealed range")
	}
	data := append([]byte{}, raw[request.Offset:min(int64(len(raw)), request.Offset+int64(request.Limit))]...)
	return api.BlobChunk{ObjectID: ref.ID, Offset: request.Offset, Data: data, SHA256: api.Digest(hash(data))}, nil
}

func validateReviewOutput(r reviewRecord, raw []byte) error {
	if r.Test != nil && r.Preparation != nil {
		return fault(api.CodeIntegrity, "test worker retained conflicting native protocols")
	}
	if r.Test != nil {
		return validateTestOutput(r, raw)
	}
	if r.Preparation != nil {
		return validateCheckOutput(r, raw)
	}
	var evidence api.ReviewEvidence
	if api.DecodeObject(raw, &evidence) != nil || !sameDataBytes(raw, evidence) || api.ValidateReviewEvidence(evidence, r.Input.Subject) != nil ||
		evidence.VerifierLeaseID != r.Job.Lease.ID || evidence.Diff != r.Input.Request.Diff || !reflect.DeepEqual(evidence.Checks, r.Input.Checks) || !reflect.DeepEqual(evidence.Inventory, r.Input.Inventory) || !reflect.DeepEqual(evidence.Resolutions, r.Input.Resolutions) {
		return fault(api.CodeIntegrity, "review output changed its exact sealed evidence")
	}
	if evidence.Coverage == api.CoverageComplete {
		receipt := api.ReviewReceipt{ID: r.Job.ID, Reviewer: r.Scope.Actor, Diff: evidence.Diff, Checks: r.Input.Request.Checks, RecordInventory: evidence.Inventory.Manifest, RefusalResolution: r.Input.Request.RefusalResolution, Coverage: evidence.Coverage, Evidence: &evidence}
		if err := api.ValidateReviewAcceptance(r.Scope, receipt, r.Input.Subject, r.Input.Required); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) reviewWorkerResult(ctx context.Context, p api.WorkerPrincipal, submission api.WorkerResultSubmission) (receipt api.WorkerResultReceipt, resultErr error) {
	var r reviewRecord
	if err := storedProjection(ctx, s.db, "review_job", p.Lease.OperationID, &r); err != nil {
		return receipt, err
	}
	if r.Ack != nil {
		if !sameValue(r.Ack.Submission, submission) {
			return receipt, fault(api.CodeIdempotencyConflict, "review result retry changed its original bytes")
		}
		meta, raw, err := objectRow(ctx, s.db, r.Ack.Receipt.Result.ID)
		if err != nil {
			return receipt, err
		}
		if meta.Ref != r.Ack.Receipt.Result || !bytes.Equal(raw, submission.Result) {
			return receipt, fault(api.CodeIntegrity, "review result acknowledgement lost its retained bytes")
		}
		return r.Ack.Receipt, nil
	}
	if submission.LeaseID != p.Lease.ID || submission.ExpectedGeneration != p.Lease.Generation || submission.InputSHA256 != p.Lease.Input.SHA256 || len(submission.Result) == 0 || len(submission.Result) > api.MaxFrameBytes {
		return receipt, fault(api.CodeConflict, "review result changed its original input or generation")
	}
	if err := validateReviewOutput(r, submission.Result); err != nil {
		return receipt, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return receipt, err
	}
	defer finish(tx, &resultErr)
	ref, err := s.reviewBytes(ctx, tx, r, "worker_result", append([]byte{}, submission.Result...))
	if err != nil {
		return receipt, err
	}
	event, err := s.reviewEvent(r, "blob.committed", ref)
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
	if err := s.saveReview(ctx, tx, r); err != nil {
		return receipt, err
	}
	if err := tx.Commit(); err != nil {
		return receipt, err
	}
	s.notifyChanged()
	return receipt, nil
}

func (s *Service) validateReviewOutcome(ctx context.Context, db queryer, record api.EffectRecord, outcome api.EffectOutcome) error {
	var r reviewRecord
	if err := storedProjection(ctx, db, "review_job", record.Effect.OperationID, &r); err != nil {
		return err
	}
	if record.Effect.Worker == nil || !sameValue(*record.Effect.Worker, r.Job.Plan) || record.Effect.ID != r.Job.Lease.EffectID || outcome.EffectID != record.Effect.ID || outcome.ClaimID != record.ClaimID || outcome.Status != "succeeded" || outcome.Error != nil || outcome.Output == nil || outcome.Observation == nil || r.Ack == nil || *outcome.Output != r.Ack.Receipt.Result || r.Process.ID == "" {
		return fault(api.CodePrerequisite, "review requires its original result and completed measured worker")
	}
	o := outcome.Observation
	when, err := time.Parse(time.RFC3339Nano, string(o.ObservedAt))
	if err != nil || when.After(s.deps.Clock.Now()) || o.Handle != r.Process || o.State != "exited" || o.ExitCode == nil || *o.ExitCode != 0 || o.Signal != nil || o.Survivors == nil || *o.Survivors != 0 {
		return fault(api.CodeContainmentUnknown, "review worker has no measured successful known-zero terminal lifetime")
	}
	if r.Retirement == nil || r.Retirement.Release == nil || !sameValue(r.Retirement.Release.Quiescence, *o) {
		return fault(api.CodeContainmentUnknown, "review worker has no retained native retirement measurement")
	}
	var worker api.WorkerLease
	if err := storedProjection(ctx, db, "worker_lease", r.Job.Lease.ID, &worker); err != nil {
		return err
	}
	want := r.Job.Lease
	want.ConsumedBy, want.Generation = r.WorkerLaunchID, want.Generation+2
	if worker != want || r.Ack.Receipt.Generation != worker.Generation {
		return fault(api.CodeIntegrity, "review result lost its exact consumption and result generation advances")
	}
	meta, raw, err := objectRow(ctx, db, r.Ack.Receipt.Result.ID)
	if err != nil {
		return err
	}
	if meta.Ref != *outcome.Output || meta.SourceOperationID != r.Job.Intent.OperationID || meta.Origin != "service" || meta.ACL.LifeID != worker.Target.LifeID || !bytes.Equal(raw, r.Ack.Submission.Result) {
		return fault(api.CodeIntegrity, "review measured result has foreign bytes or provenance")
	}
	return validateReviewOutput(r, raw)
}
