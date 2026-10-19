package lifecycle

import (
	"context"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// ArchiveControl is an installed service/store capability, not an RPC or an
// uploaded plan. ReserveArchive must atomically verify invocation ownership,
// consume the original proof once, fence the life/epoch/end, retain the frozen
// input and WorkerLease, and enqueue exactly one fixed Worker effect. It leaves
// the public reply pending. The outbox completes that same reply and emits
// archive.verified only after the confined worker's actual hash/read-back.
// Generic DeferredReply currently covers org publication only; it must not be
// repurposed or supplied a fabricated ArchiveReceipt for this reservation.
type ArchiveControl = archivejob.Control
type ArchiveIntent = archivejob.Intent
type ArchiveJob = archivejob.Job

// These private retained worker records bind a measured frozen snapshot and
// archive chunks to the original operation. Nil writer/export counts are
// unknown. An agent process's zero survivors cannot stand in for this freeze.
type ArchiveFreeze = archivejob.Freeze
type ArchiveCompletion = archivejob.Completion

func (s *Service) pendingMutation(ctx context.Context, scope api.Scope) (api.MutationReceipt, error) {
	key := api.RequestKey{Method: scope.Request.Method, IdempotencyKey: scope.Request.IdempotencyKey, RequestSHA256: scope.Request.RequestSHA256}
	receipt, err := s.deps.Store.LookupReceipt(ctx, scope, key)
	if err != nil {
		return api.MutationReceipt{}, failure(err)
	}
	if !receiptMatches(scope, key, receipt) || receipt.Reply != nil || receipt.Operation.Status != "pending" || !validID(receipt.Operation.ID) {
		return api.MutationReceipt{}, integrity("mutation lost its exact pending reservation")
	}
	owned, err := s.ownsMutation(ctx, scope, key, receipt)
	if err != nil {
		return api.MutationReceipt{}, err
	}
	if !owned {
		return api.MutationReceipt{}, integrity("mutation cannot complete another executor's reservation")
	}
	var original api.Request
	if api.DecodeObject(receipt.RawRequest, &original) != nil || !reflect.DeepEqual(original, scope.Request) {
		return api.MutationReceipt{}, integrity("mutation changed its retained input bytes")
	}
	return receipt, nil
}

func (s *Service) archiveJob(ctx context.Context, scope api.Scope, control ArchiveControl, lane api.Lane, intent ArchiveIntent, job ArchiveJob) error {
	if job.Intent != intent || !validID(job.ID) || !validID(job.Lease.ID) || job.Lease.Kind != "archive" || job.Lease.Target != intent.Request.Target ||
		job.Lease.OperationID != intent.OperationID || !validID(job.Lease.EffectID) || !validGeneration(job.Lease.Generation) ||
		job.Plan.Schema != "laneboss.worker-plan.v2" || job.Plan.Kind != "archive" || job.Plan.Input != job.Lease.Input ||
		job.Plan.GrantSetID != job.Lease.GrantSetID || !validBudget(job.Plan.Budget) {
		return integrity("archive job differs from its original reservation")
	}
	retained, err := control.ArchiveJob(ctx, scope, intent.OperationID)
	if err != nil {
		return failure(err)
	}
	if !reflect.DeepEqual(retained, job) {
		return integrity("archive reservation was not retained exactly")
	}
	expires, err := time.Parse(time.RFC3339Nano, string(job.Lease.ExpiresAt))
	if err != nil || !s.deps.Clock.Now().Before(expires) {
		return problem(api.CodeConflict, "archive worker reservation expired", "Reconcile its original job; do not issue a replacement worker.")
	}
	worker, err := s.deps.Store.WorkerLease(ctx, archiveLeaseScope(scope), job.Lease.ID)
	if err != nil {
		return failure(err)
	}
	want := job.Lease
	want.ConsumedBy, want.Generation = worker.ConsumedBy, worker.Generation
	if worker.Generation < job.Lease.Generation || worker.Generation > job.Lease.Generation+1 || !reflect.DeepEqual(worker, want) {
		return integrity("archive worker changed its retained lease")
	}
	effect, err := s.deps.Store.Effect(ctx, archiveLeaseScope(scope), job.Lease.EffectID)
	if err != nil {
		return failure(err)
	}
	cause := effect.Effect.Context
	if effectRecord(effect) != nil || effect.State != api.EffectPending && effect.State != api.EffectClaimed ||
		cause == nil || cause.Kind != api.InternalLifecycleEffect || cause.Config != scope.Config ||
		cause.Actor.Kind != "service" || !validID(cause.Actor.ID) || cause.RequestedBy != scope.Actor || cause.Target != intent.Request.Target ||
		cause.CauseOperationID != intent.OperationID || cause.CauseRequestID != scope.Request.RequestID ||
		cause.EffectID != job.Lease.EffectID || cause.CancellationEpoch != lane.CancellationEpoch ||
		!reflect.DeepEqual(effect.Effect, api.Effect{ID: job.Lease.EffectID, OperationID: intent.OperationID, Context: cause, Worker: &job.Plan}) {
		return integrity("archive has no exact durable worker effect")
	}
	raw, err := s.readBlob(ctx, scope, job.Lease.RuntimeManifest)
	if err != nil {
		return err
	}
	var runtime api.RuntimeManifest
	if api.DecodeObject(raw, &runtime) != nil || runtime.Bootstrap != job.Plan.Executable || !validDigest(runtime.Bootstrap.SHA256) || !validID(runtime.Bootstrap.ID) {
		return integrity("archive worker differs from its installed runtime")
	}
	if !reflect.DeepEqual(job.Plan.Argv, []string{"laneboss", "internal", "worker", "--binding", "/runtime/laneboss-worker.json", "--lease", string(job.Lease.ID)}) {
		return integrity("archive worker changed its fixed bootstrap arguments")
	}
	raw, err = s.operationBlob(ctx, scope, job.Lease.Input, intent.OperationID)
	if err != nil {
		return err
	}
	var input archivejob.Input
	if api.DecodeObject(raw, &input) != nil || input.Schema != "laneboss.archive-input.v2" || input.Intent != intent ||
		input.JobID != job.ID || input.Freeze != job.Freeze || !validID(input.ReceiptID) || !validID(input.StoreID) || input.Budget != job.Plan.Budget {
		return integrity("archive worker input changed its exact retained intent")
	}
	grants, err := s.deps.Store.Grants(ctx, job.Lease.GrantSetID)
	if err != nil {
		return failure(err)
	}
	if grants.ID != job.Lease.GrantSetID || grants.LifeID != lane.LifeID || grants.Revoked || len(grants.Secrets)+len(grants.Profiles)+len(grants.Network)+len(grants.Channels)+len(grants.Resources) != 0 {
		return integrity("archive worker has unrelated authority")
	}
	grantEnd, err := time.Parse(time.RFC3339Nano, string(grants.ExpiresAt))
	if !validTime(grants.ExpiresAt) || err != nil || !s.deps.Clock.Now().Before(grantEnd) {
		return problem(api.CodeConflict, "archive worker grants expired", "Reconcile its original job under current archive authority.")
	}
	policy, err := s.deps.Store.Policy(ctx, scope)
	if err != nil {
		return failure(err)
	}
	if grants.PolicyGeneration != policy.Generation || scope.PolicyGeneration != policy.Generation || !validDigest(grants.SHA256) {
		return integrity("archive worker grants do not bind current policy")
	}
	for _, data := range grants.Data {
		if data.Access != "ro" || data.Delegate {
			return integrity("archive worker has writable source authority")
		}
	}
	raw, err = s.operationBlob(ctx, scope, job.Freeze, intent.OperationID)
	if err != nil {
		return err
	}
	metadata, err := s.deps.Store.ObjectMetadata(ctx, archiveLeaseScope(scope), job.Freeze.ID)
	if err != nil {
		return failure(err)
	}
	if metadata.Origin != "service" || metadata.ACL.LifeID != lane.LifeID || job.Freeze.Class != "manifest" {
		return integrity("archive freeze has no protected service provenance")
	}
	var freeze ArchiveFreeze
	if api.DecodeObject(raw, &freeze) != nil || freeze.Target != intent.Request.Target || freeze.LaunchID != lane.LaunchID ||
		freeze.CancellationEpoch != intent.CancellationEpoch || freeze.Writers == nil || *freeze.Writers != 0 ||
		freeze.WritableExports == nil || *freeze.WritableExports != 0 || !validTime(freeze.ObservedAt) || freeze.Snapshot.Class != "manifest" {
		return integrity("archive has no measured frozen input snapshot")
	}
	raw, err = s.operationBlob(ctx, scope, freeze.Snapshot, intent.OperationID)
	if err != nil {
		return err
	}
	return archiveManifest(raw)
}

// archiveLeaseScope is the scope for lane archive's internal verification reads of the archive job this
// caller's own pending operation reserved (job.Lease.OperationID and the retained job are checked first):
// its worker lease, its effect, and the freeze, manifest and part objects the service and worker wrote,
// each provenance-checked against this job. Frozen source content keeps the caller's own ACL.
// Those store reads admit only an internal scope, so they run as the lifecycle service, as credentials.go
// reads its holdings (boxes 87-88: "worker lease belongs to another endpoint", "effect lookup is
// service-internal"). The caller's policy, receipt and job reads keep its own scope.
func archiveLeaseScope(scope api.Scope) api.Scope {
	return api.Scope{Config: scope.Config, Actor: api.Actor{Kind: "service", ID: "lifecycle"}}
}

func archiveManifest(raw []byte) error {
	if _, err := archivejob.Manifest(raw); err != nil {
		return integrity("archive snapshot has no immutable object manifest")
	}
	return nil
}

func (s *Service) operationBlob(ctx context.Context, scope api.Scope, ref api.BlobRef, operation api.ID) ([]byte, error) {
	metadata, err := s.deps.Store.ObjectMetadata(ctx, archiveLeaseScope(scope), ref.ID)
	if err != nil {
		return nil, failure(err)
	}
	if metadata.SourceOperationID != operation || metadata.Origin != "service" && metadata.Origin != "worker" {
		return nil, integrity("worker object has foreign operation provenance")
	}
	return s.readBlob(ctx, scope, ref)
}

func (s *Service) archiveCompletion(ctx context.Context, scope api.Scope, lane api.Lane, job ArchiveJob, receipt api.ArchiveReceipt) error {
	if !validID(receipt.ID) || receipt.LifeID != lane.LifeID || !validID(receipt.StoreID) || receipt.Manifest.Class != "manifest" ||
		!validDigest(receipt.ArchiveSHA256) || receipt.ArchiveSHA256 != receipt.ReadBackSHA256 || !validTime(receipt.VerifiedAt) {
		return integrity("archive reply has no verified read-back receipt")
	}
	effect, err := s.deps.Store.Effect(ctx, archiveLeaseScope(scope), job.Lease.EffectID)
	if err != nil {
		return failure(err)
	}
	if effectRecord(effect) != nil || effect.State != api.EffectCompleted || effect.Outcome == nil || effect.Outcome.Status != "succeeded" || effect.Outcome.Error != nil ||
		effect.Outcome.EffectID != job.Lease.EffectID || effect.Outcome.Output == nil || effect.Outcome.Output.Class != "worker_result" || effect.Outcome.Observation == nil {
		return integrity("archive reply preceded its actual worker completion")
	}
	if effect.Effect.Worker == nil || !reflect.DeepEqual(*effect.Effect.Worker, job.Plan) || effect.Effect.OperationID != job.Intent.OperationID {
		return integrity("archive completion replaced its original worker effect")
	}
	observation := *effect.Outcome.Observation
	if validateObservation(observation.Handle, observation) != nil || requireQuiescence(observation) != nil ||
		observation.Handle.Target != job.Intent.Request.Target || observation.ExitCode == nil || *observation.ExitCode != 0 {
		return integrity("archive worker has no successful terminal observation")
	}
	worker, err := s.deps.Store.WorkerLease(ctx, archiveLeaseScope(scope), job.Lease.ID)
	if err != nil {
		return failure(err)
	}
	want := job.Lease
	want.ConsumedBy, want.Generation = worker.ConsumedBy, worker.Generation
	if !validID(worker.ConsumedBy) || worker.Generation < job.Lease.Generation || worker.Generation > job.Lease.Generation+1 || !reflect.DeepEqual(worker, want) {
		return integrity("archive completion lost its retained worker lease")
	}
	principal, err := s.deps.Store.Launch(ctx, worker.ConsumedBy)
	if err != nil {
		return failure(err)
	}
	if principal.ID != worker.ConsumedBy || principal.Kind != "worker" || principal.Actor.Kind != "worker" || principal.Actor.Level != 0 || principal.Actor.Role != "" || principal.HostUID == 0 ||
		principal.Config != scope.Config || principal.Target != worker.Target || principal.GrantSetID != worker.GrantSetID ||
		principal.Revoked || !validID(principal.ContainmentID) || principal.ProcessGeneration == "" ||
		principal.ContainmentID != observation.Handle.ContainmentID || principal.ProcessGeneration != observation.Handle.Generation {
		return integrity("archive result has no confined worker principal")
	}
	agent, err := s.deps.Store.Launch(ctx, lane.LaunchID)
	if err != nil {
		return failure(err)
	}
	if principal.HostUID == agent.HostUID {
		return integrity("archive worker reused the agent principal")
	}
	raw, err := s.operationBlob(ctx, scope, *effect.Outcome.Output, job.Intent.OperationID)
	if err != nil {
		return err
	}
	var result ArchiveCompletion
	if api.DecodeObject(raw, &result) != nil || result.Receipt != receipt || result.Archive.SHA256 != receipt.ArchiveSHA256 ||
		result.Archive.Parts == nil || len(result.Archive.Parts) == 0 || result.Archive.Bytes < 1 || uint64(result.Archive.Bytes) > maxInteger {
		return integrity("archive reply differs from its measured worker output")
	}
	raw, err = s.operationBlob(ctx, scope, job.Lease.Input, job.Intent.OperationID)
	if err != nil {
		return err
	}
	var input archivejob.Input
	if api.DecodeObject(raw, &input) != nil || input.Schema != "laneboss.archive-input.v2" || input.Intent != job.Intent || input.JobID != job.ID || input.Freeze != job.Freeze ||
		input.ReceiptID != receipt.ID || input.StoreID != receipt.StoreID || input.Budget != job.Plan.Budget {
		return integrity("archive receipt changed its reserved input or identity")
	}
	raw, err = s.operationBlob(ctx, scope, job.Freeze, job.Intent.OperationID)
	if err != nil {
		return err
	}
	var freeze ArchiveFreeze
	if api.DecodeObject(raw, &freeze) != nil || freeze.Target != job.Intent.Request.Target || freeze.Snapshot != receipt.Manifest {
		return integrity("archive receipt replaced its immutable frozen manifest")
	}
	raw, err = s.operationBlob(ctx, scope, receipt.Manifest, job.Intent.OperationID)
	if err != nil {
		return err
	}
	tree, err := archivejob.Manifest(raw)
	if err != nil {
		return integrity("archive receipt has an invalid frozen inventory")
	}
	allowed := make(map[api.ID]bool, len(result.Archive.Parts))
	// Parts carry this job's pinned provenance (checked below), so they are read as the service; frozen
	// sources keep the caller's own Store ACL for both the check and the read-back.
	parts := make(map[api.ID]bool, len(result.Archive.Parts))
	for _, part := range result.Archive.Parts {
		metadata, err := s.deps.Store.ObjectMetadata(ctx, archiveLeaseScope(scope), part.ID)
		if err != nil {
			return failure(err)
		}
		if metadata.Ref != part || metadata.SourceOperationID != job.Intent.OperationID || metadata.Origin != "service" && metadata.Origin != "worker" ||
			metadata.ACL.Config != scope.Config || metadata.ACL.LifeID != lane.LifeID {
			return integrity("archive part has foreign operation or life provenance")
		}
		allowed[part.ID], parts[part.ID] = true, true
	}
	// Canonical regeneration reads only the exact frozen content inventory.
	// These immutable sources can predate the archive operation. Preserve the
	// caller's current Store ACL checks rather than borrowing service authority.
	for _, entry := range tree.Entries {
		for _, ref := range manifest.ContentRefs(entry) {
			metadata, err := s.deps.Store.ObjectMetadata(ctx, scope, ref.ID)
			if err != nil {
				return failure(err)
			}
			if metadata.Ref != ref || metadata.ACL.Config != scope.Config {
				return integrity("canonical archive source differs from its frozen reference")
			}
			allowed[ref.ID] = true
		}
	}
	readBack, err := archivejob.ReadBack(ctx, result.Archive, tree, func(ctx context.Context, request api.BlobReadRequest) (api.BlobChunk, error) {
		if !allowed[request.ObjectID] {
			return api.BlobChunk{}, integrity("archive read-back selected an unretained part or frozen source")
		}
		read := scope
		if parts[request.ObjectID] {
			read = archiveLeaseScope(scope)
		}
		chunk, err := s.deps.Store.Blob(ctx, read, request)
		return chunk, failure(err)
	}, job.Plan.Budget.DiskBytes)
	if err != nil || readBack != receipt.ReadBackSHA256 {
		if err != nil {
			return failure(err)
		}
		return integrity("archive bytes failed independent read-back")
	}
	found := false
	err = s.walkEvents(ctx, scope, lane, job.Intent.Request.Target, func(event api.Event) error {
		if event.Kind == "archive.verified" && event.OperationID == job.Intent.OperationID && event.Seq > job.Intent.EndSeq {
			var actual api.ArchiveReceipt
			if api.DecodeObject(event.Payload, &actual) != nil || actual != receipt {
				return integrity("archive event differs from its measured completion")
			}
			found = true
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !found {
		return integrity("archive completion has no committed verification event")
	}
	return nil
}
