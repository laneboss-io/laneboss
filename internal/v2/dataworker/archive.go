package dataworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/grants/lstate"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// ArchiveJob is supplied only by the native fixed-worker bridge. Read and Sink
// are authenticated capabilities of that actual worker connection. The worker
// gets immutable frozen objects, never the mutable agent workspace or secrets.
type ArchiveJob struct {
	Principal api.WorkerPrincipal
	Scope     api.Scope
	Bootstrap api.WorkerBootstrap
	Read      archivejob.ReadObject
	Sink      archivejob.PartSink
	Clock     api.Clock
}

func RunArchive(ctx context.Context, job ArchiveJob) (api.WorkerResultReceipt, error) {
	var zero api.WorkerResultReceipt
	if err := checkContext(ctx); err != nil {
		return zero, err
	}
	if missing(job.Bootstrap) || missing(job.Clock) || job.Read == nil || missing(job.Sink) {
		return zero, lstate.Error(api.CodePrerequisite, "archive requires native bootstrap and durable scoped object ports")
	}
	p := job.Principal
	if job.Scope.Actor != p.Record.Actor || job.Scope.Config != p.Endpoint.Config || job.Scope.LaunchID != p.Record.ID ||
		job.Scope.EndpointGeneration != p.Endpoint.EndpointGeneration || job.Scope.Request.Method != "" || p.Lease.Kind != "archive" {
		return zero, lstate.Error(api.CodeForbidden, "archive worker cannot borrow its requester identity")
	}
	if err := api.ValidateWorkerPrincipal(p, p.Endpoint, p.Peer, api.WorkerInputRead, job.Clock.Now()); err != nil {
		return zero, err
	}
	envelope, err := job.Bootstrap.WorkerInput(ctx, job.Scope, api.WorkerInputRequest{LeaseID: p.Lease.ID})
	if err != nil {
		return zero, err
	}
	if err := api.ValidateWorkerInput(p, envelope, job.Clock.Now()); err != nil {
		return zero, err
	}
	var input archivejob.Input
	if api.DecodeObject(envelope.Bytes, &input) != nil || input.Schema != "laneboss.archive-input.v2" || input.JobID != p.StageID ||
		p.Lease.Input.Class != "archive_input" || !manifest.ValidID(p.Lease.Target.LifeID) || p.Lease.Target.Run == 0 || uint64(p.Lease.Target.Run) > manifest.MaxInteger ||
		!manifest.ValidID(p.Lease.GrantSetID) || !manifest.ValidID(p.Lease.EffectID) || !manifest.ValidID(input.Intent.OperationID) ||
		input.Intent.Request.Target != p.Lease.Target || input.Intent.OperationID != p.Lease.OperationID || input.Intent.CancellationEpoch != p.CancellationEpoch ||
		input.Intent.Request.ExpectedGeneration == 0 || uint64(input.Intent.Request.ExpectedGeneration) > manifest.MaxInteger ||
		!manifest.ValidID(input.Intent.EndEventID) || input.Intent.EndSeq == 0 || uint64(input.Intent.EndSeq) > manifest.MaxInteger ||
		!manifest.ValidID(input.ReceiptID) || !manifest.ValidID(input.StoreID) || input.Freeze.Class != "manifest" || manifest.Blob(input.Freeze) != nil ||
		manifest.Budget(input.Budget) != nil || p.Claim.Record.Effect.Worker == nil || p.Claim.Record.Effect.Worker.Schema != "laneboss.worker-plan.v2" || p.Claim.Record.Effect.Worker.Kind != "archive" ||
		p.Claim.Record.Effect.Worker.Input != p.Lease.Input || p.Claim.Record.Effect.Worker.GrantSetID != p.Lease.GrantSetID ||
		p.Claim.Record.Effect.Worker.Budget != input.Budget {
		return zero, lstate.Error(api.CodeIntegrity, "archive input differs from its original fenced worker reservation")
	}
	raw, err := readWorkerObject(ctx, job.Read, input.Freeze)
	if err != nil {
		return zero, err
	}
	var freeze archivejob.Freeze
	freezeErr := api.DecodeObject(raw, &freeze)
	frozenAt, timeErr := manifest.Time(freeze.ObservedAt)
	if freezeErr != nil || freeze.Target != p.Lease.Target || freeze.CancellationEpoch != p.CancellationEpoch ||
		!manifest.ValidID(freeze.LaunchID) || freeze.Writers == nil || *freeze.Writers != 0 || freeze.WritableExports == nil || *freeze.WritableExports != 0 ||
		freeze.Snapshot.Class != "manifest" || manifest.Blob(freeze.Snapshot) != nil || timeErr != nil || frozenAt.After(job.Clock.Now()) {
		return zero, lstate.Error(api.CodeContainmentUnknown, "archive requires a measured immutable zero-writer snapshot")
	}
	raw, err = readWorkerObject(ctx, job.Read, freeze.Snapshot)
	if err != nil {
		return zero, err
	}
	tree, err := archivejob.Manifest(raw)
	if err != nil {
		return zero, err
	}
	// Frozen source objects are immutable, digest-pinned input. Reuse only
	// small verified objects within this invocation and its memory budget;
	// archive parts still come from the durable sink for independent read-back.
	cache, err := newArchiveReadCache(tree, job.Read, min(input.Budget.MemoryBytes/4, 4<<20))
	if err != nil {
		return zero, err
	}
	defer cache.clear()
	if err := cache.loadInline(input.Inline); err != nil {
		return zero, err
	}
	job.Read = cache.read
	writer := &archiveWriter{ctx: ctx, job: job, digest: sha256.New(), parts: []api.BlobRef{}}
	if err := archivejob.Write(ctx, writer, tree, job.Read, input.Budget.DiskBytes); err != nil {
		return zero, err
	}
	if err := writer.flush(); err != nil {
		return zero, err
	}
	assembly := api.ObjectAssembly{SHA256: api.Digest(hex.EncodeToString(writer.digest.Sum(nil))), Bytes: writer.total, Parts: writer.parts}
	readBack, err := archivejob.ReadBack(ctx, assembly, tree, job.Read, input.Budget.DiskBytes)
	if err != nil {
		return zero, err
	}
	if err := api.ValidateWorkerPrincipal(p, p.Endpoint, p.Peer, api.WorkerResultAppend, job.Clock.Now()); err != nil {
		return zero, err
	}
	completion := archivejob.Completion{Archive: assembly, Receipt: api.ArchiveReceipt{ID: input.ReceiptID, LifeID: p.Lease.Target.LifeID,
		Manifest: freeze.Snapshot, ArchiveSHA256: assembly.SHA256, ReadBackSHA256: readBack,
		VerifiedAt: api.Timestamp(job.Clock.Now().UTC().Format(time.RFC3339Nano)), StoreID: input.StoreID}}
	raw, err = json.Marshal(completion)
	if err == nil {
		raw, err = api.CanonicalJSON(raw)
	}
	if err != nil {
		return zero, err
	}
	if len(raw) > api.MaxFrameBytes {
		return zero, lstate.Error(api.CodeBudget, "archive part inventory exceeds the bounded result frame")
	}
	submission := api.WorkerResultSubmission{LeaseID: p.Lease.ID, ExpectedGeneration: p.Lease.Generation, InputSHA256: p.Lease.Input.SHA256, Result: raw}
	receipt, err := job.Bootstrap.WorkerResult(ctx, job.Scope, submission)
	if err != nil {
		return zero, err
	}
	if err := api.ValidateWorkerResult(p, submission, receipt, job.Clock.Now()); err != nil {
		return zero, err
	}
	return receipt, nil
}

type archiveWriter struct {
	ctx    context.Context
	job    ArchiveJob
	digest hash.Hash
	buffer []byte
	parts  []api.BlobRef
	total  int64
}

func (w *archiveWriter) Write(data []byte) (int, error) {
	written := 0
	for len(data) != 0 {
		if err := w.ctx.Err(); err != nil {
			return written, err
		}
		count := min(len(data), api.MaxChunkBytes-len(w.buffer))
		w.buffer = append(w.buffer, data[:count]...)
		written += count
		data = data[count:]
		if len(w.buffer) == api.MaxChunkBytes {
			if err := w.flush(); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

func (w *archiveWriter) flush() error {
	if len(w.buffer) == 0 {
		return nil
	}
	if len(w.parts) >= manifest.MaxEntries {
		return lstate.Error(api.CodeBudget, "archive exceeds the bounded retained part inventory")
	}
	// Recheck expiry before every append as well as at final submission. The
	// installed receiver must independently recheck current revocation/claim.
	p := w.job.Principal
	if err := api.ValidateWorkerPrincipal(p, p.Endpoint, p.Peer, api.WorkerResultAppend, w.job.Clock.Now()); err != nil {
		return err
	}
	digest, size := manifest.Hash(w.buffer), len(w.buffer)
	ref, err := w.job.Sink.ArchivePart(w.ctx, w.job.Scope, p.Lease.ID, uint64(len(w.parts)), append([]byte(nil), w.buffer...))
	if err != nil {
		return err
	}
	if manifest.Blob(ref) != nil || ref.Class != "artifact" || ref.Bytes != int64(size) || ref.SHA256 != digest {
		return lstate.Error(api.CodeIntegrity, "archive sink acknowledgement changed its actual persisted part")
	}
	_, _ = w.digest.Write(w.buffer)
	w.total += int64(size)
	w.parts = append(w.parts, ref)
	w.buffer = w.buffer[:0]
	return nil
}
