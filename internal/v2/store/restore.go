package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
)

// RestoreRootSource is an installed native capability, never request data.
// It resolves the authenticated caller's existing lane workspace allocations.
type RestoreRootSource interface {
	RestoreRoots(context.Context, api.Scope) ([]string, error)
}

// RestoreWriter is the installed native staging/publication capability.
// It never lends a lane's filesystem identity to the service.
type RestoreWriter interface {
	RestoreRootSource
	StageRestore(context.Context, api.Scope, api.RestoreRequest, api.ObjectManifest, archivejob.ReadObject, uint64) (api.ID, api.RestoreReceipt, error)
	PublishRestore(context.Context, api.Scope, api.ID) error
	AbortRestore(context.Context, api.Scope, api.ID) error
}

// RestoreArchive reads a pinned, ACL-checked snapshot outside the writer lock.
// Only final live authority, proof consumption and publication share a commit.
func (s *Service) RestoreArchive(ctx context.Context, scope api.Scope, request api.RestoreRequest) (result api.RestoreReceipt, resultErr error) {
	s.mu.Lock()
	pending, lane, err := s.restoreAuthority(ctx, scope, request)
	s.mu.Unlock()
	if err != nil {
		return result, err
	}
	native, ok := s.deps.CleanupNative.(RestoreWriter)
	if !ok {
		return result, fault(api.CodeForbidden, "restore_target_scope")
	}
	readScope := scope
	if readScope.ReadView == nil {
		view, err := s.BeginRead(ctx, scope)
		if err != nil {
			return result, err
		}
		defer func() { resultErr = errors.Join(resultErr, view.Close()) }()
		readScope.ReadView = view
	}
	db, err := s.reader(readScope)
	if err != nil {
		return result, err
	}
	archived, receipt, tree, err := s.restoreSource(ctx, readScope, db, request)
	if err != nil {
		return result, err
	}
	allowed := map[api.ID]api.BlobRef{}
	for _, entry := range tree.Entries {
		for _, ref := range manifest.ContentRefs(entry) {
			allowed[ref.ID] = ref
		}
	}
	read := func(ctx context.Context, q api.BlobReadRequest) (api.BlobChunk, error) {
		ref, ok := allowed[q.ObjectID]
		if !ok {
			return api.BlobChunk{}, fault(api.CodeForbidden, "restore read escaped the frozen inventory")
		}
		metadata, _, err := s.readObjectRow(ctx, readScope, db, q.ObjectID)
		if err != nil {
			return api.BlobChunk{}, err
		}
		if metadata.Ref != ref {
			return api.BlobChunk{}, fault(api.CodeIntegrity, "restore frozen object pin changed")
		}
		return s.blob(ctx, readScope, db, q)
	}
	id, report, err := native.StageRestore(ctx, scope, request, tree, read, archived.Job.Plan.Budget.DiskBytes)
	if err != nil {
		return result, err
	}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, native.AbortRestore(context.WithoutCancel(ctx), scope, id))
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	current, actual, err := s.restoreAuthority(ctx, scope, request)
	if err != nil {
		return result, err
	}
	if current.Operation.ID != pending.Operation.ID || actual.Generation != lane.Generation || actual.CancellationEpoch != lane.CancellationEpoch {
		return result, fault(api.CodeConflict, "restore_generation_changed")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	if scope.Actor.Kind == "human" {
		target, err := s.authorizationTarget(ctx, tx, scope, scope.Request)
		if err != nil {
			return result, err
		}
		if err := s.guards(ctx, tx, api.Transaction{Scope: scope, Guards: []api.TransactionGuard{{Proof: &api.ProofUse{Proof: *scope.Request.Proof, Target: target}}}}, pending.Operation.ID); err != nil {
			return result, err
		}
	}
	if err := native.PublishRestore(ctx, scope, id); err != nil {
		return result, err
	}
	if err := s.scope(ctx, tx, scope); err != nil {
		return result, err
	}
	result = api.RestoreReceipt{Target: request.Target, Path: request.Path, Head: report.Head, ArchiveReceiptID: receipt.ID, Manifest: receipt.Manifest,
		ClearedModes: report.ClearedModes, SkippedPaths: report.SkippedPaths}
	if err := s.finishRestore(ctx, tx, scope, lane, pending, result); err != nil {
		return api.RestoreReceipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return api.RestoreReceipt{}, err
	}
	s.notifyChanged()
	return result, nil
}

// Called only while holding the writer lock, before staging and at commit.
func (s *Service) restoreAuthority(ctx context.Context, scope api.Scope, request api.RestoreRequest) (pending api.MutationReceipt, lane api.Lane, err error) {
	if err = s.available(); err != nil {
		return
	}
	if err = s.scope(ctx, s.db, scope); err != nil {
		return
	}
	if scope.Request.Method != "lane.restore" || scope.Connection == nil || scope.Actor.Kind != "human" && scope.Actor.Kind != "lane" {
		err = fault(api.CodeForbidden, "restore requires the actual lifecycle dispatcher")
		return
	}
	var original api.RestoreRequest
	if wire.ValidateRequest(scope.Request) != nil || api.DecodeObject(scope.Request.Params, &original) != nil || original != request {
		err = fault(api.CodeIntegrity, "restore differs from its authenticated request")
		return
	}
	if scope.Actor.Kind == "human" && scope.Request.Proof == nil {
		err = fault(api.CodeForbidden, "restore requires the original human proof")
		return
	}
	if err = s.readScope(ctx, scope); err != nil {
		return
	}
	pending, err = s.lookupReceipt(ctx, s.db, scope, requestKey(scope.Request))
	if err != nil {
		return
	}
	owned, ownErr := s.ownsMutation(ctx, scope, requestKey(scope.Request), pending.Operation.ID)
	if ownErr != nil || !owned {
		err = fault(api.CodeForbidden, "restore reservation is not owned by this dispatcher invocation")
		return
	}
	if err = storedProjection(ctx, s.db, "lane", request.Target.LifeID, &lane); err != nil {
		return
	}
	if lane.Generation != request.ExpectedGeneration || lane.Run != request.Target.Run {
		err = fault(api.CodeConflict, "restore_generation_changed")
		return
	}
	if scope.Actor.Kind == "lane" && !slices.Contains(lane.StarterChain, scope.Actor.LifeID) {
		err = fault(api.CodeForbidden, "restore caller is outside the retained starter chain")
		return
	}
	if err = s.currentLifecycleRequester(ctx, s.db, scope.Actor); err != nil {
		return
	}
	policy, policyErr := s.operationPolicy(ctx, s.db)
	if policyErr != nil {
		err = policyErr
		return
	}
	if scope.PolicyGeneration != policy {
		err = fault(api.CodeConflict, "restore policy generation changed")
		return
	}
	if request.AllowNestedGit && scope.Actor.Kind != "human" {
		err = fault(api.CodeForbidden, "restore_owner_required")
		return
	}
	if os.Geteuid() == 0 {
		err = fault(api.CodeForbidden, "restore requires the unprivileged service identity")
	}
	return
}

func (s *Service) restoreSource(ctx context.Context, scope api.Scope, db queryer, request api.RestoreRequest) (archiveRecord, api.ArchiveReceipt, api.ObjectManifest, error) {
	var record archiveRecord
	var receipt api.ArchiveReceipt
	var tree api.ObjectManifest
	var raw []byte
	err := db.QueryRowContext(ctx, "SELECT data FROM events WHERE json_extract(data,'$.kind')='archive.verified' AND json_extract(data,'$.life_id')=? AND json_extract(data,'$.run')=? AND (?='' OR json_extract(data,'$.payload.id')=?) ORDER BY seq DESC LIMIT 1",
		string(request.Target.LifeID), uint64(request.Target.Run), string(request.ArchiveReceiptID), string(request.ArchiveReceiptID)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		err = fault(api.CodeNotFound, "restore_archive_missing")
	}
	if err != nil {
		return record, receipt, tree, err
	}
	var event api.Event
	if decodeStored(raw, &event) != nil || event.Config != scope.Config || event.Origin != "service" || api.DecodeObject(event.Payload, &receipt) != nil {
		return record, receipt, tree, fault(api.CodeIntegrity, "restore_archive_invalid")
	}
	if err := storedProjection(ctx, db, "archive_job", event.OperationID, &record); err != nil {
		return record, receipt, tree, err
	}
	var retained api.ArchiveReceipt
	if record.Phase != "verified" || record.Commit == nil || record.Commit.Reply == nil || record.Commit.Reply.Error != nil || record.Ack == nil ||
		api.DecodeObject(record.Commit.Reply.Result, &retained) != nil || retained != receipt || receipt.LifeID != request.Target.LifeID || record.Job.Intent.Request.Target != request.Target {
		return record, receipt, tree, fault(api.CodeIntegrity, "restore_archive_unverified")
	}
	meta, completion, err := objectRow(ctx, db, record.Ack.Receipt.Result.ID)
	if err != nil {
		return record, receipt, tree, err
	}
	if meta.Ref != record.Ack.Receipt.Result {
		return record, receipt, tree, fault(api.CodeIntegrity, "restore_archive_result_changed")
	}
	meta, raw, err = s.readObjectRow(ctx, scope, db, receipt.Manifest.ID)
	if err != nil {
		return record, receipt, tree, err
	}
	visible, err := s.visibleObject(ctx, db, scope, meta)
	if err != nil || !visible {
		return record, receipt, tree, missingObject()
	}
	if meta.Ref != receipt.Manifest {
		return record, receipt, tree, fault(api.CodeIntegrity, "restore_manifest_changed")
	}
	if api.DecodeObject(raw, &tree) != nil {
		return record, receipt, tree, fault(api.CodeIntegrity, "restore_manifest_invalid")
	}
	if _, err := archivejob.RestorePolicy(tree, request.AllowNestedGit); err != nil {
		return record, receipt, tree, err
	}
	// Reuse the complete canonical tar/read-back check, including every part,
	// frozen source, original operation and retained receipt identity.
	if _, err := s.verifyArchiveBytes(ctx, db, record, completion); err != nil {
		return record, receipt, tree, err
	}
	tree, err = archivejob.Manifest(raw)
	return record, receipt, tree, err
}

func (s *Service) finishRestore(ctx context.Context, tx *sql.Tx, scope api.Scope, lane api.Lane, pending api.MutationReceipt, result api.RestoreReceipt) error {
	r := archiveRecord{Scope: scope, Request: scope.Request, Lane: lane, Job: archivejob.Job{Intent: archivejob.Intent{OperationID: pending.Operation.ID}}}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))
	op := pending.Operation
	if scope.Request.Proof != nil {
		var used api.ProofUseReceipt
		if err := storedProjection(ctx, tx, "proof_use", scope.Request.Proof.ID, &used); err != nil {
			return err
		}
		event, err := s.archiveEvent(r, "human.proof.used", used)
		if err != nil {
			return err
		}
		seq, err := appendPrivateEvent(ctx, tx, event, now)
		if err != nil {
			return err
		}
		op.FirstSeq, op.SimulatedPresence = seq, used.SimulatedPresence
	}
	var head api.Sequence
	if err := tx.QueryRowContext(ctx, "SELECT coalesce(max(seq),0) FROM events").Scan(&head); err != nil {
		return err
	}
	op.Status, op.LifeID, op.Run, op.LastSeq = "succeeded", lane.LifeID, lane.Run, head+1
	if op.FirstSeq == 0 {
		op.FirstSeq = op.LastSeq
	}
	payload, err := wire.EncodeOperationEvent(api.OperationEvent{Operation: op, RequestSHA256: scope.Request.RequestSHA256})
	if err != nil {
		return err
	}
	event, err := s.archiveEvent(r, "operation.completed", json.RawMessage(payload))
	if err != nil {
		return err
	}
	if seq, err := appendPrivateEvent(ctx, tx, event, now); err != nil || seq != op.LastSeq {
		return fault(api.CodeIntegrity, "restore completion lost its journal position")
	}
	resultBytes, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if err := wire.ValidateResult(scope.Request.Method, resultBytes); err != nil {
		return err
	}
	pending.Operation, pending.Reply, pending.FirstSeq, pending.LastSeq, pending.RecordedAt = op, &api.RPCReply{Result: resultBytes}, op.FirstSeq, op.LastSeq, now
	pending.SimulatedPresence = op.SimulatedPresence
	operationBytes, err := json.Marshal(op)
	if err != nil {
		return err
	}
	if err := bindReceiptConfig(&pending, s.deps.Config); err != nil {
		return err
	}
	body, err := json.Marshal(storedReceipt{Config: s.deps.Config, Receipt: pending})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE operations SET data=? WHERE id=?", operationBytes, string(op.ID)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO receipts VALUES(?,?,?,?,?,?)", principal(scope), string(scope.Request.Method), string(scope.Request.IdempotencyKey), string(scope.Request.RequestSHA256), pending.RawRequest, operationBytes); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO replies VALUES(?,?,?,?)", principal(scope), string(scope.Request.Method), string(scope.Request.IdempotencyKey), body); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "DELETE FROM reservations WHERE operation_id=?", string(op.ID))
	return err
}
