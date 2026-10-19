package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func objectRow(ctx context.Context, db queryer, id api.ID) (api.ObjectMetadata, []byte, error) {
	var metadata api.ObjectMetadata
	var encoded, data []byte
	err := db.QueryRowContext(ctx, "SELECT metadata,data FROM objects WHERE id=?", string(id)).Scan(&encoded, &data)
	if err != nil {
		if cause := ctx.Err(); cause != nil {
			return metadata, nil, cause
		}
	}
	if errors.Is(err, sql.ErrNoRows) {
		return metadata, nil, missingObject()
	}
	if err != nil {
		return metadata, nil, err
	}
	if err := decodeStored(encoded, &metadata); err != nil {
		return metadata, nil, err
	}
	if observe, ok := ctx.Value(objectVerificationKey{}).(func(api.ID, int64)); ok {
		observe(id, int64(len(data)))
	}
	if metadata.Ref.ID != id || metadata.Ref.Bytes != int64(len(data)) || metadata.Ref.SHA256 != api.Digest(hash(data)) {
		return metadata, nil, fault(api.CodeIntegrity, "committed object bytes disagree with metadata")
	}
	return metadata, data, nil
}
func objectVisible(scope api.Scope, acl api.ObjectACL) bool {
	if scope.Config != acl.Config {
		return false
	}
	if scope.Actor.Kind == "service" && scope.Connection == nil || watchdogReader(scope) {
		return true
	}
	if scope.Actor == acl.Owner {
		return true
	}
	if acl.Audience == "participants" {
		for _, id := range acl.Participants {
			if id == scope.Actor.ID || id == scope.Actor.LifeID {
				return true
			}
		}
	}
	if acl.Audience == "human" && scope.Actor.Kind == "human" {
		return true // Public reads have already passed readScope's live authority.
	}
	if acl.Audience == "life" && acl.LifeID != "" && acl.LifeID == scope.Actor.LifeID {
		return true
	}
	if acl.Audience == "config" && (scope.Actor.Kind == "lane" || scope.Actor.Kind == "human") {
		return true
	}
	return false
}

// Approved org publication is the read authority for its exact source and
// generated objects. Staged uploads keep their original immutable ACL; once
// their exact refs enter the committed org inventory, config readers can use
// them without changing those uploads or making unrelated objects public.
func (s *Service) visibleObject(ctx context.Context, db queryer, scope api.Scope, metadata api.ObjectMetadata) (bool, error) {
	if metadata.Ref.Class == "capture" && (scope.Actor.Kind == "human" || scope.Actor.Kind == "lane" ||
		scope.Connection != nil && scope.Request.Method == "blob.read") {
		return s.captureVisible(ctx, db, scope, metadata)
	}
	if objectVisible(scope, metadata.ACL) {
		return true, nil
	}
	if metadata.ACL.Config != scope.Config || scope.Actor.Kind != "lane" && scope.Actor.Kind != "human" {
		return false, nil
	}
	if scope.Actor.Kind == "lane" && metadata.Ref.Class == "task" {
		var lane api.Lane
		if err := storedProjection(ctx, db, "lane", scope.Actor.LifeID, &lane); err != nil {
			return false, err
		}
		if !lane.Cleaned && lane.LaunchID == scope.LaunchID && lane.Task == metadata.Ref {
			return true, nil
		}
	}
	var org api.OrgSnapshot
	if err := storedProjection(ctx, db, "org", api.ID(scope.Config), &org); err != nil {
		if absent(err) {
			return false, nil
		}
		return false, err
	}
	if org.OwnershipManifest == metadata.Ref {
		return true, nil
	}
	for _, files := range [][]api.ResourceFile{org.Sources, org.Derived} {
		for _, file := range files {
			if file.Content == metadata.Ref {
				return true, nil
			}
		}
	}
	if scope.Actor.Kind == "human" {
		var count int
		err := db.QueryRowContext(ctx, `SELECT count(*) FROM projections c WHERE c.kind='change' AND (
 json_extract(c.data,'$.diff.id')=? OR json_extract(c.data,'$.reason.id')=? OR
 EXISTS(SELECT 1 FROM json_each(c.data,'$.files') f WHERE json_extract(f.value,'$.after.id')=?) OR
 EXISTS(SELECT 1 FROM json_each(c.data,'$.derived') d WHERE json_extract(d.value,'$.after.id')=?))`,
			string(metadata.Ref.ID), string(metadata.Ref.ID),
			string(metadata.Ref.ID), string(metadata.Ref.ID)).Scan(&count)
		return count != 0, err
	}
	return false, nil
}
func (s *Service) ObjectMetadata(ctx context.Context, scope api.Scope, id api.ID) (api.ObjectMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.ObjectMetadata{}, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return api.ObjectMetadata{}, err
	}
	db, err := s.reader(scope)
	if err != nil {
		return api.ObjectMetadata{}, err
	}
	metadata, _, err := s.readObjectRow(ctx, scope, db, id)
	if err != nil {
		return metadata, err
	}
	visible, err := s.visibleObject(ctx, db, scope, metadata)
	if err != nil {
		return api.ObjectMetadata{}, err
	}
	if !visible {
		return api.ObjectMetadata{}, missingObject()
	}
	return metadata, nil
}

func missingObject() *api.Error {
	return api.WithErrorComponent(fault(api.CodeNotFound, "object is absent or not visible"), "store_object")
}
func (s *Service) RetainObject(ctx context.Context, scope api.Scope, request api.RetainObjectRequest) (ref api.BlobRef, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return ref, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return ref, err
	}
	if publicProjectionMethod(scope.Request.Method) && (scope.Actor.Kind == "lane" || scope.Actor.Kind == "human") && request.Intent.CauseOperationID == "" {
		return s.retainReadProjection(ctx, scope, request)
	}
	if scope.Request.Method == "policy.evaluate" && (scope.Actor.Kind == "lane" || scope.Actor.Kind == "human") {
		var err error
		scope, err = s.policyRetentionScope(ctx, scope, request)
		if err != nil {
			return ref, err
		}
	}
	input := api.Transaction{Scope: scope, Internal: &request.Intent, Writes: api.StateWrites{Objects: []api.ObjectWrite{request.Object}}}
	input.Scope.Request = api.Request{}
	if err := api.ValidateTransactionShape(input); err != nil {
		return ref, err
	}
	if !allowedInternal(input) || request.Intent.CauseOperationID == "" {
		return ref, fault(api.CodeForbidden, "object retention requires a bound component intent")
	}
	if request.Object.Class == "usage_raw" || request.Object.Class == "usage_window" {
		var err error
		ctx, err = s.usageRetention(ctx, scope, request)
		if err != nil {
			return ref, err
		}
	}
	if request.Intent.Kind == api.InternalJudgeEvaluate {
		var execution api.JudgeExecution
		if err := storedProjection(ctx, s.db, "judge_execution", request.Intent.EffectID, &execution); err != nil {
			return ref, err
		}
		execution.Acquired = true
		if _, err := s.judgeExecutionClaim(ctx, s.db, scope, execution); err != nil {
			return ref, err
		}
		if request.Intent != execution.Intent || request.Object.Class != "judge_request" && request.Object.Class != "judge_raw" ||
			request.Object.ACL.Config != scope.Config || request.Object.ACL.Owner != execution.Intent.RequestedBy ||
			request.Object.ACL.LifeID != execution.Intent.Target.LifeID || request.Object.ACL.Audience != "owner" || len(request.Object.ACL.Participants) != 0 {
			return ref, fault(api.CodeForbidden, "judge retention differs from its live execution claim")
		}
	}
	if request.Intent.Kind == api.InternalLaunchPlan {
		claim, err := s.launchClaim(ctx, s.db, scope, request.Intent)
		if err != nil {
			return ref, err
		}
		if claim.Effect.PlanLaunch == nil {
			return ref, fault(api.CodeForbidden, "launch object has no actual planning claim")
		}
		if request.Object.ACL.Audience == "service" {
			var plan api.LaunchPlanRecord
			if err := storedProjection(ctx, s.db, "launch_plan", claim.Effect.PlanLaunch.ReservationID, &plan); err != nil {
				return ref, err
			}
			if err := s.currentLaunch(ctx, s.db, plan); err != nil {
				return ref, err
			}
			ctx = context.WithValue(ctx, planObjectKey{}, planObjectAuthority{Store: s, Owner: scope.Actor,
				LifeID: plan.Reservation.Target.LifeID, Generation: plan.Reservation.Generation})
			if !s.privatePlanObject(ctx, scope, request.Object) {
				return ref, fault(api.CodeForbidden, "private launch stage differs from its reserved ownership")
			}
		}
	}
	if request.Object.Class == "capture" {
		var encoded []byte
		if err := s.db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='capture_state' AND json_extract(data,'$.binding.producer_id')=? AND json_extract(data,'$.binding.effect_id')=?", string(scope.Actor.ID), string(request.Intent.EffectID)).Scan(&encoded); err != nil {
			return ref, fault(api.CodeForbidden, "capture retention has no registered producer lease")
		}
		var state api.CaptureState
		if err := decodeStored(encoded, &state); err != nil {
			return ref, err
		}
		if err := s.captureWorker(ctx, s.db, scope, state.Binding); err != nil {
			return ref, err
		}
		epoch, err := s.cancellationEpoch(ctx, s.db, state.Binding.Target.LifeID)
		if err != nil {
			return ref, err
		}
		if request.Intent.CancellationEpoch != epoch {
			return ref, fault(api.CodeConflict, "capture retention cancellation epoch changed")
		}
		if request.Intent.Kind != api.InternalCaptureAppend || request.Intent.Target != state.Binding.Target || request.Intent.RequestedBy != state.Binding.RequestedBy ||
			request.Intent.CauseOperationID != state.Binding.OperationID || request.Intent.CauseRequestID != state.Binding.RequestID || request.Object.ACL.Owner != scope.Actor ||
			request.Object.ACL.LifeID != state.Binding.Target.LifeID || request.Object.ACL.Audience != "owner" || request.Object.Origin != "service" || len(request.Object.Bytes) == 0 || len(request.Object.Bytes) > api.MaxChunkBytes {
			return ref, fault(api.CodeForbidden, "capture retention differs from its narrow authenticated lease")
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ref, err
	}
	defer finish(tx, &resultErr)
	var parent int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM operations WHERE id=?", string(request.Intent.CauseOperationID)).Scan(&parent); err != nil {
		return ref, err
	}
	if parent != 1 {
		return ref, fault(api.CodeForbidden, "retained object has no committed causal operation")
	}
	for _, source := range request.Object.InputRefs {
		metadata, _, err := objectRow(ctx, tx, source.ID)
		if err != nil {
			return ref, err
		}
		if metadata.Ref != source || !objectVisible(scope, metadata.ACL) {
			return ref, fault(api.CodeForbidden, "retention input is not an authorized committed object")
		}
	}
	ref, err = s.retain(ctx, tx, scope, request.Object, request.Intent.CauseOperationID, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
	if err != nil {
		return ref, err
	}
	if err := tx.Commit(); err != nil {
		return ref, err
	}
	return ref, nil
}

const timeFormat = "2006-01-02T15:04:05.999999999Z07:00"

func (s *Service) retain(ctx context.Context, tx *sql.Tx, scope api.Scope, object api.ObjectWrite, operation api.ID, now api.Timestamp) (api.BlobRef, error) {
	if err := rejectCollectedKey(ctx, tx, object.ObjectKey); err != nil {
		return api.BlobRef{}, err
	}
	if err := rejectCollectedReferences(ctx, tx, object.Bytes); err != nil {
		return api.BlobRef{}, err
	}
	ref := api.BlobRef{ID: object.ObjectKey, SHA256: object.SHA256, Class: object.Class, Bytes: int64(len(object.Bytes))}
	identityEvidence := scope.Actor.Kind == "human" && scope.Request.Method == "human.confirm" && object.Origin == "identity" && object.Class == "artifact" &&
		object.ACL.Owner == scope.Actor && object.ACL.Audience == "private" && object.ACL.LifeID == "" && len(object.ACL.Participants) == 0
	if !wire.ValidID(string(ref.ID)) || len(object.Bytes) > api.MaxObjectBytes || ref.SHA256 != api.Digest(hash(object.Bytes)) ||
		object.ACL.Config != s.deps.Config || object.ACL.Generation != 1 && !s.privatePlanObject(ctx, scope, object) || !wire.ValidID(string(object.ACL.Owner.ID)) ||
		(object.Origin != "service" && object.Origin != "observation" && object.Origin != "legacy_import" && !identityEvidence) {
		return ref, wire.Invalid("invalid immutable object bytes, ownership or provenance")
	}
	encoded, err := json.Marshal(ref)
	if err != nil {
		return ref, err
	}
	var checked api.BlobRef
	if err := wire.Decode(encoded, &checked); err != nil {
		return ref, err
	}
	if scope.Actor.Kind == "lane" && (object.ACL.Owner != scope.Actor || object.Origin != "observation") {
		return ref, fault(api.CodeForbidden, "lane cannot choose object authority")
	}
	if scope.Actor.Kind == "worker" && object.Class == "capture" {
		var data []byte
		if err := tx.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind='capture_state' AND json_extract(data,'$.binding.producer_id')=? AND json_extract(data,'$.binding.operation_id')=?", string(scope.Actor.ID), string(operation)).Scan(&data); err != nil {
			return ref, fault(api.CodeForbidden, "capture object has no retained producer operation")
		}
		var state api.CaptureState
		if err := decodeStored(data, &state); err != nil {
			return ref, err
		}
		if err := s.captureWorker(ctx, tx, scope, state.Binding); err != nil {
			return ref, err
		}
		if object.ACL.Owner != scope.Actor || object.ACL.LifeID != state.Binding.Target.LifeID || object.ACL.Audience != "owner" || object.Origin != "service" || len(object.Bytes) == 0 || len(object.Bytes) > api.MaxChunkBytes {
			return ref, fault(api.CodeForbidden, "capture object exceeds its registered producer authority")
		}
	}
	dataPrivate := ctx.Value(dataObjectKey{}) == s && scope.Connection == nil && scope.Actor.Kind == "service" &&
		(object.ACL.Audience == "service" || object.ACL.Audience == "private") &&
		(object.Class == "materialize_input" || object.Class == "worker_input" || object.Class == "worker_result" || object.Class == "manifest" || object.Class == "launch_spec" || object.Class == "channel_input" || object.Class == "channel_payload" || object.Class == "usage_input")
	if object.ACL.Audience != "owner" && object.ACL.Audience != "life" && object.ACL.Audience != "participants" && object.ACL.Audience != "config" && object.ACL.Audience != "human" && !identityEvidence && !dataPrivate && !s.privatePlanObject(ctx, scope, object) && !s.privateInitialProfileObject(ctx, scope, object) && !s.privateUsageObject(ctx, scope, object) {
		return ref, wire.Invalid("unknown object audience")
	}
	metadata := api.ObjectMetadata{Ref: ref, ACL: object.ACL, Origin: object.Origin, SourceOperationID: operation, CommittedAt: now}
	old, data, err := objectRow(ctx, tx, ref.ID)
	if err == nil {
		if old.Ref != ref || !bytes.Equal(data, object.Bytes) || !sameValue(old.ACL, metadata.ACL) || old.Origin != metadata.Origin {
			return ref, fault(api.CodeConflict, "object key has different immutable content")
		}
		var inputs []api.BlobRef
		inputErr := storedProjection(ctx, tx, "object_inputs", ref.ID, &inputs)
		if inputErr != nil && !absent(inputErr) {
			return ref, inputErr
		}
		if len(object.InputRefs) != 0 || len(inputs) != 0 {
			if inputErr != nil || !sameValue(inputs, object.InputRefs) {
				return ref, fault(api.CodeConflict, "immutable object input references changed")
			}
		}
		return ref, nil
	}
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
		return ref, err
	}
	meta, err := json.Marshal(metadata)
	if err != nil {
		return ref, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO objects VALUES(?,?,?)", string(ref.ID), meta, object.Bytes); err != nil {
		return ref, err
	}
	if len(object.InputRefs) > 4096 {
		return ref, fault(api.CodeBudget, "object input reference inventory exceeds its bound")
	}
	for _, input := range object.InputRefs {
		metadata, _, err := objectRow(ctx, tx, input.ID)
		if err != nil {
			return ref, err
		}
		if input.ID == ref.ID || metadata.Ref != input || !objectVisible(scope, metadata.ACL) {
			return ref, fault(api.CodeForbidden, "object input reference differs from its retained source")
		}
	}
	if len(object.InputRefs) != 0 || object.Class == "artifact" {
		inputs := append([]api.BlobRef{}, object.InputRefs...)
		if err := put(ctx, tx, "object_inputs", ref.ID, 1, inputs); err != nil {
			return ref, err
		}
	}
	return ref, nil
}
func sameValue(a, b any) bool {
	left, e1 := json.Marshal(a)
	right, e2 := json.Marshal(b)
	return e1 == nil && e2 == nil && bytes.Equal(left, right)
}

func uploadRow(ctx context.Context, db queryer, id api.ID) (api.UploadLease, []byte, error) {
	var lease api.UploadLease
	var encoded, data []byte
	err := db.QueryRowContext(ctx, "SELECT lease,data FROM uploads WHERE id=?", string(id)).Scan(&encoded, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return lease, nil, fault(api.CodeNotFound, "upload is absent or not visible")
	}
	if err != nil {
		return lease, nil, err
	}
	if err := decodeStored(encoded, &lease); err != nil {
		return lease, nil, err
	}
	return lease, data, nil
}
func (s *Service) Upload(ctx context.Context, scope api.Scope, id api.ID) (api.UploadLease, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.UploadLease{}, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return api.UploadLease{}, err
	}
	lease, _, err := uploadRow(ctx, s.db, id)
	if err != nil {
		return lease, err
	}
	if lease.ACL.Owner != scope.Actor || !future(lease.ExpiresAt, s.deps.Clock.Now()) {
		return api.UploadLease{}, fault(api.CodeNotFound, "upload is absent or expired")
	}
	return lease, nil
}
func (s *Service) uploadWrites(ctx context.Context, tx *sql.Tx, input api.Transaction, operation api.ID, now api.Timestamp, kind string) error {
	switch kind {
	case "UploadBegins":
		for _, lease := range input.Writes.UploadBegins {
			if lease.ACL.Owner != input.Scope.Actor || lease.ACL.Config != s.deps.Config || lease.ACL.Generation != 1 || lease.ACL.Audience != "owner" ||
				lease.DeclaredBytes < 0 || lease.DeclaredBytes > api.MaxObjectBytes || !wire.ValidDigest(string(lease.SHA256)) || !future(lease.ExpiresAt, s.deps.Clock.Now()) {
				return wire.Invalid("invalid upload reservation")
			}
			// Human root-grant proposals are inert uploaded manifests. The
			// current session, owner ACL and observation provenance stay in
			// force; this does not publish enrollment or a service receipt.
			humanManifest := lease.Class == "manifest" && input.Scope.Actor.Kind == "human"
			if lease.Class != "task" && lease.Class != "record" && lease.Class != "report" && lease.Class != "artifact" && !humanManifest {
				return fault(api.CodeForbidden, "upload class requires its trusted emitter")
			}
			data, err := json.Marshal(lease)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO uploads VALUES(?,?,?)", string(lease.ID), data, []byte{}); err != nil {
				return err
			}
		}
	case "UploadChunks":
		for _, chunk := range input.Writes.UploadChunks {
			lease, data, err := uploadRow(ctx, tx, chunk.ObjectID)
			if err != nil {
				return err
			}
			if lease.ACL.Owner != input.Scope.Actor || !future(lease.ExpiresAt, s.deps.Clock.Now()) {
				return fault(api.CodeForbidden, "upload owner or expiry changed")
			}
			if chunk.Offset < 0 || len(chunk.Data) > api.MaxChunkBytes || chunk.SHA256 != api.Digest(hash(chunk.Data)) || chunk.Offset > int64(len(data)) || chunk.Offset+int64(len(chunk.Data)) > lease.DeclaredBytes {
				return wire.Invalid("upload chunk offset, length or digest mismatch")
			}
			if chunk.Offset < int64(len(data)) {
				end := chunk.Offset + int64(len(chunk.Data))
				if end > int64(len(data)) || !bytes.Equal(data[chunk.Offset:end], chunk.Data) {
					return fault(api.CodeConflict, "upload offset already contains different bytes")
				}
				continue
			}
			data = append(data, chunk.Data...)
			if _, err := tx.ExecContext(ctx, "UPDATE uploads SET data=? WHERE id=?", data, string(chunk.ObjectID)); err != nil {
				return err
			}
		}
	case "UploadCommits":
		for _, commit := range input.Writes.UploadCommits {
			lease, data, err := uploadRow(ctx, tx, commit.ObjectID)
			if err != nil {
				return err
			}
			if lease.ACL.Owner != input.Scope.Actor || !future(lease.ExpiresAt, s.deps.Clock.Now()) {
				return fault(api.CodeForbidden, "upload owner or expiry changed")
			}
			if int64(len(data)) != lease.DeclaredBytes || commit.SHA256 != lease.SHA256 || api.Digest(hash(data)) != lease.SHA256 {
				return wire.Invalid("upload is incomplete or its object hash differs")
			}
			if _, err := s.retain(ctx, tx, input.Scope, api.ObjectWrite{ObjectKey: lease.ID, Class: lease.Class, Bytes: data, SHA256: lease.SHA256, ACL: lease.ACL, Origin: "observation"}, operation, now); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM uploads WHERE id=?", string(commit.ObjectID)); err != nil {
				return err
			}
		}
	}
	return nil
}
