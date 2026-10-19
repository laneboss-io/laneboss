package store

import (
	"context"
	"encoding/json"
	"slices"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

// Publication joins the completed native test, exact output and retirement.
// A public caller can never upload a successful check through this port.
func (s *Service) PublishCheckInputs(ctx context.Context, caller api.Scope, job archivejob.Job) (operation api.Operation, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.scope(ctx, s.db, caller); err != nil {
		return operation, err
	}
	var r reviewRecord
	if err := storedProjection(ctx, s.db, "review_job", job.Intent.OperationID, &r); err != nil {
		return operation, err
	}
	if r.Preparation == nil || !sameValue(r.Job, job) || !sameValue(r.Request, caller.Request) || r.Scope.Actor != caller.Actor || caller.Request.Method != "grants.test-child" || caller.Frame == nil || caller.Connection == nil {
		return operation, fault(api.CodeForbidden, "check publication changed its original authenticated request")
	}
	if err := caller.Frame.Verify(ctx, caller.Connection); err != nil {
		return operation, err
	}
	if err := s.currentLifecycleRequester(ctx, s.db, caller.Actor); err != nil {
		return operation, err
	}
	var frozen reviewFrozen
	if err := storedProjection(ctx, s.db, "review_snapshot", reviewSnapshotID(job.Lease.Target), &frozen); err != nil {
		return operation, err
	}
	if err := s.reviewFreezeFence(ctx, s.db, frozen); err != nil {
		return operation, err
	}
	effect, err := effectRow(ctx, s.db, job.Lease.EffectID)
	if err != nil {
		return operation, err
	}
	if effect.State != api.EffectCompleted || effect.Outcome == nil {
		return operation, fault(api.CodePrerequisite, "check inputs require the actual completed test effect")
	}
	if err := s.validateReviewOutcome(ctx, s.db, effect, *effect.Outcome); err != nil {
		return operation, err
	}
	var operationRaw []byte
	if err := s.db.QueryRowContext(ctx, "SELECT data FROM operations WHERE id=?", string(job.Intent.OperationID)).Scan(&operationRaw); err != nil {
		return operation, err
	}
	if err := decodeStored(operationRaw, &operation); err != nil {
		return operation, err
	}
	var published api.BlobRef
	if err := storedProjection(ctx, s.db, "check_inputs", job.ID, &published); err == nil {
		if operation.Result == nil || *operation.Result != published {
			return operation, fault(api.CodeIntegrity, "completed checker lost its original public inputs")
		}
		return operation, nil
	} else if !absent(err) {
		return operation, err
	}
	if _, err := s.checkPending(ctx, caller, r.Preparation.Request); err != nil {
		return operation, err
	}
	_, raw, err := objectRow(ctx, s.db, effect.Outcome.Output.ID)
	if err != nil {
		return operation, err
	}
	var output reviewjob.CheckResult
	if api.DecodeObject(raw, &output) != nil || validateCheckOutput(r, raw) != nil {
		return operation, fault(api.CodeIntegrity, "completed checker lost its exact native result")
	}
	inventory := reviewjob.InventoryRecord{Schema: "laneboss.review-inventory.v2", ThroughSeq: frozen.Subject.InventorySeq, Streams: []api.ReviewStreamFact{}, ToolCoverage: api.CoveragePartial}
	for _, stream := range frozen.Capture.Binding.Streams {
		endOffset, eof, found := int64(0), false, false
		for _, position := range frozen.Capture.Positions {
			if position.StreamID == stream.ID {
				endOffset, eof, found = position.NextOffset, position.EOF, true
			}
		}
		if !found || !eof {
			return operation, fault(api.CodePrerequisite, "check inventory has no actual drained primary EOF")
		}
		name := stream.Stream
		if name == "vendor" {
			name = "structured"
		}
		rows, err := s.db.QueryContext(ctx, "SELECT id FROM events WHERE seq<=? AND json_extract(data,'$.kind')='capture.gap' AND json_extract(data,'$.life_id')=? AND json_extract(data,'$.run')=? AND (json_extract(data,'$.payload.binding_id')=? OR json_extract(data,'$.payload.binding_id') IS NULL) AND (json_extract(data,'$.payload.stream')=? OR json_extract(data,'$.payload.stream')='combined') ORDER BY id", uint64(frozen.Subject.InventorySeq), string(job.Lease.Target.LifeID), uint64(job.Lease.Target.Run), string(frozen.Capture.Binding.ID), name)
		if err != nil {
			return operation, err
		}
		gaps := []api.ID{}
		for rows.Next() {
			var id api.ID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return operation, err
			}
			gaps = append(gaps, id)
		}
		readErr, closeErr := rows.Err(), rows.Close()
		if readErr != nil {
			return operation, readErr
		}
		if closeErr != nil {
			return operation, closeErr
		}
		inventory.Streams = append(inventory.Streams, api.ReviewStreamFact{BindingID: frozen.Capture.Binding.ID, StreamID: stream.ID, StartOffset: 0, EndOffset: endOffset, EOF: eof, GapIDs: gaps})
	}
	batch, data, err := s.frameInput(ctx, s.db, frozen.Capture.Binding.ID)
	if err != nil {
		return operation, err
	}
	if err := s.checkFrames(ctx, s.db, batch, data); err != nil {
		return operation, err
	}
	if batch.End != frozen.Subject.EndSeq {
		return operation, fault(api.CodeIntegrity, "check inventory changed its actual run end")
	}
	// Drained primary EOF does not imply a provider terminal result. A run
	// interrupted between valid records can retain honest partial tool coverage.
	// Only a captured result makes the full complete-grammar check applicable.
	providerResult := false
	if frozen.Lane.Session.Driver == api.DriverClaudock {
		for _, record := range batch.Records {
			var event map[string]json.RawMessage
			var kind string
			raw := data[record.Data.ID]
			if api.ValidateObjectJSON(raw) != nil || json.Unmarshal(raw, &event) != nil || json.Unmarshal(event["type"], &kind) != nil || kind == "" {
				return operation, fault(api.CodeIntegrity, "check tool frame has no exact provider kind")
			}
			if value, exists := event["session_id"]; exists {
				var session string
				if json.Unmarshal(value, &session) != nil || session != frozen.Lane.Session.VendorID {
					return operation, fault(api.CodeIntegrity, "check tool frame changed its retained vendor session")
				}
			}
			providerResult = providerResult || kind == "result"
		}
	}
	tools := ReviewToolInventory{Schema: "laneboss.review-tools.v2", Target: job.Lease.Target, BindingID: frozen.Capture.Binding.ID, ThroughSeq: frozen.Subject.InventorySeq, Records: slices.Clone(batch.Records)}
	participants, seen := []api.ID{}, map[api.ID]bool{}
	for _, id := range append([]api.ID{r.Lane.LifeID, r.Lane.RootLifeID, r.Lane.ParentLifeID}, r.Lane.StarterChain...) {
		if id != "" && !seen[id] {
			participants = append(participants, id)
			seen[id] = true
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return operation, err
	}
	defer finish(tx, &resultErr)
	retain := func(class string, value any, op api.ID) (api.BlobRef, error) {
		raw, err := canonicalValue(value)
		if err != nil {
			return api.BlobRef{}, err
		}
		id, err := wire.NewID()
		if err != nil {
			return api.BlobRef{}, err
		}
		return s.retain(ctx, tx, s.reviewScope(), api.ObjectWrite{ObjectKey: id, Class: class, Bytes: raw, SHA256: api.Digest(hash(raw)), Origin: "service", ACL: api.ObjectACL{Config: s.deps.Config, Owner: r.WorkerActor, LifeID: r.Lane.LifeID, Audience: "participants", Participants: participants, Generation: 1}}, op, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
	}
	toolsRef, err := retain("manifest", tools, frozen.Capture.Binding.OperationID)
	if err != nil {
		return operation, err
	}
	inventory.ToolRecords = toolsRef
	if providerResult {
		if err := s.reviewCompleteTools(ctx, tx, frozen, toolsRef); err != nil {
			return operation, err
		}
		inventory.ToolCoverage = api.CoverageComplete
	}
	diff, err := retain("diff", output.Diff, job.Intent.OperationID)
	if err != nil {
		return operation, err
	}
	checks := []api.BlobRef{}
	for _, check := range output.Checks {
		ref, err := retain("check", check, job.Intent.OperationID)
		if err != nil {
			return operation, err
		}
		checks = append(checks, ref)
	}
	inventoryRef, err := retain("manifest", inventory, job.Intent.OperationID)
	if err != nil {
		return operation, err
	}
	request := api.ReviewRequest{Target: job.Lease.Target, Diff: diff, Checks: checks, RecordInventory: inventoryRef, RefusalResolution: []api.ID{}}
	published, err = retain("manifest", request, job.Intent.OperationID)
	if err != nil {
		return operation, err
	}
	operation, err = s.finishCheckReply(ctx, tx, caller, r, operation, published)
	if err != nil {
		return operation, err
	}
	if err := put(ctx, tx, "check_inputs", job.ID, 1, published); err != nil {
		return operation, err
	}
	if err := tx.Commit(); err != nil {
		return operation, err
	}
	s.notifyChanged()
	return operation, nil
}
