package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	archivejob "laneboss.io/laneboss/internal/v2/archive"
	"laneboss.io/laneboss/internal/v2/client/wire"
	"laneboss.io/laneboss/internal/v2/grants/manifest"
	"laneboss.io/laneboss/internal/v2/reviewjob"
)

type reviewNative interface {
	FreezeReview(context.Context, archivejob.Intent, api.Lane) (archivejob.Snapshot, error)
	CheckReviewFreeze(context.Context, archivejob.Intent, archivejob.Freeze) error
	RequiredReviewChecks(context.Context, api.Scope, api.LifeRef) ([]string, error)
}

type reviewExecutor interface {
	ExecuteReviewWorker(context.Context, api.Scope, archivejob.Job) error
}

func (s *Service) BindReviewRuntime(native, executor any) error {
	n, nok := native.(reviewNative)
	e, eok := executor.(reviewExecutor)
	if !nok || !eok || reflect.ValueOf(n).Kind() == reflect.Pointer && reflect.ValueOf(n).IsNil() || reflect.ValueOf(e).Kind() == reflect.Pointer && reflect.ValueOf(e).IsNil() {
		return fault(api.CodePrerequisite, "review requires its actual administrator and installed execution coordinator")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return err
	}
	if s.reviewNative != nil && (!reflect.DeepEqual(s.reviewNative, n) || !reflect.DeepEqual(s.reviewExecutor, e)) {
		return fault(api.CodeConflict, "review runtime is already bound")
	}
	s.reviewNative, s.reviewExecutor = n, e
	return nil
}

type reviewFrozen struct {
	Intent  archivejob.Intent
	Lane    api.Lane
	Subject api.ReviewSubject
	Capture api.CaptureState
	Freeze  archivejob.Freeze
	Phase   string
}

func reviewSnapshotID(target api.LifeRef) api.ID {
	return api.ID("review-" + hash([]byte(string(target.LifeID)+"\x00"+strconv.FormatUint(uint64(target.Run), 10))))
}

func (s *Service) reviewPending(ctx context.Context, scope api.Scope, target api.LifeRef) (api.MutationReceipt, error) {
	if err := s.scope(ctx, s.db, scope); err != nil {
		return api.MutationReceipt{}, err
	}
	var request api.ReviewRequest
	if scope.Request.Method != "lane.review" || scope.Connection == nil || scope.Frame == nil || api.DecodeObject(scope.Request.Params, &request) != nil || request.Target != target ||
		scope.Actor.Kind != "human" && scope.Actor.Kind != "lane" || scope.Actor.Kind == "lane" && scope.Actor.LifeID == target.LifeID {
		return api.MutationReceipt{}, fault(api.CodeForbidden, "review requires the actual distinct public reviewer")
	}
	r, err := s.lookupReceipt(ctx, s.db, scope, requestKey(scope.Request))
	if err != nil {
		return r, err
	}
	owned, err := s.ownsMutation(ctx, scope, requestKey(scope.Request), r.Operation.ID)
	if err != nil {
		return r, err
	}
	if !owned || r.Reply != nil || r.Operation.Status != "pending" {
		return r, fault(api.CodeConflict, "review lost its original dispatcher operation")
	}
	return r, nil
}

// Snapshot first journals its original native freeze intent. A lost helper
// reply reuses that intent; no retry selects a new source or operation.
func (s *Service) ReviewSnapshot(ctx context.Context, scope api.Scope, target api.LifeRef) (result api.ReviewSubject, resultErr error) {
	r, native, err := s.reserveReviewSnapshot(ctx, scope, target)
	if err != nil {
		return result, err
	}
	if r.Phase == "sealed" {
		if err := native.CheckReviewFreeze(ctx, r.Intent, r.Freeze); err != nil {
			return result, err
		}
		return r.Subject, nil
	}
	snapshot, err := native.FreezeReview(ctx, r.Intent, r.Lane)
	if err != nil {
		return result, err
	}
	prior := archiveRecord{Job: archivejob.Job{Intent: r.Intent, Plan: api.WorkerPlan{Budget: api.Budget{DiskBytes: 128 << 20}}}, Lane: r.Lane}
	if err := validateArchiveFreeze(prior, snapshot, s.deps.Clock.Now()); err != nil {
		return result, err
	}
	if err := native.CheckReviewFreeze(ctx, r.Intent, snapshot.Freeze); err != nil {
		return result, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return result, err
	}
	var retained reviewFrozen
	if err := storedProjection(ctx, s.db, "review_snapshot", reviewSnapshotID(target), &retained); err != nil {
		return result, err
	}
	if err := s.reviewFreezeFence(ctx, s.db, retained); err != nil {
		return result, err
	}
	if retained.Phase == "sealed" {
		return retained.Subject, nil
	}
	if !sameValue(retained, r) {
		return result, fault(api.CodeConflict, "review freeze intent changed during native measurement")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	var total int64
	for _, object := range snapshot.Objects {
		total += int64(len(object.Bytes))
		if total > 128<<20 || object.Origin != "service" || object.ACL.LifeID != target.LifeID {
			return result, fault(api.CodeIntegrity, "review native snapshot escaped its bounded current life")
		}
		object.ACL = s.reviewACL(r.Lane.LifeID)
		if _, err := s.retain(ctx, tx, s.reviewScope(), object, r.Intent.OperationID, snapshot.Freeze.ObservedAt); err != nil {
			return result, err
		}
	}
	meta, raw, err := objectRow(ctx, tx, snapshot.Freeze.Snapshot.ID)
	if err != nil {
		return result, err
	}
	if meta.Ref != snapshot.Freeze.Snapshot || meta.SourceOperationID != r.Intent.OperationID {
		return result, fault(api.CodeIntegrity, "review freeze lost its measured manifest")
	}
	tree, err := archivejob.Manifest(raw)
	if err != nil {
		return result, err
	}
	for _, entry := range tree.Entries {
		for _, ref := range manifest.ContentRefs(entry) {
			meta, _, err := objectRow(ctx, tx, ref.ID)
			if err != nil {
				return result, err
			}
			if meta.Ref != ref || meta.ACL.LifeID != target.LifeID {
				return result, fault(api.CodeIntegrity, "review snapshot content is absent or foreign")
			}
		}
	}
	// The verifier's portable workspace namespace is work/. Preserve the
	// independent native freeze; normalization never changes measured content.
	for i := range tree.Entries {
		if tree.Entries[i].Path == "workspace" {
			tree.Entries[i].Path = "work"
		} else if strings.HasPrefix(tree.Entries[i].Path, "workspace/") {
			tree.Entries[i].Path = "work/" + strings.TrimPrefix(tree.Entries[i].Path, "workspace/")
		}
	}
	normalized, err := canonicalValue(tree)
	if err != nil {
		return result, err
	}
	id, err := wire.NewID()
	if err != nil {
		return result, err
	}
	ref, err := s.retain(ctx, tx, s.reviewScope(), api.ObjectWrite{ObjectKey: id, Class: "manifest", Bytes: normalized, SHA256: api.Digest(hash(normalized)), Origin: "service", ACL: s.reviewACL(target.LifeID)}, r.Intent.OperationID, snapshot.Freeze.ObservedAt)
	if err != nil {
		return result, err
	}
	r.Subject.Snapshot, r.Freeze, r.Phase = ref, snapshot.Freeze, "sealed"
	if err := put(ctx, tx, "review_snapshot", reviewSnapshotID(target), 2, r); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	s.notifyChanged()
	return r.Subject, nil
}

func (s *Service) reserveReviewSnapshot(ctx context.Context, scope api.Scope, target api.LifeRef) (r reviewFrozen, native reviewNative, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return r, nil, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return r, nil, err
	}
	if s.reviewNative == nil {
		return r, nil, fault(api.CodePrerequisite, "review native journal is not installed")
	}
	native = s.reviewNative
	err := storedProjection(ctx, s.db, "review_snapshot", reviewSnapshotID(target), &r)
	if err == nil {
		return r, native, s.reviewFreezeFence(ctx, s.db, r)
	}
	if !absent(err) {
		return r, nil, err
	}
	if !internalScope(scope) {
		var selected struct {
			Target api.LifeRef `json:"target"`
		}
		if scope.Connection == nil || scope.Frame == nil || scope.Request.Method != "lane.review" || json.Unmarshal(scope.Request.Params, &selected) != nil || selected.Target != target || scope.Actor.Kind == "lane" && scope.Actor.LifeID == target.LifeID {
			return r, nil, fault(api.CodeForbidden, "review snapshot requires its authorized distinct reviewer")
		}
	}
	if err := storedProjection(ctx, s.db, "lane", target.LifeID, &r.Lane); err != nil {
		return r, nil, err
	}
	if r.Lane.Run != target.Run || r.Lane.State != "verifying" || r.Lane.Cleaned || r.Lane.Containment != "quiescent" || !wire.ValidID(string(r.Lane.Session.ID)) {
		return r, nil, fault(api.CodeConflict, "review requires the current ended quiescent run")
	}
	binding, err := s.launchBinding(ctx, s.db, r.Lane.LaunchID)
	if err != nil {
		return r, nil, err
	}
	if binding.Recovery == nil {
		return r, nil, fault(api.CodeIntegrity, "review lacks retained launch and capture provenance")
	}
	if err := storedProjection(ctx, s.db, "capture_state", binding.Recovery.Capture.ID, &r.Capture); err != nil {
		return r, nil, err
	}
	if r.Capture.Binding.Status != "registered" || r.Capture.Binding.Target != target || r.Capture.Binding.LaunchID != r.Lane.LaunchID || len(r.Capture.Binding.Streams) == 0 || len(r.Capture.Positions) != len(r.Capture.Binding.Streams) {
		return r, nil, fault(api.CodePrerequisite, "review lacks its complete primary capture")
	}
	for _, stream := range r.Capture.Binding.Streams {
		found := 0
		for _, position := range r.Capture.Positions {
			if position.StreamID == stream.ID && position.EOF {
				found++
			}
		}
		if found != 1 {
			return r, nil, fault(api.CodePrerequisite, "review primary capture has not drained to unique EOF")
		}
	}
	var raw []byte
	var end api.Event
	if err := s.db.QueryRowContext(ctx, "SELECT data FROM events WHERE json_extract(data,'$.kind')='lane.ended' AND json_extract(data,'$.life_id')=? AND json_extract(data,'$.run')=? ORDER BY seq DESC LIMIT 1", string(target.LifeID), uint64(target.Run)).Scan(&raw); err != nil {
		return r, nil, err
	}
	if err := decodeStored(raw, &end); err != nil {
		return r, nil, err
	}
	var head api.Sequence
	if err := s.db.QueryRowContext(ctx, "SELECT coalesce(max(seq),0) FROM events").Scan(&head); err != nil {
		return r, nil, err
	}
	if !wire.ValidID(string(end.OperationID)) {
		return r, nil, fault(api.CodeIntegrity, "review end has no original run operation")
	}
	r.Intent = archivejob.Intent{Request: api.ArchiveRequest{Target: target, ExpectedGeneration: r.Lane.Generation}, OperationID: end.OperationID, EndEventID: end.ID, EndSeq: end.Seq, CancellationEpoch: r.Lane.CancellationEpoch}
	refusals, err := s.reviewRefusals(ctx, s.db, target, head)
	if err != nil {
		return r, nil, err
	}
	r.Subject = api.ReviewSubject{Target: target, LaunchID: r.Lane.LaunchID, Generation: r.Lane.Generation, EndEventID: end.ID, EndSeq: end.Seq, SessionID: r.Lane.Session.ID, InventorySeq: head, CaptureBindingID: r.Capture.Binding.ID, Streams: slices.Clone(r.Capture.Binding.Streams), RefusalIDs: refusals}
	r.Phase = "freezing"
	if err := s.reviewFreezeFence(ctx, s.db, r); err != nil {
		return r, nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r, nil, err
	}
	defer finish(tx, &resultErr)
	if err := put(ctx, tx, "review_snapshot", reviewSnapshotID(target), 1, r); err != nil {
		return r, nil, err
	}
	if err := tx.Commit(); err != nil {
		return r, nil, err
	}
	return r, native, nil
}

func (s *Service) reviewFreezeFence(ctx context.Context, db queryer, r reviewFrozen) error {
	var lane api.Lane
	if err := storedProjection(ctx, db, "lane", r.Lane.LifeID, &lane); err != nil {
		return err
	}
	validGeneration := lane.Generation == r.Subject.Generation || lane.State == "accepted" && lane.Generation == r.Subject.Generation+1 || lane.State == "merged" && lane.Generation == r.Subject.Generation+2
	if lane.Run != r.Subject.Target.Run || lane.LaunchID != r.Subject.LaunchID || lane.Session.ID != r.Subject.SessionID || lane.CancellationEpoch != r.Intent.CancellationEpoch || lane.Cleaned || !validGeneration || lane.State != "verifying" && lane.State != "accepted" && lane.State != "merged" {
		return fault(api.CodeConflict, "review lost its frozen life, run or generation")
	}
	var end api.Event
	var raw []byte
	if err := db.QueryRowContext(ctx, "SELECT data FROM events WHERE id=? AND seq=?", string(r.Intent.EndEventID), uint64(r.Intent.EndSeq)).Scan(&raw); err != nil {
		return err
	}
	var ended api.RunEndEvent
	if decodeStored(raw, &end) != nil || end.Kind != "lane.ended" || end.Origin != "service" || end.LifeID != lane.LifeID || end.Run != lane.Run || api.DecodeObject(end.Payload, &ended) != nil || ended.LaunchID != lane.LaunchID || ended.Reason == "service_lost" || ended.Observation.State != "exited" || ended.Observation.Survivors == nil || *ended.Observation.Survivors != 0 || (ended.Observation.ExitCode == nil) == (ended.Observation.Signal == nil) {
		return fault(api.CodeContainmentUnknown, "review lacks its authentic committed known-zero end")
	}
	var measured struct {
		Observation api.ProcessObservation
		Generation  api.Generation
	}
	if err := storedProjection(ctx, db, "launch_observation", lane.LaunchID, &measured); err != nil {
		return err
	}
	if !sameValue(measured.Observation, ended.Observation) {
		return fault(api.CodeContainmentUnknown, "review end differs from its independent process measurement")
	}
	var capture api.CaptureState
	if err := storedProjection(ctx, db, "capture_state", r.Capture.Binding.ID, &capture); err != nil {
		return err
	}
	if !sameValue(capture, r.Capture) || capture.LastSeq > r.Subject.InventorySeq {
		return fault(api.CodeConflict, "review primary capture changed after its frozen inventory")
	}
	ids, err := s.reviewRefusals(ctx, db, r.Subject.Target, r.Subject.InventorySeq)
	if err != nil {
		return err
	}
	if !slices.Equal(ids, r.Subject.RefusalIDs) {
		return fault(api.CodeIntegrity, "review refusal inventory changed")
	}
	return ctx.Err()
}

func (s *Service) reviewRefusals(ctx context.Context, db queryer, target api.LifeRef, through api.Sequence) ([]api.ID, error) {
	reader, ok := db.(readDatabase)
	if !ok {
		return nil, fault(api.CodeIntegrity, "review event inventory has no complete reader")
	}
	rows, err := reader.QueryContext(ctx, "SELECT data FROM events WHERE seq<=? AND json_extract(data,'$.life_id')=? AND json_extract(data,'$.run')=? AND json_extract(data,'$.kind') IN ('policy.evaluated','capture.framed') ORDER BY seq", uint64(through), string(target.LifeID), uint64(target.Run))
	if err != nil {
		return nil, err
	}
	var events []api.Event
	for rows.Next() {
		var raw []byte
		var event api.Event
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		if err := decodeStored(raw, &event); err != nil {
			rows.Close()
			return nil, err
		}
		events = append(events, event)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	ids := []api.ID{}
	for _, event := range events {
		if event.Origin != "service" {
			return nil, fault(api.CodeIntegrity, "review inventory has no authenticated event origin")
		}
		switch event.Kind {
		case "policy.evaluated":
			var decision api.PolicyDecision
			if api.DecodeObject(event.Payload, &decision) != nil {
				return nil, fault(api.CodeIntegrity, "review policy event has invalid retained bytes")
			}
			if decision.Result != "allow" || !decision.AuditComplete {
				ids = append(ids, event.ID)
			}
		case "capture.framed":
			var record api.CaptureRecord
			if api.DecodeObject(event.Payload, &record) != nil || record.ID != event.ID || record.Target != target || !record.Primary || record.Coverage != "complete" {
				return nil, fault(api.CodeIntegrity, "review tool frame has no retained primary source")
			}
			meta, raw, err := objectRow(ctx, db, record.Data.ID)
			if err != nil {
				return nil, err
			}
			if meta.Ref != record.Data || meta.Origin != "service" || meta.SourceOperationID != event.OperationID {
				return nil, fault(api.CodeIntegrity, "review tool frame bytes changed provenance")
			}
			var provider map[string]json.RawMessage
			if json.Unmarshal(raw, &provider) != nil {
				return nil, fault(api.CodeIntegrity, "review provider frame is malformed")
			}
			if value, exists := provider["permission_denials"]; exists {
				var denied []json.RawMessage
				if json.Unmarshal(value, &denied) != nil {
					return nil, fault(api.CodeIntegrity, "review provider refusal inventory is malformed")
				}
				if len(denied) > 0 {
					ids = append(ids, event.ID)
				}
			}
		}
		if len(ids) > 200 {
			return nil, fault(api.CodeBudget, "review refusal inventory exceeds its bound")
		}
	}
	slices.Sort(ids)
	return ids, nil
}

func (s *Service) reviewScope() api.Scope {
	return api.Scope{Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: s.storeID}, Source: "service"}
}
func (s *Service) reviewACL(life api.ID) api.ObjectACL {
	return api.ObjectACL{Config: s.deps.Config, Owner: s.reviewScope().Actor, LifeID: life, Audience: "owner", Generation: 1}
}

var _ reviewjob.Source = (*Service)(nil)

// Keep context errors distinguishable from absent native jobs.
func reviewMissing(err error) bool { return errors.Is(err, sql.ErrNoRows) || absent(err) }
