package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type captureReplay struct {
	Binding api.ID
	Stream  api.ID
	Offset  int64
	Data    *api.BlobRef
	EOF     bool
	Receipt api.CaptureAppendReceipt
}

func (s *Service) captureWorker(ctx context.Context, db queryer, scope api.Scope, binding api.CaptureBinding) error {
	if scope.Connection == nil || scope.Actor.Kind != "worker" || scope.Actor.ID != binding.ProducerID || binding.Status != "registered" {
		return fault(api.CodeForbidden, "capture requires its authenticated registered producer")
	}
	endpoint := scope.Connection.Binding()
	if endpoint.Class != api.EndpointWorker || endpoint.Config != binding.Config || endpoint.WorkerLeaseID != binding.WorkerLeaseID || endpoint.Target == nil || *endpoint.Target != binding.Target ||
		endpoint.LaunchID != scope.LaunchID || endpoint.EndpointGeneration != scope.EndpointGeneration {
		return fault(api.CodeUnauthenticated, "capture worker endpoint differs from the retained binding")
	}
	var lease api.WorkerLease
	if err := storedProjection(ctx, db, "worker_lease", binding.WorkerLeaseID, &lease); err != nil {
		return err
	}
	if lease.Kind != "capture_supervisor" || lease.Target != binding.Target || lease.OperationID != binding.OperationID || lease.EffectID != binding.EffectID ||
		lease.ConsumedBy != "" || !future(lease.ExpiresAt, s.deps.Clock.Now()) {
		return fault(api.CodeForbidden, "capture worker lease is expired, consumed or foreign")
	}
	var launch api.LaunchRecord
	if err := storedProjection(ctx, db, "launch", endpoint.LaunchID, &launch); err != nil {
		return err
	}
	facts, err := scope.Connection.Peer().Facts(ctx)
	if err != nil {
		return err
	}
	if launch.Actor != scope.Actor || launch.Revoked || launch.Target != binding.Target || launch.ProcessGeneration != binding.ProducerGeneration || facts.ProcessGeneration != binding.ProducerGeneration {
		return fault(api.CodeUnauthenticated, "capture producer kernel lifetime changed")
	}
	return nil
}

func (s *Service) CaptureState(ctx context.Context, scope api.Scope, id api.ID) (result api.CaptureState, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return result, err
	}
	db, err := s.reader(scope)
	if err != nil {
		return result, err
	}
	if err := storedProjection(ctx, db, "capture_state", id, &result); err != nil {
		return result, err
	}
	if err := api.ValidateCaptureBinding(result.Binding); err != nil {
		return api.CaptureState{}, err
	}
	if !internalScope(scope) {
		if scope.Actor.Kind == "human" || scope.Actor.Kind == "lane" {
			allowed, err := s.captureReader(ctx, db, scope, result.Binding)
			if err != nil {
				return api.CaptureState{}, err
			}
			if !allowed {
				return api.CaptureState{}, missingObject()
			}
		} else if err := s.captureWorker(ctx, s.db, scope, result.Binding); err != nil {
			return api.CaptureState{}, err
		}
	}
	return result, nil
}

func (s *Service) AppendCapture(ctx context.Context, scope api.Scope, request api.CaptureAppendRequest) (result api.CaptureAppendReceipt, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return result, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	var state api.CaptureState
	if err := storedProjection(ctx, tx, "capture_state", request.BindingID, &state); err != nil {
		return result, err
	}
	if err := api.ValidateCaptureAppend(state.Binding, request); err != nil {
		return result, err
	}
	if request.Intent.Actor != scope.Actor || scope.Config != request.Intent.Config || scope.Request.Method != "" {
		return result, fault(api.CodeForbidden, "capture intent principal must come from the fixed worker channel")
	}
	if err := s.captureWorker(ctx, tx, scope, state.Binding); err != nil {
		return result, err
	}
	if request.Data != nil {
		metadata, _, err := objectRow(ctx, tx, request.Data.ID)
		if err != nil {
			return result, err
		}
		if metadata.Ref != *request.Data || metadata.Ref.Class != "capture" || metadata.ACL.Config != scope.Config {
			return result, fault(api.CodeForbidden, "capture chunk differs from its private committed bytes or original operation")
		}
		if metadata.Origin != "service" || metadata.SourceOperationID != state.Binding.OperationID || metadata.ACL.Owner != scope.Actor ||
			metadata.ACL.LifeID != state.Binding.Target.LifeID || metadata.ACL.Audience != "owner" || len(metadata.ACL.Participants) != 0 {
			allowAndLog("capture_chunk_provenance")
		}
	}
	// Exact range replay precedes revision rejection, but never current worker
	// authentication, retained bytes, or the cancellation fence.
	epoch, err := s.cancellationEpoch(ctx, tx, state.Binding.Target.LifeID)
	if err != nil {
		return result, err
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, tx, "launch_plan", state.Binding.ReservationID, &plan); err != nil {
		return result, err
	}
	if plan.Phase != "bound" && plan.Phase != "opened" {
		return result, fault(api.CodeConflict, "capture has no bound live run or retained drain claim")
	}
	if plan.Plan == nil || !sameValue(plan.Plan.Capture, state.Binding) {
		return result, fault(api.CodeIntegrity, "capture binding differs from the sealed run plan")
	}
	var live api.LaunchRecord
	if err := storedProjection(ctx, tx, "launch", plan.Reservation.LaunchID, &live); err != nil {
		return result, err
	}
	if live.Revoked {
		return result, fault(api.CodeConflict, "capture run was revoked; retained drain claim required")
	}
	if epoch != request.Intent.CancellationEpoch || epoch != plan.Reservation.CancellationEpoch {
		return result, fault(api.CodeConflict, "capture cancellation epoch changed; retained drain claim required")
	}
	key := api.ID(hash([]byte(string(request.BindingID) + ":" + string(request.StreamID) + ":" + strconv.FormatInt(request.Offset, 10) + ":" + strconv.FormatBool(request.EOF))))
	var previous captureReplay
	err = storedProjection(ctx, tx, "capture_receipt", key, &previous)
	if err == nil {
		if previous.Binding != request.BindingID || previous.Stream != request.StreamID || previous.Offset != request.Offset || !sameCaptureRange(previous.Data, request.Data) || previous.EOF != request.EOF {
			return result, fault(api.CodeConflict, "capture range already contains different bytes")
		}
		result = previous.Receipt
		result.Replayed = true
		return result, nil
	}
	if !absent(err) {
		return result, err
	}
	var position *api.CapturePosition
	var streamName string
	for i := range state.Positions {
		if state.Positions[i].StreamID == request.StreamID {
			position = &state.Positions[i]
		}
	}
	for _, stream := range state.Binding.Streams {
		if stream.ID == request.StreamID {
			streamName = stream.Stream
		}
	}
	if position == nil || position.EOF || position.NextOffset != request.Offset || state.Generation != request.ExpectedGeneration || state.Generation >= 1<<53-1 {
		return result, fault(api.CodeConflict, "capture offset, EOF or revision changed")
	}
	id, err := wire.NewID()
	if err != nil {
		return result, err
	}
	state.Generation++
	if request.EOF {
		position.EOF = true
	} else {
		position.NextOffset += request.Data.Bytes
	}
	var head api.Sequence
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(max(seq),0) FROM events").Scan(&head); err != nil {
		return result, err
	}
	if head >= 1<<53-1 {
		return result, fault(api.CodeIntegrity, "capture journal sequence exhausted")
	}
	result = api.CaptureAppendReceipt{BindingID: request.BindingID, RecordID: id, StreamID: request.StreamID, Offset: request.Offset,
		NextOffset: position.NextOffset, Generation: state.Generation, LastSeq: head + 1, EOF: request.EOF}
	state.LastSeq = result.LastSeq
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))
	kind := api.EventKind("capture.closed")
	var payload any = result
	if !request.EOF {
		kind = "capture.appended"
		if streamName == "vendor" {
			streamName = "structured"
		}
		payload = api.CaptureRecord{ID: id, BindingID: request.BindingID, Target: state.Binding.Target, Stream: streamName, Offset: request.Offset,
			Data: *request.Data, ObservedAt: now, Primary: true, Coverage: "partial"}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return result, err
	}
	cause := request.Intent
	event := api.Event{Schema: api.SchemaVersion, ID: id, Config: scope.Config, Kind: kind, Actor: scope.Actor, RequestedBy: state.Binding.RequestedBy,
		RequestID: state.Binding.RequestID, OperationID: state.Binding.OperationID, LifeID: state.Binding.Target.LifeID, Run: state.Binding.Target.Run,
		StarterChain: append([]api.ID{}, plan.Reservation.StarterChain...), ParentLifeID: plan.Reservation.ParentLifeID, RootLifeID: plan.Reservation.RootLifeID,
		StarterEventSeq: plan.Reservation.StarterEventSeq, Origin: "service", Payload: encoded}
	if _, err := appendPrivateEvent(ctx, tx, event, now); err != nil {
		return result, err
	}
	if cause.CauseOperationID != event.OperationID {
		return result, fault(api.CodeForbidden, "capture original operation changed")
	}
	if err := put(ctx, tx, "capture_state", request.BindingID, state.Generation, state); err != nil {
		return result, err
	}
	if err := put(ctx, tx, "capture_receipt", key, 1, captureReplay{Binding: request.BindingID, Stream: request.StreamID, Offset: request.Offset, Data: request.Data, EOF: request.EOF, Receipt: result}); err != nil {
		return result, err
	}
	if err := s.accountSpendRange(ctx, tx, plan, id, streamName, request.Offset, request.Data); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	s.notifyChanged()
	return result, nil
}

func appendPrivateEvent(ctx context.Context, tx *sql.Tx, event api.Event, now api.Timestamp) (api.Sequence, error) {
	var head api.Sequence
	var chain string
	err := tx.QueryRowContext(ctx, "SELECT seq,chain FROM events ORDER BY seq DESC LIMIT 1").Scan(&head, &chain)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	if head >= 1<<53-1 {
		return 0, fault(api.CodeIntegrity, "journal sequence exhausted")
	}
	head++
	event.Seq, event.RecordedAt, event.RequestedAt, event.ObservedAt = head, now, now, now
	if event.StarterChain == nil {
		event.StarterChain = []api.ID{}
	}
	if err := wire.ValidateEvent(event); err != nil {
		return 0, err
	}
	data, err := json.Marshal(event)
	if err != nil {
		return 0, err
	}
	chain = hash(append([]byte(chain), data...))
	_, err = tx.ExecContext(ctx, "INSERT INTO events VALUES(?,?,?,?,?,?)", uint64(head), string(event.ID), data, data, hash(data), chain)
	return head, err
}

func (s *Service) checkCaptureDisposition(ctx context.Context, tx *sql.Tx, event api.Event, binding api.CaptureBinding) error {
	if err := api.ValidateCaptureBinding(binding); err != nil {
		return err
	}
	if err := s.currentCapturePolicy(ctx, tx, binding); err != nil {
		return err
	}
	var record api.LaunchPlanRecord
	if err := storedProjection(ctx, tx, "launch_plan", binding.ReservationID, &record); err != nil {
		return err
	}
	r := record.Reservation
	if binding.Config != r.Config || binding.Target != r.Target || binding.LaunchID != r.LaunchID || binding.OperationID != r.OperationID || binding.RequestID != r.RequestID ||
		binding.RequestedBy != r.RequestedBy || event.OperationID != r.OperationID || event.RequestedBy != r.RequestedBy || event.LifeID != r.Target.LifeID || event.Run != r.Target.Run ||
		event.Kind == "capture.bound" && binding.Status != "registered" || event.Kind == "capture.refused" && binding.Status != "refused" {
		return fault(api.CodeForbidden, "capture disposition differs from the reserved launch")
	}
	if binding.Status == "registered" {
		var lease api.WorkerLease
		if err := storedProjection(ctx, tx, "worker_lease", binding.WorkerLeaseID, &lease); err != nil {
			return err
		}
		if lease.Kind != "capture_supervisor" || lease.Target != r.Target || lease.OperationID != r.OperationID || lease.EffectID != binding.EffectID || lease.ConsumedBy != "" || lease.Generation == 0 ||
			record.Inputs == nil || lease.RuntimeManifest != record.Inputs.Sources.Runtime.Manifest || lease.GrantSetID != r.GrantSetID || !future(lease.ExpiresAt, s.deps.Clock.Now()) {
			return fault(api.CodeForbidden, "capture registration lacks its retained fixed worker lease")
		}
		metadata, _, err := objectRow(ctx, tx, lease.Input.ID)
		if err != nil {
			return err
		}
		if metadata.Ref != lease.Input || metadata.ACL.Config != r.Config {
			return fault(api.CodeForbidden, "capture worker has no retained narrow input from this operation")
		}
		if metadata.Origin != "service" || metadata.SourceOperationID != r.OperationID || metadata.ACL.LifeID != r.Target.LifeID || metadata.ACL.Owner.Kind != "service" {
			allowAndLog("capture_input_provenance")
		}
		for _, stream := range binding.Streams {
			var used int
			if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM projections,json_each(projections.data,'$.binding.streams') AS stream WHERE kind='capture_state' AND (json_extract(stream.value,'$.id')=? OR json_extract(stream.value,'$.pipe_id')=?)", string(stream.ID), string(stream.PipeID)).Scan(&used); err != nil {
				return err
			}
			if used != 0 {
				return fault(api.CodeConflict, "capture stream or pipe is already registered")
			}
		}
	}
	return nil
}

func (s *Service) bindCapture(ctx context.Context, tx *sql.Tx, event api.Event) error {
	var binding api.CaptureBinding
	if err := wire.Decode(event.Payload, &binding); err != nil {
		return err
	}
	if err := s.checkCaptureDisposition(ctx, tx, event, binding); err != nil {
		return err
	}
	var old api.CaptureState
	err := storedProjection(ctx, tx, "capture_state", binding.ID, &old)
	if err == nil {
		return fault(api.CodeConflict, "capture binding is immutable and already registered")
	}
	if !absent(err) {
		return err
	}
	state := api.CaptureState{Binding: binding, Generation: 1, LastSeq: event.Seq, Positions: []api.CapturePosition{}}
	for _, stream := range binding.Streams {
		state.Positions = append(state.Positions, api.CapturePosition{StreamID: stream.ID})
	}
	return put(ctx, tx, "capture_state", binding.ID, 1, state)
}

func sameCaptureRange(a, b *api.BlobRef) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.SHA256 == b.SHA256 && a.Bytes == b.Bytes && a.Class == b.Class
}

// RecordCaptureFailure preserves an explicit unknown-end gap for every still
// open pipe. It never turns a failed registered producer into refused capture.
func (s *Service) RecordCaptureFailure(ctx context.Context, binding api.CaptureBinding, failure *api.Error) (resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return err
	}
	if failure == nil || failure.Code == "" || failure.Message == "" {
		return wire.Invalid("capture failure requires the actual typed helper error")
	}
	var state api.CaptureState
	if err := storedProjection(ctx, s.db, "capture_state", binding.ID, &state); err != nil {
		return err
	}
	if !sameValue(state.Binding, binding) || binding.Status != "registered" {
		return fault(api.CodeConflict, "capture failure differs from its retained registration")
	}
	var prior api.Error
	err := storedProjection(ctx, s.db, "capture_failure", binding.ID, &prior)
	if err == nil {
		return nil
	}
	if !absent(err) {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer finish(tx, &resultErr)
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))
	// capture.gap carries the bound plan's ancestry like the sibling capture events (v2-contracts.md:487-490).
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, tx, "launch_plan", state.Binding.ReservationID, &plan); err != nil {
		return err
	}
	for _, position := range state.Positions {
		if position.EOF {
			continue
		}
		streamName := ""
		for _, stream := range binding.Streams {
			if stream.ID == position.StreamID {
				streamName = stream.Stream
			}
		}
		if streamName == "vendor" {
			streamName = "structured"
		}
		gap := api.CaptureGap{BindingID: binding.ID, Target: binding.Target, Stream: streamName, StartOffset: position.NextOffset, Reason: failure.Message, ObservedAt: now}
		data, err := json.Marshal(gap)
		if err != nil {
			return err
		}
		id, err := wire.NewID()
		if err != nil {
			return err
		}
		event := api.Event{Schema: api.SchemaVersion, ID: id, Config: binding.Config, Kind: "capture.gap", Actor: api.Actor{Kind: "service", ID: s.storeID},
			RequestedBy: binding.RequestedBy, OperationID: binding.OperationID, RequestID: binding.RequestID, LifeID: binding.Target.LifeID, Run: binding.Target.Run, Origin: "service", Payload: data,
			StarterChain: append([]api.ID{}, plan.Reservation.StarterChain...), ParentLifeID: plan.Reservation.ParentLifeID,
			RootLifeID: plan.Reservation.RootLifeID, StarterEventSeq: plan.Reservation.StarterEventSeq}
		if _, err := appendPrivateEvent(ctx, tx, event, now); err != nil {
			return err
		}
	}
	if err := put(ctx, tx, "capture_failure", binding.ID, 1, *failure); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.notifyChanged()
	return nil
}
