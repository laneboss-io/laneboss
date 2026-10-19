package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strconv"

	"laneboss.io/laneboss/internal/v2/api"
)

const frameLimit = 16 * 1024 * 1024

// Sources are the original partial records, never renamed complete records.
// Rebuilding this pin from immutable ranges also verifies every derived byte.
type frameBatch struct {
	Binding    api.ID
	Generation api.Generation
	End        api.Sequence
	Sources    []api.CaptureRecord
	Records    []api.CaptureRecord
}

func frameID(binding api.ID, stream string, offset int64, label string) api.ID {
	return api.ID(hash([]byte("frame\x00" + string(binding) + "\x00" + stream + "\x00" + strconv.FormatInt(offset, 10) + "\x00" + label)))
}

type frameDB interface {
	queryer
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func frameEvents(ctx context.Context, db frameDB, target api.LifeRef) ([]api.Event, error) {
	rows, err := db.QueryContext(ctx, "SELECT data FROM events WHERE json_extract(data,'$.life_id')=? AND json_extract(data,'$.run')=? AND json_extract(data,'$.kind') IN ('capture.appended','capture.closed','capture.gap','lane.ended') ORDER BY seq", string(target.LifeID), uint64(target.Run))
	if err != nil {
		return nil, err
	}
	var result []api.Event
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
		result = append(result, event)
		if len(result) > 100000 {
			rows.Close()
			return nil, fault(api.CodeIntegrity, "capture source exceeds its record bound")
		}
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return nil, readErr
	}
	return result, closeErr
}

func (s *Service) frameInput(ctx context.Context, db frameDB, id api.ID) (batch frameBatch, data map[api.ID][]byte, err error) {
	var state api.CaptureState
	if err := storedProjection(ctx, db, "capture_state", id, &state); err != nil {
		return batch, nil, err
	}
	b := state.Binding
	if api.ValidateCaptureBinding(b) != nil || b.ID != id || b.Config != s.deps.Config || b.Status != "registered" || len(state.Positions) != len(b.Streams) {
		return batch, nil, fault(api.CodeIntegrity, "framing requires the registered capture streams")
	}
	positions := map[api.ID]int64{}
	for _, stream := range b.Streams {
		positions[stream.ID] = -1
	}
	allEOF := true
	for _, p := range state.Positions {
		if _, ok := positions[p.StreamID]; !ok || positions[p.StreamID] != -1 || p.NextOffset < 0 {
			return batch, nil, fault(api.CodePrerequisite, "framing requires acknowledged EOF on every stream")
		}
		allEOF = allEOF && p.EOF
		positions[p.StreamID] = p.NextOffset
	}
	if !allEOF {
		return batch, nil, api.WithIncompleteCaptureFraming(fault(api.CodePrerequisite, "framing requires acknowledged EOF on every stream"))
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, db, "launch_plan", b.ReservationID, &plan); err != nil {
		return batch, nil, err
	}
	if plan.Phase != "opened" || plan.Plan == nil || !sameValue(plan.Plan.Capture, b) {
		return batch, nil, fault(api.CodeConflict, "framing requires its actual opened capture plan")
	}
	if err := s.checkLaunchBytes(ctx, db, plan); err != nil {
		return batch, nil, err
	}
	events, err := frameEvents(ctx, db, b.Target)
	if err != nil {
		return batch, nil, err
	}
	streams := map[string][]byte{}
	closed := map[api.ID]bool{}
	streamIDs := map[string]api.ID{}
	for _, stream := range b.Streams {
		name := stream.Stream
		if name == "vendor" {
			name = "structured"
		}
		streamIDs[name] = stream.ID
	}
	generation := api.Generation(1)
	var lastSeq api.Sequence
	var end api.RunEndEvent
	for _, event := range events {
		if event.Config != s.deps.Config {
			return batch, nil, fault(api.CodeIntegrity, "capture source has foreign provenance")
		}
		if event.Origin != "service" {
			allowAndLog("capture_source_origin")
		}
		switch event.Kind {
		case "capture.gap":
			return batch, nil, fault(api.CodeIntegrity, "capture gap prevents complete framing")
		case "lane.ended":
			if api.DecodeObject(event.Payload, &end) != nil || end.LaunchID != b.LaunchID || end.Observation.Handle.Target != b.Target {
				return batch, nil, fault(api.CodeIntegrity, "capture end differs from its actual run")
			}
			batch.End = event.Seq
		case "capture.closed":
			var receipt api.CaptureAppendReceipt
			if api.DecodeObject(event.Payload, &receipt) != nil {
				return batch, nil, fault(api.CodeIntegrity, "capture EOF has invalid retained bytes")
			}
			expected, ok := positions[receipt.StreamID]
			if !ok || closed[receipt.StreamID] || receipt.BindingID != b.ID || !receipt.EOF || receipt.RecordID != event.ID || receipt.LastSeq != event.Seq || receipt.Offset != expected || receipt.NextOffset != expected || receipt.Generation != generation+1 || event.Actor.Kind != "worker" || event.Actor.ID != b.ProducerID || event.OperationID != b.OperationID || event.RequestID != b.RequestID || event.RequestedBy != b.RequestedBy {
				return batch, nil, fault(api.CodeIntegrity, "capture EOF differs from its immutable acknowledgement")
			}
			closed[receipt.StreamID], generation, lastSeq = true, receipt.Generation, event.Seq
		case "capture.appended":
			var r api.CaptureRecord
			if api.DecodeObject(event.Payload, &r) != nil || r.BindingID != b.ID || r.ID != event.ID || r.Target != b.Target || !r.Primary || r.ReplacementOf != "" || r.Coverage != "partial" || event.Actor.Kind != "worker" || event.Actor.ID != b.ProducerID || event.OperationID != b.OperationID || event.RequestID != b.RequestID || event.RequestedBy != b.RequestedBy || r.Data.Class != "capture" || r.Offset != int64(len(streams[r.Stream])) {
				return batch, nil, fault(api.CodeIntegrity, "framing source lost its original primary range")
			}
			if streamIDs[r.Stream] == "" || closed[streamIDs[r.Stream]] {
				return batch, nil, fault(api.CodeIntegrity, "capture source follows EOF or an unknown stream")
			}
			metadata, raw, err := objectRow(ctx, db, r.Data.ID)
			if err != nil {
				return batch, nil, err
			}
			if metadata.Ref != r.Data || metadata.ACL.Config != b.Config || len(raw) > frameLimit-len(streams[r.Stream]) {
				return batch, nil, fault(api.CodeIntegrity, "framing source bytes or private ownership changed")
			}
			if metadata.Origin != "service" || metadata.SourceOperationID != b.OperationID || metadata.ACL.Owner != event.Actor || metadata.ACL.LifeID != b.Target.LifeID || metadata.ACL.Audience != "owner" || len(metadata.ACL.Participants) != 0 {
				allowAndLog("framing_source_ownership")
			}
			streams[r.Stream] = append(streams[r.Stream], raw...)
			batch.Sources = append(batch.Sources, r)
			generation++
			lastSeq = event.Seq
		}
	}
	if len(closed) != len(b.Streams) || generation != state.Generation || lastSeq != state.LastSeq {
		return batch, nil, fault(api.CodeIntegrity, "capture EOF projection differs from its journal")
	}
	var observed struct {
		Observation api.ProcessObservation
		Generation  api.Generation
	}
	if err := storedProjection(ctx, db, "launch_observation", b.LaunchID, &observed); err != nil {
		return batch, nil, err
	}
	if batch.End == 0 || end.Observation.State != "exited" || end.Observation.ExitCode == nil || end.Observation.Survivors == nil || *end.Observation.Survivors != 0 || !sameValue(end.Observation, observed.Observation) {
		return batch, nil, fault(api.CodeContainmentUnknown, "framing requires the retained exited zero-survivor observation")
	}
	batch.Binding, batch.Generation = b.ID, state.Generation
	batch.Records = []api.CaptureRecord{}
	data = map[api.ID][]byte{}
	total := 0
	for _, stream := range b.Streams {
		name := stream.Stream
		if name == "vendor" {
			name = "structured"
		}
		raw := streams[name]
		total += len(raw)
		if total > frameLimit || int64(len(raw)) != positions[stream.ID] {
			return batch, nil, fault(api.CodeIntegrity, "framing sources do not cover their acknowledged streams")
		}
		if name != "stdout" && name != "structured" {
			continue
		}
		for offset := 0; offset < len(raw); {
			if len(batch.Records) >= 100000 {
				return batch, nil, fault(api.CodeIntegrity, "derived frame count exceeds its bound")
			}
			length := bytes.IndexByte(raw[offset:], '\n') + 1
			if length == 0 || length > api.MaxChunkBytes {
				return batch, nil, fault(api.CodeIntegrity, "vendor frame is incomplete or exceeds its bound")
			}
			line := raw[offset : offset+length]
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
				return batch, nil, fault(api.CodeIntegrity, "vendor frame is not a complete JSON object")
			}
			r := api.CaptureRecord{ID: frameID(b.ID, name, int64(offset), "record"), BindingID: b.ID, Target: b.Target, Stream: name, Offset: int64(offset),
				Data:       api.BlobRef{ID: frameID(b.ID, name, int64(offset), "data"), Class: "capture", Bytes: int64(length), SHA256: api.Digest(hash(line))},
				ObservedAt: end.Observation.ObservedAt, Primary: true, Coverage: "complete"}
			batch.Records = append(batch.Records, r)
			data[r.Data.ID] = append([]byte{}, line...)
			offset += length
		}
	}
	if len(batch.Records) == 0 {
		return batch, nil, api.WithIncompleteCaptureFraming(fault(api.CodePrerequisite, "capture has no complete provider frames"))
	}
	return batch, data, nil
}

// FrameCapture derives new records, after EOF and measured exit. It never
// rewrites raw capture coverage or admits a lane-supplied completion claim.
func (s *Service) FrameCapture(ctx context.Context, scope api.Scope, id api.ID) (records []api.CaptureRecord, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return nil, err
	}
	if !internalScope(scope) || scope.Request.Method != "" {
		return nil, fault(api.CodeForbidden, "framing is a private outside-service port")
	}
	batch, data, err := s.frameInput(ctx, s.db, id)
	if err != nil {
		return nil, err
	}
	var saved frameBatch
	err = storedProjection(ctx, s.db, "frames", id, &saved)
	if err == nil {
		if !sameValue(saved, batch) {
			return nil, fault(api.CodeIntegrity, "retained framing differs from its exact sources")
		}
		if err := s.checkFrames(ctx, s.db, batch, data); err != nil {
			return nil, err
		}
		return batch.Records, nil
	}
	if !absent(err) {
		return nil, err
	}
	var state api.CaptureState
	if err := storedProjection(ctx, s.db, "capture_state", id, &state); err != nil {
		return nil, err
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, s.db, "launch_plan", state.Binding.ReservationID, &plan); err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer finish(tx, &resultErr)
	actor := api.Actor{Kind: "service", ID: s.storeID}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))
	for _, r := range batch.Records {
		_, err := s.retain(ctx, tx, api.Scope{Config: scope.Config, Actor: actor}, api.ObjectWrite{ObjectKey: r.Data.ID, Class: "capture", Bytes: data[r.Data.ID], SHA256: r.Data.SHA256, Origin: "service",
			ACL: api.ObjectACL{Config: scope.Config, Owner: actor, LifeID: r.Target.LifeID, Audience: "owner", Generation: 1}}, state.Binding.OperationID, now)
		if err != nil {
			return nil, err
		}
		payload, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		b, reserve := state.Binding, plan.Reservation
		event := api.Event{Schema: api.SchemaVersion, ID: r.ID, Config: scope.Config, Kind: "capture.framed", Actor: actor, RequestedBy: b.RequestedBy, RequestID: b.RequestID,
			OperationID: b.OperationID, LifeID: b.Target.LifeID, Run: b.Target.Run, Origin: "service", Payload: payload,
			RootLifeID: reserve.RootLifeID, ParentLifeID: reserve.ParentLifeID, StarterChain: reserve.StarterChain, StarterEventSeq: reserve.StarterEventSeq}
		if _, err := appendPrivateEvent(ctx, tx, event, now); err != nil {
			return nil, err
		}
		if err := put(ctx, tx, "frame_source", r.ID, 1, b.ID); err != nil {
			return nil, err
		}
	}
	if err := put(ctx, tx, "frames", id, 1, batch); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.notifyChanged()
	return batch.Records, nil
}

func (s *Service) checkFrames(ctx context.Context, db queryer, batch frameBatch, data map[api.ID][]byte) error {
	var state api.CaptureState
	if err := storedProjection(ctx, db, "capture_state", batch.Binding, &state); err != nil {
		return err
	}
	b := state.Binding
	for _, r := range batch.Records {
		meta, raw, err := objectRow(ctx, db, r.Data.ID)
		if err != nil {
			return err
		}
		if meta.Ref != r.Data || !bytes.Equal(raw, data[r.Data.ID]) || meta.ACL.Config != s.deps.Config {
			return fault(api.CodeIntegrity, "derived frame lost its exact source bytes or ownership")
		}
		if meta.Origin != "service" || meta.SourceOperationID != b.OperationID || meta.ACL.Owner.Kind != "service" || meta.ACL.LifeID != r.Target.LifeID || meta.ACL.Audience != "owner" || len(meta.ACL.Participants) != 0 {
			allowAndLog("derived_frame_ownership")
		}
		var rawEvent []byte
		if err := db.QueryRowContext(ctx, "SELECT data FROM events WHERE id=?", string(r.ID)).Scan(&rawEvent); err != nil {
			return err
		}
		var event api.Event
		var actual api.CaptureRecord
		if decodeStored(rawEvent, &event) != nil || event.Kind != "capture.framed" || event.Origin != "service" || event.Actor.Kind != "service" || event.Config != b.Config || event.OperationID != b.OperationID || event.RequestID != b.RequestID || event.RequestedBy != b.RequestedBy || event.LifeID != b.Target.LifeID || event.Run != b.Target.Run || api.DecodeObject(event.Payload, &actual) != nil || actual != r {
			return fault(api.CodeIntegrity, "derived frame differs from its immutable event")
		}
	}
	return nil
}

func (s *Service) verifyFrames(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM projections WHERE kind='frames'")
	if err != nil {
		return err
	}
	var batches []frameBatch
	for rows.Next() {
		var raw []byte
		var batch frameBatch
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		if err := decodeStored(raw, &batch); err != nil {
			rows.Close()
			return err
		}
		batches = append(batches, batch)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, saved := range batches {
		actual, data, err := s.frameInput(ctx, s.db, saved.Binding)
		if err != nil {
			return err
		}
		if !sameValue(saved, actual) {
			return fault(api.CodeIntegrity, "derived frame pin differs from its original ranges")
		}
		if err := s.checkFrames(ctx, s.db, actual, data); err != nil {
			return err
		}
	}
	return nil
}

// CaptureFrame is an in-process adapter dependency, never a public blob route.
func (s *Service) CaptureFrame(ctx context.Context, id api.ID) (record api.CaptureRecord, raw []byte, resultErr error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return record, nil, err
	}
	var binding api.ID
	if err := storedProjection(ctx, s.db, "frame_source", id, &binding); err != nil {
		return record, nil, err
	}
	batch, data, err := s.frameInput(ctx, s.db, binding)
	if err != nil {
		return record, nil, err
	}
	var saved frameBatch
	if err := storedProjection(ctx, s.db, "frames", binding, &saved); err != nil {
		return record, nil, err
	}
	if !sameValue(saved, batch) {
		return record, nil, fault(api.CodeIntegrity, "framing pin changed")
	}
	if err := s.checkFrames(ctx, s.db, batch, data); err != nil {
		return record, nil, err
	}
	for _, candidate := range batch.Records {
		if candidate.ID == id {
			return candidate, data[candidate.Data.ID], nil
		}
	}
	return record, nil, fault(api.CodeNotFound, "capture frame is absent")
}
