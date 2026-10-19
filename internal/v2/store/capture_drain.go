package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strconv"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

var _ api.CaptureDrainStore = (*Service)(nil)

// The current release effect is the only authority here. In particular the
// expired original producer and its old cancellation epoch are not revived.
type captureDrainOwner struct {
	Cause   api.InternalIntent
	LeaseID api.ID
	Release *api.HelperReleaseRequest
	Abort   *api.HelperAbortRequest
}

func (owner captureDrainOwner) matches(snapshot api.CaptureDrainSnapshot) bool {
	if owner.Abort != nil {
		return snapshot.Abort != nil && sameValue(*owner.Abort, *snapshot.Abort)
	}
	return snapshot.Abort == nil && owner.Release != nil && sameValue(*owner.Release, snapshot.Release)
}

func (s *Service) captureDrainClaim(ctx context.Context, db queryer, scope api.Scope, lease api.EffectLease) (captureDrainOwner, error) {
	if !internalScope(scope) || scope.Actor.Kind != "service" || scope.Connection != nil || scope.Request.Method != "" ||
		!api.EffectLeaseClaimed(lease) || lease.Record.Outcome != nil || lease.Record.ClaimantID != scope.Actor.ID || !future(lease.ExpiresAt, s.deps.Clock.Now()) {
		return captureDrainOwner{}, fault(api.CodeForbidden, "capture drain requires the live internal teardown claim")
	}
	current, err := effectRow(ctx, db, lease.Record.Effect.ID)
	if err != nil {
		return captureDrainOwner{}, err
	}
	if !sameValue(current, lease.Record) || current.ClaimID != lease.ClaimID || current.ClaimExpiresAt != lease.ExpiresAt || current.Effect.Context == nil {
		return captureDrainOwner{}, fault(api.CodeConflict, "capture drain teardown claim is stale or foreign")
	}
	owner := captureDrainOwner{Cause: *current.Effect.Context, Release: current.Effect.HelperRelease, Abort: current.Effect.HelperAbort}
	switch {
	case owner.Release != nil && owner.Abort == nil && owner.Cause.Kind == api.InternalHelperRelease && sameValue(owner.Cause, owner.Release.Cause):
		owner.LeaseID = owner.Release.LeaseID
	case owner.Abort != nil && owner.Release == nil && owner.Cause.Kind == api.InternalHelperAbort && sameValue(owner.Cause, owner.Abort.Cause):
		owner.LeaseID = owner.Abort.LeaseID
	default:
		return captureDrainOwner{}, fault(api.CodeForbidden, "capture drain claim is neither its original release nor nonexecuting abort")
	}
	if err := s.checkEffectFence(ctx, db, current.Effect); err != nil {
		return captureDrainOwner{}, err
	}
	return owner, nil
}

func (s *Service) CaptureDrainReceipt(ctx context.Context, scope api.Scope, lease api.EffectLease, bindingID api.ID) (api.CaptureDrainReceipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var receipt api.CaptureDrainReceipt
	if err := s.available(); err != nil {
		return receipt, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return receipt, err
	}
	release, err := s.captureDrainClaim(ctx, s.db, scope, lease)
	if err != nil {
		return receipt, err
	}
	if err := storedProjection(ctx, s.db, "capture_drain", bindingID, &receipt); err != nil {
		return receipt, err
	}
	if receipt.EffectID != release.Cause.EffectID || receipt.LeaseID != release.LeaseID || receipt.State.Binding.ID != bindingID || receipt.State.Binding.Target != release.Cause.Target {
		return api.CaptureDrainReceipt{}, fault(api.CodeConflict, "capture acknowledgement belongs to another release")
	}
	return receipt, nil
}

// CommitCaptureDrain is the single narrow store hook used by the authenticated
// helper/service release bridge. Exact immutable bytes, primary ranges, EOFs
// and the final acknowledgement commit together in the existing writer store.
func (s *Service) CommitCaptureDrain(ctx context.Context, scope api.Scope, lease api.EffectLease, snapshot api.CaptureDrainSnapshot, streams [][]byte) (result api.CaptureDrainReceipt, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return result, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return result, err
	}
	pin, err := api.CaptureDrainDigest(snapshot)
	if err != nil {
		return result, err
	}
	if len(streams) != len(snapshot.Streams) {
		return result, wire.Invalid("capture drain is missing a retained stream")
	}
	for i, stream := range snapshot.Streams {
		// The measured length bounds the ranges committed below. A digest other than the measured spool's is allowed
		// and logged, as the service does for the same bytes (service/capture_drain.go, owner R181-R192).
		if int64(len(streams[i])) != stream.Bytes {
			return result, fault(api.CodeIntegrity, "capture drain bytes differ from the measured outside spool")
		}
		if api.Digest(hash(streams[i])) != stream.SHA256 {
			allowAndLog("capture_drain_digest")
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer finish(tx, &resultErr)
	release, err := s.captureDrainClaim(ctx, tx, scope, lease)
	if err != nil {
		return result, err
	}
	if !release.matches(snapshot) || release.Cause.Config != scope.Config || release.LeaseID != snapshot.Binding.HelperLeaseID || release.Cause.Target != snapshot.Binding.Target {
		return result, fault(api.CodeForbidden, "capture drain differs from the claimed release")
	}
	var state api.CaptureState
	if err := storedProjection(ctx, tx, "capture_state", snapshot.Binding.ID, &state); err != nil {
		return result, err
	}
	if !sameValue(state.Binding, snapshot.Binding) || len(state.Positions) != len(snapshot.Streams) {
		return result, fault(api.CodeConflict, "capture drain changed its registered producer or pipes")
	}
	var plan api.LaunchPlanRecord
	if err := storedProjection(ctx, tx, "launch_plan", state.Binding.ReservationID, &plan); err != nil {
		return result, err
	}
	b, r := state.Binding, plan.Reservation
	if b.Config != scope.Config || b.Target != r.Target || b.LaunchID != r.LaunchID || b.OperationID != r.OperationID || b.RequestID != r.RequestID || b.RequestedBy != r.RequestedBy ||
		plan.Plan == nil || !sameValue(plan.Plan.Capture, b) || plan.Plan.Lease.ID != release.LeaseID || release.Release != nil && plan.Plan.Lease.ContainmentID != release.Release.Observation.Handle.ContainmentID {
		return result, fault(api.CodePrerequisite, "capture drain lacks the original retained launch and helper allocation")
	}
	var gap api.Error
	if err := storedProjection(ctx, tx, "capture_failure", b.ID, &gap); err == nil {
		return result, fault(api.CodeContainmentUnknown, "capture drain retains an unresolved producer failure")
	} else if !absent(err) {
		return result, err
	}
	err = storedProjection(ctx, tx, "capture_drain", b.ID, &result)
	if err == nil {
		if result.SnapshotSHA256 != pin || result.EffectID != release.Cause.EffectID || result.LeaseID != release.LeaseID || !sameValue(result.State, state) {
			return api.CaptureDrainReceipt{}, fault(api.CodeConflict, "capture drain replay changed its original pin or acknowledgement")
		}
		return result, nil
	}
	if !absent(err) {
		return result, err
	}
	// Compare any already acknowledged prefix against actual immutable objects,
	// including after service restart. Offset equality alone is insufficient.
	prefixes, err := captureDrainPrefixes(ctx, tx, b)
	if err != nil {
		return result, err
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))
	for i, stream := range snapshot.Streams {
		position := &state.Positions[i]
		prefix := prefixes[stream.StreamID]
		if position.StreamID != stream.StreamID || position.NextOffset != int64(len(prefix)) || position.NextOffset > stream.Bytes || !bytes.Equal(prefix, streams[i][:position.NextOffset]) || position.EOF && position.NextOffset != stream.Bytes {
			return result, fault(api.CodeIntegrity, "capture drain disagrees with an acknowledged contiguous prefix")
		}
		for position.NextOffset < stream.Bytes {
			offset := position.NextOffset
			end := min(offset+api.MaxChunkBytes, stream.Bytes)
			data := streams[i][offset:end]
			objectID := drainObjectID(b.ID, stream.StreamID, offset)
			ref, err := s.retain(ctx, tx, scope, api.ObjectWrite{ObjectKey: objectID, Class: "capture", Bytes: data, SHA256: api.Digest(hash(data)), Origin: "service",
				ACL: api.ObjectACL{Config: b.Config, Owner: api.Actor{Kind: "worker", ID: b.ProducerID}, LifeID: b.Target.LifeID, Audience: "owner", Generation: 1}}, b.OperationID, now)
			if err != nil {
				return result, err
			}
			if err := s.appendDrainedRange(ctx, tx, &state, plan, i, &ref, now); err != nil {
				return result, err
			}
		}
		if !position.EOF {
			if err := s.appendDrainedRange(ctx, tx, &state, plan, i, nil, now); err != nil {
				return result, err
			}
		}
	}
	result = api.CaptureDrainReceipt{EffectID: release.Cause.EffectID, LeaseID: release.LeaseID, SnapshotSHA256: pin, State: state}
	if err := put(ctx, tx, "capture_state", b.ID, state.Generation, state); err != nil {
		return result, err
	}
	if err := put(ctx, tx, "capture_drain", b.ID, 1, result); err != nil {
		return result, err
	}
	if err := s.spendRelease(ctx, tx, plan, now); err != nil {
		return result, err
	}
	if err := tx.Commit(); err != nil {
		return result, err
	}
	s.notifyChanged()
	return result, nil
}

// drainObjectID is the immutable object CommitCaptureDrain retains for one drained range; no other writer derives it.
func drainObjectID(binding, stream api.ID, offset int64) api.ID {
	return api.ID(hash([]byte("capture-drain-object:" + string(binding) + ":" + string(stream) + ":" + strconv.FormatInt(offset, 10))))
}

func captureDrainPrefixes(ctx context.Context, tx *sql.Tx, binding api.CaptureBinding) (map[api.ID][]byte, error) {
	rows, err := tx.QueryContext(ctx, "SELECT data FROM events WHERE json_extract(data,'$.kind')='capture.appended' AND json_extract(data,'$.payload.binding_id')=? ORDER BY seq", string(binding.ID))
	if err != nil {
		return nil, err
	}
	var records []api.CaptureRecord
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		var event api.Event
		if err := decodeStored(raw, &event); err != nil {
			rows.Close()
			return nil, err
		}
		var record api.CaptureRecord
		if err := json.Unmarshal(event.Payload, &record); err != nil {
			rows.Close()
			return nil, err
		}
		if event.Config != binding.Config || event.OperationID != binding.OperationID || event.RequestID != binding.RequestID || event.RequestedBy != binding.RequestedBy || event.LifeID != binding.Target.LifeID || event.Run != binding.Target.Run || !record.Primary || record.Target != binding.Target {
			rows.Close()
			return nil, fault(api.CodeIntegrity, "retained capture prefix changed its provenance")
		}
		records = append(records, record)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	result := map[api.ID][]byte{}
	var total int64
	for _, record := range records {
		var streamID api.ID
		for _, stream := range binding.Streams {
			name := stream.Stream
			if name == "vendor" {
				name = "structured"
			}
			if name == record.Stream {
				streamID = stream.ID
			}
		}
		meta, data, err := objectRow(ctx, tx, record.Data.ID)
		if err != nil {
			return nil, err
		}
		total += int64(len(data))
		if streamID == "" || record.Offset != int64(len(result[streamID])) || meta.Ref != record.Data || meta.Ref.Class != "capture" || meta.SourceOperationID != binding.OperationID || total > api.MaxCaptureDrainBytes {
			return nil, fault(api.CodeIntegrity, "retained capture prefix has a hole or changed bytes")
		}
		result[streamID] = append(result[streamID], data...)
	}
	return result, nil
}

func (s *Service) appendDrainedRange(ctx context.Context, tx *sql.Tx, state *api.CaptureState, plan api.LaunchPlanRecord, index int, ref *api.BlobRef, now api.Timestamp) error {
	offset := state.Positions[index].NextOffset
	if err := appendDrainedRange(ctx, tx, state, plan, index, ref, now); err != nil {
		return err
	}
	var id api.ID
	if err := tx.QueryRowContext(ctx, "SELECT id FROM events WHERE seq=?", uint64(state.LastSeq)).Scan(&id); err != nil {
		return err
	}
	return s.accountSpendRange(ctx, tx, plan, id, state.Binding.Streams[index].Stream, offset, ref)
}

func appendDrainedRange(ctx context.Context, tx *sql.Tx, state *api.CaptureState, plan api.LaunchPlanRecord, index int, ref *api.BlobRef, now api.Timestamp) error {
	if state.Generation >= 1<<53-1 {
		return fault(api.CodeIntegrity, "capture drain revision exhausted")
	}
	id, err := wire.NewID()
	if err != nil {
		return err
	}
	position := &state.Positions[index]
	offset := position.NextOffset
	state.Generation++
	if ref == nil {
		position.EOF = true
	} else {
		position.NextOffset += ref.Bytes
	}
	receipt := api.CaptureAppendReceipt{BindingID: state.Binding.ID, RecordID: id, StreamID: position.StreamID, Offset: offset, NextOffset: position.NextOffset, Generation: state.Generation, EOF: ref == nil}
	kind := api.EventKind("capture.closed")
	var payload any = receipt
	if ref != nil {
		kind = "capture.appended"
		name := state.Binding.Streams[index].Stream
		if name == "vendor" {
			name = "structured"
		}
		payload = api.CaptureRecord{ID: id, BindingID: state.Binding.ID, Target: state.Binding.Target, Stream: name, Offset: offset, Data: *ref, ObservedAt: now, Primary: true, Coverage: "partial"}
	}
	// The receipt payload must carry the actual upcoming durable sequence.
	var head api.Sequence
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(max(seq),0) FROM events").Scan(&head); err != nil {
		return err
	}
	receipt.LastSeq = head + 1
	if ref == nil {
		payload = receipt
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	b, r := state.Binding, plan.Reservation
	event := api.Event{Schema: api.SchemaVersion, ID: id, Config: b.Config, Kind: kind, Actor: api.Actor{Kind: "worker", ID: b.ProducerID}, RequestedBy: b.RequestedBy, RequestID: b.RequestID, OperationID: b.OperationID,
		LifeID: b.Target.LifeID, Run: b.Target.Run, StarterChain: append([]api.ID{}, r.StarterChain...), ParentLifeID: r.ParentLifeID, RootLifeID: r.RootLifeID, StarterEventSeq: r.StarterEventSeq, Origin: "service", Payload: raw}
	seq, err := appendPrivateEvent(ctx, tx, event, now)
	if err != nil {
		return err
	}
	state.LastSeq = seq
	key := api.ID(hash([]byte(string(b.ID) + ":" + string(position.StreamID) + ":" + strconv.FormatInt(offset, 10) + ":" + strconv.FormatBool(ref == nil))))
	return put(ctx, tx, "capture_receipt", key, 1, captureReplay{Binding: b.ID, Stream: position.StreamID, Offset: offset, Data: ref, EOF: ref == nil, Receipt: receipt})
}
