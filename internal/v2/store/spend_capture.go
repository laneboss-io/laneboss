package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strconv"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/runner/claudock"
)

type spendCursor struct {
	NextOffset int64
	Tail       []byte
	Generation api.Generation
	Results    int64
}
type spendChunkPin struct {
	Digest api.Digest
	Bytes  int64
	EOF    bool
}
type spendResult struct {
	Usage        api.VendorSpend
	Capture      api.CaptureRecord
	CredentialID api.ID
}

// Called only inside AppendCapture/CommitCaptureDrain, after their native
// producer, immutable object and contiguous range checks. JSON may span chunks.
func (s *Service) accountSpendChunk(ctx context.Context, tx *sql.Tx, plan api.LaunchPlanRecord, record api.CaptureRecord, data []byte, eof bool) error {
	if plan.Plan == nil || plan.Plan.Runner.Slot.Mode != "claude-api-key" {
		return nil
	}
	if record.Stream == "stderr" {
		return nil
	}
	if plan.Plan.Runner.Driver != api.DriverClaudock || record.Stream != "stdout" && record.Stream != "vendor" && record.Stream != "structured" ||
		!record.Primary || record.ReplacementOf != "" || record.BindingID != plan.Plan.Capture.ID || record.Target != plan.Reservation.Target || record.Offset < 0 ||
		!eof && (record.Data.Class != "capture" || record.Data.Bytes != int64(len(data)) || record.Data.SHA256 != api.Digest(hash(data))) {
		return fault(api.CodeIntegrity, "spend capture differs from its sealed primary vendor stream")
	}
	b, err := spendForSlot(ctx, tx, plan.Plan.Runner.Slot)
	if err != nil {
		return err
	}
	stream := record.Stream
	if stream == "vendor" {
		stream = "structured"
	}
	key := api.ID(hash([]byte("spend-stream:" + string(record.BindingID) + ":" + stream)))
	chunkKey := api.ID(hash([]byte(string(key) + ":" + strconv.FormatInt(record.Offset, 10) + ":" + strconv.FormatBool(eof))))
	pin := spendChunkPin{Digest: api.Digest(hash(data)), Bytes: int64(len(data)), EOF: eof}
	var previous spendChunkPin
	if err := storedProjection(ctx, tx, "spend_chunk", chunkKey, &previous); err == nil {
		if previous != pin {
			return fault(api.CodeIntegrity, "spend range replay changed its exact bytes")
		}
		return nil
	} else if !absent(err) {
		return err
	}
	var cursor spendCursor
	if err := storedProjection(ctx, tx, "spend_cursor", key, &cursor); err != nil && !absent(err) {
		return err
	}
	if cursor.NextOffset != record.Offset || cursor.Generation >= 1<<53-1 || int64(len(data)) > 1<<53-1-cursor.NextOffset {
		return fault(api.CodeIntegrity, "spend stream lost its contiguous durable cursor")
	}
	buffer := append(bytes.Clone(cursor.Tail), data...)
	cursor.NextOffset += int64(len(data))
	cursor.Generation++
	var accountingErr error
	for {
		end := bytes.IndexByte(buffer, '\n')
		if end < 0 && !eof {
			break
		}
		if end < 0 {
			end = len(buffer)
		}
		line := bytes.TrimSpace(buffer[:end])
		if end < len(buffer) {
			buffer = buffer[end+1:]
		} else {
			buffer = nil
		}
		if len(line) > 0 {
			usage, err := claudock.ParseSpendLine(line, plan.Plan.Runner.Session.VendorID)
			if err != nil {
				accountingErr = err
				break
			}
			if usage != nil {
				cursor.Results++
				id := api.ID(hash([]byte(string(b.CredentialID) + ":" + usage.SessionID + ":" + usage.ResultID)))
				var prior spendResult
				if err := storedProjection(ctx, tx, "spend_result", id, &prior); err == nil {
					if prior.Usage != *usage || prior.CredentialID != b.CredentialID {
						accountingErr = fault(api.CodeIntegrity, "vendor result replay changed its cost or usage")
						break
					}
				} else if absent(err) {
					if usage.CostMicros > 1<<53-1-b.SpentMicros {
						accountingErr = fault(api.CodeBudget, "credential spend counter exhausted")
						break
					}
					b.SpentMicros += usage.CostMicros
					b.RemainingMicros = spendEstimate(b)
					if err := put(ctx, tx, "spend_result", id, 1, spendResult{*usage, record, b.CredentialID}); err != nil {
						return err
					}
					now := api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))
					lane := api.Lane{LifeID: plan.Reservation.Target.LifeID, Run: plan.Reservation.Target.Run, ParentLifeID: plan.Reservation.ParentLifeID, RootLifeID: plan.Reservation.RootLifeID, StarterChain: plan.Reservation.StarterChain, StarterEventSeq: plan.Reservation.StarterEventSeq}
					if _, err := s.appendSpendEvent(ctx, tx, lane, "spend.recorded", api.SpendRecorded{Usage: *usage, CaptureID: record.ID, RemainingMicros: b.RemainingMicros}, plan.Reservation.OperationID, plan.Reservation.RequestID, now); err != nil {
						return err
					}
				} else {
					return err
				}
			}
		}
		if len(buffer) == 0 {
			break
		}
	}
	if len(buffer) > 1<<20 {
		accountingErr = fault(api.CodeIntegrity, "vendor spend record exceeds its bounded capture line")
	}
	if eof && cursor.Results == 0 {
		accountingErr = fault(api.CodeIntegrity, "API run ended without a vendor cost result")
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))
	if accountingErr != nil {
		// The raw capture is still acknowledged and retained. Unknown cost is
		// a durable closed gate and a stop, never a zero-cost accounting success.
		b.NeedsReading, b.AwaitingSince = true, now
		b.AccountingError = &api.Error{Code: api.CodeIntegrity, Owner: "lb-v2-spend", Message: "captured vendor cost is incomplete; operator reconciliation required"}
		if _, err := s.appendSpendEvent(ctx, tx, api.Lane{}, "spend.unknown", spendJournal(b, "spend.unknown"), plan.Reservation.OperationID, plan.Reservation.RequestID, now); err != nil {
			return err
		}
		buffer = nil
	}
	cursor.Tail = bytes.Clone(buffer)
	if b.Generation >= 1<<53-1 {
		return fault(api.CodeIntegrity, "credential spend generation exhausted")
	}
	b.Generation++
	if err := put(ctx, tx, "spend_pool", b.CredentialID, b.Generation, b); err != nil {
		return err
	}
	if err := put(ctx, tx, "spend_cursor", key, cursor.Generation, cursor); err != nil {
		return err
	}
	if err := put(ctx, tx, "spend_chunk", chunkKey, 1, pin); err != nil {
		return err
	}
	if accountingErr != nil || b.RemainingMicros <= b.FloorMicros {
		return s.stopSpendPool(ctx, tx, b, now)
	}
	return nil
}

func (s *Service) accountSpendRange(ctx context.Context, tx *sql.Tx, plan api.LaunchPlanRecord, id api.ID, stream string, offset int64, ref *api.BlobRef) error {
	if plan.Plan == nil || plan.Plan.Runner.Slot.Mode != "claude-api-key" {
		return nil
	}
	r := api.CaptureRecord{ID: id, BindingID: plan.Plan.Capture.ID, Target: plan.Reservation.Target, Stream: stream, Offset: offset, Primary: true, Coverage: "partial"}
	var data []byte
	if ref != nil {
		meta, raw, err := objectRow(ctx, tx, ref.ID)
		if err != nil {
			return err
		}
		if meta.Ref != *ref || meta.Origin != "service" || meta.SourceOperationID != plan.Reservation.OperationID || meta.ACL.LifeID != plan.Reservation.Target.LifeID || meta.Ref.SHA256 != api.Digest(hash(raw)) {
			return fault(api.CodeIntegrity, "spend bytes lost their original capture provenance")
		}
		r.Data = *ref
		data = raw
	}
	return s.accountSpendChunk(ctx, tx, plan, r, data, ref == nil)
}

func (s *Service) spendRelease(ctx context.Context, tx *sql.Tx, plan api.LaunchPlanRecord, now api.Timestamp) error {
	if plan.Plan == nil || plan.Plan.Runner.Slot.Mode != "claude-api-key" {
		return nil
	}
	b, err := spendForSlot(ctx, tx, plan.Plan.Runner.Slot)
	if err != nil {
		return err
	}
	if b.Generation >= 1<<53-1 {
		return fault(api.CodeIntegrity, "credential spend generation exhausted")
	}
	b.NeedsReading, b.AwaitingSince = true, now
	b.Generation++
	return put(ctx, tx, "spend_pool", b.CredentialID, b.Generation, b)
}

// queue the ordinary durable stop effect for every current lane sharing this
// credential. The outbox measures shutdown, revokes endpoints and drains capture.
func (s *Service) stopSpendPool(ctx context.Context, tx *sql.Tx, b api.SpendBalance, now api.Timestamp) error {
	lanes, err := projectionValues[api.Lane](ctx, tx, "lane")
	if err != nil {
		return err
	}
	plans, err := projectionValues[api.LaunchPlanRecord](ctx, tx, "launch_plan")
	if err != nil {
		return err
	}
	for _, lane := range lanes {
		if lane.Cleaned || lane.State != "running" && lane.State != "preparing" && lane.State != "profile_wait" && lane.State != "lost" {
			continue
		}
		matched := false
		for _, plan := range plans {
			if plan.Reservation.LaunchID != lane.LaunchID || plan.Plan == nil || plan.Plan.Runner.Slot.Mode != "claude-api-key" {
				continue
			}
			pool, err := spendForSlot(ctx, tx, plan.Plan.Runner.Slot)
			if err != nil {
				return err
			}
			matched = pool.CredentialID == b.CredentialID
		}
		if !matched {
			continue
		}
		if lane.Generation >= 1<<53-1 || lane.CancellationEpoch >= 1<<53-1 {
			return fault(api.CodeIntegrity, "spend stop lane generation exhausted")
		}
		var launch api.LaunchRecord
		if err := storedProjection(ctx, tx, "launch", lane.LaunchID, &launch); err != nil {
			return err
		}
		if launch.Config != s.deps.Config || launch.Target != (api.LifeRef{LifeID: lane.LifeID, Run: lane.Run}) || launch.Revoked || launch.ProcessGeneration == "" || launch.ContainmentID == "" {
			return fault(api.CodeContainmentUnknown, "spend stop lacks its retained process identity")
		}
		var observed struct {
			Observation api.ProcessObservation
			Generation  api.Generation
		}
		if err := storedProjection(ctx, tx, "launch_observation", lane.LaunchID, &observed); err != nil {
			if absent(err) && lane.State == "preparing" {
				// A very short turn can finish before Launch returns its native
				// handle. Retain its spend now; the first measured observation
				// must publish the stop before the original launch can advance.
				if err := putGenerated(ctx, tx, "spend_stop_pending", lane.LaunchID, 1, spendProfile{b.CredentialID}); err != nil {
					return err
				}
				continue
			}
			return err
		}
		handle := observed.Observation.Handle
		if handle.ID == "" || handle.Target != launch.Target || handle.ContainmentID != launch.ContainmentID || handle.Generation != launch.ProcessGeneration {
			return fault(api.CodeContainmentUnknown, "spend stop differs from its measured native process handle")
		}
		operation := api.ID(hash([]byte("spend-stop:" + string(lane.LaunchID))))
		next := lane
		next.State = "stopping"
		next.Generation++
		next.CancellationEpoch++
		first, err := s.appendSpendEvent(ctx, tx, lane, "spend.stopped", spendJournal(b, "spend.stopped"), operation, operation, now)
		if err != nil {
			return err
		}
		last, err := s.appendSpendEvent(ctx, tx, lane, "lane.stopping", api.StateEvent{From: lane.State, To: next.State, Generation: next.Generation}, operation, operation, now)
		if err != nil {
			return err
		}
		next.LastSeq = last
		if err := put(ctx, tx, "lane", lane.LifeID, next.Generation, next); err != nil {
			return err
		}
		cause := api.InternalIntent{ID: operation, Kind: api.InternalLifecycleEffect, Config: s.deps.Config, Actor: api.Actor{Kind: "service", ID: "lifecycle"}, RequestedBy: api.Actor{Kind: "service", ID: "spend"}, CauseOperationID: operation, CauseRequestID: operation,
			EffectID: api.ID(hash([]byte("spend-stop-effect:" + string(lane.LaunchID)))), Target: launch.Target, LogicalTurnID: lane.LogicalTurnID, CancellationEpoch: next.CancellationEpoch}
		effect := api.Effect{ID: cause.EffectID, OperationID: operation, Context: &cause, Stop: &handle}
		if err := validateEffect(effect); err != nil {
			return err
		}
		raw, err := json.Marshal(effect)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO effects(id,operation_id,data) VALUES(?,?,?)", string(effect.ID), string(operation), raw); err != nil {
			return err
		}
		state, err := encodeEffectState(api.EffectRecord{Effect: effect, Generation: 1, State: api.EffectPending, LastSeq: last})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO effect_states VALUES(?,?)", string(effect.ID), state); err != nil {
			return err
		}
		if err := s.retainSpendOperation(ctx, tx, api.Operation{ID: operation, Status: "pending", LifeID: lane.LifeID, Run: lane.Run, FirstSeq: first, LastSeq: last}, effect); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) stopObservedSpend(ctx context.Context, tx *sql.Tx, launchID api.ID) error {
	var pending spendProfile
	if err := storedProjection(ctx, tx, "spend_stop_pending", launchID, &pending); err != nil {
		if absent(err) {
			return nil
		}
		return err
	}
	b, err := readSpendPool(ctx, tx, pending.CredentialID)
	if err != nil {
		return err
	}
	if b.RemainingMicros > b.FloorMicros && b.AccountingError == nil {
		return nil
	}
	return s.stopSpendPool(ctx, tx, b, api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat)))
}
