package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Verify reconstructs capture positions from immutable events. Projection
// history alone cannot establish that offsets, EOF or primary provenance were
// derived from the registered streams and retained immutable bytes.
func (s *Service) verifyLaunchState(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM projections WHERE kind='launch_plan' ORDER BY id")
	if err != nil {
		return err
	}
	var plans []api.LaunchPlanRecord
	for rows.Next() {
		var data []byte
		var plan api.LaunchPlanRecord
		if err := rows.Scan(&data); err != nil {
			rows.Close()
			return err
		}
		if err := decodeStored(data, &plan); err != nil {
			rows.Close()
			return err
		}
		plans = append(plans, plan)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, plan := range plans {
		if err := s.checkLaunchBytes(ctx, s.db, plan); err != nil {
			return err
		}
		var owner launchOwner
		if err := storedProjection(ctx, s.db, "launch_operation", plan.Reservation.OperationID, &owner); err != nil {
			return err
		}
		r := plan.Reservation
		owns := owner.Request.OperationID == r.OperationID
		if r.Loop != nil {
			owns = owner.Request.OperationID == "" && owner.Request.ContinuationID == "" && len(owner.Request.Guards) == 0 &&
				owner.Request.Loop != nil && *owner.Request.Loop == r.Loop.Selector
		}
		if owner.ReservationID != r.ID || owner.Actor != r.RequestedBy || !owns {
			return fault(api.CodeIntegrity, "launch reservation lost its owner handoff")
		}
		var authority launchAuthority
		if err := storedProjection(ctx, s.db, "launch_authority", plan.Reservation.ID, &authority); err != nil {
			return err
		}
		if authority.Ceiling.ID == "" {
			return fault(api.CodeIntegrity, "launch reservation lost its original authority")
		}
		if plan.Phase == "bound" || plan.Phase == "opened" {
			if _, err := s.launchBinding(ctx, s.db, plan.Reservation.LaunchID); err != nil {
				return err
			}
		}
	}
	rows, err = s.db.QueryContext(ctx, "SELECT data FROM events WHERE json_extract(data,'$.kind') IN ('capture.bound','capture.refused','capture.appended','capture.closed') ORDER BY seq")
	if err != nil {
		return err
	}
	states := map[api.ID]api.CaptureState{}
	for rows.Next() {
		var data []byte
		var event api.Event
		if err := rows.Scan(&data); err != nil {
			rows.Close()
			return err
		}
		if err := wire.Decode(data, &event); err != nil {
			rows.Close()
			return err
		}
		switch event.Kind {
		case "capture.bound", "capture.refused":
			var binding api.CaptureBinding
			if err := wire.Decode(event.Payload, &binding); err != nil {
				rows.Close()
				return err
			}
			if err := api.ValidateCaptureBinding(binding); err != nil {
				rows.Close()
				return err
			}
			if _, exists := states[binding.ID]; exists {
				rows.Close()
				return fault(api.CodeIntegrity, "capture registration was replaced")
			}
			state := api.CaptureState{Binding: binding, Generation: 1, LastSeq: event.Seq, Positions: []api.CapturePosition{}}
			for _, stream := range binding.Streams {
				state.Positions = append(state.Positions, api.CapturePosition{StreamID: stream.ID})
			}
			states[binding.ID] = state
		case "capture.appended":
			var record api.CaptureRecord
			if err := wire.Decode(event.Payload, &record); err != nil {
				rows.Close()
				return err
			}
			state, exists := states[record.BindingID]
			if !exists || !record.Primary || record.ID != event.ID || record.Target != state.Binding.Target || event.Actor.ID != state.Binding.ProducerID || event.Actor.Kind != "worker" ||
				event.OperationID != state.Binding.OperationID || event.RequestID != state.Binding.RequestID || event.RequestedBy != state.Binding.RequestedBy || record.Coverage != "partial" {
				rows.Close()
				return fault(api.CodeIntegrity, "primary capture event lost its registered provenance")
			}
			stream := api.ID("")
			for _, bound := range state.Binding.Streams {
				name := bound.Stream
				if name == "vendor" {
					name = "structured"
				}
				if name == record.Stream {
					stream = bound.ID
				}
			}
			position := -1
			for i := range state.Positions {
				if state.Positions[i].StreamID == stream {
					position = i
				}
			}
			if position < 0 || state.Positions[position].EOF || state.Positions[position].NextOffset != record.Offset {
				rows.Close()
				return fault(api.CodeIntegrity, "capture journal is not contiguous")
			}
			state.Positions[position].NextOffset += record.Data.Bytes
			state.Generation++
			state.LastSeq = event.Seq
			states[record.BindingID] = state
		case "capture.closed":
			var receipt api.CaptureAppendReceipt
			if err := wire.Decode(event.Payload, &receipt); err != nil {
				rows.Close()
				return err
			}
			state, exists := states[receipt.BindingID]
			position := -1
			for i := range state.Positions {
				if state.Positions[i].StreamID == receipt.StreamID {
					position = i
				}
			}
			if !exists || position < 0 || state.Positions[position].EOF || state.Positions[position].NextOffset != receipt.Offset || !receipt.EOF || receipt.NextOffset != receipt.Offset ||
				receipt.Generation != state.Generation+1 || receipt.LastSeq != event.Seq || receipt.RecordID != event.ID {
				rows.Close()
				return fault(api.CodeIntegrity, "capture EOF lost its exact acknowledgement")
			}
			state.Positions[position].EOF = true
			state.Generation++
			state.LastSeq = event.Seq
			states[receipt.BindingID] = state
		}
	}
	readErr, closeErr = rows.Err(), rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for id, expected := range states {
		var actual api.CaptureState
		if err := storedProjection(ctx, s.db, "capture_state", id, &actual); err != nil {
			return err
		}
		if !sameValue(actual, expected) {
			return fault(api.CodeIntegrity, "capture projection differs from committed ranges and EOF")
		}
	}
	rows, err = s.db.QueryContext(ctx, "SELECT data FROM projections WHERE kind='capture_receipt'")
	if err != nil {
		return err
	}
	var receipts []captureReplay
	for rows.Next() {
		var data []byte
		var receipt captureReplay
		if err := rows.Scan(&data); err != nil {
			rows.Close()
			return err
		}
		if err := decodeStored(data, &receipt); err != nil {
			rows.Close()
			return err
		}
		receipts = append(receipts, receipt)
	}
	readErr, closeErr = rows.Err(), rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, saved := range receipts {
		state, exists := states[saved.Binding]
		if !exists {
			return fault(api.CodeIntegrity, "capture acknowledgement lost its binding")
		}
		if saved.Data != nil {
			metadata, _, err := objectRow(ctx, s.db, saved.Data.ID)
			if err != nil {
				return err
			}
			if metadata.Ref != *saved.Data || metadata.Ref.Class != "capture" || metadata.SourceOperationID != state.Binding.OperationID || metadata.ACL.Owner.ID != state.Binding.ProducerID {
				return fault(api.CodeIntegrity, "capture acknowledgement lost its exact committed bytes")
			}
		}
		var data []byte
		if err := s.db.QueryRowContext(ctx, "SELECT data FROM events WHERE seq=?", uint64(saved.Receipt.LastSeq)).Scan(&data); err != nil {
			return err
		}
		var event api.Event
		if err := wire.Decode(data, &event); err != nil {
			return err
		}
		if event.ID != saved.Receipt.RecordID || event.OperationID != state.Binding.OperationID {
			return fault(api.CodeIntegrity, "capture acknowledgement lost its committed event")
		}
	}
	var inventory int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM projections WHERE kind='capture_state'").Scan(&inventory); err != nil {
		return err
	}
	if inventory != len(states) {
		return fault(api.CodeIntegrity, "capture state has no original registration event")
	}
	return s.verifyDataStages(ctx)
}
