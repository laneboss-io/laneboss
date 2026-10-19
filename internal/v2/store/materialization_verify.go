package store

import (
	"bytes"
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) checkMaterializedPlan(ctx context.Context, db queryer, plan api.LaunchPlanRecord, next api.LaunchPlan) error {
	var saved dataStageRecord
	if err := storedProjection(ctx, db, "data_stage", plan.DataStageID, &saved); err != nil {
		return err
	}
	if err := s.checkDataRecord(ctx, db, plan, saved); err != nil {
		return err
	}
	var measured api.LaunchDataResult
	if err := storedProjection(ctx, db, "data_measurement", saved.Stage.ID, &measured); err != nil {
		return err
	}
	worker, err := effectRow(ctx, db, saved.Stage.Worker.EffectID)
	if err != nil {
		return err
	}
	if worker.Outcome == nil || !sameValue(measured.Data, next.Data) || saved.Stage.AgentLeaseID != next.Lease.ID || !sameValue(saved.Stage.Reservation, next.Reservation) || !sameValue(saved.Stage.Inputs, next.Inputs) {
		return fault(api.CodeConflict, "launch plan differs from its completed materialization stage")
	}
	return s.checkDataOutcome(ctx, db, saved, measured, *worker.Outcome)
}

// Startup verifies original frozen records and acknowledgement events. Current
// grant revocation/expiry is an authorization check, not corruption of history.
func (s *Service) verifyDataStages(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT data FROM projections WHERE kind='data_stage' ORDER BY id")
	if err != nil {
		return err
	}
	var stages []dataStageRecord
	for rows.Next() {
		var raw []byte
		var saved dataStageRecord
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		if err := decodeStored(raw, &saved); err != nil {
			rows.Close()
			return err
		}
		stages = append(stages, saved)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, saved := range stages {
		stage := saved.Stage
		var plan api.LaunchPlanRecord
		if err := storedProjection(ctx, s.db, "launch_plan", stage.Reservation.ID, &plan); err != nil {
			return err
		}
		if plan.DataStageID != stage.ID || !sameValue(plan.Reservation, stage.Reservation) || plan.Inputs == nil || !sameValue(*plan.Inputs, stage.Inputs) || saved.Parent.Record.Effect.PlanLaunch == nil || saved.Parent.Record.Effect.PlanLaunch.ReservationID != stage.Reservation.ID || saved.Parent.Record.Effect.ID != stage.ParentEffectID {
			return fault(api.CodeIntegrity, "retained materialization lost its original plan and parent")
		}
		switch saved.Phase {
		case "reserved":
			continue
		case "sealed", "claimed", "opened":
		default:
			return fault(api.CodeIntegrity, "retained materialization has an unknown phase")
		}
		meta, raw, err := objectRow(ctx, s.db, stage.Worker.Input.ID)
		if err != nil {
			return err
		}
		if meta.Ref != stage.Worker.Input || stage.Plan.Input != meta.Ref || meta.SourceOperationID != stage.Reservation.OperationID {
			return fault(api.CodeIntegrity, "retained materialization lost its exact input bytes")
		}
		var input dataJobInput
		if err := api.DecodeObject(raw, &input); err != nil {
			return err
		}
		if !sameDataBytes(raw, input) || input.StageID != stage.ID || input.Storage != stage.Storage || !sameValue(input.Reservation, stage.Reservation) || !sameValue(input.Grants, stage.Grants) || input.Source != stage.Inputs.Sources.Project || input.Output != saved.Output || input.Budget != stage.Plan.Budget {
			return fault(api.CodeIntegrity, "retained materialization input differs from its frozen stage")
		}
		worker, err := effectRow(ctx, s.db, stage.Worker.EffectID)
		if err != nil {
			return err
		}
		if worker.Effect.Worker == nil || !sameValue(*worker.Effect.Worker, stage.Plan) || worker.Effect.OperationID != stage.Reservation.OperationID {
			return fault(api.CodeIntegrity, "retained materialization child effect changed")
		}
		var ack dataAcknowledgement
		err = storedProjection(ctx, s.db, "data_ack", stage.Worker.ID, &ack)
		if err != nil && !absent(err) {
			return err
		}
		if err == nil {
			meta, raw, err := objectRow(ctx, s.db, ack.Receipt.Result.ID)
			if err != nil {
				return err
			}
			if meta.Ref != ack.Receipt.Result || !bytes.Equal(raw, ack.Submission.Result) || ack.Receipt.StageID != stage.ID || ack.Receipt.LeaseID != stage.Worker.ID || ack.Receipt.Generation != stage.Worker.Generation+1 {
				return fault(api.CodeIntegrity, "retained worker acknowledgement changed its bytes or job")
			}
			if _, err := s.validateDataOutput(ctx, s.db, saved, raw); err != nil {
				return err
			}
			var eventRaw []byte
			if err := s.db.QueryRowContext(ctx, "SELECT data FROM events WHERE seq=?", uint64(ack.Receipt.CommittedSeq)).Scan(&eventRaw); err != nil {
				return err
			}
			var event api.Event
			var ref api.BlobRef
			if json.Unmarshal(eventRaw, &event) != nil || api.DecodeObject(event.Payload, &ref) != nil || event.Kind != "blob.committed" || event.Actor != saved.Actor || ref != ack.Receipt.Result || event.OperationID != stage.Reservation.OperationID {
				return fault(api.CodeIntegrity, "retained worker acknowledgement lost its actual commit event")
			}
		}
		if worker.Outcome != nil && worker.Outcome.Status == "succeeded" {
			if err := s.validateMaterializationOutcome(ctx, s.db, worker, *worker.Outcome); err != nil {
				return err
			}
		}
	}
	return nil
}
