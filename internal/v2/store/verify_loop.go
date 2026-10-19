package store

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) verifyLoopReceipts(ctx context.Context, operations map[api.ID][]byte, references map[api.ID]bool) error {
	rows, err := s.db.QueryContext(ctx, "SELECT id FROM projections WHERE kind='loop_receipt'")
	if err != nil {
		return err
	}
	var ids []api.ID
	for rows.Next() {
		var id api.ID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, id := range ids {
		var plan api.LaunchPlanRecord
		if err := storedProjection(ctx, s.db, "launch_plan", id, &plan); err != nil {
			return err
		}
		if plan.Reservation.ID != id || plan.Reservation.Loop == nil {
			return fault(api.CodeIntegrity, "private loop receipt has no matching reservation")
		}
		receipt, err := s.reservationReceipt(ctx, s.db, plan)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(receipt.Operation)
		if err != nil {
			return err
		}
		var owner string
		if err := s.db.QueryRowContext(ctx, "SELECT principal FROM operations WHERE id=?", string(receipt.Operation.ID)).Scan(&owner); err != nil {
			return err
		}
		var public int
		if err := s.db.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM receipts WHERE json_extract(operation,'$.id')=?) + (SELECT count(*) FROM reservations WHERE operation_id=?)", string(receipt.Operation.ID), string(receipt.Operation.ID)).Scan(&public); err != nil {
			return err
		}
		if public != 0 || operations[receipt.Operation.ID] == nil ||
			!validOperationEvolution(operations[receipt.Operation.ID], raw) || owner != principal(api.Scope{Actor: receipt.Actor}) {
			return fault(api.CodeIntegrity, "private loop operation lost its unique receipt")
		}
		references[receipt.Operation.ID] = true
	}
	return nil
}
