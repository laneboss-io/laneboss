package store

import (
	"context"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func (s *Service) validateTurnEvents(ctx context.Context, db queryer, input api.Transaction) error {
	for _, event := range input.Events {
		if event.Kind != "lane.turn" {
			continue
		}
		if !wire.ValidID(string(event.LogicalTurnID)) {
			return fault(api.CodeInvalid, "turn event requires its logical turn identity")
		}
		var turn api.TurnSnapshot
		matches := 0
		for _, candidate := range input.Writes.Turns {
			if candidate.LogicalTurnID == event.LogicalTurnID {
				turn, matches = candidate, matches+1
			}
		}
		if matches > 1 {
			return fault(api.CodeConflict, "turn event has ambiguous snapshot writes")
		}
		if matches == 0 {
			if err := storedProjection(ctx, db, "turn", event.LogicalTurnID, &turn); err != nil {
				return err
			}
		}
		target := api.LifeRef{LifeID: event.LifeID, Run: event.Run}
		if turn.Generation == 0 || turn.LogicalTurnID != event.LogicalTurnID || turn.Target != target {
			return fault(api.CodeForbidden, "turn event differs from its real turn snapshot")
		}
	}
	return nil
}
