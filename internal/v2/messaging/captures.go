package messaging

import (
	"context"
	"reflect"

	"laneboss.io/laneboss/internal/v2/api"
)

func (s *Service) receiptCaptures(ctx context.Context, scope api.Scope, request api.DeliveryReceiptRequest) error {
	turn, err := s.deps.Store.Turn(ctx, scope, request.Receipt.Target, request.Intent.LogicalTurnID)
	if err != nil {
		return err
	}
	if turn.Target != request.Receipt.Target || request.Intent.Target != request.Receipt.Target || turn.LogicalTurnID != request.Receipt.LogicalTurnID || turn.Prompt == nil || turn.Generation == 0 {
		return problem(api.CodeConflict, "receipt has no retained logical-turn prompt")
	}
	if err := s.objectMetadata(ctx, scope, *turn.Prompt); err != nil {
		return err
	}
	wanted := make(map[api.ID]bool)
	for _, id := range request.CaptureIDs {
		if !validID(id) || wanted[id] {
			return problem(api.CodeInvalid, "receipt has invalid or duplicate capture IDs")
		}
		wanted[id] = true
	}
	if request.Receipt.Status == "delivered" && len(wanted) == 0 {
		return problem(api.CodeConflict, "completed delivery needs its actual primary capture")
	}
	query := api.EventTailRequest{LifeID: request.Receipt.Target.LifeID, Run: request.Receipt.Target.Run}
	seen := make(map[string]bool)
	found := make(map[api.ID]bool)
	eventIDs := make(map[api.ID]bool)
	var previousSeq api.Sequence
	promptObserved := false
	for {
		if err := ctx.Err(); err != nil {
			return cancelled(err)
		}
		page, err := s.deps.Store.Events(ctx, scope, query)
		if err != nil {
			return err
		}
		for _, event := range page.Events {
			if event.Origin != "service" || event.Config != scope.Config || event.LifeID != request.Receipt.Target.LifeID || event.Run != request.Receipt.Target.Run || event.LogicalTurnID != request.Receipt.LogicalTurnID {
				continue
			}
			if event.Schema != api.SchemaVersion || !validID(event.ID) || event.Seq == 0 || event.Seq > maxExact || eventIDs[event.ID] || event.Seq <= previousSeq {
				return problem(api.CodeIntegrity, "capture observations have invalid or unordered event envelopes")
			}
			eventIDs[event.ID], previousSeq = true, event.Seq
			switch event.Kind {
			case "capture.appended":
				var capture api.CaptureRecord
				if err := decodeBody(event.Payload, &capture); err != nil {
					return problem(api.CodeIntegrity, "receipt capture has an invalid retained payload")
				}
				if !wanted[capture.ID] {
					continue
				}
				if found[capture.ID] || capture.Target != request.Receipt.Target || !capture.Primary || capture.Coverage != "complete" || capture.Offset < 0 || !validTimestamp(capture.ObservedAt) {
					return problem(api.CodeConflict, "receipt capture is duplicated, incomplete or from another run")
				}
				if err := s.objectMetadata(ctx, scope, capture.Data); err != nil {
					return err
				}
				found[capture.ID] = true
			case "prompt.observed":
				var observed api.TurnEvent
				if err := decodeBody(event.Payload, &observed); err != nil {
					return problem(api.CodeIntegrity, "prompt observation has an invalid retained payload")
				}
				if observed.Task == turn.Task && observed.Prompt == *turn.Prompt && observed.Status == request.Receipt.PromptStatus && reflect.DeepEqual(observed.MailIDs, turn.MailIDs) {
					promptObserved = true
				}
			}
		}
		if page.Complete {
			break
		}
		if page.Cursor == "" || len(page.Cursor) > maxCursor || seen[page.Cursor] {
			return problem(api.CodeIntegrity, "receipt capture pagination is incomplete or cyclic")
		}
		seen[page.Cursor], query.Cursor = true, page.Cursor
	}
	if len(found) != len(wanted) || !promptObserved {
		return problem(api.CodeConflict, "receipt lacks its correlated capture or prompt observation")
	}
	return nil
}
