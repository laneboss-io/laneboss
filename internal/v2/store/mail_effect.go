package store

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func queuedMailEffect(effect api.Effect) bool {
	mail, cause := effect.Deliver, effect.Context
	return mail != nil && cause != nil && cause.Kind == api.InternalMailDeliver && cause.Target.Run == 0 &&
		cause.Target.LifeID == mail.RecipientLifeID && cause.LogicalTurnID == "" && cause.CancellationEpoch == 0 &&
		mail.RecipientLifeID != "" && mail.ChannelGrantID == "" && mail.Generation == 1 && mail.Status == "queued" && mail.LogicalTurnID == "" && mail.QueuedSeq == 0
}

func (s *Service) validateMailTransaction(ctx context.Context, db queryer, input api.Transaction) error {
	if input.Internal == nil || input.Internal.Kind != api.InternalMailDeliver {
		return nil
	}
	record, err := effectRow(ctx, db, input.Internal.EffectID)
	if err != nil {
		return err
	}
	if !queuedMailEffect(record.Effect) {
		return nil
	}
	claim, ok := api.EffectLeaseFromContext(ctx)
	if !ok || !sameValue(claim.Record, record) || claim.ClaimID != record.ClaimID || claim.ExpiresAt != record.ClaimExpiresAt ||
		record.State != api.EffectClaimed || record.Outcome != nil || record.ClaimantID != input.Scope.Actor.ID || !future(record.ClaimExpiresAt, s.deps.Clock.Now()) {
		return fault(api.CodeConflict, "mail receipt lost its current durable queue effect claim")
	}
	if len(input.Events) != 1 || len(input.Writes.Mail) != 1 || len(input.Effects) != 0 {
		return fault(api.CodeForbidden, "queued delivery completion requires one exact mail receipt")
	}
	cause, intent, next := record.Effect.Context, input.Internal, input.Writes.Mail[0]
	if intent.Config != cause.Config || intent.Actor != input.Scope.Actor || intent.RequestedBy != cause.RequestedBy || intent.CauseOperationID != record.Effect.OperationID || intent.CauseRequestID != cause.CauseRequestID || intent.Target.LifeID != cause.Target.LifeID {
		return fault(api.CodeForbidden, "queued receipt changed its authenticated enqueue cause")
	}
	var previous api.Mail
	if err := storedProjection(ctx, db, "mail", record.Effect.Deliver.ID, &previous); err != nil {
		return err
	}
	if previous.Status != "delivering" || previous.LogicalTurnID != intent.LogicalTurnID || next.Status != "delivered" && next.Status != "returned" || next.Generation != previous.Generation+1 {
		return fault(api.CodeConflict, "queued receipt changed its selected mail generation or turn")
	}
	expected := previous
	expected.Generation, expected.Status = next.Generation, next.Status
	if !sameValue(next, expected) {
		return fault(api.CodeForbidden, "delivery receipt rewrote immutable mail content or provenance")
	}
	var lane api.Lane
	if err := storedProjection(ctx, db, "lane", intent.Target.LifeID, &lane); err != nil {
		return err
	}
	if lane.Run != intent.Target.Run || lane.LogicalTurnID != intent.LogicalTurnID || lane.CancellationEpoch != intent.CancellationEpoch {
		return fault(api.CodeConflict, "delivery receipt targets a stale run or cancellation epoch")
	}
	var receipt api.MailReceipt
	event := input.Events[0]
	if err := wire.Decode(event.Payload, &receipt); err != nil {
		return err
	}
	if event.Kind != api.EventKind("mail."+next.Status) || receipt.MailID != next.ID || receipt.Target != intent.Target || receipt.LogicalTurnID != intent.LogicalTurnID || receipt.Status != next.Status {
		return fault(api.CodeForbidden, "queued receipt event differs from its actual mail transition")
	}
	return nil
}

func (s *Service) validateMailOutcome(ctx context.Context, db queryer, record api.EffectRecord, outcome api.EffectOutcome) error {
	if record.Effect.Deliver == nil || outcome.Status != "succeeded" {
		return nil
	}
	var mail api.Mail
	if err := storedProjection(ctx, db, "mail", record.Effect.Deliver.ID, &mail); err != nil {
		return err
	}
	original := record.Effect.Deliver
	if outcome.Output == nil || *outcome.Output != mail.Content || outcome.Observation == nil || mail.Sender != original.Sender || mail.RecipientLifeID != original.RecipientLifeID || mail.Content != original.Content || mail.Status != "delivered" && mail.Status != "returned" || mail.LogicalTurnID == "" {
		return fault(api.CodeIntegrity, "mail effect has no actual retained logical-delivery result")
	}
	var raw []byte
	if err := db.QueryRowContext(ctx, `SELECT data FROM events WHERE json_extract(data,'$.operation_id')=? AND json_extract(data,'$.kind')=? AND json_extract(data,'$.payload.mail_id')=? ORDER BY seq DESC LIMIT 1`, string(record.Effect.OperationID), "mail."+mail.Status, string(mail.ID)).Scan(&raw); err != nil {
		return fault(api.CodePrerequisite, "mail effect awaits its authenticated logical-turn receipt")
	}
	var event api.Event
	var receipt api.MailReceipt
	if err := decodeStored(raw, &event); err != nil {
		return err
	}
	if err := json.Unmarshal(event.Payload, &receipt); err != nil {
		return err
	}
	if event.Origin != "service" || event.Actor.Kind != "service" || event.RequestedBy != record.Effect.Context.RequestedBy || receipt.LogicalTurnID != mail.LogicalTurnID || receipt.Target != outcome.Observation.Handle.Target || receipt.ObservedAt != outcome.Observation.ObservedAt || receipt.PromptStatus != outcome.Observation.PromptStatus || receipt.Status != mail.Status {
		return fault(api.CodeIntegrity, "mail effect completion differs from its authentic receipt")
	}
	var endRaw []byte
	if err := db.QueryRowContext(ctx, `SELECT data FROM events WHERE json_extract(data,'$.life_id')=? AND json_extract(data,'$.run')=? AND json_extract(data,'$.kind')='lane.ended' ORDER BY seq DESC LIMIT 1`, string(receipt.Target.LifeID), uint64(receipt.Target.Run)).Scan(&endRaw); err != nil {
		return err
	}
	var endEvent api.Event
	var end api.RunEndEvent
	if err := decodeStored(endRaw, &endEvent); err != nil {
		return err
	}
	if err := wire.Decode(endEvent.Payload, &end); err != nil {
		return err
	}
	if endEvent.Origin != "service" || endEvent.LogicalTurnID != receipt.LogicalTurnID || end.ProfileContinuation || end.Reason == "limit" || end.Reason != receipt.Cause || !sameValue(end.Observation, *outcome.Observation) {
		return fault(api.CodeIntegrity, "mail outcome lacks its real completed logical-turn end")
	}
	return nil
}
