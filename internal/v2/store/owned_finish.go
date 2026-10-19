package store

import (
	"context"
	"database/sql"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Caller holds mu and a writer transaction after its domain-specific independent
// readbacks. The original effect, operation, event and (if pending) typed reply
// become visible together. This never rewrites an already delivered reply.
func (s *Service) finishOwnedEffect(ctx context.Context, tx *sql.Tx, scope api.Scope, lease api.EffectLease, outcome api.EffectOutcome, domainSeq api.Sequence, reply *api.RPCReply) (api.Commit, error) {
	var zero api.Commit
	record, err := effectRow(ctx, tx, lease.Record.Effect.ID)
	if err != nil {
		return zero, err
	}
	if !sameValue(record, lease.Record) || record.ClaimantID != scope.Actor.ID || record.ClaimID != lease.ClaimID || record.Outcome != nil || outcome.Status == "succeeded" && !future(lease.ExpiresAt, s.deps.Clock.Now()) {
		return zero, fault(api.CodeConflict, "owned completion lost its current original effect claim")
	}
	if outcome.Status == "succeeded" {
		if err := s.checkEffectFence(ctx, tx, record.Effect); err != nil {
			return zero, err
		}
	}
	var pending int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM effects JOIN effect_states USING(id) WHERE operation_id=? AND effects.id<>? AND json_extract(effect_states.data,'$.Outcome') IS NULL", string(record.Effect.OperationID), string(record.Effect.ID)).Scan(&pending); err != nil {
		return zero, err
	}
	if pending != 0 {
		return zero, fault(api.CodeConflict, "owned completion has another unfinished operation effect")
	}
	var raw []byte
	var operation api.Operation
	if err := tx.QueryRowContext(ctx, "SELECT data FROM operations WHERE id=?", string(record.Effect.OperationID)).Scan(&raw); err != nil {
		return zero, err
	}
	if err := decodeStored(raw, &operation); err != nil {
		return zero, err
	}
	if operation.Status != "pending" && operation.Status != "running" {
		return zero, fault(api.CodeConflict, "owned operation is already terminal")
	}
	hasDomain := domainSeq != 0
	if !hasDomain {
		if err := tx.QueryRowContext(ctx, "SELECT coalesce(max(seq),0) FROM events").Scan(&domainSeq); err != nil {
			return zero, err
		}
	}
	if domainSeq >= 1<<53-1 {
		return zero, fault(api.CodeIntegrity, "owned completion journal sequence exhausted")
	}
	operation.Status, operation.Error, operation.LastSeq = "succeeded", nil, domainSeq+1
	if outcome.Status == "failed" {
		if outcome.Error == nil {
			return zero, fault(api.CodeInvalid, "failed owned outcome lacks its reason")
		}
		operation.Status, operation.Error = "failed", outcome.Error
	}
	if operation.FirstSeq == 0 {
		operation.FirstSeq = domainSeq + 1
		if hasDomain {
			operation.FirstSeq = domainSeq
		}
	}
	operation.LifeID, operation.Run = record.Effect.Context.Target.LifeID, record.Effect.Context.Target.Run
	operation.Result = outcome.Output
	var actor api.Actor
	if err := storedProjection(ctx, tx, "reservation_actor", operation.ID, &actor); err != nil {
		return zero, err
	}
	var requestRaw []byte
	err = tx.QueryRowContext(ctx, "SELECT request FROM reservations WHERE operation_id=?", string(operation.ID)).Scan(&requestRaw)
	reserved := err == nil
	if err != nil && err != sql.ErrNoRows {
		return zero, err
	}
	if !reserved {
		if err := tx.QueryRowContext(ctx, "SELECT request FROM receipts WHERE json_extract(operation,'$.id')=?", string(operation.ID)).Scan(&requestRaw); err != nil {
			return zero, err
		}
	}
	request, err := wire.DecodeRequest(requestRaw)
	if err != nil {
		return zero, err
	}
	payload, err := wire.EncodeOperationEvent(api.OperationEvent{Operation: operation, RequestSHA256: request.RequestSHA256})
	if err != nil {
		return zero, err
	}
	id, err := wire.NewID()
	if err != nil {
		return zero, err
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))
	kind := api.EventKind("operation.completed")
	if outcome.Status == "failed" {
		kind = "operation.failed"
	}
	event := api.Event{Schema: api.SchemaVersion, ID: id, Config: s.deps.Config, Kind: kind, Actor: scope.Actor, RequestedBy: record.Effect.Context.RequestedBy,
		OperationID: operation.ID, RequestID: request.RequestID, LifeID: operation.LifeID, Run: operation.Run, Origin: "service", StarterChain: []api.ID{}, Payload: payload}
	var lane api.Lane
	if err := storedProjection(ctx, tx, "lane", operation.LifeID, &lane); err == nil {
		event.ParentLifeID, event.RootLifeID, event.StarterEventSeq = lane.ParentLifeID, lane.RootLifeID, lane.StarterEventSeq
		event.StarterChain = append([]api.ID{}, lane.StarterChain...)
	} else if !absent(err) {
		return zero, err
	}
	seq, err := appendPrivateEvent(ctx, tx, event, now)
	if err != nil {
		return zero, err
	}
	if seq != operation.LastSeq {
		return zero, fault(api.CodeIntegrity, "owned completion appended at a different journal head")
	}
	record.Outcome, record.State, record.LastSeq = &outcome, terminalEffectState(outcome), seq
	record.Generation++
	state, err := encodeEffectState(record)
	if err != nil {
		return zero, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE effect_states SET data=? WHERE id=?", state, string(record.Effect.ID)); err != nil {
		return zero, err
	}
	operationRaw, err := json.Marshal(operation)
	if err != nil {
		return zero, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE operations SET data=? WHERE id=?", operationRaw, string(operation.ID)); err != nil {
		return zero, err
	}
	commit := api.Commit{Operation: operation, FirstSeq: domainSeq, LastSeq: seq, Reply: reply}
	if !hasDomain {
		commit.FirstSeq = seq
	}
	if reserved {
		if reply == nil {
			return zero, fault(api.CodeIntegrity, "pending owned operation lacks its exact typed reply")
		}
		originalScope := api.Scope{Config: s.deps.Config, Actor: actor, Request: request}
		receipt, err := s.lookupReceipt(ctx, tx, originalScope, requestKey(request))
		if err != nil {
			return zero, err
		}
		receipt.Operation, receipt.Reply, receipt.FirstSeq, receipt.LastSeq, receipt.RecordedAt = operation, reply, commit.FirstSeq, seq, now
		body, err := json.Marshal(storedReceipt{Config: s.deps.Config, Receipt: receipt})
		if err != nil {
			return zero, err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO receipts VALUES(?,?,?,?,?,?)", principal(originalScope), string(request.Method), string(request.IdempotencyKey), string(request.RequestSHA256), requestRaw, operationRaw); err != nil {
			return zero, err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO replies VALUES(?,?,?,?)", principal(originalScope), string(request.Method), string(request.IdempotencyKey), body); err != nil {
			return zero, err
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM reservations WHERE operation_id=?", string(operation.ID)); err != nil {
			return zero, err
		}
	}
	return commit, nil
}
