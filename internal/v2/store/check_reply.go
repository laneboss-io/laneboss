package store

import (
	"context"
	"database/sql"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// The complete public operation and its exact reply become visible with the
// published inputs. Worker completion alone keeps the dispatcher pending.
func (s *Service) finishCheckReply(ctx context.Context, tx *sql.Tx, caller api.Scope, r reviewRecord, operation api.Operation, published api.BlobRef) (api.Operation, error) {
	var head api.Sequence
	if err := tx.QueryRowContext(ctx, "SELECT coalesce(max(seq),0) FROM events").Scan(&head); err != nil {
		return operation, err
	}
	if head >= 1<<53-1 {
		return operation, fault(api.CodeIntegrity, "check publication sequence exhausted")
	}
	operation.Status, operation.Error, operation.LifeID, operation.Run, operation.Result = "succeeded", nil, r.Job.Lease.Target.LifeID, r.Job.Lease.Target.Run, &published
	operation.LastSeq = head + 1
	if operation.FirstSeq == 0 {
		operation.FirstSeq = operation.LastSeq
	}
	raw, err := json.Marshal(operation)
	if err != nil {
		return operation, err
	}
	payload, err := wire.EncodeOperationEvent(api.OperationEvent{Operation: operation, RequestSHA256: r.Request.RequestSHA256})
	if err != nil {
		return operation, err
	}
	id, err := wire.NewID()
	if err != nil {
		return operation, err
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(timeFormat))
	event := api.Event{Schema: api.SchemaVersion, ID: id, Config: s.deps.Config, Kind: "operation.completed", Actor: s.reviewScope().Actor, RequestedBy: r.Scope.Actor, OperationID: operation.ID, RequestID: r.Request.RequestID,
		LifeID: operation.LifeID, Run: operation.Run, ParentLifeID: r.Lane.ParentLifeID, RootLifeID: r.Lane.RootLifeID, StarterChain: append([]api.ID{}, r.Lane.StarterChain...), StarterEventSeq: r.Lane.StarterEventSeq, Origin: "service", Payload: payload}
	seq, err := appendPrivateEvent(ctx, tx, event, now)
	if err != nil {
		return operation, err
	}
	if seq != operation.LastSeq {
		return operation, fault(api.CodeIntegrity, "check publication changed its committed sequence")
	}
	if _, err := tx.ExecContext(ctx, "UPDATE operations SET data=? WHERE id=?", raw, string(operation.ID)); err != nil {
		return operation, err
	}
	receipt, err := s.lookupReceipt(ctx, tx, caller, requestKey(r.Request))
	if err != nil {
		return operation, err
	}
	if receipt.Reply != nil || receipt.Operation.ID != operation.ID || !sameValue(receipt.Actor, r.Scope.Actor) {
		return operation, fault(api.CodeConflict, "check publication changed its original pending reply")
	}
	receipt.Operation, receipt.FirstSeq, receipt.LastSeq, receipt.RecordedAt = operation, operation.FirstSeq, seq, now
	receipt.Reply = &api.RPCReply{Result: raw}
	if err := wire.ValidateResult(r.Request.Method, raw); err != nil {
		return operation, err
	}
	body, err := json.Marshal(storedReceipt{Config: s.deps.Config, Receipt: receipt})
	if err != nil {
		return operation, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO receipts VALUES(?,?,?,?,?,?)", principal(caller), string(r.Request.Method), string(r.Request.IdempotencyKey), string(r.Request.RequestSHA256), receipt.RawRequest, raw); err != nil {
		return operation, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO replies VALUES(?,?,?,?)", principal(caller), string(r.Request.Method), string(r.Request.IdempotencyKey), body); err != nil {
		return operation, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM reservations WHERE operation_id=?", string(operation.ID)); err != nil {
		return operation, err
	}
	return operation, nil
}
