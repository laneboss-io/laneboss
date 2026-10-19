package store

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type reservationOwnerKey struct{}

type reservationOwner struct {
	store     *Service
	operation api.ID
	live      bool
}

// TrackMutation supplies an invocation-local retirement capability. A copied
// request or a losing reservation cannot retire the actual insertion winner.
// All owner state and recovery decisions share the sole writer's mutex.
func (s *Service) TrackMutation(ctx context.Context) (context.Context, func()) {
	owner := &reservationOwner{store: s, live: true}
	return context.WithValue(ctx, reservationOwnerKey{}, owner), func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		owner.live = false
		if s.reservationOwners[owner.operation] == owner {
			delete(s.reservationOwners, owner.operation)
		}
	}
}

type abandonedReservation struct {
	principal, method, key, digest string
	raw                            []byte
	operation                      api.ID
	deadline                       string
}

// RecoverReservations seals expired, ownerless preflight reservations. A new
// writer acquires the exclusive OS lock before it can observe old reservations;
// current writer invocations remain protected even after cancellation/expiry.
// Durable effects retain their own reconciliation route and are never erased.
func (s *Service) RecoverReservations(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return err
	}
	for operation := range s.reservationOwners {
		var remaining int
		if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM reservations WHERE operation_id=?", operation).Scan(&remaining); err != nil {
			return err
		}
		if remaining == 0 {
			delete(s.reservationOwners, operation)
		}
	}
	rows, err := s.db.QueryContext(ctx, "SELECT principal,method,key,digest,request,operation_id,deadline FROM reservations ORDER BY deadline,operation_id LIMIT 200")
	if err != nil {
		return err
	}
	var pending []abandonedReservation
	for rows.Next() {
		var row abandonedReservation
		if err := rows.Scan(&row.principal, &row.method, &row.key, &row.digest, &row.raw, &row.operation, &row.deadline); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, row)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, row := range pending {
		deadline, err := time.Parse(time.RFC3339Nano, row.deadline)
		if err != nil {
			return fault(api.CodeIntegrity, "reservation recovery found an invalid deadline")
		}
		if s.deps.Clock.Now().Before(deadline) {
			continue
		}
		if owner := s.reservationOwners[row.operation]; owner != nil && owner.live {
			continue
		}
		var effects int
		if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM effects WHERE operation_id=?", row.operation).Scan(&effects); err != nil {
			return err
		}
		if effects != 0 {
			continue
		}
		var archives int
		if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM projections WHERE kind='archive_job' AND id=?", string(row.operation)).Scan(&archives); err != nil {
			return err
		}
		if archives != 0 {
			continue
		}
		if err := s.failAbandonedReservation(ctx, row); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) reservationActor(ctx context.Context, row abandonedReservation) (api.Actor, error) {
	var actor api.Actor
	err := storedProjection(ctx, s.db, "reservation_actor", row.operation, &actor)
	if absent(err) {
		// Older draft.4 reservations kept the principal but not its full DTO.
		// Lane level/role are immutable retained life attributes, not new grants.
		parts := strings.Split(row.principal, ":")
		if len(parts) != 3 {
			return actor, fault(api.CodeIntegrity, "reservation recovery lost its original principal")
		}
		actor = api.Actor{Kind: parts[0], ID: api.ID(parts[1]), LifeID: api.ID(parts[2])}
		if actor.Kind == "lane" {
			var lane api.Lane
			if err := storedProjection(ctx, s.db, "lane", actor.LifeID, &lane); err != nil {
				return actor, err
			}
			actor.Level, actor.Role = lane.Level, lane.Role
		}
	} else if err != nil {
		return actor, err
	}
	data, err := json.Marshal(actor)
	var checked api.Actor
	if err != nil || wire.Decode(data, &checked) != nil || principal(api.Scope{Actor: actor}) != row.principal {
		return actor, fault(api.CodeIntegrity, "reservation recovery found an invalid actor binding")
	}
	return actor, nil
}

// Caller holds the writer lock. This path grants no caller authority and runs
// no preflight; it retains a failed reply under the original principal/key.
func (s *Service) failAbandonedReservation(ctx context.Context, row abandonedReservation) (resultErr error) {
	request, err := wire.DecodeRequest(row.raw)
	if err != nil || request.Config != s.deps.Config || string(request.Method) != row.method || string(request.IdempotencyKey) != row.key || string(request.RequestSHA256) != row.digest {
		return fault(api.CodeIntegrity, "reservation recovery found changed request bytes")
	}
	actor, err := s.reservationActor(ctx, row)
	if err != nil {
		return err
	}
	scope := api.Scope{Config: s.deps.Config, Actor: actor, Request: request}
	receipt, err := s.lookupReceipt(ctx, s.db, scope, requestKey(request))
	if err != nil {
		return err
	}
	if receipt.Operation.ID != row.operation || receipt.Reply != nil || receipt.Operation.Status != "pending" {
		return fault(api.CodeIntegrity, "reservation recovery found a nonpending operation")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer finish(tx, &resultErr)
	var head api.Sequence
	if err := tx.QueryRowContext(ctx, "SELECT coalesce(max(seq),0)+1 FROM events").Scan(&head); err != nil {
		return err
	}
	if head >= 1<<53 {
		return fault(api.CodeIntegrity, "journal sequence exhausted")
	}
	failure := fault(api.CodeUnavailable, "reservation owner ended before committing its reply")
	failure.OperationID = row.operation
	operation := receipt.Operation
	operation.Status, operation.Error, operation.LastSeq = "failed", failure, head
	if operation.FirstSeq == 0 {
		operation.FirstSeq = head
	}
	payload, err := wire.EncodeOperationEvent(api.OperationEvent{Operation: operation, RequestSHA256: request.RequestSHA256})
	if err != nil {
		return err
	}
	id, err := wire.NewID()
	if err != nil {
		return err
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))
	event := api.Event{Schema: api.SchemaVersion, ID: id, Config: s.deps.Config, Kind: "operation.failed",
		Actor: api.Actor{Kind: "service", ID: s.storeID}, RequestedBy: actor, OperationID: row.operation,
		RequestID: request.RequestID, LifeID: operation.LifeID, Run: operation.Run, Origin: "service", Payload: payload}
	if _, err := appendPrivateEvent(ctx, tx, event, now); err != nil {
		return err
	}
	operationData, err := json.Marshal(operation)
	if err != nil {
		return err
	}
	receipt.Operation, receipt.Reply = operation, &api.RPCReply{Error: failure}
	receipt.FirstSeq, receipt.LastSeq, receipt.RecordedAt = operation.FirstSeq, head, now
	receiptData, err := json.Marshal(storedReceipt{Config: s.deps.Config, Receipt: receipt})
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE operations SET data=? WHERE id=? AND principal=?", operationData, row.operation, row.principal); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO receipts VALUES(?,?,?,?,?,?)", row.principal, row.method, row.key, row.digest, row.raw, operationData); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO replies VALUES(?,?,?,?)", row.principal, row.method, row.key, receiptData); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM reservations WHERE principal=? AND method=? AND key=? AND operation_id=?", row.principal, row.method, row.key, row.operation); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.notifyChanged()
	return nil
}
