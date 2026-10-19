package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func decodeStored(data []byte, out any) error {
	if err := api.ValidateObjectJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fault(api.CodeIntegrity, "invalid retained typed state")
	}
	normalizeStoredReplyNull(reflect.ValueOf(out))
	return nil
}

// RPCReply is an internal DTO whose nil RawMessage marshals as JSON null.
// encoding/json otherwise decodes that null into four literal result bytes,
// accidentally turning an error-only retained reply into a two-arm union.
// Normalize only this typed internal nil representation, never public frames,
// successful results, arbitrary object bytes or source/derived arrays.
func normalizeStoredReplyNull(value reflect.Value) {
	if !value.IsValid() {
		return
	}
	if value.Kind() == reflect.Pointer {
		if !value.IsNil() {
			normalizeStoredReplyNull(value.Elem())
		}
		return
	}
	if value.Type() == reflect.TypeFor[api.RPCReply]() && value.CanAddr() && value.Addr().CanInterface() {
		reply := value.Addr().Interface().(*api.RPCReply)
		if reply.Error != nil && bytes.Equal(bytes.TrimSpace(reply.Result), []byte("null")) {
			reply.Result = nil
		}
		return
	}
	switch value.Kind() {
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			if value.Type().Field(index).IsExported() {
				normalizeStoredReplyNull(value.Field(index))
			}
		}
	case reflect.Slice, reflect.Array:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		for index := 0; index < value.Len(); index++ {
			normalizeStoredReplyNull(value.Index(index))
		}
	}
}
func requestKey(request api.Request) api.RequestKey {
	return api.RequestKey{Method: request.Method, IdempotencyKey: request.IdempotencyKey, RequestSHA256: request.RequestSHA256}
}

// The supervisor will merge final draft.4 after this lane. The storage envelope
// already binds Config; this bridge also fills the added typed field when that
// reviewed API is present, without editing the shared contract in this lane.
type storedReceipt struct {
	Config  string
	Receipt api.MutationReceipt
}

func bindReceiptConfig(receipt *api.MutationReceipt, config string) error {
	field := reflect.ValueOf(receipt).Elem().FieldByName("Config")
	if field.IsValid() {
		if field.Kind() != reflect.String || field.String() != "" && field.String() != config {
			return fault(api.CodeIntegrity, "receipt belongs to another configuration")
		}
		field.SetString(config)
	}
	return nil
}
func (s *Service) LookupReceipt(ctx context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return api.MutationReceipt{}, err
	}
	if err := s.scope(ctx, s.db, scope); err != nil {
		return api.MutationReceipt{}, err
	}
	if scope.Request.Method != "" {
		if err := wire.ValidateRequest(scope.Request); err != nil {
			return api.MutationReceipt{}, err
		}
		if scope.Actor.Kind != "human" && scope.Request.Proof != nil {
			return api.MutationReceipt{}, fault(api.CodeForbidden, "lane or worker cannot replay a human proof")
		}
	}
	return s.lookupReceipt(ctx, s.db, scope, key)
}
func (s *Service) lookupReceipt(ctx context.Context, db queryer, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	var receipt api.MutationReceipt
	if !wire.ValidID(string(key.IdempotencyKey)) || !wire.ValidDigest(string(key.RequestSHA256)) || !api.Methods[key.Method].Mutation {
		return receipt, wire.Invalid("invalid receipt lookup key")
	}
	var digest string
	var data []byte
	err := db.QueryRowContext(ctx, "SELECT digest,data FROM receipts JOIN replies USING(principal,method,key) WHERE principal=? AND method=? AND key=?",
		principal(scope), string(key.Method), string(key.IdempotencyKey)).Scan(&digest, &data)
	if err == nil {
		if digest != string(key.RequestSHA256) {
			return receipt, fault(api.CodeIdempotencyConflict, "idempotency key has different request content")
		}
		var stored storedReceipt
		if err := decodeStored(data, &stored); err != nil {
			return receipt, err
		}
		if stored.Config != s.deps.Config || stored.Config != scope.Config {
			return receipt, fault(api.CodeIntegrity, "receipt configuration differs from bound store")
		}
		receipt = stored.Receipt
		if receipt.SimulatedPresence != receipt.Operation.SimulatedPresence {
			return receipt, fault(api.CodeIntegrity, "receipt dropped operation presence provenance")
		}
		if err := bindReceiptConfig(&receipt, stored.Config); err != nil {
			return receipt, err
		}
		if receipt.Actor != scope.Actor || receipt.Key != key || receipt.Reply == nil && receipt.Deferred == nil {
			return receipt, fault(api.CodeIntegrity, "retained receipt binding is invalid")
		}
		if receipt.Deferred != nil {
			if err := s.validateOrgReceipt(ctx, db, receipt); err != nil {
				return receipt, err
			}
		}
		return receipt, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return receipt, fault(api.CodeIntegrity, "cannot read exact receipt")
	}
	var operationID, recorded string
	err = db.QueryRowContext(ctx, "SELECT digest,request,operation_id,recorded FROM reservations WHERE principal=? AND method=? AND key=?",
		principal(scope), string(key.Method), string(key.IdempotencyKey)).Scan(&digest, &receipt.RawRequest, &operationID, &recorded)
	if errors.Is(err, sql.ErrNoRows) {
		return receipt, fault(api.CodeNotFound, "request has no durable reservation")
	}
	if err != nil {
		return receipt, fault(api.CodeIntegrity, "cannot read request reservation")
	}
	if digest != string(key.RequestSHA256) {
		return receipt, fault(api.CodeIdempotencyConflict, "idempotency key has different request content")
	}
	var operationData []byte
	if err := db.QueryRowContext(ctx, "SELECT data FROM operations WHERE id=? AND principal=?", operationID, principal(scope)).Scan(&operationData); err != nil {
		return receipt, fault(api.CodeIntegrity, "reserved operation is absent")
	}
	if err := wire.Decode(operationData, &receipt.Operation); err != nil {
		return receipt, err
	}
	receipt.Key, receipt.Actor, receipt.RecordedAt = key, scope.Actor, api.Timestamp(recorded)
	if key.Method == "org.change.apply" {
		var job orgApply
		if err := storedProjection(ctx, db, "org_apply", receipt.Operation.ID, &job); err == nil {
			receipt.Deferred = &job.Deferred
		} else if !absent(err) {
			return receipt, err
		}
	}
	receipt.SimulatedPresence = receipt.Operation.SimulatedPresence
	var generation api.Generation
	if err := storedProjection(ctx, db, "reservation_policy", receipt.Operation.ID, &generation); err == nil {
		receipt.PolicyGeneration = generation
	} else if !absent(err) {
		return receipt, err
	}
	if err := bindReceiptConfig(&receipt, scope.Config); err != nil {
		return receipt, err
	}
	return receipt, nil
}
func (s *Service) ReserveRequest(ctx context.Context, input api.RequestReservation) (api.MutationReceipt, error) {
	receipt, _, err := s.ReserveMutation(ctx, input)
	return receipt, err
}

// ReserveMutation reports the actual insertion winner under the sole writer.
// A replay returns its retained receipt and never grants new execution rights.
func (s *Service) ReserveMutation(ctx context.Context, input api.RequestReservation) (receipt api.MutationReceipt, won bool, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return receipt, false, err
	}
	if err := s.scope(ctx, s.db, input.Scope); err != nil {
		return receipt, false, err
	}
	request := input.Scope.Request
	if err := wire.ValidateRequest(request); err != nil {
		return receipt, false, err
	}
	if !api.Methods[request.Method].Mutation || request.Config != s.deps.Config {
		return receipt, false, wire.Invalid("reservation requires a bound mutation")
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return receipt, false, err
	}
	if _, err := wire.DecodeRequest(input.RawRequest); err != nil || !wire.SameJSON(encoded, input.RawRequest) {
		return receipt, false, wire.Invalid("reservation raw request mismatch")
	}
	deadline, err := time.Parse(time.RFC3339Nano, string(input.Deadline))
	if err != nil || !deadline.After(s.deps.Clock.Now()) {
		return receipt, false, wire.Invalid("reservation deadline is expired")
	}
	previous, err := s.lookupReceipt(ctx, s.db, input.Scope, requestKey(request))
	var typed *api.Error
	if err == nil {
		return previous, false, nil
	}
	if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
		return receipt, false, err
	}
	if err := s.dispatchAllowed(ctx, s.db); err != nil {
		return receipt, false, err
	}
	switch request.Method {
	case "org.change.propose", "org.change.approve", "org.change.apply", "lane.start", "lane.adopt", "lane.resume", "lane.turn", "grants.root", "grants.enroll":
		if err := s.orgGenerationReady(ctx, s.db); err != nil {
			return receipt, false, err
		}
	}
	owner, _ := ctx.Value(reservationOwnerKey{}).(*reservationOwner)
	if owner == nil {
		// A legacy in-process caller has no retirement callback. Conservatively
		// keep its reservation live until this writer closes.
		owner = &reservationOwner{store: s, live: true}
	}
	if owner.store != s || !owner.live || owner.operation != "" {
		return receipt, false, fault(api.CodeConflict, "mutation invocation is retired or already reserved")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return receipt, false, err
	}
	defer finish(tx, &resultErr)
	id, err := wire.NewID()
	if err != nil {
		return receipt, false, err
	}
	operation := api.Operation{ID: id, Status: "pending"}
	metadata := api.Transaction{Scope: input.Scope}
	if request.Proof != nil {
		var proof api.VerifiedHumanProof
		if err := storedProjection(ctx, tx, "proof", request.Proof.ID, &proof); err != nil {
			return receipt, false, err
		}
		if _, err := s.proofCredential(ctx, tx, proof); err != nil {
			return receipt, false, err
		}
		operation.SimulatedPresence = proof.SimulatedPresence
	}
	inherited, err := s.transactionPresence(ctx, tx, metadata)
	if err != nil {
		return receipt, false, err
	}
	operation.SimulatedPresence = operation.SimulatedPresence || inherited
	generation, err := s.operationPolicy(ctx, tx)
	if err != nil {
		return receipt, false, err
	}
	if err := put(ctx, tx, "reservation_policy", id, 1, generation); err != nil {
		return receipt, false, err
	}
	if err := put(ctx, tx, "reservation_actor", id, 1, input.Scope.Actor); err != nil {
		return receipt, false, err
	}
	data, err := json.Marshal(operation)
	if err != nil {
		return receipt, false, err
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))
	if _, err := tx.ExecContext(ctx, "INSERT INTO operations VALUES(?,?,?)", string(id), principal(input.Scope), data); err != nil {
		return receipt, false, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?)", principal(input.Scope), string(request.Method), string(request.IdempotencyKey),
		string(request.RequestSHA256), input.RawRequest, string(id), string(input.Deadline), string(now)); err != nil {
		return receipt, false, err
	}
	if err := tx.Commit(); err != nil {
		return receipt, false, err
	}
	owner.operation = id
	if s.reservationOwners == nil {
		s.reservationOwners = make(map[api.ID]*reservationOwner)
	}
	s.reservationOwners[id] = owner
	receipt = api.MutationReceipt{Key: requestKey(request), Actor: input.Scope.Actor, Operation: operation, RawRequest: append([]byte(nil), input.RawRequest...), RecordedAt: now}
	receipt.SimulatedPresence, receipt.PolicyGeneration = operation.SimulatedPresence, generation
	if err := bindReceiptConfig(&receipt, input.Scope.Config); err != nil {
		return receipt, false, err
	}
	return receipt, true, nil
}
func (s *Service) AwaitReceipt(ctx context.Context, scope api.Scope, key api.RequestKey) (api.MutationReceipt, error) {
	for {
		s.mu.RLock()
		changed := s.changed
		s.mu.RUnlock()
		receipt, err := s.LookupReceipt(ctx, scope, key)
		if err != nil || receipt.Reply != nil {
			return receipt, err
		}
		var deadline string
		s.mu.RLock()
		if err := s.available(); err != nil {
			s.mu.RUnlock()
			return receipt, err
		}
		err = s.db.QueryRowContext(ctx, "SELECT deadline FROM reservations WHERE principal=? AND method=? AND key=?", principal(scope), string(key.Method), string(key.IdempotencyKey)).Scan(&deadline)
		s.mu.RUnlock()
		if errors.Is(err, sql.ErrNoRows) {
			continue // Completion may have removed it after the pending lookup.
		}
		if err != nil {
			return receipt, fault(api.CodeIntegrity, "pending request lost its deadline")
		}
		end, err := time.Parse(time.RFC3339Nano, deadline)
		if err != nil {
			return receipt, err
		}
		remaining := end.Sub(s.deps.Clock.Now())
		if remaining <= 0 {
			return receipt, &api.Error{Code: api.CodeUnavailable, Message: "reserved request requires reconciliation", OperationID: receipt.Operation.ID, Instead: "Inspect the existing durable operation; do not issue a replacement key."}
		}
		timer := time.NewTimer(remaining)
		select {
		case <-ctx.Done():
			timer.Stop()
			return receipt, fault(api.CodeDeadline, "waiting for receipt exceeded request deadline")
		case <-changed:
			timer.Stop()
		case <-timer.C:
			return receipt, &api.Error{Code: api.CodeUnavailable, Message: "reserved request is still pending", OperationID: receipt.Operation.ID, Instead: "Reconcile this operation before repeating any external work."}
		}
	}
}
func (s *Service) notifyChanged() { close(s.changed); s.changed = make(chan struct{}) }
