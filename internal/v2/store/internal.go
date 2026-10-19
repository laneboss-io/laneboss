package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type internalCommit struct {
	Digest string
	Commit api.Commit
	Actor  api.Actor
}

// Caller holds the sole writer lock. Internal intent is not accepted on RPC.
func (s *Service) transactInternal(ctx context.Context, input api.Transaction) (commit api.Commit, resultErr error) {
	if input.Internal.Kind == api.InternalAdminEnroll {
		capability, ok := ctx.Value(enrollmentCommitKey{}).(enrollmentCommitAuthority)
		if !ok || len(input.Writes.Enrollments) != 1 || capability.Store != s || capability.Intent != input.Internal.ID || capability.Validation != input.Writes.Enrollments[0].ValidationID {
			return commit, fault(api.CodeForbidden, "enrollment commit lacks its native administrator capability")
		}
		if capability.NativeScope.Connection != nil {
			if s.deps.Enrollment == nil {
				return commit, api.NotImplemented("lb-v2-admin", "protected administrator enrollment endpoint")
			}
			if err := wire.VerifyAdministrator(ctx, *s.deps.Enrollment, capability.NativeScope.Connection, capability.NativeScope.Frame); err != nil {
				return commit, err
			}
		}
	}
	// Fresh prepare/open inputs receive their private policy stamp below.
	// Exact committed replay is selected before reading a newer policy head.
	if input.Internal.Kind != api.InternalHelperPrepare && input.Internal.Kind != api.InternalHelperOpen {
		if err := s.validateInternalShape(ctx, input); err != nil {
			return commit, err
		}
	}
	if !allowedInternal(input) {
		return commit, fault(api.CodeForbidden, "internal emitter does not cover these writes or events")
	}
	encoded, err := json.Marshal(struct {
		Intent  *api.InternalIntent
		Writes  api.StateWrites
		Events  []api.Event
		Effects []api.Effect
		Compare []api.Compare
		Guards  []api.TransactionGuard
		Cleanup planCleanupRequests `json:",omitempty"`
	}{input.Internal, input.Writes, input.Events, input.Effects, input.Compare, input.Guards, s.cleanupRequests(ctx)})
	if err != nil {
		return commit, err
	}
	digest := hash(encoded)
	receiptID := s.internalReceiptID(ctx, input)
	var previous internalCommit
	err = storedProjection(ctx, s.db, "internal_commit", receiptID, &previous)
	if err == nil {
		if previous.Digest != digest || previous.Actor != input.Scope.Actor {
			return commit, fault(api.CodeIdempotencyConflict, "internal intent ID has different content")
		}
		previous.Commit.Replayed = true
		return previous.Commit, nil
	}
	var typed *api.Error
	if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
		return commit, err
	}
	input, err = s.prepareIdentityBindings(ctx, input)
	if err != nil {
		return commit, err
	}
	input, err = s.bindCurrentLaunchPolicy(ctx, input)
	if err != nil {
		return commit, err
	}
	if err := s.validateInternalShape(ctx, input); err != nil {
		return commit, err
	}
	if err := s.validatePlanCleanup(ctx, s.db, input); err != nil {
		return commit, err
	}
	if len(s.cleanupRequests(ctx)) == 0 {
		if err := s.internalDispatchAllowed(ctx, input); err != nil {
			return commit, err
		}
	}
	if err := s.validateLaunchTransaction(ctx, s.db, input); err != nil {
		return commit, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return commit, err
	}
	defer finish(tx, &resultErr)
	operationID := input.Internal.CauseOperationID
	journal := watchdogJournal(input)
	if journal {
		operationID, err = wire.NewID()
		if err != nil {
			return commit, err
		}
	}
	if operationID == "" {
		operationID = input.Internal.ID
	}
	operation := api.Operation{ID: operationID, Status: "succeeded"}
	if journal {
		input, operation.Status, err = s.stampWatchdogJournal(ctx, tx, input, operationID)
		if err != nil {
			return commit, err
		}
		operation.LifeID, operation.Run = input.Internal.Target.LifeID, input.Internal.Target.Run
	}
	var owner string
	var data []byte
	err = tx.QueryRowContext(ctx, "SELECT principal,data FROM operations WHERE id=?", string(operationID)).Scan(&owner, &data)
	if err == nil {
		if err := wire.Decode(data, &operation); err != nil {
			return commit, err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return commit, err
	}
	if len(input.Effects) != 0 && operation.Status != "failed" {
		operation.Status = "pending"
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))
	if err := s.compare(ctx, tx, input.Compare); err != nil {
		return commit, err
	}
	if err := s.guards(ctx, tx, input, operationID); err != nil {
		return commit, err
	}
	simulated, err := s.transactionPresence(ctx, tx, input)
	if err != nil {
		return commit, err
	}
	operation.SimulatedPresence = operation.SimulatedPresence || simulated
	if err := s.writeState(ctx, tx, input, operationID, now); err != nil {
		return commit, err
	}
	var head api.Sequence
	var chain string
	err = tx.QueryRowContext(ctx, "SELECT seq,chain FROM events ORDER BY seq DESC LIMIT 1").Scan(&head, &chain)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return commit, err
	}
	first := api.Sequence(0)
	for _, event := range input.Events {
		if event.Actor != input.Internal.Actor || event.RequestedBy != input.Internal.RequestedBy || event.Config != s.deps.Config || event.Seq != 0 {
			return commit, fault(api.CodeForbidden, "internal event causality differs from emitter")
		}
		original, err := json.Marshal(event)
		if err != nil {
			return commit, err
		}
		head++
		event.Seq, event.RecordedAt = head, now
		event.OperationID = operationID
		event.RequestID = input.Internal.CauseRequestID
		if event.RequestID == "" {
			event.RequestID = input.Internal.ID
		}
		if event.RequestedAt == "" {
			event.RequestedAt = now
		}
		if event.ObservedAt == "" {
			event.ObservedAt = now
		}
		if event.StarterChain == nil {
			event.StarterChain = []api.ID{}
		}
		if err := wire.ValidateEvent(event); err != nil {
			return commit, err
		}
		data, err := json.Marshal(event)
		if err != nil {
			return commit, err
		}
		chain = hash(append([]byte(chain), data...))
		if _, err := tx.ExecContext(ctx, "INSERT INTO events VALUES(?,?,?,?,?,?)", uint64(head), string(event.ID), data, original, hash(data), chain); err != nil {
			return commit, err
		}
		if err := s.project(ctx, tx, event); err != nil {
			return commit, err
		}
		if first == 0 {
			first = head
		}
		if operation.FirstSeq == 0 {
			operation.FirstSeq = head
		}
		operation.LastSeq = head
	}
	if err := s.stampAuthority(ctx, tx, input, operationID); err != nil {
		return commit, err
	}
	for _, effect := range input.Effects {
		if err := validateEffect(effect); err != nil {
			return commit, err
		}
		if effect.OperationID != operationID || effect.Context.RequestedBy != input.Internal.RequestedBy {
			return commit, fault(api.CodeForbidden, "internal effect differs from causal operation")
		}
		data, err := json.Marshal(effect)
		if err != nil {
			return commit, err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO effects(id,operation_id,data) VALUES(?,?,?)", string(effect.ID), string(operationID), data); err != nil {
			return commit, err
		}
		state, err := encodeEffectState(api.EffectRecord{Effect: effect, Generation: 1, State: api.EffectPending, LastSeq: head})
		if err != nil {
			return commit, err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO effect_states VALUES(?,?)", string(effect.ID), state); err != nil {
			return commit, err
		}
	}
	if err := s.writePlanCleanup(ctx, tx, input); err != nil {
		return commit, err
	}
	if journal && first == 0 {
		head, err = s.watchdogOperationEvent(ctx, tx, input, &operation, now, api.Digest(digest))
		if err != nil {
			return commit, err
		}
		first = head
	}
	data, err = json.Marshal(operation)
	if err != nil {
		return commit, err
	}
	if owner == "" {
		owner = principal(input.Scope)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO operations VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", string(operationID), owner, data); err != nil {
		return commit, err
	}
	commit = api.Commit{Operation: operation, FirstSeq: first, LastSeq: head}
	if err := put(ctx, tx, "internal_commit", receiptID, 1, internalCommit{Digest: digest, Commit: commit, Actor: input.Scope.Actor}); err != nil {
		return commit, err
	}
	if err := tx.Commit(); err != nil {
		return commit, err
	}
	s.notifyChanged()
	return commit, nil
}
