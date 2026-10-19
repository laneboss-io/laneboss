package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Transact commits durable intent only. It never launches a process or performs
// network/worker work. Reconciliation must observe the immutable effect ID.
func (s *Service) Transact(ctx context.Context, input api.Transaction) (commit api.Commit, resultErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.available(); err != nil {
		return commit, err
	}
	if err := s.scope(ctx, s.db, input.Scope); err != nil {
		return commit, err
	}
	if input.Internal != nil {
		return s.transactInternal(ctx, input)
	}
	request := input.Scope.Request
	if err := wire.ValidateRequest(request); err != nil {
		return commit, err
	}
	if input.Scope.Actor.Kind != "human" && request.Proof != nil {
		return commit, fault(api.CodeForbidden, "lane or worker cannot submit a human proof")
	}
	if request.Config != s.deps.Config || !api.Methods[request.Method].Mutation {
		return commit, wire.Invalid("transaction requires same-configuration mutation metadata")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return commit, fault(api.CodeUnavailable, "cannot begin state transaction")
	}
	defer finish(tx, &resultErr)
	var previousDigest string
	var previous []byte
	err = tx.QueryRowContext(ctx, `SELECT digest,operation FROM receipts
 WHERE principal=? AND method=? AND key=?`, principal(input.Scope), string(request.Method), string(request.IdempotencyKey)).Scan(&previousDigest, &previous)
	if err == nil {
		if previousDigest != string(request.RequestSHA256) {
			return commit, fault(api.CodeIdempotencyConflict, "idempotency key has different request content")
		}
		if err := wire.Decode(previous, &commit.Operation); err != nil {
			return commit, fault(api.CodeIntegrity, "saved operation receipt is invalid")
		}
		var data []byte
		if err := tx.QueryRowContext(ctx, "SELECT data FROM replies WHERE principal=? AND method=? AND key=?", principal(input.Scope), string(request.Method), string(request.IdempotencyKey)).Scan(&data); err != nil {
			return commit, fault(api.CodeIntegrity, "exact reply is absent")
		}
		var stored storedReceipt
		if err := decodeStored(data, &stored); err != nil {
			return commit, err
		}
		receipt := stored.Receipt
		if stored.Config != s.deps.Config || receipt.Actor != input.Scope.Actor || receipt.Key != requestKey(request) {
			return commit, fault(api.CodeIntegrity, "saved receipt binding mismatch")
		}
		if receipt.Deferred != nil && receipt.Reply == nil && (input.Reply != nil || input.Deferred == nil || *input.Deferred != *receipt.Deferred) {
			return commit, fault(api.CodeForbidden, "guarded publication can only complete through its original claimed effect")
		}
		commit.Deferred = receipt.Deferred
		commit.Reply, commit.FirstSeq, commit.LastSeq, commit.Replayed = receipt.Reply, receipt.FirstSeq, receipt.LastSeq, true
		return commit, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return commit, fault(api.CodeIntegrity, "cannot read idempotency receipt")
	}
	// Current authorization and completed replay precede mutable preflight.
	cascade := s.isGrantCascade(ctx, input)
	// The ordinary final refusal route has no authority writes, events,
	// effects or consumed guards; ValidateTransactionShape enforces that below.
	errorOnly := input.Reply != nil && input.Reply.Error != nil
	if request.Method == "grants.revoke" && !errorOnly {
		if !cascade {
			return commit, fault(api.CodeForbidden, "grant revocation requires the private cascade coordinator")
		}
		input, err = s.buildGrantCascade(ctx, tx, input)
		if err != nil {
			return commit, err
		}
	}
	if err := api.ValidateTransactionShape(input); err != nil {
		return commit, err
	}
	if len(input.Events) > 200 || len(input.Effects) > 200 {
		return commit, wire.Invalid("transaction event/effect count exceeds bounds")
	}
	if request.Method == "lane.check" && len(input.Writes.Lanes) == 1 {
		var head api.Sequence
		if err := tx.QueryRowContext(ctx, "SELECT coalesce(max(seq),0) FROM events").Scan(&head); err != nil {
			return commit, err
		}
		for _, guard := range input.Guards {
			if guard.Proof != nil {
				head++
			}
		}
		input.Writes.Lanes = append([]api.Lane{}, input.Writes.Lanes...)
		input.Writes.Lanes[0].LastSeq = head + api.Sequence(len(input.Events))
	}
	if err := s.validateLaunchTransaction(ctx, tx, input); err != nil {
		return commit, err
	}
	if err := s.validateChangeTransaction(ctx, tx, input); err != nil {
		return commit, err
	}
	if err := s.checkTestTransaction(ctx, tx, input); err != nil {
		return commit, err
	}
	laneAuthored, err := s.publicLaneEvents(ctx, tx, input)
	if err != nil {
		return commit, err
	}
	operationID, err := wire.NewID()
	if err != nil {
		return commit, err
	}
	// A module can allocate the correlation ID before creating its intent.
	if len(input.Events) != 0 && input.Events[0].OperationID != "" {
		operationID = input.Events[0].OperationID
	}
	if len(input.Events) == 0 && len(input.Effects) != 0 {
		operationID = input.Effects[0].OperationID
	}
	var reservedID, reservedDigest string
	var reservedRaw []byte
	reserveErr := tx.QueryRowContext(ctx, "SELECT operation_id,digest,request FROM reservations WHERE principal=? AND method=? AND key=?", principal(input.Scope), string(request.Method), string(request.IdempotencyKey)).Scan(&reservedID, &reservedDigest, &reservedRaw)
	if reserveErr != nil && !errors.Is(reserveErr, sql.ErrNoRows) {
		return commit, reserveErr
	}
	if reserveErr == nil && reservedDigest != string(request.RequestSHA256) {
		return commit, fault(api.CodeIdempotencyConflict, "idempotency key has different pending request content")
	}
	if reserveErr == nil && request.Method == "org.change.apply" {
		var job orgApply
		if err := storedProjection(ctx, tx, "org_apply", api.ID(reservedID), &job); err == nil {
			if input.Deferred == nil || input.Reply != nil || *input.Deferred != job.Deferred || !sameValue(input.Effects, []api.Effect{job.Effect}) {
				return commit, fault(api.CodeForbidden, "guarded publication can only complete through its original claimed effect")
			}
			var operation api.Operation
			var raw []byte
			if err := tx.QueryRowContext(ctx, "SELECT data FROM operations WHERE id=?", reservedID).Scan(&raw); err != nil {
				return commit, err
			}
			if err := decodeStored(raw, &operation); err != nil {
				return commit, err
			}
			return api.Commit{Operation: operation, Deferred: &job.Deferred, Replayed: true}, nil
		} else if !absent(err) {
			return commit, err
		}
	}
	if reserveErr == nil {
		var archives int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM projections WHERE kind='archive_job' AND id=?", reservedID).Scan(&archives); err != nil {
			return commit, err
		}
		if archives != 0 {
			return commit, fault(api.CodeForbidden, "retained archive reply requires its verified original completion")
		}
	}
	if reserveErr == nil {
		encoded, err := json.Marshal(request)
		if err != nil || !wire.SameJSON(encoded, reservedRaw) {
			return commit, fault(api.CodeConflict, "pending reservation belongs to another request instance")
		}
		input.RawRequest = append([]byte(nil), reservedRaw...)
	} else if err := s.dispatchAllowed(ctx, tx); err != nil {
		return commit, err
	}
	proposedID := operationID
	if reservedID != "" {
		operationID = api.ID(reservedID)
	}
	if !wire.ValidID(string(operationID)) {
		return commit, wire.Invalid("invalid operation correlation")
	}
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM operations WHERE id=?", string(operationID)).Scan(&exists); err != nil {
		return commit, fault(api.CodeIntegrity, "cannot inspect operation correlation")
	}
	if exists != 0 && reservedID == "" {
		return commit, fault(api.CodeConflict, "operation ID belongs to an existing mutation")
	}
	var lastSeq uint64
	var chain string
	err = tx.QueryRowContext(ctx, "SELECT seq,chain FROM events ORDER BY seq DESC LIMIT 1").Scan(&lastSeq, &chain)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return commit, fault(api.CodeIntegrity, "cannot read journal head")
	}
	operation := api.Operation{ID: operationID, Status: "succeeded"}
	if len(input.Effects) != 0 {
		operation.Status = "pending"
	}
	if request.Method == "lane.clean" && len(input.Effects) != 0 {
		// Clean enqueues its collector without a lane event. Retain the
		// original target now so completion cannot change the immutable
		// receipt's life/run while publishing its measured cleaned event.
		var clean api.CleanRequest
		if err := wire.Decode(request.Params, &clean); err != nil {
			return commit, err
		}
		operation.LifeID, operation.Run = clean.Target.LifeID, clean.Target.Run
	}
	if request.Method == "grants.test-child" && len(input.Effects) != 0 {
		var test api.TestChildRequest
		if err := wire.Decode(request.Params, &test); err != nil {
			return commit, err
		}
		operation.LifeID, operation.Run = test.Child.LifeID, test.Child.Run
		// Native dispatch already reserved the operation. The actual admission
		// event supplies a sequence even for lane callers without proof events.
		event, err := s.testAdmissionEvent(ctx, tx, input)
		if err != nil {
			return commit, err
		}
		input.Events = append(input.Events, event)
	}
	now := api.Timestamp(s.deps.Clock.Now().UTC().Format(time.RFC3339Nano))
	if err := s.compare(ctx, tx, input.Compare); err != nil {
		return commit, err
	}
	if err := s.guards(ctx, tx, input, operationID); err != nil {
		return commit, err
	}
	if request.Method == "lane.stop" && !errorOnly && len(input.Events) == 0 && len(input.Effects) == 0 {
		result, target, err := s.terminalStop(ctx, tx, input)
		if err != nil {
			return commit, err
		}
		operation.Stop, operation.LifeID, operation.Run = &result, target.LifeID, target.Run
	}
	if input.Deferred != nil {
		if reservedID == "" || input.Deferred.OperationID != operationID {
			return commit, fault(api.CodeForbidden, "publication requires its exact original durable request reservation")
		}
		if err := s.reserveOrgApply(ctx, tx, input); err != nil {
			return commit, err
		}
	}
	if err := s.checkSecretMutation(ctx, tx, input); err != nil {
		return commit, err
	}
	if err := s.projectSecretStage(ctx, tx, input, operationID); err != nil {
		return commit, err
	}
	if err := s.checkCapabilityEnrollment(ctx, tx, input); err != nil {
		return commit, err
	}
	simulated, err := s.transactionPresence(ctx, tx, input)
	if err != nil {
		return commit, err
	}
	operation.SimulatedPresence = simulated
	if reservedID != "" {
		var data []byte
		var retained api.Operation
		if err := tx.QueryRowContext(ctx, "SELECT data FROM operations WHERE id=?", reservedID).Scan(&data); err != nil {
			return commit, err
		}
		if err := decodeStored(data, &retained); err != nil {
			return commit, err
		}
		operation.SimulatedPresence = operation.SimulatedPresence || retained.SimulatedPresence
	}
	for _, guard := range input.Guards {
		if guard.Proof == nil {
			continue
		}
		var used api.ProofUseReceipt
		if err := storedProjection(ctx, tx, "proof_use", guard.Proof.Proof.ID, &used); err != nil {
			return commit, err
		}
		payload, err := json.Marshal(used)
		if err != nil {
			return commit, err
		}
		id, err := wire.NewID()
		if err != nil {
			return commit, err
		}
		input.Events = append(input.Events, api.Event{Schema: api.SchemaVersion, ID: id, Config: s.deps.Config, Kind: "human.proof.used", Actor: api.Actor{Kind: "service", ID: s.storeID}, RequestedBy: input.Scope.Actor, Origin: "service", StarterChain: []api.ID{}, Payload: payload})
	}
	if err := s.writeState(ctx, tx, input, operationID, now); err != nil {
		return commit, err
	}
	for _, event := range input.Events {
		natural := request.Method == "lane.check" || request.Method == "grants.test-child" || cascade
		orgChange := request.Method == "org.change.propose" || request.Method == "org.change.approve"
		if natural || orgChange {
			event.Actor = api.Actor{Kind: "service", ID: s.storeID}
			event.RequestedBy = input.Scope.Actor
			event.Origin = "service"
		}
		original, err := json.Marshal(event)
		if err != nil {
			return commit, wire.Invalid("invalid event bytes")
		}
		var existingInput []byte
		var existingSeq uint64
		err = tx.QueryRowContext(ctx, "SELECT seq,input FROM events WHERE id=?", string(event.ID)).Scan(&existingSeq, &existingInput)
		if err == nil {
			if !wire.SameJSON(original, existingInput) {
				return commit, fault(api.CodeConflict, "event ID has different bytes")
			}
			// A new reservation cannot attach another operation/effect to a prior
			// event. The original key replay was already handled above. Linking
			// different keys to exact prior results needs the reply amendment.
			return commit, api.NotImplemented("lb-v2-service", "store.event-receipt-link")
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return commit, fault(api.CodeIntegrity, "cannot inspect event identity")
		}
		if request.Method == "records.append" && event.Kind == "record.appended" {
			var params api.RecordAppendRequest
			var record api.Record
			if err := wire.Decode(request.Params, &params); err != nil {
				return commit, err
			}
			if err := wire.Decode(event.Payload, &record); err != nil {
				return commit, err
			}
			if record.Content != params.Content || record.Collection != params.Collection || record.Origin != "observation" || (record.Collection != "observations" && record.Collection != "reports") {
				return commit, fault(api.CodeForbidden, "record event differs from authenticated append intent")
			}
		}
		if lastSeq >= 1<<53-1 {
			return commit, fault(api.CodeIntegrity, "journal sequence exhausted")
		}
		if event.Seq != 0 || event.Config != s.deps.Config || event.Schema != api.SchemaVersion {
			return commit, wire.Invalid("event config, schema or assigned sequence mismatch")
		}
		if event.OperationID != "" && event.OperationID != proposedID || event.RequestID != "" && event.RequestID != request.RequestID {
			return commit, wire.Invalid("event request correlation mismatch")
		}
		generatedProof := event.Kind == "human.proof.used" && event.Actor == (api.Actor{Kind: "service", ID: s.storeID})
		if !natural && !orgChange && !generatedProof && event.Actor != input.Scope.Actor || event.RequestedBy != input.Scope.Actor {
			return commit, fault(api.CodeForbidden, "event actor must match authenticated transaction principal")
		}
		if input.Scope.Actor.Kind == "lane" && !natural && !orgChange && !laneAuthored {
			if event.LifeID != input.Scope.Actor.LifeID || event.Origin != "observation" || (event.Kind != "record.appended" && event.Kind != "blob.committed") {
				return commit, fault(api.CodeForbidden, "lane event cannot claim authoritative or foreign-life facts")
			}
			if request.Method == "records.append" && event.Kind != "record.appended" ||
				request.Method == "decisions.mutate" && event.Kind != "decision.changed" {
				return commit, fault(api.CodeForbidden, "record submission cannot create authoritative events")
			}
		}
		lastSeq++
		event.Seq, event.RecordedAt = api.Sequence(lastSeq), now
		event.OperationID, event.RequestID = operationID, request.RequestID
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
		if event.Kind == "mail.queued" || event.Kind == "report.submitted" {
			var mail api.Mail
			if err := wire.Decode(event.Payload, &mail); err != nil {
				return commit, err
			}
			if mail.Sender != input.Scope.Actor || mail.QueuedSeq != 0 && mail.QueuedSeq != event.Seq {
				return commit, fault(api.CodeForbidden, "mail sender or queued sequence differs from current operation")
			}
			if event.Kind == "report.submitted" {
				var queued api.Mail
				if err := storedProjection(ctx, tx, "mail", mail.ID, &queued); err != nil {
					return commit, err
				}
				mail.QueuedSeq = queued.QueuedSeq
				if mail.QueuedSeq == 0 || mail.QueuedSeq >= event.Seq {
					return commit, fault(api.CodeIntegrity, "report lost its preceding queue event")
				}
			} else {
				mail.QueuedSeq = event.Seq
			}
			data, err := json.Marshal(mail)
			if err != nil {
				return commit, err
			}
			event.Payload = data
		}
		if event.Origin != "service" && event.Kind != "record.appended" && event.Kind != "blob.committed" {
			return commit, fault(api.CodeForbidden, "observation cannot emit an authoritative event kind")
		}
		data, err := json.Marshal(event)
		if err != nil {
			return commit, wire.Invalid("event cannot be encoded")
		}
		chain = hash(append([]byte(chain), data...))
		if _, err := tx.ExecContext(ctx, "INSERT INTO events VALUES(?,?,?,?,?,?)", lastSeq, string(event.ID), data, original, hash(data), chain); err != nil {
			return commit, fault(api.CodeIntegrity, "cannot append journal event")
		}
		// The TestChild admission event is generated above after the exact
		// staged worker and guards were checked. Its operation is persisted by
		// this transaction below; it does not have a second event projection.
		if request.Method != "grants.test-child" || event.Kind != "operation.accepted" {
			if err := s.project(ctx, tx, event); err != nil {
				return commit, err
			}
		}
		if operation.FirstSeq == 0 {
			operation.FirstSeq = event.Seq
		}
		operation.LastSeq = event.Seq
		if event.LifeID != "" && !cascade {
			if operation.LifeID != "" && operation.LifeID != event.LifeID {
				return commit, wire.Invalid("operation spans different lane lives")
			}
			operation.LifeID, operation.Run = event.LifeID, event.Run
		}
	}
	if err := s.stampAuthority(ctx, tx, input, operationID); err != nil {
		return commit, err
	}
	for _, submitted := range input.Effects {
		effect := submitted
		if !wire.ValidID(string(effect.ID)) || effect.OperationID != proposedID || effectCount(effect) != 1 {
			return commit, wire.Invalid("effect must have one payload and matching operation ID")
		}
		if err := validateEffect(effect); err != nil {
			return commit, err
		}
		if effect.Context.Config != input.Scope.Config ||
			effect.Context.RequestedBy != input.Scope.Actor || effect.Context.CauseRequestID != request.RequestID {
			return commit, fault(api.CodeForbidden, "effect context differs from authenticated cause")
		}
		if reservedID != "" {
			data, err := json.Marshal(effect)
			if err != nil {
				return commit, err
			}
			if err := decodeStored(data, &effect); err != nil {
				return commit, err
			}
			effect.OperationID, effect.Context.CauseOperationID = operationID, operationID
			stampEffectCause(&effect)
		}
		data, err := json.Marshal(effect)
		if err != nil || len(data) > api.MaxFrameBytes {
			return commit, wire.Invalid("invalid bounded effect")
		}
		var previous []byte
		err = tx.QueryRowContext(ctx, "SELECT data FROM effects WHERE id=?", string(effect.ID)).Scan(&previous)
		if err == nil {
			if !wire.SameJSON(data, previous) {
				return commit, fault(api.CodeConflict, "effect ID has different bytes")
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return commit, fault(api.CodeIntegrity, "cannot inspect effect identity")
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO effects(id,operation_id,data) VALUES(?,?,?)", string(effect.ID), string(operationID), data); err != nil {
			return commit, fault(api.CodeIntegrity, "cannot persist outbox intent")
		}
		stateData, err := encodeEffectState(api.EffectRecord{Effect: effect, Generation: 1, State: api.EffectPending, LastSeq: api.Sequence(lastSeq)})
		if err != nil {
			return commit, err
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO effect_states VALUES(?,?)", string(effect.ID), stateData); err != nil {
			return commit, err
		}
	}
	if input.Reply != nil && input.Reply.Error != nil {
		operation.Status, operation.Error = "failed", input.Reply.Error
	}
	data, err := json.Marshal(operation)
	if err != nil {
		return commit, fault(api.CodeIntegrity, "operation encoding failed")
	}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return commit, wire.Invalid("request encoding failed")
	}
	if len(input.RawRequest) != 0 {
		if _, err := wire.DecodeRequest(input.RawRequest); err != nil || !wire.SameJSON(input.RawRequest, requestBytes) {
			return commit, wire.Invalid("raw request differs from authenticated request")
		}
		requestBytes = append([]byte(nil), input.RawRequest...)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO operations VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data WHERE operations.principal=excluded.principal", string(operationID), principal(input.Scope), data); err != nil {
		return commit, fault(api.CodeIntegrity, "cannot persist operation")
	}
	if input.Deferred != nil {
		// Final receipt/reply rows are immutable. Keep the pending binding in
		// the original reservation plus its durable org_apply projection; only
		// measured completion inserts the one final receipt.
		if err := tx.Commit(); err != nil {
			return commit, fault(api.CodeIntegrity, "cannot commit deferred publication")
		}
		s.notifyChanged()
		return api.Commit{Operation: operation, Deferred: input.Deferred}, nil
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO receipts VALUES(?,?,?,?,?,?)", principal(input.Scope), string(request.Method), string(request.IdempotencyKey), string(request.RequestSHA256), requestBytes, data); err != nil {
		return commit, fault(api.CodeIntegrity, "cannot persist idempotency receipt")
	}
	var reply *api.RPCReply
	if input.Deferred == nil {
		reply, err = s.finalReply(ctx, tx, input, operation)
		if err != nil {
			return commit, err
		}
	}
	// Receipt ranges describe this operation's events. The journal head may
	// include unrelated earlier events when this transaction emits none.
	receipt := api.MutationReceipt{Key: requestKey(request), Actor: input.Scope.Actor, Operation: operation, Reply: reply, Deferred: input.Deferred,
		RawRequest: requestBytes, FirstSeq: operation.FirstSeq, LastSeq: operation.LastSeq, RecordedAt: now}
	receipt.SimulatedPresence = operation.SimulatedPresence
	receipt.PolicyGeneration, err = s.operationPolicy(ctx, tx)
	if err != nil {
		return commit, err
	}
	if request.Method == "guidance.select" && reply.Error == nil {
		var guidance api.Guidance
		if err := wire.Decode(reply.Result, &guidance); err != nil {
			return commit, err
		}
		receipt.PolicyGeneration = guidance.PolicyGeneration
	}
	if err := bindReceiptConfig(&receipt, s.deps.Config); err != nil {
		return commit, err
	}
	receiptData, err := json.Marshal(storedReceipt{Config: s.deps.Config, Receipt: receipt})
	if err != nil {
		return commit, err
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO replies VALUES(?,?,?,?)", principal(input.Scope), string(request.Method), string(request.IdempotencyKey), receiptData); err != nil {
		return commit, err
	}
	if input.Deferred == nil {
		if _, err := tx.ExecContext(ctx, "DELETE FROM reservations WHERE principal=? AND method=? AND key=?", principal(input.Scope), string(request.Method), string(request.IdempotencyKey)); err != nil {
			return commit, err
		}
	}
	if err := tx.Commit(); err != nil {
		return commit, fault(api.CodeIntegrity, "state transaction commit failed")
	}
	s.notifyChanged()
	return api.Commit{Reply: reply, Deferred: input.Deferred, Operation: operation, FirstSeq: operation.FirstSeq, LastSeq: operation.LastSeq}, nil
}

func effectCount(effect api.Effect) int {
	value := reflect.ValueOf(effect)
	count := 0
	for i := 0; i < value.NumField(); i++ {
		if value.Type().Field(i).Name != "Context" && value.Field(i).Kind() == reflect.Pointer && !value.Field(i).IsNil() {
			count++
		}
	}
	return count
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Service) scope(ctx context.Context, db queryer, scope api.Scope) error {
	if scope.Config != s.deps.Config || !wire.ValidID(string(scope.Actor.ID)) {
		return fault(api.CodeUnauthenticated, "authenticated configuration scope is required")
	}
	if scope.Connection != nil && api.Methods[scope.Request.Method].Mutation {
		if scope.Frame == nil {
			return fault(api.CodeUnauthenticated, "public mutation lacks its credential-verified frame")
		}
		if err := scope.Frame.Verify(ctx, scope.Connection); err != nil {
			return err
		}
	}
	switch scope.Actor.Kind {
	case "scheduler":
		return api.CheckSchedulerScope(ctx, scope, s.deps.Clock.Now())
	case "service", "watchdog":
		if scope.Connection != nil {
			return fault(api.CodeUnauthenticated, "internal actor cannot arrive from a public endpoint")
		}
		return nil
	case "human":
		if scope.Connection == nil || scope.Connection.Binding().Class != api.EndpointHuman || scope.Connection.Binding().Config != s.deps.Config ||
			scope.Connection.Binding().EndpointGeneration != scope.EndpointGeneration || scope.Connection.Peer() == nil {
			return fault(api.CodeUnauthenticated, "human scope requires its authenticated connection")
		}
		return scope.Connection.Peer().Alive(ctx)
	case "worker":
		if scope.Connection == nil || scope.Connection.Binding().Class != api.EndpointWorker || scope.Connection.Peer() == nil {
			return fault(api.CodeUnauthenticated, "worker requires a live installed worker connection")
		}
		if err := scope.Connection.Peer().Alive(ctx); err != nil {
			return err
		}
		binding := scope.Connection.Binding()
		var lease api.WorkerLease
		if err := storedProjection(ctx, db, "worker_lease", binding.WorkerLeaseID, &lease); err != nil {
			return err
		}
		if lease.Kind == "materialize" {
			// Fixed data jobs have no generic store authority, including when
			// their frame names result.append. Each dedicated handler checks
			// its actual operation through dataWorkerScope instead.
			return fault(api.CodeForbidden, "materialization workers must use dedicated job operations")
		}
		var launch api.LaunchRecord
		if err := projection(ctx, db, "launch", binding.LaunchID, &launch); err != nil {
			return err
		}
		if launch.Config != scope.Config || binding.Config != scope.Config || launch.Actor != scope.Actor || binding.LaunchID != scope.LaunchID || launch.Revoked || lease.ConsumedBy != "" || !future(lease.ExpiresAt, s.deps.Clock.Now()) || lease.Target != launch.Target ||
			binding.Target == nil || *binding.Target != lease.Target || binding.EndpointGeneration != scope.EndpointGeneration {
			return fault(api.CodeUnauthenticated, "worker lease or launch changed")
		}
		if err := s.grantRevocationFence(ctx, db, launch.GrantSetID); err != nil {
			return err
		}
		return launchPeer(ctx, scope.Connection, launch)
	case "lane":
		if scope.LaunchID == "" || scope.Actor.LifeID == "" {
			return fault(api.CodeUnauthenticated, "current launch binding is required")
		}
		var record api.LaunchRecord
		if err := projection(ctx, db, "launch", scope.LaunchID, &record); err != nil {
			var typed *api.Error
			if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
				return fault(api.CodeUnauthenticated, "launch binding is absent")
			}
			return err
		}
		if record.Revoked || record.Target.LifeID != scope.Actor.LifeID || record.Actor != scope.Actor ||
			record.EndpointGeneration != scope.EndpointGeneration || record.Config != scope.Config {
			return fault(api.CodeUnauthenticated, "launch binding is revoked or changed")
		}
		if err := s.grantRevocationFence(ctx, db, record.GrantSetID); err != nil {
			return err
		}
		if scope.Connection != nil {
			binding := scope.Connection.Binding()
			if binding.Class != api.EndpointLane || binding.LaunchID != scope.LaunchID || binding.Target == nil || *binding.Target != record.Target || scope.Connection.Peer() == nil {
				return fault(api.CodeUnauthenticated, "lane connection differs from committed launch")
			}
			if err := scope.Connection.Peer().Alive(ctx); err != nil {
				return err
			}
			if err := launchPeer(ctx, scope.Connection, record); err != nil {
				return err
			}
		}
		return nil
	}
	return fault(api.CodeUnauthenticated, "unknown authenticated principal kind")
}

func launchPeer(ctx context.Context, connection api.ConnectionContext, record api.LaunchRecord) error {
	facts, err := connection.Peer().Facts(ctx)
	if err != nil {
		return err
	}
	// Each CLI child has its own connector process generation, pinned by the
	// transport peer/frame. The launch record pins their shared UID/containment.
	if facts.HostUID != record.HostUID || facts.ContainmentID != record.ContainmentID {
		return fault(api.CodeUnauthenticated, "launch peer UID or containment changed")
	}
	return nil
}

func projection(ctx context.Context, db queryer, kind string, id api.ID, out any) error {
	var data []byte
	err := db.QueryRowContext(ctx, "SELECT data FROM projections WHERE kind=? AND id=?", kind, string(id)).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return fault(api.CodeNotFound, "object is not visible or does not exist")
	}
	if err != nil {
		return fault(api.CodeIntegrity, "cannot read protected projection")
	}
	if err := wire.Decode(data, out); err != nil {
		return fault(api.CodeIntegrity, "invalid protected projection")
	}
	return nil
}

func put(ctx context.Context, tx *sql.Tx, kind string, id api.ID, generation api.Generation, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fault(api.CodeIntegrity, "projection encoding failed")
	}
	if !collectionProjection(kind) {
		if err := rejectCollectedReferences(ctx, tx, data); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO projection_history(kind,id,data,sha256) VALUES(?,?,?,?)", kind, string(id), data, hash(data)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO projections VALUES(?,?,?,?)
 ON CONFLICT(kind,id) DO UPDATE SET generation=excluded.generation,data=excluded.data`, kind, string(id), uint64(generation), data); err != nil {
		return fault(api.CodeIntegrity, "projection update failed")
	}
	return nil
}

func (s *Service) project(ctx context.Context, tx *sql.Tx, event api.Event) error {
	switch event.Kind {
	case "capture.bound", "capture.refused":
		return s.bindCapture(ctx, tx, event)
	case "operation.accepted", "operation.completed", "operation.failed", "worker.completed", "worker.failed":
		return api.NotImplemented("lb-v2-service", "store.effect-completion-contract")
	case "blob.committed":
		var ref api.BlobRef
		if err := wire.Decode(event.Payload, &ref); err != nil {
			return err
		}
		metadata, _, err := objectRow(ctx, tx, ref.ID)
		if err != nil {
			return err
		}
		if metadata.Ref != ref {
			return fault(api.CodeIntegrity, "blob event differs from committed bytes")
		}
		return nil
	case "record.appended", "decision.changed":
		var record api.Record
		if err := wire.Decode(event.Payload, &record); err != nil {
			return err
		}
		if record.Actor != event.Actor || record.LifeID != event.LifeID || record.Origin != event.Origin {
			return fault(api.CodeForbidden, "record provenance does not match its event")
		}
		if event.Actor.Kind == "lane" && (record.LifeID != event.Actor.LifeID || record.Origin != "observation") {
			return fault(api.CodeForbidden, "lane record must remain its own observation")
		}
		var old api.Record
		err := projection(ctx, tx, "record", record.ID, &old)
		if err == nil {
			// Updating a record requires atomic generation comparison support.
			if record.Generation != old.Generation+1 || event.Kind != "decision.changed" {
				return fault(api.CodeConflict, "record generation did not advance")
			}
			return put(ctx, tx, "record", record.ID, record.Generation, record)
		}
		var typed *api.Error
		if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
			return err
		}
		if record.Generation != 1 {
			return fault(api.CodeConflict, "new record generation must be one")
		}
		return put(ctx, tx, "record", record.ID, record.Generation, record)
	case "identity.bound", "identity.revoked":
		if event.Actor.Kind != "service" {
			return fault(api.CodeForbidden, "only the service may project launch identity")
		}
		var record api.LaunchRecord
		if err := wire.Decode(event.Payload, &record); err != nil {
			return err
		}
		if record.Config != s.deps.Config || record.Target.LifeID != event.LifeID || record.Target.Run != event.Run {
			return wire.Invalid("launch binding target mismatch")
		}
		if err := s.checkIdentityAncestry(ctx, tx, record); err != nil {
			return err
		}
		if event.Kind == "identity.revoked" && !record.Revoked {
			return wire.Invalid("revocation must record revoked state")
		}
		if event.Kind == "identity.bound" && record.Revoked {
			return wire.Invalid("new launch binding cannot already be revoked")
		}
		var previous api.LaunchRecord
		err := projection(ctx, tx, "launch", record.ID, &previous)
		if err == nil {
			if previous.Revoked || record.Target != previous.Target || event.Kind != "identity.revoked" {
				return fault(api.CodeConflict, "launch binding cannot be replaced")
			}
			previous.Revoked = true
			before, beforeErr := json.Marshal(previous)
			after, afterErr := json.Marshal(record)
			if beforeErr != nil || afterErr != nil || !wire.SameJSON(before, after) {
				return fault(api.CodeConflict, "revocation cannot change launch identity")
			}
		} else {
			var typed *api.Error
			if !errors.As(err, &typed) || typed.Code != api.CodeNotFound {
				return err
			}
			if event.Kind == "identity.revoked" {
				return fault(api.CodeNotFound, "launch binding does not exist")
			}
		}
		return put(ctx, tx, "launch", record.ID, 1, record)
	case "secret.imported", "secret.rotated", "secret.revoked":
		return s.projectSecret(ctx, tx, event)
	case "grants.issued", "grants.revoked":
		var grant api.GrantEvent
		if err := wire.Decode(event.Payload, &grant); err != nil {
			return err
		}
		if grant.GrantSet.LifeID != event.LifeID {
			return wire.Invalid("grant event target mismatch")
		}
		return put(ctx, tx, "grants", grant.GrantSet.ID, grant.GrantSet.Generation, grant.GrantSet)
	case "lane.created", "lane.adopted", "lane.started", "lane.resumed", "lane.turn", "lane.state", "lane.ended", "lane.lost", "lane.cleaned":
		var lane api.Lane
		if err := storedProjection(ctx, tx, "lane", event.LifeID, &lane); err != nil {
			return err
		}
		if lane.Run != event.Run {
			return fault(api.CodeConflict, "lane event run differs from projection")
		}
		return nil
	case "org.change.proposed", "org.change.approved", "org.change.applied", "org.change.rejected":
		return s.projectChange(ctx, tx, event)
	case "mail.queued", "report.submitted", "mail.delivered", "mail.returned":
		if event.Kind == "mail.queued" || event.Kind == "report.submitted" {
			var mail api.Mail
			if err := wire.Decode(event.Payload, &mail); err != nil {
				return err
			}
			if mail.Sender != event.RequestedBy || mail.QueuedSeq == 0 || mail.Generation == 0 {
				return fault(api.CodeForbidden, "mail projection provenance differs from journal")
			}
			if event.Kind == "report.submitted" {
				var queued api.Mail
				if err := storedProjection(ctx, tx, "mail", mail.ID, &queued); err != nil {
					return err
				}
				if mail.QueuedSeq >= event.Seq || !sameValue(queued, mail) {
					return fault(api.CodeForbidden, "report differs from its original queue event")
				}
				return nil
			}
			if mail.QueuedSeq != event.Seq {
				return fault(api.CodeForbidden, "queue sequence differs from journal")
			}
			return put(ctx, tx, "mail", mail.ID, mail.Generation, mail)
		}
		var receipt api.MailReceipt
		if err := wire.Decode(event.Payload, &receipt); err != nil {
			return err
		}
		var mail api.Mail
		if err := storedProjection(ctx, tx, "mail", receipt.MailID, &mail); err != nil {
			return err
		}
		if receipt.Target.LifeID != mail.RecipientLifeID {
			return fault(api.CodeForbidden, "mail delivery target differs from committed recipient")
		}
		if mail.Status != receipt.Status || mail.LogicalTurnID != receipt.LogicalTurnID {
			return fault(api.CodeConflict, "mail receipt has no matching atomic projection transition")
		}
		return nil
	}
	return nil
}
