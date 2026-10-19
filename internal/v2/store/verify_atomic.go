package store

import (
	"context"
	"encoding/json"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

func (s *Service) projectionHistory(ctx context.Context) (map[string][]byte, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT kind,id,data,sha256 FROM projection_history ORDER BY seq")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	latest := make(map[string][]byte)
	for rows.Next() {
		var kind, id, digest string
		var data []byte
		if err := rows.Scan(&kind, &id, &data, &digest); err != nil {
			return nil, err
		}
		if hash(data) != digest {
			return nil, fault(api.CodeIntegrity, "projection history bytes changed")
		}
		if err := api.ValidateObjectJSON(data); err != nil {
			return nil, err
		}
		latest[kind+":"+id] = data
	}
	return latest, rows.Err()
}
func validOperationEvolution(data, initial []byte) bool {
	var current, before api.Operation
	if wire.Decode(data, &current) != nil {
		return false
	}
	if initial == nil {
		return true
	} // Verified against reservations/internal commits below.
	if wire.Decode(initial, &before) != nil {
		return false
	}
	return current.ID == before.ID && current.LifeID == before.LifeID && current.Run == before.Run && (!before.SimulatedPresence || current.SimulatedPresence) && (current.FirstSeq == before.FirstSeq || before.FirstSeq == 0 && current.FirstSeq <= current.LastSeq) && current.LastSeq >= before.LastSeq
}
func (s *Service) verifyAtomicState(ctx context.Context, operations map[api.ID][]byte) error {
	rows, err := s.db.QueryContext(ctx, "SELECT principal,method,key,data FROM replies")
	if err != nil {
		return err
	}
	receipts := make([]api.MutationReceipt, 0)
	references := make(map[api.ID]bool)
	for rows.Next() {
		var owner, method, key string
		var data []byte
		var stored storedReceipt
		if err := rows.Scan(&owner, &method, &key, &data); err != nil {
			rows.Close()
			return err
		}
		if err := decodeStored(data, &stored); err != nil {
			rows.Close()
			return err
		}
		receipt := stored.Receipt
		if stored.Config != s.deps.Config || bindReceiptConfig(&receipt, stored.Config) != nil {
			rows.Close()
			return fault(api.CodeIntegrity, "receipt store configuration changed")
		}
		if receipt.Reply == nil && receipt.Deferred == nil || receipt.Key.Method != api.Method(method) || receipt.Key.IdempotencyKey != api.ID(key) ||
			owner != principal(api.Scope{Actor: receipt.Actor}) || operations[receipt.Operation.ID] == nil {
			rows.Close()
			return fault(api.CodeIntegrity, "exact receipt binding mismatch")
		}
		if receipt.Reply != nil && receipt.Reply.Error == nil {
			if err := wire.ValidateResult(receipt.Key.Method, receipt.Reply.Result); err != nil {
				rows.Close()
				return err
			}
		}
		request, err := wire.DecodeRequest(receipt.RawRequest)
		if err != nil || requestKey(request) != receipt.Key {
			rows.Close()
			return fault(api.CodeIntegrity, "exact receipt raw request mismatch")
		}
		receipts = append(receipts, receipt)
		references[receipt.Operation.ID] = true
	}
	readErr := rows.Err()
	if err := rows.Close(); err != nil {
		return err
	}
	if readErr != nil {
		return readErr
	}
	for _, receipt := range receipts {
		if receipt.Deferred != nil {
			if err := s.validateOrgReceipt(ctx, s.db, receipt); err != nil {
				return err
			}
		}
		var operationData []byte
		if err := s.db.QueryRowContext(ctx, "SELECT operation FROM receipts WHERE principal=? AND method=? AND key=?", principal(api.Scope{Actor: receipt.Actor}), string(receipt.Key.Method), string(receipt.Key.IdempotencyKey)).Scan(&operationData); err != nil {
			return err
		}
		if !sameValue(receipt.Operation, json.RawMessage(operationData)) {
			return fault(api.CodeIntegrity, "exact reply operation mismatch")
		}
		var owner string
		if err := s.db.QueryRowContext(ctx, "SELECT principal FROM operations WHERE id=?", string(receipt.Operation.ID)).Scan(&owner); err != nil {
			return err
		}
		if owner != principal(api.Scope{Actor: receipt.Actor}) {
			return fault(api.CodeIntegrity, "operation principal differs from receipt")
		}
	}
	var receiptCount int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM receipts").Scan(&receiptCount); err != nil {
		return err
	}
	if receiptCount != len(receipts) {
		return fault(api.CodeIntegrity, "receipt and exact reply inventories differ")
	}
	rows, err = s.db.QueryContext(ctx, "SELECT operation_id,principal,request,digest FROM reservations")
	if err != nil {
		return err
	}
	for rows.Next() {
		var id api.ID
		var owner, digest string
		var raw []byte
		if err := rows.Scan(&id, &owner, &raw, &digest); err != nil {
			rows.Close()
			return err
		}
		request, err := wire.DecodeRequest(raw)
		if err != nil || string(request.RequestSHA256) != digest || request.Config != s.deps.Config || operations[id] == nil || owner == "" {
			rows.Close()
			return fault(api.CodeIntegrity, "pending reservation binding changed")
		}
		references[id] = true
	}
	readErr = rows.Err()
	if err := rows.Close(); err != nil {
		return err
	}
	if readErr != nil {
		return readErr
	}
	rows, err = s.db.QueryContext(ctx, "SELECT data FROM projections WHERE kind='internal_commit'")
	if err != nil {
		return err
	}
	for rows.Next() {
		var data []byte
		var saved internalCommit
		if err := rows.Scan(&data); err != nil {
			rows.Close()
			return err
		}
		if err := decodeStored(data, &saved); err != nil {
			rows.Close()
			return err
		}
		if operations[saved.Commit.Operation.ID] == nil {
			rows.Close()
			return fault(api.CodeIntegrity, "internal receipt references an absent operation")
		}
		references[saved.Commit.Operation.ID] = true
	}
	readErr = rows.Err()
	if err := rows.Close(); err != nil {
		return err
	}
	if readErr != nil {
		return readErr
	}
	if err := s.verifyLoopReceipts(ctx, operations, references); err != nil {
		return err
	}
	for id := range operations {
		if !references[id] {
			return fault(api.CodeIntegrity, "operation has no reservation or durable receipt")
		}
	}
	rows, err = s.db.QueryContext(ctx, "SELECT metadata,data FROM objects")
	if err != nil {
		return err
	}
	for rows.Next() {
		var encoded, data []byte
		var metadata api.ObjectMetadata
		if err := rows.Scan(&encoded, &data); err != nil {
			rows.Close()
			return err
		}
		if err := decodeStored(encoded, &metadata); err != nil {
			rows.Close()
			return err
		}
		if metadata.Ref.SHA256 != api.Digest(hash(data)) || metadata.Ref.Bytes != int64(len(data)) || metadata.ACL.Config != s.deps.Config || operations[metadata.SourceOperationID] == nil {
			rows.Close()
			return fault(api.CodeIntegrity, "object bytes or ACL changed")
		}
	}
	readErr = rows.Err()
	if err := rows.Close(); err != nil {
		return err
	}
	if readErr != nil {
		return readErr
	}
	var intents, states int
	if err := s.db.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM effects),(SELECT count(*) FROM effect_states)").Scan(&intents, &states); err != nil {
		return err
	}
	if intents != states {
		return fault(api.CodeIntegrity, "effect intent and claim inventories differ")
	}
	rows, err = s.db.QueryContext(ctx, "SELECT effects.id,effects.data,effect_states.data FROM effects JOIN effect_states USING(id) ORDER BY effects.seq")
	if err != nil {
		return err
	}
	defer rows.Close()
	records := make([]api.EffectRecord, 0, states)
	for rows.Next() {
		var id string
		var original, state []byte
		var effect api.Effect
		var record api.EffectRecord
		if err := rows.Scan(&id, &original, &state); err != nil {
			return err
		}
		if decodeStored(original, &effect) != nil || decodeStored(state, &record) != nil || !sameValue(effect, record.Effect) || string(effect.ID) != id || record.Generation == 0 {
			return fault(api.CodeIntegrity, "effect state differs from immutable intent")
		}
		if err := validateEffectState(record); err != nil {
			return err
		}
		if record.Outcome != nil {
			if err := measuredOutcome(effect, *record.Outcome); err != nil {
				return err
			}
		}
		records = append(records, record)
	}
	readErr = rows.Err()
	if err := rows.Close(); err != nil {
		return err
	}
	if readErr != nil {
		return readErr
	}
	if len(records) != intents {
		return fault(api.CodeIntegrity, "effect claim has no immutable intent")
	}
	type summary struct {
		pending int
		failed  *api.Error
		last    api.Sequence
	}
	byOperation := make(map[api.ID]summary)
	for _, record := range records {
		current := byOperation[record.Effect.OperationID]
		if record.Outcome == nil {
			current.pending++
		} else {
			if record.Outcome.Status == "failed" && current.failed == nil {
				current.failed = record.Outcome.Error
			}
			if record.LastSeq > current.last {
				current.last = record.LastSeq
			}
			var eventData []byte
			if err := s.db.QueryRowContext(ctx, "SELECT data FROM events WHERE seq=?", uint64(record.LastSeq)).Scan(&eventData); err != nil {
				return err
			}
			var event api.Event
			var payload api.OperationEvent
			if wire.Decode(eventData, &event) != nil || wire.Decode(event.Payload, &payload) != nil || event.OperationID != record.Effect.OperationID ||
				payload.Operation.ID != record.Effect.OperationID || payload.Operation.LastSeq != record.LastSeq ||
				event.RequestedBy != record.Effect.Context.RequestedBy || event.RequestID != record.Effect.Context.CauseRequestID {
				return fault(api.CodeIntegrity, "effect completion event lost its causal receipt")
			}
			expectedKind := api.EventKind("operation.accepted")
			if payload.Operation.Status == "succeeded" {
				expectedKind = "operation.completed"
			} else if payload.Operation.Status == "failed" {
				expectedKind = "operation.failed"
			}
			if event.Kind != expectedKind {
				return fault(api.CodeIntegrity, "completion event claims a different operation state")
			}
		}
		byOperation[record.Effect.OperationID] = current
	}
	for id, state := range byOperation {
		var operation api.Operation
		if wire.Decode(operations[id], &operation) != nil || operation.LastSeq < state.last {
			return fault(api.CodeIntegrity, "operation lost its completed effect sequence")
		}
		expected := "succeeded"
		waitsForReview, err := s.reviewWaitsForReply(ctx, s.db, id)
		if err != nil {
			return err
		}
		if state.pending != 0 || waitsForReview {
			expected = "pending"
		}
		if state.failed != nil {
			expected = "failed"
		}
		if operation.Status != expected || !sameValue(operation.Error, state.failed) {
			return fault(api.CodeIntegrity, "operation status differs from measured effect outcomes")
		}
	}
	return s.verifyOrgApplies(ctx)
}
