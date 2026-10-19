package store

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

// Verify reports measured state; a failed invariant is an integrity error and
// cannot be converted into a successful empty manifest or an automatic repair.
func (s *Service) Verify(ctx context.Context, request api.VerifyRequest) (api.Verification, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := api.Verification{Problems: []string{}}
	if err := s.available(); err != nil {
		return result, err
	}
	if request.Scope != "all" || request.ObjectID != "" {
		return result, api.NotImplemented("lb-v2-service", "store.partial-verification")
	}
	broken := func(message string) (api.Verification, error) {
		result.Problems = append(result.Problems, message)
		return result, fault(api.CodeIntegrity, message)
	}
	var verdict string
	if err := s.verifyFiles(); err != nil {
		return broken("state filesystem privacy changed")
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&verdict); err != nil || verdict != "ok" {
		return broken("SQLite integrity check failed")
	}
	if err := s.verifySchema(ctx); err != nil {
		return broken("store schema or immutable triggers changed")
	}
	rows, err := s.db.QueryContext(ctx, "SELECT seq,id,data,input,sha256,chain FROM events ORDER BY seq")
	if err != nil {
		return broken("journal verification read failed")
	}
	expected := make(map[string][]byte)
	chain := ""
	for rows.Next() {
		var sequence uint64
		var id, digest, savedChain string
		var data, input []byte
		if err := rows.Scan(&sequence, &id, &data, &input, &digest, &savedChain); err != nil {
			if closeErr := rows.Close(); closeErr != nil {
				return broken("journal verification close failed")
			}
			return broken("journal verification row failed")
		}
		var event api.Event
		if err := wire.Decode(data, &event); err != nil || wire.ValidateEvent(event) != nil ||
			event.Seq != api.Sequence(result.Events+1) || uint64(event.Seq) != sequence ||
			string(event.ID) != id || event.Config != s.deps.Config || hash(data) != digest {
			if closeErr := rows.Close(); closeErr != nil {
				return broken("invalid journal close failed")
			}
			return broken("journal envelope, bytes or sequence mismatch")
		}
		if _, err := wire.Parse(input); err != nil {
			if closeErr := rows.Close(); closeErr != nil {
				return broken("invalid source close failed")
			}
			return broken("journal source bytes are invalid")
		}
		chain = hash(append([]byte(chain), data...))
		if chain != savedChain {
			if closeErr := rows.Close(); closeErr != nil {
				return broken("journal chain close failed")
			}
			return broken("journal hash chain mismatch")
		}
		switch event.Kind {
		case "record.appended", "decision.changed":
			var record api.Record
			if err := wire.Decode(event.Payload, &record); err != nil {
				if closeErr := rows.Close(); closeErr != nil {
					return broken("invalid record close failed")
				}
				return broken("journal record payload mismatch")
			}
			expected["record:"+string(record.ID)] = event.Payload
		case "identity.bound", "identity.revoked":
			var record api.LaunchRecord
			if err := wire.Decode(event.Payload, &record); err != nil {
				if closeErr := rows.Close(); closeErr != nil {
					return broken("invalid launch close failed")
				}
				return broken("journal launch payload mismatch")
			}
			expected["launch:"+string(record.ID)] = event.Payload
		}
		result.Events++
	}
	readErr := rows.Err()
	if closeErr := rows.Close(); readErr != nil || closeErr != nil {
		return broken("journal verification did not finish")
	}
	history, err := s.projectionHistory(ctx)
	if err != nil {
		return broken("projection history is invalid")
	}
	rows, err = s.db.QueryContext(ctx, "SELECT kind,id,data FROM projections")
	if err != nil {
		return broken("projection verification read failed")
	}
	for rows.Next() {
		var kind, id string
		var data []byte
		if err := rows.Scan(&kind, &id, &data); err != nil || !sameStoredJSON(data, history[kind+":"+id]) ||
			(expected[kind+":"+id] != nil && !sameStoredJSON(data, expected[kind+":"+id])) {
			if closeErr := rows.Close(); closeErr != nil {
				return broken("invalid projection close failed")
			}
			return broken("projection disagrees with committed events")
		}
		delete(expected, kind+":"+id)
		delete(history, kind+":"+id)
		result.Objects++
	}
	readErr = rows.Err()
	if closeErr := rows.Close(); readErr != nil || closeErr != nil || len(expected) != 0 || len(history) != 0 {
		return broken("projection inventory disagrees with committed events")
	}
	rows, err = s.db.QueryContext(ctx, "SELECT principal,method,key,digest,request,operation FROM receipts")
	if err != nil {
		return broken("receipt verification read failed")
	}
	operations := make(map[api.ID][]byte)
	for rows.Next() {
		var owner, method, key, digest string
		var requestData, operationData []byte
		if err := rows.Scan(&owner, &method, &key, &digest, &requestData, &operationData); err != nil {
			if closeErr := rows.Close(); closeErr != nil {
				return broken("invalid receipt close failed")
			}
			return broken("receipt verification row failed")
		}
		request, requestErr := wire.DecodeRequest(requestData)
		var operation api.Operation
		operationErr := wire.Decode(operationData, &operation)
		if requestErr != nil || operationErr != nil || owner == "" || string(request.Method) != method ||
			string(request.IdempotencyKey) != key || string(request.RequestSHA256) != digest ||
			request.Config != s.deps.Config || !api.Methods[request.Method].Mutation ||
			operation.LastSeq < operation.FirstSeq || uint64(operation.LastSeq) > result.Events {
			if closeErr := rows.Close(); closeErr != nil {
				return broken("invalid receipt content close failed")
			}
			return broken("idempotency receipt content mismatch")
		}
		if _, exists := operations[operation.ID]; exists {
			if closeErr := rows.Close(); closeErr != nil {
				return broken("duplicate operation close failed")
			}
			return broken("operation has duplicate reservation")
		}
		operations[operation.ID] = operationData
		result.Objects++
	}
	readErr = rows.Err()
	if closeErr := rows.Close(); readErr != nil || closeErr != nil {
		return broken("receipt verification did not finish")
	}
	rows, err = s.db.QueryContext(ctx, "SELECT id,data FROM operations")
	if err != nil {
		return broken("operation verification read failed")
	}
	for rows.Next() {
		var id api.ID
		var data []byte
		if err := rows.Scan(&id, &data); err != nil || !validOperationEvolution(data, operations[id]) {
			if closeErr := rows.Close(); closeErr != nil {
				return broken("invalid operation close failed")
			}
			return broken("operation and receipt disagree")
		}
		operations[id] = data
		result.Objects++
	}
	readErr = rows.Err()
	if closeErr := rows.Close(); readErr != nil || closeErr != nil {
		return broken("operation inventory disagrees with receipts")
	}
	rows, err = s.db.QueryContext(ctx, "SELECT id,operation_id,data FROM effects")
	if err != nil {
		return broken("outbox verification read failed")
	}
	for rows.Next() {
		var id, operationID api.ID
		var data []byte
		var effect api.Effect
		if err := rows.Scan(&id, &operationID, &data); err != nil || decodeStored(data, &effect) != nil ||
			effect.ID != id || effect.OperationID != operationID || operations[operationID] == nil || validateEffect(effect) != nil {
			if closeErr := rows.Close(); closeErr != nil {
				return broken("invalid outbox close failed")
			}
			return broken("outbox effect content mismatch")
		}
		result.Objects++
	}
	readErr = rows.Err()
	if closeErr := rows.Close(); readErr != nil || closeErr != nil {
		return broken("outbox verification did not finish")
	}
	if err := s.verifyAtomicState(ctx, operations); err != nil {
		return broken("atomic receipt, object or effect state disagrees")
	}
	if err := s.verifyDispatch(ctx); err != nil {
		return broken("durable dispatch barrier disagrees with freeze receipt")
	}
	if err := s.verifyLaunchState(ctx); err != nil {
		return broken("retained launch or capture state disagrees with its original evidence")
	}
	if err := s.verifyFrames(ctx); err != nil {
		return broken("derived capture frames disagree with their original ranges")
	}
	if err := s.verifyDelegationState(ctx); err != nil {
		return broken("delegation lease authority verification failed")
	}
	if err := s.verifyCredentialProjections(ctx); err != nil {
		return broken("credential projection metadata or reverse index disagrees")
	}
	if err := s.verifySecretMetadata(ctx); err != nil {
		return broken("secret metadata disagrees with its immutable journal")
	}
	if err := s.verifyCleanupOutbox(ctx); err != nil {
		return broken("failed-plan cleanup outbox disagrees with its committed plan")
	}
	if err := s.verifyArchives(ctx); err != nil {
		return broken("archive jobs disagree with their retained bytes or atomic completion")
	}
	if err := s.verifyReviews(ctx); err != nil {
		return broken("review jobs disagree with their retained source, input or measured result")
	}
	if err := s.verifyCollections(ctx); err != nil {
		return broken("collection journals disagree with their retained bytes or atomic completion")
	}
	result.OK = true
	return result, nil
}

func (s *Service) verifySchema(ctx context.Context) error {
	return verifySchemaDDL(ctx, s.db, ddl)
}

func verifySchemaDDL(ctx context.Context, db queryer, source string) error {
	expectedObjects := 0
	for _, statement := range strings.Split(source, ";\n") {
		statement = strings.TrimSpace(statement)
		words := strings.Fields(statement)
		if len(words) < 3 || words[0] != "CREATE" {
			continue
		}
		expectedObjects++
		kind, name := strings.ToLower(words[1]), words[2]
		var stored string
		if err := db.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type=? AND name=?", kind, name).Scan(&stored); err != nil {
			return fault(api.CodeIntegrity, "store schema object is missing")
		}
		if strings.TrimSuffix(strings.TrimSpace(stored), ";") != strings.TrimSuffix(statement, ";") {
			return fault(api.CodeIntegrity, "store schema object changed")
		}
	}
	var actualObjects int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE substr(name,1,7)<>'sqlite_'").Scan(&actualObjects); err != nil || actualObjects != expectedObjects {
		return fault(api.CodeIntegrity, "unexpected store schema object")
	}
	return nil
}

func validateEffect(effect api.Effect) error {
	if !wire.ValidID(string(effect.ID)) || !wire.ValidID(string(effect.OperationID)) || effectCount(effect) != 1 {
		return wire.Invalid("effect requires one payload and valid identity")
	}
	if effect.Context == nil {
		return wire.Invalid("effect requires durable causality context")
	}
	if err := api.ValidateTransactionShape(api.Transaction{
		Scope: api.Scope{Config: effect.Context.Config}, Internal: effect.Context, Effects: []api.Effect{effect},
	}); err != nil {
		return err
	}
	intent := effect.Context
	for _, actor := range []api.Actor{intent.Actor, intent.RequestedBy} {
		encoded, err := json.Marshal(actor)
		if err != nil {
			return err
		}
		var checked api.Actor
		if err := wire.Decode(encoded, &checked); err != nil {
			return err
		}
	}
	if err := api.ValidateTransactionShape(api.Transaction{
		Scope: api.Scope{Config: intent.Config}, Internal: intent,
	}); err != nil {
		return err
	}
	if !wire.ValidID(string(intent.ID)) || !wire.ValidID(intent.Config) ||
		intent.CauseOperationID != effect.OperationID || intent.EffectID != effect.ID ||
		!wire.ValidID(string(intent.CauseRequestID)) || !wire.ValidID(string(intent.Target.LifeID)) || intent.Target.Run == 0 && !queuedMailEffect(effect) {
		return wire.Invalid("effect context does not match durable causality")
	}
	value := reflect.ValueOf(effect)
	for i := 0; i < value.NumField(); i++ {
		if value.Type().Field(i).Name == "Context" {
			continue
		}
		field := value.Field(i)
		if field.Kind() == reflect.Pointer && !field.IsNil() {
			data, err := json.Marshal(field.Interface())
			if err != nil {
				return wire.Invalid("effect payload cannot be encoded")
			}
			return api.DecodeObject(data, reflect.New(field.Type().Elem()).Interface())
		}
	}
	return wire.Invalid("effect payload is missing")
}
