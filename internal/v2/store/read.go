package store

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"laneboss.io/laneboss/internal/v2/api"
	"laneboss.io/laneboss/internal/v2/client/wire"
)

type cursor struct {
	Version  int    `json:"version"`
	Store    api.ID `json:"store"`
	Binding  string `json:"binding"`
	Position uint64 `json:"position"`
	Snapshot uint64 `json:"snapshot"`
}

func (s *Service) cursor(scope api.Scope, filter any, token string) (cursor, error) {
	data, err := json.Marshal(struct {
		Config    string         `json:"config"`
		Principal string         `json:"principal"`
		Endpoint  api.Generation `json:"endpoint"`
		Policy    api.Generation `json:"policy"`
		Filter    any            `json:"filter"`
	}{s.deps.Config, principal(scope), scope.EndpointGeneration, scope.PolicyGeneration, filter})
	if err != nil {
		return cursor{}, wire.Invalid("invalid cursor filters")
	}
	binding := hash(data)
	if token == "" {
		return cursor{Version: 1, Store: s.storeID, Binding: binding}, nil
	}
	if len(token) > 4096 {
		return cursor{}, wire.Invalid("cursor exceeds bounds")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return cursor{}, wire.Invalid("invalid cursor")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return cursor{}, wire.Invalid("invalid cursor encoding")
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return cursor{}, wire.Invalid("invalid cursor signature")
	}
	mac := hmac.New(sha256.New, s.key)
	if _, err := mac.Write(payload); err != nil {
		return cursor{}, fault(api.CodeIntegrity, "cursor MAC failed")
	}
	if !hmac.Equal(mac.Sum(nil), signature) {
		return cursor{}, wire.Invalid("cursor authentication failed")
	}
	var current cursor
	if err := wire.Decode(payload, &current); err != nil {
		return current, err
	}
	if current.Version != 1 || current.Store != s.storeID || current.Binding != binding {
		return current, fault(api.CodeCursorExpired, "cursor scope, filters or generation changed")
	}
	return current, nil
}

func (s *Service) signCursor(current cursor) (string, error) {
	data, err := json.Marshal(current)
	if err != nil {
		return "", fault(api.CodeIntegrity, "cursor encoding failed")
	}
	mac := hmac.New(sha256.New, s.key)
	if _, err := mac.Write(data); err != nil {
		return "", fault(api.CodeIntegrity, "cursor MAC failed")
	}
	return base64.RawURLEncoding.EncodeToString(data) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *Service) Operation(ctx context.Context, scope api.Scope, id api.ID) (api.Operation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var operation api.Operation
	if err := s.available(); err != nil {
		return operation, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return operation, err
	}
	db, err := s.reader(scope)
	if err != nil {
		return operation, err
	}
	var owner string
	var data []byte
	err = db.QueryRowContext(ctx, "SELECT principal,data FROM operations WHERE id=?", string(id)).Scan(&owner, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return operation, fault(api.CodeNotFound, "operation is not visible or does not exist")
	}
	if err != nil {
		return operation, fault(api.CodeIntegrity, "cannot read operation")
	}
	if !administrative(scope) && owner != principal(scope) {
		return operation, fault(api.CodeNotFound, "operation is not visible or does not exist")
	}
	if err := wire.Decode(data, &operation); err != nil {
		return operation, fault(api.CodeIntegrity, "invalid operation receipt")
	}
	return operation, nil
}

func administrative(scope api.Scope) bool {
	return scope.Actor.Kind == "human" && scope.Connection != nil || scope.Actor.Kind == "service" && scope.Connection == nil ||
		scope.Actor.Kind == "scheduler" && scope.Connection == nil || watchdogReader(scope)
}

// This authority is created only inside the installed service. Public scopes
// are rejected by scope() before visibility is considered, even if an endpoint
// relabels its actor. A watchdog's internal reads must retain its own principal.
func watchdogReader(scope api.Scope) bool {
	return scope.Actor.Kind == "watchdog" && scope.Connection == nil && scope.Frame == nil && scope.Source == "watchdog" && scope.Request.Method == ""
}

// visibleLife uses only protected launch bindings, never event labels or levels.
func (s *Service) visibleLife(ctx context.Context, scope api.Scope, life api.ID) (bool, error) {
	if administrative(scope) {
		return true, nil
	}
	if life == "" || scope.Actor.Kind != "lane" {
		return false, nil
	}
	if life == scope.Actor.LifeID {
		return true, nil
	}
	db, err := s.reader(scope)
	if err != nil {
		return false, err
	}
	rows, err := db.QueryContext(ctx, "SELECT data FROM projections WHERE kind='launch' AND json_extract(data,'$.target.life_id')=?", string(life))
	if err != nil {
		return false, fault(api.CodeIntegrity, "cannot read starter graph")
	}
	defer rows.Close()
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return false, fault(api.CodeIntegrity, "cannot read starter binding")
		}
		var record api.LaunchRecord
		if err := wire.Decode(data, &record); err != nil {
			return false, fault(api.CodeIntegrity, "invalid starter binding")
		}
		if record.Target.LifeID == life {
			for _, ancestor := range record.StarterChain {
				if ancestor == scope.Actor.LifeID {
					return true, nil
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return false, fault(api.CodeIntegrity, "starter graph read failed")
	}
	return false, nil
}

func (s *Service) Lane(ctx context.Context, scope api.Scope, target api.LifeRef) (api.Lane, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var lane api.Lane
	if err := s.available(); err != nil {
		return lane, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return lane, err
	}
	visible, err := s.visibleLife(ctx, scope, target.LifeID)
	if err != nil {
		return lane, err
	}
	if !visible {
		return lane, api.WithErrorComponent(fault(api.CodeNotFound, "lane is not visible or does not exist"), "store_lane")
	}
	db, err := s.reader(scope)
	if err != nil {
		return lane, err
	}
	err = storedProjection(ctx, db, "lane", target.LifeID, &lane)
	if err == nil && target.Run != 0 && lane.Run != target.Run {
		return api.Lane{}, api.WithErrorComponent(fault(api.CodeNotFound, "selected run is absent"), "store_lane")
	}
	return lane, err
}

func (s *Service) Lanes(ctx context.Context, scope api.Scope, request api.ListRequest) (api.LanePage, error) {
	var page api.LanePage
	values, next, err := s.listProjection(ctx, scope, "lane", request)
	if err != nil {
		return page, err
	}
	page.Lanes, page.Cursor = []api.Lane{}, next
	for _, data := range values {
		var lane api.Lane
		if err := wire.Decode(data, &lane); err != nil {
			return page, err
		}
		page.Lanes = append(page.Lanes, lane)
	}
	return page, nil
}

func (s *Service) Events(ctx context.Context, scope api.Scope, request api.EventTailRequest) (api.EventPage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	page := api.EventPage{Events: []api.Event{}}
	if err := s.available(); err != nil {
		return page, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return page, err
	}
	// A human mutation's own read (lane.check) runs under its exact operation proof, which readScope
	// checked above (operationReadScope); it holds no read session. A human with a session sees every
	// event of the life, so the proof grants that view, for the proof's own lane only (box 78).
	proofRead := false
	if scope.Actor.Kind == "human" && api.Methods[scope.Request.Method].Mutation && scope.Request.Proof != nil {
		target, err := s.authorizationTarget(ctx, s.db, scope, scope.Request)
		if err != nil {
			return page, err
		}
		proofRead = wire.ValidID(string(request.LifeID)) && target.TargetID == request.LifeID
	}
	configurationEvents := request.LifeID == "" && request.Run == 0 && internalScope(scope)
	// Life-scoped reads (no run) are allowed for the watchdog reader (it7) and internal scopes (it3), with a valid life ID.
	lifeEvents := (watchdogReader(scope) || internalScope(scope)) && wire.ValidID(string(request.LifeID)) && request.Run == 0
	if !configurationEvents && !lifeEvents && (!wire.ValidID(string(request.LifeID)) || request.Run == 0) || request.Since > 1<<53-1 {
		return page, wire.Invalid("event read requires selected life and run")
	}
	if request.Until != "" {
		if _, ok := api.EventSchemas[request.Until]; !ok {
			return page, wire.Invalid("unknown terminal event kind")
		}
	}
	if !configurationEvents {
		visible, err := s.visibleLife(ctx, scope, request.LifeID)
		if err != nil {
			return page, err
		}
		if !visible {
			return page, fault(api.CodeNotFound, "selected life is not visible or does not exist")
		}
	}
	filter := request
	filter.Cursor, filter.Follow, filter.DeadlineMS = "", false, 0
	filter.Since = 0
	if request.Cursor != "" && request.Since != 0 {
		return page, wire.Invalid("cursor cannot be combined with since")
	}
	current, err := s.cursor(scope, filter, request.Cursor)
	if err != nil {
		return page, err
	}
	var head uint64
	db, err := s.reader(scope)
	if err != nil {
		return page, err
	}
	// Resolve attach authority before opening the event cursor. The writer
	// has one database connection, so visibility cannot issue nested queries
	// while an unpinned event row iterator holds that connection.
	var attachBinding api.CaptureBinding
	if scope.Request.Method == "lane.attach" && (scope.Actor.Kind == "human" || scope.Actor.Kind == "lane") {
		var raw []byte
		err := db.QueryRowContext(ctx, `SELECT data FROM projections WHERE kind='capture_state'
 AND json_extract(data,'$.binding.target.life_id')=?
 AND json_extract(data,'$.binding.target.run')=?`, string(request.LifeID), uint64(request.Run)).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return page, missingObject()
		}
		if err != nil {
			return page, err
		}
		var state api.CaptureState
		if err := decodeStored(raw, &state); err != nil {
			return page, err
		}
		allowed, err := s.captureReader(ctx, db, scope, state.Binding)
		if err != nil {
			return page, err
		}
		if !allowed {
			return page, missingObject()
		}
		attachBinding = state.Binding
	}
	if err := db.QueryRowContext(ctx, "SELECT coalesce(max(seq),0) FROM events").Scan(&head); err != nil {
		return page, fault(api.CodeIntegrity, "cannot read event snapshot")
	}
	if request.Cursor == "" {
		current.Position = uint64(request.Since)
	}
	// Event cursors are exclusive live positions. New commits after a snapshot
	// remain readable on the next call with the same authenticated cursor.
	current.Snapshot = head
	rows, err := db.QueryContext(ctx, `SELECT seq,data,
 EXISTS(SELECT 1 FROM projections AS mail WHERE mail.kind='mail'
 AND mail.id=json_extract(events.data,'$.payload.mail_id') AND json_extract(mail.data,'$.sender.life_id')=?)
 FROM events WHERE seq>? AND seq<=? AND coalesce(json_extract(data,'$.life_id'),'')=? AND (? OR coalesce(json_extract(data,'$.run'),0)=?) ORDER BY seq LIMIT 1001`,
		string(scope.Actor.LifeID), current.Position, head, string(request.LifeID), lifeEvents, uint64(request.Run))
	if err != nil {
		return page, fault(api.CodeIntegrity, "cannot read journal page")
	}
	defer rows.Close()
	bytes := 0
	scanned := 0
	page.Complete = true
	for rows.Next() {
		scanned++
		if scanned > 1000 {
			page.Complete = false
			break
		}
		var sequence uint64
		var data []byte
		var sentByCaller bool
		if err := rows.Scan(&sequence, &data, &sentByCaller); err != nil {
			return page, fault(api.CodeIntegrity, "cannot decode journal row")
		}
		var event api.Event
		if err := wire.Decode(data, &event); err != nil {
			return page, fault(api.CodeIntegrity, "invalid journal envelope")
		}
		if err := wire.ValidateEvent(event); err != nil {
			return page, fault(api.CodeIntegrity, "invalid journal payload")
		}
		allowed := proofRead
		if !allowed {
			if allowed, err = wire.EventVisible(ctx, scope, event); err != nil {
				return page, err
			}
		}
		// Attach needs the registered binding, whose general event-tail view
		// remains private. Its capture reader set is narrower than tree reads.
		if event.Kind == "capture.bound" && attachBinding.ID != "" {
			var binding api.CaptureBinding
			if err := wire.Decode(event.Payload, &binding); err != nil {
				return page, err
			}
			if !sameValue(binding, attachBinding) {
				return page, fault(api.CodeIntegrity, "attach event differs from its registered capture")
			}
			allowed = true
		}
		if !allowed && scope.Actor.Kind == "lane" && sentByCaller && (event.Kind == "mail.delivered" || event.Kind == "mail.returned") {
			allowed = true
		}
		if !configurationEvents && (event.LifeID != request.LifeID || !lifeEvents && event.Run != request.Run) || !allowed {
			current.Position = sequence
			continue
		}
		// Leave space for the envelope, cursor and JSON expansion. A legal frame
		// too large to page is an explicit error, not an empty successful page.
		if len(data) > api.MaxFrameBytes/2 {
			return page, fault(api.CodeUnsupported, "event exceeds bounded page capacity")
		}
		if len(page.Events) == 200 || bytes+len(data) > api.MaxFrameBytes/2 {
			page.Complete = false
			break
		}
		current.Position = sequence
		page.Events = append(page.Events, event)
		bytes += len(data)
		if request.Until != "" && event.Kind == request.Until && event.Origin == "service" {
			break // Life/run and visibility were checked before until.
		}
	}
	if err := rows.Err(); err != nil {
		return page, fault(api.CodeIntegrity, "journal page read failed")
	}
	page.Cursor, err = s.signCursor(current)
	return page, err
}

func (s *Service) EventVisible(ctx context.Context, scope api.Scope, event api.Event) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return false, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return false, err
	}
	visible, err := wire.EventVisible(ctx, scope, event)
	if err != nil || visible || (event.Kind != "mail.delivered" && event.Kind != "mail.returned") {
		return visible, err
	}
	var receipt api.MailReceipt
	if err := wire.Decode(event.Payload, &receipt); err != nil {
		return false, err
	}
	var mail api.Mail
	db, err := s.reader(scope)
	if err != nil {
		return false, err
	}
	if err := storedProjection(ctx, db, "mail", receipt.MailID, &mail); err != nil {
		return false, err
	}
	return mail.Sender.LifeID == scope.Actor.LifeID, nil
}

func (s *Service) Records(ctx context.Context, scope api.Scope, request api.RecordQuery) (api.RecordPage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	page := api.RecordPage{Records: []api.Record{}}
	if err := s.available(); err != nil {
		return page, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return page, err
	}
	db, err := s.reader(scope)
	if err != nil {
		return page, err
	}
	requestData, err := json.Marshal(request)
	if err != nil {
		return page, wire.Invalid("invalid record query")
	}
	var checked api.RecordQuery
	if err := wire.Decode(requestData, &checked); err != nil || request.Limit < 1 || request.Limit > 200 {
		return page, wire.Invalid("invalid record query or page limit")
	}
	if request.RecordID != "" {
		if request.Query != "" || request.Cursor != "" || request.SearchMode != "keyword" || request.Limit != 1 {
			return page, wire.Invalid("exact record lookup cannot include search or cursor")
		}
		var record api.Record
		err := projection(ctx, db, "record", request.RecordID, &record)
		var typed *api.Error
		if errors.As(err, &typed) && typed.Code == api.CodeNotFound {
			return page, nil
		}
		if err != nil {
			return page, err
		}
		if request.Collection != "" && record.Collection != request.Collection || request.LifeID != "" && record.LifeID != request.LifeID {
			return page, nil
		}
		visible, err := s.visibleRecord(ctx, scope, record)
		if err != nil {
			return page, err
		}
		if visible {
			page.Records = append(page.Records, record)
		}
		return page, nil
	}
	if request.Collection == "" {
		return page, wire.Invalid("record query requires a collection or exact ID")
	}
	if request.SearchMode != "keyword" {
		return page, api.NotImplemented("lb-v2-service", "store.content-search")
	}
	if len(request.Query) > 4096 {
		return page, wire.Invalid("keyword query exceeds its bounded text input")
	}
	filter := request
	filter.Cursor = ""
	current, err := s.cursor(scope, filter, request.Cursor)
	if err != nil {
		return page, err
	}
	if request.Cursor == "" {
		if err := db.QueryRowContext(ctx, "SELECT coalesce(max(rowid),0) FROM projections WHERE kind='record'").Scan(&current.Snapshot); err != nil {
			return page, fault(api.CodeIntegrity, "cannot open record snapshot")
		}
	}
	scanLimit := request.Limit + 1
	if request.Query != "" {
		scanLimit = 1001
	}
	rows, err := db.QueryContext(ctx, `SELECT records.rowid,records.data FROM projections AS records
 WHERE records.kind='record' AND records.rowid>? AND records.rowid<=? AND json_extract(records.data,'$.collection')=?
 AND (?='' OR json_extract(records.data,'$.life_id')=?)
 AND (? OR json_extract(records.data,'$.life_id')=?
 OR (json_extract(records.data,'$.collection')='decisions' AND json_extract(records.data,'$.origin')='service' AND json_extract(records.data,'$.life_id') IS NULL)
 OR EXISTS(SELECT 1 FROM projections AS launches, json_each(launches.data,'$.starter_chain') AS ancestors
 WHERE launches.kind='launch' AND json_extract(launches.data,'$.target.life_id')=json_extract(records.data,'$.life_id') AND ancestors.value=?))
 ORDER BY records.rowid LIMIT ?`, current.Position, current.Snapshot, request.Collection, string(request.LifeID), string(request.LifeID), administrative(scope), string(scope.Actor.LifeID), string(scope.Actor.LifeID), scanLimit)
	if err != nil {
		return page, fault(api.CodeIntegrity, "cannot read records")
	}
	type row struct {
		position uint64
		record   api.Record
	}
	all := make([]row, 0)
	for rows.Next() {
		var position uint64
		var data []byte
		if err := rows.Scan(&position, &data); err != nil {
			closeErr := rows.Close()
			return page, errors.Join(fault(api.CodeIntegrity, "cannot decode record row"), closeErr)
		}
		var record api.Record
		if err := wire.Decode(data, &record); err != nil {
			closeErr := rows.Close()
			return page, errors.Join(fault(api.CodeIntegrity, "invalid record projection"), closeErr)
		}
		all = append(all, row{position, record})
	}
	readErr := rows.Err()
	if closeErr := rows.Close(); readErr != nil || closeErr != nil {
		return page, fault(api.CodeIntegrity, "record page read failed")
	}
	for index, row := range all {
		if len(page.Records) == request.Limit || index == 1000 {
			page.Cursor, err = s.signCursor(current)
			return page, err
		}
		current.Position = row.position
		record := row.record
		if record.Collection != request.Collection || request.LifeID != "" && request.LifeID != record.LifeID {
			continue
		}
		visible, err := s.visibleRecord(ctx, scope, record)
		if err != nil {
			return page, err
		}
		if visible {
			if request.Query != "" {
				metadata, data, err := s.readObjectRow(ctx, scope, db, record.Content.ID)
				if err != nil {
					return page, err
				}
				if metadata.Ref != record.Content {
					return page, fault(api.CodeIntegrity, "record search content differs from its committed reference")
				}
				if !objectVisible(scope, metadata.ACL) || !strings.Contains(strings.ToLower(string(data)), strings.ToLower(request.Query)) {
					continue
				}
			}
			page.Records = append(page.Records, record)
		}
	}
	return page, err
}

func (s *Service) Launch(ctx context.Context, launchID api.ID) (api.LaunchRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var record api.LaunchRecord
	if err := s.available(); err != nil {
		return record, err
	}
	err := projection(ctx, s.db, "launch", launchID, &record)
	return record, err
}

func (s *Service) Grants(ctx context.Context, grantSetID api.ID) (api.GrantSet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var grants api.GrantSet
	if err := s.available(); err != nil {
		return grants, err
	}
	err := projection(ctx, s.db, "grants", grantSetID, &grants)
	return grants, err
}

func (s *Service) Policy(ctx context.Context, scope api.Scope) (api.EffectivePolicy, error) {
	role := api.RoleContext{}
	if scope.Actor.Kind == "lane" {
		lane, err := s.Lane(ctx, scope, api.LifeRef{LifeID: scope.Actor.LifeID})
		if err != nil {
			return api.EffectivePolicy{}, err
		}
		if lane.Level != scope.Actor.Level || lane.Role != scope.Actor.Role {
			return api.EffectivePolicy{}, fault(api.CodeForbidden, "policy role differs from its authenticated life")
		}
		role = api.RoleContext{Level: lane.Level, Role: lane.Role}
	}
	return s.policyForRole(ctx, scope, role)
}

func (s *Service) Mail(ctx context.Context, scope api.Scope, request api.ListRequest) (api.MailPage, error) {
	var page api.MailPage
	values, next, err := s.listProjection(ctx, scope, "mail", request)
	if err != nil {
		return page, err
	}
	page.Messages, page.Cursor = []api.Mail{}, next
	for _, data := range values {
		var mail api.Mail
		if err := wire.Decode(data, &mail); err != nil {
			return page, err
		}
		page.Messages = append(page.Messages, mail)
	}
	return page, nil
}

func (s *Service) Change(ctx context.Context, scope api.Scope, id api.ID) (api.ChangeRequest, error) {
	if scope.Actor.Kind != "human" && !internalScope(scope) && scope.Actor.Level != 6 {
		return api.ChangeRequest{}, fault(api.CodeForbidden, "org changes require human or L6 authority")
	}
	return scopedProjection[api.ChangeRequest](ctx, s, scope, "change", id)
}

func (s *Service) Blob(ctx context.Context, scope api.Scope, request api.BlobReadRequest) (api.BlobChunk, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var chunk api.BlobChunk
	if err := s.available(); err != nil {
		return chunk, err
	}
	if err := s.readScope(ctx, scope); err != nil {
		return chunk, err
	}
	db, err := s.reader(scope)
	if err != nil {
		return chunk, err
	}
	return s.blob(ctx, scope, db, request)
}

// The caller has authenticated scope and holds the store lock. Both ordinary
// reads and the policy writer use this one checked chunk implementation.
func (s *Service) blob(ctx context.Context, scope api.Scope, db queryer, request api.BlobReadRequest) (api.BlobChunk, error) {
	var chunk api.BlobChunk
	if request.Offset < 0 || request.Limit < 1 || request.Limit > api.MaxChunkBytes {
		return chunk, wire.Invalid("invalid object read bounds")
	}
	metadata, data, err := s.readObjectRow(ctx, scope, db, request.ObjectID)
	if err != nil {
		return chunk, err
	}
	visible, err := s.visibleObject(ctx, db, scope, metadata)
	if err != nil {
		return chunk, err
	}
	if !visible {
		return chunk, missingObject()
	}
	if request.Offset > int64(len(data)) {
		return chunk, wire.Invalid("object offset exceeds length")
	}
	end := request.Offset + int64(request.Limit)
	if end > int64(len(data)) {
		end = int64(len(data))
	}
	chunk = api.BlobChunk{ObjectID: request.ObjectID, Offset: request.Offset, Data: append([]byte{}, data[request.Offset:end]...)}
	chunk.SHA256 = api.Digest(hash(chunk.Data))
	return chunk, nil
}

func (s *Service) visibleRecord(ctx context.Context, scope api.Scope, record api.Record) (bool, error) {
	if record.LifeID == "" && record.Collection == "decisions" && record.Origin == "service" && scope.Actor.Kind == "lane" {
		return true, nil
	}
	return s.visibleLife(ctx, scope, record.LifeID)
}

func (s *Service) PendingEffects(ctx context.Context, request api.CursorRequest) ([]api.Effect, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.available(); err != nil {
		return nil, err
	}
	if request.Limit < 1 || request.Limit > 200 {
		return nil, wire.Invalid("effect page limit must be between 1 and 200")
	}
	if request.Cursor != "" {
		return nil, api.NotImplemented("lb-v2-service", "store.outbox-cursor-contract")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT effects.data,effect_states.data FROM effects JOIN effect_states USING(id)
 WHERE json_extract(effect_states.data,'$.Outcome') IS NULL
 AND (json_extract(effect_states.data,'$.ClaimID')='' OR json_extract(effect_states.data,'$.ClaimExpiresAt')<=?)
 ORDER BY effects.seq LIMIT ?`, s.deps.Clock.Now().UTC().Format(timeFormat), request.Limit)
	if err != nil {
		// Preserve the SQL driver's exact cancellation, rather than turning
		// a requested service stop into a retained integrity fault.
		if err == context.Canceled || err == context.DeadlineExceeded {
			return nil, err
		}
		return nil, fault(api.CodeIntegrity, "cannot read durable effects")
	}
	defer rows.Close()
	effects := make([]api.Effect, 0)
	for rows.Next() {
		var data, state []byte
		if err := rows.Scan(&data, &state); err != nil {
			return nil, fault(api.CodeIntegrity, "cannot read effect row")
		}
		var effect api.Effect
		if err := decodeStored(data, &effect); err != nil || validateEffect(effect) != nil {
			return nil, fault(api.CodeIntegrity, "invalid durable effect")
		}
		var record api.EffectRecord
		if err := decodeStored(state, &record); err != nil {
			return nil, err
		}
		if err := validateEffectState(record); err != nil {
			return nil, err
		}
		if !sameValue(effect, record.Effect) {
			return nil, fault(api.CodeIntegrity, "pending effect differs from its immutable intent")
		}
		effects = append(effects, effect)
	}
	if err := rows.Err(); err != nil {
		if err == context.Canceled || err == context.DeadlineExceeded {
			return nil, err
		}
		return nil, fault(api.CodeIntegrity, "durable effect read failed")
	}
	return effects, nil
}
