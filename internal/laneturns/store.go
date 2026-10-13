package laneturns

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

var storeSchema = []string{
	"CREATE TABLE meta (\n    key TEXT PRIMARY KEY,\n    value TEXT NOT NULL\n)",
	"CREATE TABLE events (\n    seq INTEGER PRIMARY KEY AUTOINCREMENT,\n    id TEXT NOT NULL UNIQUE,\n    kind TEXT NOT NULL,\n    lane TEXT,\n    actor TEXT NOT NULL,\n    occurred_at TEXT,\n    payload TEXT NOT NULL,\n    protocol_version TEXT NOT NULL,\n    recorded_at TEXT NOT NULL,\n    sha256 TEXT NOT NULL\n)",
	"CREATE TABLE lanes (\n    lane TEXT PRIMARY KEY,\n    projection TEXT NOT NULL\n)",
	"CREATE TRIGGER events_no_update BEFORE UPDATE ON events\nBEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND",
	"CREATE TRIGGER events_no_delete BEFORE DELETE ON events\nBEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND",
	"CREATE TRIGGER events_no_replace BEFORE INSERT ON events\nWHEN EXISTS (SELECT 1 FROM events WHERE seq = NEW.seq OR id = NEW.id)\nBEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND",
	"CREATE TRIGGER meta_no_update BEFORE UPDATE ON meta\nBEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND",
	"CREATE TRIGGER meta_no_delete BEFORE DELETE ON meta\nBEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND",
}

const metaLockSQL = "CREATE TRIGGER meta_no_insert BEFORE INSERT ON meta\nBEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND"

type eventStore struct {
	state    *stateDir
	db       *sql.DB
	fileInfo os.FileInfo
}

func openStore(s *stateDir, write bool) (*eventStore, error) {
	if s == nil {
		return nil, nil
	}
	if err := s.checkLocation(); err != nil {
		return nil, err
	}
	lock, err := lockRoot(s.root, ".", 60, "state directory lock", !write, false)
	if err != nil {
		return nil, err
	}
	defer lock.close()
	marker, err := s.marker()
	if err != nil {
		return nil, err
	}
	recorded := obj(marker["store"])
	info, statErr := s.root.Lstat("events.sqlite")
	if statErr != nil && !os.IsNotExist(statErr) {
		return nil, statErr
	}
	if statErr == nil && !info.Mode().IsRegular() {
		return nil, refused("events.sqlite is a symbolic link or not a regular file")
	}
	if recorded != nil && (os.IsNotExist(statErr) || info.Size() == 0) {
		return nil, integrity("the store that the ownership marker records is missing or empty (truncated): %s", filepath.Join(s.path, "events.sqlite"))
	}
	if !write && (os.IsNotExist(statErr) || info.Size() == 0) {
		return nil, nil
	}
	if write && os.IsNotExist(statErr) {
		f, err := regularAt(s.root, "events.sqlite", "the event store", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		f.Close()
		info, err = s.root.Lstat("events.sqlite")
		if err != nil {
			return nil, err
		}
	}
	mode := "rw"
	uri := url.URL{Scheme: "file", Path: filepath.Join(s.path, "events.sqlite")}
	q := url.Values{"mode": {mode}, "_pragma": {"busy_timeout(10000)"}}
	uri.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, integrity("the event store is not readable")
	}
	db.SetMaxOpenConns(1)
	st := &eventStore{state: s, db: db, fileInfo: info}
	ok := false
	defer func() {
		if !ok {
			db.Close()
		}
	}()
	var version, count int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return nil, integrity("the event store is not readable")
	}
	if err = db.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&count); err != nil {
		return nil, integrity("the event store schema is not readable")
	}
	if recorded == nil && version == 0 && count == 0 {
		if !write {
			return nil, nil
		}
		conn, err := db.Conn(context.Background())
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		if _, err = conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
			return nil, storeError(err)
		}
		committed := false
		defer func() {
			if !committed {
				conn.ExecContext(context.Background(), "ROLLBACK")
			}
		}()
		for _, statement := range storeSchema {
			if _, err = conn.ExecContext(context.Background(), statement); err != nil {
				return nil, integrity("the event store schema could not be created")
			}
		}
		id, err := randomID()
		if err != nil {
			return nil, err
		}
		meta := map[string]string{"format": "event-store", "config": s.c.name, "created_at": nowStamp(), "store_id": id}
		for _, key := range []string{"config", "created_at", "format", "store_id"} {
			if _, err = conn.ExecContext(context.Background(), "INSERT INTO meta (key, value) VALUES (?, ?)", key, meta[key]); err != nil {
				return nil, err
			}
		}
		if _, err = conn.ExecContext(context.Background(), metaLockSQL); err != nil {
			return nil, err
		}
		if _, err = conn.ExecContext(context.Background(), "PRAGMA user_version = 1"); err != nil {
			return nil, err
		}
		if _, err = conn.ExecContext(context.Background(), "COMMIT"); err != nil {
			return nil, err
		}
		committed = true
		conn.Close()
		version = 1
	}
	if version != 1 {
		return nil, integrity("the store is not an event store of version 1")
	}
	rows, err := db.Query("SELECT key, value FROM meta")
	if err != nil {
		return nil, integrity("the store metadata is not readable")
	}
	meta := map[string]string{}
	for rows.Next() {
		var key, value string
		if err = rows.Scan(&key, &value); err != nil {
			rows.Close()
			return nil, err
		}
		meta[key] = value
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, key := range []string{"format", "config", "created_at", "store_id"} {
		if _, ok := meta[key]; !ok {
			return nil, integrity("the store metadata is missing a required field")
		}
	}
	if len(meta) != 4 || meta["format"] != "event-store" || meta["config"] != s.c.name || !launchPattern.MatchString(meta["store_id"]) {
		return nil, integrity("the store metadata does not describe an event store of configuration %s", s.c.name)
	}
	if recorded != nil && recorded["id"] != meta["store_id"] {
		return nil, integrity("the store is not the store the ownership marker records")
	}
	if recorded == nil {
		var events int
		if err = db.QueryRow("SELECT count(*) FROM events").Scan(&events); err != nil {
			return nil, err
		}
		if events > 0 {
			return nil, integrity("the store holds events but the ownership marker records no store, so it is not adopted")
		}
		if !write {
			return nil, nil
		}
		if err = s.writeMarker(meta["store_id"], meta["created_at"]); err != nil {
			return nil, err
		}
	}
	ok = true
	return st, nil
}
func (s *eventStore) close() {
	if s != nil {
		s.db.Close()
	}
}
func storeError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "locked") || strings.Contains(strings.ToLower(err.Error()), "busy") {
		return &busyStoreError{&problem{2, "refused", "the store is busy (database is locked): the event could not be appended within its wait; nothing was recorded"}}
	}
	return integrity("the event store could not be read or written")
}
func (s *eventStore) checkFile() error {
	if err := s.state.checkLocation(); err != nil {
		return err
	}
	now, err := s.state.root.Lstat("events.sqlite")
	if err != nil || !now.Mode().IsRegular() || !os.SameFile(now, s.fileInfo) {
		return integrity("the event store changed while it was in use")
	}
	return nil
}
func currentRow(v object) bool {
	base := emptyRow("")
	if v == nil {
		return false
	}
	for k := range base {
		if _, ok := v[k]; !ok {
			return false
		}
	}
	for k := range v {
		if _, ok := base[k]; !ok && k != "mail" && k != "refusals" {
			return false
		}
	}
	times := obj(v["times"])
	if len(times) != 8 {
		return false
	}
	for k := range obj(base["times"]) {
		if _, ok := times[k]; !ok {
			return false
		}
	}
	if m, ok := v["mail"]; ok {
		mail := obj(m)
		if len(mail) != 8 {
			return false
		}
		for _, k := range []string{"turn_based", "idle_seconds", "last", "waiting", "returned", "in_flight", "delivered", "settled"} {
			if _, ok := mail[k]; !ok {
				return false
			}
		}
		if _, ok := mail["turn_based"].(bool); !ok {
			return false
		}
		if !validMailRow(mail, v) {
			return false
		}
	}
	return true
}
func parseRow(data string) (object, error) {
	v, err := decodeJSON([]byte(data))
	if err != nil || !currentRow(v) {
		return nil, integrity("the lane projection is not in this version's form; run state rebuild")
	}
	return v, nil
}
func (s *eventStore) row(lane string) (object, error) {
	if s == nil {
		return nil, nil
	}
	if err := s.checkFile(); err != nil {
		return nil, err
	}
	var data string
	err := s.db.QueryRow("SELECT projection FROM lanes WHERE lane = ?", lane).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, storeError(err)
	}
	return parseRow(data)
}
func (s *eventStore) rows() ([]object, error) {
	result := []object{}
	if s == nil {
		return result, nil
	}
	if err := s.checkFile(); err != nil {
		return nil, err
	}
	rows, err := s.db.Query("SELECT projection FROM lanes ORDER BY lane")
	if err != nil {
		return nil, storeError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var data string
		if err = rows.Scan(&data); err != nil {
			return nil, err
		}
		row, err := parseRow(data)
		if err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}
func (s *eventStore) events(lane, kind string) ([]object, error) {
	found := []object{}
	if s == nil {
		return found, nil
	}
	if err := s.checkFile(); err != nil {
		return nil, err
	}
	rows, err := s.db.Query("SELECT seq, id, kind, lane, actor, occurred_at, payload, protocol_version, recorded_at, sha256 FROM events WHERE (? = '' OR lane = ?) AND (? = '' OR kind = ?) ORDER BY seq", lane, lane, kind, kind)
	if err != nil {
		return nil, storeError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var seq int
		var id, k, actor, payload, protocol, recorded, hash string
		var laneValue, at sql.NullString
		if err = rows.Scan(&seq, &id, &k, &laneValue, &actor, &at, &payload, &protocol, &recorded, &hash); err != nil {
			return nil, err
		}
		p, err := decodeJSON([]byte(payload))
		if err != nil {
			return nil, integrity("event seq %d: stored payload is not valid JSON", seq)
		}
		form, err := canonical(p)
		if err != nil || !bytes.Equal(form, []byte(payload)) {
			return nil, integrity("event seq %d: stored payload is not a canonical JSON object", seq)
		}
		e := object{"seq": seq, "id": id, "kind": k, "lane": nil, "actor": actor, "occurred_at": nil, "payload": p, "protocol_version": protocol, "recorded_at": recorded}
		if laneValue.Valid {
			e["lane"] = laneValue.String
		}
		if at.Valid {
			e["occurred_at"] = at.String
		}
		data, err := canonical(e)
		if err != nil || digest(data) != hash {
			return nil, integrity("event seq %d: stored hash does not match its content", seq)
		}
		e["sha256"] = hash
		found = append(found, e)
	}
	return found, rows.Err()
}
func (s *eventStore) last(lane, kind string) (object, error) {
	all, err := s.events(lane, kind)
	if err != nil || len(all) == 0 {
		return nil, err
	}
	e := all[len(all)-1]
	if strings.HasPrefix(kind, "lane.") {
		if err = checkPayload(kind, obj(e["payload"])); err != nil {
			return nil, integrity("event seq %d: %s; no lane command acts on an event written in an earlier form", integer(e["seq"]), err.Error())
		}
	}
	return e, nil
}
func envelope(kind, lane, actor string, payload object) (object, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	data, err := canonical(payload)
	if err != nil {
		return nil, err
	}
	normalized, err := decodeJSON(data)
	if err != nil {
		return nil, err
	}
	e := object{"id": "ev-" + id, "kind": kind, "lane": nil, "actor": actor, "occurred_at": nowStamp(), "payload": normalized, "protocol_version": protocolVersion}
	if lane != "" {
		e["lane"] = lane
	}
	return e, nil
}
func (s *eventStore) append(e object) (object, error) {
	var err error
	e, err = normalizeEnvelope(e)
	if err != nil {
		return nil, err
	}
	if err := s.checkFile(); err != nil {
		return nil, err
	}
	if err := checkValueCredentials(e, "event", 0); err != nil {
		return nil, err
	}
	kind, lane := str(e["kind"]), str(e["lane"])
	p := obj(e["payload"])
	if strings.HasPrefix(kind, "lane.") {
		if !lanePattern.MatchString(lane) {
			return nil, refused("the event requires a lane")
		}
		if err := checkPayload(kind, p); err != nil {
			return nil, err
		}
	}
	if strings.HasPrefix(kind, "loop.") {
		if err := checkLoopEvent(e); err != nil {
			return nil, err
		}
	}
	if kind == "lane.started" || kind == "lane.adopted" || kind == "lane.resumed" {
		if err := checkBinding(s.state, lane, kind, p); err != nil {
			return nil, err
		}
	}
	if kind == "brief.rendered" {
		if err := checkRendered(s.state, lane, p); err != nil {
			return nil, err
		}
	}
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err = conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return nil, storeError(err)
	}
	committed := false
	defer func() {
		if !committed {
			conn.ExecContext(context.Background(), "ROLLBACK")
		}
	}()
	var existing int
	err = conn.QueryRowContext(context.Background(), "SELECT seq FROM events WHERE id = ?", e["id"]).Scan(&existing)
	if err == nil {
		var data, oldKind, oldLane, oldActor, oldAt, oldProtocol string
		var nullableLane, nullableAt sql.NullString
		err = conn.QueryRowContext(context.Background(), "SELECT kind,lane,actor,occurred_at,payload,protocol_version FROM events WHERE id = ?", e["id"]).Scan(&oldKind, &nullableLane, &oldActor, &nullableAt, &data, &oldProtocol)
		if err != nil {
			return nil, err
		}
		oldLane = nullableLane.String
		oldAt = nullableAt.String
		form, _ := canonical(p)
		if oldKind != kind || oldLane != lane || oldActor != str(e["actor"]) || oldAt != str(e["occurred_at"]) || oldProtocol != str(e["protocol_version"]) || data != string(form) {
			return nil, integrity("an event id already exists with different content")
		}
		return object{"id": e["id"], "seq": existing}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, storeError(err)
	}
	var current object
	if strings.HasPrefix(kind, "lane.") {
		var data string
		err = conn.QueryRowContext(context.Background(), "SELECT projection FROM lanes WHERE lane = ?", lane).Scan(&data)
		if err == nil {
			current, err = parseRow(data)
			if err != nil {
				return nil, err
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return nil, storeError(err)
		}
		if kind == "lane.refusal" || kind == "lane.workaround_suspected" {
			collection, field := "recorded", "refusal"
			if kind == "lane.workaround_suspected" {
				collection = "suspected"
				field = "suspicion"
			}
			entry := obj(obj(refusalState(current)[collection])[str(p[field])])
			if entry != nil {
				var seq int
				var id, oldKind, actor, payload, protocol, recorded, hash string
				var oldLane, at sql.NullString
				err = conn.QueryRowContext(context.Background(), "SELECT seq,id,kind,lane,actor,occurred_at,payload,protocol_version,recorded_at,sha256 FROM events WHERE seq = ?", entry["seq"]).Scan(&seq, &id, &oldKind, &oldLane, &actor, &at, &payload, &protocol, &recorded, &hash)
				if err != nil {
					return nil, integrity("the refusal projection names a missing event")
				}
				oldPayload, err := decodeJSON([]byte(payload))
				if err != nil {
					return nil, err
				}
				old := object{"seq": seq, "id": id, "kind": oldKind, "lane": nil, "actor": actor, "occurred_at": nil, "payload": oldPayload, "protocol_version": protocol, "recorded_at": recorded}
				if oldLane.Valid {
					old["lane"] = oldLane.String
				}
				if at.Valid {
					old["occurred_at"] = at.String
				}
				encoded, err := canonical(old)
				if err != nil || digest(encoded) != hash || oldKind != kind || oldLane.String != lane || oldPayload[field] != p[field] {
					return nil, integrity("the refusal projection does not name the event its identity promises")
				}
				old["sha256"] = hash
				return old, nil
			}
		}
		if err = checkTransition(current, e); err != nil {
			return nil, err
		}
	}
	var seq int
	err = conn.QueryRowContext(context.Background(), "SELECT max(coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'events'), 0), coalesce((SELECT max(seq) FROM events), 0)) + 1").Scan(&seq)
	if err != nil {
		return nil, storeError(err)
	}
	stored := copyObject(e)
	stored["seq"] = seq
	stored["recorded_at"] = nowStamp()
	hashed, err := canonical(stored)
	if err != nil {
		return nil, err
	}
	stored["sha256"] = digest(hashed)
	payload, err := canonical(p)
	if err != nil {
		return nil, err
	}
	_, err = conn.ExecContext(context.Background(), "INSERT INTO events (seq,id,kind,lane,actor,occurred_at,payload,protocol_version,recorded_at,sha256) VALUES (?,?,?,?,?,?,?,?,?,?)", seq, e["id"], kind, e["lane"], e["actor"], e["occurred_at"], string(payload), e["protocol_version"], stored["recorded_at"], stored["sha256"])
	if err != nil {
		return nil, storeError(err)
	}
	if strings.HasPrefix(kind, "lane.") {
		if current == nil {
			current = emptyRow(lane)
		}
		projection := applyEvent(current, stored)
		data, err := canonical(projection)
		if err != nil {
			return nil, err
		}
		if _, err = conn.ExecContext(context.Background(), "INSERT OR REPLACE INTO lanes (lane, projection) VALUES (?, ?)", lane, string(data)); err != nil {
			return nil, storeError(err)
		}
	}
	if _, err = conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return nil, storeError(err)
	}
	committed = true
	return stored, nil
}

type laneSession struct {
	state *stateDir
	store *eventStore
	c     *configuration
}

func openSession(c *configuration, create bool) (*laneSession, error) {
	state, err := openState(c, create)
	if err != nil {
		return nil, err
	}
	s := &laneSession{state: state, c: c}
	s.store, err = openStore(state, false)
	if err != nil {
		state.close()
		return nil, err
	}
	return s, nil
}
func (s *laneSession) close() { s.store.close(); s.state.close() }
func (s *laneSession) refresh() error {
	s.store.close()
	st, err := openStore(s.state, false)
	s.store = st
	return err
}
func (s *laneSession) known(lane string) (object, error) {
	row, err := s.store.row(lane)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, refused("lane %s is not known to configuration %s", lane, s.c.name)
	}
	return row, nil
}
func (s *laneSession) latest(lane string) (object, error) {
	e, err := s.store.last(lane, "lane.started")
	if err != nil {
		return nil, err
	}
	if e == nil {
		e, err = s.store.last(lane, "lane.adopted")
	}
	if err != nil || e == nil {
		return nil, err
	}
	return obj(e["payload"]), nil
}
func (s *laneSession) append(kind, lane, actor string, p object) (object, error) {
	e, err := envelope(kind, lane, actor, p)
	if err != nil {
		return nil, err
	}
	return s.appendEnvelope(e, false)
}
func (s *laneSession) appendEnvelope(e object, draining bool) (object, error) {
	return s.appendEnvelopeWait(e, draining, 10000)
}
func (s *laneSession) appendEnvelopeWait(e object, draining bool, milliseconds int) (object, error) {
	lane := str(e["lane"])
	var lock *fileLock
	if lane != "" && strings.HasPrefix(str(e["kind"]), "lane.") {
		dir, err := s.state.dir("lanes/"+lane, true)
		if err != nil {
			return nil, err
		}
		defer dir.Close()
		lock, err = lockRoot(dir, ".", 60, "lane directory lock", false, false)
		if err != nil {
			return nil, err
		}
		defer lock.close()
		if !draining {
			if err = s.drainLocked(lane, dir); err != nil {
				return nil, err
			}
		}
	}
	st, err := openStore(s.state, true)
	if err != nil {
		return nil, err
	}
	defer st.close()
	if _, err = st.db.Exec("PRAGMA busy_timeout = " + fmtInt(milliseconds)); err != nil {
		return nil, storeError(err)
	}
	return st.append(e)
}
func (s *laneSession) drain(lane string) error {
	dir, err := s.state.dir("lanes/"+lane, false)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	queue, _, err := pendingQueue(dir)
	if err != nil {
		return err
	}
	if len(queue) == 0 {
		return nil
	}
	lock, err := lockRoot(dir, ".", 60, "lane directory lock", false, false)
	if err != nil {
		return err
	}
	defer lock.close()
	if err = s.drainLocked(lane, dir); err != nil {
		return err
	}
	return s.refresh()
}
func (s *laneSession) drainLocked(lane string, dir *os.Root) error {
	queue, asides, err := pendingQueue(dir)
	if err != nil {
		return err
	}
	if len(queue) == 0 {
		return nil
	}
	if len(asides) > 0 {
		if err = writeAtomic(dir, "pending.jsonl", append(bytes.Join(queue, []byte{'\n'}), '\n'), 0600, true); err != nil {
			return err
		}
		for _, name := range asides {
			if err = dir.Remove(name); err != nil {
				return err
			}
		}
	}
	st, err := openStore(s.state, true)
	if err != nil {
		return err
	}
	defer st.close()
	for len(queue) > 0 {
		e, parseErr := decodeJSON(queue[0])
		if parseErr != nil {
			err = archiveRefused(dir, nil, "the line is not an event (not a JSON object)", queue[0])
		} else {
			if str(e["lane"]) != lane {
				return integrity("a pending event names another lane")
			}
			_, err = st.append(e)
			if err != nil {
				var unsupported *unsupportedEventError
				var busy *busyStoreError
				var p *problem
				if errors.As(err, &unsupported) || errors.As(err, &busy) || !errors.As(err, &p) || p.code != 2 {
					return refused("lane %s has %d event(s) waiting to be recorded; nothing is done for it before they are: %s", lane, len(queue), err.Error())
				}
				err = archiveRefused(dir, e, p.message, nil)
			}
		}
		if err != nil {
			return err
		}
		queue = queue[1:]
		if len(queue) == 0 {
			err = dir.Remove("pending.jsonl")
		} else {
			err = writeAtomic(dir, "pending.jsonl", append(bytes.Join(queue, []byte{'\n'}), '\n'), 0600, true)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
func archiveRefused(dir *os.Root, e object, reason string, line []byte) error {
	data, err := readAt(dir, "refused.jsonl", "refused.jsonl", 16*1024*1024)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if e != nil {
		for _, old := range bytes.Split(data, []byte{'\n'}) {
			v, err := decodeJSON(old)
			if err == nil && obj(v["envelope"])["id"] == e["id"] {
				return nil
			}
		}
	}
	entry := object{"envelope": e, "reason": reason}
	if e == nil {
		entry["line"] = string(line)
	}
	encoded, err := canonical(entry)
	if err != nil {
		return err
	}
	return writeAtomic(dir, "refused.jsonl", append(append(data, encoded...), '\n'), 0600, true)
}
func pendingQueue(dir *os.Root) ([][]byte, []string, error) {
	data, err := readAt(dir, "pending.jsonl", "pending.jsonl", 16*1024*1024)
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, err
	}
	queue := [][]byte{}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) > 0 {
			queue = append(queue, line)
		}
	}
	f, err := dir.Open(".")
	if err != nil {
		return nil, nil, err
	}
	entries, err := f.ReadDir(-1)
	f.Close()
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(entries, func(i, j int) bool {
		a, _ := entries[i].Info()
		b, _ := entries[j].Info()
		if a != nil && b != nil && !a.ModTime().Equal(b.ModTime()) {
			return a.ModTime().Before(b.ModTime())
		}
		return entries[i].Name() < entries[j].Name()
	})
	asides := []string{}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "pending-") && strings.HasSuffix(entry.Name(), ".jsonl") {
			extra, err := readAt(dir, entry.Name(), "pending aside", 16*1024*1024)
			if err != nil {
				return nil, nil, err
			}
			for _, line := range bytes.Split(extra, []byte{'\n'}) {
				if len(bytes.TrimSpace(line)) > 0 {
					queue = append(queue, line)
				}
			}
			asides = append(asides, entry.Name())
		}
	}
	return queue, asides, nil
}
func eventRef(e object) object {
	if e == nil {
		return nil
	}
	return object{"id": e["id"], "seq": e["seq"]}
}
func (s *laneSession) record(lane, launch string) (object, error) {
	if !launchPattern.MatchString(launch) {
		return nil, integrity("the run record's launch is invalid")
	}
	data, err := s.state.read("lanes/"+lane+"/runs/"+launch+".json", maxBrief)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	v, err := decodeJSON(data)
	if err != nil || v["launch"] != launch || v["processes"] == nil {
		return nil, integrity("the run record of lane %s launch %s is not a run record", lane, launch)
	}
	return v, nil
}
