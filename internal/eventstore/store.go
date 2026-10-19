package eventstore

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	_ "modernc.org/sqlite"
)

type schemaObject struct{ kind, name, table, statement string }

var schema = []schemaObject{
	{"table", "meta", "meta", "CREATE TABLE meta (\n    key TEXT PRIMARY KEY,\n    value TEXT NOT NULL\n)"},
	{"table", "events", "events", "CREATE TABLE events (\n    seq INTEGER PRIMARY KEY AUTOINCREMENT,\n    id TEXT NOT NULL UNIQUE,\n    kind TEXT NOT NULL,\n    lane TEXT,\n    actor TEXT NOT NULL,\n    occurred_at TEXT,\n    payload TEXT NOT NULL,\n    protocol_version TEXT NOT NULL,\n    recorded_at TEXT NOT NULL,\n    sha256 TEXT NOT NULL\n)"},
	{"table", "lanes", "lanes", "CREATE TABLE lanes (\n    lane TEXT PRIMARY KEY,\n    projection TEXT NOT NULL\n)"},
	{"trigger", "events_no_update", "events", "CREATE TRIGGER events_no_update BEFORE UPDATE ON events\nBEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND"},
	{"trigger", "events_no_delete", "events", "CREATE TRIGGER events_no_delete BEFORE DELETE ON events\nBEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND"},
	{"trigger", "events_no_replace", "events", "CREATE TRIGGER events_no_replace BEFORE INSERT ON events\nWHEN EXISTS (SELECT 1 FROM events WHERE seq = NEW.seq OR id = NEW.id)\nBEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND"},
	{"trigger", "meta_no_update", "meta", "CREATE TRIGGER meta_no_update BEFORE UPDATE ON meta\nBEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND"},
	{"trigger", "meta_no_delete", "meta", "CREATE TRIGGER meta_no_delete BEFORE DELETE ON meta\nBEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND"},
	{"trigger", "meta_no_insert", "meta", "CREATE TRIGGER meta_no_insert BEFORE INSERT ON meta\nBEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND"},
}

const columns = "seq, id, kind, lane, actor, occurred_at, payload, protocol_version, recorded_at, sha256"

var envelopeFields = []string{"id", "kind", "lane", "actor", "occurred_at", "payload", "protocol_version"}

type Store struct {
	Dir        *Directory
	db         *sql.DB
	connection *sql.Conn
	Meta       Object
}

func database(path, mode string) (*Store, error) {
	uri := url.URL{Scheme: "file", Path: path, RawQuery: "mode=" + mode}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, Integrity("the event store is not readable")
	}
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(context.Background())
	if err != nil {
		db.Close()
		return nil, Integrity("the event store is not readable")
	}
	s := &Store{db: db, connection: conn}
	if _, err = conn.ExecContext(context.Background(), "PRAGMA busy_timeout = 10000"); err != nil {
		s.Close()
		return nil, Integrity("the event store is not readable")
	}
	return s, nil
}
func (s *Store) Close() { s.connection.Close(); s.db.Close() }
func (s *Store) exec(query string, args ...any) error {
	_, err := s.connection.ExecContext(context.Background(), query, args...)
	if err != nil {
		return Integrity("SQLite operation failed in the event store")
	}
	return nil
}
func (s *Store) scalar(query string, args ...any) (int64, error) {
	var n int64
	err := s.connection.QueryRowContext(context.Background(), query, args...).Scan(&n)
	if err != nil {
		return 0, Integrity("the event store is not readable")
	}
	return n, nil
}
func (s *Store) rollback() { s.connection.ExecContext(context.Background(), "ROLLBACK") }

func (s *Store) identity() (Object, error) {
	if err := s.exec("BEGIN"); err != nil {
		return nil, err
	}
	defer s.rollback()
	version, err := s.scalar("PRAGMA user_version")
	if err != nil {
		return nil, err
	}
	count, err := s.scalar("SELECT count(*) FROM sqlite_master")
	if err != nil {
		return nil, err
	}
	if version == 0 && count == 0 {
		return nil, nil
	}
	if version != 1 {
		return nil, Integrity("the store is not an event store of version 1")
	}
	return s.metadata()
}
func (s *Store) metadata() (Object, error) {
	rows, err := s.connection.QueryContext(context.Background(), "SELECT key, value FROM meta")
	if err != nil {
		return nil, Integrity("the store metadata is not readable")
	}
	defer rows.Close()
	meta := Object{}
	for rows.Next() {
		var k, v string
		if err = rows.Scan(&k, &v); err != nil {
			return nil, Integrity("the store metadata is not readable")
		}
		meta[k] = v
	}
	if rows.Err() != nil {
		return nil, Integrity("the store metadata is not readable")
	}
	return meta, nil
}
func (s *Store) check(expected string) error {
	meta, err := s.identity()
	if err != nil {
		return err
	}
	if meta == nil {
		return Integrity("the file has no event store schema")
	}
	if len(meta) != 4 || meta["format"] != "event-store" || meta["config"] == nil || meta["created_at"] == nil || meta["store_id"] == nil {
		return Integrity("the store metadata does not describe an event store")
	}
	if meta["config"] != s.Dir.Config.Name {
		owner := "another"
		if nameGrammar.MatchString(text(meta["config"])) {
			owner = shown(text(meta["config"]))
		}
		return Integrity("the store belongs to configuration %s, not %s", owner, shown(s.Dir.Config.Name))
	}
	if expected != "" && meta["store_id"] != expected {
		return Integrity("the file is not the store the ownership marker records")
	}
	s.Meta = meta
	return nil
}
func (s *Store) initialize() error {
	if err := s.exec("BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer s.rollback()
	version, err := s.scalar("PRAGMA user_version")
	if err != nil {
		return err
	}
	if version == 0 {
		count, err := s.scalar("SELECT count(*) FROM sqlite_master")
		if err != nil {
			return err
		}
		if count != 0 {
			return Integrity("the file is not an event store")
		}
		for _, entry := range schema[:len(schema)-1] {
			if err = s.exec(entry.statement); err != nil {
				return err
			}
		}
		id, err := randomID()
		if err != nil {
			return err
		}
		meta := Object{"format": "event-store", "config": s.Dir.Config.Name, "created_at": now(), "store_id": id}
		for _, key := range []string{"config", "created_at", "format", "store_id"} {
			if err = s.exec("INSERT INTO meta (key, value) VALUES (?, ?)", key, meta[key]); err != nil {
				return err
			}
		}
		if err = s.exec(schema[len(schema)-1].statement); err != nil {
			return err
		}
		if err = s.exec("PRAGMA user_version = 1"); err != nil {
			return err
		}
	}
	if err = s.exec("COMMIT"); err != nil {
		return err
	}
	return s.check("")
}

// Open never adopts an unrecorded store with content or recreates a recorded store.
func Open(d *Directory, write bool) (*Store, error) {
	if d == nil {
		return nil, nil
	}
	unlock, err := d.Lock(!write)
	if err != nil {
		return nil, err
	}
	defer unlock()
	marker, err := d.Marker()
	if err != nil {
		return nil, err
	}
	info, err := d.StoreInfo()
	if err != nil {
		return nil, err
	}
	recorded := object(marker["store"])
	if recorded != nil {
		if info == nil {
			return nil, Integrity("the store that the ownership marker records is missing")
		}
		if info.Size() == 0 {
			return nil, Integrity("the store that the ownership marker records is empty (truncated)")
		}
		s, err := database(filepath.Join(d.Path, storeFile), "rw")
		if err != nil {
			return nil, err
		}
		s.Dir = d
		if err = s.check(text(recorded["id"])); err != nil {
			s.Close()
			return nil, err
		}
		return s, nil
	}
	var store *Store
	if info != nil && info.Size() > 0 {
		store, err = database(filepath.Join(d.Path, storeFile), "rw")
		if err != nil {
			return nil, err
		}
		store.Dir = d
		meta, e := store.identity()
		if e != nil {
			store.Close()
			return nil, e
		}
		if meta == nil {
			store.Close()
			store = nil
		} else {
			if e = store.check(""); e != nil {
				store.Close()
				return nil, e
			}
			count, e := store.scalar("SELECT count(*) FROM events")
			if e != nil {
				store.Close()
				return nil, e
			}
			if count > 0 {
				store.Close()
				return nil, Integrity("the event store holds events but the ownership marker records no store, so it is not adopted")
			}
		}
	}
	if !write {
		if store != nil {
			store.Close()
		}
		return nil, nil
	}
	if marker == nil {
		if err = d.RecordStore("", ""); err != nil {
			if store != nil {
				store.Close()
			}
			return nil, err
		}
	}
	if store == nil {
		store, err = database(filepath.Join(d.Path, storeFile), "rwc")
		if err != nil {
			return nil, err
		}
		store.Dir = d
		if err = store.initialize(); err != nil {
			store.Close()
			return nil, err
		}
	}
	if err = d.RecordStore(text(store.Meta["store_id"]), text(store.Meta["created_at"])); err != nil {
		store.Close()
		return nil, err
	}
	return store, nil
}

func envelope(e Object) Object {
	m := Object{}
	for _, k := range envelopeFields {
		m[k] = e[k]
	}
	return m
}
func eventHash(e Object) string {
	m := envelope(e)
	m["seq"] = e["seq"]
	m["recorded_at"] = e["recorded_at"]
	return digest([]byte(Canonical(m)))
}

type scanner interface{ Scan(...any) error }

func rowEvent(row scanner) (Object, error) {
	e, err := eventContent(row)
	if err != nil {
		return nil, err
	}
	if where, rule := credentialValue(e); rule != "" {
		return nil, Integrity("event seq %d: %s looks like a credential (%s)", num(e["seq"]), where, rule)
	}
	return e, nil
}

// eventContent is the shared integrity reader. Display readers screen values
// after verification; command readers also reject stored credentials.
func eventContent(row scanner) (Object, error) {
	var seq int64
	var id, kind, actor, payload, protocol, recorded, hash string
	var lane, occurred sql.NullString
	if err := row.Scan(&seq, &id, &kind, &lane, &actor, &occurred, &payload, &protocol, &recorded, &hash); err != nil {
		return nil, Integrity("the event store contains an unreadable event")
	}
	p, err := Parse([]byte(payload), "the stored payload")
	if err != nil {
		return nil, Integrity("event seq %d: stored payload is not valid JSON", seq)
	}
	e := Object{"seq": seq, "id": id, "kind": kind, "lane": nil, "actor": actor, "occurred_at": nil, "payload": p, "protocol_version": protocol, "recorded_at": recorded, "sha256": hash}
	if lane.Valid {
		e["lane"] = lane.String
	}
	if occurred.Valid {
		e["occurred_at"] = occurred.String
	}
	if object(p) == nil || Canonical(p) != payload {
		return nil, Integrity("event seq %d: stored payload is not a canonical JSON object", seq)
	}
	if eventHash(e) != hash {
		return nil, Integrity("event seq %d: stored hash does not match its content", seq)
	}
	return e, nil
}
func (s *Store) Events(since int64) ([]Object, error) {
	rows, err := s.connection.QueryContext(context.Background(), "SELECT "+columns+" FROM events WHERE seq > ? ORDER BY seq", since)
	if err != nil {
		return nil, Integrity("the event store is not readable")
	}
	defer rows.Close()
	found := []Object{}
	for rows.Next() {
		e, err := rowEvent(rows)
		if err != nil {
			return nil, err
		}
		found = append(found, e)
	}
	if rows.Err() != nil {
		return nil, Integrity("the event store is not readable")
	}
	return found, nil
}
func (s *Store) findEvent(field string, value any) (Object, error) {
	rows, err := s.connection.QueryContext(context.Background(), "SELECT "+columns+" FROM events WHERE "+field+" = ?", value)
	if err != nil {
		return nil, Integrity("the event store is not readable")
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return nil, Integrity("the event store is not readable")
		}
		return nil, nil
	}
	return rowEvent(rows)
}
func projection(textValue string) (Object, error) {
	v, err := Parse([]byte(textValue), "the lane projection")
	if err != nil {
		return nil, Integrity("the lane projection is not readable; run state rebuild")
	}
	if !currentForm(object(v)) {
		return nil, Integrity("the lane projection is not in this version's form; run state rebuild")
	}
	if _, rule := credentialValue(v); rule != "" {
		return nil, Integrity("the lane projection looks like a credential; run state rebuild")
	}
	return object(v), nil
}
func (s *Store) Lane(lane string) (Object, error) {
	var value string
	err := s.connection.QueryRowContext(context.Background(), "SELECT projection FROM lanes WHERE lane = ?", lane).Scan(&value)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, Integrity("the lane projection is not readable")
	}
	return projection(value)
}
func (s *Store) Lanes() ([]Object, error) {
	rows, err := s.connection.QueryContext(context.Background(), "SELECT projection FROM lanes ORDER BY lane")
	if err != nil {
		return nil, Integrity("the lane projection is not readable")
	}
	defer rows.Close()
	result := []Object{}
	for rows.Next() {
		var value string
		if rows.Scan(&value) != nil {
			return nil, Integrity("the lane projection is not readable")
		}
		p, err := projection(value)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	if rows.Err() != nil {
		return nil, Integrity("the lane projection is not readable")
	}
	return result, nil
}
func receipt(e Object, duplicate bool) Object {
	return Object{"id": e["id"], "seq": e["seq"], "recorded_at": e["recorded_at"], "sha256": e["sha256"], "duplicate": duplicate}
}

func (s *Store) Append(value any) (Object, error) {
	e, err := Validate(value)
	if err != nil {
		return nil, err
	}
	if e["kind"] == "brief.rendered" {
		if err = CheckRendered(e, s.Dir); err != nil {
			return nil, err
		}
	}
	kind := text(e["kind"])
	if strings.HasPrefix(kind, "loop.") {
		if err = checkLoop(e); err != nil {
			return nil, err
		}
	}
	if kind == "lane.started" || kind == "lane.resumed" || kind == "lane.adopted" {
		if err = checkBinding(e, s.Dir); err != nil {
			return nil, err
		}
	}
	if strings.HasPrefix(kind, "lane.") {
		unlock, err := s.Dir.LaneLock(text(e["lane"]))
		if err != nil {
			return nil, err
		}
		defer unlock()
	}
	if err = s.exec("BEGIN IMMEDIATE"); err != nil {
		return nil, err
	}
	defer s.rollback()
	stored, err := s.findEvent("id", e["id"])
	if err != nil {
		return nil, err
	}
	if stored != nil {
		if !equal(envelope(stored), envelope(e)) {
			return nil, Integrity("event id %s already exists with different content", shown(text(e["id"])))
		}
		return receipt(stored, true), nil
	}
	var current Object
	if strings.HasPrefix(kind, "lane.") || strings.HasPrefix(kind, "resource.") {
		current, err = s.Lane(text(e["lane"]))
		if err != nil {
			return nil, err
		}
		if seq := recordedSeq(current, e); seq != nil {
			old, err := s.findEvent("seq", seq)
			if err != nil {
				return nil, err
			}
			if old == nil {
				return nil, Integrity("the lane projection names an event that is missing")
			}
			return receipt(old, true), nil
		}
		if strings.HasPrefix(kind, "lane.") {
			if err = checkTransition(current, e); err != nil {
				return nil, err
			}
		}
		if strings.HasPrefix(kind, "resource.") || kind == "lane.state" && (object(e["payload"])["state"] == "accepted" || object(e["payload"])["state"] == "merged") {
			all, err := s.Events(0)
			if err != nil {
				return nil, err
			}
			if err = checkResourceAppend(all, current, e); err != nil {
				return nil, err
			}
		}
	}
	seq, err := s.scalar("SELECT max(coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'events'), 0), coalesce((SELECT max(seq) FROM events), 0)) + 1")
	if err != nil {
		return nil, err
	}
	e["seq"] = seq
	e["recorded_at"] = now()
	e["sha256"] = eventHash(e)
	if err = s.exec("INSERT INTO events ("+columns+") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", e["seq"], e["id"], e["kind"], e["lane"], e["actor"], e["occurred_at"], Canonical(e["payload"]), e["protocol_version"], e["recorded_at"], e["sha256"]); err != nil {
		return nil, err
	}
	if strings.HasPrefix(kind, "lane.") {
		if current == nil {
			current = empty(text(e["lane"]))
		}
		apply(current, e)
		if err = s.exec("INSERT OR REPLACE INTO lanes (lane, projection) VALUES (?, ?)", e["lane"], Canonical(current)); err != nil {
			return nil, err
		}
	}
	if err = s.exec("COMMIT"); err != nil {
		return nil, err
	}
	return receipt(e, false), nil
}

func storedFailure(e Object, err error) error {
	return Integrity("event seq %d: %s", num(e["seq"]), err.Error())
}
func (s *Store) checkedEvents() ([]Object, []Object, error) {
	events, err := s.Events(0)
	if err != nil {
		return nil, nil, err
	}
	for _, e := range events {
		if _, err = Validate(envelope(e)); err != nil {
			return nil, nil, storedFailure(e, err)
		}
	}
	computed, err := fold(events)
	if err != nil {
		return nil, nil, err
	}
	if err = replayResources(events); err != nil {
		return nil, nil, err
	}
	return events, computed, nil
}
func (s *Store) Rebuild() ([]Object, error) {
	if err := s.exec("BEGIN IMMEDIATE"); err != nil {
		return nil, err
	}
	defer s.rollback()
	_, computed, err := s.checkedEvents()
	if err != nil {
		return nil, err
	}
	if err = s.exec("DELETE FROM lanes"); err != nil {
		return nil, err
	}
	for _, p := range computed {
		if err = s.exec("INSERT INTO lanes (lane, projection) VALUES (?, ?)", p["lane"], Canonical(p)); err != nil {
			return nil, err
		}
	}
	if err = s.exec("COMMIT"); err != nil {
		return nil, err
	}
	return computed, nil
}
func (s *Store) verifySchema() error {
	var status string
	if s.connection.QueryRowContext(context.Background(), "PRAGMA integrity_check").Scan(&status) != nil || status != "ok" {
		return Integrity("SQLite integrity_check failed")
	}
	version, err := s.scalar("PRAGMA user_version")
	if err != nil {
		return err
	}
	if version != 1 {
		return Integrity("schema definition mismatch: user_version")
	}
	want := map[schemaObject]bool{}
	for _, o := range schema {
		want[o] = true
	}
	rows, err := s.connection.QueryContext(context.Background(), "SELECT type, name, tbl_name, sql FROM sqlite_master")
	if err != nil {
		return Integrity("schema definition mismatch")
	}
	defer rows.Close()
	for rows.Next() {
		var o schemaObject
		var statement sql.NullString
		if rows.Scan(&o.kind, &o.name, &o.table, &statement) != nil {
			return Integrity("schema definition mismatch")
		}
		o.statement = statement.String
		internal := o.kind == "table" && o.name == "sqlite_sequence" && o.table == "sqlite_sequence" && strings.HasPrefix(o.statement, "CREATE TABLE sqlite_sequence")
		for _, name := range []string{"meta", "events", "lanes"} {
			internal = internal || o.kind == "index" && o.name == "sqlite_autoindex_"+name+"_1" && o.table == name && !statement.Valid
		}
		if internal {
			continue
		}
		if !want[o] {
			return Integrity("schema definition mismatch")
		}
		delete(want, o)
	}
	if rows.Err() != nil || len(want) > 0 {
		return Integrity("schema definition mismatch")
	}
	return nil
}
func (s *Store) Verify() (Object, error) {
	if err := s.exec("BEGIN"); err != nil {
		return nil, err
	}
	defer s.rollback()
	if err := s.verifySchema(); err != nil {
		return nil, err
	}
	meta, err := s.metadata()
	if err != nil {
		return nil, err
	}
	if len(meta) != 4 || meta["format"] != "event-store" || meta["config"] != s.Dir.Config.Name {
		return nil, Integrity("store metadata mismatch")
	}
	if err = checkTimestamp(meta["created_at"], "created_at"); err != nil {
		return nil, Integrity("store metadata mismatch: created_at")
	}
	marker, err := s.Dir.Marker()
	if err != nil {
		return nil, err
	}
	if object(marker["store"])["id"] != meta["store_id"] {
		return nil, Integrity("the ownership marker does not record this store")
	}
	events, computed, err := s.checkedEvents()
	if err != nil {
		return nil, err
	}
	previous := int64(0)
	for _, e := range events {
		if num(e["seq"]) != previous+1 {
			return nil, Integrity("event seq %d follows seq %d: an event is missing", num(e["seq"]), previous)
		}
		if err = checkTimestamp(e["recorded_at"], "recorded_at"); err != nil {
			return nil, storedFailure(e, err)
		}
		if !strings.HasSuffix(text(e["recorded_at"]), "Z") {
			return nil, Integrity("event seq %d: stored envelope is not valid", num(e["seq"]))
		}
		previous = num(e["seq"])
	}
	sequence, err := s.scalar("SELECT coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'events'), 0)")
	if err != nil {
		return nil, err
	}
	if sequence != previous {
		return nil, Integrity("seq %d was issued but the last stored event is seq %d: events were removed", sequence, previous)
	}
	rows, err := s.connection.QueryContext(context.Background(), "SELECT lane, projection FROM lanes ORDER BY lane")
	if err != nil {
		return nil, Integrity("the lane projection is not readable")
	}
	i := 0
	matches := true
	for rows.Next() {
		var lane, value string
		if rows.Scan(&lane, &value) != nil {
			matches = false
			break
		}
		if i >= len(computed) || computed[i]["lane"] != lane || Canonical(computed[i]) != value {
			matches = false
		}
		i++
	}
	rowErr := rows.Err()
	rows.Close()
	if !matches || rowErr != nil || i != len(computed) {
		return nil, Integrity("the stored lane projection does not match the events; run state rebuild")
	}
	kept, err := verifyInputs(s.Dir, events)
	if err != nil {
		return nil, err
	}
	mail, orphans, err := verifyMail(s.Dir, events)
	if err != nil {
		return nil, err
	}
	return Object{"ok": true, "exists": true, "config": s.Dir.Config.Name, "events": len(events), "lanes": len(computed), "kept_inputs": kept, "mail_files": mail, "mail_orphans": orphans, "store": filepath.Join(s.Dir.Path, storeFile)}, nil
}
func VerifyEmpty(c *Configuration, d *Directory) (Object, error) {
	kept, mail, orphans := 0, 0, 0
	var err error
	if d != nil {
		kept, err = verifyInputs(d, nil)
		if err != nil {
			return nil, err
		}
		mail, orphans, err = verifyMail(d, nil)
		if err != nil {
			return nil, err
		}
	}
	return Object{"ok": true, "exists": false, "config": c.Name, "events": 0, "lanes": 0, "kept_inputs": kept, "mail_files": mail, "mail_orphans": orphans, "store": filepath.Join(c.StatePath, storeFile)}, nil
}
func fold(events []Object) ([]Object, error) {
	byLane := map[string]Object{}
	for _, e := range events {
		if strings.HasPrefix(text(e["kind"]), "lane.") {
			lane := text(e["lane"])
			current := byLane[lane]
			if err := checkTransition(current, e); err != nil {
				return nil, storedFailure(e, err)
			}
			if current == nil {
				current = empty(lane)
				byLane[lane] = current
			}
			apply(current, e)
		}
	}
	names := make([]string, 0, len(byLane))
	for n := range byLane {
		names = append(names, n)
	}
	sort.Strings(names)
	result := []Object{}
	for _, n := range names {
		result = append(result, byLane[n])
	}
	return result, nil
}
func eventLabel(e Object) string {
	if e["seq"] != nil {
		return fmt.Sprintf("event seq %d", num(e["seq"]))
	}
	return "a brief.rendered event"
}
