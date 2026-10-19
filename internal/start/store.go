package start

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	_ "modernc.org/sqlite"
)

type storeSnapshot struct {
	events []map[string]any
	lanes  []map[string]any
	root   *os.Root
	lock   *os.File
	db     *sql.DB
	tx     *sql.Tx
}

func (s *storeSnapshot) close() {
	if s.tx != nil {
		s.tx.Rollback()
	}
	if s.db != nil {
		s.db.Close()
	}
	if s.lock != nil {
		syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		s.lock.Close()
	}
	if s.root != nil {
		s.root.Close()
	}
}

var schemaSQL = map[string]string{
	"table:meta:meta":                  "CREATE TABLE meta (\n    key TEXT PRIMARY KEY,\n    value TEXT NOT NULL\n)",
	"table:events:events":              "CREATE TABLE events (\n    seq INTEGER PRIMARY KEY AUTOINCREMENT,\n    id TEXT NOT NULL UNIQUE,\n    kind TEXT NOT NULL,\n    lane TEXT,\n    actor TEXT NOT NULL,\n    occurred_at TEXT,\n    payload TEXT NOT NULL,\n    protocol_version TEXT NOT NULL,\n    recorded_at TEXT NOT NULL,\n    sha256 TEXT NOT NULL\n)",
	"table:lanes:lanes":                "CREATE TABLE lanes (\n    lane TEXT PRIMARY KEY,\n    projection TEXT NOT NULL\n)",
	"trigger:events_no_update:events":  "CREATE TRIGGER events_no_update BEFORE UPDATE ON events\nBEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND",
	"trigger:events_no_delete:events":  "CREATE TRIGGER events_no_delete BEFORE DELETE ON events\nBEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND",
	"trigger:events_no_replace:events": "CREATE TRIGGER events_no_replace BEFORE INSERT ON events\nWHEN EXISTS (SELECT 1 FROM events WHERE seq = NEW.seq OR id = NEW.id)\nBEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND",
	"trigger:meta_no_update:meta":      "CREATE TRIGGER meta_no_update BEFORE UPDATE ON meta\nBEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND",
	"trigger:meta_no_delete:meta":      "CREATE TRIGGER meta_no_delete BEFORE DELETE ON meta\nBEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND",
	"trigger:meta_no_insert:meta":      "CREATE TRIGGER meta_no_insert BEFORE INSERT ON meta\nBEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND",
}

func openSnapshot(c *configuration) (snapshot *storeSnapshot, err error) {
	if err := c.checkStateChain(); err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(c.state)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, refused("cannot open the state directory " + scrub(c.state))
	}
	root, err := os.OpenRoot(real)
	if err != nil {
		return nil, refused("cannot open the state directory " + scrub(c.state))
	}
	s := &storeSnapshot{root: root}
	defer func() {
		if err != nil || snapshot == nil {
			s.close()
		}
	}()
	lock, err := root.Open(".")
	if err != nil {
		return nil, refused("cannot lock the state directory")
	}
	s.lock = lock
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_SH); err != nil {
		lock.Close()
		s.lock = nil
		fallback, e := root.OpenFile(".lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
		if e != nil {
			return nil, refused("cannot lock the state directory")
		}
		s.lock = fallback
		if e = syscall.Flock(int(fallback.Fd()), syscall.LOCK_SH); e != nil {
			return nil, refused("cannot lock the state directory")
		}
	}
	var marker map[string]any
	markerBytes, e := readState(root, markerName, 65536)
	if e == nil {
		value, e := parseJSON(markerBytes)
		if e != nil || !validMarker(value) || object(value)["config"] != c.name {
			return nil, integrity("the ownership marker is not a valid marker of configuration " + c.name)
		}
		marker = object(value)
	} else if !os.IsNotExist(e) {
		return nil, integrity("the ownership marker cannot be read inside the state directory")
	}
	info, e := root.Lstat("events.sqlite")
	recorded := object(marker["store"])
	if os.IsNotExist(e) {
		if len(recorded) > 0 {
			return nil, integrity("the store that the ownership marker records is missing")
		}
		return nil, nil
	}
	if e != nil {
		return nil, integrity("the store cannot be read")
	}
	if !info.Mode().IsRegular() {
		return nil, refused("the store is a symbolic link or not a regular file; the store is a regular file inside the state directory")
	}
	if info.Size() == 0 {
		if len(recorded) > 0 {
			return nil, integrity("the store that the ownership marker records is empty (truncated)")
		}
		return nil, nil
	}
	// Keep an open descriptor while SQLite opens, and reject a path replacement.
	f, e := root.OpenFile("events.sqlite", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, integrity("the store cannot be opened")
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil || !os.SameFile(before, info) {
		return nil, integrity("the store changed while it was being opened")
	}
	u := url.URL{Scheme: "file", Path: filepath.Join(real, "events.sqlite")}
	query := url.Values{"mode": []string{"rw"}, "_pragma": []string{"busy_timeout(10000)"}}
	u.RawQuery = query.Encode()
	s.db, e = sql.Open("sqlite", u.String())
	if e != nil {
		return nil, integrity("the store is not a readable event store")
	}
	s.db.SetMaxOpenConns(1)
	s.tx, e = s.db.Begin()
	if e != nil {
		return nil, integrity("the store is not a readable event store")
	}
	var version, objects int
	if e = s.tx.QueryRow("PRAGMA user_version").Scan(&version); e != nil {
		return nil, integrity("the store is not a readable event store")
	}
	if e = s.tx.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&objects); e != nil {
		return nil, integrity("the store is not a readable event store")
	}
	after, e := os.Stat(filepath.Join(real, "events.sqlite"))
	if e != nil || !os.SameFile(before, after) {
		return nil, integrity("the store changed while it was being opened")
	}
	if len(recorded) == 0 && version == 0 && objects == 0 {
		return nil, nil
	}
	if version != 1 {
		return nil, integrity("schema definition mismatch: user_version")
	}
	meta := map[string]any{}
	rows, e := s.tx.Query("SELECT key, value FROM meta")
	if e != nil {
		return nil, integrity("the store metadata cannot be read")
	}
	for rows.Next() {
		var key, value string
		if e = rows.Scan(&key, &value); e != nil {
			rows.Close()
			return nil, integrity("the store metadata cannot be read")
		}
		meta[key] = value
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, integrity("the store metadata cannot be read")
	}
	if !exactKeys(meta, "format", "config", "created_at", "store_id") || meta["format"] != "event-store" {
		return nil, integrity("store metadata mismatch")
	}
	if meta["config"] != c.name {
		return nil, integrity("the store belongs to another configuration")
	}
	if err := timestampCheck("", meta["created_at"], "created_at"); err != nil {
		return nil, integrity("store metadata mismatch: created_at")
	}
	if !storeID.MatchString(str(meta["store_id"])) {
		return nil, integrity("store metadata mismatch: store_id")
	}
	if len(recorded) > 0 && (recorded["id"] != meta["store_id"] || recorded["created_at"] != meta["created_at"]) {
		return nil, integrity("the ownership marker does not record this store")
	}
	if len(recorded) == 0 {
		var count int
		if e = s.tx.QueryRow("SELECT count(*) FROM events").Scan(&count); e != nil {
			return nil, integrity("the store cannot be read")
		}
		if count > 0 {
			return nil, integrity("the store holds events but the ownership marker records no store, so it is not adopted")
		}
		return nil, nil
	}
	if err = s.verifySchema(); err != nil {
		return nil, err
	}
	if err = s.readEvents(); err != nil {
		return nil, err
	}
	s.lanes, err = fold(s.events)
	if err != nil {
		return nil, err
	}
	if err = s.verifyProjection(); err != nil {
		return nil, err
	}
	if err = s.verifyFiles(); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *storeSnapshot) verifySchema() error {
	var verdict string
	if err := s.tx.QueryRow("PRAGMA integrity_check").Scan(&verdict); err != nil || verdict != "ok" {
		return integrity("SQLite integrity_check failed")
	}
	rows, err := s.tx.Query("SELECT type, name, tbl_name, sql FROM sqlite_master")
	if err != nil {
		return integrity("schema definition cannot be read")
	}
	defer rows.Close()
	actual := map[string]string{}
	internal := map[string]bool{"table:sqlite_sequence:sqlite_sequence": true, "index:sqlite_autoindex_meta_1:meta": true, "index:sqlite_autoindex_events_1:events": true, "index:sqlite_autoindex_lanes_1:lanes": true}
	for rows.Next() {
		var kind, name, table string
		var statement sql.NullString
		if err := rows.Scan(&kind, &name, &table, &statement); err != nil {
			return integrity("schema definition cannot be read")
		}
		key := kind + ":" + name + ":" + table
		if internal[key] && (!statement.Valid || strings.HasPrefix(statement.String, "CREATE TABLE sqlite_sequence")) {
			continue
		}
		actual[key] = statement.String
	}
	if err := rows.Err(); err != nil {
		return integrity("schema definition cannot be read")
	}
	if len(actual) != len(schemaSQL) {
		return integrity("schema definition mismatch")
	}
	for key, statement := range schemaSQL {
		if actual[key] != statement {
			return integrity("schema definition mismatch: " + strings.Split(key, ":")[1])
		}
	}
	return nil
}
func (s *storeSnapshot) readEvents() error {
	rows, err := s.tx.Query("SELECT seq,id,kind,lane,actor,occurred_at,payload,protocol_version,recorded_at,sha256 FROM events ORDER BY seq")
	if err != nil {
		return integrity("events cannot be read")
	}
	s.events = []map[string]any{}
	previous := int64(0)
	for rows.Next() {
		var seq int64
		var id, kind, actor, payload, protocol, recorded, sha string
		var lane, occurred sql.NullString
		if err := rows.Scan(&seq, &id, &kind, &lane, &actor, &occurred, &payload, &protocol, &recorded, &sha); err != nil {
			rows.Close()
			return integrity("a stored event cannot be read")
		}
		if seq != previous+1 {
			rows.Close()
			return integrity(fmt.Sprintf("event seq %d follows seq %d: an event is missing", seq, previous))
		}
		value, err := parseJSON([]byte(payload))
		if err != nil {
			rows.Close()
			return integrity(fmt.Sprintf("event seq %d: stored payload is not valid JSON", seq))
		}
		m, ok := value.(map[string]any)
		if !ok || canonical(value) != payload {
			rows.Close()
			return integrity(fmt.Sprintf("event seq %d: stored payload is not a canonical JSON object", seq))
		}
		event := map[string]any{"seq": seq, "id": id, "kind": kind, "lane": nil, "actor": actor, "occurred_at": nil, "payload": m, "protocol_version": protocol, "recorded_at": recorded}
		if lane.Valid {
			event["lane"] = lane.String
		}
		if occurred.Valid {
			event["occurred_at"] = occurred.String
		}
		if digest([]byte(canonical(event))) != sha {
			rows.Close()
			return integrity(fmt.Sprintf("event seq %d: stored hash does not match its content", seq))
		}
		if err := checkEnvelope(event); err != nil {
			rows.Close()
			return integrity(fmt.Sprintf("event seq %d: %s", seq, err))
		}
		event["sha256"] = sha
		s.events = append(s.events, event)
		previous = seq
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return integrity("events cannot be read")
	}
	var issued int64
	err = s.tx.QueryRow("SELECT seq FROM sqlite_sequence WHERE name='events'").Scan(&issued)
	if err != nil && err != sql.ErrNoRows {
		return integrity("event sequence cannot be read")
	}
	if issued != previous {
		return integrity("events were removed: the issued sequence does not match the last event")
	}
	return nil
}
func checkEnvelope(event map[string]any) error {
	envelope := map[string]any{}
	for _, key := range []string{"id", "kind", "lane", "actor", "occurred_at", "payload", "protocol_version"} {
		envelope[key] = event[key]
	}
	if where, rule := credentialInValue(envelope); rule != "" {
		return integrity(where + ": looks like a credential (" + rule + ")")
	}
	fields := map[string]validator{"id": textCheck(`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`, 128), "kind": textCheck(`[a-z][a-z0-9_]{0,31}(?:\.[a-z][a-z0-9_]{0,31}){1,3}`, 131), "lane": nullable(textCheck(`[a-z0-9][a-z0-9._-]{0,63}`, 64)), "actor": textCheck(`[A-Za-z0-9][A-Za-z0-9._:@/+() -]{0,127}`, 128), "occurred_at": nullable(timestampCheck), "protocol_version": textCheck(`[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}`, 14)}
	for key, check := range fields {
		if err := check("event", envelope[key], key); err != nil {
			return integrity(err.Error())
		}
	}
	if err := timestampCheck("event", event["recorded_at"], "recorded_at"); err != nil || !strings.HasSuffix(str(event["recorded_at"]), "Z") {
		return integrity("recorded_at: stored envelope is not valid")
	}
	payload := object(event["payload"])
	if len([]byte(canonical(payload))) > 1024*1024 {
		return integrity("payload: must be at most 1 MiB in canonical form")
	}
	kind := str(event["kind"])
	if strings.HasPrefix(kind, "lane.") {
		return lanePayload(kind, str(event["lane"]), payload)
	}
	if strings.HasPrefix(kind, "resource.") {
		return resourcePayload(kind, str(event["lane"]), payload)
	}
	return nil
}
func (s *storeSnapshot) verifyProjection() error {
	rows, err := s.tx.Query("SELECT lane,projection FROM lanes ORDER BY lane")
	if err != nil {
		return integrity("the lane projection cannot be read")
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		var lane, projection string
		if err := rows.Scan(&lane, &projection); err != nil {
			return integrity("the lane projection cannot be read")
		}
		if i >= len(s.lanes) || str(s.lanes[i]["lane"]) != lane || canonical(s.lanes[i]) != projection {
			return integrity("the stored lane projection does not match the events; run state rebuild")
		}
		i++
	}
	if rows.Err() != nil {
		return integrity("the lane projection cannot be read")
	}
	if i != len(s.lanes) {
		return integrity("the stored lane projection does not match the events; run state rebuild")
	}
	return nil
}
