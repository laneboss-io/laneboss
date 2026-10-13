package doctorbase

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type schemaEntry struct{ Kind, Name, Table, SQL string }

var storeSchema = []schemaEntry{
	{"table", "meta", "meta", "CREATE TABLE meta (\n    key TEXT PRIMARY KEY,\n    value TEXT NOT NULL\n)"},
	{"table", "events", "events", "CREATE TABLE events (\n    seq INTEGER PRIMARY KEY AUTOINCREMENT,\n    id TEXT NOT NULL UNIQUE,\n    kind TEXT NOT NULL,\n    lane TEXT,\n    actor TEXT NOT NULL,\n    occurred_at TEXT,\n    payload TEXT NOT NULL,\n    protocol_version TEXT NOT NULL,\n    recorded_at TEXT NOT NULL,\n    sha256 TEXT NOT NULL\n)"},
	{"table", "lanes", "lanes", "CREATE TABLE lanes (\n    lane TEXT PRIMARY KEY,\n    projection TEXT NOT NULL\n)"},
	{"trigger", "events_no_update", "events", "CREATE TRIGGER events_no_update BEFORE UPDATE ON events\nBEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND"},
	{"trigger", "events_no_delete", "events", "CREATE TRIGGER events_no_delete BEFORE DELETE ON events\nBEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND"},
	{"trigger", "events_no_replace", "events", "CREATE TRIGGER events_no_replace BEFORE INSERT ON events\nWHEN EXISTS (SELECT 1 FROM events WHERE seq = NEW.seq OR id = NEW.id)\nBEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND"},
	{"trigger", "meta_no_update", "meta", "CREATE TRIGGER meta_no_update BEFORE UPDATE ON meta\nBEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND"},
	{"trigger", "meta_no_delete", "meta", "CREATE TRIGGER meta_no_delete BEFORE DELETE ON meta\nBEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND"},
}
var metaLock = schemaEntry{"trigger", "meta_no_insert", "meta", "CREATE TRIGGER meta_no_insert BEFORE INSERT ON meta\nBEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND"}
var envelopeFields = []string{"id", "kind", "lane", "actor", "occurred_at", "payload", "protocol_version"}
var eventID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var eventKind = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}(?:\.[a-z][a-z0-9_]{0,31}){1,3}$`)
var laneName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var actorName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}$`)
var versionGrammar = regexp.MustCompile(`^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$`)
var timestampGrammar = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3}(?:[0-9]{3})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})$`)

func validTimestamp(v any) bool {
	s, ok := v.(string)
	if !ok || !timestampGrammar.MatchString(s) {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}

type Store struct {
	DB         *sql.DB
	Path, Name string
}

func openStore(path, name, mode string) (*Store, error) {
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Set("mode", mode)
	q.Add("_pragma", "busy_timeout(10000)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db, path, name}, nil
}
func (s *Store) Close() error { return s.DB.Close() }

type sqlReader interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

func readMetadata(q sqlReader) (map[string]any, error) {
	rows, err := q.Query("SELECT key, value FROM meta")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]any{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		if _, ok := m[k]; ok {
			return nil, Integrity("store metadata mismatch")
		}
		m[k] = v
	}
	return m, rows.Err()
}
func (s *Store) identity(q sqlReader) (map[string]any, error) {
	var version, objects int
	if err := q.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return nil, Integrity("%s is not a readable event store", s.Path)
	}
	if err := q.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&objects); err != nil {
		return nil, Integrity("%s is not a readable event store", s.Path)
	}
	if version == 0 && objects == 0 {
		return nil, nil
	}
	if version != 1 {
		return nil, Integrity("%s is not an event store of version 1", s.Path)
	}
	m, err := readMetadata(q)
	if err != nil {
		return nil, Integrity("%s is not a readable event store", s.Path)
	}
	if !ExactKeys(m, "format", "config", "created_at", "store_id") || m["format"] != "event-store" {
		return nil, Integrity("the store metadata does not describe an event store")
	}
	if m["config"] != s.Name {
		return nil, Integrity("the store belongs to another configuration")
	}
	return m, nil
}
func initializeStore(s *Store) (map[string]any, error) {
	tx, err := s.DB.BeginTx(context.Background(), nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var version, objects int
	if err := tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if version == 0 {
		if err := tx.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&objects); err != nil {
			return nil, err
		}
		if objects != 0 {
			return nil, Integrity("%s is not an event store", s.Path)
		}
		for _, entry := range storeSchema {
			if _, err := tx.Exec(entry.SQL); err != nil {
				return nil, err
			}
		}
		id, err := RandomID()
		if err != nil {
			return nil, err
		}
		m := map[string]any{"format": "event-store", "config": s.Name, "created_at": UTCNow(), "store_id": id}
		for _, k := range Keys(m) {
			if _, err := tx.Exec("INSERT INTO meta (key, value) VALUES (?, ?)", k, m[k]); err != nil {
				return nil, err
			}
		}
		if _, err := tx.Exec(metaLock.SQL); err != nil {
			return nil, err
		}
		if _, err := tx.Exec("PRAGMA user_version = 1"); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.identity(s.DB)
}
func storeInfo(state *State) (os.FileInfo, error) {
	info, err := state.Root.Lstat(StoreName)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, Refuse("%s is a symbolic link or not a regular file; the store is a regular file inside the state directory", filepath.Join(state.Real, StoreName))
	}
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		side, err := state.Root.Lstat(StoreName + suffix)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		if err == nil && !side.Mode().IsRegular() {
			return nil, Refuse("a store sidecar is a symbolic link or not a regular file")
		}
	}
	if !state.Same() {
		return nil, Refuse("the state directory %s changed while it was in use", state.Real)
	}
	return info, nil
}
func requireStore(info os.FileInfo, path string) error {
	if info == nil {
		return Integrity("the store that the ownership marker records is missing: %s; to start over deliberately, remove the store and the marker (docs/architecture.md, 'Starting over')", path)
	}
	if info.Size() == 0 {
		return Integrity("the store that the ownership marker records is empty (truncated): %s", path)
	}
	return nil
}
func VerifyRecorded(c *Configuration, z *Zones) (bool, string) {
	state, err := OpenState(c, z, false)
	if err != nil {
		return false, Detail(err)
	}
	if state == nil {
		return true, "no store has been created yet"
	}
	defer state.Close()
	lock, err := state.Lock(true)
	if err != nil {
		return false, Detail(err)
	}
	defer lock.Close()
	marker, err := state.Marker()
	if err != nil {
		return false, Detail(err)
	}
	info, err := storeInfo(state)
	if err != nil {
		return false, Detail(err)
	}
	recorded := Object(Object(marker)["store"])
	path := filepath.Join(state.Real, StoreName)
	if len(recorded) > 0 {
		if err := requireStore(info, path); err != nil {
			return false, Detail(err)
		}
	} else if info == nil || info.Size() == 0 {
		return true, "no store has been created yet"
	}
	store, err := openStore(path, c.Name, "rw")
	if err != nil {
		return false, "the store cannot be read"
	}
	defer store.Close()
	meta, err := store.identity(store.DB)
	if err != nil {
		return false, Detail(err)
	}
	if len(recorded) == 0 {
		if meta == nil {
			return true, "no store has been created yet"
		}
		var count int
		if err := store.DB.QueryRow("SELECT count(*) FROM events").Scan(&count); err != nil {
			return false, "the store cannot be read"
		}
		if count > 0 {
			return false, fmt.Sprintf("%s holds %d event(s) but the ownership marker records no store, so it is not adopted (docs/architecture.md, 'Starting over')", path, count)
		}
		return true, "no store has been created yet"
	}
	if meta == nil || meta["store_id"] != recorded["id"] {
		return false, path + " is not the store the ownership marker records"
	}
	count, err := store.Verify(state)
	if err != nil {
		return false, Detail(err)
	}
	return true, fmt.Sprintf("the recorded store verifies (%d event(s))", count)
}

func (s *Store) Verify(state *State) (int, error) {
	tx, err := s.DB.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var integrity string
	if err := tx.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil {
		return 0, Integrity("the store cannot be read")
	}
	if integrity != "ok" {
		return 0, Integrity("SQLite integrity_check failed")
	}
	meta, err := s.identity(tx)
	if err != nil {
		return 0, err
	}
	if meta == nil {
		return 0, Integrity("%s has no event store schema", s.Path)
	}
	if !validTimestamp(meta["created_at"]) {
		return 0, Integrity("store metadata mismatch: created_at")
	}
	if state != nil {
		marker, err := state.Marker()
		if err != nil {
			return 0, err
		}
		recorded := Object(Object(marker)["store"])
		if recorded["id"] != meta["store_id"] {
			return 0, Integrity("the ownership marker does not record this store")
		}
	}
	if err := verifySchema(tx); err != nil {
		return 0, err
	}
	events, err := readEvents(tx)
	if err != nil {
		return 0, err
	}
	previous := int64(0)
	for _, event := range events {
		seq := event["seq"].(int64)
		if seq != previous+1 {
			return 0, Integrity("event seq %d follows seq %d: an event is missing", seq, previous)
		}
		if err := validateStored(event); err != nil {
			return 0, Integrity("event seq %d: %s", seq, err.Error())
		}
		previous = seq
	}
	var issued int64
	err = tx.QueryRow("SELECT seq FROM sqlite_sequence WHERE name = 'events'").Scan(&issued)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	if issued != previous {
		return 0, Integrity("seq %d was issued but the last stored event is seq %d: events were removed", issued, previous)
	}
	if err := verifyProjections(tx, events); err != nil {
		return 0, err
	}
	if state != nil {
		if err := verifyKept(state, events); err != nil {
			return 0, err
		}
	}
	return len(events), nil
}
func verifySchema(q sqlReader) error {
	expected := map[schemaEntry]bool{}
	for _, entry := range append(append([]schemaEntry{}, storeSchema...), metaLock) {
		expected[entry] = true
	}
	rows, err := q.Query("SELECT type, name, tbl_name, sql FROM sqlite_master")
	if err != nil {
		return err
	}
	defer rows.Close()
	bad := map[string]bool{}
	for rows.Next() {
		var kind, name, table string
		var statement sql.NullString
		if err := rows.Scan(&kind, &name, &table, &statement); err != nil {
			return err
		}
		internal := kind == "table" && name == "sqlite_sequence" && table == "sqlite_sequence" && strings.HasPrefix(statement.String, "CREATE TABLE sqlite_sequence") || kind == "index" && !statement.Valid && ((name == "sqlite_autoindex_meta_1" && table == "meta") || (name == "sqlite_autoindex_events_1" && table == "events") || (name == "sqlite_autoindex_lanes_1" && table == "lanes"))
		if internal {
			continue
		}
		entry := schemaEntry{kind, name, table, statement.String}
		if expected[entry] {
			delete(expected, entry)
		} else {
			if CredentialText(name) || !regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`).MatchString(name) {
				name = "(an unrecognized object)"
			}
			bad[name] = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for entry := range expected {
		bad[entry.Name] = true
	}
	if len(bad) > 0 {
		names := []string{}
		for name := range bad {
			names = append(names, name)
		}
		sort.Strings(names)
		return Integrity("schema definition mismatch: %s", strings.Join(names, ", "))
	}
	return nil
}
func eventHash(event map[string]any) (string, error) {
	hashed := map[string]any{}
	for _, field := range envelopeFields {
		hashed[field] = event[field]
	}
	hashed["seq"] = event["seq"]
	hashed["recorded_at"] = event["recorded_at"]
	b, err := Canonical(hashed)
	if err != nil {
		return "", err
	}
	return Hash(b), nil
}
func readEvents(q sqlReader) ([]map[string]any, error) {
	rows, err := q.Query("SELECT seq, id, kind, lane, actor, occurred_at, payload, protocol_version, recorded_at, sha256 FROM events ORDER BY seq")
	if err != nil {
		return nil, Integrity("the store cannot be read")
	}
	defer rows.Close()
	events := []map[string]any{}
	for rows.Next() {
		var seq int64
		var id, kind, actor, payload, protocol, recorded, digest string
		var lane, occurred sql.NullString
		if err := rows.Scan(&seq, &id, &kind, &lane, &actor, &occurred, &payload, &protocol, &recorded, &digest); err != nil {
			return nil, Integrity("the store contains an unreadable event")
		}
		v, err := ParseJSON([]byte(payload))
		if err != nil {
			return nil, Integrity("event seq %d: stored payload is not valid JSON", seq)
		}
		m, ok := v.(map[string]any)
		form, canonicalErr := Canonical(v)
		if !ok || canonicalErr != nil || string(form) != payload {
			return nil, Integrity("event seq %d: stored payload is not a canonical JSON object", seq)
		}
		event := map[string]any{"seq": seq, "id": id, "kind": kind, "lane": nil, "actor": actor, "occurred_at": nil, "payload": m, "protocol_version": protocol, "recorded_at": recorded, "sha256": digest}
		if lane.Valid {
			event["lane"] = lane.String
		}
		if occurred.Valid {
			event["occurred_at"] = occurred.String
		}
		computed, err := eventHash(event)
		if err != nil || computed != digest {
			return nil, Integrity("event seq %d: stored hash does not match its content", seq)
		}
		events = append(events, event)
	}
	return events, rows.Err()
}
func validateStored(event map[string]any) error {
	for _, field := range envelopeFields {
		if CredentialValue(event[field]) {
			return fmt.Errorf("stored envelope looks like a credential")
		}
	}
	for field, grammar := range map[string]*regexp.Regexp{"id": eventID, "kind": eventKind, "actor": actorName, "protocol_version": versionGrammar} {
		if !grammar.MatchString(String(event[field])) {
			return fmt.Errorf("%s: stored envelope is not valid", field)
		}
	}
	if event["lane"] != nil && !laneName.MatchString(String(event["lane"])) {
		return fmt.Errorf("lane: stored envelope is not valid")
	}
	if event["occurred_at"] != nil && !validTimestamp(event["occurred_at"]) {
		return fmt.Errorf("occurred_at: is not a valid date and time")
	}
	if !validTimestamp(event["recorded_at"]) || !strings.HasSuffix(String(event["recorded_at"]), "Z") {
		return fmt.Errorf("recorded_at: stored envelope is not valid")
	}
	payload, err := Canonical(event["payload"])
	if err != nil || len(payload) > 1024*1024 {
		return fmt.Errorf("payload: must be at most 1 MiB in canonical form")
	}
	if strings.HasPrefix(String(event["kind"]), "lane.") {
		return validateLane(event)
	}
	if strings.HasPrefix(String(event["kind"]), "resource.") {
		return validateResource(event)
	}
	return nil
}

// Record is the lane-less event write needed by the disk gate. The caller's
// configuration directory lock prevents marker/store creation from being half read.
func Record(state *State, kind string, payload map[string]any) (err error) {
	if state == nil {
		return Refuse("a state directory is required to record the disk reading")
	}
	if kind != "disk.warn" && kind != "disk.stop" {
		return Refuse("the disk recorder accepts only disk.warn and disk.stop")
	}
	if CredentialValue(payload) {
		return Refuse("the disk event payload looks like a credential")
	}
	lock, err := state.Lock(false)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	marker, err := state.Marker()
	if err != nil {
		return err
	}
	info, err := storeInfo(state)
	if err != nil {
		return err
	}
	path := filepath.Join(state.Real, StoreName)
	recorded := Object(Object(marker)["store"])
	if len(recorded) > 0 {
		if err := requireStore(info, path); err != nil {
			return err
		}
	}
	mode := "rw"
	if info == nil || info.Size() == 0 {
		mode = "rwc"
	}
	store, err := openStore(path, state.Config.Name, mode)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, store.Close()) }()
	meta, err := store.identity(store.DB)
	if err != nil {
		return err
	}
	if len(recorded) > 0 {
		if meta == nil || meta["store_id"] != recorded["id"] {
			return Integrity("%s is not the store the ownership marker records", path)
		}
	} else {
		if meta != nil {
			var count int
			if err := store.DB.QueryRow("SELECT count(*) FROM events").Scan(&count); err != nil {
				return err
			}
			if count > 0 {
				return Integrity("the ownership marker records no store, so the existing events are not adopted")
			}
		}
		if marker == nil {
			bytes, err := json.Marshal(map[string]any{"config": state.Config.Name, "format": 2, "store": nil})
			if err != nil {
				return err
			}
			if err := WriteAtomic(state.Root, MarkerName, append(bytes, '\n'), false); err != nil {
				return err
			}
		}
		if meta == nil {
			meta, err = initializeStore(store)
			if err != nil {
				return err
			}
		}
		bytes, err := json.Marshal(map[string]any{"config": state.Config.Name, "format": 2, "store": map[string]any{"id": meta["store_id"], "created_at": meta["created_at"]}})
		if err != nil {
			return err
		}
		if err := WriteAtomic(state.Root, MarkerName, append(bytes, '\n'), true); err != nil {
			return err
		}
	}
	_, err = store.append(kind, payload)
	return err
}
func (s *Store) append(kind string, payload map[string]any) (map[string]any, error) {
	conn, err := s.DB.Conn(context.Background())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		return nil, err
	}
	defer conn.ExecContext(context.Background(), "ROLLBACK")
	var seq int64
	if err := conn.QueryRowContext(context.Background(), "SELECT max(coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'events'), 0), coalesce((SELECT max(seq) FROM events), 0)) + 1").Scan(&seq); err != nil {
		return nil, err
	}
	id, err := RandomID()
	if err != nil {
		return nil, err
	}
	event := map[string]any{"id": "ev-" + id, "kind": kind, "lane": nil, "actor": "laneboss", "occurred_at": nil, "payload": payload, "protocol_version": ProtocolVersion, "seq": seq, "recorded_at": UTCNow()}
	if kind == "disk.warn" || kind == "disk.stop" {
		event["occurred_at"] = UTCNow()
	}
	digest, err := eventHash(event)
	if err != nil {
		return nil, err
	}
	bytes, err := Canonical(payload)
	if err != nil {
		return nil, err
	}
	event["sha256"] = digest
	if _, err := conn.ExecContext(context.Background(), "INSERT INTO events (seq, id, kind, lane, actor, occurred_at, payload, protocol_version, recorded_at, sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", seq, event["id"], kind, nil, "laneboss", event["occurred_at"], string(bytes), ProtocolVersion, event["recorded_at"], digest); err != nil {
		return nil, err
	}
	if _, err := conn.ExecContext(context.Background(), "COMMIT"); err != nil {
		return nil, err
	}
	return event, nil
}
func ScratchRoundTrip(state *State) (err error) {
	id, err := RandomID()
	if err != nil {
		return err
	}
	scratch := ".doctor-" + id
	if err := state.Root.Mkdir(scratch, 0700); err != nil {
		return err
	}
	defer func() {
		root, openErr := state.Root.OpenRoot(scratch)
		if openErr != nil {
			err = errors.Join(err, openErr)
			return
		}
		f, openErr := root.Open(".")
		if openErr != nil {
			root.Close()
			err = errors.Join(err, openErr)
			return
		}
		entries, readErr := f.ReadDir(-1)
		closeErr := f.Close()
		err = errors.Join(err, readErr, closeErr)
		for _, entry := range entries {
			err = errors.Join(err, root.Remove(entry.Name()))
		}
		err = errors.Join(err, root.Close())
		err = errors.Join(err, state.Root.Remove(scratch))
	}()
	if !state.Same() {
		return Refuse("the state directory changed while it was in use")
	}
	store, err := openStore(filepath.Join(state.Real, scratch, StoreName), state.Config.Name, "rwc")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, store.Close()) }()
	if _, err := initializeStore(store); err != nil {
		return err
	}
	appended, err := store.append("doctor.probe", map[string]any{"check": "store.round_trip"})
	if err != nil {
		return err
	}
	read, err := readEvents(store.DB)
	if err != nil {
		return err
	}
	if len(read) != 1 || read[0]["id"] != appended["id"] || read[0]["sha256"] != appended["sha256"] {
		return Integrity("the scratch store did not read back the event it appended")
	}
	_, err = store.Verify(nil)
	return err
}
