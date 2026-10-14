package lane

import (
	"bytes"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
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

const metaLock = "CREATE TRIGGER meta_no_insert BEFORE INSERT ON meta\nBEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND"

type session struct {
	c    *configuration
	root *os.Root
	dir  *os.File
	db   *sql.DB
}

func openSession(c *configuration, create bool) (*session, error) {
	s := &session{c: c}
	if err := c.checkPath(c.state, "the state directory", false); err != nil {
		return nil, err
	}
	if create {
		if err := os.MkdirAll(c.state, 0700); err != nil {
			return nil, refuse("cannot create the state directory")
		}
	}
	if _, err := os.Stat(c.state); os.IsNotExist(err) {
		return s, nil
	} else if err != nil {
		return nil, err
	}
	r, err := rootDirectory(c.state)
	if err != nil {
		return nil, err
	}
	s.root = r
	s.dir, err = openDirectory(c.state)
	if err != nil {
		s.close()
		return nil, err
	}
	if err = s.refresh(); err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}
func (s *session) close() {
	if s.db != nil {
		s.db.Close()
		s.db = nil
	}
	if s.root != nil {
		s.root.Close()
		s.root = nil
	}
	if s.dir != nil {
		s.dir.Close()
		s.dir = nil
	}
}
func (s *session) marker() (object, error) {
	if s.root == nil {
		return nil, nil
	}
	b, err := rootRead(s.root, ".laneboss-state", 64*1024)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, integrity("the ownership marker is unreadable")
	}
	v, err := parseJSON(b)
	m := obj(v)
	if err != nil || !exactKeys(m, strings.Fields("config format store")) || str(m["config"]) != s.c.name || !whole(m["format"], 2, 2) {
		return nil, integrity("the ownership marker is not a valid marker of this configuration")
	}
	if m["store"] != nil {
		recorded := obj(m["store"])
		if !exactKeys(recorded, []string{"id", "created_at"}) || !match(`[0-9a-f]{32}`, str(recorded["id"])) || !match(`[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z`, str(recorded["created_at"])) {
			return nil, integrity("the ownership marker has invalid store metadata")
		}
	}
	return m, nil
}
func (s *session) refresh() error {
	if s.db != nil {
		s.db.Close()
		s.db = nil
	}
	if s.root == nil {
		return nil
	}
	db, err := s.openStore(false, 10)
	if err != nil {
		return err
	}
	s.db = db
	return nil
}
func (s *session) openStore(write bool, timeout float64) (*sql.DB, error) {
	if err := s.checkStateIdentity(); err != nil {
		return nil, err
	}
	unlock, err := lockFile(s.dir, 10, !write)
	if err != nil {
		return nil, err
	}
	defer unlock()
	marker, err := s.marker()
	if err != nil {
		return nil, err
	}
	recorded := obj(marker["store"])
	info, err := s.root.Lstat("events.sqlite")
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if info != nil && !info.Mode().IsRegular() {
		return nil, refuse("events.sqlite is a symbolic link or not a regular file")
	}
	if recorded != nil && (info == nil || info.Size() == 0) {
		return nil, integrity("the store that the ownership marker records is missing or empty: %s", filepath.Join(s.c.state, "events.sqlite"))
	}
	if !write && recorded == nil && (info == nil || info.Size() == 0) {
		return nil, nil
	}
	mode := "rw"
	if write && recorded == nil {
		mode = "rwc"
	}
	path := filepath.Join(s.c.state, "events.sqlite")
	u := url.URL{Scheme: "file", Path: path}
	q := url.Values{"mode": {mode}, "_pragma": {fmt.Sprintf("busy_timeout(%d)", int(timeout*1000))}}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, integrity("SQLite operation failed")
	}
	db.SetMaxOpenConns(1)
	fail := func(e error) (*sql.DB, error) { db.Close(); return nil, e }
	if err = db.Ping(); err != nil {
		return fail(integrity("%s is not a readable event store", path))
	}
	if err = s.checkStateIdentity(); err != nil {
		return fail(err)
	}
	var version, objects int
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fail(integrity("the store schema is unreadable"))
	}
	if err = db.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&objects); err != nil {
		return fail(integrity("the store schema is unreadable"))
	}
	if version == 0 && objects == 0 {
		if !write {
			return fail(nil)
		}
		if _, err = db.Exec("BEGIN IMMEDIATE"); err != nil {
			return fail(err)
		}
		ok := false
		defer func() {
			if !ok {
				db.Exec("ROLLBACK")
			}
		}()
		for _, statement := range storeSchema {
			if _, err = db.Exec(statement); err != nil {
				return fail(err)
			}
		}
		meta := object{"format": "event-store", "config": s.c.name, "created_at": utcNow(), "store_id": newID()}
		for _, k := range []string{"config", "created_at", "format", "store_id"} {
			if _, err = db.Exec("INSERT INTO meta (key,value) VALUES (?,?)", k, meta[k]); err != nil {
				return fail(err)
			}
		}
		if _, err = db.Exec(metaLock); err != nil {
			return fail(err)
		}
		if _, err = db.Exec("PRAGMA user_version = 1"); err != nil {
			return fail(err)
		}
		if _, err = db.Exec("COMMIT"); err != nil {
			return fail(err)
		}
		ok = true
		version = 1
	}
	if version != 1 {
		return fail(integrity("the store is not an event store of version 1"))
	}
	rows, err := db.Query("SELECT key,value FROM meta")
	if err != nil {
		return fail(integrity("the store metadata is unreadable"))
	}
	meta := object{}
	for rows.Next() {
		var key, value any
		if err = rows.Scan(&key, &value); err != nil {
			rows.Close()
			return fail(err)
		}
		k, ok1 := key.(string)
		v, ok2 := value.(string)
		if !ok1 || !ok2 {
			rows.Close()
			return fail(integrity("the store metadata contains a non-text field"))
		}
		meta[k] = v
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return fail(err)
	}
	if !exactKeys(meta, strings.Fields("format config created_at store_id")) || str(meta["format"]) != "event-store" || str(meta["config"]) != s.c.name {
		return fail(integrity("the store metadata does not describe this configuration's event store"))
	}
	if !match(`[0-9a-f]{32}`, str(meta["store_id"])) || !validTimestamp(meta["created_at"]) {
		return fail(integrity("the store metadata has an invalid identifier or creation time"))
	}
	if recorded != nil && str(recorded["id"]) != str(meta["store_id"]) {
		return fail(integrity("the store is not the store the ownership marker records"))
	}
	if recorded == nil {
		var count int
		if err = db.QueryRow("SELECT count(*) FROM events").Scan(&count); err != nil {
			return fail(err)
		}
		if count > 0 {
			return fail(integrity("the store holds events but the ownership marker records no store, so it is not adopted"))
		}
		if !write {
			return fail(nil)
		}
		m := object{"config": s.c.name, "format": 2, "store": object{"id": meta["store_id"], "created_at": meta["created_at"]}}
		if err = rootWrite(s.root, ".laneboss-state", append(canonical(m), '\n'), true, 0600); err != nil {
			return fail(err)
		}
	}
	return db, nil
}
func decodeProjection(text string) (object, error) {
	v, err := parseJSON([]byte(text))
	if err != nil || !currentProjection(obj(v)) {
		return nil, integrity("the lane projection is not in this version's form; run state rebuild")
	}
	return obj(v), nil
}
func (s *session) row(lane string) (object, error) {
	if s.db == nil {
		return nil, nil
	}
	var text string
	err := s.db.QueryRow("SELECT projection FROM lanes WHERE lane=?", lane).Scan(&text)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, integrity("the lane projection is unreadable")
	}
	return decodeProjection(text)
}
func (s *session) known(lane string) (object, error) {
	row, err := s.row(lane)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, refuse("lane %s is not known to configuration %s", lane, s.c.name)
	}
	return row, nil
}
func (s *session) rows() ([]object, error) {
	found := []object{}
	if s.db == nil {
		return found, nil
	}
	rows, err := s.db.Query("SELECT projection FROM lanes ORDER BY lane")
	if err != nil {
		return nil, integrity("the lane projections are unreadable")
	}
	defer rows.Close()
	for rows.Next() {
		var text string
		if err = rows.Scan(&text); err != nil {
			return nil, err
		}
		m, e := decodeProjection(text)
		if e != nil {
			return nil, e
		}
		found = append(found, m)
	}
	return found, rows.Err()
}

const eventColumns = "seq,id,kind,lane,actor,occurred_at,payload,protocol_version,recorded_at,sha256"

type scanner interface{ Scan(...any) error }

func readEvent(row scanner) (object, error) {
	values := make([]any, 10)
	targets := make([]any, 10)
	for i := range values {
		targets[i] = &values[i]
	}
	if err := row.Scan(targets...); err != nil {
		return nil, err
	}
	seq, ok := values[0].(int64)
	if !ok || seq < 1 {
		return nil, integrity("an event has a non-integer sequence")
	}
	texts := make([]string, 10)
	for _, index := range []int{1, 2, 4, 6, 7, 8, 9} {
		var valid bool
		texts[index], valid = values[index].(string)
		if !valid {
			return nil, integrity("event seq %d: stored envelope has a non-text field", seq)
		}
	}
	for _, index := range []int{3, 5} {
		if values[index] != nil {
			var valid bool
			texts[index], valid = values[index].(string)
			if !valid {
				return nil, integrity("event seq %d: stored envelope has a non-text field", seq)
			}
		}
	}
	id, kind, actor, text, protocol, recorded, hash := texts[1], texts[2], texts[4], texts[6], texts[7], texts[8], texts[9]
	v, err := parseJSON([]byte(text))
	if err != nil || obj(v) == nil || string(canonical(v)) != text {
		return nil, integrity("event seq %d: stored payload is not a canonical JSON object", seq)
	}
	e := object{"seq": seq, "id": id, "kind": kind, "lane": nil, "actor": actor, "occurred_at": nil, "payload": v, "protocol_version": protocol, "recorded_at": recorded, "sha256": hash}
	if values[3] != nil {
		e["lane"] = texts[3]
	}
	if values[5] != nil {
		e["occurred_at"] = texts[5]
	}
	hashed := clone(e)
	delete(hashed, "sha256")
	if digest(canonical(hashed)) != hash {
		return nil, integrity("event seq %d: stored hash does not match its content", seq)
	}
	if strings.HasPrefix(kind, "lane.") {
		if err = validatePayload(kind, str(e["lane"]), obj(v)); err != nil {
			return nil, integrity("event seq %d: %s; it was written by an earlier version and no lane command acts on it", seq, err)
		}
	}
	return e, nil
}
func (s *session) last(lane, kind string) (object, error) {
	if s.db == nil {
		return nil, nil
	}
	e, err := readEvent(s.db.QueryRow("SELECT "+eventColumns+" FROM events WHERE lane=? AND kind=? ORDER BY seq DESC LIMIT 1", lane, kind))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return e, err
}
func (s *session) laneEvents(lane string, kinds ...string) ([]object, error) {
	found := []object{}
	if s.db == nil {
		return found, nil
	}
	query := "SELECT " + eventColumns + " FROM events WHERE lane=?"
	values := []any{lane}
	if len(kinds) > 0 {
		place := []string{}
		for _, k := range kinds {
			place = append(place, "?")
			values = append(values, k)
		}
		query += " AND kind IN (" + strings.Join(place, ",") + ")"
	}
	rows, err := s.db.Query(query+" ORDER BY seq", values...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		e, err := readEvent(rows)
		if err != nil {
			return nil, err
		}
		found = append(found, e)
	}
	return found, rows.Err()
}
func envelope(lane, kind string, p object, actor string) object {
	return object{"id": "ev-" + newID(), "kind": kind, "lane": nullable(lane), "actor": actor, "occurred_at": utcNow(), "payload": p, "protocol_version": protocolVersion}
}
func normalizeEnvelope(e object) (object, error) {
	e = obj(nativeJSON(e))
	if e == nil {
		return nil, refuse("an event must be a JSON object")
	}
	if err := checkSecrets(e); err != nil {
		return nil, err
	}
	for k := range e {
		if !contains(strings.Fields("id kind lane actor occurred_at payload protocol_version"), k) {
			return nil, refuse("an event contains an unknown field")
		}
	}
	e = clone(e)
	if e["id"] == nil || e["id"] == "" {
		e["id"] = "ev-" + newID()
	}
	if !match(`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`, str(e["id"])) || !match(`[a-z][a-z0-9_]{0,31}(?:\.[a-z][a-z0-9_]{0,31}){1,3}`, str(e["kind"])) || !match(`[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}`, str(e["actor"])) || !match(`[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}`, str(e["protocol_version"])) {
		return nil, refuse("an event has an invalid envelope field")
	}
	if e["lane"] != nil && !match(`[a-z0-9][a-z0-9._-]{0,63}`, str(e["lane"])) {
		return nil, refuse("lane is invalid")
	}
	if obj(e["payload"]) == nil || len(canonical(e["payload"])) > 1024*1024 {
		return nil, refuse("payload must be a JSON object of at most 1 MiB")
	}
	if e["occurred_at"] != nil && !validTimestamp(e["occurred_at"]) {
		return nil, refuse("occurred_at must be a valid timestamp")
	}
	if strings.HasPrefix(str(e["kind"]), "loop.") {
		if err := validateLoop(e); err != nil {
			return nil, err
		}
	}
	if strings.HasPrefix(str(e["kind"]), "resource.") {
		if err := validateResource(str(e["kind"]), str(e["lane"]), obj(e["payload"])); err != nil {
			return nil, err
		}
	}
	if strings.HasPrefix(str(e["kind"]), "lane.") {
		if err := validatePayload(str(e["kind"]), str(e["lane"]), obj(e["payload"])); err != nil {
			return nil, err
		}
	}
	for _, k := range []string{"occurred_at", "lane"} {
		if _, ok := e[k]; !ok {
			e[k] = nil
		}
	}
	return e, nil
}
func (s *session) appendRaw(e object, timeout float64) (object, error) {
	e, err := normalizeEnvelope(e)
	if err != nil {
		return nil, err
	}
	kind, lane := str(e["kind"]), str(e["lane"])
	if err = s.validateBinding(kind, lane, obj(e["payload"])); err != nil {
		return nil, err
	}
	if kind == "brief.rendered" {
		if err = s.checkRendered(e); err != nil {
			return nil, err
		}
	}
	db, err := s.openStore(true, timeout)
	if err != nil {
		return nil, &storeUnavailableError{err}
	}
	defer db.Close()
	if _, err = db.Exec("BEGIN IMMEDIATE"); err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			db.Exec("ROLLBACK")
		}
	}()
	old, err := readEvent(db.QueryRow("SELECT "+eventColumns+" FROM events WHERE id=?", e["id"]))
	if err == nil {
		content := clone(old)
		for _, k := range strings.Fields("seq recorded_at sha256") {
			delete(content, k)
		}
		if !bytes.Equal(canonical(content), canonical(e)) {
			return nil, integrity("event id already exists with different content")
		}
		return old, nil
	}
	if err != sql.ErrNoRows {
		return nil, err
	}
	var current object
	if strings.HasPrefix(kind, "lane.") {
		var text string
		err = db.QueryRow("SELECT projection FROM lanes WHERE lane=?", lane).Scan(&text)
		if err == nil {
			current, err = decodeProjection(text)
		}
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		found := refusalState(current)
		idField, group := "", ""
		if kind == "lane.refusal" {
			idField, group = "refusal", "recorded"
		} else if kind == "lane.workaround_suspected" {
			idField, group = "suspicion", "suspected"
		}
		if idField != "" {
			if m := obj(obj(found[group])[str(obj(e["payload"])[idField])]); m != nil {
				return readEvent(db.QueryRow("SELECT "+eventColumns+" FROM events WHERE seq=?", m["seq"]))
			}
		}
		if err = checkTransition(current, e); err != nil {
			return nil, err
		}
		if kind == "lane.state" && contains([]string{"accepted", "merged"}, str(obj(e["payload"])["state"])) {
			if err = checkResources(db, lane, obj(e["payload"])); err != nil {
				return nil, err
			}
		}
	}
	if strings.HasPrefix(kind, "resource.") {
		if err = checkResourceAppend(db, e); err != nil {
			return nil, err
		}
	}
	var seq int64
	if err = db.QueryRow("SELECT max(coalesce((SELECT seq FROM sqlite_sequence WHERE name='events'),0),coalesce((SELECT max(seq) FROM events),0))+1").Scan(&seq); err != nil {
		return nil, err
	}
	e["seq"] = seq
	e["recorded_at"] = utcNow()
	hash := digest(canonical(e))
	e["sha256"] = hash
	if _, err = db.Exec("INSERT INTO events (seq,id,kind,lane,actor,occurred_at,payload,protocol_version,recorded_at,sha256) VALUES (?,?,?,?,?,?,?,?,?,?)", seq, e["id"], kind, e["lane"], e["actor"], e["occurred_at"], string(canonical(e["payload"])), e["protocol_version"], e["recorded_at"], hash); err != nil {
		return nil, err
	}
	if strings.HasPrefix(kind, "lane.") {
		projection := applyProjection(current, e)
		if _, err = db.Exec("INSERT OR REPLACE INTO lanes (lane,projection) VALUES (?,?)", lane, string(canonical(projection))); err != nil {
			return nil, err
		}
	}
	if _, err = db.Exec("COMMIT"); err != nil {
		return nil, err
	}
	committed = true
	return e, nil
}
