package brief

import (
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// These are the existing event store's exact sqlite_master definitions. The
// Python verifier compares the definitions, including their whitespace.
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

type eventStore struct {
	db    *sql.DB
	state *stateDirectory
	meta  map[string]string
}

func sqlFailure() error {
	return integrity("SQLite operation failed")
}
func utcNow() string { return time.Now().UTC().Format("2006-01-02T15:04:05.000000Z") }

func openStore(s *stateDirectory) (_ *eventStore, err error) {
	marker, err := s.marker()
	if err != nil {
		return nil, err
	}
	info, err := s.dir.fileInfo("events.sqlite")
	if err != nil {
		return nil, refused("cannot inspect the event store")
	}
	if info != nil && !info.Mode().IsRegular() {
		return nil, refused("events.sqlite is a symbolic link or not a regular file; the store is a regular file inside the state directory")
	}
	if !s.dir.same() {
		return nil, refused("the state directory changed while it was in use")
	}
	recorded := tableValue(marker["store"])
	if len(recorded) > 0 {
		if info == nil {
			return nil, integrity("the store that the ownership marker records is missing")
		}
		if info.Size() == 0 {
			return nil, integrity("the store that the ownership marker records is empty (truncated)")
		}
	}
	mode := "rwc"
	if info != nil && info.Size() > 0 || len(recorded) > 0 {
		mode = "rw"
	}
	uri := (&url.URL{Scheme: "file", Path: filepath.Join(s.dir.path, "events.sqlite")}).String()
	db, err := sql.Open("sqlite", uri+"?mode="+mode)
	if err != nil {
		return nil, sqlFailure()
	}
	db.SetMaxOpenConns(1)
	store := &eventStore{db: db, state: s}
	defer func() {
		if err != nil {
			db.Close()
		}
	}()
	if _, err = db.Exec("PRAGMA busy_timeout = 10000"); err != nil {
		return nil, sqlFailure()
	}
	if len(recorded) > 0 {
		if err = store.check(recorded["id"].(string)); err != nil {
			return nil, err
		}
		return store, nil
	}
	var version, objects int64
	if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return nil, sqlFailure()
	}
	if err = db.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&objects); err != nil {
		return nil, sqlFailure()
	}
	if version != 0 || objects != 0 {
		if err = store.check(""); err != nil {
			return nil, err
		}
		var count int64
		if err = db.QueryRow("SELECT count(*) FROM events").Scan(&count); err != nil {
			return nil, sqlFailure()
		}
		if count > 0 {
			return nil, integrity("the store holds events but the ownership marker records no store, so it is not adopted")
		}
	}
	if marker == nil {
		if err = s.writeMarker(nil, false); err != nil {
			return nil, err
		}
	}
	if version == 0 && objects == 0 {
		if err = store.initialize(); err != nil {
			return nil, err
		}
	}
	if err = s.writeMarker(map[string]any{"id": store.meta["store_id"], "created_at": store.meta["created_at"]}, true); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *eventStore) transaction(action func() error) (err error) {
	if _, err := s.db.Exec("BEGIN IMMEDIATE"); err != nil {
		return sqlFailure()
	}
	defer func() {
		if err != nil {
			if _, rollbackError := s.db.Exec("ROLLBACK"); rollbackError != nil {
				err = integrity("SQLite operation failed and its transaction could not be rolled back")
			}
		}
	}()
	if err = action(); err != nil {
		return err
	}
	if _, err = s.db.Exec("COMMIT"); err != nil {
		return sqlFailure()
	}
	return nil
}

func (s *eventStore) initialize() error {
	err := s.transaction(func() error {
		var version, count int64
		if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
			return sqlFailure()
		}
		if version != 0 {
			return integrity("the new event store has an unexpected schema version")
		}
		if err := s.db.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&count); err != nil {
			return sqlFailure()
		}
		if count != 0 {
			return integrity("the file is not an event store")
		}
		for _, statement := range storeSchema {
			if _, err := s.db.Exec(statement); err != nil {
				return sqlFailure()
			}
		}
		id, err := randomID()
		if err != nil {
			return err
		}
		values := map[string]string{"format": "event-store", "config": s.state.c.name, "created_at": utcNow(), "store_id": id}
		for _, key := range []string{"config", "created_at", "format", "store_id"} {
			if _, err := s.db.Exec("INSERT INTO meta (key, value) VALUES (?, ?)", key, values[key]); err != nil {
				return sqlFailure()
			}
		}
		if _, err := s.db.Exec(metaLock); err != nil {
			return sqlFailure()
		}
		if _, err := s.db.Exec("PRAGMA user_version = 1"); err != nil {
			return sqlFailure()
		}
		return nil
	})
	if err != nil {
		return err
	}
	return s.check("")
}

func (s *eventStore) check(expectedID string) error {
	var version int64
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return integrity("the store is not a readable event store")
	}
	if version != 1 {
		return integrity("the file is not an event store of version 1")
	}
	rows, err := s.db.Query("SELECT key, value FROM meta")
	if err != nil {
		return integrity("the store metadata is not readable")
	}
	meta := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			rows.Close()
			return integrity("the store metadata is not readable")
		}
		meta[key] = value
	}
	rowError := rows.Err()
	rows.Close()
	if rowError != nil {
		return sqlFailure()
	}
	if len(meta) != 4 || meta["format"] != "event-store" || meta["config"] == "" || meta["created_at"] == "" || meta["store_id"] == "" {
		return integrity("the store metadata does not describe an event store")
	}
	if meta["config"] != s.state.c.name {
		return integrity("the store belongs to another configuration")
	}
	if expectedID != "" && meta["store_id"] != expectedID {
		return integrity("the file is not the store the ownership marker records")
	}
	if !storeIDPattern.MatchString(meta["store_id"]) || !recordedAtPattern.MatchString(meta["created_at"]) {
		return integrity("store metadata mismatch: store_id or created_at")
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000000Z", meta["created_at"]); err != nil {
		return integrity("store metadata mismatch: created_at")
	}
	s.meta = meta
	return nil
}

func (s *eventStore) references(lane, hash string) (bool, error) {
	copy, err := canonical("lanes/" + lane + "/inputs/" + hash)
	if err != nil {
		return false, err
	}
	var count int64
	if err := s.db.QueryRow("SELECT count(*) FROM events WHERE kind = 'brief.rendered' AND lane = ? AND instr(payload, ?) > 0", lane, string(copy)).Scan(&count); err != nil {
		return false, sqlFailure()
	}
	return count > 0, nil
}

func (s *eventStore) append(lane, version string, payload map[string]any) (map[string]any, error) {
	if !protocolVersionPattern.MatchString(version) {
		return nil, refused("protocol_version: must match [0-9]{1,4}.[0-9]{1,4}.[0-9]{1,4}")
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	event := map[string]any{"id": "ev-" + id, "kind": "brief.rendered", "lane": lane, "actor": program, "occurred_at": nil, "payload": payload, "protocol_version": version}
	if field, rule := credentialInValue(event); rule != "" {
		return nil, refused("%s: looks like a credential (%s); nothing was stored", field, rule)
	}
	data, err := canonical(payload)
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, refused("payload: must be at most 1 MiB in canonical form")
	}
	// The same files are rechecked at the reserved event's write boundary.
	for _, value := range payload["inputs"].([]any) {
		item := value.(map[string]any)
		hash := item["sha256"].(string)
		kept, err := s.state.readInput(lane, hash)
		if err != nil {
			return nil, err
		}
		if digest(kept) != hash {
			return nil, refused("a brief.rendered event: kept input does not match its hash")
		}
	}
	err = s.transaction(func() error {
		var seq int64
		if err := s.db.QueryRow("SELECT max(coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'events'), 0), coalesce((SELECT max(seq) FROM events), 0)) + 1").Scan(&seq); err != nil {
			return sqlFailure()
		}
		event["seq"], event["recorded_at"] = seq, utcNow()
		encoded, err := canonical(event)
		if err != nil {
			return err
		}
		event["sha256"] = digest(encoded)
		if _, err := s.db.Exec("INSERT INTO events (seq, id, kind, lane, actor, occurred_at, payload, protocol_version, recorded_at, sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", seq, event["id"], event["kind"], lane, program, nil, string(data), version, event["recorded_at"], event["sha256"]); err != nil {
			return sqlFailure()
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": event["id"], "seq": event["seq"]}, nil
}

func writeRendered(state *stateDirectory, outputDir *directory, outputName string, o options, version string, brief, protocolBytes []byte, rules []ruleFile, output []byte) (_ map[string]any, err error) {
	store, err := openStore(state)
	if err != nil {
		return nil, err
	}
	defer store.db.Close()
	created := []string{}
	written := false
	defer func() {
		if err == nil {
			return
		}
		if written {
			if removeError := outputDir.root.Remove(outputName); removeError != nil && !errors.Is(removeError, os.ErrNotExist) {
				err = integrity("render failed and its output could not be removed")
			}
		}
		for _, hash := range created {
			referenced, checkError := store.references(o.lane, hash)
			if checkError != nil {
				err = integrity("render failed; a kept input was retained because its references could not be checked")
				continue
			}
			if !referenced {
				if removeError := state.removeInput(o.lane, hash); removeError != nil {
					err = integrity("render failed and an unreferenced kept input could not be removed")
				}
			}
		}
	}()
	source, err := realPath(o.source)
	if err != nil {
		return nil, err
	}
	consumed := []struct {
		role, detail, value string
		data                []byte
	}{{"brief", "path", source, brief}, {"protocol", "version", version, protocolBytes}}
	for _, rule := range rules {
		consumed = append(consumed, struct {
			role, detail, value string
			data                []byte
		}{"rules", "path", rule.path, rule.data})
	}
	inputs, hashes := []any{}, []any{}
	for _, input := range consumed {
		copy, hash, wasCreated, keepError := state.keep(o.lane, input.data)
		if keepError != nil {
			return nil, keepError
		}
		if wasCreated {
			created = append(created, hash)
		}
		inputs = append(inputs, map[string]any{"role": input.role, input.detail: input.value, "sha256": hash, "copy": copy})
		hashes = append(hashes, map[string]any{"role": input.role, "sha256": hash})
	}
	outputPath := filepath.Join(outputDir.path, outputName)
	if err := outputDir.writeNew(outputName, output, false, 0644); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, refused("--out %s already exists; a rendered brief is never replaced", safePath(outputPath))
		}
		return nil, refused("--out: cannot write %s: %s", safePath(outputPath), osReason(err))
	}
	written = true
	outputHash := digest(output)
	var project any
	if o.projectSet {
		project = o.project
	}
	payload := map[string]any{"inputs": inputs, "output": map[string]any{"path": outputPath, "sha256": outputHash}, "project": project, "touches": o.touches, "launcher_version": launcherVersion}
	appended, err := store.append(o.lane, version, payload)
	if err != nil {
		return nil, err
	}
	return map[string]any{"event": appended, "out": outputPath, "sha256": map[string]any{"output": outputHash, "inputs": hashes}}, nil
}
