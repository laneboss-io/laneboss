package decisions

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"laneboss.io/laneboss/internal/faults"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
)

var recordColumns = strings.Fields("id record_json record_sha256 verbatim verbatim_sha256 q_text d_text q_sha256 d_sha256 project area kind status answered_utc level instance")
var modelColumns = strings.Fields("model provider dimension entry_sha256")
var vectorColumns = strings.Fields("record_id which_text model dimension text text_sha256 vector vector_sha256 created_at entry_sha256")
var egressColumns = strings.Fields("id record_id which_text text text_sha256 model at endpoint_host input_type previous_entry_sha256 entry_sha256")
var laneColumns = strings.Fields("id config lane part source_path source_sha256 text created_utc ingested_utc level instance")
var feedbackColumns = strings.Fields("case_id event at source entry_sha256")

type progress struct {
	created, model          string
	receipts, sent, vectors int
}
type store struct {
	db       *sql.DB
	conn     *sql.Conn
	legacy   bool
	progress *progress
}

var ctx = context.Background()

func openStore(path, command string, p *progress) (s *store, err error) {
	f, e := os.Stat(path)
	exists := e == nil
	if e != nil && !os.IsNotExist(e) && !errors.Is(e, syscall.ENOTDIR) {
		return nil, access("cannot reach the database path: permission denied")
	}
	if command != "init" && (!exists || !f.Mode().IsRegular()) {
		return nil, invalid("database does not exist; run init first")
	}
	if command == "init" && exists && !f.Mode().IsRegular() {
		return nil, invalid("database path is not a file")
	}
	if command == "init" && !exists {
		file, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil && !os.IsExist(e) {
			if os.IsPermission(e) {
				return nil, access("cannot create the database file: its directory is not writable")
			}
			return nil, invalid("unreadable database path")
		}
		if e == nil {
			p.created = path
			if e = file.Close(); e != nil {
				return nil, e
			}
		}
	}
	if member(command, "verify export add") && syscall.Access(path, 2) != nil {
		return nil, access("this command needs write permission on the database file")
	}
	abs, e := filepath.Abs(path)
	if e != nil {
		return nil, invalid("unreadable database path")
	}
	uri := (&url.URL{Scheme: "file", Path: abs}).String() + "?mode=rw"
	db, e := sql.Open("sqlite", uri)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	conn, e := db.Conn(ctx)
	if e != nil {
		db.Close()
		return nil, e
	}
	s = &store{db: db, conn: conn, progress: p}
	defer func() {
		if err != nil {
			s.close()
		}
	}()
	if _, e = s.exec("PRAGMA busy_timeout = 10000"); e != nil {
		return s, e
	}
	if _, e = s.exec("PRAGMA foreign_keys = ON"); e != nil {
		return s, e
	}
	if _, e = s.exec("PRAGMA secure_delete = ON"); e != nil {
		return s, e
	}
	version, e := s.count("PRAGMA user_version")
	if e != nil {
		return s, e
	}
	s.legacy = command == "migrate" && version >= 1 && version <= 3
	if command == "init" && version == 0 {
		tables, e := s.query("SELECT name FROM sqlite_master WHERE type='table'")
		if e != nil {
			return s, e
		}
		if len(tables) > 0 {
			return s, integrity("database is not an empty decision store")
		}
		e = s.transaction(func() error {
			for _, defs := range [][]definition{versionOne, versionTwo, versionThree} {
				for _, d := range defs {
					if _, e := s.exec(d.sql); e != nil {
						return e
					}
				}
			}
			if e := s.addVersionFour(); e != nil {
				return e
			}
			_, e := s.exec("PRAGMA user_version = 4")
			return e
		})
		if e != nil {
			return s, e
		}
	} else if version != schemaVersion && !(command == "migrate" && version >= 1 && version <= 3) {
		if version >= 1 && version <= 3 {
			return s, integrity(fmt.Sprintf("unsupported database schema_version %d: this code uses %d; run the migrate command to upgrade the store (nothing is upgraded automatically)", version, schemaVersion))
		}
		return s, integrity(fmt.Sprintf("unsupported database schema_version %d", version))
	}
	return s, nil
}
func (s *store) close() {
	if s != nil {
		if s.conn != nil {
			s.conn.Close()
		}
		if s.db != nil {
			s.db.Close()
		}
	}
}
func (s *store) exec(q string, args ...any) (sql.Result, error) {
	if err := faults.SQL(q); err != nil {
		return nil, err
	}
	for i, v := range args {
		if n, ok := integer(v); ok {
			args[i] = n
		}
	}
	return s.conn.ExecContext(ctx, q, args...)
}
func (s *store) query(q string, args ...any) ([]object, error) {
	if err := faults.SQL(q); err != nil {
		return nil, err
	}
	rows, e := s.conn.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	cols, e := rows.Columns()
	if e != nil {
		return nil, e
	}
	out := []object{}
	for rows.Next() {
		v := make([]any, len(cols))
		ptr := make([]any, len(cols))
		for i := range v {
			ptr[i] = &v[i]
		}
		if e = rows.Scan(ptr...); e != nil {
			return nil, e
		}
		m := object{}
		for i, k := range cols {
			m[k] = v[i]
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
func (s *store) one(q string, args ...any) (object, error) {
	a, e := s.query(q, args...)
	if e != nil || len(a) == 0 {
		return nil, e
	}
	return a[0], nil
}
func (s *store) count(q string, args ...any) (int, error) {
	m, e := s.one(q, args...)
	if e != nil {
		return 0, e
	}
	if m == nil {
		return 0, integrity("SQLite query returned no count")
	}
	for _, v := range m {
		n, ok := integer(v)
		if !ok {
			return 0, integrity("SQLite query returned an invalid count")
		}
		return int(n), nil
	}
	return 0, integrity("SQLite query returned no count")
}
func (s *store) transaction(fn func() error) (err error) {
	if _, err = s.exec("BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer func() {
		if caught := recover(); caught != nil {
			s.exec("ROLLBACK")
			panic(caught)
		}
		if err != nil {
			s.exec("ROLLBACK")
		}
	}()
	if err = fn(); err != nil {
		return err
	}
	_, err = s.exec("COMMIT")
	return err
}
func (s *store) insertMapping(table string, columns []string, v object) error {
	args := make([]any, len(columns))
	slots := make([]string, len(columns))
	for i, c := range columns {
		x, ok := v[c]
		if !ok {
			return invalid("missing required field: " + table + "." + c)
		}
		args[i] = x
		slots[i] = "?"
	}
	_, e := s.exec("INSERT INTO "+table+" ("+strings.Join(columns, ",")+") VALUES ("+strings.Join(slots, ",")+")", args...)
	return e
}
func recordValues(v object) object {
	q, d := projections(v)
	serialized := canonical(v)
	t, _ := timestamp(v["answered_at"], "answered_at")
	return object{"id": v["id"], "record_json": serialized, "record_sha256": digest(serialized), "verbatim": []byte(str(obj(v["answer"])["verbatim"])), "verbatim_sha256": obj(v["answer"])["sha256"], "q_text": q, "d_text": d, "q_sha256": digest(q), "d_sha256": digest(d), "project": v["project"], "area": v["area"], "kind": v["kind"], "status": v["status"], "answered_utc": iso(t, false), "level": v["level"], "instance": v["instance"]}
}
func (s *store) checkedRecord(row object) (object, error) {
	raw, e := parseJSON([]byte(str(row["record_json"])))
	if e != nil {
		return nil, integrity("record " + str(row["id"]) + ": " + e.Error())
	}
	v, e := validateRecord(raw)
	if e != nil {
		return nil, integrity("record " + str(row["id"]) + ": " + e.Error())
	}
	if !equal(raw, v) {
		return nil, integrity("record " + str(row["id"]) + ": required derived record metadata is missing or incorrect")
	}
	expected := recordValues(v)
	for _, c := range recordColumns {
		have, ok := row[c]
		if !ok && !(s.legacy && (c == "level" || c == "instance")) {
			return nil, integrity("record " + str(row["id"]) + ": missing stored column: " + c)
		}
		if !storedEqual(have, expected[c]) {
			return nil, integrity("record " + str(row["id"]) + ": " + c + " does not match the record")
		}
	}
	return v, nil
}
func (s *store) get(id string) (object, error) {
	row, e := s.one("SELECT * FROM records WHERE id = ?", id)
	if e != nil {
		return nil, e
	}
	if row == nil {
		return nil, invalid("unknown id: " + id)
	}
	return s.checkedRecord(row)
}
func (s *store) firstWritten(id string) (string, error) {
	row, e := s.one("SELECT record_sha256 FROM first_written WHERE record_id = ?", id)
	return str(row["record_sha256"]), e
}
func (s *store) index(v object, rowID any) error {
	q, d := projections(v)
	if _, e := s.exec("DELETE FROM keyword_index WHERE rowid = ?", rowID); e != nil {
		return e
	}
	_, e := s.exec("INSERT INTO keyword_index(rowid, id, q_text, d_text) VALUES (?, ?, ?, ?)", rowID, v["id"], q, d)
	return e
}
func (s *store) insertRecord(v object, first string) error {
	old, e := s.one("SELECT * FROM records WHERE id = ?", v["id"])
	if e != nil {
		return e
	}
	if old != nil {
		existing, e := s.checkedRecord(old)
		if e != nil {
			return e
		}
		if obj(existing["answer"])["verbatim"] != obj(v["answer"])["verbatim"] {
			return invalid("answer.verbatim of an existing id is immutable: " + str(v["id"]))
		}
		return invalid("duplicate id: " + str(v["id"]))
	}
	if e = s.insertMapping("records", recordColumns, recordValues(v)); e != nil {
		return e
	}
	row, e := s.one("SELECT row_id FROM records WHERE id = ?", v["id"])
	if e != nil {
		return e
	}
	if e = s.index(v, row["row_id"]); e != nil {
		return e
	}
	if first != "" {
		_, e = s.exec("INSERT INTO first_written (record_id, record_sha256) VALUES (?, ?)", v["id"], first)
	}
	return e
}
func (s *store) updateRecord(v object) error {
	values := recordValues(v)
	sets := []string{}
	args := []any{}
	for _, c := range recordColumns[1:] {
		sets = append(sets, c+" = ?")
		args = append(args, values[c])
	}
	args = append(args, v["id"])
	if _, e := s.exec("UPDATE records SET "+strings.Join(sets, ",")+" WHERE id = ?", args...); e != nil {
		return e
	}
	row, e := s.one("SELECT row_id FROM records WHERE id = ?", v["id"])
	if e != nil {
		return e
	}
	return s.index(v, row["row_id"])
}
func (s *store) add(original any) (object, error) {
	v, e := validateRecord(original)
	if e != nil {
		return nil, e
	}
	if str(v["supersedes"]) != "" || str(v["superseded_by"]) != "" {
		return nil, invalid("linked records must be written with supersede or import")
	}
	e = s.transaction(func() error { return s.insertRecord(v, digest(canonical(v))) })
	return v, e
}
func (s *store) supersede(id string, original any) (object, error) {
	v, e := validateRecord(original)
	if e != nil {
		return nil, e
	}
	if e = markSuperseding(v, id); e != nil {
		return nil, e
	}
	e = s.transaction(func() error {
		old, e := s.get(id)
		if e != nil {
			return e
		}
		if e = markSuperseded(old, str(v["id"])); e != nil {
			return e
		}
		if e = s.insertRecord(v, digest(canonical(v))); e != nil {
			return e
		}
		return s.updateRecord(old)
	})
	return v, e
}
func (s *store) annotate(id string, outcome any) (object, error) {
	if e := validateOutcome(outcome); e != nil {
		return nil, e
	}
	var v object
	e := s.transaction(func() error {
		var e error
		v, e = s.get(id)
		if e != nil {
			return e
		}
		for k, items := range obj(outcome) {
			a := append([]any{}, list(obj(v["outcome"])[k])...)
			obj(v["outcome"])[k] = append(a, list(items)...)
		}
		return s.updateRecord(v)
	})
	return v, e
}

var configPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
var lanePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func (s *store) checkedLane(row object) (object, error) {
	v := object{}
	for _, c := range laneColumns {
		x, ok := row[c]
		if !ok && !(s.legacy && (c == "level" || c == "instance")) {
			return nil, integrity("lane record: missing stored column: " + c)
		}
		if ok {
			v[c] = x
		}
	}
	bad := func(e error) (object, error) {
		return nil, integrity("lane record " + str(row["id"]) + ": " + e.Error())
	}
	if e := scope(v); e != nil {
		return bad(e)
	}
	for _, c := range laneColumns[:9] {
		if e := textValue(v[c], c, false, false); e != nil {
			return bad(e)
		}
	}
	if !configPattern.MatchString(str(v["config"])) || !lanePattern.MatchString(str(v["lane"])) || !member(str(v["part"]), "report events attachment") || !hashPattern.MatchString(str(v["source_sha256"])) {
		return bad(invalid("invalid lane record identity"))
	}
	expected := str(v["config"]) + "/" + str(v["lane"]) + "/" + str(v["part"]) + "/" + str(v["source_sha256"])[:16]
	if v["id"] != expected {
		return bad(invalid("id does not name its configuration, lane, part and source hash"))
	}
	if digest(v["text"]) != v["source_sha256"] {
		return bad(invalid("source_sha256 does not name the record's own text"))
	}
	for _, f := range []string{"created_utc", "ingested_utc"} {
		if _, e := timestamp(v[f], f); e != nil {
			return bad(e)
		}
	}
	return v, nil
}
func checkedModel(v object) error {
	label := "model " + str(v["model"])
	if e := checkEntry(v, label); e != nil {
		return e
	}
	if trimmed(str(v["model"])) == "" {
		return integrity(label + ": invalid model name")
	}
	if !member(str(v["provider"]), "fake voyage") {
		return integrity(label + ": invalid provider")
	}
	if n, ok := integer(v["dimension"]); !ok || n < 1 || n > 4096 {
		return integrity(label + ": invalid dimension")
	}
	return nil
}
func packVector(v any, dimension int) ([]byte, error) {
	a, ok := v.([]any)
	if !ok || len(a) != dimension {
		return nil, invalid("embedding dimension mismatch")
	}
	blob := make([]byte, 4*dimension)
	for i, x := range a {
		n, ok := number(x)
		if !ok {
			return nil, invalid("embedding contains invalid or nonfinite numbers")
		}
		f := float32(n)
		if math.IsInf(float64(f), 0) || math.IsNaN(float64(f)) {
			return nil, invalid("embedding overflows float32")
		}
		binary.LittleEndian.PutUint32(blob[i*4:], math.Float32bits(f))
	}
	return blob, nil
}
func unpackVector(v any, dimension int) ([]float64, error) {
	if dimension < 1 || dimension > 4096 {
		return nil, integrity("invalid vector dimension")
	}
	blob, ok := v.([]byte)
	if !ok || len(blob) != dimension*4 {
		return nil, integrity("invalid float32 vector blob")
	}
	a := make([]float64, dimension)
	nonzero := false
	for i := range a {
		n := float64(math.Float32frombits(binary.LittleEndian.Uint32(blob[i*4:])))
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, integrity("nonfinite or zero vector")
		}
		a[i] = n
		nonzero = nonzero || n != 0
	}
	if !nonzero {
		return nil, integrity("nonfinite or zero vector")
	}
	return a, nil
}
func checkedVector(v object, dimension int) ([]float64, error) {
	label := "vector " + str(v["record_id"]) + " " + str(v["which_text"]) + " " + str(v["model"])
	if e := checkEntry(v, label); e != nil {
		return nil, e
	}
	if _, ok := v["text"].(string); !ok || !member(str(v["which_text"]), "q_text d_text") {
		return nil, integrity(label + ": invalid text metadata")
	}
	if _, ok := v["vector"].([]byte); !ok || v["text_sha256"] != digest(v["text"]) || v["vector_sha256"] != digest(v["vector"]) {
		return nil, integrity(label + ": hash mismatch")
	}
	n, ok := integer(v["dimension"])
	if !ok || n != int64(dimension) {
		return nil, integrity(label + ": dimension mismatch")
	}
	if _, e := timestamp(v["created_at"], label+".created_at"); e != nil {
		return nil, integrity(label + ": " + e.Error())
	}
	return unpackVector(v["vector"], dimension)
}
func (s *store) stats() (object, error) {
	out := object{}
	for _, c := range []struct{ key, q string }{{"schema_version", "PRAGMA user_version"}, {"records", "SELECT count(*) FROM records"}, {"vectors", "SELECT count(*) FROM vectors"}, {"egress_entries", "SELECT count(*) FROM egress_log"}, {"records_without_vectors", "SELECT count(*) FROM records r WHERE NOT EXISTS (SELECT 1 FROM vectors v WHERE v.record_id = r.id)"}, {"stale_vectors", "SELECT count(*) FROM vectors v JOIN records r ON r.id = v.record_id WHERE v.text_sha256 != CASE v.which_text WHEN 'q_text' THEN r.q_sha256 ELSE r.d_sha256 END"}} {
		n, e := s.count(c.q)
		if e != nil {
			return nil, e
		}
		out[c.key] = n
	}
	for _, c := range []struct{ table, key string }{{"lane_records", "lane_records"}, {"feedback", "feedback_events"}} {
		n, e := s.count("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?", c.table)
		if e != nil {
			return nil, e
		}
		out[c.key] = 0
		if n > 0 {
			n, e = s.count("SELECT count(*) FROM " + c.table)
			if e != nil {
				return nil, e
			}
			out[c.key] = n
		}
	}
	n, e := s.count("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'first_written'")
	if e != nil {
		return nil, e
	}
	out["records_without_first_written"] = out["records"]
	if n > 0 {
		n, e = s.count("SELECT count(*) FROM records r WHERE NOT EXISTS (SELECT 1 FROM first_written f WHERE f.record_id = r.id)")
		if e != nil {
			return nil, e
		}
		out["records_without_first_written"] = n
	}
	a, e := s.query("SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'lane_records' ORDER BY name")
	if e != nil {
		return nil, e
	}
	triggers := []string{}
	for _, r := range a {
		triggers = append(triggers, str(r["name"]))
	}
	out["lane_record_triggers"] = triggers
	a, e = s.query("SELECT status, count(*) AS count FROM records GROUP BY status ORDER BY status")
	if e != nil {
		return nil, e
	}
	statuses := object{}
	for _, r := range a {
		statuses[str(r["status"])] = r["count"]
	}
	out["statuses"] = statuses
	a, e = s.query("SELECT * FROM models ORDER BY model")
	if e != nil {
		return nil, e
	}
	out["models"] = a
	return out, nil
}
func (s *store) layoutMismatch(version int) (string, error) {
	rows, e := s.query("SELECT type, name, tbl_name, sql FROM sqlite_master")
	if e != nil {
		return "", e
	}
	actual := map[string]definition{}
	for _, r := range rows {
		d := definition{str(r["type"]), str(r["name"]), str(r["tbl_name"]), str(r["sql"])}
		k := d.kind + "\x00" + d.name
		if _, ok := actual[k]; ok {
			return "duplicate " + d.kind + " " + d.name, nil
		}
		actual[k] = d
	}
	expected := expectedLayout(version)
	all := map[string]bool{}
	for k := range actual {
		all[k] = true
	}
	for k := range expected {
		all[k] = true
	}
	ordered := []string{}
	for k := range all {
		ordered = append(ordered, k)
	}
	sort.Slice(ordered, func(i, j int) bool {
		a, b := strings.Split(ordered[i], "\x00"), strings.Split(ordered[j], "\x00")
		if a[1] != b[1] {
			return a[1] < b[1]
		}
		return a[0] < b[0]
	})
	for _, k := range ordered {
		have, h := actual[k]
		want, w := expected[k]
		if h && w && have == want {
			continue
		}
		p := strings.Split(k, "\x00")
		if !w {
			return "unexpected " + p[0] + " " + p[1], nil
		}
		if !h {
			return "missing " + p[0] + " " + p[1], nil
		}
		return "changed " + p[0] + " " + p[1], nil
	}
	return "", nil
}
func (s *store) verify() (object, error) {
	if _, e := s.exec("BEGIN IMMEDIATE"); e != nil {
		return nil, e
	}
	v, e := s.verifySnapshot(schemaVersion)
	_, r := s.exec("ROLLBACK")
	if e != nil {
		return nil, e
	}
	return v, r
}
func (s *store) verifySnapshot(version int) (object, error) {
	mismatch, e := s.layoutMismatch(version)
	if e != nil {
		return nil, e
	}
	if mismatch != "" {
		return nil, integrity("schema definition mismatch: " + mismatch)
	}
	if _, e = s.exec("INSERT INTO keyword_index(keyword_index) VALUES ('integrity-check')"); e != nil {
		if sqliteCode(e) == 5 || sqliteCode(e) == 6 || sqliteCode(e) == 8 || sqliteCode(e) == 10 || sqliteCode(e) == 13 {
			return nil, e
		}
		return nil, integrity("keyword index internal integrity problem")
	}
	rows, e := s.query("PRAGMA integrity_check")
	if e != nil {
		return nil, e
	}
	if len(rows) != 1 || str(rows[0]["integrity_check"]) != "ok" {
		return nil, integrity("SQLite integrity_check failed")
	}
	rows, e = s.query("PRAGMA foreign_key_check")
	if e != nil {
		return nil, e
	}
	if len(rows) > 0 {
		return nil, integrity("foreign key integrity problem")
	}
	rows, e = s.query("SELECT * FROM records ORDER BY id")
	if e != nil {
		return nil, e
	}
	records := map[string]object{}
	order := []string{} // load order (ORDER BY id), so integrity messages are deterministic like the Python store
	unverified := 0
	for _, row := range rows {
		v, e := s.checkedRecord(row)
		if e != nil {
			return nil, e
		}
		id := str(v["id"])
		records[id] = v
		order = append(order, id)
		index, e := s.one("SELECT rowid, * FROM keyword_index WHERE rowid = ?", row["row_id"])
		if e != nil {
			return nil, e
		}
		if index == nil || !storedEqual(index["rowid"], row["row_id"]) || index["id"] != row["id"] || index["q_text"] != row["q_text"] || index["d_text"] != row["d_text"] {
			return nil, integrity("record " + id + ": keyword index mismatch")
		}
		for _, source := range list(obj(v["provenance"])["sources"]) {
			if _, ok := obj(source)["line_text"]; !ok {
				unverified++
			}
		}
	}
	n, e := s.count("SELECT count(*) FROM keyword_index")
	if e != nil {
		return nil, e
	}
	if n != len(records) {
		return nil, integrity("keyword index has extra rows")
	}
	lanes := map[string]object{}
	if version >= 3 {
		rows, e = s.query("SELECT * FROM lane_records ORDER BY id")
		if e != nil {
			return nil, e
		}
		for _, row := range rows {
			v, e := s.checkedLane(row)
			if e != nil {
				return nil, e
			}
			lanes[str(v["id"])] = v
			index, e := s.one("SELECT rowid, * FROM lane_keyword_index WHERE rowid = ?", row["row_id"])
			if e != nil {
				return nil, e
			}
			if index == nil || !storedEqual(index["rowid"], row["row_id"]) || index["id"] != row["id"] || index["text"] != row["text"] {
				return nil, integrity("lane record " + str(v["id"]) + ": keyword index mismatch")
			}
		}
		n, e = s.count("SELECT count(*) FROM lane_keyword_index")
		if e != nil {
			return nil, e
		}
		if n != len(lanes) {
			return nil, integrity("the lane record keyword index has extra rows")
		}
	}
	if version >= 4 {
		events, e := s.feedback()
		if e != nil {
			return nil, e
		}
		for _, v := range events {
			if records[str(v["case_id"])] == nil && lanes[str(v["case_id"])] == nil {
				return nil, integrity("feedback: case is missing")
			}
		}
	}
	for _, id := range order {
		v := records[id]
		for _, pair := range [][2]string{{"supersedes", "superseded_by"}, {"superseded_by", "supersedes"}} {
			target := str(v[pair[0]])
			if target != "" && (records[target] == nil || records[target][pair[1]] != id) {
				return nil, integrity("record " + id + ": broken " + pair[0] + " link")
			}
		}
		visited := map[string]bool{}
		current := v
		for str(current["supersedes"]) != "" {
			cid := str(current["id"])
			if visited[cid] {
				return nil, integrity("record " + id + ": supersession cycle")
			}
			visited[cid] = true
			current = records[str(current["supersedes"])]
			if current == nil {
				return nil, integrity("record " + id + ": supersession target is missing")
			}
		}
	}
	if version >= 2 {
		rows, e = s.query("SELECT record_id, record_sha256 FROM first_written")
		if e != nil {
			return nil, e
		}
		for _, r := range rows {
			if records[str(r["record_id"])] == nil {
				return nil, integrity("first-written hash for a missing record")
			}
			if !hashPattern.MatchString(str(r["record_sha256"])) {
				return nil, integrity("record " + str(r["record_id"]) + ": invalid first-written hash")
			}
		}
	}
	models := map[string]object{}
	rows, e = s.query("SELECT * FROM models ORDER BY model")
	if e != nil {
		return nil, e
	}
	for _, r := range rows {
		if e = checkedModel(r); e != nil {
			return nil, e
		}
		models[str(r["model"])] = r
	}
	receipts, e := s.egress()
	if e != nil {
		return nil, e
	}
	sent := map[string]bool{}
	previous := ""
	for i, v := range receipts {
		n, ok := integer(v["id"])
		if !ok || n != int64(i+1) {
			return nil, integrity("egress ids are not contiguous")
		}
		label := fmt.Sprintf("egress entry %d", n)
		if v["previous_entry_sha256"] != previous {
			return nil, integrity(label + ": previous hash mismatch")
		}
		if e = checkEntry(v, label); e != nil {
			return nil, e
		}
		if _, ok := v["text"].(string); !ok || v["text_sha256"] != digest(v["text"]) {
			return nil, integrity(label + ": hash mismatch")
		}
		if _, e = timestamp(v["at"], label+".at"); e != nil {
			return nil, integrity(e.Error())
		}
		if v["which_text"] == "query" {
			if v["record_id"] != nil || v["input_type"] != "query" {
				return nil, integrity(label + ": invalid query metadata")
			}
		} else if !member(str(v["which_text"]), "q_text d_text") || v["input_type"] != "document" {
			return nil, integrity(label + ": invalid document metadata")
		}
		sent[receiptKey(v)] = true
		previous = str(v["entry_sha256"])
	}
	rows, e = s.query("SELECT * FROM vectors ORDER BY record_id, which_text, model")
	if e != nil {
		return nil, e
	}
	for _, r := range rows {
		model := models[str(r["model"])]
		if model == nil {
			return nil, integrity("vector: model is missing")
		}
		d, _ := integer(model["dimension"])
		if _, e = checkedVector(r, int(d)); e != nil {
			return nil, e
		}
		if !sent[receiptKey(r)] {
			return nil, integrity("vector: missing egress receipt")
		}
	}
	out, e := s.stats()
	if e != nil {
		return nil, e
	}
	out["ok"] = true
	out["source_hashes_unverified"] = unverified
	return out, nil
}
func receiptKey(v object) string {
	return canonical([]any{v["record_id"], v["which_text"], v["model"], v["text_sha256"]})
}
func (s *store) egress() ([]object, error) { return s.query("SELECT * FROM egress_log ORDER BY id") }
func (s *store) feedback() ([]object, error) {
	rows, e := s.query("SELECT * FROM feedback ORDER BY id")
	if e != nil {
		return nil, e
	}
	out := []object{}
	for _, r := range rows {
		v, e := checkedFeedback(r)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, nil
}

func checkedFeedback(row object) (object, error) {
	v := object{}
	for _, c := range feedbackColumns {
		v[c] = row[c]
	}
	if e := checkEntry(v, "feedback"); e != nil {
		return nil, e
	}
	if !member(str(v["event"]), "merged accepted abandoned refusal cited") || trimmed(str(v["source"])) == "" {
		return nil, integrity("feedback: invalid event or source")
	}
	if _, e := timestamp(v["at"], "feedback.at"); e != nil {
		return nil, integrity(e.Error())
	}
	return v, nil
}
func (s *store) addVersionFour() error {
	for _, table := range []string{"records", "lane_records"} {
		for _, c := range []string{"level INTEGER", "instance TEXT"} {
			if _, e := s.exec("ALTER TABLE " + table + " ADD COLUMN " + c); e != nil {
				return e
			}
		}
	}
	for _, d := range versionFour {
		if _, e := s.exec(d.sql); e != nil {
			return e
		}
	}
	return nil
}
func (s *store) migrate() (object, error) {
	version, e := s.count("PRAGMA user_version")
	if e != nil {
		return nil, e
	}
	unchanged := func() object {
		return object{"migrated": false, "from_schema_version": schemaVersion, "to_schema_version": schemaVersion, "message": "already at schema_version 4; nothing was changed"}
	}
	if version == schemaVersion {
		return unchanged(), nil
	}
	started := version
	var verified object
	did := false
	e = s.transaction(func() error {
		var e error
		version, e = s.count("PRAGMA user_version")
		if e != nil {
			return e
		}
		if version == schemaVersion {
			return nil
		}
		if version < 1 || version > 3 {
			return integrity(fmt.Sprintf("unsupported database schema_version %d", version))
		}
		started = version
		row, e := s.one("SELECT sql FROM sqlite_master WHERE type='table' AND name='egress_log'")
		if e != nil {
			return e
		}
		if row != nil && str(row["sql"]) == strings.Replace(egressSQL, "    previous_entry_sha256 TEXT NOT NULL,\n", "", 1) {
			n, e := s.count("SELECT count(*) FROM egress_log")
			if e != nil {
				return e
			}
			return integrity(olderLayoutMessage(n))
		}
		for version < 4 {
			verified, e = s.verifySnapshot(version)
			if e != nil {
				return e
			}
			switch version {
			case 1:
				for _, d := range versionTwo {
					if _, e = s.exec(d.sql); e != nil {
						return e
					}
				}
			case 2:
				for _, d := range versionThree {
					if _, e = s.exec(d.sql); e != nil {
						return e
					}
				}
			case 3:
				if e = s.addVersionFour(); e != nil {
					return e
				}
			}
			version++
		}
		if _, e = s.verifySnapshot(4); e != nil {
			return e
		}
		if _, e = s.exec("PRAGMA user_version = 4"); e != nil {
			return e
		}
		did = true
		return nil
	})
	if e != nil {
		return nil, e
	}
	s.legacy = false
	if !did {
		return unchanged(), nil
	}
	return object{"migrated": true, "from_schema_version": started, "to_schema_version": schemaVersion, "records": verified["records"], "vectors": verified["vectors"], "egress_entries": verified["egress_entries"], "message": "verified each layout, added the missing schema objects, level and instance columns and append-only feedback, and stamped schema_version 4; existing content and hashes are unchanged; legacy scopes are NULL"}, nil
}

func olderLayoutMessage(receipts int) string {
	prefix := "cannot migrate: this schema_version 1 store has the older layout, written before the egress hash chain (its egress_log has no previous_entry_sha256). "
	if receipts == 0 {
		return prefix + "It has no egress receipts, so its records can be moved as they are: export it with the old release and import the export into a new store with this release."
	}
	return prefix + "It holds " + plural(receipts, "egress receipt") + ", and egress history cannot be carried into a version-2 store. What works: export it with the old release, keep the manifest line and the record lines of that export, set the models, vectors and egress counts in the manifest to 0, import the result into a new store, run embed again (this sends the texts to the provider again), and keep the old store file as the record of what was sent before. The Older layout section of docs/decisions.md shows the commands."
}
