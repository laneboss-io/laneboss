package decisionsrv

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"modernc.org/sqlite"
)

const schemaVersion = 4

var recordColumns = strings.Fields("id record_json record_sha256 verbatim verbatim_sha256 q_text d_text q_sha256 d_sha256 project area kind status answered_utc level instance")
var laneColumns = strings.Fields("id config lane part source_path source_sha256 text created_utc ingested_utc level instance")
var feedbackColumns = strings.Fields("case_id event at source entry_sha256")
var egressColumns = strings.Fields("id record_id which_text text text_sha256 model at endpoint_host input_type previous_entry_sha256 entry_sha256")

type sqlReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}
type sqlWriter interface {
	sqlReader
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func databaseError(err error, readonly bool) error {
	if err == nil {
		return nil
	}
	var ce *commandError
	if errors.As(err, &ce) {
		return ce
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() & 255 {
		case 5, 6:
			return &commandError{5, "database busy: another process held the write lock for longer than the 10-second wait; nothing was changed; try again later"}
		case 8, 14:
			return &commandError{6, "permission problem: SQLite cannot write the database. verify, export, migrate and every command that writes need write permission on the database file; commands that change the store also need write permission on its directory, where SQLite keeps its rollback journal; nothing was changed"}
		case 10, 13:
			if readonly {
				return &commandError{7, "storage problem: SQLite failed while it read the database file; this command only reads, so nothing was changed"}
			}
			return &commandError{7, "storage problem: SQLite failed while it read or wrote the database; nothing was changed"}
		case 19:
			return invalid("refused write: database constraint")
		}
	}
	if os.IsPermission(err) {
		return &commandError{6, "permission problem: cannot reach the database path: permission denied; nothing was changed"}
	}
	return integrity("SQLite operation failed")
}
func unsupportedVersion(v int) error {
	if v >= 1 && v <= 3 {
		return integrity(fmt.Sprintf("unsupported database schema_version %d: this code uses %d; run the migrate command to upgrade the store (nothing is upgraded automatically)", v, schemaVersion))
	}
	return integrity(fmt.Sprintf("unsupported database schema_version %d", v))
}
func openStore(path string, readonly bool, timeout time.Duration) (*sql.DB, error) {
	info, e := os.Stat(path)
	if e != nil {
		if os.IsPermission(e) {
			return nil, databaseError(e, readonly)
		}
		return nil, invalid("database does not exist; run init first")
	}
	if !info.Mode().IsRegular() {
		return nil, invalid("database does not exist; run init first")
	}
	abs, e := filepath.Abs(path)
	if e != nil {
		return nil, invalid("unreadable database path")
	}
	u := url.URL{Scheme: "file", Path: abs}
	q := url.Values{}
	if readonly {
		q.Set("mode", "ro")
	} else {
		q.Set("mode", "rw")
	}
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", timeout.Milliseconds()))
	q.Add("_pragma", "foreign_keys(1)")
	if !readonly {
		q.Add("_pragma", "secure_delete(ON)")
	}
	u.RawQuery = q.Encode()
	db, e := sql.Open("sqlite", u.String())
	if e != nil {
		return nil, databaseError(e, readonly)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	var version int
	e = db.QueryRow("PRAGMA user_version").Scan(&version)
	if e != nil {
		db.Close()
		return nil, databaseError(e, readonly)
	}
	if version != schemaVersion {
		db.Close()
		return nil, unsupportedVersion(version)
	}
	return db, nil
}
func readRows(ctx context.Context, r sqlReader, query string, args ...any) ([]object, error) {
	rows, e := r.QueryContext(ctx, query, args...)
	if e != nil {
		return nil, databaseError(e, true)
	}
	defer rows.Close()
	cols, e := rows.Columns()
	if e != nil {
		return nil, databaseError(e, true)
	}
	out := []object{}
	for rows.Next() {
		values := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if e = rows.Scan(ptrs...); e != nil {
			return nil, databaseError(e, true)
		}
		m := object{}
		for i, k := range cols {
			if b, ok := values[i].([]byte); ok {
				values[i] = bytes.Clone(b)
			}
			m[k] = values[i]
		}
		out = append(out, m)
	}
	return out, databaseError(rows.Err(), true)
}
func recordValues(r object) ([]any, error) {
	q, d := projections(r)
	serial, e := canonical(r)
	if e != nil {
		return nil, e
	}
	a := obj(r["answer"])
	t, e := timestamp(r["answered_at"], "answered_at")
	if e != nil {
		return nil, e
	}
	return []any{r["id"], serial, digest(serial), []byte(str(a["verbatim"])), a["sha256"], q, d, digest(q), digest(d), r["project"], r["area"], r["kind"], r["status"], pythonTime(t), r["level"], r["instance"]}, nil
}
func checkedRecord(row object) (object, error) {
	parsed, e := parseJSON([]byte(str(row["record_json"])))
	if e != nil {
		return nil, recordDamage(row, e)
	}
	r := obj(parsed)
	before, e := canonical(r)
	if e != nil {
		return nil, recordDamage(row, e)
	}
	r, e = validateRecord(r)
	if e != nil {
		return nil, recordDamage(row, e)
	}
	after, e := canonical(r)
	if e != nil {
		return nil, recordDamage(row, e)
	}
	if before != after {
		return nil, recordDamage(row, invalid("required derived record metadata is missing or incorrect"))
	}
	values, e := recordValues(r)
	if e != nil {
		return nil, recordDamage(row, e)
	}
	for i, col := range recordColumns {
		actual, ok := row[col]
		if !ok {
			return nil, recordDamage(row, invalid("missing stored column: "+col))
		}
		if !equalValue(actual, values[i]) {
			return nil, recordDamage(row, invalid(col+" does not match the record"))
		}
	}
	return r, nil
}
func equalValue(a, b any) bool {
	if ai, ok := integer(a); ok {
		if bi, yes := integer(b); yes {
			return ai == bi
		}
	}
	return reflect.DeepEqual(a, b)
}
func recordDamage(row object, e error) error {
	return integrity("record " + str(row["id"]) + ": " + strings.TrimPrefix(e.Error(), "invalid input: "))
}
func checkedLane(row object) (object, error) {
	r := object{}
	for _, col := range laneColumns {
		v, ok := row[col]
		if !ok {
			return nil, integrity("lane record " + str(row["id"]) + ": missing stored column: " + col)
		}
		r[col] = v
	}
	if e := validateLaneRecord(r); e != nil {
		return nil, integrity("lane record " + str(row["id"]) + ": " + strings.TrimPrefix(e.Error(), "invalid input: "))
	}
	return r, nil
}
func checkedFeedback(row object) (object, error) {
	r := object{}
	for _, col := range feedbackColumns {
		r[col] = row[col]
	}
	if e := checkEntry(r, "feedback"); e != nil {
		return nil, e
	}
	if _, ok := feedbackEvents[str(r["event"])]; !ok || strings.TrimSpace(str(r["source"])) == "" {
		return nil, integrity("feedback: invalid event or source")
	}
	if _, e := timestamp(r["at"], "feedback.at"); e != nil {
		return nil, integrity(strings.TrimPrefix(e.Error(), "invalid input: "))
	}
	return r, nil
}
func checkedModel(row object) error {
	label := "model " + str(row["model"])
	if e := checkEntry(row, label); e != nil {
		return e
	}
	if strings.TrimSpace(str(row["model"])) == "" {
		return integrity(label + ": invalid model name")
	}
	if row["provider"] != "fake" && row["provider"] != "voyage" {
		return integrity(label + ": invalid provider")
	}
	n, ok := integer(row["dimension"])
	if !ok || n < 1 || n > 4096 {
		return integrity(label + ": invalid dimension")
	}
	return nil
}
func checkedVector(row object, dimension int) ([]float64, error) {
	label := "vector " + str(row["record_id"]) + " " + str(row["which_text"]) + " " + str(row["model"])
	if e := checkEntry(row, label); e != nil {
		return nil, e
	}
	text, ok := row["text"].(string)
	if !ok || (row["which_text"] != "q_text" && row["which_text"] != "d_text") {
		return nil, integrity(label + ": invalid text metadata")
	}
	blob, ok := row["vector"].([]byte)
	if !ok || row["text_sha256"] != digest(text) || row["vector_sha256"] != digest(blob) {
		return nil, integrity(label + ": hash mismatch")
	}
	n, ok := integer(row["dimension"])
	if !ok || n != int64(dimension) {
		return nil, integrity(label + ": dimension mismatch")
	}
	if _, e := timestamp(row["created_at"], label+".created_at"); e != nil {
		return nil, integrity(label + ": " + strings.TrimPrefix(e.Error(), "invalid input: "))
	}
	v, e := unpackVector(blob, dimension)
	if e != nil {
		return nil, integrity(label + ": " + strings.TrimPrefix(e.Error(), "integrity problem: "))
	}
	return v, nil
}
func unpackVector(blob []byte, dimension int) ([]float64, error) {
	if dimension < 1 || dimension > 4096 {
		return nil, integrity("invalid vector dimension")
	}
	if len(blob) != dimension*4 {
		return nil, integrity("invalid float32 vector blob")
	}
	v := make([]float64, dimension)
	nonzero := false
	for i := range v {
		v[i] = float64(math.Float32frombits(binary.LittleEndian.Uint32(blob[i*4:])))
		if !finite(v[i]) {
			return nil, integrity("nonfinite or zero vector")
		}
		nonzero = nonzero || v[i] != 0
	}
	if !nonzero {
		return nil, integrity("nonfinite or zero vector")
	}
	return v, nil
}
func insertMapping(ctx context.Context, w sqlWriter, table string, columns []string, r object) (sql.Result, error) {
	values := make([]any, len(columns))
	marks := make([]string, len(columns))
	for i, c := range columns {
		values[i] = r[c]
		marks[i] = "?"
	}
	res, e := w.ExecContext(ctx, "INSERT INTO "+table+" ("+strings.Join(columns, ",")+") VALUES ("+strings.Join(marks, ",")+")", values...)
	return res, databaseError(e, false)
}
func insertRecord(ctx context.Context, w sqlWriter, r object) error {
	values, e := recordValues(r)
	if e != nil {
		return e
	}
	marks := make([]string, len(values))
	for i := range marks {
		marks[i] = "?"
	}
	res, e := w.ExecContext(ctx, "INSERT INTO records ("+strings.Join(recordColumns, ",")+") VALUES ("+strings.Join(marks, ",")+")", values...)
	if e != nil {
		return databaseError(e, false)
	}
	rowID, e := res.LastInsertId()
	if e != nil {
		return databaseError(e, false)
	}
	q, d := projections(r)
	if _, e = w.ExecContext(ctx, "INSERT INTO keyword_index(rowid,id,q_text,d_text) VALUES (?,?,?,?)", rowID, r["id"], q, d); e != nil {
		return databaseError(e, false)
	}
	h, e := canonicalHash(r)
	if e != nil {
		return e
	}
	_, e = w.ExecContext(ctx, "INSERT INTO first_written(record_id,record_sha256) VALUES (?,?)", r["id"], h)
	return databaseError(e, false)
}
func updateRecord(ctx context.Context, w sqlWriter, r object) error {
	values, e := recordValues(r)
	if e != nil {
		return e
	}
	sets := []string{}
	for _, c := range recordColumns[1:] {
		sets = append(sets, c+" = ?")
	}
	args := append(values[1:], r["id"])
	if _, e = w.ExecContext(ctx, "UPDATE records SET "+strings.Join(sets, ",")+" WHERE id = ?", args...); e != nil {
		return databaseError(e, false)
	}
	var rowID int64
	if e = w.QueryRowContext(ctx, "SELECT row_id FROM records WHERE id = ?", r["id"]).Scan(&rowID); e != nil {
		return databaseError(e, false)
	}
	if _, e = w.ExecContext(ctx, "DELETE FROM keyword_index WHERE rowid = ?", rowID); e != nil {
		return databaseError(e, false)
	}
	q, d := projections(r)
	_, e = w.ExecContext(ctx, "INSERT INTO keyword_index(rowid,id,q_text,d_text) VALUES (?,?,?,?)", rowID, r["id"], q, d)
	return databaseError(e, false)
}
func insertLane(ctx context.Context, w sqlWriter, r object) (bool, error) {
	if e := validateLaneRecord(r); e != nil {
		return false, e
	}
	rows, e := readRows(ctx, w, "SELECT * FROM lane_records WHERE id = ?", r["id"])
	if e != nil {
		return false, e
	}
	if len(rows) > 0 {
		old, e := checkedLane(rows[0])
		if e != nil {
			return false, e
		}
		if old["source_sha256"] != r["source_sha256"] {
			return false, integrity("lane record " + str(r["id"]) + " already exists with a different source hash")
		}
		if !equalValue(old["level"], r["level"]) || old["instance"] != r["instance"] {
			return false, invalid("a lane record's scope cannot be changed by re-ingest")
		}
		return false, nil
	}
	res, e := insertMapping(ctx, w, "lane_records", laneColumns, r)
	if e != nil {
		return false, e
	}
	id, e := res.LastInsertId()
	if e != nil {
		return false, databaseError(e, false)
	}
	_, e = w.ExecContext(ctx, "INSERT INTO lane_keyword_index(rowid,id,text) VALUES (?,?,?)", id, r["id"], r["text"])
	return e == nil, databaseError(e, false)
}
func appendFeedback(ctx context.Context, w sqlWriter, id, event, source, at string) (object, error) {
	if _, ok := feedbackEvents[event]; !ok {
		return nil, invalid("unsupported feedback event")
	}
	if e := textValue(source, "feedback source", false, false); e != nil {
		return nil, e
	}
	if at == "" {
		at = utcNow()
	}
	if _, e := timestamp(at, "feedback.at"); e != nil {
		return nil, e
	}
	var count int
	if e := w.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM records WHERE id = ?) + (SELECT count(*) FROM lane_records WHERE id = ?)", id, id).Scan(&count); e != nil {
		return nil, databaseError(e, false)
	}
	if count == 0 {
		return nil, invalid("feedback case does not exist")
	}
	old, e := readRows(ctx, w, "SELECT * FROM feedback WHERE case_id = ? AND event = ? AND source = ?", id, event, source)
	if e != nil {
		return nil, e
	}
	if len(old) > 0 {
		r, e := checkedFeedback(old[0])
		if e != nil {
			return nil, e
		}
		r["added"] = false
		return r, nil
	}
	r := object{"case_id": id, "event": event, "at": at, "source": source}
	h, e := entryHash(r)
	if e != nil {
		return nil, e
	}
	r["entry_sha256"] = h
	if _, e = insertMapping(ctx, w, "feedback", feedbackColumns, r); e != nil {
		return nil, e
	}
	r["added"] = true
	return r, nil
}

// Own a BEGIN IMMEDIATE transaction on one connection. Never commit a partial batch.
func writeTransaction(ctx context.Context, db *sql.DB, work func(sqlWriter) error) (failure error) {
	conn, e := db.Conn(ctx)
	if e != nil {
		return databaseError(e, false)
	}
	defer conn.Close()
	if _, e = conn.ExecContext(ctx, "BEGIN IMMEDIATE"); e != nil {
		return databaseError(e, false)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if _, rollbackError := conn.ExecContext(context.Background(), "ROLLBACK"); rollbackError != nil && !strings.Contains(rollbackError.Error(), "no transaction is active") {
			failure = databaseError(rollbackError, false)
		}
	}()
	if e = work(conn); e != nil {
		return e
	}
	_, e = conn.ExecContext(ctx, "COMMIT")
	committed = e == nil
	return databaseError(e, false)
}

func logQuery(path string, p *embeddingProvider, query string) error {
	db, e := openStore(path, false, 10*time.Second)
	if e != nil {
		return e
	}
	defer db.Close()
	return writeTransaction(context.Background(), db, func(w sqlWriter) error {
		var previous string
		var id int64
		e := w.QueryRowContext(context.Background(), "SELECT entry_sha256 FROM egress_log ORDER BY id DESC LIMIT 1").Scan(&previous)
		if e != nil && e != sql.ErrNoRows {
			return databaseError(e, false)
		}
		if e = w.QueryRowContext(context.Background(), "SELECT coalesce(max(id),0)+1 FROM egress_log").Scan(&id); e != nil {
			return databaseError(e, false)
		}
		r := object{"id": id, "record_id": nil, "which_text": "query", "text": query, "text_sha256": digest(query), "model": p.model, "at": utcNow(), "endpoint_host": p.host, "input_type": "query", "previous_entry_sha256": previous}
		h, e := entryHash(r)
		if e != nil {
			return e
		}
		r["entry_sha256"] = h
		_, e = insertMapping(context.Background(), w, "egress_log", egressColumns, r)
		return e
	})
}
