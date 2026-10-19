package orgtree

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"laneboss.io/laneboss/internal/decisionsrv"

	"modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"
)

const decisionStorePath = home + "/" + decisionsrv.DefaultStoreRelativePath
const decisionStoreUnreadable = "decision store cannot be read; secret scan could not complete"

var decisionStoreSuffixes = []string{"", "-wal", "-shm", "-journal"}

type storeFileSnapshot struct {
	info os.FileInfo
	data []byte
	hash [sha256.Size]byte
}

type storeReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func decisionStoreFile(relative string) bool {
	for _, suffix := range decisionStoreSuffixes {
		if relative == decisionStorePath+suffix {
			return true
		}
	}
	return false
}

// Read through no-follow descriptors, retaining the bounded bytes as well as
// their identities. Hashes detect same-size changes that restore the old mtime.
func (t *tree) decisionStoreSnapshot() (map[string]*storeFileSnapshot, error) {
	snapshot := make(map[string]*storeFileSnapshot)
	for _, suffix := range decisionStoreSuffixes {
		relative := decisionStorePath + suffix
		if !t.withinBudget() || !t.parentsSafe(relative) {
			return nil, errors.New(decisionStoreUnreadable)
		}
		info, err := os.Lstat(t.filename(relative))
		if os.IsNotExist(err) && suffix != "" {
			snapshot[relative] = nil
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			t.problem(relative, "managed files must be regular files, not symbolic links or devices")
			return nil, errors.New(decisionStoreUnreadable)
		}
		if info.Size() > maxFileBytes {
			t.problem(relative, "file exceeds the 2 MiB validation limit; secret scan could not complete")
			return nil, errors.New(decisionStoreUnreadable)
		}
		stream, err := os.OpenFile(t.filename(relative), os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		opened, statErr := stream.Stat()
		if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
			stream.Close()
			return nil, errors.New(decisionStoreUnreadable)
		}
		data, readErr := io.ReadAll(io.LimitReader(stream, maxFileBytes+1))
		finished, finishErr := stream.Stat()
		closeErr := stream.Close()
		if readErr != nil || finishErr != nil || closeErr != nil || len(data) > maxFileBytes ||
			!os.SameFile(opened, finished) || opened.Size() != finished.Size() || !opened.ModTime().Equal(finished.ModTime()) {
			return nil, errors.New(decisionStoreUnreadable)
		}
		snapshot[relative] = &storeFileSnapshot{finished, data, sha256.Sum256(data)}
	}
	return snapshot, nil
}

func (t *tree) scanDecisionStore() {
	if err := t.readDecisionStore(); err != nil {
		t.problem(decisionStorePath, decisionStoreUnreadable)
	}
}

func (t *tree) readDecisionStore() (err error) {
	mode, err := decisionStoreFaultMode()
	if err != nil {
		return err
	}
	legacy := mode == "org-store-legacy-scan"
	skip := mode == "org-store-skip-text"
	before, err := t.decisionStoreSnapshot()
	if err != nil {
		return err
	}
	main := before[decisionStorePath]
	pageSize := sqlitePageSize(main.data)
	if pageSize == 0 {
		return errors.New(decisionStoreUnreadable)
	}
	if t.binaryFiles == nil {
		t.binaryFiles = make(map[string]bool)
	}
	skipCompanions, err := decisionStoreCompanionFault()
	if err != nil {
		return err
	}
	for _, suffix := range decisionStoreSuffixes[1:] {
		relative := decisionStorePath + suffix
		item := before[relative]
		if item == nil {
			continue
		}
		if !skipCompanions && !validStoreCompanion(suffix, item.data, before, pageSize) {
			// A familiar filename alone never grants the binary exception.
			if _, ok := t.read(relative, true); !ok {
				return errors.New(decisionStoreUnreadable)
			}
			continue
		}
		t.binaryFiles[relative] = true
	}
	if !legacy && !skip {
		if mode == "org-store-raw-join" {
			for relative, item := range before {
				if item != nil && (!skipCompanions || relative == decisionStorePath) {
					if err = t.scanRawStoreText(relative, item.data, 1); err != nil {
						return err
					}
				}
			}
		} else if err = t.scanRawStore(before, skipCompanions); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithDeadline(context.Background(), t.deadline)
	defer cancel()
	copyPath, cleanup, err := copyDecisionStore(before, t.binaryFiles)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, cleanup()) }()
	query := url.Values{"mode": {"ro"}}
	if legacy {
		query.Set("immutable", "1")
	} else if mode == "org-store-copy-nolock" {
		// Reproduce e735a26's WAL refusal only on the private test copy.
		query.Set("nolock", "1")
		query.Add("_pragma", "locking_mode(EXCLUSIVE)")
	}
	query.Add("_pragma", "query_only(ON)")
	uri := url.URL{Scheme: "file", Path: copyPath, RawQuery: query.Encode()}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = sqlite.Limit(conn, sqlitelib.SQLITE_LIMIT_LENGTH, maxFileBytes); err != nil {
		return err
	}
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var check string
	if err = tx.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&check); err != nil {
		return err
	}
	if check != "ok" {
		return errors.New(decisionStoreUnreadable)
	}
	remaining := maxFileBytes
	tables := []string{"records"}
	if !legacy {
		tables, err = t.scanStoreSchema(ctx, tx, &remaining, skip, mode == "org-store-fts-double")
		if err != nil {
			return err
		}
	}
	if !skip {
		for _, table := range tables {
			if err = t.scanStoreTable(ctx, tx, table, &remaining, legacy); err != nil {
				return err
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	if err = conn.Close(); err != nil {
		return err
	}
	if err = db.Close(); err != nil {
		return err
	}
	after, err := t.decisionStoreSnapshot()
	if err != nil {
		return err
	}
	for relative, initial := range before {
		current := after[relative]
		if initial == nil && current == nil {
			continue
		}
		if initial == nil || current == nil || !os.SameFile(initial.info, current.info) ||
			initial.info.Size() != current.info.Size() || !initial.info.ModTime().Equal(current.info.ModTime()) ||
			initial.hash != current.hash {
			return errors.New(decisionStoreUnreadable)
		}
	}
	return scanTime(t.deadline)
}

func (t *tree) scanStoreSchema(ctx context.Context, db storeReader, remaining *int, skip, doubleFTS bool) ([]string, error) {
	var version int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return nil, err
	}
	if version != 4 {
		return nil, errors.New(decisionStoreUnreadable)
	}
	expected := make(map[string]decisionsrv.HistorySchemaObject)
	for _, entry := range decisionsrv.HistorySchema() {
		expected[entry.Kind+"/"+entry.Name] = entry
	}
	rows, err := db.QueryContext(ctx, "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := make(map[string]bool)
	var tables []string
	for rows.Next() {
		if !t.withinBudget() {
			return nil, errors.New(decisionStoreUnreadable)
		}
		var kind, name, table string
		var statement sql.NullString
		if err = rows.Scan(&kind, &name, &table, &statement); err != nil {
			return nil, err
		}
		if !skip {
			for _, field := range []struct{ column, text string }{{"type", kind}, {"name", name}, {"tbl_name", table}, {"sql", statement.String}} {
				if err = t.scanStoreText("sqlite_schema", name, field.column, field.text, remaining); err != nil {
					return nil, err
				}
			}
		}
		key := kind + "/" + name
		want, known := expected[key]
		matches := known && !seen[key] && table == want.Table &&
			statement.Valid != want.NullSQL && statement.String == want.Statement
		if !matches {
			t.problem(decisionStorePath, "decision-store schema definition mismatch")
		}
		seen[key] = true
		// FTS text is read once from its ordinary content shadow table. The
		// schema gate still validates the virtual table; unknown modules are
		// never invoked. The tagged mutation restores the duplicate charge.
		virtual := strings.HasPrefix(strings.ToUpper(strings.TrimSpace(statement.String)), "CREATE VIRTUAL TABLE")
		if kind == "table" && (!virtual || (matches && doubleFTS)) {
			tables = append(tables, name)
		}
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	for key := range expected {
		if !seen[key] {
			t.problem(decisionStorePath, "decision-store schema objects are missing")
		}
	}
	return tables, rows.Close()
}

func storeIdentifier(name string) string {
	return "\"" + strings.ReplaceAll(name, "\"", "\"\"") + "\""
}

// These are the contract's binary encodings, not user text. Valid UTF-8 BLOBs
// are scanned even in these columns; only their non-UTF-8 encodings are exempt.
func binaryStoreColumn(table, column string) bool {
	switch table + "." + column {
	case "vectors.vector",
		"keyword_index_data.block", "lane_keyword_index_data.block",
		"keyword_index_idx.term", "lane_keyword_index_idx.term",
		"keyword_index_docsize.sz", "lane_keyword_index_docsize.sz":
		return true
	}
	return false
}

func (t *tree) scanStoreTable(ctx context.Context, db storeReader, table string, remaining *int, legacy bool) error {
	rows, err := db.QueryContext(ctx, "SELECT * FROM "+storeIdentifier(table))
	if err != nil {
		return err
	}
	defer rows.Close()
	columns, err := rows.ColumnTypes()
	if err != nil {
		return err
	}
	keyColumn := -1
	for _, name := range []string{"id", "record_id", "case_id", "model", "k"} {
		for i, column := range columns {
			if keyColumn < 0 && column.Name() == name {
				keyColumn = i
			}
		}
	}
	ordinal := 0
	for rows.Next() {
		if !t.withinBudget() {
			return errors.New(decisionStoreUnreadable)
		}
		ordinal++
		values := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}
		if err = rows.Scan(pointers...); err != nil {
			return err
		}
		key := "#" + strconv.Itoa(ordinal)
		if keyColumn >= 0 {
			switch value := values[keyColumn].(type) {
			case string:
				key = value
			case int64:
				key = strconv.FormatInt(value, 10)
			}
		}
		for i, value := range values {
			var text string
			switch value := value.(type) {
			case string:
				text = value
			case []byte:
				if legacy {
					continue
				}
				if !utf8.Valid(value) {
					if binaryStoreColumn(table, columns[i].Name()) {
						continue
					}
					return errors.New(decisionStoreUnreadable)
				}
				text = string(value)
			default:
				if value != nil && strings.EqualFold(columns[i].DatabaseTypeName(), "TEXT") {
					return errors.New(decisionStoreUnreadable)
				}
				continue
			}
			if err = t.scanStoreText(table, key, columns[i].Name(), text, remaining); err != nil {
				return err
			}
		}
	}
	if err = rows.Err(); err != nil {
		return err
	}
	return rows.Close()
}

func (t *tree) scanStoreText(table, row, column, text string, remaining *int) error {
	if len(text) > *remaining {
		t.problem(decisionStorePath, "schema and row text exceed the 2 MiB validation limit; secret scan could not complete")
		return errors.New(decisionStoreUnreadable)
	}
	*remaining -= len(text)
	if !utf8.ValidString(text) {
		return errors.New(decisionStoreUnreadable)
	}
	where := "table " + label(table) + " row " + label(row)
	if table == "records" {
		where = "decision " + label(row)
	}
	found, err := findCredentialUntil(text, t.deadline)
	if err != nil {
		return err
	}
	if found != nil {
		t.problem(decisionStorePath, fmt.Sprintf("secret value detected in %s column %s (%s); keep secret names only", where, label(column), found.rule))
	}
	if table == "records" && column == "record_json" {
		value, err := decodeJSON(text)
		if err != nil {
			return err
		}
		found, err := credentialValueUntil(value, t.deadline)
		if err != nil {
			return err
		}
		if found {
			t.problem(decisionStorePath, fmt.Sprintf("secret value detected in %s column record_json (structured data); keep secret names only", where))
		}
	}
	return nil
}
