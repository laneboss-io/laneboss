package decisions

import "strings"

const schemaVersion = 4

type definition struct{ kind, name, table, sql string }

const recordsSQL = `CREATE TABLE records (
    row_id INTEGER PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL,
    record_sha256 TEXT NOT NULL,
    verbatim BLOB NOT NULL,
    verbatim_sha256 TEXT NOT NULL,
    q_text TEXT NOT NULL,
    d_text TEXT NOT NULL,
    q_sha256 TEXT NOT NULL,
    d_sha256 TEXT NOT NULL,
    project TEXT NOT NULL,
    area TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    answered_utc TEXT NOT NULL
)`
const laneSQL = `CREATE TABLE lane_records (
    row_id INTEGER PRIMARY KEY,
    id TEXT NOT NULL UNIQUE,
    config TEXT NOT NULL,
    lane TEXT NOT NULL,
    part TEXT NOT NULL CHECK(part IN ('report', 'events', 'attachment')),
    source_path TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    text TEXT NOT NULL,
    created_utc TEXT NOT NULL,
    ingested_utc TEXT NOT NULL
)`
const egressSQL = `CREATE TABLE egress_log (
    id INTEGER PRIMARY KEY,
    record_id TEXT REFERENCES records(id),
    which_text TEXT NOT NULL CHECK(which_text IN ('q_text', 'd_text', 'query')),
    text TEXT NOT NULL,
    text_sha256 TEXT NOT NULL,
    model TEXT NOT NULL,
    at TEXT NOT NULL,
    endpoint_host TEXT NOT NULL,
    input_type TEXT NOT NULL CHECK(input_type IN ('document', 'query')),
    previous_entry_sha256 TEXT NOT NULL,
    entry_sha256 TEXT NOT NULL
)`

var versionOne = []definition{
	{"table", "records", "records", recordsSQL},
	{"index", "exact_metadata", "records", "CREATE INDEX exact_metadata ON records(project, area, status, kind, answered_utc)"},
	{"table", "keyword_index", "keyword_index", "CREATE VIRTUAL TABLE keyword_index USING fts5(id, q_text, d_text, tokenize='trigram')"},
	{"trigger", "immutable_answer", "records", "CREATE TRIGGER immutable_answer BEFORE UPDATE OF verbatim ON records\nWHEN NEW.verbatim != OLD.verbatim BEGIN\n    SELECT RAISE(ABORT, 'answer.verbatim is immutable');\nEND"},
	{"table", "models", "models", `CREATE TABLE models (
    model TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    dimension INTEGER NOT NULL CHECK(dimension > 0),
    entry_sha256 TEXT NOT NULL
)`},
	{"table", "vectors", "vectors", `CREATE TABLE vectors (
    record_id TEXT NOT NULL REFERENCES records(id),
    which_text TEXT NOT NULL CHECK(which_text IN ('q_text', 'd_text')),
    model TEXT NOT NULL REFERENCES models(model),
    dimension INTEGER NOT NULL CHECK(dimension > 0),
    text TEXT NOT NULL,
    text_sha256 TEXT NOT NULL,
    vector BLOB NOT NULL,
    vector_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    entry_sha256 TEXT NOT NULL,
    PRIMARY KEY(record_id, which_text, model)
)`},
	{"table", "egress_log", "egress_log", egressSQL},
}

func guard(name, event, table, message, when string) definition {
	condition := "\nBEGIN"
	if when != "" {
		condition = "\nWHEN " + when + " BEGIN"
	}
	return definition{"trigger", name, table, "CREATE TRIGGER " + name + " BEFORE " + event + " ON " + table + condition + "\n    SELECT RAISE(ABORT, '" + message + "');\nEND"}
}

var versionTwo = []definition{
	{"table", "first_written", "first_written", `CREATE TABLE first_written (
    record_id TEXT PRIMARY KEY REFERENCES records(id),
    record_sha256 TEXT NOT NULL
) WITHOUT ROWID`},
	guard("records_no_delete", "DELETE", "records", "records are never deleted", ""),
	guard("records_no_replace", "INSERT", "records", "a record is written once and never replaced", "EXISTS (SELECT 1 FROM records WHERE id = NEW.id OR row_id = NEW.row_id)"),
	guard("records_fixed_ids", "UPDATE", "records", "record ids never change", "NEW.row_id IS NOT OLD.row_id OR NEW.id IS NOT OLD.id"),
	guard("models_no_delete", "DELETE", "models", "models are never deleted", ""),
	guard("models_no_update", "UPDATE", "models", "models never change", ""),
	guard("models_no_replace", "INSERT", "models", "a model is written once and never replaced", "EXISTS (SELECT 1 FROM models WHERE model = NEW.model OR rowid = NEW.rowid)"),
	guard("egress_log_no_delete", "DELETE", "egress_log", "egress receipts are never deleted", ""),
	guard("egress_log_no_update", "UPDATE", "egress_log", "egress receipts never change", ""),
	guard("egress_log_no_replace", "INSERT", "egress_log", "an egress receipt is written once and never replaced", "EXISTS (SELECT 1 FROM egress_log WHERE id = NEW.id)"),
	guard("first_written_no_delete", "DELETE", "first_written", "first-written hashes are never deleted", ""),
	guard("first_written_no_update", "UPDATE", "first_written", "first-written hashes never change", ""),
	guard("first_written_no_replace", "INSERT", "first_written", "a first-written hash is written once", "EXISTS (SELECT 1 FROM first_written WHERE record_id = NEW.record_id)"),
}
var versionThree = []definition{
	{"table", "lane_records", "lane_records", laneSQL},
	{"table", "lane_keyword_index", "lane_keyword_index", "CREATE VIRTUAL TABLE lane_keyword_index USING fts5(id, text, tokenize='trigram')"},
	guard("lane_records_no_delete", "DELETE", "lane_records", "lane records are never deleted", ""),
	guard("lane_records_no_update", "UPDATE", "lane_records", "lane records never change", ""),
	guard("lane_records_no_replace", "INSERT", "lane_records", "a lane record is written once and never replaced", "EXISTS (SELECT 1 FROM lane_records WHERE id = NEW.id OR row_id = NEW.row_id)"),
}
var versionFour = []definition{
	{"table", "feedback", "feedback", `CREATE TABLE feedback (
    id INTEGER PRIMARY KEY,
    case_id TEXT NOT NULL,
    event TEXT NOT NULL CHECK(event IN ('merged', 'accepted', 'abandoned', 'refusal', 'cited')),
    at TEXT NOT NULL,
    source TEXT NOT NULL,
    entry_sha256 TEXT NOT NULL UNIQUE,
    UNIQUE(case_id, event, source)
)`},
	{"index", "feedback_case", "feedback", "CREATE INDEX feedback_case ON feedback(case_id, at)"},
	{"index", "records_scope", "records", "CREATE INDEX records_scope ON records(level, instance)"},
	{"index", "lane_records_scope", "lane_records", "CREATE INDEX lane_records_scope ON lane_records(level, instance)"},
	guard("records_fixed_scope", "UPDATE", "records", "record scope never changes", "NEW.level IS NOT OLD.level OR NEW.instance IS NOT OLD.instance"),
	guard("feedback_no_delete", "DELETE", "feedback", "feedback is never deleted", ""),
	guard("feedback_no_update", "UPDATE", "feedback", "feedback never changes", ""),
	guard("feedback_no_replace", "INSERT", "feedback", "feedback is written once and never replaced", "EXISTS (SELECT 1 FROM feedback WHERE id = NEW.id OR entry_sha256 = NEW.entry_sha256 OR (case_id = NEW.case_id AND event = NEW.event AND source = NEW.source))"),
}

func expectedLayout(version int) map[string]definition {
	m := map[string]definition{}
	add := func(defs []definition) {
		for _, d := range defs {
			m[d.kind+"\x00"+d.name] = d
		}
	}
	add(versionOne)
	if version >= 2 {
		add(versionTwo)
	}
	if version >= 3 {
		add(versionThree)
	}
	if version >= 4 {
		add(versionFour)
		for _, table := range []string{"records", "lane_records"} {
			d := m["table\x00"+table]
			d.sql = strings.TrimSuffix(d.sql, ")") + ", level INTEGER, instance TEXT)"
			m["table\x00"+table] = d
		}
	}
	shadow := func(prefix string, cols string) {
		for _, p := range []struct{ name, sql string }{{"data", "(id INTEGER PRIMARY KEY, block BLOB)"}, {"idx", "(segid, term, pgno, PRIMARY KEY(segid, term)) WITHOUT ROWID"}, {"content", "(id INTEGER PRIMARY KEY, " + cols + ")"}, {"docsize", "(id INTEGER PRIMARY KEY, sz BLOB)"}, {"config", "(k PRIMARY KEY, v) WITHOUT ROWID"}} {
			name := prefix + "_" + p.name
			add([]definition{{"table", name, name, "CREATE TABLE '" + name + "'" + p.sql}})
		}
	}
	shadow("keyword_index", "c0, c1, c2")
	if version >= 3 {
		shadow("lane_keyword_index", "c0, c1")
	}
	for _, table := range []string{"records", "models", "vectors"} {
		add([]definition{{"index", "sqlite_autoindex_" + table + "_1", table, ""}})
	}
	if version >= 3 {
		add([]definition{{"index", "sqlite_autoindex_lane_records_1", "lane_records", ""}})
	}
	if version >= 4 {
		add([]definition{{"index", "sqlite_autoindex_feedback_1", "feedback", ""}, {"index", "sqlite_autoindex_feedback_2", "feedback", ""}})
	}
	return m
}
