"""Exact database layouts: every table, index and trigger of each schema version, as SQLite keeps it.

SQLite stores the text of each CREATE statement in sqlite_master, so a layout is compared object by object:
name, type, table and the stored text must all be equal, and no other object may exist. Version 1 is the layout
the previous release wrote. The older layout is schema_version 1 before the egress hash chain. Version 2 is
version 1 unchanged plus the first_written table and the triggers that keep rows from being replaced. Version 3 is
version 2 unchanged plus the lane_records table, the keyword index over its text and the triggers that make its
rows append-only. Version 4 appends nullable level and instance columns and adds append-only feedback events.
"""

SCHEMA_VERSION = 4
PREVIOUS_SCHEMA_VERSION = 3
# Every schema version this code can still open for the migrate command; nothing below the current version is
# opened by any other command, and nothing is ever upgraded automatically.
MIGRATABLE_VERSIONS = (1, 2, 3)

RECORDS = """CREATE TABLE records (
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
)"""
EXACT_METADATA = "CREATE INDEX exact_metadata ON records(project, area, status, kind, answered_utc)"
KEYWORD_INDEX = "CREATE VIRTUAL TABLE keyword_index USING fts5(id, q_text, d_text, tokenize='trigram')"
IMMUTABLE_ANSWER = (
    "CREATE TRIGGER immutable_answer BEFORE UPDATE OF verbatim ON records\n"
    "WHEN NEW.verbatim != OLD.verbatim BEGIN\n"
    "    SELECT RAISE(ABORT, 'answer.verbatim is immutable');\n"
    "END"
)
MODELS = """CREATE TABLE models (
    model TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    dimension INTEGER NOT NULL CHECK(dimension > 0),
    entry_sha256 TEXT NOT NULL
)"""
VECTORS = """CREATE TABLE vectors (
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
)"""
EGRESS_LOG = """CREATE TABLE egress_log (
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
)"""
OLDER_EGRESS_LOG = EGRESS_LOG.replace("    previous_entry_sha256 TEXT NOT NULL,\n", "")

# The tables FTS5 creates for keyword_index, with the text FTS5 gives them.
KEYWORD_SHADOWS = (
    ("keyword_index_data", "CREATE TABLE 'keyword_index_data'(id INTEGER PRIMARY KEY, block BLOB)"),
    ("keyword_index_idx",
     "CREATE TABLE 'keyword_index_idx'(segid, term, pgno, PRIMARY KEY(segid, term)) WITHOUT ROWID"),
    ("keyword_index_content", "CREATE TABLE 'keyword_index_content'(id INTEGER PRIMARY KEY, c0, c1, c2)"),
    ("keyword_index_docsize", "CREATE TABLE 'keyword_index_docsize'(id INTEGER PRIMARY KEY, sz BLOB)"),
    ("keyword_index_config", "CREATE TABLE 'keyword_index_config'(k PRIMARY KEY, v) WITHOUT ROWID"),
)

FIRST_WRITTEN = """CREATE TABLE first_written (
    record_id TEXT PRIMARY KEY REFERENCES records(id),
    record_sha256 TEXT NOT NULL
) WITHOUT ROWID"""

# A lane's own records: its final report, its events as text lines, and any file the supervisor attaches. They are
# written by `ingest-lane` and never change. `part` is one of report, events and attachment; `id` is built from the
# configuration, the lane, the part and the first 16 hex digits of the source sha256, so the same source adds nothing.
LANE_RECORDS = """CREATE TABLE lane_records (
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
)"""
LANE_KEYWORD_INDEX = "CREATE VIRTUAL TABLE lane_keyword_index USING fts5(id, text, tokenize='trigram')"

# The tables FTS5 creates for lane_keyword_index, with the text FTS5 gives them.
LANE_KEYWORD_SHADOWS = (
    ("lane_keyword_index_data", "CREATE TABLE 'lane_keyword_index_data'(id INTEGER PRIMARY KEY, block BLOB)"),
    ("lane_keyword_index_idx",
     "CREATE TABLE 'lane_keyword_index_idx'(segid, term, pgno, PRIMARY KEY(segid, term)) WITHOUT ROWID"),
    ("lane_keyword_index_content", "CREATE TABLE 'lane_keyword_index_content'(id INTEGER PRIMARY KEY, c0, c1)"),
    ("lane_keyword_index_docsize", "CREATE TABLE 'lane_keyword_index_docsize'(id INTEGER PRIMARY KEY, sz BLOB)"),
    ("lane_keyword_index_config", "CREATE TABLE 'lane_keyword_index_config'(k PRIMARY KEY, v) WITHOUT ROWID"),
)


def guard(name, event, table, message, when=None):
    """A trigger that refuses a statement. A BEFORE INSERT guard also stops INSERT OR REPLACE and upserts: a
    replacement deletes the old row without firing delete triggers unless recursive_triggers is on."""
    condition = "\nWHEN {} BEGIN".format(when) if when else "\nBEGIN"
    return "CREATE TRIGGER {} BEFORE {} ON {}{}\n    SELECT RAISE(ABORT, '{}');\nEND".format(
        name, event, table, condition, message)


GUARDS = (
    ("records_no_delete", "records", guard("records_no_delete", "DELETE", "records", "records are never deleted")),
    ("records_no_replace", "records", guard(
        "records_no_replace", "INSERT", "records", "a record is written once and never replaced",
        "EXISTS (SELECT 1 FROM records WHERE id = NEW.id OR row_id = NEW.row_id)")),
    # Every update of records, not only UPDATE OF row_id, id: the row id is also reachable as rowid, _rowid_
    # and oid, and an update that names those does not select a trigger declared for the column row_id.
    ("records_fixed_ids", "records", guard(
        "records_fixed_ids", "UPDATE", "records", "record ids never change",
        "NEW.row_id IS NOT OLD.row_id OR NEW.id IS NOT OLD.id")),
    ("models_no_delete", "models", guard("models_no_delete", "DELETE", "models", "models are never deleted")),
    ("models_no_update", "models", guard("models_no_update", "UPDATE", "models", "models never change")),
    ("models_no_replace", "models", guard(
        "models_no_replace", "INSERT", "models", "a model is written once and never replaced",
        "EXISTS (SELECT 1 FROM models WHERE model = NEW.model OR rowid = NEW.rowid)")),
    ("egress_log_no_delete", "egress_log", guard(
        "egress_log_no_delete", "DELETE", "egress_log", "egress receipts are never deleted")),
    ("egress_log_no_update", "egress_log", guard(
        "egress_log_no_update", "UPDATE", "egress_log", "egress receipts never change")),
    ("egress_log_no_replace", "egress_log", guard(
        "egress_log_no_replace", "INSERT", "egress_log", "an egress receipt is written once and never replaced",
        "EXISTS (SELECT 1 FROM egress_log WHERE id = NEW.id)")),
    ("first_written_no_delete", "first_written", guard(
        "first_written_no_delete", "DELETE", "first_written", "first-written hashes are never deleted")),
    ("first_written_no_update", "first_written", guard(
        "first_written_no_update", "UPDATE", "first_written", "first-written hashes never change")),
    ("first_written_no_replace", "first_written", guard(
        "first_written_no_replace", "INSERT", "first_written", "a first-written hash is written once",
        "EXISTS (SELECT 1 FROM first_written WHERE record_id = NEW.record_id)")),
)

# Statements in creation order, as (type, name, table, sql). Autoindexes and FTS5's own tables are created by
# SQLite, so they appear only in the layouts below.
VERSION_1_STATEMENTS = (
    ("table", "records", "records", RECORDS),
    ("index", "exact_metadata", "records", EXACT_METADATA),
    ("table", "keyword_index", "keyword_index", KEYWORD_INDEX),
    ("trigger", "immutable_answer", "records", IMMUTABLE_ANSWER),
    ("table", "models", "models", MODELS),
    ("table", "vectors", "vectors", VECTORS),
    ("table", "egress_log", "egress_log", EGRESS_LOG),
)
VERSION_2_ADDITIONS = (("table", "first_written", "first_written", FIRST_WRITTEN),) + tuple(
    ("trigger", name, table, sql) for name, table, sql in GUARDS)
# A lane record is append-only like a decision record: an update or a delete is refused, and so is a replacement
# (which drops the old row without firing delete triggers unless recursive_triggers is on).
LANE_GUARDS = (
    ("lane_records_no_delete", "lane_records", guard(
        "lane_records_no_delete", "DELETE", "lane_records", "lane records are never deleted")),
    ("lane_records_no_update", "lane_records", guard(
        "lane_records_no_update", "UPDATE", "lane_records", "lane records never change")),
    ("lane_records_no_replace", "lane_records", guard(
        "lane_records_no_replace", "INSERT", "lane_records", "a lane record is written once and never replaced",
        "EXISTS (SELECT 1 FROM lane_records WHERE id = NEW.id OR row_id = NEW.row_id)")),
)
VERSION_3_ADDITIONS = (
    ("table", "lane_records", "lane_records", LANE_RECORDS),
    ("table", "lane_keyword_index", "lane_keyword_index", LANE_KEYWORD_INDEX),
) + tuple(("trigger", name, table, sql) for name, table, sql in LANE_GUARDS)

# ALTER TABLE appends columns without rewriting existing JSON, hashes, answers, ids or timestamps. NULL means
# legacy/unscoped, and such rows are excluded by scoped history searches. All earlier triggers remain in place.
VERSION_4_ALTERS = tuple("ALTER TABLE {} ADD COLUMN {}".format(table, column)
                         for table in ("records", "lane_records")
                         for column in ("level INTEGER", "instance TEXT"))
FEEDBACK = """CREATE TABLE feedback (
    id INTEGER PRIMARY KEY,
    case_id TEXT NOT NULL,
    event TEXT NOT NULL CHECK(event IN ('merged', 'accepted', 'abandoned', 'refusal', 'cited')),
    at TEXT NOT NULL,
    source TEXT NOT NULL,
    entry_sha256 TEXT NOT NULL UNIQUE,
    UNIQUE(case_id, event, source)
)"""
FEEDBACK_GUARDS = (
    ("feedback_no_delete", "feedback", guard("feedback_no_delete", "DELETE", "feedback", "feedback is never deleted")),
    ("feedback_no_update", "feedback", guard("feedback_no_update", "UPDATE", "feedback", "feedback never changes")),
    ("feedback_no_replace", "feedback", guard(
        "feedback_no_replace", "INSERT", "feedback", "feedback is written once and never replaced",
        "EXISTS (SELECT 1 FROM feedback WHERE id = NEW.id OR entry_sha256 = NEW.entry_sha256 "
        "OR (case_id = NEW.case_id AND event = NEW.event AND source = NEW.source))")),
)
VERSION_4_ADDITIONS = (
    ("table", "feedback", "feedback", FEEDBACK),
    ("index", "feedback_case", "feedback", "CREATE INDEX feedback_case ON feedback(case_id, at)"),
    ("index", "records_scope", "records", "CREATE INDEX records_scope ON records(level, instance)"),
    ("index", "lane_records_scope", "lane_records", "CREATE INDEX lane_records_scope ON lane_records(level, instance)"),
    ("trigger", "records_fixed_scope", "records", guard(
        "records_fixed_scope", "UPDATE", "records", "record scope never changes",
        "NEW.level IS NOT OLD.level OR NEW.instance IS NOT OLD.instance")),
) + tuple(("trigger", name, table, sql) for name, table, sql in FEEDBACK_GUARDS)


def layout(statements, lane=False):
    """Expected objects keyed by (type, name): SQLite lets a trigger share an index's or a table's name, so a name
    alone does not identify an object."""
    objects = {(kind, name): (table, sql) for kind, name, table, sql in statements}
    objects.update((("table", name), (name, sql)) for name, sql in KEYWORD_SHADOWS)
    if lane:
        objects.update((("table", name), (name, sql)) for name, sql in LANE_KEYWORD_SHADOWS)
    for table in ("records", "models", "vectors"):
        objects[("index", "sqlite_autoindex_{}_1".format(table))] = (table, None)
    if lane:
        objects[("index", "sqlite_autoindex_lane_records_1")] = ("lane_records", None)
    return objects


VERSION_1 = layout(VERSION_1_STATEMENTS)
OLDER = dict(VERSION_1)
OLDER[("table", "egress_log")] = ("egress_log", OLDER_EGRESS_LOG)
VERSION_2 = layout(VERSION_1_STATEMENTS + VERSION_2_ADDITIONS)
VERSION_3 = layout(VERSION_1_STATEMENTS + VERSION_2_ADDITIONS + VERSION_3_ADDITIONS, lane=True)
VERSION_4 = dict(VERSION_3)
# SQLite's ADD COLUMN preserves the old SQL up to the closing parenthesis and appends ', <definition>'.
for _table, _definition in (("records", RECORDS), ("lane_records", LANE_RECORDS)):
    VERSION_4[("table", _table)] = (_table, _definition[:-1] + ", level INTEGER, instance TEXT)")
VERSION_4.update({(kind, name): (table, sql) for kind, name, table, sql in VERSION_4_ADDITIONS})
VERSION_4[("index", "sqlite_autoindex_feedback_1")] = ("feedback", None)
VERSION_4[("index", "sqlite_autoindex_feedback_2")] = ("feedback", None)


def stored_objects(connection):
    """Every row of sqlite_master keyed by (type, name). Two rows with the same key cannot exist in SQLite; if they
    ever did, the duplicate is kept under a key that matches nothing, so the comparison still sees it."""
    objects = {}
    for kind, name, table, sql in connection.execute("SELECT type, name, tbl_name, sql FROM sqlite_master"):
        key = (kind, name)
        if key in objects:
            key = ("duplicate " + kind, name)
        objects[key] = (table, sql)
    return objects


def difference(stored, expected):
    """The first object, by name and type, whose stored definition differs from the expected one; None if all
    agree."""
    for key in sorted(set(stored) | set(expected), key=lambda item: (item[1], item[0])):
        kind, name = key
        have, want = stored.get(key), expected.get(key)
        if have == want:
            continue
        if want is None:
            return "unexpected {} {}".format(kind, name)
        if have is None:
            return "missing {} {}".format(kind, name)
        return "changed {} {}".format(kind, name)
    return None
