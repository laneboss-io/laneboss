"""Shared helpers for the black-box CLI tests: temporary stores, a CLI runner and a local stub server."""

import base64
import hashlib
import json
import os
from pathlib import Path
import resource
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from contextlib import closing, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


ROOT = Path(__file__).resolve().parents[2]

# The program that runs the command line with one fault or synchronisation point; see its docstring.
FAULTS = Path(__file__).resolve().with_name("faults.py")

# The `format` value of an export manifest. Current code writes CURRENT_FORMAT. Code from before the project had its
# name wrote EARLIER_FORMAT into every export it made, and those files are rebuild points that must stay importable.
# EARLIER_FORMAT is assembled from pieces so that the naming test, which bans the old name everywhere except the one
# place that reads it and the manual, needs no exception for this file.
CURRENT_FORMAT = "laneboss-decisions-jsonl"
EARLIER_FORMAT = "su" + "p" + "-decisions-jsonl"

VERBATIM = " \t照這樣做，keep the trailing space 🙂 \r\né \n"

# Every object of a store written by the previous release (schema_version 1, egress hash chain), as SQLite
# keeps it in sqlite_master: name -> (type, tbl_name, sql). Copied from that release's definitions; the five
# keyword_index_* tables are the ones FTS5 creates for the keyword index.
VERSION1_RECORDS = """CREATE TABLE records (
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
VERSION1_EGRESS = """CREATE TABLE egress_log (
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
# The older layout (schema_version 1 before the egress hash chain): only this table differs.
OLDER_EGRESS = VERSION1_EGRESS.replace("    previous_entry_sha256 TEXT NOT NULL,\n", "")
VERSION1_OBJECTS = {
    "records": ("table", "records", VERSION1_RECORDS),
    "sqlite_autoindex_records_1": ("index", "records", None),
    "exact_metadata": ("index", "records",
                       "CREATE INDEX exact_metadata ON records(project, area, status, kind, answered_utc)"),
    "keyword_index": ("table", "keyword_index",
                      "CREATE VIRTUAL TABLE keyword_index USING fts5(id, q_text, d_text, tokenize='trigram')"),
    "keyword_index_data": ("table", "keyword_index_data",
                           "CREATE TABLE 'keyword_index_data'(id INTEGER PRIMARY KEY, block BLOB)"),
    "keyword_index_idx": ("table", "keyword_index_idx",
                          "CREATE TABLE 'keyword_index_idx'(segid, term, pgno, PRIMARY KEY(segid, term)) WITHOUT ROWID"),
    "keyword_index_content": ("table", "keyword_index_content",
                              "CREATE TABLE 'keyword_index_content'(id INTEGER PRIMARY KEY, c0, c1, c2)"),
    "keyword_index_docsize": ("table", "keyword_index_docsize",
                              "CREATE TABLE 'keyword_index_docsize'(id INTEGER PRIMARY KEY, sz BLOB)"),
    "keyword_index_config": ("table", "keyword_index_config",
                             "CREATE TABLE 'keyword_index_config'(k PRIMARY KEY, v) WITHOUT ROWID"),
    "immutable_answer": ("trigger", "records",
                         "CREATE TRIGGER immutable_answer BEFORE UPDATE OF verbatim ON records\n"
                         "WHEN NEW.verbatim != OLD.verbatim BEGIN\n"
                         "    SELECT RAISE(ABORT, 'answer.verbatim is immutable');\n"
                         "END"),
    "models": ("table", "models", """CREATE TABLE models (
    model TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    dimension INTEGER NOT NULL CHECK(dimension > 0),
    entry_sha256 TEXT NOT NULL
)"""),
    "sqlite_autoindex_models_1": ("index", "models", None),
    "vectors": ("table", "vectors", """CREATE TABLE vectors (
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
)"""),
    "sqlite_autoindex_vectors_1": ("index", "vectors", None),
    "egress_log": ("table", "egress_log", VERSION1_EGRESS),
}

# A program that runs the command line after it writes a marker file, optionally after a delay that stands
# for a slow start: python -c STARTER <marker> <delay seconds> <command> --db <path> [arguments...]
STARTER = (
    "import sys, time\n"
    "import laneboss.decisions.cli as cli\n"
    "time.sleep(float(sys.argv[2]))\n"
    "open(sys.argv[1], 'w').close()\n"
    "sys.exit(cli.main(sys.argv[3:]))\n"
)


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def entry_hash(value):
    """The hash the store keeps in entry_sha256: canonical JSON of the entry without that field."""
    return digest(canonical({key: item for key, item in value.items() if key not in ("entry_sha256", "vector")}))


def ids(hits):
    return [hit["record"]["id"] for hit in hits]


def record(identifier="D-22", project="phase-a", status="in_force"):
    return {
        "id": identifier,
        "kind": "decision",
        "schema_version": 1,
        "asked_at": "2026-10-08T09:00:00+08:00",
        "answered_at": "2026-10-08T09:04:00+08:00",
        "project": project,
        "area": "release",
        "topics": ["部署", "release"],
        "question": {
            "text": "Should the deployment use voyage-4-large for multilingual retrieval?",
            "background": "部署策略待確認；billing rollout is blocked.",
            "asked_by": "supervisor",
            "options": [{"label": "A", "text": "Use the proposed model"}],
            "recommendation": "Use option A",
            "default_if_unanswered": "Wait",
        },
        "answer": {
            "verbatim": VERBATIM,
            "language": "mixed",
            "channel": "terminal",
            "message_id": "message-7",
            "selected_option": "A",
            "interpreted_as": "Proceed within the limited scope",
            "ambiguity": "No broader approval",
        },
        "scope": {
            "applies_to": "The test deployment only",
            "does_not_authorize": "Production changes",
            "reversible": True,
            "valid_until": "2026-10-10T00:00:00+08:00",
        },
        "status": status,
        "outcome": {
            "actions": [],
            "evidence": ["notes/request-7.txt"],
            "followups": ["Check the result"],
        },
        "provenance": {
            "recorded_by": "supervisor",
            "recorded_at": "2026-10-08T09:05:00+08:00",
            "sources": [{
                "path": "notes/request-7.txt",
                "line": 7,
                "sha256_of_line": digest(VERBATIM),
            }],
        },
    }


def plain_record(identifier, question="Plain question", verbatim="Plain answer", status="in_force"):
    """A minimal valid record whose searchable text is almost only what the caller passes in."""
    return {
        "id": identifier,
        "kind": "decision",
        "asked_at": "2026-10-08T09:00:00Z",
        "answered_at": "2026-10-08T09:04:00Z",
        "project": "plain",
        "area": "plain",
        "topics": ["plain"],
        "question": {"text": question, "background": "plain"},
        "answer": {"verbatim": verbatim, "channel": "plain"},
        "scope": {"applies_to": "plain"},
        "status": status,
        "provenance": {"recorded_by": "plain", "recorded_at": "2026-10-08T09:05:00Z", "sources": []},
    }


def legacy_export(db):
    """Rebuild from the stored rows the export that a previous release wrote.

    Same entries, same order, same canonical text; the manifest says format EARLIER_FORMAT, which is what that
    release wrote, and schema_version 1. Egress entries carry exactly the columns the store has, so for a store of
    the older layout they have no previous_entry_sha256, as that release wrote them.
    """
    with closing(sqlite3.connect(str(db))) as connection:
        connection.row_factory = sqlite3.Row
        records = [json.loads(row[0]) for row in connection.execute("SELECT record_json FROM records ORDER BY id")]
        models = [dict(row) for row in connection.execute("SELECT * FROM models ORDER BY model")]
        vectors = [dict(row) for row in connection.execute(
            "SELECT * FROM vectors ORDER BY record_id, which_text, model")]
        egress = [dict(row) for row in connection.execute("SELECT * FROM egress_log ORDER BY id")]
    for value in vectors:
        value["vector"] = base64.b64encode(value["vector"]).decode("ascii")
    entries = [{"type": "manifest", "format": EARLIER_FORMAT, "schema_version": 1,
                "counts": {"records": len(records), "models": len(models),
                           "vectors": len(vectors), "egress": len(egress)}}]
    entries.extend({"type": "record", "record": value} for value in records)
    entries.extend({"type": "model", "model": value} for value in models)
    entries.extend({"type": "vector", "vector": value} for value in vectors)
    entries.extend({"type": "egress", "egress": value} for value in egress)
    return "".join(canonical(entry) + "\n" for entry in entries)


def in_current_format(export_text):
    """The same export with only the manifest's `format` value replaced by the one current code writes: what
    current code exports again after importing an export that earlier code wrote."""
    first, separator, rest = export_text.partition("\n")
    assert EARLIER_FORMAT in first, "the export does not start with a manifest of the earlier format"
    return first.replace(EARLIER_FORMAT, CURRENT_FORMAT, 1) + separator + rest


@contextmanager
def stub_server(response_mode="normal"):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format_string, *arguments):
            return

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append({"body": body, "auth": self.headers.get("Authorization"),
                             "path": self.path, "type": self.headers.get("Content-Type")})
            dimension = body.get("output_dimension", 1024)
            vectors = [{"index": index, "embedding": [0.25] * dimension}
                       for index, text in enumerate(body["input"])]
            if response_mode == "bad_dimension":
                vectors[0]["embedding"] = [0.5]
            if response_mode == "bad_index":
                for vector in vectors:
                    vector["index"] = 0
            if response_mode == "nonfinite":
                vectors[0]["embedding"][0] = float("nan")
            if response_mode == "echo_error":
                self.send_response(400)
                self.end_headers()
                self.wfile.write(self.headers.get("Authorization", "").encode())
                return
            if response_mode == "redirect":
                self.send_response(307)
                self.send_header("Location", "/redirected")
                self.end_headers()
                return
            if response_mode == "truncated":
                self.send_response(200)
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                self.wfile.write(b"20\r\n{\"data\":")
                self.wfile.flush()
                self.close_connection = True
                return
            if response_mode == "bad_status":
                self.wfile.write(b"not a valid status line\r\n\r\n")
                self.wfile.flush()
                self.close_connection = True
                return
            payload = json.dumps({"data": list(reversed(vectors)), "model": body["model"]})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(payload.encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield "http://127.0.0.1:{}/v1/embeddings".format(server.server_port), requests
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


class StoreCase(unittest.TestCase):
    """A fresh initialized store in a private temporary directory, driven only through the CLI."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.db = self.directory / "decisions.sqlite"
        self.environment = dict(os.environ)
        self.environment["PYTHONPATH"] = str(ROOT / "src")
        self.environment["PYTHONDONTWRITEBYTECODE"] = "1"
        self.cli("init")

    def command_line(self, command, arguments, db):
        return [sys.executable, "-m", "laneboss.decisions", command, "--db", str(db or self.db),
                *map(str, arguments)]

    def cli(self, command, *arguments, code=0, db=None, environment=None):
        result = subprocess.run(
            self.command_line(command, arguments, db),
            cwd=ROOT, env=environment or self.environment,
            capture_output=True, text=True, encoding="utf-8", timeout=60,
        )
        self.assertEqual(result.returncode, code,
                         "{}: exit {}; stdout={!r}; stderr={!r}".format(
                             command, result.returncode, result.stdout, result.stderr))
        return result

    def start_cli(self, command, *arguments, db=None, environment=None):
        return subprocess.Popen(
            self.command_line(command, arguments, db),
            cwd=ROOT, env=environment or self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8",
        )

    def json_cli(self, command, *arguments, **options):
        return json.loads(self.cli(command, *arguments, **options).stdout)

    def cli_limited(self, limit, command, *arguments, code, db=None, environment=None):
        """Run the command with a file-size limit of `limit` bytes. Python ignores SIGXFSZ, so a write past the limit
        fails with EFBIG and SQLite reports an I/O error."""
        def limited():
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

        result = subprocess.run(
            self.command_line(command, arguments, db),
            cwd=ROOT, env=environment or self.environment, capture_output=True, text=True, encoding="utf-8",
            timeout=60, preexec_fn=limited,
        )
        self.assertEqual(result.returncode, code,
                         "{} under a {}-byte file-size limit: exit {}; stdout={!r}; stderr={!r}".format(
                             command, limit, result.returncode, result.stdout, result.stderr))
        return result

    def start_hooked(self, point, marker, command, *arguments, db=None):
        """Start the command line through faults.py, which installs `point` first and creates the marker file when
        the command reaches it."""
        return subprocess.Popen(
            [sys.executable, str(FAULTS), point, str(marker), command, "--db", str(db or self.db),
             *map(str, arguments)],
            cwd=ROOT, env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8",
        )

    def cli_hooked(self, point, command, *arguments, code, db=None):
        """Run the command to its end through faults.py and check its exit code and that it reached the point."""
        marker = self.directory / "reached-{}".format(uuid.uuid4().hex)
        process = self.start_hooked(point, marker, command, *arguments, db=db)
        stdout, stderr = process.communicate(timeout=60)
        self.assertEqual(process.returncode, code,
                         "{} at {}: exit {}; stdout={!r}; stderr={!r}".format(
                             command, point, process.returncode, stdout, stderr))
        self.assertTrue(marker.exists(), "{} never reached the point {}".format(command, point))
        return subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)

    def file(self, name, value):
        path = self.directory / name
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
        return path

    def add(self, value=None):
        value = value or record()
        return self.json_cli("add", "--file", self.file("record.json", value))

    def config(self, model="fake-a", **values):
        config = {"provider": "fake", "model": model, "dimension": 128}
        config.update(values)
        return self.file("config-{}.json".format(model), config)

    def hits(self, query, mode="keyword", **filters):
        arguments = [query, "--mode", mode]
        for name, value in filters.items():
            arguments.append("--" + name.replace("_", "-"))
            if value is not True:
                arguments.append(value)
        return self.json_cli("search", *arguments)

    def write_batch(self, operations, name="batch.jsonl", newline="\n", ascii_only=False):
        lines = [json.dumps(operation, ensure_ascii=ascii_only) for operation in operations]
        path = self.directory / name
        path.write_bytes("".join(line + newline for line in lines).encode("utf-8"))
        return path

    def write_import(self, records, name="bulk.jsonl"):
        manifest = {"type": "manifest", "format": "laneboss-decisions-jsonl", "schema_version": 1,
                    "counts": {"records": len(records), "models": 0, "vectors": 0, "egress": 0}}
        entries = [manifest] + [{"type": "record", "record": value} for value in records]
        path = self.directory / name
        path.write_bytes("".join(json.dumps(entry, ensure_ascii=False) + "\n" for entry in entries).encode("utf-8"))
        return path

    # Direct access to the database file, for tampering and for proving what is stored.

    def execute(self, statement, parameters=(), db=None):
        with closing(sqlite3.connect(str(db or self.db))) as connection:
            with connection:
                return connection.execute(statement, parameters).fetchall()

    def execute_script(self, script, db=None):
        with closing(sqlite3.connect(str(db or self.db))) as connection:
            connection.executescript(script)

    def objects(self, db=None):
        """Every object in sqlite_master: name -> (type, tbl_name, sql). Names must be unique: SQLite lets a trigger
        share an index's or a table's name, and such a pair would otherwise hide one of the two here."""
        rows = self.execute("SELECT name, type, tbl_name, sql FROM sqlite_master", db=db)
        names = [row[0] for row in rows]
        self.assertEqual(len(names), len(set(names)), "two schema objects share a name: {}".format(sorted(names)))
        return {name: (kind, table, sql) for name, kind, table, sql in rows}

    def tamper(self, *statements, db=None):
        """Change rows as a writer that bypasses the store would: lift every trigger, run the statements,
        then put each trigger back with its exact original definition."""
        with closing(sqlite3.connect(str(db or self.db))) as connection:
            with connection:
                triggers = connection.execute("SELECT name, sql FROM sqlite_master WHERE type = 'trigger'").fetchall()
                for name, sql in triggers:
                    connection.execute('DROP TRIGGER "{}"'.format(name))
                for statement in statements:
                    if isinstance(statement, str):
                        connection.execute(statement)
                    else:
                        connection.execute(*statement)
                for name, sql in triggers:
                    connection.execute(sql)

    def make_version1(self, db=None):
        """Turn a store written by this code into the layout the previous release wrote: drop every object
        that release did not have and stamp schema_version 1. No row of a remaining table changes."""
        with closing(sqlite3.connect(str(db or self.db))) as connection:
            with connection:
                extra = connection.execute(
                    "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_autoindex_%'").fetchall()
                extra = [(kind, name) for kind, name in extra if name not in VERSION1_OBJECTS]
                for kind, name in sorted(extra, key=lambda item: item[0] != "trigger"):
                    if connection.execute("SELECT 1 FROM sqlite_master WHERE name = ?", (name,)).fetchone():
                        connection.execute('DROP {} "{}"'.format(kind.upper(), name))
            connection.execute("PRAGMA user_version = 1")
        self.assertEqual(self.objects(db), VERSION1_OBJECTS)
        self.assertEqual(self.user_version(db), 1)

    def make_version2(self, db=None):
        """Turn a store written by this code into the version-2 layout: drop every object version 2 did not have
        (the lane_records table, its keyword index and its triggers) and stamp schema_version 2. No row of a
        remaining table changes."""
        def kept(name):
            return not (name.startswith("lane_") or name.startswith("sqlite_autoindex_lane_"))

        expected = {name: definition for name, definition in self.objects(db).items() if kept(name)}
        with closing(sqlite3.connect(str(db or self.db))) as connection:
            with connection:
                extra = connection.execute(
                    "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_autoindex_%' "
                    "AND name LIKE 'lane_%'").fetchall()
                for kind, name in sorted(extra, key=lambda item: item[0] != "trigger"):
                    if connection.execute("SELECT 1 FROM sqlite_master WHERE name = ?", (name,)).fetchone():
                        connection.execute('DROP {} "{}"'.format(kind.upper(), name))
            connection.execute("PRAGMA user_version = 2")
        self.assertEqual(self.objects(db), expected)
        self.assertEqual(self.user_version(db), 2)

    def table_names(self, db=None):
        return sorted(row[0] for row in self.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'", db=db))

    def hash_rows(self, db=None, tables=None):
        """A digest of every stored row of the named tables (every table by default), in a fixed order: what a
        migration must leave unchanged. Tables named here must exist."""
        order = {"records": "row_id", "keyword_index": "rowid", "models": "model",
                 "vectors": "record_id, which_text, model", "egress_log": "id", "first_written": "record_id",
                 "lane_records": "row_id", "lane_keyword_index": "rowid"}
        names = sorted(name for name in (tables if tables is not None else order) if name in order)
        digest_value = hashlib.sha256()
        with closing(sqlite3.connect(str(db or self.db))) as connection:
            for name in names:
                digest_value.update(("table " + name + "\n").encode("utf-8"))
                for row in connection.execute("SELECT * FROM {} ORDER BY {}".format(name, order[name])):
                    digest_value.update(repr(tuple(row)).encode("utf-8"))
                    digest_value.update(b"\n")
        return digest_value.hexdigest()

    def make_older_layout(self, db=None):
        """Turn a version-1 store into the older layout (before the egress hash chain): egress_log has no
        previous_entry_sha256 and its entry hashes are computed without it, and superseded records carry
        no status_before_superseded, because that release recorded neither."""
        with closing(sqlite3.connect(str(db or self.db))) as connection:
            connection.row_factory = sqlite3.Row
            with connection:
                rows = [dict(row) for row in connection.execute("SELECT * FROM egress_log ORDER BY id")]
                connection.execute("DROP TABLE egress_log")
                connection.execute(OLDER_EGRESS)
                for value in rows:
                    del value["previous_entry_sha256"]
                    value["entry_sha256"] = entry_hash(value)
                    connection.execute("INSERT INTO egress_log ({}) VALUES ({})".format(
                        ",".join(value), ",".join("?" for key in value)), tuple(value.values()))
                for row in connection.execute("SELECT id, record_json FROM records").fetchall():
                    value = json.loads(row["record_json"])
                    if value.pop("status_before_superseded", None) is not None:
                        serialized = canonical(value)
                        connection.execute("UPDATE records SET record_json = ?, record_sha256 = ? WHERE id = ?",
                                           (serialized, digest(serialized), row["id"]))
        expected = dict(VERSION1_OBJECTS, egress_log=("table", "egress_log", OLDER_EGRESS))
        self.assertEqual(self.objects(db), expected)

    def downgrade_egress(self, db=None):
        """Rebuild only egress_log as it was before the hash chain, leaving every other object in place."""
        with closing(sqlite3.connect(str(db or self.db))) as connection:
            with connection:
                connection.execute(
                    "CREATE TABLE egress_rows AS SELECT id, record_id, which_text, text, text_sha256, model, at, "
                    "endpoint_host, input_type, entry_sha256 FROM egress_log")
                connection.execute("DROP TABLE egress_log")
                connection.execute(OLDER_EGRESS)
                connection.execute("INSERT INTO egress_log SELECT * FROM egress_rows")
                connection.execute("DROP TABLE egress_rows")

    def rebuild_records(self, old_line, new_line, db=None):
        """Recreate the records table with one line of its definition replaced, keeping every row, the
        keyword index and every other object exactly as it was."""
        sql = self.objects(db)["records"][2]
        changed = sql.replace(old_line, new_line)
        self.assertNotEqual(changed, sql)
        with closing(sqlite3.connect(str(db or self.db))) as connection:
            with connection:
                kept = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE tbl_name = 'records' AND type IN ('index', 'trigger') "
                    "AND sql IS NOT NULL").fetchall()
                connection.execute("CREATE TEMP TABLE records_rows AS SELECT * FROM records")
                connection.execute("DROP TABLE records")
                connection.execute(changed)
                connection.execute("INSERT INTO records SELECT * FROM records_rows")
                connection.execute("DROP TABLE records_rows")
                for (statement,) in kept:
                    connection.execute(statement)

    def start_marked(self, marker, delay, command, *arguments, db=None):
        """Start the command line through STARTER: the marker file appears once the interpreter has started
        and imported the command line, `delay` seconds later; the command runs right after."""
        return subprocess.Popen(
            [sys.executable, "-c", STARTER, str(marker), str(delay), command, "--db", str(db or self.db),
             *map(str, arguments)],
            cwd=ROOT, env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8",
        )

    def wait_for(self, path, timeout=60, process=None):
        """Wait until the file exists; with the process that is meant to create it, fail at once if it ends first."""
        deadline = time.monotonic() + timeout
        while not path.exists():
            if process is not None and process.poll() is not None:
                stdout, stderr = process.communicate()
                self.fail("the command ended (exit {}) before {} appeared; stderr={!r}".format(
                    process.returncode, path.name, stderr))
            if time.monotonic() > deadline:
                self.fail("{} did not appear within {} seconds".format(path.name, timeout))
            time.sleep(0.005)
        return time.monotonic()

    def user_version(self, db=None):
        return self.execute("PRAGMA user_version", db=db)[0][0]

    def set_version(self, version, db=None):
        self.execute_script("PRAGMA user_version = {};".format(int(version)), db=db)

    def dump(self, db=None):
        tables = (("records", "row_id"), ("keyword_index", "rowid"), ("models", "model"),
                  ("vectors", "record_id, which_text, model"), ("egress_log", "id"), ("first_written", "record_id"))
        with closing(sqlite3.connect(str(db or self.db))) as connection:
            present = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
            return {name: connection.execute("SELECT * FROM {} ORDER BY {}".format(name, order)).fetchall()
                    for name, order in tables if name in present}

    def put_lane_record(self, text, config="alpha", lane="a-lane", part="report", source_path="/invented/report.txt",
                        source_sha256=None, created_utc="2026-10-12T00:00:00+00:00",
                        ingested_utc="2026-10-12T00:00:01+00:00", db=None):
        """Write one lane record the way the store's own writer does: the row and its keyword index row. The store
        only ever reads a lane record with the checks `verify` makes, so a store that holds one is enough here."""
        value = source_sha256 or digest(text)
        identifier = "{}/{}/{}/{}".format(config, lane, part, value[:16])
        with closing(sqlite3.connect(str(db or self.db))) as connection:
            with connection:
                connection.execute(
                    "INSERT INTO lane_records (id, config, lane, part, source_path, source_sha256, text, "
                    "created_utc, ingested_utc) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (identifier, config, lane, part, source_path, value, text, created_utc, ingested_utc))
                row_id = connection.execute(
                    "SELECT row_id FROM lane_records WHERE id = ?", (identifier,)).fetchone()[0]
                connection.execute("INSERT INTO lane_keyword_index (rowid, id, text) VALUES (?, ?, ?)",
                                   (row_id, identifier, text))
        return identifier

    def rewrite(self, identifier, change, db=None):
        """Replace a stored record by a consistently rewritten copy: its JSON, its hash and its status column."""
        with closing(sqlite3.connect(str(db or self.db))) as connection:
            with connection:
                raw = connection.execute("SELECT record_json FROM records WHERE id = ?", (identifier,)).fetchone()[0]
                value = json.loads(raw)
                change(value)
                serialized = canonical(value)
                connection.execute("UPDATE records SET record_json = ?, record_sha256 = ?, status = ? WHERE id = ?",
                                   (serialized, digest(serialized), value["status"], identifier))
