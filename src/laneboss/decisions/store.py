"""Single-file storage, immutable answers, integrity checks and portable exports."""

import base64
import copy
import os
from pathlib import Path
import re
import sqlite3
import stat
import struct
import math
from urllib.parse import quote

from .layout import (
    MIGRATABLE_VERSIONS, OLDER, PREVIOUS_SCHEMA_VERSION, SCHEMA_VERSION, VERSION_1, VERSION_1_STATEMENTS, VERSION_2,
    VERSION_2_ADDITIONS, VERSION_3, VERSION_3_ADDITIONS, difference, stored_objects,
)
from .schema import (
    AccessProblem, IntegrityError, InvalidInput, SIDES, canonical, mark_superseded, mark_superseding, parse_json,
    projections, sha256, timestamp, utc_now, validate_lane_record, validate_outcome, validate_record,
)


RECORD_COLUMNS = (
    "id", "record_json", "record_sha256", "verbatim", "verbatim_sha256",
    "q_text", "d_text", "q_sha256", "d_sha256", "project", "area", "kind", "status", "answered_utc",
)
VECTOR_COLUMNS = (
    "record_id", "which_text", "model", "dimension", "text", "text_sha256",
    "vector", "vector_sha256", "created_at", "entry_sha256",
)
EGRESS_COLUMNS = (
    "id", "record_id", "which_text", "text", "text_sha256", "model", "at", "endpoint_host",
    "input_type", "previous_entry_sha256", "entry_sha256",
)
MODEL_COLUMNS = ("model", "provider", "dimension", "entry_sha256")
LANE_RECORD_COLUMNS = (
    "id", "config", "lane", "part", "source_path", "source_sha256", "text", "created_utc", "ingested_utc",
)
HASH_PATTERN = re.compile("[0-9a-f]{64}")

# The `format` value of an export manifest. Export writes EXPORT_FORMAT. Code from before the project had its name wrote
# EARLIER_EXPORT_FORMAT into every export it made. Those files are rebuild points that must stay importable, so import
# reads both values and no other. The earlier value is the identifier of a data format, not a name to rename.
EXPORT_FORMAT = "laneboss-decisions-jsonl"
EARLIER_EXPORT_FORMAT = "sup-decisions-jsonl"
EXPORT_FORMATS = (EXPORT_FORMAT, EARLIER_EXPORT_FORMAT)

OLDER_LAYOUT = (
    "cannot migrate: this schema_version 1 store has the older layout, written before the egress hash chain "
    "(its egress_log has no previous_entry_sha256). "
)
OLDER_EXPORT = (
    "this export comes from an older release whose egress receipts have no previous_entry_sha256 (they predate "
    "the egress hash chain), so it cannot be imported as it is and its egress history cannot be carried into this "
    "store. Its records can: keep the manifest line and the record lines, set the models, vectors and egress "
    "counts in the manifest to 0, and import that; see the \"Older layout\" section of docs/decisions.md"
)


def is_busy(error):
    """True for the SQLite errors that mean another connection holds a lock, not that data is damaged."""
    return isinstance(error, sqlite3.OperationalError) and str(error).startswith(
        ("database is locked", "database table is locked"))


def is_access_problem(error):
    """True for the SQLite errors that mean the database file or its directory cannot be written."""
    return isinstance(error, sqlite3.OperationalError) and str(error).startswith(
        ("attempt to write a readonly database", "unable to open database file"))


def is_storage_problem(error):
    """True for the SQLite errors that mean a write to the database file or its journal failed: the disk is
    full, a file-size limit was reached, or the operating system reported an I/O error."""
    return isinstance(error, sqlite3.OperationalError) and str(error).startswith(
        ("database or disk is full", "disk I/O error"))


def passes_through(error):
    return is_busy(error) or is_access_problem(error) or is_storage_problem(error)


def plural(count, noun):
    return "{} {}{}".format(count, noun, "" if count == 1 else "s")


def older_layout_message(receipts):
    if not receipts:
        return OLDER_LAYOUT + (
            "It has no egress receipts, so its records can be moved as they are: export it with the old release "
            "and import the export into a new store with this release.")
    return OLDER_LAYOUT + (
        "It holds {}, and egress history cannot be carried into a version-2 store. What works: export it with "
        "the old release, keep the manifest line and the record lines of that export, set the models, vectors and "
        "egress counts in the manifest to 0, import the result into a new store, run embed again (this sends the "
        "texts to the provider again), and keep the old store file as the record of what was sent before. The "
        "\"Older layout\" section of docs/decisions.md shows the commands.").format(plural(receipts, "egress receipt"))


class Progress:
    """What a failed command has already left behind, for an honest error message: the database file that init
    created, and what a command that commits more than once (embed) has already stored."""

    def __init__(self):
        self.created = None
        self.model = None
        self.receipts = 0
        self.sent = 0
        self.vectors = 0

    def __bool__(self):
        return bool(self.created or self.model or self.receipts or self.sent or self.vectors)

    def describe(self):
        stored = (["the model row for " + self.model] if self.model else []) + (
            [plural(self.receipts, "egress receipt")] if self.receipts else []) + (
            [plural(self.vectors, "vector")] if self.vectors else [])
        text = "this command had already stored " + (" and ".join(stored) if stored else "nothing")
        if self.sent:
            text += ", and had sent {} to the embedding provider".format(plural(self.sent, "text"))
            if self.sent > self.vectors:
                text += "; the vectors for {} were not stored".format(plural(self.sent - self.vectors, "text"))
        return text


def entry_hash(value):
    return sha256(canonical({key: item for key, item in value.items()
                             if key not in ("entry_sha256", "vector")}))


def check_entry(value, label):
    try:
        if value["entry_sha256"] != entry_hash(value):
            raise IntegrityError(label + ": metadata hash mismatch")
    except (ValueError, TypeError, KeyError, UnicodeError) as error:
        raise IntegrityError(label + ": invalid metadata") from error


def pack_vector(vector, dimension):
    if not isinstance(vector, list) or len(vector) != dimension:
        raise InvalidInput("embedding dimension mismatch")
    if any(type(number) not in (int, float) or not math.isfinite(number) for number in vector):
        raise InvalidInput("embedding contains invalid or nonfinite numbers")
    try:
        blob = struct.pack("<{}f".format(dimension), *vector)
    except (OverflowError, struct.error) as error:
        raise InvalidInput("embedding cannot be encoded as float32") from error
    if not all(math.isfinite(number) for number in struct.unpack("<{}f".format(dimension), blob)):
        raise InvalidInput("embedding overflows float32")
    return blob


def unpack_vector(blob, dimension):
    if type(dimension) is not int or dimension < 1 or dimension > 4096:
        raise IntegrityError("invalid vector dimension")
    if not isinstance(blob, bytes) or len(blob) != dimension * 4:
        raise IntegrityError("invalid float32 vector blob")
    vector = struct.unpack("<{}f".format(dimension), blob)
    if not all(math.isfinite(number) for number in vector) or not any(vector):
        raise IntegrityError("nonfinite or zero vector")
    return vector


def export_into_pipe(path):
    """True for an existing named pipe; False for a path that does not exist. Anything else is refused."""
    try:
        mode = os.stat(path).st_mode
    except FileNotFoundError:
        return False
    except OSError as error:
        raise InvalidInput("cannot write export file") from error
    if stat.S_ISFIFO(mode):
        return True
    raise InvalidInput("export destination already exists")


def write_export(path, into_pipe, entries):
    flags = os.O_WRONLY if into_pipe else os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as error:
        raise InvalidInput("export destination already exists") from error
    except OSError as error:
        raise InvalidInput("cannot write export file") from error
    # The path was a pipe when export began; another process may have replaced it since. Check what was actually
    # opened, not the path again, and write nothing unless it is still a pipe. (A new file is created with
    # O_EXCL, so it cannot be anything else.)
    if into_pipe and not stat.S_ISFIFO(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise InvalidInput("export destination changed: it is no longer a named pipe; nothing was written")
    try:
        with open(descriptor, "w", encoding="utf-8", newline="\n") as output:
            for entry in entries:
                output.write(canonical(entry) + "\n")
    except OSError as error:
        raise InvalidInput("cannot write export file") from error


def unsupported_version(version):
    """The error for a store of a schema version this code does not use."""
    if version in MIGRATABLE_VERSIONS:
        return IntegrityError(
            "unsupported database schema_version {}: this code uses {}; run the migrate command to "
            "upgrade the store (nothing is upgraded automatically)".format(version, SCHEMA_VERSION))
    return IntegrityError("unsupported database schema_version {}".format(version))


def read_only_uri(path):
    """The URI that opens a database file for reading only, whatever characters its path holds."""
    return "file:" + quote(os.path.abspath(str(path))) + "?mode=ro"


class Store:
    def __init__(self, path, initialize=False, migrating=False, progress=None, readonly=False, shared=False):
        # The caller may pass its own Progress to learn what this constructor did before it failed: no Store exists
        # to ask when it raises. A read-only store cannot be initialised and writes nothing; a shared store may be
        # used from several threads, which then have to take turns.
        self.progress = Progress() if progress is None else progress
        location = Path(path)
        try:
            exists, is_file = location.exists(), location.is_file()
        except PermissionError as error:
            raise AccessProblem("cannot reach the database path: permission denied") from error
        if not initialize and not is_file:
            raise InvalidInput("database does not exist; run init first")
        if initialize and exists and not is_file:
            raise InvalidInput("database path is not a file")
        if initialize and not exists:
            try:
                descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(descriptor)
                self.progress.created = str(path)
            except FileExistsError:
                pass
            except PermissionError as error:
                raise AccessProblem("cannot create the database file: its directory is not writable") from error
        if readonly:
            self.connection = sqlite3.connect(read_only_uri(path), timeout=10, uri=True,
                                              check_same_thread=not shared)
        else:
            self.connection = sqlite3.connect(str(path), timeout=10, check_same_thread=not shared)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        version = self.connection.execute("PRAGMA user_version").fetchone()[0]
        accepted = (SCHEMA_VERSION,) + MIGRATABLE_VERSIONS if migrating else (SCHEMA_VERSION,)
        if initialize and version == 0:
            tables = self.connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            if tables:
                self.close()
                raise IntegrityError("database is not an empty decision store")
            statements = "".join(
                sql + ";\n" for kind, name, table, sql in
                VERSION_1_STATEMENTS + VERSION_2_ADDITIONS + VERSION_3_ADDITIONS)
            try:
                self.connection.executescript(
                    "BEGIN IMMEDIATE;\n" + statements + "PRAGMA user_version = {};\nCOMMIT;".format(SCHEMA_VERSION))
            except sqlite3.DatabaseError as error:
                self.connection.rollback()
                self.close()
                if passes_through(error):
                    raise
                raise IntegrityError("init requires SQLite FTS5 with the trigram tokenizer") from error
        elif version not in accepted:
            self.close()
            raise unsupported_version(version)

    def close(self):
        self.connection.close()

    def rows(self):
        return self.connection.execute("SELECT * FROM records ORDER BY id").fetchall()

    def _record_values(self, record):
        question_text, decision_text = projections(record)
        serialized = canonical(record)
        return (
            record["id"], serialized, sha256(serialized), record["answer"]["verbatim"].encode("utf-8"),
            record["answer"]["sha256"], question_text, decision_text,
            sha256(question_text), sha256(decision_text), record["project"], record["area"],
            record["kind"], record["status"], timestamp(record["answered_at"], "answered_at").isoformat(),
        )

    def checked_record(self, row):
        try:
            original = parse_json(row["record_json"])
            record = validate_record(original)
            if record != original:
                raise InvalidInput("required derived record metadata is missing or incorrect")
            for column, expected in zip(RECORD_COLUMNS, self._record_values(record)):
                if row[column] != expected:
                    raise InvalidInput(column + " does not match the record")
            return record
        except (InvalidInput, KeyError, TypeError, ValueError, UnicodeError) as error:
            raise IntegrityError("record {}: {}".format(row["id"], error)) from error

    def get(self, identifier):
        row = self.connection.execute("SELECT * FROM records WHERE id = ?", (identifier,)).fetchone()
        if row is None:
            raise InvalidInput("unknown id: " + identifier)
        return self.checked_record(row)

    def first_written(self, identifier):
        """The SHA-256 of the record as it was first written, or None for a record that predates it."""
        row = self.connection.execute(
            "SELECT record_sha256 FROM first_written WHERE record_id = ?", (identifier,)).fetchone()
        return None if row is None else row[0]

    def _insert_record(self, record, first_written=None):
        old = self.connection.execute("SELECT * FROM records WHERE id = ?", (record["id"],)).fetchone()
        if old is not None:
            existing = self.checked_record(old)
            if existing["answer"]["verbatim"] != record["answer"]["verbatim"]:
                raise InvalidInput("answer.verbatim of an existing id is immutable: " + record["id"])
            raise InvalidInput("duplicate id: " + record["id"])
        cursor = self.connection.execute(
            "INSERT INTO records ({}) VALUES ({})".format(
                ",".join(RECORD_COLUMNS), ",".join("?" for column in RECORD_COLUMNS)),
            self._record_values(record),
        )
        self._index(record, cursor.lastrowid)
        if first_written is not None:
            self.connection.execute("INSERT INTO first_written (record_id, record_sha256) VALUES (?, ?)",
                                    (record["id"], first_written))

    def _index(self, record, row_id):
        question_text, decision_text = projections(record)
        self.connection.execute("DELETE FROM keyword_index WHERE rowid = ?", (row_id,))
        self.connection.execute("INSERT INTO keyword_index(rowid, id, q_text, d_text) VALUES (?, ?, ?, ?)",
                                (row_id, record["id"], question_text, decision_text))

    def _update_record(self, record):
        values = self._record_values(record)
        self.connection.execute(
            "UPDATE records SET {} WHERE id = ?".format(
                ",".join(column + " = ?" for column in RECORD_COLUMNS[1:])),
            values[1:] + (record["id"],),
        )
        row_id = self.connection.execute("SELECT row_id FROM records WHERE id = ?", (record["id"],)).fetchone()[0]
        self._index(record, row_id)

    def lane_rows(self):
        return self.connection.execute("SELECT * FROM lane_records ORDER BY id").fetchall()

    def checked_lane_record(self, row):
        """The stored lane record, checked: every field and the id built from the source hash must agree."""
        try:
            original = {column: row[column] for column in LANE_RECORD_COLUMNS}
            record = validate_lane_record(original)
            if record != original:
                raise InvalidInput("required lane record metadata is missing or incorrect")
            return record
        except (InvalidInput, KeyError, TypeError, ValueError, UnicodeError) as error:
            raise IntegrityError("lane record {}: {}".format(row["id"], error)) from error

    def lane_records(self):
        return [(row, self.checked_lane_record(row)) for row in self.lane_rows()]

    def lane_record(self, identifier):
        row = self.connection.execute("SELECT * FROM lane_records WHERE id = ?", (identifier,)).fetchone()
        if row is None:
            raise InvalidInput("unknown lane record id: " + identifier)
        return self.checked_lane_record(row)

    def _index_lane_record(self, record, row_id):
        self.connection.execute("INSERT INTO lane_keyword_index(rowid, id, text) VALUES (?, ?, ?)",
                                (row_id, record["id"], record["text"]))

    def insert_lane_record(self, original):
        """Append one lane record. True when it was written, False when its id is already stored with the same
        source hash: ingesting the same source twice adds nothing."""
        record = validate_lane_record(original)
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            row = self.connection.execute(
                "SELECT source_sha256 FROM lane_records WHERE id = ?", (record["id"],)).fetchone()
            if row is not None:
                if row[0] != record["source_sha256"]:
                    raise IntegrityError("lane record {} already exists with a different source hash".format(
                        record["id"]))
                return False
            cursor = self.connection.execute(
                "INSERT INTO lane_records ({}) VALUES ({})".format(
                    ",".join(LANE_RECORD_COLUMNS), ",".join("?" for column in LANE_RECORD_COLUMNS)),
                tuple(record[column] for column in LANE_RECORD_COLUMNS))
            self._index_lane_record(record, cursor.lastrowid)
        return True

    def add(self, original):
        record = validate_record(original)
        if record.get("supersedes") or record.get("superseded_by"):
            raise InvalidInput("linked records must be written with supersede or import")
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            self._insert_record(record, sha256(canonical(record)))
        return record

    def supersede(self, identifier, original):
        record = validate_record(original)
        mark_superseding(record, identifier)
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            old = self.get(identifier)
            mark_superseded(old, record["id"])
            self._insert_record(record, sha256(canonical(record)))
            self._update_record(old)
        return record

    def annotate(self, identifier, outcome):
        validate_outcome(outcome)
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            record = self.get(identifier)
            for field, items in outcome.items():
                record["outcome"].setdefault(field, []).extend(items)
            self._update_record(record)
        return record

    def ensure_model(self, provider):
        value = {"model": provider.model, "provider": provider.name, "dimension": provider.dimension}
        value["entry_sha256"] = entry_hash(value)
        created = False
        with self.connection:
            old = self.connection.execute("SELECT * FROM models WHERE model = ?", (provider.model,)).fetchone()
            if old:
                self.checked_model(old)
            if old and dict(old) != value:
                raise InvalidInput("model already exists with different provider or dimension")
            if not old:
                self._insert_mapping("models", MODEL_COLUMNS, value)
                created = True
        if created:
            self.progress.model = provider.model

    def checked_model(self, row):
        value = dict(row)
        label = "model {}".format(value["model"])
        check_entry(value, label)
        if not isinstance(value["model"], str) or not value["model"].strip():
            raise IntegrityError(label + ": invalid model name")
        if value["provider"] not in ("fake", "voyage"):
            raise IntegrityError(label + ": invalid provider")
        if type(value["dimension"]) is not int or not 1 <= value["dimension"] <= 4096:
            raise IntegrityError(label + ": invalid dimension")
        return value

    def checked_vector(self, row, dimension):
        value = dict(row)
        label = "vector {} {} {}".format(value["record_id"], value["which_text"], value["model"])
        check_entry(value, label)
        if not isinstance(value["text"], str) or value["which_text"] not in SIDES:
            raise IntegrityError(label + ": invalid text metadata")
        if (value["text_sha256"] != sha256(value["text"])
                or not isinstance(value["vector"], bytes) or value["vector_sha256"] != sha256(value["vector"])):
            raise IntegrityError(label + ": hash mismatch")
        if value["dimension"] != dimension:
            raise IntegrityError(label + ": dimension mismatch")
        try:
            timestamp(value["created_at"], label + ".created_at")
            return unpack_vector(value["vector"], value["dimension"])
        except (IntegrityError, InvalidInput) as error:
            raise IntegrityError(label + ": " + str(error)) from error

    def _insert_mapping(self, table, columns, value):
        self.connection.execute("INSERT INTO {} ({}) VALUES ({})".format(
            table, ",".join(columns), ",".join("?" for column in columns)),
            tuple(value[column] for column in columns))

    def log_egress(self, items, provider, input_type):
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            previous = self.connection.execute(
                "SELECT entry_sha256 FROM egress_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous_hash = previous[0] if previous else ""
            next_id = self.connection.execute("SELECT coalesce(max(id), 0) + 1 FROM egress_log").fetchone()[0]
            for position, item in enumerate(items):
                value = {
                    "id": next_id + position, "record_id": item["record_id"],
                    "which_text": item["which_text"], "text": item["text"],
                    "text_sha256": sha256(item["text"]), "model": provider.model,
                    "at": utc_now(), "endpoint_host": provider.host, "input_type": input_type,
                    "previous_entry_sha256": previous_hash,
                }
                value["entry_sha256"] = entry_hash(value)
                self._insert_mapping("egress_log", EGRESS_COLUMNS, value)
                previous_hash = value["entry_sha256"]
        self.progress.receipts += len(items)

    def egress(self):
        return [dict(row) for row in self.connection.execute("SELECT * FROM egress_log ORDER BY id")]

    def save_vectors(self, items, provider, vectors):
        with self.connection:
            for item, vector in zip(items, vectors):
                blob = pack_vector(vector, provider.dimension)
                unpack_vector(blob, provider.dimension)
                value = {
                    "record_id": item["record_id"], "which_text": item["which_text"],
                    "model": provider.model, "dimension": provider.dimension,
                    "text": item["text"], "text_sha256": sha256(item["text"]),
                    "vector": blob, "vector_sha256": sha256(blob), "created_at": utc_now(),
                }
                value["entry_sha256"] = entry_hash(value)
                self.connection.execute("DELETE FROM vectors WHERE record_id = ? AND which_text = ? AND model = ?",
                                        (item["record_id"], item["which_text"], provider.model))
                self._insert_mapping("vectors", VECTOR_COLUMNS, value)
        self.progress.vectors += len(items)

    def stats(self):
        connection = self.connection
        records = connection.execute("SELECT count(*) FROM records").fetchone()[0]
        has_first_written = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'first_written'").fetchone()
        has_lane_records = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'lane_records'").fetchone()
        return {
            "schema_version": connection.execute("PRAGMA user_version").fetchone()[0],
            "records": records,
            "lane_records": connection.execute("SELECT count(*) FROM lane_records").fetchone()[0]
            if has_lane_records else 0,
            "lane_record_triggers": sorted(row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'lane_records'"))
            if has_lane_records else [],
            "records_without_first_written": connection.execute(
                "SELECT count(*) FROM records r WHERE NOT EXISTS "
                "(SELECT 1 FROM first_written f WHERE f.record_id = r.id)").fetchone()[0]
            if has_first_written else records,
            "records_without_vectors": connection.execute(
                "SELECT count(*) FROM records r WHERE NOT EXISTS "
                "(SELECT 1 FROM vectors v WHERE v.record_id = r.id)").fetchone()[0],
            "vectors": connection.execute("SELECT count(*) FROM vectors").fetchone()[0],
            "egress_entries": connection.execute("SELECT count(*) FROM egress_log").fetchone()[0],
            "statuses": {row[0]: row[1] for row in connection.execute(
                "SELECT status, count(*) FROM records GROUP BY status ORDER BY status")},
            "models": [dict(row) for row in connection.execute("SELECT * FROM models ORDER BY model")],
            "stale_vectors": connection.execute(
                "SELECT count(*) FROM vectors v JOIN records r ON r.id = v.record_id WHERE "
                "v.text_sha256 != CASE v.which_text WHEN 'q_text' THEN r.q_sha256 ELSE r.d_sha256 END"
            ).fetchone()[0],
        }

    def migrate(self):
        """Verify a version 1 or version 2 store completely, add the objects the next version introduced and stamp
        the current version, in one transaction. Every step is verified before the next: a version-1 store is made
        version 2 first, and then version 3, so a failure in the middle leaves the store as it was."""
        version = self.connection.execute("PRAGMA user_version").fetchone()[0]
        if version == SCHEMA_VERSION:
            return self._unchanged_version(version)
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            version = self.connection.execute("PRAGMA user_version").fetchone()[0]
            if version == SCHEMA_VERSION:
                return self._unchanged_version(version)
            if version not in MIGRATABLE_VERSIONS:
                raise IntegrityError("unsupported database schema_version {}".format(version))
            started_at = version
            stored = stored_objects(self.connection)
            if stored == OLDER:
                receipts = self.connection.execute("SELECT count(*) FROM egress_log").fetchone()[0]
                raise IntegrityError(older_layout_message(receipts))
            if version == 1:
                mismatch = difference(stored, VERSION_1)
                if mismatch:
                    raise IntegrityError("schema definition mismatch: " + mismatch)
                verified = self._verify_snapshot(VERSION_1)
                for kind, name, table, sql in VERSION_2_ADDITIONS:
                    self.connection.execute(sql)
                mismatch = difference(stored_objects(self.connection), VERSION_2)
                if mismatch:
                    raise IntegrityError("migration produced an unexpected layout: " + mismatch)
                version = PREVIOUS_SCHEMA_VERSION
                stored = stored_objects(self.connection)
            mismatch = difference(stored, VERSION_2)
            if mismatch:
                raise IntegrityError("schema definition mismatch: " + mismatch)
            verified = self._verify_snapshot(VERSION_2)
            for kind, name, table, sql in VERSION_3_ADDITIONS:
                self.connection.execute(sql)
            self.connection.execute("PRAGMA user_version = {}".format(SCHEMA_VERSION))
            mismatch = difference(stored_objects(self.connection), VERSION_3)
            if mismatch:
                raise IntegrityError("migration produced an unexpected layout: " + mismatch)
        return {
            "migrated": True, "from_schema_version": started_at, "to_schema_version": SCHEMA_VERSION,
            "records": verified["records"], "vectors": verified["vectors"],
            "egress_entries": verified["egress_entries"],
            "message": ("verified the whole store, added the first_written table and the row-protection triggers, "
                        "then the lane_records table, its keyword index and its triggers, and stamped "
                        "schema_version {}; no existing row was changed").format(SCHEMA_VERSION),
        }

    @staticmethod
    def _unchanged_version(version):
        return {
            "migrated": False, "from_schema_version": version, "to_schema_version": version,
            "message": "already at schema_version {}; nothing was changed".format(version),
        }

    def verify(self, expected=None):
        # BEGIN IMMEDIATE takes the write lock before anything is read, so a writer that is mid-transaction
        # is waited for (the busy timeout applies) instead of failing at once: opening the FTS5 table reads
        # its configuration, and a connection that already holds a read lock gets SQLITE_BUSY without waiting.
        started = not self.connection.in_transaction
        if started:
            self.connection.execute("BEGIN IMMEDIATE")
        try:
            return self._verify_snapshot(expected or VERSION_3)
        finally:
            if started and self.connection.in_transaction:
                self.connection.rollback()

    def _verify_snapshot(self, expected):
        # The caller's transaction holds the write lock (BEGIN IMMEDIATE), so no writer can commit between the
        # reads below and produce a false mismatch.
        connection = self.connection
        mismatch = difference(stored_objects(connection), expected)
        if mismatch:
            raise IntegrityError("schema definition mismatch: " + mismatch)
        try:
            connection.execute("INSERT INTO keyword_index(keyword_index) VALUES ('integrity-check')")
        except sqlite3.DatabaseError as error:
            if passes_through(error):
                raise
            raise IntegrityError("keyword index internal integrity problem") from error
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise IntegrityError("SQLite integrity_check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise IntegrityError("foreign key integrity problem")
        records = {}
        for row in self.rows():
            record = self.checked_record(row)
            records[record["id"]] = record
            index = connection.execute("SELECT rowid, * FROM keyword_index WHERE rowid = ?", (row["row_id"],)).fetchone()
            if index is None or tuple(index) != (row["row_id"], row["id"], row["q_text"], row["d_text"]):
                raise IntegrityError("record {}: keyword index mismatch".format(row["id"]))
        if connection.execute("SELECT count(*) FROM keyword_index").fetchone()[0] != len(records):
            raise IntegrityError("keyword index has extra rows")
        if ("table", "lane_records") in expected:
            lane_records = {}
            for row in self.lane_rows():
                value = self.checked_lane_record(row)
                lane_records[value["id"]] = value
                index = connection.execute(
                    "SELECT rowid, * FROM lane_keyword_index WHERE rowid = ?", (row["row_id"],)).fetchone()
                if index is None or tuple(index) != (row["row_id"], row["id"], row["text"]):
                    raise IntegrityError("lane record {}: keyword index mismatch".format(row["id"]))
            if connection.execute("SELECT count(*) FROM lane_keyword_index").fetchone()[0] != len(lane_records):
                raise IntegrityError("the lane record keyword index has extra rows")
        for identifier, record in records.items():
            for field, back_link in (("supersedes", "superseded_by"), ("superseded_by", "supersedes")):
                target = record.get(field)
                if target and (target not in records or records[target].get(back_link) != identifier):
                    raise IntegrityError("record {}: broken {} link".format(identifier, field))
            visited = set()
            current = record
            while current.get("supersedes"):
                if current["id"] in visited:
                    raise IntegrityError("record {}: supersession cycle".format(identifier))
                visited.add(current["id"])
                target = records.get(current["supersedes"])
                if target is None:
                    raise IntegrityError("record {}: supersession target is missing".format(identifier))
                current = target
        if ("table", "first_written") in expected:
            for identifier, value in connection.execute("SELECT record_id, record_sha256 FROM first_written"):
                if identifier not in records:
                    raise IntegrityError("first-written hash for a missing record: {}".format(identifier))
                if not isinstance(value, str) or HASH_PATTERN.fullmatch(value) is None:
                    raise IntegrityError("record {}: invalid first-written hash".format(identifier))
        models = {}
        for row in connection.execute("SELECT * FROM models ORDER BY model"):
            value = self.checked_model(row)
            models[value["model"]] = value
        sent = set()
        previous_hash = ""
        expected_id = 1
        for value in self.egress():
            label = "egress entry {}".format(value["id"])
            if value["id"] != expected_id:
                raise IntegrityError("egress ids are not contiguous")
            if value["previous_entry_sha256"] != previous_hash:
                raise IntegrityError(label + ": previous hash mismatch")
            check_entry(value, label)
            if not isinstance(value["text"], str) or value["text_sha256"] != sha256(value["text"]):
                raise IntegrityError(label + ": hash mismatch")
            try:
                timestamp(value["at"], label + ".at")
            except InvalidInput as error:
                raise IntegrityError(str(error)) from error
            if value["which_text"] == "query":
                if value["record_id"] is not None or value["input_type"] != "query":
                    raise IntegrityError(label + ": invalid query metadata")
            elif value["which_text"] not in SIDES or value["input_type"] != "document":
                raise IntegrityError(label + ": invalid document metadata")
            sent.add((value["record_id"], value["which_text"], value["model"], value["text_sha256"]))
            previous_hash = value["entry_sha256"]
            expected_id += 1
        for row in connection.execute("SELECT * FROM vectors ORDER BY record_id, which_text, model"):
            value = dict(row)
            label = "vector {} {} {}".format(value["record_id"], value["which_text"], value["model"])
            model = models.get(value["model"])
            if model is None:
                raise IntegrityError(label + ": model is missing")
            self.checked_vector(row, model["dimension"])
            if (value["record_id"], value["which_text"], value["model"], value["text_sha256"]) not in sent:
                raise IntegrityError(label + ": missing egress receipt")
        unverified_sources = sum(1 for record in records.values() for source in record["provenance"]["sources"]
                                 if "line_text" not in source)
        return {"ok": True, "source_hashes_unverified": unverified_sources, **self.stats()}

    def export(self, path):
        into_pipe = export_into_pipe(path)
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            self.verify()
            stats = self.stats()
            first_written = {row[0]: row[1] for row in self.connection.execute(
                "SELECT record_id, record_sha256 FROM first_written")}
            manifest = {"type": "manifest", "format": EXPORT_FORMAT, "schema_version": 1,
                        "counts": {"records": stats["records"], "models": len(stats["models"]),
                                   "vectors": stats["vectors"], "egress": stats["egress_entries"]}}
            if first_written:
                manifest["first_written"] = len(first_written)
            entries = [manifest]
            for row in self.rows():
                entry = {"type": "record", "record": self.checked_record(row)}
                if row["id"] in first_written:
                    entry["first_written_sha256"] = first_written[row["id"]]
                entries.append(entry)
            entries.extend({"type": "model", "model": dict(row)} for row in self.connection.execute(
                "SELECT * FROM models ORDER BY model"))
            for row in self.connection.execute("SELECT * FROM vectors ORDER BY record_id, which_text, model"):
                value = dict(row)
                value["vector"] = base64.b64encode(value["vector"]).decode("ascii")
                entries.append({"type": "vector", "vector": value})
            entries.extend({"type": "egress", "egress": value} for value in self.egress())
        # The transaction has ended and the write lock is released before the output is written, so a slow
        # reader of a pipe never holds up other writers.
        write_export(path, into_pipe, entries)
        return {"exported": stats["records"], "out": str(path)}

    def import_file(self, path):
        try:
            with open(path, encoding="utf-8") as source:
                entries = [parse_json(line) for line in source]
        except (OSError, UnicodeError) as error:
            raise InvalidInput("cannot read import file") from error
        if not entries or not isinstance(entries[0], dict):
            raise InvalidInput("import requires a manifest")
        manifest = entries.pop(0)
        if (manifest.get("type") != "manifest" or manifest.get("format") not in EXPORT_FORMATS
                or manifest.get("schema_version") != 1):
            raise InvalidInput("invalid import manifest")
        declared = manifest.get("first_written")
        if "first_written" in manifest and (type(declared) is not int or declared < 1):
            raise InvalidInput("invalid import manifest: first_written must be a positive integer")
        for entry in entries:
            if (isinstance(entry, dict) and entry.get("type") == "egress" and isinstance(entry.get("egress"), dict)
                    and "previous_entry_sha256" not in entry["egress"]):
                raise InvalidInput(OLDER_EXPORT)
        counts = {"records": 0, "models": 0, "vectors": 0, "egress": 0}
        carried = 0
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            # A destination whose own layout is wrong is an integrity problem of the store (exit 3), reported before
            # anything is written. The check runs under this transaction's write lock, which no other connection can
            # take before it ends, so the layout cannot change between the check and the writes: a change made while
            # the import waited for the lock is found here. Problems of the imported data, found below and by the
            # final verification, are invalid input.
            mismatch = difference(stored_objects(self.connection), VERSION_3)
            if mismatch:
                raise IntegrityError("schema definition mismatch: " + mismatch)
            try:
                stats = self.stats()
                if stats["records"] or stats["models"] or stats["egress_entries"] or stats["lane_records"]:
                    raise InvalidInput("import requires an empty initialized store")
                for entry in entries:
                    category = required_category(entry)
                    value = entry[category]
                    if category == "record":
                        first = None
                        if "first_written_sha256" in entry:
                            first = entry["first_written_sha256"]
                            if declared is None:
                                raise InvalidInput("a record carries first_written_sha256 but the manifest declares "
                                                   "no first_written count")
                            if not isinstance(first, str) or HASH_PATTERN.fullmatch(first) is None:
                                raise InvalidInput("first_written_sha256 must be a SHA-256 hex digest")
                            carried += 1
                        self._insert_record(validate_record(value), first)
                        counts["records"] += 1
                    elif category == "vector":
                        value = copy.deepcopy(value)
                        value["vector"] = base64.b64decode(value["vector"], validate=True)
                        self._insert_mapping("vectors", VECTOR_COLUMNS, value)
                        counts["vectors"] += 1
                    elif category == "model":
                        self._insert_mapping("models", MODEL_COLUMNS, value)
                        counts["models"] += 1
                    else:
                        self._insert_mapping("egress_log", EGRESS_COLUMNS, value)
                        counts["egress"] += 1
                if counts != manifest.get("counts"):
                    raise InvalidInput("import manifest counts mismatch")
                if carried != (declared or 0):
                    raise InvalidInput("import manifest first_written count mismatch")
                self.verify()
            except (sqlite3.Error, OverflowError, KeyError, TypeError, ValueError, IntegrityError) as error:
                if passes_through(error):
                    raise
                raise InvalidInput("invalid import: " + str(error)) from error
        return {"imported": counts["records"]}


def required_category(entry):
    if not isinstance(entry, dict) or entry.get("type") not in ("record", "model", "vector", "egress"):
        raise InvalidInput("invalid import entry type")
    category = entry["type"]
    if not isinstance(entry.get(category), dict):
        raise InvalidInput("invalid import entry payload")
    allowed = {"type", category} | ({"first_written_sha256"} if category == "record" else set())
    unknown = sorted(set(entry) - allowed)
    if unknown:
        raise InvalidInput("unknown import entry field: " + unknown[0])
    return category
