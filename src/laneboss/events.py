"""The event and state store: one append-only SQLite file per configuration.

Every event is written by EventStore.append(), inside BEGIN IMMEDIATE. A later single-writer
service and an offline spool will sit in front of exactly that function, so it takes a plain
envelope and returns a plain result; it knows nothing about the command line. The lane table is a
projection of the events: append() keeps it current and rebuild() recomputes it from events alone.

A store that existed is never silently recreated: the state directory's ownership marker records the
store's id once it is created, and from then on a missing, empty or different store is an integrity
problem for every command (see statedir.py and docs/architecture.md for the deliberate way to start over).
"""

from datetime import datetime, timezone
import json
import math
import os
import re
import sqlite3
from urllib.parse import quote
import uuid

from . import credentials, fsguard, lanes, multiplexer, resources
from .errors import IntegrityProblem, Refused
from .jsonutil import canonical, canonical_bytes, sha256_hex

STORE_FORMAT = "event-store"
STORE_VERSION = 1
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
KIND = re.compile(r"[a-z][a-z0-9_]{0,31}(?:\.[a-z][a-z0-9_]{0,31}){1,3}")
LANE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
ACTOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}")
PROTOCOL_VERSION = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}")
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                       r"(?:\.[0-9]{3}(?:[0-9]{3})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})")
DIGEST = re.compile(r"[0-9a-f]{64}")
ENVELOPE_FIELDS = ("id", "kind", "lane", "actor", "occurred_at", "payload", "protocol_version")
STORE_FIELDS = ("seq", "recorded_at", "sha256")
HASHED_FIELDS = ENVELOPE_FIELDS + ("seq", "recorded_at")
META_KEYS = {"format", "config", "created_at", "store_id"}
MAX_PAYLOAD_BYTES = 1024 * 1024

SCHEMA = (
    ("table", "meta", "meta", "CREATE TABLE meta (\n"
     "    key TEXT PRIMARY KEY,\n"
     "    value TEXT NOT NULL\n"
     ")"),
    ("table", "events", "events", "CREATE TABLE events (\n"
     "    seq INTEGER PRIMARY KEY AUTOINCREMENT,\n"
     "    id TEXT NOT NULL UNIQUE,\n"
     "    kind TEXT NOT NULL,\n"
     "    lane TEXT,\n"
     "    actor TEXT NOT NULL,\n"
     "    occurred_at TEXT,\n"
     "    payload TEXT NOT NULL,\n"
     "    protocol_version TEXT NOT NULL,\n"
     "    recorded_at TEXT NOT NULL,\n"
     "    sha256 TEXT NOT NULL\n"
     ")"),
    ("table", "lanes", "lanes", "CREATE TABLE lanes (\n"
     "    lane TEXT PRIMARY KEY,\n"
     "    projection TEXT NOT NULL\n"
     ")"),
    ("trigger", "events_no_update", "events", "CREATE TRIGGER events_no_update BEFORE UPDATE ON events\n"
     "BEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND"),
    ("trigger", "events_no_delete", "events", "CREATE TRIGGER events_no_delete BEFORE DELETE ON events\n"
     "BEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND"),
    ("trigger", "events_no_replace", "events", "CREATE TRIGGER events_no_replace BEFORE INSERT ON events\n"
     "WHEN EXISTS (SELECT 1 FROM events WHERE seq = NEW.seq OR id = NEW.id)\n"
     "BEGIN\n    SELECT RAISE(ABORT, 'events are append-only');\nEND"),
    ("trigger", "meta_no_update", "meta", "CREATE TRIGGER meta_no_update BEFORE UPDATE ON meta\n"
     "BEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND"),
    ("trigger", "meta_no_delete", "meta", "CREATE TRIGGER meta_no_delete BEFORE DELETE ON meta\n"
     "BEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND"),
)
# Created after the metadata rows: no further row may ever be inserted into meta.
META_LOCK = ("trigger", "meta_no_insert", "meta", "CREATE TRIGGER meta_no_insert BEFORE INSERT ON meta\n"
             "BEGIN\n    SELECT RAISE(ABORT, 'store metadata is immutable');\nEND")
INTERNAL = {("table", "sqlite_sequence", "sqlite_sequence"), ("index", "sqlite_autoindex_meta_1", "meta"),
            ("index", "sqlite_autoindex_events_1", "events"), ("index", "sqlite_autoindex_lanes_1", "lanes")}


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def check_timestamp(value, field):
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        raise Refused(field + ": must be a timestamp such as 2026-10-08T09:00:00Z or 2026-10-08T17:00:00+08:00")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        raise Refused(field + ": is not a valid date and time") from None


def check_grammar(value, pattern, field, required=True):
    if value is None and not required:
        return None
    if value is None:
        raise Refused(field + ": is required")
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise Refused(field + ": must match " + pattern.pattern)
    return value


def finite_numbers(value):
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, dict):
        return all(finite_numbers(item) for item in value.values())
    if isinstance(value, list):
        return all(finite_numbers(item) for item in value)
    return True


def validate_envelope(value):
    """Return the normalized envelope, or raise Refused naming the field (never echoing a value)."""
    if not isinstance(value, dict):
        raise Refused("an event must be a JSON object")
    found = credentials.find_in_value(value)
    if found:
        raise Refused("{}: looks like a credential ({}); nothing was stored".format(found[0], found[1]))
    for field in STORE_FIELDS:
        if field in value:
            raise Refused(field + ": is set by the store; a caller cannot supply it")
    for field in value:
        if field not in ENVELOPE_FIELDS:
            raise Refused((field if re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", field) else "a field")
                          + ": unknown field; an event has " + ", ".join(ENVELOPE_FIELDS))
    event = {
        "id": check_grammar(value.get("id"), ID, "id", required=False) or "ev-" + uuid.uuid4().hex,
        "kind": check_grammar(value.get("kind"), KIND, "kind"),
        "lane": check_grammar(value.get("lane"), LANE, "lane", required=False),
        "actor": check_grammar(value.get("actor"), ACTOR, "actor"),
        "occurred_at": value.get("occurred_at"),
        "payload": value.get("payload"),
        "protocol_version": check_grammar(value.get("protocol_version"), PROTOCOL_VERSION, "protocol_version"),
    }
    if event["occurred_at"] is not None:
        check_timestamp(event["occurred_at"], "occurred_at")
    if event["payload"] is None:
        raise Refused("payload: is required (a JSON object)")
    if not isinstance(event["payload"], dict):
        raise Refused("payload: must be a JSON object")
    if not finite_numbers(event["payload"]):
        raise Refused("payload: numbers must be finite")
    if len(canonical_bytes(event["payload"])) > MAX_PAYLOAD_BYTES:
        raise Refused("payload: must be at most 1 MiB in canonical form")
    if event["kind"].startswith("lane."):
        lanes.check(event["kind"], event["lane"], event["payload"])
    if event["kind"].startswith("resource."):
        resources.check(event["kind"], event["lane"], event["payload"])
    return event


def event_hash(event):
    return sha256_hex(canonical_bytes({field: event[field] for field in HASHED_FIELDS}))


def content(event):
    return canonical({field: event[field] for field in ENVELOPE_FIELDS})


def require_recorded(info, path):
    if info is None:
        raise IntegrityProblem("the store that the ownership marker records is missing: {}; to start over "
                               "deliberately, remove the store and the marker (docs/architecture.md, 'Starting "
                               "over')".format(path))
    if info.st_size == 0:
        raise IntegrityProblem("the store that the ownership marker records is empty (truncated): {}".format(path))


def unrecorded_store(path, name):
    """Open a store the marker does not record: None for a file without a schema (an interrupted creation);
    the store when it holds no event; an integrity problem when it holds events (R11)."""
    store = EventStore(path, name, "rw")
    try:
        if store.identity() is None:
            store.close()
            return None
        store.check(None)
        count = store.connection.execute("SELECT count(*) FROM events").fetchone()[0]
        if count:
            raise IntegrityProblem("{} holds {} event(s) but the ownership marker records no store, so it is not "
                                   "adopted (docs/architecture.md, 'Starting over')".format(path, count))
    except BaseException:
        store.close()
        raise
    return store


def open_for_write(state, timeout=10):
    """The store for writing. The caller holds the exclusive state directory lock. A store is created only
    when the marker records none; only a store without events (an interrupted creation) is adopted. `timeout` is how
    long a write waits for a store another process is writing."""
    marker = state.marker()
    info = state.store_info()
    path = state.store_path()
    name = state.configuration.name
    recorded = marker.get("store") if marker else None
    if recorded:
        require_recorded(info, path)
        store = EventStore.opened(path, name, "rw", recorded["id"], timeout)
        store.state = state
        return store
    store = unrecorded_store(path, name) if info is not None and info.st_size > 0 else None
    try:
        if marker is None:
            state.ensure_marker()
        if store is None:
            store = EventStore(path, name, "rwc", timeout)
            store.initialize()
        state.record_store(store.meta["store_id"], store.meta["created_at"])
    except BaseException:
        if store is not None:
            store.close()
        raise
    store.state = state
    return store


def open_for_read(state):
    """The store for reading, or None when there is nothing to read. The caller holds the shared lock, so no
    creation is half done; a reader that still sees an unrecorded store with content looks again before it
    reports anything. Never creates anything."""
    marker, info = state.marker(), state.store_info()
    if not (marker or {}).get("store") and info is not None and info.st_size > 0:
        marker, info = state.marker(), state.store_info()
    recorded = (marker or {}).get("store")
    path = state.store_path()
    name = state.configuration.name
    if recorded:
        require_recorded(info, path)
        store = EventStore.opened(path, name, "rw", recorded["id"])
        store.state = state
        return store
    if info is None or info.st_size == 0:
        return None
    store = unrecorded_store(path, name)
    if store is not None:
        store.close()
    return None


def stored_projection(text):
    """A stored lane row, which must be readable and in this version's form (an earlier version's row is rewritten
    by state rebuild)."""
    try:
        projection = json.loads(text)
    except (TypeError, ValueError):
        raise IntegrityProblem("the lane projection is not readable; run state rebuild") from None
    if not lanes.current_form(projection):
        raise IntegrityProblem("the lane projection is not in this version's form; run state rebuild")
    return projection


ROLES = ("brief", "protocol")
RENDERED_KEYS = {"inputs", "output", "project", "touches", "launcher_version"}
RELEASE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?")


def check_rendered(event, state, failure):
    """A brief.rendered event carries exactly what rendering writes, and every kept copy it names exists and
    hashes to its name (R12). `failure` is Refused at append and IntegrityProblem at verify."""
    label = "event seq {}".format(event["seq"]) if event.get("seq") else "a brief.rendered event"

    def fail(message):
        raise failure("{}: {}".format(label, message))

    payload = event["payload"]
    lane = event["lane"]
    if lane is None:
        fail("needs a lane")
    if set(payload) != RENDERED_KEYS:
        fail("its payload must hold exactly inputs, output, project, touches and launcher_version")
    inputs = payload["inputs"]
    if not isinstance(inputs, list) or len(inputs) < 2:
        fail("inputs must list the brief, the protocol and each rules file")
    for index, item in enumerate(inputs):
        role = ROLES[index] if index < len(ROLES) else "rules"
        detail = "version" if role == "protocol" else "path"
        if not isinstance(item, dict) or set(item) != {"role", "sha256", "copy", detail} or item["role"] != role:
            fail("input {} is not a {} input".format(index, role))
        digest = item["sha256"]
        if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None or \
                item["copy"] != "lanes/{}/inputs/{}".format(lane, digest):
            fail("input {} is not kept under the lane by its hash".format(index))
        value = item[detail]
        if not isinstance(value, str) or not value or (role == "protocol" and PROTOCOL_VERSION.fullmatch(value) is None):
            fail("input {} has no valid {}".format(index, detail))
        data = state.read_input(lane, digest) if state is not None else None
        if data is None:
            fail("kept input {} is missing".format(item["copy"]))
        if sha256_hex(data) != digest:
            fail("kept input {} does not match its hash".format(item["copy"]))
    output = payload["output"]
    if not (isinstance(output, dict) and set(output) == {"path", "sha256"} and isinstance(output["path"], str)
            and output["path"].startswith("/") and isinstance(output["sha256"], str)
            and DIGEST.fullmatch(output["sha256"]) is not None):
        fail("output must name an absolute path and its hash")
    project = payload["project"]
    if project is not None and (not isinstance(project, str) or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", project) is None):
        fail("project is not a project name")
    touches = payload["touches"]
    if not isinstance(touches, list) or any(not isinstance(touch, str) for touch in touches) or \
            touches != sorted(set(touches)) or any(touch not in ("billing", "deploy") for touch in touches):
        fail("touches must be a sorted list of billing and deploy")
    if not isinstance(payload["launcher_version"], str) or RELEASE.fullmatch(payload["launcher_version"]) is None:
        fail("launcher_version is not a version")


class EventStore:
    def __init__(self, path, config_name, mode, timeout=10):
        self.path = path
        self.config_name = config_name
        self.meta = None
        self.state = None
        uri = "file:{}?mode={}".format(quote(str(path), safe="/"), mode)
        self.connection = sqlite3.connect(uri, uri=True, timeout=timeout, isolation_level=None)
        self.connection.row_factory = sqlite3.Row

    @classmethod
    def opened(cls, path, config_name, mode, expected_id, timeout=10):
        store = cls(path, config_name, mode, timeout)
        try:
            store.check(expected_id)
        except BaseException:
            store.close()
            raise
        return store

    def close(self):
        self.connection.close()

    def _rollback(self):
        if self.connection.in_transaction:
            self.connection.execute("ROLLBACK")

    def initialize(self):
        """Create the schema once, with a new store id. Returns the metadata."""
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            if self.connection.execute("PRAGMA user_version").fetchone()[0] == 0:
                if self.connection.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]:
                    raise IntegrityProblem(str(self.path) + " is not an event store")
                for _, _, _, statement in SCHEMA:
                    self.connection.execute(statement)
                values = {"format": STORE_FORMAT, "config": self.config_name, "created_at": utc_now(),
                          "store_id": uuid.uuid4().hex}
                for key in sorted(values):
                    self.connection.execute("INSERT INTO meta (key, value) VALUES (?, ?)", (key, values[key]))
                self.connection.execute(META_LOCK[3])
                self.connection.execute("PRAGMA user_version = {}".format(STORE_VERSION))
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return self.check(None)

    def identity(self):
        """The store's metadata read in one snapshot, or None for a file that has no schema yet."""
        try:
            self.connection.execute("BEGIN")
            try:
                version = self.connection.execute("PRAGMA user_version").fetchone()[0]
                objects = self.connection.execute("SELECT count(*) FROM sqlite_master").fetchone()[0]
                if version == 0 and objects == 0:
                    return None
                if version != STORE_VERSION:
                    raise IntegrityProblem("{} is not an event store of version {}".format(self.path, STORE_VERSION))
                return dict(self.connection.execute("SELECT key, value FROM meta").fetchall())
            finally:
                self._rollback()
        except sqlite3.DatabaseError:
            raise IntegrityProblem("{} is not a readable event store".format(self.path)) from None

    def check(self, expected_id):
        meta = self.identity()
        if meta is None:
            raise IntegrityProblem("{} has no event store schema".format(self.path))
        if meta.get("format") != STORE_FORMAT or set(meta) != META_KEYS:
            raise IntegrityProblem("the store metadata does not describe an event store")
        if meta.get("config") != self.config_name:
            owner = meta.get("config")
            raise IntegrityProblem("the store belongs to configuration {}, not {}".format(
                owner if isinstance(owner, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", owner) else "another",
                self.config_name))
        if expected_id is not None and meta.get("store_id") != expected_id:
            raise IntegrityProblem("{} is not the store the ownership marker records".format(self.path))
        self.meta = meta
        return meta

    def _row_event(self, row):
        """Turn a stored row into an event, checking its payload form and its hash."""
        label = "event seq {}".format(row["seq"])
        try:
            payload = json.loads(row["payload"])
            form = canonical(payload)
            event = {field: row[field] for field in ENVELOPE_FIELDS + STORE_FIELDS if field != "payload"}
            event["payload"] = payload
            digest = event_hash(event)
        except (TypeError, ValueError, Refused):
            raise IntegrityProblem(label + ": stored payload is not valid JSON") from None
        if not isinstance(payload, dict) or form != row["payload"]:
            raise IntegrityProblem(label + ": stored payload is not a canonical JSON object")
        if digest != row["sha256"]:
            raise IntegrityProblem(label + ": stored hash does not match its content")
        return event

    def append(self, envelope, draining=False):
        """The one write path for events. Returns id, seq, recorded_at, sha256 and duplicate. A reserved kind
        is checked against what the launcher itself writes before anything is stored (R12), a lane event against
        its lane's projection, a resource event against its lane's row and the fold of the stored resource events,
        and a lane.state that accepts or merges against that fold, inside the same transaction that stores it. A
        lane event is refused while the lane has waiting events (pending.py), except from the one that appends them
        in order (draining); the check and the append hold the lane directory's lock, so no event can be queued
        between them."""
        event = validate_envelope(envelope)
        directory = None
        if lanes.is_lane_event(event) and not draining and self.state is not None:
            directory = self.state.open_lane(event["lane"])
        if directory is None:
            return self._append(event)
        try:
            with fsguard.Lock(directory):
                if lane_waiting(directory):
                    raise Refused("lane {} has events waiting to be recorded; lane check records them first, so the "
                                  "lane's events keep their order".format(event["lane"]))
                return self._append(event)
        finally:
            os.close(directory)

    def _append(self, event):
        if event["kind"] == "brief.rendered":
            check_rendered(event, self.state, Refused)
        if event["kind"].startswith("loop."):
            # The loop's own events are checked here and nowhere else (not by verify, not by rebuild).
            lanes.check_loop(event["kind"], event["lane"], event["payload"])
        if event["kind"] in ("lane.started", "lane.resumed", "lane.adopted") and self.state is not None:
            lanes.check_binding(event, self.state.real, multiplexer.socket_path(self.config_name, self.state.real))
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            row = self.connection.execute("SELECT * FROM events WHERE id = ?", (event["id"],)).fetchone()
            if row is not None:
                stored = self._row_event(row)
                if content(stored) != content(event):
                    raise IntegrityProblem("event id {} already exists with different content".format(event["id"]))
                self.connection.execute("ROLLBACK")
                return {"id": stored["id"], "seq": stored["seq"], "recorded_at": stored["recorded_at"],
                        "sha256": stored["sha256"], "duplicate": True}
            projection = None
            if lanes.is_lane_event(event):
                current = self.connection.execute(
                    "SELECT projection FROM lanes WHERE lane = ?", (event["lane"],)).fetchone()
                projection = stored_projection(current[0]) if current else None
                existing = lanes.recorded_seq(projection, event)
                if existing is not None:
                    # The same refusal or suspicion found again (by another scan, or after a re-scan) is a duplicate.
                    row = self.connection.execute("SELECT * FROM events WHERE seq = ?", (existing,)).fetchone()
                    if row is None:
                        raise IntegrityProblem("the lane projection names event seq {}, which is missing".format(
                            existing))
                    stored = self._row_event(row)
                    self.connection.execute("ROLLBACK")
                    return {"id": stored["id"], "seq": stored["seq"], "recorded_at": stored["recorded_at"],
                            "sha256": stored["sha256"], "duplicate": True}
                lanes.check_transition(projection, event, Refused)
                if event["kind"] == "lane.state" and event["payload"]["state"] in resources.ACCEPTING:
                    resources.check_state(self._records(event["lane"]), event, Refused)
            elif event["kind"].startswith("resource."):
                current = self.connection.execute(
                    "SELECT projection FROM lanes WHERE lane = ?", (event["lane"],)).fetchone()
                resources.check_transition(stored_projection(current[0]) if current else None, self._records(), event,
                                           Refused)
            event["seq"] = self.connection.execute(
                "SELECT max(coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'events'), 0), "
                "coalesce((SELECT max(seq) FROM events), 0)) + 1").fetchone()[0]
            event["recorded_at"] = utc_now()
            event["sha256"] = event_hash(event)
            self.connection.execute(
                "INSERT INTO events (seq, id, kind, lane, actor, occurred_at, payload, protocol_version, "
                "recorded_at, sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (event["seq"], event["id"], event["kind"], event["lane"], event["actor"], event["occurred_at"],
                 canonical(event["payload"]), event["protocol_version"], event["recorded_at"], event["sha256"]))
            if lanes.is_lane_event(event):
                self.connection.execute("INSERT OR REPLACE INTO lanes (lane, projection) VALUES (?, ?)",
                                        (event["lane"], canonical(lanes.apply(
                                            projection or lanes.empty(event["lane"]), event))))
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return {"id": event["id"], "seq": event["seq"], "recorded_at": event["recorded_at"],
                "sha256": event["sha256"], "duplicate": False}

    def references(self, lane, digest):
        """True when a brief.rendered event of this lane names the kept copy lanes/<lane>/inputs/<digest>."""
        copy = json.dumps("lanes/{}/inputs/{}".format(lane, digest))
        row = self.connection.execute("SELECT count(*) FROM events WHERE kind = 'brief.rendered' AND lane = ? AND "
                                      "instr(payload, ?) > 0", (lane, copy)).fetchone()
        return bool(row[0])

    def events(self, since=0):
        rows = self.connection.execute("SELECT * FROM events WHERE seq > ? ORDER BY seq", (since,)).fetchall()
        return [self._row_event(row) for row in rows]

    def lane_events(self, lane, kinds):
        """The lane's events of these kinds, in order, hash-checked and, being lane events, in this version's form."""
        rows = self.connection.execute(
            "SELECT * FROM events WHERE lane = ? AND kind IN ({}) ORDER BY seq".format(", ".join("?" * len(kinds))),
            (lane, *kinds)).fetchall()
        found = []
        for row in rows:
            event = self._row_event(row)
            try:
                lanes.check(event["kind"], event["lane"], event["payload"], IntegrityProblem)
            except IntegrityProblem as error:
                raise IntegrityProblem("event seq {}: {}; it was written by an earlier version of the launcher and no "
                                       "lane command acts on it (state verify lists every such event)".format(
                                           row["seq"], error)) from None
            found.append(event)
        return found

    def kind_events(self, kind, lane=None):
        """The hash-checked events of one kind (of one lane, when given), newest first, in whatever form they hold: the
        events of the loop (docs/architecture.md, "The `lane loop` command") are checked at append only, so a store may
        hold one in another form, which the reader tells by lanes.loop_form()."""
        if lane is None:
            rows = self.connection.execute("SELECT * FROM events WHERE kind = ? ORDER BY seq DESC", (kind,)).fetchall()
        else:
            rows = self.connection.execute("SELECT * FROM events WHERE kind = ? AND lane = ? ORDER BY seq DESC",
                                           (kind, lane)).fetchall()
        return [self._row_event(row) for row in rows]

    def last_event(self, lane, kind):
        """The most recent event of this kind for this lane, hash-checked and, for a lane event, in this version's
        form, or None. A lane event an earlier version wrote is an integrity problem: no lane command acts on it."""
        row = self.connection.execute("SELECT * FROM events WHERE lane = ? AND kind = ? ORDER BY seq DESC LIMIT 1",
                                      (lane, kind)).fetchone()
        if row is None:
            return None
        event = self._row_event(row)
        if lanes.is_lane_event(event):
            try:
                lanes.check(event["kind"], event["lane"], event["payload"], IntegrityProblem)
            except IntegrityProblem as error:
                raise IntegrityProblem("event seq {}: {}; it was written by an earlier version of the launcher and no "
                                       "lane command acts on it (state verify lists every such event)".format(
                                           row["seq"], error)) from None
        return event

    def resource_events(self, lane=None):
        """The stored resource events (those of one lane when it is given), in order, hash-checked and, being resource
        events, in this version's form."""
        rows = self.connection.execute(
            "SELECT * FROM events WHERE substr(kind, 1, 9) = 'resource.' AND (? IS NULL OR lane = ?) ORDER BY seq",
            (lane, lane)).fetchall()
        found = []
        for row in rows:
            event = self._row_event(row)
            try:
                resources.check(event["kind"], event["lane"], event["payload"], IntegrityProblem)
            except IntegrityProblem as error:
                raise IntegrityProblem("event seq {}: {}; it is not in this version's form and no resource command "
                                       "acts on it (state verify lists every such event)".format(
                                           row["seq"], error)) from None
            found.append(event)
        return found

    def _records(self, lane=None):
        """The fold of the stored resource events (those of one lane when it is given): what an event that is being
        appended is checked against, read inside the transaction that stores it."""
        return resources.fold(self.resource_events(lane), IntegrityProblem)

    def lanes(self):
        rows = self.connection.execute("SELECT lane, projection FROM lanes ORDER BY lane").fetchall()
        return [stored_projection(row["projection"]) for row in rows]

    def lane(self, name):
        """The stored projection of one lane, or None."""
        row = self.connection.execute("SELECT projection FROM lanes WHERE lane = ?", (name,)).fetchone()
        return stored_projection(row["projection"]) if row is not None else None

    def rebuild(self):
        """Recompute the lane projection from events alone and replace the stored one. Every event is checked as
        verify checks it (envelope, payload and the lanes' life cycle), so a store that verify rejects is not
        rebuilt."""
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            stored = self.events()
            for event in stored:
                try:
                    validate_envelope({field: event[field] for field in ENVELOPE_FIELDS})
                except Refused as error:
                    raise IntegrityProblem("event seq {}: {}".format(event["seq"], error)) from None
            projections = lanes.fold(stored, IntegrityProblem)
            resources.replay(stored, IntegrityProblem, resources.GATE_VERSION)
            self.connection.execute("DELETE FROM lanes")
            for projection in projections:
                self.connection.execute("INSERT INTO lanes (lane, projection) VALUES (?, ?)",
                                        (projection["lane"], canonical(projection)))
            self.connection.execute("COMMIT")
        except BaseException:
            self._rollback()
            raise
        return projections

    def verify(self, state=None):
        """Recompute every hash and check schema, metadata, sequence, projection, kept inputs and integrity."""
        self.connection.execute("BEGIN")
        try:
            return self._verify(state)
        finally:
            self._rollback()

    def _verify(self, state):
        connection = self.connection
        if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise IntegrityProblem("SQLite integrity_check failed")
        if connection.execute("PRAGMA user_version").fetchone()[0] != STORE_VERSION:
            raise IntegrityProblem("schema definition mismatch: user_version")
        expected = {(kind, name, table, statement) for kind, name, table, statement in SCHEMA + (META_LOCK,)}
        actual = set()
        for row in connection.execute("SELECT type, name, tbl_name, sql FROM sqlite_master"):
            entry = (row[0], row[1], row[2])
            if entry in INTERNAL and (row[3] is None or row[3].startswith("CREATE TABLE sqlite_sequence")):
                continue
            actual.add(tuple(row))
        if actual != expected:
            names = sorted({entry[1] for entry in actual.symmetric_difference(expected)})
            raise IntegrityProblem("schema definition mismatch: " + ", ".join(names))
        meta = dict(connection.execute("SELECT key, value FROM meta").fetchall())
        if set(meta) != META_KEYS or meta["format"] != STORE_FORMAT:
            raise IntegrityProblem("store metadata mismatch")
        if meta["config"] != self.config_name:
            raise IntegrityProblem("the store belongs to another configuration")
        try:
            check_timestamp(meta["created_at"], "created_at")
        except Refused:
            raise IntegrityProblem("store metadata mismatch: created_at") from None
        if state is not None:
            recorded = (state.marker() or {}).get("store")
            if not recorded or recorded.get("id") != meta["store_id"]:
                raise IntegrityProblem("the ownership marker does not record this store")
        events = []
        previous = 0
        for row in connection.execute("SELECT * FROM events ORDER BY seq"):
            if row["seq"] != previous + 1:
                raise IntegrityProblem("event seq {} follows seq {}: an event is missing".format(row["seq"], previous))
            event = self._row_event(row)
            try:
                normalized = validate_envelope({field: event[field] for field in ENVELOPE_FIELDS})
                check_timestamp(event["recorded_at"], "recorded_at")
            except Refused as error:
                raise IntegrityProblem("event seq {}: {}".format(row["seq"], error)) from None
            if normalized["id"] != event["id"] or not event["recorded_at"].endswith("Z"):
                raise IntegrityProblem("event seq {}: stored envelope is not valid".format(row["seq"]))
            events.append(event)
            previous = row["seq"]
        sequence = connection.execute("SELECT seq FROM sqlite_sequence WHERE name = 'events'").fetchone()
        if (sequence[0] if sequence else 0) != previous:
            raise IntegrityProblem("seq {} was issued but the last stored event is seq {}: events were removed".format(
                sequence[0] if sequence else 0, previous))
        stored = [(row["lane"], row["projection"]) for row in connection.execute(
            "SELECT lane, projection FROM lanes ORDER BY lane")]
        computed = lanes.fold(events, IntegrityProblem)
        resources.replay(events, IntegrityProblem, resources.GATE_VERSION)
        if stored != [(projection["lane"], canonical(projection)) for projection in computed]:
            raise IntegrityProblem("the stored lane projection does not match the events; run state rebuild")
        kept = mail_files = mail_orphans = 0
        if state is not None:
            from . import mail  # a module that imports this one: loaded when it is first used
            kept = verify_inputs(state, events)
            mail_files, mail_orphans = mail.verify(state, events)
        return {"ok": True, "exists": True, "config": self.config_name, "events": len(events),
                "lanes": len(computed), "kept_inputs": kept, "mail_files": mail_files, "mail_orphans": mail_orphans,
                "store": str(self.path)}


def lane_waiting(directory):
    """True when the opened lane directory holds waiting events: pending.jsonl, or events kept aside
    (pending-LAUNCH-ID.jsonl), that are not empty."""
    for name in os.listdir(directory):
        if name == "pending.jsonl" or (name.startswith("pending-") and name.endswith(".jsonl")):
            try:
                if os.stat(name, dir_fd=directory, follow_symlinks=False).st_size > 0:
                    return True
            except FileNotFoundError:
                continue
    return False


def verify_inputs(state, events):
    """Every brief.rendered event is what rendering writes and its kept copies hash right; every kept file is
    named by its hash. Names found on disk are printed only when they match the lane and digest grammars."""
    for event in events:
        if event["kind"] == "brief.rendered":
            check_rendered(event, state, IntegrityProblem)
    count = 0
    for lane, name in state.all_inputs():
        if name.startswith(".tmp-"):
            continue
        where = "lanes/{}/inputs".format(lane if LANE.fullmatch(lane) else "<a lane directory>")
        if DIGEST.fullmatch(name) is None:
            raise IntegrityProblem("a kept input under {} is not named by a SHA-256 digest".format(where))
        data = state.read_input(lane, name)
        if data is None or sha256_hex(data) != name:
            raise IntegrityProblem("kept input {}/{} does not match its hash".format(where, name))
        count += 1
    return count
