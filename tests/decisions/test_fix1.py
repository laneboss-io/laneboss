"""Black-box tests for fix round 1: exact layouts, first-written hashes, row protection, the older layout,
partial progress on a busy store, permissions, export into a pipe, term equivalence and write failures."""

import copy
import itertools
import json
import os
import shutil
import sqlite3
import subprocess
import threading
import time
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .support import (
    ROOT, VERSION1_OBJECTS, StoreCase, canonical, digest, ids, in_current_format, legacy_export, plain_record, record,
)


def add_op(value):
    return {"op": "add", "record": value}


def supersede_op(target, value):
    return {"op": "supersede", "target": target, "record": value}


def with_evidence(value, evidence):
    value = copy.deepcopy(value)
    if evidence is None:
        value.pop("outcome", None)
    else:
        value["outcome"] = {"evidence": evidence}
    return value


class LayoutTest(StoreCase):
    def populate(self):
        self.add()
        self.json_cli("supersede", "D-22", "--file", self.file("new.json", record("D-23")))
        self.json_cli("embed", "--config", self.config())

    def test_version_two_adds_to_version_one(self):
        current = self.objects()
        self.make_version2()
        fresh = self.objects()
        for name, definition in VERSION1_OBJECTS.items():
            self.assertEqual(fresh.get(name), definition, name)
        added = {name: definition for name, definition in fresh.items() if name not in VERSION1_OBJECTS}
        self.assertTrue(added, "version 2 must add objects to the version 1 layout")
        self.assertTrue(all(kind in ("table", "index", "trigger") for kind, table, sql in added.values()), added)
        self.json_cli("migrate")
        self.assertEqual(self.objects(), current)
        self.populate()
        self.make_version1()
        self.json_cli("migrate")
        self.assertEqual(self.objects(), current)
        self.json_cli("verify")

    def test_layout_changes_are_refused(self):
        changes = (
            ("lost primary key", "records",
             lambda: self.rebuild_records("    row_id INTEGER PRIMARY KEY,\n", "    row_id INTEGER,\n")),
            ("changed column type", "records",
             lambda: self.rebuild_records("    verbatim BLOB NOT NULL,\n", "    verbatim TEXT NOT NULL,\n")),
            ("extra trigger", "audit_insert",
             lambda: self.execute_script("CREATE TRIGGER audit_insert AFTER INSERT ON records BEGIN SELECT 1; END;")),
            ("extra index", "extra_lookup", lambda: self.execute_script("CREATE INDEX extra_lookup ON records(kind);")),
            ("extra table", "loose_notes", lambda: self.execute_script("CREATE TABLE loose_notes (body TEXT);")),
            ("extra view", "recent_ids", lambda: self.execute_script("CREATE VIEW recent_ids AS SELECT id FROM records;")),
        )
        self.populate()
        pristine = self.directory / "pristine.sqlite"
        shutil.copyfile(str(self.db), str(pristine))
        # Versions 1–3 are checked by migrate before additions; current version 4 is checked by verify.
        # A change to any of them
        # is refused and nothing is written.
        for label, name, change in changes:
            for version in (1, 2, 3, 4):
                with self.subTest(change=label, version=version):
                    shutil.copyfile(str(pristine), str(self.db))
                    if version == 1:
                        self.make_version1()
                    elif version == 2:
                        self.make_version2()
                    elif version == 3:
                        self.make_version3()
                    change()
                    before = self.db.read_bytes()
                    result = self.cli("verify" if version == 4 else "migrate", code=3)
                    self.assertIn("schema", result.stderr)
                    self.assertIn(name, result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertEqual(self.user_version(), version)
                    self.assertEqual(self.db.read_bytes(), before)


class FirstWrittenTest(StoreCase):
    def load(self, operations, code=0, db=None):
        return self.cli("load", "--in", self.write_batch(operations), code=code, db=db)

    def load_json(self, operations, db=None):
        return json.loads(self.load(operations, db=db).stdout)

    def refused(self, operations, *expected):
        before = self.db.read_bytes()
        result = self.load(operations, code=2)
        for text in expected:
            self.assertIn(text, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(self.db.read_bytes(), before)

    def test_changed_outcome_is_refused(self):
        batch = [add_op(plain_record("T-1")),
                 add_op(with_evidence(plain_record("R-1"), ["first", "second"])),
                 supersede_op("T-1", with_evidence(plain_record("N-1", verbatim="Newer"), ["first", "second"]))]
        self.load(batch)
        for change, evidence in (("shortened", ["first"]), ("emptied", []), ("omitted", None)):
            for position, identifier in ((1, "R-1"), (2, "N-1")):
                with self.subTest(change=change, record=identifier):
                    changed = copy.deepcopy(batch)
                    changed[position]["record"] = with_evidence(changed[position]["record"], evidence)
                    self.refused(changed, "line {}".format(position + 1), identifier, "outcome.evidence")
        self.assertEqual(self.json_cli("stats")["records"], 3)

    def test_annotated_record_reruns_unchanged(self):
        batch = [add_op(record("D-30")), supersede_op("D-30", record("D-31"))]
        self.load(batch)
        for identifier in ("D-30", "D-31"):
            self.json_cli("annotate", identifier, "--file", self.file(
                "outcome.json", {"evidence": ["checks/later.txt"], "followups": ["Look again"]}))
        before = self.db.read_bytes()
        result = self.load_json(batch)
        self.assertEqual((result["added"], result["superseded"], result["unchanged"]), (0, 0, 2))
        self.assertEqual(result["unchanged_by_weaker_comparison"], [])
        self.assertEqual(self.db.read_bytes(), before)
        annotated = with_evidence(record("D-30"), ["notes/request-7.txt", "checks/later.txt"])
        self.refused([add_op(annotated)], "D-30", "outcome")

    def test_line_order_is_irrelevant(self):
        self.add(plain_record("S-1"))
        batches = (
            ("conflicting copies", False, [add_op(with_evidence(plain_record("N-1"), ["a", "b"])),
                                           add_op(with_evidence(plain_record("N-1"), ["a"]))]),
            ("identical copies", True, [add_op(plain_record("N-2")), add_op(plain_record("N-2"))]),
            ("target added by another line", True, [add_op(plain_record("N-3")),
                                                     supersede_op("N-3", plain_record("N-4"))]),
            ("chain across lines", True, [add_op(plain_record("N-5")), supersede_op("N-5", plain_record("N-6")),
                                          supersede_op("N-6", plain_record("N-7"))]),
            ("one target twice", False, [supersede_op("S-1", plain_record("N-8")),
                                         supersede_op("S-1", plain_record("N-9"))]),
            ("cycle", False, [supersede_op("N-11", plain_record("N-10")),
                              supersede_op("N-10", plain_record("N-11"))]),
        )
        pristine = self.directory / "pristine.sqlite"
        shutil.copyfile(str(self.db), str(pristine))
        for label, accepted, batch in batches:
            states = set()
            for order in itertools.permutations(range(len(batch))):
                with self.subTest(batch=label, order=order):
                    shutil.copyfile(str(pristine), str(self.db))
                    before = self.db.read_bytes()
                    self.load([batch[index] for index in order], code=0 if accepted else 2)
                    if accepted:
                        rows = self.execute("SELECT id, record_json FROM records ORDER BY id")
                        states.add(repr((rows, self.dump().get("first_written"))))
                        self.json_cli("verify")
                    else:
                        self.assertEqual(self.db.read_bytes(), before)
            if accepted:
                self.assertEqual(len(states), 1, label)

    def test_migrated_records_are_weaker(self):
        batch = [add_op(record("D-30")), add_op(record("D-31")), supersede_op("D-30", record("D-32"))]
        self.load(batch)
        self.make_version1()
        self.json_cli("migrate")
        self.assertEqual(self.json_cli("stats")["records_without_first_written"], 3)
        result = self.load_json(batch)
        self.assertEqual(result["unchanged"], 3)
        self.assertEqual(result["unchanged_by_weaker_comparison"], ["D-30", "D-31", "D-32"])
        self.load([add_op(record("D-40"))])
        result = self.load_json([add_op(record("D-40")), add_op(record("D-31"))])
        self.assertEqual(result["unchanged_by_weaker_comparison"], ["D-31"])
        self.assertEqual(self.json_cli("stats")["records_without_first_written"], 3)

    def test_first_written_in_exports(self):
        written = self.add(record("D-30"))
        newer = self.json_cli("supersede", "D-30", "--file", self.file("new.json", record("D-31")))
        self.json_cli("annotate", "D-31", "--file", self.file("outcome.json", {"evidence": ["checks/later.txt"]}))
        target = self.directory / "out.jsonl"
        self.json_cli("export", "--out", target)
        entries = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]
        records = {entry["record"]["id"]: entry for entry in entries if entry["type"] == "record"}
        self.assertEqual(entries[0]["first_written"], 2)
        self.assertEqual(records["D-30"]["first_written_sha256"], digest(canonical(written)))
        self.assertEqual(records["D-31"]["first_written_sha256"], digest(canonical(newer)))
        self.assertNotEqual(digest(canonical(records["D-31"]["record"])), digest(canonical(newer)))
        other = self.directory / "other.sqlite"
        self.json_cli("init", db=other)
        self.json_cli("import", "--in", target, db=other)
        self.json_cli("verify", db=other)
        again = self.directory / "again.jsonl"
        self.json_cli("export", "--out", again, db=other)
        self.assertEqual(target.read_bytes(), again.read_bytes())
        result = self.load_json([add_op(record("D-30")), supersede_op("D-30", record("D-31"))], db=other)
        self.assertEqual((result["unchanged"], result["unchanged_by_weaker_comparison"]), (2, []))

    def test_previous_exports_import(self):
        self.add(record("D-30"))
        old = self.directory / "old.jsonl"
        old.write_bytes(legacy_export(self.db).encode("utf-8"))
        other = self.directory / "other.sqlite"
        self.json_cli("init", db=other)
        self.json_cli("import", "--in", old, db=other)
        self.assertEqual(self.json_cli("stats", db=other)["records_without_first_written"], 1)
        result = self.load_json([add_op(record("D-30"))], db=other)
        self.assertEqual((result["unchanged"], result["unchanged_by_weaker_comparison"]), (1, ["D-30"]))
        again = self.directory / "again.jsonl"
        self.json_cli("export", "--out", again, db=other)
        self.assertEqual(in_current_format(old.read_text(encoding="utf-8")).encode("utf-8"), again.read_bytes())

    def test_import_checks_first_written(self):
        self.add(record("D-30"))
        self.add(record("D-31"))
        target = self.directory / "out.jsonl"
        self.json_cli("export", "--out", target)
        entries = [json.loads(line) for line in target.read_text(encoding="utf-8").splitlines()]

        def wrong_count(lines):
            lines[0]["first_written"] = 5

        def undeclared(lines):
            lines[0].pop("first_written", None)
            lines[1]["first_written_sha256"] = "0" * 64

        def malformed(lines):
            lines[0]["first_written"] = 2
            lines[1]["first_written_sha256"] = "XYZ"
            lines[2]["first_written_sha256"] = "0" * 64

        def unknown_key(lines):
            lines[1]["note"] = "x"

        for label, change in (("wrong count", wrong_count), ("undeclared", undeclared),
                              ("malformed", malformed), ("unknown key", unknown_key)):
            with self.subTest(change=label):
                lines = copy.deepcopy(entries)
                change(lines)
                path = self.directory / (label.replace(" ", "-") + ".jsonl")
                path.write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")
                other = self.directory / (label.replace(" ", "-") + ".sqlite")
                self.json_cli("init", db=other)
                result = self.cli("import", "--in", path, db=other, code=2)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(self.json_cli("stats", db=other)["records"], 0)


class ProtectionTest(StoreCase):
    def setUp(self):
        super().setUp()
        self.add()
        self.add(record("D-23"))
        self.json_cli("embed", "--config", self.config())
        self.pristine = self.dump()

    def row(self, table, where):
        with closing(sqlite3.connect(str(self.db))) as connection:
            connection.row_factory = sqlite3.Row
            return dict(connection.execute("SELECT * FROM {} WHERE {}".format(table, where)).fetchone())

    def statement(self, verb, table, value):
        return ("{} INTO {} ({}) VALUES ({})".format(verb, table, ",".join(value), ",".join("?" for key in value)),
                tuple(value.values()))

    def assert_refused(self, statement, parameters=()):
        with closing(sqlite3.connect(str(self.db))) as connection:
            self.assertEqual(connection.execute("PRAGMA recursive_triggers").fetchone()[0], 0)
            with self.assertRaises(sqlite3.IntegrityError):
                with connection:
                    connection.execute(statement, parameters)
        self.assertEqual(self.dump(), self.pristine)

    def test_replace_skips_delete_triggers(self):
        scratch = self.directory / "scratch.sqlite"
        with closing(sqlite3.connect(str(scratch), isolation_level=None)) as connection:
            connection.execute("CREATE TABLE kept (key TEXT PRIMARY KEY, value TEXT)")
            connection.execute("CREATE TRIGGER kept_no_delete BEFORE DELETE ON kept BEGIN SELECT RAISE(ABORT, 'no'); END")
            connection.execute("INSERT INTO kept VALUES ('a', 'first')")
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM kept")
            connection.execute("INSERT OR REPLACE INTO kept VALUES ('a', 'second')")
            self.assertEqual(connection.execute("SELECT value FROM kept").fetchone()[0], "second")
            connection.execute("PRAGMA recursive_triggers = ON")
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("INSERT OR REPLACE INTO kept VALUES ('a', 'third')")

    def test_records(self):
        original = self.row("records", "id = 'D-22'")
        other = self.row("records", "id = 'D-23'")
        changed = dict(original, verbatim=b"changed", record_json=original["record_json"].replace("keep", "kept"))
        moved = dict(other, id="X-1")
        cases = (
            self.statement("INSERT OR REPLACE", "records", changed),
            self.statement("REPLACE", "records", {key: item for key, item in changed.items() if key != "row_id"}),
            self.statement("INSERT OR REPLACE", "records", moved),
            ("INSERT INTO records ({}) VALUES ({}) ON CONFLICT(id) DO UPDATE SET status = 'withdrawn'".format(
                ",".join(changed), ",".join("?" for key in changed)), tuple(changed.values())),
            ("DELETE FROM records WHERE id = 'D-22'",),
            ("UPDATE records SET id = 'X-1' WHERE id = 'D-22'",),
            ("UPDATE OR REPLACE records SET id = 'D-23' WHERE id = 'D-22'",),
            ("UPDATE OR REPLACE records SET row_id = ? WHERE id = 'D-22'", (other["row_id"],)),
        )
        for case in cases:
            with self.subTest(statement=case[0][:60]):
                self.assert_refused(*case)
        self.json_cli("verify")

    def test_models(self):
        original = self.row("models", "model = 'fake-a'")
        changed = dict(original, dimension=64)
        cases = (
            self.statement("INSERT OR REPLACE", "models", changed),
            self.statement("INSERT OR REPLACE", "models", dict(changed, model="fake-z", rowid=1)),
            ("DELETE FROM models",),
            ("UPDATE models SET dimension = 64",),
        )
        for case in cases:
            with self.subTest(statement=case[0][:60]):
                self.assert_refused(*case)
        self.json_cli("verify")

    def test_egress_log(self):
        original = self.row("egress_log", "id = 1")
        cases = (
            self.statement("INSERT OR REPLACE", "egress_log", dict(original, endpoint_host="elsewhere")),
            ("DELETE FROM egress_log WHERE id = 2",),
            ("UPDATE egress_log SET endpoint_host = 'elsewhere' WHERE id = 1",),
            ("UPDATE OR REPLACE egress_log SET id = 2 WHERE id = 1",),
        )
        for case in cases:
            with self.subTest(statement=case[0][:60]):
                self.assert_refused(*case)
        self.json_cli("verify")

    def test_first_written(self):
        original = self.row("first_written", "record_id = 'D-22'")
        changed = {key: ("0" * 64 if key != "record_id" else item) for key, item in original.items()}
        cases = (
            self.statement("INSERT OR REPLACE", "first_written", changed),
            ("DELETE FROM first_written WHERE record_id = 'D-22'",),
            ("UPDATE first_written SET record_id = 'D-23' WHERE record_id = 'D-22'",),
        )
        for case in cases:
            with self.subTest(statement=case[0][:60]):
                self.assert_refused(*case)
        self.json_cli("verify")


def manual_records_only():
    """The two lines of docs/decisions.md that build records-only.jsonl, exactly as the manual prints them, so
    the test cannot drift from the text a reader copies."""
    text = (ROOT / "docs" / "decisions.md").read_text(encoding="utf-8")
    lines = [line for line in text.splitlines()
             if line.startswith(("head -n 1 old-export.jsonl", "grep '^{\"record\":' old-export.jsonl"))]
    if len(lines) != 2:
        raise AssertionError("docs/decisions.md must print exactly the two records-only commands, found {}".format(
            len(lines)))
    return "\n".join(lines) + "\n"


class OlderLayoutTest(StoreCase):
    def populate(self, embed=True):
        self.add()
        self.json_cli("supersede", "D-22", "--file", self.file("new.json", record("D-23")))
        if embed:
            config = self.config()
            self.json_cli("embed", "--config", config)
            self.hits("deployment", "vector", config=config)
        self.make_version1()
        self.make_older_layout()

    def test_migrate_with_egress_history(self):
        self.populate()
        before = self.db.read_bytes()
        result = self.cli("migrate", code=3)
        for text in ("older layout", "previous_entry_sha256", "5 egress receipts", "cannot be carried",
                     "manifest", "record lines", "embed", "keep the old store"):
            self.assertIn(text, result.stderr)
        self.assertEqual(self.user_version(), 1)
        self.assertEqual(self.db.read_bytes(), before)

    def test_migrate_without_egress_history(self):
        self.populate(embed=False)
        before = self.db.read_bytes()
        result = self.cli("migrate", code=3)
        for text in ("older layout", "no egress receipts", "export it with the old release", "import"):
            self.assertIn(text, result.stderr)
        self.assertEqual(self.db.read_bytes(), before)

    def test_import_names_the_cause(self):
        self.populate()
        old = self.directory / "old-export.jsonl"
        old.write_bytes(legacy_export(self.db).encode("utf-8"))
        other = self.directory / "other.sqlite"
        self.json_cli("init", db=other)
        result = self.cli("import", "--in", old, db=other, code=2)
        for text in ("older release", "previous_entry_sha256", "hash chain", "record lines"):
            self.assertIn(text, result.stderr)
        self.assertNotIn("invalid import: 'previous_entry_sha256'", result.stderr)
        self.assertEqual(self.json_cli("stats", db=other)["records"], 0)

    def test_records_only_route(self):
        self.populate()
        expected = {identifier: json.loads(raw) for identifier, raw in
                    self.execute("SELECT id, record_json FROM records")}
        (self.directory / "old-export.jsonl").write_bytes(legacy_export(self.db).encode("utf-8"))
        result = subprocess.run(["sh", "-c", manual_records_only()], cwd=str(self.directory),
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        other = self.directory / "other.sqlite"
        self.json_cli("init", db=other)
        self.json_cli("import", "--in", self.directory / "records-only.jsonl", db=other)
        self.json_cli("verify", db=other)
        for identifier, value in expected.items():
            self.assertEqual(self.json_cli("get", identifier, db=other), value)
        self.assertEqual(self.json_cli("embed", "--config", self.config(), db=other)["embedded"], 4)
        self.json_cli("verify", db=other)

    def test_export_without_egress_imports(self):
        self.populate(embed=False)
        old = self.directory / "old-export.jsonl"
        old.write_bytes(legacy_export(self.db).encode("utf-8"))
        other = self.directory / "other.sqlite"
        self.json_cli("init", db=other)
        self.json_cli("import", "--in", old, db=other)
        self.json_cli("verify", db=other)
        self.assertNotIn("status_before_superseded", self.json_cli("get", "D-22", db=other))

    def test_superseded_without_history_rerun(self):
        self.populate(embed=False)
        old = self.directory / "old-export.jsonl"
        old.write_bytes(legacy_export(self.db).encode("utf-8"))
        other = self.directory / "other.sqlite"
        self.json_cli("init", db=other)
        self.json_cli("import", "--in", old, db=other)
        before = other.read_bytes()
        result = self.cli("load", "--in", self.write_batch([add_op(record("D-22"))]), db=other, code=2)
        for text in ("line 1", "D-22", "earlier status", "leave the line out"):
            self.assertIn(text, result.stderr)
        self.assertEqual(other.read_bytes(), before)
        result = json.loads(self.cli("load", "--in", self.write_batch(
            [supersede_op("D-22", record("D-23"))], name="newer.jsonl"), db=other).stdout)
        self.assertEqual((result["unchanged"], result["unchanged_by_weaker_comparison"]), (1, ["D-23"]))


class EmbedBusyTest(StoreCase):
    def test_busy_after_the_provider_was_called(self):
        self.add()
        received, release = threading.Event(), threading.Event()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format_string, *arguments):
                return

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                received.set()
                release.wait(60)
                data = [{"index": index, "embedding": [0.25] * body["output_dimension"]}
                        for index in range(len(body["input"]))]
                payload = json.dumps({"data": data, "model": body["model"]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(payload)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(worker.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(release.set)
        config = self.file("http.json", {
            "provider": "voyage", "api_key_env": "TEST_EMBED_KEY", "dimension": 256,
            "endpoint": "http://127.0.0.1:{}/v1/embeddings".format(server.server_port)})
        environment = dict(self.environment, TEST_EMBED_KEY="invented-test-value")
        process = self.start_cli("embed", "--config", config, environment=environment)
        self.assertTrue(received.wait(60), "the provider was never called")
        with closing(sqlite3.connect(str(self.db), timeout=1, isolation_level=None)) as holder:
            holder.execute("BEGIN IMMEDIATE")
            release.set()
            stdout, stderr = process.communicate(timeout=90)
            holder.execute("ROLLBACK")
        self.assertEqual(process.returncode, 5, stderr)
        self.assertIn("database busy", stderr)
        self.assertNotIn("nothing was changed", stderr)
        for text in ("model row", "2 egress receipts", "provider", "embed again"):
            self.assertIn(text, stderr)
        stats = self.json_cli("stats")
        self.assertEqual((stats["egress_entries"], stats["vectors"]), (2, 0))
        self.assertEqual([model["model"] for model in stats["models"]], ["voyage-4-large"])
        self.json_cli("verify")
        result = self.json_cli("embed", "--config", config, environment=environment)
        self.assertEqual(result["embedded"], 2)
        self.assertEqual(self.json_cli("stats")["egress_entries"], 4)
        self.json_cli("verify")


class PermissionTest(StoreCase):
    def prepare(self, name, version):
        folder = self.directory / name
        folder.mkdir()
        db = folder / "store.sqlite"
        self.json_cli("init", db=db)
        self.json_cli("add", "--file", self.file("permission.json", record()), db=db)
        if version == 1:
            self.make_version1(db=db)
        elif version == 2:
            self.make_version2(db=db)
        elif version == 3:
            self.make_version3(db=db)
        return folder, db

    def locked(self, path, mode):
        os.chmod(str(path), mode)
        self.addCleanup(os.chmod, str(path), 0o700 if path.is_dir() else 0o600)
        self.assertFalse(os.access(str(path), os.W_OK), "run the suite as an unprivileged user")

    def test_read_only_file(self):
        exports = self.directory / "exports"
        exports.mkdir()
        # Preserve read-only v3 refusals and add the current v4 rows; migrate covers all older layouts.
        # Every one refuses a read-only file with the permission
        # problem, before any write, and leaves the store's bytes and its schema version as they were.
        commands = (("verify", 3), ("verify", 4), ("export", 3), ("export", 4),
                    ("migrate", 1), ("migrate", 2), ("migrate", 3), ("add", 3), ("add", 4))
        for command, version in commands:
            with self.subTest(command=command, version=version):
                folder, db = self.prepare("read-only-{}-{}".format(command, version), version)
                self.locked(db, 0o400)
                before = db.read_bytes()
                arguments = {"export": ("--out", exports / "out.jsonl"),
                             "add": ("--file", self.file("other.json", record("D-23")))}.get(command, ())
                result = self.cli(command, *arguments, db=db, code=6)
                self.assertIn("permission problem", result.stderr)
                self.assertIn("write permission", result.stderr)
                self.assertNotIn("integrity problem", result.stderr)
                self.assertEqual(db.read_bytes(), before)
                self.assertEqual(self.user_version(db), version)
                self.assertFalse((exports / "out.jsonl").exists())

    def test_unwritable_directory(self):
        exports = self.directory / "exports"
        exports.mkdir()
        folder, db = self.prepare("unwritable-4", 4)
        self.locked(folder, 0o500)
        before = db.read_bytes()
        self.json_cli("verify", db=db)
        self.json_cli("export", "--out", exports / "out.jsonl", db=db)
        result = self.cli("add", "--file", self.file("other.json", record("D-23")), db=db, code=6)
        self.assertIn("permission problem", result.stderr)
        self.assertNotIn("integrity problem", result.stderr)
        self.assertEqual(db.read_bytes(), before)
        # migrate is the one command that opens a store of an earlier version, so it is checked against every
        # version it still opens (1, 2 and 3): the first write it makes is
        # the one the unwritable directory refuses, and the store's bytes and schema version are left as they were.
        for version in (1, 2, 3):
            with self.subTest(version=version):
                folder, db = self.prepare("unwritable-{}".format(version), version)
                self.locked(folder, 0o500)
                before = db.read_bytes()
                result = self.cli("migrate", db=db, code=6)
                self.assertIn("permission problem", result.stderr)
                self.assertIn("directory", result.stderr)
                self.assertNotIn("integrity problem", result.stderr)
                self.assertEqual(db.read_bytes(), before)
                self.assertEqual(self.user_version(db), version)


class ExportPipeTest(StoreCase):
    def read(self, reader, process, wanted=None, timeout=60):
        """Read from a non-blocking pipe until `wanted` bytes arrived, or until the writer is done."""
        data = b""
        deadline = time.monotonic() + timeout
        while wanted is None or len(data) < wanted:
            if time.monotonic() > deadline:
                self.fail("the pipe stayed silent")
            try:
                chunk = os.read(reader, 65536 if wanted is None else wanted - len(data))
            except BlockingIOError:
                time.sleep(0.01)
                continue
            if chunk:
                data += chunk
            elif process.poll() is not None:
                break
            else:
                time.sleep(0.01)
        return data

    def test_export_into_slow_pipe(self):
        large = record()
        large["question"]["background"] = "A long background line. " * 20000
        self.add(large)
        pipe = self.directory / "export.pipe"
        os.mkfifo(str(pipe))
        reader = os.open(str(pipe), os.O_RDONLY | os.O_NONBLOCK)
        try:
            exporter = self.start_cli("export", "--out", pipe)
            received = self.read(reader, exporter, wanted=1)
            time.sleep(0.5)
            self.assertIsNone(exporter.poll(), "the export must still be writing into the full pipe")
            started = time.monotonic()
            self.json_cli("add", "--file", self.file("other.json", record("D-23")))
            self.assertLess(time.monotonic() - started, 9.0)
            self.assertIsNone(exporter.poll(), "the export must still be waiting for its reader")
            received += self.read(reader, exporter)
            stdout, stderr = exporter.communicate(timeout=60)
        finally:
            os.close(reader)
        self.assertEqual(exporter.returncode, 0, stderr)
        lines = received.decode("utf-8").splitlines()
        self.assertEqual(json.loads(lines[0])["counts"]["records"], 1)
        self.assertEqual([json.loads(line)["record"]["id"] for line in lines[1:]], ["D-22"])
        self.assertEqual(json.loads(stdout)["exported"], 1)
        self.assertEqual(self.json_cli("verify")["records"], 2)


class TermEquivalenceTest(StoreCase):
    def test_sharp_s_and_double_s(self):
        self.add(plain_record("G-1", "Meet at the Straße corner", "Agreed"))
        self.add(plain_record("G-2", "Meet at the Strasse corner", "Agreed"))
        cases = (
            (("Straße", "STRASSE"), []),
            (("STRAßE", "straße", "Straße"), ["G-1"]),
            (("STRASSE", "strasse", "Strasse"), ["G-2"]),
            (("ß", "SS"), ["G-1", "G-2"]),
            (("ße", "sse"), ["G-2"]),
            (("ße", "SSE", "Corner"), ["G-2"]),
        )
        # A repeated term must give exactly the result of the term written once. Different terms may leave
        # identical-looking matches (a match does not name its term), so that alone is not a repeat.
        repeated = {("STRAßE", "straße", "Straße"): "straße", ("STRASSE", "strasse", "Strasse"): "strasse",
                    ("ß", "SS"): "ss"}
        for terms, expected in cases:
            results = []
            for order in itertools.permutations(terms):
                with self.subTest(order=order):
                    hits = self.hits(" ".join(order))
                    self.assertEqual(sorted(ids(hits)), expected)
                    results.append(hits)
            for hits in results[1:]:
                self.assertEqual(hits, results[0], terms)
            if terms in repeated:
                self.assertEqual(results[0], self.hits(repeated[terms]), terms)


class LoadWriteFailureTest(StoreCase):
    def test_late_failure_rolls_back(self):
        self.add()
        self.execute_script("CREATE TRIGGER test_abort BEFORE INSERT ON records WHEN NEW.id = 'D-33' "
                            "BEGIN SELECT RAISE(ABORT, 'test-installed abort'); END;")
        batch = [add_op(record("D-30")), add_op(record("D-31")), supersede_op("D-22", record("D-32")),
                 add_op(record("D-33")), add_op(record("D-34"))]
        before = self.db.read_bytes()
        result = self.cli("load", "--in", self.write_batch(batch), code=2)
        for text in ("line 4", "D-33", "test-installed abort"):
            self.assertIn(text, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(self.db.read_bytes(), before)
        self.execute_script("DROP TRIGGER test_abort;")
        self.assertEqual(self.json_cli("stats")["records"], 1)
        self.assertEqual(self.json_cli("get", "D-22")["status"], "in_force")
        self.json_cli("verify")
        self.assertEqual(json.loads(self.cli("load", "--in", self.write_batch(batch)).stdout)["records_after"], 6)
