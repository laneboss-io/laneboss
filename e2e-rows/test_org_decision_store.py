"""Built-CLI org decision-store rows for a disposable Linux test machine.

Run check-org-decision-store.sh, or supply the release and laneboss_faults
binaries and an evidence directory through LANEBOSS_ORG_STORE_*.
Every row retains its real CLI inputs, output bytes, exit codes and store.
The mutant skips the product's text scan, never changes a test result, and
must be caught by the ordinary secret row before the restored row passes.
"""

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
import uuid


STORE_RELATIVE = ".laneboss/shared/services/decisions.sqlite"
UNREADABLE = "decision store cannot be read; secret scan could not complete"
NON_UTF8 = "file must be UTF-8; secret scan could not complete"
SYMLINK = "managed files and directories must not be symbolic links"
# The scanner's own TestScanDeadline uses this harmless secret-assignment shape.
CANARY = "password = 'harmless-canary'"
FAULT_POINT = "org-store-skip-text"
SECRET_ASSERTION = "secret decision must refuse"


def setUpModule():
    if not sys.platform.startswith("linux"):
        raise RuntimeError("org decision-store rows require the disposable Linux machine")
    global RELEASE, FAULTS, EVIDENCE
    names = ("LANEBOSS_ORG_STORE_BINARY", "LANEBOSS_ORG_STORE_FAULTS_BINARY",
             "LANEBOSS_ORG_STORE_EVIDENCE")
    paths = []
    for name in names:
        value = os.environ.get(name)
        if not value:
            raise RuntimeError(name + " must be supplied")
        path = Path(value)
        if not path.is_absolute():
            raise RuntimeError(name + " must name an absolute path")
        paths.append(path.resolve(strict=True))
    RELEASE, FAULTS, EVIDENCE = paths
    if not EVIDENCE.is_dir() or not all(path.is_file() and os.access(path, os.X_OK)
                                       for path in (RELEASE, FAULTS)):
        raise RuntimeError("org decision-store prerequisites are incomplete")


class OrgStoreRows(unittest.TestCase):
    binary_override = None
    fault_point = None

    def setUp(self):
        self.directory = EVIDENCE / (self._testMethodName + "-" + uuid.uuid4().hex[:10])
        self.directory.mkdir()
        self.home = self.directory / "home"
        self.home.mkdir()
        self.binary = self.binary_override or RELEASE
        self.env = {"HOME": str(self.home), "PATH": os.defpath, "LC_ALL": "C"}
        self.org = self.directory / "org"
        self.services = self.org / ".laneboss/shared/services"
        self.store = self.org / STORE_RELATIVE
        self.marker = self.directory / "mutant-reached"
        self.counter = 0
        self.observed = {}
        created = self.cli_json("org", "init", self.org, "--name", "store-demo")
        self.assertIs(created["ok"], True, "the real org fixture must be created")
        self.cli_json("decisions", "init", "--db", self.store)

    def cli(self, *args, fault=False):
        self.counter += 1
        argv = [str(self.binary), *map(str, args)]
        environment = dict(self.env)
        if fault and self.fault_point:
            environment["LANEBOSS_FAULTS"] = json.dumps({
                "point": self.fault_point, "marker": str(self.marker),
            })
        stem = self.directory / ("command-" + str(self.counter))
        stem.with_suffix(".input.json").write_text(json.dumps(argv) + "\n", encoding="utf-8")
        result = subprocess.run(argv, cwd=self.directory, env=environment,
                                capture_output=True, timeout=90)
        stem.with_suffix(".stdout").write_bytes(result.stdout)
        stem.with_suffix(".stderr").write_bytes(result.stderr)
        stem.with_suffix(".exit").write_text(str(result.returncode) + "\n", encoding="utf-8")
        result.stdout = result.stdout.decode("utf-8")
        result.stderr = result.stderr.decode("utf-8")
        return result

    def cli_json(self, *args):
        result = self.cli(*args)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def add_decision(self, answer, topics=None):
        identifier = "D-" + uuid.uuid4().hex[:24]
        record = {
            "id": identifier, "kind": "owner-decision",
            "asked_at": "2026-10-08T09:00:00Z",
            "answered_at": "2026-10-08T09:05:00Z",
            "project": "demo", "area": "org", "topics": topics or ["store"],
            "question": {"text": "Which review applies to " + identifier + "?",
                         "background": "Isolated org-store row."},
            "answer": {"verbatim": answer, "channel": "terminal"},
            "scope": {"applies_to": "demo"}, "status": "in_force",
            "provenance": {"recorded_by": "row", "recorded_at": "2026-10-08T09:05:00Z",
                           "sources": []},
        }
        source = self.directory / (identifier + ".json")
        source.write_text(json.dumps(record) + "\n", encoding="utf-8")
        added = self.cli_json("decisions", "add", "--db", self.store, "--file", source)
        self.assertEqual(added["id"], identifier)
        self.assertEqual(added["answer"]["verbatim"], answer)
        # Independently read the actual database, so a successful add response
        # alone cannot make the canary fixture look populated.
        uri = self.store.as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as database:
            row = database.execute(
                "SELECT id, record_json, d_text FROM records WHERE id = ?", (identifier,),
            ).fetchone()
        self.assertIsNotNone(row, "the CLI must persist the input decision")
        self.assertEqual(row[0], identifier)
        self.assertEqual(json.loads(row[1])["answer"]["verbatim"], answer)
        self.assertIn(answer, row[2], "the actual stored text must carry the input")
        (self.directory / (identifier + ".stored.json")).write_text(
            json.dumps({"id": row[0], "record_json": row[1], "d_text": row[2]}) + "\n",
            encoding="utf-8",
        )
        return identifier

    def store_snapshot(self):
        snapshot = {}
        for suffix in ("", "-wal", "-shm", "-journal"):
            path = Path(str(self.store) + suffix)
            if path.exists():
                info = path.stat()
                snapshot[suffix] = (path.read_bytes(), info.st_mode, info.st_mtime_ns)
        return snapshot

    def org_checks(self):
        results = {}
        # Run and keep both commands before asserting, so the mutant row can
        # prove that both validate and render actually accepted the bad store.
        for action in ("validate", "render"):
            args = ["org", action, self.org]
            if action == "validate":
                args += ["--format", "json"]
            result = self.cli(*args, fault=True)
            results[action] = result
            self.observed[action] = {
                "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
            }
        return results

    def problems(self, action, result, reason="org must refuse this input"):
        self.assertEqual(result.returncode, 2, reason + " (" + action + "): " + result.stderr)
        if action == "validate":
            report = json.loads(result.stdout)
            self.assertIs(report["valid"], False)
            self.assertTrue(report["problems"], "a failed validation must explain its refusal")
            return report["problems"]
        self.assertEqual(result.stdout, "", "a failed render must not report success")
        return [{"path": path, "message": message}
                for line in result.stderr.splitlines() if ": " in line
                for path, message in [line.split(": ", 1)]]

    def check_problem(self, action, result, relative, message):
        self.assertIn({"path": relative, "message": message}, self.problems(action, result))

    def test_secret_decision_refused(self):
        """Fails if either command accepts, omits the row/column, or exposes the fake credential."""
        answer = CANARY + "; row " + uuid.uuid4().hex
        identifier = self.add_decision(answer)
        before = self.store_snapshot()
        results = self.org_checks()
        self.assertEqual(self.store_snapshot(), before, "org scans must leave store bytes unchanged")
        for action, result in results.items():
            problems = self.problems(action, result, SECRET_ASSERTION)
            for column in ("record_json", "d_text"):
                prefix = "secret value detected in decision " + identifier + " column " + column + " ("
                self.assertTrue(any(problem["path"] == STORE_RELATIVE
                                    and problem["message"].startswith(prefix)
                                    and problem["message"].endswith("; keep secret names only")
                                    for problem in problems),
                                action + " must name the actual decision id and text column")
            self.assertNotIn("harmless-canary", result.stdout + result.stderr,
                             "diagnostics must not repeat the matched credential bytes")

    def test_clean_store(self):
        """Fails if clean binary stores cannot validate/render or scanning writes store files."""
        self.add_decision("Keep the review requirement for " + uuid.uuid4().hex + ".")
        # Empty companions are valid; arbitrary binary SHM bytes belong to the
        # separate invalid-companion control below.
        Path(str(self.store) + "-wal").write_bytes(b"")
        Path(str(self.store) + "-shm").write_bytes(b"")
        Path(str(self.store) + "-journal").write_bytes(b"")
        before = self.store_snapshot()
        for action, result in self.org_checks().items():
            self.assertEqual(result.returncode, 0, action + ": " + result.stderr)
            output = json.loads(result.stdout)
            if action == "validate":
                self.assertIs(output["valid"], True)
                self.assertEqual(output["problems"], [])
            else:
                self.assertIs(output["ok"], True)
                self.assertEqual(output["changed"], 0, "unchanged sources must not rewrite rules")
        self.assertEqual(self.store_snapshot(), before, "read-only scanning must preserve every store file")

    def test_corrupt_store(self):
        """Fails if corruption is silently skipped or gets only the old UTF-8 refusal."""
        self.store.rename(self.directory / "original.sqlite")
        data = b"\xffbroken SQLite\x00" + uuid.uuid4().bytes
        self.store.write_bytes(data)
        (self.directory / "corrupt-input.bin").write_bytes(data)
        for action, result in self.org_checks().items():
            self.check_problem(action, result, STORE_RELATIVE, UNREADABLE)
        self.assertEqual(self.store.read_bytes(), data, "refused scans must preserve corrupt input")

    def test_symlink_store(self):
        """Fails if a managed store symlink is followed or replaced."""
        target = self.directory / "retained.sqlite"
        self.store.rename(target)
        before = target.read_bytes()
        self.store.symlink_to(target)
        for action, result in self.org_checks().items():
            self.check_problem(action, result, STORE_RELATIVE, SYMLINK)
        self.assertTrue(self.store.is_symlink(), "the refused link must remain available as evidence")
        self.assertEqual(target.read_bytes(), before, "the symlink target must remain unchanged")

    def test_binary_services_control(self):
        """Fails if the store exception also admits another managed non-UTF-8 file."""
        self.add_decision("Keep the review requirement for " + uuid.uuid4().hex + ".")
        relative = ".laneboss/shared/services/notes.bin"
        data = b"\xff\xfe" + uuid.uuid4().bytes
        (self.services / "notes.bin").write_bytes(data)
        (self.directory / "notes-input.bin").write_bytes(data)
        for action, result in self.org_checks().items():
            self.check_problem(action, result, relative, NON_UTF8)
        self.assertEqual((self.org / relative).read_bytes(), data)


    def secret_problem(self, action, result, relative, prefix):
        problems = self.problems(action, result, "store text must be scanned")
        self.assertTrue(any(problem["path"] == relative
                            and problem["message"].startswith(prefix)
                            and problem["message"].endswith("; keep secret names only")
                            for problem in problems), "store text must be scanned: " + action + " " + prefix)
        self.assertNotIn("harmless-canary", result.stdout + result.stderr)

    def wal_decision(self, answer):
        writer = sqlite3.connect(self.store)
        self.wal_writer = writer
        self.addCleanup(writer.close)
        self.assertEqual(writer.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        # An idle connection does not prevent another connection's close-time
        # checkpoint. Hold a real reader snapshot before the CLI writes, so
        # that the retained decision is demonstrably only in WAL pages.
        writer.execute("BEGIN")
        writer.execute("SELECT count(*) FROM records").fetchone()
        before = self.store.read_bytes()
        identifier = self.add_decision(answer)
        self.assertIsNone(writer.execute("SELECT id FROM records WHERE id = ?", (identifier,)).fetchone(),
                          "the pinned reader must still see the pre-insert snapshot")
        self.assertEqual(self.store.read_bytes(), before, "the new decision must live only in WAL pages")
        with closing(sqlite3.connect(self.store.as_uri() + "?mode=ro&immutable=1", uri=True)) as main:
            self.assertIsNone(main.execute("SELECT id FROM records WHERE id = ?", (identifier,)).fetchone(),
                              "the main database must not already contain the decision")
        for suffix in ("", "-wal", "-shm"):
            source = Path(str(self.store) + suffix)
            if source.exists():
                (self.directory / ("input" + (suffix or "-main") + ".bin")).write_bytes(source.read_bytes())
        return identifier

    def test_wal_secret_refused(self):
        """Fails unless CURRENT WAL-only decision text is scanned, with the real id and column."""
        identifier = self.wal_decision(CANARY + "; row " + uuid.uuid4().hex)
        before = self.store_snapshot()
        for action, result in self.org_checks().items():
            for column in ("record_json", "d_text"):
                prefix = "secret value detected in decision " + identifier + " column " + column + " ("
                self.secret_problem(action, result, STORE_RELATIVE, prefix)
        self.assertEqual(self.store_snapshot(), before, "reading current WAL must not alter any store file")

    def test_clean_wal_store(self):
        """Fails if a real clean WAL cannot be read without modifying the database or SHM."""
        self.wal_decision("Keep the review requirement for " + uuid.uuid4().hex + ".")
        before = self.store_snapshot()
        for action, result in self.org_checks().items():
            self.assertEqual(result.returncode, 0, "clean WAL must remain usable: " + result.stderr)
            output = json.loads(result.stdout)
            self.assertIs(output["valid" if action == "validate" else "ok"], True)
        self.assertEqual(self.store_snapshot(), before, "WAL scanning must leave inputs unchanged")

    def test_other_table_secret(self):
        """Fails if text in the real lane_records table is omitted."""
        identifier = "R-" + uuid.uuid4().hex[:24]
        text = CANARY + "; row " + uuid.uuid4().hex
        with closing(sqlite3.connect(self.store)) as database:
            database.execute(
                "INSERT INTO lane_records (id,config,lane,part,source_path,source_sha256,text,"
                "created_utc,ingested_utc) VALUES (?,?,?,?,?,?,?,?,?)",
                (identifier, "fixture", "fixture", "report", "report.md",
                 hashlib.sha256(text.encode()).hexdigest(), text,
                 "2026-10-08T09:00:00Z", "2026-10-08T09:05:00Z"),
            )
            database.commit()
            self.assertEqual(database.execute("SELECT text FROM lane_records WHERE id = ?",
                                              (identifier,)).fetchone()[0], text)
        for action, result in self.org_checks().items():
            self.secret_problem(action, result, STORE_RELATIVE,
                                "secret value detected in table lane_records row " + identifier + " column text (")

    def test_schema_secret(self):
        """Fails if SQL schema text containing a credential shape is omitted."""
        name = "note_" + uuid.uuid4().hex[:12]
        text = CANARY.replace("'", "")
        with closing(sqlite3.connect(self.store)) as database:
            database.execute("CREATE VIEW " + name + " AS SELECT '" + text + "' AS body")
            database.commit()
            self.assertIn(text, database.execute("SELECT sql FROM sqlite_schema WHERE name = ?",
                                                 (name,)).fetchone()[0])
        for action, result in self.org_checks().items():
            self.secret_problem(action, result, STORE_RELATIVE,
                                "secret value detected in table sqlite_schema row " + name + " column sql (")
            self.check_problem(action, result, STORE_RELATIVE, "decision-store schema definition mismatch")

    def test_blob_text_secret(self):
        """Fails if UTF-8 credential text stored only as records.verbatim BLOB is skipped."""
        donor = self.add_decision("Keep the review requirement for " + uuid.uuid4().hex + ".")
        identifier = "B-" + uuid.uuid4().hex[:24]
        canary = (CANARY + "; row " + uuid.uuid4().hex).encode()
        with closing(sqlite3.connect(self.store)) as database:
            cursor = database.execute("SELECT * FROM records WHERE id = ?", (donor,))
            row = dict(zip((column[0] for column in cursor.description), cursor.fetchone()))
            row.pop("row_id")
            row["id"], row["verbatim"] = identifier, canary
            row["verbatim_sha256"] = hashlib.sha256(canary).hexdigest()
            # This intentionally inconsistent record models an untrusted store:
            # clean JSON/projections cannot excuse a secret in a separate BLOB.
            columns = list(row)
            database.execute("INSERT INTO records (" + ",".join(columns) + ") VALUES ("
                             + ",".join("?" for _ in columns) + ")", [row[column] for column in columns])
            database.commit()
            self.assertEqual(database.execute("SELECT typeof(verbatim),verbatim FROM records WHERE id = ?",
                                              (identifier,)).fetchone(), ("blob", canary))
        for action, result in self.org_checks().items():
            self.secret_problem(action, result, STORE_RELATIVE,
                                "secret value detected in decision " + identifier + " column verbatim (")

    def test_raw_tail_secret(self):
        """Fails if credential text beyond live SQLite pages escapes raw-byte screening."""
        self.store.write_bytes(self.store.read_bytes() + b"\n" + CANARY.encode() + b"\n")
        with closing(sqlite3.connect(self.store.as_uri() + "?mode=ro&immutable=1", uri=True)) as database:
            self.assertEqual(database.execute("PRAGMA quick_check").fetchone()[0], "ok",
                             "the fixture must remain a readable SQLite store")
        for action, result in self.org_checks().items():
            self.secret_problem(action, result, STORE_RELATIVE, "secret value detected on line ")

    def test_orphan_companion_text(self):
        """Fails if companion names beside a missing store evade ordinary credential scanning."""
        self.store.rename(self.directory / "retained.sqlite")
        for suffix in ("-wal", "-shm", "-journal"):
            Path(str(self.store) + suffix).write_text(CANARY + "\n", encoding="utf-8")
        for action, result in self.org_checks().items():
            for suffix in ("-wal", "-shm", "-journal"):
                self.secret_problem(action, result, STORE_RELATIVE + suffix, "secret value detected on line ")

    def test_invalid_shm_text(self):
        """Fails if plain credential text under a fake SHM name is exempted."""
        Path(str(self.store) + "-shm").write_text(CANARY + "\n", encoding="utf-8")
        for action, result in self.org_checks().items():
            self.secret_problem(action, result, STORE_RELATIVE + "-shm", "secret value detected on line ")

    def test_invalid_companion_binary(self):
        """Fails if a non-SQLite binary companion escapes the old UTF-8 rule."""
        for suffix in ("-wal", "-shm", "-journal"):
            Path(str(self.store) + suffix).write_bytes(b"\xffnot a SQLite companion")
        for action, result in self.org_checks().items():
            for suffix in ("-wal", "-shm", "-journal"):
                self.check_problem(action, result, STORE_RELATIVE + suffix, NON_UTF8)

    def test_unknown_schema_refused(self):
        """Fails if an extra table is accepted simply because its text is clean."""
        with closing(sqlite3.connect(self.store)) as database:
            database.execute("CREATE TABLE extra_note (body TEXT)")
            database.execute("INSERT INTO extra_note VALUES (?)", ("ordinary note " + uuid.uuid4().hex,))
            database.commit()
        for action, result in self.org_checks().items():
            self.check_problem(action, result, STORE_RELATIVE, "decision-store schema definition mismatch")


    def test_checkpointed_wal_store(self):
        """Fails if an ordinary checkpointed WAL-mode header becomes unusable."""
        identifier = self.wal_decision("Keep the checkpointed review " + uuid.uuid4().hex + ".")
        # Release the reader snapshot before asking SQLite to checkpoint.
        self.wal_writer.rollback()
        checkpoint = self.wal_writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        self.assertEqual(checkpoint[0], 0, "the real checkpoint must complete")
        self.wal_writer.close()
        self.assertEqual(self.store.read_bytes()[19], 2, "the main file must remain in WAL mode")
        for suffix in ("-wal", "-shm"):
            path = Path(str(self.store) + suffix)
            if path.exists():
                self.assertEqual(path.stat().st_size, 0, "a checkpointed fixture must have no remaining WAL")
        with closing(sqlite3.connect(self.store.as_uri() + "?mode=ro&immutable=1", uri=True)) as database:
            self.assertEqual(database.execute("SELECT id FROM records WHERE id = ?", (identifier,)).fetchone()[0],
                             identifier)
        before = self.store_snapshot()
        for action, result in self.org_checks().items():
            self.assertEqual(result.returncode, 0, "checkpointed WAL must remain usable: " + result.stderr)
            output = json.loads(result.stdout)
            self.assertIs(output["valid" if action == "validate" else "ok"], True)
        self.assertEqual(self.store_snapshot(), before)

    def test_fts_budget_counts_once(self):
        """Fails if the same physical FTS content is charged again through its virtual table."""
        # Populate FTS through its module, not its content shadow alone. The
        # multibyte text keeps the valid index below the physical file limit
        # while charging the actual UTF-8 text twice exceeds the text budget.
        payload = "note " + uuid.uuid4().hex + " " + "\u4e00" * 360000
        with closing(sqlite3.connect(self.store)) as database:
            database.execute("INSERT INTO keyword_index (rowid,id,q_text,d_text) VALUES (?,?,?,?)",
                             (1, "fixture", "ordinary question", payload))
            database.commit()
            self.assertEqual(database.execute("SELECT c2 FROM keyword_index_content WHERE id=1").fetchone()[0],
                             payload)
            self.assertEqual(database.execute("SELECT d_text FROM keyword_index WHERE rowid=1").fetchone()[0],
                             payload, "the virtual table must expose the same physical content")
            database.execute("INSERT INTO keyword_index(keyword_index) VALUES ('integrity-check')")
            self.assertEqual(database.execute("PRAGMA quick_check").fetchone()[0], "ok",
                             "the fixture must be a valid SQLite/FTS store before org scanning")
        self.assertLess(self.store.stat().st_size, 2 * 1024 * 1024, "the actual store must fit the file budget")
        self.assertGreater(2 * len(payload.encode("utf-8")), 2 * 1024 * 1024,
                           "double charging the fixture's real text must exceed the budget")
        for action, result in self.org_checks().items():
            self.assertEqual(result.returncode, 0, "FTS content must be counted once: " + result.stderr)
            output = json.loads(result.stdout)
            self.assertIs(output["valid" if action == "validate" else "ok"], True)

    def test_adjacent_clean_values(self):
        """Fails if separate clean values are joined into one raw credential assignment."""
        identifier = self.add_decision(":ordinary-note-" + uuid.uuid4().hex, topics=["password"])
        with closing(sqlite3.connect(self.store)) as database:
            question, answer = database.execute("SELECT q_text,d_text FROM records WHERE id=?",
                                                (identifier,)).fetchone()
            self.assertTrue(question.endswith("password"))
            self.assertTrue(answer.startswith(":ordinary-note-"))
        self.assertIn((question + answer).encode(), self.store.read_bytes(),
                      "the real record must store both clean values contiguously")
        for action, result in self.org_checks().items():
            self.assertEqual(result.returncode, 0, "adjacent clean values must remain usable: " + result.stderr)
            output = json.loads(result.stdout)
            self.assertIs(output["valid" if action == "validate" else "ok"], True)


class OrgStoreMutant(unittest.TestCase):
    def assert_restored(self, row, outcome):
        # Keep actual traceback text in the assertion message rather than a
        # nested tuple repr that unittest abbreviates in the box transcript.
        details = row._testMethodName + "\n" + "\n".join(
            trace for _, trace in outcome.errors + outcome.failures)
        self.assertEqual(outcome.testsRun, 1, details)
        self.assertEqual(outcome.errors, [], details)
        self.assertEqual(outcome.failures, [], details)
        self.assertEqual(outcome.skipped, [], details)

    def run_secret_row(self, binary, point, name="test_secret_decision_refused"):
        row = OrgStoreRows(name)
        row.binary_override = binary
        row.fault_point = point
        outcome = unittest.TestResult()
        row.run(outcome)
        (row.directory / "row-result.json").write_text(json.dumps({
            "tests_run": outcome.testsRun,
            "errors": [trace for _, trace in outcome.errors],
            "failures": [trace for _, trace in outcome.failures],
            "skipped": [reason for _, reason in outcome.skipped],
            "observed": row.observed,
        }) + "\n", encoding="utf-8")
        return row, outcome

    def test_skip_text_mutant_caught(self):
        """Fails unless the real skip mutation is reached, the ordinary row fails, and restoration passes."""
        mutant, red = self.run_secret_row(FAULTS, FAULT_POINT)
        self.assertEqual(red.testsRun, 1)
        self.assertEqual((red.errors, red.skipped), ([], []),
                         "the mutant must fail the row, not its fixture or a skipped test")
        self.assertEqual(len(red.failures), 1, "the ordinary secret row must catch the real mutation")
        self.assertIn(SECRET_ASSERTION, red.failures[0][1])
        self.assertTrue(mutant.marker.is_file(), "the compiled text-scan mutation must be reached")
        for action in ("validate", "render"):
            actual = mutant.observed[action]
            self.assertEqual(actual["exit_code"], 0, "the mutant must really accept the bad store")
            output = json.loads(actual["stdout"])
            self.assertIs(output["valid" if action == "validate" else "ok"], True)
        # First restore the same tagged binary, then prove release builds ignore
        # the mutation request altogether. Both run the unchanged ordinary row.
        for binary, point in ((FAULTS, None), (RELEASE, FAULT_POINT)):
            restored, green = self.run_secret_row(binary, point)
            self.assert_restored(restored, green)
            self.assertFalse(restored.marker.exists(), "the text-scan mutation must remain inactive")
        print("RESTORED ORG MUTANT org-store-skip-text caught: secret decision must refuse")


    def test_review_mutants_caught(self):
        """Each regression row must fail on its actual coverage mutation before restoration passes."""
        cases = [
            ("org-store-legacy-scan", name)
            for name in ("test_wal_secret_refused", "test_other_table_secret", "test_schema_secret",
                         "test_blob_text_secret", "test_raw_tail_secret")
        ] + [
            ("org-store-companion-names", "test_orphan_companion_text"),
            ("org-store-companion-names", "test_invalid_shm_text"),
        ]
        for point, name in cases:
            with self.subTest(point=point, row=name):
                mutant, red = self.run_secret_row(FAULTS, point, name)
                self.assertEqual(red.testsRun, 1)
                self.assertEqual((red.errors, red.skipped), ([], []), "a fixture error is not a caught regression")
                self.assertEqual(len(red.failures), 1, "the ordinary row must catch the changed product path")
                self.assertIn("store text must be scanned", red.failures[0][1])
                self.assertTrue(mutant.marker.is_file(), "the compiled coverage mutation must be reached")
                for action in ("validate", "render"):
                    self.assertEqual(mutant.observed[action]["exit_code"], 0,
                                     "the old coverage must actually accept the hidden text")
                for binary, requested in ((FAULTS, None), (RELEASE, point)):
                    restored, green = self.run_secret_row(binary, requested, name)
                    self.assert_restored(restored, green)
                    self.assertFalse(restored.marker.exists(), "restored and release paths must scan actual inputs")


    def test_wal_copy_mutants_caught(self):
        """Reproduce e735a26's real refusal, then restore the same WAL rows."""
        cases = (
            ("org-store-copy-nolock", "test_wal_secret_refused", "store text must be scanned"),
            ("org-store-copy-nolock", "test_clean_wal_store", "clean WAL must remain usable"),
            ("org-store-copy-nolock", "test_checkpointed_wal_store", "checkpointed WAL must remain usable"),
            ("org-store-fts-double", "test_fts_budget_counts_once", "FTS content must be counted once"),
            ("org-store-raw-join", "test_adjacent_clean_values", "adjacent clean values must remain usable"),
        )
        for point, name, assertion in cases:
            with self.subTest(point=point, row=name):
                mutant, red = self.run_secret_row(FAULTS, point, name)
                self.assertEqual((red.errors, red.skipped), ([], []), "a setup error is not a caught regression")
                self.assertEqual(red.testsRun, 1)
                self.assertEqual(len(red.failures), 1)
                self.assertIn(assertion, red.failures[0][1])
                self.assertTrue(mutant.marker.is_file(), "the real failing product path must be reached")
                for action in ("validate", "render"):
                    self.assertEqual(mutant.observed[action]["exit_code"], 2,
                                     "the mutated product must actually refuse the fixture")
                for binary, requested in ((FAULTS, None), (RELEASE, point)):
                    restored, green = self.run_secret_row(binary, requested, name)
                    self.assert_restored(restored, green)
                    self.assertFalse(restored.marker.exists(), "the restored path must use the actual snapshot")


if __name__ == "__main__":
    unittest.main()
