"""Black-box tests for fix round 2: row-id spellings, carried first-written hashes, schema names shared across
object types, the export destination at open time, explicit nulls in the weaker comparison, which commands check
the layout, and a migrate that fails after it has started adding objects."""

import json
import os
from pathlib import Path
import shutil
import sqlite3
from contextlib import closing

from .support import StoreCase, canonical, digest, plain_record, record


def add_op(value):
    return {"op": "add", "record": value}


def supersede_op(target, value):
    return {"op": "supersede", "target": target, "record": value}


class RowIdSpellingTest(StoreCase):
    def setUp(self):
        super().setUp()
        self.add(record("D-22"))
        self.add(record("D-23"))
        self.assertEqual(self.execute("SELECT row_id, id FROM records ORDER BY row_id"), [(1, "D-22"), (2, "D-23")])
        self.snapshot()

    def snapshot(self):
        self.pristine_file = self.directory / "pristine.sqlite"
        shutil.copyfile(str(self.db), str(self.pristine_file))

    def refused(self, statement, parameters=()):
        """An ordinary connection (recursive triggers off) must be refused, and nothing may change. Every statement
        starts from the same copy, so one accepted statement cannot hide what the next one does."""
        shutil.copyfile(str(self.pristine_file), str(self.db))
        pristine = self.dump()
        answers = self.execute("SELECT id, verbatim FROM records ORDER BY id")
        with closing(sqlite3.connect(str(self.db))) as connection:
            self.assertEqual(connection.execute("PRAGMA recursive_triggers").fetchone()[0], 0)
            with self.assertRaises(sqlite3.IntegrityError):
                with connection:
                    connection.execute(statement, parameters)
        self.assertEqual(self.dump(), pristine)
        self.assertEqual(self.execute("SELECT id, verbatim FROM records ORDER BY id"), answers)
        self.json_cli("verify")

    def test_records_row_id_spellings(self):
        for name in ("rowid", "_rowid_", "oid", "ROWID", "row_id", '"row_id"'):
            for statement in ("UPDATE OR REPLACE records SET {0} = 1 WHERE {0} = 2",
                              "UPDATE records SET {0} = 3 WHERE {0} = 2",
                              "UPDATE OR IGNORE records SET {0} = 1 WHERE {0} = 2"):
                with self.subTest(statement=statement.format(name)):
                    self.refused(statement.format(name))

    def test_records_id_spellings(self):
        for name in ("id", "ID", '"id"', "[id]", "`id`"):
            for statement in ("UPDATE OR REPLACE records SET {0} = 'D-23' WHERE row_id = 1",
                              "UPDATE records SET {0} = 'X-1' WHERE row_id = 1"):
                with self.subTest(statement=statement.format(name)):
                    self.refused(statement.format(name))

    def test_insert_with_row_id_spellings(self):
        with closing(sqlite3.connect(str(self.db))) as connection:
            connection.row_factory = sqlite3.Row
            row = dict(connection.execute("SELECT * FROM records WHERE row_id = 2").fetchone())
        for name in ("rowid", "_rowid_", "oid"):
            value = dict(row, id="X-1")
            del value["row_id"]
            value[name] = 1
            with self.subTest(column=name):
                self.refused("INSERT OR REPLACE INTO records ({}) VALUES ({})".format(
                    ",".join(value), ",".join("?" for key in value)), tuple(value.values()))

    def test_other_protected_tables(self):
        self.json_cli("embed", "--config", self.config())
        self.json_cli("embed", "--config", self.config("fake-b"))
        self.snapshot()
        for statement in ("UPDATE OR REPLACE egress_log SET rowid = 1 WHERE rowid = 2",
                          "UPDATE egress_log SET oid = 90 WHERE oid = 1",
                          "UPDATE OR REPLACE egress_log SET _rowid_ = 1 WHERE _rowid_ = 2",
                          "UPDATE OR REPLACE models SET rowid = 1 WHERE rowid = 2",
                          "UPDATE models SET _rowid_ = 90 WHERE _rowid_ = 1",
                          "UPDATE OR REPLACE first_written SET record_id = 'D-23' WHERE record_id = 'D-22'"):
            with self.subTest(statement=statement):
                self.refused(statement)


class CarriedHashTest(StoreCase):
    def test_hash_of_another_answer(self):
        approve = plain_record("D-30", verbatim="Approve")
        decline = plain_record("D-30", verbatim="Decline")
        scratch = self.directory / "scratch.sqlite"
        self.json_cli("init", db=scratch)
        approve_hash = digest(canonical(self.json_cli("add", "--file", self.file("approve.json", approve), db=scratch)))
        holder = self.directory / "holder.sqlite"
        self.json_cli("init", db=holder)
        self.json_cli("add", "--file", self.file("decline.json", decline), db=holder)
        exported = self.directory / "holder.jsonl"
        self.json_cli("export", "--out", exported, db=holder)
        lines = [json.loads(line) for line in exported.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(lines[0]["first_written"], 1)
        self.assertNotEqual(lines[1]["first_written_sha256"], approve_hash)
        lines[1]["first_written_sha256"] = approve_hash
        carried = self.directory / "carried.jsonl"
        carried.write_text("".join(json.dumps(line, ensure_ascii=False) + "\n" for line in lines), encoding="utf-8")
        self.json_cli("import", "--in", carried)
        self.json_cli("verify")
        before = self.db.read_bytes()
        result = self.cli("load", "--in", self.write_batch([add_op(approve), add_op(plain_record("D-31"))]), code=2)
        for text in ("line 1", "D-30", "answer.verbatim"):
            self.assertIn(text, result.stderr)
        self.assertEqual(self.db.read_bytes(), before)
        self.cli("get", "D-31", code=2)
        self.assertEqual(self.json_cli("get", "D-30")["answer"]["verbatim"], "Decline")


class NameCollisionTest(StoreCase):
    def collide(self):
        self.execute_script(
            "DROP INDEX exact_metadata;"
            "CREATE TRIGGER exact_metadata AFTER INSERT ON records BEGIN SELECT 1; END;"
            "CREATE INDEX exact_metadata ON records(project, area, status, kind, answered_utc);")
        kinds = sorted(row[0] for row in self.execute("SELECT type FROM sqlite_master WHERE name = 'exact_metadata'"))
        self.assertEqual(kinds, ["index", "trigger"])

    def test_trigger_named_like_an_index(self):
        self.add()
        pristine = self.directory / "pristine.sqlite"
        shutil.copyfile(str(self.db), str(pristine))
        # Version 1 and version 2 are the layouts the migrate command opens, and it compares the stored objects
        # against that version's before it adds anything; version 3 is the current layout, which verify compares
        # against its own. In every one a trigger that shares the index's name is an extra object and is refused.
        for version in (1, 2, 3):
            with self.subTest(version=version):
                shutil.copyfile(str(pristine), str(self.db))
                if version == 1:
                    self.make_version1()
                elif version == 2:
                    self.make_version2()
                self.collide()
                before = self.db.read_bytes()
                result = self.cli("verify" if version == 3 else "migrate", code=3)
                for text in ("schema", "trigger exact_metadata"):
                    self.assertIn(text, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(self.db.read_bytes(), before)
                self.assertEqual(self.user_version(), version)


class ExportDestinationTest(StoreCase):
    def test_pipe_replaced_before_open(self):
        self.add()
        pipe = self.directory / "export.pipe"
        os.mkfifo(str(pipe))
        evidence = b"evidence that must stay as it is\n"
        replacement = self.directory / "replacement.txt"
        replacement.write_bytes(evidence)
        marker = self.directory / "checked"
        with closing(sqlite3.connect(str(self.db), timeout=1, isolation_level=None)) as holder:
            holder.execute("BEGIN IMMEDIATE")
            exporter = self.start_hooked("pipe-checked", marker, "export", "--out", pipe)
            # The marker appears once the export has looked at its destination and found a named pipe. It then waits
            # for the write lock this connection holds, so the replacement below always comes after that first
            # check, however the processes are scheduled: only the check of the opened descriptor can refuse it.
            self.wait_for(marker, process=exporter)
            os.replace(str(replacement), str(pipe))
            holder.execute("ROLLBACK")
        stdout, stderr = exporter.communicate(timeout=60)
        self.assertEqual(exporter.returncode, 2, stderr)
        self.assertIn("export destination changed", stderr)
        self.assertIn("no longer a named pipe", stderr)
        self.assertNotIn("already exists", stderr)
        self.assertEqual(pipe.read_bytes(), evidence)


class ExplicitNullTest(StoreCase):
    def test_explicit_nulls_after_migration(self):
        first = record("N-1")
        first["superseded_by"] = None
        second = record("N-2")
        second["status_before_superseded"] = None
        third = record("N-3")
        third["superseded_by"] = None
        third["status_before_superseded"] = None
        newer = record("N-4")
        for value in (first, second, third):
            self.json_cli("add", "--file", self.file("value.json", value))
        self.json_cli("supersede", "N-3", "--file", self.file("newer.json", newer))
        stored = json.loads(self.execute("SELECT record_json FROM records WHERE id = 'N-1'")[0][0])
        self.assertIn("superseded_by", stored)
        batch = [add_op(first), add_op(second), add_op(third), supersede_op("N-3", newer)]
        result = json.loads(self.cli("load", "--in", self.write_batch(batch, name="first-written.jsonl")).stdout)
        self.assertEqual((result["unchanged"], result["unchanged_by_weaker_comparison"]), (4, []))
        self.make_version1()
        self.json_cli("migrate")
        before = self.db.read_bytes()
        result = json.loads(self.cli("load", "--in", self.write_batch(batch)).stdout)
        self.assertEqual((result["added"], result["superseded"], result["unchanged"]), (0, 0, 4))
        self.assertEqual(result["unchanged_by_weaker_comparison"], ["N-1", "N-2", "N-3", "N-4"])
        self.assertEqual(self.db.read_bytes(), before)
        changed = dict(first, project="phase-z")
        result = self.cli("load", "--in", self.write_batch([add_op(changed)], name="changed.jsonl"), code=2)
        self.assertIn("project", result.stderr)


class LayoutScopeTest(StoreCase):
    def test_which_commands_check_the_layout(self):
        self.add()
        self.execute_script("CREATE INDEX extra_lookup ON records(kind);")
        batch = self.write_batch([add_op(record("D-40"))])
        self.assertIn("extra_lookup", self.cli("verify", code=3).stderr)
        self.assertIn("extra_lookup", self.cli("export", "--out", self.directory / "out.jsonl", code=3).stderr)
        self.assertFalse((self.directory / "out.jsonl").exists())
        self.assertIn("extra_lookup", self.cli("load", "--in", batch, code=3).stderr)
        healthy = self.directory / "healthy.sqlite"
        self.json_cli("init", db=healthy)
        self.json_cli("add", "--file", self.file("healthy.json", record("D-50")), db=healthy)
        source = self.directory / "healthy.jsonl"
        self.json_cli("export", "--out", source, db=healthy)
        other = self.directory / "other.sqlite"
        self.json_cli("init", db=other)
        self.execute_script("CREATE INDEX extra_lookup ON records(kind);", db=other)
        self.assertIn("extra_lookup", self.cli("import", "--in", source, db=other, code=3).stderr)
        self.assertEqual(self.json_cli("stats", db=other)["records"], 0)
        # The other commands check only the schema version and the records they read or write.
        self.json_cli("get", "D-22")
        self.json_cli("stats")
        self.assertEqual([hit["record"]["id"] for hit in self.hits("deployment")], ["D-22"])
        self.json_cli("egress", "--list")
        self.json_cli("load", "--in", batch, "--dry-run")
        self.json_cli("add", "--file", self.file("other.json", record("D-23")))
        self.json_cli("annotate", "D-23", "--file", self.file("outcome.json", {"evidence": ["checks/later.txt"]}))
        self.json_cli("supersede", "D-23", "--file", self.file("newer.json", record("D-24")))
        self.assertIs(self.json_cli("migrate")["migrated"], False)
        self.cli("verify", code=3)


class LateMigrateFailureTest(StoreCase):
    def test_file_size_limit_stops_migrate(self):
        self.add()
        self.json_cli("supersede", "D-22", "--file", self.file("new.json", record("D-23")))
        self.json_cli("annotate", "D-23", "--file", self.file("outcome.json", {"evidence": ["checks/result.txt"]}))
        config = self.config()
        self.json_cli("embed", "--config", config)
        self.hits("deployment", "vector", config=config)
        self.make_version1()
        # No free pages: the objects that migrate adds must grow the file.
        self.execute_script("VACUUM;")
        self.assertEqual(self.execute("PRAGMA freelist_count")[0][0], 0)
        before_rows, before_bytes = self.dump(), self.db.read_bytes()
        result = self.cli_limited(len(before_bytes) + 512, "migrate", code=7)
        self.assertIn("storage problem", result.stderr)
        self.assertIn("nothing was changed", result.stderr)
        self.assertNotIn("integrity problem", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertFalse(Path(str(self.db) + "-journal").exists())
        self.assertEqual(self.db.read_bytes(), before_bytes)
        self.assertEqual(self.user_version(), 1)
        self.assertEqual(self.dump(), before_rows)
        self.assertIs(self.json_cli("migrate")["migrated"], True)
        self.json_cli("verify")
