"""Black-box tests for the incremental loader: load --db X --in batch.jsonl [--dry-run]."""

import json
import os
import sqlite3
import time
from contextlib import closing

from .support import VERBATIM, StoreCase, digest, ids, plain_record, record

COUNT_KEYS = ("added", "superseded", "unchanged", "records_before", "records_after")


def add_op(value):
    return {"op": "add", "record": value}


def supersede_op(target, value):
    return {"op": "supersede", "target": target, "record": value}


def counts(added, superseded, unchanged, before, after):
    return dict(zip(COUNT_KEYS, (added, superseded, unchanged, before, after)))


def classic(result):
    """The five counts of a load result; any other key must be one of the documented additions."""
    unexpected = set(result) - set(COUNT_KEYS) - {"unchanged_by_weaker_comparison", "dry_run"}
    assert not unexpected, unexpected
    return {key: result[key] for key in COUNT_KEYS}


class LoadCase(StoreCase):
    def load(self, operations, *arguments, code=0, name="batch.jsonl", **options):
        return self.cli("load", "--in", self.write_batch(operations, name=name, **options), *arguments, code=code)

    def load_json(self, operations, *arguments, **options):
        return json.loads(self.load(operations, *arguments, **options).stdout)

    def raw_batch(self, lines, name="raw.jsonl"):
        data = b"".join((line if isinstance(line, bytes) else line.encode("utf-8")) + b"\n" for line in lines)
        path = self.directory / name
        path.write_bytes(data)
        return path

    def assert_refused(self, path, *expected, arguments=()):
        """The whole batch is refused with exit 2, the message names what is wrong, and the file is untouched."""
        before = self.db.read_bytes()
        result = self.cli("load", "--in", path, *arguments, code=2)
        for text in expected:
            self.assertIn(text, result.stderr)
        self.assertNotIn("Traceback", result.stderr)
        self.assertEqual(self.db.read_bytes(), before)
        return result


class LoadBasicsTest(LoadCase):
    def test_adds_to_a_populated_store(self):
        self.add()
        self.add(record("D-23"))
        result = self.load_json([add_op(record("D-30")), add_op(record("D-31"))])
        self.assertEqual(classic(result), counts(2, 0, 0, 2, 4))
        self.assertEqual(ids(self.hits("", "exact")), ["D-22", "D-23", "D-30", "D-31"])
        self.json_cli("verify")
        other = self.directory / "other.sqlite"
        self.json_cli("init", db=other)
        for identifier in ("D-22", "D-23", "D-30", "D-31"):
            self.json_cli("add", "--file", self.file("one.json", record(identifier)), db=other)
        self.assertEqual(self.dump(), self.dump(db=other))
        for identifier in ("D-30", "D-31"):
            self.assertEqual(self.json_cli("get", identifier), self.json_cli("get", identifier, db=other))

    def test_loads_into_an_empty_store(self):
        result = self.load_json([add_op(record("D-30"))])
        self.assertEqual(classic(result), counts(1, 0, 0, 0, 1))
        self.json_cli("verify")

    def test_rerun_changes_nothing(self):
        self.add()
        batch = [add_op(record("D-30")), supersede_op("D-22", record("D-31")), add_op(record("D-32"))]
        self.assertEqual(classic(self.load_json(batch)), counts(2, 1, 0, 1, 4))
        before = self.db.read_bytes()
        self.assertEqual(classic(self.load_json(batch)), counts(0, 0, 3, 4, 4))
        self.assertEqual(self.db.read_bytes(), before)
        self.json_cli("verify")

    def test_partly_new_batch(self):
        self.add()
        batch = [add_op(record("D-22")), add_op(record("D-30"))]
        self.assertEqual(classic(self.load_json(batch)), counts(1, 0, 1, 1, 2))

    def test_batch_may_use_its_own_records(self):
        batch = [add_op(record("C-1")), supersede_op("C-1", record("C-2")), supersede_op("C-2", record("C-3"))]
        self.assertEqual(classic(self.load_json(batch)), counts(1, 2, 0, 0, 3))
        first, second, third = (self.json_cli("get", name) for name in ("C-1", "C-2", "C-3"))
        self.assertEqual((first["status"], first["status_before_superseded"], first["superseded_by"]),
                         ("superseded", "in_force", "C-2"))
        self.assertEqual((second["status"], second["supersedes"], second["superseded_by"]),
                         ("superseded", "C-1", "C-3"))
        self.assertEqual((third["status"], third["supersedes"]), ("in_force", "C-2"))
        self.json_cli("verify")
        before = self.db.read_bytes()
        self.assertEqual(classic(self.load_json(batch)), counts(0, 0, 3, 3, 3))
        self.assertEqual(self.db.read_bytes(), before)


class LoadRefusalTest(LoadCase):
    def test_bad_line_in_the_middle(self):
        self.add()
        invalid = record("D-32")
        del invalid["question"]["text"]
        batch = [add_op(record("D-30")), add_op(record("D-31")), add_op(invalid),
                 add_op(record("D-33")), add_op(record("D-34"))]
        before = self.db.read_bytes()
        result = self.load(batch, code=2)
        self.assertIn("line 3", result.stderr)
        self.assertIn("question.text", result.stderr)
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(self.json_cli("stats")["records"], 1)
        self.cli("get", "D-30", code=2)

    def test_malformed_lines_name_their_line(self):
        self.add()
        good = json.dumps(add_op(record("D-30")))
        other = record("D-31")
        cases = (
            ("not json", "{not json", "invalid JSON"),
            ("blank", "", "empty line"),
            ("array", "[]", "object"),
            ("number", "7", "object"),
            ("unknown op", json.dumps({"op": "upsert", "record": other}), "op"),
            ("no op", json.dumps({"record": other}), "op"),
            ("no record", json.dumps({"op": "add"}), "record"),
            ("extra key", json.dumps({"op": "add", "record": other, "note": "x"}), "note"),
            ("target on add", json.dumps({"op": "add", "target": "D-22", "record": other}), "target"),
            ("no target", json.dumps({"op": "supersede", "record": other}), "target"),
            ("target not text", json.dumps({"op": "supersede", "target": 7, "record": other}), "target"),
            ("unknown target", json.dumps(supersede_op("D-99", other)), "D-99"),
            ("same id", json.dumps(supersede_op("D-22", record("D-22"))), "new id"),
            ("linked add", json.dumps(add_op(dict(other, supersedes="D-22"))), "supersedes"),
            ("duplicate key", '{"op":"add","op":"add","record":{}}', "duplicate"),
            ("record not object", json.dumps({"op": "add", "record": []}), "record"),
            ("bad record field", json.dumps(add_op(dict(other, kind="unknown"))), "kind"),
            ("unknown record key", json.dumps(add_op(dict(other, typo="x"))), "typo"),
            ("invalid utf-8", b"\xff\xfe{}", "UTF-8"),
        )
        for name, line, expected in cases:
            with self.subTest(case=name):
                path = self.raw_batch([good, line])
                self.assert_refused(path, "line 2", expected)
        self.assertEqual(self.json_cli("stats")["records"], 1)

    def test_empty_and_missing_batches(self):
        self.add()
        empty = self.directory / "empty.jsonl"
        empty.write_bytes(b"")
        self.assert_refused(empty, "empty")
        blank = self.directory / "blank.jsonl"
        blank.write_bytes(b"\n")
        self.assert_refused(blank, "line 1")
        self.cli("load", "--in", self.directory / "absent.jsonl", code=2)

    def test_conflicting_id_refuses_the_batch(self):
        self.add()
        changed = record("D-22")
        changed["question"]["text"] = "A different question"
        before = self.db.read_bytes()
        result = self.load([add_op(record("D-40")), add_op(changed)], code=2)
        self.assertIn("D-22", result.stderr)
        self.assertIn("line 2", result.stderr)
        self.assertEqual(self.db.read_bytes(), before)
        self.cli("get", "D-40", code=2)

    def test_answer_bytes_are_part_of_identity(self):
        self.add()
        variants = {
            "trailing space": VERBATIM + " ",
            "lf for crlf": VERBATIM.replace("\r\n", "\n"),
            "composed accent": VERBATIM.replace("é", "é"),
            "stripped": VERBATIM.strip(),
            "case": VERBATIM.replace("keep", "Keep"),
        }
        for name, text in variants.items():
            with self.subTest(change=name):
                changed = record("D-22")
                changed["answer"]["verbatim"] = text
                path = self.write_batch([add_op(changed)])
                self.assert_refused(path, "D-22", "answer.verbatim")
        self.assertEqual(self.json_cli("get", "D-22")["answer"]["verbatim"], VERBATIM)

    def test_any_other_difference_conflicts(self):
        self.add()
        changes = {
            "asked_at": lambda value: value.update(asked_at="2026-10-08T08:00:00+08:00"),
            "project": lambda value: value.update(project="phase-z"),
            "status": lambda value: value.update(status="withdrawn"),
            "topics": lambda value: value.update(topics=["other"]),
            "question": lambda value: value["question"].update(text="Changed"),
            "scope": lambda value: value["scope"].update(reversible=False),
            "provenance": lambda value: value["provenance"].update(recorded_by="someone"),
            "language": lambda value: value["answer"].update(language="en"),
        }
        for name, change in changes.items():
            with self.subTest(field=name):
                value = record("D-22")
                change(value)
                self.assert_refused(self.write_batch([add_op(value)]), "D-22")

    def test_supersede_conflicts(self):
        self.add()
        self.json_cli("supersede", "D-22", "--file", self.file("new.json", record("D-23")))
        before = self.db.read_bytes()
        again = self.write_batch([add_op(record("D-40")), supersede_op("D-22", record("D-24"))])
        self.assert_refused(again, "D-22", "line 2")
        changed = record("D-23")
        changed["question"]["text"] = "A different question"
        self.assert_refused(self.write_batch([supersede_op("D-22", changed)]), "D-23")
        unlinked = self.write_batch([add_op(record("D-50")), supersede_op("D-50", record("D-23"))])
        self.assert_refused(unlinked, "D-23")
        self.assertEqual(self.db.read_bytes(), before)

    def test_dry_run_reports_conflicts(self):
        self.add()
        changed = record("D-22")
        changed["project"] = "phase-z"
        self.assert_refused(self.write_batch([add_op(changed)]), "D-22", arguments=("--dry-run",))


class LoadSupersedeTest(LoadCase):
    def test_same_history_as_the_command(self):
        for status in ("in_force", "fulfilled", "withdrawn"):
            with self.subTest(status=status):
                by_command = self.directory / (status + "-command.sqlite")
                by_load = self.directory / (status + "-load.sqlite")
                for path in (by_command, by_load):
                    self.json_cli("init", db=path)
                    self.json_cli("add", "--file", self.file("old.json", record("O-1", status=status)), db=path)
                self.json_cli("supersede", "O-1", "--file", self.file("new.json", record("N-1")), db=by_command)
                batch = self.write_batch([supersede_op("O-1", record("N-1"))])
                result = json.loads(self.cli("load", "--in", batch, db=by_load).stdout)
                self.assertEqual(classic(result), counts(0, 1, 0, 1, 2))
                old = self.json_cli("get", "O-1", db=by_load)
                self.assertEqual((old["status"], old["status_before_superseded"], old["superseded_by"]),
                                 ("superseded", status, "N-1"))
                self.assertEqual(self.json_cli("get", "N-1", db=by_load)["supersedes"], "O-1")
                for identifier in ("O-1", "N-1"):
                    self.assertEqual(self.json_cli("get", identifier, db=by_command),
                                     self.json_cli("get", identifier, db=by_load))
                self.assertEqual(self.dump(db=by_command), self.dump(db=by_load))
                self.json_cli("verify", db=by_load)

    def test_annotation_after_loading(self):
        batch = [add_op(record("D-30"))]
        self.load_json(batch)
        self.json_cli("annotate", "D-30", "--file", self.file("outcome.json", {"evidence": ["checks/new.txt"]}))
        self.assertEqual(classic(self.load_json(batch)), counts(0, 0, 1, 1, 1))
        claimed = record("D-30")
        claimed["outcome"]["evidence"] = ["notes/request-7.txt", "claims/other.txt"]
        self.assert_refused(self.write_batch([add_op(claimed)]), "D-30")

    def test_defaults_do_not_matter(self):
        self.add(plain_record("P-1"))
        spelled = plain_record("P-1")
        spelled["schema_version"] = 1
        spelled["outcome"] = {}
        spelled["answer"]["message_id"] = None
        reordered = dict(reversed(list(spelled.items())))
        self.assertEqual(classic(self.load_json([add_op(spelled), add_op(reordered)])), counts(0, 0, 2, 1, 1))


class LoadDryRunTest(LoadCase):
    def test_dry_run_writes_nothing(self):
        self.add()
        batch = [add_op(record("D-30")), supersede_op("D-22", record("D-31"))]
        path = self.write_batch(batch)
        before = self.db.read_bytes()
        stamp = self.db.stat().st_mtime_ns
        dry = json.loads(self.cli("load", "--in", path, "--dry-run").stdout)
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(self.db.stat().st_mtime_ns, stamp)
        self.assertEqual(sorted(os.listdir(str(self.directory))), ["batch.jsonl", "decisions.sqlite", "record.json"])
        self.assertIs(dry["dry_run"], True)
        self.assertEqual({key: dry[key] for key in COUNT_KEYS}, counts(1, 1, 0, 1, 3))
        real = json.loads(self.cli("load", "--in", path).stdout)
        self.assertEqual(dry, dict(real, dry_run=True))
        again = json.loads(self.cli("load", "--in", path, "--dry-run").stdout)
        self.assertEqual({key: again[key] for key in COUNT_KEYS}, counts(0, 0, 2, 3, 3))

    def test_dry_run_on_a_read_only_file(self):
        self.add()
        path = self.write_batch([add_op(record("D-30"))])
        os.chmod(str(self.db), 0o400)
        try:
            result = json.loads(self.cli("load", "--in", path, "--dry-run").stdout)
        finally:
            os.chmod(str(self.db), 0o600)
        self.assertEqual(result["added"], 1)
        self.assertEqual(self.json_cli("stats")["records"], 1)


class LoadEmbeddingTest(LoadCase):
    def test_load_never_embeds(self):
        self.add()
        config = self.config()
        self.json_cli("embed", "--config", config)
        receipts = self.json_cli("egress", "--list")
        self.load_json([add_op(record("D-30"))])
        stats = self.json_cli("stats")
        self.assertEqual((stats["records"], stats["vectors"], stats["records_without_vectors"]), (2, 2, 1))
        self.assertEqual(self.json_cli("egress", "--list"), receipts)
        self.json_cli("verify")
        filled = self.json_cli("embed", "--config", config)
        self.assertEqual((filled["embedded"], filled["skipped"]), (2, 2))
        stats = self.json_cli("stats")
        self.assertEqual((stats["vectors"], stats["records_without_vectors"]), (4, 0))
        self.json_cli("verify")
        self.assertEqual(len(self.json_cli("egress", "--list")), 4)

    def test_vectorless_count_without_embed(self):
        self.assertEqual(self.json_cli("stats")["records_without_vectors"], 0)
        self.load_json([add_op(record("D-30")), add_op(record("D-31"))])
        self.assertEqual(self.json_cli("stats")["records_without_vectors"], 2)


class LoadBytesTest(LoadCase):
    def test_answer_bytes_come_back_exact(self):
        answers = (
            " \t keep\r\nline two\r\n  é  \n ",
            "before\x00after \U0001f642 \n",
            " \r\n\t x \r\n",
            "é and é side by side",
        )
        variants = (("\n", False), ("\n", True), ("\r\n", False))
        number = 0
        for text in answers:
            for newline, ascii_only in variants:
                number += 1
                identifier = "B-{}".format(number)
                with self.subTest(answer=text, newline=newline, ascii_only=ascii_only):
                    batch = [add_op(plain_record(identifier, "Question text", text))]
                    self.load_json(batch, newline=newline, ascii_only=ascii_only)
                    answer = self.json_cli("get", identifier)["answer"]
                    self.assertEqual(answer["verbatim"].encode("utf-8"), text.encode("utf-8"))
                    self.assertEqual(answer["sha256"], digest(text))
                    stored = self.execute("SELECT verbatim FROM records WHERE id = ?", (identifier,))
                    self.assertEqual(stored[0][0], text.encode("utf-8"))
        self.json_cli("verify")


class LoadBusyTest(LoadCase):
    def test_busy_store_is_reported(self):
        self.add()
        path = self.write_batch([add_op(record("D-30"))])
        marker = self.directory / "started"
        with closing(sqlite3.connect(str(self.db), timeout=1, isolation_level=None)) as holder:
            holder.execute("BEGIN IMMEDIATE")
            process = self.start_marked(marker, 0, "load", "--in", path)
            started = self.wait_for(marker)
            stdout, stderr = process.communicate(timeout=90)
            elapsed = time.monotonic() - started
            holder.execute("ROLLBACK")
        self.assertGreaterEqual(elapsed, 9.5)
        self.assertEqual(process.returncode, 5, stderr)
        self.assertIn("database busy", stderr)
        self.assertIn("nothing was changed", stderr)
        self.assertEqual(self.json_cli("stats")["records"], 1)
