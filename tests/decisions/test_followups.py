"""Black-box tests for the follow-ups the decision store was accepted with: what the storage-problem message (exit 7)
says on each path, the layout check that import makes under its own write lock, and the store a killed load leaves."""

import json
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import time
from contextlib import closing

from .support import StoreCase, plain_record, record, stub_server


def add_op(value):
    return {"op": "add", "record": value}


def supersede_op(target, value):
    return {"op": "supersede", "target": target, "record": value}


class StorageProblemTest(StoreCase):
    """Exit 7 says what SQLite was doing and what exists or is stored afterwards, and nothing that is not true."""

    def test_read_failure_says_reading(self):
        self.add()
        batch = self.write_batch([add_op(record("D-30"))])
        exported = self.directory / "out.jsonl"
        commands = (
            ("get", ("D-22",)),
            ("stats", ()),
            ("search", ("deployment",)),
            ("search", ("", "--mode", "exact")),
            ("egress", ("--list",)),
            ("load", ("--in", batch, "--dry-run")),
            ("verify", ()),
            ("export", ("--out", exported)),
        )
        before = self.db.read_bytes()
        for command, arguments in commands:
            with self.subTest(command=command, arguments=[str(item) for item in arguments]):
                # The first statement the command runs fails with the error SQLite reports when the operating
                # system refuses a read, "disk I/O error" (see faults.py for why the failure is raised here).
                result = self.cli_hooked("io-error", command, *arguments, code=7)
                self.assertIn("storage problem", result.stderr)
                self.assertIn("while it read the database file", result.stderr)
                self.assertIn("only reads", result.stderr)
                self.assertIn("nothing was changed", result.stderr)
                for claim in ("could not write", "rolls", "rolled back"):
                    self.assertNotIn(claim, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(self.db.read_bytes(), before)
                self.assertFalse(exported.exists())
        self.json_cli("verify")

    def test_limited_init_names_its_file(self):
        for limit in (100, 8192):
            with self.subTest(limit=limit):
                fresh = self.directory / "fresh-{}.sqlite".format(limit)
                result = self.cli_limited(limit, "init", db=fresh, code=7)
                self.assertIn("storage problem", result.stderr)
                self.assertIn("created the database file " + str(fresh), result.stderr)
                self.assertIn("holds no store", result.stderr)
                self.assertNotIn("nothing was changed", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                # What the message says is what is there: the new file, empty, and no journal.
                self.assertTrue(fresh.is_file())
                self.assertEqual(fresh.stat().st_size, 0)
                self.assertFalse(Path(str(fresh) + "-journal").exists())
                self.assertEqual(self.json_cli("init", db=fresh), {"ok": True, "schema_version": 4})
                self.json_cli("verify", db=fresh)

    def test_limited_init_of_an_empty_file(self):
        existing = self.directory / "existing.sqlite"
        existing.write_bytes(b"")
        result = self.cli_limited(8192, "init", db=existing, code=7)
        self.assertIn("storage problem", result.stderr)
        self.assertIn("nothing was changed", result.stderr)
        self.assertNotIn("created", result.stderr)
        self.assertEqual(existing.stat().st_size, 0)
        self.assertEqual(self.json_cli("init", db=existing), {"ok": True, "schema_version": 4})

    def test_embed_names_stored_batches(self):
        for number in range(30, 34):
            self.add(record("D-{}".format(number)))
        scratch = self.directory / "scratch.sqlite"
        shutil.copyfile(str(self.db), str(scratch))
        start = self.db.stat().st_size
        environment = dict(self.environment, TEST_EMBED_KEY="invented-test-value")
        with stub_server() as (endpoint, requests):
            config = self.file("http.json", {"provider": "voyage", "endpoint": endpoint, "dimension": 256,
                                             "api_key_env": "TEST_EMBED_KEY", "batch_size": 1})
            # Embedding a copy to its end shows how large the file gets; the limit below stops the real run in
            # the middle, in some later batch, after earlier batches were committed.
            self.cli("embed", "--config", config, db=scratch, environment=environment)
            texts = len(requests)
            self.assertEqual(texts, 8)
            complete = scratch.stat().st_size
            del requests[:]
            result = self.cli_limited(start + (complete - start) // 2, "embed", "--config", config, code=7,
                                      environment=environment)
            sent = sum(len(request["body"]["input"]) for request in requests)
        stats = self.json_cli("stats")
        self.assertTrue(0 < stats["vectors"] < texts, "the limit did not stop embed between batches: {}".format(stats))
        message = result.stderr
        self.assertIn("storage problem", message)
        self.assertNotIn("nothing was changed", message)
        self.assertIn("the model row for voyage-4-large", message)
        # Every number in the message is the number of the same thing as the store and the provider saw it.
        self.assertEqual(int(re.search(r"(\d+) egress receipts?", message).group(1)), stats["egress_entries"])
        self.assertEqual(int(re.search(r"stored .*?(\d+) vectors?", message).group(1)), stats["vectors"])
        self.assertEqual(int(re.search(r"had sent (\d+) texts?", message).group(1)), sent)
        unstored = re.search(r"the vectors for (\d+) texts? were not stored", message)
        if sent > stats["vectors"]:
            self.assertEqual(int(unstored.group(1)), sent - stats["vectors"])
        else:
            self.assertIsNone(unstored)
        self.assertIn("Run embed again", message)
        self.json_cli("verify")
        with stub_server() as (endpoint, requests):
            config = self.file("http.json", {"provider": "voyage", "endpoint": endpoint, "dimension": 256,
                                             "api_key_env": "TEST_EMBED_KEY", "batch_size": 1})
            finished = self.json_cli("embed", "--config", config, environment=environment)
        self.assertEqual(finished["embedded"], texts - stats["vectors"])
        self.assertEqual(self.json_cli("stats")["vectors"], texts)
        self.json_cli("verify")


class ImportLayoutLockTest(StoreCase):
    """import checks the destination's layout under its own write lock."""

    def test_layout_change_during_lock_wait(self):
        self.add(record("D-22"))
        self.add(record("D-23"))
        source = self.directory / "source.jsonl"
        self.json_cli("export", "--out", source)
        lines = source.read_text(encoding="utf-8").splitlines()
        manifest = json.loads(lines[0])
        manifest["counts"]["records"] += 5
        miscounted = self.directory / "miscounted.jsonl"
        miscounted.write_text("".join(line + "\n" for line in [json.dumps(manifest)] + lines[1:]), encoding="utf-8")
        # The miscounted file is refused for its data, but only after its records were inserted: a layout problem
        # reported instead shows that the layout was checked before the first insertion.
        for name, path in (("valid", source), ("miscounted", miscounted)):
            with self.subTest(export=name):
                destination = self.directory / (name + ".sqlite")
                self.json_cli("init", db=destination)
                empty = self.dump(db=destination)
                marker = self.directory / (name + ".marker")
                with closing(sqlite3.connect(str(destination), timeout=1, isolation_level=None)) as holder:
                    holder.execute("BEGIN IMMEDIATE")
                    importer = self.start_hooked("lock-wanted", marker, "import", "--in", path, db=destination)
                    # The marker appears when the import, which has read its file, is about to ask for the write
                    # lock this connection holds. Whatever the import checked before asking, it checked before the
                    # change below, which becomes visible to it only when the lock is free.
                    self.wait_for(marker, process=importer)
                    holder.execute("CREATE INDEX extra_lookup ON records(kind)")
                    holder.execute("COMMIT")
                stdout, stderr = importer.communicate(timeout=60)
                self.assertEqual(importer.returncode, 3, stderr)
                for text in ("integrity problem", "schema definition mismatch", "extra_lookup"):
                    self.assertIn(text, stderr)
                self.assertNotIn("invalid import", stderr)
                self.assertNotIn("Traceback", stderr)
                self.assertEqual(self.dump(db=destination), empty)


class KilledLoadTest(StoreCase):
    """A load that is killed while it writes leaves the store as it was; the same batch then loads."""

    RECORDS = 1000
    # Where in a complete load's time from the first sign of its rollback journal to its end each kill comes: right
    # at the start, while the batch is being written, and while the whole store is verified before the commit. (Whether
    # SQLite has changed the database file itself by then depends on the page cache of its build; the journal always
    # exists.)
    MOMENTS = (0.0, 0.08, 0.2, 0.35, 0.5, 0.62, 0.72, 0.8)

    def large_batch(self):
        words = " ".join("word{}".format(number) for number in range(300))
        operations = [supersede_op("D-22", plain_record("K-00000", "0 " + words, "Answer 0"))]
        operations.extend(add_op(plain_record("K-{:05d}".format(number), "{} {}".format(number, words),
                                              "Answer {}".format(number)))
                          for number in range(1, self.RECORDS))
        return self.write_batch(operations)

    def wait_for_journal(self, db, process):
        """The moment the rollback journal of db first exists: the load has started to write."""
        journal = Path(str(db) + "-journal")
        while not journal.exists():
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                self.fail("the load ended (exit {}) without writing a journal: {!r}".format(process.returncode, stderr))
            time.sleep(0.001)
        return time.monotonic()

    def journal_window(self, batch):
        """Seconds from the first sign of the journal to the end of a complete load of the batch on this machine,
        measured on a copy of the store."""
        scratch = self.directory / "scratch.sqlite"
        shutil.copyfile(str(self.db), str(scratch))
        process = self.start_cli("load", "--in", batch, db=scratch)
        began = self.wait_for_journal(scratch, process)
        stdout, stderr = process.communicate(timeout=120)
        ended = time.monotonic()
        self.assertEqual(process.returncode, 0, stderr)
        return ended - began

    def test_killed_load_leaves_a_sound_store(self):
        self.add(record("D-22"))
        self.add(record("D-23"))
        batch = self.large_batch()
        original = self.directory / "original.sqlite"
        shutil.copyfile(str(self.db), str(original))
        pristine = self.db.read_bytes()
        window = self.journal_window(batch)
        landed = 0
        for moment in self.MOMENTS:
            with self.subTest(moment=moment):
                process = self.start_cli("load", "--in", batch)
                began = self.wait_for_journal(self.db, process)
                time.sleep(max(0.0, began + moment * window - time.monotonic()))
                process.kill()
                stdout, stderr = process.communicate(timeout=60)
                if process.returncode != -signal.SIGKILL:
                    # It finished before the kill came: the batch is stored. Start again from the original store.
                    shutil.copyfile(str(original), str(self.db))
                    continue
                landed += 1
                # Reopening finishes what the dead process left (SQLite restores the file from its journal).
                self.json_cli("verify")
                self.assertEqual(self.json_cli("stats")["records"], 2)
                self.cli("get", "K-00001", code=2)
                self.assertEqual(self.json_cli("get", "D-22")["status"], "in_force")
                self.assertEqual(self.db.read_bytes(), pristine)
        self.assertGreaterEqual(landed, len(self.MOMENTS) - 2, "most kills must reach a load that is still writing")
        result = json.loads(self.cli("load", "--in", batch).stdout)
        self.assertEqual((result["added"], result["superseded"], result["unchanged"]),
                         (self.RECORDS - 1, 1, 0))
        self.json_cli("verify")
        self.assertEqual(self.json_cli("stats")["records"], 2 + self.RECORDS)
        self.assertEqual(self.json_cli("get", "D-22")["status"], "superseded")
        again = json.loads(self.cli("load", "--in", batch).stdout)
        self.assertEqual((again["added"], again["superseded"], again["unchanged"]), (0, 0, self.RECORDS))
