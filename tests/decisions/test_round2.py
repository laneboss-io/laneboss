"""Black-box tests for the second review round: error mapping, lock handling, proofs and ranking."""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import closing

from .support import ROOT, VERBATIM, StoreCase, entry_hash, ids, plain_record, record


class ErrorMappingTest(StoreCase):
    def test_missing_egress_column(self):
        self.add()
        self.json_cli("embed", "--config", self.config())
        self.downgrade_egress()
        for command, arguments in (("verify", ()), ("export", ("--out", self.directory / "out.jsonl"))):
            with self.subTest(command=command):
                result = self.cli(command, *arguments, code=3)
                self.assertIn("egress_log", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
        self.assertFalse((self.directory / "out.jsonl").exists())


class BusyTest(StoreCase):
    def test_lock_timeout_is_busy(self):
        self.add()
        with closing(sqlite3.connect(str(self.db), timeout=1, isolation_level=None)) as holder:
            holder.execute("BEGIN IMMEDIATE")
            commands = (("verify",), ("add", "--file", self.file("second.json", record("D-23"))))
            processes, started = [], []
            for position, command in enumerate(commands):
                marker = self.directory / "started-{}".format(position)
                processes.append(self.start_marked(marker, 0, *command))
                started.append(self.wait_for(marker))
            results = [process.communicate(timeout=90) for process in processes]
            finished = time.monotonic()
            self.cli("stats")
            holder.execute("ROLLBACK")
        for process, began, (stdout, stderr) in zip(processes, started, results):
            self.assertGreaterEqual(finished - began, 9.5, "the command did not wait for the lock")
            self.assertEqual(process.returncode, 5, stderr)
            self.assertIn("database busy", stderr)
            self.assertIn("nothing was changed", stderr)
            self.assertNotIn("integrity problem", stderr)
        self.json_cli("verify")
        self.assertEqual(self.json_cli("stats")["records"], 1)


class ConcurrentWriterTest(StoreCase):
    # The writer holds the lock from before the command starts until HOLD seconds after the command has
    # signalled that it is running; START_DELAY stands for a slow start, which must not weaken the proof.
    HOLD = 2.0
    START_DELAY = 1.5

    def test_verify_waits_for_writer(self):
        stdout = self.run_beside_writer("verify")
        self.assertEqual(json.loads(stdout)["records"], 2)
        self.json_cli("verify")

    def test_export_waits_for_writer(self):
        target = self.directory / "waited.jsonl"
        stdout = self.run_beside_writer("export", "--out", target)
        self.assertEqual(json.loads(stdout)["exported"], 2)
        self.assertEqual(len(target.read_text(encoding="utf-8").splitlines()), 3)

    def run_beside_writer(self, command, *arguments):
        """Run the command while another connection is inside BEGIN IMMEDIATE; return its stdout."""
        self.add()
        donor = self.directory / "donor.sqlite"
        self.json_cli("init", db=donor)
        self.json_cli("add", "--file", self.file("other.json", record("D-77")), db=donor)
        with closing(sqlite3.connect(str(donor))) as source:
            cursor = source.execute("SELECT * FROM records WHERE id = 'D-77'")
            names = [column[0] for column in cursor.description]
            row = dict(zip(names, cursor.fetchone()))
            index = source.execute("SELECT id, q_text, d_text FROM keyword_index WHERE rowid = ?",
                                   (row["row_id"],)).fetchone()
        columns = [name for name in names if name != "row_id"]
        marker = self.directory / "started"
        with closing(sqlite3.connect(str(self.db), timeout=10, isolation_level=None)) as writer:
            writer.execute("BEGIN IMMEDIATE")
            inserted = writer.execute(
                "INSERT INTO records ({}) VALUES ({})".format(",".join(columns), ",".join("?" for name in columns)),
                [row[name] for name in columns])
            writer.execute("INSERT INTO keyword_index(rowid, id, q_text, d_text) VALUES (?, ?, ?, ?)",
                           (inserted.lastrowid,) + tuple(index))
            process = self.start_marked(marker, self.START_DELAY, command, *arguments)
            self.wait_for(marker)
            time.sleep(self.HOLD)
            early = process.poll()
            writer.execute("COMMIT")
            stdout, stderr = process.communicate(timeout=60)
        self.assertIsNone(early, "the command ended while the writer still held the lock: {}".format(stderr))
        self.assertEqual(process.returncode, 0, stderr)
        return stdout


class LibraryTest(unittest.TestCase):
    def test_verify_then_add_is_clean(self):
        source = str(ROOT / "src")
        sys.path.insert(0, source)
        self.addCleanup(sys.path.remove, source)
        from laneboss.decisions.store import Store
        with tempfile.TemporaryDirectory() as directory:
            store = Store(os.path.join(directory, "library.sqlite"), initialize=True)
            try:
                store.add(record("L-1"))
                self.assertFalse(store.connection.in_transaction)
                self.assertTrue(store.verify()["ok"])
                self.assertFalse(store.connection.in_transaction)
                store.add(record("L-2"))
                self.assertFalse(store.connection.in_transaction)
                self.assertTrue(store.verify()["ok"])
                self.assertEqual(store.stats()["records"], 2)
                self.assertFalse(store.connection.in_transaction)
            finally:
                store.close()


class EgressChainTest(StoreCase):
    def setUp(self):
        super().setUp()
        self.add()
        self.add(record("D-23"))
        config = self.config()
        self.json_cli("embed", "--config", config)
        for number in range(3):
            self.hits("query {}".format(number), "vector", config=config)
        kinds = [entry["which_text"] for entry in self.json_cli("egress", "--list")]
        self.assertEqual(kinds, ["q_text", "d_text", "q_text", "d_text", "query", "query", "query"])
        self.json_cli("verify")

    def refused(self):
        result = self.cli("verify", code=3)
        self.assertIn("egress", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def relink(self, position):
        with closing(sqlite3.connect(str(self.db))) as connection:
            connection.row_factory = sqlite3.Row
            value = dict(connection.execute("SELECT * FROM egress_log WHERE id = ?", (position,)).fetchone())
        value["previous_entry_sha256"] = "f" * 64
        value["entry_sha256"] = entry_hash(value)
        self.tamper(("UPDATE egress_log SET previous_entry_sha256 = ?, entry_sha256 = ? WHERE id = ?",
                     (value["previous_entry_sha256"], value["entry_sha256"], position)))

    def test_deleted_middle_query_receipt(self):
        self.tamper("DELETE FROM egress_log WHERE id = 6")
        self.refused()

    def test_swapped_entry_ids(self):
        self.tamper("UPDATE egress_log SET id = 100 WHERE id = 5",
                    "UPDATE egress_log SET id = 5 WHERE id = 6",
                    "UPDATE egress_log SET id = 6 WHERE id = 100")
        self.refused()

    def test_relinked_first_entry(self):
        self.relink(1)
        self.refused()

    def test_relinked_middle_entry(self):
        self.relink(6)
        self.refused()


class SupersessionTest(StoreCase):
    def test_missing_chain_target(self):
        self.add(record("A-1"))
        self.add(record("B-1"))

        def link_first(value):
            value["supersedes"] = "B-1"

        def link_second(value):
            value["superseded_by"] = "A-1"
            value["status_before_superseded"] = "in_force"
            value["status"] = "superseded"
            value["supersedes"] = "GONE-0"

        self.rewrite("A-1", link_first)
        self.rewrite("B-1", link_second)
        result = self.cli("verify", code=3)
        self.assertIn("supersession target is missing", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_prior_status_is_kept(self):
        for position, status in enumerate(("withdrawn", "fulfilled")):
            old_id, new_id = "P-{}".format(position), "N-{}".format(position)
            self.add(record(old_id, status=status))
            self.json_cli("supersede", old_id, "--file", self.file("new.json", record(new_id)))
            old = self.json_cli("get", old_id)
            self.assertEqual(old["status"], "superseded")
            self.assertEqual(old["status_before_superseded"], status)
            self.assertEqual(old["superseded_by"], new_id)
            self.assertEqual(old["answer"]["verbatim"], VERBATIM)
            self.assertEqual(self.json_cli("get", new_id)["supersedes"], old_id)
        self.json_cli("verify")


class KeywordTermsTest(StoreCase):
    def test_id_term_and_decision_term(self):
        self.add(plain_record("K-4471", "Which window applies", "Use the lanternfish window"))
        self.add(plain_record("K-1000", "Notes about 4471 only", "Nothing here"))
        self.add(plain_record("K-2000", "Another topic", "The lanternfish note"))
        for query in ("4471 lanternfish", "lanternfish 4471"):
            with self.subTest(query=query):
                hits = self.hits(query)
                self.assertEqual(ids(hits), ["K-4471"])
                self.assertEqual({match["field"] for match in hits[0]["matches"]}, {"id", "d_text"})

    def fill_marker_store(self):
        self.add(plain_record("S-1", "The zq marker", "Use marmalade"))
        self.add(plain_record("S-2", "The zq marker only", "Nothing"))
        self.add(plain_record("S-3", "A different marker", "Use marmalade too"))

    def test_short_term_with_long_term(self):
        self.fill_marker_store()
        for query in ("zq marmalade", "marmalade zq", "ZQ Marmalade"):
            with self.subTest(query=query):
                self.assertEqual(ids(self.hits(query)), ["S-1"])
        self.assertEqual(sorted(ids(self.hits("zq"))), ["S-1", "S-2"])
        self.assertEqual(sorted(ids(self.hits("marmalade"))), ["S-1", "S-3"])

    def test_repeated_term_matches(self):
        self.fill_marker_store()
        for term in ("marmalade", "zq"):
            single = self.hits(term)
            for query in (term + " " + term, " ".join([term] * 3), term.upper() + " " + term):
                with self.subTest(query=query):
                    repeated = self.hits(query)
                    self.assertEqual(ids(repeated), ids(single))
                    for hit in repeated:
                        keys = [json.dumps(match, sort_keys=True) for match in hit["matches"]]
                        self.assertEqual(len(keys), len(set(keys)), keys)
                    self.assertEqual([hit["matches"] for hit in repeated], [hit["matches"] for hit in single])


ACCEPTED_TIMES = ("2026-10-08T09:00:00Z", "2026-10-08T09:00:00.123Z", "2026-10-08T09:00:00.123456+08:00",
                  "2026-10-08T09:00:00-05:30", "2026-10-08T09:00:00.123-05:30")
REFUSED_TIMES = ("2026-10-08T09:00:00.1Z", "2026-10-08T09:00:00.12Z", "2026-10-08T09:00:00.1234Z",
                 "2026-10-08T09:00:00.1234567Z", "2026-10-08T09:00:00+0800", "2026-10-08T09:00:00+08",
                 "2026-10-08T09:00:00", "2026-10-08 09:00:00Z")
TIME_FIELDS = (
    ("asked_at", ("asked_at",)),
    ("answered_at", ("answered_at",)),
    ("provenance.recorded_at", ("provenance", "recorded_at")),
    ("scope.valid_until", ("scope", "valid_until")),
    ("outcome.actions.at", ("outcome", "actions", 0, "at")),
)


class TimestampTableTest(StoreCase):
    def stamped(self, identifier, path, text):
        value = record(identifier)
        value["outcome"]["actions"] = [{"at": "2026-10-08T09:10:00Z", "text": "Checked"}]
        target = value
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = text
        return value

    def test_accepted_forms(self):
        count = 0
        for label, path in TIME_FIELDS:
            for text in ACCEPTED_TIMES:
                count += 1
                with self.subTest(field=label, text=text):
                    value = self.stamped("T-{}".format(count), path, text)
                    self.json_cli("add", "--file", self.file("ok.json", value))
        self.assertEqual(self.json_cli("stats")["records"], count)

    def test_refused_forms(self):
        for label, path in TIME_FIELDS:
            for text in REFUSED_TIMES:
                with self.subTest(field=label, text=text):
                    value = self.stamped("T-1", path, text)
                    result = self.cli("add", "--file", self.file("bad.json", value), code=2)
                    self.assertIn(label, result.stderr)
        self.assertEqual(self.json_cli("stats")["records"], 0)

    def test_annotation_time_forms(self):
        self.add()
        for text in ACCEPTED_TIMES:
            with self.subTest(text=text):
                body = {"actions": [{"at": text, "text": "Checked"}]}
                self.json_cli("annotate", "D-22", "--file", self.file("ok.json", body))
        for text in REFUSED_TIMES:
            with self.subTest(text=text):
                body = {"actions": [{"at": text, "text": "Checked"}]}
                result = self.cli("annotate", "D-22", "--file", self.file("bad.json", body), code=2)
                self.assertIn("outcome.actions.at", result.stderr)
        self.assertEqual(len(self.json_cli("get", "D-22")["outcome"]["actions"]), len(ACCEPTED_TIMES))

    def test_search_bound_forms(self):
        self.add()
        for option in ("--date-from", "--date-to"):
            for text in ACCEPTED_TIMES + ("2026-10-08",):
                with self.subTest(option=option, text=text):
                    self.json_cli("search", "", "--mode", "exact", option, text)
            for text in REFUSED_TIMES + ("2026-13-45",):
                with self.subTest(option=option, text=text):
                    self.cli("search", "", "--mode", "exact", option, text, code=2)


UNKNOWN_KEY_PLACES = (
    ("record", ()),
    ("question", ("question",)),
    ("question.options", ("question", "options", 0)),
    ("answer", ("answer",)),
    ("scope", ("scope",)),
    ("outcome", ("outcome",)),
    ("outcome.actions", ("outcome", "actions", 0)),
    ("provenance", ("provenance",)),
    ("provenance.sources", ("provenance", "sources", 0)),
)


class UnknownKeyTableTest(StoreCase):
    def test_every_object_refuses_extra_keys(self):
        for label, path in UNKNOWN_KEY_PLACES:
            with self.subTest(place=label):
                value = record()
                value["outcome"]["actions"] = [{"at": "2026-10-08T09:10:00Z", "text": "Checked"}]
                target = value
                for part in path:
                    target = target[part]
                target["typo"] = "x"
                result = self.cli("add", "--file", self.file("typo.json", value), code=2)
                self.assertEqual(result.stderr, "invalid input: unknown field: {}.typo\n".format(label))
        self.assertEqual(self.json_cli("stats")["records"], 0)

    def test_annotation_refuses_extra_keys(self):
        self.add()
        action = {"at": "2026-10-08T09:10:00Z", "text": "Checked", "typo": "x"}
        for label, body in (("outcome", {"typo": ["x"]}), ("outcome.actions", {"actions": [action]})):
            with self.subTest(place=label):
                result = self.cli("annotate", "D-22", "--file", self.file("typo.json", body), code=2)
                self.assertEqual(result.stderr, "invalid input: unknown field: {}.typo\n".format(label))


class ScannerCheckoutTest(StoreCase):
    def test_scan_passes_after_bytecode_run(self):
        checkout = self.directory / "checkout"
        shutil.copytree(ROOT, checkout, ignore=shutil.ignore_patterns(
            ".git", "__pycache__", "*.pyc", "*.sqlite"))
        for arguments in (("init", "-q"), ("add", "-A")):
            result = subprocess.run(["git", *arguments], cwd=str(checkout), capture_output=True, text=True,
                                    timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
        environment = dict(self.environment)
        environment.pop("PYTHONDONTWRITEBYTECODE", None)
        environment.pop("PYTHONPYCACHEPREFIX", None)
        environment["PYTHONPATH"] = str(checkout / "src")
        # Some system interpreters keep bytecode in a per-user cache instead of beside the sources;
        # clearing the prefix makes this run leave __pycache__ directories inside the checkout.
        program = ("import runpy, sys; sys.pycache_prefix = None; database = sys.argv[1]; "
                   "sys.argv = ['laneboss.decisions', 'init', '--db', database]; "
                   "runpy.run_module('laneboss.decisions', run_name='__main__')")
        run = subprocess.run(
            [sys.executable, "-c", program, str(self.directory / "scan.sqlite")],
            cwd=str(checkout), env=environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(list(checkout.rglob("*.pyc")), "the run must leave bytecode inside the checkout")
        scan = subprocess.run(["sh", str(checkout / "scripts" / "scan.sh"), str(checkout)],
                              capture_output=True, text=True, timeout=120)
        self.assertEqual(scan.returncode, 0, scan.stdout)


def ranking_corpus():
    """About a hundred short records. Only the records with all of "ui", "rollout" and "freeze" can match
    the query "ui rollout freeze": the target Z-100, five longer notes E-01..E-05 that mention "ui" once,
    and six long notes D-12..D-17 that repeat "ui" 12 to 17 times."""
    tail = " window with meeting notes archived with older release material"
    records = [plain_record("Z-100", "Plan the ui ui rollout freeze window", "Agreed")]
    for number in range(1, 6):
        records.append(plain_record("E-{:02d}".format(number), "Plan the ui rollout freeze" + tail, "Agreed"))
    for count in range(12, 18):
        question = "Plan the " + " ".join(["ui"] * count) + " rollout freeze" + tail
        records.append(plain_record("D-{}".format(count), question, "Agreed"))
    for number in range(1, 21):
        records.append(plain_record("R-{:03d}".format(number),
                                    "Review the rollout checklist item {}".format(number), "Agreed"))
        records.append(plain_record("W-{:03d}".format(number),
                                    "Confirm the freeze calendar entry {}".format(number), "Agreed"))
        records.append(plain_record("U-{:03d}".format(number),
                                    "Update the guide for screen {}".format(number), "Agreed"))
    for number in range(1, 29):
        records.append(plain_record("N-{:03d}".format(number),
                                    "Discuss the budget topic {}".format(number), "Agreed"))
    return records


class RankingTest(StoreCase):
    def setUp(self):
        super().setUp()
        self.json_cli("import", "--in", self.write_import(ranking_corpus()))
        self.assertEqual(self.json_cli("stats")["records"], 100)

    def test_multi_term_target_leads(self):
        found = ids(self.hits("ui rollout freeze", limit="50"))
        self.assertEqual(len(found), 12, found)
        position = found.index("Z-100") + 1 if "Z-100" in found else None
        self.assertEqual(found[0], "Z-100", "target is at position {}: {}".format(position, found))
        expected = ["Z-100"] + ["E-0{}".format(number) for number in range(1, 6)] \
            + ["D-{}".format(count) for count in range(12, 18)]
        self.assertEqual(found, expected)

    def test_scores_never_increase(self):
        for query in ("rollout", "freeze", "ui", "ui rollout", "rollout freeze", "ui rollout freeze"):
            with self.subTest(query=query):
                scores = [hit["score"] for hit in self.hits(query, limit="100")]
                self.assertTrue(scores)
                self.assertEqual(scores, sorted(scores, reverse=True))

    def test_every_term_leaves_evidence(self):
        hits = self.hits("ui rollout freeze", limit="50")
        target = [hit for hit in hits if hit["record"]["id"] == "Z-100"][0]
        self.assertEqual(sorted(match["index"] for match in target["matches"]),
                         ["keyword:fts5", "keyword:fts5", "keyword:substring"])
        self.assertEqual({match["field"] for match in target["matches"]}, {"q_text"})
        self.assertEqual(target["matched_text"], "question")
