"""LB-109 part b: a lane's own records in the decision store, made and read through the real commands.

The launcher starts the lane, the stand-in writes its final message, and `laneboss decisions ingest-lane` reads
that lane through the launcher's own records. Everything is observed through the two installed command lines and
through SQLite: nothing here reads the product's internals.
"""

import json
import sqlite3

from . import lanesupport, support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class LaneIngestTest(lanesupport.LaneTest):
    def decisions(self, *arguments, code=0):
        return self.run_laneboss("decisions", *arguments, code=code, environment=self.env("alpha"))

    def decision_json(self, *arguments, code=0):
        return json.loads(self.decisions(*arguments, code=code).stdout)

    def fresh_store(self):
        path = self.directory / "decisions.sqlite"
        self.decisions("init", "--db", str(path))
        return path

    def finished(self, lane, runner="ok", script=None):
        """Start a lane whose run ends by itself, and wait for the end to be recorded."""
        if script is not None:
            (self.records["alpha"] / "{}.1.script".format(lane)).write_text(script, encoding="utf-8")
        self.start(lane, "--runner", runner, "--model", "ingest-model-1", "--effort", "high",
                   "--worktree", self.scratch(lane))
        self.wait_event("lane.ended", lane)
        return lane

    def ingest(self, db, lane, *attachments, code=0):
        arguments = ["ingest-lane", "--db", str(db), "--config", "alpha", "--lane", lane]
        for path in attachments:
            arguments += ["--attach", str(path)]
        result = self.decisions(*arguments, code=code)
        return json.loads(result.stdout) if code == 0 else result

    def test_ingest_a_finished_lane_twice(self):
        db = self.fresh_store()
        self.finished("i-ok")
        ledger = self.directory / "ledger.md"
        ledger.write_text("| lb-record | accepted |\n", encoding="utf-8")
        receipt = self.ingest(db, "i-ok", ledger)
        self.assertEqual(receipt["lane"], "i-ok")
        self.assertEqual(receipt["rows_added"], 3)
        self.assertEqual(receipt["rows_existing"], 0)
        self.assertEqual([row["id"].split("/")[2] for row in receipt["rows"]],
                         ["report", "events", "attachment"])
        for row in receipt["rows"]:
            self.assertRegex(row["sha256"], "^[0-9a-f]{64}$")
            self.assertEqual(row["id"], "alpha/i-ok/{}/{}".format(row["id"].split("/")[2], row["sha256"][:16]))
        report_id = receipt["rows"][0]["id"]

        # The runner's own final message is the report: the stand-in printed it and nothing else did. The term does
        # not select the report alone: the events row is the launcher's own stored envelopes for the lane, and the
        # brief.rendered envelope names the configuration's rule file, rules/standing.md, whose name holds the term.
        # So the report is named by what only it holds: the line the runner printed.
        hits = self.decision_json("search", "--db", str(db), "standin", "--kind", "lane_record", "--mode", "keyword")
        self.assertTrue(hits, "the ingest-lane report is not searchable by keyword")
        found = {hit["lane_record"]["id"]: hit for hit in hits}
        self.assertIn(report_id, found)
        self.assertEqual(found[report_id]["matched_text"], "lane")
        self.assertIn("standin: ok i-ok run 1", found[report_id]["lane_record"]["text"])
        self.assertEqual([identifier for identifier in found
                          if "standin: ok i-ok run 1" in found[identifier]["lane_record"]["text"]], [report_id])

        # Asking again adds nothing: the source hashes are the ids.
        again = self.ingest(db, "i-ok", ledger)
        self.assertEqual((again["rows_added"], again["rows_existing"]), (0, 3))
        self.assertEqual(again["rows"], receipt["rows"])

        # The launcher recorded each ingest with the lane: the first receipt says what it added, the second that
        # the same sources were already stored and nothing was added.
        recorded = self.lane_events("i-ok", "lane.ingested")
        self.assertEqual([event["payload"] for event in recorded],
                         [{"lane": "i-ok", "rows_added": 3, "rows_existing": 0, "rows": receipt["rows"]},
                          {"lane": "i-ok", "rows_added": 0, "rows_existing": 3, "rows": receipt["rows"]}])

        stats = self.decision_json("stats", "--db", str(db))
        self.assertEqual(stats["lane_records"], 3)
        self.assertEqual(stats["lane_record_triggers"],
                         ["lane_records_no_delete", "lane_records_no_replace", "lane_records_no_update"])
        verified = self.decision_json("verify", "--db", str(db))
        self.assertIs(verified["ok"], True)
        self.assertEqual(verified["lane_records"], 3)
        self.assert_sound()

    def test_a_running_lane_is_refused(self):
        db = self.fresh_store()
        self.start("i-run", "--runner", "forever", "--model", "ingest-model-1", "--effort", "high",
                   "--worktree", self.scratch("i-run"))
        self.wait_event("lane.started", "i-run")
        try:
            result = self.ingest(db, "i-run", code=2)
            self.assertIn("is running run 1", result.stderr)
            self.assertIn("not ingested", result.stderr)
        finally:
            self.lane("stop", "--lane", "i-run")
        self.assertEqual(self.decision_json("stats", "--db", str(db))["lane_records"], 0)

    def test_a_lane_with_no_report_is_refused(self):
        db = self.fresh_store()
        # A streamer with an empty script prints nothing, so its log is empty and there is no report to ingest.
        self.finished("i-silent", runner="streamer", script="[]\n")
        result = self.ingest(db, "i-silent", code=2)
        self.assertIn("an empty report is not ingested", result.stderr)
        self.assertEqual(self.decision_json("stats", "--db", str(db))["lane_records"], 0)

    def test_a_lane_record_is_append_only(self):
        db = self.fresh_store()
        self.finished("i-guarded")
        receipt = self.ingest(db, "i-guarded")
        report_id = receipt["rows"][0]["id"]
        with sqlite3.connect(str(db)) as connection:
            with self.assertRaises(sqlite3.IntegrityError) as changed:
                connection.execute("UPDATE lane_records SET text = 'changed' WHERE id = ?", (report_id,))
            self.assertIn("lane records never change", str(changed.exception))
        with sqlite3.connect(str(db)) as connection:
            with self.assertRaises(sqlite3.IntegrityError) as removed:
                connection.execute("DELETE FROM lane_records WHERE id = ?", (report_id,))
            self.assertIn("lane records are never deleted", str(removed.exception))
        self.decision_json("verify", "--db", str(db))

    def test_an_unknown_lane_is_refused(self):
        db = self.fresh_store()
        # A lane that ran makes the event store exist; a name it never used is not in it.
        self.finished("i-somebody")
        result = self.ingest(db, "i-absent", code=2)
        self.assertIn("is not in the event store", result.stderr)
        self.assertEqual(self.decision_json("stats", "--db", str(db))["lane_records"], 0)
