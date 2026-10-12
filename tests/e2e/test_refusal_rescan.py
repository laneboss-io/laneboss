"""Refusals F. lane scan is safe to repeat: the second scan appends nothing. A lane resumed twice has each run's
refusals under its run, a later run's shell write to a refused target is a suspicion of the earlier run's refusal, and
refusal ids are the same after state rebuild. Fix round 1, decision 11: one refusal, one identity. Fix round 2, ruling
R36: a record that changes under the reader is not coverage, and what a scan found not covered stays shown."""

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

from . import refusalsupport, support
from .refusalsupport import expected_path, hook, refused_steps, shell_steps


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class RescanTest(refusalsupport.RefusalTest):
    def test_resumed_lane_keeps_runs_apart(self):
        lane = "f-runs"
        self.scenario(lane, [{"open": {}}] + refused_steps("claude-code") + [{"exit": 0}], run=1)
        self.scenario(lane, [{"open": {}}] + shell_steps("c2", "printf 'x\\n' > notes/plan.md")
                      + refused_steps("claude-code", "c3", "printf 'halt\\n' > notes/halt.md", hook("halt"))
                      + [{"exit": 0}], run=2)
        self.scenario(lane, [{"open": {}}] + refused_steps(
            "claude-code", "c4", "rm -rf notes", "Permission to use Bash has been denied.") + [{"exit": 0}], run=3)
        directory = self.scratch(lane)
        (directory / "notes").mkdir()
        started = self.start(lane, "--runner", "claude", "--model", "session-model-1", "--worktree", directory)
        self.wait_event("lane.ended", lane, run=1)
        for run in (2, 3):
            self.lane_json("resume", "--lane", lane)
            self.wait_event("lane.ended", lane, run=run)
        refusals = {item["payload"]["call"]["id"]: item["payload"] for item in self.kind_events(lane, "lane.refusal")}
        self.assertEqual({call: item["run"] for call, item in refusals.items()}, {"c1": 1, "c3": 2, "c4": 3})
        self.assertEqual({call: item["guard"] for call, item in refusals.items()},
                         {"c1": "doc-guard", "c3": "doc-guard", "c4": "perm"})
        self.assertEqual(refusals["c4"]["targets"], [expected_path(started["worktree"], "notes")])
        suspicion = self.suspicion_of(lane, "c2")
        self.assertEqual(len(suspicion), 1)
        self.assertEqual((suspicion[0]["payload"]["run"], suspicion[0]["payload"]["refusal"]),
                         (2, refusals["c1"]["refusal"]))
        coverage = self.refusals(lane)["coverage"]
        self.assertEqual([(item["run"], item["complete"], item["covered"]) for item in coverage],
                         [(1, True, True), (2, True, True), (3, True, True)])
        count = len(self.events())
        for attempt in range(2):
            scanned = self.scan(lane)
            self.assertEqual(scanned["appended"], {"refusals": 0, "suspicions": 0})
            self.assertEqual(scanned["recorded"], {"refusals": 3, "suspicions": 1})
        self.assertEqual(len(self.events()), count)
        before = self.refusals(lane)
        lanes = self.run_laneboss("state", "lanes", "--config", "alpha", environment=self.env("alpha")).stdout
        rebuilt = self.run_laneboss("state", "rebuild", "--config", "alpha", environment=self.env("alpha")).stdout
        self.assertEqual(rebuilt, lanes)
        after = self.refusals(lane)
        self.assertEqual([item["refusal"] for item in after["refusals"]], [item["refusal"] for item in before["refusals"]])
        self.assertEqual(after["refusals"], before["refusals"])
        self.assertEqual(after["suspicions"], before["suspicions"])
        self.assertEqual(self.scan(lane)["appended"], {"refusals": 0, "suspicions": 0})
        self.assert_sound()

    def test_one_refusal_one_identity(self):
        # Decision 11: two templates that reach one file give one event.
        lane = "f-twice"
        self.start_session(lane, "claude-code", [{"open": {}}] + refused_steps("claude-code") + [{"exit": 0}],
                           runner="twice")
        self.wait_event("lane.ended", lane)
        self.assertEqual(len(self.kind_events(lane, "lane.refusal")), 1)
        self.assertEqual(self.scan(lane)["appended"], {"refusals": 0, "suspicions": 0})
        self.assertEqual(len(self.kind_events(lane, "lane.refusal")), 1)
        self.assert_sound()

    def test_long_first_line_is_read(self):
        # Fix round 2, ruling R36: a record is read once its first line is complete, however long that line is (up to
        # the line limit). A record whose first line is 80 KiB long holds a refusal after it, beside a second record
        # under the same template: the refusal is found, and the run is covered.
        lane = "f-long"
        steps = [{"open": {}}] + shell_steps("s1", "ls")
        steps += [{"open": {"first": 80 * 1024}}] + refused_steps("claude-code", "l1") + [{"exit": 0}]
        self.start_session(lane, "claude-code", steps)
        self.wait_event("lane.ended", lane)
        self.assertEqual([item["payload"]["call"]["id"] for item in self.kind_events(lane, "lane.refusal")], ["l1"])
        coverage = self.coverage(lane)
        self.assertEqual((coverage["covered"], len(coverage["records"])), (True, 2))
        self.assertEqual(self.scan(lane)["appended"], {"refusals": 0, "suspicions": 0})
        self.assert_sound()

    def test_replaced_record_is_not_coverage(self):
        # Fix round 2, ruling R36: a claude-code record that changes under the reader is not coverage. One record is
        # emptied and written again, shorter; another's first line changes (its file replaced by a larger one); a third,
        # partly read (a block of an unknown type), is replaced by a clean one. Each is not covered for good and nothing
        # more is read from it: the refusals in the new contents are never recorded, not by lane scan either. A fourth
        # record whose first line never ends is partly read. The gate asks for --accept-uncovered.
        lane = "f-replace"
        steps = [{"open": {}}] + refused_steps("claude-code", "a1")
        steps += [{"open": {}}] + refused_steps("claude-code", "b1")
        steps += [{"open": {}}, {"block": {"role": "assistant", "type": "hologram"}}] + refused_steps("claude-code", "c1")
        steps += [{"mark": "written"}, {"wait": "go"}, {"exit": 0}]
        started = self.start_session(lane, "claude-code", steps)
        self.marked(lane, "written")
        first, second, third = self.record(lane)["records"]
        deadline = time.monotonic() + 30
        while len(self.kind_events(lane, "lane.refusal")) < 3:
            self.assertLess(time.monotonic(), deadline, "the live scan did not read the three records")
            time.sleep(0.5)
        with open(first, "rb") as handle:
            lines = handle.read().splitlines(True)
        shorter = lines[1].replace(b'"a1"', b'"a2"').split(b'"content": [{"type": "text", "text": ')[0]
        shorter += (b'"content": [{"type": "text", "text": "Permission to use Bash has been denied."}], "is_error": true}]}}'
                    b'\n')
        with open(first, "r+b") as handle:
            handle.truncate(0)
            handle.write(lines[0] + shorter)
        with open(second, "rb") as handle:
            larger = handle.read().replace(b'"b1"', b'"b2"') + b'{"type": "summary", "summary": "more"}\n'
        with open(second + ".new", "wb") as handle:
            handle.write(larger)
        os.replace(second + ".new", second)
        clean = [{"type": "assistant", "timestamp": refusalsupport.stamp(), "cwd": str(started["worktree"]),
                  "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "c2", "name": "Bash",
                                                                "input": {"command": "rm notes/plan.md"}}]}},
                 {"type": "user", "timestamp": refusalsupport.stamp(), "cwd": str(started["worktree"]),
                  "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "c2", "is_error": True,
                                                           "content": hook("clean")}]}}]
        with open(third + ".new", "w", encoding="utf-8") as handle:
            handle.write("".join(json.dumps(line) + "\n" for line in clean))
        os.replace(third + ".new", third)
        unfinished = os.path.join(os.path.dirname(first), "unfinished.jsonl")
        with open(unfinished, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(clean[0])[:-1])
        self.go(lane)
        self.wait_event("lane.ended", lane)
        for listed in (self.coverage(lane), self.scan(lane)["runs"][0]):
            reasons = {item.get("path"): item["reason"] for item in listed["not_covered"]}
            self.assertEqual((reasons.get(first), reasons.get(second)), ("replaced", "replaced"))
            self.assertIn(reasons.get(third), ("replaced", "partly-read"))
            self.assertEqual(reasons.get(unfinished), "partly-read")
            self.assertIs(listed["covered"], False)
        self.assertEqual(sorted(item["payload"]["call"]["id"] for item in self.kind_events(lane, "lane.refusal")),
                         ["a1", "b1", "c1"])
        result = self.lane("mark", "--lane", lane, "--state", "accepted", code=2)
        self.assertIn("--accept-uncovered", result.stderr)
        self.lane_json("mark", "--lane", lane, "--state", "accepted", "--accept-uncovered")
        self.assertEqual(len(self.kind_events(lane, "lane.refusal")), 3)
        self.assert_sound()

    def kept_path(self, lane, run=1):
        launch = [item for item in self.kind_events(lane, "lane.started") if item["payload"]["run"] == run][0]
        return Path(self.paths("alpha")["state_dir"]) / "lanes" / lane / "scans" / (launch["payload"]["launch"] + ".json")

    def kept_coverage(self, lane, run=1):
        """The coverage file kept for a run of the lane, read whole (None while there is none or it is being written)."""
        try:
            return json.loads(self.kept_path(lane, run).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def test_unfinished_first_line_completes(self):
        # Fix round 4, decision 5: a record whose first line is still unfinished when the live scan saves its coverage,
        # completed later, is read, and the run is covered at the end.
        lane = "f-unfinished"
        started = self.start_session(lane, "claude-code", [{"open": {}}] + shell_steps("s1", "ls")
                                     + [{"mark": "written"}, {"wait": "go"}, {"exit": 0}])
        self.marked(lane, "written")
        path = os.path.join(os.path.dirname(self.record(lane)["records"][0]), "unfinished.jsonl")
        first = json.dumps({"type": "user", "timestamp": refusalsupport.stamp(), "cwd": str(started["worktree"]),
                            "message": {"role": "user", "content": "begin"}})
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(first[:-1])
        written = time.time()
        deadline = time.monotonic() + 30
        while not (self.kept_path(lane).exists() and self.kept_path(lane).stat().st_mtime > written + 2):
            self.assertLess(time.monotonic(), deadline, "the live scan saved no coverage while the line was unfinished")
            time.sleep(0.5)
        second = json.dumps({"type": "assistant", "timestamp": refusalsupport.stamp(), "cwd": str(started["worktree"]),
                             "message": {"role": "assistant", "content": [{"type": "text", "text": "done"}]}})
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(first[-1:] + "\n" + second + "\n")
        self.go(lane)
        self.wait_event("lane.ended", lane)
        coverage = self.coverage(lane)
        self.assertEqual((coverage["covered"], coverage["not_covered"]), (True, []))
        self.assertEqual([(item["state"], item["lines"]) for item in coverage["records"] if item["path"] == path],
                         [("covered", 2)])
        self.assert_sound()

    def test_short_record_grows(self):
        # Fix round 4, decision 5: a record shorter than 4096 bytes that grows between two scans stays covered. Fix round
        # 5, decision 2: the stand-in pauses after its first write until its checkpoint is saved, and the saved offset
        # after the second write is larger.
        lane = "f-grows"
        steps = [{"open": {}}] + shell_steps("g1", "ls") + [{"mark": "one"}, {"wait": "grow"}]
        steps += shell_steps("g2", "ls -la") + [{"mark": "two"}, {"wait": "go"}, {"exit": 0}]
        self.start_session(lane, "claude-code", steps)
        offsets = []
        for mark in ("one", "two"):
            self.marked(lane, mark)
            path = self.record(lane)["records"][0]
            self.assertLess(os.path.getsize(path), 4096)
            self.wait_for_checkpoint(lane, path)
            offsets += [entry["seen"] for entry in self.kept_coverage(lane)["inventory"]
                        if entry["path"] == os.path.realpath(path)]
            scanned = self.scan(lane)
            self.assertEqual([item["state"] for item in scanned["runs"][0]["records"] if item["path"] == path],
                             ["covered"])
            self.assertEqual([item["reason"] for item in scanned["not_covered"]], ["running"])
            (self.records["alpha"] / (lane + ".grow")).write_text("grow\n", encoding="utf-8")
        self.assertEqual(len(offsets), 2)
        self.assertGreater(offsets[1], offsets[0])
        self.go(lane)
        self.wait_event("lane.ended", lane)
        coverage = self.coverage(lane)
        self.assertEqual((coverage["covered"], coverage["not_covered"]), (True, []))
        self.assert_sound()

    def wait_for_log_entry(self, lane, log, wanted, what, within=30.0):
        """Wait at most `within` seconds until the inventory saved for run 1 holds an entry for the run's own log for
        which wanted(entry); return run 1's saved coverage. Fix round 7, decision 4: the deadline is checked after each
        look and before what it found is accepted, so that an entry found after the deadline fails."""
        deadline = time.monotonic() + within
        while True:
            kept = self.kept_coverage(lane) or {}
            entries = [entry for entry in kept.get("inventory", []) if entry.get("path") == log]
            self.assertLessEqual(time.monotonic(), deadline, "the live scan did not save " + what)
            if entries and wanted(entries[0]):
                return kept
            time.sleep(0.1)

    def test_older_log_cut_under_a_new_reader(self):
        # Fix round 6, decisions 1, 2 and 4: run 1 ended with its range [0, E) and a resume began run 2 at E. Run 2's
        # stand-in cuts the log below E as its first step, before the new live reader first reads run 1's range (run 1's
        # saved row then shows fewer lines than run 1 wrote, which proves that order). That reader sees run 1's log
        # shorter than its recorded end and saves run 1 truncated within 2 seconds of the cut; the log then grows past E
        # again, and run 1 stays truncated and not covered at the final write, after lane scan and at the gate.
        lane = "f-older"
        self.scenario(lane, [{"say": "line {}".format(number)} for number in range(40)] + [{"exit": 0}], run=1)
        started = self.start(lane, "--runner", "texter", "--model", "session-model-1", "--worktree", self.scratch(lane))
        log = started["log"]
        self.wait_event("lane.ended", lane, run=1)
        data = Path(log).read_bytes()
        written = [item["lines"] for item in self.coverage(lane)["records"] if item["path"] == log][0]
        self.scenario(lane, [{"truncate": {"path": log, "size": data.index(b"line 10\n")}}, {"mark": "cut"},
                             {"wait": "grow"}] + [{"say": "more {}".format(number)} for number in range(80)]
                      + [{"exit": 0}], run=2)
        self.lane_json("resume", "--lane", lane)
        moment = self.marked(lane, "cut", run=2)
        kept = self.wait_for_log_entry(lane, log, lambda entry: entry["state"] == "truncated",
                                       "run 1 truncated within 2 seconds of the cut", within=moment + 2.0 - time.time())
        rows = [item["lines"] for item in kept["records"] if item["path"] == log]
        self.assertTrue(rows and rows[0] < written, "the new reader read run 1's range before the cut: {} of {} lines"
                        .format(rows, written))
        (self.records["alpha"] / (lane + ".grow")).write_text("grow\n", encoding="utf-8")
        self.wait_event("lane.ended", lane, run=2)
        self.assertGreater(os.path.getsize(log), len(data))
        scanned = {item["run"]: item for item in self.scan(lane)["runs"]}
        for listed in (self.coverage(lane, run=1), scanned[1]):
            self.assertIn(("truncated", log), [(item["reason"], item.get("path")) for item in listed["not_covered"]])
            self.assertIs(listed["covered"], False)
        result = self.lane("mark", "--lane", lane, "--state", "accepted", code=2)
        self.assertIn("--accept-uncovered", result.stderr)
        self.assert_sound()

    def test_log_cut_while_the_run_lives(self):
        # Fix round 5, decision 1: the run's own log cut while the run lives. The live reader sees it shorter than what
        # it has read and saves the run as truncated at that look; nothing turns it back, not the runner writing its
        # block again to the former length, not the run's end, not an intact resume: run 1 is truncated and not covered
        # after the live scan, after lane scan and at the gate, and run 2 is covered.
        lane = "f-cut"
        block = [{"say": "block begins"}] + refused_steps("text")
        self.scenario(lane, block + [{"mark": "written"}, {"wait": "again"}] + block + [{"exit": 0}], run=1)
        self.scenario(lane, [{"say": "run two"}, {"exit": 0}], run=2)
        started = self.start(lane, "--runner", "texter", "--model", "session-model-1", "--worktree", self.scratch(lane))
        log = started["log"]
        self.marked(lane, "written")
        deadline = time.monotonic() + 30
        while b"GUARD_SKIP" not in Path(log).read_bytes():
            self.assertLess(time.monotonic(), deadline, "the block did not reach the log")
            time.sleep(0.1)
        data = Path(log).read_bytes()
        self.wait_for_log_entry(lane, log, lambda entry: entry["seen"] >= len(data), "the read position")
        os.truncate(log, data.index(b"block begins"))
        # Fix round 6, decision 4: saved at the look that saw it, so within 2 seconds of the cut (the periodic write is
        # every 5 seconds).
        self.wait_for_log_entry(lane, log, lambda entry: entry["state"] == "truncated", "the drop within 2 seconds",
                                within=2.0)
        (self.records["alpha"] / (lane + ".again")).write_text("again\n", encoding="utf-8")
        self.wait_event("lane.ended", lane, run=1)
        self.assertGreaterEqual(os.path.getsize(log), len(data))
        scanned = {item["run"]: item for item in self.scan(lane)["runs"]}
        for listed in (self.coverage(lane, run=1), scanned[1]):
            self.assertIn(("truncated", log), [(item["reason"], item.get("path")) for item in listed["not_covered"]])
            self.assertIs(listed["covered"], False)
        self.lane_json("resume", "--lane", lane)
        self.wait_event("lane.ended", lane, run=2)
        runs = {item["run"]: item for item in self.scan(lane)["runs"]}
        self.assertEqual((runs[1]["covered"], runs[2]["covered"]), (False, True))
        result = self.lane("mark", "--lane", lane, "--state", "accepted", code=2)
        self.assertIn("--accept-uncovered", result.stderr)
        self.assert_sound()

    def test_older_record_judged_at_its_end(self):
        # Fix round 7, decision 1: a record of an ended run is judged only after it has been read to its end. Run 1's
        # second record holds a metadata line and, as its LAST line and without a newline, its only assistant line: run
        # 1 ends covered. A resume writes a separate healthy record. The new live reader holds that last line back in
        # its passes before the final one, and run 1 stays covered through them (checked once the reader's periodic
        # write of run 2, 5 seconds after it began, is there), at the final write, after lane scan and at the gate.
        lane = "f-last-line"
        self.scenario(lane, [{"open": {}}] + shell_steps("l1", "ls") + [{"mark": "written"}, {"wait": "go"},
                                                                         {"exit": 0}], run=1)
        self.scenario(lane, [{"open": {}}] + shell_steps("l2", "ls") + [{"mark": "written"}, {"wait": "again"},
                                                                         {"exit": 0}], run=2)
        started = self.start(lane, "--runner", "claude", "--model", "session-model-1", "--worktree", self.scratch(lane))
        self.marked(lane, "written")
        path = os.path.join(os.path.dirname(self.record(lane)["records"][0]), "last-line.jsonl")
        lines = [{"type": "system", "timestamp": refusalsupport.stamp(), "cwd": str(started["worktree"]),
                  "content": "session begins"},
                 {"type": "assistant", "timestamp": refusalsupport.stamp(), "cwd": str(started["worktree"]),
                  "message": {"role": "assistant", "content": [{"type": "text", "text": "done"}]}}]
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(lines[0]) + "\n" + json.dumps(lines[1]))
        self.go(lane)
        self.wait_event("lane.ended", lane, run=1)
        coverage = self.coverage(lane)
        self.assertEqual((coverage["covered"], [(item["state"], item["lines"]) for item in coverage["records"]
                                                if item["path"] == path]), (True, [("covered", 2)]))
        self.lane_json("resume", "--lane", lane)
        self.marked(lane, "written", run=2)
        deadline = time.monotonic() + 30
        while self.kept_coverage(lane, run=2) is None:
            self.assertLess(time.monotonic(), deadline, "the live scan saved nothing of run 2")
            time.sleep(0.2)
        kept = self.kept_coverage(lane)
        self.assertEqual((kept["covered"], [entry["state"] for entry in kept["inventory"]
                                            if entry["path"] == os.path.realpath(path)]), (True, ["covered"]))
        (self.records["alpha"] / (lane + ".again")).write_text("again\n", encoding="utf-8")
        self.wait_event("lane.ended", lane, run=2)
        scanned = {item["run"]: item for item in self.scan(lane)["runs"]}
        for listed in (self.coverage(lane, run=1), scanned[1]):
            self.assertEqual((listed["covered"], listed["not_covered"]), (True, []))
        self.lane_json("mark", "--lane", lane, "--state", "accepted")
        self.assert_sound()

    def test_second_bad_state_is_saved_once(self):
        # Fix round 7, decision 2: run 1's record, saved partly-read (a block of an unknown type), is replaced while a
        # resumed run's live reader follows the lane. The change is saved once: over the passes that follow, run 1's
        # coverage file is not written again (run 2's periodic write goes to run 2's file), the saved inventory keeps
        # the first bad state, and run 1 stays not covered.
        lane = "f-bad-twice"
        self.scenario(lane, [{"open": {}}, {"block": {"role": "assistant", "type": "hologram"}}]
                      + shell_steps("t1", "ls") + [{"exit": 0}], run=1)
        self.scenario(lane, [{"open": {}}] + shell_steps("t2", "ls") + [{"mark": "written"}, {"wait": "again"},
                                                                         {"exit": 0}], run=2)
        started = self.start(lane, "--runner", "claude", "--model", "session-model-1", "--worktree", self.scratch(lane))
        self.wait_event("lane.ended", lane, run=1)
        path = self.record(lane)["records"][0]
        self.assertEqual(self.reasons(self.coverage(lane)), ["partly-read"])
        self.lane_json("resume", "--lane", lane)
        self.marked(lane, "written", run=2)
        before = self.kept_path(lane).stat().st_mtime_ns
        clean = {"type": "user", "timestamp": refusalsupport.stamp(), "cwd": str(started["worktree"]),
                 "message": {"role": "user", "content": "clean"}}
        with open(path + ".new", "w", encoding="utf-8") as handle:
            handle.write(json.dumps(clean) + "\n")
        os.replace(path + ".new", path)
        deadline = time.monotonic() + 30
        while self.kept_path(lane).stat().st_mtime_ns == before:
            self.assertLess(time.monotonic(), deadline, "the live scan did not save the replaced record")
            time.sleep(0.1)
        after = self.kept_path(lane).stat().st_mtime_ns
        time.sleep(3)
        self.assertEqual(self.kept_path(lane).stat().st_mtime_ns, after,
                         "run 1's coverage was written again in the six passes after the change was saved")
        kept = self.kept_coverage(lane)
        self.assertEqual((kept["covered"], [entry["state"] for entry in kept["inventory"]
                                            if entry["path"] == os.path.realpath(path)]), (False, ["partly-read"]))
        (self.records["alpha"] / (lane + ".again")).write_text("again\n", encoding="utf-8")
        self.wait_event("lane.ended", lane, run=2)
        self.assertIs(self.coverage(lane)["covered"], False)
        self.assert_sound()

    def test_late_entry_fails_the_wait(self):
        # Fix round 7, decision 4: the wait for a saved entry checks its deadline before it accepts what it found. An
        # entry found only after the deadline (the test process held up past it), or with a deadline already past,
        # fails the test; one found in time is returned.
        found = {"inventory": [{"path": "lane.log", "state": "truncated"}]}

        def late(lane, run=1):
            time.sleep(0.5)
            return found

        def at_once(lane, run=1):
            return found

        def wanted(entry):
            return entry["state"] == "truncated"

        self.kept_coverage = late
        with self.assertRaises(self.failureException):
            self.wait_for_log_entry("f-late", "lane.log", wanted, "the entry in time", within=0.2)
        self.kept_coverage = at_once
        with self.assertRaises(self.failureException):
            self.wait_for_log_entry("f-late", "lane.log", wanted, "the entry in time", within=-1.0)
        self.assertIs(self.wait_for_log_entry("f-late", "lane.log", wanted, "the entry in time", within=5.0), found)

    def wait_for_checkpoint(self, lane, path):
        """Wait until the inventory the live scan saved holds the record read to its end: the offset is the file's
        size and the anchor is the hash of the 4096 bytes before it (fix round 4, decision 4)."""
        with open(path, "rb") as handle:
            data = handle.read()
        anchor = hashlib.sha256(data[-4096:]).hexdigest()
        deadline = time.monotonic() + 30
        while True:
            entries = [entry for entry in (self.kept_coverage(lane) or {}).get("inventory", [])
                       if entry.get("path") == os.path.realpath(path)]
            if entries and (entries[0]["seen"], entries[0]["tail"]) == (len(data), anchor):
                return
            self.assertLess(time.monotonic(), deadline, "the live scan did not save its checkpoint of the record")
            time.sleep(0.5)

    def rewritten(self, lane, near):
        """A record the live scan reads whole, then rewritten in place keeping its first line and its size: one
        placeholder result becomes a guard's message, in the last 4096 bytes before the reader's place (near) or
        further back (far). Returns the lane's start and the record's path once the run has ended."""
        message = hook("rewritten").splitlines()[0]
        steps = [{"open": {}}] + shell_steps("c1", "printf 'x\\n' > notes/plan.md", text="x" * len(message), error=True)
        steps += shell_steps("c3", "printf 'y\\n' > notes/plan.md")
        for number in range(60):
            steps += shell_steps("f{}".format(number), "ls src/module-{}".format(number), text="nothing here")
        steps += shell_steps("c9", "ls", text="y" * len(message), error=True) + refused_steps("claude-code", "r0")
        started = self.start_session(lane, "claude-code", steps + [{"mark": "written"}, {"wait": "go"}, {"exit": 0}])
        self.marked(lane, "written")
        path = self.record(lane)["records"][0]
        self.wait_for_checkpoint(lane, path)
        placeholder = (("y" if near else "x") * len(message)).encode("ascii")
        with open(path, "r+b") as handle:
            data = handle.read()
            self.assertEqual(data.count(placeholder), 1)
            handle.seek(data.index(placeholder))
            handle.write(message.encode("ascii"))
        self.go(lane)
        self.wait_event("lane.ended", lane)
        return started, path

    def test_rewrite_behind_reader_is_replaced(self):
        # Fix round 3, decision 2: a record rewritten with its first line and size kept, but with a refusal in the last
        # 4096 bytes before the live reader's place, is replaced: the run is not covered.
        _, path = self.rewritten("f-near", near=True)
        coverage = self.coverage("f-near")
        self.assertIn(("replaced", path), [(item["reason"], item.get("path")) for item in coverage["not_covered"]])
        self.assertIs(coverage["covered"], False)
        self.assertEqual([item["payload"]["call"]["id"] for item in self.kind_events("f-near", "lane.refusal")], ["r0"])
        self.assert_sound()

    def test_gate_reads_from_the_beginning(self):
        # Fix round 3, decision 2: a rewrite that keeps the first line and the 4096 bytes before the reader's place is
        # not seen by the live scan (the documented limit: it stays covered), but the scan of lane mark reads every
        # record from its beginning: it records the refusal and the suspicion after it, and refuses.
        started, path = self.rewritten("f-far", near=False)
        self.assertIs(self.coverage("f-far")["covered"], True)
        self.assertEqual([item["payload"]["call"]["id"] for item in self.kind_events("f-far", "lane.refusal")], ["r0"])
        result = self.lane("mark", "--lane", "f-far", "--state", "accepted", code=2)
        self.assertIn(expected_path(started["worktree"], "notes/plan.md"), result.stderr)
        self.assertEqual(sorted(item["payload"]["call"]["id"] for item in self.kind_events("f-far", "lane.refusal")),
                         ["c1", "r0"])
        self.assertEqual(len(self.suspicion_of("f-far", "c3")), 1)
        self.assertEqual(self.lane_events("f-far", "lane.state"), [])
        self.assert_sound()

    def test_unreadable_coverage_is_kept(self):
        # Fix round 3, decision 3: a coverage file that exists and cannot be read (malformed, or without the format
        # number) is not an empty one: the scan reports coverage-unreadable naming it, the run is not covered, the
        # file is not replaced, and marking is held up.
        lane = "f-damaged"
        steps = [{"open": {}}] + shell_steps("d1", "ls") + [{"open": {}}] + shell_steps("d2", "ls") + [{"exit": 0}]
        self.start_session(lane, "claude-code", steps)
        self.wait_event("lane.ended", lane)
        second = self.ended_by_itself(lane)["records"][1]
        os.unlink(second)
        self.assertIn(("missing", second), [(item["reason"], item["path"]) for item in self.scan(lane)["not_covered"]])
        launch = self.kind_events(lane, "lane.started")[0]["payload"]["launch"]
        kept = Path(self.paths("alpha")["state_dir"]) / "lanes" / lane / "scans" / (launch + ".json")
        for damaged in (b"{not json", json.dumps({"launch": launch}).encode("utf-8")):
            kept.write_bytes(damaged)
            scanned = self.scan(lane)
            self.assertIn(("coverage-unreadable", os.path.realpath(str(kept))),
                          [(item["reason"], os.path.realpath(item["path"])) for item in scanned["not_covered"]])
            self.assertIs(scanned["runs"][0]["covered"], False)
            self.assertEqual(kept.read_bytes(), damaged)
            self.lane("mark", "--lane", lane, "--state", "accepted", code=2)
        self.assert_sound()

    def test_damaged_coverage_body_is_kept(self):
        # Fix round 4, decision 2: a coverage file with the right format number and launch but a damaged body is
        # coverage-unreadable too, never an unhandled error; it is not overwritten, and the refusal the scan finds is
        # still recorded.
        lane = "f-body"
        steps = [{"open": {}}, {"mark": "opened"}, {"wait": "go"}] + refused_steps("claude-code") + [{"exit": 0}]
        self.start_session(lane, "claude-code", steps)
        self.marked(lane, "opened")
        self.kill_supervisor(lane)
        self.go(lane)
        self.ended_by_itself(lane)
        self.lane_json("check")
        launch = self.kind_events(lane, "lane.started")[0]["payload"]["launch"]
        kept = Path(self.paths("alpha")["state_dir"]) / "lanes" / lane / "scans" / (launch + ".json")
        kept.parent.mkdir(parents=True, exist_ok=True)
        base = {"format": 1, "lane": lane, "run": 1, "launch": launch, "scanned_at": None, "by": "lane scan",
                "complete": True, "configured": True, "covered": True, "records": [],
                "skipped": {"other_directory": 0, "before_run": 0}, "not_covered": [], "inventory": []}
        entry = {"path": "/nowhere/a.jsonl", "shown": "/nowhere/a.jsonl", "format": "claude-code", "first": None,
                 "seen": 0, "tail": None, "state": "covered"}
        bodies = [dict(base, inventory=None), dict(base, inventory=[dict(entry, path=7)]),
                  dict(base, not_covered="none"), dict(base, inventory=[dict(entry, seen="far")]),
                  dict(base, records=[3])]
        for number, body in enumerate(bodies):
            with self.subTest(body=number):
                damaged = json.dumps(body).encode("utf-8")
                kept.write_bytes(damaged)
                scanned = self.scan(lane)
                self.assertIn(("coverage-unreadable", os.path.realpath(str(kept))),
                              [(item["reason"], os.path.realpath(item["path"])) for item in scanned["not_covered"]])
                self.assertIs(scanned["runs"][0]["covered"], False)
                self.assertEqual(kept.read_bytes(), damaged)
                self.assertEqual(scanned["recorded"]["refusals"], 1)
                listed = self.refusals(lane)
                self.assertIn("coverage-unreadable", [item["reason"] for item in listed["not_covered"]])
        self.lane("mark", "--lane", lane, "--state", "accepted", code=2)
        self.assert_sound()

    def check_resumed_log(self, lane, removed):
        """Two runs of the text stand-in with the same output, a refusal at the same place of each; the lane's log is
        removed between them when `removed`. Returns the scan after the second run and the log's path."""
        steps = refused_steps("text") + [{"exit": 0}]
        self.scenario(lane, steps, run=1)
        self.scenario(lane, steps, run=2)
        started = self.start(lane, "--runner", "texter", "--model", "session-model-1", "--worktree", self.scratch(lane))
        self.wait_event("lane.ended", lane, run=1)
        if removed:
            os.unlink(started["log"])
        self.lane_json("resume", "--lane", lane)
        self.wait_event("lane.ended", lane, run=2)
        refusals = self.kind_events(lane, "lane.refusal")
        self.assertEqual(sorted(item["payload"]["run"] for item in refusals), [1, 2])
        if removed:
            self.assertEqual(refusals[0]["payload"]["record"]["offset"], refusals[1]["payload"]["record"]["offset"])
        return self.scan(lane), started["log"]

    def test_log_removed_before_a_resume(self):
        # Fix round 4, decision 1: the run's own log removed after run 1 and written anew by run 2. Run 2's range begins
        # before run 1's ends: run 1 is truncated and not covered, run 2 is read normally and its refusal, at the same
        # offset as run 1's, is a refusal of its own; marking asks for --accept-uncovered.
        scanned, log = self.check_resumed_log("f-recreated", removed=True)
        runs = {item["run"]: item for item in scanned["runs"]}
        self.assertIn(("truncated", log), [(item["reason"], item.get("path")) for item in runs[1]["not_covered"]])
        self.assertEqual((runs[1]["covered"], runs[2]["covered"]), (False, True))
        self.assertEqual(scanned["appended"], {"refusals": 0, "suspicions": 0})
        result = self.lane("mark", "--lane", "f-recreated", "--state", "accepted", code=2)
        self.assertIn("--accept-uncovered", result.stderr)
        self.assert_sound()

    def test_log_kept_across_a_resume(self):
        # Fix round 4, decision 1, the healthy case: with the log intact the two runs stay covered, each with its own
        # refusal.
        scanned, _ = self.check_resumed_log("f-intact", removed=False)
        self.assertEqual([(item["run"], item["covered"]) for item in scanned["runs"]], [(1, True), (2, True)])
        self.assertEqual(scanned["appended"], {"refusals": 0, "suspicions": 0})
        self.assert_sound()

    def test_slower_scan_loses_nothing(self):
        # Fix round 2, ruling R36: a scan merges what it saw into the coverage it finds on disk when it writes, so a
        # slower scan that writes last takes back nothing a faster one found. A lane scan reads a record that a slow
        # guard keeps busy for several seconds; meanwhile the record is deleted, and a second scan finds it missing and
        # writes first; the slow scan writes last; the record stays missing.
        config = self.home / "configs" / "alpha" / "config.toml"
        config.write_text(config.read_text(encoding="utf-8")
                          + "\n[[guards]]\nname = \"slow\"\npattern = '^a.*.*.*.*.*.*.*b'\n", encoding="utf-8")
        lane = "f-slow"
        steps = [{"open": {}}] + shell_steps("q1", "ls") + [{"open": {}}]
        for number in range(6):
            steps += shell_steps("s{}".format(number), "ls", text="a" * 4000, error=True)
        self.start_session(lane, "claude-code", steps + [{"exit": 0}])
        self.wait_event("lane.ended", lane)
        slow = self.ended_by_itself(lane)["records"][1]
        self.scan(lane)
        scanning = subprocess.Popen([str(self.command), "lane", "scan", "--config", "alpha", "--lane", lane],
                                    env=self.env("alpha"), cwd=str(self.directory), stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
        time.sleep(2)
        os.unlink(slow)
        quick = self.scan(lane)
        self.assertIn(("missing", slow), [(item["reason"], item.get("path")) for item in quick["not_covered"]])
        out, err = scanning.communicate(timeout=120)
        self.assertEqual(scanning.returncode, 0, err)
        coverage = self.coverage(lane)
        self.assertIn(("missing", slow), [(item["reason"], item.get("path")) for item in coverage["not_covered"]])
        self.assertIs(coverage["covered"], False)
        self.assert_sound()

    def test_second_scan_appends_nothing(self):
        lane = "f-missed"
        steps = [{"open": {}}, {"mark": "opened"}, {"wait": "go"}] + refused_steps("claude-code")
        steps += shell_steps("c2", "printf 'x\\n' > notes/plan.md") + [{"exit": 0}]
        self.start_session(lane, "claude-code", steps)
        self.marked(lane, "opened")
        self.kill_supervisor(lane)
        self.go(lane)
        self.ended_by_itself(lane)
        self.lane_json("check")
        first = self.scan(lane)
        self.assertEqual(first["appended"], {"refusals": 1, "suspicions": 1})
        count = len(self.events())
        second = self.scan(lane)
        self.assertEqual(second["appended"], {"refusals": 0, "suspicions": 0})
        self.assertEqual(second["recorded"], {"refusals": 1, "suspicions": 1})
        self.assertEqual(len(self.events()), count)
        self.assertEqual(first["runs"][0]["run"], 1)
        self.assertIs(first["runs"][0]["covered"], True)
        self.assert_sound()
