"""Refusals G. What a scan covers: a record that cannot be read and a record in a format the launcher does not recognise
are reported as not covered, never taken for "no refusals"; a record of another working directory and a record written
before the run are not the run's; unknown lines are skipped and counted. lane refusals shows what was not covered."""

import json
import os
import time

from . import refusalsupport, support
from .refusalsupport import refused_steps


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class CoverageTest(refusalsupport.RefusalTest):
    def test_what_is_covered(self):
        if os.geteuid() == 0:
            self.fail("run the suite as a non-root user: root ignores file modes")
        lane = "g-cover"
        directory = self.scratch(lane)
        (directory / "notes").mkdir()
        elsewhere = self.scratch("g-elsewhere")
        # A record of this working directory written before the run, holding a refusal.
        slug = "".join(character if character.isalnum() else "-" for character in str(directory))
        old = self.user_home / ".claude" / "projects" / slug / "before.jsonl"
        old.parent.mkdir(parents=True)
        lines = [{"type": "assistant", "timestamp": "2026-01-02T03:04:05.000Z", "cwd": str(directory),
                  "message": {"content": [{"type": "tool_use", "id": "old-1", "name": "Bash",
                                           "input": {"command": "echo old > notes/old.md"}}]}},
                 {"type": "user", "timestamp": "2026-01-02T03:04:06.000Z", "cwd": str(directory),
                  "message": {"content": [{"type": "tool_result", "tool_use_id": "old-1", "is_error": True,
                                           "content": refusalsupport.hook("old")}]}}]
        old.write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")
        os.utime(str(old), (1767323045, 1767323045))
        steps = [
            # Another working directory's record, with a refusal: not this lane's.
            {"open": {"cwd": str(elsewhere)}}] + refused_steps("claude-code", "e1") + [
            # A record in a shape the launcher does not know.
            {"open": {}}, {"raw": json.dumps({"kind": "turn", "version": 9, "text": "a newer format"})},
            {"raw": json.dumps({"kind": "turn", "version": 9, "text": "still newer"})},
            # A record that cannot be read.
            {"open": {}}] + refusalsupport.shell_steps("u1", "ls") + [{"chmod": 0},
            # The main record: unknown lines are skipped and counted, the refusal is found.
            {"open": {}}, {"raw": "this line is not JSON"}, {"raw": json.dumps([1, 2, 3])},
            {"raw": json.dumps({"no_type": True})}, {"raw": json.dumps({"type": "telemetry", "cwd": str(directory)})},
        ] + refused_steps("claude-code", "m1") + [{"exit": 0}]
        self.scenario(lane, steps)
        self.start(lane, "--runner", "claude", "--model", "session-model-1", "--worktree", directory)
        self.wait_event("lane.ended", lane)
        record = self.ended_by_itself(lane)
        other, newer, unreadable, main = record["records"]
        self.addCleanup(os.chmod, unreadable, 0o600)
        refusals = self.kind_events(lane, "lane.refusal")
        self.assertEqual([item["payload"]["call"]["id"] for item in refusals], ["m1"])
        self.assertEqual(refusals[0]["payload"]["record"]["path"], main)
        for listed in (self.refusals(lane), self.scan(lane)):
            coverage = (listed["coverage"] if "coverage" in listed else listed["runs"])[0]
            self.assertEqual((coverage["run"], coverage["complete"], coverage["covered"]), (1, True, False))
            self.assertEqual(sorted((item["reason"], item.get("path")) for item in coverage["not_covered"]),
                             sorted([("unreadable", unreadable), ("unrecognised", newer)]))
            records = {item["path"]: item for item in coverage["records"]}
            self.assertEqual(sorted(records), sorted([main, newer, unreadable]))
            self.assertEqual(records[main]["state"], "covered")
            self.assertEqual((records[main]["unknown_lines"], records[main]["other_lines"]), (3, 1))
            self.assertEqual(records[unreadable]["state"], "unreadable")
            self.assertEqual(records[newer]["state"], "unrecognised")
            self.assertNotIn(other, records)
            self.assertNotIn(str(old), records)
            self.assertGreaterEqual(coverage["skipped"]["other_directory"], 1)
            self.assertGreaterEqual(coverage["skipped"]["before_run"], 1)
        listed = self.refusals(lane)
        self.assertEqual(sorted((item["run"], item["reason"]) for item in listed["not_covered"]),
                         [(1, "unreadable"), (1, "unrecognised")])
        # What was not covered holds up accepted and merged, naming it, until the supervisor accepts it explicitly;
        # then the decision records it.
        for state in ("accepted", "merged"):
            result = self.lane("mark", "--lane", lane, "--state", state, code=2)
            self.assertIn(unreadable, result.stderr)
            self.assertIn(newer, result.stderr)
        self.lane("mark", "--lane", lane, "--state", "verifying", "--accept-uncovered", code=2)
        self.assertEqual(self.lane_events(lane, "lane.state"), [])
        marked = self.lane_json("mark", "--lane", lane, "--state", "accepted", "--accept-uncovered")
        self.assertEqual(sorted(item["reason"] for item in marked["scan"]["not_covered"]), ["unreadable", "unrecognised"])
        state = self.lane_events(lane, "lane.state")[0]["payload"]
        self.assertEqual(state["state"], "accepted")
        self.assertEqual(sorted((item["run"], item["reason"], item["path"]) for item in state["not_covered"]),
                         sorted([(1, "unreadable", unreadable), (1, "unrecognised", newer)]))
        self.assert_sound()

    def test_unreadable_peer_blocks_acceptance(self):
        # A healthy file under the same template must never stand in for an
        # unreadable record. Create the peer after the live scanner is gone so
        # no previous inventory can supply its ownership to a fresh scan.
        if os.geteuid() == 0:
            self.fail("run the suite as a non-root user: root ignores file modes")
        lane = "g-unreadable-peer"
        self.start_session(lane, "claude-code", [{"open": {}}]
                           + refusalsupport.shell_steps("readable", "ls") + [{"exit": 0}])
        self.wait_event("lane.ended", lane)
        main = self.ended_by_itself(lane)["records"][0]
        self.assertIs(self.scan(lane)["runs"][0]["covered"], True)
        peer = os.path.join(os.path.dirname(main), "unreadable-peer.jsonl")
        with open(main, "rb") as source, open(peer, "wb") as destination:
            destination.write(source.read())
        stamp = os.stat(main).st_mtime
        os.utime(peer, (stamp, stamp))
        os.chmod(peer, 0)
        self.addCleanup(os.chmod, peer, 0o600)
        for state in ("accepted", "merged"):
            result = self.lane("mark", "--lane", lane, "--state", state, code=2)
            self.assertIn(peer, result.stderr)
        self.assertEqual(self.lane_events(lane, "lane.state"), [])
        for coverage in (self.coverage(lane), self.scan(lane)["runs"][0]):
            self.assertIs(coverage["covered"], False)
            self.assertIn(("unreadable", peer),
                          [(item["reason"], item.get("path")) for item in coverage["not_covered"]])
        self.assert_sound()

    def test_slow_matching_is_bounded(self):
        # A guard pattern that passes validation but backtracks without end on a long line: matching that result stops
        # at its bound and the result is reported as not covered; the refusal after it is still found.
        config = self.home / "configs" / "alpha" / "config.toml"
        config.write_text(config.read_text(encoding="utf-8")
                          + "\n[[guards]]\nname = \"slow\"\npattern = '^a.*.*.*.*.*.*.*b'\n", encoding="utf-8")
        steps = [{"open": {}}] + refusalsupport.shell_steps("s1", "ls", text="a" * 4000, error=True)
        steps += refused_steps("claude-code", "s2") + [{"exit": 0}]
        self.start_session("g-slow", "claude-code", steps)
        self.wait_event("lane.ended", "g-slow")
        self.assertEqual([item["payload"]["call"]["id"] for item in self.kind_events("g-slow", "lane.refusal")], ["s2"])
        coverage = self.refusals("g-slow")["coverage"][0]
        self.assertEqual([item["reason"] for item in coverage["not_covered"]], ["timed-out"])
        self.assertEqual(coverage["records"][0]["timed_out"], 1)
        scanned = self.scan("g-slow")
        self.assertEqual([item["reason"] for item in scanned["not_covered"]], ["timed-out"])
        self.assertEqual(scanned["appended"], {"refusals": 0, "suspicions": 0})
        self.lane("mark", "--lane", "g-slow", "--state", "accepted", code=2)
        # The load-time check is a partial rule: an ambiguous alternation passes it, and the alarm is the bound.
        config.write_text(config.read_text(encoding="utf-8").replace("'^a.*.*.*.*.*.*.*b'", "'^(a|aa)+$'"),
                          encoding="utf-8")
        self.run_laneboss("config", "validate", "alpha", environment=self.env("alpha"))
        steps = [{"open": {}}] + refusalsupport.shell_steps("s3", "ls", text="a" * 60 + "!", error=True)
        self.start_session("g-slow2", "claude-code", steps + [{"exit": 0}])
        self.wait_event("lane.ended", "g-slow2")
        coverage = self.coverage("g-slow2")
        self.assertEqual(self.reasons(coverage), ["timed-out"])
        self.assertIs(coverage["covered"], False)
        self.assert_sound()

    def test_cuts_are_counted(self):
        # Decision 3: a result longer than the bound is matched on its first and its last 64 KiB, a line on its first
        # 4096 characters. A refusal just after 64 KiB of a 100 KiB result is found, by the tail; one in the middle of
        # 300 KiB is not, and the record counts the cut; a cut alone does not make the run uncovered. Fix round 2,
        # decision 7: the tail starts at the first line that begins inside it, so the end of a long line that looks
        # like a guard's message is not one (t5), and a long line inside both windows is counted once (t4).
        filler = "x" * 99 + "\n"
        fragment = refusalsupport.hook("fragment").splitlines()[0]
        steps = [{"open": {}}]
        steps += refusalsupport.shell_steps("t1", "make", text=filler * 655 + refusalsupport.hook("tail") + "\n"
                                            + filler * 360, error=True)
        steps += refusalsupport.shell_steps("t2", "make", text=filler * 1500 + refusalsupport.hook("middle") + "\n"
                                            + filler * 1500, error=True)
        steps += refusalsupport.shell_steps("t3", "make", text="y" * 5000, error=True)
        steps += refusalsupport.shell_steps("t4", "make", text=filler * 400 + "w" * 6000 + "\n" + filler * 300,
                                            error=True)
        steps += refusalsupport.shell_steps("t5", "make", text="v" * 70000 + fragment + "z" * (65536 - len(fragment)),
                                            error=True) + [{"exit": 0}]
        self.start_session("g-cut", "claude-code", steps)
        self.wait_event("lane.ended", "g-cut")
        refusals = [item["payload"] for item in self.kind_events("g-cut", "lane.refusal")]
        self.assertEqual([item["call"]["id"] for item in refusals], ["t1"])
        self.assertIn("tail", refusals[0]["message"]["text"])
        for coverage in (self.coverage("g-cut"), self.scan("g-cut")["runs"][0]):
            record = coverage["records"][0]
            self.assertEqual((record["cut_results"], record["cut_lines"]), (2, 3))
            self.assertEqual((coverage["covered"], coverage["not_covered"]), (True, []))
        self.assert_sound()

    def test_unknown_block_is_not_covered(self):
        # Decision 3: an assistant or user line holding a block of a type the parser does not know makes the record
        # partly read and the run not covered; marking asks for --accept-uncovered.
        steps = [{"open": {}}, {"block": {"role": "assistant", "type": "hologram"}}]
        steps += refusalsupport.shell_steps("u1", "ls") + [{"exit": 0}]
        self.start_session("g-block", "claude-code", steps)
        self.wait_event("lane.ended", "g-block")
        coverage = self.coverage("g-block")
        self.assertEqual(self.reasons(coverage), ["partly-read"])
        self.assertEqual(coverage["records"][0]["state"], "partly-read")
        result = self.lane("mark", "--lane", "g-block", "--state", "accepted", code=2)
        self.assertIn("--accept-uncovered", result.stderr)
        self.lane_json("mark", "--lane", "g-block", "--state", "accepted", "--accept-uncovered")
        self.assert_sound()

    def test_missing_records_are_not_coverage(self):
        # Decision 4: a configured path that matches no file for a run, a directory that cannot be listed, and a record
        # an earlier scan of the run saw that is gone now are each not coverage.
        self.start_session("g-typo", "claude-code", [{"open": {}}] + refusalsupport.shell_steps("t1", "ls")
                           + [{"exit": 0}], runner="missing")
        self.wait_event("lane.ended", "g-typo")
        coverage = self.coverage("g-typo")
        self.assertEqual((self.reasons(coverage), coverage["covered"]), (["no-record"], False))
        self.lane("mark", "--lane", "g-typo", "--state", "accepted", code=2)

        steps = [{"open": {}}] + refusalsupport.shell_steps("d1", "ls") + [{"open": {}}]
        steps += refusalsupport.shell_steps("d2", "ls") + [{"exit": 0}]
        started = self.start_session("g-gone", "claude-code", steps)
        self.wait_event("lane.ended", "g-gone")
        first, second = self.ended_by_itself("g-gone")["records"]
        self.assertEqual(self.scan("g-gone")["not_covered"], [])
        os.unlink(second)
        coverage = self.scan("g-gone")["runs"][0]
        self.assertEqual([(item["reason"], item["path"]) for item in coverage["not_covered"]], [("missing", second)])
        self.assertIs(coverage["covered"], False)

        directory = os.path.dirname(first)
        os.chmod(directory, 0)
        self.addCleanup(os.chmod, directory, 0o700)
        coverage = self.scan("g-gone")["runs"][0]
        self.assertIn(("unreadable", directory), [(item["reason"], item["path"]) for item in coverage["not_covered"]])
        self.assertIs(coverage["covered"], False)
        self.assertTrue(started["worktree"])
        self.assert_sound()

    def test_attribution_has_an_end(self):
        # Decision 6: a line belongs to a run only from its start to its end plus five seconds. A session another
        # program starts in the directory after the lane ended, and lines written between two runs, are not the lane's;
        # a second session that a hook of the lane's own agent starts while the run lives is.
        lane = "g-window"
        steps = [{"open": {}}] + refusalsupport.shell_steps("w1", "ls") + [{"open": {}}]
        steps += refused_steps("claude-code", "w2") + [{"exit": 0}]
        started = self.start_session(lane, "claude-code", steps)
        self.wait_event("lane.ended", lane, run=1)
        self.assertEqual([item["payload"]["call"]["id"] for item in self.kind_events(lane, "lane.refusal")], ["w2"])
        time.sleep(6)
        refusalsupport.write_session(self.user_home, started["worktree"], "between")
        self.scenario(lane, [{"open": {}}] + refusalsupport.shell_steps("w3", "ls") + [{"exit": 0}], run=2)
        self.lane_json("resume", "--lane", lane)
        self.wait_event("lane.ended", lane, run=2)
        self.lane_json("mark", "--lane", lane, "--state", "abandoned")
        time.sleep(6)
        refusalsupport.write_session(self.user_home, started["worktree"], "newcomer")
        scanned = self.scan(lane)
        self.assertEqual(scanned["appended"], {"refusals": 0, "suspicions": 0})
        self.assertEqual([item["payload"]["call"]["id"] for item in self.kind_events(lane, "lane.refusal")], ["w2"])
        self.assertGreaterEqual(sum(item["outside_runs"] for coverage in scanned["runs"]
                                    for item in coverage["records"]), 4)
        self.assert_sound()

    def test_records_stay_out_of_homes(self):
        # Decision 7: a record whose real path is inside a configuration or state directory of the launcher is refused,
        # however it was reached; a placeholder value that holds a path component makes its template unusable.
        self.add_config("beta")
        home = self.user_home
        lane = "g-zone"
        steps = [{"open": {"dir": "linked"}}] + refusalsupport.shell_steps("z1", "ls")
        steps += [{"mark": "opened"}, {"wait": "go"}, {"exit": 0}]
        self.start_session(lane, "claude-code", steps, runner="linked")
        self.marked(lane, "opened")
        beta = self.start_session("g-foreign", "text", refused_steps("text") + [{"exit": 0}], config="beta")
        self.wait_event("lane.ended", "g-foreign", config="beta")
        os.symlink(beta["log"], str(home / "linked" / "evil.jsonl"))
        self.go(lane)
        self.wait_event("lane.ended", lane)
        for coverage in (self.coverage(lane), self.scan(lane)["runs"][0]):
            self.assertIn(("refused-zone", str(home / "linked" / "evil.jsonl")),
                          [(item["reason"], item["path"]) for item in coverage["not_covered"]])
        self.assertEqual(self.kind_events(lane, "lane.refusal"), [])

        (home / "records" / "v1").mkdir(parents=True)
        steps = [{"open": {"dir": "other"}}] + refused_steps("claude-code", "o1") + [{"exit": 0}]
        self.start_session("g-model", "claude-code", steps, runner="modelled", model="v1/../../other")
        self.wait_event("lane.ended", "g-model")
        coverage = self.coverage("g-model")
        self.assertIn("bad-placeholder", self.reasons(coverage))
        self.assertIs(coverage["covered"], False)
        self.assertEqual(self.kind_events("g-model", "lane.refusal"), [])
        self.assert_sound()

    def test_no_record_is_not_covered(self):
        # A run whose runner writes no session record at all is not covered.
        self.start_session("g-none", "claude-code", [{"exit": 0}])
        self.wait_event("lane.ended", "g-none")
        coverage = self.refusals("g-none")["coverage"][0]
        self.assertEqual((coverage["complete"], coverage["covered"]), (True, False))
        self.assertEqual([item["reason"] for item in coverage["not_covered"]], ["no-record"])
        self.assert_sound()

    def test_runner_without_records(self):
        # A runner without record templates is not scanned: nothing is reported missing, and marking is not held up.
        self.start("g-plain", "--runner", "plain", "--model", "plain-model-1", "--worktree", self.scratch("g-plain"))
        self.wait_event("lane.ended", "g-plain")
        coverage = self.refusals("g-plain")["coverage"][0]
        self.assertEqual((coverage["configured"], coverage["covered"], coverage["not_covered"]), (False, False, []))
        self.assertEqual(self.lane_json("mark", "--lane", "g-plain", "--state", "merged")["state"], "merged")
        self.assert_sound()

    def test_recursive_discovery_follows_links(self):
        # Fix round 2, decision 4: a recursive template follows a link to a directory, and a link back up ends, so the
        # record behind the link is read; a clean record elsewhere under the template does not stand in for it.
        deep = self.user_home / "deep"
        (deep / "plain").mkdir(parents=True)
        os.symlink(str(self.user_home / ".claude"), str(deep / "linked"))
        os.symlink(str(deep), str(deep / "plain" / "loop"))
        steps = [{"open": {"dir": "deep/plain"}}] + refusalsupport.shell_steps("p1", "ls")
        steps += [{"open": {}}] + refused_steps("claude-code", "l1") + [{"exit": 0}]
        self.start_session("g-deep", "claude-code", steps, runner="deep")
        self.wait_event("lane.ended", "g-deep")
        self.assertEqual([item["payload"]["call"]["id"] for item in self.kind_events("g-deep", "lane.refusal")], ["l1"])
        self.assertIs(self.coverage("g-deep")["covered"], True)
        self.assertEqual(self.scan("g-deep")["appended"], {"refusals": 0, "suspicions": 0})
        self.assert_sound()

    def test_discovery_bound_is_reported(self):
        # Fix round 2, decision 4: more candidate directories than the bound (10,000) make the run not covered
        # (too-many-records), although the records kept are clean and the refusal lies past the bound.
        many = self.user_home / "deep" / "many"
        for number in range(10001):
            (many / "d{:05d}".format(number)).mkdir(parents=True)
        steps = [{"open": {"dir": "deep/a-plain"}}] + refusalsupport.shell_steps("p1", "ls")
        steps += [{"open": {"dir": "deep/zz/sub"}}] + refused_steps("claude-code", "z1") + [{"exit": 0}]
        self.start_session("g-many", "claude-code", steps, runner="deep")
        self.wait_event("lane.ended", "g-many")
        for coverage in (self.coverage("g-many"), self.scan("g-many")["runs"][0]):
            self.assertIn("too-many-records", self.reasons(coverage))
            self.assertIs(coverage["covered"], False)
        result = self.lane("mark", "--lane", "g-many", "--state", "accepted", code=2)
        self.assertIn("--accept-uncovered", result.stderr)
        self.assert_sound()

    def test_own_log_is_the_launchers_file(self):
        # Fix round 2, decision 5: the run's own log is opened as the launcher's own file, without following a link. A
        # finished lane's log replaced by a link to another configuration's lane log is refused-zone: nothing of the
        # other log is read.
        self.add_config("beta")
        theirs = self.start_session("g-theirs", "text", refused_steps("text") + [{"exit": 0}], config="beta")
        self.wait_event("lane.ended", "g-theirs", config="beta")
        lane = "g-mine"
        mine = self.start_session(lane, "text", [{"say": "line {}".format(number)} for number in range(20)]
                                  + [{"exit": 0}])
        self.wait_event("lane.ended", lane)
        os.unlink(mine["log"])
        os.symlink(theirs["log"], mine["log"])
        scanned = self.scan(lane)
        self.assertEqual(scanned["appended"], {"refusals": 0, "suspicions": 0})
        self.assertIn(("refused-zone", mine["log"]), [(item["reason"], item["path"]) for item in scanned["not_covered"]])
        self.assertIs(scanned["runs"][0]["covered"], False)
        self.assertEqual(self.kind_events(lane, "lane.refusal"), [])
        self.assert_sound()

    def test_truncated_log_is_not_covered(self):
        # Fix round 3, decision 1: a run's own log shorter than the end of the byte range recorded for the run is
        # truncated: what can still be read is read, and the run is not covered.
        lane = "g-short"
        started = self.start_session(lane, "text", [{"say": "line {}".format(number)} for number in range(40)]
                                     + [{"exit": 0}])
        self.wait_event("lane.ended", lane)
        coverage = self.coverage(lane)
        self.assertGreaterEqual(coverage["records"][0]["lines"], 40)
        self.assertIs(coverage["covered"], True)
        with open(started["log"], "r+b") as handle:
            handle.truncate(20)
        scanned = self.scan(lane)
        self.assertIn(("truncated", started["log"]), [(item["reason"], item["path"]) for item in scanned["not_covered"]])
        self.assertIs(scanned["runs"][0]["covered"], False)
        result = self.lane("mark", "--lane", lane, "--state", "accepted", code=2)
        self.assertIn("--accept-uncovered", result.stderr)
        self.assert_sound()

    def test_later_session_is_not_the_runs(self):
        # Fix round 3, decision 4: a session that begins after an ended run's window, holds only metadata lines, grows
        # and then gets an ordinary message is not that run's record: the run stays covered at every scan.
        lane = "g-later"
        started = self.start_session(lane, "claude-code", [{"open": {}}] + refusalsupport.shell_steps("h1", "ls")
                                     + [{"exit": 0}])
        self.wait_event("lane.ended", lane)
        self.assertIs(self.scan(lane)["runs"][0]["covered"], True)
        later = os.path.join(os.path.dirname(self.ended_by_itself(lane)["records"][0]), "later.jsonl")
        time.sleep(6)
        envelope = {"cwd": str(started["worktree"])}
        lines = [dict(envelope, type="file-history-snapshot"), dict(envelope, type="file-history-snapshot"),
                 dict(envelope, type="user", message={"role": "user", "content": "carry on"})]
        for number, line in enumerate(lines, 1):
            with open(later, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(dict(line, timestamp=refusalsupport.stamp())) + "\n")
            scanned = self.scan(lane)
            self.assertEqual((scanned["runs"][0]["covered"], scanned["not_covered"]), (True, []))
            # Fix round 4, decision 3: its row says it lies outside the run, with its count; it is not in the inventory.
            row = [item for item in scanned["runs"][0]["records"] if item["path"] == later]
            self.assertEqual([(item["state"], item["lines"], item["outside_runs"]) for item in row], [("outside", 0, number)])
        launch = self.kind_events(lane, "lane.started")[0]["payload"]["launch"]
        kept = os.path.join(self.paths("alpha")["state_dir"], "lanes", lane, "scans", launch + ".json")
        with open(kept, encoding="utf-8") as handle:
            self.assertNotIn(os.path.realpath(later), [entry["path"] for entry in json.load(handle)["inventory"]])
        self.assert_sound()

    def test_unfamiliar_lines_are_unrecognised(self):
        # Fix round 2, decision 6: a record is recognised only when an assistant or user line was read with blocks the
        # parser knows. A record whose every line is of another kind (a writer that renamed its line types and kept the
        # envelope) is unrecognised, and the refusal in its body is never taken for "no refusals".
        call = {"message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": "v1", "name": "Bash", "input": {"command": refusalsupport.REFUSED}}]}}
        answer = {"message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "v1", "is_error": True,
             "content": [{"type": "text", "text": refusalsupport.hook("renamed")}]}]}}
        steps = [{"open": {}}, {"line": {"type": "assistant_turn", "body": call}},
                 {"line": {"type": "user_turn", "body": answer}}, {"exit": 0}]
        self.start_session("g-renamed", "claude-code", steps)
        self.wait_event("lane.ended", "g-renamed")
        coverage = self.coverage("g-renamed")
        self.assertEqual(self.reasons(coverage), ["unrecognised"])
        self.assertEqual(coverage["records"][0]["state"], "unrecognised")
        result = self.lane("mark", "--lane", "g-renamed", "--state", "accepted", code=2)
        self.assertIn("--accept-uncovered", result.stderr)
        self.assert_sound()
