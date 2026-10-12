"""E. lane resume continues the same lane in the same directory with the runner's resume template, after a limit, a
dropped stream, a timeout or a stop; the log is appended and a follow-up message arrives rendered as a file."""

import os
from pathlib import Path

from . import lanesupport, support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


MESSAGE = "# Follow-up\n\nThe account changed; carry on from where you stopped.\n"


class LaneResumeTest(lanesupport.LaneTest):
    def first_run(self, lane, *arguments):
        self.start(lane, *arguments)
        ended = self.wait_event("lane.ended", lane, run=1)
        started = self.wait_event("lane.started", lane, run=1)["payload"]
        log = Path(started["log"]).read_bytes()
        self.assertTrue(log)
        return started, ended, log

    def check_second_run(self, lane, first, log, account):
        started = self.wait_event("lane.started", lane, run=2)["payload"]
        ended = self.wait_event("lane.ended", lane, run=2)["payload"]
        self.assertEqual((started["how"], started["run"], ended["reason"], ended["exit_code"]),
                         ("resume", 2, "exit", 0))
        self.assertEqual(started["worktree"], first["worktree"])
        self.assertEqual(started["log"], first["log"])
        self.assertEqual(started["account"], account)
        record = self.record(lane, run=2, ended=True)
        self.assertEqual(os.path.realpath(record["cwd"]), os.path.realpath(first["worktree"]))
        self.assertEqual(record["argv"][:2], ["ok", "resumed"])
        self.assertEqual(record["environment"]["LANEBOSS_RUN"], "2")
        appended = Path(first["log"]).read_bytes()
        self.assertTrue(appended.startswith(log), "the first run's output is still the prefix of the log")
        self.assertIn("standin: ok {} run 2".format(lane).encode("utf-8"), appended[len(log):])
        lane_row = self.status(lane)
        self.assertEqual((lane_row["run"], lane_row["resumes"], lane_row["running"], lane_row["account"]),
                         (2, 1, False, account))
        return started, record

    def test_resume_after_limit(self):
        first, ended, log = self.first_run("web-e1", "--project", "web", "--runner", "limit", "--model", "lim-model-1")
        self.assertEqual((ended["payload"]["reason"], first["account"]), ("limit", "acc-two"))
        message = self.directory / "follow-up.md"
        message.write_text(MESSAGE, encoding="utf-8")
        resumed = self.lane_json("resume", "--lane", "web-e1", "--account", "acc-three", "--message", message)
        self.assertEqual((resumed["run"], resumed["account"]), (2, "acc-three"))
        started, record = self.check_second_run("web-e1", first, log, "acc-three")
        self.assertEqual(started["chosen_by"]["account"], "supervisor")
        event = self.wait_event("lane.resumed", "web-e1")
        self.assertLess(event["seq"], self.wait_event("lane.started", "web-e1", run=2)["seq"])
        self.assertEqual((event["payload"]["run"], event["payload"]["after"]), (2, "limit"))
        rendered = Path(event["payload"]["message"]["path"])
        self.assertEqual(record["message"]["path"], str(rendered))
        text = record["message"]["text"]
        self.assertTrue(text.startswith(MESSAGE))
        self.assertIn("<!-- laneboss launcher block: begin (protocol ", text)
        self.assertEqual(support.digest(rendered.read_bytes()), event["payload"]["message"]["sha256"])
        self.assertEqual(record["argv"], ["ok", "resumed", "--lane", "web-e1", "--brief", first["brief"]["path"],
                                          "--message", str(rendered), "--account", "acc-three"])
        self.assert_sound()

    def test_resume_after_other_ends(self):
        first, ended, log = self.first_run("e-dropped", "--runner", "dropped", "--model", "drop-model-1", "--worktree",
                                           self.scratch("e-dropped"))
        self.assertEqual(ended["payload"]["reason"], "dropped")
        resumed = self.lane_json("resume", "--lane", "e-dropped")
        self.assertEqual(resumed["run"], 2)
        _, record = self.check_second_run("e-dropped", first, log, None)
        # Without --message the runner still gets a rendered follow-up file.
        self.assertIn("<!-- laneboss launcher block: begin", record["message"]["text"])

        first, ended, log = self.first_run("e-timeout", "--runner", "stubborn", "--model", "stub-model-1",
                                           "--worktree", self.scratch("e-timeout"), "--budget", "0.05")
        self.assertEqual(ended["payload"]["reason"], "timeout")
        self.lane_json("resume", "--lane", "e-timeout", "--budget", "1")
        started, _ = self.check_second_run("e-timeout", first, log, None)
        self.assertEqual(started["budget_minutes"], 1)

        self.start("e-stop", "--runner", "forever", "--model", "ever-model-1", "--worktree", self.scratch("e-stop"))
        self.record("e-stop")
        result = self.lane("resume", "--lane", "e-stop", code=2)
        self.assertIn("running", result.stderr)
        self.assertEqual(self.lane_events("e-stop", "lane.resumed"), [])
        self.lane_json("stop", "--lane", "e-stop")
        first = self.wait_event("lane.started", "e-stop", run=1)["payload"]
        self.assertEqual(self.wait_event("lane.ended", "e-stop", run=1)["payload"]["reason"], "stopped")
        log = Path(first["log"]).read_bytes()
        self.lane_json("resume", "--lane", "e-stop", "--account", "acc-three")
        self.check_second_run("e-stop", first, log, "acc-three")
        self.assert_sound()

    def test_resume_refusals(self):
        self.lane("resume", "--lane", "e-unknown", code=2)
        self.start("e-plain", "--runner", "plain", "--model", "plain-model-1", "--worktree", self.scratch("e-plain"))
        self.wait_event("lane.ended", "e-plain")
        message = self.directory / "unused.md"
        message.write_text(MESSAGE, encoding="utf-8")
        # The plain runner's resume template has no {message}: a message would be dropped, so it is refused.
        result = self.lane("resume", "--lane", "e-plain", "--message", message, code=2)
        self.assertIn("message", result.stderr)
        self.lane("resume", "--lane", "e-plain", "--account", "acc-two", code=2)
        self.assertEqual(self.lane_events("e-plain", "lane.resumed"), [])
        self.lane_json("resume", "--lane", "e-plain")
        self.assertEqual(self.wait_event("lane.ended", "e-plain", run=2)["payload"]["reason"], "exit")
        self.assert_sound()
