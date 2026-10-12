"""A. lane start: returns at once, hands the runner the rendered brief as a file, and the supervising process reports
the run through events that a subscriber sees as they happen."""

import json
import os
from pathlib import Path
import time

from . import lanesupport, support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


BRIEF = "# Brief: say hello\n\nSay hello from the stand-in.\nNon-ASCII stays: é中\n"


class LaneStartTest(lanesupport.LaneTest):
    def test_start_runs_the_rendered_brief(self):
        repo = self.repos["alpha"]
        before = (self.git(repo, "rev-parse", "--abbrev-ref", "HEAD"), self.git(repo, "rev-parse", "HEAD"),
                  sorted(path.name for path in repo.iterdir()))
        follower = self.follow()
        began = time.monotonic()
        started = self.start("web-a1", "--project", "web", "--difficulty", "review", text=BRIEF)
        returned = time.monotonic()
        # It returned at once: the stand-in naps for two seconds and has not ended yet.
        self.assertLess(returned - began, 30)
        self.assertEqual(self.lane_events("web-a1", "lane.ended"), [])
        self.assertEqual((started["lane"], started["run"], started["how"]), ("web-a1", 1, "start"))
        self.assertEqual((started["runner"], started["model"], started["effort"], started["account"]),
                         ("nap", "review-model-6", None, "acc-two"))

        arrived_start, start_event = follower.wait(self, "lane.started", "web-a1")
        arrived_end, end_event = follower.wait(self, "lane.ended", "web-a1")
        record = self.record("web-a1", ended=True)
        self.assertLessEqual(abs(arrived_start - record["started"]), 2.0)
        self.assertLessEqual(arrived_end - record["ended"], 2.0)
        self.assertGreaterEqual(arrived_end, record["ended"] - 0.5)
        self.assertEqual(start_event["seq"], started["event"]["seq"])
        self.assertLess(start_event["seq"], end_event["seq"])
        self.assertEqual((end_event["payload"]["run"], end_event["payload"]["reason"],
                          end_event["payload"]["exit_code"], end_event["payload"]["signal"]), (1, "exit", 0, None))
        self.assertGreaterEqual(end_event["payload"]["duration_seconds"], 1.5)

        payload = start_event["payload"]
        for key in ("runner", "model", "effort", "account", "worktree", "branch", "log", "brief", "budget_minutes"):
            self.assertEqual(payload[key], started[key], key)
        self.assertEqual(payload["chosen_by"], {"runner": "routing", "model": "routing", "effort": None,
                                                "account": "default"})
        self.assertEqual((payload["difficulty"], payload["project"], payload["budget_minutes"]), ("review", "web", 30))
        # The runner was given the rendered brief as a file: the input bytes, then the launcher block.
        brief_path = Path(payload["brief"]["path"])
        self.assertTrue(brief_path.is_absolute())
        rendered = brief_path.read_bytes()
        self.assertEqual(support.digest(rendered), payload["brief"]["sha256"])
        self.assertTrue(rendered.startswith(BRIEF.encode("utf-8")))
        block = rendered[len(BRIEF.encode("utf-8")):].decode("utf-8")
        self.assertIn("<!-- laneboss launcher block: begin (protocol ", block)
        self.assertIn(support.PROTOCOL_FILE.read_text(encoding="utf-8"), block)
        self.assertIn("Lane: web-a1", block)
        self.assertEqual(record["brief"]["path"], str(brief_path))
        self.assertEqual(record["brief"]["text"].encode("utf-8"), rendered)
        # Every placeholder was filled with the run's own values.
        worktree = Path(payload["worktree"])
        self.assertEqual(record["argv"], ["nap", "--lane", "web-a1", "--brief", str(brief_path), "--model",
                                          "review-model-6", "--account", "acc-two", "--log", payload["log"],
                                          "--worktree", str(worktree), "--project", "web"])
        self.assertEqual(os.path.realpath(record["cwd"]), os.path.realpath(str(worktree)))
        self.assertEqual(record["environment"]["LANEBOSS_CONFIG"], "alpha")
        self.assertEqual(record["environment"]["LANEBOSS_LANE"], "web-a1")
        self.assertEqual(record["environment"]["LANEBOSS_RUN"], "1")
        self.assertEqual(record["environment"]["E2E_MARKER"], "set-by-the-caller")
        self.assertIsNone(record["environment"]["TMUX"])
        # The log holds the runner's output.
        log = Path(payload["log"]).read_text(encoding="utf-8")
        self.assertIn("standin: nap web-a1 run 1", log)
        self.assertIn("standin: nap over", log)
        # The worktree is new, carries the lane name and is on a branch named after the lane.
        self.assertIn("web-a1", worktree.name)
        self.assertTrue(worktree.is_dir())
        self.assertEqual(payload["branch"], "web-a1")
        self.assertEqual(self.git(worktree, "rev-parse", "--abbrev-ref", "HEAD"), "web-a1")
        self.assertEqual(payload["base"], before[1])
        # The repository's main working copy is untouched.
        self.assertEqual((self.git(repo, "rev-parse", "--abbrev-ref", "HEAD"), self.git(repo, "rev-parse", "HEAD"),
                          sorted(path.name for path in repo.iterdir())), before)
        self.assertEqual(self.git(repo, "status", "--porcelain"), "")
        lane = self.status("web-a1")
        self.assertEqual((lane["state"], lane["run"], lane["running"], lane["reason"], lane["exit_code"]),
                         ("verifying", 1, False, "exit", 0))
        self.assertEqual((lane["runner"], lane["model"], lane["account"], lane["resumes"], lane["lost"]),
                         ("nap", "review-model-6", "acc-two", 0, 0))
        self.assert_sound()

    def test_tail_filters_a_lane_and_stops(self):
        self.start("web-a2", "--project", "web", "--difficulty", "standard")
        self.start("web-a3", "--project", "web", "--difficulty", "standard")
        self.wait_event("lane.ended", "web-a2")
        self.wait_event("lane.ended", "web-a3")
        lines = self.run_laneboss("event", "tail", "--config", "alpha", "--lane", "web-a3", "--follow", "--until",
                                  "lane.ended", environment=self.env("alpha")).stdout.splitlines()
        events = [json.loads(line) for line in lines]
        self.assertEqual([item["lane"] for item in events], ["web-a3"] * len(events))
        self.assertEqual([item["kind"] for item in events], ["brief.rendered", "lane.started", "lane.ended"])
        self.run_laneboss("event", "tail", "--config", "alpha", "--until", "Not A Kind", code=2,
                          environment=self.env("alpha"))
        self.assert_sound()
