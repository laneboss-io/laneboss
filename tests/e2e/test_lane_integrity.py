"""I. Lane events are checked at append, whoever appends them, and nothing that looks like a credential reaches an
event: the log may hold a runner's output, events never quote it."""

from contextlib import closing
import json
from pathlib import Path
import sqlite3

from . import lanesupport, support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class LaneIntegrityTest(lanesupport.LaneTest):
    def hand(self, kind, lane, payload, code):
        return self.append(self.event(kind, lane=lane, payload=payload), code=code)

    def test_malformed_lane_events_are_refused(self):
        self.start("i-ran", "--runner", "plain", "--model", "plain-model-1", "--worktree", self.scratch("i-ran"))
        ended = self.wait_event("lane.ended", "i-ran")
        started = self.wait_event("lane.started", "i-ran")
        count = len(self.events())
        good_end = dict(ended["payload"])
        cases = [
            ("started without a payload", "lane.started", "i-new", {}),
            ("started with an alias model", "lane.started", "i-new", dict(started["payload"], model="alias")),
            ("started with an unknown field", "lane.started", "i-new", dict(started["payload"], colour="red")),
            ("started that skips a run", "lane.started", "i-ran", dict(started["payload"], run=3, how="resume")),
            ("start of a lane that has run", "lane.started", "i-ran", dict(started["payload"], run=2)),
            ("ended with an unknown reason", "lane.ended", "i-ran", dict(good_end, reason="finished")),
            ("ended with an exit code and a signal", "lane.ended", "i-ran", dict(good_end, signal=9)),
            ("ended of a lane that is not running", "lane.ended", "i-ran", good_end),
            ("stuck of a lane that is not running", "lane.stuck", "i-ran",
             {"run": 1, "quiet_seconds": 5, "output_bytes": 0}),
            ("stuck with a missing field", "lane.stuck", "i-ran", {"run": 1}),
            ("timeout with a negative budget", "lane.timeout", "i-ran",
             {"run": 1, "budget_minutes": -1, "elapsed_seconds": 1}),
            ("lost of a lane that is not running", "lane.lost", "i-ran", {"run": 1, "survivors": 0}),
            ("resumed as run one", "lane.resumed", "i-ran", {"run": 1, "after": "exit", "message": None}),
            ("cleaned before merged or abandoned", "lane.cleaned", "i-ran", {"removed": [], "kept": []}),
            ("state with another field", "lane.state", "i-ran", {"state": "accepted", "note": "x"}),
            ("landing with a payload", "lane.merged", "i-ran", {"by": "someone"}),
            ("planned with a payload", "lane.planned", "i-new", {"when": "later"}),
            ("an unknown lane kind", "lane.finished", "i-ran", {}),
        ]
        for label, kind, lane, payload in cases:
            with self.subTest(label):
                result = self.hand(kind, lane, payload, code=2)
                self.assertTrue(result.stderr.startswith("refused:"), result.stderr)
        self.assertEqual(len(self.events()), count)
        # The kinds a supervisor writes by hand are still accepted with their documented payloads.
        self.hand("lane.planned", "i-planned", {}, code=0)
        self.hand("lane.state", "i-ran", {"state": "accepted"}, code=0)
        self.hand("lane.deployed", "i-ran", {}, code=0)
        self.assertEqual(len(self.events()), count + 3)
        # A planned lane has not run, so starting it is not a reuse.
        self.start("i-planned", "--runner", "plain", "--model", "plain-model-1", "--worktree",
                   self.scratch("i-planned"))
        self.assertEqual(self.wait_event("lane.started", "i-planned")["payload"]["run"], 1)
        self.wait_event("lane.ended", "i-planned")
        self.assert_sound()

    def test_earlier_rows_need_a_rebuild(self):
        self.start("i-old", "--runner", "plain", "--model", "plain-model-1", "--worktree", self.scratch("i-old"))
        self.wait_event("lane.ended", "i-old")
        listing = self.run_laneboss("state", "lanes", "--config", "alpha", environment=self.env("alpha")).stdout
        # The row as version 0.2.0 kept it: fewer times and none of the run's fields.
        earlier = {"lane": "i-old", "state": "verifying", "state_at": None, "events": 2, "last_seq": 3,
                   "times": {name: None for name in ("planned", "started", "ended", "timeout", "stuck")},
                   "landing": {"merged": None, "deployed": None, "landed": None}}
        store = Path(self.laneboss_json("config", "path", "alpha")["store"])
        with closing(sqlite3.connect(str(store))) as connection:
            connection.execute("UPDATE lanes SET projection = ? WHERE lane = 'i-old'", (json.dumps(earlier),))
            connection.commit()
        self.assertIn("state rebuild", self.lane("status", "--lane", "i-old", code=3).stderr)
        self.assertIn("state rebuild", self.hand("lane.state", "i-old", {"state": "accepted"}, code=3).stderr)
        self.assertEqual(self.run_laneboss("state", "rebuild", "--config", "alpha",
                                           environment=self.env("alpha")).stdout, listing)
        self.assertEqual(self.status("i-old")["reason"], "exit")
        self.assert_sound()

    def test_credentials_never_reach_an_event(self):
        follower = self.follow()
        self.start("i-secret", "--runner", "secret", "--model", "secret-model-1", "--worktree",
                   self.scratch("i-secret"))
        _, ended = follower.wait(self, "lane.ended", "i-secret")
        self.assertEqual(ended["payload"]["reason"], "limit")
        record = self.record("i-secret", ended=True)
        secret = record["secret"]
        started = self.wait_event("lane.started", "i-secret")["payload"]
        self.assertIn(secret, Path(started["log"]).read_text(encoding="utf-8"))
        everything = self.run_laneboss("state", "events", "--config", "alpha", environment=self.env("alpha")).stdout
        self.assertNotIn(secret, everything)
        self.assertNotIn(secret, json.dumps([event for _, event in follower.seen]))
        # A value that looks like a credential in the runner's arguments (here, the working directory's name) is
        # refused before anything starts, and the refusal does not repeat it.
        value = "Zx81-Qw72" + "-Lm55-Np09"
        directory = self.scratch("password=" + value)
        result = self.start("i-arg", "--runner", "plain", "--model", "plain-model-1", "--worktree", directory, code=2)
        self.assertNotIn(value, result.stdout + result.stderr)
        self.assertEqual(self.lane_events("i-arg"), [])
        self.assertFalse((self.records["alpha"] / "i-arg.1.json").exists())
        self.assertNotIn(value, self.run_laneboss("state", "events", "--config", "alpha",
                                                  environment=self.env("alpha")).stdout)
        self.assert_sound()
