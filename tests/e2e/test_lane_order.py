"""Fix round 2, findings 8 and 10 and follow-ups 3 and 4 (ruling R23): a lane's events keep their order, an event the
store refuses is counted as refused and never as recorded, readers of the pending file survive its removal, the last
matching line decides a run's reason, and an account the configuration does not list is never repeated.
"""

import json
import os
from pathlib import Path
import threading
import uuid

from . import lanesupport, support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class LaneOrderTest(lanesupport.LaneTest):
    def test_cleanup_event_keeps_its_place(self):
        self.start("web-q1", "--project", "web", "--runner", "plain", "--model", "plain-model-1")
        self.wait_event("lane.ended", "web-q1")
        self.lane_json("mark", "--lane", "web-q1", "--state", "merged")
        store = Path(self.paths()["store"])
        store.chmod(0o444)
        self.addCleanup(store.chmod, 0o644)
        cleaned = self.lane_json("clean", "--lane", "web-q1")
        self.assertIs(cleaned["pending"], True)
        store.chmod(0o644)
        # The lane is started again while its cleanup event still waits: the cleanup is stored first.
        self.start("web-q1", "--project", "web", "--runner", "plain", "--model", "plain-model-1", "--reuse")
        self.wait_event("lane.ended", "web-q1", run=2)
        cleanup = self.wait_event("lane.cleaned", "web-q1")
        second = self.wait_event("lane.started", "web-q1", run=2)
        self.assertLess(cleanup["seq"], second["seq"])
        live = self.status("web-q1")["live"]
        self.assertEqual((live["pending_events"], live["refused_events"]), (0, 0))
        self.assert_sound()

    def test_refused_events_are_counted(self):
        self.start("q-ref", "--runner", "plain", "--model", "plain-model-1", "--worktree", self.scratch("q-ref"))
        self.wait_event("lane.ended", "q-ref")
        started = self.wait_event("lane.started", "q-ref")
        # A pending event that the lane's life cycle no longer allows: the store refuses it for good.
        envelope = {"id": "ev-" + uuid.uuid4().hex, "kind": "lane.stuck", "lane": "q-ref", "actor": "laneboss",
                    "occurred_at": started["occurred_at"], "protocol_version": started["protocol_version"],
                    "payload": {"run": 7, "quiet_seconds": 5, "output_bytes": 0}}
        pending = Path(self.paths()["state_dir"]) / "lanes" / "q-ref" / "pending.jsonl"
        pending.write_text(json.dumps(envelope) + "\n", encoding="utf-8")
        self.assertEqual(self.status("q-ref")["live"]["pending_events"], 1)
        checked = self.lane_json("check")
        self.assertEqual(checked["recorded"], [])
        self.assertEqual(checked["refused"], [{"lane": "q-ref", "events": 1}])
        live = self.status("q-ref")["live"]
        self.assertEqual((live["pending_events"], live["refused_events"]), (0, 1))
        self.assertEqual(self.lane_events("q-ref", "lane.stuck"), [])
        again = self.lane_json("check")
        self.assertEqual((again["recorded"], again["refused"]), ([], []))
        self.assert_sound()

    def test_pending_reader_survives_removal(self):
        self.start("q-read", "--runner", "plain", "--model", "plain-model-1", "--worktree", self.scratch("q-read"))
        started = self.wait_event("lane.started", "q-read")
        self.wait_event("lane.ended", "q-read")
        directory = Path(self.paths()["state_dir"]) / "lanes" / "q-read"
        source = directory / "e2e-pending-source"
        envelope = {"id": "ev-" + uuid.uuid4().hex, "kind": "lane.stuck", "lane": "q-read", "actor": "laneboss",
                    "occurred_at": started["occurred_at"], "protocol_version": started["protocol_version"],
                    "payload": {"run": 1, "quiet_seconds": 5, "output_bytes": 0}}
        source.write_text(json.dumps(envelope) + "\n", encoding="utf-8")
        target = directory / "pending.jsonl"
        done = threading.Event()

        def toggle():
            # A drainer that appends and removes the pending file over and over.
            while not done.is_set():
                os.link(str(source), str(target))
                os.unlink(str(target))

        toggler = threading.Thread(target=toggle, daemon=True)
        toggler.start()
        failures = []
        try:
            for attempt in range(40):
                result = self.lane("status", "--lane", "q-read", code=None)
                if result.returncode != 0:
                    failures.append(result.stderr.strip())
        finally:
            done.set()
            toggler.join(10)
        self.assertFalse(target.exists())
        source.unlink()
        self.assertEqual(failures, [])
        self.assert_sound()

    def test_last_matching_line_decides(self):
        for lane, runner, reason in (("q-ld", "limitdrop", "dropped"), ("q-dl", "droplimit", "limit")):
            with self.subTest(runner=runner):
                self.start(lane, "--runner", runner, "--model", "both-model-1", "--worktree", self.scratch(lane))
                ended = self.wait_event("lane.ended", lane)
                self.assertEqual((ended["payload"]["reason"], ended["payload"]["pattern"],
                                  ended["payload"]["classification"]), (reason, reason + "_patterns[0]", "matched"))
        self.assert_sound()

    def test_account_value_never_echoed(self):
        token = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0" + "K1l2M3n4O5p6Q7r8"
        result = self.start("q-acct", "--runner", "ok", "--model", "ok-model-1", "--effort", "high", "--account", token,
                            "--worktree", self.scratch("q-acct"), code=2)
        self.assertNotIn(token, result.stdout + result.stderr)
        self.assertIn("acc-one", result.stderr)
        self.start("q-acct", "--runner", "ok", "--model", "ok-model-1", "--effort", "high", "--account", "acc-one",
                   "--worktree", self.directory / "work" / "q-acct")
        self.wait_event("lane.ended", "q-acct")
        result = self.lane("resume", "--lane", "q-acct", "--account", token, code=2)
        self.assertNotIn(token, result.stdout + result.stderr)
        self.assertEqual(self.lane_events("q-acct", "lane.resumed"), [])
        self.assert_sound()
