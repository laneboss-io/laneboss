"""Fix round 1, finding 1 (ruling R13): stopping a run never waits for the store, and an event is never dropped.

The supervising process first makes sure the run's processes are gone, then records. An event it cannot append (the
store is busy past its wait, or unwritable) waits in the lane's pending file and is appended later, in order and with
its original time, by the supervising process or by the next lane check.
"""

from datetime import datetime
import os
from pathlib import Path
import time

from . import lanesupport, support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


def moment(event):
    value = event["occurred_at"] or event["recorded_at"]
    return datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value).timestamp()


class LaneRecordTest(lanesupport.LaneTest):
    def test_busy_store_across_exit(self):
        self.start("r-exit", "--runner", "leaver", "--model", "leaver-model-1", "--worktree", self.scratch("r-exit"))
        record = self.record("r-exit")
        pids = [record["pid"]] + record["children"]
        self.assertTrue(all(self.alive(pid) for pid in pids))
        release = self.hold_store()
        self.go("r-exit")
        # The runner exits 7 and leaves a child: both are gone while the store is still held.
        self.assert_gone(pids, timeout=5)
        deadline = time.monotonic() + 10
        while self.status("r-exit")["live"]["pending_events"] < 1:
            self.assertLess(time.monotonic(), deadline, "the end of the run was not kept as pending")
            time.sleep(0.2)
        self.assertEqual(self.lane_events("r-exit", "lane.ended"), [])
        held_until = time.time()
        release()
        ended = self.wait_event("lane.ended", "r-exit", timeout=20)
        started = self.wait_event("lane.started", "r-exit")
        self.assertEqual((ended["payload"]["reason"], ended["payload"]["exit_code"]), ("exit", 7))
        self.assertLess(started["seq"], ended["seq"])
        self.assertLess(moment(ended), held_until, "the end keeps the time it happened, not the time it was stored")
        self.assertLessEqual(abs(moment(ended) - record["started"]), 30)
        deadline = time.monotonic() + 10
        while self.status("r-exit")["live"]["pending_events"]:
            self.assertLess(time.monotonic(), deadline, "pending events were not cleared after they were appended")
            time.sleep(0.2)
        self.assert_sound()

    def test_busy_store_across_budget(self):
        self.start("r-budget", "--runner", "forever", "--model", "ever-model-1", "--worktree",
                   self.scratch("r-budget"), "--budget", "0.05")
        record = self.record("r-budget")
        pids = [record["pid"]] + record["children"]
        release = self.hold_store()
        began = time.time()
        # The budget (3 seconds) passes while the store is held: the run is stopped at once all the same.
        self.assert_gone(pids, timeout=12)
        self.assertLess(time.time() - began, 12)
        self.assertEqual(self.lane_events("r-budget", "lane.timeout"), [])
        held_until = time.time()
        release()
        ended = self.wait_event("lane.ended", "r-budget", timeout=20)
        timeout = self.wait_event("lane.timeout", "r-budget")
        self.assertLess(timeout["seq"], ended["seq"])
        self.assertEqual(ended["payload"]["reason"], "timeout")
        self.assertLess(moment(timeout), held_until)
        self.assertLessEqual(moment(timeout), moment(ended))
        self.assert_sound()

    def test_unwritable_store_caught_up(self):
        self.start("r-ro", "--runner", "waiter", "--model", "waiter-model-1", "--worktree", self.scratch("r-ro"))
        self.record("r-ro")
        store = Path(self.paths()["store"])
        store.chmod(0o444)
        self.addCleanup(store.chmod, 0o644)
        self.go("r-ro")
        # The supervising process cannot record the end; it keeps it pending and, after a while, ends.
        deadline = time.monotonic() + 45
        while True:
            live = self.status("r-ro")["live"]
            if not live["supervisor"]["alive"]:
                break
            self.assertLess(time.monotonic(), deadline, "the supervising process never ended")
            time.sleep(0.5)
        self.assertEqual(live["pending_events"], 1)
        self.assertEqual(self.lane_events("r-ro", "lane.ended"), [])
        store.chmod(0o644)
        checked = self.lane_json("check")
        self.assertEqual(checked["lost"], [])
        self.assertEqual(checked["recorded"], [{"lane": "r-ro", "events": 1}])
        ended = self.wait_event("lane.ended", "r-ro")
        self.assertEqual((ended["payload"]["reason"], ended["payload"]["exit_code"]), ("exit", 0))
        self.assertEqual(self.lane_events("r-ro", "lane.lost"), [])
        self.assertEqual(self.status("r-ro")["live"]["pending_events"], 0)
        self.assertEqual(self.lane_json("check")["recorded"], [])
        self.assertTrue(os.access(str(store), os.W_OK))
        self.assert_sound()
