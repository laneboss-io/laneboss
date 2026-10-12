"""Refusals J. Following a run's records never slows its control: a stand-in that writes ten thousand record lines a
second is still stopped at its budget on time, and a refusal at the start of the flood is still recorded."""

import os
import signal
import subprocess
import time

from . import refusalsupport, support
from .lanesupport import moment
from .refusalsupport import refused_steps

BUDGET_MINUTES = 0.1


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class FloodTest(refusalsupport.RefusalTest):
    def check_flood(self, fmt, lane):
        follower = self.follow()
        steps = [{"open": {}}] + refused_steps(fmt) + [{"mark": "flood"}, {"flood": {"seconds": 120, "rate": 10000}}]
        self.start_session(lane, fmt, steps, "--budget", str(BUDGET_MINUTES))
        _, started = follower.wait(self, "lane.started", lane)
        _, refusal = follower.wait(self, "lane.refusal", lane)
        _, timeout = follower.wait(self, "lane.timeout", lane, timeout=60)
        _, ended = follower.wait(self, "lane.ended", lane, timeout=60)
        budget = BUDGET_MINUTES * 60
        self.assertGreaterEqual(timeout["payload"]["elapsed_seconds"], budget)
        self.assertLessEqual(timeout["payload"]["elapsed_seconds"], budget + 1.5)
        self.assertLessEqual(moment(timeout) - moment(started), budget + 2.0)
        self.assertEqual(ended["payload"]["reason"], "timeout")
        self.assertLessEqual(moment(ended) - moment(timeout), 15.0)
        record = self.record(lane)
        self.assert_gone([record["pid"]])
        with open(record["records"][0], "rb") as handle:
            written = sum(1 for _ in handle)
        self.assertGreater(written, 20000, "the stand-in did not flood its record")
        self.assertEqual(refusal["payload"]["guard"], "doc-guard")
        self.assert_sound()

    def test_claude_code(self):
        self.check_flood("claude-code", "j-claude")

    def scanner_of(self, lane):
        """The process id of the lane's scanning process: the supervising process's child that runs the scan."""
        supervisor = self.status(lane)["live"]["supervisor"]["pid"]
        deadline = time.monotonic() + 20
        while True:
            listing = subprocess.run(["ps", "-A", "-o", "pid=", "-o", "ppid=", "-o", "args="], capture_output=True,
                                     text=True).stdout
            for line in listing.splitlines():
                parts = line.split(None, 2)
                if len(parts) == 3 and parts[1] == str(supervisor) and "refusals import follow" in parts[2]:
                    return int(parts[0])
            self.assertLess(time.monotonic(), deadline, "no scanning process beside the run")
            time.sleep(0.2)

    def test_stopped_scanner_end_is_bounded(self):
        # Decision 8: with its scanning process suspended (by its own process id), a run that ends by itself has its
        # end in the store less than eight seconds after its processes are gone; the scanning process is not a
        # survivor and does not outlive the supervising process.
        lane = "j-stopped"
        follower = self.follow()
        self.start_session(lane, "claude-code", [{"open": {}}, {"mark": "opened"}, {"wait": "go"}, {"exit": 0}])
        self.marked(lane, "opened")
        scanner = self.scanner_of(lane)
        os.kill(scanner, signal.SIGSTOP)
        self.addCleanup(self.kill_quietly, scanner)
        self.go(lane)
        record = self.ended_by_itself(lane)
        arrived, ended = follower.wait(self, "lane.ended", lane, timeout=60)
        self.assertLess(arrived - record["ended"], 8.0)
        self.assertEqual(ended["payload"]["survivors"], 0)
        self.assert_gone([scanner], timeout=10)
        self.assert_sound()

    def test_stopped_scanner_timeout_is_bounded(self):
        # The same bound when the budget ends the run.
        lane = "j-stopped-budget"
        follower = self.follow()
        self.start_session(lane, "claude-code", [{"open": {}}, {"mark": "opened"}, {"wait": "go"}, {"exit": 0}],
                           "--budget", "0.1")
        self.marked(lane, "opened")
        scanner = self.scanner_of(lane)
        os.kill(scanner, signal.SIGSTOP)
        self.addCleanup(self.kill_quietly, scanner)
        _, timeout = follower.wait(self, "lane.timeout", lane, timeout=60)
        arrived, ended = follower.wait(self, "lane.ended", lane, timeout=60)
        record = self.record(lane)
        self.assert_gone([record["pid"]], timeout=10)
        # The stand-in ends at the first SIGTERM (the grace is two seconds): its processes are gone at the latest two
        # seconds after the budget passed.
        self.assertLess(arrived - (moment(timeout) + 2.0), 8.0)
        self.assertEqual((ended["payload"]["reason"], ended["payload"]["survivors"]), ("timeout", 0))
        self.assert_gone([scanner], timeout=10)
        self.assert_sound()

    def kill_quietly(self, pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
