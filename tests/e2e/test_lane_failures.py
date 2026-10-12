"""Fix round 2, findings 2, 5, 6 and 7 and follow-up 8 (rulings R21, R22 and R25): a failed observation is never a
conclusion, recording never holds up the control loop, the run record catches up with what was sampled, and a
process's identity does not depend on the caller's time zone.
"""

import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time

from . import lanesupport, support
from .lanesupport import moment

# On macOS denysignals.py denies signals with sandbox-exec, and a sandboxed process may not run a setuid program;
# ps is setuid root there, so the process table cannot be read under that denial.
PS = shutil.which("ps")
MACOS_SANDBOX_HIDES_PS = sys.platform == "darwin" and PS is not None and bool(os.stat(PS).st_mode & stat.S_ISUID)

BARRIER_PS = """out=$("{real}" "$@")
status=$?
if [ -n "$E2E_PS_BARRIER" ] && mkdir "$E2E_PS_BARRIER/taken" 2>/dev/null; then
  i=0
  while [ ! -e "$E2E_PS_BARRIER/go" ] && [ $i -lt 600 ]; do sleep 0.1; i=$((i+1)); done
fi
printf '%s\\n' "$out"
exit $status
"""


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class LaneFailureTest(lanesupport.LaneTest):
    def test_stop_reports_survivors(self):
        for mode in ("pidfd", "stop"):
            with self.subTest(mode=mode):
                lane = "f-" + mode
                self.start(lane, "--runner", "forever", "--model", "ever-model-1", "--worktree", self.scratch(lane))
                record = self.record(lane)
                pids = [record["pid"]] + record["children"]
                self.kill_supervisor(lane)
                self.lane_json("check")
                result = self.denied(mode, "lane", "stop", "--config", "alpha", "--lane", lane)
                alive = [pid for pid in pids if self.alive(pid)]
                if mode == "stop":
                    self.assertEqual(len(alive), len(pids), "a process was stopped although stopping was denied")
                if alive and MACOS_SANDBOX_HIDES_PS and mode == "stop":
                    # sandbox-exec cannot deny signals without denying the setuid ps as well: the command cannot
                    # read the process table, says so, and does nothing it cannot verify.
                    self.assertEqual(result.returncode, 2, result)
                    self.assertIn("the process table cannot be read", result.stderr)
                    self.assertNotIn("removed", result.stdout)
                    self.assertEqual(self.status(lane)["live"]["survivors"], len(alive))
                    stopped = self.lane_json("stop", "--lane", lane)
                    self.assertEqual(stopped["removed"], len(alive))
                elif alive:
                    # Whatever survives is reported, and nothing alive is counted as removed.
                    self.assertEqual(result.returncode, 2, result)
                    self.assertIn("{} of {} process(es) removed".format(len(pids) - len(alive), len(pids)),
                                  result.stderr)
                    self.assertIn("{} survive".format(len(alive)), result.stderr)
                    for pid in alive:
                        self.assertIn(str(pid), result.stderr)
                    self.assertEqual(self.status(lane)["live"]["survivors"], len(alive))
                    stopped = self.lane_json("stop", "--lane", lane)
                    self.assertEqual(stopped["removed"], len(alive))
                else:
                    self.assertEqual(result.returncode, 0, result)
                    self.assertEqual(json.loads(result.stdout)["removed"], len(pids))
                self.assert_gone(pids, timeout=5)
                self.assertEqual(self.status(lane)["live"]["survivors"], 0)
        self.assert_sound()

    def test_unkillable_runner_has_no_end(self):
        lane = "f-runner"
        result = self.denied("stop", "lane", "start", "--config", "alpha", "--lane", lane, "--brief",
                             self.brief("alpha-" + lane), "--runner", "forever", "--model", "ever-model-1",
                             "--worktree", self.scratch(lane), "--budget", "0.05")
        if MACOS_SANDBOX_HIDES_PS:
            # sandbox-exec cannot deny signals without denying the setuid ps as well: the start cannot see its
            # supervising process, says so, and no run starts.
            self.assertEqual(result.returncode, 2, result)
            self.assertIn("the process table cannot be read", result.stderr)
            self.assertEqual(self.lane_events(lane, "lane.started"), [])
            self.assertFalse((self.records["alpha"] / (lane + ".1.json")).exists())
            return
        self.assertEqual(result.returncode, 0, result)
        record = self.record(lane)
        pids = [record["pid"]] + record["children"]
        # The budget (3 seconds) passes and the supervising process cannot stop the runner: no end is recorded, the
        # supervising process keeps trying, and status shows it.
        deadline = time.monotonic() + 20
        while True:
            lane_status = self.status(lane)
            if lane_status["live"].get("stopping"):
                break
            self.assertLess(time.monotonic(), deadline, "status never showed the run being stopped: {}".format(
                lane_status["live"]))
            time.sleep(0.5)
        self.assertEqual(lane_status["live"]["stopping"]["survivors"], len(pids))
        time.sleep(3.0)
        self.assertTrue(self.status(lane)["running"])
        self.assertEqual(self.lane_events(lane, "lane.ended"), [])
        self.assertTrue(all(self.alive(pid) for pid in pids))
        self.assertIs(self.status(lane)["live"]["supervisor"]["alive"], True)
        for pid in pids:
            os.kill(pid, signal.SIGKILL)
        ended = self.wait_event("lane.ended", lane, timeout=20)
        self.assertEqual((ended["payload"]["reason"], ended["payload"]["exit_code"], ended["payload"]["signal"],
                          ended["payload"]["survivors"]), ("timeout", None, 9, 0))
        self.assertLess(self.wait_event("lane.timeout", lane)["seq"], ended["seq"])
        self.assert_sound()

    def test_check_reads_rows_first(self):
        self.environment["LANEBOSS_PROCESSES"] = "portable"
        self.start("o-old", "--runner", "plain", "--model", "plain-model-1", "--worktree", self.scratch("o-old"))
        self.wait_event("lane.ended", "o-old")
        barrier = self.directory / "ps-barrier"
        barrier.mkdir()
        fake = self.fake_program("ps", BARRIER_PS.format(real=shutil.which("ps")))
        check = subprocess.Popen([str(self.command), "lane", "check", "--config", "alpha"], cwd=str(self.directory),
                                 env=self.with_path(fake, E2E_PS_BARRIER=str(barrier)), stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 30
        while not (barrier / "taken").exists():
            self.assertIsNone(check.poll(), "lane check ended before it read the process table")
            self.assertLess(time.monotonic(), deadline, "lane check never read the process table")
            time.sleep(0.05)
        # A run starts after lane check read the process table and before it has finished.
        self.start("o-new", "--runner", "persist", "--model", "ever-model-1", "--worktree", self.scratch("o-new"))
        record = self.record("o-new")
        (barrier / "go").write_text("go\n", encoding="utf-8")
        output, errors = check.communicate(timeout=60)
        self.assertEqual(check.returncode, 0, errors)
        self.assertEqual(json.loads(output)["lost"], [])
        self.assertEqual(self.lane_events("o-new", "lane.lost"), [])
        self.assertTrue(self.status("o-new")["running"])
        self.assertTrue(self.alive(record["pid"]))
        self.lane_json("stop", "--lane", "o-new")
        self.assert_sound()

    def test_check_needs_the_process_table(self):
        self.environment["LANEBOSS_PROCESSES"] = "portable"
        self.start("o-ps", "--runner", "persist", "--model", "ever-model-1", "--worktree", self.scratch("o-ps"))
        record = self.record("o-ps")
        failing = self.fake_program("ps", 'echo "ps: cannot read the process table" >&2\nexit 1\n')
        slow = self.fake_program("ps", 'exec "{}" 600\n'.format(shutil.which("sleep")))
        cases = (("empty PATH", dict(self.env("alpha"), PATH="")), ("failing ps", self.with_path(failing)),
                 ("slow ps", self.with_path(slow)))
        for name, environment in cases:
            with self.subTest(name):
                began = time.monotonic()
                checked = self.run_laneboss("lane", "check", "--config", "alpha", code=None, environment=environment)
                self.assertEqual(checked.returncode, 2, checked)
                self.assertIn("process table", checked.stderr)
                self.assertLess(time.monotonic() - began, 45)
                self.assertEqual(self.lane_events("o-ps", "lane.lost"), [])
                stopped = self.run_laneboss("lane", "stop", "--config", "alpha", "--lane", "o-ps", code=None,
                                            environment=environment)
                self.assertEqual(stopped.returncode, 2, stopped)
                self.assertTrue(self.alive(record["pid"]))
        self.assertTrue(self.status("o-ps")["running"])
        self.assertEqual(self.lane_json("check")["alive"], ["o-ps"])
        self.lane_json("stop", "--lane", "o-ps")
        self.assert_gone([record["pid"]], timeout=5)
        self.assert_sound()

    def test_recording_never_delays_budget(self):
        self.start("o-quiet", "--runner", "quiet", "--model", "quiet-model-1", "--worktree", self.scratch("o-quiet"),
                   "--budget", "0.1")
        record = self.record("o-quiet")
        started = moment(self.wait_event("lane.started", "o-quiet"))
        release = self.hold_store()
        # The run is quiet after two seconds: lane.stuck cannot be stored, and lane check keeps draining the lane's
        # pending events, holding their lock while it waits for the store.
        done = threading.Event()

        def drain():
            while not done.is_set():
                self.lane("check", code=None)

        drainer = threading.Thread(target=drain, daemon=True)
        drainer.start()
        self.addCleanup(done.set)
        gone = None
        while gone is None and time.time() < started + 30:
            if not self.alive(record["pid"]):
                gone = time.time()
            time.sleep(0.05)
        self.assertIsNotNone(gone, "the run outlived its budget by half a minute")
        # Budget 6 s, then SIGTERM, which the stand-in obeys at once.
        self.assertLess(gone - started, 6 + 4, "the run was stopped late: the control loop waited on recording")
        done.set()
        release()
        drainer.join(90)
        self.lane_json("check")
        ended = self.wait_event("lane.ended", "o-quiet", timeout=40)
        timeout = self.wait_event("lane.timeout", "o-quiet")
        stuck = self.wait_event("lane.stuck", "o-quiet")
        self.assertLess(stuck["seq"], timeout["seq"])
        self.assertLess(timeout["seq"], ended["seq"])
        self.assertEqual(ended["payload"]["reason"], "timeout")
        self.assertLess(abs(moment(timeout) - (started + 6)), 2.0)
        self.assertLess(abs(moment(ended) - gone), 1.5, "the end does not carry the time it was observed")
        self.assert_sound()

    def test_run_record_catches_up(self):
        if os.geteuid() == 0:
            self.fail("run the suite as a non-root user: root ignores directory permissions")
        self.start("o-late", "--runner", "late", "--model", "late-model-1", "--worktree", self.scratch("o-late"))
        record = self.record("o-late")
        runs = self.run_record_path("o-late").parent
        runs.chmod(0o500)
        self.addCleanup(runs.chmod, 0o700)
        self.go("o-late")
        path = self.records["alpha"] / "o-late.1.helper.json"
        deadline = time.monotonic() + 20
        while not path.is_file():
            self.assertLess(time.monotonic(), deadline, "the helper left no record")
            time.sleep(0.1)
        worker = json.loads(path.read_text(encoding="utf-8"))["worker"]
        # The worker is sampled while the run record cannot be written; then the directory is writable again.
        time.sleep(1.5)
        runs.chmod(0o700)
        time.sleep(2.0)
        self.kill_supervisor("o-late")
        checked = self.lane_json("check")
        self.assertEqual(checked["lost"][0]["survivors"], 2)
        stopped = self.lane_json("stop", "--lane", "o-late")
        self.assertEqual(stopped["removed"], 2)
        self.assert_gone([record["pid"], worker], timeout=5)
        self.assert_sound()

    def test_time_zone_keeps_identity(self):
        self.environment["LANEBOSS_PROCESSES"] = "portable"
        self.environment["TZ"] = "UTC0"
        self.start("z-zone", "--runner", "persist", "--model", "ever-model-1", "--worktree", self.scratch("z-zone"))
        record = self.record("z-zone")
        time.sleep(1.0)
        self.environment["TZ"] = "JST-9"
        live = self.status("z-zone")["live"]
        self.assertIs(live["supervisor"]["alive"], True)
        checked = self.lane_json("check")
        self.assertEqual((checked["lost"], checked["alive"]), ([], ["z-zone"]))
        stopped = self.lane_json("stop", "--lane", "z-zone")
        self.assertEqual(stopped["reason"], "stopped")
        self.assert_gone([record["pid"]] + record["children"], timeout=5)
        self.assertEqual(self.lane_events("z-zone", "lane.lost"), [])
        self.assert_sound()

    def test_classifier_does_not_outlive(self):
        self.start("z-bound", "--runner", "regex", "--model", "regex-model-1", "--worktree", self.scratch("z-bound"))
        ended = self.wait_event("lane.ended", "z-bound", timeout=40)
        self.assertEqual(ended["payload"]["classification"], "timed-out")
        self.assertEqual(self.classifiers(), [])
        self.start("z-killed", "--runner", "regex", "--model", "regex-model-1", "--worktree", self.scratch("z-killed"))
        deadline = time.monotonic() + 20
        while not self.classifiers():
            self.assertLess(time.monotonic(), deadline, "no classification process appeared")
            time.sleep(0.05)
        os.kill(self.status("z-killed")["live"]["supervisor"]["pid"], signal.SIGKILL)
        deadline = time.monotonic() + 5
        while self.classifiers():
            self.assertLess(time.monotonic(), deadline, "the classification process outlived the supervising process")
            time.sleep(0.1)
        self.lane_json("check")
        self.assert_sound()
