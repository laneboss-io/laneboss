"""Fix round 3 (rulings R22, R23 and R27): the survivor count of an end is taken once the runner is gone; lane stop
finishes a stop whose supervising process died; the recorder keeps every event it could not record; a launch without
its run record blocks the lane; one claims registry per account; a direct append cannot overtake a pending event;
clean releases the claim of a directory made again; the documented writes and bounds; the recorder's durability,
counted by event id.
"""

import fcntl
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid

from . import lanesupport, support
from .lanesupport import moment

PS = shutil.which("ps")
MACOS_SANDBOX_HIDES_PS = sys.platform == "darwin" and PS is not None and bool(os.stat(PS).st_mode & stat.S_ISUID)


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


def listing(root):
    return sorted(str(path.relative_to(root)) for path in Path(root).rglob("*"))


class LaneRecoveryTest(lanesupport.LaneTest):
    def lane_dir(self, lane, config="alpha"):
        return Path(self.paths(config)["state_dir"]) / "lanes" / lane

    def stuck(self, lane, started, run=1):
        """A lane.stuck envelope of the lane's run, as the supervising process writes it."""
        return {"id": "ev-" + uuid.uuid4().hex, "kind": "lane.stuck", "lane": lane, "actor": "laneboss",
                "occurred_at": started["occurred_at"], "protocol_version": started["protocol_version"],
                "payload": {"run": run, "quiet_seconds": 5, "output_bytes": 0}}

    def ids(self, config="alpha"):
        return [item["id"] for item in self.events(config)]

    def test_survivor_count_is_fresh(self):
        lane = "v-fresh"
        result = self.denied("stop", "lane", "start", "--config", "alpha", "--lane", lane, "--brief",
                             self.brief("alpha-" + lane), "--runner", "forever", "--model", "ever-model-1",
                             "--worktree", self.scratch(lane), "--budget", "0.05")
        if MACOS_SANDBOX_HIDES_PS:
            # sandbox-exec cannot deny signals without denying the setuid ps as well (test_lane_failures.py).
            self.assertEqual(result.returncode, 2, result)
            self.assertIn("the process table cannot be read", result.stderr)
            return
        self.assertEqual(result.returncode, 0, result)
        record = self.record(lane)
        path = self.run_record_path(lane)
        deadline = time.monotonic() + 40
        while json.loads(path.read_text(encoding="utf-8")).get("stopping") is None:
            self.assertLess(time.monotonic(), deadline, "the run was never shown as being stopped")
            time.sleep(0.05)
        written = path.stat().st_mtime_ns
        while path.stat().st_mtime_ns == written:
            self.assertLess(time.monotonic(), deadline, "the supervising process stopped trying")
            time.sleep(0.02)
        # After each write of the run record the supervising process sleeps 2 s, tries to stop the run for about 2 s
        # and then waits 2 s for the runner. In that wait the child is removed and seen gone first, then the runner:
        # the child, alive at the supervising process's last look before, is no survivor of the end.
        time.sleep(4.3)
        os.kill(record["children"][0], signal.SIGKILL)
        self.assert_gone(record["children"], timeout=1)
        os.kill(record["pid"], signal.SIGKILL)
        ended = self.wait_event("lane.ended", lane, timeout=30)
        self.assertEqual((ended["payload"]["reason"], ended["payload"]["exit_code"], ended["payload"]["signal"],
                          ended["payload"]["survivors"]), ("timeout", None, 9, 0))
        self.assert_sound()

    def test_stop_after_supervisor_dies(self):
        lane = "v-stop"
        # A pane process of tmux cannot be held stopped (tmux continues it after SIGSTOP, and SIGTTOU is discarded in
        # its orphaned process group), so the supervising process is made unable to stop the run instead: it gets
        # the stop request, keeps trying, and dies before it has stopped anything.
        result = self.denied("stop", "lane", "start", "--config", "alpha", "--lane", lane, "--brief",
                             self.brief("alpha-" + lane), "--runner", "forever", "--model", "ever-model-1",
                             "--worktree", self.scratch(lane))
        if MACOS_SANDBOX_HIDES_PS:
            self.assertEqual(result.returncode, 2, result)
            self.assertIn("the process table cannot be read", result.stderr)
            return
        self.assertEqual(result.returncode, 0, result)
        record = self.record(lane)
        pids = [record["pid"]] + record["children"]
        time.sleep(1.0)
        supervisor = self.status(lane)["live"]["supervisor"]["pid"]
        stop = subprocess.Popen([str(self.command), "lane", "stop", "--config", "alpha", "--lane", lane],
                                cwd=str(self.directory), env=self.env("alpha"), stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 30
        while not self.status(lane)["live"].get("stopping"):
            self.assertLess(time.monotonic(), deadline, "the supervising process never tried to stop the run")
            time.sleep(0.2)
        os.kill(supervisor, signal.SIGKILL)
        output, errors = stop.communicate(timeout=120)
        alive = [pid for pid in pids if self.alive(pid)]
        if stop.returncode == 0:
            result = json.loads(output)
            self.assertEqual((result["stopped_by"], result["removed"], result["survivors"]),
                             ("lane-stop", len(pids), 0), result)
            self.assertEqual(alive, [])
        else:
            self.assertEqual(stop.returncode, 2, errors)
            self.assertTrue(alive)
            for pid in alive:
                self.assertIn(str(pid), errors)
            self.lane_json("stop", "--lane", lane)
        self.assert_gone(pids, timeout=5)
        checked = self.lane_json("check")
        self.assertEqual([(item["lane"], item["survivors"]) for item in checked["lost"]], [(lane, 0)])
        self.assert_sound()

    def test_unreadable_pending_is_retried(self):
        lane = "v-unread"
        self.start(lane, "--runner", "waiter", "--model", "waiter-model-1", "--worktree", self.scratch(lane))
        self.record(lane)
        started = self.wait_event("lane.started", lane)
        release = self.hold_store()
        pending = self.lane_dir(lane) / "pending.jsonl"
        stuck = self.stuck(lane, started)
        pending.write_text(json.dumps(stuck) + "\n", encoding="utf-8")
        pending.chmod(0)
        self.addCleanup(lambda: pending.exists() and pending.chmod(0o600))
        self.go(lane)
        finished = self.record(lane, ended=True)
        # The runner has ended; its end cannot be recorded while the pending file cannot be read.
        time.sleep(3.0)
        pending.chmod(0o600)
        release()
        ended = self.wait_event("lane.ended", lane, timeout=40)
        self.assertEqual((ended["payload"]["reason"], ended["payload"]["exit_code"]), ("exit", 0))
        self.assertLess(abs(moment(ended) - finished["ended"]), 3.0)
        kept = [item for item in self.lane_events(lane, "lane.stuck") if item["id"] == stuck["id"]]
        self.assertEqual(len(kept), 1)
        self.assertLess(kept[0]["seq"], ended["seq"])
        self.assertEqual(self.ids().count(ended["id"]), 1)
        self.assert_sound()

    def test_unrecorded_end_waits_for_check(self):
        lane = "v-later"
        self.start(lane, "--runner", "waiter", "--model", "waiter-model-1", "--worktree", self.scratch(lane))
        self.record(lane)
        started = self.wait_event("lane.started", lane)
        supervisor = self.status(lane)["live"]["supervisor"]["pid"]
        release = self.hold_store()
        pending = self.lane_dir(lane) / "pending.jsonl"
        stuck = self.stuck(lane, started)
        pending.write_text(json.dumps(stuck) + "\n", encoding="utf-8")
        pending.chmod(0)
        self.addCleanup(lambda: pending.exists() and pending.chmod(0o600))
        self.go(lane)
        finished = self.record(lane, ended=True)
        # The supervising process cannot record the end and exits; the next lane check records it.
        deadline = time.monotonic() + 60
        while self.alive(supervisor):
            self.assertLess(time.monotonic(), deadline, "the supervising process never exited")
            time.sleep(0.2)
        pending.chmod(0o600)
        release()
        self.lane_json("check")
        ended = self.wait_event("lane.ended", lane)
        self.assertEqual((ended["payload"]["reason"], ended["payload"]["exit_code"]), ("exit", 0))
        self.assertLess(abs(moment(ended) - finished["ended"]), 3.0)
        kept = [item for item in self.lane_events(lane, "lane.stuck") if item["id"] == stuck["id"]]
        self.assertEqual(len(kept), 1)
        self.assertLess(kept[0]["seq"], ended["seq"])
        self.assertEqual(self.lane_events(lane, "lane.lost"), [])
        self.assertEqual(self.status(lane)["live"]["pending_events"], 0)
        self.assert_sound()

    def test_unrecordable_end_is_reported(self):
        if os.geteuid() == 0:
            self.fail("run the suite as a non-root user: root ignores directory permissions")
        lane = "v-nowhere"
        self.start(lane, "--runner", "waiter", "--model", "waiter-model-1", "--worktree", self.scratch(lane))
        self.record(lane)
        supervisor = self.status(lane)["live"]["supervisor"]["pid"]
        store = Path(self.paths()["store"])
        directory = self.lane_dir(lane)
        store.chmod(0o444)
        self.addCleanup(store.chmod, 0o644)
        directory.chmod(0o500)
        self.addCleanup(directory.chmod, 0o700)
        self.go(lane)
        # Neither the store nor the lane's directory can take the end: the supervising process says so and exits.
        deadline = time.monotonic() + 60
        while self.alive(supervisor):
            self.assertLess(time.monotonic(), deadline, "the supervising process never exited")
            time.sleep(0.2)
        directory.chmod(0o700)
        store.chmod(0o644)
        watch = (directory / "watch.log").read_text(encoding="utf-8")
        self.assertIn("could not be recorded anywhere", watch)
        self.assertIn("the supervising process exits with status 1", watch)
        checked = self.lane_json("check")
        self.assertEqual([(item["lane"], item["survivors"]) for item in checked["lost"]], [(lane, 0)])
        self.assertEqual(self.lane_events(lane, "lane.ended"), [])
        self.assert_sound()

    def test_missing_record_blocks_resume(self):
        lane = "v-norec"
        scratch = self.scratch(lane)
        self.start(lane, "--runner", "forever", "--model", "ever-model-1", "--worktree", scratch)
        record = self.record(lane)
        pids = [record["pid"]] + record["children"]
        self.kill_supervisor(lane)
        self.assertEqual(self.lane_json("check")["lost"][0]["survivors"], len(pids))
        path = self.run_record_path(lane)
        saved = path.read_bytes()
        path.unlink()
        # Nothing proves the lost run's processes are gone any more: resume, a reused start and clean refuse.
        result = self.lane("resume", "--lane", lane, code=2)
        self.assertIn("run record", result.stderr)
        self.lane_json("mark", "--lane", lane, "--state", "abandoned")
        result = self.start(lane, "--runner", "plain", "--model", "plain-model-1", "--worktree", scratch, "--reuse",
                            code=2)
        self.assertIn("run record", result.stderr)
        result = self.lane("clean", "--lane", lane, code=2)
        self.assertIn("run record", result.stderr)
        self.assertEqual(self.lane_events(lane, "lane.resumed") + self.lane_events(lane, "lane.cleaned"), [])
        self.assertEqual(len(self.lane_events(lane, "lane.started")), 1)
        self.assertTrue(all(self.alive(pid) for pid in pids))
        path.write_bytes(saved)
        result = self.lane("resume", "--lane", lane, code=2)
        self.assertIn("surviv", result.stderr)
        self.assertEqual(self.lane_json("stop", "--lane", lane)["removed"], len(pids))
        self.assert_gone(pids, timeout=5)
        self.lane_json("resume", "--lane", lane)
        self.assertEqual(self.wait_event("lane.ended", lane, run=2)["payload"]["reason"], "exit")
        self.assert_sound()

    def test_one_registry_per_account(self):
        self.add_config("beta")
        states = self.directory / "states"
        for name in ("alpha", "beta"):
            config = self.home / "configs" / name / "config.toml"
            config.write_text(config.read_text(encoding="utf-8").replace(
                "[lanes]\n", "[state]\npath = {}\n\n[lanes]\n".format(json.dumps(str(states / name)))),
                encoding="utf-8")
        homes = {name: self.directory / ("state-home-" + name) for name in ("alpha", "beta")}
        environments = {}
        for name, home in homes.items():
            home.mkdir()
            environments[name] = dict(self.env(name), LANEBOSS_STATE_HOME=str(home))
        shared = self.scratch("v-shared")
        started = json.loads(self.run_laneboss(
            "lane", "start", "--config", "alpha", "--lane", "v-one", "--brief", self.brief("alpha-v-one"), "--runner",
            "persist", "--model", "ever-model-1", "--worktree", shared, environment=environments["alpha"]).stdout)
        record = self.record("v-one")
        # The same plain directory, another configuration with another state home: the claim is found all the same.
        result = self.run_laneboss(
            "lane", "start", "--config", "beta", "--lane", "v-two", "--brief", self.brief("beta-v-two"), "--runner",
            "writer", "--model", "writer-model-1", "--worktree", shared, code=2, environment=environments["beta"])
        self.assertIn("claimed by lane v-one of configuration alpha", result.stderr)
        self.assertFalse((shared / "work.txt").exists())
        self.assertEqual(list(self.records["beta"].iterdir()), [])
        self.assertEqual(started["claims"], str(self.directory / "claims"))
        self.run_laneboss("lane", "stop", "--config", "alpha", "--lane", "v-one", environment=environments["alpha"])
        self.assert_gone([record["pid"]], timeout=5)
        # A later command that would look in another registry refuses instead of deciding from it.
        moved = dict(environments["alpha"], LANEBOSS_TEST_CLAIMS_DIR=str(self.directory / "other-claims"))
        result = self.run_laneboss("lane", "resume", "--config", "alpha", "--lane", "v-one", code=2,
                                   environment=moved)
        self.assertIn("registry", result.stderr)
        self.run_laneboss("lane", "resume", "--config", "alpha", "--lane", "v-one", environment=environments["alpha"])
        self.run_laneboss("lane", "stop", "--config", "alpha", "--lane", "v-one", environment=environments["alpha"])

    def test_append_waits_for_pending(self):
        lane = "v-order"
        self.start(lane, "--runner", "waiter", "--model", "waiter-model-1", "--worktree", self.scratch(lane))
        self.record(lane)
        started = self.wait_event("lane.started", lane)
        release = self.hold_store()
        envelope = self.directory / "merged.json"
        envelope.write_text(json.dumps({"kind": "lane.merged", "lane": lane, "actor": "supervisor", "payload": {},
                                        "protocol_version": started["protocol_version"]}), encoding="utf-8")
        direct = subprocess.Popen([str(self.command), "event", "append", "--config", "alpha", "--file",
                                   str(envelope)], cwd=str(self.directory), env=self.env("alpha"),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # The direct append has checked for pending events and waits for the store (at most 10 s); then the runner
        # ends and the recorder cannot store lane.ended.
        time.sleep(0.5)
        self.go(lane)
        pending = self.lane_dir(lane) / "pending.jsonl"
        deadline = time.monotonic() + 5
        while not pending.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        if pending.exists():
            # The end waits in the pending file. Every drainer is held off (the lane's lock, taken between the
            # recorder's attempts) and the store is let go: the direct append must not be stored before that end.
            descriptor = os.open(str(self.lane_dir(lane)), os.O_RDONLY)
            try:
                while True:
                    try:
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        time.sleep(0.01)
                release()
                try:
                    output, errors = direct.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    direct.kill()
                    output, errors = direct.communicate()
                self.assertNotEqual(direct.returncode, 0, "a direct append was stored while the lane's end was "
                                                          "pending: " + output)
                self.assertIn("waiting to be recorded", errors, "the direct append failed for another reason")
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
        else:
            release()
            output, errors = direct.communicate(timeout=30)
            self.assertEqual(direct.returncode, 0, errors)
            merged = self.wait_event("lane.merged", lane)
            ended = self.wait_event("lane.ended", lane, timeout=40)
            self.assertLess(merged["seq"], ended["seq"])
        self.wait_event("lane.ended", lane, timeout=40)
        self.assert_sound()

    def test_clean_after_directory_recreated(self):
        lane = "v-again"
        plain = self.scratch(lane)
        self.start(lane, "--runner", "plain", "--model", "plain-model-1", "--worktree", plain)
        self.wait_event("lane.ended", lane)
        self.lane_json("mark", "--lane", lane, "--state", "abandoned")
        registry = next(path for path in (self.directory / "claims", self.state_home / ".lane-claims")
                        if path.is_dir())
        self.assertEqual(len(list(registry.iterdir())), 1)
        # The directory is removed and made again under the same path: a directory with another identity.
        aside = plain.with_name(lane + "-old")
        plain.rename(aside)
        plain.mkdir()
        shutil.rmtree(str(aside))
        (plain / "keep.txt").write_text("the new directory's own file\n", encoding="utf-8")
        self.lane_json("clean", "--lane", lane)
        self.assertEqual(list(registry.iterdir()), [])
        self.assertEqual(listing(plain), ["keep.txt"])
        self.start("v-again2", "--runner", "plain", "--model", "plain-model-1", "--worktree", plain)
        self.wait_event("lane.ended", "v-again2")
        self.assertEqual(listing(plain), ["keep.txt"])
        self.assert_sound()

    def test_check_appends_before_failing(self):
        self.environment["LANEBOSS_PROCESSES"] = "portable"
        lane = "v-first"
        self.start(lane, "--runner", "waiter", "--model", "waiter-model-1", "--worktree", self.scratch(lane))
        self.record(lane)
        supervisor = self.status(lane)["live"]["supervisor"]["pid"]
        store = Path(self.paths()["store"])
        store.chmod(0o444)
        self.addCleanup(store.chmod, 0o644)
        self.go(lane)
        deadline = time.monotonic() + 60
        while self.alive(supervisor):
            self.assertLess(time.monotonic(), deadline, "the supervising process never exited")
            time.sleep(0.2)
        store.chmod(0o644)
        self.assertEqual(self.status(lane)["live"]["pending_events"], 1)
        failing = self.fake_program("ps", 'echo "ps: cannot read the process table" >&2\nexit 1\n')
        # lane check appends the pending end first, then fails at the process table.
        result = self.run_laneboss("lane", "check", "--config", "alpha", code=2, environment=self.with_path(failing))
        self.assertIn("process table", result.stderr)
        self.assertEqual(self.wait_event("lane.ended", lane)["payload"]["reason"], "exit")
        self.assertEqual(self.lane_events(lane, "lane.lost"), [])
        self.assert_sound()

    def test_end_delay_is_bounded(self):
        lane = "v-delay"
        self.start(lane, "--runner", "slowend", "--model", "slow-model-1", "--worktree", self.scratch(lane))
        record = self.record(lane, ended=True)
        ended = self.wait_event("lane.ended", lane, timeout=40)
        # The runner's end is observed at once; then its child gets SIGTERM, which it ignores, SIGKILL after the
        # leftover grace (1 s), and the classification runs into its bound (2 s) before the end is queued.
        self.assertLess(abs(moment(ended) - record["ended"]), 1.5)
        recorded = moment(dict(ended, occurred_at=None))
        self.assertGreater(recorded - moment(ended), 2.5)
        self.assertLess(recorded - moment(ended), 7.0)
        self.assertEqual((ended["payload"]["classification"], ended["payload"]["survivors"]), ("timed-out", 0))
        self.assert_gone(record["children"], timeout=5)
        self.assert_sound()

    def test_two_drainers_count_once(self):
        lane = "v-drain"
        self.start(lane, "--runner", "persist", "--model", "ever-model-1", "--worktree", self.scratch(lane))
        record = self.record(lane)
        started = self.wait_event("lane.started", lane)
        release = self.hold_store()
        envelopes = [self.stuck(lane, started) for index in range(6)]
        pending = self.lane_dir(lane) / "pending.jsonl"
        pending.write_text("".join(json.dumps(item) + "\n" for item in envelopes), encoding="utf-8")
        checks = [subprocess.Popen([str(self.command), "lane", "check", "--config", "alpha"], cwd=str(self.directory),
                                   env=self.env("alpha"), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                  for index in range(2)]
        time.sleep(1.0)
        release()
        for check in checks:
            check.communicate(timeout=60)
        self.assertEqual([check.returncode for check in checks], [0, 0])
        self.lane_json("check")
        ids = self.ids()
        self.assertEqual([ids.count(item["id"]) for item in envelopes], [1] * len(envelopes))
        self.assertFalse(pending.exists())
        self.assertFalse((self.lane_dir(lane) / "refused.jsonl").exists())
        self.lane_json("stop", "--lane", lane)
        self.assert_gone([record["pid"]], timeout=5)
        self.assert_sound()

    def test_drained_twice_is_stored_once(self):
        lane = "v-twice"
        self.start(lane, "--runner", "persist", "--model", "ever-model-1", "--worktree", self.scratch(lane))
        record = self.record(lane)
        started = self.wait_event("lane.started", lane)
        # A drainer that crashed after the store took an event and before it rewrote the pending file leaves that
        # event at the head of the queue.
        stored = {key: started[key] for key in ("id", "kind", "lane", "actor", "occurred_at", "payload",
                                                "protocol_version")}
        fresh = self.stuck(lane, started)
        pending = self.lane_dir(lane) / "pending.jsonl"
        pending.write_text(json.dumps(stored) + "\n" + json.dumps(fresh) + "\n", encoding="utf-8")
        self.lane_json("check")
        ids = self.ids()
        self.assertEqual((ids.count(stored["id"]), ids.count(fresh["id"])), (1, 1))
        self.assertFalse(pending.exists())
        self.assertFalse((self.lane_dir(lane) / "refused.jsonl").exists())
        self.lane_json("stop", "--lane", lane)
        self.assert_gone([record["pid"]], timeout=5)
        self.assert_sound()
