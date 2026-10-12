"""Fix round 4 (rulings R28 and R29): writes of events to files complete or fail whole; one owner of the recorder's
queue; lane stop acts on the run record read after it saw the supervising process gone; a reused start keeps the
recorded claims registry; a process group is the run's only through a verified member in the same snapshot; events
written by an earlier commit are an integrity refusal; leftovers are published under the lane's lock; a supervisor
may declare a launch gone.
"""

from contextlib import closing
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import time
import uuid

from . import lanesupport, support

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
LEADER = "import os, time\nos.setsid()\nprint(os.getpid(), flush=True)\ntime.sleep(600)\n"


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def listing(root):
    return sorted(str(path.relative_to(root)) for path in Path(root).rglob("*"))


def exists(pid):
    """True while the process id is taken, a zombie included."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class LaneHandoffTest(lanesupport.LaneTest):
    def lane_dir(self, lane, config="alpha"):
        return Path(self.paths(config)["state_dir"]) / "lanes" / lane

    def envelope(self, lane, started, kind="lane.stuck", payload=None):
        return {"id": "ev-" + uuid.uuid4().hex, "kind": kind, "lane": lane, "actor": "laneboss",
                "occurred_at": started["occurred_at"], "protocol_version": started["protocol_version"],
                "payload": payload if payload is not None else {"run": 1, "quiet_seconds": 5, "output_bytes": 0}}

    def ids(self, config="alpha"):
        return [item["id"] for item in self.events(config)]

    def aside(self, directory):
        return sorted(path.name for path in directory.glob("pending-*.jsonl"))

    def wait_gone(self, pid, timeout=60):
        deadline = time.monotonic() + timeout
        while self.alive(pid):
            self.assertLess(time.monotonic(), deadline, "process {} never exited".format(pid))
            time.sleep(0.2)

    def test_short_write_keeps_aside(self):
        lane = "h-short"
        self.start(lane, "--runner", "plain", "--model", "plain-model-1", "--worktree", self.scratch(lane))
        self.wait_event("lane.ended", lane)
        started = self.wait_event("lane.started", lane)
        directory = self.lane_dir(lane)
        first = self.envelope(lane, started, "lane.deployed", {})
        kept = [self.envelope(lane, started, "lane.deployed", {}) for index in range(8)]
        (directory / "pending.jsonl").write_text(json.dumps(first) + "\n", encoding="utf-8")
        aside = directory / "pending-{}-e2e00000.jsonl".format(started["payload"]["launch"])
        aside.write_text("".join(json.dumps(item) + "\n" for item in kept), encoding="utf-8")
        release = self.hold_store()
        # A file-size limit lets the drain write only part of what it moves from the leftover file.
        limit = (directory / "pending.jsonl").stat().st_size + aside.stat().st_size // 2
        subprocess.run([str(self.command), "lane", "check", "--config", "alpha"], cwd=str(self.directory),
                       env=self.env("alpha"), capture_output=True, text=True, timeout=60,
                       preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit)))
        release()
        self.lane_json("check")
        ids = self.ids()
        self.assertEqual([ids.count(item["id"]) for item in [first] + kept], [1] * (1 + len(kept)))
        self.assertFalse((directory / "refused.jsonl").exists())
        self.assertEqual(self.aside(directory), [])
        self.assertFalse((directory / "pending.jsonl").exists())
        self.assert_sound()

    def test_recorder_handoff_keeps_all(self):
        lane = "h-handoff"
        self.start(lane, "--runner", "persist", "--model", "ever-model-1", "--worktree", self.scratch(lane),
                   "--budget", "0.05")
        record = self.record(lane)
        supervisor = self.status(lane)["live"]["supervisor"]["pid"]
        directory = self.lane_dir(lane)
        # The lane's lock is held across the budget's end: the recorder's first write (lane.timeout, lane.ended
        # behind it) waits for it far longer than any wait of the supervising process.
        descriptor = os.open(str(directory), os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            self.assert_gone([record["pid"]], timeout=20)
            time.sleep(22.0)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        self.wait_gone(supervisor)
        self.lane_json("check")
        ids = self.ids()
        timeout = self.wait_event("lane.timeout", lane)
        ended = self.wait_event("lane.ended", lane)
        self.assertEqual((ids.count(timeout["id"]), ids.count(ended["id"])), (1, 1))
        self.assertLess(timeout["seq"], ended["seq"])
        self.assertEqual(ended["payload"]["reason"], "timeout")
        self.assertEqual(self.aside(directory), [])
        self.assertFalse((directory / "pending.jsonl").exists())
        self.assertFalse((directory / "refused.jsonl").exists())
        self.assert_sound()

    def test_stop_rereads_the_record(self):
        self.environment["LANEBOSS_PROCESSES"] = "portable"
        lane = "h-stale"
        self.start(lane, "--runner", "late", "--model", "late-model-1", "--worktree", self.scratch(lane))
        record = self.record(lane)
        supervisor = self.status(lane)["live"]["supervisor"]["pid"]
        path = self.run_record_path(lane)
        barrier = self.directory / "ps-barrier"
        barrier.mkdir()
        fake = self.fake_program("ps", BARRIER_PS.format(real=PS))
        stop = subprocess.Popen([str(self.command), "lane", "stop", "--config", "alpha", "--lane", lane],
                                cwd=str(self.directory), env=self.with_path(fake, E2E_PS_BARRIER=str(barrier)),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 30
        while not (barrier / "taken").exists():
            self.assertLess(time.monotonic(), deadline, "lane stop never asked about the supervising process")
            time.sleep(0.05)
        # lane stop has read the run record and asks whether the supervising process lives. Meanwhile the run starts
        # a worker, the supervising process records it and dies.
        self.go(lane)
        helper = self.records["alpha"] / (lane + ".1.helper.json")
        while not helper.is_file():
            self.assertLess(time.monotonic(), deadline, "the helper left no record")
            time.sleep(0.1)
        worker = json.loads(helper.read_text(encoding="utf-8"))["worker"]
        self.sentinels.append(worker)
        while worker not in [item["pid"] for item in json.loads(path.read_text(encoding="utf-8"))["processes"]]:
            self.assertLess(time.monotonic(), deadline, "the supervising process never recorded the worker")
            time.sleep(0.1)
        os.kill(supervisor, signal.SIGKILL)
        self.wait_gone(supervisor, timeout=10)
        (barrier / "go").write_text("go\n", encoding="utf-8")
        output, errors = stop.communicate(timeout=120)
        self.assertEqual(stop.returncode, 0, errors)
        self.assertEqual(json.loads(output)["stopped_by"], "lane-stop")
        self.assert_gone([record["pid"], worker], timeout=5)
        self.assertEqual([(item["lane"], item["survivors"]) for item in self.lane_json("check")["lost"]],
                         [(lane, 0)])
        self.assert_sound()

    def test_reuse_checks_registry(self):
        self.add_config("beta")
        shared = self.scratch("h-shared")
        self.start("h-old", "--runner", "plain", "--model", "plain-model-1", "--worktree", shared)
        self.wait_event("lane.ended", "h-old")
        self.lane_json("mark", "--lane", "h-old", "--state", "abandoned")
        self.lane_json("clean", "--lane", "h-old")
        self.start("h-beta", "--runner", "persist", "--model", "ever-model-1", "--worktree", shared, config="beta")
        record = self.record("h-beta", config="beta")
        before = listing(shared)
        moved = dict(self.env("alpha"), LANEBOSS_TEST_CLAIMS_DIR=str(self.directory / "other-claims"))
        # alpha's lane started again in that directory, with the test registry mistakenly moved: refused.
        result = self.run_laneboss("lane", "start", "--config", "alpha", "--lane", "h-old", "--brief",
                                   self.brief("alpha-h-old-again"), "--runner", "writer", "--model", "writer-model-1",
                                   "--worktree", shared, "--reuse", code=2, environment=moved)
        self.assertIn("registry", result.stderr)
        self.assertEqual(len(self.lane_events("h-old", "lane.started")), 1)
        self.assertEqual(listing(shared), before)
        self.assertEqual(list((self.directory / "other-claims").glob("*.json")), [])
        self.assertTrue(self.alive(record["pid"]))
        self.assertTrue(self.status("h-beta", config="beta")["running"])
        self.lane_json("stop", "--lane", "h-beta", config="beta")
        self.assert_sound()
        self.assert_sound("beta")

    def leader(self, pid):
        """An unrelated session leader under the process id `pid` (Linux, root through sudo), or None."""
        if not sys.platform.startswith("linux") or shutil.which("sudo") is None or subprocess.run(
                ["sudo", "-n", "true"], capture_output=True).returncode != 0:
            return None
        for attempt in range(100):
            subprocess.run(["sudo", "-n", "sh", "-c", "echo {} > /proc/sys/kernel/ns_last_pid".format(pid - 1)],
                           capture_output=True)
            process = subprocess.Popen([sys.executable, "-c", LEADER], stdout=subprocess.PIPE, text=True)
            if process.pid == pid:
                process.stdout.readline()

                def end():
                    process.kill()
                    process.wait()
                    process.stdout.close()

                self.addCleanup(end)
                return process
            process.kill()
            process.wait()
            process.stdout.close()
        return None

    def test_group_needs_live_member(self):
        lane = "h-group"
        result = self.denied("stop", "lane", "start", "--config", "alpha", "--lane", lane, "--brief",
                             self.brief("alpha-" + lane), "--runner", "setsider", "--model", "setsid-model-1",
                             "--worktree", self.scratch(lane))
        if MACOS_SANDBOX_HIDES_PS:
            self.assertEqual(result.returncode, 2, result)
            self.assertIn("the process table cannot be read", result.stderr)
            return
        self.assertEqual(result.returncode, 0, result)
        record = self.record(lane)
        runner, child = record["pid"], record["children"][0]
        self.sentinels.append(child)
        path = self.run_record_path(lane)
        deadline = time.monotonic() + 30
        while child not in [item["pid"] for item in json.loads(path.read_text(encoding="utf-8"))["processes"]]:
            self.assertLess(time.monotonic(), deadline, "the supervising process never sampled the child")
            time.sleep(0.1)
        # The child leaves the runner's process group and session; the runner exits. The supervising process cannot
        # remove the child (its signals are denied). Once it has collected the runner, the runner's process id, which
        # was its process group's id, is taken by an unrelated session leader.
        self.go(lane)
        while exists(runner):
            self.assertLess(time.monotonic(), deadline, "the runner was never collected")
            time.sleep(0.005)
        leader = self.leader(runner)
        ended = self.wait_event("lane.ended", lane, timeout=60)
        recorded = [item["pid"] for item in json.loads(path.read_text(encoding="utf-8"))["processes"]]
        if leader is not None:
            # The id is in the record once: the runner's own identity. A second entry would be the leader's.
            self.assertEqual(recorded.count(leader.pid), 1, "an unrelated process entered the run record")
            self.assertIsNone(leader.poll())
        self.assertEqual(ended["payload"]["survivors"], 1)
        self.assert_sound()

    def test_old_payload_is_refused(self):
        self.start("h-new", "--runner", "plain", "--model", "plain-model-1", "--worktree", self.scratch("h-new"))
        self.wait_event("lane.ended", "h-new")
        written = [item for item in self.events() if item["lane"] == "h-new" and item["kind"] in
                   ("lane.started", "lane.ended")]
        # The same two events under another lane, as an earlier commit of this branch wrote them: lane.started without
        # claims, lane.ended without survivors; the lane's projection row as that commit kept it.
        store = Path(self.paths()["store"])
        with closing(sqlite3.connect(str(store))) as connection:
            seq = connection.execute("SELECT max(seq) FROM events").fetchone()[0]
            projection = json.loads(connection.execute("SELECT projection FROM lanes WHERE lane = 'h-new'").fetchone()[0])
            for item in written:
                seq += 1
                payload = {key: value for key, value in item["payload"].items() if key not in ("claims", "survivors")}
                event = {"seq": seq, "id": "ev-" + uuid.uuid4().hex, "kind": item["kind"], "lane": "h-older",
                         "actor": item["actor"], "occurred_at": item["occurred_at"], "payload": payload,
                         "protocol_version": item["protocol_version"], "recorded_at": item["recorded_at"]}
                digest = hashlib.sha256(canonical(event).encode("utf-8")).hexdigest()
                connection.execute("INSERT INTO events (seq, id, kind, lane, actor, occurred_at, payload, "
                                   "protocol_version, recorded_at, sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                   (seq, event["id"], event["kind"], "h-older", event["actor"], event["occurred_at"],
                                    canonical(payload), event["protocol_version"], event["recorded_at"], digest))
            projection.update(lane="h-older", last_seq=seq)
            connection.execute("INSERT INTO lanes (lane, projection) VALUES (?, ?)", ("h-older", canonical(projection)))
            connection.commit()
        self.lane_json("mark", "--lane", "h-older", "--state", "abandoned")
        for arguments in (("status", "--lane", "h-older"), ("stop", "--lane", "h-older"), ("resume", "--lane", "h-older"),
                          ("clean", "--lane", "h-older")):
            with self.subTest(arguments=arguments):
                result = self.lane(*arguments, code=3)
                self.assertIn("earlier version", result.stderr)
        result = self.start("h-older", "--runner", "plain", "--model", "plain-model-1", "--worktree",
                            self.scratch("h-older"), "--reuse", code=3)
        self.assertIn("earlier version", result.stderr)

    def test_leftovers_wait_for_lock(self):
        lane = "h-aside"
        self.start(lane, "--runner", "waiter", "--model", "waiter-model-1", "--worktree", self.scratch(lane))
        self.record(lane)
        started = self.wait_event("lane.started", lane)
        supervisor = self.status(lane)["live"]["supervisor"]["pid"]
        directory = self.lane_dir(lane)
        pending = directory / "pending.jsonl"
        stuck = self.envelope(lane, started)
        pending.write_text(json.dumps(stuck) + "\n", encoding="utf-8")
        pending.chmod(0)
        self.addCleanup(lambda: pending.exists() and pending.chmod(0o600))
        # Whoever holds the lane directory's lock goes first: here the test. The run ends; its end cannot go to the
        # unreadable pending file, and the supervising process may keep it aside only under that lock.
        descriptor = os.open(str(directory), os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            self.go(lane)
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                self.assertEqual(self.aside(directory), [], "events were kept aside while another held the lane's lock")
                time.sleep(0.2)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        self.wait_gone(supervisor)
        pending.chmod(0o600)
        self.lane_json("check")
        ended = self.wait_event("lane.ended", lane)
        ids = self.ids()
        self.assertEqual((ids.count(stuck["id"]), ids.count(ended["id"])), (1, 1))
        kept = [item for item in self.lane_events(lane, "lane.stuck") if item["id"] == stuck["id"]]
        self.assertLess(kept[0]["seq"], ended["seq"])
        self.assertEqual(self.aside(directory), [])
        self.assert_sound()

    def test_gone_refusals(self):
        lane = "h-gone1"
        self.start(lane, "--runner", "forever", "--model", "ever-model-1", "--worktree", self.scratch(lane))
        record = self.record(lane)
        # A readable run record: the normal survivor path applies, so the declaration is refused.
        self.kill_supervisor(lane)
        self.lane_json("check")
        result = self.lane("mark", "--lane", lane, "--gone", code=2)
        self.assertIn("run record", result.stderr)
        self.lane_json("stop", "--lane", lane)
        self.assert_gone([record["pid"]] + record["children"], timeout=5)
        # Without its record, but with its session and supervising process alive: refused too.
        other = "h-gone2"
        self.start(other, "--runner", "persist", "--model", "ever-model-1", "--worktree", self.scratch(other))
        live = self.record(other)
        path = self.run_record_path(other)
        # The supervising process writes the run record again only when it finds a process of the run that is not in
        # it yet (or retries a failed write). The record is deleted once it lists every process of the run, the runner
        # and the one child the stand-in starts: then nothing is left for the supervising process to write.
        wanted = {live["pid"], *live["children"]}
        deadline = time.monotonic() + 30
        while True:
            before = path.read_text(encoding="utf-8")
            if wanted <= {item["pid"] for item in json.loads(before)["processes"]}:
                break
            self.assertLess(time.monotonic(), deadline, "the supervising process never recorded the run's processes")
            time.sleep(0.1)
        path.unlink()
        result = self.lane("mark", "--lane", other, "--gone", code=2)
        if path.exists():
            self.fail("the supervising process wrote the run record again, so it had something to write after all; "
                      "before the deletion it held {}, now it holds {}".format(
                          before, path.read_text(encoding="utf-8")))
        self.assertIn("alive", result.stderr)
        self.assertEqual(self.lane_events(other, "lane.gone") + self.lane_events(lane, "lane.gone"), [])
        self.assertTrue(self.alive(live["pid"]))

    def test_gone_lets_lane_go_on(self):
        bystander = "h-bystand"
        self.start(bystander, "--runner", "persist", "--model", "ever-model-1", "--worktree", self.scratch(bystander))
        watched = self.record(bystander)
        before = self.lane_events(bystander)
        lane = "h-gone"
        scratch = self.scratch(lane)
        self.start(lane, "--runner", "forever", "--model", "ever-model-1", "--worktree", scratch)
        record = self.record(lane)
        self.kill_supervisor(lane)
        self.lane_json("check")
        self.lane_json("stop", "--lane", lane)
        self.assert_gone([record["pid"]] + record["children"], timeout=5)
        self.run_record_path(lane).unlink()
        self.lane("resume", "--lane", lane, code=2)
        # The supervisor declares the open launch gone; no end is made up.
        marked = self.lane_json("mark", "--lane", lane, "--gone")
        self.assertEqual(marked["kind"], "lane.gone")
        gone = self.wait_event("lane.gone", lane)
        self.assertEqual(gone["actor"], "supervisor")
        self.assertEqual(self.lane_events(lane, "lane.ended"), [])
        self.assertIsNone(self.status(lane)["exit_code"])
        self.lane_json("resume", "--lane", lane)
        self.assertEqual(self.wait_event("lane.ended", lane, run=2)["payload"]["reason"], "exit")
        self.lane_json("mark", "--lane", lane, "--state", "abandoned")
        self.lane_json("clean", "--lane", lane)
        self.start(lane, "--runner", "plain", "--model", "plain-model-1", "--worktree", scratch, "--reuse")
        self.wait_event("lane.ended", lane, run=3)
        self.assertEqual(self.lane_events(bystander), before)
        self.assertTrue(self.alive(watched["pid"]))
        self.lane_json("stop", "--lane", bystander)
        self.assert_sound()
