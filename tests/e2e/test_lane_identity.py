"""Fix round 1, findings 2 to 6 (rulings R14, R15 and R16): every run has an identity and every signal checks it;
the tmux server is reached by the socket path the launch recorded; the run's process tree is followed while it lives.
"""

import json
import time

from . import lanesupport, support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class LaneIdentityTest(lanesupport.LaneTest):
    def test_survivors_of_a_lost_run(self):
        self.start("i-orphan", "--runner", "forever", "--model", "ever-model-1", "--worktree",
                   self.scratch("i-orphan"))
        record = self.record("i-orphan")
        pids = [record["pid"]] + record["children"]
        self.kill_supervisor("i-orphan")
        # The runner and its child go on without supervision.
        self.assertTrue(all(self.alive(pid) for pid in pids))
        checked = self.lane_json("check")
        self.assertEqual(checked["lost"][0]["lane"], "i-orphan")
        lost = self.wait_event("lane.lost", "i-orphan")
        self.assertEqual((lost["payload"]["run"], lost["payload"]["survivors"]), (1, 2))
        self.assertEqual(self.status("i-orphan")["live"]["survivors"], 2)
        result = self.lane("resume", "--lane", "i-orphan", code=2)
        self.assertIn("surviv", result.stderr)
        self.assertEqual(self.lane_events("i-orphan", "lane.resumed"), [])
        self.lane("clean", "--lane", "i-orphan", code=2)
        stopped = self.lane_json("stop", "--lane", "i-orphan")
        self.assertEqual((stopped["run"], stopped["removed"]), (1, 2))
        self.assert_gone(pids, timeout=5)
        self.assertEqual(self.status("i-orphan")["live"]["survivors"], 0)
        self.lane_json("resume", "--lane", "i-orphan")
        self.assertEqual(self.wait_event("lane.ended", "i-orphan", run=2)["payload"]["reason"], "exit")
        self.assert_sound()

    def test_signals_check_the_start_time(self):
        self.start("i-ident", "--runner", "forever", "--model", "ever-model-1", "--worktree",
                   self.scratch("i-ident"))
        record = self.record("i-ident")
        pids = [record["pid"]] + record["children"]
        self.kill_supervisor("i-ident")
        self.lane_json("check")
        # An unrelated process appears in the run record under its own process id but with a start time that is not
        # its own, as a process that took over a recorded process id after the recorded one ended would look.
        wrong = self.sentinel()
        path = self.run_record_path("i-ident")
        run_record = json.loads(path.read_text(encoding="utf-8"))
        reference = next(item for item in run_record["processes"] if item["pid"] == record["pid"])
        run_record["processes"].append(dict(reference, pid=wrong.pid))
        path.write_text(json.dumps(run_record), encoding="utf-8")
        self.assertEqual(self.status("i-ident")["live"]["survivors"], 2)
        stopped = self.lane_json("stop", "--lane", "i-ident")
        self.assertEqual(stopped["removed"], 2)
        self.assert_gone(pids, timeout=5)
        time.sleep(1.0)
        self.assertIsNone(wrong.poll(), "a process whose start time does not match the record was signalled")
        self.assert_sound()

    def test_stop_acts_on_one_run(self):
        self.start("i-one", "--runner", "persist", "--model", "ever-model-1", "--worktree", self.scratch("i-one"))
        self.record("i-one")
        first = self.lane_json("stop", "--lane", "i-one")
        launch_one = self.wait_event("lane.started", "i-one", run=1)["payload"]["launch"]
        self.assertEqual((first["run"], first["launch"], first["reason"]), (1, launch_one, "stopped"))
        self.lane_json("resume", "--lane", "i-one")
        self.wait_event("lane.started", "i-one", run=2)
        record = self.record("i-one", run=2)
        result = self.lane("stop", "--lane", "i-one", "--run", "1", code=2)
        self.assertIn("run 2", result.stderr)
        time.sleep(0.5)
        self.assertTrue(self.alive(record["pid"]))
        self.assertTrue(self.status("i-one")["running"])
        second = self.lane_json("stop", "--lane", "i-one", "--run", "2")
        launch_two = self.wait_event("lane.started", "i-one", run=2)["payload"]["launch"]
        self.assertEqual((second["run"], second["launch"]), (2, launch_two))
        self.assertNotEqual(launch_one, launch_two)
        self.assert_gone([record["pid"]], timeout=5)
        self.assert_sound()

    def test_socket_ignores_environment(self):
        self.start("i-sock", "--runner", "forever", "--model", "ever-model-1", "--worktree", self.scratch("i-sock"))
        record = self.record("i-sock")
        socket = self.status("i-sock")["live"]["session"]["socket"]
        other = self.directory / "other-tmux"
        other.mkdir()
        for value in (str(other), None):
            if value is None:
                self.environment.pop("TMUX_TMPDIR", None)
            else:
                self.environment["TMUX_TMPDIR"] = value
            with self.subTest(TMUX_TMPDIR=value):
                lane = self.status("i-sock")
                self.assertEqual(lane["live"]["session"]["socket"], socket)
                self.assertIs(lane["live"]["session_alive"], True)
                self.assertIs(lane["live"]["supervisor"]["alive"], True)
                checked = self.lane_json("check")
                self.assertEqual((checked["lost"], checked["alive"]), ([], ["i-sock"]))
                self.assertEqual(self.lane_events("i-sock", "lane.lost"), [])
        self.lane_json("stop", "--lane", "i-sock")
        self.assert_gone([record["pid"]], timeout=5)
        self.environment["TMUX_TMPDIR"] = str(other)
        resumed = self.lane_json("resume", "--lane", "i-sock")
        self.assertEqual(resumed["session"]["socket"], socket)
        self.assertEqual(self.wait_event("lane.ended", "i-sock", run=2)["payload"]["reason"], "exit")
        self.assert_sound()

    def helper(self, lane, timeout=20):
        path = self.records["alpha"] / "{}.1.helper.json".format(lane)
        deadline = time.monotonic() + timeout
        while not path.is_file():
            self.assertLess(time.monotonic(), deadline, "the helper left no record")
            time.sleep(0.1)
        return json.loads(path.read_text(encoding="utf-8"))

    def test_detached_descendants_are_followed(self):
        for lane, extra in (("i-tree-stop", []), ("i-tree-budget", ["--budget", "0.15"])):
            with self.subTest(lane):
                self.start(lane, "--runner", "detacher", "--model", "detach-model-1", "--worktree",
                           self.scratch(lane), *extra)
                record = self.record(lane)
                helper = self.helper(lane)
                deadline = time.monotonic() + 10
                while self.alive(helper["helper"]):
                    self.assertLess(time.monotonic(), deadline, "the helper did not exit")
                    time.sleep(0.1)
                self.assertTrue(self.alive(helper["worker"]))
                if extra:
                    ended = self.wait_event("lane.ended", lane, timeout=40)
                    self.assertEqual(ended["payload"]["reason"], "timeout")
                else:
                    self.lane_json("stop", "--lane", lane)
                self.assert_gone([record["pid"], helper["worker"]], timeout=5)
        self.assert_sound()
