"""C and D. The budget stops a run and its whole process tree; a quiet log is reported and the run goes on; a run's end
is classified by the runner's patterns."""

from . import lanesupport, support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class LaneBudgetTest(lanesupport.LaneTest):
    def test_budget_stops_the_whole_tree(self):
        # The stubborn stand-in ignores SIGTERM and has two children that ignore it too, one in a session of its own.
        follower = self.follow()
        self.start("c-timeout", "--runner", "stubborn", "--model", "stubborn-model-1", "--worktree",
                   self.scratch("c-timeout"), "--budget", "0.05")
        record = self.record("c-timeout")
        pids = [record["pid"]] + record["children"]
        self.assertEqual(len(pids), 3)
        self.assertTrue(all(self.alive(pid) for pid in pids))
        _, timeout = follower.wait(self, "lane.timeout", "c-timeout")
        _, ended = follower.wait(self, "lane.ended", "c-timeout")
        self.assertLess(timeout["seq"], ended["seq"])
        self.assertEqual((timeout["payload"]["run"], timeout["payload"]["budget_minutes"]), (1, 0.05))
        self.assertGreaterEqual(timeout["payload"]["elapsed_seconds"], 3.0)
        self.assertEqual((ended["payload"]["reason"], ended["payload"]["exit_code"], ended["payload"]["signal"]),
                         ("timeout", None, 9))
        self.assert_gone(pids)
        lane = self.status("c-timeout")
        self.assertEqual((lane["running"], lane["reason"], lane["live"]["session_alive"]), (False, "timeout", False))
        self.assert_sound()

    def test_quiet_run_keeps_running(self):
        follower = self.follow()
        self.start("c-quiet", "--runner", "quiet", "--model", "quiet-model-1", "--worktree", self.scratch("c-quiet"))
        record = self.record("c-quiet")
        _, stuck = follower.wait(self, "lane.stuck", "c-quiet")
        self.assertEqual((stuck["payload"]["run"], stuck["payload"]["quiet_seconds"]), (1, 2))
        self.assertTrue(self.alive(record["pid"]))
        self.assertEqual(self.lane_events("c-quiet", "lane.ended"), [])
        lane = self.status("c-quiet")
        self.assertEqual((lane["state"], lane["running"], lane["live"]["session_alive"]), ("running", True, True))
        self.assertIsNotNone(lane["times"]["stuck"])
        self.assertGreaterEqual(lane["live"]["quiet_seconds"], 2.0)
        stopped = self.lane_json("stop", "--lane", "c-quiet")
        self.assertEqual(stopped["reason"], "stopped")
        self.assert_gone([record["pid"]])
        self.assert_sound()

    def test_end_is_classified(self):
        cases = (("d-limit", "limit", "limit", 1, "limit_patterns[0]"),
                 ("d-dropped", "dropped", "dropped", 1, "dropped_patterns[0]"),
                 ("d-fail", "fail", "exit", 3, None),
                 ("d-ok", "plain", "exit", 0, None))
        for lane, runner, _, _, _ in cases:
            arguments = ["--runner", runner, "--model", runner + "-model-1", "--worktree", self.scratch(lane)]
            if runner == "limit":
                arguments += ["--account", "acc-three"]
            self.start(lane, *arguments)
        for lane, runner, reason, code, pattern in cases:
            with self.subTest(lane):
                payload = self.wait_event("lane.ended", lane)["payload"]
                self.assertEqual((payload["reason"], payload["exit_code"], payload["signal"], payload["pattern"]),
                                 (reason, code, None, pattern))
                self.assertEqual(self.status(lane)["reason"], reason)
        self.assert_sound()
