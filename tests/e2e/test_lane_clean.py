"""G. lane mark records the supervisor's decisions, and lane clean removes only what the launcher made, never by force,
and keeps the lane's record."""

from pathlib import Path

from . import lanesupport, support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class LaneCleanTest(lanesupport.LaneTest):
    def finished(self, lane, runner="plain"):
        self.start(lane, "--project", "web", "--runner", runner, "--model", runner + "-model-1")
        self.wait_event("lane.ended", lane)
        return self.wait_event("lane.started", lane)["payload"]

    def branches(self, name):
        """The repository's branches of this name, read without Git's markers for checked-out branches."""
        return self.git(self.repos["alpha"], "branch", "--list", "--format=%(refname:short)", name).split()

    def lane_directory(self, lane):
        return Path(self.laneboss_json("config", "path", "alpha")["state_dir"]) / "lanes" / lane

    def test_merged_lane_is_cleaned(self):
        started = self.finished("web-g1")
        worktree = Path(started["worktree"])
        result = self.lane("clean", "--lane", "web-g1", code=2)
        self.assertIn("merged or abandoned", result.stderr)
        self.lane_json("mark", "--lane", "web-g1", "--state", "accepted")
        self.lane("clean", "--lane", "web-g1", code=2)
        marked = self.lane_json("mark", "--lane", "web-g1", "--state", "merged")
        self.assertEqual(marked["kind"], "lane.state")
        kept_before = sorted(str(path.relative_to(self.lane_directory("web-g1")))
                             for path in self.lane_directory("web-g1").rglob("*"))
        self.assertIn("output.log", kept_before)
        cleaned = self.lane_json("clean", "--lane", "web-g1")
        self.assertFalse(worktree.exists())
        self.assertEqual(self.branches("web-g1"), [])
        event = self.wait_event("lane.cleaned", "web-g1")
        self.assertEqual(event["payload"], {"removed": cleaned["removed"], "kept": cleaned["kept"]})
        self.assertIn({"item": "worktree", "path": str(worktree)}, event["payload"]["removed"])
        self.assertIn({"item": "branch", "name": "web-g1"}, event["payload"]["removed"])
        self.assertIn({"item": "lane-directory", "path": str(self.lane_directory("web-g1")), "why": "record"},
                      event["payload"]["kept"])
        # The lane's directory in the state directory is still there: logs, rendered briefs and kept inputs.
        self.assertEqual(sorted(str(path.relative_to(self.lane_directory("web-g1")))
                                for path in self.lane_directory("web-g1").rglob("*")), kept_before)
        self.assertTrue(Path(started["log"]).is_file())
        self.assertTrue(Path(started["brief"]["path"]).is_file())
        self.lane("clean", "--lane", "web-g1", code=2)
        # A merged and cleaned lane may be started again, but only when the caller says so.
        self.start("web-g1", "--project", "web", "--runner", "plain", "--model", "plain-model-1", code=2)
        again = self.start("web-g1", "--project", "web", "--runner", "plain", "--model", "plain-model-1", "--reuse")
        self.assertEqual((again["run"], again["how"]), (2, "reuse"))
        self.wait_event("lane.ended", "web-g1", run=2)
        self.assertTrue(Path(again["worktree"]).is_dir())
        self.assert_sound()

    def test_uncommitted_work_is_never_removed(self):
        started = self.finished("web-g2", runner="writer")
        worktree = Path(started["worktree"])
        self.assertTrue((worktree / "work.txt").is_file())
        self.lane_json("mark", "--lane", "web-g2", "--state", "abandoned")
        count = len(self.events())
        result = self.lane("clean", "--lane", "web-g2", code=2)
        self.assertIn("uncommitted", result.stderr)
        self.assertTrue((worktree / "work.txt").is_file())
        self.assertEqual(self.branches("web-g2"), ["web-g2"])
        self.assertEqual(len(self.events()), count)
        self.assertEqual(self.lane_events("web-g2", "lane.cleaned"), [])
        self.assert_sound()

    def test_abandoned_lane_keeps_its_branch(self):
        started = self.finished("web-g3")
        self.lane_json("mark", "--lane", "web-g3", "--state", "abandoned")
        cleaned = self.lane_json("clean", "--lane", "web-g3")
        self.assertFalse(Path(started["worktree"]).exists())
        self.assertEqual(self.branches("web-g3"), ["web-g3"])
        self.assertIn({"item": "branch", "name": "web-g3", "why": "abandoned"}, cleaned["kept"])
        self.assertNotIn("branch", [item["item"] for item in cleaned["removed"]])
        self.assert_sound()

    def test_mark_records_decisions(self):
        self.finished("web-g4")
        for landing in ("merged", "deployed", "landed"):
            result = self.lane_json("mark", "--lane", "web-g4", "--landing", landing)
            self.assertEqual(result["kind"], "lane." + landing)
        lane = self.status("web-g4")
        self.assertTrue(all(lane["landing"][name] for name in ("merged", "deployed", "landed")))
        self.assertEqual(lane["state"], "verifying")
        self.lane("mark", "--lane", "web-g4", "--state", "running", code=2)
        self.lane("mark", "--lane", "web-g4", "--landing", "shipped", code=2)
        self.lane("mark", "--lane", "web-g4", code=2)
        self.lane("mark", "--lane", "web-g-absent", "--state", "merged", code=2)
        self.start("web-g5", "--project", "web", "--runner", "forever", "--model", "ever-model-1")
        self.record("web-g5")
        self.lane("mark", "--lane", "web-g5", "--state", "abandoned", code=2)
        self.lane_json("stop", "--lane", "web-g5")
        self.lane_json("mark", "--lane", "web-g5", "--state", "abandoned")
        self.assert_sound()
