"""Fix round 1, findings 8, 9 and 10 and follow-ups 1, 2, 6 and 7 (rulings R17 and R18): a working directory is
claimed by one lane of one configuration; clean removes only what still carries the lane's claim and branch, and
says what Git left behind; the launcher's Git commands ignore inherited Git variables.
"""

import os
from pathlib import Path
import stat
import subprocess
import time

from . import lanesupport, support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


def listing(root):
    return sorted(str(path.relative_to(root)) for path in Path(root).rglob("*"))


class LaneClaimTest(lanesupport.LaneTest):
    def branches(self, repo, name):
        return self.git(repo, "branch", "--list", "--format=%(refname:short)", name).split()

    def test_claimed_worktree_refused(self):
        self.add_config("beta")
        started = self.start("web-c1", "--project", "web", "--runner", "persist", "--model", "ever-model-1")
        record = self.record("web-c1")
        worktree = Path(started["worktree"])
        before = listing(worktree)
        result = self.start("c1-beta", "--runner", "writer", "--model", "writer-model-1", "--worktree", worktree,
                            config="beta", code=2)
        self.assertIn("alpha", result.stderr)
        self.assertEqual(list(self.records["beta"].iterdir()), [])
        self.assertFalse((worktree / "work.txt").exists())
        self.assertEqual(listing(worktree), before)
        self.assertEqual(self.lane_events("c1-beta", config="beta"), [])
        self.assertTrue(self.alive(record["pid"]))
        self.lane_json("stop", "--lane", "web-c1")
        self.assert_sound()
        self.assert_sound("beta")

    def test_clean_keeps_a_replacement_worktree(self):
        repo = self.repos["alpha"]
        started = self.start("web-c2", "--project", "web", "--runner", "plain", "--model", "plain-model-1")
        self.wait_event("lane.ended", "web-c2")
        worktree = Path(started["worktree"])
        self.lane_json("mark", "--lane", "web-c2", "--state", "merged")
        # By hand: the lane's worktree goes, and another worktree on another branch takes its path.
        self.git(repo, "worktree", "remove", worktree)
        self.git(repo, "worktree", "add", "-q", "-b", "replacement", worktree)
        (worktree / "README.txt").write_text("the replacement's own change, committed\n", encoding="utf-8")
        self.git(worktree, "commit", "-q", "-am", "replacement work")
        before = listing(worktree)
        cleaned = self.lane_json("clean", "--lane", "web-c2")
        self.assertTrue(worktree.is_dir())
        self.assertEqual(listing(worktree), before)
        self.assertEqual(self.git(worktree, "rev-parse", "--abbrev-ref", "HEAD"), "replacement")
        self.assertEqual(self.branches(repo, "replacement"), ["replacement"])
        self.assertIn({"item": "worktree", "path": str(worktree), "why": "not-this-lane"}, cleaned["kept"])
        self.assertNotIn("worktree", [item["item"] for item in cleaned["removed"]])
        self.assert_sound()

    def test_resume_after_directory_taken(self):
        shared = self.scratch("shared")
        self.start("c3-first", "--runner", "plain", "--model", "plain-model-1", "--worktree", shared)
        self.wait_event("lane.ended", "c3-first")
        self.lane_json("mark", "--lane", "c3-first", "--state", "abandoned")
        self.lane_json("clean", "--lane", "c3-first")
        self.start("c3-second", "--runner", "plain", "--model", "plain-model-1", "--worktree", shared)
        self.wait_event("lane.ended", "c3-second")
        result = self.lane("resume", "--lane", "c3-first", code=2)
        self.assertIn("c3-", result.stderr)
        self.assertEqual(self.lane_events("c3-first", "lane.resumed"), [])
        self.assert_sound()

    def test_two_starts_on_one_directory(self):
        shared = self.scratch("both")
        processes = []
        # An unexpected error shows its traceback in the failure message.
        environment = dict(self.env("alpha"), LANEBOSS_DEBUG="1")
        for lane in ("c4-one", "c4-two"):
            arguments = [str(self.command), "lane", "start", "--config", "alpha", "--lane", lane, "--brief",
                         str(self.brief("alpha-" + lane)), "--runner", "persist", "--model", "ever-model-1",
                         "--worktree", str(shared)]
            processes.append(subprocess.Popen(arguments, cwd=str(self.directory), env=environment,
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        results = [(process.wait(timeout=60), process.communicate()) for process in processes]
        codes = sorted(code for code, _ in results)
        self.assertEqual(codes, [0, 2], results)
        winner = ["c4-one", "c4-two"][[code for code, _ in results].index(0)]
        # The loser is refused because the directory is taken, and for no other reason.
        loser = results[[code for code, _ in results].index(2)][1][1]
        self.assertTrue("claimed by lane " + winner in loser or "lane {} already works in".format(winner) in loser,
                        results)
        self.assertEqual(len(self.lane_events("c4-one", "lane.started") + self.lane_events("c4-two", "lane.started")), 1)
        self.lane_json("stop", "--lane", winner)
        self.assert_sound()

    def test_clean_and_resume_do_not_interleave(self):
        self.start("web-c5", "--project", "web", "--runner", "plain", "--model", "plain-model-1")
        self.wait_event("lane.ended", "web-c5")
        started = self.wait_event("lane.started", "web-c5")["payload"]
        self.lane_json("mark", "--lane", "web-c5", "--state", "abandoned")
        processes = []
        for action in ("clean", "resume"):
            processes.append(subprocess.Popen([str(self.command), "lane", action, "--config", "alpha", "--lane",
                                               "web-c5"], cwd=str(self.directory), env=self.env("alpha"),
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        clean, resume = [(process.wait(timeout=60), process.communicate()) for process in processes]
        if resume[0] == 0:
            # The resume came first: its run started in the worktree, so the clean was refused.
            self.assertEqual(clean[0], 2, clean)
            self.assertTrue(Path(started["worktree"]).is_dir())
            self.wait_event("lane.ended", "web-c5", run=2)
        else:
            # The clean came first: the worktree is gone and the resume was refused before any run started.
            self.assertEqual((clean[0], resume[0]), (0, 2), (clean, resume))
            self.assertFalse(Path(started["worktree"]).exists())
            self.assertEqual(self.lane_events("web-c5", "lane.resumed"), [])
        self.assert_sound()

    def test_main_working_copy_is_refused(self):
        repo = self.repos["alpha"]
        before = listing(repo)
        result = self.start("c6-main", "--runner", "writer", "--model", "writer-model-1", "--worktree", repo, code=2)
        self.assertIn("main working copy", result.stderr)
        self.assertEqual(listing(repo), before)
        self.assertFalse((repo / "work.txt").exists())
        self.assertEqual(list(self.records["alpha"].iterdir()), [])
        inside = repo / "docs"
        self.start("c6-inside", "--runner", "writer", "--model", "writer-model-1", "--worktree", inside, code=2)
        self.assertEqual(listing(repo), before)

    def test_git_variables_do_not_redirect(self):
        self.add_config("beta")
        alpha, beta = self.repos["alpha"], self.repos["beta"]
        # beta has a merged branch with the name alpha's lane will use.
        self.git(beta, "branch", "web-c7")
        state = {"branches": self.git(beta, "branch", "--list", "--format=%(refname:short)"),
                 "worktrees": self.git(beta, "worktree", "list", "--porcelain"),
                 "head": self.git(beta, "rev-parse", "HEAD"), "files": listing(beta)}
        for name, value in (("GIT_DIR", beta / ".git"), ("GIT_WORK_TREE", beta), ("GIT_INDEX_FILE", beta / ".git" /
                                                                                          "index")):
            self.environment[name] = str(value)
        started = self.start("web-c7", "--project", "web", "--runner", "plain", "--model", "plain-model-1")
        self.assertTrue(started["worktree"].startswith(str(alpha) + "-"))
        self.wait_event("lane.ended", "web-c7")
        self.lane_json("resume", "--lane", "web-c7")
        self.wait_event("lane.ended", "web-c7", run=2)
        self.lane_json("mark", "--lane", "web-c7", "--state", "merged")
        cleaned = self.lane_json("clean", "--lane", "web-c7")
        self.assertIn({"item": "branch", "name": "web-c7"}, cleaned["removed"])
        for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
            self.environment.pop(name)
        self.assertEqual(self.branches(alpha, "web-c7"), [])
        self.assertFalse(Path(started["worktree"]).exists())
        self.assertEqual({"branches": self.git(beta, "branch", "--list", "--format=%(refname:short)"),
                          "worktrees": self.git(beta, "worktree", "list", "--porcelain"),
                          "head": self.git(beta, "rev-parse", "HEAD"), "files": listing(beta)}, state)
        self.assert_sound()

    def test_partial_removal_is_reported(self):
        if os.geteuid() == 0:
            self.fail("run the suite as a non-root user: root ignores directory permissions")
        started = self.start("web-c8", "--project", "web", "--runner", "plain", "--model", "plain-model-1")
        self.wait_event("lane.ended", "web-c8")
        worktree = Path(started["worktree"])
        self.lane_json("mark", "--lane", "web-c8", "--state", "merged")
        docs = worktree / "docs"
        docs.chmod(stat.S_IRUSR | stat.S_IXUSR)
        self.addCleanup(docs.chmod, stat.S_IRWXU)
        before = listing(worktree)
        result = self.lane("clean", "--lane", "web-c8", code=2)
        after = listing(worktree) if worktree.exists() else []
        if after == before:
            self.assertIn("unchanged", result.stderr)
        else:
            self.assertIn("partly removed", result.stderr)
            self.assertIn("{} of {}".format(len(before) - len(after), len(before)), result.stderr)
        self.assertEqual(self.lane_events("web-c8", "lane.cleaned"), [])
        docs.chmod(stat.S_IRWXU)
        self.assert_sound()
