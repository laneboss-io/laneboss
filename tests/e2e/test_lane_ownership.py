"""Fix round 2, findings 1 and 9 and follow-ups 2, 5 and 6 (rulings R20, R24 and R26): a failed start undoes only
what it made; sessions and sockets are acted on by identity; clean refuses a foreign claim and releases its own; a
directory Git cannot be asked about is refused; nothing is written into a plain working directory; the lanes lock
is waited for only so long.
"""

import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from . import lanesupport, support

# git for the test: the first call of each launcher that creates a branch or a worktree waits until two launchers
# have reached that point, so both have passed their checks before either creates anything.
BARRIER_GIT = """barrier="{barrier}"
if {{ [ "$3" = worktree ] && [ "$4" = add ]; }} || {{ [ "$3" = branch ] && [ "${{4#-}}" = "$4" ]; }}; then
  touch "$barrier/$PPID"
  i=0
  while [ "$(ls "$barrier" | wc -l)" -lt 2 ] && [ $i -lt 200 ]; do sleep 0.1; i=$((i+1)); done
fi
exec "{real}" "$@"
"""
# git for the test: just before the launcher creates its branch or worktree, someone else creates the branch.
RIVAL_GIT = """if {{ [ "$3" = worktree ] && [ "$4" = add ]; }} || {{ [ "$3" = branch ] && [ "${{4#-}}" = "$4" ]; }}; then
  "{real}" -C "$2" branch {branch} 2>/dev/null
fi
exec "{real}" "$@"
"""


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


def listing(root):
    return sorted(str(path.relative_to(root)) for path in Path(root).rglob("*"))


class LaneOwnershipTest(lanesupport.LaneTest):
    def branches(self, repo, name):
        return self.git(repo, "branch", "--list", "--format=%(refname:short)", name).split()

    def test_losing_start_leaves_winner(self):
        self.add_config("beta")
        alpha = self.repos["alpha"]
        # Both configurations name alpha's repository by mistake and start the same lane at the same time.
        (self.home / "configs" / "beta" / "projects" / "web.toml").write_text(lanesupport.project_text(alpha),
                                                                              encoding="utf-8")
        barrier = self.directory / "git-barrier"
        barrier.mkdir()
        fake = self.fake_program("git", BARRIER_GIT.format(barrier=barrier, real=shutil.which("git")))
        processes = {}
        for config in ("alpha", "beta"):
            arguments = [str(self.command), "lane", "start", "--config", config, "--lane", "web-w1", "--brief",
                         str(self.brief(config + "-web-w1")), "--project", "web", "--runner", "persist", "--model",
                         "ever-model-1"]
            processes[config] = subprocess.Popen(arguments, cwd=str(self.directory), env=self.with_path(fake, config),
                                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        results = {config: (process.wait(timeout=90), process.communicate()) for config, process in processes.items()}
        self.assertEqual(sorted(code for code, _ in results.values()), [0, 2], results)
        winner = next(config for config, (code, _) in results.items() if code == 0)
        loser = "beta" if winner == "alpha" else "alpha"
        started = json.loads(results[winner][1][0])
        worktree = Path(started["worktree"])
        record = self.record("web-w1", config=winner)
        # The losing start undid nothing of the winner's: its worktree, branch, claim and runner are untouched.
        self.assertTrue(worktree.is_dir())
        self.assertEqual(self.git(worktree, "rev-parse", "--abbrev-ref", "HEAD"), "web-w1")
        self.assertEqual(self.branches(alpha, "web-w1"), ["web-w1"])
        self.assertTrue(self.alive(record["pid"]))
        self.assertEqual(self.lane_events("web-w1", config=loser), [])
        self.lane_json("stop", "--lane", "web-w1", config=winner)
        self.lane_json("mark", "--lane", "web-w1", "--state", "merged", config=winner)
        cleaned = self.lane_json("clean", "--lane", "web-w1", config=winner)
        self.assertIn({"item": "worktree", "path": str(worktree)}, cleaned["removed"])
        self.assertIn({"item": "branch", "name": "web-w1"}, cleaned["removed"])
        self.assert_sound()
        self.assert_sound("beta")

    def test_failed_add_keeps_branch(self):
        repo = self.repos["alpha"]
        fake = self.fake_program("git", RIVAL_GIT.format(real=shutil.which("git"), branch="web-w2"))
        result = self.run_laneboss("lane", "start", "--config", "alpha", "--lane", "web-w2", "--brief",
                                   self.brief("alpha-web-w2"), "--project", "web", "--runner", "plain", "--model",
                                   "plain-model-1", code=2, environment=self.with_path(fake))
        self.assertIn("web-w2", result.stderr)
        # The branch someone else made is kept; nothing of this start is left.
        self.assertEqual(self.branches(repo, "web-w2"), ["web-w2"])
        self.assertFalse(Path(str(repo) + "-web-w2").exists())
        self.assertEqual(self.lane_events("web-w2"), [])

    def test_clean_spares_a_replaced_session(self):
        self.start("s-repl", "--runner", "plain", "--model", "plain-model-1", "--worktree", self.scratch("s-repl"))
        self.wait_event("lane.ended", "s-repl")
        self.lane_json("mark", "--lane", "s-repl", "--state", "abandoned")
        socket = self.paths()["socket"]
        # Another session took the lane's name at the lane's socket; its process is not the lane's.
        self.tmux(socket, "-f", os.devnull, "new-session", "-d", "-s", "s-repl", sys.executable, "-c",
                  "import time; time.sleep(600)")
        pane = int(self.tmux(socket, "list-panes", "-t", "=s-repl", "-F", "#{pane_pid}").stdout.split()[0])
        self.sentinels.append(pane)
        cleaned = self.lane_json("clean", "--lane", "s-repl")
        self.assertNotIn("session", [item["item"] for item in cleaned["removed"]])
        self.assertIn({"item": "session", "name": "s-repl", "why": "not-this-lane"}, cleaned["kept"])
        time.sleep(0.5)
        self.assertTrue(self.alive(pane))
        self.assertIn("s-repl", self.tmux(socket, "list-sessions", "-F", "#{session_name}").stdout.split())
        self.assert_sound()

    def test_socket_link_is_refused(self):
        self.add_config("beta")
        self.start("s-one", "--runner", "persist", "--model", "ever-model-1", "--worktree", self.scratch("s-one"))
        one = self.record("s-one")
        self.start("s-two", "--runner", "plain", "--model", "plain-model-1", "--worktree", self.scratch("s-two"))
        self.wait_event("lane.ended", "s-two")
        self.lane_json("mark", "--lane", "s-two", "--state", "abandoned")
        self.start("s-two", "--runner", "persist", "--model", "ever-model-1", "--worktree",
                   self.scratch("s-two-beta"), config="beta")
        two = self.record("s-two", config="beta")
        socket = Path(self.paths()["socket"])
        aside = socket.with_name(socket.name + ".aside")
        socket.rename(aside)
        socket.symlink_to(self.paths("beta")["socket"])

        def restore():
            if socket.is_symlink():
                socket.unlink()
                aside.rename(socket)

        self.addCleanup(restore)
        # alpha's socket path now leads to beta's server, where a live lane has the name of alpha's finished one.
        for arguments in (("status",), ("status", "--lane", "s-one"), ("check",), ("stop", "--lane", "s-one"),
                          ("clean", "--lane", "s-two"), ("resume", "--lane", "s-two")):
            with self.subTest(arguments=arguments):
                result = self.lane(*arguments, code=2)
                self.assertIn("link", result.stderr)
        time.sleep(0.5)
        self.assertTrue(self.alive(one["pid"]))
        self.assertTrue(self.alive(two["pid"]))
        self.assertTrue(self.status("s-two", config="beta")["running"])
        restore()
        directory = socket.parent
        directory.chmod(0o750)
        try:
            result = self.lane("status", "--lane", "s-one", code=2)
            self.assertIn(str(directory), result.stderr)
        finally:
            directory.chmod(0o700)
        self.lane_json("stop", "--lane", "s-one")
        self.lane_json("stop", "--lane", "s-two", config="beta")
        self.assert_gone([one["pid"], two["pid"]], timeout=5)
        self.assert_sound()
        self.assert_sound("beta")

    def test_clean_refuses_foreign_claim(self):
        self.add_config("beta")
        repo = self.repos["alpha"]
        started = self.start("web-f1", "--project", "web", "--runner", "plain", "--model", "plain-model-1")
        self.wait_event("lane.ended", "web-f1")
        self.lane_json("mark", "--lane", "web-f1", "--state", "merged")
        worktree = Path(started["worktree"])
        self.git(repo, "worktree", "remove", worktree)
        self.git(repo, "worktree", "add", "-q", "-b", "replacement", worktree)
        self.start("f1-beta", "--runner", "persist", "--model", "ever-model-1", "--worktree", worktree, config="beta")
        record = self.record("f1-beta", config="beta")
        before = listing(worktree)
        result = self.lane("clean", "--lane", "web-f1", code=2)
        self.assertIn("beta", result.stderr)
        # Refused before anything was removed: the lane's merged branch and the replacement are both still there.
        self.assertEqual(self.branches(repo, "web-f1"), ["web-f1"])
        self.assertEqual(listing(worktree), before)
        self.assertEqual(self.lane_events("web-f1", "lane.cleaned"), [])
        self.assertTrue(self.alive(record["pid"]))
        self.lane_json("stop", "--lane", "f1-beta", config="beta")
        self.assert_sound()
        self.assert_sound("beta")

    def test_kept_worktree_loses_claim(self):
        started = self.start("web-f2", "--project", "web", "--runner", "plain", "--model", "plain-model-1")
        self.wait_event("lane.ended", "web-f2")
        self.lane_json("mark", "--lane", "web-f2", "--state", "merged")
        worktree = Path(started["worktree"])
        # The lane's branch was renamed in its worktree: clean keeps the worktree, and with it no claim of the lane.
        self.git(worktree, "branch", "-m", "web-f2", "renamed")
        cleaned = self.lane_json("clean", "--lane", "web-f2")
        self.assertIn({"item": "worktree", "path": str(worktree), "why": "not-this-lane"}, cleaned["kept"])
        self.assertTrue(worktree.is_dir())
        self.start("f2-next", "--runner", "plain", "--model", "plain-model-1", "--worktree", worktree)
        self.assertEqual(self.wait_event("lane.ended", "f2-next")["payload"]["reason"], "exit")
        self.assert_sound()

    def test_worktree_needs_git_answer(self):
        failing = self.fake_program("git", 'echo "fatal: cannot run here" >&2\nexit 128\n')
        plain = self.scratch("g-plain")
        result = self.run_laneboss("lane", "start", "--config", "alpha", "--lane", "g-fail", "--brief",
                                   self.brief("alpha-g-fail"), "--runner", "writer", "--model", "writer-model-1",
                                   "--worktree", plain, code=2, environment=self.with_path(failing))
        self.assertIn("Git", result.stderr)
        self.assertEqual(listing(plain), [])
        repo = self.repos["alpha"]
        before = listing(repo)
        (repo / ".git").chmod(0)
        try:
            self.start("g-locked", "--runner", "writer", "--model", "writer-model-1", "--worktree", repo, code=2)
        finally:
            (repo / ".git").chmod(0o755)
        self.assertFalse((repo / "work.txt").exists())
        self.assertEqual(listing(repo), before)
        self.assertEqual(self.lane_events("g-fail") + self.lane_events("g-locked"), [])

    def test_plain_directory_stays_clean(self):
        plain = self.scratch("g-own")
        self.start("g-own", "--runner", "plain", "--model", "plain-model-1", "--worktree", plain)
        self.wait_event("lane.ended", "g-own")
        self.assertEqual(listing(plain), [])
        # The executor makes its working directory a repository: no launcher file shows up in it.
        self.git(plain, "init", "-q")
        self.assertEqual(self.git(plain, "status", "--porcelain", "--untracked-files=all"), "")
        self.lane_json("resume", "--lane", "g-own")
        self.wait_event("lane.ended", "g-own", run=2)
        self.lane_json("mark", "--lane", "g-own", "--state", "abandoned")
        cleaned = self.lane_json("clean", "--lane", "g-own")
        self.assertIn({"item": "worktree", "path": str(plain), "why": "not-created"}, cleaned["kept"])
        shutil.rmtree(str(plain / ".git"))
        # The claim was released: another lane may work there now.
        self.start("g-next", "--runner", "plain", "--model", "plain-model-1", "--worktree", plain)
        self.wait_event("lane.ended", "g-next")
        self.assertEqual(listing(plain), [])
        self.assert_sound()

    def test_lanes_lock_wait_is_bounded(self):
        config = self.home / "configs" / "alpha" / "config.toml"
        config.write_text(config.read_text(encoding="utf-8").replace(
            "stop_grace_seconds = 2\n", "stop_grace_seconds = 2\nlock_wait_seconds = 2\n"), encoding="utf-8")
        self.start("g-first", "--runner", "plain", "--model", "plain-model-1", "--worktree", self.scratch("g-first"))
        self.wait_event("lane.ended", "g-first")
        descriptor = os.open(str(Path(self.paths()["state_dir"]) / "lanes.lock"), os.O_RDWR)
        self.addCleanup(os.close, descriptor)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        began = time.monotonic()
        result = self.start("g-second", "--runner", "plain", "--model", "plain-model-1", "--worktree",
                            self.scratch("g-second"), code=2)
        self.assertLess(time.monotonic() - began, 15)
        self.assertIn("lanes lock", result.stderr)
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        self.start("g-second", "--runner", "plain", "--model", "plain-model-1", "--worktree",
                   self.directory / "work" / "g-second")
        self.wait_event("lane.ended", "g-second")
        self.assert_sound()
