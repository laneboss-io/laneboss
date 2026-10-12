"""LB-109a. The disk line at the start of a lane: a real file system read the way `df` reads it, the latch between
the two lines, and the refusal of a new lane or worktree.

Black box, through the installed `laneboss` command only, against a real small file system that the box prep mounts
(`LB_PREP=launcher` provides `LANEBOSS_CASE_INSENSITIVE_DIR`, a 32 MiB vfat image). Nothing here mocks the reading:
the test fills the mount with real files in a folder of its own and crosses the lines for real. A mount that is
missing, or too large to fill in a test, FAILS this module's tests with a clear line; it never skips, because a
skipped disk test proves nothing about a full disk.
"""

import fcntl
import json
import os
from pathlib import Path
import re
import subprocess

from . import lanesupport, support

WARN = 10
STOP = 20
CHUNK = 1024 * 1024
MAX_MOUNT = 128 * 1024 * 1024
MIN_MOUNT = 4 * 1024 * 1024
FILL = "lane-disk-fill"


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class DiskTest(lanesupport.LaneTest):
    """A configuration `alpha` whose `[disk]` watches the mount the box prep made for this suite."""

    def setUp(self):
        super().setUp()
        self.mount = self.small_file_system()
        self.fill = self.mount / FILL
        self.fill.mkdir(exist_ok=True)
        self.addCleanup(self.remove_fill)
        self.configure_disk("alpha")

    # The real file system.

    def small_file_system(self):
        """The mounted image the box prep made, checked for real. Every way of not having it FAILS this test."""
        declared = os.environ.get("LANEBOSS_CASE_INSENSITIVE_DIR")
        if not declared:
            self.fail("the box prep did not provide LANEBOSS_CASE_INSENSITIVE_DIR (run with LB_PREP=launcher); the "
                      "disk line is tested by filling a real small file system, and a mocked reading is never used")
        mount = Path(declared)
        if not mount.is_dir():
            self.fail("LANEBOSS_CASE_INSENSITIVE_DIR is {} but that is not a directory, so the disk line has no real "
                      "file system to be measured on".format(declared))
        stats = os.statvfs(str(mount))
        size = stats.f_blocks * stats.f_frsize
        if size < MIN_MOUNT or size > MAX_MOUNT:
            self.fail("the mounted file system at {} holds {} bytes; the disk line is tested by filling a small one "
                      "(the prep makes 32 MiB, this test fills at most {})".format(mount, size, MAX_MOUNT))
        return mount

    # The configuration and the command.

    def configure_disk(self, config="alpha", path=None, warn=WARN, stop=STOP):
        """Write the `[disk]` section of a test configuration; a path of None watches this test's own fill folder."""
        file = self.home / "configs" / config / "config.toml"
        text = file.read_text(encoding="utf-8")
        text = text.split("\n[disk]\n")[0].rstrip("\n")
        text += "\n\n[disk]\npath = {}\nwarn_percent = {}\nstop_percent = {}\n".format(
            json.dumps(str(path if path is not None else self.fill)), warn, stop)
        file.write_text(text, encoding="utf-8")

    def remove_disk(self, config="alpha"):
        file = self.home / "configs" / config / "config.toml"
        text = file.read_text(encoding="utf-8")
        file.write_text(text.split("\n[disk]\n")[0].rstrip("\n") + "\n", encoding="utf-8")

    def recording_git(self, config="alpha"):
        """Hooks in the configuration's repository that record a branch creation and a worktree checkout, each into
        its own file in a directory of this test's own, and that directory. A refused start whose end state looks
        clean can still have made the branch and the worktree and removed them again in its own undo, so the end
        state cannot tell a refusal that came first from one that came late; the repository itself can. Git runs
        `reference-transaction` whenever a reference is created and `post-checkout` whenever it checks a work tree
        out, and both run from the repository a start uses. The variable the hooks read is named without a `GIT_`
        prefix because Git is handed the caller's environment without any `GIT_` variable in it."""
        markers = self.directory / "git-markers"
        markers.mkdir()
        hooks = self.repos[config] / ".git" / "hooks"
        for hook, marker in (("reference-transaction", "branch"), ("post-checkout", "worktree")):
            path = hooks / hook
            path.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$E2E_HOOK_MARKERS/{}\"\n".format(marker),
                            encoding="utf-8")
            path.chmod(0o755)
        self.environment["E2E_HOOK_MARKERS"] = str(markers)
        return markers

    def ran_git(self, markers):
        """What the recording hooks saw, sorted: [] when nothing was recorded."""
        return sorted(path.name for path in markers.iterdir())

    def read_disk(self, config="alpha"):
        """`laneboss disk` as JSON, whatever its exit code is (0 for ok and warn, 3 for stop)."""
        result = self.run_laneboss("disk", "--config", config, code=None, environment=self.env(config))
        self.assertIn(result.returncode, (0, 3),
                      "laneboss disk exited {}; it exits 0 for ok and warn and 3 for stop; stderr={!r}".format(
                          result.returncode, result.stderr))
        return json.loads(result.stdout)

    def start_raw(self, lane, *arguments, **options):
        """`lane start` with the whole completed process kept, for the line it writes to standard error."""
        config = options.pop("config", "alpha")
        code = options.pop("code", 0)
        return self.lane("start", "--lane", lane, "--brief", self.brief(config + "-" + lane), *arguments,
                         config=config, code=code)

    def disk_events(self, kind, config="alpha"):
        return [item for item in self.events(config) if item["kind"] == kind]

    # Filling the real file system.

    def chunks(self):
        return sorted(self.fill.glob("chunk-*.bin"))

    def write_chunk(self, number):
        self.fill.mkdir(exist_ok=True)
        path = self.fill / "chunk-{:04d}.bin".format(number)
        path.write_bytes(bytes(CHUNK))
        return path

    def fill_to(self, target):
        """Write real files into this test's own folder of the mount until the reading reaches `target` percent."""
        written = 0
        while True:
            report = self.read_disk()
            if report["used_percent"] >= target:
                return report
            self.assertLess(written, 256, "the mount never reached {}% after {} MiB of fill files".format(
                target, written))
            written += 1
            self.write_chunk(written)

    def reduce_between(self, low, high):
        """Remove this test's fill files, one at a time, until the reading is at or above `low` and below `high`."""
        while True:
            report = self.read_disk()
            if low <= report["used_percent"] < high:
                return report
            if report["used_percent"] < low:
                self.fail("the reading fell to {:.1f}%, below {}%, while fill files were removed".format(
                    report["used_percent"], low))
            left = self.chunks()
            if not left:
                self.fail("no fill file is left and the reading is still {:.1f}%, not below {}%".format(
                    report["used_percent"], high))
            left[-1].unlink()

    def empty_fill(self):
        """Remove this test's fill files, keeping the folder the configuration watches."""
        for path in self.chunks():
            path.unlink()

    def remove_fill(self):
        """Teardown: the fill files go, and the folder with them, because another test uses this mount."""
        self.empty_fill()
        if self.fill.is_dir() and not any(self.fill.iterdir()):
            self.fill.rmdir()

    # The cases.

    def test_a_reading_is_the_real_file_system(self):
        """`laneboss disk` prints the reading of the mount, and a real file written on the mount moves it."""
        self.empty_fill()
        before = self.read_disk()
        self.assertEqual(sorted(before),
                         ["free_bytes", "latched", "path", "state", "stop_percent", "used_percent", "warn_percent"])
        self.assertEqual(before["path"], str(self.fill))
        self.assertEqual((before["warn_percent"], before["stop_percent"]), (WARN, STOP))
        self.assertEqual(before["state"], "ok")
        self.assertIs(before["latched"], False)
        self.assertLess(before["used_percent"], WARN)
        self.assertGreater(before["free_bytes"], 0)
        self.run_laneboss("disk", "--config", "alpha", code=0, environment=self.env("alpha"))
        self.write_chunk(1)
        after = self.read_disk()
        self.assertGreater(after["used_percent"], before["used_percent"],
                           "a real file on the mount must raise the reading")
        self.assertLess(after["free_bytes"], before["free_bytes"])
        self.empty_fill()

    def test_warn_starts_and_says_so(self):
        """At the warn line a lane still starts; the launcher says so on standard error and records disk.warn."""
        report = self.fill_to(WARN)
        self.assertEqual(report["state"], "warn")
        self.assertLess(report["used_percent"], STOP)
        self.assertIs(report["latched"], False)
        self.run_laneboss("disk", "--config", "alpha", code=0, environment=self.env("alpha"))
        result = self.start_raw("web-d1", "--project", "web", "--difficulty", "standard")
        self.assertEqual(result.returncode, 0, "stderr={!r}".format(result.stderr))
        self.assertEqual(json.loads(result.stdout)["lane"], "web-d1")
        self.assertEqual(result.stderr.strip(), "warning: disk {} is {:.1f}% used (warn line {}%)".format(
            self.fill, report["used_percent"], WARN))
        warned = self.disk_events("disk.warn")
        self.assertEqual(len(warned), 1, warned)
        self.assertIsNone(warned[0]["lane"])
        self.assertEqual(warned[0]["payload"], {"path": str(self.fill), "used_percent": report["used_percent"],
                                                "free_bytes": report["free_bytes"], "warn_percent": WARN,
                                                "stop_percent": STOP})
        self.wait_event("lane.ended", "web-d1")
        self.assert_sound()

    def test_stop_refuses_before_anything(self):
        """At the stop line a start is refused with the one line, an event is recorded, and nothing was EVER made:
        no lane directory, no branch and no worktree, watched at the repository itself."""
        markers = self.recording_git()
        report = self.fill_to(STOP)
        self.assertEqual(report["state"], "stop")
        self.assertGreaterEqual(report["used_percent"], STOP)
        stopped = self.run_laneboss("disk", "--config", "alpha", code=3, environment=self.env("alpha"))
        self.assertEqual(json.loads(stopped.stdout)["state"], "stop")
        result = self.start_raw("web-d2", "--project", "web", "--difficulty", "standard", code=None)
        self.assertEqual(result.returncode, 2, "stdout={!r}; stderr={!r}".format(result.stdout, result.stderr))
        match = re.fullmatch(
            r"refused: disk (.+) is ([0-9]+\.[0-9])% used \(stop line {}%\); no new lane or worktree starts until it "
            r"is under {}%".format(STOP, WARN), result.stderr.strip())
        self.assertIsNotNone(match, "the refusal line is {!r}".format(result.stderr))
        self.assertEqual(match.group(1), str(self.fill))
        self.assertGreaterEqual(float(match.group(2)), STOP)
        events = self.disk_events("disk.stop")
        self.assertEqual(len(events), 1, events)
        self.assertIsNone(events[0]["lane"])
        self.assertEqual(events[0]["payload"]["path"], str(self.fill))
        self.assertEqual(events[0]["payload"]["used_percent"], report["used_percent"])
        self.assertEqual((events[0]["payload"]["warn_percent"], events[0]["payload"]["stop_percent"]), (WARN, STOP))
        # Nothing of the lane was made: no lane directory, no worktree, no branch.
        state = Path(self.paths("alpha")["state_dir"])
        self.assertFalse((state / "lanes" / "web-d2").exists(), "a lane directory was made for a refused start")
        self.assertFalse((self.directory / "repo-alpha-web-d2").exists(), "a worktree was made for a refused start")
        self.assertEqual(self.git(self.repos["alpha"], "rev-parse", "--verify", "--quiet", "refs/heads/web-d2",
                                  code=None), "")
        self.assertEqual(self.lane_events("web-d2"), [])
        # ...and nothing of it ever existed. The branch and the worktree a late refusal would have made are removed
        # again by the start's own undo, so the end state above cannot see them; the repository's hooks record every
        # branch creation and every worktree checkout, and a refusal that came first lets neither run.
        self.assertEqual(self.ran_git(markers), [],
                         "a refused start ran git in the lane's repository; the markers are what it ran")
        # The same hooks do fire for a start that goes on, so an empty marker directory means they never ran, not
        # that they are broken.
        self.empty_fill()
        self.start("web-d2b", "--project", "web", "--difficulty", "standard")
        self.wait_event("lane.ended", "web-d2b")
        self.assertEqual(self.ran_git(markers), ["branch", "worktree"],
                         "the recording hooks did not fire for a start that went on, so they prove nothing")
        self.assert_sound()

    def test_the_latch_holds_between_the_lines(self):
        """A stop reading sets the latch: a later reading between the two lines is still stop, and still refuses."""
        self.fill_to(STOP)
        self.assertEqual(self.read_disk()["state"], "stop")
        between = self.reduce_between(WARN, STOP)
        self.assertGreaterEqual(between["used_percent"], WARN)
        self.assertLess(between["used_percent"], STOP)
        held = self.read_disk()
        self.assertEqual(held["state"], "stop", "the latch must hold between the two lines")
        self.assertIs(held["latched"], True)
        result = self.start_raw("web-d3", "--project", "web", "--difficulty", "standard", code=None)
        self.assertEqual(result.returncode, 2, "stdout={!r}; stderr={!r}".format(result.stdout, result.stderr))
        self.assertIn("no new lane or worktree starts", result.stderr)
        self.assertFalse((self.directory / "repo-alpha-web-d3").exists())

    def test_the_latch_clears_below_warn(self):
        """Only a reading below the warn line clears the latch; then a start goes on with no warning at all."""
        self.fill_to(STOP)
        self.assertEqual(self.read_disk()["state"], "stop")
        self.empty_fill()
        report = self.read_disk()
        self.assertEqual(report["state"], "ok")
        self.assertIs(report["latched"], False)
        self.assertLess(report["used_percent"], WARN)
        self.run_laneboss("disk", "--config", "alpha", code=0, environment=self.env("alpha"))
        result = self.start_raw("web-d4", "--project", "web", "--difficulty", "standard")
        self.assertEqual(result.returncode, 0, "stderr={!r}".format(result.stderr))
        self.assertEqual(result.stderr.strip(), "", "a start under the warn line has nothing to warn about")
        self.assertEqual(self.disk_events("disk.warn"), [])
        self.wait_event("lane.ended", "web-d4")
        self.assert_sound()

    def test_the_latch_is_the_file_systems(self):
        """A stop reading taken in one configuration holds another configuration watching the same file system back
        until the reading is under the warn line: the latch belongs to the disk, not to one configuration."""
        self.add_config("beta")
        self.configure_disk("beta", path=self.fill)
        self.fill_to(STOP)
        self.assertEqual(self.read_disk("alpha")["state"], "stop")
        between = self.reduce_between(WARN, STOP)
        self.assertGreaterEqual(between["used_percent"], WARN)
        self.assertLess(between["used_percent"], STOP)
        # The reading fell between the two lines: on its own beta would see only the warning and start.
        held = self.read_disk("beta")
        self.assertEqual(held["state"], "stop",
                         "the latch of the file system was not seen by a second configuration watching it")
        self.assertIs(held["latched"], True)
        self.assertFalse((self.state_home / "beta" / "disk.latch").exists(),
                         "configuration beta holds a latch of its own, so the hold is not the file system's")
        refused = self.start_raw("web-d7", "--project", "web", "--difficulty", "standard", config="beta", code=None)
        self.assertEqual(refused.returncode, 2, "stdout={!r}; stderr={!r}".format(refused.stdout, refused.stderr))
        self.assertIn("no new lane or worktree starts", refused.stderr)
        self.assertFalse((self.directory / "repo-beta-web-d7").exists(),
                         "a worktree was made for a start refused by the latch of another configuration")
        # Under the warn line the file system's latch clears, and beta starts again.
        self.empty_fill()
        self.assertEqual(self.read_disk("beta")["state"], "ok")
        result = self.start_raw("web-d7", "--project", "web", "--difficulty", "standard", config="beta")
        self.assertEqual(result.returncode, 0, "stderr={!r}".format(result.stderr))
        self.wait_event("lane.ended", "web-d7", config="beta")
        self.assert_sound("beta")

    def test_the_latch_is_locked_for_a_start(self):
        """The latch's read-decide-write is locked: while another process holds that lock, a start waits for it
        rather than reading the latch and writing it at the same time as that process."""
        self.empty_fill()
        self.read_disk()
        latches = self.state_home / "disk-latches"
        self.assertTrue(latches.is_dir(), "the shared latch directory {} was not made".format(latches))
        holding = os.open(str(latches), os.O_RDONLY)
        self.addCleanup(os.close, holding)
        fcntl.flock(holding, fcntl.LOCK_EX)
        with self.assertRaises(subprocess.TimeoutExpired, msg="a start did not wait for the latch's lock"):
            subprocess.run([str(self.command), "lane", "start", "--config", "alpha", "--lane", "web-d10",
                            "--brief", str(self.brief("alpha-web-d10")), "--project", "web", "--difficulty",
                            "standard"],
                           cwd=str(self.directory), env=self.env("alpha"), capture_output=True, text=True,
                           encoding="utf-8", timeout=5)
        fcntl.flock(holding, fcntl.LOCK_UN)
        result = self.start_raw("web-d10", "--project", "web", "--difficulty", "standard")
        self.assertEqual(result.returncode, 0, "stderr={!r}".format(result.stderr))
        self.wait_event("lane.ended", "web-d10")
        self.assert_sound()

    def test_a_stop_survives_a_read_only_store(self):
        """At a full disk the state directory sits on the watched file system, so recording the reading is exactly
        what fails there: the reading and its refusal were decided before that write and must survive it. The state
        directory is made unable to take a new file - the stand-in for a file system with no room left, which is
        what a full disk is - after a start that went on made the store and the lanes lock in it, so what fails is
        the record and not the lock that start takes before the gate."""
        self.start("web-d0", "--project", "web", "--difficulty", "standard")
        self.wait_event("lane.ended", "web-d0")
        self.fill_to(STOP)
        self.assertEqual(self.read_disk()["state"], "stop")
        state = Path(self.paths("alpha")["state_dir"])
        for name in ("events.sqlite", "lanes.lock"):
            self.assertTrue((state / name).is_file(),
                            "{} holds no {}; this case needs a state directory that is otherwise complete".format(
                                state, name))
        self.addCleanup(os.chmod, str(state), 0o700)
        os.chmod(str(state), 0o500)
        result = self.start_raw("web-d11", "--project", "web", "--difficulty", "standard", code=None)
        self.assertEqual(result.returncode, 2, "stdout={!r}; stderr={!r}".format(result.stdout, result.stderr))
        self.assertRegex(result.stderr, r"refused: disk .* is [0-9]+\.[0-9]% used \(stop line {}%\); no new lane or "
                                        r"worktree starts until it is under {}%".format(STOP, WARN))
        self.assertIn("note: the disk reading could not be recorded", result.stderr,
                      "the refusal must carry the note that the reading could not be recorded")
        self.assertFalse((self.directory / "repo-alpha-web-d11").exists())
        os.chmod(str(state), 0o700)
        self.assertEqual(self.read_disk()["state"], "stop")

    def test_resume_is_not_refused_in_stop(self):
        """`lane resume` creates nothing new: it goes on although the disk is at the stop line."""
        self.start("web-d5", "--project", "web", "--difficulty", "standard")
        self.wait_event("lane.ended", "web-d5")
        self.fill_to(STOP)
        self.assertEqual(self.read_disk()["state"], "stop")
        resumed = self.lane_json("resume", "--lane", "web-d5")
        self.assertEqual((resumed["lane"], resumed["run"]), ("web-d5", 2))
        self.wait_event("lane.ended", "web-d5", run=2)
        self.assert_sound()

    def test_a_bad_disk_config_is_rejected(self):
        """A warn line at or above the stop line, and a line outside 1 to 99, are refused by config validate."""
        self.run_laneboss("config", "validate", "alpha", code=0, environment=self.env("alpha"))
        cases = [("the warn line at the stop line", dict(warn=90, stop=90)),
                 ("the warn line above the stop line", dict(warn=95, stop=90)),
                 ("a warn line below 1", dict(warn=0, stop=90)),
                 ("a warn line above 99", dict(warn=100, stop=90)),
                 ("a stop line above 99", dict(warn=85, stop=120))]
        for label, values in cases:
            with self.subTest(label):
                self.configure_disk("alpha", **values)
                result = self.run_laneboss("config", "validate", "alpha", code=2, environment=self.env("alpha"))
                self.assertIn("disk", result.stderr, result.stderr)
                self.run_laneboss("disk", "--config", "alpha", code=2, environment=self.env("alpha"))
        self.configure_disk("alpha")

    def test_an_unreadable_path_refuses(self):
        """A file system that cannot be read refuses the reading and the start, and never looks like an empty disk.
        The refusal is pinned as the disk's own, so any other refusal does not pass this test."""
        missing = self.directory / "no-such-file-system"
        self.assertFalse(missing.exists())
        self.configure_disk("alpha", path=missing)
        pattern = (r"refused: the disk reading failed: {} cannot be read \(.*\); no new lane or worktree "
                   r"starts".format(re.escape(str(missing))))
        result = self.run_laneboss("disk", "--config", "alpha", code=2, environment=self.env("alpha"))
        self.assertRegex(result.stderr.strip(), pattern, "stderr was {!r}".format(result.stderr))
        refusal = self.start_raw("web-d6", "--project", "web", "--difficulty", "standard", code=None)
        self.assertEqual(refusal.returncode, 2, "stdout={!r}; stderr={!r}".format(refusal.stdout, refusal.stderr))
        self.assertRegex(refusal.stderr.strip(), pattern, "stderr was {!r}".format(refusal.stderr))
        self.assertFalse((self.directory / "repo-alpha-web-d6").exists())
        self.assertFalse((Path(self.paths("alpha")["state_dir"]) / "lanes" / "web-d6").exists())

    def test_no_usable_blocks_refuses(self):
        """statvfs can succeed and still report no usable blocks: that file system is unreadable, not empty, and it
        is refused rather than read as 0%."""
        stats = os.statvfs("/proc")
        self.assertEqual((stats.f_blocks, stats.f_bfree, stats.f_bavail), (0, 0, 0),
                         "/proc reports blocks here, so it is not the real file system this case needs (one whose "
                         "statvfs succeeds and reports no usable blocks) and the reading is not mocked for it")
        self.configure_disk("alpha", path="/proc")
        result = self.run_laneboss("disk", "--config", "alpha", code=2, environment=self.env("alpha"))
        self.assertRegex(result.stderr.strip(),
                         r"refused: the disk reading failed: /proc reports no usable blocks \(blocks 0, free 0, "
                         r"available 0\); a file system that cannot be read is never taken for an empty one, and no "
                         r"new lane or worktree starts", "stderr was {!r}".format(result.stderr))
        refusal = self.start_raw("web-d9", "--project", "web", "--difficulty", "standard", code=None)
        self.assertEqual(refusal.returncode, 2, "stdout={!r}; stderr={!r}".format(refusal.stdout, refusal.stderr))
        self.assertIn("reports no usable blocks", refusal.stderr)
        self.assertFalse((self.directory / "repo-alpha-web-d9").exists())
        self.configure_disk("alpha")

    def test_the_default_watches_the_user_home(self):
        """Without a `[disk]` section the launcher watches the user's home directory, at 85 and 90."""
        self.remove_disk("alpha")
        report = self.read_disk()
        self.assertEqual(report["path"], str(self.user_home))
        self.assertEqual((report["warn_percent"], report["stop_percent"]), (85, 90))
        self.assertIn(report["state"], ("ok", "warn", "stop"))
