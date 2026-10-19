"""Mail/lifecycle synchronization rows for an already built CLI on Linux.

Set LANEBOSS_BIN and an absolute LANEBOSS_ROW_EVIDENCE outside the checkout.
These rows use real controlling-terminal identities, actual flock descriptors,
real stop/turn/clean/reuse commands and retained message bytes. No model service
or product import is used. Run red on the release base, then green on the fix.
"""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import unittest
import uuid

from test_report_messages import ReportMessageFixture


class MailLifecycleRows(ReportMessageFixture, unittest.TestCase):
    fixture_prefix = "lb-s0-mailclean-"

    def setUp(self):
        self.assertEqual(sys.platform, "linux", "mail races require the disposable Linux box")
        self.evidence_directory = Path(os.environ["LANEBOSS_ROW_EVIDENCE"])
        self.assertTrue(self.evidence_directory.is_absolute())
        self.assertFalse(self.evidence_directory.is_relative_to(Path(__file__).resolve().parents[1]))
        self.evidence_directory.mkdir(parents=True, exist_ok=True)
        super().setUp()
        self.mail_calls = 0
        shutil.copy2(self.binary, self.directory / "tested-laneboss")
        (self.directory / "binary.sha256").write_text(
            hashlib.sha256(self.binary.read_bytes()).hexdigest() + "\n", encoding="utf-8")
        (self.directory / "row.txt").write_text(self._testMethodName + "\n", encoding="utf-8")
        for name in ("test_mailclean.py", "test_report_messages.py", "reportsupport.py", "orgsupport.py"):
            shutil.copy2(Path(__file__).with_name(name), self.directory / name)

    def write_config(self, file_channel=False):
        super().write_config(file_channel)
        source = self.config_dir / "config.toml"
        text = source.read_text(encoding="utf-8")
        source.write_text(text.replace("[lanes]\n", "[lanes]\nlock_wait_seconds = 15\n", 1),
                          encoding="utf-8")

    def request(self, controller, args):
        self.mail_calls += 1
        prefix = self.directory / ("mail-call-%04d" % self.mail_calls)
        prefix.with_suffix(".input.json").write_text(json.dumps(list(map(str, args))) + "\n", encoding="utf-8")
        result = controller.request(args)
        prefix.with_suffix(".stdout").write_text(result["stdout"], encoding="utf-8")
        prefix.with_suffix(".stderr").write_text(result["stderr"], encoding="utf-8")
        prefix.with_suffix(".exit").write_text(str(result["code"]) + "\n", encoding="utf-8")
        return result

    def lane_directory(self, lane):
        paths = self.cli("config", "path", "rows")
        self.assert_code(paths, 0, "locate the lane state")
        return Path(json.loads(paths["stdout"])["state_dir"]) / "lanes" / lane

    def message(self, lane):
        path = self.directory / (lane + "-message.md")
        path.write_text("Mail race canary " + uuid.uuid4().hex + "\n", encoding="utf-8")
        return path, ["lane", "send", "--config", "rows", "--lane", lane, "--file", str(path)]

    def assert_queued(self, lane, result, source):
        self.assert_code(result, 0, "enqueue the actual message")
        receipt = json.loads(result["stdout"])
        data = source.read_bytes()
        self.assertEqual(Path(receipt["file"]).read_bytes(), data)
        self.assertEqual(receipt["sha256"], hashlib.sha256(data).hexdigest())
        mailed = self.lane_events(lane, "lane.mailed")
        self.assertEqual(len(mailed), 1)
        self.assertEqual(mailed[0]["actor"], "supervisor:mini-a")
        self.assertEqual(mailed[0]["payload"]["sha256"], receipt["sha256"])
        self.assertEqual(mailed[0]["payload"]["bytes"], len(data))
        status = self.await_value(lambda: self.idle_status(lane), "the stopped lane did not settle")
        self.assertEqual(status["mail"]["waiting"], [receipt["sequence"]])
        self.assertIsNone(status["mail"]["in_flight"])
        self.assertEqual(status["mail"]["delivered"], 0)
        self.assertEqual(self.lane_events(lane, "lane.delivered"), [])
        return receipt

    def sender_opened_lock(self, controller, locked):
        # Observe only descriptor identities, never process arguments or settings.
        # An open descriptor proves the real send passed its initial life and
        # permission checks and is trying the held mail lock; no timing sleep
        # stands in for this synchronization point.
        actor = controller
        if controller.delegate is not None:
            delegate = controller.delegate
            actor = delegate.roles[("rows", delegate.default_role)]
        parent = actor.process.pid
        children = Path("/proc/%d/task/%d/children" % (parent, parent)).read_text().split()
        identity = os.fstat(locked.fileno())
        for child in children:
            descriptors = Path("/proc") / child / "fd"
            try:
                names = list(descriptors.iterdir())
            except FileNotFoundError:
                continue  # A short-lived child exited between the two reads.
            for descriptor in names:
                try:
                    info = descriptor.stat()
                except FileNotFoundError:
                    continue  # A descriptor closed while it was enumerated.
                if (info.st_dev, info.st_ino) == (identity.st_dev, identity.st_ino):
                    return True
        return False

    def stopped_send(self, lane, finish_life=None, hold_lifecycle=False):
        worktree = self.start_lane(lane)
        sender = self.role("mini-a")
        source, args = self.message(lane)
        directory = self.lane_directory(lane)
        with ExitStack() as held, ThreadPoolExecutor(max_workers=1) as executor:
            if hold_lifecycle:
                lifecycle = held.enter_context((directory.parent.parent / "lanes.lock").open("r+b"))
                fcntl.flock(lifecycle, fcntl.LOCK_EX)
            with (directory / "mail.lock").open("a+b") as locked:
                fcntl.flock(locked, fcntl.LOCK_EX)
                future = executor.submit(self.request, sender, args)
                try:
                    self.await_value(lambda: self.sender_opened_lock(sender, locked),
                                     "send did not reach the held mail lock")
                    stopped = self.request(self.human, ["lane", "stop", "--config", "rows", "--lane", lane])
                    self.assert_code(stopped, 0, "stop must not wait for an enqueuer's mail lock")
                    self.assertEqual(json.loads(stopped["stdout"])["survivors"], 0)
                    self.await_value(lambda: self.idle_status(lane), "stop left a live lane")
                    if finish_life is not None:
                        finish_life(lane, worktree)
                finally:
                    fcntl.flock(locked, fcntl.LOCK_UN)
            result = future.result(timeout=20)
        return worktree, source, result

    def test_mail_ignores_global_lifecycle_lock(self):
        """b41ffa7 refuses send when another command holds lanes.lock."""
        lane = "held-lifecycle"
        self.start_lane(lane, once=True)
        self.await_value(lambda: self.idle_status(lane), "the initial run did not end")
        source, args = self.message(lane)
        with (self.lane_directory(lane).parent.parent / "lanes.lock").open("r+b") as locked:
            fcntl.flock(locked, fcntl.LOCK_EX)
            try:
                result = self.request(self.role("mini-a"), args)
            finally:
                fcntl.flock(locked, fcntl.LOCK_UN)
        self.assert_queued(lane, result, source)

    def test_mail_during_stop_kept_for_turn(self):
        """Mail behind a held lifecycle lock survives stop for a later real turn."""
        lane = "mail-during-stop"
        worktree, source, result = self.stopped_send(lane, hold_lifecycle=True)
        receipt = self.assert_queued(lane, result, source)
        old_prompt = json.loads((worktree / "ready.json").read_text())["prompt_file"]
        (worktree / "once").write_text("Exit after reading the resumed prompt.\n", encoding="utf-8")
        turned = self.request(self.role("mini-a"), ["lane", "turn", "--config", "rows", "--lane", lane])
        self.assert_code(turned, 0, "a later turn must receive the durable queue")
        self.assertTrue(json.loads(turned["stdout"])["started"])

        def new_prompt():
            ready = json.loads((worktree / "ready.json").read_text())
            return ready["prompt_file"] if ready["prompt_file"] != old_prompt else None

        prompt = self.await_value(new_prompt, "the resumed runner did not read the queued mail")
        status = self.await_value(lambda: self.idle_status(lane), "the resumed turn did not end")
        self.assertEqual((status["reason"], status["exit_code"]), ("exit", 0))
        self.assertEqual(Path(prompt).read_bytes().count(source.read_bytes()), 1)
        self.assertEqual(status["mail"]["waiting"], [])
        self.assertEqual(status["mail"]["delivered"], 1)
        delivered = self.lane_events(lane, "lane.delivered")
        self.assertEqual(delivered[-1]["payload"]["sequences"], [receipt["sequence"]])

    def test_waiting_send_rechecks_abandonment(self):
        """A life closed while send waits must refuse without a mail file or event."""
        def abandon(lane, _worktree):
            marked = self.request(self.human, ["lane", "mark", "--config", "rows", "--lane", lane,
                                               "--state", "abandoned"])
            self.assert_code(marked, 0, "close the stopped lane's life")

        lane = "closed-mail-life"
        _, _, result = self.stopped_send(lane, abandon)
        self.assert_code(result, 2, "mail must refuse the now-abandoned life")
        self.assertIn("abandoned", result["stderr"])
        self.assertEqual(self.lane_events(lane, "lane.mailed"), [])
        self.assertEqual(list((self.lane_directory(lane) / "mail").glob("*")), [])

    def test_waiting_send_rechecks_reuse(self):
        """The previous starter's permission must not survive reuse by another starter."""
        replacement = self.role("mini-b")

        def reuse(lane, worktree):
            for action in (["mark", "--state", "abandoned"], ["clean"]):
                result = self.request(self.human, ["lane", action[0], "--config", "rows", "--lane", lane,
                                                   *action[1:]])
                self.assert_code(result, 0, "close and collect the previous life")
            (worktree / "once").write_text("Read the new life's prompt and exit.\n", encoding="utf-8")
            result = self.request(replacement, ["lane", "start", "--config", "rows", "--lane", lane,
                                                "--worktree", str(worktree), "--brief", str(self.directory / (lane + ".md")),
                                                "--runner", "row-runner", "--model", "row-runner-model-1", "--turns",
                                                "--role", "executor", "--level", "3", "--reuse"])
            self.assert_code(result, 0, "start the new life under its actual new starter")
            self.await_value(lambda: self.idle_status(lane), "the replacement run did not end")

        lane = "reused-mail-life"
        _, _, result = self.stopped_send(lane, reuse)
        self.assert_code(result, 2, "the old starter must not message the new life")
        self.assertIn("may not message", result["stderr"])
        self.assertEqual(self.lane_events(lane, "lane.mailed"), [])
        self.assertEqual(list((self.lane_directory(lane) / "mail").glob("*")), [])


if __name__ == "__main__":
    unittest.main()
