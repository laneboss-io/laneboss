"""Attach sender compatibility with real caller and turn authorization.

Run on the disposable Linux test machine with LANEBOSS_BIN naming a supplied
build. Only the agent is a stand-in; the launcher, queue, claims, events, caller
sessions, tmux and resumed prompt are real. Set LANEBOSS_ROW_EVIDENCE to retain
the fixtures. No private-suite code is imported or changed.
"""

import hashlib
import json
from pathlib import Path
import sys
import unittest
import uuid

from test_report_messages import ReportMessageFixture


def setUpModule():
    if sys.platform != "linux":
        raise RuntimeError("attach sender rows require the disposable Linux test machine")


class AttachSenderRows(ReportMessageFixture, unittest.TestCase):
    fixture_prefix = "lb-s0-cattach-"

    def recorded_call(self, label, controller, arguments, stdin=""):
        result = controller.request(arguments, stdin=stdin)
        for suffix, text in (("stdin", stdin), ("stdout", result["stdout"]), ("stderr", result["stderr"])):
            (self.directory / (label + "." + suffix)).write_bytes(text.encode("utf-8"))
        (self.directory / (label + ".json")).write_text(
            json.dumps({"arguments": arguments, "exit_code": result["code"]}), encoding="utf-8",
        )
        return result

    def attach_line(self, lane, text, supervisor="mini-a"):
        return self.recorded_call(
            "attach-" + supervisor, self.role(supervisor),
            ["lane", "attach", "--config", "rows", "--lane", lane],
            stdin=text + "\n/exit\n",
        )

    def assert_mail(self, lane, text):
        events = self.lane_events(lane, "lane.mailed")
        self.assertEqual(len(events), 1, "a typed line must enqueue exactly one message")
        event = events[0]
        payload = event["payload"]
        self.assertEqual(payload["sender"], "attach",
                         "attach must preserve its input-source label in the actual stored mail")
        self.assertEqual(event["actor"], "supervisor:mini-a",
                         "the label must not replace the authenticated principal")
        data = text.encode("utf-8")
        self.assertEqual(payload["sequence"], 1)
        self.assertEqual(payload["bytes"], len(data))
        self.assertEqual(payload["sha256"], hashlib.sha256(data).hexdigest())
        path = (self.states / "rows" / "lanes" / lane / "mail" /
                ("{:09d}-{}".format(payload["sequence"], payload["sha256"])))
        self.assertEqual(path.read_bytes(), data, "typed mail must retain the exact UTF-8 bytes")
        return event

    def wait_delivered(self, lane, text, run=2):
        def delivered():
            status = self.idle_status(lane)
            if status is None or status["run"] != run:
                return None
            return status if status["mail"]["delivered"] == 1 else None

        status = self.await_value(delivered, "the real turn did not deliver the attached message")
        self.assertEqual((status["reason"], status["exit_code"], status["live"]["survivors"]),
                         ("exit", 0, 0))
        self.assertEqual(status["mail"]["waiting"], [])
        [started] = [event for event in self.lane_events(lane, "lane.started")
                     if event["payload"]["run"] == run]
        self.assertEqual(started["payload"]["mail"], [1])
        self.assertEqual(started["actor"], "supervisor:mini-a")
        ready = json.loads((self.worktrees[lane] / "ready.json").read_text(encoding="utf-8"))
        prompt = Path(ready["prompt_file"]).read_bytes()
        resumed = self.lane_events(lane, "lane.resumed")[-1]["payload"]["message"]
        self.assertEqual(prompt, Path(resumed["path"]).read_bytes())
        self.assertEqual(hashlib.sha256(prompt).hexdigest(), resumed["sha256"])
        self.assertIn(b"## Message 1 from attach at ", prompt)
        self.assertEqual(prompt.count(text.encode("utf-8")), 1)
        self.assertEqual(self.lane_events(lane, "lane.delivered")[-1]["payload"]["sequences"], [1])

    def test_typed_line_keeps_source_and_actor(self):
        lane = "typed"
        self.start_lane(lane, once=True)
        self.await_value(lambda: self.idle_status(lane), "the initial run did not settle")
        text = "Review this plan, including café: " + uuid.uuid4().hex
        result = self.attach_line(lane, text)
        self.assert_code(result, 0, "the recorded starter must be able to type through attach")
        self.assertIn("message 1 sent", result["stdout"])
        self.assertIn("turn started: run 2", result["stdout"])
        self.assert_mail(lane, text)
        self.wait_delivered(lane, text)

        before = self.events()
        refused = self.attach_line(lane, "Foreign attach must not enqueue mail.", "mini-b")
        self.assert_code(refused, 2, "a different supervisor must not gain attach access")
        self.assertIn("may not attach to", refused["stderr"])
        self.assertEqual(self.events(), before)
        forged = self.recorded_call(
            "forged-label", self.role("mini-a"),
            ["lane", "send", "--config", "rows", "--lane", lane, "--from", "attach", "-"],
            stdin="A CLI sender cannot claim the attach label.\n",
        )
        self.assert_code(forged, 2, "--from must remain bound to the resolved principal")
        self.assertIn("--from must equal the resolved principal ID", forged["stderr"])
        self.assertEqual(self.events(), before)

    def test_queued_attach_rechecks_actor(self):
        lane = "queued"
        worktree = self.start_lane(lane)
        text = "Queued attach authorization canary " + uuid.uuid4().hex
        result = self.attach_line(lane, text)
        self.assert_code(result, 0, "attach must leave the live runner going after storing the line")
        self.assertIn("message 1 queued", result["stdout"])
        self.assert_mail(lane, text)
        stopped = self.human.request(["lane", "stop", "--config", "rows", "--lane", lane])
        self.assert_code(stopped, 0, "stop the fixture's first run before consuming queued mail")
        status = self.await_value(lambda: self.idle_status(lane), "the stopped initial run did not settle")
        self.assertEqual(status["mail"]["waiting"], [1])
        (worktree / "once").write_text("Read the next prompt and exit.\n", encoding="utf-8")

        config = self.config_dir / "config.toml"
        original = config.read_text(encoding="utf-8")
        section = '\n[supervisors.mini-a]\nlevel = 4\nrunner = "row-runner"\n'
        self.assertEqual(original.count(section), 1, "the fixture must remove exactly its sender's role")
        config.write_text(original.replace(section, "", 1), encoding="utf-8")
        try:
            before = self.events()
            prompts = sorted(worktree.glob("prompt-*.txt"))
            refused = self.recorded_call(
                "revoked-turn", self.human, ["lane", "turn", "--config", "rows", "--lane", lane],
            )
            self.assert_code(refused, 2, "queued attach mail must not outlive its sender's authority")
            self.assertIn("the carried message's sender cannot be resolved", refused["stderr"])
            self.assertEqual(self.events(), before, "a refused queued sender must start no run")
            self.assertEqual(sorted(worktree.glob("prompt-*.txt")), prompts)
        finally:
            config.write_text(original, encoding="utf-8")

        resumed = self.recorded_call(
            "restored-turn", self.human, ["lane", "turn", "--config", "rows", "--lane", lane],
        )
        self.assert_code(resumed, 0, "restoring the sender must allow the same stored message")
        self.assertEqual(json.loads(resumed["stdout"])["run"], 2)
        self.wait_delivered(lane, text)
