"""Fix round 1, decision 1: hook refusals in claude-code records are read. The program keeps a hook's message about a
call as an attachment line (hook_blocking_error with the text in attachment.blockingError.blockingError, or
hook_non_blocking_error with the text in stderr), while the call's own result is a success. Both are offered to the
guards whatever the result's error flag; the refusal is tied to the call the attachment names and says it came through
a hook; workarounds after it are suspected as after any refusal, live and by lane scan, and the gate holds."""

from . import refusalsupport, support
from .refusalsupport import expected_path, hook, hooked_steps, shell_steps


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class HookRefusalTest(refusalsupport.RefusalTest):
    def test_blocking_hook(self):
        lane = "k-block"
        follower = self.follow()
        steps = [{"open": {}}] + hooked_steps("c1", event="PreToolUse") + [{"mark": "refused"}]
        steps += shell_steps("c2", "printf 'x\\n' > notes/plan.md") + [{"wait": "go"}, {"exit": 0}]
        started = self.start_session(lane, "claude-code", steps)
        arrived, event = follower.wait(self, "lane.refusal", lane)
        self.assertLessEqual(arrived - self.marked(lane, "refused"), 5.0)
        payload = event["payload"]
        self.assertEqual((payload["guard"], payload["via"], payload["hook"]),
                         ("doc-guard", "hook", {"event": "PreToolUse", "name": "PreToolUse:Bash"}))
        self.assertEqual((payload["tool"], payload["call"]["id"]), ("Bash", "c1"))
        self.assertTrue(payload["command"]["text"].startswith("cat > notes/plan.md"))
        self.assertTrue(payload["message"]["text"].startswith("PreToolUse:Bash hook error"))
        self.assertIn("hook_blocking_error", self.read_line(payload["record"]))
        plan = expected_path(started["worktree"], "notes/plan.md")
        self.assertEqual(payload["targets"], [plan])
        _, suspicion = follower.wait(self, "lane.workaround_suspected", lane)
        self.assertEqual((suspicion["payload"]["refusal"], suspicion["payload"]["paths"]), (payload["refusal"], [plan]))
        self.go(lane)
        self.wait_event("lane.ended", lane)
        self.assertEqual(self.scan(lane)["appended"], {"refusals": 0, "suspicions": 0})
        result = self.lane("mark", "--lane", lane, "--state", "accepted", code=2)
        self.assertIn(plan, result.stderr)
        self.review(lane, payload["refusal"], plan, "clean")
        self.lane_json("mark", "--lane", lane, "--state", "accepted")
        self.assert_sound()

    def test_non_blocking_hook_found_by_scan(self):
        # A hook's non-blocking message, written after the supervising process is gone: lane scan finds it.
        lane = "k-nonblock"
        steps = [{"open": {}}, {"mark": "opened"}, {"wait": "go"}]
        steps += hooked_steps("c1", kind="non-blocking", event="PostToolUse")
        steps += shell_steps("c2", "printf 'x\\n' > notes/plan.md") + [{"exit": 0}]
        started = self.start_session(lane, "claude-code", steps)
        self.marked(lane, "opened")
        self.kill_supervisor(lane)
        self.go(lane)
        self.ended_by_itself(lane)
        self.lane_json("check")
        scanned = self.scan(lane)
        self.assertEqual(scanned["appended"], {"refusals": 1, "suspicions": 1})
        refusal = self.kind_events(lane, "lane.refusal")[0]["payload"]
        self.assertEqual((refusal["via"], refusal["hook"]["event"]), ("hook", "PostToolUse"))
        self.assertIn("hook_non_blocking_error", self.read_line(refusal["record"]))
        plan = expected_path(started["worktree"], "notes/plan.md")
        result = self.lane("mark", "--lane", lane, "--state", "merged", code=2)
        self.assertIn(plan, result.stderr)
        self.assert_sound()

    def test_other_attachments_are_not_matched(self):
        # A hook that succeeded, or added context, with a whole message the guard matches in each of its texts is not a
        # refusal; nor is a tool result that is not an error. The record is covered. (Fix round 2, decision 7: the text
        # matches the configured guard, so the test fails if such an attachment is ever offered to the guards.)
        lane = "k-quiet"
        quoted = hook("quoted in a hook's output")
        attachments = [{"type": "hook_success", "hookName": "PostToolUse:Bash", "toolUseID": "c1",
                        "hookEvent": "PostToolUse", "stdout": quoted, "stderr": quoted, "content": quoted,
                        "exitCode": 0},
                       {"type": "hook_additional_context", "hookName": "PostToolUse:Bash", "toolUseID": "c1",
                        "hookEvent": "PostToolUse", "content": [quoted]}]
        steps = [{"open": {}}, {"shell": {"id": "c1", "command": "ls"}},
                 {"result": {"id": "c1", "text": hook("quoted in a listing"), "error": False}}]
        steps += [{"line": {"type": "attachment", "body": {"attachment": item}}} for item in attachments]
        steps += [{"exit": 0}]
        directory = self.scratch("alpha-" + lane)
        self.start_session(lane, "claude-code", steps, worktree=directory)
        self.wait_event("lane.ended", lane)
        self.assertEqual(self.kind_events(lane, "lane.refusal"), [])
        self.assertEqual(self.coverage(lane)["not_covered"], [])
        self.assert_sound()
