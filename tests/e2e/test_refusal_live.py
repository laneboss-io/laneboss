"""Refusals A and H. While a run lives, its supervising process follows the run's session records: a refusal that a
running stand-in writes appears as lane.refusal through event tail --follow within five seconds, with the guard's name,
the tool, the start of the refused command and its targets, and the run goes on. Each of the three formats goes
through the whole of it; a text record names no command and no targets, and its event says so."""

from . import refusalsupport, support
from .refusalsupport import expected_path, refused_steps


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class LiveRefusalTest(refusalsupport.RefusalTest):
    def check_live(self, fmt, lane):
        steps = ([] if fmt == "text" else [{"open": {}}]) + refused_steps(fmt)
        steps += [{"mark": "refused"}, {"wait": "go"}, {"exit": 0}]
        follower = self.follow()
        started = self.start_session(lane, fmt, steps)
        arrived, event = follower.wait(self, "lane.refusal", lane)
        refused_at = self.marked(lane, "refused")
        self.assertLessEqual(arrived - refused_at, 5.0, "lane.refusal arrived more than five seconds after the refusal")
        payload = event["payload"]
        self.assertEqual((payload["run"], payload["guard"], payload["kind"], payload["format"]),
                         (1, "doc-guard", "hook", fmt))
        self.assertTrue(payload["refusal"].startswith("rf-"))
        message = payload["message"]
        self.assertIs(message["withheld"], False)
        self.assertTrue(message["text"].startswith("PreToolUse:Bash hook error: [/opt/guards/doc-guard.sh]: BLOCKED"))
        self.assertIn("BLOCKED by doc_guard", self.read_line(payload["record"]))
        if fmt == "text":
            # A text record has no calls: no tool, no command and no targets, so no workaround can be checked.
            self.assertEqual((payload["tool"], payload["command"], payload["call"], payload["targets"]),
                             (None, None, None, []))
            self.assertIs(payload["workarounds_checked"], False)
            self.assertEqual(payload["record"]["path"], started["log"])
            self.assertIsNone(payload["at"])
        else:
            self.assertEqual(payload["tool"], "Bash")
            self.assertIs(payload["command"]["withheld"], False)
            self.assertTrue(payload["command"]["text"].startswith("cat > notes/plan.md <<'EOF'"))
            self.assertEqual(payload["command"]["length"], len(refusalsupport.REFUSED))
            self.assertEqual(payload["targets"], [expected_path(started["worktree"], "notes/plan.md")])
            self.assertIs(payload["workarounds_checked"], True)
            self.assertEqual(payload["call"]["id"], "c1")
            self.assertIn("notes/plan.md", self.read_line(payload["call"]["record"]))
            self.assertRegex(payload["at"], r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T")
            self.assertEqual(event["occurred_at"], payload["at"])
        # The run goes on: the stand-in is alive and the lane still runs.
        record = self.record(lane)
        self.assertTrue(self.alive(record["pid"]))
        self.assertEqual(self.lane_events(lane, "lane.ended"), [])
        self.assertIs(self.status(lane)["running"], True)
        self.go(lane)
        _, ended = follower.wait(self, "lane.ended", lane)
        self.assertEqual((ended["payload"]["reason"], ended["payload"]["exit_code"]), ("exit", 0))
        self.assertLess(event["seq"], ended["seq"])
        self.assertEqual([item["payload"]["refusal"] for item in self.kind_events(lane, "lane.refusal")],
                         [payload["refusal"]])
        row = self.status(lane)
        self.assertEqual(list(row["refusals"]["recorded"]), [payload["refusal"]])
        self.assertEqual((row["refusals"]["suspected"], row["refusals"]["unreviewed"]), ({}, []))
        listed = self.refusals(lane)
        self.assertEqual(listed["lane"], lane)
        self.assertEqual([item["refusal"] for item in listed["refusals"]], [payload["refusal"]])
        self.assertEqual((listed["suspicions"], listed["unreviewed"]), ([], []))
        self.assertEqual(len(listed["coverage"]), 1)
        coverage = listed["coverage"][0]
        self.assertEqual((coverage["run"], coverage["complete"], coverage["covered"], coverage["not_covered"]),
                         (1, True, True, []))
        self.assertEqual([item["format"] for item in coverage["records"]], [fmt])
        self.assert_sound()

    def test_claude_code(self):
        self.check_live("claude-code", "a-claude")

    def test_text(self):
        self.check_live("text", "a-text")

    def test_no_refusal_no_event(self):
        # A run whose records hold no refusal leaves no refusal event and is covered.
        steps = [{"open": {}}] + refusalsupport.shell_steps("c1", "ls notes", text="plan.md") + [{"exit": 0}]
        self.start_session("a-quiet", "claude-code", steps)
        self.wait_event("lane.ended", "a-quiet")
        self.assertEqual([item["kind"] for item in self.lane_events("a-quiet") if item["kind"] in refusalsupport.KINDS],
                         [])
        coverage = self.refusals("a-quiet")["coverage"][0]
        self.assertEqual((coverage["covered"], coverage["not_covered"]), (True, []))
        self.assertNotIn("refusals", self.status("a-quiet"))
        self.assert_sound()
