"""Refusals C, D and H. With a suspicion whose paths are not reviewed, lane mark --state accepted and --state merged exit 2
and name the paths; after lane review of each path they succeed, and --state abandoned succeeds at once; the events
carry the verdicts. A refusal that appears in a record after the run's last live scan is still found before accepted is
recorded, because marking first scans every run to its end."""

import subprocess
import time

from . import refusalsupport, support
from .refusalsupport import REFUSED, expected_path, refused_steps, shell_steps


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class GateTest(refusalsupport.RefusalTest):
    def check_gate(self, fmt, lane):
        refused = REFUSED + "\ncp notes/plan.md notes/plan-copy.md"
        steps = [{"open": {}}] + refused_steps(fmt, command=refused)
        steps += shell_steps("c2", "printf 'a\\n' > notes/plan.md && printf 'b\\n' > notes/plan-copy.md")
        steps += [{"exit": 0}]
        started = self.start_session(lane, fmt, steps)
        self.wait_event("lane.ended", lane)
        plan = expected_path(started["worktree"], "notes/plan.md")
        copy = expected_path(started["worktree"], "notes/plan-copy.md")
        refusal = self.kind_events(lane, "lane.refusal")[0]["payload"]
        self.assertEqual(refusal["targets"], sorted([plan, copy]))
        suspicion = self.suspicion_of(lane, "c2")[0]["payload"]
        self.assertEqual((suspicion["how"], suspicion["paths"]), (["shell-write"], sorted([plan, copy])))
        for state in ("accepted", "merged"):
            with self.subTest(state=state):
                result = self.lane("mark", "--lane", lane, "--state", state, code=2)
                self.assertIn(plan, result.stderr)
                self.assertIn(copy, result.stderr)
                self.assertIn(refusal["refusal"], result.stderr)
        self.assertEqual(self.kind_events(lane, "lane.state"), [])
        note = self.directory / "note.md"
        note.write_text("Written through the shell after the refusal; reported to the owner.\n", encoding="utf-8")
        reviewed = self.review(lane, refusal["refusal"], plan, "workaround", "--note", note)
        self.assertEqual((reviewed["verdict"], reviewed["path"], reviewed["suspicions"]),
                         ("workaround", plan, [suspicion["suspicion"]]))
        # One path is reviewed; the other still blocks, and is the only one named.
        result = self.lane("mark", "--lane", lane, "--state", "accepted", code=2)
        self.assertIn(copy, result.stderr)
        self.assertNotIn(plan, result.stderr)
        # A path relative to the lane's working directory names the same file.
        self.review(lane, refusal["refusal"], "notes/plan-copy.md", "clean")
        self.assertEqual(self.lane_json("mark", "--lane", lane, "--state", "accepted")["state"], "accepted")
        self.assertEqual(self.lane_json("mark", "--lane", lane, "--state", "merged")["state"], "merged")
        verdicts = [item["payload"] for item in self.kind_events(lane, "lane.refusal_reviewed")]
        self.assertEqual([(item["path"], item["verdict"]) for item in verdicts], [(plan, "workaround"), (copy, "clean")])
        self.assertEqual(verdicts[0]["note"]["text"], note.read_text(encoding="utf-8"))
        self.assertEqual(verdicts[0]["note"]["sha256"], support.digest(note.read_bytes()))
        self.assertIsNone(verdicts[1]["note"])
        self.assertTrue(all(item["actor"] == "supervisor" for item in self.kind_events(lane, "lane.refusal_reviewed")))
        row = self.status(lane)
        self.assertEqual(row["refusals"]["unreviewed"], [])
        self.assertEqual([(item["path"], item["verdict"]) for item in row["refusals"]["verdicts"]],
                         [(plan, "workaround"), (copy, "clean")])
        # Another lane with a suspicion that nobody reviewed is abandoned at once.
        other = lane + "-abandon"
        steps = [{"open": {}}] + refused_steps(fmt) + shell_steps("c2", "printf 'x\\n' > notes/plan.md") + [{"exit": 0}]
        self.start_session(other, fmt, steps)
        self.wait_event("lane.ended", other)
        self.assertEqual(len(self.refusals(other)["unreviewed"]), 1)
        self.assertEqual(self.lane_json("mark", "--lane", other, "--state", "abandoned")["state"], "abandoned")
        self.assert_sound()

    def test_claude_code(self):
        self.check_gate("claude-code", "c-claude")

    def test_mark_and_resume_are_serialised(self):
        # Decision 5: a resume that starts while a mark scans the lane's runs either is seen by the mark or waits for
        # it; never is accepted recorded over a run the mark did not scan. A slow guard pattern keeps the mark's scan
        # busy for several seconds (each of its results is stopped at the one-second bound).
        config = self.home / "configs" / "alpha" / "config.toml"
        config.write_text(config.read_text(encoding="utf-8")
                          + "\n[[guards]]\nname = \"slow\"\npattern = '^a.*.*.*.*.*.*.*b'\n", encoding="utf-8")
        lane = "c-race"
        steps = [{"open": {}}]
        for number in range(6):
            steps += shell_steps("s{}".format(number), "ls", text="a" * 4000, error=True)
        self.scenario(lane, [{"open": {}}, {"exit": 0}], run=2)
        self.start_session(lane, "claude-code", steps + [{"exit": 0}])
        self.wait_event("lane.ended", lane)
        marking = subprocess.Popen([str(self.command), "lane", "mark", "--config", "alpha", "--lane", lane, "--state",
                                    "accepted", "--accept-uncovered"], env=self.env("alpha"), cwd=str(self.directory),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(1.5)
        resumed = self.lane("resume", "--lane", lane, code=None)
        out, err = marking.communicate(timeout=120)
        self.wait_event("lane.ended", lane, run=2) if resumed.returncode == 0 else None
        states = self.kind_events(lane, "lane.state")
        started = [item for item in self.kind_events(lane, "lane.started") if item["payload"]["run"] == 2]
        if marking.returncode == 0:
            self.assertEqual(len(states), 1, err)
            self.assertTrue(not started or states[0]["seq"] < started[0]["seq"],
                            "accepted was recorded after run 2 began, which the mark did not scan")
        else:
            self.assertEqual(states, [])
        self.assert_sound()

    def test_review_refusals(self):
        steps = [{"open": {}}] + refused_steps("claude-code") + shell_steps("c2", "printf 'x\\n' > notes/plan.md")
        started = self.start_session("c-review", "claude-code", steps + [{"exit": 0}])
        self.wait_event("lane.ended", "c-review")
        refusal = self.kind_events("c-review", "lane.refusal")[0]["payload"]["refusal"]
        plan = expected_path(started["worktree"], "notes/plan.md")
        count = len(self.events())
        self.review("c-review", "rf-" + "0" * 24, plan, "clean", code=2)
        self.review("c-review", refusal, expected_path(started["worktree"], "notes/other.md"), "clean", code=2)
        self.review("c-review", refusal, plan, "fine", code=2)
        self.review("c-unknown", refusal, plan, "clean", code=2)
        secret = "Zx81-Qw72" + "-Lm55-Np09"
        note = self.directory / "secret-note.md"
        note.write_text("password = {}\n".format(secret), encoding="utf-8")
        result = self.review("c-review", refusal, plan, "clean", "--note", note, code=2)
        self.assertNotIn(secret, result.stdout + result.stderr)
        self.assertEqual(len(self.events()), count)
        self.review("c-review", refusal, plan, "clean")
        self.assertEqual(self.refusals("c-review")["unreviewed"], [])
        self.assert_sound()

    def test_refusal_after_the_last_live_scan(self):
        # The stand-in writes the refusal and the workaround only after its supervising process is gone: no live scan
        # sees them. Marking the lane accepted first scans every run to its end, so it finds both.
        lane = "d-late"
        steps = [{"open": {}}, {"mark": "opened"}, {"wait": "go"}] + refused_steps("claude-code")
        steps += shell_steps("c2", "printf 'x\\n' > notes/plan.md") + [{"exit": 0}]
        started = self.start_session(lane, "claude-code", steps)
        self.marked(lane, "opened")
        self.kill_supervisor(lane)
        self.go(lane)
        self.ended_by_itself(lane)
        self.assertEqual(self.lane_json("check")["lost"][0]["lane"], lane)
        self.assertEqual(self.kind_events(lane, "lane.refusal"), [])
        coverage = self.refusals(lane)["coverage"][0]
        self.assertIs(coverage["complete"], False)
        plan = expected_path(started["worktree"], "notes/plan.md")
        result = self.lane("mark", "--lane", lane, "--state", "accepted", code=2)
        self.assertIn(plan, result.stderr)
        refusals = self.kind_events(lane, "lane.refusal")
        self.assertEqual(len(refusals), 1)
        self.review(lane, refusals[0]["payload"]["refusal"], plan, "clean")
        marked = self.lane_json("mark", "--lane", lane, "--state", "accepted")
        self.assertLess(refusals[0]["seq"], marked["event"]["seq"])
        coverage = self.refusals(lane)["coverage"][0]
        self.assertEqual((coverage["complete"], coverage["covered"]), (True, True))

        # Without a workaround the refusal alone does not block: it is recorded before accepted is.
        lane = "d-alone"
        steps = [{"open": {}}, {"mark": "opened"}, {"wait": "go"}] + refused_steps("claude-code") + [{"exit": 0}]
        self.start_session(lane, "claude-code", steps)
        self.marked(lane, "opened")
        self.kill_supervisor(lane)
        self.go(lane)
        self.ended_by_itself(lane)
        self.lane_json("check")
        marked = self.lane_json("mark", "--lane", lane, "--state", "accepted")
        refusals = self.kind_events(lane, "lane.refusal")
        self.assertEqual(len(refusals), 1)
        self.assertLess(refusals[0]["seq"], marked["event"]["seq"])
        self.assertEqual(marked["scan"]["appended"], {"refusals": 1, "suspicions": 0})
        self.assert_sound()
