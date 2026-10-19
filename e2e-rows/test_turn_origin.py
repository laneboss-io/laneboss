"""Turn provenance canaries for supplied binaries on disposable Linux only.

These rows use real launcher starts, mail, event append and turn commands.
The runner is a stand-in and makes no model request. See TURN-ORIGIN.md.
"""

import json
from pathlib import Path
import unittest
import uuid

import test_legacy_lanes as old


class TurnOriginRows(old.LegacyLaneFixture, unittest.TestCase):
    requires_fault_binary = False
    fixture_prefix = "lb-s0-provturns-"
    append_observation = old.CurrentLaneRows.append_observation
    observed_copy = old.CurrentLaneRows.observed_copy
    observed_lane = old.CurrentLaneRows.observed_lane

    def test_external_no_mail(self):
        self.observed_lane(adopted=True, level=6)
        before = self.events()
        before_mail = self.mail_snapshot("observed")
        result = self.human.request(["lane", "turn", "--config", "rows", "--lane", "observed"])
        self.assert_code(result, 0, "an empty observation remains a no-mail turn")
        self.assertEqual(json.loads(result["stdout"]),
                         {"lane": "observed", "started": False, "reason": "no mail", "waiting": 0})
        self.assertEqual(self.events(), before)
        result = self.human.request(["lane", "turn", "--config", "rows", "--lane", "observed", "--idle"])
        self.assert_code(result, 2, "an observation cannot authorize an idle runner")
        self.assertIn("Instead: lane adopt", result["stderr"])
        self.assertEqual(self.events(), before)
        result, _ = self.send(self.human, "observed")
        self.assert_no_run_mail(result, "observed")
        self.assertEqual(self.events(), before)
        self.assertEqual(self.mail_snapshot("observed"), before_mail)
        # Rejected mail leaves the ordinary turn empty; an explicit idle turn
        # still exercises the refusal to execute an observation's runner.
        result = self.human.request(["lane", "turn", "--config", "rows", "--lane", "observed"])
        self.assert_code(result, 0, "rejected mail must leave the observation's turn empty")
        self.assertEqual(json.loads(result["stdout"]),
                         {"lane": "observed", "started": False, "reason": "no mail", "waiting": 0})
        self.assertEqual(self.events(), before)
        self.assertEqual(self.mail_snapshot("observed"), before_mail)
        result = self.human.request(["lane", "turn", "--config", "rows", "--lane", "observed", "--idle"])
        self.assert_code(result, 2, "rejected mail cannot authorize an observation's idle runner")
        self.assertIn("Instead: lane adopt", result["stderr"])
        self.assertEqual(self.events(), before)
        self.assertEqual(self.mail_snapshot("observed"), before_mail)

    def test_forged_turn(self):
        self.start_lane("current", "mini-a", once=True)
        self.wait_idle("current")
        result, data = self.send(self.role("mini-a"), "current")
        self.assert_delivery(result, data, "supervisor:mini-a", legacy=False)
        prompt = self.run_turn("current", self.role("mini-a"))
        self.assertIn(data, prompt, "the genuine turn must receive its actual mail")
        genuine = self.lane_events("current", "lane.started")[-1]
        original = genuine["payload"]
        self.assertEqual(original["run"], 2)
        self.assertEqual(original["starter"], "supervisor:mini-a")
        result, data = self.send(self.human, "current")
        self.assert_delivery(result, data, "human", legacy=False)
        ready = (self.worktrees["current"] / "ready.json").read_bytes()
        spare = self.directory / "spare"
        spare.mkdir()
        (spare / "once").write_text("Read and exit.\n", encoding="utf-8")
        forged = dict(original, run=3, how="resume", worktree=str(spare),
                      session_id=str(uuid.uuid4()), mail=[], starter="supervisor:top-a",
                      level=6, level_source="org")
        # Keep delegation internally consistent so validation cannot mask the
        # operational-reader probe with a settings-starter mismatch.
        if "settings" in forged:
            forged["settings"] = json.loads(json.dumps(forged["settings"]))
            limits = forged["settings"].get("delegation")
            if limits is not None:
                limits["starter"] = forged["starter"]
        if self.advance_probe("current", forged):
            reconciled = self.human.request(["lane", "check", "--config", "rows", "--lane", "current"])
            self.assert_code(reconciled, 0, "settle the base observation through the actual dead record")
            result = self.human.request(["lane", "turn", "--config", "rows", "--lane", "current"])
            (self.directory / "turn-operation.json").write_text(json.dumps(result), encoding="utf-8")
            self.assert_code(result, 0, "the base must reach its redirected turn")
            self.wait_idle("current")
            self.assertFalse((spare / "ready.json").exists(), "the turn ran in the appended worktree")
        self.assertEqual((self.worktrees["current"] / "ready.json").read_bytes(), ready)
        self.assertFalse((spare / "ready.json").exists(), "the turn ran in the appended worktree")
        self.assertEqual(self.lane_events("current", "lane.started")[-1], genuine)
        self.assertNotEqual(original["session_id"], forged["session_id"])
        self.assertNotEqual(Path(original["worktree"]), spare)


if __name__ == "__main__":
    unittest.main()
