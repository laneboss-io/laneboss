"""Harness regressions only; these fixtures establish no installed authority."""

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent))
from run import Case
from observations import CaseFailure, digest


class HarnessTests(unittest.TestCase):
    def make_case(self, directory):
        root = Path(directory)
        return Case({"test_root": str(root), "evidence_root": str(root / "evidence")}, root / "result.json")

    def test_public_events_select_actual_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            case = self.make_case(directory)
            case.lanes = {"a3": {"life_id": "recipient"}}
            calls = []
            rows = {1: [{"id": "old", "seq": 4, "life_id": "recipient", "run": 1}],
                    2: [{"id": "current", "seq": 3, "life_id": "recipient", "run": 2}]}

            def cli(actor, command, params):
                calls.append((command, params))
                if command == ["lane", "status"]:
                    return {"life_id": params["life_id"], "run": 2}
                if params["run"] <= 0:
                    raise CaseFailure("public event.tail requires an exact run")
                return {"events": rows[params["run"]], "complete": True, "cursor": ""}

            case.cli = cli
            observed = case.events("a3")
            self.assertEqual([row["id"] for row in observed], ["current", "old"])
            self.assertEqual([params["run"] for command, params in calls if command == ["event", "tail"]], [1, 2])

    def test_human_step_retains_typed_wait(self):
        with tempfile.TemporaryDirectory() as directory:
            case = self.make_case(directory)
            case.active = "HUMAN-SEND"
            with self.assertRaises(CaseFailure):
                case.human_send()
            wait = json.loads((case.evidence / "owner-wait.json").read_bytes())
            self.assertEqual(wait["code"], "prerequisite_missing")
            self.assertEqual(wait["owner"], "lb-v2-identity")
            self.assertEqual(case.last_exit, 69)
            self.assertFalse(case.results["HUMAN-SEND"]["reached"])
            self.assertFalse(case.collected)

    def test_owner_confirmation_label_can_f3cd(self):
        for label in (True, {"confirmed": True}, ""):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                case = self.make_case(directory)
                case.fixture["human"] = label
                with self.assertRaises(CaseFailure):
                    case.human_send()
                self.assertTrue(case.owner_waiting)
                self.assertFalse(case.collected)

    def test_d6_wait_contains_no_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            case = self.make_case(directory)
            with self.assertRaises(CaseFailure):
                case.channel_selectors()
            wait = json.loads((case.evidence / "owner-wait.json").read_bytes())
            self.assertEqual(wait["code"], "prerequisite_missing")
            self.assertEqual(wait["owner"], "lb-v2-approval")
            self.assertNotIn("approved", wait)
            self.assertFalse(any(result["verdict"] == "pass" for result in case.results.values()))

    def test_owner_wait_returns_incomplet_d937(self):
        class WaitingSetup(Case):
            def setup(self):
                # Exercise the real run/finally/result path with its actual
                # missing-owner step; no ready actor or approval is modeled.
                self.human_send()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = {"test_root": str(root), "evidence_root": str(root / "evidence"),
                       "phase": "candidate", "mutation_id": "",
                       "binary_sha256": digest(b"unused fixture artifact"),
                       "source_sha256": digest(b"owner wait fixture input")}
            case = WaitingSetup(context, root / "result.json")
            self.assertEqual(case.run(), 69)
            result = json.loads((root / "result.json").read_bytes())
            self.assertFalse(result["collection"]["processes_quiescent"])
            self.assertFalse(result["collection"]["temporary_resources_collected"])
            self.assertTrue(all(not item["reached"] and item["verdict"] == "fail" for item in result["assertions"]))


if __name__ == "__main__":
    unittest.main()
