"""Summary refusal controls; no synthetic report is runtime evidence."""

import copy
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("summary", Path(__file__).with_name("summary.py"))
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)
probe_spec = importlib.util.spec_from_file_location("summary_probe", Path(__file__).with_name("reply_test.py"))
controls = importlib.util.module_from_spec(probe_spec)
probe_spec.loader.exec_module(controls)


class SummaryControls(unittest.TestCase):
    def fake_fixture(self):
        probe = controls.Probe(self, controls.Clock(), real=False)
        observed = probe.run()
        proof = probe.record["vendor_proof"]
        names = summary.expected_checks("installed-lifecycle", reply=True, fake=True)
        rows = []
        for name in names:
            value = {"executed": True}
            if name == "lane.claudock.reply":
                value.update(observed)
            elif name in ("lane.claudock.running", "lane.claudock.events"):
                value["vendor_proof"] = copy.deepcopy(proof)
            elif name.startswith("lane.claudock.lifecycle."):
                value["purpose"] = summary.steps.LIFECYCLE_ONLY
            elif name == "cleanup":
                value["api_key_canary"] = {"vendor_proofs": [copy.deepcopy(proof)]}
            elif name == "admin.publication":
                value["canary_spend"] = {"fake_reading": True}
            rows.append({"check": name, "result": "pass", "presence": "simulated", "observed": value})
        return {"scope": "installed-lifecycle", "reply_mode": "fake-key", "presence": "simulated",
                "human_approval": "not_proven", "required_checks": names, "failure": None, "checks": rows}

    def fixture(self):
        names = summary.expected_checks("installed-lifecycle")
        return {"scope": "installed-lifecycle", "presence": "simulated", "human_approval": "not_proven",
                "required_checks": names, "failure": None,
                "checks": [{"check": name, "result": "pass", "presence": "simulated", "observed": {"executed": True}} for name in names]}

    def test_complete_formatter_input(self):
        # This checks formatting only; these synthetic rows never enter an
        # installed report or count as ceremony/process acceptance evidence.
        passed, text = summary.describe(self.fixture())
        self.assertTrue(passed)
        self.assertIn("PASS: installed-lifecycle; presence=simulated", text)
        self.assertIn("failed=0 unrun=0", text)

    def test_empty_or_missing_is_failure(self):
        for mode in ("empty", "missing", "unrun", "unmarked", "absent-checks", "absent-report"):
            with self.subTest(mode=mode):
                report = self.fixture()
                if mode == "empty": report["checks"] = []
                elif mode == "missing": report["checks"].pop()
                elif mode == "unrun": report["checks"][0]["observed"]["executed"] = False
                elif mode == "unmarked": report["checks"][0]["presence"] = "hardware"
                elif mode == "absent-checks": report.pop("checks")
                else: report = None
                passed, text = summary.describe(report)
                self.assertFalse(passed)
                self.assertTrue(text.startswith("FAIL:"))
                self.assertIn("step=", text)

    def test_actual_owner_is_printed(self):
        report = self.fixture()
        error = {"owner": "lb-v2-identity", "code": "not_implemented", "message": "identity.BeginEnrollment is not implemented"}
        report["failure"] = {"check": "human.enrollment", "observed": {"executed": True, "refusal": error}}
        passed, text = summary.describe(report)
        self.assertFalse(passed)
        self.assertIn("owner=lb-v2-identity code=not_implemented", text)
        self.assertIn("human_approval=not_proven", text)

    def test_fake_summary(self):
        passed, text = summary.describe(self.fake_fixture())
        self.assertTrue(passed, "complete fake-key report was rejected")
        self.assertIn("Claude Code reached the vendor with the fake key", text.splitlines())
        self.assertNotIn("a real model turn completed and was billed", text)
        self.assertIn("canary balance is credential setup only; does not prove the agent ran", text)
        for step in summary.steps.LIFECYCLE_STEPS:
            self.assertIn("step=lane.claudock.lifecycle." + step + " lifecycle only; does not prove the agent ran", text)

    def test_fake_rows(self):
        for name in ("lane.claudock.reply", "lane.claudock.running", "lane.claudock.events", "cleanup"):
            with self.subTest(row=name):
                report = self.fake_fixture()
                observed = next(row["observed"] for row in report["checks"] if row["check"] == name)
                if name == "lane.claudock.reply":
                    observed["spend"]["records"] = []
                elif name == "cleanup":
                    observed["api_key_canary"]["vendor_proofs"] = [{}]
                else:
                    observed["vendor_proof"] = {}
                passed, text = summary.describe(report)
                self.assertFalse(passed, "forged fake row was credited")
                self.assertIn("the agent never started", text)

    def test_lifecycle_scope(self):
        report = self.fake_fixture()
        for step in summary.steps.LIFECYCLE_STEPS:
            old = "lane.claudock." + step
            self.assertNotIn(old, report["required_checks"], "lifecycle name implies an agent run")
        observed = next(row["observed"] for row in report["checks"]
                        if row["check"] == "lane.claudock.lifecycle.quiescent")
        del observed["purpose"]
        passed, _ = summary.describe(report)
        self.assertFalse(passed, "unlabeled lifecycle row was credited")

    def test_fake_mutations(self):
        cases = (("test_fake_summary", False, "complete fake-key report was rejected"),
                 ("test_fake_rows", True, "forged fake row was credited"),
                 ("test_lifecycle_scope", True, "unlabeled lifecycle row was credited"))
        for name, verdict, reason in cases:
            with self.subTest(control=name), mock.patch.object(summary.steps, "fake_row_passed", lambda *_: verdict):
                result = unittest.TestResult()
                SummaryControls(name).run(result)
                self.assertEqual(result.errors, [], "summary mutation caused an unrelated error")
                self.assertTrue(any(reason in detail for _, detail in result.failures), "summary mutation escaped its control")


if __name__ == "__main__":
    unittest.main()
