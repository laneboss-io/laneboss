"""Run on the disposable Linux verifier; these import the actual red runner."""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

import mutations


class FailureDiagnosticTests(unittest.TestCase):
    def setUp(self):
        mutations.step(stage=self.id())

    def diagnostic(self, output):
        result = io.StringIO()
        with redirect_stdout(result):
            mutations.failure("candidate test failed", output)
        record = json.loads(result.getvalue())
        self.assertEqual(record["verdict"], "fail")
        return record["diagnostic"]

    def test_early_failure(self):
        header = "--- FAIL: TestDataStageDispatch/child_first (0.01s)\n"
        assertion = ("    materialization_linux_test.go:196: "
                     "materialization dispatch repeated a retained launch\n")
        later = "--- PASS: TestLater (0.01s)\n" * 1000
        for verbose in (False, True):
            with self.subTest(verbose=verbose):
                failure = assertion + header if verbose else header + assertion
                output = "=== RUN   TestDataStageDispatch/child_first\n" + failure + later + "FAIL\n"
                diagnostic = self.diagnostic(output)
                self.assertIn(header, diagnostic, "early test FAIL line was displaced by the tail")
                self.assertIn(assertion, diagnostic, "early failing assertion was displaced by the tail")
                self.assertTrue(diagnostic.endswith("FAIL\n"))
                self.assertLessEqual(len(diagnostic), 12000)

    def test_short_output(self):
        output = "--- FAIL: TestShort (0.01s)\n    short_test.go:12: refused\nFAIL\n"
        self.assertEqual(self.diagnostic(output), output)

    def test_final_failure(self):
        output = "--- FAIL: TestEarly (0.01s)\n    early_test.go:12: refused\n" + "later output\n" * 2000
        result = io.StringIO()
        with redirect_stdout(result):
            mutations.failure("candidate test failed", output)
            final = mutations.failure("candidate test failed")
        records = [json.loads(line) for line in result.getvalue().splitlines()]
        self.assertIn("--- FAIL: TestEarly", records[-1]["diagnostic"],
                      "outer failure discarded the failing test diagnostic")
        self.assertEqual(records[0]["diagnostic"], records[-1]["diagnostic"])
        self.assertEqual(final, records[-1])

    def test_new_step(self):
        self.diagnostic("--- FAIL: TestEarlier (0.01s)\n")
        mutations.step(stage="a different failed step")
        result = io.StringIO()
        with redirect_stdout(result):
            mutations.failure("later setup error")
        self.assertEqual(json.loads(result.getvalue())["diagnostic"], "later setup error")

    def test_build_output_tail(self):
        output = "build progress\n" * 2000 + "compile diagnostic at the end\n"
        self.assertEqual(self.diagnostic(output), output[-12000:])

    def test_selected_inventory(self):
        # These declarations are inputs to Go list, never executed tests.
        with tempfile.TemporaryDirectory(prefix="lb-service-inventory-") as temporary:
            source = Path(temporary).resolve()
            (source / "go.mod").write_text("module inventory.invalid/fixture\n\ngo 1.26.0\n")
            root = source / "internal/v2/store"
            root.mkdir(parents=True)
            (root / "ordinary_test.go").write_text(
                'package store\nimport "testing"\nfunc TestVisible(t *testing.T) { t.Fatal("inventory input must not execute") }\n')
            (root / "tagged_test.go").write_text(
                '//go:build laneboss_e2e_authenticator\n\npackage store\nimport "testing"\n'
                'func TestTagged(t *testing.T) { t.Fatal("inventory input must not execute") }\n')
            for variant, flags, expected in (
                    ("normal", [], {"TestVisible"}),
                    ("faults", ["-tags", "laneboss_faults"], {"TestVisible"}),
                    ("tagged", ["-tags", "laneboss_e2e_authenticator"], {"TestVisible", "TestTagged"})):
                folder = source / variant
                folder.mkdir()
                observed = mutations.selected_tests(source, "store", flags, folder)
                self.assertEqual(observed, expected, "build constraints changed declared test inventory")
                retained = json.loads((folder / "declared-tests.json").read_text())
                self.assertEqual(set(retained["tests"]), expected, "selected test inventory lost its evidence")


if __name__ == "__main__":
    unittest.main()
