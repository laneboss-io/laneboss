"""Unit tests for mutation evidence classification, not product E2E proof."""

import copy
from contextlib import redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest

import mutations


class MutationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.mutation = mutations.checked_catalog()[0]
        self.target = "/".join(self.mutation.test)

    def event(self, action, name=None, output=None):
        row = {"Package": mutations.PACKAGE, "Action": action}
        if name is not None:
            row["Test"] = name
        if output is not None:
            row["Output"] = output
        return row

    def trace(self, phase):
        terminal = "fail" if phase == "red" else "pass"
        return [self.event("run", self.target),
                self.event("output", self.target,
                           self.mutation.failure_contains + "\n"),
                self.event(terminal, self.target), self.event(terminal)]

    def test_actual_red_then_green_observations(self):
        red = mutations.analyze(self.trace("red"), 1, self.mutation, "red")
        self.assertEqual(red["failed"], [self.target])
        self.assertEqual(red["observed_exit"], 1)
        green = mutations.analyze(self.trace("green"), 0, self.mutation, "green")
        self.assertEqual(green["passed"], [self.target])
        self.assertEqual(green["failed"], [])

    def test_compile_failure_is_not_a_kill(self):
        rows = [self.event("output", output="fixture compiler failure\n"),
                self.event("fail")]
        with self.assertRaisesRegex(mutations.MutationFailure, "did not run"):
            mutations.analyze(rows, 1, self.mutation, "red")

    def test_compiler_diagnostics(self):
        item = next(item for item in mutations.catalog() if item.id == "lifecycle-cause")
        with tempfile.TemporaryDirectory() as directory:
            stdout, stderr = Path(directory) / "stdout", Path(directory) / "stderr"
            stdout.write_bytes(b"fixture compiler stdout\n")
            stderr.write_bytes(b"approved.go:191: declared and not used: causeID\n")
            captured = io.StringIO()
            with redirect_stderr(captured):
                with self.assertRaisesRegex(mutations.MutationFailure,
                                            "lifecycle-cause/red: a compile failure cannot kill a mutation"):
                    mutations.require_compiled(item, "red", 1, stdout, stderr)
            diagnostic = captured.getvalue()
            self.assertIn("lifecycle-cause/red: compiler exited 1", diagnostic)
            self.assertIn(stdout.read_text(), diagnostic)
            self.assertIn(stderr.read_text(), diagnostic)

    def test_vet_mode_blocks_tests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proof = mutations.Proof(root, root / "evidence", [self.mutation], "", 1, 1,
                                    vet_only=True)
            with self.assertRaisesRegex(mutations.MutationFailure,
                                        "static vet mode cannot compile or execute tests"):
                proof.test_phase(self.mutation, "red")

    def test_cli_package_binding(self):
        item = next(item for item in mutations.catalog() if item.package == mutations.CLI_PACKAGE)
        target = "/".join(item.test)
        rows = [
            {"Package": item.package, "Action": "run", "Test": target},
            {"Package": item.package, "Action": "output", "Test": target, "Output": item.failure_contains},
            {"Package": item.package, "Action": "fail", "Test": target},
            {"Package": item.package, "Action": "fail"},
        ]
        self.assertEqual(mutations.analyze(rows, 1, item, "red")["failed"], [target])
        for row in rows:
            row["Package"] = mutations.PACKAGE
        with self.assertRaisesRegex(mutations.MutationFailure, "wrong package"):
            mutations.analyze(rows, 1, item, "red")

    def test_unrelated_failure_is_not_a_kill(self):
        rows = [self.event("run", "TestOtherBoundary"),
                self.event("fail", "TestOtherBoundary"), self.event("fail")]
        with self.assertRaisesRegex(mutations.MutationFailure, "unrelated test"):
            mutations.analyze(rows, 1, self.mutation, "red")

    def test_wrong_reason_is_not_a_kill(self):
        rows = self.trace("red")
        rows[1]["Output"] = "fixture dependency was unavailable\n"
        with self.assertRaisesRegex(mutations.MutationFailure, "assertion failure"):
            mutations.analyze(rows, 1, self.mutation, "red")

    def test_panic_is_not_a_kill(self):
        rows = self.trace("red")
        rows[1]["Output"] += "panic: fixture crash\n"
        with self.assertRaisesRegex(mutations.MutationFailure, "panic"):
            mutations.analyze(rows, 1, self.mutation, "red")

    def test_skip_is_not_a_kill(self):
        rows = self.trace("red")
        rows[2]["Action"] = "skip"
        with self.assertRaisesRegex(mutations.MutationFailure, "skipped tests"):
            mutations.analyze(rows, 1, self.mutation, "red")

    def test_abnormal_exit_is_not_a_kill(self):
        with self.assertRaisesRegex(mutations.MutationFailure, "fail normally"):
            mutations.analyze(self.trace("red"), -9, self.mutation, "red")

    def test_surviving_mutant_is_a_failure(self):
        with self.assertRaisesRegex(mutations.MutationFailure, "fail normally"):
            mutations.analyze(self.trace("green"), 0, self.mutation, "red")

    def test_empty_green_is_not_a_pass(self):
        with self.assertRaisesRegex(mutations.MutationFailure, "did not run"):
            mutations.analyze([self.event("pass")], 0, self.mutation, "green")

    def test_failed_green_is_not_a_pass(self):
        with self.assertRaisesRegex(mutations.MutationFailure, "did not pass"):
            mutations.analyze(self.trace("red"), 1, self.mutation, "green")

    def test_duplicate_terminal_is_a_failure(self):
        rows = self.trace("red")
        rows.insert(3, copy.deepcopy(rows[2]))
        with self.assertRaisesRegex(mutations.MutationFailure, "duplicate terminal"):
            mutations.analyze(rows, 1, self.mutation, "red")

    def test_truncated_trace_is_a_failure(self):
        rows = self.trace("red")[:-1]
        with self.assertRaisesRegex(mutations.MutationFailure, "package terminal"):
            mutations.analyze(rows, 1, self.mutation, "red")

    def test_output_after_terminal_is_invalid(self):
        rows = self.trace("red")
        rows.append(self.event("output", self.target, self.mutation.failure_contains))
        with self.assertRaisesRegex(mutations.MutationFailure, "after the package terminal"):
            mutations.analyze(rows, 1, self.mutation, "red")

    def test_subtest_failure_must_reach_target(self):
        item = next(item for item in mutations.catalog() if len(item.test) > 1)
        parent, child = item.test[0], "/".join(item.test)
        rows = [self.event("run", parent), self.event("run", child),
                self.event("output", child, item.failure_contains + "\n"),
                self.event("fail", child), self.event("fail", parent),
                self.event("fail")]
        observed = mutations.analyze(rows, 1, item, "red")
        self.assertIn(child, observed["failed"])
        rows[1]["Test"] = parent + "/unrelated"
        with self.assertRaisesRegex(mutations.MutationFailure, "unrelated test"):
            mutations.analyze(rows, 1, item, "red")

    def test_invalid_json_is_a_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_bytes(b"not JSON\n")
            with self.assertRaisesRegex(mutations.MutationFailure, "complete JSONL"):
                mutations.read_records(path)

    def test_catalog_anchors_match_source(self):
        root = Path(__file__).resolve().parents[4]
        entries = mutations.checked_catalog()
        for item in entries:
            with self.subTest(mutation=item.id):
                before = (root / item.file).read_bytes()
                after = mutations.exact_replacement(before, item)
                self.assertNotEqual(before, after)
                self.assertNotEqual(mutations.sha(before), mutations.sha(after))
        controls = json.loads((root / mutations.CASE_PATH / "red-controls.json").read_bytes())
        names = {item.id for item in entries}
        for row in controls["controls"]:
            self.assertIn(row["id"], names)

    def test_anchor_drift_is_a_failure(self):
        item = self.mutation
        for data in (b"no matching source", item.before.encode() * 2):
            with self.assertRaisesRegex(mutations.MutationFailure, "exactly once"):
                mutations.exact_replacement(data, item)


if __name__ == "__main__":
    unittest.main()
