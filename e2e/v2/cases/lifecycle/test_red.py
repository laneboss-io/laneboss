"""Runner unit tests for the authorized Linux phase; no native acceptance."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("lifecycle_red", Path(__file__).with_name("red.py"))
red = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(red)
PACKAGE = "laneboss.io/laneboss/internal/v2/lifecycle"


def test_events(name, passed, output=""):
    return [{"Action": "run", "Package": PACKAGE, "Test": name},
            {"Action": "output", "Package": PACKAGE, "Test": name, "Output": output},
            {"Action": "pass" if passed else "fail", "Package": PACKAGE, "Test": name},
            {"Action": "pass" if passed else "fail", "Package": PACKAGE}]


class VerdictTests(unittest.TestCase):
    def test_archive_path_boundary(self):
        self.assertTrue(red.owned_path("internal/v2/archive/read.go"))
        for path in ["internal/v2/archive/stream.go", "internal/v2/archive/hdr_test.go",
                     "internal/v2/archive/../read.go", "/internal/v2/archive/read.go"]:
            with self.subTest(path=path):
                self.assertFalse(red.owned_path(path))
        self.assertFalse(red.owned_path("internal/v2/archive/read.go", "ReadBack"))

    def test_classification(self):
        row = {"test": "TestGuard/pin", "expect": "required guard refused"}
        cases = [
            ("detected", 1, test_events(row["test"], False, row["expect"]), "detected", "named assertion"),
            ("passed", 0, test_events(row["test"], True), "survived", "passed with"),
            ("other-assertion", 1, test_events(row["test"], False, "another failure"), "survived", "without its expected"),
            ("build", 1, [{"Action": "build-fail", "Package": PACKAGE}], "invalid_evidence", "build"),
            ("old-build", 1, [{"Action": "fail", "Package": PACKAGE, "FailedBuild": PACKAGE}], "invalid_evidence", "build"),
            ("missing", 0, test_events("TestGuard/other", True), "invalid_evidence", "did not run"),
            ("panic", 1, test_events(row["test"], False, "panic: " + row["expect"]), "invalid_evidence", "panicked"),
            ("unfinished", 1, [{"Action": "run", "Test": row["test"]}], "invalid_evidence", "did not finish"),
        ]
        for name, code, events, status, reason in cases:
            with self.subTest(name=name):
                actual, detail, failed = red.mutation_verdict(row, code, events)
                self.assertEqual(actual, status)
                self.assertIn(reason, detail)
                self.assertEqual(row["test"] in failed,
                                 any(event.get("Test") == row["test"] and event["Action"] == "fail"
                                     for event in events))


class RunnerTests(unittest.TestCase):
    def invoke(self, root, outcomes, faults=False, green=True):
        source, evidence = root / "source", root / "evidence"
        source.mkdir()
        (source / "go.mod").write_text("module fixture.invalid/runner\n")
        target = source / "internal/v2/lifecycle/guard.go"
        target.parent.mkdir(parents=True)
        target.write_text("package lifecycle\nconst guarded = true\n")
        rows = [{"id": name, "rule": name.replace("-", "_"), "status": "guard",
                 "file": "internal/v2/lifecycle/guard.go", "before": "guarded = true", "after": "guarded = false",
                 "package": "./internal/v2/lifecycle", "test": "TestGuard/" + name, "expect": "required guard refused"}
                for name in outcomes]
        catalog = root / "catalog.json"
        catalog.write_text(json.dumps({"schema": "lifecycle.mutations.v1", "mutations": rows}))
        calls = []

        def recorded_run(tree, directory, packages, test=None, faults=False):
            calls.append((directory.name, faults))
            if test is None:
                return (0 if green else 1), test_events("TestGuard/baseline", green, "baseline failure" if not green else "")
            kind = outcomes[directory.name]
            if kind == "build":
                return 1, [{"Action": "build-fail", "Package": PACKAGE}]
            if kind == "missing":
                return 0, test_events("TestGuard/other", True)
            return (0 if kind == "pass" else 1), test_events(
                test, kind == "pass", "required guard refused" if kind == "detected" else "another failure")

        argv = ["red.py", "--source", str(source), "--evidence", str(evidence), "--suite", "guards"]
        if faults:
            argv.append("--faults")
        output = io.StringIO()
        with mock.patch.object(red, "CATALOG", catalog), mock.patch.object(red, "go_run", side_effect=recorded_run), \
                mock.patch.object(red.sys, "argv", argv), contextlib.redirect_stdout(output):
            try:
                code = red.main()
            except RuntimeError as error:
                code = error
        return code, json.loads((evidence / "summary.json").read_bytes()), output.getvalue(), calls, evidence

    def test_all_survivors_and_green(self):
        for faults in (False, True):
            with self.subTest(faults=faults), tempfile.TemporaryDirectory() as temporary:
                outcomes = {"first": "pass", "middle": "detected", "last": "other"}
                code, summary, output, calls, evidence = self.invoke(Path(temporary), outcomes, faults=faults)
                self.assertEqual(code, 1)
                self.assertEqual(calls, [(name, faults) for name in [*outcomes, "green"]])
                self.assertEqual(summary["status"], "survivors")
                self.assertEqual(summary["green"], "passed")
                self.assertEqual([row["status"] for row in summary["mutations"]], ["survived", "detected", "survived"])
                self.assertEqual([row["id"] for row in summary["survivors"]], ["first", "last"])
                for survivor in summary["survivors"]:
                    self.assertTrue(survivor["reason"])
                    self.assertIn(survivor["id"] + ": SURVIVED -> " + survivor["reason"], output)
                self.assertNotIn("PASS: lifecycle", output)
                for name in outcomes:
                    self.assertIn("guarded = false", (evidence / name / "source/internal/v2/lifecycle/guard.go").read_text())

    def test_invalid_evidence_still_stops(self):
        for kind in ("build", "missing"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                code, summary, output, calls, _ = self.invoke(Path(temporary), {"first": "pass", "bad": kind, "last": "detected"})
                self.assertIsInstance(code, RuntimeError)
                self.assertEqual(calls, [("first", False), ("bad", False)])
                self.assertEqual(summary["status"], "failed")
                self.assertEqual(summary["green"], "not_run")
                self.assertEqual(summary["mutations"][-1]["status"], "invalid_evidence")
                self.assertEqual([row["id"] for row in summary["survivors"]], ["first"])
                self.assertIn("first: SURVIVED", output)
                self.assertNotIn("PASS: lifecycle", output)

    def test_success_requires_green(self):
        for green in (True, False):
            with self.subTest(green=green), tempfile.TemporaryDirectory() as temporary:
                code, summary, output, calls, _ = self.invoke(Path(temporary), {"only": "detected"}, green=green)
                self.assertEqual(calls, [("only", False), ("green", False)])
                self.assertEqual(summary["survivors"], [])
                if green:
                    self.assertEqual(code, 0)
                    self.assertEqual(summary["status"], "guard_fixtures_passed")
                    self.assertIn("PASS: lifecycle", output)
                else:
                    self.assertIsInstance(code, RuntimeError)
                    self.assertEqual(summary["status"], "failed")
                    self.assertNotIn("PASS: lifecycle", output)


if __name__ == "__main__":
    unittest.main()
