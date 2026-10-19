"""Run only on the disposable Linux box; exercise the evidence verifier."""

import importlib.util
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("integrate_red", Path(__file__).with_name("red-controls.py"))
controls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controls)


class PlanControlTests(unittest.TestCase):
    def test_loaded(self):
        expected = set()
        for name in ("launch-plan-controls.json", "consumer-controls.json", "credential-controls.json", "contract-controls.json", "cleanup-controls.json", "store-controls.json", "store-r2-controls.json"):
            manifest = json.loads(Path(__file__).with_name(name).read_bytes())
            expected.update(row["id"] for row in manifest["controls"])
        active = {row[0] for row in controls.GO_CONTROLS}
        self.assertTrue(expected)
        self.assertTrue(expected <= active, "launch controls are absent from runner")



class AnchorControlTests(unittest.TestCase):
    def fixture(self, root):
        source, evidence = root / "source", root / "evidence"
        path = source / "internal/v2/api/fixture.go"
        path.parent.mkdir(parents=True)
        evidence.mkdir()
        path.write_text("first\nrepeat repeat\n\tif unfinished {\n")
        def row(name, edits, relative="api/fixture.go"):
            return (name, "api", "TestProbe", "probe assertion", relative, edits)
        rows = [
            row("missing", [("absent-one", ""), ("absent-two", "")]),
            row("ambiguous", [("repeat", "")]),
            row("block", [("REMOVE_BLOCK", "\tif unfinished {")]),
            row("unreadable", [("absent", "")], "api/missing.go"),
            row("valid", [("first", "changed")]),
        ]
        return source, evidence, rows

    def test_reports_all(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, evidence, rows = self.fixture(Path(temporary))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                prepared, failures = controls.prepare_go_controls(source, evidence, rows)
            self.assertEqual([row["id"] for row in failures], [row[0] for row in rows[:-1]],
                             "broken anchors were not retained")
            self.assertEqual([len(row["anchor_errors"]) for row in failures], [2, 1, 1, 1],
                             "not every broken edit was reported")
            self.assertEqual([row[0][0] for row in prepared], ["valid"])
            self.assertIn("changed", prepared[0][1])
            self.assertEqual(json.loads((evidence / "anchor-results.json").read_bytes()), failures)
            for row in failures:
                self.assertIn("BROKEN ANCHOR " + row["id"], output.getvalue())
                self.assertIsNone(row["red_exit"])
                self.assertIsNone(row["candidate_exit"])
                retained = json.loads((evidence / row["id"] / "mutation.json").read_bytes())
                self.assertEqual(retained["anchor_errors"], row["anchor_errors"])
            self.assertEqual(failures[0]["anchor_errors"][0]["occurrences"], 0)
            self.assertEqual(failures[1]["anchor_errors"][0]["occurrences"], 2)
            self.assertIn("closing delimiter", failures[2]["anchor_errors"][0]["error"])

    def verdict(self, action, code):
        # Protocol fixtures for orchestration only; no Go execution is claimed.
        events = [{"Action": "run", "Test": "TestProbe"},
                  {"Action": "output", "Test": "TestProbe", "Output": "probe assertion\n"},
                  {"Action": action, "Test": "TestProbe"}]
        return subprocess.CompletedProcess(["protocol-fixture"], code,
                                          b"\n".join(json.dumps(row).encode() for row in events) + b"\n", b"")

    def test_continues(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, evidence, rows = self.fixture(Path(temporary))
            output = io.StringIO()
            with contextlib.redirect_stdout(output), mock.patch.object(
                    controls, "run", side_effect=[self.verdict("fail", 1), self.verdict("pass", 0)]) as invoked:
                results = controls.run_go_controls(source, evidence, rows)
                code = controls.finish_results(evidence, results)
            self.assertEqual(invoked.call_count, 2, "constructible control was not executed")
            self.assertEqual(code, 1, "broken anchors became a successful run")
            self.assertEqual(len(results), len(rows))
            self.assertEqual(results[-1]["id"], "valid")
            self.assertEqual(results[-1]["status"], "passed")
            self.assertIn("changed", (evidence / "valid/source/internal/v2/api/fixture.go").read_text())
            self.assertIn("first", (source / "internal/v2/api/fixture.go").read_text())
            self.assertFalse((evidence / "missing/source").exists())
            self.assertEqual(json.loads((evidence / "results.json").read_bytes()), results)
            self.assertIn("4 broken controls, 5 anchor errors", output.getvalue())
            self.assertNotIn("PASS: draft.4 regression controls", output.getvalue())

    def test_clean(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, evidence, rows = self.fixture(Path(temporary))
            output = io.StringIO()
            with contextlib.redirect_stdout(output), mock.patch.object(
                    controls, "run", side_effect=[self.verdict("fail", 1), self.verdict("pass", 0)]):
                results = controls.run_go_controls(source, evidence, rows[-1:])
                code = controls.finish_results(evidence, results)
            self.assertEqual(code, 0)
            self.assertEqual(len(results), 1)
            self.assertIn("PASS: draft.4 regression controls", output.getvalue())
            self.assertEqual(json.loads((evidence / "anchor-results.json").read_bytes()), [])

class GoVerdictTests(unittest.TestCase):
    test = "TestBoundary/limit"
    diagnostic = "expected typed code invalid_request"

    def event(self, action, test=None, output=""):
        return {"Action": action, "Test": self.test if test is None else test, "Output": output}

    def result(self, events, code=1, stderr=b"", plain=b""):
        return subprocess.CompletedProcess(["go", "test"], code,
                                           b"\n".join(json.dumps(row).encode() for row in events) + b"\n" + plain,
                                           stderr)

    def test_accepts_reached_red_and_candidate(self):
        for code, action in ((1, "fail"), (0, "pass")):
            with self.subTest(code=code):
                result = self.result([self.event("run"), self.event("output", output=self.diagnostic + "\n"),
                                      self.event(action)], code)
                controls.go_verdict(result, self.test, code, self.diagnostic if code else "")

    def test_accepts_descendant_assertion(self):
        child = self.test + "/nested"
        result = self.result([self.event("run"), self.event("run", child),
                              self.event("output", child, self.diagnostic + "\n"),
                              self.event("fail", child), self.event("fail")])
        controls.go_verdict(result, self.test, 1, self.diagnostic)

    def test_reports_survived_with_output_tail(self):
        for code in (0, 1):
            # An unrelated package failure cannot kill a passing named mutant.
            with self.subTest(code=code):
                output = "".join(f"observation {index}\n" for index in range(20))
                result = self.result([self.event("run"), self.event("output", output=output),
                                      self.event("pass")], code)
                with self.assertRaisesRegex(RuntimeError, "^SURVIVED:") as caught:
                    controls.go_verdict(result, self.test, 1, self.diagnostic)
                message = str(caught.exception)
                self.assertIn(self.test, message)
                self.assertIn(f"exit={code}", message)
                self.assertIn("observation 19", message)
                self.assertNotIn("observation 0\n", message)

    def test_reports_not_reached(self):
        cases = {
            "compile": [],
            "other_test": [self.event("run", "TestOther"), self.event("fail", "TestOther")],
            "no_run": [self.event("fail")],
            "crash": [self.event("run")],
            "skip": [self.event("run"), self.event("skip")],
            "duplicate_run": [self.event("run"), self.event("run"), self.event("fail")],
            "duplicate_end": [self.event("run"), self.event("fail"), self.event("pass")],
            "reversed": [self.event("fail"), self.event("run")],
        }
        for fault, events in cases.items():
            for expected in (0, 1):
                with self.subTest(fault=fault, expected=expected):
                    result = self.result(events + [self.event("output", "", "FAIL package [build failed]\n")],
                                         stderr=b"source.go:7: undefined: missing\n")
                    with self.assertRaisesRegex(RuntimeError, "^NOT REACHED:") as caught:
                        controls.go_verdict(result, self.test, expected, self.diagnostic if expected else "")
                    self.assertIn("FAIL package [build failed]", str(caught.exception))
                    self.assertIn("source.go:7: undefined: missing", str(caught.exception))

    def test_reports_setup_and_bad_output(self):
        for plain in (b"go: module setup failed\n", b'{"Action": broken\n'):
            with self.subTest(plain=plain):
                with self.assertRaisesRegex(RuntimeError, "^NOT REACHED:") as caught:
                    controls.go_verdict(self.result([], plain=plain), self.test, 1, self.diagnostic)
                self.assertIn(plain.decode().strip(), str(caught.exception))

    def test_rejects_inconsistent_exit(self):
        for code, action, expected, label in ((0, "fail", 1, "INVALID VERDICT"),
                                              (1, "fail", 0, "CANDIDATE FAILED"),
                                              (1, "pass", 0, "CANDIDATE FAILED")):
            with self.subTest(code=code, action=action, expected=expected):
                result = self.result([self.event("run"), self.event("output", output="assertion details\n"),
                                      self.event(action)], code)
                with self.assertRaisesRegex(RuntimeError, "^" + label + ":") as caught:
                    controls.go_verdict(result, self.test, expected)
                self.assertIn("assertion details", str(caught.exception))

    def test_requires_intended_assertion(self):
        for outside in ("TestOther", self.test + "Other", "TestBoundary", ""):
            with self.subTest(outside=outside):
                result = self.result([self.event("run"), self.event("output", output="unrelated panic\n"),
                                      self.event("output", outside, self.diagnostic + "\n"), self.event("fail")],
                                     stderr=(self.diagnostic + "\n").encode())
                with self.assertRaisesRegex(RuntimeError, "^WRONG FAILURE:") as caught:
                    controls.go_verdict(result, self.test, 1, self.diagnostic)
                self.assertIn("unrelated panic", str(caught.exception))


class ScannerVerdictTests(unittest.TestCase):
    def evidence(self, root, red):
        case = "nonexistent-own-path"
        directory = root / "lb-v2-integrate-scan-fixture"
        directory.mkdir()
        rows = []
        for mode in ("working", "staged"):
            rows.append({"id": case, "mode": mode, "exit": 0 if red else 1, "passed": not red})
            (directory / f"{case}-{mode}.stdout").write_text(
                "SCAN PASS: fixture\n" if red else "SCAN FAIL sample.go:2 long-secret-like-token\n")
            (directory / f"{case}-{mode}.stderr").write_bytes(b"")
        (directory / "results.json").write_text(json.dumps(rows))
        label = "FAIL" if red else "PASS"
        result = subprocess.CompletedProcess(["fixture"], 1 if red else 0,
                                             f"{label} {case}/working\n{label} {case}/staged\n".encode(), b"")
        return case, directory, rows, result

    def test_accepts_observed_verdicts(self):
        for red in (False, True):
            with self.subTest(red=red), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                case, _, _, result = self.evidence(root, red)
                controls.scanner_verdict(result, root, case, red)

    def test_rejects_errors(self):
        for fault in ("setup_exit", "syntax_error", "only_working", "wrong_case", "missing_results", "wrong_candidate_exit"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                red = fault != "wrong_candidate_exit"
                case, directory, rows, result = self.evidence(root, red)
                if fault == "setup_exit":
                    rows[0]["exit"] = 2
                    (directory / f"{case}-working.stdout").write_text("SCAN ERROR: prerequisite missing\n")
                elif fault == "syntax_error":
                    (directory / f"{case}-staged.stderr").write_text("SyntaxError: broken scanner\n")
                elif fault == "only_working":
                    result.stdout = f"FAIL {case}/working\n".encode()
                elif fault == "wrong_case":
                    rows[1]["id"] = "another-case"
                elif fault == "wrong_candidate_exit":
                    rows[1]["exit"] = 0
                (directory / "results.json").write_text(json.dumps(rows))
                if fault == "missing_results":
                    (directory / "results.json").unlink()
                with self.assertRaises(RuntimeError):
                    controls.scanner_verdict(result, root, case, red)


if __name__ == "__main__":
    unittest.main()
