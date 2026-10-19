"""Linux-only harness parser checks, separate from actual Go mutation evidence."""

import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest

import mutate


def events(outcome="fail", message="guard rejected the canary"):
    parent = "TestControl"
    leaf = parent + "/boundary"
    return [
        {"Action": "start"}, {"Action": "run", "Test": parent},
        {"Action": "run", "Test": leaf},
        {"Action": "output", "Test": leaf, "Output": message + "\n"},
        {"Action": outcome, "Test": leaf},
        {"Action": outcome, "Test": parent}, {"Action": outcome},
    ]


def encoded(values):
    return b"".join(
        (json.dumps({"Package": mutate.PACKAGE, **event}) + "\n").encode()
        for event in values
    )


class TestMutationObserver(unittest.TestCase):
    def setUp(self):
        self.mutation = {
            "test": "TestControl", "subtests": ["boundary"],
            "markers": ["guard rejected the canary"],
        }

    def test_reached_red_then_green(self):
        red = mutate.observe(encoded(events()), self.mutation, 1, False, True)
        green = mutate.observe(encoded(events("pass")), self.mutation, 0, False, False)
        self.assertEqual(red["failed"], ["TestControl", "TestControl/boundary"])
        self.assertEqual(green["failed"], [])
        self.assertTrue(red["validated"] and green["validated"])

    def test_rejects_false_red(self):
        for name, data, exit_code, timeout in (
            ("survived", events("pass"), 0, False),
            ("build-error", [{"Action": "fail"}], 1, False),
            ("missing-test", events("fail")[:1] + [{"Action": "fail"}], 1, False),
            ("wrong-assertion", events("fail", "unrelated setup failed"), 1, False),
            ("panic", events("fail", "panic: guard rejected the canary"), 1, False),
            ("timeout", events(), 1, True),
            ("signal", events(), -9, False),
            ("skip", events("skip"), 1, False),
            ("wrong-exit", events(), 2, False),
        ):
            with self.subTest(name=name):
                with self.assertRaises(mutate.CheckFailure):
                    mutate.observe(encoded(data), self.mutation, exit_code, timeout, True)

    def test_rejects_false_green(self):
        with self.assertRaises(mutate.CheckFailure):
            mutate.observe(encoded(events()), self.mutation, 1, False, False)
        with self.assertRaises(mutate.CheckFailure):
            mutate.observe(encoded([{"Action": "pass"}]), self.mutation, 0, False, False)

    def test_rejects_other_failures(self):
        data = events()
        data.insert(-1, {"Action": "fail", "Test": "TestOther"})
        with self.assertRaises(mutate.CheckFailure):
            mutate.observe(encoded(data), self.mutation, 1, False, True)
        data = events()
        data.insert(-1, {"Action": "pass", "Test": "TestControl/boundary"})
        with self.assertRaises(mutate.CheckFailure):
            mutate.observe(encoded(data), self.mutation, 1, False, True)

    def test_reports_wrong_failure(self):
        observed = {}
        with self.assertRaises(mutate.CheckFailure) as caught:
            mutate.observe(encoded(events("fail", "wrong cause")), self.mutation, 1, False, True, observed)
        self.assertIn("TestControl/boundary", observed["failed"])
        self.assertNotIn("validated", observed)
        self.assertIn("TestControl/boundary", str(caught.exception))
        self.assertIn('missing markers: ["guard rejected the canary"]', str(caught.exception))

    def test_stdout_failure_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "red.stdout").write_bytes(encoded(events(message="unexpected cause")))
            (root / "red.stderr").write_bytes(b"test stderr canary\n")
            (root / "green.stdout").write_bytes(b"")
            (root / "green.stderr").write_bytes(b"compiler canary\n")
            red = {"name": "red-test", "exit_code": 1, "timed_out": False,
                   "stdout": {"path": "red.stdout"}, "stderr": {"path": "red.stderr"}}
            green = {"name": "green-build", "exit_code": 1, "timed_out": False,
                     "stdout": {"path": "green.stdout"}, "stderr": {"path": "green.stderr"}}
            for phase, reason, commands in (
                ("red-observe", "missing markers: union:", [red]),
                ("green-build", "green compilation failed", [red, green]),
                ("restore-source", "input source changed", [red]),
                ("input-integrity", "original input changed", [red]),
            ):
                with self.subTest(phase=phase):
                    result = {"mutation_id": "synthetic", "verdict": "fail", "commands": commands,
                              "failure": {"phase": phase, "reason": reason},
                              "red": {"observation": {"failed": ["TestControl/boundary"]}}}
                    output = StringIO()
                    with redirect_stdout(output):
                        mutate.print_result(result, root)
                    rendered = output.getvalue()
                    for required in ("MUTATION synthetic: fail", "PHASE: " + phase, "REASON: " + reason,
                                     "RED ASSERTION: TestControl/boundary", "unexpected cause",
                                     "test stderr canary", "exit=1; timed_out=False"):
                        self.assertIn(required, rendered)
                    if phase == "green-build":
                        self.assertIn("OUTPUT: green-build", rendered)
                        self.assertIn("compiler canary", rendered)
                    self.assertNotIn('"Package"', rendered)

    def test_output_tail_keeps_last_lines(self):
        text = "".join("line-" + str(number) + "\n" for number in range(30))
        expected = ["line-" + str(number) for number in range(10, 30)]
        self.assertEqual(mutate.output_tail(text.encode()), expected)
        raw = encoded([{"Action": "output", "Test": "TestControl", "Output": text},
                       {"Action": "fail", "Test": "TestControl"}, {"Action": "fail"}])
        self.assertEqual(mutate.output_tail(raw, True), expected)
        self.assertEqual(mutate.output_tail(b"not-json\n\xff\n", True), ["not-json", "\ufffd"])

    def test_stdout_without_command(self):
        result = {"mutation_id": "synthetic", "verdict": "fail", "commands": [],
                  "failure": {"phase": "mutate-source", "reason": "anchor is ambiguous"}}
        output = StringIO()
        with redirect_stdout(output):
            mutate.print_result(result, Path("unused"))
        self.assertIn("PHASE: mutate-source", output.getvalue())
        self.assertIn("REASON: anchor is ambiguous", output.getvalue())
        self.assertIn("no build or test command completed", output.getvalue())

    def test_mutation_scope_is_owned(self):
        with self.assertRaises(mutate.CheckFailure):
            mutate.production_file("internal/v2/api/policy.go")
        with self.assertRaises(mutate.CheckFailure):
            mutate.production_file("internal/v2/policy/cache_test.go")
        with self.assertRaises(mutate.CheckFailure):
            mutate.production_file("../policy.go")
        with self.assertRaises(mutate.CheckFailure):
            mutate.relative_file(".git/config")
        self.assertEqual(str(mutate.production_file("internal/v2/policy/evaluate.go")), "internal/v2/policy/evaluate.go")


if __name__ == "__main__":
    unittest.main()
