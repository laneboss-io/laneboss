#!/usr/bin/env python3
"""Linux-only red/green checks for the outside observer and real probe script."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
CASE = None
SOURCE = None


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(data):
    return hashlib.sha256(data).hexdigest()


class CaseChecks(unittest.TestCase):
    def rejected(self, action, message):
        try:
            action()
        except CASE.CaseFailure:
            return
        self.fail(message)

    def test_reserved_code(self):
        self.rejected(lambda: CASE.check_denial("reserved", {
            "code": "invalid_request", "message":
            "secret target is a reserved or invalid environment name"}),
            "unrelated invalid request passed the reserved denial")
        CASE.check_denial("reserved", {"code": "forbidden", "message":
                          "secret target is a reserved or invalid environment name"})

    def test_reserved_diagnostic(self):
        self.rejected(lambda: CASE.check_denial("reserved", {
            "code": "forbidden", "message": "unrelated scope refusal"}),
            "unrelated forbidden error passed the reserved denial")

    def test_reserved_capture(self):
        capture = b"\n".join(json.dumps({"name": name, "ok": True}).encode()
                             for name in ("env", "file", "undelegated"))
        self.rejected(lambda: CASE.reserved_capture({"reserved_unchanged": True}, capture),
                      "bare reserved observer flag passed without a probe verdict")
        capture += b'\n{"name":"reserved","ok":true}'
        CASE.reserved_capture({"reserved_unchanged": True}, capture)
        changed = capture.replace(b'"name":"reserved","ok":true',
                                  b'"name":"reserved","ok":false')
        self.rejected(lambda: CASE.reserved_capture({"reserved_unchanged": True}, changed),
                      "failed reserved probe passed the observer correlation")

    def test_independent_assertions(self):
        for failing in (0, 1):
            result = {"assertions": [{"reached": False, "verdict": "fail"}
                                      for _ in range(2)]}
            called = []

            def action(index):
                def run(active):
                    called.append(index)
                    active["reached"] = True
                    if index == failing:
                        raise CASE.CaseFailure("synthetic reached boundary refusal")
                    active["verdict"] = "pass"
                return run

            passed = CASE.independent_assertions(result, (action(0), action(1)))
            self.assertFalse(passed, "failed assertion was reported as a pass")
            self.assertEqual(called, [0, 1], "one assertion prevented the other from running")
            self.assertTrue(all(row["reached"] for row in result["assertions"]),
                            "independent assertion was left unreached")
            self.assertEqual(result["assertions"][failing]["verdict"], "fail")
            self.assertEqual(result["assertions"][1-failing]["verdict"], "pass")

    def test_probe_independence(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-secrets-probe-") as temporary:
            root = Path(temporary)
            value, baseline = os.urandom(48).hex(), os.urandom(48).hex()
            plan = {"env_name": "TASK_TOKEN", "env_sha256": digest(value.encode()),
                    "reserved_env_name": "TZDIR", "reserved_sha256": digest(baseline.encode()),
                    "file_path": str(root / "missing-selected-file"),
                    "file_sha256": digest(os.urandom(64)),
                    "hidden_env_names": ["HIDDEN_TOKEN"],
                    "hidden_file_paths": [str(root / "missing-hidden-file")]}
            plan_path = root / "plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            for changed in (False, True):
                process = subprocess.run([sys.executable, str(SOURCE / "probe.py"),
                                          "--plan", str(plan_path)], capture_output=True,
                                         timeout=30, check=False,
                                         env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                                              "TASK_TOKEN": value,
                                              "TZDIR": "changed" if changed else baseline})
                self.assertEqual(process.returncode, 1, "missing selected file did not fail probe")
                self.assertFalse(value.encode() in process.stdout + process.stderr or
                                 baseline.encode() in process.stdout + process.stderr,
                                 "probe printed synthetic environment values")
                rows = [json.loads(line) for line in process.stdout.splitlines()]
                self.assertTrue(len(rows) == 4 and all(set(row) == {"name", "ok"} for row in rows),
                                "probe output shape differs")
                observed = {row["name"]: row["ok"] for row in rows}
                self.assertTrue(observed["env"], "env probe failed after another probe error")
                self.assertFalse(observed["file"], "missing selected file passed")
                self.assertTrue(observed["undelegated"], "missing selected file skipped undelegated probe")
                self.assertEqual(observed["reserved"], not changed,
                                 "reserved probe ignored the selected baseline digest")

    def test_leak_reached(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-secrets-observer-") as temporary:
            root = Path(temporary)
            canary = os.urandom(48).hex().encode()
            artifact, task, operation, life, launch = [os.urandom(32).hex() for _ in range(5)]
            capture = b"actual synthetic capture"
            ref = {"id": "task-a", "sha256": task, "bytes": 1, "class": "task"}
            payload = {"task": ref, "launch_id": launch, "lane": {
                "task": ref, "launch_id": launch, "cancellation_epoch": 0,
                "counters": {"failures": 0, "retries": 0}, "session": {"history_id": "history-a"}}}
            observation = {"binary_sha256": artifact, "life_id": life, "run": 1,
                           "operation_id": operation, "injection_capture_sha256": digest(capture)}
            events = [{"schema": 2, "kind": "lane.started", "operation_id": operation,
                       "life_id": life, "run": 1, "payload": payload, "leak": canary.decode()},
                      {"schema": 2, "kind": "capture.appended", "origin": "service", "payload": {
                          "stream": "stdout", "offset": 0, "binding_id": "actual-primary-binding",
                          "primary": True, "target": {"life_id": life, "run": 1},
                          "data": {"sha256": digest(capture), "bytes": len(capture)}}}]
            (root / "events.jsonl").write_bytes(b"\n".join(json.dumps(row).encode() for row in events))
            (root / "injection.json").write_text(json.dumps(observation), encoding="utf-8")
            (root / "capture").write_bytes(capture)
            active = {"reached": False, "evidence": []}
            self.rejected(lambda: CASE.load_observation(
                {"evidence_root": str(root), "binary_sha256": artifact},
                {"observations": {"events": "events.jsonl", "injection": "injection.json",
                                  "injection_capture": "capture"}},
                "injection", [{"id": operation}], active, [canary]),
                "event leak passed the outside observer")
            self.assertTrue(active["reached"], "actual leak evidence was left unreached")
            self.assertTrue(active["evidence"], "actual leak evidence references were lost")


FAULTS = (
    ("reserved-code", "run.py", '"reserved": {"forbidden"}',
     '"reserved": {"forbidden", "invalid_request"}', "test_reserved_code",
     "unrelated invalid request passed the reserved denial"),
    ("reserved-diagnostic", "run.py", 'error.get("message") ==',
     'True or error.get("message") ==', "test_reserved_diagnostic",
     "unrelated forbidden error passed the reserved denial"),
    ("reserved-capture", "run.py", 'def reserved_capture(injection, capture):\n',
     'def reserved_capture(injection, capture):\n    if len(capture.splitlines()) == 3:\n        return\n',
     "test_reserved_capture", "bare reserved observer flag passed without a probe verdict"),
    ("reserved-probe", "probe.py", 'plan["reserved_sha256"]',
     'hashlib.sha256(value.encode("utf-8", "surrogateescape")).hexdigest()',
     "test_probe_independence", "reserved probe ignored the selected baseline digest"),
    ("assertion-abort", "run.py", 'failed = True\n            active',
     'failed = True\n            break\n            active', "test_independent_assertions",
     "one assertion prevented the other from running"),
    ("probe-abort", "probe.py", 'outcomes["file"] = False\n    try:',
     'outcomes["file"] = False\n        return outcomes\n    try:', "test_probe_independence",
     "missing selected file skipped undelegated probe"),
    ("late-reached", "run.py", '    active["reached"] = True\n    active["evidence"]',
     '    active["reached"] = False\n    active["evidence"]', "test_leak_reached",
     "actual leak evidence was left unreached"),
)


def retained_run(directory, test, output):
    command = [sys.executable, str(directory / "check_case.py"), "--source", str(directory),
               "--unit", "--test", test]
    process = subprocess.run(command, capture_output=True, timeout=90, check=False,
                             env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    for suffix, data in (("out", process.stdout), ("err", process.stderr)):
        output.with_suffix("." + suffix).write_bytes(data)
    output.with_suffix(".json").write_text(json.dumps({"argv": command, "exit": process.returncode,
        "stdout_sha256": digest(process.stdout), "stderr_sha256": digest(process.stderr)}), encoding="utf-8")
    return process.returncode, process.stdout + process.stderr


def main():
    global CASE, SOURCE
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--unit", action="store_true")
    parser.add_argument("--test", default="all")
    args = parser.parse_args()
    if sys.platform != "linux":
        print("secrets case checks require disposable Linux", file=sys.stderr)
        return 69
    SOURCE = args.source.resolve()
    if not (SOURCE / "run.py").is_file():
        SOURCE = SOURCE / "e2e/v2/cases/secrets"
    if args.unit:
        CASE = load("secrets_case_checks", SOURCE / "run.py")
        suite = (unittest.defaultTestLoader.loadTestsFromTestCase(CaseChecks) if args.test == "all"
                 else unittest.defaultTestLoader.loadTestsFromName(args.test, CaseChecks))
        if args.test == "all":
            installed = load("installed_case_checks", SOURCE / "checks_install.py")
            suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(installed.InstalledChecks))
        result = unittest.TextTestRunner(verbosity=2, stream=sys.stdout).run(suite)
        return 0 if result.wasSuccessful() and not result.skipped else 1
    if args.output is None:
        parser.error("output is required")
    root = args.output.resolve()
    if root.exists() or root.is_relative_to(SOURCE) or SOURCE.is_relative_to(root):
        print("case check output must be new and separate from source", file=sys.stderr)
        return 1
    root.mkdir(mode=0o700, parents=True)
    report = {"status": "failed", "controls": []}
    try:
        for name, file, before, after, test, diagnostic in FAULTS:
            entry = {"id": name, "killed": False}
            report["controls"].append(entry)
            for phase in ("red", "green"):
                directory = root / name / phase
                directory.mkdir(mode=0o700, parents=True)
                inputs = []
                for selected in ("run.py", "probe.py", "check_case.py"):
                    data = (SOURCE / selected).read_bytes()
                    (directory / selected).write_bytes(data)
                    inputs.append({"path": selected, "sha256": digest(data), "bytes": len(data)})
                entry[phase + "_inputs"] = inputs
                if phase == "red":
                    target = directory / file
                    original = target.read_text(encoding="utf-8")
                    if original.count(before) != 1:
                        raise ValueError("case fault anchor changed")
                    target.write_text(original.replace(before, after, 1), encoding="utf-8")
                code, output = retained_run(directory, test, root / (name + "-" + phase))
                if (test.encode() not in output or b"... skipped" in output or
                        b"(skipped=" in output):
                    raise ValueError("case control did not reach its named check")
                if phase == "red" and not (code == 1 and diagnostic.encode() in output):
                    raise ValueError("case control missed its intended red diagnostic")
                if phase == "green" and not (code == 0 and b"OK" in output):
                    raise ValueError("case candidate did not pass green")
            entry["killed"] = True
        code, output = retained_run(SOURCE, "all", root / "candidate-all")
        if code != 0 or b"OK" not in output:
            raise ValueError("complete case check suite failed")
        report["status"] = "red_then_green"
        return 0
    except (OSError, ValueError, subprocess.SubprocessError):
        print("secrets case controls failed; retain evidence", file=sys.stderr)
        return 1
    finally:
        (root / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
