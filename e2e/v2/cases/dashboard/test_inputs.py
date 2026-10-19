"""Private fresh-input and independent collection controls, Linux only."""

import copy
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from case import request_digest
from fixture_io import FixtureError, FixtureInputs, external_collected, private_read, private_write


class Recorder:
    def __init__(self):
        self.values = {}

    def save(self, name, value):
        self.values[name] = value
        return {"path": name}


def collection():
    target = {"life_id": "life", "run": 2}
    check = {"handle": {"target": target, "containment_id": "containment"},
             "state": "exited", "survivors": 0, "exit_code": 0, "observed_at": "2026-01-01T00:00:00Z"}
    previous = copy.deepcopy(check)
    previous["handle"]["target"]["run"] = 1
    row = {"target": target, "check": check, "status": {"life_id": "life", "run": 2,
           "cleaned": True, "state": "abandoned", "last_seq": 20},
           "archive": {"id": "archive", "life_id": "life", "archive_sha256": "31" * 32,
                       "read_back_sha256": "31" * 32},
           "clean_operation": {"id": "clean", "life_id": "life", "run": 2, "status": "succeeded", "last_seq": 20},
           "native": {"action": "remove_clean", "helper_journal_complete": True, "worktree_measured": True,
                      "branch_measured": True, "journal_sha256": "32" * 32, "enrollment_sha256": "33" * 32},
           "observations": [previous, check]}
    return {"schema": "laneboss.dash-collection.v2", "targets": [row],
            "https": {"cookie_after_close_status": 401, "listener_errno": 111,
                      "listener_pid": 100, "listener_exit": 0, "session_pid": 101, "session_exit": 0},
            "presence": "simulated", "human_approval": "not_proven"}


class InputTests(unittest.TestCase):
    def fixture(self, root):
        root = Path(root).resolve()
        for name in ("requests", "responses"):
            (root / name).mkdir(mode=0o700)
        controls = root / "controls.json"
        private_write(controls, {"schema": "laneboss.dash-inputs.v2", "config": "fixture", "handoff": str(root),
            "targets": [{"life_id": "life-" + str(i), "run": 1} for i in range(5)]})
        return FixtureInputs(controls, "fixture", Recorder(), timeout=1)

    def test_private_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "input.json"
            raw = b'{ "unmodified": [1, 2] }\n'
            private_write(path, raw)
            self.assertEqual(private_read(path), raw, "private input bytes were reserialized")
            for mode in (0o644, 0o666, 0o400):
                path.chmod(mode)
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    private_read(path)
            path.chmod(0o600)
            linked = path.with_name("linked.json")
            linked.symlink_to(path)
            with self.assertRaises(ValueError):
                private_read(linked)
            hard = path.with_name("hard.json")
            os.link(path, hard)
            with self.assertRaises(ValueError):
                private_read(path)

    def test_immutable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "input.json"
            private_write(path, b"first")
            with self.assertRaises(ValueError):
                private_write(path, b"replacement")
            self.assertEqual(private_read(path), b"first")

    def test_cli_handoff(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = self.fixture(directory)
            proof = {"id": "issued-proof", "expires_at": "2030-01-01T00:00:00Z",
                     "request_sha256": request_digest("fixture", "human.session", {})}
            proof_file = Path(directory).resolve() / "proof.json"
            private_write(proof_file, proof)
            with patch.object(inputs, "exchange", return_value={"proof_file": str(proof_file)}) as exchange:
                self.assertEqual(inputs.cli("DASH-TREE"), str(proof_file))
            exchange.assert_called_once_with("cli-proof", "DASH-TREE")
            proof["request_sha256"] = request_digest("other", "human.session", {})
            bad_file = proof_file.with_name("foreign.json")
            private_write(bad_file, proof)
            with patch.object(inputs, "exchange", return_value={"proof_file": str(bad_file)}):
                with self.assertRaises(ValueError):
                    inputs.cli("DASH-RAW")

    def test_action_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = self.fixture(directory)
            path = Path(directory).resolve() / "action.json"
            raw = b'{ "request_id":"actual", "params": {"run": 1} }\n'
            private_write(path, raw)
            with patch.object(inputs, "exchange", return_value={"request_file": str(path)}) as exchange:
                self.assertEqual(inputs.get("DASH-STOP")["request_id"], "actual")
                self.assertEqual(inputs.wire("DASH-STOP"), raw, "exact action wire bytes changed")
            self.assertEqual(exchange.call_count, 1, "one action consumed multiple fresh proofs")

    def test_exchange(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = self.fixture(directory)
            errors = []
            def producer():
                try:
                    deadline = time.monotonic() + 2
                    while not list(inputs.requests.glob("*.json")):
                        if time.monotonic() > deadline:
                            raise RuntimeError("test handoff request absent")
                        time.sleep(0.005)
                    path = next(inputs.requests.glob("*.json"))
                    request = json.loads(private_read(path))
                    private_write(inputs.responses / path.name, dict(request, result={"observed": request["key"]}))
                except Exception as error:
                    errors.append(error)
            worker = threading.Thread(target=producer)
            worker.start()
            result = inputs.exchange("cli-proof", "DASH-TREE")
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(result, {"observed": "DASH-TREE"}, "handoff returned a different actual response")

    def test_exact_error(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = self.fixture(directory)
            refusal = {"code": "not_implemented", "owner": "fixture-owner", "message": "exact installed refusal"}
            def answer(path, request):
                # The independent producer supplies an actual response file.
                private_write(inputs.responses / path.name, dict(request, error=refusal))
                return b""
            original = private_write
            def write(path, request):
                raw = original(path, request)
                answer(path, request)
                return raw
            with patch("fixture_io.private_write", side_effect=write):
                with self.assertRaises(FixtureError) as failure:
                    inputs.exchange("action", "DASH-STOP")
            self.assertEqual(failure.exception.error, refusal, "owner refusal was reworded")

    def test_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = self.fixture(directory)
            inputs.timeout = 0
            with self.assertRaises(FixtureError) as failure:
                inputs.exchange("action", "DASH-STOP")
            self.assertEqual(failure.exception.error["code"], "deadline_exceeded")

    def test_failed_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = self.fixture(directory)
            refusal = {"owner": "fixture-owner", "code": "forbidden", "message": "stopped"}
            with patch.object(inputs, "exchange", return_value={}) as exchange:
                inputs.collect(refusal)
            exchange.assert_called_once_with("collect", "external", refusal)

    def test_collection(self):
        self.assertTrue(external_collected(collection(), {("life", 1), ("life", 2)}), "measured complete collection was rejected")
        self.assertFalse(external_collected(collection(), {("foreign", 1)}), "uncollected target passed")
        self.assertFalse(external_collected(collection(), set()), "no measured target passed")
        for value in (None, {}, [], "report", {"schema": "laneboss.dash-collection.v2", "targets": [None]}):
            self.assertFalse(external_collected(value, {("life", 2)}), "malformed collection passed")

    def test_collection_targets(self):
        for section, field, bad in (
                ("check", "state", "running"), ("check", "survivors", 1), ("check", "survivors", False),
                ("check", "observed_at", ""), ("check", "handle", {}), ("check", "exit_code", None),
                ("status", "cleaned", False), ("status", "life_id", "foreign"), ("status", "run", 3),
                ("status", "state", "verifying"), ("status", "last_seq", 19),
                ("archive", "id", ""), ("archive", "life_id", "foreign"), ("archive", "read_back_sha256", "different"),
                ("clean_operation", "status", "pending"), ("clean_operation", "life_id", "foreign"),
                ("clean_operation", "run", 3), ("clean_operation", "last_seq", 0),
                ("clean_operation", "error", {"code": "forbidden"}),
                ("native", "action", "retain_dirty"), ("native", "helper_journal_complete", False),
                ("native", "worktree_measured", False), ("native", "branch_measured", False),
                ("native", "journal_sha256", ""), ("native", "enrollment_sha256", "")):
            report = copy.deepcopy(collection())
            report["targets"][0][section][field] = bad
            with self.subTest(section=section, field=field):
                self.assertFalse(external_collected(report, {("life", 2)}), "unmeasured external collection passed")

    def test_collection_history(self):
        for field, bad in (("state", "running"), ("survivors", 1), ("observed_at", ""), ("handle", {})):
            report = copy.deepcopy(collection())
            report["targets"][0]["observations"][0][field] = bad
            self.assertFalse(external_collected(report, {("life", 1), ("life", 2)}), "resume history was not collected")
        report = collection()
        report["targets"][0]["observations"] = [report["targets"][0]["check"]]
        self.assertFalse(external_collected(report, {("life", 1), ("life", 2)}), "old resume run was omitted")

    def test_collection_https(self):
        for field, bad in (("cookie_after_close_status", 200), ("listener_errno", 110),
                           ("listener_pid", 0), ("listener_exit", None), ("session_pid", 100), ("session_exit", None)):
            report = copy.deepcopy(collection())
            report["https"][field] = bad
            self.assertFalse(external_collected(report, {("life", 2)}), "uncollected HTTPS/session passed")
        for field, bad in (("presence", "hardware"), ("human_approval", "proven")):
            report = collection()
            report[field] = bad
            self.assertFalse(external_collected(report, {("life", 2)}), "false human provenance passed")


if __name__ == "__main__":
    unittest.main()
