"""Installed-CLI handoff controls, not service or human-presence acceptance."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


CASE_PATH = Path(__file__).resolve().parents[1] / "cases" / "secrets" / "run.py"
SPEC = importlib.util.spec_from_file_location("item2_secrets", CASE_PATH)
CASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CASE)


class Item2Flow(unittest.TestCase):
    def fixture(self, root):
        inputs, evidence = root / "inputs", root / "evidence"
        inputs.mkdir(mode=0o700)
        evidence.mkdir(mode=0o700)
        context = {"test_root": str(inputs), "evidence_root": str(evidence),
                   "binary": "/installed/laneboss", "config": "flow-case",
                   "binding_file": "/installed/binding.json"}
        steps, records, infos = [], [], []
        for index, name in enumerate(CASE.STEPS[:8]):
            method = CASE.METHODS[name]
            body = {} if index < 2 else {"name": name, "version": str(index)}
            request_file = name + ".json"
            (inputs / request_file).write_text(json.dumps(body))
            step = {"name": name, "method": method, "request": request_file,
                    "idempotency_key": (str(index) + "k") * 16}
            if method in {"human.session", "secret.import"}:
                step["proof"] = name + ".proof.json"
                (inputs / step["proof"]).write_text("{}")
            steps.append(step)
            if method == "human.session":
                value = {"id": "session", "config": context["config"],
                         "expires_at": "2099-01-01T00:00:00Z",
                         "idle_expires_at": "2099-01-01T00:00:00Z"}
            elif method == "secret.import":
                value = {"name": name, "version": body["version"],
                         "source_handle": "source-" + str(index), "key_id": "key", "revoked": False}
                infos.append(value)
            else:
                value = {"id": "receipt-" + str(index)}
            request = {"protocol": "laneboss.rpc.v2", "schema": 2,
                       "config": context["config"], "method": method,
                       "params": body, "request_id": "request-" + str(index),
                       "idempotency_key": step["idempotency_key"]}
            response = {"protocol": "laneboss.rpc.v2", "schema": 2,
                        "request_id": request["request_id"], "result": value}
            records.append({"name": name, "request": request, "response": response})
        request = {"config": context["config"], "method": "secret.list", "params": {}, "request_id": "metadata"}
        records.append({"name": "metadata", "request": request, "response": {
            "protocol": "laneboss.rpc.v2", "schema": 2,
            "request_id": request["request_id"], "result": {"secrets": infos}}})
        return context, steps, records

    def test_installed_cli(self):
        with tempfile.TemporaryDirectory() as temporary:
            context, steps, records = self.fixture(Path(temporary))
            process = Mock(returncode=0)
            process.stdout = io.BytesIO(b"".join(json.dumps(row).encode() + b"\n" for row in records))
            process.stderr = io.BytesIO(b"")
            process.wait.return_value = 0
            result = {"assertions": [{"evidence": []}, {"evidence": []}]}
            with patch.object(CASE.subprocess, "Popen", return_value=process) as opened:
                try:
                    receipts, transcript = CASE.human_flow(context, {}, steps, [], result)
                except KeyError as error:
                    self.fail("installed flow still requires a foreign helper: " + str(error))
            argv = opened.call_args.args[0]
            self.assertEqual(argv[:3], [context["binary"], "human", "session"])
            self.assertIn("--flow", argv)
            self.assertEqual(len(receipts), len(steps))
            self.assertEqual([row["name"] for row in transcript], [row["name"] for row in steps])
            evidence = Path(context["evidence_root"])
            for row in transcript:
                for field in ("request", "response"):
                    ref = row[field]
                    raw = (evidence / ref["path"]).read_bytes()
                    self.assertEqual(hashlib.sha256(raw).hexdigest(), ref["sha256"])
            self.assertEqual(json.loads((evidence / "human-flow.json").read_bytes()), transcript)
        self.owner_wait()

    def owner_wait(self):
        with tempfile.TemporaryDirectory() as temporary:
            context, steps, _ = self.fixture(Path(temporary))
            process = Mock(returncode=69)
            wait = {"name": "import-env", "wait": {"code": "prerequisite_missing"},
                    "step": "human_confirmation", "completed": False}
            process.stdout = io.BytesIO(json.dumps(wait).encode() + b"\n")
            process.stderr = io.BytesIO(b"")
            process.wait.return_value = 69
            result = {"assertions": [{"evidence": []}, {"evidence": []}]}
            with patch.object(CASE.subprocess, "Popen", return_value=process):
                with self.assertRaises(CASE.CaseFailure):
                    CASE.human_flow(context, {}, steps, [], result)
            paths = list(Path(context["evidence_root"]).glob("flow-wait-*.json"))
            self.assertEqual(len(paths), 1)
            saved = json.loads(paths[0].read_bytes())
            self.assertEqual(saved["kind"], "owner_wait")
            self.assertEqual(saved["step"], "human_confirmation")
            self.assertFalse(saved["completed"])


if __name__ == "__main__":
    unittest.main()
