"""Negative audit controls; they do not impersonate an installed service."""

import importlib.util
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("agent_evidence", Path(__file__).with_name("agent_evidence.py"))
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class EvidenceRefusals(unittest.TestCase):
    def sample(self):
        expected = {"config": "fixture-case", "challenge": "case-challenge",
                    "life": "real-life", "run": 1, "uid": 12345, "launch_id": "real-launch",
                    "client": "/run/laneboss/client", "binding": "/run/laneboss/binding.json",
                    "version": "1.0.0", "output": "/home/lane/serve-state"}
        log = dict(expected, schema="laneboss.serve-observed.v1", program="laneboss-serve-fixture",
                   calls=[], passed=True)
        return expected, log

    def test_summary_cannot_replace_cli(self):
        expected, log = self.sample()
        with tempfile.TemporaryDirectory(prefix="lb-v2-serve-audit-") as directory:
            root = Path(directory)
            (root / "transcript.json").write_text(json.dumps(log))
            with self.assertRaisesRegex(evidence.InvalidEvidence, "command sequence"):
                evidence.audit(root, expected)

    def test_unrun_command_is_rejected(self):
        expected, log = self.sample()
        names = ("identity", "blob-begin", "blob-chunk", "blob-commit", "append",
                 "get", "read", "retry", "changed", "unready")
        log["calls"] = [{"name": name, "started": False, "timed_out": False,
                         "exit_code": 0} for name in names]
        with tempfile.TemporaryDirectory(prefix="lb-v2-serve-audit-") as directory:
            root = Path(directory)
            (root / "transcript.json").write_text(json.dumps(log))
            with self.assertRaisesRegex(evidence.InvalidEvidence, "did not execute"):
                evidence.audit(root, expected)

    def test_path_escape_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-serve-audit-") as directory:
            with self.assertRaisesRegex(evidence.InvalidEvidence, "nonlocal"):
                evidence.read(Path(directory), "../other-lane")

    def test_complete_output_contract(self):
        # This is an audit-format fixture, not authenticated service evidence.
        expected, log = self.sample()
        content = ("SERVE-STATE " + expected["challenge"] + "\n").encode()
        digest = hashlib.sha256(content).hexdigest()
        ref = {"id": "uploaded", "class": "record", "bytes": len(content), "sha256": digest}
        actor = {"kind": "lane", "id": "caller", "life_id": expected["life"]}
        record = {"id": "record", "collection": "observations", "content": ref,
                  "actor": actor, "life_id": expected["life"], "run": expected["run"]}
        append = {"collection": "observations", "content": ref, "related_ids": []}
        cases = [
            ("identity", ["identity", "self"], {},
             {"config": expected["config"], "actor": actor, "launch_id": expected["launch_id"]}),
            ("blob-begin", ["blob", "begin"], {"class": "record", "bytes": len(content), "sha256": digest}, {"object_id": ref["id"]}),
            ("blob-chunk", ["blob", "chunk"], {"object_id": ref["id"], "offset": 0, "data": base64.b64encode(content).decode(), "sha256": digest}, {}),
            ("blob-commit", ["blob", "commit"], {"object_id": ref["id"], "sha256": digest}, ref),
            ("append", ["records", "append"], append, record),
            ("get", ["records", "get"], {"record_id": record["id"]}, record),
            ("read", ["blob", "read"], {"object_id": ref["id"], "offset": 0, "limit": len(content)},
             {"object_id": ref["id"], "offset": 0, "data": base64.b64encode(content).decode(), "sha256": digest}),
            ("retry", ["records", "append"], append, record),
            ("changed", ["records", "append"], dict(append, collection="reports"), {"code": "idempotency_conflict"}),
            ("unready", ["judge", "list"], {}, {"generation": 1, "projection": {"id": "configuration", "class": "manifest"}}),
        ]
        with tempfile.TemporaryDirectory(prefix="lb-v2-serve-audit-") as directory:
            root = Path(directory)
            (root / "content.input").write_bytes(content)
            for name, method, request, result in cases:
                request_name = ("append" if name == "retry" else "identity" if name == "unready" else name) + ".request.json"
                key = expected["challenge"] + "-" + ("append" if name in ("retry", "changed") else name)
                argv = [expected["client"], *method, "--config", expected["config"], "--binding", expected["binding"],
                        "--request", expected["output"] + "/" + request_name, "--request-id", key]
                if name in ("blob-begin", "blob-chunk", "blob-commit", "append", "retry", "changed"):
                    argv += ["--idempotency-key", key]
                log["calls"].append({"name": name, "argv": argv, "request": request_name,
                                     "stdout": name + ".stdout", "stderr": name + ".stderr",
                                     "started": True, "timed_out": False, "exit_code": 2 if name == "changed" else 0})
                (root / request_name).write_text(json.dumps(request))
                (root / (name + ".stdout")).write_bytes(b"" if name == "changed" else json.dumps(result).encode())
                (root / (name + ".stderr")).write_bytes(json.dumps(result).encode() if name == "changed" else b"")
            transcript = root / "transcript.json"
            transcript.write_text(json.dumps(log))
            self.assertEqual(evidence.audit(root, expected)["content_sha256"], digest)
            original = log["calls"][0]["argv"][:]
            index = log["calls"][0]["argv"].index("--request") + 1
            log["calls"][0]["argv"][index] = "serve-state/identity.request.json"
            transcript.write_text(json.dumps(log))
            with self.assertRaisesRegex(evidence.InvalidEvidence, "another client"):
                evidence.audit(root, expected)
            log["calls"][0]["argv"] = original
            transcript.write_text(json.dumps(log))
            self.assertEqual(evidence.audit(root, expected)["calls"], len(cases))


if __name__ == "__main__":
    unittest.main()
