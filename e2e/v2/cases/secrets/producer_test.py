"""Linux component controls. These never issue service proofs or vendor turns."""

import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[4]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


PRODUCER = module("secret_producer", ROOT / "scripts/v2-serve/case_secrets.py")
OBSERVER = module("secret_observer", ROOT / "scripts/v2-serve/secret_observer.py")
CONSUMER = module("secret_consumer", Path(__file__).with_name("run.py"))


class ProducerChecks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lb-v2-case-secrets-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.test, self.evidence = self.root / "test", self.root / "evidence"
        self.test.mkdir(mode=0o700)
        self.evidence.mkdir(mode=0o700)
        self.context = {"schema": "laneboss.e2e-context.v2", "case_id": "secrets", "phase": "candidate",
                        "mutation_id": "", "test_root": str(self.test), "evidence_root": str(self.evidence),
                        "binary": str(self.root / "absent-client"), "binary_sha256": os.urandom(32).hex(),
                        "source_sha256": os.urandom(32).hex(), "config": "secret-component",
                        "binding_file": str(self.test / "binding.json"), "profile_grant_ids": []}
        self.targets = {"env_name": "TASK_TOKEN", "file_path": "/task/task.key",
                        "hidden_env_name": "HIDDEN_TOKEN", "reserved_env_name": "TZDIR"}

    def fixture(self):
        return PRODUCER.prepare(self.context, os.urandom(64), self.targets)

    def test_private_sources(self):
        fixture = self.fixture()
        self.assertEqual(tuple(step["name"] for step in fixture["steps"]), CONSUMER.STEPS)
        for step in fixture["steps"]:
            self.assertFalse((self.test / step["request"]).exists(), "prewritten request bypassed coordination")
            self.assertEqual(step["method"], CONSUMER.METHODS.get(step["name"], "lane.start"))
        keys = [step["idempotency_key"] for step in fixture["steps"] if step["name"] != "key"]
        self.assertEqual(len(set(keys)), 20, "retry keys were reused for different intents")
        sources = [PRODUCER.read(self.test / name) for name in fixture["canary_files"].values()]
        self.assertEqual(len(set(sources)), 3, "private random sources were reused")
        self.assertTrue(all(len(source) >= 32 for source in sources))
        plan = json.loads(PRODUCER.read(self.test / "secret-inputs/probe-plan.json"))
        self.assertEqual(plan["env_sha256"], PRODUCER.sha(sources[0]))
        self.assertEqual(plan["file_sha256"], PRODUCER.sha(sources[1]))
        self.assertTrue(all(source not in json.dumps(fixture).encode() for source in sources), "fixture exposed secret bytes")

    def test_private_input_refusal(self):
        path = self.test / "input"
        raw = os.urandom(64)
        PRODUCER.put(path, raw)
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "private bounded input"):
            PRODUCER.read(path)
        path.chmod(0o600)
        self.assertEqual(PRODUCER.read(path), raw)
        alias = self.test / "alias"
        os.link(path, alias)
        with self.assertRaisesRegex(ValueError, "private bounded input"):
            PRODUCER.read(path)
        alias.unlink()
        self.assertEqual(PRODUCER.read(path), raw)

    def test_no_early_release(self):
        fixture = self.fixture()
        coordinator = PRODUCER.Coordinator(self.context, fixture, None, None, "/unused/sealer", "human-unit")
        with self.assertRaises(PRODUCER.MissingSetup):
            coordinator.next_flow()
        self.assertFalse((self.test / fixture["steps"][0]["request"]).exists(), "missing proof completed a human step")
        coordinator.done.add("human-session")
        coordinator.next_flow()
        self.assertFalse((self.test / fixture["steps"][1]["request"]).exists(), "key was released without its session reply")

    def test_native_independence(self):
        fixture = self.fixture()
        coordinator = PRODUCER.Coordinator(self.context, fixture, None, None, "/unused/sealer")
        PRODUCER.document(self.evidence / "next-step.json", {"index": 17, "name": "lease-first", "method": "lane.start"})
        with self.assertRaises(PRODUCER.MissingSetup) as stopped:
            coordinator.later()
        self.assertEqual(stopped.exception.step, "native_lease-first")
        self.assertFalse(stopped.exception.record()["completed"])
        self.assertFalse(coordinator.requests, "credential prerequisite was replaced with a fixture result")

    def test_flow_hash_refusal(self):
        fixture = self.fixture()
        coordinator = PRODUCER.Coordinator(self.context, fixture, None, None, "/unused/sealer")
        coordinator.done.add("human-session")
        coordinator.requests["human-session"] = {}
        # Declared component envelopes, with no installed or human-authority
        # credit. Only the retained hash is wrong; all correlation fields fit.
        identifier = os.urandom(16).hex()
        PRODUCER.document(self.test / fixture["steps"][0]["request"], {})
        PRODUCER.document(self.evidence / "request.json", {"config": self.context["config"],
            "method": "human.session", "params": {}, "request_id": identifier})
        PRODUCER.document(self.evidence / "response.json", {"protocol": "laneboss.rpc.v2", "schema": 2,
            "request_id": identifier, "result": {"id": os.urandom(16).hex()}})
        ref = {"path": "request.json", "sha256": PRODUCER.sha(b"changed"),
               "bytes": len(PRODUCER.read(self.evidence / "request.json"))}
        response_ref = {"path": "response.json", "sha256": PRODUCER.sha(PRODUCER.read(self.evidence / "response.json")),
                        "bytes": len(PRODUCER.read(self.evidence / "response.json"))}
        PRODUCER.document(self.evidence / "human-flow.json", [{"name": "human-session", "request": ref,
            "response": response_ref, "input_sha256": PRODUCER.sha(PRODUCER.read(self.test / fixture["steps"][0]["request"]))}])
        with self.assertRaisesRegex(ValueError, "flow handoff hash differs"):
            coordinator.observe_flow()
        self.assertFalse(coordinator.responses, "changed handoff became an actual response")

    def test_live_auth_wait(self):
        path, result = self.test / "context.json", self.evidence / "result.json"
        PRODUCER.document(path, self.context)
        before = PRODUCER.read(path)
        code = PRODUCER.run_installed(path, result, sealer="/unused/sealer")
        self.assertNotEqual(code, 0, "empty profile list passed the live credential case")
        value = json.loads(PRODUCER.read(result))
        self.assertEqual([row["id"] for row in value["assertions"]], list(CONSUMER.ASSERTIONS))
        self.assertTrue(all(not row["reached"] and row["verdict"] == "fail" for row in value["assertions"]))
        self.assertFalse(value["collection"]["processes_quiescent"])
        wait = json.loads(PRODUCER.read(self.evidence / "vendor-authentication.wait.json"))
        self.assertEqual(wait["step"], "vendor_authentication")
        self.assertFalse(wait["completed"])
        self.assertEqual(PRODUCER.read(path), before, "live context was rewritten")

    def test_sealer_pin(self):
        fixture = self.fixture()
        selected = Path("/usr/bin/false").resolve(strict=True)
        binary = selected.read_bytes()
        coordinator = PRODUCER.Coordinator(self.context, fixture, None, None, selected,
                                          sealer_sha256=PRODUCER.sha(binary + b"changed"))
        with self.assertRaises(ValueError) as stopped:
            coordinator.seal({}, "env")
        self.assertFalse((self.evidence / "seal-env.exit.json").exists(), "an unpinned helper was executed")
        self.assertIn("executable digest differs", str(stopped.exception))
        coordinator.sealer_sha256 = PRODUCER.sha(binary)
        with self.assertRaisesRegex(ValueError, "sealed upload producer refused"):
            coordinator.seal({}, "env")
        self.assertEqual(json.loads(PRODUCER.read(self.evidence / "seal-env.exit.json"))["exit"], 1)
        self.assertEqual(PRODUCER.read(self.evidence / "secret-seal.bin", 16777216), binary)

    def test_standalone_waits(self):
        selected = Path("/usr/bin/false").resolve(strict=True)
        self.context["binary"] = str(selected)
        self.context["binary_sha256"] = PRODUCER.sha(selected.read_bytes())
        baseline = self.test / "baseline.private"
        PRODUCER.put(baseline, os.urandom(64))
        inputs = {"schema": "laneboss.secret-inputs.v1", "config": self.context["config"],
                  "binary_sha256": self.context["binary_sha256"], "reserved_baseline": str(baseline),
                  "targets": self.targets, "sealer": {"path": "/unused/sealer"}}
        context_path, input_path, result = self.test / "context.json", self.test / "inputs.json", self.evidence / "result.json"
        PRODUCER.document(context_path, self.context)
        PRODUCER.document(input_path, inputs)
        completed = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "scripts/v2-serve/case_secrets.py"),
            "--context", str(context_path), "--inputs", str(input_path), "--result", str(result)],
            capture_output=True, timeout=30, check=False)
        self.assertNotEqual(completed.returncode, 0, "standalone preparation passed a missing live profile")
        frozen = json.loads(PRODUCER.read(result))
        self.assertTrue(all(not row["reached"] and row["verdict"] == "fail" for row in frozen["assertions"]))
        self.assertFalse((self.evidence / "secret-authority").exists(), "standalone wait started a human ceremony")

    def test_native_result(self):
        self.context["profile_grant_ids"] = ["explicit-component-selector"]
        result = self.evidence / "result.json"
        self.assertEqual(PRODUCER.incomplete(self.context, result, "native_setup"), 69)
        value = json.loads(PRODUCER.read(result))
        self.assertEqual([row["id"] for row in value["assertions"]], list(CONSUMER.ASSERTIONS))
        self.assertTrue(all(row["observed_exit"] == 69 and not row["reached"] and row["verdict"] == "fail"
                            for row in value["assertions"]))
        self.assertFalse(value["collection"]["temporary_resources_collected"])

    def test_archive_scan(self):
        canary = os.urandom(64)
        hidden = OBSERVER.variants({"test": canary})

        def archive(data):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as stream:
                info = tarfile.TarInfo("actual-data")
                info.size = len(data)
                stream.addfile(info, io.BytesIO(data))
            return buffer.getvalue()

        for encoded in hidden:
            with self.assertRaisesRegex(ValueError, "archive member discloses"):
                OBSERVER.archive_values(archive(encoded), hidden)
        self.assertEqual(OBSERVER.archive_values(archive(os.urandom(72)), hidden), 1)

    def test_primary_chunks(self):
        target, operation = {"life_id": "component-life", "run": 3}, {"id": "actual-operation"}
        content = {"one": os.urandom(64), "two": os.urandom(75)}

        def read(method, request):
            self.assertEqual(method, "blob.read")
            value = content[request["object_id"]]
            part = value[request["offset"]:request["offset"] + request["limit"]]
            return dict(request, data=base64.b64encode(part).decode(), sha256=OBSERVER.sha(part))

        events = [{"kind": "lane.started", **target, "operation_id": operation["id"], "payload": {}}]
        offset = 0
        for name, data in content.items():
            events.append({"kind": "capture.appended", "origin": "service", "payload": {
                "target": target, "primary": True, "stream": "stdout", "binding_id": "primary-binding",
                "offset": offset, "data": {"id": name, "bytes": len(data), "sha256": OBSERVER.sha(data)}}})
            offset += len(data)
        events[-1]["payload"]["offset"] += 1
        with self.assertRaisesRegex(ValueError, "overlapping or incomplete"):
            OBSERVER.primary(read, events, target, operation)
        events[-1]["payload"]["offset"] -= 1
        capture, _ = OBSERVER.primary(read, events, target, operation)
        self.assertEqual(capture, b"".join(content.values()))
        path = self.evidence / "actual.capture"
        PRODUCER.put(path, capture)
        observation = dict(target, injection_capture_sha256=PRODUCER.sha(capture))
        self.assertEqual(CONSUMER.observed_capture(events, path, observation, "injection"), capture)
        events[-1]["payload"]["offset"] += 1
        with self.assertRaisesRegex(CONSUMER.CaseFailure, "overlapping or incomplete"):
            CONSUMER.observed_capture(events, path, observation, "injection")
        events[-1]["payload"]["offset"] -= 1
        with self.assertRaisesRegex(ValueError, "exact actual launch"):
            OBSERVER.primary(read, events, target, {"id": "other-operation"})

    def test_process_generation(self):
        child = subprocess.Popen(["sh", "-c", "read item"], stdin=subprocess.PIPE)
        try:
            old = OBSERVER.process(child.pid)
            self.assertEqual(old["pid"], child.pid)
            self.assertTrue(old["start_time"].isdigit())
            child.communicate(b"done\n", timeout=10)
            self.assertEqual(child.returncode, 0)
            now = OBSERVER.process(child.pid)
            self.assertTrue(now is None or now["start_time"] != old["start_time"], "exited process generation survived")
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=10)
            if child.stdin is not None:
                child.stdin.close()

    def test_fake_containment_refused(self):
        with self.assertRaisesRegex(ValueError, "actual cgroup-v2"):
            OBSERVER.Containment(self.test, {"life_id": "unit", "run": 1}, os.getuid(), self.test, ["absent"])


if __name__ == "__main__":
    if sys.platform != "linux":
        raise SystemExit("producer checks require disposable Linux")
    unittest.main(verbosity=2)
