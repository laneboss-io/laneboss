"""G0 adapter units only; synthetic RPCs never establish OS-LINUX evidence."""

import argparse
import base64
import copy
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--producer", type=Path, default=ROOT / "scripts/v2-serve/case_linux.py")
options, unit_args = parser.parse_known_args()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


CORE = module("linux_wiring_producer", options.producer)
IO = module("linux_wiring_io", ROOT / "scripts/v2-serve/item_context.py")
G0 = module("linux_wiring_g0", HERE / "g0.py")
HANDOFF = module("linux_wiring_handoff", HERE / "handoff.py")


class Fixture:
    """Local byte/process fixture, with no installed service or credentials."""
    def __init__(self, root):
        self.root, self.stage = root / "outer", ROOT
        self.root.mkdir(mode=0o700)
        self.config, self.human_prefix = "unit-linux", "baseline"
        self.current = "item.linux.prepare"
        self.rows = {name: {"observed": {}} for name in
                     ("item.linux.prepare", "item.linux.run", "item.linux.collection")}
        self.rows["baseline"] = {"observed": {"nonce": os.urandom(12).hex()}}
        self.human = SimpleNamespace(read=mock.Mock(return_value={"generation": 17}), session=mock.Mock())
        self.agent = {"vendor_stood_in": False}
        self.installed = {"binding_file": str(self.root / "binding")}
        self.calls = []
        self.current_calls = []
        self.failure = None
        self.linux_plan_file = None

    def keep(self, name, raw):
        path = self.root / name
        IO.keep(path, raw)
        return path

    def keep_json(self, name, value):
        return self.keep(name, IO.encoded(value))

    def checked_cli(self, label, words, body, **options):
        self.calls.append((label, words, copy.deepcopy(body), dict(options)))
        self.current_calls.append(self.current)
        if self.failure is not None:
            raise self.failure
        # This executes cat solely to test preservation of arbitrary stdout
        # bytes. These synthetic bytes never go to an installed case result.
        result = subprocess.run(["/bin/cat", str(self.root / "reply")],
                                capture_output=True, check=False)
        stem = "unit-" + str(len(self.calls))
        self.keep(stem + ".stdout", result.stdout)
        self.keep(stem + ".stderr", result.stderr)
        self.last = {"stdout": stem + ".stdout", "stderr": stem + ".stderr",
                     "exit_code": result.returncode}
        if result.returncode != 0:
            raise RuntimeError("unit cat subprocess failed")
        return json.loads(result.stdout)


class Wiring(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="lb-v2-case-linux-", dir="/opt")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def fixture(self):
        return Fixture(self.root)

    def context(self, case):
        test, evidence = self.root / "input", self.root / "evidence"
        test.mkdir(mode=0o700)
        evidence.mkdir(mode=0o700)
        return {"config": case.config, "test_root": str(test), "evidence_root": str(evidence),
                "profile_grant_ids": ["unit-profile"], "case_id": "linux"}

    def session(self):
        case = self.fixture()
        session = G0.Session(case, {}, IO.require, RuntimeError, CORE.Producer, IO)
        session.context = self.context(case)
        session.producer = SimpleNamespace(
            start={"lane": os.urandom(12).hex()}, root=Path(session.context["test_root"]),
            before_call=mock.Mock(), after_call=mock.Mock(), closed=True)
        return case, session

    def test_boot(self):
        self.assertTrue(callable(getattr(CORE, "boot", None)), "G0 boot hook is absent")
        case = self.fixture()
        with mock.patch.dict(os.environ, {"LANEBOSS_LINUX_PLAN": ""}):
            value = CORE.boot(case)
        self.assertEqual(set(value), {"bundle", "assets"})
        raw = (HERE / "canary.py").read_bytes()
        self.assertEqual(value["bundle"]["documents"], [])
        kept = (case.root / "linux-canary.input.py").read_bytes()
        self.assertEqual(kept, raw, "boot changed canary source bytes")
        asset = value["assets"][0]
        self.assertEqual(set(asset), {"id", "role", "file", "mode"})
        self.assertEqual(Path(asset["file"]).read_bytes(), raw)
        self.assertEqual((asset["id"], asset["role"], asset["mode"]),
                         ("linux-canary", "case-tool", 0o444))
        self.assertEqual(case.linux_boot, {
            "canary_sha256": hashlib.sha256(raw).hexdigest(),
            "canary_bytes": len(raw), "asset_ids": ["linux-canary"]})
        self.assertEqual(json.loads((case.root / "linux-boot.input.json").read_bytes()),
                         case.linux_boot)

    def test_contract(self):
        names = tuple(inspect.signature(CORE.prepare).parameters)
        self.assertEqual(names, ("case", "require", "fail", "blocked"),
                         "G0 prepare signature differs")
        self.assertTrue(callable(getattr(CORE, "abort", None)), "G0 abort hook is absent")

    def test_live_gate_preserved(self):
        case = self.fixture()
        baseline = copy.deepcopy(case.rows["baseline"])
        with self.assertRaisesRegex(RuntimeError, "real_driver_authorization"):
            CORE.prepare(case, IO.require, ValueError, RuntimeError)
        self.assertEqual(case.human_prefix, "itemlinux")
        self.assertEqual(case.rows["baseline"], baseline)
        self.assertEqual(case.calls, [])
        wait = json.loads((case.root / "linux-owner-wait.input.json").read_bytes())
        self.assertEqual(wait["code"], "prerequisite_missing")
        self.assertEqual(wait["owner"], "laneboss")
        self.assertFalse(wait["completed"])

    def test_prepared_callbacks(self):
        case = self.fixture()
        plan = {"authorization": "/unit/authority", "profile_grant_ids": ["unit-profile"]}
        path = self.root / "plan.json"
        IO.keep(path, IO.encoded(plan))
        case.linux_plan_file = path
        prepared = CORE.prepare(case, IO.require, ValueError, RuntimeError)
        self.assertEqual(prepared["binding_file"], Path(case.installed["binding_file"]))
        self.assertEqual(prepared["profile_grant_ids"], plan["profile_grant_ids"])
        self.assertEqual(prepared["inputs"], {})
        for name in ("populate", "transport", "collect"):
            self.assertTrue(callable(prepared[name]))
            self.assertIs(prepared[name].__self__, case.linux_session)
        self.assertEqual(case.calls, [])

    def test_vendor_fixture_cannot_be_live(self):
        case = self.fixture()
        plan = {"authorization": "/unit/authority", "profile_grant_ids": ["unit-profile"]}
        path = self.root / "plan.json"
        IO.keep(path, IO.encoded(plan))
        case.linux_plan_file = path
        case.agent["vendor_stood_in"] = True
        with self.assertRaisesRegex(RuntimeError, "real_driver_runtime"):
            CORE.prepare(case, IO.require, ValueError, RuntimeError)
        self.assertEqual(case.calls, [])
        case.agent["vendor_stood_in"] = False
        prepared = CORE.prepare(case, IO.require, ValueError, RuntimeError)
        self.assertTrue(callable(prepared["populate"]))
        self.assertEqual(case.calls, [])

    def test_populate_defers_publication(self):
        case = self.fixture()
        context = self.context(case)

        class Buffered(CORE.Producer):
            def prepare(self, plan, *, publish=True):
                self.publish_inputs = publish
                self.input("unit.bin", os.urandom(47))
                return self

        session = G0.Session(case, {}, IO.require, RuntimeError, Buffered, IO)
        inputs = session.populate(context)
        path = Path(context["test_root"]) / "unit.bin"
        self.assertFalse(path.exists(), "populate wrote a leaf before the shared exporter")
        self.assertIs(session.producer.context, context)
        refs = IO.retain_inputs(context, inputs)
        self.assertEqual(path.read_bytes(), inputs["unit.bin"])
        self.assertEqual(refs[0]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        with self.assertRaisesRegex(ValueError, "already attempted"):
            session.populate(context)

    def test_populate_keeps_failed_inputs(self):
        case = self.fixture()
        context = self.context(case)
        context["profile_grant_ids"] = []
        session = G0.Session(case, {}, IO.require, RuntimeError, CORE.Producer, IO)
        binary = case.root / "binary"
        IO.keep(binary, os.urandom(48))
        context.update(binary=str(binary), binary_sha256=IO.sha(binary))
        with self.assertRaisesRegex(RuntimeError, "real_driver_authorization"):
            session.populate(context)
        self.assertTrue((case.root / "linux-prep-linux-wait.json.input").exists())
        self.assertFalse((Path(context["test_root"]) / "linux-wait.json").exists())
        self.assertEqual(case.calls, [])

    def test_transport_exact_bytes(self):
        case, session = self.session()
        raw = b'{ "id": "unit-op", "status": "pending", "life_id": "unit-life", "run": 1 }\n'
        IO.keep(case.root / "reply", raw)
        session.producer.before_call.side_effect = lambda *_: setattr(
            case, "current", "human.itemlinux.control.confirm")
        with self.assertRaisesRegex(ValueError, "exact authorized input"):
            session.invoke("lane start", {"lane": "foreign"}, "unit-request", "unit-key")
        self.assertEqual(case.calls, [])
        reply = session.invoke("lane start", session.producer.start, "unit-request", "unit-key")
        self.assertEqual(base64.b64decode(reply["stdout"], validate=True), raw)
        self.assertEqual(reply["exit_code"], 0)
        self.assertEqual(case.calls[0][2], session.producer.start)
        self.assertEqual(case.calls[0][3]["request_id"], "unit-request")
        self.assertEqual(case.calls[0][3]["idempotency_key"], "unit-key")
        self.assertIn("session_proof", case.calls[0][3])
        self.assertEqual(session.target, {"life_id": "unit-life", "run": 1})
        self.assertEqual(case.human_prefix, "itemlinux")
        self.assertEqual(case.current_calls, ["item.linux.run"])

    def test_foreign_target_stops_before_cli(self):
        case, session = self.session()
        session.target = {"life_id": "unit-life", "run": 1}
        with self.assertRaisesRegex(ValueError, "another life"):
            session.invoke("lane status", {"life_id": "foreign", "run": 1}, "r", "k")
        self.assertEqual(case.calls, [])
        IO.keep(case.root / "reply", IO.encoded({"generation": 29}))
        result = session.invoke("lane status", session.target, "r", "k")
        self.assertEqual(json.loads(base64.b64decode(result["stdout"]))["generation"], 29)

    def test_native_refusal_not_retried(self):
        case, session = self.session()
        refusal = RuntimeError("unit original native refusal")
        case.failure = refusal
        with self.assertRaises(RuntimeError) as caught:
            session.invoke("lane start", session.producer.start, "r", "k")
        self.assertIs(caught.exception, refusal)
        self.assertIs(session.stopped, refusal)
        with self.assertRaisesRegex(ValueError, "first refusal"):
            session.invoke("lane start", session.producer.start, "r", "k")
        self.assertEqual(len(case.calls), 1)

    def test_operation_refusal_stops(self):
        case, session = self.session()
        error = {"owner": "unit-owner", "code": "forbidden", "message": "unit original operation refusal"}
        IO.keep(case.root / "reply", IO.encoded({"id": "unit-op", "status": "failed", "error": error}))
        with self.assertRaisesRegex(RuntimeError, "operation refused"):
            session.invoke("lane start", session.producer.start, "r", "k")
        self.assertIsNotNone(session.stopped)
        self.assertEqual(case.rows["item.linux.run"]["observed"]["refusal"], error)
        with self.assertRaisesRegex(ValueError, "first refusal"):
            session.invoke("lane start", session.producer.start, "r", "k")
        self.assertEqual(len(case.calls), 1)
        self.assertEqual(len(session.abort()), 1)
        self.assertEqual(len(case.calls), 1)

    def test_collection_failure_cached(self):
        case, session = self.session()
        with self.assertRaisesRegex(ValueError, "clean operation") as first:
            session.collect(session.context, [])
        session.proxy = SimpleNamespace(call=mock.Mock())
        with self.assertRaises(ValueError) as second:
            session.collect(session.context, [])
        self.assertIs(second.exception, first.exception)
        session.proxy.call.assert_not_called()
        self.assertEqual(case.calls, [])

    def test_collection_requires_native(self):
        case, session = self.session()
        session.clean = {"id": "unit-clean", "status": "succeeded"}
        session.operations["unit-clean"] = session.clean
        session.target = {"life_id": "unit-life", "run": 1}
        session.record = {"cell": {"observer_paths": {
            "worktree": str(self.root / "removed-worktree")}}, "uid": 65431}
        session.proxy = SimpleNamespace(call=mock.Mock(return_value={"cleaned": True}))
        case.native_cleanup_evidence = mock.Mock(side_effect=RuntimeError("unit native collection gate"))
        with self.assertRaisesRegex(RuntimeError, "unit native collection gate"):
            session.collect(session.context, ["unit-clean"])
        case.native_cleanup_evidence.assert_called_once_with(
            {"name": "itemlinux", "target": session.target}, {"cleaned": True}, session.clean)

    def test_collection_cache_scope(self):
        _, session = self.session()
        receipt = {"operation_ids": ["unit-operation"], "evidence": []}
        session.receipt = receipt
        with self.assertRaisesRegex(ValueError, "context differs"):
            session.collect(dict(session.context, config="foreign"), [])
        with self.assertRaisesRegex(ValueError, "omitted"):
            session.collect(session.context, ["unknown"])
        self.assertIs(session.collect(session.context, ["unit-operation"]), receipt)

    def test_remote_rejects_missing_exit(self):
        case = SimpleNamespace(refused=False)
        remote = HANDOFF.Remote.__new__(HANDOFF.Remote)
        remote.case = case
        with mock.patch.object(HANDOFF.wire, "exchange", return_value={"stdout": "", "stderr": ""}):
            with self.assertRaisesRegex(RuntimeError, "original gate"):
                remote.rpc(["lane", "status"], {}, "r", "k")
        self.assertTrue(case.refused)
        with mock.patch.object(HANDOFF.wire, "exchange") as exchange:
            with self.assertRaisesRegex(RuntimeError, "first refusal"):
                remote.rpc(["lane", "status"], {}, "r", "k")
            exchange.assert_not_called()
        remote = HANDOFF.Remote.__new__(HANDOFF.Remote)
        remote.case = SimpleNamespace(refused=False)
        packet = {"exit_code": 2, "stdout": base64.b64encode(os.urandom(39)).decode(),
                  "stderr": base64.b64encode(b"unit refusal bytes").decode()}
        with mock.patch.object(HANDOFF.wire, "exchange", return_value=packet):
            self.assertEqual(remote.rpc(["lane", "status"], {}, "r", "k"), packet)

    def test_abort_untouched_scope(self):
        case = self.fixture()
        session = G0.Session(case, {}, IO.require, RuntimeError, CORE.Producer, IO)
        self.assertEqual(session.abort(), [])
        self.assertEqual(case.calls, [])

    def test_abort_keeps_failed_close(self):
        _, session = self.session()
        session.producer.closed = True
        problems = session.abort()
        self.assertIn("no observed receipt", problems[0]["reason"])
        path = Path(session.context["test_root"]) / "outside-collection.json"
        path.write_bytes(IO.encoded({"errors": ["unit close failed"]}))
        self.assertIn("incomplete", session.abort()[0]["reason"])
        path.write_bytes(IO.encoded({"errors": [], "public": {"retained": False}}))
        self.assertEqual(session.abort(), [])

    def test_frozen_result_location(self):
        case = self.fixture()
        context = self.context(case)
        binary = case.keep("unit-binary", os.urandom(31))
        context.update(schema="laneboss.e2e-context.v2", phase="candidate", mutation_id="",
            binary=str(binary), binary_sha256=IO.sha(binary), source_sha256=IO.sha(options.producer),
            binding_file=str(case.root / "binding"), profile_grant_ids=[])
        context_path = Path(context["test_root"]) / "context.json"
        IO.keep(context_path, IO.encoded(context))
        consumer = module("linux_result_scope", HERE / "run.py")
        bad = self.root / "outside-result.json"
        with self.assertRaisesRegex(RuntimeError, "frozen case scopes"):
            consumer.main(["--context", str(context_path), "--result", str(bad)])
        self.assertFalse(bad.exists())
        self.assertFalse(bad.with_name(bad.name + ".pending").exists())
        valid = Path(context["test_root"]) / "result.json"
        self.assertEqual(consumer.main(["--context", str(context_path), "--result", str(valid)]), 69)
        value = json.loads(valid.read_bytes())
        self.assertFalse(value["assertions"][0]["reached"])
        self.assertFalse(value["collection"]["processes_quiescent"])


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0], *unit_args], verbosity=2)
