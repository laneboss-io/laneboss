"""G0 contract controls; no unit response is installed-service evidence."""

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import case
from fixture_io import FixtureError, FixtureInputs, private_write
import test_inputs
from test_producer import producer, SOURCE
from test_data import data_module


def need(condition, message):
    if not condition:
        raise ValueError(message)


class G0Tests(unittest.TestCase):
    def owner(self):
        return SimpleNamespace(stage=SOURCE, config="fixture", human_prefix="",
            agent={"path": Path("/test/actor")},
            current="item.dashboard.prepare", item_lives=[],
            installed={"binding_file": "/test/binding.json"},
            rows={"item.dashboard." + name: {"observed": {}} for name in ("prepare", "run", "collection")},
            human=SimpleNamespace(public={"principal_id": "principal"}, proof=Mock(return_value=Path("/test/proof.json"))))

    def test_g0_import(self):
        path = SOURCE / "scripts/v2-serve/item_dispatch.py"
        spec = importlib.util.spec_from_file_location("g0_dispatch", path)
        dispatch = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dispatch)
        module = dispatch.producer("dashboard")
        for name in ("boot", "prepare", "abort"):
            self.assertTrue(callable(getattr(module, name, None)), "G0 dashboard producer entry is missing")

    def test_boot(self):
        owner = self.owner()
        owner.keep = Mock()
        boot = producer.boot(owner)
        self.assertEqual(set(boot), {"assets", "bundle"})
        self.assertEqual(len(boot["bundle"]["sources"]), 4, "G0 role sources were omitted")
        self.assertEqual({(r["level"], r["role"]) for r in boot["bundle"]["contexts"]},
                         {(3, "reviewer"), (6, "supervisor")})
        for source in boot["bundle"]["sources"]:
            level = 3 if "/L3/" in source["path"] else 6
            relative = Path(source["path"]).relative_to(".laneboss")
            expected = (SOURCE / "templates/v2/roles" / ("L%d" % level) / relative.name).read_bytes()
            self.assertEqual(base64.b64decode(source["data"], validate=True), expected,
                             "G0 boot source bytes differ from measured templates")
        self.assertEqual(owner.keep.call_count, 7)

    def test_prepare_gate(self):
        owner = self.owner()
        with patch.object(producer, "start_handoff", return_value=None):
            with self.assertRaises(RuntimeError) as stopped:
                producer.prepare(owner, need, ValueError, RuntimeError)
        self.assertIn("HTTPS/bootstrap entry is absent", str(stopped.exception))
        self.assertEqual(owner.human_prefix, "itemdashboard", "G0 preparation used the baseline human proof catalog")
        refusal = owner.rows["item.dashboard.prepare"]["observed"]["refusal"]
        self.assertEqual(refusal["owner"], "lb-v2-service")
        self.assertEqual(refusal["code"], "prerequisite_missing")
        self.assertEqual(owner.item_lives, [], "missing native handoff allocated an action target")

    def message(self, kind="cli-proof", key="DASH-TREE"):
        return {"action": "rpc", "command": "dashboard inputs", "request_id": "nonce",
            "idempotency_key": "nonce", "denied": False,
            "request": {"schema": "laneboss.dash-handoff.v2", "config": "fixture", "nonce": "nonce",
                        "kind": kind, "key": key}}

    def test_transport(self):
        owner = self.owner()
        data = SimpleNamespace(action=Mock(return_value=Path("/test/action.json")))
        adapter = producer.G0Dashboard(owner, None, data, need, ValueError)
        prepared = adapter.prepared()
        self.assertEqual(set(prepared), {"binding_file", "profile_grant_ids", "populate", "environment", "transport", "collect"})
        reply = prepared["transport"](self.message())
        value = json.loads(base64.b64decode(reply["stdout"], validate=True))
        self.assertEqual(value["result"], {"proof_file": "/test/proof.json"})
        self.assertEqual(owner.human_prefix, "itemdashboard", "fresh CLI proof used another scope")
        owner.human.proof.assert_called_once_with("read", "human.session", {}, "principal", 0)
        reply = prepared["transport"](self.message("action", "DASH-STOP"))
        self.assertEqual(json.loads(base64.b64decode(reply["stdout"]))["result"]["request_file"], "/test/action.json")
        data.action.assert_called_once_with("DASH-STOP")
        malformed = self.message()
        malformed["request_id"] = "foreign"
        with self.assertRaises(ValueError):
            prepared["transport"](malformed)

    def test_transport_failure(self):
        owner = self.owner()
        data = SimpleNamespace(action=Mock(return_value=Path("/test/action.json")))
        adapter = producer.G0Dashboard(owner, None, data, need, ValueError)
        refusal = {"owner": "fixture-owner", "code": "forbidden", "message": "exact installed refusal"}
        message = self.message("collect", "external")
        message["request"]["failure"] = refusal
        reply = adapter.transport(message)
        self.assertEqual(json.loads(base64.b64decode(reply["stdout"]))["error"], refusal)
        adapter.transport(self.message("action", "DASH-STOP"))
        self.assertFalse(data.action.called, "G0 repeated a mutation after its refused gate")
        with self.assertRaises(ValueError):
            adapter.collect({}, [])
        self.assertEqual(owner.rows["item.dashboard.run"]["observed"]["refusal"], refusal)

    def test_observer_reply(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = test_inputs.InputTests().fixture(directory)
            request = self.message()["request"]
            returned = dict(request, result={"proof_file": "/test/current.json"})
            reply = {"exit_code": 0, "stdout": base64.b64encode(json.dumps(returned).encode()).decode(), "stderr": ""}
            with patch.object(inputs, "observer", return_value=reply) as observer:
                self.assertEqual(inputs.observer_exchange(request), returned["result"], "G0 input response was substituted")
            self.assertEqual(observer.call_args.args[0]["request"], request)
            returned["nonce"] = "foreign"
            reply["stdout"] = base64.b64encode(json.dumps(returned).encode()).decode()
            with patch.object(inputs, "observer", return_value=reply):
                with self.assertRaises(ValueError):
                    inputs.observer_exchange(request)

    def test_observer_collection(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = test_inputs.InputTests().fixture(directory)
            inputs.recorder.root = Path(directory).resolve()
            inputs.observed_operation("actual-operation")
            inputs.observed_operation("actual-operation")
            raw = (json.dumps(test_inputs.collection()) + "\n").encode()
            private_write(inputs.recorder.root / "outside-dashboard.json", raw)
            ref = {"path": "outside-dashboard.json", "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
            receipt = {"processes_quiescent": True, "temporary_resources_collected": True,
                       "operation_ids": ["actual-operation"], "evidence": [ref]}
            request = self.message("collect", "external")["request"]
            with patch.object(inputs, "observer", return_value=receipt) as observer:
                self.assertEqual(inputs.observer_exchange(request), json.loads(raw), "G0 collection report was substituted")
            observer.assert_called_once_with({"action": "collect", "operation_ids": ["actual-operation"]})
            for field, bad in (("operation_ids", []), ("evidence", []), ("processes_quiescent", False)):
                changed = dict(receipt, **{field: bad})
                with patch.object(inputs, "observer", return_value=changed):
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        inputs.observer_exchange(request)
            corrupt = copy.deepcopy(receipt)
            corrupt["evidence"][0]["sha256"] = "ff" * 32
            with patch.object(inputs, "observer", return_value=corrupt):
                with self.assertRaises(ValueError):
                    inputs.observer_exchange(request)

    def test_cached_collection(self):
        owner = self.owner()
        adapter = producer.G0Dashboard(owner, None, SimpleNamespace(collect=Mock()), need, ValueError)
        receipt = {"operation_ids": ["actual-operation"], "evidence": [{"path": "outside-dashboard.json"}]}
        adapter.receipt = receipt
        self.assertIs(adapter.collect({}, ["actual-operation"]), receipt, "G0 reran a completed collector")
        self.assertFalse(adapter.data.collect.called)
        with self.assertRaises(ValueError):
            adapter.collect({}, ["foreign-operation"])

    def test_prefix(self):
        owner = self.owner()
        owner.human_prefix = "itemdashboard"
        data = data_module.DashData(owner, {}, None, None, None)
        before = set(owner.rows)
        data.stage("action")
        self.assertEqual(owner.human_prefix, "itemdashboard", "producer replaced the G0 human prefix")
        self.assertEqual(owner.current, "item.dashboard.prepare")
        data.phase = "run"
        data.stage("action")
        self.assertEqual(owner.current, "item.dashboard.run", "G0 action overwrote the preparation row")
        self.assertTrue(all(key.startswith("human.itemdashboard.") for key in set(owner.rows) - before),
                        "producer created proof rows outside the G0 catalog")


if __name__ == "__main__":
    unittest.main()
