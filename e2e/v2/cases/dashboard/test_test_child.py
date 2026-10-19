"""Native ports are component doubles; only installed runs establish authority."""

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fixture_io import FixtureError
from test_producer import SOURCE


def load(name):
    spec = importlib.util.spec_from_file_location("child_" + name, SOURCE / "scripts/v2-serve" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


child = load("item_test_child")


class TestChildTests(unittest.TestCase):
    def setUp(self):
        self.objects = {}
        self.target = {"life_id": "component-child", "run": 2}
        self.subject = {"target": self.target, "end_seq": 70,
                        "snapshot": {"sha256": hashlib.sha256(b"frozen tree").hexdigest()}}
        self.budget = {"wall_ms": 1000, "processes": 4, "spend_micros": 0}
        candidate = self.object("candidate", "manifest", b'{"entries":[]}')
        self.plan = {"schema": "laneboss.worker-plan.v2", "kind": "test", "input": candidate,
                     "grant_set_id": "component-grants", "budget": self.budget}
        self.request = {"child": self.target, "candidate": candidate,
                        "test_plan": self.document("plan", "manifest", self.plan), "budget": self.budget}
        self.operation = {"id": "component-operation", "life_id": self.target["life_id"], "run": 2,
                          "status": "succeeded", "first_seq": 100, "last_seq": 109}
        self.binding = {"id": "component-capture", "config": "fixture", "target": self.target,
            "status": "registered", "operation_id": self.operation["id"], "worker_lease_id": "component-worker",
            "launch_id": "component-launch", "helper_lease_id": "component-helper",
            "streams": [{"id": "component-stdout", "stream": "stdout"}, {"id": "component-stderr", "stream": "stderr"}]}
        self.check = {"schema": "laneboss.check.v2", "name": "workspace", "target": self.target,
            "end_seq": self.subject["end_seq"], "snapshot_sha256": self.subject["snapshot"]["sha256"],
            "exit_code": 0, "worker_lease_id": self.binding["worker_lease_id"], "operation_id": self.operation["id"]}
        self.check_ref = self.document("check", "check", self.check)
        output = self.object("output", "worker_result", b'{"checked":"component candidate"}')
        captured = self.object("capture", "capture", b'component check output\n')
        self.release = {"operation_id": self.operation["id"], "lease_id": self.binding["helper_lease_id"],
            "quiescence": {"handle": {"id": self.binding["launch_id"], "target": self.target},
                           "state": "exited", "exit_code": 0, "survivors": 0}}
        payloads = [("capture.bound", self.binding), ("capture.appended", {
            "binding_id": self.binding["id"], "target": self.target, "stream": "stdout", "offset": 0,
            "primary": True, "coverage": "partial", "data": captured}),
            ("capture.closed", {"binding_id": self.binding["id"], "stream_id": "component-stdout",
                "offset": captured["bytes"], "next_offset": captured["bytes"], "eof": True}),
            ("capture.closed", {"binding_id": self.binding["id"], "stream_id": "component-stderr",
                "offset": 0, "next_offset": 0, "eof": True}), ("blob.committed", self.check_ref),
            ("worker.completed", {"worker_id": "component-worker", "kind": "test", "input": self.request["test_plan"],
                "output": output, "status": "succeeded"}), ("helper.released", self.release)]
        self.events = [{"seq": 100 + index, "config": "fixture", "life_id": self.target["life_id"], "run": 2,
            "operation_id": self.operation["id"], "origin": "service", "kind": kind, "payload": value}
            for index, (kind, value) in enumerate(payloads)]
        self.case = SimpleNamespace(config="fixture", keep_json=Mock(), human=SimpleNamespace(read=Mock(side_effect=self.read)))
        self.runner = child.ChildTests(self.case)
        self.submit = Mock(return_value=copy.deepcopy(self.operation))
        self.native = patch.object(child, "native_release", return_value={"survivors": []}).start()
        self.addCleanup(patch.stopall)

    def object(self, name, kind, raw):
        self.objects[name] = raw
        return {"id": name, "class": kind, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}

    def document(self, name, kind, value):
        return self.object(name, kind, json.dumps(value, sort_keys=True).encode())

    def read(self, label, command, request):
        if command == ["operation", "get"]:
            self.assertEqual(request, {"operation_id": self.operation["id"]})
            return copy.deepcopy(self.operation)
        if command == ["event", "tail"]:
            return {"events": copy.deepcopy(self.events), "complete": True}
        if command == ["lane", "status"]:
            return dict(self.target, grant_set_id="component-grants")
        self.assertEqual(command, ["blob", "read"])
        raw = self.objects[request["object_id"]][request["offset"]:request["offset"] + request["limit"]]
        return {"object_id": request["object_id"], "offset": request["offset"],
                "data": base64.b64encode(raw).decode(), "sha256": hashlib.sha256(raw).hexdigest()}

    def execute(self):
        return self.runner.execute(self.request, self.submit, subject=self.subject, required=["workspace"])

    def test_result(self):
        result = self.execute()
        self.submit.assert_called_once_with(self.request)
        self.assertEqual(result["operation"], self.operation, "TestChild returned an uncompleted operation")
        self.assertEqual(base64.b64decode(result["capture"]["stdout"]), self.objects["capture"],
                         "TestChild discarded its actual primary output")
        self.assertEqual(result["checks"], [{"ref": self.check_ref, "check": self.check}])
        self.native.assert_called_once_with(self.case, self.release, self.target, self.operation["id"])
        reads = self.case.human.read.call_args_list
        self.assertTrue(any(call.args[1] == ["operation", "get"] for call in reads),
                        "TestChild accepted submit without an operation read-back")
        self.assertIn(self.operation["id"], self.runner.results, "TestChild lost its managed worker")

    def test_operation(self):
        submitted = self.submit.return_value
        self.operation["id"] = "foreign-operation"
        self.submit.return_value = submitted
        for event in self.events:
            event["operation_id"] = self.operation["id"]
        self.binding["operation_id"] = self.operation["id"]
        self.release["operation_id"] = self.operation["id"]
        self.check["operation_id"] = self.operation["id"]
        self.events[4]["payload"] = self.document("check", "check", self.check)
        # Return a foreign record even though the selector remains original.
        original = self.case.human.read.side_effect
        self.case.human.read.side_effect = lambda label, command, request: copy.deepcopy(self.operation) if command == ["operation", "get"] else original(label, command, request)
        with self.assertRaisesRegex(ValueError, "reserved child or sequence", msg="foreign TestChild operation passed"):
            self.execute()

    def test_pending(self):
        original, count = self.case.human.read.side_effect, 0
        def read(label, command, request):
            nonlocal count
            if command == ["operation", "get"]:
                count += 1
                return dict(self.operation, status="pending" if count == 1 else "succeeded")
            return original(label, command, request)
        self.case.human.read.side_effect = read
        with patch.object(child.time, "sleep"):
            result = self.execute()
        self.assertEqual(result["operation"]["status"], "succeeded", "pending TestChild response received completion credit")

    def test_event_scope(self):
        self.events[5]["run"] = 1
        with self.assertRaises(ValueError, msg="foreign worker event passed TestChild"):
            self.execute()

    def test_plan(self):
        self.plan["input"] = dict(self.request["candidate"], id="foreign-candidate")
        self.request["test_plan"] = self.document("plan", "manifest", self.plan)
        with self.assertRaises(ValueError, msg="TestChild accepted another candidate in the sealed plan"):
            self.execute()

    def test_output_hash(self):
        self.objects["output"] = self.objects["output"].replace(b"candidate", b"different")
        with self.assertRaises(ValueError, msg="TestChild accepted changed worker output bytes"):
            self.execute()

    def test_worker(self):
        self.events[5]["payload"]["kind"] = "archive"
        with self.assertRaises(ValueError, msg="another worker kind passed TestChild"):
            self.execute()

    def test_capture_range(self):
        self.events[1]["payload"]["offset"] = 3
        with self.assertRaises(ValueError, msg="discontinuous TestChild primary output passed"):
            self.execute()

    def test_capture_origin(self):
        self.events[1]["payload"]["primary"] = False
        with self.assertRaises(ValueError, msg="nonprimary TestChild output passed"):
            self.execute()

    def test_eof(self):
        del self.events[3]
        with self.assertRaises(ValueError, msg="one EOF passed as drained TestChild output"):
            self.execute()

    def test_release(self):
        self.release["quiescence"]["handle"]["id"] = "another-launch"
        with self.assertRaises(ValueError, msg="another native worker release passed TestChild"):
            self.execute()

    def test_native(self):
        self.execute()
        self.native.assert_called_once_with(self.case, self.release, self.target, self.operation["id"])
        self.assertEqual(self.runner.results[self.operation["id"]]["outside"], {"survivors": []},
                         "TestChild discarded its independent native observation")

    def test_native_journal(self):
        receipt = dict(self.release, containment_id="component-containment")
        lease = {"id": receipt["lease_id"], "containment_id": receipt["containment_id"], "uid": 32001}
        journal = {"schema": "laneboss.helper-lease.v2", "reviews": [{"Worker": {"Lease": lease, "Collected": True},
            "Retirement": {"Proof": {"release": receipt}}}]}
        self.assertEqual(child.released_worker(journal, receipt), lease, "actual nested native worker release was lost")
        journal["reviews"][0]["Worker"]["Collected"] = False
        with self.assertRaises(ValueError, msg="uncollected nested TestChild helper worker passed"):
            child.released_worker(journal, receipt)

    def test_grants_native_observer(self):
        grants = load("case_grants")
        observed = {"journal_sha256": hashlib.sha256(b"component native journal").hexdigest()}
        nested = Mock(return_value=observed)
        protected = Mock()
        def sibling(name):
            return SimpleNamespace(nested_native_zero=nested) if name == "item_test_child" else SimpleNamespace(read_protected=protected)
        receipt = {"lease_id": "actual-helper", "containment_id": "actual-containment"}
        with patch.object(grants.Path, "is_file", return_value=False), patch.object(grants, "sibling", side_effect=sibling):
            result = grants.native_zero(self.case, receipt, child.need)
        self.assertEqual(result, observed, "grants collector ignored native TestChild journal observer")
        nested.assert_called_once_with(self.case, receipt, protected)

    def test_check_subject(self):
        self.check["snapshot_sha256"] = hashlib.sha256(b"another tree").hexdigest()
        self.events[4]["payload"] = self.document("check", "check", self.check)
        with self.assertRaises(ValueError, msg="TestChild accepted a check for another frozen subject"):
            self.execute()

    def test_check_worker(self):
        self.check["worker_lease_id"] = "another-worker"
        self.events[4]["payload"] = self.document("check", "check", self.check)
        with self.assertRaises(ValueError, msg="TestChild accepted a check from another worker"):
            self.execute()

    def test_required(self):
        self.check["name"] = "another-check"
        self.events[4]["payload"] = self.document("check", "check", self.check)
        with self.assertRaises(ValueError, msg="TestChild omitted a required measured check"):
            self.execute()

    def test_refusal(self):
        original = FixtureError({"owner": "lb-v2-grants", "code": "prerequisite_missing", "message": "component native worker absent"})
        self.submit.side_effect = original
        with self.assertRaises(FixtureError) as caught:
            self.execute()
        self.assertIs(caught.exception, original)
        with self.assertRaises(FixtureError, msg="TestChild retried after its native refusal") as repeated:
            self.execute()
        self.assertIs(repeated.exception, original)
        self.assertEqual(self.submit.call_count, 1, "TestChild retried after its native refusal")
        self.case.human.read.assert_not_called()

    def bound(self, response):
        self.original = Mock(return_value=response)
        self.collect = Mock(side_effect=lambda context, operations: {"operation_ids": operations, "evidence": [{"path": "outside.json"}]})
        self.io = load("item_context")
        self.prepared = child.bind(self.case, {"transport": self.original, "collect": self.collect}, self.io)
        self.runner = self.case.item_test_child
        return self.prepared

    def test_transport(self):
        raw = (json.dumps(self.operation, indent=2) + "\n").encode()
        response = {"exit_code": 0, "stdout": base64.b64encode(raw).decode(), "stderr": ""}
        prepared = self.bound(response)
        message = {"command": "grants test-child", "request": self.request}
        self.assertIs(prepared["transport"](message), response, "TestChild transport changed original reply bytes")
        self.original.assert_called_once_with(message)
        self.assertIn(self.operation["id"], self.runner.results, "TestChild transport did not await and measure its worker")

    def test_transport_refusal(self):
        error = {"owner": "lb-v2-grants", "code": "prerequisite_missing", "message": "component proof handoff absent"}
        response = {"exit_code": 2, "stdout": "", "stderr": base64.b64encode(json.dumps(error).encode()).decode()}
        prepared = self.bound(response)
        self.assertIs(prepared["transport"]({"command": "grants test-child", "request": self.request}), response)
        self.assertEqual(getattr(self.runner.failure, "error", None), error, "TestChild transport lost the exact native refusal")
        with self.assertRaises(child.NativeFailure):
            prepared["transport"]({"command": "grants revoke", "request": {}})
        self.original.assert_called_once()
        self.case.human.read.assert_not_called()

    def test_collection(self):
        prepared = self.bound({})
        self.execute()
        with tempfile.TemporaryDirectory() as directory:
            context = {"evidence_root": directory}
            receipt = prepared["collect"](context, ["action-operation"])
            managed = ["action-operation", self.operation["id"]]
            self.collect.assert_called_once_with(context, managed)
            retained = Path(directory) / receipt["evidence"][-1]["path"]
            self.assertEqual(json.loads(retained.read_bytes()), [self.runner.results[self.operation["id"]]],
                             "collection omitted exact TestChild result bytes")
            self.assertEqual(receipt["operation_ids"], managed, "nested TestChild operation was omitted from collection")

    def test_dispatch(self):
        dispatch = load("item_dispatch")
        def populate(context):
            self.assertTrue(callable(getattr(getattr(self.case, "item_test_child", None), "execute", None)),
                            "dispatcher did not bind TestChild before populate")
            raise ValueError("component population boundary")
        prepared = {"binding_file": "/test/binding", "profile_grant_ids": [], "collect": Mock(), "populate": populate}
        with patch.object(dispatch.context_io, "create", return_value=({}, Path("/test/context"))):
            with self.assertRaisesRegex(ValueError, "component population boundary"):
                dispatch.run(self.case, "dashboard", prepared)


if __name__ == "__main__":
    unittest.main()
