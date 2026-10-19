"""Capture reads use the installed human RPC; run on the Linux box."""

import base64
import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest


spec = importlib.util.spec_from_file_location("cap_flow", Path(__file__).with_name("lifecycle.py"))
flow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flow)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


class CaptureReads(unittest.TestCase):
    def fixture(self):
        target = {"life_id": "child", "run": 2}
        bodies = {"out": b"vendor stdout\x00\xff\n", "err": b"401 vendor refusal\n"}
        calls, kept = [], {}

        def read(label, words, request):
            calls.append((words, request))
            if words == ["identity", "self"]:
                return {"config": "demo", "actor": {"kind": "human", "id": "owner"}}
            self.assertEqual(words, ["blob", "read"])
            raw = bodies[request["object_id"]]
            offset = request["offset"]
            raw = raw[offset:offset + min(5, request["limit"])]
            return {"object_id": request["object_id"], "offset": offset,
                    "data": base64.b64encode(raw).decode(), "sha256": hashlib.sha256(raw).hexdigest()}

        binding = {"id": "binding", "config": "demo", "status": "registered", "target": target,
                   "operation_id": "op", "producer_id": "producer", "streams": [
                       {"id": "out-stream", "stream": "stdout"}, {"id": "err-stream", "stream": "stderr"}]}
        events = [{"id": "bound", "kind": "capture.bound", "config": "demo", **target,
                   "origin": "service", "operation_id": "op", "payload": binding}]
        for name, stream in (("out", "stdout"), ("err", "stderr")):
            raw = bodies[name]
            events.append({"id": name, "kind": "capture.appended", "config": "demo", **target,
                "origin": "service", "operation_id": "op", "payload": {
                    "id": name, "binding_id": "binding", "target": target, "primary": True,
                    "stream": stream, "offset": 0, "coverage": "partial",
                    "data": {"id": name, "class": "capture", "bytes": len(raw),
                             "sha256": hashlib.sha256(raw).hexdigest()}}})
        case = SimpleNamespace(config="demo", human=SimpleNamespace(read=read,
            public={"principal_id": "owner"}), keep=lambda name, raw: kept.update({name: raw}))
        return case, {"name": "claudock", "target": target}, events, calls, kept, bodies

    def test_owner_rpc(self):
        case, record, events, calls, kept, bodies = self.fixture()
        result = flow.capture_read(case, record, events, require)
        self.assertEqual(result["reader"], {"kind": "human", "id": "owner"})
        self.assertEqual(result["method"], "blob.read")
        self.assertEqual(result["stdout"], bodies["out"].decode("utf-8", errors="replace"))
        self.assertEqual(result["stderr"], bodies["err"].decode("utf-8", errors="replace"))
        self.assertEqual(kept["claudock-reply.stdout"], bodies["out"])
        self.assertEqual(kept["claudock-reply.stderr"], bodies["err"])
        self.assertGreater(sum(words == ["blob", "read"] for words, _ in calls), 2)

    def test_reply_row(self):
        self.assertIn("lane.claudock.reply", flow.checks())

    def test_changed_chunk(self):
        case, record, events, _, _, _ = self.fixture()
        original = case.human.read

        def changed(label, words, request):
            result = original(label, words, request)
            if words == ["blob", "read"]:
                result["sha256"] = hashlib.sha256(b"changed").hexdigest()
            return result

        case.human.read = changed
        with self.assertRaisesRegex(ValueError, "chunk"):
            flow.capture_read(case, record, events, require)

    def test_wrong_human(self):
        case, record, events, _, _, _ = self.fixture()
        case.human.public["principal_id"] = "other-human"
        with self.assertRaisesRegex(ValueError, "human"):
            flow.capture_read(case, record, events, require)

    def test_foreign_capture(self):
        for field, value in (("config", "other"), ("run", 1), ("origin", "observation")):
            with self.subTest(field=field):
                case, record, events, _, _, _ = self.fixture()
                events[1][field] = value
                with self.assertRaisesRegex(ValueError, "capture"):
                    flow.capture_read(case, record, events, require)

    def test_gap(self):
        case, record, events, _, _, _ = self.fixture()
        events[1]["payload"]["offset"] = 1
        with self.assertRaisesRegex(ValueError, "capture"):
            flow.capture_read(case, record, events, require)


if __name__ == "__main__":
    unittest.main()
