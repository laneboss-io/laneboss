"""Installed relay ordering: readiness and RPC replies precede stdout EOF.

The event/blob read port is a component fixture. The real relay reader executes
against exact hashed report bytes; no capture event or EOF is invented.
"""

import base64
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("prep", HERE / "prep_probe.py")
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)
GRANTS = PREP.GRANTS


class LiveRelay(unittest.TestCase):
    def test_wait_kind(self):
        case, record, target, pages, objects, publish = self.fixture()
        publish({"type": "grants.ready", "target": target})
        relay = GRANTS.Relay(case, record, GRANTS.io.require, ValueError)
        relay.wait("grants.ready")
        trace = case.rows[case.current]["observed"]["relay_wait"]
        self.assertEqual(trace["kind"], "grants.ready")
        self.assertFalse(trace["nonce_required"])
        ticks = iter((0, 121))
        with mock.patch.object(GRANTS, "time", SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda _: None)):
            with self.assertRaisesRegex(ValueError, "relay committed report deadline.*grants.reply"):
                relay.wait("grants.reply", uuid.uuid4().hex)
        trace = case.rows[case.current]["observed"]["relay_wait"]
        self.assertEqual(trace["kind"], "grants.reply")
        self.assertTrue(trace["nonce_required"])
        self.assertEqual(trace["seen_kinds"], ["grants.ready"])
        self.assertEqual(len(pages), 1, "waiting manufactured a committed reply")

    def fixture(self):
        area = tempfile.TemporaryDirectory(prefix="relay-live-")
        self.addCleanup(area.cleanup)
        root = Path(area.name)
        case = PREP.BOOT.BootFixture(root)
        case.config, case.current = "relay-case", "item.grants.prepare"
        case.rows = {case.current: {"observed": {}}}
        target = {"life_id": "live-parent", "run": 1}
        record = {"target": target, "operation": {"id": "actual-start"}}
        actor = {"kind": "lane", "id": "parent-principal", "life_id": target["life_id"], "level": 5, "role": "supervisor"}
        pages, objects = [], {}

        def publish(value):
            raw = GRANTS.io.encoded({"schema": "laneboss.relay-report.v1", "message": value})
            ref = {"id": uuid.uuid4().hex, "class": "report", "sha256": GRANTS.sha(raw), "bytes": len(raw)}
            objects[ref["id"]] = raw
            event = {"seq": len(pages) + 1, "kind": "blob.committed", "config": case.config,
                "life_id": target["life_id"], "run": target["run"], "origin": "observation",
                "actor": copy.deepcopy(actor), "requested_by": copy.deepcopy(actor), "payload": ref}
            pages.append(event)
            return event

        def read(label, words, request):
            if words == ["event", "tail"]:
                self.assertEqual(request["life_id"], target["life_id"])
                return {"events": copy.deepcopy(pages), "complete": True, "cursor": ""}
            self.assertEqual(words, ["blob", "read"])
            raw = objects[request["object_id"]]
            part = raw[request["offset"]:request["offset"] + request["limit"]]
            return {"object_id": request["object_id"], "offset": request["offset"],
                "data": base64.b64encode(part).decode(), "sha256": GRANTS.sha(part)}

        case.human = SimpleNamespace(read=read)
        return case, record, target, pages, objects, publish

    def test_ready_before_exit(self):
        case, record, target, pages, objects, publish = self.fixture()
        ready = {"type": "grants.ready", "target": target, "metadata_only": True}
        publish(ready)
        relay = GRANTS.Relay(case, record, GRANTS.io.require, ValueError)
        self.assertEqual(relay.values_now(), [ready],
                         "live grants-parent readiness is unavailable before stdout EOF")
        self.assertEqual(relay.wait("grants.ready"), ready)
        nonce = uuid.uuid4().hex
        reply = {"type": "grants.reply", "target": target, "nonce": nonce,
            "exit_code": 0, "stdout": base64.b64encode(b'{"profiles":[]}').decode(), "stderr": ""}
        publish(reply)
        self.assertEqual(relay.wait("grants.reply", nonce), reply)
        exiting = {"type": "grants.exiting", "target": target, "nonce": uuid.uuid4().hex,
            "exit_code": 0, "stdout": "", "stderr": ""}
        publish(exiting)
        self.assertEqual(relay.wait("grants.exiting", exiting["nonce"]), exiting)
        self.assertFalse(any(row["kind"].startswith("capture.") for row in pages))
        self.assertEqual(relay.values_now(), [ready, reply, exiting], "event replay duplicated reports")

    def test_foreign_report(self):
        for field in ("actor", "requested_by", "life_id", "run", "origin", "bytes"):
            with self.subTest(field=field):
                case, record, target, pages, objects, publish = self.fixture()
                event = publish({"type": "grants.ready", "target": target})
                if field in ("actor", "requested_by"):
                    event[field]["life_id"] = "foreign-life"
                elif field == "bytes":
                    objects[event["payload"]["id"]] += b"changed"
                else:
                    event[field] = 2 if field == "run" else "foreign"
                with self.assertRaises(ValueError):
                    GRANTS.Relay(case, record, GRANTS.io.require, ValueError).values_now()

    def test_terminal_capture(self):
        for fault in ("", "missing-eof", "worker", "operation", "offset", "primary", "gap", "changed-message"):
            with self.subTest(fault=fault):
                case, record, target, pages, objects, publish = self.fixture()
                ready = {"type": "grants.ready", "target": target, "metadata_only": True}
                publish(ready)
                relay = GRANTS.Relay(case, record, GRANTS.io.require, ValueError)
                self.assertEqual(relay.wait("grants.ready"), ready)
                requester = {"kind": "human", "id": "operator"}
                binding = {"id": "capture-binding", "config": case.config, "target": target,
                    "operation_id": record["operation"]["id"], "request_id": "start-request",
                    "requested_by": requester, "producer_id": "capture-worker", "status": "registered", "generation": 1,
                    "streams": [{"id": "out-stream", "stream": "stdout"}, {"id": "err-stream", "stream": "stderr"}]}
                common = {"config": case.config, "life_id": target["life_id"], "run": target["run"],
                    "operation_id": binding["operation_id"], "request_id": binding["request_id"], "requested_by": requester,
                    "actor": {"kind": "worker", "id": binding["producer_id"]}, "origin": "service"}

                def append(kind, payload):
                    seq = len(pages) + 1
                    event = dict(copy.deepcopy(common), id="event-" + str(seq), seq=seq, kind=kind, payload=payload)
                    pages.append(event)
                    return event

                append("capture.bound", binding)
                captured = dict(ready, metadata_only=False) if fault == "changed-message" else ready
                raw = json.dumps(captured, separators=(",", ":")).encode() + b"\n"
                ref = {"id": "capture-bytes", "class": "capture", "sha256": GRANTS.sha(raw), "bytes": len(raw)}
                objects[ref["id"]] = raw
                data = {"binding_id": binding["id"], "stream": "stdout", "target": target,
                    "primary": fault != "primary", "coverage": "partial", "offset": 1 if fault == "offset" else 0, "data": ref}
                event = append("capture.appended", data)
                data["id"] = event["id"]
                if fault == "worker":
                    event["actor"]["id"] = "foreign-worker"
                elif fault == "operation":
                    event["operation_id"] = "foreign-operation"
                for stream, offset, generation in (("out-stream", len(raw), 3), ("err-stream", 0, 4)):
                    receipt = {"binding_id": binding["id"], "stream_id": stream, "offset": offset,
                        "next_offset": offset, "eof": True, "generation": generation}
                    event = append("capture.closed", receipt)
                    receipt.update(record_id=event["id"], last_seq=event["seq"])
                if fault == "missing-eof":
                    pages.pop()
                elif fault == "gap":
                    append("capture.gap", {"binding_id": binding["id"]})
                if fault:
                    with self.assertRaises(ValueError):
                        relay.verify_transcript()
                else:
                    relay.verify_transcript()


def committed_trace(path):
    trace = json.loads(Path(path).read_bytes())
    with tempfile.TemporaryDirectory(prefix="relay-trace-") as area:
        case = PREP.BOOT.BootFixture(Path(area))
        case.config = trace["config"]
        case.current = "item.grants.prepare"
        case.rows = {case.current: {"observed": {}}}
        record = {"target": trace["target"], "operation": {"id": trace["operation"]}}
        objects = {key: base64.b64decode(raw, validate=True) for key, raw in trace["objects"].items()}
        visible = []

        def read(label, words, request):
            if words == ["event", "tail"]:
                return {"events": copy.deepcopy(visible), "complete": True, "cursor": ""}
            if words != ["blob", "read"]:
                raise ValueError("trace selected another public read")
            raw = objects[request["object_id"]]
            part = raw[request["offset"]:request["offset"] + request["limit"]]
            return {"object_id": request["object_id"], "offset": request["offset"],
                "data": base64.b64encode(part).decode(), "sha256": GRANTS.sha(part)}

        case.human = SimpleNamespace(read=read)
        relay = GRANTS.Relay(case, record, GRANTS.io.require, ValueError)
        for event, expected in zip(trace["events"], trace["messages"], strict=True):
            visible.append(event)
            actual = relay.wait(expected["type"], expected.get("nonce"))
            if actual != expected:
                raise ValueError("actual public report bytes differ from their actor message")
        foreign = copy.deepcopy(trace["events"][0])
        foreign["actor"]["life_id"] = "foreign-life"
        visible[:] = [foreign]
        try:
            GRANTS.Relay(case, record, GRANTS.io.require, ValueError).values_now()
        except ValueError as error:
            if "authenticated original actor" not in str(error):
                raise
        else:
            raise ValueError("foreign committed report crossed the actor boundary")
        print("PASS: actual blob APIs ready/RPC/exit before EOF; foreign actor refused")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--trace":
        committed_trace(sys.argv[2])
    else:
        unittest.main()
