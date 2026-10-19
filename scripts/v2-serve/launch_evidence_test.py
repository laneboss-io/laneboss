"""Reader controls only; synthetic metadata is never installed-run evidence."""

import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest
import uuid


spec = importlib.util.spec_from_file_location("launch_evidence", Path(__file__).with_name("launch_evidence.py"))
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


def sample():
    def identifier():
        return uuid.uuid4().hex
    pins = {name: hashlib.sha256(identifier().encode()).hexdigest() for name in ("agent", "runtime", "supervisor")}
    target = {"life_id": identifier(), "run": 1}
    operation = dict(target, id=identifier())
    reservation = {"id": identifier(), "config": "fixture-case", "operation_id": operation["id"],
                   "target": target, "launch_id": identifier(), "spec_id": identifier(),
                   "grant_set_id": identifier(), "request_id": identifier(),
                   "requested_by": {"kind": "human", "id": identifier()}}
    lease = {"id": identifier()}
    home = {"id": identifier()}
    executable = {"id": identifier(), "sha256": pins["agent"], "version": "1.0.0"}
    capture = {"id": identifier(), "config": "fixture-case", "target": target,
               "reservation_id": reservation["id"], "launch_id": reservation["launch_id"],
               "helper_lease_id": lease["id"], "operation_id": operation["id"],
               "request_id": reservation["request_id"], "requested_by": reservation["requested_by"],
               "status": "registered", "producer_id": identifier(), "producer_generation": identifier(),
               "boot_id": identifier(), "supervisor": {"sha256": pins["supervisor"]},
               "streams": [{"id": identifier(), "pipe_id": identifier(), "stream": name} for name in ("stdout", "stderr")]}
    plan = {"reservation": reservation, "lease": lease,
            "inputs": {"grants": {"id": reservation["grant_set_id"]}, "sources": {
                "reservation_id": reservation["id"], "runtime": {"driver": "codex", "executable": executable,
                    "manifest": {"sha256": pins["runtime"]}}}},
            "data": {"reservation_id": reservation["id"], "target": target, "lease_id": lease["id"],
                     "home": {"life_id": target["life_id"], "home": home}},
            "runner": {"home": home, "driver": "codex", "executable": executable}, "capture": capture}
    event = {"operation_id": operation["id"], "config": "fixture-case", "origin": "service"}
    events = [dict(event, kind="capture.bound", seq=1, payload=capture),
              dict(event, kind="launch.planned", seq=2, payload={"phase": "planned", "generation": 1,
                   "reservation": reservation, "plan": plan})]
    return events, operation, pins


class LaunchReaderControls(unittest.TestCase):
    def test_identical_page_overlap_is_exact(self):
        event = {"id": uuid.uuid4().hex, "seq": 1, "payload": {"value": uuid.uuid4().hex}}
        self.assertEqual(reader.merge([event], [copy.deepcopy(event)]), [event])

    def test_changed_event_refuses(self):
        event = {"id": uuid.uuid4().hex, "seq": 1, "payload": {"value": uuid.uuid4().hex}}
        for changed in (dict(event, payload={"value": uuid.uuid4().hex}), dict(event, id=uuid.uuid4().hex)):
            with self.assertRaises(ValueError):
                reader.merge([event], [changed])

    def test_claimed_summary_has_no_plan(self):
        with self.assertRaisesRegex(ValueError, "launch.planned"):
            reader.observe([{"passed": True}], {"id": "actual-operation"}, "fixture-case", {})

    def test_cross_run_and_pin_drift_refuse(self):
        for field in ("operation", "target", "agent", "runtime", "supervisor", "pipe"):
            events, operation, pins = sample()
            capture = events[0]["payload"]
            if field == "operation":
                operation = dict(operation, id=uuid.uuid4().hex)
            elif field == "target":
                capture["target"] = dict(capture["target"], run=2)
            elif field == "pipe":
                capture["streams"][1]["pipe_id"] = capture["streams"][0]["pipe_id"]
            else:
                pins[field] = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
            with self.assertRaises(ValueError):
                reader.observe(events, operation, "fixture-case", pins)

    def test_real_refusal_is_retained(self):
        events, operation, pins = sample()
        capture = events[0]["payload"]
        capture["status"] = "refused"
        capture["refusal"] = {"code": "not_implemented", "owner": "lb-v2-admin", "message": "capture unavailable"}
        events[0]["kind"] = "capture.refused"
        result = reader.observe(events, operation, "fixture-case", pins)
        self.assertEqual(result["capture"]["status"], "refused")
        self.assertEqual(result["capture"]["refusal"], capture["refusal"])

    def test_late_registration_refuses(self):
        events, operation, pins = sample()
        events[0]["seq"] = 4
        events.append(dict(copy.deepcopy(events[0]), kind="run.started", seq=3, payload={}))
        with self.assertRaisesRegex(ValueError, "after release"):
            reader.observe(events, operation, "fixture-case", pins)


if __name__ == "__main__":
    unittest.main()
