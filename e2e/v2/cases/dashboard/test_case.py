"""Acceptance-classifier unit tests; execute only on the Linux test machine."""

import copy
import json
import unittest
from unittest.mock import patch

from case import control_passed, exercise_positive, positive_observed, request_digest, service_state_seen


class CaseTests(unittest.TestCase):
    def test_poll_headers(self):
        request, response, readback = self.stop_fixture()
        request.update({"config": "fixture", "method": "lane.stop"})
        request["request_sha256"] = request_digest("fixture", "lane.stop", request["params"])
        response["result"]["simulated_presence"] = True
        initial = copy.deepcopy(response)
        initial["result"]["status"] = "pending"
        marked = {"X-Laneboss-Presence": "simulated", "X-Laneboss-Human-Approval": "not_proven"}
        event = {"id": "event", "kind": "lane.state", "origin": "service", "life_id": "life", "run": 2,
                 "seq": 8, "payload": {"from": "running", "to": "verifying", "generation": 4}}
        class Recorder:
            def __init__(self):
                self.values = {}
            def save(self, name, value):
                self.values[name] = value
                return {"path": name}
        recorder = Recorder()
        replies = [
            (200, {}, json.dumps({"result": {**readback, "state": "running", "generation": 3, "last_seq": 7}}).encode()),
            (200, marked, json.dumps(initial).encode()),
            (200, {}, json.dumps(response).encode()),
            (200, {}, json.dumps({"result": readback}).encode()),
            (200, {}, ("data: " + json.dumps({"event": event}) + "\n\n").encode()),
        ]
        pending_replies = iter(replies)
        def reply(*args, **kwargs):
            status, headers, raw = next(pending_replies)
            body = kwargs.get("body")
            if isinstance(body, dict) and body.get("method") == "operation.get":
                parsed = json.loads(raw)
                parsed["request_id"] = body["request_id"]
                raw = json.dumps(parsed).encode()
            return status, headers, raw
        with patch("case.http_call", side_effect=reply) as calls:
            passed, _ = exercise_positive(None, "https://console.example.test", "fixture", {}, "DASH-STOP", "lane.stop", {"DASH-STOP": request}, recorder)
        self.assertEqual(calls.call_count, 5)
        self.assertFalse(passed, "operation poll reused initial presence headers")
        self.assertEqual(recorder.values["http/dash-stop_positive.json"]["headers"], {})

    def test_service_event(self):
        request, _, readback = self.stop_fixture()
        target = request["params"]["target"]
        event = {"id": "event", "kind": "lane.state", "origin": "service", "life_id": "life",
                 "run": 2, "seq": 8, "payload": {"from": "running", "to": "verifying", "generation": 4}}
        frames = [{"frame": {"event": event}}, {"frame": {"end": True}}]
        self.assertTrue(service_state_seen(frames, target, readback))
        self.assertFalse(service_state_seen([{"frame": {"end": True}}], target, readback),
                         "terminal SSE frame passed without a service event")
        self.assertFalse(service_state_seen(frames, target, readback, 8), "historical service event passed the stop baseline")
        for field, value in (("end", True), ("error", {"code": "forbidden"})):
            changed = copy.deepcopy(frames)
            changed[0]["frame"][field] = value
            self.assertFalse(service_state_seen(changed, target, readback), "terminal or error frame passed as an event delivery")
        for field, value in (("origin", "runner"), ("life_id", "foreign"), ("run", 3), ("seq", 9)):
            changed = copy.deepcopy(frames)
            changed[0]["frame"]["event"][field] = value
            self.assertFalse(service_state_seen(changed, target, readback),
                             "foreign or uncommitted SSE event passed provenance checks")
        changed = copy.deepcopy(frames)
        changed[0]["frame"]["event"]["payload"]["to"] = "running"
        self.assertFalse(service_state_seen(changed, target, readback), "SSE state payload did not match read-back")

    def test_no_positive(self):
        self.assertFalse(
            control_passed(True, False),
            "refusal-only evidence passed an action",
        )
        self.assertFalse(control_passed(False, True))
        self.assertTrue(control_passed(True, True))

    def test_pending(self):
        request, response, readback = self.stop_fixture()
        response["result"]["status"] = "pending"
        self.assertFalse(
            positive_observed("lane.stop", request, 200, response, readback, {}),
            "pending operation passed as completed control",
        )

    def test_readback(self):
        request, response, readback = self.stop_fixture()
        self.assertTrue(positive_observed("lane.stop", request, 200, response, readback, {}))
        stale = copy.deepcopy(readback)
        stale["generation"] = request["params"]["expected_generation"]
        self.assertFalse(
            positive_observed("lane.stop", request, 200, response, stale, {}),
            "stale lane projection passed a control",
        )

    def test_presence(self):
        request, response, readback = self.stop_fixture()
        response["result"]["simulated_presence"] = True
        self.assertFalse(
            positive_observed("lane.stop", request, 200, response, readback, {}),
            "simulated action passed without presence reporting",
        )
        self.assertTrue(positive_observed("lane.stop", request, 200, response, readback, {
            "X-Laneboss-Presence": "simulated",
            "X-Laneboss-Human-Approval": "not_proven",
        }))

    @staticmethod
    def stop_fixture():
        request = {"request_id": "request", "params": {
            "target": {"life_id": "life", "run": 2}, "expected_generation": 3,
        }}
        response = {"request_id": request["request_id"], "result": {
            "id": "operation", "status": "succeeded", "life_id": "life", "run": 2, "last_seq": 8,
        }}
        readback = {"life_id": "life", "run": 2, "state": "verifying", "generation": 4, "last_seq": 8}
        return request, response, readback


if __name__ == "__main__":
    unittest.main()
