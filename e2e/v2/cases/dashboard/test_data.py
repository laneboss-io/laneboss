"""Current-generation and real-review request preparation controls."""

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


SOURCE = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location("dash_data", SOURCE / "scripts/v2-serve/dash_data.py")
data_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = data_module
SPEC.loader.exec_module(data_module)


class DataTests(unittest.TestCase):
    def test_abandon(self):
        with tempfile.TemporaryDirectory() as directory:
            data, lane = self.fixture(directory)
            with patch.object(data, "lane", return_value=lane):
                request = json.loads(data.action("DASH-ABANDONED").read_bytes())
            review = request["params"]["review"]
            self.assertEqual(set(review), {"id", "reviewer", "diff", "checks", "record_inventory", "refusal_resolution", "coverage"},
                             "abandonment request lost the typed zero review")
            self.assertEqual(review["id"], "")
            self.assertEqual(review["checks"], [])

    def fixture(self, directory):
        root = Path(directory).resolve()
        def upload(label, kind, raw):
            return {"id": label, "class": kind, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        def keep(name, value):
            path = root / name
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            return path
        owner = SimpleNamespace(config="fixture", human_prefix="", rows={}, passed=Mock(),
            human=SimpleNamespace(upload=upload), keep_json=keep)
        data = data_module.DashData(owner, {}, None, None, lambda aid, target: {"target": target})
        data.bind(SimpleNamespace(proof=Mock(return_value={"id": "issued-proof"}), rpc=Mock()), case)
        data.records = {aid: {"target": {"life_id": aid.lower(), "run": 1},
                             "request": {"budget": {"wall_ms": 1000}}} for aid in data_module.ACTIONS}
        lane = {"life_id": "actual-life", "run": 1, "generation": 8, "state": "verifying"}
        return data, lane

    def test_mail_target(self):
        with tempfile.TemporaryDirectory() as directory:
            data, lane = self.fixture(directory)
            with patch.object(data, "lane", return_value=lane):
                request = json.loads(data.action("HUMAN-SEND").read_bytes())
            arguments = data.browser.proof.call_args.args
            self.assertEqual(arguments[0], "mail.send")
            self.assertEqual(arguments[2:], ("fixture", 0), "mail proof used recipient instead of authorization target")
            self.assertEqual(request["params"]["recipient_life_id"], lane["life_id"])

    def test_stop_live(self):
        with tempfile.TemporaryDirectory() as directory:
            data, lane = self.fixture(directory)
            with patch.object(data, "lane", return_value=lane), patch.object(data, "observe") as observed:
                request = json.loads(data.action("DASH-STOP").read_bytes())
            observed.assert_called_once_with(data.records["DASH-STOP"], running=True)
            self.assertEqual(request["params"]["expected_generation"], lane["generation"])
            self.assertEqual(data.browser.proof.call_args.args[2:], (lane["life_id"], lane["generation"]))

    def test_resume_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            data, lane = self.fixture(directory)
            current = dict(lane, generation=9)
            with patch.object(data, "lane", side_effect=[lane, current]), patch.object(data, "quiescent"):
                request = json.loads(data.action("DASH-RESUME").read_bytes())
            self.assertEqual(request["params"]["expected_generation"], 9, "resume proof used generation before terminal observation")
            self.assertEqual(request["params"]["message"]["class"], "task")
            self.assertEqual(data.browser.proof.call_args.args[2:], (lane["life_id"], 9))

    def test_review(self):
        with tempfile.TemporaryDirectory() as directory:
            data, lane = self.fixture(directory)
            receipt = {"id": "verified-review", "coverage": "complete", "evidence": {"subject": {"target": lane["life_id"]}}}
            operation = {"id": "actual-acceptance", "status": "succeeded", "last_seq": 19}
            data.browser.rpc.side_effect = [receipt, operation]
            with patch.object(data, "lane", side_effect=[lane, lane, dict(lane, generation=9, state="accepted")]), patch.object(data, "await_operation", return_value=operation) as awaited:
                request = json.loads(data.action("DASH-MERGED").read_bytes())
            self.assertEqual(data.browser.rpc.call_args_list[0].args[0], "lane.review", "merged did not invoke genuine service review")
            self.assertEqual(data.browser.rpc.call_args_list[1].args[1]["state"], "accepted")
            awaited.assert_called_once_with(operation, {"life_id": lane["life_id"], "run": 1})
            self.assertEqual(request["params"]["review"], receipt)
            self.assertEqual(request["params"]["expected_generation"], 9)
            self.assertEqual([call.args[0] for call in data.browser.proof.call_args_list], ["lane.review", "lane.mark", "lane.mark"])

    def test_accept_readback(self):
        with tempfile.TemporaryDirectory() as directory:
            data, lane = self.fixture(directory)
            data.browser.rpc.side_effect = [{"id": "actual-review", "coverage": "complete", "evidence": {"subject": {}}},
                {"id": "actual-acceptance", "status": "succeeded", "last_seq": 19}]
            with patch.object(data, "lane", side_effect=[lane, lane, dict(lane, generation=9)]), patch.object(data, "await_operation"):
                with self.assertRaises(ValueError, msg="merged request passed without accepted read-back"):
                    data.action("DASH-MERGED")
            self.assertEqual(data.prepared, {})

    def test_partial_review(self):
        with tempfile.TemporaryDirectory() as directory:
            data, lane = self.fixture(directory)
            operation = {"id": "actual-acceptance", "status": "succeeded", "last_seq": 19}
            data.browser.rpc.side_effect = [{"id": "review", "coverage": "partial", "evidence": {"subject": {}}}, operation]
            with patch.object(data, "lane", side_effect=[lane, lane, dict(lane, generation=9, state="accepted")]), patch.object(data, "await_operation", return_value=operation):
                with self.assertRaises(ValueError):
                    data.action("DASH-MERGED")
            self.assertEqual(data.browser.proof.call_count, 1, "partial review allowed a merged proof")

    def capture_pages(self, record):
        target = record["target"]
        event = lambda kind, payload: dict(target, kind=kind, origin="service", payload=payload)
        binding = event("capture.bound", {"id": "actual-binding", "target": target,
            "streams": [{"id": "actual-out"}, {"id": "actual-err"}]})
        closed = lambda stream: event("capture.closed", {"binding_id": "actual-binding", "stream_id": stream, "eof": True})
        return [{"events": [binding, closed("actual-out")], "complete": True},
                {"events": [binding, closed("actual-out"), closed("actual-err")], "complete": True}]

    def test_capture_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            data, _ = self.fixture(directory)
            record = data.records["DASH-MERGED"]
            data.read = Mock(side_effect=self.capture_pages(record))
            with patch.object(data_module.time, "sleep"):
                data.capture_ready(record)
            self.assertEqual(data.read.call_count, 2)
            self.assertEqual(data.read.call_args.args[0], "event.tail", "capture readiness did not read actual run events")

    def test_capture_eof(self):
        with tempfile.TemporaryDirectory() as directory:
            data, _ = self.fixture(directory)
            record = data.records["DASH-MERGED"]
            data.read = Mock(return_value=self.capture_pages(record)[0])
            with patch.object(data_module.time, "monotonic", side_effect=[0, 121]):
                with self.assertRaises(ValueError, msg="one committed EOF passed as the entire primary capture"):
                    data.capture_ready(record)


if __name__ == "__main__":
    unittest.main()
