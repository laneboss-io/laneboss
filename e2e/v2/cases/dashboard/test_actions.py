"""Action completion, exact wire and consumer wiring controls."""

import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import case
from fixture_io import FixtureError
import test_case
from test_inputs import Recorder


class ActionTests(unittest.TestCase):
    def request(self, method="lane.stop"):
        request, response, readback = test_case.CaseTests.stop_fixture()
        params = request["params"]
        if method == "lane.resume":
            response["result"]["run"] += 1
            readback.update({"run": params["target"]["run"] + 1, "state": "running"})
        request.update(case.build_rpc_envelope("fixture", method, params, req_id=request["request_id"]))
        return request, response, readback

    def run_action(self, method="lane.stop", operation_id=None, refused=None):
        request, response, readback = self.request(method)
        initial = copy.deepcopy(response)
        initial["result"]["status"] = "pending"
        queries = []
        recorder = Recorder()
        def reply(opener, url, **kwargs):
            body = kwargs.get("body")
            query = json.loads(body) if isinstance(body, bytes) else body
            queries.append((url, query))
            if "/events?" in url:
                event = {"id": "event", "kind": "lane.state", "origin": "service", "life_id": "life", "run": 2,
                         "seq": 8, "payload": {"from": "stopping", "to": "verifying", "generation": 4}}
                return 200, {}, ("data: " + json.dumps({"event": event}) + "\n\n").encode()
            if query["method"] == method:
                if refused:
                    return 403, {}, json.dumps({"request_id": query["request_id"], "error": refused}).encode()
                return 200, {}, json.dumps(initial).encode()
            if query["method"] == "operation.get":
                polled = copy.deepcopy(response)
                polled["request_id"] = query["request_id"]
                if operation_id:
                    polled["result"]["id"] = operation_id
                return 200, {}, json.dumps(polled).encode()
            if query["method"] == "lane.status":
                value = dict(readback)
                if len(queries) == 1 and method == "lane.stop":
                    value.update({"state": "running", "generation": 3, "last_seq": 7})
                return 200, {}, json.dumps({"request_id": query["request_id"], "result": value}).encode()
            raise AssertionError("unexpected request")
        aid = "DASH-RESUME" if method == "lane.resume" else "DASH-STOP"
        with patch("case.http_call", side_effect=reply):
            observed = case.exercise_positive(None, "https://console.example.test", "fixture", {},
                                              aid, method, {aid: request}, recorder)
        return observed, queries, recorder

    def test_same_operation(self):
        (passed, _), queries, _ = self.run_action()
        self.assertTrue(passed, "same completed operation did not pass")
        self.assertEqual(len([q for _, q in queries if q and q["method"] == "lane.stop"]), 1)
        (passed, _), _, _ = self.run_action(operation_id="different-operation")
        self.assertFalse(passed, "foreign operation completion passed")

    def test_resume_run(self):
        (passed, _), queries, _ = self.run_action("lane.resume")
        self.assertTrue(passed, "resumed operation did not pass its new-run read-back")
        reads = [q for _, q in queries if q and q["method"] == "lane.status"]
        self.assertEqual(reads[-1]["params"]["run"], 3, "resume read-back requested the previous run")

    def test_owner_refusal(self):
        refusal = {"owner": "fixture-owner", "code": "not_implemented", "message": "exact owner refusal"}
        with self.assertRaises(FixtureError) as failure:
            self.run_action(refused=refusal)
        self.assertEqual(failure.exception.error, refusal, "positive owner refusal changed")

    def test_mail_readback(self):
        params = {"recipient_life_id": "recipient", "content": {"id": "content", "sha256": "41" * 32}}
        request = case.build_rpc_envelope("fixture", "mail.send", params)
        mail = {"id": "mail", "queued_seq": 8, "source": "dashboard", "sender": {"kind": "human", "id": "principal"}, **params}
        response = {"request_id": request["request_id"], "result": mail}
        self.assertTrue(case.positive_observed("mail.send", request, 200, response, {"messages": [mail]}, {}))
        for field, bad in (("id", "foreign"), ("queued_seq", 9), ("source", "cli"),
                           ("sender", {"kind": "lane"}), ("recipient_life_id", "foreign"), ("content", {})):
            changed = copy.deepcopy(mail)
            changed[field] = bad
            with self.subTest(field=field):
                self.assertFalse(case.positive_observed("mail.send", request, 200, response,
                    {"messages": [changed]}, {}), "changed immutable mail read-back passed")

    def test_cli_failure_stops_http(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            binary = root / "binary"
            binary.write_bytes(b"unit artifact bytes; never executed")
            context = {"schema": "laneboss.e2e-context.v2", "case_id": "dashboard", "binary": str(binary),
                       "binary_sha256": case.sha256_bytes(binary.read_bytes()), "source_sha256": "42" * 32,
                       "config": "fixture", "binding_file": str(root / "binding.json"), "evidence_root": str(root / "evidence")}
            context_file, result_file = root / "context.json", root / "result.json"
            context_file.write_text(json.dumps(context))
            inputs = SimpleNamespace(document={**context, "targets": []}, cache={}, collect=lambda failure: {"error": failure})
            probes = {aid: {"exit": 0, "populated": True, "session_proof_sha256": "43" * 32, "stderr": None}
                      for aid, _ in case.VIEW_ASSERTIONS}
            probes["DASH-RAW"]["exit"] = 2
            with patch("case.FixtureInputs", return_value=inputs), patch("case.run_cli", return_value={"exit": 0}), \
                    patch("case.verify_cli_flag_guards", return_value=(True, {"path": "flags"})), \
                    patch("case.probe_cli_views", return_value=(probes, [], {"path": "probes"})), \
                    patch("case.exercise_http_dashboard", return_value={}) as http, \
                    patch.dict("os.environ", {"LANEBOSS_DASHBOARD_URL": "https://console.example.test",
                        "LANEBOSS_DASHBOARD_COOKIE": "unit-cookie", "LANEBOSS_DASHBOARD_CONTROLS_FILE": str(root / "controls.json")}), \
                    patch.object(sys, "argv", ["case.py", "--context", str(context_file), "--result", str(result_file)]):
                with self.assertRaises(SystemExit) as stopped:
                    case.main()
            self.assertEqual(stopped.exception.code, 1)
            self.assertFalse(http.called, "unauthorized CLI read allowed dependent HTTP actions")
            result = json.loads(result_file.read_bytes())
            self.assertEqual(len(result["assertions"]), 13)
            self.assertTrue(all(row["verdict"] == "fail" for row in result["assertions"]))
            self.assertFalse(result["collection"]["temporary_resources_collected"])


if __name__ == "__main__":
    unittest.main()
