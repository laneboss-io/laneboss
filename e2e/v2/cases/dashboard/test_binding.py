"""Installed-input construction controls; unit doubles confer no authority."""

import http.server
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
import ssl
import subprocess
import tempfile
import threading
import urllib.error
import uuid
from unittest.mock import Mock, patch

import case
from fixture_io import FixtureError
from test_data import data_module
from test_producer import producer, SOURCE


def need(condition, message):
    if not condition:
        raise ValueError(message)


class BindingTests(unittest.TestCase):
    def test_startup_tracking(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = SimpleNamespace(root=Path(directory), binary=Path("/test/installed"), config="fixture",
                installed={"binding_file": "/test/binding"}, keep_json=Mock())
            process = Mock()
            process.poll.return_value = 1
            try:
                with patch.object(producer.subprocess, "Popen", return_value=process):
                    with self.assertRaises(ValueError):
                        producer.NativeSession(owner, "failed", need)
                sessions = getattr(owner, "dashboard_native", [])
                self.assertEqual(len(sessions), 1, "native startup lost its owned child before readiness")
                self.assertIs(sessions[0].process, process)
            finally:
                for session in getattr(owner, "dashboard_native", []):
                    session.stdout.close()
                    session.stderr.close()

    def test_populate_refusal(self):
        owner = SimpleNamespace(stage=SOURCE, current="item.dashboard.prepare",
            rows={"item.dashboard.prepare": {"observed": {}}})
        adapter = producer.G0Dashboard(owner, None, None, need, ValueError)
        refusal = FixtureError({"owner": "fixture-owner", "code": "forbidden", "message": "exact preparation refusal"})
        with patch.object(adapter, "_populate", side_effect=refusal):
            with self.assertRaises(FixtureError) as observed:
                adapter.populate({})
        self.assertIs(observed.exception, refusal)
        self.assertEqual(adapter.failure, refusal.error, "preparation lost the exact owning refusal")
        self.assertEqual(owner.rows[owner.current]["observed"]["refusal"], refusal.error)

    def test_https_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            certificate, key = root / "certificate.pem", root / "key.pem"
            generated = subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-days", "1", "-keyout", str(key), "-out", str(certificate), "-subj", "/CN=console.example.test",
                "-addext", "subjectAltName=DNS:console.example.test"], capture_output=True, check=False, timeout=15)
            self.assertEqual(generated.returncode, 0, "test certificate generation failed")
            nonce = uuid.uuid4().hex
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    raw = (self.path + " " + nonce).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                def log_message(self, format, *args):
                    return None
            server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            worker = threading.Thread(target=server.serve_forever)
            worker.start()
            try:
                port = server.server_address[1]
                origin = "https://console.example.test:" + str(port)
                opener = case.dashboard_opener(origin, str(certificate), "127.0.0.1")
                with opener.open(origin + "/actual-read", timeout=3) as response:
                    self.assertEqual(response.read(), ("/actual-read " + nonce).encode())
                foreign = "https://foreign.example.test:" + str(port)
                opener = case.dashboard_opener(foreign, str(certificate), "127.0.0.1")
                with self.assertRaises(urllib.error.URLError, msg="TLS accepted a certificate for another hostname"):
                    with opener.open(foreign + "/foreign-read", timeout=3) as response:
                        response.read()
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=5)
            self.assertFalse(worker.is_alive(), "TLS test listener did not stop")

    def test_factory(self):
        proposal = {"lane": "original", "task": {"id": "published-task"}, "level": 5, "driver": "codex",
            "role": "supervisor", "budget": {"wall_ms": 100}, "expected_policy_generation": 1,
            "grants": {name: [] for name in ("resources", "data", "secrets", "profiles", "network", "channels")}}
        budget = {"wall_ms": 300000, "spend_micros": 0}
        owner = SimpleNamespace(lane_inputs=Path("/test/input"), human_prefix="itemdashboard",
            root_launch_input=lambda path: json.dumps({"codex": proposal,
                "claudock-cli": dict(proposal, driver="claudock-cli")}).encode(), decode_document=json.loads,
            dashboard_boot={"budget": budget, "project_id": "actual-dashboard-project"})
        data = data_module.from_checkpoint(owner, need, ValueError)
        self.assertEqual(set(data.launches), set(data_module.ACTIONS))
        self.assertEqual(len({row["lane"] for row in data.launches.values()}), 5)
        self.assertTrue(all(row["budget"] == budget for row in data.launches.values()),
                        "fixture factory lost the installed budget")
        self.assertTrue(all(row["task"] == proposal["task"] for row in data.launches.values()))
        self.assertTrue(all(not row.get("root_ticket_id") and not row.get("profile_grant_id") for row in data.launches.values()))
        self.assertEqual(data.prefix, "itemdashboard")
        self.assertTrue(callable(data.setup) and callable(data.reviews))
        self.assertEqual(data.launches["DASH-MERGED"]["driver"], "claudock-cli",
                         "review fixture lacks actual Claudock tool coverage")

    def test_review_missing(self):
        data = SimpleNamespace(read=Mock(return_value={"events": [], "complete": True}))
        with self.assertRaises(FixtureError) as error:
            data_module.review_inputs(data, {"life_id": "actual-life", "run": 1})
        self.assertEqual(error.exception.error["owner"], "lb-v2-grants")
        self.assertEqual(error.exception.error["code"], "prerequisite_missing")

    def test_native_proof(self):
        params = {"target": {"life_id": "life", "run": 1}, "expected_generation": 3}
        digest = case.request_digest("fixture", "lane.stop", params)
        intent = {"method": "lane.stop", "target_id": "life", "request_sha256": digest, "base_generation": 3}
        challenge = dict(intent, id="actual-challenge", expires_at="2030-01-01T00:00:00Z")
        proof = {"id": "actual-proof", "request_sha256": digest, "expires_at": challenge["expires_at"], "simulated_presence": True}
        for presence in (True, False):
            owner = SimpleNamespace(config="fixture", authenticator=Path("/test/authenticator"),
                human=SimpleNamespace(private=Path("/test/private")), keep_json=Mock(return_value=Path("/test/retained.json")),
                command=Mock(side_effect=[json.dumps(intent).encode(), b'{"challenge_id":"actual-challenge"}']))
            returned = dict(proof, simulated_presence=presence)
            session = SimpleNamespace(rpc=Mock(side_effect=[challenge, returned]))
            if presence:
                observed = producer.native_proof(owner, session, "lane.stop", params, "life", 3, need)
                self.assertEqual(observed, returned)
                self.assertEqual(session.rpc.call_args_list[0].args, ("human.challenge", intent))
                self.assertEqual(session.rpc.call_args_list[1].args[0], "human.confirm")
            else:
                with self.assertRaises(ValueError):
                    producer.native_proof(owner, session, "lane.stop", params, "life", 3, need)


if __name__ == "__main__":
    unittest.main()
