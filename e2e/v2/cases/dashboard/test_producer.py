"""Producer authority-boundary tests, distinct from installed acceptance."""

import errno
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import case
from fixture_io import FixtureError, private_write
from test_inputs import Recorder


SOURCE = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location("dash_producer", SOURCE / "scripts/v2-serve/case_dashboard.py")
producer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = producer
SPEC.loader.exec_module(producer)


class ProducerTests(unittest.TestCase):
    def test_bookkeeping(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            context = root / "context.json"
            context.write_text(json.dumps({"evidence_root": str(root / "evidence")}))
            rows = {"shared-check": {"check": "shared-check", "result": "pass"}}
            owner = SimpleNamespace(source=SOURCE, rows=rows, current="shared-check", human_prefix="shared")
            refusal = FixtureError({"owner": "fixture-owner", "code": "forbidden", "message": "exact"})
            def inner(*args):
                owner.current = "dashboard-step"
                owner.rows["dashboard-step"] = {"check": "dashboard-step", "result": "fail"}
                owner.human_prefix = "dashboard"
                raise refusal
            with patch.object(producer, "_run_checkpoint", side_effect=inner):
                with self.assertRaises(FixtureError) as failure:
                    producer.run_at_checkpoint(owner, context, root / "result.json", None, None)
            self.assertIs(failure.exception, refusal)
            self.assertIs(owner.rows, rows, "producer changed shared check registry")
            self.assertEqual(owner.current, "shared-check")
            self.assertEqual(owner.human_prefix, "shared")
            retained = json.loads((root / "evidence/producer/first-failure.json").read_bytes())
            self.assertEqual(retained["error"], refusal.error)

    def test_result(self):
        context = {"case_id": "dashboard", "binary_sha256": "51" * 32, "source_sha256": "52" * 32}
        result = {"schema": "laneboss.e2e-result.v2", **context, "phase": "candidate", "mutation_id": "",
            "assertions": [{"id": aid, "reached": True, "verdict": "pass", "observed_exit": 0} for aid in case.ASSERTION_IDS],
            "collection": {"processes_quiescent": True, "temporary_resources_collected": True}}
        producer.validate_result(result, context, case.ASSERTION_IDS)
        for field, bad in (("source_sha256", "different"), ("binary_sha256", "different"),
                           ("phase", "different"), ("assertions", []), ("collection", {})):
            changed = copy.deepcopy(result)
            changed[field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                producer.validate_result(changed, context, case.ASSERTION_IDS)
        for field, bad in (("reached", False), ("verdict", "fail"), ("observed_exit", 1), ("id", "unknown")):
            changed = copy.deepcopy(result)
            changed["assertions"][0][field] = bad
            with self.subTest(field=field), self.assertRaises(ValueError):
                producer.validate_result(changed, context, case.ASSERTION_IDS)

    def browser(self, root):
        root = Path(root).resolve()
        bootstrap = root / "bootstrap.json"
        private_write(bootstrap, {"config": "fixture", "token": "native-token", "connection_id": "native-connection",
            "nonce": "browser-bound-nonce", "actor": {"kind": "human", "id": "principal"},
            "proof": {"id": "service-proof", "expires_at": "2030-01-01T00:00:00Z",
                      "request_sha256": case.request_digest("fixture", "human.session", {})}})
        owner = SimpleNamespace(config="fixture", human=SimpleNamespace(public={"principal_id": "principal"}))
        handoff = SimpleNamespace(origin="https://console.example.test", ca_file=root / "ca.pem", bootstrap_file=bootstrap)
        with patch("case.dashboard_opener", return_value=SimpleNamespace()):
            return producer.Browser(owner, case, handoff, Recorder())

    def response(self, cookie="cookie-token", attributes="; Secure; HttpOnly; SameSite=Strict; Path=/", provenance=True):
        def reply(opener, url, **kwargs):
            if "/api/v2/tree" in url:
                return 200, {}, b'{"nodes":[]}'
            request = kwargs["body"]
            headers = {"Set-Cookie": "laneboss_session=" + cookie + attributes}
            if provenance:
                headers.update({"X-Laneboss-Presence": "simulated", "X-Laneboss-Human-Approval": "not_proven"})
            return 200, headers, json.dumps({"request_id": request["request_id"], "result": {
                "id": "session-record", "config": "fixture", "simulated_presence": True}}).encode()
        return reply

    def test_native_gate(self):
        with self.assertRaises(FixtureError) as failure:
            producer.check_handoff(None)
        self.assertEqual(failure.exception.error["owner"], "lb-v2-service")
        self.assertEqual(failure.exception.error["code"], "prerequisite_missing")

    def test_cookie(self):
        with tempfile.TemporaryDirectory() as directory:
            browser = self.browser(directory)
            with patch("case.http_call", side_effect=self.response()):
                session = browser.bootstrap()
            self.assertEqual(session["id"], "session-record")
            self.assertEqual(browser.cookie, "laneboss_session=cookie-token")
        for cookie, attributes, provenance in (
                ("session-record", "; Secure; HttpOnly; SameSite=Strict; Path=/", True),
                ("cookie-token", "; HttpOnly; SameSite=Strict; Path=/", True),
                ("cookie-token", "; Secure; SameSite=Strict; Path=/", True),
                ("cookie-token", "; Secure; HttpOnly; SameSite=Lax; Path=/", True),
                ("cookie-token", "; Secure; HttpOnly; SameSite=Strict; Path=/other", True),
                ("cookie-token", "; Secure; HttpOnly; SameSite=Strict; Path=/", False)):
            with tempfile.TemporaryDirectory() as directory:
                browser = self.browser(directory)
                with patch("case.http_call", side_effect=self.response(cookie, attributes, provenance)):
                    with self.subTest(cookie=cookie, attributes=attributes), self.assertRaises(ValueError):
                        browser.bootstrap()

    def test_bootstrap_owner_error(self):
        with tempfile.TemporaryDirectory() as directory:
            browser = self.browser(directory)
            refusal = {"owner": "fixture-owner", "code": "forbidden", "message": "native bootstrap refused"}
            with patch("case.http_call", return_value=(403, {}, json.dumps({"error": refusal}).encode())):
                with self.assertRaises(FixtureError) as failure:
                    browser.bootstrap()
            self.assertEqual(failure.exception.error, refusal, "native bootstrap refusal was reworded")

    def test_https_origin(self):
        with_user = "https://{0}:{1}@{2}".format("fixture", "unused", "console.example.invalid")
        for origin in ("http://console.example.test", with_user,
                       "https://console.example.test/path", "https://console.example.test?token=1"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                case.dashboard_opener(origin)

    def test_collection_processes(self):
        # Real child ownership and wait status, with the HTTP/native response
        # mocked only in this unit. No installed service authority is claimed.
        with subprocess.Popen(["/bin/sleep", "30"]) as session, subprocess.Popen(["/bin/sleep", "30"]) as listener:
            handoff = producer.HTTPSHandoff("https://console.example.test", Path("/unused"), Path("/unused"),
                session, listener, session.terminate, listener.terminate)
            producer.check_handoff(handoff)
            browser = SimpleNamespace(handoff=handoff, consumer=case, opener=None,
                                      origin=handoff.origin, cookie="unit-cookie")
            raw = b'{"error":{"code":"unauthenticated","message":"native connection closed"}}'
            with patch("case.http_call", return_value=(401, {}, raw)), \
                    patch.object(producer.socket, "create_connection", side_effect=OSError(errno.ECONNREFUSED, "closed")):
                observed = producer.collect_https(browser)
            self.assertIsNotNone(session.poll(), "native session child survived collection")
            self.assertIsNotNone(listener.poll(), "HTTPS listener child survived collection")
            self.assertEqual(observed["session_pid"], session.pid)
            self.assertEqual(observed["listener_pid"], listener.pid)
            self.assertEqual(observed["listener_errno"], errno.ECONNREFUSED, "listener closure evidence did not use actual errno")


if __name__ == "__main__":
    unittest.main()
