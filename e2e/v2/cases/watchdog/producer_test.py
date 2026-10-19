"""Fixture/transport regressions. These units establish no installed pass."""

import base64
import copy
from datetime import datetime, timedelta, timezone
import io
import inspect
import importlib.util
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

MODULES = Path(os.environ.get("WD_MODULE_ROOT", Path(__file__).resolve().parents[4] / "scripts/v2-serve"))
sys.path.insert(0, str(MODULES))
import case_watchdog as producer
import wd_control as control
import wd_runner as runner
import wd_usage as usage
from controls import Controller, ControlError
from reader import SocketReader


class Delivery(unittest.TestCase):
    def test_case_owned_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            uid = os.getuid()
            outside = uid + 100000
            context = {"controls": str(root / "controller.json"), "case_id": "watchdog", "config": "fixture-case",
                       "binary_sha256": secrets.token_hex(32), "source_sha256": secrets.token_hex(32)}
            binding = {"schema": "laneboss.e2e-control-binding.v2", "case_id": "watchdog", "config": context["config"],
                       "socket": str(root / "control.sock"), "generation": 1, "controller_uid": outside, "case_uid": uid,
                       "binary_sha256": context["binary_sha256"], "source_sha256": context["source_sha256"], "live_auth": False,
                       "service_ids": ["service-one"], "canary_ids": ["canary-one"], "fixture_clock_ids": []}
            usage.save(Path(context["controls"]), usage.wire(binding))
            controller = Controller(context, lambda *_: None)
            self.assertEqual(controller.binding["controller_uid"], outside)
            reader_binding = {"schema": "laneboss.watchdog-reader.v1", "config": context["config"],
                              "socket": str(root / "reader.sock"), "reader_uid": outside, "case_uid": uid,
                              "binary_sha256": context["binary_sha256"], "simulated_presence": True}
            path = root / "reader.json"
            usage.save(path, usage.wire(reader_binding))
            reader = SocketReader(context, str(path), lambda *_: None)
            self.assertEqual(reader.binding["reader_uid"], outside)
            binding["case_uid"] = outside
            usage.save(Path(context["controls"]), usage.wire(binding))
            with self.assertRaises(ControlError):
                Controller(context, lambda *_: None)


class G0Contract(unittest.TestCase):
    def test_exports(self):
        self.assertTrue(callable(getattr(producer, "boot", None)), "G0 boot producer is missing")
        self.assertEqual(tuple(inspect.signature(producer.prepare).parameters), ("case", "require", "fail", "blocked"))
        self.assertTrue(callable(getattr(producer, "abort", None)), "G0 measured abort collector is missing")

    def test_launcher_two_profiles(self):
        # Exercise the published launch binder with the producer's actual
        # declaration. Boot uses real root staging; no service grant, native
        # scope, worker frame or installed result is simulated.
        spec = importlib.util.spec_from_file_location("wd_serve_launcher", MODULES / "run.py")
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        with tempfile.TemporaryDirectory() as temporary, \
             tempfile.TemporaryDirectory(prefix="lb-v2-case-watchdog-g0-", dir="/opt") as staged:
            case = launcher.Case.__new__(launcher.Case)
            case.root, case.stage = Path(temporary), Path(staged)
            shutil.copytree(MODULES.parents[1] / "templates", case.stage / "templates")
            declared = producer.boot(case)["bundle"]["root_grants"]
            self.assertEqual(len([p for p in declared["profiles"] if p["driver"] == "claudock-cli"]), 2)
            case.generated_launches, case.egress_anthropic = True, False
            case.initial_receipt, case.initial = {"generation": 1}, {"profiles": {"id": "wd-profiles"}}
            case.human_prefix = "itemwatchdog"
            inputs = case.root / "initial-inputs"
            inputs.mkdir(mode=0o700)
            usage.save(inputs / "wd-profiles", usage.wire(declared))
            issued = {name: [] for name in ("resources", "data", "secrets", "profiles", "network", "channels")}
            issued["policy_generation"] = 1
            for name in tuple(issued):
                if name == "policy_generation":
                    continue
                for row in declared[name]:
                    issued[name].append({**row, "id": secrets.token_hex(16)})
            def proposal(driver="claudock-cli"):
                return {"driver": driver, "profile_grant_id": "", "grants": {name: [] for name in issued if name != "policy_generation"}}

            request = proposal()
            try:
                case.bind_root_launch(request, issued)
            except launcher.Failed as error:
                self.fail("published G0 launcher cannot bind the watchdog inventory: " + str(error))
            selected = next(p for p in issued["profiles"] if p["id"] == request["profile_grant_id"])
            self.assertEqual(selected["profile_id"], "serve-profile-claudock-cli")
            self.assertEqual(case.fixture_profile_selectors["claudock-cli"], selected["profile_id"])
            self.assertNotIn("profile_id", request, "fixture metadata escaped into a public launch request")

            # Select another declared profile through the same generic binder;
            # its input order and the canonical fixture name confer no default.
            case.fixture_profile_selectors = {"claudock-cli": "wd-profile-b"}
            case.human_prefix = "wd-explicit-b"
            other = proposal()
            try:
                case.bind_root_launch(other, issued)
            except launcher.Failed as error:
                self.fail("explicit second profile was refused: " + str(error))
            selected_b = next(p for p in issued["profiles"] if p["id"] == other["profile_grant_id"])
            self.assertEqual(selected_b["profile_id"], "wd-profile-b")
            self.assertNotEqual(other["profile_grant_id"], request["profile_grant_id"])

            for selector in (None, "", "undeclared-profile", "serve-profile-codex", selected_b["id"], 7):
                with self.subTest(refused_selector=selector):
                    case.fixture_profile_selectors = {} if selector is None else {"claudock-cli": selector}
                    refused = proposal()
                    before = copy.deepcopy(refused)
                    with self.assertRaises(launcher.Failed):
                        case.bind_root_launch(refused, issued)
                    self.assertEqual(refused, before, "refused selection mutated the public proposal")

            case.fixture_profile_selectors = {"claudock-cli": "serve-profile-claudock-cli"}
            changed = copy.deepcopy(issued)
            next(p for p in changed["profiles"] if p["profile_id"] == "wd-profile-b")["provider"] = "foreign"
            with self.assertRaisesRegex(launcher.Failed, "approved fixture scope"):
                case.bind_root_launch(proposal(), changed)

            # Existing one-profile drivers still bind without selector metadata.
            del case.fixture_profile_selectors
            case.human_prefix = "wd-unique-codex"
            unique = proposal("codex")
            case.bind_root_launch(unique, issued)
            selected_unique = next(p for p in issued["profiles"] if p["id"] == unique["profile_grant_id"])
            self.assertEqual(selected_unique["profile_id"], "serve-profile-codex")


class Producer(unittest.TestCase):
    def test_usage_uid_enrollment(self):
        with tempfile.TemporaryDirectory() as temporary:
            uid = os.getuid()
            ledger = usage.Ledger(temporary, ["profile-a", "profile-b"], case_uid=uid+1,
                                  runner_uids=[uid+2], usage_uid=None)
            enrollment = {"schema": "laneboss.wd-enroll.v1", "lease_id": "actual-lease",
                          "uid": uid+2, "active": True}
            with self.assertRaises(usage.Gate):
                ledger.enroll(uid+2, enrollment)
            ledger.enroll(0, enrollment)
            self.assertEqual(ledger.usage_uids, {uid+2})
            changed = dict(enrollment, uid=uid+3)
            with self.assertRaises(usage.Gate):
                ledger.enroll(0, changed)
            ledger.enroll(0, dict(enrollment, active=False))
            self.assertFalse(ledger.usage_uids)

    def test_profile_affinity(self):
        expiry = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
        profiles = [{"id": "grant-a", "profile_id": "profile-a", "driver": "claudock-cli", "provider": "fixture",
                     "delegate": True, "paid": False, "expires_at": expiry},
                    {"id": "grant-b", "profile_id": "profile-b", "driver": "claudock-cli", "provider": "fixture",
                     "delegate": True, "paid": False, "expires_at": expiry}]
        self.assertEqual(producer.selected_profiles({"profiles": profiles}, ["grant-a", "grant-b"]), profiles)
        for field, value in (("driver", "codex"), ("provider", "foreign"), ("delegate", False),
                             ("paid", True), ("profile_id", "profile-a"), ("expires_at", "2000-01-01T00:00:00Z")):
            changed = copy.deepcopy(profiles)
            changed[1][field] = value
            with self.subTest(field=field), self.assertRaises(usage.Gate):
                producer.selected_profiles({"profiles": changed}, ["grant-a", "grant-b"])

    def ledger(self, root):
        uid = os.getuid()
        return usage.Ledger(root, ["profile-a", "profile-b"], case_uid=uid + 1,
                            runner_uids=[uid + 2], usage_uid=uid + 3, capacity=11)

    def test_quota_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = self.ledger(root)
            nonce = secrets.token_hex(16)
            def phase(value):
                data = usage.wire({"cell": "no-room", "phase": value, "nonce": nonce})
                # State-machine unit: outside file ownership has its own
                # private-file and native identity checks, not this double.
                read = usage.private
                with patch.object(usage, "private", side_effect=lambda path, *a, **k: data if path == root / "phase.json" else read(path, *a, **k)):
                    ledger.control(root / "phase.json")
            phase("seed")
            phase("ready")
            phase("exhausted")
            first = copy.deepcopy(ledger.state)
            phase("exhausted")
            self.assertEqual(ledger.state, first, "phase replay changed the durable timer input")
            rebuilt = self.ledger(root)
            self.assertEqual(rebuilt.state, first, "provider restart restored room without authority")
            request = {"schema": "laneboss.wd-provider.v1", "op": "poll", "request_id": secrets.token_hex(16),
                       "profile_id": "profile-b", "cell": "no-room"}
            measured = ledger.request(os.getuid() + 2, request)["result"]
            self.assertEqual(measured["action"], "limit")
            self.assertEqual(measured["used"], measured["capacity"])
            request["op"] = "usage"
            with self.assertRaisesRegex(usage.Gate, "outside usage worker"):
                ledger.request(os.getuid() + 2, request)
            response = ledger.request(os.getuid() + 3, request)["result"]
            raw = base64.b64decode(response["raw"], validate=True)
            self.assertEqual(usage.digest(raw), response["sha256"])
            self.assertEqual(len(raw), response["bytes"])
            self.assertEqual([row.split(b"\t")[3] for row in raw.splitlines()[1:]], [b"100", b"100"])
            phase("restored")
            request["op"] = "poll"
            response = ledger.request(os.getuid() + 2, request)["result"]
            self.assertEqual(response["action"], "complete")
            self.assertEqual(response["used"], 1)
            with self.assertRaises(usage.Gate):
                phase("exhausted")

    def fixture(self, root):
        args = SimpleNamespace(config="fixture-case", binding=str(root / "outside.json"), run=1,
            history=secrets.token_hex(8), session=secrets.token_hex(8), vendor_session=secrets.token_hex(8),
            home=secrets.token_hex(8), life=secrets.token_hex(8), wait_ms=1000, driver="claudock-cli", client="unused")
        enrollment = {"schema": "laneboss.wd-runner.v1", "vendor_stood_in": True, "provider_socket": str(root / "quota.sock"),
                      "provider_uid": os.getuid() + 1, "history_dir": "history", "canary": {}}
        return runner.Fixture(args, enrollment)

    def test_history(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"HOME": temporary}):
            fixture = self.fixture(Path(temporary))
            nonce = secrets.token_hex(16)
            prompt = ("Cell: limit\nHistory nonce: " + nonce + "\n").encode()
            first = fixture.history(prompt)
            fixture.args.run = 2
            injected = ("Cell: limit\nHistory nonce: " + secrets.token_hex(16) + "\n").encode()
            continued = fixture.history(injected)
            self.assertEqual(continued, first, "continued token was copied from a later prompt")
            self.assertEqual(continued["nonce"], nonce)
            fixture.args.home = secrets.token_hex(8)
            with self.assertRaisesRegex(usage.Gate, "retained identity"):
                fixture.history(injected)

    def test_limit_is_observed(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"HOME": temporary}):
            fixture = self.fixture(Path(temporary))
            nonce = secrets.token_hex(16)
            fixture.history(("Cell: limit\nHistory nonce: " + nonce + "\n").encode())
            fixture.args.run = 2
            output = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
            with patch.object(fixture, "selected_profile", return_value="profile-a"), \
                 patch.object(runner, "query", return_value={"action": "limit", "used": 4, "capacity": 11}), \
                 patch.object(sys, "stdout", output):
                with self.assertRaisesRegex(usage.Gate, "observed exhaustion"):
                    fixture.run(b"Continue retained history.\n")
            output.seek(0)
            self.assertFalse(any(usage.parse(line).get("is_error") is True for line in output.buffer.getvalue().splitlines()))

    def test_exact_empty_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "stdout"
            usage.save(path, b"")
            self.assertEqual(path.read_bytes(), b"")
            path.chmod(0o644)
            with self.assertRaises(usage.Gate):
                usage.private(path, {os.getuid()}, allow_empty=True)


class Restart(unittest.TestCase):
    def test_old_exit_is_independent(self):
        children = []
        def start():
            child = subprocess.Popen([sys.executable, "-I", "-B", str(Path(__file__).with_name("wait_probe.py"))],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            children.append(child)
            self.assertEqual(child.stdout.readline(), b"ready\n")
            return child
        try:
            old = start()
            first = control.process(old.pid)
            time.sleep(0.02)
            new = start()
            second = control.process(new.pid)
            self.assertGreater(second["generation"], first["generation"])
            controller = control.FixedController.__new__(control.FixedController)
            controller.enrollment = {"service_id": "service-one", "unit": "unused"}
            selected = iter([(first, []), (second, [])])
            controller.service = lambda: next(selected)
            controller.command = lambda _: (b"", [])
            native_poll = control.select.poll
            class BoundedPoll:
                def __init__(self):
                    self.poller = native_poll()
                def register(self, *args):
                    self.poller.register(*args)
                def poll(self, _):
                    return self.poller.poll(20)
            with patch.object(control.select, "poll", BoundedPoll):
                with self.assertRaisesRegex(usage.Gate, "old service process did not actually exit"):
                    controller.restart({"service_id": "service-one", "expected_generation": first["generation"]})
            self.assertIsNone(old.poll())
            selected = iter([(first, []), (second, [])])
            controller.service = lambda: next(selected)
            def exit_old(_):
                old.stdin.close()
                old.stdin = None
                self.assertEqual(old.wait(timeout=5), 0)
                return b"", []
            controller.command = exit_old
            result = controller.restart({"service_id": "service-one", "expected_generation": first["generation"]})
            self.assertTrue(result["old_exited"])
            self.assertEqual(result["old_pid"], old.pid)
            self.assertEqual(result["new_pid"], new.pid)
            self.assertEqual(result["current_generation"], second["generation"])
        finally:
            for child in children:
                if child.poll() is None:
                    child.terminate()
                child.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
