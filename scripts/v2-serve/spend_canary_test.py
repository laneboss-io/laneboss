"""Harness controls; execute only on the disposable Linux box as root.

The CLI boundary is recorded here, not represented as an installed-service
measurement. The installed serve entry must independently obtain its receipt.
"""

from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid


spec = importlib.util.spec_from_file_location(
    "serve_spend_controls", Path(__file__).resolve().with_name("run.py"))
serve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(serve)


class SpendCanary(unittest.TestCase):
    def roots(self):
        temporary = tempfile.TemporaryDirectory(
            prefix="lb-v2-r3canary-", dir="/opt")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        evidence = root / "evidence"
        evidence.mkdir(mode=0o700)
        return root, evidence

    def balance(self):
        return {
            "credential_id": "canary-api-pool", "seed_micros": 10000000,
            "spent_micros": 0, "reading_micros": 10000000,
            "remaining_micros": 10000000, "floor_micros": 5000000,
            "generation": 1, "needs_reading": False,
            "observed_at": datetime.now(timezone.utc).isoformat(),
        }

    def case(self):
        root, evidence = self.roots()
        case = serve.Case.__new__(serve.Case)
        case.root, case.admin_inputs = evidence, root
        case.api_key_canary = SimpleNamespace(retainable=lambda data: data)
        case.current = "admin.publication"
        case.rows = {case.current: {
            "result": "pass", "observed": {"valid": True, "problems": []}}}
        case.initial = {"profiles": {"id": "published-profiles"}}
        profile = "canary-" + uuid.uuid4().hex[:12]
        profiles = {"profiles": [
            {"driver": "claudock-cli", "profile_id": profile},
            {"driver": "codex", "profile_id": "other-profile"}]}

        def read(ref):
            self.assertEqual(ref, case.initial["profiles"])
            return serve.encoded(profiles)

        case.publication_blob = read
        case.calls = []
        case.last = None

        def admin(mode, request):
            case.calls.append((mode, request))
            case.last = {"exit_code": 0, "label": mode}
            return self.balance()

        case.admin_call = admin
        return case, profile, profiles

    def method(self, case):
        method = getattr(case, "reconcile_canary_spend", None)
        self.assertTrue(callable(method),
                        "canary never enrolls an operator balance reading")
        return method

    def test_protected_fake_tool(self):
        root, evidence = self.roots()
        factory = getattr(serve.provision, "canary_balance", None)
        self.assertTrue(callable(factory),
                        "canary lacks a protected fake balance executable")
        profile = "profile-" + uuid.uuid4().hex[:12]
        request = factory(root, evidence, profile)
        self.assertEqual(request["profile_ids"], [profile])
        self.assertEqual(request["credential_id"], "canary-api-pool")
        self.assertEqual(request["selector"], "CANARY")
        self.assertEqual(request["floor_micros"], 5000000)
        self.assertEqual(set(request), {
            "command", "selector", "credential_id", "profile_ids",
            "floor_micros"})
        tool = Path(request["command"])
        self.assertEqual(tool.parent, root)
        self.assertEqual(stat.S_IMODE(tool.stat().st_mode), 0o700)
        self.assertEqual(tool.stat().st_uid, 0)
        self.assertEqual(tool.stat().st_nlink, 1)
        self.assertIn(b"fake", tool.read_bytes().lower())
        output = subprocess.check_output([str(tool)])
        self.assertEqual(output, b"CANARY  10.00 USD\n")
        self.assertEqual((evidence / "canary-balance.input.sh").read_bytes(),
                         tool.read_bytes())

    def test_published_profile_and_receipt(self):
        case, profile, _ = self.case()
        self.method(case)()
        self.assertEqual(len(case.calls), 1)
        mode, request = case.calls[0]
        self.assertEqual(mode, "spend-reconcile")
        self.assertEqual(request["profile_ids"], [profile])
        self.assertTrue(Path(request["command"]).is_file())
        observed = case.rows[case.current]["observed"]
        self.assertTrue(observed["valid"])
        self.assertEqual(observed["problems"], [])
        reading = observed["canary_spend"]
        self.assertTrue(reading["fake_reading"])
        self.assertEqual(reading.get("purpose"), "credential setup only; does not prove the agent ran")
        self.assertEqual(reading["balance"]["remaining_micros"], 10000000)
        declaration = json.loads(
            (case.root / "canary-spend.fixture.json").read_bytes())
        self.assertTrue(declaration["fake_reading"])
        self.assertFalse(declaration["authenticated_service"])
        self.assertEqual(declaration["profile_ids"], [profile])

    def test_bad_receipt_stops(self):
        bad = (
            {"credential_id": "unrelated-pool"}, {"seed_micros": 0},
            {"spent_micros": 1}, {"reading_micros": 0},
            {"remaining_micros": 5000000}, {"floor_micros": 0},
            {"generation": 0}, {"generation": True},
            {"needs_reading": True},
            {"accounting_error": {"code": "integrity_error"}},
            {"observed_at": ""},
        )
        for changed in bad:
            with self.subTest(field=next(iter(changed))):
                case, _, _ = self.case()
                method = self.method(case)
                reply = dict(self.balance(), **changed)
                case.admin_call = lambda *_: reply
                with self.assertRaises(serve.Failed):
                    method()

    def test_cli_refusal_stops(self):
        case, _, _ = self.case()
        method = self.method(case)

        def refuse(*_):
            raise serve.Failed("recorded administrator refusal")

        case.admin_call = refuse
        with self.assertRaisesRegex(serve.Failed, "administrator refusal"):
            method()
        self.assertNotIn("canary_spend", case.rows[case.current]["observed"])

    def test_profile_scope_stops(self):
        for missing in (True, False):
            with self.subTest(missing=missing):
                case, _, profiles = self.case()
                method = self.method(case)
                if missing:
                    profiles["profiles"] = profiles["profiles"][1:]
                else:
                    profiles["profiles"].append(profiles["profiles"][0])
                with self.assertRaises(serve.Failed):
                    method()
                self.assertEqual(case.calls, [])

    def test_no_canary_no_reading(self):
        case, _, _ = self.case()
        method = self.method(case)
        case.api_key_canary = None
        method()
        self.assertEqual(case.calls, [])
        self.assertEqual(list(case.root.iterdir()), [])

    def test_before_lane_dispatch(self):
        case = serve.Case.__new__(serve.Case)
        reached = []
        for name in ("install", "prepare_human", "publish_initial",
                     "reconcile_canary_spend"):
            setattr(case, name, lambda name=name: reached.append(name))
        case.human = SimpleNamespace(enroll=lambda: reached.append("enroll"))
        case.suite = "lifecycle"
        case.item_module = None
        with patch.object(serve.flow, "run",
                          side_effect=lambda *_: reached.append("lane")):
            case.run()
        self.assertEqual(reached, [
            "install", "prepare_human", "enroll", "publish_initial",
            "reconcile_canary_spend", "lane"],
            "lane dispatch reached before spend enrollment")

    def test_installed_admin_route(self):
        case, _, _ = self.case()
        case.config = "canary-controls"
        case.binary = case.admin_inputs / "laneboss"
        case.installation_file = case.admin_inputs / "installation.json"
        case.installed = {"binding_file": str(case.admin_inputs / "binding")}
        case.index = 0
        case.receipts = []
        calls = []

        def command(label, argv, **options):
            calls.append((label, argv, options))
            case.last = {"exit_code": 0}
            return serve.encoded(self.balance())

        case.command = command
        request = {"command": "/opt/fake-balance", "selector": "CANARY",
                   "credential_id": "canary-api-pool",
                   "profile_ids": ["profile-one"], "floor_micros": 5000000}
        with patch.object(serve.provision, "path_metadata", return_value=[]):
            serve.Case.admin_call(case, "spend-reconcile", request)
        self.assertEqual(len(calls), 1)
        label, argv, options = calls[0]
        self.assertEqual(label, "spend-reconcile")
        self.assertEqual(argv[:-1], [
            str(case.binary), "internal", "helper", "--config", case.config,
            "--installation", str(case.installation_file), "--spend-reconcile"])
        path = Path(argv[-1])
        self.assertEqual(json.loads(path.read_bytes()), request)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertTrue(options["clean"])
        self.assertIsNone(options["expected"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
