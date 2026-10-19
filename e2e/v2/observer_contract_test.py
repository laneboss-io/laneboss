#!/usr/bin/python3 -I
"""Outside-observer request contracts, not human authentication evidence."""

import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest


def module(name, case):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / "cases" / case / "run.py")
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class ObserverContracts(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="lb-v2-it2-observer-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.root.chmod(0o700)
        self.binding = self.root / "human.json"
        self.binding.write_text(json.dumps({"class": "human", "config": "observer-fixture"}))
        self.binding.chmod(0o600)
        self.context = {"binary": "/unused/test-client", "config": "observer-fixture",
            "test_root": str(self.root), "evidence_root": str(self.root / "evidence"),
            "binding_file": str(self.binding)}
        self.admin = module("admin_observer_contract", "admin")

    def observer(self):
        return self.admin.Observer(self.context, {}, self.root / "result.json")

    def test_child_event_selection(self):
        observer = self.observer()
        observer.child = {"life_id": "actual-prepared-child", "run": 7}
        selected = []

        def read(label, words, request):
            selected.append((request["life_id"], request["run"]))
            self.assertEqual(selected[-1], (observer.child["life_id"], observer.child["run"]),
                             "outside observer requested an unselected event stream")
            return {"complete": True, "events": []}

        observer.cli = read
        self.assertEqual(observer.events(), [])
        self.assertEqual(len(selected), 1)

    def test_event_foreign_stale_and_replay(self):
        for fault in ("foreign-life", "foreign-run", "stale", "replayed"):
            with self.subTest(fault=fault):
                observer = self.observer()
                observer.child = {"life_id": "actual-prepared-child", "run": 7}
                def read(label,words,request):
                    event = dict(observer.child, config=observer.context["config"],schema=2,seq=101)
                    if fault == "foreign-life": event["life_id"] = "another-child"
                    if fault == "foreign-run": event["run"] += 1
                    if fault == "stale": event["seq"] = 99
                    events = [event,event] if fault == "replayed" else [event]
                    return {"complete": True,"events":events}
                observer.cli = read
                with self.assertRaises(self.admin.Failed,msg="outside observer accepted foreign, stale or replayed events"):
                    observer.events(100)

    def test_missing_human_authority_stops(self):
        observer = self.observer()

        def forbidden(*args, **kwargs):
            self.fail("outside observer invoked a CLI without fresh human authority")

        observer.command = forbidden
        try:
            observer.cli("doctor", ["doctor"], {})
        except RuntimeError as error:
            self.assertEqual(getattr(error, "code", None), "prerequisite_missing")
            self.assertEqual(getattr(error, "step", None), "human_confirmation")
        else:
            self.fail("missing human authority was reported as completed")

    def test_actual_proof_file_forwarded(self):
        observer = self.observer()
        authority = self.root / "authority"
        authority.mkdir(mode=0o700)
        proof = authority / "000001.proof.json"
        proof.write_text(json.dumps({"id": "component-proof", "request_sha256": "a" * 64,
                                     "expires_at": "2030-01-01T00:00:00Z"}))
        proof.chmod(0o600)
        calls = []

        def execute(label, args, expected=None):
            calls.append(args)
            self.assertIn("--proof", args, "outside CLI omitted its actual proof file")
            selected = Path(args[args.index("--proof") + 1])
            self.assertEqual(selected, proof)
            return types.SimpleNamespace(returncode=0, stdout=json.dumps({"proof_id":
                json.loads(selected.read_bytes())["id"]}).encode(), stderr=b"")

        observer.command = execute
        self.assertEqual(observer.cli("doctor", ["doctor"], {}), {"proof_id": "component-proof"})
        self.assertEqual(len(calls), 1)

    def test_live_credentials_stop_at_owner(self):
        case = module("secrets_owner_contract", "secrets")
        context = dict(self.context, schema="laneboss.e2e-context.v2",case_id="secrets",
            phase="candidate",binary_sha256="a"*64,source_sha256="b"*64,profile_grant_ids=[])
        result = {"assertions": [{"evidence": []}, {"evidence": []}]}
        (self.root / "evidence").mkdir(mode=0o700)
        try:
            case.run_case(context,result)
        except RuntimeError as error:
            self.assertEqual(getattr(error,"code",None),"prerequisite_missing")
            self.assertEqual(getattr(error,"step",None),"vendor_authentication")
        else:
            self.fail("missing live authentication was reported as complete")


if __name__ == "__main__":
    unittest.main()
