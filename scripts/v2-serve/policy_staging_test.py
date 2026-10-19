"""Actual policy staging and its 1777-ancestor control; Linux root box only."""

import importlib.util
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
import urllib.request


def sibling(name, path=None):
    spec = importlib.util.spec_from_file_location(
        "staging_" + name, path or Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


provision = sibling("provision")
serve = sibling("run")
judge = sibling("policy_judge")


class PolicyStaging(unittest.TestCase):
    def exercise(self, stager):
        self.assertEqual(os.geteuid(), 0, "staging controls require the authorized Linux root box")
        with tempfile.TemporaryDirectory(prefix="lb-v2-policy-staging-", dir="/var/tmp") as directory:
            evidence = Path(directory)
            self.assertEqual(stat.S_IMODE(evidence.parent.stat().st_mode), 0o1777)
            case = serve.Case(Path(__file__).resolve().parents[2], evidence,
                              config="policy-staging-" + os.urandom(4).hex())
            case.stage = provision.stage(case.source, case.root)
            try:
                boot = stager.boot(case)
                handoff = getattr(case, "policy_judge_input", case.root / "policy-judge.input.json")
                raw = provision.read_protected(handoff, mode=0o600)
                self.assertEqual(raw, (case.root / "policy-judge.input.json").read_bytes())
                enrolled = stager.document(raw)
                self.assertEqual(enrolled["judge"], boot["enrollment"]["judge"])
                controller = Path(enrolled["controller"])
                private = Path(handoff).parent
                self.assertTrue(private.is_relative_to(case.stage))
                self.assertEqual(private.stat().st_uid, 0)
                self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
                self.assertEqual(controller.parent, private)
                self.assertEqual(stager.sha(provision.read_protected(controller, 64 << 20, mode=0o555)),
                                 enrolled["controller_sha256"])
                config = stager.document(provision.read_protected(
                    controller.with_name("policy-judge.config.json"), mode=0o600))
                self.assertEqual(config["config"], case.config)

                # Populate real HTTP evidence before using the outside controller.
                rule = os.urandom(8).hex()
                body = stager.encoded({"model": enrolled["judge"]["model"], "state": {
                    "context": {"config": case.config}, "rules": [{"id": rule, "text": "Public read."}],
                    "decisions": [], "commands": []}, "questions": {rule: {"type": "noul"}}})
                request = urllib.request.Request(case.policy_judge.endpoint + "/v1/systemone",
                    body, {"Content-Type": "application/json"})
                with urllib.request.urlopen(request, timeout=10) as response:
                    self.assertEqual(stager.document(response.read())["model"], enrolled["judge"]["model"])
                nonce = os.urandom(16).hex()
                for index, phase in enumerate(stager.OUTAGES):
                    raw = stager.encoded({"stage": phase, "config": case.config,
                        "nonce": nonce, "org_generation": index + 2})
                    control = provision.administrator_input(private, phase + ".request", raw)
                    self.assertEqual(provision.read_protected(control, mode=0o600), raw)
                    observed = stager.document(case.command("control-" + phase,
                        [str(controller), "--request", str(control)], clean=True))
                    self.assertEqual(observed["input_sha256"], stager.sha(raw))
                    self.assertEqual(observed["stage"], phase)
                    self.assertTrue(observed["evidence"])
                    for ref in observed["evidence"]:
                        self.assert_ref(case, private, ref)
                collected = case.policy_judge.close()
                self.assertTrue(collected["closed"])
                self.assertEqual(collected["errors"], [])
                self.assertTrue(collected["requests"])
                for ref in collected["evidence"]:
                    self.assert_ref(case, private, ref)
                self.assertEqual(stager.document(
                    (case.root / "policy-http/collection.json").read_bytes()), collected)
            finally:
                if hasattr(case, "policy_judge"):
                    case.policy_judge.close()
                shutil.rmtree(case.stage)

    def assert_ref(self, case, private, ref):
        path = Path(ref["path"])
        raw = provision.read_protected(path, ref["bytes"], mode=0o600)
        self.assertTrue(path.is_relative_to(private))
        self.assertEqual(len(raw), ref["bytes"])
        self.assertEqual(judge.sha(raw), ref["sha256"])
        self.assertEqual(raw, (case.root / "policy-http" / path.name).read_bytes())

    def test_policy_world_writable_stage(self):
        self.exercise(judge)
        print("GREEN: actual handoff, controller, config, requests and HTTP/control refs passed protected reads")
        path = Path(judge.__file__)
        original = path.read_bytes()
        before = b'private = runtime / "private"'
        after = b'private = case.root / "private"'
        self.assertEqual(original.count(before), 1, "staging mutation anchor is missing or ambiguous")
        with tempfile.TemporaryDirectory(prefix="lb-v2-policy-stager-control-") as directory:
            mutated = Path(directory) / "policy_judge.py"
            mutated.write_bytes(original.replace(before, after, 1))
            with self.assertRaisesRegex(ValueError, r"unprotected root staging path: /var/tmp$") as rejected:
                self.exercise(sibling("world_writable_judge", mutated))
            print("RED: actual stager moved back below a 1777 ancestor: " + str(rejected.exception))
        self.assertEqual(path.read_bytes(), original, "staging control changed candidate source")


if __name__ == "__main__":
    unittest.main()
