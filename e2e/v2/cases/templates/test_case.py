"""Case-input routing tests. These fixtures do not authenticate a real endpoint."""

import json
from pathlib import Path
import tempfile
import unittest

import run as case_module


class ProbeCase(case_module.Case):
    def __init__(self, context, enrolled):
        super().__init__(context)
        self.enrolled, self.probes = enrolled, []

    def command(self, words, request, **options):
        if words != ["identity", "self"] or request != {}:
            raise AssertionError("caller fixture attempted an unrelated operation")
        binding = options["caller"]["binding_file"]
        self.probes.append(binding)
        return self.enrolled[binding]


class CaseInputs(unittest.TestCase):
    def context(self, directory):
        root = Path(directory).resolve(strict=True)
        test, evidence = root / "inputs", root / "evidence"
        test.mkdir(mode=0o700)
        evidence.mkdir(mode=0o700)
        primary = test / "primary.json"
        primary.write_text("{}")
        primary.chmod(0o600)
        return {"test_root": str(test), "evidence_root": str(evidence),
                "binding_file": str(primary), "config": "case-templates"}

    def test_policy_uses_session(self):
        with tempfile.TemporaryDirectory() as directory:
            context = self.context(directory)
            case = case_module.Case(context)
            proof = {"id": "session-one", "request_sha256": case_module.digest(b"fixture session intent"),
                     "expires_at": "2030-01-01T00:10:00Z"}
            path = Path(context["test_root"]) / "session.json"
            path.write_text(json.dumps(proof))
            path.chmod(0o600)
            case.setup_callers({"reader_kind": "human", "session_proofs": [path.name]})
            args = case.proof_args(["policy", "evaluate"], {"fixture": "preview"},
                                   "commands/001", case.default_caller)
            self.assertEqual(args[0], "--idempotency-key")
            self.assertRegex(args[1], r"^[A-Za-z0-9_-]{22,128}$")
            self.assertEqual(args[2], "--proof")
            self.assertEqual(Path(args[3]).read_bytes(), path.read_bytes())
            self.assertEqual(case.default_caller["session_proofs"], [])
            case.assertions[case.current]["reached"] = True
            with self.assertRaisesRegex(case_module.CaseFailure, "fresh connection-session proof"):
                case.proof_args(["policy", "evaluate"], {}, "commands/002", case.default_caller)
            self.assertFalse(case.assertions[case.current]["reached"])

    def test_separate_callers(self):
        with tempfile.TemporaryDirectory() as directory:
            context = self.context(directory)
            root = Path(context["test_root"]).resolve(strict=True)
            enrolled = {}
            for name, level, life in (("fallback", 3, "fallback-life"), ("reviewer", 6, "l6-life")):
                path = root / (name + ".json")
                path.write_text("{}")
                path.chmod(0o600)
                enrolled[str(path)] = {"config": context["config"],
                    "actor": {"kind": "lane", "level": level, "life_id": life, "role": "executor"}}
            case = ProbeCase(context, enrolled)
            case.setup_callers({"reader_kind": "human", "session_proofs": []})
            first = case.caller({"binding_file": "fallback.json", "reader_kind": "lane"})
            second = case.caller({"binding_file": "reviewer.json", "reader_kind": "lane"})
            self.assertEqual(first["identity"]["actor"]["life_id"], "fallback-life")
            self.assertEqual(second["identity"]["actor"]["level"], 6)
            self.assertNotEqual(first["binding_file"], second["binding_file"])
            self.assertEqual(case.default_caller["binding_file"], context["binding_file"])
            self.assertEqual(case.default_caller["reader_kind"], "human")
            self.assertIs(first, case.caller({"binding_file": "fallback.json", "reader_kind": "lane"}))
            self.assertEqual(len(case.probes), 2)

    def test_caller_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            context = self.context(directory)
            case = case_module.Case(context)
            case.setup_callers({"reader_kind": "human"})
            case.assertions[case.current]["reached"] = True
            with self.assertRaisesRegex(case_module.CaseFailure, "escapes its scope"):
                case.caller({"binding_file": "../outside", "reader_kind": "lane"})
            self.assertFalse(case.assertions[case.current]["reached"])

    def test_symlink_root(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve(strict=True)
            real = base / "real"
            real.mkdir(mode=0o700)
            context = self.context(real)
            alias = base / "alias"
            alias.symlink_to(real, target_is_directory=True)
            context["test_root"] = str(alias / "inputs")
            context["evidence_root"] = str(alias / "evidence")
            context["binding_file"] = str(alias / "inputs" / "primary.json")
            primary = str(Path(context["binding_file"]).resolve(strict=True))
            fallback = Path(context["test_root"]) / "fallback.json"
            fallback.write_text("{}")
            fallback.chmod(0o600)
            enrolled = {
                primary: {"config": context["config"], "actor": {"kind": "human"}},
                str(fallback.resolve(strict=True)): {"config": context["config"],
                    "actor": {"kind": "lane", "life_id": "fallback-life", "level": 3}},
            }
            case = ProbeCase(context, enrolled)
            case.setup_callers({"reader_kind": "human"})
            self.assertEqual(case.default_caller["binding_file"], primary)
            self.assertIs(case.callers[primary], case.default_caller)
            selected = case.caller({"binding_file": "primary.json", "reader_kind": "human"})
            self.assertIs(selected, case.default_caller)
            fallback_caller = case.caller({"binding_file": "fallback.json", "reader_kind": "lane"})
            self.assertEqual(fallback_caller["identity"]["actor"]["life_id"], "fallback-life")
            self.assertEqual(case.probes, [primary, str(fallback.resolve(strict=True))])


if __name__ == "__main__":
    unittest.main()
