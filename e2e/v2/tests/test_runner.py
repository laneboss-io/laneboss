"""Harness controls. These tests are not product/service acceptance evidence."""

import copy
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "e2e" / "v2"))

import artifacts
import box
import box_support
from manifests import discover, result_file
from suite import load_suite, module_paths, validate_child
from support import Failure, evidence, load, save, sha256


# Deliberate discovery-only fixture: a test with no public CLI must not pass
# when executed. It is never a product case or an acceptance runner.
MODULE = ("from box_support import BlackBoxCase\n"
          "class Row(BlackBoxCase):\n"
          "    def test_red_no_cli(self):\n"
          "        return\n")


class DiscoveryControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "test_smoke.py").write_text(MODULE)

    def test_default_empty_module(self):
        (self.root / "test_empty.py").write_text("class NotATest:\n    value = 1\n")
        with self.assertRaisesRegex(Failure, "zero tests"):
            load_suite(self.root, [])
        (self.root / "test_empty.py").write_text(MODULE.replace("Row", "Other"))
        self.assertEqual(load_suite(self.root, []).countTestCases(), 2)

    def test_named_empty_module(self):
        (self.root / "test_empty.py").write_text("value = 1\n")
        with self.assertRaisesRegex(Failure, "zero tests"):
            load_suite(self.root, ["test_empty"])
        self.assertEqual(load_suite(self.root, ["test_smoke"]).countTestCases(), 1)

    def test_wrong_method_name(self):
        (self.root / "test_method.py").write_text(MODULE.replace("test_red_no_cli", "check_red"))
        with self.assertRaisesRegex(Failure, "zero tests"):
            load_suite(self.root, [])

    def test_bad_filename(self):
        (self.root / "test_bad-name.py").write_text(MODULE)
        with self.assertRaisesRegex(Failure, "module name"):
            module_paths(self.root, [])

    def test_nested_module(self):
        (self.root / "nested").mkdir()
        (self.root / "nested" / "test_hidden.py").write_text(MODULE)
        with self.assertRaisesRegex(Failure, "nested"):
            module_paths(self.root, [])

    def test_foreign_base(self):
        (self.root / "test_foreign.py").write_text(MODULE.replace(
            "from box_support import BlackBoxCase",
            "from unittest import TestCase as BlackBoxCase"))
        with self.assertRaisesRegex(Failure, "black-box base"):
            load_suite(self.root, [])

    def test_import_exit_is_child_only(self):
        # A real process exits 0 before writing a completion record.
        result = subprocess.run([sys.executable, "-I", "-c", "import os; os._exit(0)"],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        selected = self.root / "selected.json"
        save(selected, ["red"])
        with self.assertRaises(FileNotFoundError):
            validate_child(selected, self.root / "absent.json", result.returncode)

    def test_partial_child_is_not_success(self):
        selected, result = self.root / "selected.json", self.root / "result.json"
        save(selected, ["one", "two"])
        value = {"selected_ids": ["one", "two"], "started_ids": ["one"],
                 "completed_ids": ["one"], "tests_run": 1, "successful": True,
                 "cli_calls": {"one": 1}, "failures": 0, "errors": 0}
        save(result, value)
        with self.assertRaisesRegex(Failure, "omitted"):
            validate_child(selected, result, 0)
        value.update({"started_ids": ["one", "two"], "completed_ids": ["one", "two"],
                      "tests_run": 2, "cli_calls": {"one": 1, "two": 1}})
        save(result, value)
        self.assertEqual(validate_child(selected, result, 0)["tests_run"], 2)

    def test_no_cli_is_not_success(self):
        selected, result = self.root / "selected.json", self.root / "result.json"
        save(selected, ["one"])
        value = {"selected_ids": ["one"], "started_ids": ["one"], "completed_ids": ["one"],
                 "tests_run": 1, "successful": True, "cli_calls": {"one": 0},
                 "failures": 0, "errors": 0}
        save(result, value)
        with self.assertRaisesRegex(Failure, "no product CLI"):
            validate_child(selected, result, 0)

    def test_service_identity_is_refused(self):
        context = box_support.Context.__new__(box_support.Context)
        with self.assertRaisesRegex(Failure, "setup-only"):
            context.as_user("service", ["/usr/bin/id"])
        directory = self.root / "evidence" / "cmd"
        directory.mkdir(parents=True)
        record = directory / "c.json"
        save(record, {"identity": "service"})
        with self.assertRaisesRegex(Failure, "state owner"):
            box_support.audit_service_commands(self.root)
        save(record, {"identity": "operator"})
        self.assertIsNone(box_support.audit_service_commands(self.root))


class ResultControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.operation = self.root / "operation.json"
        save(self.operation, {"actual_exit": 0, "random": os.urandom(8).hex()})
        reference = evidence(self.root, self.operation)
        self.context = {"case_id": "sample", "phase": "candidate", "mutation_id": "",
                        "binary_sha256": "a" * 64, "source_sha256": "b" * 64,
                        "evidence_root": str(self.root)}
        self.case = {"assertion_ids": ["ROW"]}
        self.value = {"schema": "laneboss.e2e-result.v2",
                      **{key: self.context[key] for key in ("case_id", "phase", "mutation_id",
                                                         "binary_sha256", "source_sha256")},
                      "assertions": [{"id": "ROW", "reached": True, "verdict": "pass",
                                      "observed_exit": 0, "evidence": [reference]}],
                      "collection": {"processes_quiescent": True,
                                     "temporary_resources_collected": True,
                                     "evidence": [reference]}}
        self.target = self.root / "result.json"

    def validate(self, exit_code=0, **kwargs):
        save(self.target, self.value)
        return result_file(self.target, self.case, self.context, exit_code, **kwargs)

    def test_missing_or_duplicate_row(self):
        self.value["assertions"] = []
        with self.assertRaisesRegex(Failure, "missing declared"):
            self.validate()
        self.value["assertions"] = [
            {"id": "ROW", "reached": True, "verdict": "pass", "observed_exit": 0,
             "evidence": [evidence(self.root, self.operation)]}] * 2
        with self.assertRaisesRegex(Failure, "duplicate"):
            self.validate()

    def test_real_exit_beats_claim(self):
        with self.assertRaisesRegex(Failure, "exited nonzero"):
            self.validate(7)
        self.assertEqual(self.validate()["assertions"][0]["verdict"], "pass")

    def test_changed_evidence_is_red(self):
        self.operation.write_bytes(os.urandom(10))
        with self.assertRaisesRegex(Failure, "mismatch"):
            self.validate()

    def test_linked_evidence_is_red(self):
        link = self.root / "linked"
        link.symlink_to(self.operation.name)
        self.value["assertions"][0]["evidence"][0]["path"] = "linked"
        with self.assertRaisesRegex(Failure, "linked"):
            self.validate()

    def test_setup_crash_is_not_red_kill(self):
        for value in (self.context, self.value):
            value.update({"phase": "red", "mutation_id": "mutation"})
        self.value["assertions"][0].update({"reached": False, "verdict": "fail"})
        with self.assertRaisesRegex(Failure, "before reaching"):
            self.validate(2, red_assertion="ROW")
        self.value["assertions"][0]["reached"] = True
        self.assertEqual(self.validate(1, red_assertion="ROW")["phase"], "red")

    def test_survivor_is_not_pass(self):
        self.value["collection"]["processes_quiescent"] = False
        with self.assertRaisesRegex(Failure, "collect"):
            self.validate()


class ArtifactControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "run"
        (self.root / "evidence").mkdir(parents=True)
        (self.root / "evidence" / "raw").write_bytes(os.urandom(32))
        self.out = Path(self.temp.name) / "harvest"
        self.summary = {"exit_code": 0, "outcome": "passed", "artifact_collection_ok": False}

    def test_bundle_failure_is_atomic(self):
        with patch.object(artifacts, "verify_bundle", side_effect=OSError("red read-back")):
            code = artifacts.finish(self.root, self.summary, self.out)
        self.assertEqual(code, 2)
        self.assertEqual(list(self.out.iterdir()), [])
        summary = load(self.root / "evidence" / "summary.json")
        self.assertEqual(summary["exit_code"], 2)
        manifest = load(self.root / "evidence" / "manifest.json")
        row = next(item for item in manifest["files"] if item["path"] == "evidence/summary.json")
        self.assertEqual(row["sha256"], sha256(self.root / row["path"]))
        self.assertEqual(artifacts.finish(self.root, self.summary, self.out), 2)
        self.assertEqual(len(list(self.out.glob("*.tar"))), 1)

    def test_manifest_failure_drops_stale(self):
        artifacts.manifest(self.root)
        with patch.object(artifacts, "manifest", side_effect=OSError("red full disk")):
            self.assertEqual(artifacts.finish(self.root, self.summary), 2)
        self.assertFalse((self.root / "evidence" / "manifest.json").exists())

    def test_missing_binary_is_red(self):
        save(self.root / "context.json", {"paths": {"binary": str(self.root / "missing")},
                                         "binary_sha256": "a" * 64})
        with self.assertRaisesRegex(Failure, "missing"):
            box.retain_binary(self.root)

    def test_source_directory_link_is_red(self):
        source = Path(self.temp.name) / "source"
        source.mkdir()
        (source / "hidden").symlink_to(self.root, target_is_directory=True)
        with patch.object(box, "ROOT", source):
            with self.assertRaisesRegex(Failure, "linked directory"):
                box.keep_source(self.root)
