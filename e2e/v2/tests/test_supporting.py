"""Decoder controls with explicit inert fixtures; never supporting acceptance."""

import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "e2e/v2"))

import ladder_supporting
from support import Failure, bytes_hash, evidence, load, regular, save, sha256


class SupportingControls(unittest.TestCase):
    def fixture(self, root):
        binary, binding = root / "candidate", root / "binding"
        binary.write_bytes(os.urandom(100))
        binding.write_bytes(os.urandom(80))
        target = {"test_root": str(root), "binary_sha256": sha256(binary),
                  "source_sha256": bytes_hash(os.urandom(100))}
        value = {"schema": "laneboss.ladder-supporting.v1", **{key: target[key]
                 for key in ("binary_sha256", "source_sha256")}, "cases": []}
        for name, (assertion, owner) in ladder_supporting.REQUIRED.items():
            case_dir = root / "e2e/v2/cases" / name
            case_dir.mkdir(parents=True)
            # An entry that cannot pass any candidate. It is never executed;
            # these fixtures exercise the evidence decoder's closed envelope.
            (case_dir / "run.sh").write_text("#!/bin/sh\nexit 91\n")
            save(case_dir / "case.json", {"schema": "laneboss.e2e-case.v2", "id": name,
                 "owner": owner, "platforms": ["linux"], "requires": [], "entry": "run.sh",
                 "timeout_seconds": 10, "live_auth": False, "assertion_ids": [assertion]})
            scope = root / name
            inputs, output = scope / "inputs", scope / "evidence"
            inputs.mkdir(parents=True)
            output.mkdir()
            started = time.monotonic_ns()
            raw = output / "input.bin"
            raw.write_bytes(os.urandom(64))
            reference = evidence(output, raw)
            execution = {"exit_code": 0, "timed_out": False, "started_ns": started,
                         "ended_ns": time.monotonic_ns()}
            context = {"schema": "laneboss.e2e-context.v2", "case_id": name, "phase": "candidate",
                       "config": "case-" + name,
                       "mutation_id": "", "binary": str(binary), "binding_file": str(binding),
                       "test_root": str(inputs), "evidence_root": str(output), "profile_grant_ids": [],
                       **{key: target[key] for key in ("binary_sha256", "source_sha256")}}
            identity = {key: context[key] for key in ("case_id", "phase", "mutation_id", "binary_sha256", "source_sha256")}
            result = {"schema": "laneboss.e2e-result.v2", **identity,
                      "assertions": [{"id": assertion, "reached": True, "verdict": "pass",
                                      "observed_exit": 0, "evidence": [reference]}],
                      "collection": {"processes_quiescent": True, "temporary_resources_collected": True,
                                     "evidence": [reference]}}
            observer = {"schema": "laneboss.e2e-observer.v2", **identity,
                        "assertions": [{"id": assertion, "reached": True, "verdict": "pass"}],
                        "resources_collected": True, "evidence": [reference]}
            item = {"id": name}
            for label, data in (("context", context), ("result", result), ("observer", observer), ("execution", execution)):
                path = scope / (label + ".json")
                save(path, data)
                item[label], item[label + "_sha256"] = str(path), sha256(path)
            value["cases"].append(item)
        save(root / "supporting.json", value)
        return target, value

    def verify(self, root, target):
        with patch.object(ladder_supporting, "ROOT", root), patch.object(ladder_supporting, "immutable", side_effect=regular):
            return ladder_supporting.verify_supporting(target)

    def test_foreign_stale_replay_missing(self):
        for fault in ("foreign", "stale", "replayed", "missing_observer", "unreached", "timeout", "bad_evidence"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                target, value = self.fixture(root)
                self.assertEqual({row["id"] for row in self.verify(root, target)}, set(ladder_supporting.REQUIRED))
                if fault == "foreign":
                    value["source_sha256"] = bytes_hash(os.urandom(50))
                elif fault == "replayed":
                    value["cases"][1]["context"] = value["cases"][0]["context"]
                    value["cases"][1]["context_sha256"] = value["cases"][0]["context_sha256"]
                elif fault == "missing_observer":
                    del value["cases"][0]["observer"]
                elif fault == "bad_evidence":
                    (root / "service/evidence/input.bin").write_bytes(os.urandom(65))
                else:
                    item = value["cases"][0]
                    name = "execution" if fault == "timeout" else "result"
                    path = Path(item[name])
                    data = load(path)
                    if fault == "stale":
                        data["binary_sha256"] = bytes_hash(os.urandom(50))
                    elif fault == "unreached":
                        data["assertions"][0]["reached"] = False
                    else:
                        data["timed_out"] = True
                    save(path, data)
                    if fault != "stale":
                        item[name + "_sha256"] = sha256(path)
                save(root / "supporting.json", value)
                with self.assertRaises(Failure):
                    self.verify(root, target)

    def test_plan_or_records_no_certify(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target, _ = self.fixture(root)
            path = root / "e2e/v2/cases/integrate/case.json"
            manifest = load(path)
            manifest["assertion_ids"] = ["INTEGRATE-RECORDS"]
            save(path, manifest)
            with self.assertRaises(Failure) as caught:
                self.verify(root, target)
            self.assertEqual((caught.exception.code, caught.exception.owner), ("not_implemented", "lb-v2-integrate"))
            self.assertIn("INTEGRATED-RELEASE", str(caught.exception))
