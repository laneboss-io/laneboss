"""Retained serve handoff controls; fixtures are never installed acceptance."""

import base64
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "e2e/v2"))

from serve_handoff import (Retained, STAGES, expected_checks, pinned, public_blob,
                           report_rows, require_passed, stage_timings, fixture_output)
from installed_ladder import launch_context
from support import Failure, bytes_hash, decode, encoded, evidence, load, save


def report():
    names = expected_checks("installed-lifecycle")
    return {"schema": "laneboss.serve-report.v2", "config": "case-serve",
            "scope": "installed-lifecycle", "required_checks": names,
            "presence": "simulated", "human_approval": "not_proven",
            "authenticator_tag": "laneboss_e2e_authenticator", "failure": None,
            "manifest": "case-serve/manifest.json",
            "checks": [{"check": name, "result": "pass", "presence": "simulated",
                        "observed": {"executed": True}} for name in names]}


class ServeReportControls(unittest.TestCase):
    def test_catalog_control(self):
        value = report()
        value["checks"].pop()
        value["required_checks"].pop()
        with self.assertRaisesRegex(Failure, "catalog"):
            report_rows(value)
        self.assertEqual(list(report_rows(report())), expected_checks("installed-lifecycle"))
        self.assertIn("state.drop-reply", expected_checks("serve-state"))

    def test_unexecuted_row(self):
        value = report()
        rows = report_rows(value)
        rows["health"]["observed"]["executed"] = False
        with self.assertRaisesRegex(Failure, "did not execute"):
            require_passed(value, rows)
        rows["health"]["observed"]["executed"] = True
        require_passed(value, rows)

    def test_stored_refusal_owner(self):
        value = report()
        rows = report_rows(value)
        refusal = {"code": "deadline_exceeded", "owner": "lb-v2-service", "message": "measured timeout"}
        rows["admin.publish"]["observed"]["refusal"] = refusal
        with self.assertRaises(Failure) as caught:
            require_passed(value, rows)
        self.assertEqual((caught.exception.owner, caught.exception.code),
                         (refusal["owner"], refusal["code"]))
        del rows["admin.publish"]["observed"]["refusal"]
        require_passed(value, rows)

    def test_simulated_presence(self):
        value = report()
        value["human_approval"] = "proven"
        with self.assertRaisesRegex(Failure, "software presence"):
            report_rows(value)
        value["human_approval"] = "not_proven"
        self.assertEqual(report_rows(value)["human.session"]["presence"], "simulated")


class ServeBytesControls(unittest.TestCase):
    def seal(self, directory, value):
        root = directory / value["config"]
        inventory = [evidence(root, path) for path in sorted(root.rglob("*"))
                     if path.is_file() and path.name != "manifest.json"]
        save(root / "manifest.json", inventory)
        save(directory / "report.json", value)

    def fixture(self, directory):
        value = report()
        root = directory / value["config"]
        root.mkdir()
        records = [{"stage": stage, "elapsed_ms": index + 1}
                   for index, stage in enumerate(sorted(STAGES))]
        raw = b"".join(encoded(item).replace(b"\n", b"") + b"\n" for item in records)
        (root / "100-journal-service.stdout").write_bytes(raw)
        (root / "101-journal-helper.stdout").write_bytes(b"")
        for stem in ("100-journal-service", "101-journal-helper"):
            save(root / (stem + ".exit.json"), {"exit_code": 0, "timed_out": False, "elapsed_ms": 1})
            save(root / (stem + ".argv.json"), ["journalctl", "--no-pager"])
        journals = [
            {"role": role, "stdout": name, "exit_code": 0, "result": "captured" if data else "empty",
             "bytes": len(data), "lines": len(data.splitlines()), "sha256": bytes_hash(data)}
            for role, name, data in (("service", "100-journal-service.stdout", raw),
                                     ("helper", "101-journal-helper.stdout", b""))]
        observed = next(row["observed"] for row in value["checks"] if row["check"] == "cleanup")
        observed["unit_journals"] = journals
        observed["initial_publish_timings"] = [{
            "role": "service", "stdout": journals[0]["stdout"], "sha256": bytes_hash(raw),
            "records": [dict(item, line=index + 1) for index, item in enumerate(records)], "invalid_lines": []}]
        self.seal(directory, value)
        return value, root

    def test_manifest_and_layout(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            value, root = self.fixture(directory)
            value["manifest"] = "ready/service-context.json"
            save(directory / "report.json", value)
            with self.assertRaisesRegex(Failure, "manifest"):
                Retained(directory, {})
            value["manifest"] = "case-serve/manifest.json"
            save(directory / "report.json", value)
            retained = Retained(directory, {})
            self.assertEqual(retained.root, root)
            original = (root / "100-journal-service.stdout").read_bytes()
            (root / "100-journal-service.stdout").write_bytes(original + b"changed")
            with self.assertRaisesRegex(Failure, "hash or size"):
                Retained(directory, {})
            (root / "100-journal-service.stdout").write_bytes(original)
            self.assertEqual(Retained(directory, {}).root, root)

    def test_journal_timing(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            value, _ = self.fixture(directory)
            cleanup = next(row for row in value["checks"] if row["check"] == "cleanup")
            timing = cleanup["observed"]["initial_publish_timings"][0]
            timing["records"][0]["elapsed_ms"] += 1
            save(directory / "report.json", value)
            with self.assertRaisesRegex(Failure, "exact retained journal"):
                stage_timings(Retained(directory, {}))
            timing["records"][0]["elapsed_ms"] -= 1
            save(directory / "report.json", value)
            observed = stage_timings(Retained(directory, {}))
            self.assertEqual(observed, [timing])

    def test_required_timing(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            value, root = self.fixture(directory)
            retained = Retained(directory, {})
            original = copy.deepcopy(retained.rows["cleanup"]["observed"])
            retained.rows["cleanup"]["observed"]["initial_publish_timings"] = []
            with self.assertRaisesRegex(Failure, "timings differ"):
                stage_timings(retained)
            retained.rows["cleanup"]["observed"] = original
            self.assertEqual(len(stage_timings(retained)[0]["records"]), len(STAGES))
            self.assertTrue((root / "manifest.json").is_file())

    def test_invalid_timing(self):
        for change in ({"elapsed_ms": True}, {"stage": "initial_publish.unknown"}):
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                value, root = self.fixture(directory)
                original = (root / "100-journal-service.stdout").read_bytes()
                lines = original.splitlines()
                lines[0] = encoded(dict(decode(lines[0]), **change)).replace(b"\n", b"")
                altered = b"\n".join(lines) + b"\n"
                (root / "100-journal-service.stdout").write_bytes(altered)
                cleanup = next(row for row in value["checks"] if row["check"] == "cleanup")
                journal = cleanup["observed"]["unit_journals"][0]
                journal.update(bytes=len(altered), sha256=bytes_hash(altered))
                self.seal(directory, value)
                with self.assertRaisesRegex(Failure, "invalid initial publication timing"):
                    stage_timings(Retained(directory, {}))
                (root / "100-journal-service.stdout").write_bytes(original)
                journal.update(bytes=len(original), sha256=bytes_hash(original))
                self.seal(directory, value)
                self.assertEqual(len(stage_timings(Retained(directory, {}))[0]["records"]), len(STAGES))

    def test_initial_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "object"
            raw = os.urandom(512)
            path.write_bytes(raw)
            retained = Mock()
            retained.path.return_value = path
            ref = {"id": "object", "class": "artifact", "bytes": len(raw), "sha256": bytes_hash(raw)}
            bad = dict(ref, sha256=bytes_hash(raw + b"changed"))
            with self.assertRaisesRegex(Failure, "pin differs"):
                pinned(retained, "initial-inputs/object", bad)
            self.assertEqual(pinned(retained, "initial-inputs/object", ref).read_bytes(), raw)

    def test_fixture_output_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor = {"schema": "laneboss.serve-agent.v1", "config": "case-serve",
                          "output": "/home/lane/serve-state"}
            path = root / "fixture-enrollment.input.json"
            retained = Mock(report={"config": descriptor["config"]})
            retained.path.return_value = path

            def enroll(value):
                raw = encoded(value)
                path.write_bytes(raw)
                retained.document.return_value = {"objects": [{"role": "serve-fixture-config", "content": {
                    "id": "descriptor", "class": "artifact", "bytes": len(raw), "sha256": bytes_hash(raw)}}]}

            enroll(descriptor)
            self.assertEqual(fixture_output(retained), descriptor["output"])
            for output in ("serve-state", "/work/main/serve-state", "/home/lane/../work/main"):
                enroll(dict(descriptor, output=output))
                with self.assertRaisesRegex(Failure, "fixture output"):
                    fixture_output(retained)
            enroll(descriptor)
            path.write_bytes(path.read_bytes() + b"changed")
            with self.assertRaisesRegex(Failure, "descriptor pin"):
                fixture_output(retained)
            enroll(descriptor)
            self.assertEqual(fixture_output(retained), descriptor["output"])

    def test_public_readback(self):
        raw = os.urandom(1000)
        ref = {"id": "object", "class": "artifact", "bytes": len(raw), "sha256": bytes_hash(raw)}
        chunks = [{"object_id": ref["id"], "offset": offset,
                   "data": base64.b64encode(part).decode(), "sha256": bytes_hash(part)}
                  for offset, part in ((0, raw[:400]), (400, raw[400:]))]
        retained = Mock()
        retained.commands.return_value = chunks[:-1]
        with self.assertRaisesRegex(Failure, "incomplete or corrupt"):
            public_blob(retained, ref)
        retained.commands.return_value = chunks
        self.assertEqual(public_blob(retained, ref), raw)

    def test_command_exit(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            value, root = self.fixture(directory)
            save(root / "001-health.stdout", {"artifact_sha256": bytes_hash(os.urandom(16))})
            save(root / "001-health.argv.json", ["installed-cli", "health"])
            save(root / "001-health.exit.json", {"exit_code": 1, "timed_out": False, "elapsed_ms": 10})
            self.seal(directory, value)
            with self.assertRaisesRegex(Failure, "command failed"):
                Retained(directory, {}).commands("health")
            save(root / "001-health.exit.json", {"exit_code": 0, "timed_out": False, "elapsed_ms": 10})
            self.seal(directory, value)
            self.assertEqual(Retained(directory, {}).commands("health"), [load(root / "001-health.stdout")])


class LaunchHandoffControls(unittest.TestCase):
    def fixture(self, directory):
        binary, source = directory / "candidate", directory / "source.tar"
        binary.write_bytes(os.urandom(100))
        source.write_bytes(os.urandom(200))
        context = {"case_id": "e2e", "phase": "candidate", "config": "tree-a", "binary": str(binary),
                   "binary_sha256": bytes_hash(binary.read_bytes()), "source_sha256": bytes_hash(source.read_bytes())}
        retained = Mock(report={"scope": "installed-lifecycle"})
        retained.path.side_effect = lambda name: binary if name == "laneboss.input" else source
        return context, retained

    def test_foreign_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            context, retained = self.fixture(Path(temporary))
            original = context["source_sha256"]
            context["source_sha256"] = bytes_hash(os.urandom(200))
            with patch("installed_ladder.context_file", return_value=context):
                with self.assertRaisesRegex(Failure, "exact installed binary or source"):
                    launch_context(Path("context.json"), retained)
                context["source_sha256"] = original
                with patch("installed_ladder.ready_plan", return_value={"rows": []}), patch(
                        "installed_ladder.verify_supporting", return_value=[]):
                    self.assertEqual(launch_context(Path("context.json"), retained), context)

    def test_missing_port_owner(self):
        with tempfile.TemporaryDirectory() as temporary:
            context, retained = self.fixture(Path(temporary))
            dependency = {"lane": "lb-v2-service", "port": "ServeInstalled", "landed": False}
            plan = {"rows": [{"depends": [dependency]}]}
            with patch("installed_ladder.context_file", return_value=context):
                with patch("installed_ladder.ready_plan", return_value=plan), patch(
                        "installed_ladder.verify_supporting", return_value=[]):
                    with self.assertRaises(Failure) as caught:
                        launch_context(Path("context.json"), retained)
                    self.assertEqual((caught.exception.owner, caught.exception.code),
                                     (dependency["lane"], "prerequisite_missing"))
                    dependency["landed"] = True
                    self.assertEqual(launch_context(Path("context.json"), retained), context)
