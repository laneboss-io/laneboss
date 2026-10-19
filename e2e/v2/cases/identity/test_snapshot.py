"""Reporter regressions with temporary source bytes and simulated subprocess faults.

These tests never claim a product mutation kill or execute their input binaries.
Run them on the authorized Linux box, not on the authoring Mac.
"""

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import controls


class SnapshotTests(unittest.TestCase):
    def source(self, root, dotted=False):
        for item in controls.INPUTS:
            path = root / item
            if item in {Path("go.mod"), Path("go.sum")}:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"reporter source fixture\n")
            else:
                path.mkdir(parents=True, exist_ok=True)
                (path / "fixture-input.txt").write_bytes(b"reporter source bytes\n")
        api = root / "internal/v2/api"
        api.mkdir()
        (api / "base.go").write_text('package api\nconst ContractRevision = "fixture"\n')
        identity = root / "internal/v2/identity"
        identity.mkdir()
        (identity / "guard.go").write_text("package identity\nfunc guard() bool { return 2 > 1 }\n")
        (identity / "guard.go").chmod(0o640)
        case = {"id": "root-endpoint", "package": "identity", "rule": "PEER", "kind": "projection",
                "test": ["TestFixture", "lane.start" if dotted else "ordinary"], "diagnostic": "fixture assertion",
                "edits": [{"file": "guard", "before": "2 > 1", "after": "2 < 1"}]}
        folder = root / controls.CASE
        (folder / "fixture-cases.json").write_text(json.dumps({
            "schema": "laneboss.identity-fixtures.v1", "contract_revision": "fixture",
            "cases": [case], "remaining_acceptance": []}))
        (folder / "mutations.json").write_text(json.dumps({
            "schema": "laneboss.identity-mutations.v1", "contract_revision": "fixture",
            "files": {"guard": ["internal", "v2", "identity", "guard.go"]}, "mutations": [case]}))
        return case

    def invoke(self, source, work, **faults):
        argv = ["controls.py", "--source", str(source), "--work-root", str(work),
                "--revision", "ccd2470", "--mode", "mutations", "--tags", "normal"]
        output = io.StringIO()
        with patch.object(controls.sys, "argv", argv), patch.object(controls.sys, "platform", "linux"), \
                patch.object(controls, "enable_subreaper"), \
                patch.object(controls, "collect_children", return_value={"quiescent": True, "observed": []}), \
                redirect_stdout(output):
            with faults.pop("context"):
                exit_code = controls.main()
        report = json.loads((work / "report.json").read_bytes())
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        return exit_code, report, rows, [controls.sys.executable, *argv]

    def test_archive_dot_reaches_build(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
            root = Path(directory).resolve()
            source, work = root / "src", root / "lb-v2-identity-controls"
            self.source(source, dotted=True)
            self.assertFalse((source / ".git").exists())
            with patch.object(controls, "build", side_effect=controls.ControlError("fixture build stop")) as build:
                code, report, rows, _ = self.invoke(source, work, context=patch.object(
                    controls, "command", return_value={"exit": 0}))
            self.assertEqual(build.call_count, 1, "literal dotted name never reached the red build")
            self.assertEqual(code, 1)
            self.assertEqual(report["failure"]["stage"], "normal/root-endpoint")
            self.assertEqual(report["results"][0]["status"], "incomplete")
            self.assertEqual(rows[-1]["status"], "failed")
            self.assertFalse(any(row.get("status") == "killed" for row in report["results"]))

    def test_failure_stdout_has_context(self):
        for step in ["inventory", "command"]:
            with self.subTest(step=step), tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
                root = Path(directory).resolve()
                source, work = root / "src", root / "lb-v2-identity-controls"
                self.source(source)
                filename = str(source / "go.mod") if step == "inventory" else "go"
                error = FileNotFoundError(2, "fixture unavailable", filename)
                context = patch.object(controls, "inventory", side_effect=error) if step == "inventory" else \
                    patch.object(controls.subprocess, "Popen", side_effect=error)
                code, report, rows, invocation = self.invoke(source, work, context=context)
                row = rows[-1]
                self.assertEqual(code, 1)
                self.assertEqual(row.get("message"), str(error), "stdout omitted the failure reason")
                self.assertEqual(row.get("path"), filename, "stdout omitted the failed path")
                self.assertEqual(row.get("command"), invocation if step == "inventory" else ["go", "version"],
                                 "stdout omitted the actual failed command")
                self.assertEqual(report["failure"]["message"], row["message"])
                self.assertEqual(report["results"], [])

    def test_dot_selector_stays_literal(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
            root = Path(directory)
            case = {"id": "root-endpoint", "package": "identity", "test": ["TestFixture", "lane.start"]}
            try:
                controls.validate_case(case)
            except controls.ControlError as error:
                self.fail("literal dotted component was rejected: " + str(error))
            binary, stdout = root / "binary-input", root / "events"
            binary.write_bytes(b"reporter input, never executed")
            target = "/".join(case["test"])
            stdout.write_text("\n".join(json.dumps({"Action": action, "Test": target}) for action in ["run", "pass"]))
            built = {"binary": controls.reference(root, binary)}
            observed = {"stdout": controls.reference(root, stdout)}
            with patch.object(controls, "command", return_value=observed) as invoked:
                result = controls.run_test(root, root, root / "case", "identity", case["test"], built)
            self.assertEqual(invoked.call_args.args[3][-1], r"-test.run=^TestFixture$/^lane\.start$")
            self.assertEqual(result["observation"]["actions"], ["run", "pass"])

    def test_entire_catalog_validates(self):
        folder = Path(controls.__file__).parent
        for name, key in [("mutations.json", "mutations"), ("fixture-cases.json", "cases")]:
            cases = json.loads((folder / name).read_bytes())[key]
            self.assertTrue(cases)
            for case in cases:
                with self.subTest(case=case["id"]):
                    try:
                        controls.validate_case(case)
                    except controls.ControlError as error:
                        self.fail("catalog name rejected: " + str(error))

    def test_pattern_and_path_names_refuse(self):
        for name in ["", ".", "..", "lane.*", "lane/start", "lane\\start", "lane[0]", "lane$", "lane\nstart"]:
            with self.subTest(name=name), self.assertRaises(controls.ControlError):
                controls.validate_case({"id": "control", "package": "identity", "test": ["TestFixture", name]})

    def test_archive_copy_stays_exact(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
            root = Path(directory)
            source = root / "src"
            self.source(source)
            expected = controls.inventory(source)
            target = root / "copy"
            controls.copy_source(source, target, expected)
            self.assertEqual(controls.inventory(target), expected)
            for name in expected:
                self.assertEqual((source / name).read_bytes(), (target / name).read_bytes())
            (source / "internal/v2/identity/guard.go").write_text("changed source\n")
            with self.assertRaisesRegex(controls.ControlError, "changed during snapshot"):
                controls.copy_source(source, root / "changed-copy", expected)

    def check_cli_snapshot_dependency(self, dependency):
        original = Path(controls.__file__).resolve().parents[4] / dependency
        data = original.read_bytes()
        with tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
            root = Path(directory)
            source, target = root / "src", root / "copy"
            self.source(source)
            path = source / dependency
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o640)
            expected = controls.inventory(source)
            self.assertIn(str(dependency), expected, "CLI snapshot omitted its dependency: " + str(dependency))
            self.assertEqual(expected[str(dependency)]["sha256"], controls.sha(data))
            controls.copy_source(source, target, expected)
            self.assertEqual((target / dependency).read_bytes(), data)
            self.assertEqual((target / dependency).stat().st_mode & 0o777, 0o640)
            self.assertEqual(controls.inventory(target), expected)

    def test_cli_snapshot_retains_jsontext(self):
        self.check_cli_snapshot_dependency(Path("internal/jsontext/unicode.go"))

    def test_cli_snapshot_retains_typesafe(self):
        self.check_cli_snapshot_dependency(Path("internal/typesafe/wire.go"))

    def test_ancestor_link_refuses(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-identity-") as directory:
            root = Path(directory)
            source = root / "src"
            self.source(source)
            outside = root / "held-internal"
            (source / "internal").rename(outside)
            (source / "internal").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(controls.ControlError, "missing or linked"):
                controls.inventory(source)


if __name__ == "__main__":
    unittest.main()
