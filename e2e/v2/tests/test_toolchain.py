"""Compiler selection controls use the box's real pinned Go executable."""

import contextlib
import io
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "e2e" / "v2"))

import box_run
import toolchain
from diagnostics import public_error, summary_line
from support import Failure, clean_environment, load, sha256


class CompilerControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.compiler = toolchain.resolve_go()
        self.pin = load(ROOT / "scripts" / "v2-e2e" / "contract.json")["go_toolchain"]

    def directory(self, name):
        root = self.root / name
        for child in ("evidence", "controller-home", "controller-tmp"):
            (root / child).mkdir(parents=True)
        return root

    def test_operator_lookup_once(self):
        alias = self.root / "operator-go"
        alias.symlink_to(self.compiler.path)
        with patch.object(toolchain.os.environ, "get", return_value=None):
            with patch.object(toolchain.shutil, "which", return_value=str(alias)) as lookup:
                selected = toolchain.resolve_go()
        lookup.assert_called_once_with("go")
        self.assertTrue(selected.path.is_absolute())
        self.assertEqual(selected.path, self.compiler.path)
        directory = self.directory("operator")
        environment = toolchain.verify_compiler(
            directory, selected, self.pin, (ROOT / "go.mod").read_text(), ROOT)
        record = load(directory / "evidence" / "go-toolchain.json")
        self.assertEqual(record["path"], str(selected.path))
        self.assertEqual(record["sha256"], sha256(selected.path))
        self.assertTrue(record["verified"])
        self.assertEqual(record["observed_version"], self.pin)
        self.assertEqual(environment["LANEBOSS_GO"], str(selected.path))
        self.assertEqual(environment["GOTOOLCHAIN"], "local")
        self.assertEqual(environment["PATH"], clean_environment(directory, directory)["PATH"])
        self.assertEqual(sha256(directory / "evidence" / "selected-go"), selected.sha256)

    def test_explicit_go_skips_lookup(self):
        with patch.object(toolchain.shutil, "which", side_effect=AssertionError("unexpected lookup")):
            selected = toolchain.resolve_go(self.compiler.path)
        self.assertEqual(selected.path, self.compiler.path)
        self.assertEqual(selected.selection, "explicit")

    def test_missing_go_is_red(self):
        with patch.object(toolchain.os.environ, "get", return_value=None):
            with patch.object(toolchain.shutil, "which", return_value=None):
                with self.assertRaisesRegex(toolchain.ToolchainError, "not found"):
                    toolchain.resolve_go()
        with self.assertRaisesRegex(toolchain.ToolchainError, "not found"):
            toolchain.resolve_go(self.root / "missing-go")

    def test_nonexecutable_is_red(self):
        candidate = self.root / "go"
        candidate.write_bytes(os.urandom(24))
        candidate.chmod(0o600)
        with self.assertRaisesRegex(toolchain.ToolchainError, "executable file"):
            toolchain.resolve_go(candidate)

    def test_wrong_version_is_red(self):
        directory = self.directory("wrong-version")
        with self.assertRaisesRegex(toolchain.ToolchainError, "contract pin"):
            toolchain.verify_compiler(directory, self.compiler, "go1.26.4",
                                      "module example\n\ngo 1.26.0\n", ROOT)
        record = load(directory / "evidence" / "go-toolchain.json")
        self.assertEqual(record["observed_exit"], 0)
        self.assertEqual(record["observed_version"], self.pin)
        self.assertFalse(record["verified"])
        self.assertFalse((directory / "evidence" / "selected-go").exists())
        good = self.directory("right-version")
        toolchain.verify_compiler(good, self.compiler, self.pin, (ROOT / "go.mod").read_text(), ROOT)
        self.assertTrue(load(good / "evidence" / "go-toolchain.json")["verified"])

    def test_module_minimum_is_enforced(self):
        with self.assertRaisesRegex(toolchain.ToolchainError, "module minimum"):
            toolchain.validate_module("go1.26.5", "go 1.27.0\n")
        self.assertEqual(toolchain.validate_module("go1.26.5", "go 1.26.0\n"), "1.26.0")
        self.assertEqual(toolchain.validate_module("go1.26.5", "go 1.26\n"), "1.26")
        with self.assertRaisesRegex(toolchain.ToolchainError, "pin is invalid"):
            toolchain.validate_module("go1.26", "go 1.26.0\n")

    def test_changed_executable_is_red(self):
        candidate = self.root / "candidate"
        candidate.write_bytes(os.urandom(24))
        candidate.chmod(0o700)
        selected = toolchain.resolve_go(candidate)
        selected.unchanged()
        candidate.write_bytes(os.urandom(24))
        with self.assertRaisesRegex(toolchain.ToolchainError, "changed"):
            selected.unchanged()

    def test_installer_pin_is_not_overridden(self):
        directory = self.directory("installer")
        script = self.root / "install.sh"
        script.write_text('GOTOOLCHAIN=go1.26.0 "$LANEBOSS_GO" build ./cmd/laneboss\n')
        with self.assertRaisesRegex(toolchain.ToolchainError, "source installer") as caught:
            toolchain.check_installer(directory, script, self.pin)
        self.assertEqual(caught.exception.owner, "lb-v2-packaging")
        record = load(directory / "evidence" / "installer-toolchain.json")
        self.assertFalse(record["compatible"])
        self.assertEqual(record["declared_versions"], ["go1.26.0"])
        self.assertEqual(record["script_sha256"], sha256(script))
        script.write_text('GOTOOLCHAIN=go1.26.5 "$LANEBOSS_GO" build ./cmd/laneboss\n')
        toolchain.check_installer(directory, script, self.pin)
        self.assertTrue(load(directory / "evidence" / "installer-toolchain.json")["compatible"])

    def test_actual_binary_compiler(self):
        directory = self.directory("binary")
        with self.assertRaisesRegex(toolchain.ToolchainError, "binary compiler"):
            toolchain.verify_binary(directory, self.compiler, "go1.26.4", self.compiler.path, ROOT)
        result = toolchain.verify_binary(directory, self.compiler, self.pin, self.compiler.path, ROOT)
        self.assertEqual(result.returncode, 0)
        self.assertIn(self.pin.encode(), result.stdout)

    def test_failed_copy_is_not_verified(self):
        directory = self.directory("copy-failure")
        with patch.object(toolchain.shutil, "copyfile", side_effect=OSError("red copy failure")):
            with self.assertRaisesRegex(OSError, "copy failure"):
                toolchain.verify_compiler(directory, self.compiler, self.pin,
                                          (ROOT / "go.mod").read_text(), ROOT)
        record = load(directory / "evidence" / "go-toolchain.json")
        self.assertTrue(record["version_matches"])
        self.assertFalse(record["verified"])
        self.assertFalse((directory / "evidence" / "selected-go").exists())

    def test_controller_records_selection(self):
        directory = self.directory("controller")
        arguments = ["box_run.py", "--kit", str(self.root / "kit.py"), "--go",
                     str(self.compiler.path), "--source-revision", "unit"]
        output = io.StringIO()
        previous_mask = os.umask(0o077)
        os.umask(previous_mask)
        self.addCleanup(os.umask, previous_mask)
        for number in (signal.SIGTERM, signal.SIGHUP):
            self.addCleanup(signal.signal, number, signal.getsignal(number))
        with patch.object(sys, "argv", arguments):
            with patch.object(box_run.box, "run_directory", return_value=directory):
                with patch.object(box_run, "resolve_go", wraps=toolchain.resolve_go) as resolve:
                    with patch.object(box_run.box, "setup",
                                      side_effect=toolchain.ToolchainError("version")) as setup:
                        with contextlib.redirect_stdout(output):
                            code = box_run.main()
        self.assertEqual(code, 2)
        resolve.assert_called_once_with(self.compiler.path)
        setup.assert_called_once()
        self.assertEqual(setup.call_args.args[2].path, self.compiler.path)
        record = load(directory / "evidence" / "invocation.json")
        self.assertEqual(record["go_path"], str(self.compiler.path))
        self.assertEqual(record["go_sha256"], self.compiler.sha256)
        line = next(line for line in output.getvalue().splitlines() if line.startswith("E2E summary:"))
        self.assertIn("diagnostic=", line)
        self.assertIn("selected Go version differs", line)
        self.assertNotIn(str(self.compiler.path), line)


class DiagnosticControls(unittest.TestCase):
    def summary(self):
        return {"outcome": "setup-error", "exit_code": 2, "tests_run": 0,
                "failures": 0, "errors": 0, "cleanup_ok": True,
                "artifact_collection_ok": True}

    def test_missing_go_is_visible(self):
        value = self.summary()
        value["public_diagnostic"] = public_error(toolchain.ToolchainError("missing"))
        line = summary_line(value)
        self.assertIn("E2E summary:", line)
        self.assertIn("Go executable was not found", line)
        self.assertIn("exit=2", line)

    def test_exception_values_stay_private(self):
        marker = os.urandom(12).hex()
        value = self.summary()
        error = OSError(2, "HOME=" + marker, "/private/" + marker)
        value["diagnostic"] = str(error)
        value["public_diagnostic"] = public_error(error)
        line = summary_line(value)
        self.assertIn("errno 2", line)
        self.assertNotIn(marker, line)
        value["public_diagnostic"] = public_error(Failure("TOKEN=" + marker))
        self.assertNotIn(marker, summary_line(value))

    def test_diagnostic_is_bounded(self):
        value = self.summary()
        value["public_diagnostic"] = "line\n" * 200
        line = summary_line(value)
        self.assertEqual(len(line.splitlines()), 1)
        self.assertLess(len(line), 450)

    def test_failed_phase_is_visible(self):
        value = self.summary()
        value["outcome"] = "failed"
        self.assertIn("product assertions failed", summary_line(value))
        value["outcome"] = "evidence-error"
        self.assertIn("evidence collection or read-back failed", summary_line(value))
