"""Linux component fault controls for the outside observer's safety cleanup."""

import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


module = importlib.util.spec_from_file_location("admin_case", Path(__file__).with_name("run.py"))
case = importlib.util.module_from_spec(module)
module.loader.exec_module(case)


class CleanupControls(unittest.TestCase):
    def fixture(self, failure_label=None):
        temporary = tempfile.TemporaryDirectory(prefix="lb-v2-admin-cleanup-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        root.chmod(0o700)
        original = os.urandom(128)
        installed, backup = root / "laneboss", root / "admin-case-original"
        target = root / "admin-case-setuid"
        installed.write_bytes(b"changed")
        backup.write_bytes(original)
        target.write_bytes(original)
        target.chmod(0o4755)
        observer = object.__new__(case.Observer)
        observer.context = {"config": "case", "binary_sha256": hashlib.sha256(original).hexdigest()}
        observer.restore_binary = installed, backup
        observer.temporary_artifacts = [backup, target]

        def command(label, argv, expected=0):
            if label == failure_label:
                raise case.Failed("injected command failure")
            # This injected command boundary performs the real corresponding
            # filesystem operation inside this test's private directory.
            if argv[2] == "chmod":
                Path(argv[-1]).chmod(int(argv[-2], 8))
            elif argv[2] == "unlink":
                Path(argv[-1]).unlink()
            elif argv[2] == "mv":
                shutil.move(argv[-2], argv[-1])
            else:
                self.fail("unexpected safety command")
            return subprocess.CompletedProcess(argv, expected)

        observer.command = command
        return observer, installed, backup, target, original

    def test_cleanup_restores_and_disarms(self):
        observer, installed, backup, target, original = self.fixture()
        observer.collect_artifact_controls()
        self.assertEqual(installed.read_bytes(), original)
        self.assertFalse(backup.exists())
        self.assertFalse(target.exists())
        self.assertEqual(observer.temporary_artifacts, [])

    def test_restore_failure_still_disarms(self):
        observer, _, backup, target, _ = self.fixture("artifact-finally-restore")
        with self.assertRaises(case.Failed):
            observer.collect_artifact_controls()
        self.assertTrue(backup.exists())
        self.assertFalse(target.exists(), "acceptance: restore failure left setuid")

    def test_unlink_failure_still_restores(self):
        observer, installed, _, target, original = self.fixture("setuid-finally-collect")
        with self.assertRaises(case.Failed):
            observer.collect_artifact_controls()
        self.assertEqual(installed.read_bytes(), original, "acceptance: unlink failure lost binary")
        self.assertFalse(target.stat().st_mode & stat.S_ISUID)


if __name__ == "__main__":
    if sys.platform != "linux":
        raise RuntimeError("supporting controls run only on the authorized Linux box")
    unittest.main()
