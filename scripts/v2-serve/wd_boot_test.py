"""Actual watchdog boot assets through the installer's root staging checks."""

import importlib.util
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest

import case_watchdog
import provision


spec = importlib.util.spec_from_file_location("wd_boot_launcher", Path(__file__).with_name("run.py"))
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class WatchdogBoot(unittest.TestCase):
    def test_boot_assets_staged(self):
        self.assertEqual(os.geteuid(), 0, "watchdog staging regression requires the disposable Linux root step")
        with tempfile.TemporaryDirectory(prefix="lb-v2-case-watchdog-boot-", dir="/opt") as temporary:
            root = Path(temporary)
            case = launcher.Case.__new__(launcher.Case)
            case.api_key_canary = None
            case.stage = root / "stage"
            case.stage.mkdir(mode=0o755)
            templates = Path(__file__).resolve().parents[2] / "templates"
            shutil.copytree(templates, case.stage / "templates")
            evidence_parent = root / "unprotected-evidence"
            evidence_parent.mkdir(mode=0o777)
            evidence_parent.chmod(0o777)
            case.root = evidence_parent / "records"
            case.root.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError, "unprotected root staging path"):
                provision.protected(case.root)
            provision.protected(case.stage)

            # Exercise the published case entry and every file it hands to
            # provision.boot(), without replacing ownership or path checks.
            declared = case_watchdog.boot(case)
            expected = {"wd-run": case.root / "wd-runtime.input.json",
                        "wd-target": case.root / "wd-target.input"}
            self.assertEqual({asset["id"] for asset in declared["assets"]}, set(expected))
            runtime = root / "runtime"
            runtime.mkdir(mode=0o755)
            for asset in declared["assets"]:
                with self.subTest(asset=asset["id"]):
                    original = expected[asset["id"]].read_bytes()
                    staged = provision.runtime_asset(runtime, asset)
                    path = Path(asset["file"])
                    self.assertTrue(path.is_relative_to(case.stage), "boot asset escaped protected source staging")
                    self.assertEqual(provision.read_protected(path, mode=0o444), original)
                    self.assertEqual((runtime / staged["relative_path"]).read_bytes(), original)
                    self.assertEqual(staged["content"]["sha256"], provision.sha(original))
                    self.assertEqual(staged["content"]["bytes"], len(original))
                    self.assertEqual(staged["mode"], asset["mode"])
                    self.assertEqual(path.stat().st_uid, 0)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)

                    # Retained evidence is a copy, not the installer's input.
                    expected[asset["id"]].write_bytes(original + b"changed evidence\n")
                    self.assertEqual(provision.read_protected(path, mode=0o444), original)
                    with self.assertRaisesRegex(ValueError, "unprotected root staging path"):
                        provision.read_protected(expected[asset["id"]])


if __name__ == "__main__":
    unittest.main()
