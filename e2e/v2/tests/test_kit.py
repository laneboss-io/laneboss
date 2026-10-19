"""Real filesystem/socket canaries for the harness's own boundary helpers."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "e2e" / "v2"))
from box_support import Recorder, socket_matches
from support import Failure, clean_environment, load, sha256
import scope

KIT = ROOT / "scripts" / "v2-e2e" / "privileged.py"
spec = importlib.util.spec_from_file_location("tested_kit", KIT)
kit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kit)


class DescriptorControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / "scope"
        self.directory.mkdir()
        self.fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.fd)
        self.canary = os.urandom(24)
        self.outside = self.root / "canary"
        self.outside.write_bytes(self.canary)
        (self.directory / "control").write_bytes(os.urandom(24))

    def test_symlink_leaf(self):
        (self.directory / "link").symlink_to(self.outside)
        with self.assertRaises(OSError):
            kit.read_at(self.fd, "link")
        self.assertEqual(kit.read_at(self.fd, "control"), (self.directory / "control").read_bytes())
        self.assertEqual(self.outside.read_bytes(), self.canary)

    def test_symlink_parent(self):
        (self.directory / "parent").symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            kit.read_at(self.fd, "parent/canary")

    def test_fifo_does_not_block(self):
        os.mkfifo(self.directory / "fifo")
        started = time.monotonic()
        with self.assertRaisesRegex(kit.KitError, "regular"):
            kit.read_at(self.fd, "fifo")
        self.assertLess(time.monotonic() - started, 1)

    def test_traversal_and_hardlink(self):
        with self.assertRaisesRegex(kit.KitError, "relative"):
            kit.read_at(self.fd, "../canary")
        os.link(self.outside, self.directory / "alias")
        with self.assertRaisesRegex(kit.KitError, "hardlinked"):
            kit.read_at(self.fd, "alias")

    def test_write_alias_keeps_canary(self):
        os.link(self.outside, self.directory / "alias")
        with self.assertRaisesRegex(kit.KitError, "linked"):
            kit.write_at(self.fd, "alias", b"red", uid=os.getuid(), gid=os.getgid(),
                         replace=True)
        self.assertEqual(self.outside.read_bytes(), self.canary)
        kit.write_at(self.fd, "new", self.canary, uid=os.getuid(), gid=os.getgid())
        self.assertEqual((self.directory / "new").read_bytes(), self.canary)

    def test_swapped_final_entry(self):
        # Swap a safe entry with an outside symlink between independent reads.
        # Both paths exercise the same descriptor reader used by root.
        for index in range(20):
            target = self.directory / ("item-" + str(index))
            target.symlink_to(self.outside)
            with self.assertRaises(OSError):
                kit.read_at(self.fd, target.name)
            target.unlink()
            target.write_bytes(os.urandom(8))
            self.assertEqual(kit.read_at(self.fd, target.name), target.read_bytes())

    def test_pinned_read_survives_swap(self):
        target = self.directory / "control"
        inside = target.read_bytes()
        opened = kit.os.fdopen
        changed = []

        def swap_before_read(descriptor, *args, **kwargs):
            target.rename(self.directory / "held")
            target.symlink_to(self.outside)
            changed.append(True)
            return opened(descriptor, *args, **kwargs)

        with patch.object(kit.os, "fdopen", side_effect=swap_before_read):
            observed = kit.read_at(self.fd, "control")
        self.assertEqual(changed, [True])
        self.assertTrue(target.is_symlink())
        self.assertEqual(observed, inside)
        self.assertNotEqual(observed, self.canary)
        # Actual path reopen after the same swap reads the different canary.
        self.assertEqual(target.read_bytes(), self.canary)


class ProcessAndSocketControls(unittest.TestCase):
    def test_scope_resource_collection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "scope"
            path.mkdir()
            instance = scope.Scope.__new__(scope.Scope)
            instance.path, instance.root, instance.baseline = path, root, []
            instance.identity = path.stat()
            with patch.object(scope, "observation", return_value={"processes": []}):
                with patch.object(scope, "members", return_value=[]):
                    receipt = instance.collect(root / "collection.json")
            self.assertFalse(path.exists())
            self.assertTrue(receipt["temporary_resources_collected"])
            self.assertTrue(load(root / "collection.json")["collected"])

    def test_scope_nested_resource_is_red(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "scope"
            (path / "unregistered").mkdir(parents=True)
            instance = scope.Scope.__new__(scope.Scope)
            instance.path, instance.root, instance.baseline = path, root, []
            instance.identity = path.stat()
            with patch.object(scope, "observation", return_value={"processes": []}):
                with patch.object(scope, "members", return_value=[]):
                    with self.assertRaisesRegex(Failure, "collection"):
                        instance.collect(root / "collection.json")
            self.assertTrue(path.is_dir())
            self.assertFalse(load(root / "collection.json")["collected"])

    def test_forced_cleanup_continues(self):
        instance = kit.Kit.__new__(kit.Kit)
        identity = {"pid": 123, "start": "boot:1", "uids": [300] * 4}
        resources = {"teardown_complete": False,
                     "users": [{"name": "fixture", "uid": 300, "gid": 300}],
                     "groups": ["fixture"], "profile_loaded": False}
        instance.resources = lambda: resources
        instance.contract = {"shutdown_timeout_seconds": 10}
        instance.signal_process = Mock()
        instance.drift = Mock(return_value=True)
        instance.store = Mock()
        instance.record = Mock()
        instance.archive = Mock()
        with patch.object(kit, "processes", side_effect=[[identity], []]):
            with patch.object(kit.time, "monotonic", side_effect=[0, 11, 11, 12]):
                with patch.object(kit.pwd, "getpwnam", return_value=SimpleNamespace(
                        pw_uid=300, pw_gid=300)):
                    with patch.object(kit.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=300)):
                        with patch.object(kit, "checked") as command:
                            with self.assertRaisesRegex(kit.KitError, "collection failed"):
                                instance.teardown()
        self.assertFalse(resources["cleanup_ok"])
        self.assertTrue(resources["teardown_complete"])
        instance.archive.assert_called_once_with(resources)
        self.assertEqual(instance.signal_process.call_count, 2)
        self.assertEqual([call.args[0][0] for call in command.call_args_list],
                         ["/usr/sbin/userdel", "/usr/sbin/groupdel"])

    def test_plain_socket_is_red(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "plain.sock"
            previous = os.umask(0o022)
            try:
                with socket.socket(socket.AF_UNIX) as endpoint:
                    endpoint.bind(str(path))
                    info = path.stat()
                    actual = {"present": True, "uid": info.st_uid, "gid": info.st_gid,
                              "mode": stat.S_IMODE(info.st_mode)}
                    self.assertEqual(actual["mode"], 0o755)
                    with self.assertRaisesRegex(Failure, "socket"):
                        socket_matches(actual, os.getuid(), os.getgid(), 0o660)
                    path.chmod(0o660)
                    actual["mode"] = stat.S_IMODE(path.stat().st_mode)
                    self.assertIsNone(socket_matches(actual, os.getuid(), os.getgid(), 0o660))
            finally:
                os.umask(previous)

    def test_timeout_keeps_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recorder = Recorder(root)
            started = time.monotonic()
            with self.assertRaisesRegex(Failure, "deadline"):
                recorder.run(["/usr/bin/timeout", "--kill-after=1s", "0.1",
                              "/usr/bin/sleep", "5"], label="red-timeout", timeout=3,
                             environment=clean_environment(root, root))
            self.assertLess(time.monotonic() - started, 4)
            receipt = load(next(root.glob("*.json")))
            self.assertTrue(receipt["timed_out"])
            self.assertIn(receipt["exit_code"], (124, 137))

    def test_sigkill_exit_race(self):
        instance = kit.Kit.__new__(kit.Kit)
        with patch.object(kit.os, "pidfd_open", side_effect=ProcessLookupError()) as opened:
            self.assertIsNone(instance.signal_process({"pid": 123}, 9))
            opened.assert_called_once_with(123)

    def test_new_resource_drift_is_red(self):
        instance = kit.Kit.__new__(kit.Kit)
        captured = {}
        instance.record = lambda name, value: captured.update(value)
        original = {"accounts": {"base": [100, 100]}, "groups": {"base": 100},
                    "process_uids": [100]}
        resources = {"baseline": original, "users": [], "groups": []}
        changed = {"accounts": {"base": [100, 100], "new": [101, 101]},
                   "groups": {"base": 100, "new": 101}, "process_uids": [100, 101]}
        with patch.object(kit, "snapshot", return_value=changed):
            self.assertFalse(instance.drift(resources))
        self.assertEqual(captured["new_process_uids"], [101])
        with patch.object(kit, "snapshot", return_value=original):
            self.assertTrue(instance.drift(resources))

    def test_root_account_input_is_red(self):
        instance = kit.Kit.__new__(kit.Kit)
        instance.resources = lambda: {"accounts": {"service": {"name": "root", "uid": 0,
                                                             "gid": 0}}}
        with self.assertRaisesRegex(kit.KitError, "changed"):
            instance.account("service")

    def test_isolated_helper_imports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helper = root / "privileged.py"
            shutil.copyfile(KIT, helper)
            (root / "json.py").write_text("raise RuntimeError('red module shadow')\n")
            environment = clean_environment(root, root)
            red = subprocess.run([sys.executable, "-B", str(helper), "--help"],
                                 cwd=root, env=environment, capture_output=True, timeout=5)
            self.assertNotEqual(red.returncode, 0)
            good = subprocess.run([sys.executable, "-I", "-B", str(helper), "--help"],
                                  cwd=root, env=environment, capture_output=True, timeout=5)
            self.assertEqual(good.returncode, 0)
            self.assertIn(b"provision", good.stdout)
