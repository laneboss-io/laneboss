"""Read-only egress prerequisite checks and isolated refusal controls."""

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("boot", Path(__file__).with_name("boot.py"))
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


class HostTools(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0, "requires disposable Linux root")
        directory = tempfile.TemporaryDirectory(prefix="lb-host-", dir="/opt")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.original = boot.EGRESS_TOOLS
        entries = []
        for spelling, package in self.original:
            path = self.root / Path(spelling).name
            path.write_bytes(b"#!/bin/sh\nexit 0\n")
            path.chmod(0o755)
            entries.append((str(path), package))
        patch = mock.patch.object(boot, "EGRESS_TOOLS", tuple(entries))
        patch.start()
        self.addCleanup(patch.stop)

    def test_present(self):
        self.assertEqual(boot.egress_tools(), {
            "nft": self.root / "nft", "ip": self.root / "ip"})

    def test_missing(self):
        (self.root / "nft").unlink()
        with self.assertRaisesRegex(boot.Stopped, "nft.*nftables"):
            boot.egress_tools()

    def test_writable(self):
        (self.root / "nft").chmod(0o777)
        with self.assertRaisesRegex(boot.Stopped, "unsafe controlled egress prerequisite"):
            boot.egress_tools()

    def test_nonexecuting(self):
        (self.root / "nft").chmod(0o644)
        with self.assertRaisesRegex(boot.Stopped, "unsafe controlled egress prerequisite"):
            boot.egress_tools()

    def test_links(self):
        os.link(self.root / "nft", self.root / "alias")
        with self.assertRaisesRegex(boot.Stopped, "unsafe controlled egress prerequisite"):
            boot.egress_tools()

    def test_directory(self):
        (self.root / "nft").unlink()
        (self.root / "nft").mkdir()
        with self.assertRaisesRegex(boot.Stopped, "unsafe controlled egress prerequisite"):
            boot.egress_tools()

    def test_gate_host(self):
        with mock.patch.object(boot, "EGRESS_TOOLS", self.original):
            found = boot.egress_tools()
        self.assertEqual(set(found), {"nft", "ip"})
        result = subprocess.run([str(found["nft"]), "--version"], check=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}, timeout=5)
        self.assertIn(b"nftables", result.stdout)
        print("gate host nft present: " + result.stdout.decode().strip())


if __name__ == "__main__":
    unittest.main(verbosity=2)
