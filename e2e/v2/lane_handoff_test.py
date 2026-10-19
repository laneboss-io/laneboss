#!/usr/bin/python3 -I
"""Real Python subprocess/descriptor controls; no service identity is claimed."""

import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True


def child():
    args = sys.argv
    request = json.loads(Path(args[args.index("--request") + 1]).read_bytes())
    try:
        data = os.pread(request["binding_fd"], 1048576, 0)
        info = os.fstat(request["socket_fd"])
        if not stat.S_ISSOCK(info.st_mode):
            return 81
        try:
            other = os.fstat(request["foreign_fd"])
        except OSError:
            other = None
        if other is not None and [other.st_dev, other.st_ino] == request["foreign_identity"]:
            return 82
        print(json.dumps({"sha256": hashlib.sha256(data).hexdigest(),
                          "socket_identity": [info.st_dev, info.st_ino]}))
        return 0
    except OSError:
        return 83


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="lb-v2-it2-handoff-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.root.chmod(0o700)
        spec = importlib.util.spec_from_file_location("grants_handoff_case",
                    Path(__file__).parent / "cases" / "grants" / "run.py")
        self.case = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.case)
        self.binding_path = self.root / "lane-binding.json"
        self.socket_path = self.root / "lane-socket"
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(self.listener.close)
        self.listener.bind(str(self.root / "native.sock"))
        os.chmod(self.root / "native.sock", 0o666)
        self.socket_fd = os.open(self.root / "native.sock", os.O_PATH | os.O_CLOEXEC)
        if self.socket_fd < 6:
            old = self.socket_fd
            self.socket_fd = fcntl.fcntl(old, fcntl.F_DUPFD_CLOEXEC, 6)
            os.close(old)
        self.addCleanup(os.close, self.socket_fd)
        self.binding_fd = os.memfd_create("handoff-fixture", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        if self.binding_fd < 6:
            old = self.binding_fd
            self.binding_fd = fcntl.fcntl(old, fcntl.F_DUPFD_CLOEXEC, 6)
            os.close(old)
        self.addCleanup(os.close, self.binding_fd)
        self.raw = json.dumps({"class": "lane", "config": "handoff-fixture",
            "contract_revision": "v2.0-draft.4",
            "socket": str(self.socket_path), "mapped_service_uid": os.geteuid(),
            "mapped_service_gid": os.getegid(), "nonce": secrets.token_hex(24)}).encode()
        os.write(self.binding_fd, self.raw)
        os.fchmod(self.binding_fd, 0o444)
        fcntl.fcntl(self.binding_fd, fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        self.binding_path.symlink_to("/proc/self/fd/" + str(self.binding_fd))
        self.socket_path.symlink_to("/proc/self/fd/" + str(self.socket_fd))
        if hasattr(self.case, "HANDOFF"):
            self.case.HANDOFF.LANE_BINDING = str(self.binding_path)
            self.case.HANDOFF.LANE_SOCKET = str(self.socket_path)
        self.foreign = os.open(self.root / "foreign", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        self.addCleanup(os.close, self.foreign)
        os.set_inheritable(self.foreign, True)
        probe = self.root / "probe"
        probe.write_bytes(Path(__file__).read_bytes())
        probe.chmod(0o500)
        self.observer = self.case.Case({"binary": str(probe), "config": "handoff-fixture",
            "binding_file": str(self.binding_path), "evidence_root": str(self.root / "evidence")})

    def test_exact_descendant_handoff(self):
        foreign = os.fstat(self.foreign)
        try:
            result = self.observer.call("identity self", {"binding_fd": self.binding_fd,
                "socket_fd": self.socket_fd, "foreign_fd": self.foreign,
                "foreign_identity": [foreign.st_dev, foreign.st_ino]})
        except AssertionError:
            # A red must reach the child's actual missing-FD read, rather than
            # count an interpreter/setup error as a killed handoff control.
            self.assertEqual(self.observer.last_exit, 83,
                             "descriptor control failed before the child's FD read")
            self.fail("Python descendant lost its fixed descriptors at exec")
        socket_info = os.fstat(self.socket_fd)
        self.assertEqual(result, {"sha256": hashlib.sha256(self.raw).hexdigest(),
            "socket_identity": [socket_info.st_dev, socket_info.st_ino]},
            "Python descendant lost its exact sealed binding or pinned socket")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "identity":
        sys.exit(child())
    unittest.main()
