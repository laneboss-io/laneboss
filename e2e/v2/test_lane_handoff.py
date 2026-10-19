import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import lane_handoff


class LaneHandoffTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(directory)
        self.listener = self.enterContext(socket.socket(socket.AF_UNIX))
        self.listener.bind(str(self.root / "socket"))
        os.chmod(self.root / "socket", 0o666)
        original = os.memfd_create("lane-binding", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        self.binding_fd = fcntl.fcntl(original, fcntl.F_DUPFD_CLOEXEC, 6)
        os.close(original)
        self.addCleanup(os.close, self.binding_fd)
        original = os.open(self.root / "socket", os.O_PATH | os.O_CLOEXEC)
        self.socket_fd = fcntl.fcntl(original, fcntl.F_DUPFD_CLOEXEC, 6)
        os.close(original)
        self.addCleanup(os.close, self.socket_fd)
        self.binding = str(self.root / "binding")
        self.endpoint = str(self.root / "endpoint")
        Path(self.binding).symlink_to(f"/proc/self/fd/{self.binding_fd}")
        Path(self.endpoint).symlink_to(f"/proc/self/fd/{self.socket_fd}")
        self.enterContext(mock.patch.object(lane_handoff, "LANE_BINDING", self.binding))
        self.enterContext(mock.patch.object(lane_handoff, "LANE_SOCKET", self.endpoint))
        self.enterContext(mock.patch.dict(os.environ, {"LANEBOSS_CONFIG": ""}))
        self.body = {"class": "lane", "config": "case-wire", "socket": self.endpoint,
                     "contract_revision": "v2.0-draft.4",
                     "mapped_service_uid": os.getuid(), "mapped_service_gid": os.getgid()}

    def seal(self, raw=None):
        raw = json.dumps(self.body).encode() if raw is None else raw
        os.write(self.binding_fd, raw)
        os.fchmod(self.binding_fd, 0o444)
        required = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                    fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        fcntl.fcntl(self.binding_fd, fcntl.F_ADD_SEALS, required)
        return raw

    def test_real_descriptors(self):
        body = self.seal()
        retained = lane_handoff.lane_descriptors("case-wire", self.binding)
        self.assertEqual(retained, (self.binding_fd, self.socket_fd))
        code = ("import hashlib,os,sys; "
                "print(hashlib.sha256(os.pread(int(sys.argv[1]),1048576,0)).hexdigest()); "
                "assert os.fstat(int(sys.argv[2])).st_ino==int(sys.argv[3])")
        command = [sys.executable, "-I", "-c", code, str(self.binding_fd),
                   str(self.socket_fd), str(os.fstat(self.socket_fd).st_ino)]
        omitted = subprocess.run(command, capture_output=True, check=False)
        self.assertNotEqual(omitted.returncode, 0)
        child = subprocess.run(command, close_fds=True, pass_fds=retained,
                               capture_output=True, check=False)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(child.stdout.strip(), hashlib.sha256(body).hexdigest().encode())
        with self.assertRaises(lane_handoff.HandoffRefusal) as refused:
            lane_handoff.lane_descriptors("foreign", self.binding)
        self.assertTrue(hasattr(refused.exception, "projection"),
                        "typed handoff refusal has no retained evidence projection")
        refusal = refused.exception.projection()
        self.assertEqual(refusal["code"], "prerequisite_missing")
        self.assertEqual(refusal["owner"], "lb-v2-linux")
        self.assertTrue(refusal["instead"])
        self.assertFalse(refusal["completed"])
        Path(self.endpoint).unlink()
        Path(self.endpoint).symlink_to(f"/proc/self/fd/{self.binding_fd}")
        with self.assertRaises(lane_handoff.HandoffRefusal):
            lane_handoff.lane_descriptors("case-wire", self.binding)

    def test_duplicate_fields(self):
        self.seal(json.dumps(self.body).encode()[:-1] + b',"config":"case-wire"}')
        with self.assertRaises(lane_handoff.HandoffRefusal):
            lane_handoff.lane_descriptors("case-wire", self.binding)

    def test_contract_revision(self):
        self.body["contract_revision"] = "v2.0-draft.3"
        self.seal()
        with self.assertRaises(lane_handoff.HandoffRefusal):
            lane_handoff.lane_descriptors("case-wire", self.binding)

    def test_projection_recheck(self):
        self.seal()
        readlink = os.readlink
        reads = 0

        def changed(path):
            nonlocal reads
            reads += 1
            if reads > 2 and path == self.binding:
                return f"/proc/self/fd/{self.socket_fd}"
            return readlink(path)

        with mock.patch.object(lane_handoff.os, "readlink", side_effect=changed):
            with self.assertRaises(lane_handoff.HandoffRefusal):
                lane_handoff.lane_descriptors("case-wire", self.binding)


if __name__ == "__main__":
    unittest.main()
