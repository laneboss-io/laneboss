import fcntl
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("lane_fds", Path(__file__).with_name("lane_fds.py"))
handoff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoff)


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        root = Path(self.scratch.name)
        handoff.BINDING_PATH, handoff.SOCKET_PATH = root / "binding", root / "socket"
        self.binding = self.memfd({"config": "case-mail", "class": "lane", "socket": "/run/laneboss/service.sock"})
        self.left, self.right = socket.socketpair()
        self.addCleanup(self.left.close)
        self.addCleanup(self.right.close)
        self.endpoint = fcntl.fcntl(self.left.fileno(), fcntl.F_DUPFD_CLOEXEC, 10)
        self.addCleanup(self.close_endpoint)
        handoff.BINDING_PATH.symlink_to("/proc/self/fd/" + str(self.binding))
        handoff.SOCKET_PATH.symlink_to("/proc/self/fd/" + str(self.endpoint))

    def close_endpoint(self):
        if self.endpoint is not None:
            os.close(self.endpoint)
            self.endpoint = None

    def memfd(self, value, sealed=True):
        fd = os.memfd_create("lane-projection-test", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
        self.addCleanup(os.close, fd)
        os.write(fd, json.dumps(value).encode())
        os.fchmod(fd, 0o444)
        if sealed:
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        retained = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 10)
        self.addCleanup(os.close, retained)
        return retained

    def test_exact_child_numbers_and_no_a_d560(self):
        descriptors = handoff.lane_fds("case-mail")
        self.assertEqual(descriptors, (self.binding, self.endpoint))
        offset = os.lseek(self.binding, 0, os.SEEK_CUR)
        self.assertEqual(handoff.lane_fds("case-mail"), descriptors)
        self.assertEqual(os.lseek(self.binding, 0, os.SEEK_CUR), offset)
        ambient = os.open(self.scratch.name, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, ambient)
        os.set_inheritable(ambient, True)
        probe = Path(self.scratch.name) / "probe.py"
        probe.write_text("import os,sys\na,b,c=map(int,sys.argv[1:])\nos.fstat(a);os.fstat(b)\ntry: os.fstat(c)\nexcept OSError: print('only fixed descriptors retained')\nelse: raise AssertionError('ambient descriptor inherited')\n")
        child = subprocess.run([sys.executable, "-I", str(probe), str(self.binding), str(self.endpoint), str(ambient)],
                               pass_fds=descriptors, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(child.stdout, b"only fixed descriptors retained\n")

    def test_foreign_configuration(self):
        with self.assertRaisesRegex(ValueError, "configuration"):
            handoff.lane_fds("foreign")

    def test_unsealed_binding(self):
        fd = self.memfd({"config": "case-mail"}, sealed=False)
        handoff.BINDING_PATH.unlink()
        handoff.BINDING_PATH.symlink_to("/proc/self/fd/" + str(fd))
        with self.assertRaisesRegex(ValueError, "sealed"):
            handoff.lane_fds("case-mail")

    def test_stale_socket(self):
        self.close_endpoint()
        with self.assertRaises(OSError):
            handoff.lane_fds("case-mail")

    def test_missing_projection(self):
        handoff.BINDING_PATH.unlink()
        with self.assertRaises(FileNotFoundError):
            handoff.lane_fds("case-mail")

    def test_descriptor_link_grammar(self):
        for link in ("/proc/self/fd/06", "/proc/self/fd/5", "/proc/self/fd/4097", "/dev/fd/10", "/proc/self/fd/10/extra"):
            handoff.BINDING_PATH.unlink()
            handoff.BINDING_PATH.symlink_to(link)
            with self.assertRaises(ValueError):
                handoff.lane_fds("case-mail")


if __name__ == "__main__":
    unittest.main()
