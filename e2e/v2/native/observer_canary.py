"""Root-only transport canaries. This server supplies no ladder observations."""

import os
from pathlib import Path
import secrets
import select
import signal
import socket
import struct
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ladder_observer import Observer, RemoteFailure, receive
from support import Failure, decode, encoded, save


class NativeObserver(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0)
        self.temporary = tempfile.TemporaryDirectory(prefix="lb-v2-it8-observer-", dir="/run")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o755)
        self.artifact, self.draw = secrets.token_hex(32), secrets.token_hex(32)
        self.path = self.root / "observer.sock"

    def client(self, uid=0):
        binding = self.root / "binding.json"
        save(binding, {"schema": "laneboss.ladder-observer.v2", "socket": str(self.path),
                       "uid": uid, "artifact_sha256": self.artifact}, mode=0o444)
        return Observer(binding, self.root / secrets.token_hex(8), self.artifact, self.draw)

    def server(self, mutate=None, calls=1):
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.path))
        listener.listen(2)
        listener.settimeout(5)
        errors = []
        replies = []

        def run():
            try:
                for _ in range(calls):
                    with listener.accept()[0] as connection:
                        connection.settimeout(5)
                        length = struct.unpack("!I", receive(connection, 4))[0]
                        request = decode(receive(connection, length))
                        response = {name: request[name] for name in
                                    ("schema", "nonce", "artifact_sha256", "draw_sha256")}
                        # Echo an independently received challenge. No ready,
                        # process, timing, collection or acceptance fact exists.
                        response["result"] = {"received_nonce": request["nonce"], "method": request["method"]}
                        if mutate is not None:
                            mutate(response, replies)
                        replies.append(response)
                        raw = encoded(response)
                        connection.sendall(struct.pack("!I", len(raw)) + raw)
            except BaseException as error:
                errors.append(error)
            finally:
                listener.close()

        thread = threading.Thread(target=run)
        thread.start()

        def finish():
            thread.join(6)
            self.assertFalse(thread.is_alive(), "native canary server survived")
            self.assertEqual(errors, [])
        self.addCleanup(finish)
        return replies

    def test_boolean_uid_is_not_native_identity(self):
        with self.assertRaisesRegex(Failure, "binding"):
            self.client(uid=False)

    def test_native_nonce_input(self):
        replies = self.server()
        result = self.client().call("preflight", {"configs": ["tree-a", "tree-b"]})
        self.assertEqual(result, replies[0]["result"])
        self.assertEqual(result["method"], "preflight")
        self.assertEqual(len(result["received_nonce"]), 32)

    def test_foreign_stale_frames(self):
        for field in ("artifact_sha256", "draw_sha256", "nonce"):
            with self.subTest(field=field):
                path = self.root / field
                path.mkdir()
                self.path = path / "observer.sock"
                self.server(lambda response, _old: response.update({field: secrets.token_hex(32)}))
                with self.assertRaisesRegex(Failure, "correlation"):
                    self.client().call("preflight", {"configs": ["tree-a", "tree-b"]})

    def test_replayed_native_response_refuses(self):
        def replay(response, old):
            if old:
                response.clear()
                response.update(old[0])
        self.server(replay, calls=2)
        client = self.client()
        client.call("preflight", {"configs": ["tree-a", "tree-b"]})
        with self.assertRaisesRegex(Failure, "correlation"):
            client.call("preflight", {"configs": ["tree-a", "tree-b"]})

    def test_typed_refusal_is_preserved(self):
        refusal = {"code": "prerequisite_missing", "message": "native observation producer absent",
                   "owner": "lb-v2-integrate", "instead": "install the reviewed producer", "retryable": False}
        def refuse(response, _old):
            del response["result"]
            response["error"] = refusal
        self.server(refuse)
        with self.assertRaises(RemoteFailure) as caught:
            self.client().call("preflight", {"configs": ["tree-a", "tree-b"]})
        self.assertEqual(caught.exception.wire(), refusal)

    def test_missing_socket(self):
        with self.assertRaises(Failure) as caught:
            self.client().call("preflight", {"configs": ["tree-a", "tree-b"]})
        self.assertEqual(caught.exception.code, "not_implemented")

    def test_nonroot_peer(self):
        directory = self.root / "foreign"
        directory.mkdir(mode=0o700)
        os.chown(directory, 65534, 65534)
        self.path = directory / "observer.sock"
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                    listener.bind(str(self.path))
                    listener.listen(1)
                    listener.settimeout(5)
                    os.write(write_fd, b"R")
                    with listener.accept()[0] as connection:
                        connection.settimeout(5)
                        # Refusal must close before any request is disclosed.
                        observed = connection.recv(1)
                        os._exit(0 if observed == b"" else 3)
            except BaseException:
                os._exit(2)
        os.close(write_fd)
        try:
            self.assertTrue(select.select([read_fd], [], [], 5)[0], "foreign listener failed setup")
            self.assertEqual(os.read(read_fd, 1), b"R")
            os.chown(self.path, 0, 0)
            os.chown(directory, 0, 0)
            directory.chmod(0o755)
            with self.assertRaisesRegex(Failure, "peer UID"):
                self.client().call("preflight", {"configs": ["tree-a", "tree-b"]})
            self.assertEqual(os.waitpid(pid, 0)[1], 0)
            pid = 0
        finally:
            os.close(read_fd)
            if pid:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    self.assertEqual(os.waitpid(pid, 0)[0], pid)
                    pid = 0
                if pid:
                    self.assertEqual(os.waitpid(pid, 0)[0], pid)


if __name__ == "__main__":
    unittest.main(verbosity=2, failfast=True)
