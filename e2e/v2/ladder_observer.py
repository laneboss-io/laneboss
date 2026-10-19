"""Independent, protected harness socket; never a production RPC bypass."""

from pathlib import Path
import secrets
import socket
import stat
import struct

from support import (Failure, atomic_bytes, decode, encoded, exact_keys,
                     immutable, load, require)


class RemoteFailure(Failure):
    def __init__(self, value, owner):
        exact_keys(value, ("code", "message", "instead", "retryable"),
                   ("owner", "operation_id"))
        super().__init__(value["message"], value["code"], value.get("owner", owner))
        self.value = value

    def wire(self):
        # Preserve the service's original error bytes separately as well.
        return self.value


def receive(connection, count):
    parts = []
    while count:
        block = connection.recv(count)
        require(bool(block), "observer disconnected before its complete frame")
        count -= len(block)
        parts.append(block)
    return b"".join(parts)


class Observer:
    def __init__(self, binding, root, artifact, draw):
        try:
            self.binding = load(immutable(binding))
        except FileNotFoundError:
            raise Failure("ladder observer binding absent", "not_implemented",
                          "lb-v2-integrate") from None
        exact_keys(self.binding, ("schema", "socket", "uid", "artifact_sha256"))
        require(self.binding["schema"] == "laneboss.ladder-observer.v2" and
                self.binding["artifact_sha256"] == artifact and
                type(self.binding["uid"]) is int and self.binding["uid"] == 0,
                "invalid independent observer binding")
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.artifact, self.draw = artifact, draw
        self.index = 0

    def call(self, method, params):
        require(method in ("preflight", "sample", "finalize", "collect"),
                "unknown ladder observer action")
        path = Path(self.binding["socket"])
        if not path.exists():
            raise Failure("ladder observer socket absent", "not_implemented",
                          "lb-v2-integrate")
        require(path.is_absolute() and path.resolve(strict=True) == path,
                "observer socket is not canonical")
        info = path.lstat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and
                info.st_mode & 0o002 == 0, "unprotected observer socket")
        for parent in path.parents:
            info = parent.stat()
            require(info.st_uid == 0 and info.st_mode & 0o022 == 0,
                    "observer socket has a writable ancestor")
        nonce = secrets.token_hex(16)
        request = {"schema": "laneboss.ladder-observe.v2", "nonce": nonce,
                   "artifact_sha256": self.artifact, "draw_sha256": self.draw,
                   "method": method, "params": params}
        raw = encoded(request)
        require(0 < len(raw) <= 1048576, "observer request exceeds frame bound")
        self.index += 1
        stem = self.root / str(self.index)
        atomic_bytes(stem.with_suffix(".request"), raw)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(30)
            try:
                connection.connect(str(path))
            except ConnectionRefusedError:
                raise Failure("ladder observer is not running", "not_implemented",
                              "lb-v2-integrate") from None
            peer = struct.unpack("3i", connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            require(peer[1] == self.binding["uid"], "observer peer UID differs")
            connection.sendall(struct.pack("!I", len(raw)) + raw)
            count = struct.unpack("!I", receive(connection, 4))[0]
            require(0 < count <= 1048576, "observer response exceeds frame bound")
            raw = receive(connection, count)
        atomic_bytes(stem.with_suffix(".response"), raw)
        response = decode(raw)
        exact_keys(response, ("schema", "nonce", "artifact_sha256", "draw_sha256"),
                   ("result", "error"))
        require(response["schema"] == request["schema"] and
                response["nonce"] == nonce and
                response["artifact_sha256"] == self.artifact and
                response["draw_sha256"] == self.draw and
                (("result" in response) != ("error" in response)),
                "observer response correlation failed")
        if "error" in response:
            raise RemoteFailure(response["error"], "lb-v2-integrate")
        return response["result"]
