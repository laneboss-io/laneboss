"""Private outside-observer channel; contains no lane transport authority."""

import json
import os
from pathlib import Path
import socket
import stat
import struct


def available():
    path = os.environ.get("LANEBOSS_ITEM_SOCKET", "")
    token = os.environ.get("LANEBOSS_ITEM_TOKEN", "")
    assert bool(path) == bool(token), "incomplete installed observer handoff"
    return bool(path)


def exchange(request):
    assert available(), "independent installed observer was not supplied"
    path = Path(os.environ["LANEBOSS_ITEM_SOCKET"])
    token = os.environ["LANEBOSS_ITEM_TOKEN"]
    info = path.lstat()
    assert path.is_absolute() and path.resolve(strict=True) == path
    assert stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid()
    assert stat.S_IMODE(info.st_mode) == 0o600 and len(token) == 32
    raw = json.dumps(dict(request, token=token), sort_keys=True).encode()
    assert 0 < len(raw) <= 2 << 20, "observer request exceeds bound"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(180)
        peer.connect(str(path))
        _, uid, _ = struct.unpack("3i", peer.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        assert uid == os.geteuid(), "observer changed UID"
        peer.sendall(struct.pack("!I", len(raw)) + raw)

        def exact(size):
            value = bytearray()
            while len(value) < size:
                part = peer.recv(size - len(value))
                assert part, "observer stopped; retain its original failure"
                value.extend(part)
            return value

        size = struct.unpack("!I", exact(4))[0]
        assert 0 < size <= 2 << 20, "observer reply exceeds bound"
        return json.loads(exact(size))
