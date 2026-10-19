"""G0's private observer channel; it conveys no product RPC authority."""

import json
import os
from pathlib import Path
import socket
import stat
import struct


def available():
    path = os.environ.get("LANEBOSS_ITEM_SOCKET", "")
    token = os.environ.get("LANEBOSS_ITEM_TOKEN", "")
    if bool(path) != bool(token):
        raise ValueError("incomplete installed policy observer handoff")
    return bool(path)


def exchange(request):
    if not available():
        raise ValueError("independent policy observer was not supplied")
    path = Path(os.environ["LANEBOSS_ITEM_SOCKET"])
    token = os.environ["LANEBOSS_ITEM_TOKEN"]
    info = path.lstat()
    if (not path.is_absolute() or path.resolve(strict=True) != path
            or not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or len(token) != 32):
        raise ValueError("unsafe installed policy observer endpoint")
    raw = json.dumps(dict(request, token=token), sort_keys=True).encode()
    if not 0 < len(raw) <= 2 << 20:
        raise ValueError("policy observer request exceeds bound")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(180)
        peer.connect(str(path))
        _, uid, _ = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != os.geteuid():
            raise ValueError("policy observer peer changed UID")
        peer.sendall(struct.pack("!I", len(raw)) + raw)

        def exact(size):
            value = bytearray()
            while len(value) < size:
                part = peer.recv(size - len(value))
                if not part:
                    raise ValueError("policy observer stopped; retain its original failure")
                value.extend(part)
            return value

        size = struct.unpack("!I", exact(4))[0]
        if not 0 < size <= 2 << 20:
            raise ValueError("policy observer response exceeds bound")
        return json.loads(exact(size))
