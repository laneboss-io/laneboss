"""Private item observer transport with no product authority."""

import json
import os
from pathlib import Path
import socket
import stat
import struct


def exchange(request):
    path = os.environ.get("LANEBOSS_ITEM_SOCKET", "")
    token = os.environ.get("LANEBOSS_ITEM_TOKEN", "")
    if not path or not token:
        raise ValueError("dirty item observer handoff is absent")
    endpoint = Path(path)
    info = endpoint.lstat()
    if (not endpoint.is_absolute() or endpoint.resolve(strict=True) != endpoint or
            not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid() or
            stat.S_IMODE(info.st_mode) != 0o600 or len(token) != 32):
        raise ValueError("dirty item observer endpoint is unsafe")
    raw = json.dumps(dict(request, token=token), sort_keys=True).encode()
    if not 0 < len(raw) <= 2 << 20:
        raise ValueError("dirty item observer request exceeds its bound")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(180)
        peer.connect(str(endpoint))
        _, uid, _ = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != os.geteuid():
            raise ValueError("dirty item observer peer changed UID")
        peer.sendall(struct.pack("!I", len(raw)) + raw)

        def exact(size):
            value = bytearray()
            while len(value) < size:
                part = peer.recv(size - len(value))
                if not part:
                    raise ValueError("dirty item observer closed before its response")
                value.extend(part)
            return bytes(value)

        size = struct.unpack("!I", exact(4))[0]
        if not 0 < size <= 2 << 20:
            raise ValueError("dirty item observer response exceeds its bound")
        return json.loads(exact(size))
