"""A root negative peer that reaches the real installed helper socket."""

import argparse
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys


def exact(connection, size):
    result = bytearray()
    while len(result) < size:
        part = connection.recv(size - len(result))
        if not part:
            raise RuntimeError("incomplete framed helper refusal")
        result.extend(part)
    return bytes(result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    if sys.platform != "linux" or os.getuid() != 0 or os.geteuid() != 0 or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", args.config):
        raise RuntimeError("authorized root negative peer required")
    # This test entry is itself installed/executed only from the protected
    # source bundle. It accepts no command, socket path or root argv selector.
    current = Path(__file__).absolute()
    while True:
        info = current.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise RuntimeError("untrusted root probe source")
        if current == Path("/"):
            break
        current = current.parent
    binding = json.loads((Path("/etc/laneboss-v2/admin") / (args.config + ".json")).read_bytes())
    if binding["service"]["uid"] == 0:
        raise RuntimeError("negative peer is the installed service")
    rows = []
    for extra in ({}, {"argv": ["/usr/bin/true"]}, {"path": "/root"}):
        request = {"protocol": "laneboss.helper.v2", "contract_revision": "v2.0-draft.4", "config": args.config,
                   "generation": binding["generation"], "artifact_sha256": binding["artifact"]["sha256"],
                   "nonce": "negative-" + os.urandom(16).hex(), "method": "probe", "params": {}, **extra}
        data = json.dumps(request).encode()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(str(Path("/run/laneboss-v2") / args.config / "helper.sock"))
            # The helper can refuse at SO_PEERCRED before reading the body.
            # Its actual framed response still has to arrive from this socket.
            send_error = None
            try:
                connection.sendall(struct.pack("!I", len(data)) + data)
            except BrokenPipeError as failure:
                # A send raced the peer rejection; receiving a complete typed
                # refusal below, rather than this exception, proves the check.
                send_error = failure.errno
            length = struct.unpack("!I", exact(connection, 4))[0]
            if not 0 < length <= 1048576:
                raise RuntimeError("invalid helper frame bound")
            response = json.loads(exact(connection, length))
        if "result" in response or response.get("error", {}).get("code") != "forbidden":
            raise RuntimeError("real nonservice peer check did not refuse")
        rows.append({"connected": True, "uid": os.getuid(), "send_errno": send_error, "request": request, "response": response})
    print(json.dumps({"connected": True, "service_uid": binding["service"]["uid"], "rows": rows}))


if __name__ == "__main__":
    main()
