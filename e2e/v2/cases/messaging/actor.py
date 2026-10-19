#!/usr/bin/env python3
"""Test relay, started inside an authentic life by the installed harness.

This does not register an identity or create a production runner. Every child
invokes the real installed CLI and inherits this process's OS confinement.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile

from lane_fds import lane_fds


MAX_FRAME = 4 * 1024 * 1024


def receive_exact(connection, size):
    result = bytearray()
    while len(result) < size:
        part = connection.recv(size - len(result))
        if not part:
            raise ValueError("truncated fixture frame")
        result.extend(part)
    return bytes(result)


def receive(connection):
    size = struct.unpack(">I", receive_exact(connection, 4))[0]
    if not 0 < size <= MAX_FRAME:
        raise ValueError("fixture frame exceeds bound")
    return json.loads(receive_exact(connection, size))


def send(connection, value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    if len(raw) > MAX_FRAME:
        raise ValueError("fixture response exceeds bound")
    connection.sendall(struct.pack(">I", len(raw)) + raw)


def execute(options, request):
    command = request["command"]
    flags = request.get("flags", [])
    if not isinstance(command, list) or not command:
        raise ValueError("fixture CLI command is missing")
    if not all(isinstance(word, str) for word in command + flags):
        raise ValueError("fixture command words must be strings")
    binary = Path(options.binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if digest != options.binary_sha256:
        raise ValueError("actor artifact changed")
    with tempfile.TemporaryDirectory(prefix="mail-input-", dir=options.work_root) as directory:
        directory = Path(directory)
        argv = [str(binary), *command, "--config", options.config]
        if "file_bytes" in request:
            content = base64.b64decode(request["file_bytes"], validate=True)
            if len(content) > 262144:
                raise ValueError("fixture mail input exceeds bound")
            path = directory / "message.txt"
            path.write_bytes(content)
            argv.extend(["--file", str(path)])
        else:
            content = json.dumps(request["params"], separators=(",", ":")).encode()
            path = directory / "request.json"
            path.write_bytes(content)
            argv.extend(["--request", str(path)])
        argv.extend(flags)
        completed = subprocess.run(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=120, check=False,
            pass_fds=lane_fds(options.config),
        )
        return {
            "exit": completed.returncode,
            "stdout": base64.b64encode(completed.stdout).decode(),
            "stderr": base64.b64encode(completed.stderr).decode(),
            "input_sha256": hashlib.sha256(content).hexdigest(),
            "input_bytes": len(content),
            "binary_sha256": digest,
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--work-root", required=True)
    options = parser.parse_args()
    endpoint = Path(options.socket)
    if not endpoint.is_absolute() or endpoint.exists():
        raise ValueError("actor socket must be new and absolute")
    # Each actor is granted only its own control directory, never a shared
    # sibling socket directory. The outside harness owns routing to them.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(endpoint))
        endpoint.chmod(0o600)
        listener.listen(4)
        try:
            running = True
            while running:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(130)
                    request = receive(connection)
                    if request == {"action": "close"}:
                        running = False
                        send(connection, {"closed": True})
                    else:
                        send(connection, execute(options, request))
        finally:
            endpoint.unlink()


if __name__ == "__main__":
    main()
