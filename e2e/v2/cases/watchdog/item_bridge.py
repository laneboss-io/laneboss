"""G0 observer client. Product authority stays in the original native actor."""
import base64
import json
import os
import secrets
import socket
import struct
import subprocess

from controls import Controller, need, parse


class Bridge:
    def __init__(self):
        self.socket = os.environ.get("LANEBOSS_ITEM_SOCKET")
        self.token = os.environ.get("LANEBOSS_ITEM_TOKEN")
        need(bool(self.socket) and bool(self.token), "G0 original-actor transport is missing")

    def call(self, command, request, request_id=None, key=None, *, denied=False):
        data = json.dumps({"action": "rpc", "token": self.token, "command": command,
            "request": request, "denied": denied, "request_id": request_id or secrets.token_hex(16),
            "idempotency_key": key or secrets.token_hex(16)}, separators=(",", ":")).encode()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(180)
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            channel.connect(self.socket)
            peer = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            need(peer[0] > 0 and peer[1] == os.geteuid(), "G0 observer kernel peer differs")
            channel.sendall(struct.pack("!I", len(data)) + data)
            size, = struct.unpack("!I", Controller.receive(channel, peer, 4))
            need(0 < size <= 2 << 20, "G0 observer response exceeds its frame bound")
            reply = parse(Controller.receive(channel, peer, size))
        need(set(reply) == {"exit_code", "stdout", "stderr"} and type(reply["exit_code"]) is int,
             "G0 transport returned no actual command receipt")
        return subprocess.CompletedProcess([command], reply["exit_code"],
            base64.b64decode(reply["stdout"], validate=True), base64.b64decode(reply["stderr"], validate=True))


class Reader:
    def __init__(self, bridge):
        self.bridge = bridge

    def preflight(self):
        result = self.bridge.call("fixture reader-open", {})
        need(result.returncode == 0, "independent G0 reader did not authenticate")
        session = parse(result.stdout)
        need(session.get("simulated_presence") is True, "G0 reader lost its declared presence provenance")

    def read(self, method, exact_params, request_id, key):
        return self.bridge.call(method.replace(".", " "), parse(exact_params), request_id, key)

    def close(self):
        return self.bridge.call("fixture reader-close", {}).returncode
