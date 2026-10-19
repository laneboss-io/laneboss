"""Harness-only transport to a separately enrolled test reader process."""

import base64
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import subprocess
import sys

from controls import Controller, ControlError, closed, need, parse, protected


class ReaderWait(RuntimeError):
    code = "prerequisite_missing"


def wire(value):
    return json.dumps(value, separators=(",", ":")).encode()


def receive(connection, peer):
    length = struct.unpack(">I", Controller.receive(connection, peer, 4))[0]
    need(0 < length <= 4 * 1024 * 1024, "reader frame exceeds its bound")
    return Controller.receive(connection, peer, length)


def send(connection, value):
    raw = wire(value)
    need(0 < len(raw) <= 4 * 1024 * 1024, "reader frame exceeds its bound")
    connection.sendall(struct.pack(">I", len(raw)) + raw)


class SocketReader:
    def __init__(self, context, binding_file, keep):
        raw, owner = protected(binding_file, {0, os.getuid()}, 1024 * 1024)
        binding = parse(raw)
        closed(binding, "schema config socket reader_uid case_uid binary_sha256 simulated_presence")
        need(binding["schema"] == "laneboss.watchdog-reader.v1" and binding["config"] == context["config"]
             and binding["case_uid"] == os.getuid() and type(binding["reader_uid"]) is int
             and binding["reader_uid"] >= 0 and owner in {0, binding["reader_uid"], binding["case_uid"]}
             and binding["binary_sha256"] == context["binary_sha256"], "reader binding differs from the case")
        if binding["simulated_presence"] is not True:
            raise ReaderWait("real human reader remains an owner human.session wait")
        self.binding, self.keep, self.closed, self.peer_pid = binding, keep, False, 0
        self.close_code = None
        keep("reader-binding.json", raw)

    def invoke(self, action, **params):
        need(not self.closed, "outside reader is closed")
        request = {"schema": "laneboss.watchdog-read.v1", "config": self.binding["config"],
                   "action": action, "request_id": secrets.token_hex(16), "nonce": secrets.token_hex(16), **params}
        self.keep("reader-request.json", wire(request))
        endpoint = Path(self.binding["socket"])
        need(endpoint.is_absolute(), "reader endpoint is relative")
        info = endpoint.lstat()
        need(stat.S_ISSOCK(info.st_mode) and info.st_uid == self.binding["reader_uid"]
             and not info.st_mode & 0o007, "reader socket differs from its enrolled owner")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(70)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            connection.connect(str(endpoint))
            peer = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            need(peer[0] > 0 and peer[1] == self.binding["reader_uid"], "reader kernel peer differs")
            self.peer_pid = peer[0]
            send(connection, request)
            raw = receive(connection, peer)
        self.keep("reader-reply.json", raw)
        reply = parse(raw)
        closed(reply, "schema config request_id nonce " + ("error" if "error" in reply else "result"))
        need(reply["schema"] == "laneboss.watchdog-reply.v1" and
             all(reply[key] == request[key] for key in ("config", "request_id", "nonce")), "reader reply correlation differs")
        if "error" in reply:
            error = reply["error"]
            if error.get("code") == "prerequisite_missing":
                raise ReaderWait(error["message"])
            raise RuntimeError("outside reader failed: " + error["message"])
        return reply["result"]

    def preflight(self):
        result = self.invoke("open")
        need(result["session"]["config"] == self.binding["config"]
             and result["session"].get("simulated_presence") is True, "reader lost its test identity provenance")

    def read(self, method, exact_params, request_id, idempotency_key):
        try:
            result = self.invoke("read", method=method, params=base64.b64encode(exact_params).decode(),
                                 read_id=request_id, key=idempotency_key)
            closed(result, "exit_code stdout stderr")
            need(type(result["exit_code"]) is int, "reader exit is not measured")
            return subprocess.CompletedProcess(["outside-reader", method], result["exit_code"],
                base64.b64decode(result["stdout"], validate=True), base64.b64decode(result["stderr"], validate=True))
        except (OSError, ControlError, ValueError) as error:
            raise RuntimeError("outside reader transport failed: " + str(error)) from error

    def close(self):
        if self.closed:
            return self.close_code
        result = self.invoke("close")
        closed(result, "exit_code")
        need(type(result["exit_code"]) is int, "reader close has no measured exit")
        self.closed = True
        self.close_code = result["exit_code"]
        return self.close_code


def serve(listener, reader, config, case_uid):
    """Run in the enrolled test identity, outside the L6 case's process."""
    try:
        while True:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(70)
                connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                peer = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                need(peer[0] > 0 and peer[1] == case_uid, "reader caller is not its enrolled case")
                request = parse(receive(connection, peer))
                action = request.get("action")
                fields = "schema config action request_id nonce" + (" method params read_id key" if action == "read" else "")
                closed(request, fields)
                need(request["schema"] == "laneboss.watchdog-read.v1" and request["config"] == config
                     and action in {"open", "read", "close"}, "outside reader received another operation")
                reply = {"schema": "laneboss.watchdog-reply.v1", **{key: request[key] for key in ("config", "request_id", "nonce")}}
                try:
                    if action == "close":
                        reply["result"] = {"exit_code": reader.close(success=False)}
                    else:
                        proof = parse(reader.proof_file.read_bytes())
                        if proof.get("simulated_presence") is not True:
                            raise ReaderWait("real human reader remains an owner human.session wait")
                        reader.ensure_open()
                        need(reader.session.get("simulated_presence") is True, "reader session lost its test identity marker")
                        if action == "open":
                            reply["result"] = {"session": reader.session}
                        else:
                            completed = reader.read(request["method"], base64.b64decode(request["params"], validate=True),
                                                    request["read_id"], request["key"])
                            reply["result"] = {"exit_code": completed.returncode,
                                "stdout": base64.b64encode(completed.stdout).decode(), "stderr": base64.b64encode(completed.stderr).decode()}
                except (RuntimeError, ControlError, OSError, ValueError) as error:
                    reply["error"] = {"code": getattr(error, "code", "integrity"), "message": str(error)}
                send(connection, reply)
                if action == "close":
                    return
    finally:
        reader.close(success=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--setup", required=True, type=Path)
    args = parser.parse_args()
    raw, _ = protected(args.setup, {0, os.getuid()}, 1024 * 1024)
    setup = parse(raw)
    closed(setup, "schema config binary human_binding proof_file evidence_root socket case_uid")
    need(setup["schema"] == "laneboss.reader-setup.v1" and type(setup["case_uid"]) is int,
         "outside reader setup differs")
    proof, _ = protected(setup["proof_file"], {0, os.getuid()}, 1024 * 1024)
    if parse(proof).get("simulated_presence") is not True:
        raise ReaderWait("real human reader remains an owner human.session wait")
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from readsession import SessionReader
    reader = SessionReader(setup["binary"], setup["config"], setup["human_binding"], setup["proof_file"],
                           Path(setup["evidence_root"]) / "session", {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                           command=("internal", "reader"))
    endpoint = Path(setup["socket"])
    need(endpoint.is_absolute(), "outside reader requires an absolute installed socket")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(endpoint))
        endpoint.chmod(0o660)
        listener.listen(4)
        serve(listener, reader, setup["config"], setup["case_uid"])
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, ControlError, OSError, ValueError) as error:
        code = getattr(error, "code", "integrity")
        sys.stderr.write(wire({"schema": "laneboss.e2e-wait.v2", "code": code,
                               "message": str(error), "passed": False}).decode() + "\n")
        sys.exit(69 if code == "prerequisite_missing" else 1)
