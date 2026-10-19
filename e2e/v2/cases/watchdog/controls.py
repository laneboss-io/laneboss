"""Client of the frozen harness-only controller, never a product endpoint."""

import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct


class ControlError(Exception):
    pass


def need(condition, message):
    if not condition:
        raise ControlError(message)


def closed(value, fields):
    need(isinstance(value, dict) and set(value) == set(fields.split()), "controller field map differs")


def positive(value):
    return type(value) is int and value > 0


def identity(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value) is not None


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parse(data):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "controller JSON has duplicate keys")
            result[key] = value
        return result
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, ValueError) as error:
        raise ControlError("controller JSON is malformed") from error


def verify_reply(reply, request):
    shared = "schema case_id request_id nonce binary_sha256"
    closed(reply, shared + (" error" if "error" in reply else " action result"))
    need(reply["schema"] == "laneboss.e2e-control-reply.v2", "controller reply schema differs")
    need(all(reply[key] == request[key] for key in ("case_id", "request_id", "nonce", "binary_sha256")),
         "controller reply correlation differs")
    if "error" in reply:
        closed(reply["error"], "code message instead evidence")
        raise ControlError("harness refused the action; retain its complete reply")
    need(reply["action"] == request["action"], "controller returned another action")
    result, params = reply["result"], request["params"]
    if request["action"] == "restart_service":
        closed(result, "service_id previous_generation current_generation old_pid new_pid old_exited evidence")
        need(result["service_id"] == params["service_id"]
             and result["previous_generation"] == params["expected_generation"]
             and positive(result["current_generation"]) and result["current_generation"] > result["previous_generation"]
             and positive(result["old_pid"]) and positive(result["new_pid"]) and result["old_exited"] is True,
             "restart lacks an observed old exit and a new service generation")
    elif request["action"] == "run_confined_canary":
        closed(result, "job_id target observed_exit containment_state survivors input_sha256 evidence")
        need(identity(result["job_id"]) and result["target"] == params["target"]
             and type(result["observed_exit"]) is int and result["observed_exit"] == 0
             and result["containment_state"] == "exited" and type(result["survivors"]) is int and result["survivors"] == 0
             and result["input_sha256"] == params["input"]["sha256"],
             "canary lacks a matching input, actual exit or zero survivors")
    else:
        raise ControlError("unsupported watchdog harness action")
    need(isinstance(result["evidence"], list) and bool(result["evidence"]), "controller evidence is absent")
    for ref in result["evidence"]:
        closed(ref, "path sha256 bytes")
        need(isinstance(ref["path"], str) and bool(ref["path"])
             and not Path(ref["path"]).is_absolute() and ".." not in Path(ref["path"]).parts
             and type(ref["bytes"]) is int and 0 <= ref["bytes"] <= 16 * 1024 * 1024
             and isinstance(ref["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", ref["sha256"]),
             "controller evidence reference differs from its bounded field map")
    return result


def protected(path, owners, bound):
    path = Path(path)
    need(path.is_absolute(), "controller path must be absolute")
    for parent in path.parents:
        info = parent.lstat()
        sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
        need(stat.S_ISDIR(info.st_mode) and info.st_uid in owners
             and (not info.st_mode & 0o022 or sticky_root), "controller ancestor is not protected")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid in owners and not info.st_mode & 0o077
             and info.st_nlink == 1 and info.st_size <= bound, "controller input is not a private ordinary file")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(bound + 1)
        need(len(data) == info.st_size and len(data) <= bound, "controller file changed or exceeded its bound")
        return data, info.st_uid
    finally:
        os.close(fd)


class Controller:
    def __init__(self, context, keep):
        self.context, self.keep = context, keep
        need(context.get("controls"), "harness controller binding is missing")
        # Bootstrap file ownership is checked before any selector is used;
        # the controller UID is subsequently checked against the actual owner.
        data, owner = protected(context["controls"], {0, os.getuid()}, 1024 * 1024)
        binding = parse(data)
        closed(binding, "schema case_id config socket generation controller_uid case_uid binary_sha256 source_sha256 live_auth service_ids canary_ids fixture_clock_ids")
        need(binding["schema"] == "laneboss.e2e-control-binding.v2"
             and binding["case_id"] == context["case_id"] and binding["config"] == context["config"]
             and binding["binary_sha256"] == context["binary_sha256"] and binding["source_sha256"] == context["source_sha256"]
             and binding["live_auth"] is False and binding["case_uid"] == os.getuid()
             and type(binding["controller_uid"]) is int and binding["controller_uid"] >= 0
             and owner in {0, binding["controller_uid"], binding["case_uid"]} and positive(binding["generation"]),
             "controller binding differs from the enrolled case/artifact/identity")
        need(all(isinstance(binding[key], list) and all(identity(item) for item in binding[key])
                 for key in ("service_ids", "canary_ids", "fixture_clock_ids")), "controller selectors are malformed")
        self.binding = binding
        self.keep("control-binding.json", data)

    def invoke(self, action, params):
        if action == "restart_service":
            closed(params, "service_id expected_generation")
            need(params["service_id"] in self.binding["service_ids"] and positive(params["expected_generation"]),
                 "service is not enrolled for this case")
        elif action == "run_confined_canary":
            closed(params, "target canary_id input")
            closed(params["target"], "life_id run")
            closed(params["input"], "id sha256 bytes class")
            need(params["canary_id"] in self.binding["canary_ids"] and identity(params["target"]["life_id"])
                 and positive(params["target"]["run"]), "canary is not enrolled for this case")
        else:
            raise ControlError("unsupported watchdog harness action")
        request = {"schema": "laneboss.e2e-control.v2", "case_id": self.context["case_id"],
                   "phase": self.context["phase"], "mutation_id": self.context["mutation_id"],
                   "binary_sha256": self.context["binary_sha256"], "request_id": secrets.token_hex(16),
                   "nonce": secrets.token_hex(16), "action": action, "params": params}
        data = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
        need(0 < len(data) <= 1024 * 1024, "controller request exceeded its frame bound")
        self.keep("control-request.json", data)
        endpoint = Path(self.binding["socket"])
        need(endpoint.is_absolute(), "controller endpoint is relative")
        for parent in endpoint.parents:
            info = parent.lstat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid in {0, self.binding["controller_uid"], os.getuid()}
                 and (not info.st_mode & 0o022 or (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)),
                 "controller socket ancestor is writable")
        info = endpoint.lstat()
        need(stat.S_ISSOCK(info.st_mode) and info.st_uid == self.binding["controller_uid"]
             and not info.st_mode & 0o007, "controller socket owner or permissions differ")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(30)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            connection.connect(str(endpoint))
            peer = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            need(peer[0] > 0 and peer[1] == self.binding["controller_uid"], "controller kernel peer differs")
            connection.sendall(struct.pack(">I", len(data)) + data)
            length = struct.unpack(">I", self.receive(connection, peer, 4))[0]
            need(0 < length <= 1024 * 1024, "controller response exceeded its frame bound")
            raw = self.receive(connection, peer, length)
        self.keep("control-reply.json", raw)
        result = verify_reply(parse(raw), request)
        evidence = []
        root = Path(self.context["evidence_root"]).resolve()
        for ref in result["evidence"]:
            path = root / ref["path"]
            need(path.resolve().is_relative_to(root), "controller evidence escaped the case root")
            content, _ = protected(path, {0, self.binding["controller_uid"], os.getuid()}, 16 * 1024 * 1024)
            need(len(content) == ref["bytes"] and digest(content) == ref["sha256"], "controller evidence hash differs")
            self.keep("control-verified.bin", content)
            evidence.append(content)
        return result, evidence

    @staticmethod
    def receive(connection, peer, length):
        result = bytearray()
        while len(result) < length:
            data, ancillary, flags, _ = connection.recvmsg(length - len(result), socket.CMSG_SPACE(12) + socket.CMSG_SPACE(256))
            credentials, invalid = [], False
            for level, kind, value in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    for fd in struct.unpack(f"{len(value) // 4}i", value[:len(value) // 4 * 4]):
                        os.close(fd)
                    invalid = True
                elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(value) == 12:
                    credentials.append(struct.unpack("3i", value))
                else:
                    invalid = True
            need(bool(data) and not invalid and not flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC)
                 and credentials == [peer], "controller frame writer or ancillary data differs")
            result.extend(data)
        return bytes(result)
