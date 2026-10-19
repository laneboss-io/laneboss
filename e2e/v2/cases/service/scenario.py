"""Real installed-artifact operations, with explicit unmet acceptance gates."""

import array
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import subprocess
import time
import uuid


class Failed(RuntimeError):
    pass


class Blocked(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise Failed(message)


def encoded(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def receive(connection, count):
    output = bytearray()
    while len(output) < count:
        chunk = connection.recv(count - len(output))
        if not chunk:
            raise Failed("socket ended before a complete response frame")
        output.extend(chunk)
    return bytes(output)


class Scenario:
    def __init__(self, context, evidence):
        self.context, self.evidence = context, evidence
        self.binary = Path(context.get("binary", ""))
        self.binding = None
        self.steps = {name: "not_run" for name in (
            "artifact", "health", "upload", "drop-reply", "restart", "retry",
            "changed-bytes", "strict-frames", "cardinality", "boundary", "watcher", "outage")}
        self.commands, self.index, self.current, self.quiescent = [], 0, "artifact", True

    def keep(self, name, data):
        path = self.evidence / name
        with path.open("xb") as stream:
            stream.write(data)
        return path

    def command(self, name, args):
        self.index += 1
        stem = "%03d-%s" % (self.index, name)
        argv = [str(self.binary), *args]
        self.commands.append(argv)
        self.keep(stem + ".argv.json", encoded(argv))
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        prior_quiescence = self.quiescent
        self.quiescent = False  # Unknown until this particular process is reaped.
        expired = False
        try:
            output, error = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            expired = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                expired = True
            output, error = process.communicate(timeout=30)
        self.keep(stem + ".stdout", output)
        self.keep(stem + ".stderr", error)
        try:
            os.killpg(process.pid, 0)
            gone = False
        except ProcessLookupError:
            gone = True
        except PermissionError:
            gone = False
        self.quiescent = prior_quiescence and gone
        self.keep(stem + ".exit.json", encoded({"exit": process.returncode, "timed_out": expired,
                                               "process_group_quiescent": gone}))
        require(not expired and gone, "CLI timeout or surviving process group")
        return process.returncode, output, error

    def cli(self, command, params, key=None, expected=None):
        name = command.replace(" ", "-")
        self.index += 1
        path = self.keep("%03d-%s-input.json" % (self.index, name), encoded(params))
        args = command.split() + ["--config", self.context["config"], "--binding", self.context["binding_file"], "--request", str(path)]
        if key is not None:
            args += ["--idempotency-key", key]
        code, output, error = self.command(name, args)
        if expected is not None:
            require(code != 0, "refused input unexpectedly succeeded")
            value = json.loads(error)
            require(value.get("code") == expected, "refusal had a different error code")
            return value
        if code != 0:
            detail = json.loads(error)
            message = "installed " + command + " refused: " + str(detail.get("code"))
            if detail.get("code") in {"not_implemented", "prerequisite_missing"}:
                raise Blocked(message)
            raise Failed(message)
        return json.loads(output)

    def request(self, method, params, key=None, schema=2):
        intent = {"protocol": "laneboss.rpc.v2", "schema": schema, "config": self.context["config"],
                  "method": method, "params": params}
        # These controlled inputs contain only ASCII keys/strings and integers;
        # sorted minimal JSON is their JCS encoding, not a generic JCS engine.
        require(all(byte < 128 for byte in encoded(intent)), "case intent is outside its canonical scalar subset")
        return {**intent, "request_id": uuid.uuid4().hex, "idempotency_key": key or uuid.uuid4().hex,
                "request_sha256": sha(encoded(intent))}

    def rpc(self, request, drop=False, descriptor=None):
        data = encoded(request)
        self.index += 1
        self.keep("%03d-rpc-input.json" % self.index, data)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(10)
            connection.connect(self.binding["socket"])
            frame = struct.pack(">I", len(data)) + data
            if descriptor is None:
                connection.sendall(frame)
            else:
                rights = array.array("i", [descriptor])
                sent = connection.sendmsg([frame], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
                require(sent == len(frame), "descriptor canary frame was not sent completely")
            if drop:
                return None
            length = struct.unpack(">I", receive(connection, 4))[0]
            require(0 < length <= 1048576, "invalid service response length")
            raw = receive(connection, length)
            self.keep("%03d-rpc-response.json" % self.index, raw)
            response = json.loads(raw)
            require(response.get("protocol") == "laneboss.rpc.v2" and response.get("schema") == 2, "wrong response protocol")
            if descriptor is None:
                require(response.get("request_id") == request["request_id"], "uncorrelated service response")
            return response

    def upload(self, content):
        digest = sha(content)
        begin = self.cli("blob begin", {"class": "record", "bytes": len(content), "sha256": digest}, uuid.uuid4().hex)
        require(begin.get("max_chunk_bytes") == 262144, "wrong upload bound")
        self.cli("blob chunk", {"object_id": begin["object_id"], "offset": 0,
                               "data": base64.b64encode(content).decode(), "sha256": digest}, uuid.uuid4().hex)
        ref = self.cli("blob commit", {"object_id": begin["object_id"], "sha256": digest}, uuid.uuid4().hex)
        require(ref["sha256"] == digest and ref["bytes"] == len(content) and ref["class"] == "record", "committed object changed")
        chunk = self.cli("blob read", {"object_id": ref["id"], "offset": 0, "limit": len(content)})
        require(base64.b64decode(chunk["data"], validate=True) == content and chunk["sha256"] == digest, "committed object bytes changed")
        return ref

    def restart(self):
        path = self.context.get("controls")
        if not isinstance(path, str):
            raise Blocked("restart needs the independent harness controller; see CONTRACT-GAPS.md")
        before = os.lstat(path)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and before.st_mode & 0o022 == 0, "unprotected controller binding")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            after = os.fstat(stream.fileno())
            require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), "controller binding changed")
            raw = stream.read(1048577)
        require(len(raw) <= 1048576, "oversized controller binding")
        binding = json.loads(raw)
        self.keep("controller-binding.json", raw)
        require(binding["schema"] == "laneboss.e2e-control-binding.v2" and binding["case_id"] == "service" and
                binding["config"] == self.context["config"] and binding["binary_sha256"] == self.context["binary_sha256"] and
                binding["source_sha256"] == self.context["source_sha256"] and binding["case_uid"] == os.geteuid() and binding["live_auth"] is False,
                "controller binding scope differs")
        require(len(binding["service_ids"]) == 1, "restart selector is absent or ambiguous")
        params = {"service_id": binding["service_ids"][0], "expected_generation": binding["generation"]}
        request = {"schema": "laneboss.e2e-control.v2", "case_id": "service", "phase": self.context["phase"],
                   "mutation_id": self.context["mutation_id"], "binary_sha256": self.context["binary_sha256"],
                   "request_id": uuid.uuid4().hex, "nonce": uuid.uuid4().hex, "action": "restart_service", "params": params}
        self.keep("restart-input.json", encoded(request))
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(60)
            connection.connect(binding["socket"])
            peer = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            require(peer[0] > 0 and peer[1] == binding["controller_uid"], "controller kernel identity differs")
            data = encoded(request); connection.sendall(struct.pack(">I", len(data)) + data)
            length = struct.unpack(">I", receive(connection, 4))[0]; require(0 < length <= 1048576, "invalid controller frame")
            raw = receive(connection, length)
        self.keep("restart-response.json", raw)
        response = json.loads(raw)
        for field in ("case_id", "request_id", "nonce", "binary_sha256", "action"):
            require(response[field] == request[field], "controller response correlation differs")
        require(response["schema"] == "laneboss.e2e-control-reply.v2", "wrong controller response")
        result = response["result"]
        require(result["service_id"] == params["service_id"] and result["previous_generation"] == params["expected_generation"] and
                result["current_generation"] > result["previous_generation"] and result["old_exited"] is True and
                result["old_pid"] > 0 and result["new_pid"] > 0 and result["old_pid"] != result["new_pid"], "restart was not independently observed")
        require(result["evidence"], "restart evidence is absent")
        for ref in result["evidence"]:
            require(set(ref) == {"path", "sha256", "bytes"}, "controller evidence fields differ")
            relative = Path(ref["path"])
            require(not relative.is_absolute() and ".." not in relative.parts, "controller evidence traversal")
            candidate = self.evidence
            for component in relative.parts:
                candidate = candidate / component
                require(not candidate.is_symlink(), "controller evidence is linked")
            retained = (self.evidence / relative).resolve(strict=True)
            retained.relative_to(self.evidence.resolve(strict=True))
            data = retained.read_bytes()
            require(len(data) == ref["bytes"] and sha(data) == ref["sha256"], "controller evidence bytes differ")

    def run(self):
        binding_path = Path(self.context["binding_file"])
        require(binding_path.is_absolute(), "binding path is not absolute")
        descriptor = os.open(binding_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "binding is not a regular file")
            raw_binding = stream.read(1048577)
        require(0 < len(raw_binding) <= 1048576, "binding size is invalid")
        self.keep("binding-input.json", raw_binding)
        self.binding = json.loads(raw_binding)
        require(self.binary.is_absolute() and sha(self.binary.read_bytes()) == self.context["binary_sha256"], "installed artifact differs")
        code, output, _ = self.command("version", ["--version"])
        metadata = json.loads(output)
        require(code == 0 and metadata.get("contract_revision") == "v2.0-draft.4", "mixed contract artifact")
        require(self.binding["config"] == self.context["config"] and self.binding["class"] == "lane", "case needs a genuinely enrolled lane binding")
        self.steps["artifact"] = "pass"
        self.current = "health"
        health = self.cli("health", {"client_version": metadata["version"], "artifact_sha256": self.context["binary_sha256"]})
        require(health["artifact_sha256"] == self.context["binary_sha256"] and isinstance(health["ready"], bool) and isinstance(health["capabilities"], list), "invalid installed health")
        require(health["ready"] is True and health["capabilities"] and
                all(item.get("available") is True for item in health["capabilities"]), "installed host readiness is incomplete")
        self.steps["health"] = "pass"
        self.current = "upload"
        content = ("Service observation " + uuid.uuid4().hex + "\n").encode()
        self.keep("record.input", content)
        ref = self.upload(content); self.steps["upload"] = "pass"
        params = {"collection": "observations", "content": ref, "related_ids": []}
        key = uuid.uuid4().hex
        self.current = "drop-reply"
        self.rpc(self.request("records.append", params, key), drop=True)
        target = self.binding["target"]
        query = {"collection": "observations", "life_id": target["life_id"], "query": "", "search_mode": "keyword", "cursor": "", "limit": 200}
        end = time.monotonic() + 10
        while True:
            page = self.cli("records query", query)
            records = [item for item in page["records"] if item["content"] == ref]
            if records:
                break
            require(time.monotonic() < end, "dropped-reply mutation was never committed")
            time.sleep(0.1)
        require(len(records) == 1, "dropped reply duplicated visible records")
        original = records[0]; self.steps["drop-reply"] = "pass"
        self.current = "restart"; self.restart(); self.steps["restart"] = "pass"
        self.current = "retry"
        replay = self.cli("records append", params, key)
        require(replay == original, "retry changed the original durable reply")
        page = self.cli("records query", query)
        require(len([item for item in page["records"] if item["content"] == ref]) == 1, "retry duplicated visible record effect")
        self.steps["retry"] = "pass"
        self.current = "changed-bytes"
        changed = {**params, "content": {**ref, "sha256": sha(content + b"changed")}}
        self.cli("records append", changed, key, expected="idempotency_conflict")
        after_refusal = self.cli("records query", query)
        require([item for item in after_refusal["records"] if item["content"]["id"] == ref["id"]] == [original],
                "changed-key refusal altered the visible committed record")
        self.steps["changed-bytes"] = "pass"
        self.current = "strict-frames"
        body = {"object_id": ref["id"], "offset": 0, "limit": len(content)}
        observed = self.rpc(self.request("blob.read", body))
        require("error" not in observed and observed["last_seq"] > 0 and
                base64.b64decode(observed["result"]["data"], validate=True) == content, "socket read lost its real snapshot head or bytes")
        unknown = self.rpc(self.request("blob.read", {**body, "unknown": True}))
        require(unknown.get("error", {}).get("code") == "invalid_request", "unknown field reached read handler")
        wrong = self.rpc(self.request("blob.read", body, schema=3))
        require(wrong.get("error", {}).get("code") == "version_mismatch", "wrong schema was accepted")
        descriptor = os.open(self.evidence / "record.input", os.O_RDONLY)
        try:
            refused = self.rpc(self.request("blob.read", body), descriptor=descriptor)
        finally:
            os.close(descriptor)
        require(refused.get("error", {}).get("code") == "invalid_request", "descriptor-bearing frame was accepted")
        self.steps["strict-frames"] = "pass"
        self.current = "cardinality"
        raise Blocked("request-scoped receipt/outbox inventory and confined/load/outage controls are required; see CONTRACT-GAPS.md")

    def complete(self):
        return all(value == "pass" for value in self.steps.values())
