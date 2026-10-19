"""Retain actual installed-CLI flow frames, including service refusals."""

import hashlib
from contextlib import nullcontext
import json
import os
from pathlib import Path
import secrets
import subprocess
import threading


def require(value, message):
    if not value:
        raise ValueError(message)


class RPCFailure(ValueError):
    def __init__(self, message, response=None, client_exit=None):
        super().__init__(message)
        self.response, self.client_exit = response, client_exit


def refused_frame(records, directory):
    for row in reversed(records):
        response = row.get("response", {})
        if isinstance(response, dict) and isinstance(response.get("error"), dict):
            return response
    try:
        raw = (Path(directory) / "stderr").read_bytes()
        if len(raw) <= 1048576:
            value = json.loads(raw)
            return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None
    return None


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


SESSION_WRITES = {"blob.begin", "blob.chunk", "blob.commit", "secret.stage"}


def needs_confirmation(method):
    return method != "lane.start" and method not in SESSION_WRITES


def save(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def document(path, value):
    save(path, json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n")


def frame(record, context, name, method, body, request_id=None):
    require(record.get("name") == name and isinstance(record.get("request"), dict) and
            isinstance(record.get("response"), dict), "actual service round trip is missing")
    request, response = record["request"], record["response"]
    require(request.get("protocol") == "laneboss.rpc.v2" and request.get("schema") == 2 and
            request.get("config") == context["config"] and request.get("method") == method and
            request.get("params") == body and request.get("request_id") and
            (request_id is None or request["request_id"] == request_id) and
            response.get("protocol") == "laneboss.rpc.v2" and response.get("schema") == 2 and
            response.get("request_id") == request["request_id"] and
            ((isinstance(response.get("result"), dict) and "error" not in response) or
             (isinstance(response.get("error"), dict) and "result" not in response)),
            "actual service frame differs from its retained intent")
    return response


def process(pid):
    base = Path("/proc") / str(pid)
    raw = (base / "stat").read_bytes()
    fields = raw[raw.rfind(b")") + 2:].split()
    require(len(fields) > 19 and fields[19].isdigit(), "actual client process generation is absent")
    return {"pid": pid, "start_time": fields[19].decode(),
            "executable_sha256": sha((base / "exe").read_bytes())}


def flow(context, directory, session_proof, steps, callback=None):
    directory = Path(directory)
    directory.mkdir(mode=0o700)
    plan = directory / "flow.json"
    document(plan, {"schema": "laneboss.client-flow.v2", "steps": steps})
    argv = [context["binary"], "human", "session", "--config", context["config"],
            "--binding", context["binding_file"], "--proof", str(session_proof), "--flow", str(plan),
            "--idempotency-key", secrets.token_hex(16)]
    document(directory / "argv.json", argv)
    require(sha(Path(context["binary"]).read_bytes()) == context["binary_sha256"], "installed client artifact changed")
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    records, output, errors, failures = [], bytearray(), bytearray(), []
    try:
        native = process(child.pid)
        require(native["executable_sha256"] == context["binary_sha256"], "actual client process executes another artifact")
        document(directory / "native.json", native)

        def reader():
            try:
                for line in child.stdout:
                    output.extend(line)
                    require(len(output) <= 16777216, "actual flow output exceeds its bound")
                    record = json.loads(line)
                    if "wait" in record:
                        require(record.get("completed") is False, "a dependency wait claimed completion")
                        continue
                    records.append(record)
                    if callback is not None:
                        callback(record)
            except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
                failures.append(error)
                child.terminate()

        def reader_errors():
            errors.extend(child.stderr.read(1048577))

        readers = [threading.Thread(target=reader), threading.Thread(target=reader_errors)]
        for selected in readers:
            selected.start()
        try:
            code = child.wait(timeout=600)
        except subprocess.TimeoutExpired:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
            raise ValueError("actual installed flow deadline") from None
        finally:
            for selected in readers:
                selected.join(timeout=65)
        require(not failures and all(not selected.is_alive() for selected in readers) and len(errors) <= 1048576,
                "actual flow could not retain its complete responses")
        return code, records
    finally:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=10)
        child.stdout.close()
        child.stderr.close()
        save(directory / "wire.jsonl", bytes(output))
        save(directory / "stderr", bytes(errors))
        document(directory / "exit.json", {"exit": child.returncode})


class Client:
    def __init__(self, context, human, evidence, diagnostics=None):
        self.context, self.human, self.root = context, human, Path(evidence)
        self.root.mkdir(mode=0o700)
        self.index = 0
        self.calls = []
        self.diagnostics = diagnostics

    def call(self, name, method, body, mutation=False, target=None, generation=0, expected=None,
             retry_key=None, proof_record=None):
        with self.diagnostics.scope(method) if self.diagnostics is not None else nullcontext():
            return self._call(name, method, body, mutation, target, generation, expected, retry_key, proof_record)

    def _call(self, name, method, body, mutation=False, target=None, generation=0, expected=None,
              retry_key=None, proof_record=None):
        self.index += 1
        directory = self.root / ("rpc-%04d" % self.index)
        request = self.root / ("rpc-%04d.request.json" % self.index)
        document(request, body)
        principal = self.human.public["principal_id"]
        session = self.human.prove("human.session", {}, principal, 0)
        step = {"name": name, "method": method, "request": str(request), "request_id": secrets.token_hex(16)}
        proof = session
        if mutation:
            step["idempotency_key"] = retry_key or secrets.token_hex(16)
            if needs_confirmation(method):
                proof = self.human.prove(method, body, target or self.context["config"], generation)
                step["proof"] = str(proof)
        if proof_record is not None:
            save(proof_record, Path(proof).read_bytes())
        code, records = flow(self.context, directory, session, [step])
        selected = [record for record in records if record.get("name") == name]
        if len(selected) != 1:
            raise RPCFailure("operation did not make one actual service round trip", refused_frame(records, directory), code)
        response = frame(selected[0], self.context, name, method, body, step["request_id"])
        document(directory / "selected.json", selected[0])
        entry = {"name": name, "method": method, "directory": str(directory.relative_to(self.root.parent)),
                 "request": str(request.relative_to(self.root.parent)), "request_sha256": sha(request.read_bytes()),
                 "wire_sha256": sha((directory / "wire.jsonl").read_bytes()), "exit": code}
        self.calls.append(entry)
        if "error" in response:
            error = response["error"]
            require(code != 0, "service refusal was returned with successful client exit")
            if expected is None:
                raise RPCFailure("installed service refused; retain exact wire error", error, code)
            if error.get("code") not in expected:
                raise RPCFailure("operation refused before its intended boundary", error, code)
            return {"error": error}, entry
        require(code == 0, "successful service response has a failed client exit")
        return response["result"], entry


def audit(context, evidence, entries, names, methods):
    require([entry.get("name") for entry in entries] == list(names), "one or more of the twenty-one steps is missing or duplicated")
    request_ids = set()
    for entry in entries:
        name = entry["name"]
        require(entry.get("method") == methods[name], "step invokes an unrelated service method")
        directory = Path(evidence) / entry["directory"]
        request = Path(evidence) / entry["request"]
        require(directory.resolve().is_relative_to(Path(evidence).resolve()) and
                request.resolve().is_relative_to(Path(evidence).resolve()), "round-trip evidence escapes its scope")
        body = request.read_bytes()
        wire = (directory / "wire.jsonl").read_bytes()
        require(sha(body) == entry["request_sha256"] and sha(wire) == entry["wire_sha256"], "retained service evidence changed")
        records = [json.loads(line) for line in wire.splitlines() if line.strip() and "wait" not in json.loads(line)]
        session_round_trip(context, records)
        selected = [record for record in records if record.get("name") == name]
        require(len(selected) == 1, "step has no unique actual service response")
        response = frame(selected[0], context, name, methods[name], json.loads(body))
        exit_record = json.loads((directory / "exit.json").read_bytes())
        require(type(exit_record.get("exit")) is int and exit_record["exit"] == entry.get("exit") and
                ((exit_record["exit"] != 0) if "error" in response else exit_record["exit"] == 0),
                "retained client exit differs from its actual service response")
        request_id = selected[0]["request"]["request_id"]
        require(request_id not in request_ids, "different steps replayed a request identity")
        request_ids.add(request_id)
        native = json.loads((directory / "native.json").read_bytes())
        require(type(native.get("pid")) is int and native["pid"] > 1 and
                str(native.get("start_time", "")).isdecimal() and native.get("executable_sha256") == context["binary_sha256"],
                "canned output has no measured installed client process")
        argv = json.loads((directory / "argv.json").read_bytes())
        require(argv[:3] == [context["binary"], "human", "session"] and
                argv[argv.index("--config") + 1] == context["config"] and
                argv[argv.index("--binding") + 1] == context["binding_file"], "round trip used another installed binding")
        if name == "bad-stage":
            same_connection(context, records)


def session_round_trip(context, records):
    selected = [row for row in records if row.get("name") == "human-session"]
    require(len(selected) == 1, "round trip has no actual same-connection human session")
    response = frame(selected[0], context, "human-session", "human.session", {})
    require("error" not in response and response["result"].get("id") and response["result"].get("config") == context["config"],
            "round trip lacks its actual service-issued human session")


def same_connection(context, records):
    """The failed import must consume the stage from this live CLI flow."""
    names = [row.get("name") for row in records]
    require(names[-3:] == ["bad-key", "bad-upload", "bad-stage"], "GCM control has no same-connection key and stage")
    key, stage, imported = records[-3:]
    for row, method in zip((key, stage, imported), ("secret.key", "secret.stage", "secret.import"), strict=True):
        frame(row, context, row["name"], method, row["request"]["params"])
    require("error" not in key["response"] and "error" not in stage["response"] and
            stage["request"]["params"]["key_id"] == key["response"]["result"]["id"] and
            imported["request"]["params"]["sealed_upload_id"] == stage["response"]["result"]["id"] and
            imported["response"].get("error", {}).get("code") == "integrity",
            "GCM control is not the actual staged import")
