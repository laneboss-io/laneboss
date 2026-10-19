"""Live CLI acceptance; inputs and observations stay outside the checkout."""

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import threading
import time
import uuid


IDS = [
    "CODEX-TWO-TURN", "CODEX-CONCURRENT", "CODEX-REFRESH", "CODEX-OUTER",
    "CODEX-SESSION", "CODEX-HELPER", "CODEX-AUTH", "CODEX-COVERAGE",
    "CODEX-SUPERVISORS",
]

# These distinguish the frozen read/stream wire forms used by this case; they
# do not authorize any command or replace the installed client's validators.
READ_COMMANDS = {"lane list", "lane status", "event tail", "blob read", "operation get"}
SESSION_COMMANDS = READ_COMMANDS | {"blob begin", "blob chunk", "blob commit"}
MUTATION_TARGETS = {
    "drop-session": "CODEX-TWO-TURN", "shared-home": "CODEX-CONCURRENT",
    "overlap-refresh": "CODEX-REFRESH", "outer-boundary": "CODEX-OUTER",
    "forged-session": "CODEX-SESSION", "omit-helper": "CODEX-HELPER",
    "borrow-auth": "CODEX-AUTH", "complete-coverage": "CODEX-COVERAGE",
    "supervisor-turn-wait": "CODEX-SUPERVISORS",
    "tool-approval": "CODEX-TWO-TURN", "inner-sandbox": "CODEX-TWO-TURN",
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def recorded_time(value):
    require(isinstance(value, str), "service timestamp is absent")
    match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z", value)
    require(match is not None, "service timestamp is not RFC3339Nano UTC")
    second = datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return second, int((match[2] or "").ljust(9, "0"))


def serialized_leases(events):
    leases = {}
    for event in events:
        if event["kind"] not in ("credential.leased", "credential.released"):
            continue
        require(event["origin"] == "service", "lease event is not service-recorded")
        slot = event["payload"]["slot"]["id"]
        key = (event["life_id"], event["run"], slot)
        row = leases.setdefault(key, {})
        require(event["kind"] not in row, "duplicate credential lease event")
        row[event["kind"]] = recorded_time(event["recorded_at"])
    require(len(leases) == 2, "missing lease/release evidence")
    intervals = []
    for row in leases.values():
        require(set(row) == {"credential.leased", "credential.released"},
                "missing lease/release evidence")
        start, end = row["credential.leased"], row["credential.released"]
        require(start < end, "lease interval is empty or reversed")
        intervals.append((start, end))
    intervals.sort()
    require(intervals[0][1] <= intervals[1][0],
            "canonical login refresh owners overlapped")


def supervisor_request(template):
    request = dict(template)
    word = request.pop("expected_answer")
    child_level = request.pop("expected_child_level")
    require(request.get("driver") == "codex", "wrong supervisor driver")
    require(isinstance(word, str) and word and all(c.isalnum() for c in word),
            "invalid supervisor plant")
    require(type(child_level) is int and 3 <= child_level < request["level"],
            "invalid supervisor child level")
    return request, word, child_level


def read_probe_command(command, path):
    # This recognizes one measurement command; it grants no tool permission.
    if not isinstance(command, str):
        return False
    try:
        words = shlex.split(command)
        if len(words) == 3 and words[0] in (
                "/bin/sh", "/bin/bash", "/usr/bin/bash", "/bin/zsh", "/usr/bin/zsh") and words[1] in ("-c", "-lc"):
            words = shlex.split(words[2])
    except ValueError:
        return False
    return words == ["/usr/bin/cat", "--", path]


def workspace_bytes(records, path, expected):
    for record in records:
        if record.get("type") != "item.completed":
            continue
        item = record.get("item", {})
        if item.get("type") != "command_execution":
            continue
        data = item.get("aggregated_output")
        if (read_probe_command(item.get("command", ""), path) and
                type(item.get("exit_code")) is int and item["exit_code"] == 0 and
                isinstance(data, str) and data.encode("utf-8") == expected):
            return
    raise AssertionError("workspace write/read probe did not return the actual expected bytes")


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key")
        value[key] = item
    return value


def invalid_constant(value):
    raise AssertionError("nonfinite JSON number")


def finite_number(value):
    number = float(value)
    require(math.isfinite(number), "nonfinite JSON number")
    return number


def exact_integer(value):
    number = int(value)
    require(abs(number) <= 2**53 - 1, "JSON integer exceeds the exact range")
    return number


def valid_strings(value):
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
    elif isinstance(value, list):
        for item in value:
            valid_strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            valid_strings(key)
            valid_strings(item)


def json_values(data):
    text = data.decode("utf-8", errors="strict")
    decoder = json.JSONDecoder(object_pairs_hook=unique_object,
                               parse_constant=invalid_constant,
                               parse_float=finite_number, parse_int=exact_integer)
    values = []
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset] in " \t\r\n":
            offset += 1
        if offset == len(text):
            break
        value, offset = decoder.raw_decode(text, offset)
        require(isinstance(value, dict), "CLI output is not a JSON object")
        valid_strings(value)
        values.append(value)
    require(values, "CLI output is empty")
    return values


def one_json(data):
    values = json_values(data)
    require(len(values) == 1, "nonstream CLI emitted multiple objects")
    return values[0]


def stream_json(data, request_id):
    values = json_values(data)
    page = values[0]
    require(set(page) == {"events", "cursor", "complete"} and
            isinstance(page["events"], list) and
            isinstance(page["cursor"], str) and
            type(page["complete"]) is bool,
            "stream initial event page is absent or malformed")
    require(len(values) > 1, "stream has no real end frame")
    events = []
    for index, frame in enumerate(values[1:], 1):
        require(set(frame) <= {"request_id", "index", "cursor", "event",
                               "end"} and
                frame.get("request_id") == request_id and
                type(frame.get("index")) is int and frame["index"] == index and
                isinstance(frame.get("cursor"), str) and
                type(frame.get("end")) is bool,
                "stream correlation, index or payload shape differs")
        if frame["end"]:
            require("event" not in frame and index == len(values) - 1,
                    "stream end has a payload or trailing frames")
        else:
            require(isinstance(frame.get("event"), dict),
                    "event stream has no event payload")
            events.append(frame["event"])
    require(values[-1]["end"], "stream disconnected without an end frame")
    return page, events


def atomic_json(path, value):
    temporary = path.with_name(path.name + ".new")
    with temporary.open("x", encoding="utf-8") as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


class Case:
    def __init__(self, context, result):
        self.context = context
        self.root = Path(context["test_root"]).resolve(strict=True)
        self.evidence = Path(context["evidence_root"]).resolve(strict=True)
        require(result.is_absolute() and not result.is_symlink() and
                ".." not in result.parts and
                result.parent.resolve(strict=True).is_relative_to(self.root),
                "result path escaped the disposable case scope")
        self.result_path = result.parent.resolve(strict=True) / result.name
        require(context["phase"] in ("red", "candidate") and
                bool(context["mutation_id"]) == (context["phase"] == "red"),
                "phase/mutation identity is invalid")
        require(context["phase"] != "red" or context["mutation_id"] in MUTATION_TARGETS,
                "unknown red mutation target")
        self.number = 0
        self.lock = threading.Lock()
        self.files = []
        self.lives = {}
        self.roots = set()
        self.attempted_names = set()
        self.initial_ids = set()
        self.assertions = []
        self.active = IDS[0]
        self.reached = False
        self.last_exit = 1
        self.quiescent = False
        self.collected = False
        self.proof_directory = None
        self.proof_ids = set()

    def proof(self, stem, command, request, invocation):
        require(self.proof_directory is not None,
                "independent human proof supplier is missing")
        method = "human.session" if command in SESSION_COMMANDS else \
            command.replace(" ", ".")
        params = {} if command in SESSION_COMMANDS else request
        path = self.proof_directory / (invocation["request_id"] + ".json")
        # This is a request for an independent fixture input, not a new RPC,
        # control action or a claim that this process verified a human.
        self.keep(stem + "-authorization-request.json", json.dumps({
            **invocation, "schema": "laneboss.codex-proof-input.v1",
            "proof_method": method, "proof_params": params,
            "proof_output": str(path)}, sort_keys=True).encode())
        deadline = time.monotonic() + 120
        while not path.exists():
            require(time.monotonic() < deadline,
                    "fresh operation/session proof input did not arrive")
            time.sleep(0.1)
        require(not path.is_symlink() and path.is_file(),
                "proof input is not an ordinary file")
        data = path.read_bytes()
        proof = one_json(data)
        require(set(proof) == {"id", "request_sha256", "expires_at"} and
                isinstance(proof["id"], str) and proof["id"] and
                isinstance(proof["request_sha256"], str) and
                len(proof["request_sha256"]) == 64 and
                isinstance(proof["expires_at"], str),
                "proof supplier did not return a ProofRef")
        with self.lock:
            require(proof["id"] not in self.proof_ids,
                    "proof reused across CLI connections")
            self.proof_ids.add(proof["id"])
        self.keep(stem + "-proof.json", data)
        return self.evidence / (stem + "-proof.json")

    def keep(self, name, data):
        require(not Path(name).is_absolute() and
                all(part not in (".", "..") for part in Path(name).parts),
                "evidence path is not a confined relative name")
        path = self.evidence / name
        require(path.parent.resolve(strict=True).is_relative_to(self.evidence),
                "evidence parent escaped its scope")
        with self.lock:
            require(not path.exists() and not path.is_symlink(),
                    "evidence name reused")
            temporary = path.with_name("." + path.name + ".new")
            with temporary.open("xb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            temporary.replace(path)
            row = {"path": name, "sha256": digest(data), "bytes": len(data)}
            self.files.append(row)
        return row

    def call(self, command, request, error=None, idempotency_key=None,
             error_owner=None, error_message=None):
        with self.lock:
            self.number += 1
            stem = f"{self.number:04d}"
        payload = json.dumps(request, sort_keys=True).encode()
        self.keep(stem + "-request.json", payload)
        path = self.evidence / (stem + "-request.json")
        request_id = uuid.uuid4().hex
        key = idempotency_key or uuid.uuid4().hex
        invocation = {"config": self.context["config"], "command": command,
                      "request_id": request_id, "idempotency_key": key,
                      "request_file": str(path),
                      "request_bytes_sha256": digest(payload),
                      "binding_file": self.context["binding_file"]}
        self.keep(stem + "-invocation.json",
                  json.dumps(invocation, sort_keys=True).encode())
        args = [self.context["binary"], *command.split(), "--config",
                self.context["config"], "--binding",
                self.context["binding_file"], "--request", str(path),
                "--request-id", request_id, "--idempotency-key", key]
        if command in ("lane start", "lane adopt"):
            require(request.get("root_ticket_id"),
                    "human root launch requires its issued ticket")
            with self.lock:
                self.attempted_names.add(request["lane"])
        else:
            args.extend(["--proof", str(self.proof(stem, command, request,
                                                   invocation))])
        self.keep(stem + "-argv.json", json.dumps(args).encode())
        completed = subprocess.run(args, capture_output=True, timeout=180)
        self.last_exit = completed.returncode
        self.keep(stem + "-stdout.json", completed.stdout)
        self.keep(stem + "-stderr.json", completed.stderr)
        self.keep(stem + "-exit.json",
                  json.dumps({"exit": completed.returncode}).encode())
        if error is not None:
            if completed.returncode == 0:
                accepted = one_json(completed.stdout)
                self.reached = True
                if accepted.get("life_id"):
                    self.roots.add(accepted["life_id"])
                    self.lives[accepted["life_id"]] = None
                    self.reached = True
            require(completed.returncode != 0, "negative control succeeded")
            value = one_json(completed.stderr)
            require(isinstance(value.get("code"), str) and
                    isinstance(value.get("message"), str) and
                    isinstance(value.get("instead"), str) and
                    type(value.get("retryable")) is bool,
                    "negative result is not a typed service error")
            require((error_owner is None or value.get("owner") == error_owner) and
                    (error_message is None or value["message"] == error_message),
                    "refusal did not reach the intended component/reason")
            self.reached = True
            require(value.get("code") == error, "wrong refusal category")
            return value
        require(completed.returncode == 0, "CLI dependency or operation failed")
        if command == "event tail" and request["follow"]:
            return stream_json(completed.stdout, request_id)
        value = one_json(completed.stdout)
        require("error" not in value, "error disguised as success")
        return value

    def upload(self, data, kind="prompt"):
        upload = self.call("blob begin", {
            "class": kind, "bytes": len(data), "sha256": digest(data)})
        for offset in range(0, len(data), 131072):
            chunk = data[offset:offset + 131072]
            self.call("blob chunk", {
                "object_id": upload["object_id"], "offset": offset,
                "data": base64.b64encode(chunk).decode(),
                "sha256": digest(chunk)})
        return self.call("blob commit", {
            "object_id": upload["object_id"], "sha256": digest(data)})

    def blob(self, reference):
        data = bytearray()
        while len(data) < reference["bytes"]:
            chunk = self.call("blob read", {
                "object_id": reference["id"], "offset": len(data),
                "limit": min(131072, reference["bytes"] - len(data))})
            part = base64.b64decode(chunk["data"], validate=True)
            require(part and chunk["object_id"] == reference["id"] and
                    chunk["offset"] == len(data) and
                    len(part) <= min(131072, reference["bytes"] - len(data)),
                    "blob identity, range or gap differs")
            require(digest(part) == chunk["sha256"], "chunk digest mismatch")
            data.extend(part)
        require(len(data) == reference["bytes"], "blob length mismatch")
        require(digest(data) == reference["sha256"], "blob digest mismatch")
        end = self.call("blob read", {"object_id": reference["id"],
                                      "offset": len(data), "limit": 1})
        require(end["object_id"] == reference["id"] and
                end["offset"] == len(data) and
                base64.b64decode(end["data"], validate=True) == b"" and
                end["sha256"] == digest(b""),
                "blob reference described only a prefix of its committed object")
        return bytes(data)

    def status(self, life):
        matching = [lane for lane in self.lanes(life)
                    if lane["life_id"] == life]
        require(len(matching) == 1, "latest life projection is absent")
        lane = self.call("lane status", {"life_id": life,
                                         "run": matching[0]["run"]})
        self.lives[life] = lane
        return lane

    def events(self, life, run=0, follow=False, until="lane.ended", since=0,
               deadline_ms=120000):
        require(not follow or run > 0,
                "event wait requires the selected actual run")
        value = self.call("event tail", {
            "life_id": life, "run": run, "since": since, "cursor": "",
            "follow": follow, "until": until if follow else "",
            "deadline_ms": deadline_ms if follow else 0})
        streamed = []
        if follow:
            value, streamed = value
        events = list(value["events"])
        cursors = set()
        while value["cursor"]:
            require(value["cursor"] not in cursors, "event cursor repeated")
            cursors.add(value["cursor"])
            value = self.call("event tail", {
                "life_id": life, "run": run, "since": since,
                "cursor": value["cursor"], "follow": False,
                "until": "", "deadline_ms": 0})
            events.extend(value["events"])
        require(value["complete"] is True, "event snapshot is incomplete")
        events.extend(streamed)
        previous = since
        for event in events:
            require(isinstance(event, dict) and
                    event["config"] == self.context["config"] and
                    event.get("life_id") == life and
                    (run == 0 or event.get("run") == run) and
                    event["origin"] == "service" and
                    type(event["seq"]) is int and event["seq"] > previous,
                    "event scope, provenance or sequence differs")
            previous = event["seq"]
            if event["kind"] == "lane.turn":
                require(isinstance(event.get("logical_turn_id"), str) and
                        re.fullmatch(r"[A-Za-z0-9_-]{1,128}", event["logical_turn_id"]),
                        "turn event omitted logical turn identity")
            if event["kind"] == "helper.released":
                self.release_receipt(event)
        if follow:
            require(any(event["kind"] == until for event in events),
                    "stream ended without the selected authentic event")
        return events

    def release_receipt(self, event):
        receipt = event["payload"]
        required = {"id", "lease_id", "containment_id", "backend",
                    "operation_id", "effect_id", "quiescence",
                    "live_connections", "queued_jobs", "writable_exports",
                    "observed_at"}
        require(isinstance(receipt, dict) and set(receipt) == required,
                "helper release is not a measured receipt")
        require(all(isinstance(receipt[key], str) and receipt[key] for key in
                    ("id", "lease_id", "containment_id", "operation_id",
                     "effect_id", "observed_at")) and
                receipt["operation_id"] == event["operation_id"] and
                receipt["backend"] == "linux-bwrap-landlock",
                "helper release causal binding differs")
        require(all(type(receipt[key]) is int and receipt[key] == 0 for key in
                    ("live_connections", "queued_jobs", "writable_exports")),
                "helper release resource counts are unknown or nonzero")
        observed = receipt["quiescence"]
        require(isinstance(observed, dict) and observed["state"] == "exited" and
                type(observed.get("survivors")) is int and
                observed["survivors"] == 0 and
                observed["handle"]["containment_id"] == receipt["containment_id"] and
                observed["handle"]["target"] == {
                    "life_id": event["life_id"], "run": event["run"]} and
                (("exit_code" in observed) != ("signal" in observed)),
                "helper release did not measure exact run quiescence")

    def lanes(self, life=None):
        request = {"cursor": "", "limit": 200}
        if life is not None:
            request["life_id"] = life
        page = self.call("lane list", request)
        lanes = list(page["lanes"])
        cursors = set()
        while page["cursor"]:
            require(page["cursor"] not in cursors, "lane cursor repeated")
            cursors.add(page["cursor"])
            request = {**request, "cursor": page["cursor"]}
            page = self.call("lane list", request)
            lanes.extend(page["lanes"])
        return lanes

    def owned_lanes(self):
        return [lane for lane in self.lanes()
                if lane["life_id"] in self.roots or
                any(parent in self.roots for parent in lane["starter_chain"])]

    def ended(self, life, run):
        events = self.events(life, run, follow=True)
        ends = [e for e in events if e["kind"] == "lane.ended"
                and e.get("life_id") == life and e.get("run") == run]
        require(len(ends) == 1, "missing or ambiguous run end")
        observation = ends[0]["payload"]["observation"]
        require(ends[0]["payload"]["reason"] == "exit",
                "run ended through an incomplete or stopped path")
        require(observation["state"] == "exited", "run exit is unknown")
        require(type(observation.get("exit_code")) is int and
                observation["exit_code"] == 0, "vendor run failed")
        require(type(observation.get("survivors")) is int and
                observation["survivors"] == 0, "vendor process survived")
        require(observation["handle"]["target"] == {"life_id": life, "run": run},
                "run end measured another target")
        return self.status(life), events

    def capture(self, events):
        streams = {}
        for event in events:
            require(event["kind"] != "capture.gap", "primary capture has a gap")
            if event["kind"] != "capture.appended":
                continue
            record = event["payload"]
            if not record["primary"]:
                continue
            require(record["coverage"] in ("partial", "unsupported"),
                    "unproved raw coverage advertised complete")
            require(not record.get("replacement_of"),
                    "primary capture was replaced")
            require(record["target"] == {"life_id": event["life_id"],
                                          "run": event["run"]},
                    "primary capture target differs from its service event")
            stream = record["stream"]
            data = streams.setdefault(stream, bytearray())
            require(record["offset"] == len(data), "capture gap or overlap")
            data.extend(self.blob(record["data"]))
        require(streams.get("stdout") or streams.get("vendor"),
                "primary vendor capture absent")
        data = bytes(streams.get("stdout") or streams.get("vendor", b""))
        return [one_json(line) for line in data.splitlines() if line.strip()]

    def answer(self, records, word):
        messages = [r.get("item", {}) for r in records
                    if r.get("type") == "item.completed"]
        require(any(m.get("type") == "agent_message"
                    and word in m.get("text", "") for m in messages),
                "planted answer absent from actual agent message")

    def passed(self, assertion, observed_exit=None):
        self.assertions.append({
            "id": assertion, "reached": True, "verdict": "pass",
            "observed_exit": self.last_exit if observed_exit is None else
            observed_exit, "evidence": list(self.files)})

    def activate(self, assertion):
        self.active = assertion
        self.reached = False

    def failure_reached(self):
        return self.reached and (self.context["phase"] != "red" or
                                MUTATION_TARGETS[self.context["mutation_id"]] == self.active)

    def operation_done(self, operation, timeout=120):
        operation_id = operation["id"]
        deadline = time.monotonic() + timeout
        while operation["status"] in ("pending", "running"):
            require(time.monotonic() < deadline, "operation did not reach a durable result")
            operation = self.call("operation get", {"operation_id": operation_id})
            require(operation["id"] == operation_id, "operation result belongs to another request")
            if operation["status"] in ("pending", "running"):
                time.sleep(0.25)
        require(operation["status"] in ("succeeded", "failed", "cancelled"),
                "operation result has an unknown status")
        return operation

    def failed_launch(self, command, request, control):
        operation = self.call(command, request)
        require(operation.get("life_id") and operation.get("run"),
                "target launch intent not reached")
        life, run = operation["life_id"], operation["run"]
        self.roots.add(life)
        self.lives[life] = None
        outcome = self.operation_done(operation)
        if outcome["status"] == "succeeded":
            self.reached = True
        require(outcome["status"] == "failed", "negative launch effect succeeded")
        error = outcome["error"]
        require(error["owner"] == control["owner"] and error["message"] == control["message"],
                "launch failed outside the intended component/reason")
        events = self.events(life, run, follow=True, until="launch.failed")
        failures = [event for event in events if event["kind"] == "launch.failed" and
                    event["operation_id"] == operation["id"]]
        require(len(failures) == 1, "missing or ambiguous launch effect failure")
        payload = failures[0]["payload"]
        require(payload["stage"] == control["stage"], "launch failure reached another stage")
        self.reached = True
        require(payload["agent_executed"] is False and
                payload["error"]["code"] == control["code"] and
                payload["error"]["owner"] == control["owner"] and
                payload["error"]["message"] == control["message"] and
                error["code"] == control["code"], "wrong measured launch failure")
        return outcome

    def write_probe(self, life, budget):
        self.reached = False
        lane = self.status(life)
        cwd = PurePosixPath(lane["workspace"]["logical_cwd"])
        require(cwd.is_absolute() and str(cwd) != "/" and ".." not in cwd.parts,
                "workspace probe needs the issued logical cwd")
        path = str(cwd / ("probe-" + uuid.uuid4().hex + ".txt"))
        expected = ("workspace probe " + uuid.uuid4().hex + "\n").encode()
        self.keep("workspace-probe-" + uuid.uuid4().hex + ".json", json.dumps({
            "life_id": life, "path": path, "bytes": len(expected),
            "sha256": digest(expected), "content": base64.b64encode(expected).decode()
        }, sort_keys=True).encode())
        command = "/usr/bin/cat -- " + shlex.quote(path)
        prompt = ("Write exactly the UTF-8 bytes encoded by this base64 to " + path + ": "
                  + base64.b64encode(expected).decode() + ". Then use a separate shell tool call "
                  + "to execute exactly: " + command + ". Preserve its actual output and exit. "
                  + "Use normal tools inside your workspace; do not simulate a tool result.\n")
        message = self.upload(prompt.encode())
        operation = self.call("lane turn", {"target": {"life_id": life, "run": lane["run"]},
                                           "expected_generation": lane["generation"],
                                           "mail_ids": [], "idle_message": message, "budget": budget})
        updated, events = self.ended(life, operation["run"])
        records = self.capture(events)
        self.reached = True
        require(updated["session"] == lane["session"], "workspace probe changed the private session")
        workspace_bytes(records, path, expected)
        self.reached = False
        self.events(life, updated["run"], follow=True, until="credential.released")

    def start(self, request):
        require(request["driver"] == "codex", "wrong driver")
        require(request["profile_grant_id"] in
                self.context["profile_grant_ids"],
                "live start profile was not delegated in the case context")
        key = uuid.uuid4().hex
        operation = self.call("lane start", request, idempotency_key=key)
        require(operation.get("life_id"), "no created life")
        with self.lock:
            self.lives[operation["life_id"]] = None
            self.roots.add(operation["life_id"])
        replay = self.call("lane start", request, idempotency_key=key)
        require(replay == operation, "same-key start changed its retained reply")
        return operation["life_id"], operation["run"]

    def run(self):
        require(sys.platform == "linux", "live case requires Linux")
        binary = Path(self.context["binary"]).read_bytes()
        require(digest(binary) == self.context["binary_sha256"],
                "artifact differs from context")
        setup_path = self.root / "setup.json"
        setup_bytes = setup_path.read_bytes()
        self.keep("setup.json", setup_bytes)
        setup = one_json(setup_bytes)
        self.setup = setup
        binding_path = Path(self.context["binding_file"])
        require(binding_path.is_absolute(), "binding file must be absolute")
        binding_bytes = binding_path.read_bytes()
        binding = one_json(binding_bytes)
        self.keep("installed-binding.json", binding_bytes)
        require(binding["schema"] == "laneboss.binding.v2" and
                binding["contract_revision"] == "v2.0-draft.4" and
                binding["protocol"] == "laneboss.rpc.v2" and
                binding["api_schema"] == 2 and binding["class"] == "human" and
                binding["config"] == self.context["config"] and
                binding["artifact_sha256"] == self.context["binary_sha256"],
                "case requires the matched installed human binding")
        proof_directory = Path(setup["proof_directory"])
        require(proof_directory.is_absolute() and not proof_directory.is_symlink(),
                "proof input directory must be an absolute ordinary directory")
        self.proof_directory = proof_directory.resolve(strict=True)
        require(self.proof_directory.is_relative_to(self.root) and
                self.proof_directory.is_dir(), "proof input directory escaped case scope")
        existing = self.lanes()
        self.initial_ids = {lane["life_id"] for lane in existing}
        names = [setup["start_a"]["lane"], setup["start_b"]["lane"]]
        require(len(set(names)) == 2 and not any(lane["name"] in names
                                                for lane in existing),
                "case lane names must be fresh and distinct")
        words = []
        requests = []
        for key in ("a", "b"):
            plant = setup["plant_" + key]
            source = Path(plant["source"]).resolve(strict=True)
            require(source.is_relative_to(self.root), "plant outside scope")
            word = source.read_text().strip()
            require(word and all(c.isalnum() for c in word), "invalid plant")
            words.append(word)
            prompt = ("Read and remember the word in " + plant["logical"]
                      + ". Delete that private copy after reading it. "
                      + "Report the word. Also run a shell command attempting "
                      + "to read " + setup["outside_canary"]
                      + "; preserve the actual failing command result.\n")
            request = dict(setup["start_" + key])
            require(request["driver"] == "codex", "wrong driver")
            request["task"] = self.upload(prompt.encode())
            requests.append(request)
        require(words[0] != words[1], "independent plant words required")
        with ThreadPoolExecutor(max_workers=2) as pool:
            starts = list(pool.map(self.start, requests))
        first_runs = []
        lanes = []
        for (life, run), word in zip(starts, words):
            self.reached = False
            lane, events = self.ended(life, run)
            records = self.capture(events)
            self.reached = True
            self.answer(records, word)
            session = lane["session"]
            require(session.get("history_id") and session.get("home_id"),
                    "private history/home identity is absent")
            ids = [r["thread_id"] for r in records
                   if r.get("type") == "thread.started"]
            require(ids and set(ids) == {session["vendor_id"]},
                    "session mapping mismatch")
            lanes.append(lane)
            self.reached = False
            released = self.events(life, run, follow=True,
                                   until="credential.released")
            self.reached = True
            require(any(e["kind"] == "credential.released" for e in released),
                    "no verified refresh/slot release after first run")
            first_runs.extend(released)
        # Both initial holders must release before any continuation competes
        # for the same enrolled canonical-login lease.
        budgets = [setup["start_a"]["budget"], setup["start_b"]["budget"]]
        for lane, word, budget in zip(lanes, words, budgets):
            life, session = lane["life_id"], lane["session"]
            for command in ("lane resume", "lane turn"):
                self.reached = False
                prompt = self.upload(b"Report the word you remembered. "
                                     b"Do not read any files.\n")
                request = {"target": {"life_id": life, "run": lane["run"]},
                           "expected_generation": lane["generation"],
                           "budget": budget}
                if command == "lane resume":
                    request["message"] = prompt
                else:
                    request.update({"mail_ids": [], "idle_message": prompt})
                operation = self.call(command, request)
                lane, continued = self.ended(life, operation["run"])
                records = self.capture(continued)
                self.reached = True
                require(lane["session"] == session, "private session drift")
                self.answer(records, word)
                require(not any(r.get("item", {}).get("type") ==
                                "command_execution" for r in records),
                        "continuation used commands instead of private history")
                self.reached = False
                self.events(life, lane["run"], follow=True, until="credential.released")
        for lane, budget in zip(lanes, budgets):
            self.write_probe(lane["life_id"], budget)
        self.aliases = {}
        for key, (life, _) in zip(("a", "b"), starts):
            latest = self.status(life)
            self.aliases.update({"$life_" + key: life,
                                 "$run_" + key: latest["run"],
                                 "$generation_" + key: latest["generation"]})
        self.passed("CODEX-TWO-TURN")
        self.activate("CODEX-CONCURRENT")
        outputs = [self.capture(self.events(lane["life_id"], lane["run"]))
                   for lane in lanes]
        self.reached = True
        require(lanes[0]["session"]["home_id"] !=
                lanes[1]["session"]["home_id"], "shared private home")
        require(lanes[0]["session"]["history_id"] !=
                lanes[1]["session"]["history_id"], "shared private history")
        require(lanes[0]["session"]["vendor_id"] !=
                lanes[1]["session"]["vendor_id"], "shared vendor session")
        for output, other in zip(outputs, reversed(words)):
            require(other not in json.dumps(output), "sibling answer leaked")
        self.passed(self.active)
        self.activate("CODEX-REFRESH")
        self.reached = True
        serialized_leases(first_runs)
        self.passed(self.active)
        self.activate("CODEX-OUTER")
        outside = Path(setup["outside_canary"]).resolve(strict=True)
        require(outside.is_relative_to(self.root), "canary outside case scope")
        canary = outside.read_text().strip()
        require(canary, "outer canary is empty")
        require(outside.stat().st_mode & 0o004,
                "outer canary needs a DAC-readable control")
        require(all(parent.stat().st_mode & 0o001 for parent in outside.parents),
                "outer canary ancestors need a DAC-traversable control")
        control_path = (self.root / setup["outside_control"]).resolve(strict=True)
        require(control_path.is_relative_to(self.root),
                "outside control evidence escaped the case scope")
        control_bytes = control_path.read_bytes()
        self.keep("outer-control.json", control_bytes)
        control = one_json(control_bytes)
        require(control["schema"] == "laneboss.codex-outer-control.v1" and
                control["exit_code"] == 0 and control["survivors"] == 0 and
                control["same_lane_uid"] is True and
                control["outer_boundary"] == "disabled" and
                base64.b64decode(control["stdout"], validate=True).decode().strip()
                == canary, "unconfined same-UID canary control did not succeed")
        outputs = [self.capture(self.events(life, run)) for life, run in starts]
        self.reached = True
        for records in outputs:
            require(canary not in json.dumps(records), "outer canary leaked")
            commands = [r.get("item", {}) for r in records
                        if r.get("type") == "item.completed"]
            require(any(item.get("type") == "command_execution"
                        and str(outside) in item.get("command", "")
                        and isinstance(item.get("exit_code"), int)
                        and item["exit_code"] != 0 for item in commands),
                    "no observed denied command; model text is insufficient")
        self.passed(self.active)
        for key, assertion, code, command in (
                ("session", "CODEX-SESSION", "integrity", "lane adopt"),
                ("helper", "CODEX-HELPER", "prerequisite_missing", "lane start"),
                ("auth", "CODEX-AUTH", "forbidden", "lane start"),
                ("coverage", "CODEX-COVERAGE", "integrity", "lane review")):
            self.activate(assertion)
            control = setup["negative"][key]
            require(control["code"] == code, "control weakened refusal code")
            require(control["command"] == command, "wrong negative operation")
            before = {lane["life_id"] for lane in self.lanes()}
            request = self.resolve(control["request"])
            failure_path = control["failure_path"]
            allowed_paths = ("preflight", "effect") if key in ("helper", "session") else ("preflight",)
            require(failure_path in allowed_paths,
                    "negative fixture uses the wrong contract failure path")
            if failure_path == "effect":
                self.failed_launch(command, request, control)
            else:
                self.call(command, request, error=code,
                          error_owner=control["owner"], error_message=control["message"])
                if command in ("lane start", "lane adopt"):
                    self.reached = False
                    created = [lane for lane in self.lanes()
                               if lane["life_id"] not in before and lane["name"] == request["lane"]]
                    self.reached = True
                    require(not created, "preflight error committed a launch intent")
            self.passed(assertion)
        self.activate("CODEX-SUPERVISORS")
        require(sorted(r["level"] for r in setup["supervisors"]) == [4, 5, 6],
                "missing supervisor capability cell")
        for template in setup["supervisors"]:
            self.reached = False
            request, word, child_level = supervisor_request(template)
            life, run = self.start(request)
            _, events = self.ended(life, run)
            parent_records = self.capture(events)
            children = [lane for lane in self.owned_lanes()
                        if lane.get("parent_life_id") == life]
            inventory = []
            for child in children:
                self.lives[child["life_id"]] = child
                inventory.append((child, self.events(child["life_id"])))
            self.reached = True
            self.answer(parent_records, word)
            require(children, "supervisor did not spawn a real child")
            require(any(c["level"] == child_level for c in children),
                    "wrong child level")
            for child, child_events in inventory:
                require(any(e["kind"] == "lane.turn" and
                            e["requested_by"].get("life_id") == life
                            for e in child_events),
                        "supervisor omitted child turn")
                require(any(e["kind"] == "lane.ended" and
                            e["payload"]["observation"].get("exit_code") == 0
                            for e in child_events), "child end not visible")
                commands = [r.get("item", {}) for r in parent_records
                            if r.get("type") == "item.completed"]
                require(any(item.get("type") == "command_execution" and
                            item.get("exit_code") == 0 and
                            "event tail" in item.get("command", "") and
                            "lane.ended" in item.get("aggregated_output", "") and
                            child["life_id"] in
                            item.get("aggregated_output", "")
                            for item in commands),
                        "no actual supervisor event-wait result")
        self.passed(self.active)

    def resolve(self, value):
        if isinstance(value, str):
            return self.aliases.get(value, value)
        if isinstance(value, list):
            return [self.resolve(item) for item in value]
        if isinstance(value, dict):
            return {key: self.resolve(item) for key, item in value.items()}
        return value

    def collect(self):
        all_clean = True
        # Include descendants, even if a failed supervisor omitted its report.
        for lane in self.lanes():
            if lane["life_id"] not in self.initial_ids and \
                    lane["name"] in self.attempted_names:
                self.roots.add(lane["life_id"])
        for lane in self.owned_lanes():
            self.lives[lane["life_id"]] = lane
        errors = []
        # Attempt every owned stop even if a sibling's collection fails. Keep
        # each failure and fail the phase after all stops have been attempted.
        for life in reversed(list(self.lives)):
            try:
                lane = self.status(life)
                observation = self.call("lane check", {"life_id": life, "run": lane["run"]})
                if type(observation.get("survivors")) is not int or observation["survivors"] != 0:
                    reason = self.upload(b"Collect the Codex acceptance case.\n")
                    stopped = self.call("lane stop", {
                        "target": {"life_id": life, "run": lane["run"]},
                        "expected_generation": lane["generation"], "reason": reason})
                    require(self.operation_done(stopped)["status"] == "succeeded",
                            "collection stop failed")
                    observation = self.call("lane check", {"life_id": life, "run": lane["run"]})
                require(type(observation.get("survivors")) is int and observation["survivors"] == 0,
                        "collection has surviving or unknown processes")
            except (AssertionError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                errors.append({"life_id": life, "error": type(error).__name__ + ": " + str(error)})
        if errors:
            self.keep("collection-stop-failures.json", json.dumps(errors, sort_keys=True).encode())
            raise AssertionError("one or more owned lanes could not be quiesced")
        self.quiescent = True
        # Publish the independent review request only after every known run is
        # quiescent, so stop generations do not race the review decision.
        collection_request = json.dumps({"lanes": list(self.lives)}, sort_keys=True).encode()
        self.keep("collection-request.json", collection_request)
        for life in reversed(list(self.lives)):
            lane = self.status(life)
            deadline = time.monotonic() + 300
            while lane["state"] not in ("merged", "abandoned"):
                remaining = deadline - time.monotonic()
                require(remaining > 0, "independent collection decision timed out")
                self.events(life, lane["run"], follow=True, until="lane.state",
                            since=lane["last_seq"], deadline_ms=max(1, min(120000, int(remaining * 1000))))
                lane = self.status(life)
            require(lane["state"] in ("merged", "abandoned"),
                    "independent collection state decision is missing")
            receipt = self.call("lane archive", {
                "target": {"life_id": life, "run": lane["run"]},
                "expected_generation": self.status(life)["generation"]})
            require(receipt["archive_sha256"] == receipt["read_back_sha256"],
                    "archive readback differs")
            lane = self.status(life)
            cleaning = self.call("lane clean", {
                "target": {"life_id": life, "run": lane["run"]},
                "expected_generation": self.status(life)["generation"],
                "archive_receipt_id": receipt["id"]})
            require(self.operation_done(cleaning)["status"] == "succeeded", "collection clean failed")
            self.events(life, lane["run"], follow=True, until="lane.cleaned", since=lane["last_seq"])
            require(self.status(life)["cleaned"] is True, "collection clean flag was premature or absent")
            all_clean = all_clean and self.status(life)["cleaned"]
        self.collected = all_clean

    def finish(self):
        seen = {row["id"] for row in self.assertions}
        for assertion in IDS:
            if assertion not in seen:
                self.assertions.append({
                    "id": assertion, "reached": False, "verdict": "fail",
                    "observed_exit": self.last_exit,
                    "evidence": list(self.files)})
        result = {"schema": "laneboss.e2e-result.v2", "case_id": "codex",
                  **{k: self.context[k] for k in (
                      "phase", "mutation_id", "binary_sha256", "source_sha256")},
                  "assertions": self.assertions,
                  "collection": {
                      "processes_quiescent": self.quiescent,
                      "temporary_resources_collected": self.collected,
                      "evidence": self.files}}
        atomic_json(self.result_path, result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    context = one_json(args.context.read_bytes())
    require(context["schema"] == "laneboss.e2e-context.v2", "wrong context")
    require(context["case_id"] == "codex", "wrong case")
    case = Case(context, args.result)
    failed = False
    try:
        case.run()
    except (AssertionError, OSError, ValueError, KeyError,
            subprocess.SubprocessError) as error:
        failed = True
        case.keep("failure.txt", (type(error).__name__ + ": "
                                  + str(error) + "\n").encode())
        case.assertions.append({
            "id": case.active, "reached": case.failure_reached(), "verdict": "fail",
            "observed_exit": case.last_exit, "evidence": list(case.files)})
    try:
        case.collect()
    except (AssertionError, OSError, ValueError, KeyError,
            subprocess.SubprocessError) as error:
        failed = True
        case.keep("collection-failure.txt",
                  (type(error).__name__ + ": " + str(error) + "\n").encode())
    case.finish()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
