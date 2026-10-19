#!/usr/bin/env python3
"""Live CLI acceptance; execute only on the authorized Linux test box."""

import argparse
import base64
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import re
import subprocess
import sys
import time


class Failure(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise Failure(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=unique_object)


def json_values(data):
    text = data.decode("utf-8")
    decoder = json.JSONDecoder(object_pairs_hook=unique_object)
    values, offset = [], 0
    while offset < len(text):
        if text[offset] in " \t\r\n":
            offset += 1
            continue
        value, offset = decoder.raw_decode(text, offset)
        values.append(value)
    return values


def tail_output(data, request, request_id, config):
    values = json_values(data)
    require(values and isinstance(values[0], dict), "event stream has no initial snapshot")
    page = values[0]
    require(isinstance(page.get("events"), list), "event snapshot has no array")
    events = list(page["events"])
    ended = False
    for index, frame in enumerate(values[1:], 1):
        require(not ended and frame.get("request_id") == request_id and frame.get("index") == index,
                "stream correlation/order changed")
        require("error" not in frame and "chunk" not in frame and type(frame.get("end")) is bool,
                "event stream returned an error or unexpected payload")
        if frame["end"]:
            require("event" not in frame, "stream end carried an event")
            ended = True
        else:
            require(isinstance(frame.get("event"), dict), "stream data has no event")
            events.append(frame["event"])
    require(ended, "event stream disconnected before its end")
    last = request["since"]
    for event in events:
        require(event["schema"] == 2 and event["config"] == config and event.get("life_id") == request["life_id"]
                and event.get("run") == request["run"] and event["seq"] > last,
                "stream snapshot/event escaped the selected life/run/sequence")
        last = event["seq"]
    require(any(e["kind"] == request["until"] and e["origin"] == "service" for e in events),
            "event stream ended without the selected authentic run end")
    return events


def validate_release(receipt, lease, target):
    require(all(receipt.get(field) for field in ("id", "lease_id", "containment_id", "operation_id", "effect_id", "observed_at")),
            "helper release lacks its measured binding")
    require(receipt["lease_id"] == lease["id"] and receipt["containment_id"] == lease["containment_id"]
            and receipt["backend"] == "linux-bwrap-landlock", "helper release lease/backend changed")
    require(all(type(receipt.get(field)) is int and receipt[field] == 0
                for field in ("live_connections", "queued_jobs", "writable_exports")),
            "helper release measurements are unknown or nonzero")
    observed = receipt["quiescence"]
    require(observed["state"] == "exited" and type(observed.get("survivors")) is int and observed["survivors"] == 0
            and observed["handle"]["target"] == target and observed["handle"]["containment_id"] == receipt["containment_id"],
            "helper release has no matching measured quiescence")
    require(receipt["observed_at"].endswith("Z") and observed["observed_at"].endswith("Z")
            and datetime.fromisoformat(receipt["observed_at"]) >= datetime.fromisoformat(observed["observed_at"]),
            "helper release measurement time is invalid")


def validate_continuation(swap, prior, continued, launch, grants):
    require(launch["profile_swap"] == swap and swap["eligibility_id"]
            and swap["profile_grant_id"] in grants
            and continued["profile_grant_id"] == swap["profile_grant_id"]
            and 0 < swap["expected_generation"] < continued["generation"]
            and swap["cancellation_epoch"] == prior["cancellation_epoch"] == continued["cancellation_epoch"],
            "profile continuation lost its draft.4 eligibility/generation fence")
    require(prior["task"] == continued["task"] and prior["counters"] == continued["counters"]
            and prior["session"]["history_id"] and continued["run"] == swap["continuation_run"]
            and swap["continuation_run"] == swap["causing_run"] + 1,
            "profile continuation changed task/history/counters or run identity")


def quota_kind(message):
    if not isinstance(message, str) or any(character in message for character in "\r\n\x00"):
        return ""
    hit = re.fullmatch(r"You['’]ve hit your (limit|usage limit|session limit|weekly limit|Opus limit|Sonnet limit)(?:[.!]| · (?:resets|limit resets) [^\r\n]+)?(?: · progress saved)?", message)
    if hit:
        return "session_limit" if hit.group(1) == "session limit" else "usage_limit"
    return "usage_limit" if re.fullmatch(r"Usage limit reached(?: · limit resets [^\r\n]+)?", message) else ""


def quota_record(record, session):
    # Static vendor sources: docs/claudock.md and profile_swap/main.go. The
    # result/errors fields are real stream fields; subtype is not invented.
    if record.get("session_id") != session:
        return False
    if record.get("type") == "rate_limit_event":
        return record.get("rate_limit_info", {}).get("status") == "rejected"
    if record.get("type") == "assistant":
        if record.get("error") != "rate_limit":
            return False
        blocks = record.get("message", {}).get("content", [])
        if not isinstance(blocks, list) or len(blocks) != 1 or blocks[0].get("type") != "text":
            return False
        messages = [blocks[0].get("text")]
    elif record.get("type") == "result":
        if record.get("is_error") is not True or record.get("subtype", "") not in {"", "success", "error_during_execution"}:
            return False
        messages = []
        if "errors" in record:
            if not isinstance(record["errors"], list) or not record["errors"]:
                return False
            messages.extend(record["errors"])
        if "result" in record:
            if not isinstance(record["result"], str):
                return False
            if record["result"]:
                messages.append(record["result"])
    else:
        return False
    kinds = [quota_kind(message) for message in messages]
    return bool(kinds) and all(kind and kind == kinds[0] for kind in kinds)


def zero_observation(observed, prepared=False):
    allowed_states = {"prepared", "exited"} if prepared else {"exited"}
    return observed.get("state") in allowed_states and type(observed.get("survivors")) is int and observed["survivors"] == 0


def aborted_observation(events, observed, life):
    target = observed.get("handle", {}).get("target", {})
    return target.get("life_id") == life and zero_observation(observed, prepared=True) and any(
        event["kind"] == "launch.failed" and event["origin"] == "service"
        and event.get("run") == target.get("run") and event["payload"]["agent_executed"] is False for event in events)


def collected_helpers(events, observed, life):
    allocated = {event["payload"]["id"]: event["payload"] for event in events if event["kind"] == "helper.allocated"}
    resolved = set()
    for event in events:
        if event["kind"] != "helper.released":
            continue
        require(event["origin"] == "service", "helper release is not an authoritative service event")
        receipt = event["payload"]
        require(receipt["lease_id"] in allocated, "helper release has no observed allocation")
        target = receipt["quiescence"]["handle"]["target"]
        require(target["life_id"] == life, "helper release belongs to another life")
        validate_release(receipt, allocated[receipt["lease_id"]], target)
        resolved.add(receipt["lease_id"])
    observations = [observed] + [event["payload"] for event in events if event["kind"] == "run.observed"]
    for lease_id, lease in allocated.items():
        if any(aborted_observation(events, item, life) and item["handle"]["containment_id"] == lease["containment_id"] for item in observations):
            resolved.add(lease_id)
    return allocated.keys() <= resolved


def verify_negative(asynchronous, before, after, events, observed):
    require(not any(event["kind"] in {"lane.started", "lane.resumed", "watchdog.swapped"} for event in events),
            "a refusal started or rotated an agent")
    if asynchronous:
        require(any(event["kind"] == "launch.failed" and event["origin"] == "service" and event.get("run") == after["run"]
                    and event["payload"]["agent_executed"] is False for event in events),
                "negative cell lacks independent no-execution evidence")
    else:
        require(not any(event["kind"] in {"launch.prepared", "launch.failed"} for event in events), "synchronous refusal emitted launch events")
        require(after["run"] == before["run"] and after["launch_id"] == before["launch_id"],
                "synchronous refusal changed the bound run")
    require(zero_observation(observed, prepared=asynchronous), "invalid launch control left unknown containment")


def validate_workspace_write(row, expected):
    require(row["errno"] == 0 and row["bytes"] == len(expected) and row["sha256"] == sha(expected),
            "vendor tool did not write the exact unpredictable workspace bytes")


def same_workspace(before, after):
    # Fix 9 takes a fresh snapshot of the same private working tree each run.
    return all(before[field] == after[field] for field in ("id", "project_id", "base", "branch", "logical_cwd"))


def validate_transcript_mode(row):
    require(row["errno"] == 0 and row.get("regular") is True and row.get("mode") == 0o600 and row.get("nlink") == 1,
            "first vendor transcript is not a private single-link 0600 file")


def validate_sibling_denial(row):
    require(type(row["errno"]) is int and row["errno"] in {1, 13} and row["bytes"] == 0,
            "existing sibling canary did not produce EPERM or EACCES")


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True) + "\n").encode()


def atomic(path, data):
    temporary = path.with_name(path.name + ".pending")
    with temporary.open("xb") as output:
        os.chmod(temporary, 0o600)
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


class Case:
    mutation_cells = {"shared-home": "shared-home", "digest-bypass": "wrong-digest",
                      "new-conversation": "lost-conversation", "quoted-limit": "quoted-limit",
                      "auth-as-limit": "auth-refusal", "history-moved": "swap"}

    def __init__(self, context, result_path):
        self.context = context
        self.result_path = result_path
        self.root = Path(context["test_root"])
        self.evidence = Path(context["evidence_root"])
        self.evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.files = []
        self.input_bytes = {}
        self.index = 0
        self.last_exit = 0
        self.reached = False
        self.life = None
        self.lives = set()
        self.quiescent = False
        self.collected = False
        self.events = []
        self.deadline = time.monotonic() + 1650

    def reach(self, cell):
        if self.context["phase"] == "red" and self.mutation_cells.get(self.context["mutation_id"]) == cell:
            self.reached = True

    def complete(self):
        require(self.quiescent and self.collected, "candidate assertion is incomplete")
        if self.context["phase"] == "candidate":
            self.reached = True

    def keep(self, name, data):
        path = self.evidence / name
        require(not path.exists(), "evidence path would be overwritten")
        atomic(path, data)
        self.files.append({"path": name, "sha256": sha(data), "bytes": len(data)})
        return path

    def invoke(self, command, request, success=True):
        require(time.monotonic() < self.deadline, "case deadline expired")
        self.index += 1
        prefix = f"cli-{self.index:04d}"
        request_file = self.keep(prefix + ".request.json", encoded(request))
        request_id, key = secrets.token_hex(16), secrets.token_hex(16)
        argv = [self.context["binary"], *command.split(), "--config",
                self.context["config"], "--binding", self.context["binding_file"], "--request", str(request_file)]
        argv += ["--request-id", request_id, "--idempotency-key", key]
        # Retain identities before invoking the CLI. A retry must reuse this
        # exact argv/key; this case never retries an uncertain mutation anew.
        self.keep(prefix + ".argv.json", encoded(argv))
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = process.communicate(timeout=min(125, self.deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            # Stop exactly this CLI PID; the CLI must not contain the agent.
            process.kill()
            stdout, stderr = process.communicate()
            self.last_exit = process.returncode
            self.keep(prefix + ".stdout", stdout)
            self.keep(prefix + ".stderr", stderr)
            self.keep(prefix + ".exit.json", encoded({"exit": process.returncode, "timeout": True}))
            raise Failure("public CLI timed out")
        self.last_exit = process.returncode
        self.keep(prefix + ".stdout", stdout)
        self.keep(prefix + ".stderr", stderr)
        self.keep(prefix + ".exit.json", encoded({"exit": process.returncode, "timeout": False}))
        if not success:
            return process.returncode, stdout, stderr
        require(process.returncode == 0, "public CLI dependency failed; retain its exact stderr")
        if command == "event tail" and request["follow"]:
            return tail_output(stdout, request, request_id, self.context["config"])
        # The installed CLI prints the typed result body, including Health's
        # own protocol field. It does not print an RPC envelope here.
        return decode(stdout)

    def upload(self, data, kind="prompt"):
        self.keep(f"input-{self.index:04d}-{secrets.token_hex(4)}", data)
        digest = sha(data)
        upload = self.invoke("blob begin", {"class": kind, "bytes": len(data), "sha256": digest})
        object_id = upload["object_id"]
        size = min(upload["max_chunk_bytes"], 131072)
        require(size > 0, "service advertised an invalid chunk bound")
        for offset in range(0, len(data), size):
            chunk = data[offset:offset + size]
            self.invoke("blob chunk", {"object_id": object_id, "offset": offset,
                        "data": base64.b64encode(chunk).decode(), "sha256": sha(chunk)})
        reference = self.invoke("blob commit", {"object_id": object_id, "sha256": digest})
        require(reference["sha256"] == digest and reference["bytes"] == len(data), "uploaded input bytes changed")
        return reference

    def blob(self, reference):
        require(0 < reference["bytes"] <= 67108864, "evidence blob is missing or oversized")
        data = bytearray()
        while len(data) < reference["bytes"]:
            chunk = self.invoke("blob read", {"object_id": reference["id"], "offset": len(data), "limit": 131072})
            content = base64.b64decode(chunk["data"], validate=True)
            require(chunk["object_id"] == reference["id"] and chunk["offset"] == len(data)
                    and content and sha(content) == chunk["sha256"], "blob chunk attribution/hash mismatch")
            data.extend(content)
        require(len(data) == reference["bytes"] and sha(data) == reference["sha256"], "evidence blob hash/size mismatch")
        return bytes(data)

    def terminal_operation(self, receipt):
        while receipt["status"] in {"pending", "running"}:
            require(time.monotonic() < self.deadline, "operation deadline expired")
            time.sleep(1)
            receipt = self.invoke("operation get", {"operation_id": receipt["id"]})
        return receipt

    def operation(self, receipt):
        receipt = self.terminal_operation(receipt)
        require(receipt["status"] == "succeeded" and "error" not in receipt, "service operation failed")
        return receipt

    def wait_run(self, life_id, after_run):
        while True:
            require(time.monotonic() < self.deadline, "continuation did not advance before the case deadline")
            selected = self.invoke("lane status", {"life_id": life_id, "run": 0})
            if selected["run"] > after_run:
                return selected
            require(selected["state"] not in {"lost", "abandoned", "merged"} and not selected["cleaned"], "continuation was cancelled or lost")
            time.sleep(1)

    def tail(self, life_id, since, follow=False, after_run=0):
        if follow:
            selected = self.wait_run(life_id, after_run)
            require(selected["run"] > 0, "follow has no selected run")
            followed = self.invoke("event tail", {"life_id": life_id, "run": selected["run"], "since": since,
                                   "cursor": "", "follow": True, "until": "lane.ended", "deadline_ms": 120000})
            # A quota continuation may already have advanced the selected run.
            # Retain all intervening committed captures/swap events as well.
            committed = self.tail(life_id, since)
            require(all(event in committed for event in followed), "stream events differ from committed history")
            return committed
        cursor, events, last = "", [], since
        for _ in range(256):
            page = self.invoke("event tail", {"life_id": life_id, "run": 0, "since": 0 if cursor else since,
                               "cursor": cursor, "follow": follow, "until": "lane.ended", "deadline_ms": 120000})
            require(isinstance(page["events"], list), "event page has no event array")
            for event in page["events"]:
                require(event["schema"] == 2 and event["config"] == self.context["config"]
                        and event["life_id"] == life_id and event["seq"] > last,
                        "event scope or saved-sequence boundary changed")
                last = event["seq"]
                events.append(event)
            cursor = page["cursor"]
            if not cursor:
                return events
        raise Failure("event pagination exceeded its bound")

    def settled(self, life_id, since):
        after_run = 0
        while True:
            require(time.monotonic() < self.deadline, "lane deadline expired")
            events = self.tail(life_id, since, True, after_run=after_run)
            require(events, "follow returned without an observed end")
            self.events.extend(events)
            for event in events:
                if event["kind"] in {"lane.started", "lane.resumed"}:
                    require(event["payload"]["boundary_backend"] == "linux-bwrap-landlock"
                            and event["payload"]["endpoint_generation"] > 0,
                            "vendor launch did not use the production Linux boundary")
            since = events[-1]["seq"]
            ends = [e for e in events if e["kind"] == "lane.ended"]
            if not ends:
                continue
            if ends[-1]["payload"]["profile_continuation"]:
                after_run = ends[-1]["run"]
                continue
            end = ends[-1]
            observed = end["payload"]["observation"]
            require(observed["state"] == "exited" and observed.get("survivors") == 0
                    and observed.get("exit_code") == 0 and "signal" not in observed,
                    "lane did not end successfully with zero survivors")
            lane = self.invoke("lane status", {"life_id": life_id, "run": end["run"]})
            check = self.invoke("lane check", {"life_id": life_id, "run": lane["run"]})
            require(check["state"] == "exited" and check.get("survivors") == 0,
                    "independent process observation is not quiescent")
            self.quiescent = True
            return lane, since

    def assistant_text(self, events):
        text = []
        for event in events:
            if event["kind"] != "capture.appended":
                continue
            capture = event["payload"]
            require(capture.get("binding_id") and capture["primary"] and capture["coverage"] == "complete", "capture coverage or producer binding is incomplete")
            if capture["stream"] not in {"stdout", "vendor"}:
                continue
            for line in self.blob(capture["data"]).splitlines():
                record = decode(line)
                if record.get("type") == "assistant" and not record.get("error"):
                    for block in record.get("message", {}).get("content", []):
                        if block.get("type") == "text":
                            text.append(block["text"])
        return "\n".join(text)

    def inputs(self, name):
        path = self.root / name
        require(path.is_file() and not path.is_symlink(), "required installed-case input is missing")
        data = path.read_bytes()
        if name in self.input_bytes:
            require(self.input_bytes[name] == data, "installed-case input changed between operations")
        else:
            self.keep("setup-" + name, data)
            self.input_bytes[name] = data
        return decode(data)

    def flow(self):
        require(sys.platform == "linux", "live acceptance requires the authorized Linux test box")
        facts = Path("/etc/os-release").read_bytes()
        require(b'VERSION_ID="24.04"' in facts and b"ID=ubuntu" in facts, "live acceptance requires Ubuntu 24.04")
        self.keep("os-release.evidence", facts)
        system = os.uname()
        self.keep("platform.json", encoded({"system": system.sysname, "release": system.release, "machine": system.machine}))
        require(self.context["schema"] == "laneboss.e2e-context.v2" and self.context["case_id"] == "claudock", "wrong case context")
        require(self.context["phase"] in {"candidate", "red"}, "unknown acceptance phase")
        require(self.context["phase"] != "red" or self.context["mutation_id"] in self.mutation_cells,
                "red control has no implemented public-operation cell")
        binary = Path(self.context["binary"])
        require(binary.is_absolute() and not binary.is_symlink() and sha(binary.read_bytes()) == self.context["binary_sha256"], "tested binary hash mismatch")
        binding_path = Path(self.context["binding_file"])
        require(binding_path.is_absolute() and not binding_path.is_symlink(), "installed binding must be an absolute regular projection")
        binding_bytes = binding_path.read_bytes()
        binding = decode(binding_bytes)
        require(binding["schema"] == "laneboss.binding.v2" and binding["contract_revision"] == "v2.0-draft.4"
                and binding["protocol"] == "laneboss.rpc.v2" and binding["api_schema"] == 2
                and binding["config"] == self.context["config"] and binding["class"] == "lane"
                and binding["artifact_sha256"] == self.context["binary_sha256"], "case requires its installed draft.4 parent-lane binding")
        self.keep("installed-binding.json", binding_bytes)
        health = self.invoke("health", {"client_version": "v2.0-draft.4", "artifact_sha256": self.context["binary_sha256"]})
        require(health["ready"] and health["protocol"] == "laneboss.rpc.v2" and health["schema"] == 2
                and health["artifact_sha256"] == self.context["binary_sha256"], "installed service is not the tested artifact")
        self.vendor_inputs()
        require(len(self.context["profile_grant_ids"]) >= 2, "two live same-provider profile grants are required")
        start = self.inputs("start.json")
        require(start["driver"] == "claudock-cli" and start["profile_grant_id"] in self.context["profile_grant_ids"], "start did not select an authorized Claudock profile")
        nonce = secrets.token_hex(16)
        task = ("Remember this nonce only in this conversation: " + nonce +
                ". Do not write any files. Reply with ready. Later messages will ask about it.\n")
        start["task"] = self.upload(task.encode())
        receipt = self.invoke("lane start", start)
        self.life = receipt.get("life_id")
        require(self.life, "start did not return a life identity")
        self.lives.add(self.life)
        self.quiescent = False
        lane, since = self.settled(self.life, 0)
        self.reach("start")
        session, workspace = lane["session"], lane["workspace"]
        require(session["driver"] == "claudock-cli" and session["vendor_id"] and session["history_id"], "real vendor session/history mapping is missing")
        transcript = self.syscall_probe(lane, {"transcript": "/home/lane/.claude/projects"}, session=session["vendor_id"])
        validate_transcript_mode(transcript["transcript"])
        for command, prompt, expected in [
            ("lane resume", "What was the nonce from our first message? Reply only with it.\n", nonce),
            ("lane turn", "Reply only with the same nonce, with its characters in reverse order.\n", nonce[::-1]),
        ]:
            message = self.upload(prompt.encode())
            request = {"target": {"life_id": self.life, "run": lane["run"]},
                       "expected_generation": lane["generation"], "budget": start["budget"]}
            if command == "lane resume":
                request["message"] = message
            else:
                request.update({"mail_ids": [], "idle_message": message})
            self.quiescent = False
            self.operation(self.invoke(command, request))
            first = len(self.events)
            lane, since = self.settled(self.life, since)
            self.reach("resume" if command == "lane resume" else "turn")
            require(lane["session"] == session and same_workspace(workspace, lane["workspace"]), "continuation changed session/history/cwd/workspace")
            require(expected in self.assistant_text(self.events[first:]), "real resumed conversation lost its unpredictable nonce")
        lane, since = self.workspace_write(lane, since, start["budget"], session, workspace)
        self.verify_swap()
        self.probe(lane)
        self.negative_controls()
        self.collect(lane)
        self.complete()

    def workspace_write(self, lane, since, budget, session, workspace):
        name = "claudock-write-" + secrets.token_hex(12) + ".txt"
        expected = ("vendor-tool-" + secrets.token_hex(24) + "\n").encode()
        logical = "/work/main/" + name
        message = self.upload(("Use a vendor file or shell tool to create " + logical +
                               " with exactly these ASCII bytes, including the final newline: " +
                               json.dumps(expected.decode()) +
                               ". Actually write the file, then reply with done.\n").encode())
        request = {"target": {"life_id": self.life, "run": lane["run"]}, "expected_generation": lane["generation"],
                   "mail_ids": [], "idle_message": message, "budget": budget}
        self.quiescent = False
        self.operation(self.invoke("lane turn", request))
        first = len(self.events)
        written, since = self.settled(self.life, since)
        require(written["session"] == session and same_workspace(workspace, written["workspace"]), "tool turn moved the private conversation")
        tool_calls = []
        for event in self.events[first:]:
            if event["kind"] != "capture.appended":
                continue
            capture = event["payload"]
            require(capture.get("binding_id") and capture["primary"] and capture["coverage"] == "complete",
                    "tool turn lacks producer-bound primary evidence")
            if capture["stream"] not in {"stdout", "vendor"}:
                continue
            for line in self.blob(capture["data"]).splitlines():
                if not line.strip():
                    continue
                record = decode(line)
                if record.get("type") == "assistant" and record.get("session_id") == session["vendor_id"]:
                    tool_calls.extend(block for block in record.get("message", {}).get("content", [])
                                      if block.get("type") == "tool_use" and block.get("name") in {"Write", "Edit", "Bash"})
        require(tool_calls, "workspace write did not reach a captured vendor tool")
        rows = self.syscall_probe(written, {"workspace-write": logical})
        validate_workspace_write(rows["workspace-write"], expected)
        return written, since

    def vendor_inputs(self):
        inputs = self.inputs("vendor-inputs.json")
        view = self.invoke("config read", {"view": "show"})
        projection = decode(self.blob(view["projection"]))
        require(projection["schema"] == "laneboss.config-view.v2" and projection["config"] == self.context["config"]
                and projection["view"] == "show" and projection["generation"] == view["generation"],
                "verified vendor resource projection lost its config/generation")
        resources = projection["resources"]
        for driver in ["claudock", "claude"]:
            item = inputs[driver]
            pin = item["executable"]
            physical = (self.root / item["bytes_relative"]).resolve()
            require(physical.is_relative_to(self.root.resolve()) and physical.is_file(), "retained vendor bytes escaped the disposable scope")
            digest = hashlib.sha256()
            with physical.open("rb") as source:
                for block in iter(lambda: source.read(1048576), b""):
                    digest.update(block)
            require(digest.hexdigest() == pin["sha256"], "retained vendor artifact digest mismatch")
            matching = [r for r in resources if r["id"] == pin["id"] and r["sha256"] == pin["sha256"]
                        and r["version"] == pin["version"] and r["verified_loaded"]]
            require(len(matching) == 1, "actual vendor artifact is not verified by the installed service")
            for kind in ["help", "version", "auth", "records"]:
                relative = item[kind + "_relative"]
                path = (self.root / relative).resolve()
                require(path.is_relative_to(self.root.resolve()) and path.is_file(), "pinned vendor source evidence is missing")
                data = path.read_bytes()
                require(data, "pinned vendor source evidence is empty")
                self.keep(driver + "-" + kind + ".evidence", data)

    def verify_swap(self):
        swaps = [e for e in self.events if e["kind"] == "watchdog.swapped"]
        require(len(swaps) == 1, "a real validated limit must cause exactly one profile swap")
        swap = swaps[0]["payload"]["swap"]
        require(swap["from_profile_id"] != swap["to_profile_id"] and swap["room"]["available"], "profile slot or outside room did not change")
        require(swap["room"]["profile_id"] == swap["to_profile_id"]
                and datetime.fromisoformat(swap["room"]["checked_at"]) <= datetime.fromisoformat(swaps[0]["observed_at"])
                < datetime.fromisoformat(swap["room"]["expires_at"]), "profile room evidence is stale or belongs to another profile")
        self.blob(swap["room"]["evidence"])
        captures = [e["payload"] for e in self.events if e["kind"] == "capture.appended"
                    and e["payload"]["id"] == swap["limit"]["capture_id"]]
        require(len(captures) == 1 and captures[0].get("binding_id") and captures[0]["primary"] and captures[0]["coverage"] == "complete"
                and captures[0]["data"]["sha256"] == swap["limit"]["capture_sha256"], "limit has no exact primary captured bytes")
        records = [decode(line) for line in self.blob(captures[0]["data"]).splitlines() if line.strip()]
        capture_target = captures[0]["target"]
        require(capture_target == swap["limit"]["target"], "quota capture belongs to another run")
        sessions = [e["payload"]["lane"]["session"]["vendor_id"] for e in self.events
                    if e["kind"] in {"lane.started", "lane.resumed"} and e["run"] == swap["causing_run"]]
        require(len(sessions) == 1, "quota capture has no unique causing session")
        require(any(quota_record(record, sessions[0]) for record in records), "limit evidence is only quoted text")
        starts = [e for e in self.events if e["kind"] == "lane.resumed"
                  and e["payload"].get("profile_continuation_of") == swap["causing_run"]]
        require(len(starts) == 1 and starts[0]["logical_turn_id"] == swaps[0]["logical_turn_id"], "profile swap replaced or duplicated the logical turn")
        before = [e for e in self.events if e["kind"] in {"lane.started", "lane.resumed"}
                  and e["run"] == swap["causing_run"]]
        ended = [e for e in self.events if e["kind"] == "lane.ended" and e["run"] == swap["causing_run"]]
        require(len(before) == 1 and len(ended) == 1, "swap has no unique causing launch/end")
        prior, continued = before[0]["payload"]["lane"], starts[0]["payload"]["lane"]
        self.reach("swap")
        require(prior["session"] == continued["session"] and same_workspace(prior["workspace"], continued["workspace"])
                and prior["model"] == continued["model"], "slot change moved the private conversation, cwd or model")
        validate_continuation(swap, prior, continued, starts[0]["payload"], self.context["profile_grant_ids"])
        for field in ["wall_ms", "cpu_seconds", "memory_bytes", "processes", "disk_bytes", "spend_micros"]:
            require(continued["budget_remaining"][field] <= ended[0]["payload"]["budget_remaining"][field], "profile continuation reset a remaining budget")

    def syscall_probe(self, lane, paths, session=None):
        # Templates are frozen TestChildRequest/WorkerPlan objects prepared by
        # the installed grants-worker harness. They carry no secret values.
        template = self.inputs("probe-request.json")
        plan = self.inputs("probe-plan.json")
        probe_input = {"schema": "claudock.probe.v1", "nonce": secrets.token_hex(16),
                       "paths": paths}
        if session is not None:
            probe_input["session"] = session
        input_bytes = encoded(probe_input)
        plan["input"] = self.upload(input_bytes, "artifact")
        template["test_plan"] = self.upload(encoded(plan), "artifact")
        template["child"] = {"life_id": self.life, "run": lane["run"]}
        receipt = self.operation(self.invoke("grants test-child", template))
        output = decode(self.blob(receipt["result"]))
        require(output["schema"] == "claudock.probe-result.v1" and output["input_sha256"] == sha(input_bytes), "syscall probe input/output attribution mismatch")
        rows = output["observations"]
        require(set(rows) == set(paths), "syscall probe omitted or added observations")
        return rows

    def probe(self, lane):
        paths = self.inputs("probe-paths.json")
        observed = {}
        for label, item in paths.items():
            original = self.root / item["observer_relative"]
            physical = original.resolve()
            require(not original.is_symlink() and physical.is_relative_to(self.root.resolve()) and physical.is_file(),
                    "canary observer is not an existing regular disposable file")
            data = physical.read_bytes()
            require(data, "canary control is empty")
            observed[label] = sha(data)
        rows = self.syscall_probe(lane, {label: item["logical"] for label, item in paths.items()})
        require(set(rows) == {"own", "sibling-history", "sibling-token"}, "syscall probe did not reach all boundaries")
        require(rows["own"]["errno"] == 0 and rows["own"]["sha256"] == observed["own"], "granted own-file control failed")
        for label in ["sibling-history", "sibling-token"]:
            validate_sibling_denial(rows[label])
        for label, item in paths.items():
            require(sha((self.root / item["observer_relative"]).read_bytes()) == observed[label], "observer canary read-back changed")

    def negative_controls(self):
        controls = self.inputs("negative-controls.json")
        require(set(controls) == {"wrong-digest", "shared-home", "lost-conversation", "auth-refusal", "quoted-limit"}, "negative control cells are missing")
        expected_codes = {"wrong-digest": "integrity", "shared-home": "integrity", "lost-conversation": "not_found"}
        for name in ["wrong-digest", "shared-home", "lost-conversation"]:
            control = controls[name]
            require(control["expected_code"] == expected_codes[name], "negative control substituted an unrelated failure code")
            request = control["request"]
            life = request["target"]["life_id"]
            self.lives.add(life)
            before = self.invoke("lane status", {"life_id": life, "run": 0})
            code, stdout, stderr = self.invoke("lane resume", request, success=False)
            if code == 0:
                receipt = decode(stdout)
                if "protocol" in receipt:
                    receipt = receipt["result"]
                terminal = self.terminal_operation(receipt)
                refusal = terminal.get("error", {})
            else:
                refusal = decode(stderr)
                if "error" in refusal:
                    refusal = refusal["error"]
            events = self.tail(life, control["since"])
            if refusal.get("code") == expected_codes[name] or any(e["kind"] in {"lane.started", "lane.resumed"} for e in events):
                self.reach(name)
            require(refusal.get("code") == expected_codes[name], "negative cell failed before reaching its intended guard or unexpectedly ran")
            after = self.invoke("lane status", {"life_id": life, "run": 0})
            check = self.invoke("lane check", {"life_id": life, "run": after["run"]})
            verify_negative(code == 0, before, after, events, check)
        auth = controls["auth-refusal"]
        life = auth["request"]["target"]["life_id"]
        self.lives.add(life)
        self.terminal_operation(self.invoke("lane resume", auth["request"]))
        events = self.tail(life, auth["since"], True)
        ends = [e for e in events if e["kind"] == "lane.ended"]
        if ends:
            self.reach("auth-refusal")
        require(ends and ends[-1]["payload"]["observation"]["state"] == "exited"
                and ends[-1]["payload"]["observation"].get("survivors") == 0,
                "real auth refusal did not reach a quiescent vendor end")
        require(not any(e["kind"] in {"watchdog.limit", "watchdog.swapped"} for e in events), "auth refusal triggered watchdog")
        auth_records = []
        for event in events:
            if event["kind"] == "capture.appended" and event["payload"]["stream"] in {"stdout", "vendor"}:
                capture = event["payload"]
                require(capture.get("binding_id") and capture["primary"] and capture["coverage"] == "complete", "auth refusal has no producer-bound complete primary capture")
                auth_records.extend(decode(line) for line in self.blob(capture["data"]).splitlines() if line.strip())
        require(any(r.get("type") == "assistant" and r.get("error") == "authentication_failed"
                    or r.get("type") == "error" and r.get("error", {}).get("code") in {"authentication_error", "invalid_api_key", "token_expired"}
                    for r in auth_records), "auth cell did not observe a real structured vendor refusal")
        control = controls["quoted-limit"]
        life = control["request"]["target"]["life_id"]
        self.lives.add(life)
        quote_request = dict(control["request"])
        quote_request["message"] = self.upload(b'Reply with exactly this quoted diagnostic: "Usage limit reached". It is quoted test text.\n')
        before = self.invoke("lane status", quote_request["target"])
        self.operation(self.invoke("lane resume", quote_request))
        first = len(self.events)
        lane, since = self.settled(life, control["since"])
        self.reach("quoted-limit")
        require("Usage limit reached" in self.assistant_text(self.events[first:]) and lane["profile_grant_id"] == before["profile_grant_id"], "quoted text was not actually emitted under the same profile")
        events = self.tail(lane["life_id"], control["since"])
        require(not any(e["kind"] in {"watchdog.limit", "watchdog.swapped"} for e in events), "quoted limit triggered watchdog")

    def collect(self, lane):
        # Stopping is authorized for these disposable cases; acceptance/merge
        # decisions and force-removal are not part of this runner case.
        observations = {}
        safe_processes = {}
        released_all = True
        for life in sorted(self.lives):
            current = self.invoke("lane status", {"life_id": life, "run": 0})
            target = {"life_id": life, "run": current["run"]}
            observation = self.invoke("lane check", target)
            events = self.tail(life, 0)
            # Stop also cancels a queued watchdog intent after an observed end.
            # An already aborted unopened gate is collected through its retained
            # no-execution/containment evidence, never relabeled as Release.
            if not aborted_observation(events, observation, life):
                reason = self.upload(b"Collect the Claudock acceptance run.\n")
                current = self.invoke("lane status", {"life_id": life, "run": 0})
                target = {"life_id": life, "run": current["run"]}
                self.operation(self.invoke("lane stop", {"target": target,
                               "expected_generation": current["generation"], "reason": reason}))
                observation = self.invoke("lane check", target)
            observations[life] = observation
            events = self.tail(life, 0)
            safe_processes[life] = zero_observation(observation) or aborted_observation(events, observation, life)
            leased = {e["payload"]["slot"]["id"] for e in events if e["kind"] == "credential.leased"}
            released = {e["payload"]["slot"]["id"] for e in events if e["kind"] == "credential.released"}
            released_all = released_all and leased <= released
            require(life != self.life or any(e["kind"] == "helper.allocated" for e in events), "main lane has no observed helper allocation")
            released_all = released_all and collected_helpers(events, observation, life)
        self.quiescent = bool(observations) and all(safe_processes.values())
        self.collected = released_all and self.quiescent
        self.keep("collection.json", encoded({"observations": observations, "credentials_released": released_all}))
        require(self.collected, "run credentials/processes were not independently collected")

    def finish(self, failure):
        if failure is not None:
            self.keep("failure.json", encoded({"reason": failure}))
        result = {"schema": "laneboss.e2e-result.v2", "case_id": "claudock",
                  "phase": self.context["phase"], "mutation_id": self.context["mutation_id"],
                  "binary_sha256": self.context["binary_sha256"], "source_sha256": self.context["source_sha256"],
                  "assertions": [{"id": "CLAUDOCK-TWO-TURN", "reached": self.reached,
                                  "verdict": "fail" if failure else "pass", "observed_exit": self.last_exit,
                                  "evidence": self.files}],
                  "collection": {"processes_quiescent": self.quiescent,
                                 "temporary_resources_collected": self.collected,
                                 "evidence": [f for f in self.files if f["path"] == "collection.json"]}}
        atomic(self.result_path, encoded(result))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    arguments = parser.parse_args()
    context = decode(arguments.context.read_bytes())
    case = Case(context, arguments.result)
    failure = None
    try:
        case.flow()
    except Failure as error:
        failure = str(error)
    except (KeyError, TypeError, ValueError, OSError, AttributeError, IndexError) as error:
        # Raw values/paths may be private. Exact CLI output remains in evidence.
        failure = "case dependency/schema failure: " + type(error).__name__
    case.finish(failure)
    print("FAIL: CLAUDOCK-TWO-TURN" if failure else "PASS: CLAUDOCK-TWO-TURN")
    return 1 if failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
