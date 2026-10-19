#!/usr/bin/env python3
"""Outside CLI/capture observer; only names and verdicts go to the terminal."""

import argparse
import base64
from datetime import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tarfile
import threading
import time


_authority_spec = importlib.util.spec_from_file_location(
    "laneboss_human_authority", Path(__file__).resolve().parents[2] / "human_authority.py")
AUTHORITY = importlib.util.module_from_spec(_authority_spec)
_authority_spec.loader.exec_module(AUTHORITY)


ASSERTIONS = ("SECRET-INJECT", "CREDENTIAL-BOUND")
STEPS = (
    "human-session", "key", "stage-env", "import-env", "stage-file", "import-file",
    "stage-hidden", "import-hidden", "start", "reserved", "wider",
    "bad-stage", "stop", "archive", "restart-locked", "recover", "tamper",
    "lease-first", "lease-second", "release-running", "release-quiet",
)
METHODS = {
    "human-session": "human.session",
    "key": "secret.key", "stage-env": "secret.stage",
    "stage-file": "secret.stage", "stage-hidden": "secret.stage",
    "import-env": "secret.import", "import-file": "secret.import",
    "import-hidden": "secret.import", "bad-stage": "secret.import",
    "stop": "lane.stop", "archive": "lane.archive",
    "release-running": "lane.clean", "release-quiet": "lane.clean",
}
DENIALS = {
    "reserved": {"forbidden"},
    "wider": {"forbidden"}, "bad-stage": {"integrity"},
    "restart-locked": {"prerequisite_missing"}, "tamper": {"integrity"},
    "lease-second": {"conflict"},
    "release-running": {"conflict", "containment_unknown"},
}


def check_denial(name, error):
    require(isinstance(error, dict), "negative control has no typed error")
    require(error.get("code") in DENIALS[name],
            "negative control failed before its intended boundary")
    require(error.get("code") != "not_implemented",
            "a missing implementation is not a negative-control pass")
    if name == "reserved":
        require(error.get("message") ==
                "secret target is a reserved or invalid environment name",
                "reserved control lacks the reserved-target diagnostic")


class CaseFailure(Exception):
    """Its message is a fixed diagnostic, never input or captured output."""


def require(condition, message):
    if not condition:
        raise CaseFailure(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def load_json(data):
    return json.loads(data, object_pairs_hook=unique_object)


def beneath(root, name):
    require(isinstance(name, str) and name and not Path(name).is_absolute(),
            "case input must use a relative path")
    parts = Path(name).parts
    require(".." not in parts, "case path escapes its scope")
    path = root.joinpath(*parts)
    current = root
    for part in parts:
        current = current / part
        require(not current.is_symlink(), "case path contains a symlink")
    require(path.resolve().is_relative_to(root.resolve()),
            "case path escapes its scope")
    return path


def read_bounded(path, maximum=1048576):
    require(path.is_file(), "required case input or evidence is missing")
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    require(len(data) <= maximum, "case input or evidence exceeds its bound")
    return data


def wait_file(path):
    # The outside coordinator creates dependent inputs from actual preceding
    # receipts. A bounded test-box wait is never human approval by elapsed time.
    deadline = time.monotonic() + 120
    while not path.is_file():
        require(time.monotonic() < deadline,
                "timed out waiting for an authenticated fixture dependency")
        time.sleep(0.2)
    return path


def digest(data):
    return hashlib.sha256(data).hexdigest()


def evidence_ref(root, path):
    data = read_bounded(path, 268435456)
    return {"path": str(path.relative_to(root)), "sha256": digest(data),
            "bytes": len(data)}


def atomic_json(path, value):
    temporary = path.with_name(path.name + ".pending")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def variants(canaries):
    result = []
    for value in canaries.values():
        result.extend((value, base64.b64encode(value), value.hex().encode("ascii")))
    return result


def no_values(data, hidden):
    return not any(value in data for value in hidden)


def archive_clean(path, hidden):
    total = 0
    entries = 0
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            entries += 1
            require(entries <= 100000, "archive entry count exceeds its bound")
            require(not member.name.startswith("/") and
                    ".." not in Path(member.name).parts,
                    "archive contains an escaping member")
            if member.isfile():
                total += member.size
                require(member.size <= 67108864 and total <= 268435456,
                        "archive expanded size exceeds its bound")
                stream = archive.extractfile(member)
                require(stream is not None, "archive member is unreadable")
                with stream:
                    require(no_values(stream.read(), hidden),
                            "archive contains synthetic secret values")
    require(entries > 0, "archive contains no independently readable entries")


def observed_capture(events, path, observation, prefix):
    capture = read_bounded(path, 16777216)
    expected = observation[prefix + "_capture_sha256"]
    require(digest(capture) == expected, "primary capture digest differs")
    records = []
    for event in events:
        if event.get("kind") != "capture.appended" or event.get("origin") != "service":
            continue
        payload = event.get("payload", {})
        if (payload.get("primary") is True and
                payload.get("target") == {"life_id": observation["life_id"],
                                          "run": observation["run"]} and
                payload.get("stream") == "stdout"):
            records.append(payload)
    require(records, "capture is not correlated with an outside primary record")
    require(all(type(row.get("offset")) is int and row["offset"] >= 0 for row in records),
            "primary capture offset is unknown")
    records.sort(key=lambda row: row["offset"])
    offset, binding = 0, records[0].get("binding_id")
    require(isinstance(binding, str) and binding, "primary capture binding is absent")
    for payload in records:
        ref = payload.get("data", {})
        size = ref.get("bytes")
        require(payload.get("binding_id") == binding and payload.get("offset") == offset and
                type(size) is int and size > 0 and offset + size <= len(capture) and
                digest(capture[offset:offset + size]) == ref.get("sha256"),
                "primary capture is mixed, overlapping or incomplete")
        offset += size
    require(offset == len(capture), "primary capture is mixed, overlapping or incomplete")
    return capture


def correlated_start(events, observation, receipts, context):
    require(observation["binary_sha256"] == context["binary_sha256"],
            "observation belongs to another artifact")
    require(type(observation["run"]) is int and observation["run"] > 0,
            "observation has no exact run")
    operation = observation["operation_id"]
    require(any(receipt.get("id") == operation for receipt in receipts),
            "observation has no actual CLI operation receipt")
    matching = [event for event in events
                if event.get("kind") in {"lane.started", "lane.resumed"}
                and event.get("operation_id") == operation
                and event.get("life_id") == observation["life_id"]
                and event.get("run") == observation["run"]]
    require(len(matching) == 1, "actual launch correlation is missing or ambiguous")
    payload = matching[0]["payload"]
    lane = payload.get("lane", {})
    require(payload.get("task") == lane.get("task") and
            isinstance(lane.get("task"), dict) and
            re.fullmatch(r"[0-9a-f]{64}", lane["task"].get("sha256", "")) is not None,
            "launch did not retain its actual task association")
    require(isinstance(lane.get("launch_id"), str) and lane["launch_id"] and
            lane["launch_id"] == payload.get("launch_id") and
            type(lane.get("cancellation_epoch")) is int and lane["cancellation_epoch"] >= 0 and
            isinstance(lane.get("counters"), dict) and
            set(lane["counters"]) == {"failures", "retries"} and
            all(type(value) is int and value >= 0 for value in lane["counters"].values()) and
            isinstance(lane.get("session", {}).get("history_id"), str) and
            lane["session"]["history_id"],
            "launch lacks draft.4 identity, history or continuation invariants")
    return payload


def flow_process(context, steps, plan_path, result):
    """Run the matched installed executable and publish each actual reply.

    The outside fixture producer can observe human-flow.json while this same
    socket remains open, then supply the next sealed request or genuine proof.
    """
    test_root = Path(context["test_root"])
    evidence_root = Path(context["evidence_root"])
    require(load_json(read_bounded(beneath(test_root, steps[0]["request"]))) == {},
            "human session input must be the exact empty request")
    command = [context["binary"], "human", "session", "--config", context["config"],
               "--binding", context["binding_file"], "--flow", str(plan_path),
               "--proof", str(beneath(test_root, steps[0]["proof"])),
               "--idempotency-key", steps[0]["idempotency_key"]]
    atomic_json(evidence_root / "human-client.argv.json", command)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
    native_stat = (Path("/proc") / str(process.pid) / "stat").read_bytes()
    native_fields = native_stat[native_stat.rfind(b")") + 2:].split()
    require(len(native_fields) > 19, "actual persistent client generation is missing")
    native_hash = digest((Path("/proc") / str(process.pid) / "exe").read_bytes())
    require(native_hash == context["binary_sha256"], "persistent client executes another installed artifact")
    atomic_json(evidence_root / "human-client.native.json", {"pid": process.pid,
        "start_time": native_fields[19].decode(), "executable_sha256": native_hash})
    transcript, waits, problems = [], [], []
    output, errors = bytearray(), bytearray()

    def observe():
        try:
            for line in process.stdout:
                output.extend(line)
                record = load_json(line)
                if "wait" in record:
                    require(record.get("completed") is False and
                            record["wait"].get("code") == "prerequisite_missing",
                            "flow wait is not an incomplete prerequisite")
                    wait = AUTHORITY.OwnerWait(record["step"])
                    path = evidence_root / ("flow-wait-%03d.json" % len(waits))
                    atomic_json(path, dict(wait.record(), name=record["name"]))
                    waits.append(path)
                    continue
                index = len(transcript)
                metadata = record["name"] == "metadata"
                require((metadata and index == 8) or
                        (index < 8 and record["name"] == steps[index]["name"]),
                        "flow response order differs from the retained plan")
                prefix = "human-metadata" if metadata else "human-%d" % index
                refs = {}
                for field in ("request", "response"):
                    path = evidence_root / (prefix + "-" + field + ".json")
                    atomic_json(path, record[field])
                    refs[field] = evidence_ref(evidence_root, path)
                if not metadata:
                    body = read_bounded(beneath(test_root, steps[index]["request"]))
                    transcript.append(dict(name=record["name"], method=record["request"]["method"],
                                           input_sha256=digest(body), **refs))
                    atomic_json(evidence_root / "human-flow.json", transcript)
        except (CaseFailure, OSError, ValueError, KeyError, TypeError, AUTHORITY.OwnerWait) as error:
            problems.append(error)
            process.terminate()

    def observe_errors():
        try:
            errors.extend(process.stderr.read())
        except OSError as error:
            problems.append(error)
            process.terminate()

    readers = [threading.Thread(target=observe), threading.Thread(target=observe_errors)]
    for reader in readers:
        reader.start()
    try:
        code = process.wait(timeout=900)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        code = 124
    finally:
        for reader in readers:
            reader.join(timeout=5)
        process.stdout.close()
        process.stderr.close()
    logs = []
    for suffix, data in (("out", output), ("err", errors)):
        path = beneath(evidence_root, "human-client." + suffix)
        with path.open("xb") as stream:
            stream.write(data)
        os.chmod(path, 0o600)
        logs.append(path)
    atomic_json(evidence_root / "human-client.exit.json", {"exit": code})
    result["assertions"][0].update(observed_exit=code, evidence=[
        evidence_ref(evidence_root, path) for path in (plan_path, *logs, *waits,
            evidence_root / "human-client.argv.json", evidence_root / "human-client.exit.json")])
    require(not problems and all(not reader.is_alive() for reader in readers),
            "installed flow transcript could not be retained")
    return code, bytes(output), bytes(errors)


def human_flow(context, fixture, steps, hidden, result):
    """The installed CLI keeps the real human connection across all stages."""
    test_root = Path(context["test_root"])
    evidence_root = Path(context["evidence_root"])
    planned = []
    for step in steps[1:8]:
        entry = dict(step, request=str(beneath(test_root, step["request"])))
        if step.get("proof"):
            entry["proof"] = str(beneath(test_root, step["proof"]))
        planned.append(entry)
    metadata_input = evidence_root / "metadata-input.json"
    atomic_json(metadata_input, {})
    planned.append({"name": "metadata", "method": "secret.list", "request": str(metadata_input)})
    plan_path = beneath(evidence_root, "human-plan.json")
    atomic_json(plan_path, {"schema": "laneboss.client-flow.v2", "steps": planned})
    code, output, errors = flow_process(context, steps, plan_path, result)
    if not no_values(output + errors, hidden):
        result["assertions"][0]["reached"] = True
    require(no_values(output + errors, hidden),
            "human client diagnostics contain synthetic secret values")
    require(code == 0, "persistent human session flow did not complete")
    flow_path = beneath(evidence_root, "human-flow.json")
    transcript = load_json(read_bounded(flow_path))
    require(isinstance(transcript, list) and len(transcript) == 8 and
            [row["name"] for row in transcript] == list(STEPS[:8]),
            "persistent human flow did not retain every actual response")
    receipts = []
    for step, row in zip(steps[:8], transcript, strict=True):
        body = read_bounded(beneath(test_root, step["request"]))
        require(row["method"] == METHODS[step["name"]] and
                digest(body) == row["input_sha256"] and no_values(body, hidden),
                "human flow differs from the retained exact operation input")
        retained = {}
        for name in ("request", "response"):
            path = beneath(evidence_root, row[name]["path"])
            data = read_bounded(path)
            require(no_values(data, hidden) and digest(data) == row[name]["sha256"] and
                    len(data) == row[name]["bytes"], "human flow evidence hash or secrecy differs")
            retained[name] = load_json(data)
        request, response = retained["request"], retained["response"]
        if step["name"] != "key":
            require(request.get("idempotency_key") == step["idempotency_key"],
                    "human flow replaced the retained mutation key")
        require(request["params"] == load_json(body) and request["config"] == context["config"] and
                request["method"] == row["method"] and
                response.get("protocol") == "laneboss.rpc.v2" and response.get("schema") == 2 and
                response.get("request_id") == request["request_id"] and
                "error" not in response and isinstance(response.get("result"), dict) and
                response["result"], "human flow response is not a successful correlated RPC result")
        receipts.append(response["result"])
    session = receipts[0]
    fields = {"id", "config", "expires_at", "idle_expires_at"}
    require(fields <= set(session) <= fields | {"simulated_presence"} and
            session["config"] == context["config"], "human session response shape differs")
    metadata_files = [beneath(evidence_root, "human-metadata-" + name + ".json")
                      for name in ("request", "response")]
    metadata_raw = [read_bounded(path) for path in metadata_files]
    require(all(no_values(raw, hidden) for raw in metadata_raw),
            "metadata observation contains secret material")
    request, response = map(load_json, metadata_raw)
    require(request.get("method") == "secret.list" and request.get("params") == {} and
            request.get("config") == context["config"] and not request.get("proof") and
            response.get("protocol") == "laneboss.rpc.v2" and response.get("schema") == 2 and
            response.get("request_id") == request.get("request_id") and "error" not in response,
            "metadata observation is not a correlated same-session read")
    infos = response.get("result", {}).get("secrets")
    require(isinstance(infos, list) and all(isinstance(info, dict) and
            set(info) == {"name", "version", "source_handle", "key_id", "revoked"} for info in infos),
            "metadata observation has an invalid names-only field map")
    imported = [receipt for step, receipt in zip(steps[:8], receipts, strict=True)
                if step["method"] == "secret.import"]
    require(all(info in infos for info in imported) and
            len({info["source_handle"] for info in infos}) == len(infos),
            "metadata observation omitted imported sources or repeated a source")
    result["assertions"][0]["evidence"].extend(evidence_ref(evidence_root, path) for path in metadata_files)
    return receipts, transcript


def helper_release(events, target, ended):
    found = []
    for event in events:
        if event.get("kind") != "helper.released" or event.get("origin") != "service":
            continue
        payload = event.get("payload", {})
        measured = payload.get("quiescence", {})
        handle = measured.get("handle", {})
        if handle.get("target") != target:
            continue
        fields = {"id", "lease_id", "containment_id", "backend", "operation_id", "effect_id",
                  "quiescence", "live_connections", "queued_jobs", "writable_exports", "observed_at"}
        require(set(payload) == fields and isinstance(payload["observed_at"], str) and
                re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z",
                             payload["observed_at"]) is not None,
                "helper release payload differs from the draft.4 field map")
        datetime.fromisoformat(payload["observed_at"].replace("Z", "+00:00"))
        require(payload.get("backend") == "linux-bwrap-landlock" and
                payload.get("containment_id") == handle.get("containment_id") and
                payload.get("operation_id") == event.get("operation_id") and
                all(isinstance(payload.get(name), str) and
                    re.fullmatch(r"[A-Za-z0-9_-]{1,128}", payload[name]) is not None
                    for name in ("id", "lease_id", "containment_id", "operation_id", "effect_id")),
                "helper release receipt lost its actual containment or causal binding")
        require(measured.get("state") == "exited" and
                type(measured.get("survivors")) is int and measured["survivors"] == 0 and
                any(row.get("handle") == handle for row in ended) and
                all(type(payload.get(name)) is int and payload[name] == 0
                    for name in ("live_connections", "queued_jobs", "writable_exports")),
                "helper release lacks known measured zero process and resource counts")
        require(any(row.get("kind") == "helper.allocated" and row.get("origin") == "service" and
                    row.get("payload", {}).get("id") == payload["lease_id"] and
                    row.get("payload", {}).get("containment_id") == payload["containment_id"]
                    for row in events), "helper release has no matching allocated lease")
        found.append(payload)
    require(found, "cleanup has no helper-measured draft.4 release receipt")


def collection_clean(receipt, test_root):
    require(receipt.get("state") == "exited" and
            type(receipt.get("survivors")) is int and receipt["survivors"] == 0,
            "cleanup lacks a truthful zero-survivor observation")
    processes = receipt.get("processes")
    resources = receipt.get("removed_paths")
    require(isinstance(processes, list) and processes and
            isinstance(resources, list) and resources,
            "cleanup has no independent process and resource inventory")
    for process in processes:
        pid, generation = process.get("pid"), process.get("start_time")
        require(type(pid) is int and pid > 1 and isinstance(generation, str),
                "cleanup process identity is incomplete")
        path = Path("/proc") / str(pid) / "stat"
        try:
            current = path.read_text(encoding="ascii")
        except FileNotFoundError:
            continue  # The observed PID no longer exists: an actual OS result.
        fields = current[current.rfind(")") + 2:].split()
        require(len(fields) > 19 and fields[19] != generation,
                "an owned process generation survived cleanup")
    for name in resources:
        require(not beneath(test_root, name).exists(),
                "a credential or runtime resource survived cleanup")


def execute_steps(context, steps, hidden, active, receipts, transcript, begin, end):
    test_root, evidence_root = Path(context["test_root"]), Path(context["evidence_root"])
    binary, profiles = Path(context["binary"]), context["profile_grant_ids"]
    for index, step in enumerate(steps[begin:end], start=begin):
        name = step["name"]
        method = METHODS.get(name, "lane.start")
        require(step["method"] == method, "case attempted an unrelated CLI method")
        atomic_json(evidence_root / "next-step.json", {"index": index, "name": name, "method": method})
        request = wait_file(beneath(test_root, step["request"]))
        request_data = read_bounded(request)
        require(no_values(request_data, hidden), "plaintext canary entered a request")
        if method == "lane.start":
            body = load_json(request_data)
            require(body.get("profile_grant_id") in profiles and
                    body.get("driver") in {"claudock-cli", "codex"},
                    "lane request selected a profile or driver outside this live cell")
        command = [str(binary), *method.split("."), "--config", context["config"],
                   "--binding-file", context["binding_file"], "--request", str(request),
                   "--idempotency-key", step["idempotency_key"]]
        if step.get("proof"):
            proof = wait_file(beneath(test_root, step["proof"]))
            command.extend(("--session-proof" if method == "lane.start" else "--proof", str(proof)))
        process = subprocess.run(command, capture_output=True, timeout=120,
                                 env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                                 check=False)
        stem = "cli-" + str(index)
        for suffix, data in (("out", process.stdout), ("err", process.stderr)):
            path = beneath(evidence_root, stem + "." + suffix)
            with path.open("xb") as stream:
                stream.write(data)
            os.chmod(path, 0o600)
        transcript.append({"step": name, "method": method,
                           "request_sha256": digest(request_data),
                           "exit": process.returncode,
                           "stdout_sha256": digest(process.stdout),
                           "stderr_sha256": digest(process.stderr)})
        atomic_json(beneath(evidence_root, "cli-transcript.json"), transcript)
        active["observed_exit"] = process.returncode
        active["evidence"] = [evidence_ref(evidence_root, path) for path in
                              (beneath(evidence_root, "cli-transcript.json"),
                               beneath(evidence_root, stem + ".out"),
                               beneath(evidence_root, stem + ".err"))]
        if not no_values(process.stdout + process.stderr, hidden):
            active["reached"] = True
        require(no_values(process.stdout + process.stderr, hidden),
                "CLI output contains synthetic secret values")
        if name in DENIALS:
            if process.returncode == 0:
                # Retain the actual unexpected success receipt. The independent
                # runner also checks operation/state evidence for a killed red.
                active["reached"] = True
            require(process.returncode != 0, "a negative operation control succeeded")
            error = load_json(process.stderr)
            check_denial(name, error)
        else:
            require(process.returncode == 0, "required CLI operation did not complete")
            receipt = load_json(process.stdout)
            require(isinstance(receipt, dict) and receipt,
                    "successful CLI operation has no receipt")
            require(receipt.get("status") not in {"failed", "cancelled"},
                    "CLI returned a failed asynchronous operation")
            receipts.append(receipt)


def load_observation(context, fixture, prefix, receipts, active, hidden):
    evidence_root = Path(context["evidence_root"])
    observed = fixture["observations"]
    events_path = wait_file(beneath(evidence_root, observed["events"]))
    event_bytes = read_bounded(events_path, 67108864)
    events = [load_json(line) for line in event_bytes.splitlines() if line.strip()]
    observation_path = wait_file(beneath(evidence_root, observed[prefix]))
    observation = load_json(read_bounded(observation_path))
    capture_path = wait_file(beneath(evidence_root, observed[prefix + "_capture"]))
    capture = observed_capture(events, capture_path, observation, prefix)
    payload = correlated_start(events, observation, receipts, context)
    # The actual launch and primary capture exist. Boundary failures below are
    # reached red evidence, including value leaks and ungranted-profile use.
    active["reached"] = True
    active["evidence"] = [evidence_ref(evidence_root, path) for path in
                          (events_path, observation_path, capture_path)]
    require(no_values(event_bytes, hidden), "events contain synthetic secret values")
    require(no_values(capture, hidden), "primary capture disclosed synthetic values")
    require(events and all(event.get("schema") == 2 for event in events),
            "actual schema-v2 event evidence is missing")
    return events, observation, payload, capture


def reserved_capture(injection, capture):
    verdicts = [load_json(line) for line in capture.splitlines() if line.strip()]
    require({row.get("name") for row in verdicts} == {"env", "file", "undelegated", "reserved"}
            and len(verdicts) == 4 and all(set(row) == {"name", "ok"} for row in verdicts),
            "canary capture is not names-only structured output")
    require(all(row["ok"] is True for row in verdicts), "actual injection canary comparison failed")
    require(injection.get("reserved_unchanged") ==
            next(row["ok"] for row in verdicts if row["name"] == "reserved"),
            "reserved observation differs from the actual probe capture")


def evaluate_injection(context, fixture, receipts, active, hidden):
    _, injection, payload, capture = load_observation(
        context, fixture, "injection", receipts, active, hidden)
    require(payload.get("secret_grant_ids") == injection.get("grant_ids")
            and len(injection.get("grant_ids", [])) == 2,
            "injection grant correlation differs from the actual start")
    reserved_capture(injection, capture)
    for name in ("env_equal", "file_equal", "undelegated_absent", "reserved_unchanged",
                 "wider_not_launched", "event_values_absent", "archive_values_absent",
                 "locked_restart_refused", "recovery_equal", "tamper_refused", "quiescent"):
        require(injection.get(name) is True, "independent secret boundary observation failed")
    evidence_root = Path(context["evidence_root"])
    archive_path = wait_file(beneath(evidence_root, fixture["observations"]["archive"]))
    archive_clean(archive_path, hidden)
    active["evidence"].append(evidence_ref(evidence_root, archive_path))
    active.update(verdict="pass", observed_exit=0)


def evaluate_credential(context, fixture, receipts, active, hidden):
    events, credential, payload, _ = load_observation(
        context, fixture, "credential", receipts, active, hidden)
    require(credential.get("profile_grant_id") in context["profile_grant_ids"] and
            payload.get("lane", {}).get("profile_grant_id") ==
            credential.get("profile_grant_id"), "credential turn used an ungranted profile")
    require(any(event.get("kind") == "credential.leased" and
                event.get("life_id") == credential["life_id"] and
                event.get("run") == credential["run"] and
                event.get("payload", {}).get("slot", {}).get("profile_id") ==
                credential.get("selected_profile_id") and
                event.get("payload", {}).get("slot", {}).get("profile_grant_id") ==
                credential.get("profile_grant_id") for event in events),
            "credential turn has no correlated selected-profile lease")
    for name in ("own_profile_turn", "other_profile_absent", "other_history_absent",
                 "registry_absent", "keyring_fallback_absent", "single_refresh_owner",
                 "running_release_refused", "quiet_release_removed", "quiescent"):
        require(credential.get(name) is True, "independent credential boundary observation failed")
    active.update(verdict="pass", observed_exit=0)


CASE_ERRORS = (CaseFailure, OSError, ValueError, KeyError, TypeError, AttributeError,
               subprocess.SubprocessError, tarfile.TarError, sqlite3.Error)


def independent_assertions(result, actions):
    require(len(actions) == len(result["assertions"]), "assertion action count differs")
    failed = False
    for active, action in zip(result["assertions"], actions, strict=True):
        try:
            action(active)
        except CASE_ERRORS as error:
            failed = True
            active["verdict"] = "fail"
    return not failed


def evaluate_collection(context, fixture, result):
    test_root, evidence_root = Path(context["test_root"]), Path(context["evidence_root"])
    observed = fixture["observations"]
    event_bytes = read_bounded(wait_file(beneath(evidence_root, observed["events"])), 67108864)
    events = [load_json(line) for line in event_bytes.splitlines() if line.strip()]
    injection = load_json(read_bounded(wait_file(beneath(evidence_root, observed["injection"]))))
    credential = load_json(read_bounded(wait_file(beneath(evidence_root, observed["credential"]))))
    collection_path = wait_file(beneath(evidence_root, observed["collection"]))
    collection = load_json(read_bounded(collection_path))
    for observation in (injection, credential):
        target = {"life_id": observation["life_id"], "run": observation["run"]}
        ended = []
        for event in events:
            if event.get("kind") == "run.observed":
                process = event.get("payload", {})
            elif event.get("kind") == "lane.ended":
                process = event.get("payload", {}).get("observation", {})
            else:
                continue
            if (process.get("handle", {}).get("target") == target and
                    process.get("state") == "exited" and
                    type(process.get("survivors")) is int and
                    process["survivors"] == 0):
                ended.append(process)
        require(ended, "cleanup has no correlated quiescence event")
        helper_release(events, target, ended)
    collection_clean(collection, test_root)
    result["collection"] = {"processes_quiescent": True,
                            "temporary_resources_collected": True,
                            "evidence": [evidence_ref(evidence_root, collection_path)]}


def run_case(context, result, diagnostics=None):
    test_root = Path(context["test_root"])
    evidence_root = Path(context["evidence_root"])
    require(sys.platform == "linux", "secrets acceptance requires disposable Linux")
    require(context["schema"] == "laneboss.e2e-context.v2" and
            context["case_id"] == "secrets", "wrong case context")
    require(context["phase"] in {"red", "candidate"}, "invalid case phase")
    for name in ("binary_sha256", "source_sha256"):
        require(re.fullmatch(r"[0-9a-f]{64}", context[name]) is not None,
                "artifact digest is invalid")
    profiles = context["profile_grant_ids"]
    if isinstance(profiles, list) and not profiles:
        wait = AUTHORITY.OwnerWait("vendor_authentication")
        path = beneath(evidence_root, "vendor-authentication.wait.json")
        atomic_json(path, wait.record())
        result["assertions"][1]["evidence"].append(evidence_ref(evidence_root, path))
        raise wait
    require(isinstance(profiles, list) and profiles and
            all(isinstance(value, str) and
                re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value) is not None
                for value in profiles),
            "live credential case requires explicitly authorized profile grants")
    binary = Path(context["binary"])
    require(digest(read_bounded(binary, 268435456)) == context["binary_sha256"],
            "installed binary differs from the context")
    require(test_root.is_absolute() and evidence_root.is_absolute() and
            test_root.is_dir() and evidence_root.is_dir(), "case scopes are absent")
    binding = load_json(read_bounded(Path(context["binding_file"])))
    require(binding.get("schema") == "laneboss.binding.v2" and
            binding.get("contract_revision") == "v2.0-draft.4" and
            binding.get("protocol") == "laneboss.rpc.v2" and binding.get("api_schema") == 2 and
            binding.get("config") == context["config"] and binding.get("class") == "human" and
            binding.get("artifact_sha256") == context["binary_sha256"],
            "case requires the matched draft.4 installed human binding")
    fixture_path = beneath(test_root, "secrets-fixture.json")
    if not fixture_path.is_file():
        wait = AUTHORITY.OwnerWait("fixture_preparation")
        path = beneath(evidence_root, "fixture-preparation.wait.json")
        atomic_json(path, wait.record())
        result["assertions"][0]["evidence"].append(evidence_ref(evidence_root, path))
        raise wait
    require(fixture_path.stat().st_mode & 0o077 == 0,
            "case fixture must be private")
    fixture = load_json(read_bounded(fixture_path))
    require(fixture.get("schema") == "laneboss.e2e-secrets.v2",
            "case fixture schema differs")
    if (evidence_root / "execution.json").exists():
        installed_spec = importlib.util.spec_from_file_location("secrets_installed_verify", Path(__file__).with_name("installed.py"))
        installed_case = importlib.util.module_from_spec(installed_spec)
        installed_spec.loader.exec_module(installed_case)
        installed_case.verify(context, fixture, result, diagnostics=diagnostics)
        return
    canaries = {name: read_bounded(beneath(test_root, fixture["canary_files"][name]), 65536)
                for name in ("env", "file", "undelegated")}
    require(all(len(value) >= 32 for value in canaries.values()) and
            len(set(canaries.values())) == 3, "synthetic canary controls are invalid")
    hidden = variants(canaries)
    steps = fixture["steps"]
    require([step["name"] for step in steps] == list(STEPS),
            "required secret operation controls are missing")
    for step in steps:
        if step["name"] != "key":
            require(isinstance(step.get("idempotency_key"), str) and
                    re.fullmatch(r"[A-Za-z0-9_-]{22,128}", step["idempotency_key"]) is not None,
                    "mutation fixture must retain its exact retry key before execution")
    receipts, transcript = [], []

    def secret_action(active):
        flow_receipts, flow_transcript = human_flow(context, fixture, steps, hidden, result)
        receipts.extend(flow_receipts)
        transcript.extend(flow_transcript)
        atomic_json(beneath(evidence_root, "cli-transcript.json"), transcript)
        execute_steps(context, steps, hidden, active, receipts, transcript, 8, 17)
        evaluate_injection(context, fixture, receipts, active, hidden)

    def credential_action(active):
        execute_steps(context, steps, hidden, active, receipts, transcript, 17, 21)
        evaluate_credential(context, fixture, receipts, active, hidden)

    # These groups share installed prerequisites, not each other's verdict.
    passed = independent_assertions(result, (secret_action, credential_action))
    evaluate_collection(context, fixture, result)
    require(passed, "one or more secret assertions failed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    # Keep a failed result even when a service/fixture prerequisite is absent.
    context = load_json(read_bounded(args.context))
    result = {"schema": "laneboss.e2e-result.v2", "case_id": "secrets",
              "phase": context["phase"], "mutation_id": context["mutation_id"],
              "binary_sha256": context["binary_sha256"],
              "source_sha256": context["source_sha256"],
              "assertions": [{"id": name, "reached": False, "verdict": "fail",
                              "observed_exit": 1, "evidence": []} for name in ASSERTIONS],
              "collection": {"processes_quiescent": False,
                             "temporary_resources_collected": False, "evidence": []}}
    exit_code = 1
    try:
        run_case(context, result)
        exit_code = 0
    except (CaseFailure, OSError, ValueError, KeyError, TypeError, AttributeError, AUTHORITY.OwnerWait,
            subprocess.SubprocessError, tarfile.TarError):
        # Raw command output remains protected in evidence. Never format an
        # exception containing a path, request, key, environment or vendor data.
        print("secrets: fail (retain case evidence; verify dependencies)", file=sys.stderr)
    finally:
        atomic_json(args.result, result)
    if exit_code == 0:
        print("secrets: pass")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
