"""Installed L5 lifecycle scope. Every observation comes from the real CLI."""

import base64
import hashlib
import json
import math
from pathlib import Path
import re
import time
import uuid


DRIVERS = (("claudock", "claudock-cli"), ("codex", "codex"))
REPLY_READ_SECONDS = 90
REPLY_COMMAND_SECONDS = 10
REAL_TURN_PROOF = "a real model turn completed and was billed"
FAKE_TURN_PROOF = "Claude Code reached the vendor with the fake key"
AGENT_NOT_STARTED = "the agent never started"
LIFECYCLE_ONLY = "lifecycle only; does not prove the agent ran"
LIFECYCLE_STEPS = ("inputs", "start", "reason", "stop", "quiescent", "abandon", "archive", "clean", "collected")
PUBLIC_RESULT_FIELDS = "is_error/subtype: not on the public path (api/spend.go:6-14, :44)"
CAPTURE_NOT_VISIBLE = "capture blob not visible to the human scope (capture_drain.go:174)"
# Only these structured classes may enter diagnostics. Never retain error text,
# headers, or an unknown vendor-supplied class as a diagnostic label.
ERROR_CLASSES = {
    "authentication_failed": "authentication_error", "authentication_error": "authentication_error",
    "invalid_api_key": "authentication_error", "token_expired": "authentication_error",
    "network_error": "network_error", "connection_error": "network_error",
    "api_connection_error": "network_error", "timeout_error": "timeout_error",
    "api_timeout_error": "timeout_error", "rate_limit": "rate_limit_error",
    "rate_limit_error": "rate_limit_error", "billing_error": "billing_error",
    "permission_error": "permission_error", "server_error": "server_error",
    "error_max_turns": "turn_limit", "error_max_budget_usd": "budget_limit",
}
# Keep base64 plus the BlobChunk/RPC envelope far below MaxFrameBytes
# (1 MiB); also below the public MaxChunkBytes limit (256 KiB).
REPLY_READ_BYTES = 32 * 1024
REPLY_TASK = (b"# Installed README task\n\n"
              b"Read README.md and report its first heading in one short reply.\n"
              b"Do not modify files.\n")


class CaptureNotVisible(Exception):
    """The public blob.read returned the specifically authorized not_found."""

STATE_CHECKS = (
    "platform", "source", "build", "fixture.build", "authenticator.build", "root.stage", "boot.inputs", "namespace.install",
    "namespace.check", "admin.install", "admin.check", "installation",
    "fixture.enrollment", "serve", "health", "authenticator.create", "human.enroll.begin",
    "human.enroll.attestation", "human.enroll.complete", "human.enrollment",
    "admin.publish", "admin.publish.retry", "admin.publication",
    "human.session.challenge", "human.session.confirm", "human.session",
    "human.grants.challenge", "human.grants.confirm", "human.grants",
    "human.ticket.challenge", "human.ticket.confirm", "human.ticket",
    "human.read.challenge", "human.read.confirm", "human.check.challenge", "human.check.confirm",
    "state.launch", "state.plan", "state.capture", "state.collect", "state.authorized", "state.append",
    "state.read", "state.drop-reply", "state.restart", "state.retry", "state.receipt-count", "state.event-count",
    "state.effect-count", "state.changed-bytes", "state.exact-retry", "unready.owner", "direct-open", "uid.direct-open", "cleanup",
)


def check_name(name, step, fake=False):
    if fake and name == "claudock" and step in LIFECYCLE_STEPS:
        return "lane.%s.lifecycle.%s" % (name, step)
    return "lane.%s.%s" % (name, step)


def checks(base=STATE_CHECKS, reply=False, fake=False):
    common = list(base[:base.index("human.session.challenge")])
    common += ["human.session.challenge", "human.session.confirm", "human.session",
               "human.read.challenge", "human.read.confirm", "uid.direct-open"]
    for name, _ in DRIVERS:
        for operation in ("session", "grants", "ticket", "read", "control"):
            common += ["human.%s.%s.%s" % (name, operation, suffix) for suffix in ("challenge", "confirm")]
        common += ["human.%s.%s" % (name, operation) for operation in ("session", "grants", "ticket")]
        # Both drivers read captures, including when no API-key probe is used.
        # Declare the row before any read can record its RPC observation.
        common += [check_name(name, step, fake) for step in (
            "inputs", "start", "running", "events", "reason", "stop", "quiescent", "reply", "abandon", "archive", "clean", "collected")]
    return tuple(dict.fromkeys([*common, "cleanup"]))


def row(case, name, step):
    case.current = check_name(name, step, getattr(case, "reply_mode", None) == "fake-key")


def vendor_error_class(event, message_class=None):
    """Classify structured status/codes; free-form messages stay private."""
    if event.get("is_error") is False:
        return "none"
    status = event.get("api_error_status")
    if type(status) is int and status >= 400:
        if status == 401:
            return "authentication_error"
        return {403: "permission_error", 429: "rate_limit_error"}.get(
            status, "server_error" if status >= 500 else "http_error")
    error = event.get("error")
    codes = [event.get("subtype")]
    codes += [error.get("code"), error.get("type")] if isinstance(error, dict) else [error]
    for code in codes:
        if isinstance(code, str) and code in ERROR_CLASSES:
            return ERROR_CLASSES[code]
    return message_class if message_class in ERROR_CLASSES.values() else "vendor_error"


def project_heading():
    """Read the heading from the same source used by the fixture publication."""
    source = Path(__file__).with_name("fixtures") / "README.md"
    for line in source.read_text().splitlines():
        match = re.match(r"^#{1,6}\s+(.+)", line)
        if match:
            heading = match[1].strip().rstrip("#").strip()
            if heading:
                return heading
    raise ValueError("fixture README has no heading")


def result_summary(event, session, require, message_class=None):
    """Allow-list vendor metadata; reply/error text never leaves memory."""
    require(event.get("type") == "result" and event.get("session_id") == session and
            isinstance(event.get("uuid"), str) and bool(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", event["uuid"])),
            "vendor result differs from the sealed session or lacks its identity")
    require(type(event.get("is_error")) is bool and isinstance(event.get("subtype"), str) and
            bool(re.fullmatch(r"[a-z][a-z0-9_]{0,63}", event["subtype"])),
            "vendor result lacks a typed disposition")
    for field in ("num_turns", "duration_ms"):
        require(type(event.get(field)) is int and 0 <= event[field] <= 2**53 - 1,
                "vendor result has an invalid count or duration")
    status = event.get("api_error_status")
    require(status is None or type(status) is int and 100 <= status <= 599,
            "vendor result has an invalid API status")
    cost = event.get("total_cost_usd")
    require(type(cost) in (int, float) and 0 <= cost <= (2**53 - 1) / 1000000 and math.isfinite(cost),
            "vendor result has an invalid reported cost")
    text = event.get("result")
    require(isinstance(text, str) or (text is None and event["is_error"] is True),
            "vendor result has an invalid result text")
    return {field: event[field] for field in (
        "type", "subtype", "is_error", "num_turns", "total_cost_usd", "duration_ms")} | {
        "api_error_status": status, "error_class": vendor_error_class(event, message_class),
        "readme_heading_verified": isinstance(text, str) and project_heading() in text,
        "result_text_present": isinstance(text, str) and bool(text),
        "result_sha256": hashlib.sha256(text.encode()).hexdigest() if isinstance(text, str) else None}


def reply_passed(observed, mode):
    """Real keys prove a billed turn; fake keys still need a vendor result."""
    if mode == "fake-key":
        return fake_reply_passed(observed)
    records = observed.get("spend", {}).get("records", [])
    process = observed.get("diagnostics", {}).get("process", {})
    return (mode == "real-key" and observed.get("mode") == mode and reply_windows_valid(observed) and
        terminal_process(process) and process.get("exit_code") == 0 and process.get("signal") is None and
        observed.get("diagnostics", {}).get("end_reason") == "exit" and
        observed.get("diagnostics", {}).get("snapshot_complete") is True and
        len(records) == 1 and records[0].get("sealed_session") is True and
        all(isinstance(records[0].get(field), str) and bool(records[0][field])
            for field in ("session_id", "result_id", "capture_id")) and
        all(type(records[0].get(field)) is int and records[0][field] >= 0 for field in (
            "cost_micros", "input_tokens", "output_tokens", "cache_read_tokens", "cache_creation_tokens")) and
        records[0]["cost_micros"] > 0 and records[0]["output_tokens"] > 0 and
        observed.get("result_present") is True and observed.get("is_error") is False and
        observed.get("readme_heading_verified") is True and vendor_result_proven(dict(observed, spend={})) and
        not any(item.get("is_error") is True for item in observed.get("public_is_error", [])))


def terminal_process(process):
    code, signal = process.get("exit_code"), process.get("signal")
    return (process.get("state") == "exited" and process.get("exited") is True and
        type(process.get("survivors")) is int and process["survivors"] == 0 and
        (type(code) is int and 0 <= code <= 2**31 - 1 and signal is None or
         type(signal) is int and 0 < signal <= 2**31 - 1 and code is None))


def reply_windows_valid(observed):
    windows, diagnostics = observed.get("windows", {}), observed.get("diagnostics", {})
    expected = {"read_seconds": REPLY_READ_SECONDS, "command_seconds": REPLY_COMMAND_SECONDS,
                "total_seconds": REPLY_READ_SECONDS}
    return (all(type(windows.get(field)) is int and windows[field] == value and value > 0
                for field, value in expected.items()) and
        observed.get("deadline_seconds") == windows["total_seconds"] and
        diagnostics.get("phase") == "read" and
        diagnostics.get("read_window_ms") == windows["read_seconds"] * 1000 and
        type(diagnostics.get("read_elapsed_ms")) is int and 0 <= diagnostics["read_elapsed_ms"] < windows["read_seconds"] * 1000)


def fake_reply_passed(observed):
    """Require the sealed result's auth refusal, never spend or exit alone."""
    return (observed.get("mode") == "fake-key" and reply_windows_valid(observed) and
            terminal_process(observed.get("diagnostics", {}).get("process", {})) and
            observed.get("diagnostics", {}).get("snapshot_complete") is True and
            observed.get("result_present") is True and observed.get("is_error") is True and
            observed.get("error_class") == "authentication_error" and
            observed.get("api_error_status") in (None, 401) and
            vendor_result_proven(dict(observed, spend={})))


def vendor_result_proven(observed):
    """Use only typed, scoped public spend or a validated capture result."""
    if not isinstance(observed, dict):
        return False
    session = observed.get("sealed_session")
    if not isinstance(session, str) or not session:
        return False
    ledger = observed.get("spend", {})
    if not isinstance(ledger, dict) or not isinstance(ledger.get("records", []), list):
        return False
    records = ledger.get("records", [])
    fields = ("cost_micros", "input_tokens", "output_tokens", "cache_read_tokens", "cache_creation_tokens")
    spend = (len(records) == 1 and isinstance(records[0], dict) and
        records[0].get("session_id") == session and records[0].get("sealed_session") is True and
        all(isinstance(records[0].get(field), str) and bool(records[0][field])
            for field in ("result_id", "capture_id")) and
        all(type(records[0].get(field)) is int and 0 <= records[0][field] <= 2**53 - 1 for field in fields))
    capture = observed.get("capture_result", {})
    return spend or (observed.get("result_present") is True and isinstance(capture, dict) and capture.get("session_id") == session and
        capture.get("sealed_session") is True and capture.get("source") == "capture.result" and
        isinstance(capture.get("result_id"), str) and bool(capture["result_id"]))


def vendor_proof(observed):
    return {name: observed[name] for name in ("sealed_session", "spend", "result_present", "capture_result")
            if name in observed}


def fake_row_passed(name, observed):
    if name == "lane.claudock.reply":
        return fake_reply_passed(observed)
    if name in ("lane.claudock.running", "lane.claudock.events"):
        return vendor_result_proven(observed.get("vendor_proof", {}))
    if name.startswith("lane.claudock.lifecycle."):
        return name.rsplit(".", 1)[-1] in LIFECYCLE_STEPS and observed.get("purpose") == LIFECYCLE_ONLY
    if name.startswith("lane.claudock."):
        return False
    if name == "cleanup":
        proofs = observed.get("api_key_canary", {}).get("vendor_proofs", [])
        return isinstance(proofs, list) and len(proofs) == 1 and all(vendor_result_proven(proof) for proof in proofs)
    return True


def reply(case, record, lane, retained_events, require):
    with case.reply_scope():
        return reply_run(case, record, lane, retained_events, require)


def reply_run(case, record, lane, retained_events, require):
    """Read the owner's vendor result after the measured quiescent row."""
    row(case, record["name"], "reply")
    started = time.monotonic()
    read_started = started
    deadline = read_started + REPLY_READ_SECONDS
    mode = "real-key" if case.real_api_key else "fake-key"
    diagnostics = {"capture_records": 0, "streams": [], "event_kinds": [],
        "lane_state": None, "process": {"state": None, "exited": False, "exit_code": None,
        "signal": None, "survivors": None}, "snapshot_complete": False, "deadline_hit": False, "elapsed_ms": 0,
        "phase": "read", "read_elapsed_ms": 0, "read_window_ms": round((deadline - read_started) * 1000),
        "end_reason": None, "process_source": "lane.quiescent"}
    observed = {"executed": True, "mode": mode, "deadline_seconds": REPLY_READ_SECONDS,
        "windows": {"read_seconds": REPLY_READ_SECONDS, "command_seconds": REPLY_COMMAND_SECONDS,
                    "total_seconds": REPLY_READ_SECONDS},
        "result_present": False, "diagnostics": diagnostics, "public_result_fields": PUBLIC_RESULT_FIELDS,
        "public_is_error": [], "capture_read": {"status": "pending"},
        "spend": {"supported": True, "source": "lane.status.credential_spend; event.tail spend.recorded",
                  "reported": False, "spent_micros": None,
                  "accounting_error": False, "records": []}}
    case.rows[case.current]["observed"] = observed
    native = record.get("quiescent_observation", {})
    require(record.get("quiescent") is True and isinstance(native, dict),
            "reply requires a prior measured quiescent observation")
    handle = native.get("handle", {})
    require(isinstance(handle, dict) and handle == record.get("handle") and
            handle.get("target") == record["target"] and native.get("observed_at"),
            "reply quiescent observation differs from its measured run")
    diagnostics["process"] = {"state": native.get("state"), "exited": native.get("state") == "exited",
        **{field: native.get(field) for field in ("exit_code", "signal", "survivors")}}
    require(terminal_process(diagnostics["process"]), "reply requires a terminal zero-survivor observation")
    bindings = [event["payload"] for event in retained_events
                if event.get("kind") == "capture.bound" and event.get("origin") == "service" and
                event.get("config") == case.config and event.get("life_id") == record["target"]["life_id"] and
                event.get("run") == record["target"]["run"]]
    require(len(bindings) == 1 and bindings[0].get("target") == record["target"] and
            bindings[0].get("launch_id") == lane["launch_id"] and bindings[0].get("status") == "registered",
            "reply lacks its registered primary capture binding")
    binding = bindings[0]["id"]
    stream_names = {stream["id"]: stream["stream"] for stream in bindings[0].get("streams", [])}
    session = lane.get("session", {}).get("vendor_id")
    require(isinstance(session, str) and bool(session), "reply lacks a sealed vendor session")
    observed["sealed_session"] = session
    seen, inventory, stream_state, kinds, event_cursor = {}, {}, {}, set(), ""
    spend_records, blob_unavailable = {}, False

    def public_error(value, source):
        if "is_error" in value:
            require(type(value["is_error"]) is bool, "public is_error is untyped")
            item = {"source": source, "is_error": value["is_error"]}
            if item not in observed["public_is_error"]:
                observed["public_is_error"].append(item)
            require(mode != "real-key" or value["is_error"] is False,
                    "public vendor result reports is_error true (" +
                    observed.get("error_class", vendor_error_class(value)) + ")")

    def stream(name):
        require(name in ("stdout", "stderr", "vendor", "structured"), "reply capture has an unknown stream")
        if name not in stream_state:
            stats = {"stream": name, "records": 0, "bytes": 0, "read_records": 0, "read_bytes": 0,
                "read_pages": 0, "max_read_page_bytes": 0,
                "closed": False, "closed_bytes": None, "result_events": 0, "non_json_lines": 0, "pending_line_bytes": 0}
            stream_state[name] = {"stats": stats, "offset": 0, "tail": b"", "error_classes": set()}
            diagnostics["streams"].append(stats)
            diagnostics["streams"].sort(key=lambda item: item["stream"])
        return stream_state[name]

    def update_clock():
        diagnostics["elapsed_ms"] = max(0, int((time.monotonic() - started) * 1000))
        diagnostics["deadline_hit"] = time.monotonic() >= deadline
        diagnostics["read_elapsed_ms"] = max(0, int((time.monotonic() - read_started) * 1000))

    def within_deadline():
        update_clock()
        if diagnostics["deadline_hit"] and mode == "fake-key" and not observed["result_present"]:
            observed["error"] = ("authentication refusal result is unavailable" if vendor_result_proven(observed)
                                 else AGENT_NOT_STARTED)
            require(False, observed["error"])
        require(not diagnostics["deadline_hit"], "vendor result " + diagnostics["phase"] + " window deadline")

    def read(label, words, request):
        within_deadline()
        try:
            value = case.capture_read(label, words, request, deadline)
        finally:
            update_clock()
        within_deadline()
        return value

    def document(raw, state):
        def unique(pairs):
            result = {}
            for key, value in pairs:
                require(key not in result, "vendor record repeats a field")
                result[key] = value
            return result
        try:
            value = json.loads(raw, object_pairs_hook=unique)
        except (ValueError, UnicodeError):
            state["stats"]["non_json_lines"] += 1
            return None
        if not isinstance(value, dict) or not isinstance(value.get("type"), str):
            state["stats"]["non_json_lines"] += 1
            return None
        return value

    def consume(name, state):
        stats = state["stats"]
        if stats["closed"] and stats["closed_bytes"] == state["offset"] and state["tail"] and not state["tail"].endswith(b"\n"):
            state["tail"] += b"\n"
        while b"\n" in state["tail"]:
            line, state["tail"] = state["tail"].split(b"\n", 1)
            require(len(line) <= 1024 * 1024, "vendor result record exceeds its bound")
            if not line.strip():
                continue
            event = document(line, state)
            if event is None:
                continue
            if event["type"] == "result":
                stats["result_events"] += 1
            if name == "stderr":
                continue
            require("session_id" not in event or event["session_id"] == session,
                    "vendor record differs from the sealed session")
            # Claude's assistant.error and error.code/type are structured
            # classes, as in the Claudock auth-refusal case. Quoted text and
            # unscoped messages cannot supply authentication evidence.
            if event["type"] in ("assistant", "error") and event.get("session_id") == session and "error" in event:
                state["error_classes"].add(vendor_error_class(event))
            if event["type"] != "result" or observed["result_present"]:
                continue
            message_class = next(iter(state["error_classes"])) if len(state["error_classes"]) == 1 else None
            observed.update(result_summary(event, session, require, message_class), result_present=True)
            observed["capture_result"] = {"session_id": event["session_id"], "result_id": event["uuid"],
                "sealed_session": event["session_id"] == session, "source": "capture.result"}
            public_error(event, "capture.result")
            if mode == "real-key":
                require(observed["readme_heading_verified"], "reply lacks README heading")
        stats["pending_line_bytes"] = len(state["tail"])
        require(len(state["tail"]) <= 1024 * 1024, "vendor result record exceeds its bound")

    identity = read("reply-reader", ["identity", "self"], {})
    actor = identity.get("actor", {})
    require(identity.get("config") == case.config and actor.get("kind") == "human" and
            actor.get("id") == case.human.public["principal_id"], "capture reader is another human")
    observed.update(reader=actor, method="blob.read")

    while True:
        within_deadline()
        current = read("reply-status", ["lane", "status"], record["target"])
        require(current.get("life_id") == record["target"]["life_id"] and current.get("run") == record["target"]["run"] and
                current.get("state") in ("running", "stopping", "verifying", "failed", "lost", "accepted", "abandoned"),
                "reply status differs from the observed lane")
        diagnostics["lane_state"] = current["state"]
        balance = current.get("credential_spend")
        public_error(current, "lane.status")
        # This tree exposes API-credential spend through Lane.CredentialSpend
        # (api/lifecycle.go). An absent observation is pending, not an invented
        # zero or a claim that the tree lacks the public spend capability.
        if balance is not None:
            require(isinstance(balance, dict) and type(balance.get("spent_micros")) is int and balance["spent_micros"] >= 0,
                    "public lane spend is untyped")
            observed["spend"].update(reported=True, spent_micros=balance["spent_micros"],
                                     accounting_error=bool(balance.get("accounting_error")))
        diagnostics["snapshot_complete"] = False
        cursor, cursors, records = event_cursor, set(), []
        while True:
            page = read("reply-captures", ["event", "tail"], dict(record["target"],
                since=0, cursor=cursor, follow=False, until="", deadline_ms=1000))
            require(isinstance(page.get("events"), list),
                    "reply capture page is absent")
            for event in page["events"]:
                if event.get("origin") != "service" or event.get("config") != case.config or \
                        event.get("life_id") != record["target"]["life_id"] or event.get("run") != record["target"]["run"]:
                    continue
                payload = event.get("payload", {})
                kind = event.get("kind")
                require(isinstance(kind, str) and re.fullmatch(r"[a-z][a-z0-9_.-]{0,95}", kind) is not None,
                        "reply event has an invalid kind")
                kinds.add(kind)
                diagnostics["event_kinds"] = sorted(kinds)
                public_error(payload, "event.tail." + kind)
                require(not (event.get("kind") == "capture.gap" and payload.get("stream") == "stdout"),
                        "reply primary capture has a gap")
                if event.get("kind") == "capture.appended":
                    identifier = payload.get("id")
                    require(isinstance(identifier, str) and bool(identifier), "reply capture identity is absent")
                    if identifier in inventory:
                        require(inventory[identifier] == payload, "reply capture replay changed")
                    else:
                        stats = stream(payload.get("stream"))["stats"]
                        size = payload.get("data", {}).get("bytes")
                        require(type(size) is int and 0 < size <= 262144, "reply capture byte size is invalid")
                        inventory[identifier] = payload
                        stats["records"] += 1
                        stats["bytes"] += size
                        diagnostics["capture_records"] = len(inventory)
                    records.append(payload)
                elif event.get("kind") == "capture.closed" and payload.get("binding_id") == binding:
                    name = stream_names.get(payload.get("stream_id"))
                    require(name is not None and payload.get("eof") is True and type(payload.get("next_offset")) is int and
                            payload["next_offset"] >= 0, "reply capture close has no exact stream end")
                    stats = stream(name)["stats"]
                    require(not stats["closed"] or stats["closed_bytes"] == payload["next_offset"],
                            "reply capture close changed its end")
                    stats["closed"], stats["closed_bytes"] = True, payload["next_offset"]
                elif kind == "spend.recorded":
                    usage = payload.get("usage", {})
                    fields = ("cost_micros", "input_tokens", "output_tokens", "cache_read_tokens", "cache_creation_tokens")
                    require(isinstance(usage.get("session_id"), str) and isinstance(usage.get("result_id"), str) and
                            all(type(usage.get(field)) is int and 0 <= usage[field] <= 2**53 - 1 for field in fields),
                            "public vendor spend lacks its typed result usage")
                    public_error(usage, "event.tail.spend.recorded.usage")
                    identifier, capture_id = event.get("id"), payload.get("capture_id")
                    require(isinstance(identifier, str) and bool(identifier) and isinstance(capture_id, str) and bool(capture_id),
                            "public vendor spend lacks its event or capture identity")
                    value = {**{field: usage[field] for field in ("session_id", "result_id", *fields)},
                             "capture_id": capture_id, "sealed_session": usage["session_id"] == session}
                    require(identifier not in spend_records or spend_records[identifier] == value, "public vendor spend replay changed")
                    spend_records[identifier] = value
                elif kind == "lane.ended":
                    require(payload.get("reason") in ("exit", "stop", "service_lost", "limit", "timeout", "dropped"),
                            "public lane end has an unknown reason")
                    diagnostics["end_reason"] = payload["reason"]
            cursor = page.get("cursor")
            if page.get("complete") is True:
                diagnostics["snapshot_complete"] = True
                # Store cursors are exclusive live positions. Continue from
                # this completed snapshot on the next poll, rather than
                # requesting the growing history again from sequence zero.
                event_cursor = cursor
                break
            require(cursor and cursor not in cursors, "reply capture cursor did not advance")
            cursors.add(cursor)
        observed["spend"]["records"] = list(spend_records.values())
        primary = [] if blob_unavailable else [item for item in records if item.get("primary") is True and item.get("stream") in ("stdout", "stderr") and
                   not item.get("replacement_of")]
        require(all(type(item.get("offset")) is int for item in primary), "reply capture offset is untyped")
        for item in sorted(primary, key=lambda entry: entry["offset"]):
            state = stream(item["stream"])
            stats = state["stats"]
            # The store emits raw capture.appended chunks as partial coverage.
            # Their pinned contiguous bytes can prove a complete vendor JSON
            # result without claiming framed tool-call or whole-run coverage.
            require(item.get("target") == record["target"] and item.get("binding_id") == binding and
                    item.get("coverage") in ("partial", "complete"), "reply capture differs from the primary run")
            identifier = item.get("id")
            require(isinstance(identifier, str) and bool(identifier), "reply capture identity is absent")
            if identifier in seen:
                require(seen[identifier] == item, "reply capture replay changed")
                continue
            ref = item.get("data", {})
            require(item["offset"] == state["offset"] and ref.get("class") == "capture" and
                    type(ref.get("bytes")) is int and 0 < ref["bytes"] <= 262144 and
                    sum(value["offset"] for value in stream_state.values()) + ref["bytes"] <= 8 * 1024 * 1024,
                    "reply capture lost its bounded contiguous range")
            offset, digest = 0, hashlib.sha256()
            while offset < ref["bytes"]:
                try:
                    chunk = read("reply-blob", ["blob", "read"], {"object_id": ref.get("id"), "offset": offset,
                        "limit": min(REPLY_READ_BYTES, ref["bytes"] - offset)})
                except CaptureNotVisible:
                    blob_unavailable = True
                    observed["capture_read"] = {"status": "not_visible", "reason": CAPTURE_NOT_VISIBLE}
                    break
                try:
                    raw = base64.b64decode(chunk.get("data", ""), validate=True)
                except (ValueError, TypeError):
                    require(False, "reply blob is not encoded bytes")
                require(chunk.get("object_id") == ref.get("id") and chunk.get("offset") == offset and
                        0 < len(raw) <= min(REPLY_READ_BYTES, ref["bytes"] - offset) and
                        hashlib.sha256(raw).hexdigest() == chunk.get("sha256"),
                        "reply blob page differs from the public capture range or digest")
                digest.update(raw)
                offset += len(raw)
                state["offset"] += len(raw)
                stats["read_bytes"] += len(raw)
                stats["read_pages"] += 1
                stats["max_read_page_bytes"] = max(stats["max_read_page_bytes"], len(raw))
                state["tail"] += raw
                consume(item["stream"], state)
            if blob_unavailable:
                break
            require(offset == ref["bytes"] and digest.hexdigest() == ref.get("sha256"),
                    "reply blob differs from the public capture digest")
            seen[identifier] = item
            stats["read_records"] += 1
            observed["capture_read"]["status"] = "read"
        # EOF can arrive on a later event snapshot after the final bytes.
        # Flush that already-read tail without re-reading or inventing bytes.
        for name, state in stream_state.items():
            consume(name, state)
        within_deadline()
        captured = [stream_state.get(name, {}).get("stats", {}) for name in stream_names.values()
                    if name in ("stdout", "stderr")]
        if diagnostics["end_reason"] == "stop" and not observed["result_present"] and captured and all(
                stats.get("closed") is True and stats.get("closed_bytes") == stats.get("read_bytes") for stats in captured):
            observed["error"] = "run stopped before its vendor result"
            require(False, observed["error"])
        if mode == "fake-key" and observed["spend"]["accounting_error"] and not vendor_result_proven(observed):
            observed["error"] = AGENT_NOT_STARTED
            require(False, AGENT_NOT_STARTED)
        if mode == "fake-key" and observed["result_present"]:
            require(observed["is_error"] is True and observed["error_class"] == "authentication_error" and
                    observed["api_error_status"] in (None, 401),
                    "fake-key vendor result class: " + observed["error_class"])
        if reply_passed(observed, mode):
            observed["outcome"] = FAKE_TURN_PROOF if mode == "fake-key" else REAL_TURN_PROOF
            case.passed(observed)
            if mode == "fake-key":
                record["vendor_proof"] = vendor_proof(observed)
            return
        remaining = deadline - time.monotonic()
        within_deadline()
        time.sleep(min(0.5, remaining))


def refusal(case, operation, fail):
    error = operation.get("error")
    if error:
        case.rows[case.current]["observed"] = {"executed": True, "owner": error.get("owner"),
            "refusal": error, "operation": operation, "command": case.last}
        raise fail("installed operation refused")


def await_operation(case, operation, require, fail, target=None):
    selected = operation
    # A pending reply carries life_id and run only once the operation journals a lane event (lane.clean's first
    # event is its proof use, box 104); then each later read must name the lane the caller targeted.
    expected = {field: operation.get(field) if operation.get(field) is not None else (target or {}).get(field)
                for field in ("life_id", "run")}
    deadline = time.monotonic() + 120
    while True:
        refusal(case, selected, fail)
        if selected.get("status") == "succeeded":
            return selected
        require(selected.get("status") in ("pending", "running"), "operation ended without successful receipt")
        require(time.monotonic() < deadline, "installed operation deadline")
        selected = case.human.read("operation-status", ["operation", "get"], {"operation_id": operation["id"]})
        require(selected.get("id") == operation.get("id") and
                all(selected.get(field) == value if operation.get(field) is not None else selected.get(field) in (None, value)
                    for field, value in expected.items()),
                "operation selector or reserved run changed")
        time.sleep(0.5)


def status(case, record, require):
    value = case.human.read("lane-status", ["lane", "status"], record["target"])
    require(value.get("life_id") == record["target"]["life_id"] and value.get("run") == record["target"]["run"] and
            value.get("level") == 5 and value.get("role") == record["request"]["role"] and
            value.get("session", {}).get("driver") == record["driver"] and
            not value.get("parent_life_id") and value.get("root_life_id") == value["life_id"] and
            value.get("starter_chain") == [] and value.get("starter_event_seq") == 0,
            "status is not the requested L5 root and driver")
    require(type(value.get("generation")) is int and value["generation"] > 0 and
            (not record.get("launch_id") or value.get("launch_id") == record["launch_id"]),
            "status lost its current generation or original launch")
    return value


def control(case, label, method, request, target, generation):
    parent = case.current
    proof = case.human.proof("control", method, request, target, generation)
    case.current = parent
    return case.human.rpc(label, method.split("."), request, proof)


def events(case, record, require):
    result, cursor, seen = [], "", set()
    deadline = time.monotonic() + 120
    while True:
        require(time.monotonic() < deadline, "event pagination deadline")
        page = case.human.read("lane-events", ["event", "tail"], dict(record["target"],
            since=0, cursor=cursor, follow=False, until="", deadline_ms=1000))
        require(isinstance(page.get("events"), list), "event page is absent")
        result.extend(page["events"])
        if page.get("complete") is True:
            return result
        next_cursor = page.get("cursor")
        require(next_cursor and next_cursor not in seen, "event cursor did not advance")
        seen.add(next_cursor)
        cursor = next_cursor


def capture_read(case, record, retained, require):
    """Read the vendor's exact captured bytes as the root ticket's human."""
    identity = case.human.read("capture-reader", ["identity", "self"], {})
    actor = identity.get("actor", {})
    require(identity.get("config") == case.config and actor.get("kind") == "human" and
            actor.get("id") == case.human.public["principal_id"], "capture reader is another human")
    target = record["target"]
    captures = [event for event in retained if event.get("kind") in
                {"capture.bound", "capture.appended", "capture.gap"}]
    require(all(event.get("config") == case.config and event.get("life_id") == target["life_id"] and
                event.get("run") == target["run"] and event.get("origin") == "service"
                for event in captures), "capture event belongs to another scope or run")
    bounds = [event["payload"] for event in captures if event["kind"] == "capture.bound"]
    require(len(bounds) == 1 and bounds[0].get("status") == "registered" and
            bounds[0].get("target") == target and bounds[0].get("config") == case.config,
            "capture has no unique registered binding")
    binding = bounds[0]
    output = {"stdout": bytearray(), "stderr": bytearray()}
    refs = []
    for event in captures:
        require(event["kind"] != "capture.gap", "capture contains an explicit gap")
        if event["kind"] != "capture.appended":
            continue
        capture = event["payload"]
        require(capture.get("binding_id") == binding["id"] and capture.get("target") == target and
                capture.get("primary") is True and not capture.get("replacement_of") and
                event.get("operation_id") == binding.get("operation_id"), "capture producer binding differs")
        stream = capture.get("stream")
        if stream not in output:
            continue
        reference = capture["data"]
        require(capture.get("offset") == len(output[stream]) and reference.get("class") == "capture" and
                type(reference.get("bytes")) is int and 0 < reference["bytes"] <= 262144,
                "capture offset or immutable reference differs")
        raw = bytearray()
        while len(raw) < reference["bytes"]:
            limit = min(131072, reference["bytes"] - len(raw))
            chunk = case.human.read("capture-blob", ["blob", "read"],
                {"object_id": reference["id"], "offset": len(raw), "limit": limit})
            data = base64.b64decode(chunk["data"], validate=True)
            require(chunk.get("object_id") == reference["id"] and chunk.get("offset") == len(raw) and
                    0 < len(data) <= limit and hashlib.sha256(data).hexdigest() == chunk.get("sha256"),
                    "capture blob chunk attribution or digest differs")
            raw.extend(data)
        require(hashlib.sha256(raw).hexdigest() == reference.get("sha256"), "capture object digest differs")
        output[stream].extend(raw)
        require(sum(len(value) for value in output.values()) <= 67108864, "capture reply exceeds its bound")
        refs.append(reference)
    require(refs, "capture has no vendor reply bytes")
    for stream, raw in output.items():
        case.keep(record["name"] + "-reply." + stream, bytes(raw))
    return {"reader": actor, "method": "blob.read", "target": target, "objects": refs,
            **{stream: raw.decode("utf-8", errors="replace") for stream, raw in output.items()}}


def observe(case, record, require, running=False):
    lane = status(case, record, require)
    result = control(case, "lane-check", "lane.check", record["target"], lane["life_id"], lane["generation"])
    require(result.get("handle", {}).get("target") == record["target"] and result.get("handle", {}).get("containment_id"),
            "native observation is not this reserved run")
    require(result.get("observed_at") and type(result.get("survivors")) is int and
            (not record.get("handle") or result["handle"] == record["handle"]),
            "native observation lost its measurement or original containment")
    if running:
        require(result.get("state") == "running" and result.get("survivors", 0) > 0 and lane.get("launch_id"),
                "start did not release a real contained process")
        record["launch_id"], record["handle"] = lane["launch_id"], result["handle"]
    return lane, result


def wait_answer(case, record, lane, require):
    """Wait within the admitted budget, then stop only the committed end."""
    budgets = (record["request"].get("budget", {}).get("wall_ms"),
               lane.get("budget_remaining", {}).get("wall_ms"))
    require(all(type(value) is int and value > 0 for value in budgets),
            "real run lacks its existing wall budget")
    deadline = record["launch_started"] + min(budgets) / 1000
    cursor, checked = "", False
    case.rows[case.current]["result"] = "fail"
    with case.budget_scope(deadline):
        while True:
            require(time.monotonic() < deadline, "run budget exhausted before vendor result")
            page = case.capture_read("answer-events", ["event", "tail"], dict(record["target"],
                since=0, cursor=cursor, follow=False, until="", deadline_ms=1000), deadline)
            require(time.monotonic() <= deadline, "run budget exhausted before vendor result")
            require(isinstance(page.get("events"), list), "natural wait lacks an event page")
            ready = False
            for event in page["events"]:
                if (event.get("origin") != "service" or event.get("config") != case.config or
                        event.get("life_id") != record["target"]["life_id"] or event.get("run") != record["target"]["run"]):
                    continue
                kind, payload = event.get("kind"), event.get("payload", {})
                if kind not in ("lane.ended", "run.observed"):
                    continue
                native = payload.get("observation", {}) if kind == "lane.ended" else payload
                if native.get("state") != "exited":
                    continue
                require(native.get("handle") == record["handle"] and native.get("observed_at"),
                        "natural exit differs from the retained process")
                process = {"state": native["state"], "exited": True,
                           **{field: native.get(field) for field in ("exit_code", "signal", "survivors")}}
                require(terminal_process(process), "natural exit lacks zero survivors")
                if kind == "lane.ended":
                    require(payload.get("reason") != "stop", "run stopped before its vendor result")
                    require(payload.get("reason") == "exit" and payload.get("launch_id") == lane["launch_id"] and
                            isinstance(event.get("id"), str) and bool(event["id"]) and
                            type(event.get("seq")) is int and event["seq"] > 0 and event.get("recorded_at"),
                            "natural exit lacks its committed end")
                    record["natural_end"] = event
                    current = status(case, record, require)
                    require(current.get("state") in ("verifying", "accepted") and
                            current.get("containment") == "quiescent", "natural exit is not committed quiescent")
                    return current
                ready = True
            # The launch reconciler's retained zero-survivor run.observed
            # makes one LaneCheck safe. A refusal propagates without retry.
            if ready and not checked:
                checked = True
                _, native = observe(case, record, require)
                require(native.get("state") == "exited" and native.get("survivors") == 0,
                        "recorded natural exit changed before its check")
            previous, cursor = cursor, page.get("cursor")
            require(isinstance(cursor, str) and (page.get("complete") is True or cursor and cursor != previous),
                    "natural wait cursor did not advance")
            remaining = deadline - time.monotonic()
            require(remaining > 0, "run budget exhausted before vendor result")
            if page.get("complete") is True:
                time.sleep(min(0.5, remaining))


def wait_exit_record(case, record, require):
    deadline = time.monotonic() + 120
    while True:
        _, observed = observe(case, record, require)
        require(observed.get("state") in ("running", "exited"),
                "natural exit has unknown containment")
        if observed["state"] == "exited":
            require(observed.get("exit_code") == 0 and "signal" not in observed and
                    observed.get("survivors") == 0,
                    "fixture did not produce a normal terminal exit")
            ended = [event for event in events(case, record, require) if
                     event.get("kind") == "lane.ended" and event.get("config") == case.config and
                     event.get("life_id") == record["target"]["life_id"] and
                     event.get("run") == record["target"]["run"]]
            require(len(ended) <= 1, "natural exit has duplicate end records")
            if ended:
                event = ended[0]
                end = event.get("payload", {})
                native = end.get("observation", {})
                require(event.get("origin") == "service" and type(event.get("seq")) is int and
                        event["seq"] > 0 and event.get("recorded_at") and end.get("reason") == "exit" and
                        end.get("launch_id") == record["handle"]["id"] and
                        native.get("handle") == record["handle"] and native.get("state") == "exited" and
                        native.get("exit_code") == 0 and "signal" not in native and native.get("survivors") == 0,
                        "recorded natural exit differs from the original quiescent process")
                lane = status(case, record, require)
                if lane.get("state") in ("verifying", "accepted") and lane.get("containment") == "quiescent":
                    case.keep_json(record["name"] + "-exit-record.json",
                                   {"event": event, "lane": lane, "native": observed})
                    record["quiescent"] = True
                    return lane
        require(time.monotonic() < deadline, "recorded natural exit deadline")
        time.sleep(0.25)


def stop(case, record, require, fail):
    name = record["name"]
    row(case, name, "reason")
    reason = case.human.upload("stop-reason", "task", ("serve2 stop " + name + " " + case.challenge + "\n").encode())
    case.passed({"reason": reason})
    row(case, name, "stop")
    finish = getattr(getattr(case, "item_module", None), "finish_lifecycle", None)
    if finish is not None:
        require(callable(finish), "item normal-exit hook is not callable")
    # The hook returns True only for a lane it ended through its own fixture.
    if finish is not None and finish(case, record, require, fail) is True:
        lane = wait_exit_record(case, record, require)
    else:
        lane = status(case, record, require)
    record["stop_attempted"] = True
    request = {"target": record["target"], "expected_generation": lane["generation"], "reason": reason}
    operation = control(case, "lane-stop", "lane.stop", request, lane["life_id"], lane["generation"])
    require(operation.get("id"), "stop lacks a real operation")
    completed = await_operation(case, operation, require, fail)
    natural = record.get("natural_end")
    if natural is not None:
        receipt = completed.get("stop", {})
        require(receipt.get("state") == lane["state"] and receipt.get("end_event_id") == natural["id"] and
                receipt.get("end_sequence") == natural["seq"] and receipt.get("end") == natural["payload"],
                "ended-run stop lacks its exact committed-end receipt")
        after = status(case, record, require)
        require(after.get("generation") == lane["generation"] and after.get("state") == lane["state"],
                "ended-run stop changed the completed lane")
        case.passed({"operation": completed, "proof": "ended-run", "end_event_id": natural["id"]})
    else:
        case.passed(completed)
    row(case, name, "quiescent")
    deadline = time.monotonic() + 120
    while True:
        lane, observed = observe(case, record, require)
        if observed.get("state") == "exited":
            require(observed.get("survivors") == 0 and
                    ((type(observed.get("exit_code")) is int and "signal" not in observed) or
                     (type(observed.get("signal")) is int and observed["signal"] > 0 and "exit_code" not in observed)),
                    "stop lacks a known terminal exit and zero survivors")
            record["quiescent"] = True
            record["quiescent_observation"] = dict(observed)
            case.passed(observed)
            # A terminal LaneCheck may commit lane.ended and advance the
            # generation. Read that commit before signing the next mutation.
            return status(case, record, require)
        require(observed.get("state") == "running" and time.monotonic() < deadline, "stop containment deadline or unknown state")
        time.sleep(0.5)


def archive_clean(case, record, lane, require, fail):
    name = record["name"]
    row(case, name, "abandon")
    empty_ref = {"id": "", "sha256": "", "bytes": 0, "class": ""}
    # Abandonment requires no positive review. This empty typed field claims
    # no review ID/evidence; accepted/merged are never requested by this case.
    empty_review = {"id": "", "reviewer": {"kind": "", "id": ""}, "diff": empty_ref, "checks": [],
                    "record_inventory": empty_ref, "refusal_resolution": [], "coverage": ""}
    request = {"target": record["target"], "expected_generation": lane["generation"], "state": "abandoned", "review": empty_review}
    operation = control(case, "lane-abandon", "lane.mark", request, lane["life_id"], lane["generation"])
    case.passed(await_operation(case, operation, require, fail))
    row(case, name, "archive")
    lane = status(case, record, require)
    require(lane.get("state") == "abandoned", "abandonment was not committed")
    request = {"target": record["target"], "expected_generation": lane["generation"]}
    archive = control(case, "lane-archive", "lane.archive", request, lane["life_id"], lane["generation"])
    require(archive.get("id") and archive.get("life_id") == lane["life_id"] and
            archive.get("manifest", {}).get("class") == "manifest" and archive.get("store_id") and
            archive.get("archive_sha256") and archive.get("archive_sha256") == archive.get("read_back_sha256"),
            "archive lacks the real verified read-back receipt")
    case.passed(archive)
    row(case, name, "clean")
    lane = status(case, record, require)
    request = {"target": record["target"], "expected_generation": lane["generation"], "archive_receipt_id": archive["id"]}
    operation = control(case, "lane-clean", "lane.clean", request, lane["life_id"], lane["generation"])
    completed = await_operation(case, operation, require, fail, record["target"])
    native = case.native_cleanup_evidence(record, lane, completed)
    case.passed({"operation": completed, "native_helper": native})
    row(case, name, "collected")
    final = status(case, record, require)
    require(final.get("cleaned") is True and final.get("state") == "abandoned", "service did not collect the disposable lane")
    retained_events = events(case, record, require)
    require(any(event.get("kind") == "lane.cleaned" and event.get("life_id") == final["life_id"] and
                event.get("run") == final["run"] for event in retained_events), "cleaned event is absent")
    record["collected"] = True
    case.passed(final)


def run(case, require, fail, blocked):
    case.human.session()
    inputs = None
    if case.lane_inputs is not None:
        data = case.root_launch_input(case.lane_inputs)
        case.keep("lane-inputs.input.json", data)
        inputs = case.decode_document(data)
    for name, driver in DRIVERS:
        case.human_prefix = name
        row(case, name, "inputs")
        if inputs is None:
            case.rows[case.current]["observed"].update({"executed": False,
                "owner_request": ["lb-v2-admin", "lb-v2-grants"], "reason": "actual enrolled L5 project/profile/task input absent"})
            raise blocked("real L5 launch selectors are required; no task/project/profile IDs are invented")
        require(isinstance(inputs, dict) and isinstance(inputs.get(driver), dict),
                "launch input lacks an exact StartRequest for " + driver)
        request = dict(inputs[driver])
        require(request.get("level") == 5 and request.get("driver") == driver and request.get("role") and
                not request.get("root_ticket_id"), "launch input is not an unticketed L5 selector for this driver")
        case.validate_initial_launch(request)
        if name == "claudock" and case.api_key_canary is not None:
            case.keep("claudock-reply-task.input.md", REPLY_TASK)
            request["task"] = case.human.upload("readme-task", "task", REPLY_TASK)
        case.passed({"driver": driver, "level": request["level"], "project_id": request.get("project_id")})
        ticket = case.human.ticket(request, case.root_grants)
        request["root_ticket_id"] = ticket["id"]
        row(case, name, "start")
        start_check = case.current
        spawn_key = "serve-start-" + uuid.uuid4().hex
        case.keep_json(name + "-start.intent.json", {"request": request, "idempotency_key": spawn_key})
        session_proof = case.human.proof("read", "human.session", {}, case.human.public["principal_id"], 0)
        case.current = start_check
        launch_started = time.monotonic()
        operation = case.checked_cli("lane-start", ["lane", "start"], request,
                                     idempotency_key=spawn_key, session_proof=str(session_proof))
        require(operation.get("id") and operation.get("life_id") and operation.get("run") == 1,
                "start lacks an actual reservation")
        record = {"name": name, "driver": driver, "request": request,
                  "target": {"life_id": operation["life_id"], "run": operation["run"]},
                  "stop_attempted": False, "quiescent": False, "collected": False,
                  "launch_started": launch_started}
        case.lane_records.append(record)
        require(operation.get("simulated_presence") is True, "start lacks simulated provenance")
        completed = await_operation(case, operation, require, fail)
        require(completed.get("simulated_presence") is True, "completed operation lost simulated provenance")
        case.passed(completed)
        row(case, name, "running")
        if case.api_key_canary is not None and driver == "claudock-cli":
            lane, observation = observe(case, record, require)
            require(observation.get("state") in ("running", "exited") and lane.get("launch_id"),
                    "fake API key lane never reached a real contained launch")
            record["launch_id"], record["handle"] = lane["launch_id"], observation["handle"]
        else:
            lane, observation = observe(case, record, require, running=True)
        running_observed = {"executed": True, "lane": lane, "observation": observation}
        fake = getattr(case, "reply_mode", None) == "fake-key" and name == "claudock"
        if fake:
            case.rows[case.current]["observed"] = running_observed
        else:
            case.passed(running_observed)
        row(case, name, "events")
        retained_events = events(case, record, require)
        for kind in ("lane.created", "lane.started", "identity.bound"):
            found = [event for event in retained_events if event.get("kind") == kind and event.get("config") == case.config and
                     event.get("life_id") == lane["life_id"] and event.get("run") == lane["run"] and event.get("origin") == "service"]
            require(found and all(event.get("seq", 0) > 0 for event in found), "required real lifecycle event absent: " + kind)
        event_observed = {"executed": True, "events": retained_events, "life_id": lane["life_id"], "run": lane["run"]}
        if fake:
            case.rows[case.current]["observed"] = event_observed
        else:
            case.passed(event_observed)
        if name == "claudock" and case.real_api_key:
            lane = wait_answer(case, record, lane, require)
            case.passed(dict(event_observed, natural_end=record["natural_end"]))
        lane = stop(case, record, require, fail)
        if name == "claudock" and case.api_key_canary is not None:
            reply(case, record, lane, retained_events, require)
            if fake:
                row(case, name, "running")
                case.passed(dict(running_observed, vendor_proof=record["vendor_proof"]))
                row(case, name, "events")
                case.passed(dict(event_observed, vendor_proof=record["vendor_proof"]))
        if name != "claudock" or case.api_key_canary is None:
            row(case, name, "reply")
            case.passed(capture_read(case, record, events(case, record, require), require))
        if case.api_key_canary is not None and driver == "claudock-cli":
            case.api_key_canary.scan_lane(case, record)
        archive_clean(case, record, lane, require, fail)
    case.human_prefix = ""


def stop_owned(case, require, fail):
    problems = []
    for record in case.lane_records:
        case.human_prefix = record["name"]
        failed = case.rows.get(case.failed_step, {}).get("observed", {})
        if case.failed_step and (case.failed_step.startswith("human.") or failed.get("refusal")):
            if not record["quiescent"]:
                problems.append({"target": record["target"], "reason": "product authority or execution gate refused; no alternate stop route"})
            if not record["collected"]:
                problems.append({"target": record["target"], "reason": "service-owned collection remains incomplete"})
            continue
        if not record["quiescent"] and not record["stop_attempted"]:
            try:
                stop(case, record, require, fail)
            except (OSError, ValueError, KeyError, TypeError, fail) as error:
                problems.append({"target": record["target"], "reason": str(error), "step": case.current})
        if not record["quiescent"]:
            problems.append({"target": record["target"], "reason": "actual terminal zero-survivor observation missing"})
        if not record["collected"]:
            problems.append({"target": record["target"], "reason": "service archive and owned-object collection remain incomplete"})
    return problems
