"""Value-free installed-suite failures and bounded native journal summaries."""

import ast
import base64
from contextlib import contextmanager
from contextvars import ContextVar
import errno
from functools import wraps
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[4]
PYTHON = (
    "e2e/v2/cases/secrets/installed.py", "e2e/v2/cases/secrets/run.py",
    "e2e/v2/cases/secrets/wire.py", "scripts/v2-serve/run.py",
    "scripts/v2-serve/provision.py", "scripts/v2-serve/human.py",
    "scripts/v2-serve/case_secrets.py", "scripts/v2-serve/secret_observer.py",
    "scripts/v2-admin/boot.py",
)
GO = ("internal/v2/admin/credwire_linux.go", "internal/v2/admin/credowner_linux.go",
      "internal/v2/assembly/resources.go", "internal/v2/cli/cli.go", "internal/v2/client/client.go",
      "internal/v2/service/authentication.go", "internal/v2/assembly/credbroker_linux.go",
      "internal/v2/assembly/credcomp_linux.go", "internal/v2/assembly/credowners_linux.go",
      "internal/v2/service/host.go", "internal/v2/api/base.go", "internal/v2/api/methods.go",
      "internal/v2/api/events.go", "internal/v2/api/json_diagnostic.go")
CODES = frozenset((
    "invalid_request", "unauthenticated", "forbidden", "not_found", "conflict",
    "idempotency_conflict", "not_implemented", "unsupported", "unavailable",
    "prerequisite_missing", "integrity", "deadline_exceeded", "budget_exhausted",
    "containment_unknown", "cancelled", "version_mismatch", "unscored", "cursor_expired",
))
LABELS = frozenset((
    "preflight", "install", "observer.controls", "human.enroll", "initial.publish",
    "human.session", "human.grants", "tools.build", "inputs.prepare", "native.setup",
    "execute", "baseline", "SECRET-INJECT", "CREDENTIAL-BOUND", "collection",
    "verify", "privacy", "results.write", "units.cleanup", "suite", "unit",
    "lane.start", "lane.stop", "lane.status", "lane.check", "lane.mark", "lane.archive", "lane.clean", "lane.quiescence",
    "operation.get", "identity.self", "grants.root", "ticket.issue", "grants.get",
    "blob.begin", "blob.chunk", "blob.commit", "blob.read", "secret.import", "secret.stage",
    "first.eight", "bad.stage", "key.controls", "finish", "report", "unknown_check", "human.endpoint",
))
STAGES = frozenset((
    "helper.before_accounts", "helper.after_accounts", "credential_publication", "credential.owner.dropped",
    "credential.owner.published", "credential.owner.accept", "credential.owner.call",
    "initial_publish.native_context", "initial_publish.protected_read", "initial_publish.load_validate",
    "initial_publish.bundle_validate", "initial_publish.object_hashes", "initial_publish.policy_validate",
    "initial_publish.template_validate", "initial_publish.revalidate", "initial_publish.plan",
    "initial_publish.seal", "initial_publish.commit", "initial_publish.read_object",
    "initial_publish.read_back", "initial_publish.total",
))
REASONS = {
    "recv_deadline": "credential_frame_recv_deadline",
    "read_deadline": "credential_owner_read_deadline",
    "credential frame peer closed its stream": "credential_frame_peer_closed",
    "credential ancillary count, writer or framing was refused (recv_deadline)": "credential_frame_recv_deadline",
    "credential ancillary count, writer or framing was refused (recv deadline)": "credential_frame_recv_deadline",
}
JOURNAL_TOKENS = {
    "event": {"credential_owner_dropped", "credential_owner_refused", "scheduler_unavailable"},
}
OWNER_REASONS = {"pin_peer", "process_generation", "no_session", "read_deadline", "read_frame", "caller_closed",
                 "request_binding", "request_decode"}
ENUM_FIELDS = frozenset(("event", "reason", "code", "stage", "method", "outcome", "kind"))
OUTCOMES = frozenset(("prepared", "imported", "rotated", "revoked", "leased", "released"))


def reason_name(message):
    return re.sub(r"[^a-z0-9]+", "_", message.lower()).strip("_")[:160]


class Catalog:
    """Only literal diagnostics in these owned/consumed sources may be printed."""

    def __init__(self, root=ROOT):
        self.messages = dict(REASONS)
        self.locations = {}
        self.commands, self.fields, self.methods, self.kinds = set(), set(), set(), set()
        for relative in PYTHON:
            path = Path(root) / relative
            self.locations[str(path.resolve())] = relative
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Dict):
                    self.fields.update(key.value for key in node.keys if isinstance(key, ast.Constant) and isinstance(key.value, str))
                if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                    self.fields.add(node.slice.value)
                if not isinstance(node, ast.Call):
                    continue
                name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
                if name == "get" and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    self.fields.add(node.args[0].value)
                if name in {"command", "cli", "checked_cli", "rpc", "read"} and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    self.commands.add(node.args[0].value)
                index = 1 if name in {"require", "check"} else 0
                if name in {"require", "check", "ValueError", "CaseFailure", "Failed", "Blocked", "RPCFailure"} and len(node.args) > index:
                    value = node.args[index]
                    if isinstance(value, ast.Constant) and isinstance(value.value, str):
                        self.messages[value.value] = reason_name(value.value)
        for relative in GO:
            raw = (Path(root) / relative).read_text(encoding="utf-8")
            self.fields.update(re.findall(r'json:"([A-Za-z_][A-Za-z0-9_]*)[,\"]', raw))
            if relative.endswith("/methods.go"):
                self.methods.update(re.findall(r'^\s*"([A-Za-z][A-Za-z0-9_.]{0,63})"\s*:', raw, re.M))
            if relative.endswith("/events.go"):
                self.kinds.update(re.findall(r'^\s*"([A-Za-z][A-Za-z0-9_.]{0,63})"\s*:', raw, re.M))
            self.kinds.update(re.findall(r'JSONFrameKind\s*=\s*"([a-z_]+)"', raw))
            self.methods.update(re.findall(r'case "([A-Za-z][A-Za-z0-9_.]{0,63})":', raw))
            self.methods.update(re.findall(r'"((?:helper|store|peer|control|identity)\.[A-Za-z0-9_.]{1,63})"\s*:', raw))
            for literal in re.findall(r'(?:Message:\s*|(?:failure|wire.Error)\([^,\n]+,\s*)("(?:[^"\\]|\\.)*")', raw):
                try:
                    message = json.loads(literal)
                except ValueError:
                    continue
                self.messages.setdefault(message, reason_name(message))
        self.fields = {name for name in self.fields if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name)} | ENUM_FIELDS

    def enum(self, name, value):
        allowed = {"event": JOURNAL_TOKENS["event"] | self.kinds, "reason": OWNER_REASONS | CODES |
                   set(REASONS.values()) | set(self.messages.values()) | {"dependency_failure"},
                   "code": CODES, "stage": STAGES, "method": self.methods, "outcome": OUTCOMES, "kind": self.kinds}
        return isinstance(value, str) and value in allowed.get(name, ())

    def reason(self, value):
        return self.messages.get(value, "unrecognized_message") if isinstance(value, str) else "unrecognized_message"

    def trace(self, error):
        frames, current = [], error.__traceback__
        while current is not None:
            path = str(Path(current.tb_frame.f_code.co_filename).resolve())
            if path in self.locations:
                frames.append({"source": self.locations[path], "line": current.tb_lineno})
            current = current.tb_next
        return frames[-5:]


def error_metadata(value, catalog, redact=None):
    if not isinstance(value, dict):
        return {}
    for key in ("error", "refusal", "result", "response"):
        child = value.get(key)
        if isinstance(child, dict):
            found = error_metadata(child, catalog, redact)
            if found:
                return found
    code = value.get("code")
    if code is None:
        return {}
    known = isinstance(code, str) and code in CODES
    row = {"code": code if known else "unrecognized_code", "reason": catalog.reason(value.get("message"))}
    if known:
        refusal = {"code": code}
        for field in ("message", "owner", "instead"):
            text = value.get(field)
            if not isinstance(text, str):
                continue
            if len(text) > 8192 or field == "owner" and text and re.fullmatch(r"lb-v2-[a-z0-9-]{1,48}", text) is None:
                text = "[redacted]"
            refusal[field] = redact(text) if redact is not None else text
        row["refusal"] = refusal
    return row


def journal_fields(value, catalog):
    fields, enums = set(), {}
    remaining = 256

    def visit(document, prefix="", depth=0):
        nonlocal remaining
        if depth >= 8 or remaining <= 0:
            return
        if isinstance(document, list):
            for child in document[:32]:
                visit(child, prefix + "[]", depth + 1)
        if not isinstance(document, dict):
            return
        for name, content in document.items():
            remaining -= 1
            if remaining < 0:
                return
            known = name in catalog.fields
            path = prefix + ("." if prefix else "") + (name if known else "*")
            fields.add(path)
            if known and name in ENUM_FIELDS and catalog.enum(name, content):
                enums[path] = content
            if known:
                visit(content, path, depth + 1)

    visit(value)
    return {"fields": sorted(fields), "enum_fields": enums}


def systemd_line(envelope, message, unit):
    if unit is None or envelope.get("_COMM") != "systemd" or envelope.get("_PID") != "1" or envelope.get("UNIT") != unit:
        return {}
    for word in ("Started", "Starting", "Stopped", "Stopping"):
        if message.startswith(word + " "):
            return {"systemd_state": word}
    if message.startswith("Failed to start "):
        return {"systemd_state": "Failed"}
    prefix = re.escape(unit) + r": "
    result = re.fullmatch(prefix + r"Failed with result '(exit-code|signal|core-dump|timeout|resources|protocol|dependency|start-limit-hit)'\.", message)
    if result:
        return {"systemd_state": "Failed", "systemd_result": result[1]}
    exited = re.fullmatch(prefix + r"(?:Main|Control) process exited, code=(exited|killed|dumped), status=[0-9]+(?:/[^\n]*)?", message)
    if exited:
        return {"systemd_state": "exit-code", "systemd_exit_kind": exited[1]}
    return {}


def journal_line(raw, catalog, unit=None, redact=None):
    """Summarize an actual line without forwarding any caller-supplied text."""
    try:
        envelope = json.loads(raw)
    except (ValueError, UnicodeError):
        return {"code": "journal_text", "reason": "text_redacted"}
    if not isinstance(envelope, dict):
        return {"code": "journal_shape", "reason": "nonobject_redacted"}
    value = envelope.get("MESSAGE", envelope)
    native = {}
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except (ValueError, UnicodeError):
            native = systemd_line(envelope, value, unit)
            decoded = {"message": value}
        value = decoded
    row = {"code": "journal_record", "reason": "unrecognized_message", **native}
    if isinstance(value, dict):
        row.update(journal_fields(value, catalog))
        row.update(error_metadata(value, catalog, redact))
        if isinstance(value.get("event"), str) and value["event"] in {"credential_owner_refused", "credential_owner_dropped"} and "message" not in value and isinstance(value.get("detail"), str):
            row.update(error_metadata({**{key: value[key] for key in ("code", "owner", "instead") if key in value},
                                       "message": value["detail"]}, catalog, redact))
        if "message" in value and row["reason"] == "unrecognized_message":
            row["reason"] = catalog.reason(value["message"])
        if isinstance(value.get("stage"), str) and value["stage"] in STAGES:
            row["stage"] = value["stage"]
        for key, allowed in JOURNAL_TOKENS.items():
            if isinstance(value.get(key), str) and value[key] in allowed:
                row[key] = value[key]
        if isinstance(value.get("method"), str) and value["method"] in catalog.methods:
            row["method"] = value["method"]
        if isinstance(value.get("reason"), str) and value["reason"].partition(" ")[0] in OWNER_REASONS:
            row["reason"] = "credential_owner_" + value["reason"].partition(" ")[0]
        detail = catalog.reason(value.get("detail"))
        if detail != "unrecognized_message":
            row["reason"] = detail
        if isinstance(value.get("reason"), str) and value["reason"] in REASONS:
            row["reason"] = REASONS[value["reason"]]
        for key in ("error", "refusal"):
            if isinstance(value.get(key), str) and value[key] in REASONS:
                row["reason"] = REASONS[value[key]]
    priority = envelope.get("PRIORITY")
    if priority in tuple(str(number) for number in range(8)):
        row["priority"] = int(priority)
    return row


class Reporter:
    def __init__(self, output=None, catalog=None, checks=()):
        self.output = sys.stderr if output is None else output
        self.catalog = catalog or Catalog()
        self.labels = set(LABELS) | set(checks)
        self.stack = ContextVar("secrets_diagnostic_stack", default=())
        self.failures, self.seen = [], []
        self.root, self.config = None, None
        self.first_journal = False
        self.sequence = 0
        self.redactions = set()

    def protect(self, values):
        for value in values:
            raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
            if len(raw) < 8:
                continue
            self.redactions.update((raw.decode("latin1"), raw.hex(), base64.b64encode(raw).decode("ascii")))
            try:
                self.redactions.add(raw.decode("utf-8"))
            except UnicodeError:
                continue

    def redact(self, value):
        for private in sorted(self.redactions, key=len, reverse=True):
            value = value.replace(private, "[redacted]")
        return value

    def attach(self, root, config):
        self.root, self.config = Path(root), config
        self.protect((str(self.root), config))

    def run(self, check, action, *args, **kwargs):
        with self.scope(check):
            return action(*args, **kwargs)

    def emit(self, kind, row):
        self.sequence += 1
        record = {"schema": "laneboss.secret-diagnostic.v1", "kind": kind, "seq": self.sequence, **row}
        raw = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        self.output.write(raw)
        self.output.flush()
        if self.root is not None:
            try:
                fd = os.open(self.root / "diagnostics.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError as error:
                self.output.write(json.dumps({"kind": "diagnostic_storage_failed", "code": errno.errorcode.get(error.errno, "EUNKNOWN")}) + "\n")
                self.output.flush()

    @contextmanager
    def scope(self, check, driver=None):
        label = check if check in self.labels else "unknown_check"
        selected = driver if driver in {"claudock-cli", "codex"} else None
        token = self.stack.set((*self.stack.get(), (label, selected)))
        try:
            yield
        except Exception as error:
            self.failure(error)
            raise
        finally:
            self.stack.reset(token)

    def failure(self, error, response=None, last=None):
        if any(saved is error for saved in self.seen):
            return
        self.seen.append(error)
        stack = self.stack.get()
        row = {"check": stack[-1][0] if stack else "suite", "context": [label for label, _ in stack[:-1]], "code": "check_failed",
               "reason": self.catalog.reason(error.args[0] if error.args else None), "trace": self.catalog.trace(error)}
        for error_type, code in ((KeyError, "missing_field"), (TypeError, "invalid_type"), (AttributeError, "missing_attribute"),
                                 (json.JSONDecodeError, "invalid_json"), (subprocess.TimeoutExpired, "command_timeout"),
                                 (sqlite3.Error, "state_read_failed"), (OSError, "os_error")):
            if isinstance(error, error_type):
                row["code"] = code
                break
        if isinstance(error, OSError):
            row["errno"] = errno.errorcode.get(error.errno, "EUNKNOWN")
        if isinstance(error, KeyError) and error.args and isinstance(error.args[0], str) and error.args[0] in self.catalog.fields:
            row["field"] = error.args[0]
        row.update(error_metadata(response or getattr(error, "response", None), self.catalog, self.redact))
        if last and type(last.get("exit_code")) is int:
            row["exit"] = last["exit_code"]
            if row["code"] == "check_failed" and last["exit_code"] != 0:
                row["code"] = "command_failed"
                if row["reason"] == "unrecognized_message":
                    row["reason"] = "command_nonzero_exit"
            if last.get("label") in self.catalog.commands:
                row["command"] = last["label"]
        elif type(getattr(error, "client_exit", None)) is int:
            row["exit"] = error.client_exit
        driver = next((driver for _, driver in reversed(stack) if driver), None)
        if driver is not None:
            row["driver"] = driver
        if driver == "claudock-cli" and any(label == "lane.stop" for label, _ in stack):
            row["check"] = "lane.claudock.stop"
            if row["reason"] == "credential_frame_recv_deadline":
                row["known_regression"] = "claudock_stop_under_repair"
        self.failures.append(row)
        self.emit("failure", row)
        if not self.first_journal and self.config is not None:
            self.first_journal = True
            self.journals("failure")

    def journals(self, phase, run=None):
        runner = subprocess.run if run is None else run
        if self.config is None or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", self.config) is None:
            self.emit("journal", {"phase": phase, "code": "journal_unavailable", "reason": "no_installed_configuration"})
            return
        for role in ("helper", "credential", "service"):
            try:
                completed = runner(["journalctl", "--no-pager", "--output=json", "--lines=12",
                    "--unit=laneboss-" + role + "@" + self.config + ".service"],
                    capture_output=True, check=False, timeout=10, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
                raw, code = completed.stdout, completed.returncode
                if self.root is not None:
                    for suffix, data in (("jsonl", raw), ("stderr", completed.stderr)):
                        path = self.root / ("journal-" + phase + "-" + role + "." + suffix)
                        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                        with os.fdopen(fd, "wb") as stream:
                            stream.write(data)
                lines = raw.splitlines()
                if code != 0 or not lines or len(raw) > 1048576:
                    self.emit("journal", {"phase": phase, "role": role, "exit": code, "code": "journal_query_failed" if code else "journal_empty"})
                    continue
                for index, line in enumerate(lines[-12:]):
                    self.emit("journal", {"phase": phase, "role": role, "line": index + 1,
                        **journal_line(line, self.catalog, unit="laneboss-" + role + "@" + self.config + ".service", redact=self.redact)})
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                self.emit("journal", {"phase": phase, "role": role, "code": "journal_query_failed",
                    "reason": "command_timeout" if isinstance(error, subprocess.TimeoutExpired) else "journal_read_failed"})

    def finish(self, code, result=None):
        if result is not None:
            for assertion in result.get("assertions", []):
                name = assertion.get("id")
                self.emit("assertion", {"check": name if isinstance(name, str) and name in {"SECRET-INJECT", "CREDENTIAL-BOUND"} else "unknown_check",
                    "reached": assertion.get("reached") is True,
                    "verdict": "pass" if assertion.get("verdict") == "pass" else "fail"})
        if code != 0:
            self.journals("final")
        self.emit("summary", {"exit": code, "failed_checks": len(self.failures),
            "first_failure": self.failures[0] if self.failures else None, "scope": "installed-standin"})


def tracked(check, driver=False):
    def decorate(action):
        @wraps(action)
        def run(self, *args, **kwargs):
            reporter = getattr(self, "diagnostics", None)
            if reporter is None:
                return action(self, *args, **kwargs)
            selected = args[0].get("request", {}).get("driver") if driver and args and isinstance(args[0], dict) else None
            with reporter.scope(check, selected):
                return action(self, *args, **kwargs)
        return run
    return decorate
