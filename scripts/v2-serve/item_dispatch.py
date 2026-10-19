"""Run each public item entry before teardown; preserve failed native gates."""

import base64
import copy
import errno
import importlib.util
import json
import os
from pathlib import Path
import shlex
import socket
import struct
import sys
import threading
import uuid


def sibling(name):
    spec = importlib.util.spec_from_file_location(
        "serve_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


context_io = sibling("item_context")


def producer(case_id):
    context_io.require(case_id.isidentifier(), "invalid item producer name")
    return sibling("case_" + case_id)


def entry_argv(entry):
    if entry.suffix == ".py":
        return [sys.executable, "-B", "-E", str(entry)]
    first = entry.read_bytes().splitlines()[0].decode("ascii")
    context_io.require(first.startswith("#!"), "shell entry has no interpreter")
    interpreter = shlex.split(first[2:])
    context_io.require(interpreter in (["/bin/sh"], ["/bin/bash"],
                       ["/usr/bin/env", "bash"]),
                       "unsupported declared shell interpreter")
    return [*interpreter, str(entry)]


def read_frame(peer):
    def exact(size):
        raw = bytearray()
        while len(raw) < size:
            part = peer.recv(size - len(raw))
            context_io.require(part, "item observer connection ended early")
            raw.extend(part)
        return bytes(raw)
    size = struct.unpack("!I", exact(4))[0]
    context_io.require(0 < size <= 2 << 20, "item observer frame exceeds bound")
    return json.loads(exact(size))


def write_frame(peer, value):
    raw = context_io.encoded(value)
    context_io.require(len(raw) <= 2 << 20, "item observer reply exceeds bound")
    peer.sendall(struct.pack("!I", len(raw)) + raw)


class Observer:
    """Private local IPC; the callback still uses original installed actors."""

    def __init__(self, case, context, prepared):
        self.case, self.context, self.prepared = case, context, prepared
        self.token = uuid.uuid4().hex
        self.path, self.server = None, None
        if prepared.get("transport") is not None:
            self.path = Path("/run") / ("lb-item-" + uuid.uuid4().hex[:20] + ".sock")
            self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.server.bind(str(self.path))
            self.path.chmod(0o600)
            self.server.listen(1)
            self.server.settimeout(0.5)
        self.done = threading.Event()
        self.error = None
        self.failure = None
        self.receipt = None
        self.collection_error = None
        self.operations = []
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def collect(self, operations):
        if self.collection_error is not None:
            raise self.collection_error
        if self.receipt is None:
            try:
                receipt = self.prepared["collect"](self.context, operations)
                self.receipt = context_io.collection(receipt, self.context)
            except Exception as error:
                self.collection_error = error
                raise
        context_io.require(set(operations) <= set(self.receipt["operation_ids"]),
                           "collection omitted a managed operation")
        return self.receipt

    def serve(self):
        try:
            while not self.done.is_set():
                try:
                    peer, _ = self.server.accept()
                except socket.timeout:
                    continue
                with peer:
                    peer.settimeout(180)
                    _, uid, _ = struct.unpack("3i", peer.getsockopt(
                        socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    context_io.require(uid == os.geteuid(),
                                       "item observer peer changed UID")
                    request = read_frame(peer)
                    context_io.require(request.pop("token", None) == self.token,
                                       "item observer token differs")
                    if request.get("action") == "collect":
                        context_io.require(set(self.operations) <= set(request["operation_ids"]),
                                           "entry omitted an observed operation")
                        self.operations = request["operation_ids"]
                        result = self.collect(self.operations)
                    else:
                        result = self.prepared["transport"](request)
                        if request.get("command") in (
                                "grants test-child", "grants revoke"):
                            raw = base64.b64decode(result["stdout"], validate=True)
                            if result["exit_code"] == 0:
                                self.operations.append(json.loads(raw)["id"])
                    write_frame(peer, result)
        except Exception as error:
            # Preserve the first callback failure. Closing the peer fails the
            # consumer too; no fabricated successful transport response exists.
            self.error = error
            if self.case is not None:
                row = self.case.rows.get(self.case.current, {})
                self.failure = {"check": self.case.current,
                                "observed": copy.deepcopy(row.get("observed", {}))}
            self.done.set()
            self.server.close()

    def start(self):
        if self.server is None:
            return {}
        self.thread.start()
        return {"LANEBOSS_ITEM_SOCKET": str(self.path),
                "LANEBOSS_ITEM_TOKEN": self.token}

    def close(self):
        if self.server is None:
            return
        self.done.set()
        self.thread.join(timeout=185)
        context_io.require(not self.thread.is_alive(),
                           "item observer did not stop")
        self.server.close()
        self.path.unlink()


class EntryScope:
    """A real systemd scope contains the public entry and its descendants."""

    def __init__(self, case, context):
        self.case, self.context = case, context
        self.unit = "lb-item-" + uuid.uuid4().hex[:20] + ".scope"
        self.group = Path("/sys/fs/cgroup/system.slice") / self.unit
        context_io.require(not os.path.lexists(self.group), "item entry scope is not fresh")
        context_io.keep(Path(context["evidence_root"]) / "entry-scope.json",
            context_io.encoded({"unit": self.unit, "config": context["config"], "fresh": True}))

    def argv(self, entry):
        return ["systemd-run", "--scope", "--quiet", "--unit=" + self.unit,
                "--slice=system.slice", "--", *entry]

    def read_group(self):
        try:
            context_io.require(not self.group.is_symlink(), "item entry cgroup is linked")
            if self.group.exists():
                processes = (self.group / "cgroup.procs").read_bytes()
                events = (self.group / "cgroup.events").read_bytes()
                return True, processes, events, None
        except OSError as error:
            if error.errno not in (errno.ENODEV, errno.ENOENT):
                raise
            return False, None, None, error.errno
        return False, None, None, None

    def collect(self, entry_exit=None):
        context_io.require(type(entry_exit) is int, "item entry exit status is unknown")
        stop_exit, stop_error = None, b""
        present, processes, events, removed_errno = self.read_group()
        if present:
            facts = dict(row.split() for row in events.decode().splitlines())
            if processes.strip() or facts.get("populated") != "0":
                self.case.command("item-entry-stop", ["systemctl", "stop", self.unit],
                                  seconds=120, clean=True, expected=None)
                stop_exit = self.case.last["exit_code"]
                if stop_exit != 0:
                    stop_error = (self.case.root / self.case.last["stderr"]).read_bytes()
            present, processes, events, last_errno = self.read_group()
            if last_errno is not None:
                removed_errno = last_errno
        if present:
            facts = dict(row.split() for row in events.decode().splitlines())
            context_io.require(not processes.strip() and facts.get("populated") == "0",
                               "item entry cgroup retained processes")
        if stop_exit not in (None, 0):
            ended = ("Failed to stop %s: Unit %s not loaded." % (self.unit, self.unit)).encode()
            context_io.require(stop_error.strip() == ended,
                               "item entry stop failed; retain its original command output")
        observation = {"unit": self.unit, "cgroup_present": present,
            "cgroup_procs": processes.decode() if present else None,
            "cgroup_events": events.decode() if present else None,
            "stop_exit_code": stop_exit, "entry_exit_code": entry_exit,
            "collection": "observed-empty" if present else "collected-after-exit",
            "removed_errno": removed_errno,
            "processes_quiescent": not present or not processes.strip()}
        ref = context_io.keep(Path(self.context["evidence_root"]) / "entry-processes.json",
                              context_io.encoded(observation))
        return {"processes_quiescent": observation["processes_quiescent"], "evidence": [ref]}


def run(case, case_id, prepared):
    # TestChild adapter: preserve actor transport; collect its native results.
    prepared = sibling("item_test_child").bind(case, prepared, context_io)
    context, context_path = context_io.create(
        case, case_id, prepared["binding_file"],
        prepared["profile_grant_ids"], phase=prepared.get("phase", "candidate"),
        mutation_id=prepared.get("mutation_id", ""), controls=prepared.get("controls"))
    inputs = dict(prepared.get("inputs", {}))
    if prepared.get("populate") is not None:
        extra = prepared["populate"](context)
        context_io.require(not set(inputs) & set(extra), "duplicate case inputs")
        inputs.update(extra)
    context_io.retain_inputs(context, inputs)
    reader = context_io.frozen(case.stage)
    manifest, entry = reader.case_file(
        case.stage / "e2e" / "v2" / "cases" / case_id / "case.json")
    result_path = Path(context["test_root"]) / "result.json"
    scope = EntryScope(case, context)
    observer = Observer(case, context, prepared)
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}
    environment.update(prepared.get("environment", {}))
    environment.update(observer.start())
    observed_exit, receipt, entry_collection, original = None, None, None, None
    try:
        case.command("item-" + case_id, scope.argv([*entry_argv(entry),
            "--context", str(context_path), "--result", str(result_path)]),
            seconds=manifest["timeout_seconds"], expected=None,
            environment=environment)
        observed_exit = case.last["exit_code"]
    except Exception as error:
        original = error
    finally:
        try:
            entry_collection = scope.collect(observed_exit)
        except Exception as error:
            original = original or error
        try:
            observer.close()
        except Exception as error:
            original = original or error
        try:
            # Collection is required even after transport or entry failure.
            receipt = observer.collect(observer.operations)
            context_io.keep(Path(context["evidence_root"]) /
                            "installed-collection.json",
                            context_io.encoded(receipt))
        except Exception as error:
            original = observer.error or original or error
            case.rows["item." + case_id + ".collection"]["observed"].update({
                "executed": True, "error": str(error)})
    value = json.loads(result_path.read_bytes()) if result_path.is_file() else None
    case.item_result = {"case_id": case_id, "exit_code": observed_exit,
        "result": value, "context": str(context_path), "collection": receipt,
        "entry_collection": entry_collection}
    if observer.error is not None or original is not None:
        if observer.failure is not None:
            case.current = observer.failure["check"]
            case.rows[case.current]["observed"] = observer.failure["observed"]
        else:
            case.current = "item." + case_id + ".run"
        raise observer.error or original
    case.current = "item." + case_id + ".run"
    value = reader.result_file(result_path, manifest, context, observed_exit,
        red_assertion=prepared.get("red_assertion"), red_check=prepared.get("red_check"))
    context_io.require(entry_collection is not None and entry_collection["processes_quiescent"] is True,
                       "public entry collection is incomplete")
    return {"case_id": case_id, "exit_code": observed_exit,
            "result": value, "context": str(context_path),
            "collection": receipt, "entry_collection": entry_collection}
