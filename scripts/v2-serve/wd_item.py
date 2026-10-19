"""G0 watchdog producer. Native actors retain every product authority."""

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import uuid

from wd_usage import Gate, private, save, wire
from wd_control import Evidence, FixedController, process


def sibling(name):
    spec = importlib.util.spec_from_file_location("wd_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


io, flow, common = sibling("item_context"), sibling("lifecycle"), sibling("case_grants")
FAMILIES = ("resources", "data", "secrets", "profiles", "network", "channels")
CHILD_TASK = b"# Watchdog quota fixture\nRetain the first task nonce in private history.\n"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def boot(case):
    provision = sibling("provision")
    # Installer inputs use protected source staging, independent of evidence.
    inputs = case.stage / "wd-boot-inputs"
    inputs.mkdir(mode=0o700)
    documents = []

    def document(name, kind, raw):
        ref = {"id": name, "class": kind, "sha256": sha(raw), "bytes": len(raw)}
        documents.append({"ref": ref, "data": base64.b64encode(raw).decode()})
        case.keep("wd-" + name + ".input", raw)
        return ref

    tree = document("wd-child-tree", "manifest", io.encoded({"schema": "laneboss.objects.v2", "entries": []}))
    case.keep("wd-wd-child-task.input", CHILD_TASK)
    expiry = (datetime.now(timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    root = {"schema": "laneboss.root-grants.v2", **{name: [] for name in FAMILIES}}
    root["profiles"] = [{"id": "", "profile_id": name, "driver": driver, "provider": "serve-fixture",
        "paid": False, "delegate": True, "expires_at": expiry} for name, driver in (
            ("serve-profile-claudock-cli", "claudock-cli"), ("wd-profile-b", "claudock-cli"), ("serve-profile-codex", "codex"))]
    case.fixture_profile_selectors = {"claudock-cli": "serve-profile-claudock-cli", "codex": "serve-profile-codex"}
    case.keep_json("wd-selectors.input.json", case.fixture_profile_selectors)
    root["data"] = [{"id": "", "source_object_id": tree["id"], "source_sha256": tree["sha256"], "relative_path": ".",
        "access": "rw", "delivery": "copy", "destination": "/data/wd-child", "delegate": True,
        "expires_at": expiry, "history_scope": "tree"}]
    sources = []
    for level, role in ((6, "supervisor"), (3, "executor")):
        for suffix, kind in (("md", "prompt"), ("toml", "drivers")):
            source = case.stage / "templates" / "v2" / "roles" / ("L" + str(level)) / (role + "." + suffix)
            sources.append({"id": "wd-l%d-%s" % (level, kind), "path": ".laneboss/L%d/roles/%s.%s" % (level, role, suffix),
                            "kind": kind, "data": base64.b64encode(source.read_bytes()).decode()})
    target_raw = os.urandom(48).hex().encode() + b"\n"
    # The outside canary observer keeps its separate private evidence file.
    target = case.keep("wd-target.input", target_raw)
    staged_target = provision.immutable_input(inputs, "wd-target.input", target_raw)
    mapped = int(Path("/proc/sys/kernel/overflowuid").read_text().strip())
    io.require(0 < mapped <= 2**32-1, "kernel has no distinct unmapped service identity")
    descriptor = {"schema": "laneboss.wd-runner.v1", "vendor_stood_in": True, "provider_socket": "/runtime/wd-provider.sock",
        "provider_uid": mapped, "history_dir": "wd-history", "canary": {"file": "/runtime/wd-target", "signal_pid": os.getpid()}}
    runtime_raw = io.encoded(descriptor)
    case.keep("wd-runtime.input.json", runtime_raw)
    runtime = provision.immutable_input(inputs, "wd-runtime.input.json", runtime_raw)
    budget = {"wall_ms": 1800000, "cpu_seconds": 120, "memory_bytes": 536870912, "processes": 32,
              "disk_bytes": 67108864, "spend_micros": 0, "currency": "USD"}
    case.wd_boot = {"tree": tree, "budget": budget, "target": str(target), "signal": process(os.getpid())}
    case.keep_json("wd-boot.input.json", case.wd_boot)
    return {"bundle": {"documents": documents, "sources": sources, "contexts": [{"level": 6, "role": "supervisor"}, {"level": 3, "role": "executor"}],
        "root_grants": root, "budget": budget, "projects": [{"id": "wd-child-enrollment", "generation": 1,
            "project_id": "wd-child", "object": tree, "base": tree["sha256"], "history_scope": "tree"}]},
        "assets": [{"id": "wd-run", "role": "watchdog-fixture", "file": str(runtime), "mode": 0o444},
                   {"id": "wd-target", "role": "watchdog-canary", "file": str(staged_target), "mode": 0o444}]}


class Relay(common.Relay):
    def __init__(self, *args):
        super().__init__(*args)
        self.raw = bytearray()

    def values_now(self):
        for event in flow.events(self.case, self.record, self.require):
            if event["seq"] in self.seen:
                continue
            self.seen.add(event["seq"])
            if event["kind"] == "capture.gap":
                raise self.fail("watchdog actor capture has a gap")
            if event["kind"] != "capture.appended":
                continue
            capture = event["payload"]
            if capture.get("stream") != "stdout":
                continue
            actor = event.get("actor", {})
            self.require(event["origin"] == "service" and actor.get("kind") in {"service", "worker"}
                and not actor.get("life_id") and event["operation_id"] == self.record["operation"]["id"]
                and capture.get("target") == self.record["target"] and capture.get("primary") is True
                and capture.get("binding_id") and capture.get("coverage") in {"partial", "complete"}
                and capture.get("offset") == self.offset and not capture.get("replacement_of"),
                "watchdog primary actor bytes are uncorrelated or discontinuous")
            if capture.get("eof"):
                continue
            raw = self.capture_blob(capture["data"])
            self.offset += len(raw)
            self.raw.extend(raw)
            self.pending.extend(raw)
            while b"\n" in self.pending:
                line, _, remaining = self.pending.partition(b"\n")
                self.pending = bytearray(remaining)
                value = json.loads(line)
                self.require(isinstance(value, dict), "watchdog actor emitted a non-object line")
                self.values.append(value)
                if value.get("type") == "watchdog.reply" and not value.get("nonce"):
                    self.refusal(value)
        return self.values

    def request(self, command, request, *, denied=False, request_id=None, key=None):
        self.require(not self.record.get("refused"), "watchdog actor stopped at its first unexpected refusal")
        saved, nonce = self.case.current, uuid.uuid4().hex
        envelope = {"schema": "laneboss.item-rpc.v1", "nonce": nonce, "command": command, "request": request,
                    "request_id": request_id or uuid.uuid4().hex, "idempotency_key": key or uuid.uuid4().hex}
        self.case.keep_json("wd-rpc-" + nonce[:20] + ".input", envelope)
        content = self.case.human.upload("wd-relay-input", "report", io.encoded(envelope))
        mail = {"recipient_life_id": self.record["target"]["life_id"], "content": content, "ask": False}
        proof = self.case.human.proof("control", "mail.send", mail, mail["recipient_life_id"], self.status()["generation"])
        self.case.current = saved
        accepted = self.case.human.rpc("wd-relay-mail", ["mail", "send"], mail, proof)
        self.require(accepted.get("content") == content and accepted.get("recipient_life_id") == mail["recipient_life_id"], "watchdog relay mail differs")
        result = self.wait("watchdog.exiting" if command == "fixture exit" else "watchdog.reply", nonce)
        self.case.current = saved
        if not denied:
            self.refusal(result)
        elif result.get("exit_code") != 0:
            error = json.loads(base64.b64decode(result["stderr"], validate=True))
            error = error.get("error", error)
            if result.get("exit_code") != 2 or error.get("code") != "conflict":
                self.record["refused"] = True
                self.refusal(result)
        return {"exit_code": result["exit_code"], "stdout": result.get("stdout") or "", "stderr": result.get("stderr") or ""}


def reply(raw, exit_code=0, diagnostic=b""):
    return {"exit_code": exit_code, "stdout": base64.b64encode(raw).decode(), "stderr": base64.b64encode(diagnostic).decode()}


class Installed:
    def __init__(self, case, require, fail):
        self.case, self.require, self.fail = case, require, fail
        self.operations, self.reader = [], None
        self.provider, self.controller = None, None
        self.control_done, self.control_error = threading.Event(), None
        self.context = None
        self.collection_started = False

    def reader_open(self):
        if self.reader is None:
            sys.path.insert(0, str(self.case.stage / "e2e" / "v2"))
            from readsession import SessionReader
            proof = self.case.human.proof("read", "human.session", {}, self.case.human.public["principal_id"], 0)
            self.reader = SessionReader(self.case.binary, self.case.config, self.case.installed["binding_file"], proof,
                self.case.root / "wd-reader", {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, command=("internal", "reader"))
        if self.reader.child is None or datetime.fromisoformat(self.reader.session["expires_at"]).timestamp() <= time.time()+10:
            self.reader.proof_file = self.case.human.proof("read", "human.session", {}, self.case.human.public["principal_id"], 0)
        self.reader.ensure_open()
        return self.reader.session

    def start_provider(self, profiles):
        case, service = self.case, self.case.admin["service"]
        base = Path(case.installed["socket"]).parent / "workers"
        base.mkdir(mode=0o700, exist_ok=True)
        self.require(base.stat().st_uid == service["uid"], "worker endpoint directory has another owner")
        directory = base / "wd-provider"
        directory.mkdir(mode=0o700)
        os.chown(directory, service["uid"], service["gid"])
        self.provider_dir, self.provider_socket = directory, base / "wd-provider.sock"
        self.phase = directory / "phase.json"
        script = directory / "provider.py"
        io.keep(script, Path(__file__).with_name("wd_usage.py").read_bytes())
        os.chown(script, service["uid"], service["gid"])
        setup = {"schema": "laneboss.wd-provider-setup.v1", "directory": str(directory), "socket": str(self.provider_socket),
            "control": str(self.phase), "profiles": profiles, "case_uid": os.getuid(),
            "runner_uids": [row["uid"] for row in case.admin["lanes"]], "usage_uid": None, "capacity": 7, "socket_gid": service["gid"]}
        setup_file = directory / "setup.json"
        io.keep(setup_file, io.encoded(setup))
        os.chown(setup_file, service["uid"], service["gid"])
        self.provider_out = (case.root / "wd-provider.stdout").open("xb")
        self.provider_err = (case.root / "wd-provider.stderr").open("xb")
        self.provider = subprocess.Popen(["/usr/bin/python3", "-I", "-B", str(script), "--setup", str(setup_file)],
            stdin=subprocess.DEVNULL, stdout=self.provider_out, stderr=self.provider_err,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, user=service["uid"], group=service["gid"], extra_groups=[])
        deadline = time.monotonic()+15
        while not self.provider_socket.exists():
            self.require(self.provider.poll() is None and time.monotonic() < deadline, "outside usage provider failed to start; retain exact stderr")
            time.sleep(0.05)
        self.provider_socket.chmod(0o666)
        case.keep_json("wd-provider-process.json", process(self.provider.pid))

    def native_probe(self, target, source, canary_id):
        proposal = copy.deepcopy(self.child)
        proposal["lane"] = "wd-probe-" + uuid.uuid4().hex[:8]
        proposal["budget"] = dict(proposal["budget"], wall_ms=90000)
        proposal["task"] = self.relay.upload("task", b"WD-PROBE " + base64.b64encode(source) + b"\n")
        operation = self.relay.call("lane start", proposal)
        self.operations.append(operation["id"])
        record = {"name": "wd-probe", "target": {"life_id": operation["life_id"], "run": operation["run"]}, "operation": operation, "collected": False}
        self.case.item_lives.append(record)
        flow.await_operation(self.case, operation, self.require, self.fail, record["target"])
        actor = Relay(self.case, record, self.require, self.fail)
        actor.wait("watchdog.probe-ready")
        identity = [e["payload"] for e in flow.events(self.case, record, self.require) if e["kind"] == "identity.bound" and e["payload"].get("kind") == "agent"]
        self.require(len(identity) == 1, "probe has no unique actual agent binding")
        binding, = identity
        group = Path("/sys/fs/cgroup/system.slice") / ("laneboss-helper@" + self.case.config + ".service") / "lanes" / binding["containment_id"]
        candidates = []
        for raw in (group / "cgroup.procs").read_text().split():
            pid = int(raw)
            try:
                fact = process(pid)
                if fact["uid"] == binding["host_uid"] and io.sha(Path("/proc") / str(pid) / "exe") == self.case.agent["sha256"]:
                    candidates.append(fact)
            except (FileNotFoundError, ProcessLookupError):
                continue
        self.require(len(candidates) == 1, "probe has no unique measured native fixture process")
        installed, fact = self, candidates[0]

        class Handle:
            pid, uid, cgroup, job_id = fact["pid"], fact["uid"], str(group), operation["id"]

            def wait(self, timeout):
                release = installed.relay.upload("report", io.encoded({"schema": "laneboss.wd-probe-release.v1", "nonce": json.loads(source)["nonce"]}))
                installed.relay.call("mail send", {"recipient_life_id": record["target"]["life_id"], "content": release, "ask": False})
                deadline = time.monotonic()+timeout
                while True:
                    lane, observed = common.checked(installed.case, record["target"], installed.require)
                    if observed["state"] == "exited":
                        installed.require(observed.get("survivors") == 0 and type(observed.get("exit_code")) is int, "probe wait lacks native exit/zero survivors")
                        record["observation"] = observed
                        return observed["exit_code"]
                    installed.require(time.monotonic() < deadline, "probe did not finish before its fixed deadline")
                    time.sleep(0.1)

            def primary(self):
                actor.values_now()
                return bytes(actor.raw)

        return Handle()

    def populate(self, context):
        self.context = context
        evidence = Evidence(context["evidence_root"], os.getuid())
        enrollment = {"schema": "laneboss.wd-controller.v1", "service_id": "wd-service", "unit": "laneboss-service@" + self.case.config + ".service",
            "canary_id": "wd-canary", "file": "/runtime/wd-target", "signal_pid": self.case.wd_boot["signal"]["pid"], "service_uid": self.case.admin["service"]["uid"]}
        self.controller = FixedController(context, enrollment, read_blob=self.relay.capture_blob,
            native_probe=self.native_probe, evidence=evidence, file_observer=self.case.wd_boot["target"])
        # Task objects use the same exact bounded read/hash checks as captures.
        def read_blob(ref):
            selected = dict(ref)
            self.require(selected["class"] == "task", "controller input is not an actual task object")
            return self.blob(selected)
        self.controller.read_blob = read_blob
        endpoint = self.case.root / "wd-control.sock"
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(endpoint)); endpoint.chmod(0o600)
        self.listener.listen(2); self.listener.settimeout(0.25)
        def serve():
            try:
                while not self.control_done.is_set():
                    try:
                        self.controller.serve_one(self.listener)
                    except socket.timeout:
                        continue
            except Exception as error:
                self.control_error = error
                self.control_done.set()
        self.control_thread = threading.Thread(target=serve, daemon=True)
        self.control_thread.start()
        io.keep(self.controls, io.encoded({"schema": "laneboss.e2e-control-binding.v2", "case_id": "watchdog", "config": context["config"],
            "socket": str(endpoint), "generation": 1, "controller_uid": os.getuid(), "case_uid": os.getuid(), "binary_sha256": context["binary_sha256"],
            "source_sha256": context["source_sha256"], "live_auth": False, "service_ids": ["wd-service"], "canary_ids": ["wd-canary"], "fixture_clock_ids": []}))
        service, refs = self.controller.service()
        self.reader_open()
        setup = {"schema": "laneboss.watchdog-case.v2", "start": self.child, "review": {}, "task_file": "wd-task.md", "mail_file": "wd-mail.md", "control": "wd-phase.json",
            "reader_binding": str(self.case.installed["binding_file"]), "canary_id": "wd-canary", "restart": {"service_id": "wd-service", "expected_generation": service["generation"]}}
        return {"setup.json": io.encoded(setup), "wd-task.md": b"# Watchdog quota fixture\nRetain the original task history.\n",
                "wd-mail.md": b"Continue the existing logical turn from private history.\n"}

    def blob(self, ref):
        raw = bytearray()
        while len(raw) < ref["bytes"]:
            part = self.relay.call("blob read", {"object_id": ref["id"], "offset": len(raw), "limit": min(262144, ref["bytes"]-len(raw))})
            data = base64.b64decode(part["data"], validate=True)
            self.require(part["offset"] == len(raw) and part["object_id"] == ref["id"] and data and sha(data) == part["sha256"], "controller input chunk differs")
            raw.extend(data)
        self.require(len(raw) == ref["bytes"] and sha(raw) == ref["sha256"], "controller input differs from committed bytes")
        return bytes(raw)

    def transport(self, request):
        self.case.current = "item.watchdog.run"
        command, body = request["command"], request["request"]
        if command == "fixture phase":
            raw = wire(body)
            temporary = self.phase.with_name("phase-" + uuid.uuid4().hex[:12])
            io.keep(temporary, raw)
            temporary.replace(self.phase)
            self.require(self.phase.read_bytes() == raw, "outside provider phase read-back differs")
            return reply(io.encoded({"sha256": sha(raw), "bytes": len(raw)}))
        if command == "fixture reader-open":
            return reply(io.encoded(self.reader_open()))
        if command == "fixture reader-close":
            return reply(io.encoded({"exit_code": self.reader.close(success=True)}))
        if command.startswith("dashboard "):
            self.reader_open()
            completed = self.reader.read(command.replace(" ", "."), io.encoded(body), request["request_id"], request["idempotency_key"])
            return reply(completed.stdout, completed.returncode, completed.stderr)
        if command == "fixture review-input":
            from wd_review import measure
            return reply(measure(self, body))
        result = self.relay.request(command, body, denied=request.get("denied", False), request_id=request["request_id"], key=request["idempotency_key"])
        if result["exit_code"] == 0 and command in {"lane start", "lane turn", "lane resume", "lane stop", "lane mark", "lane clean"}:
            operation = json.loads(base64.b64decode(result["stdout"], validate=True))
            self.operations.append(operation["id"])
            if command == "lane start":
                self.case.item_lives.append({"name": "wd-child", "operation": operation,
                    "target": {"life_id": operation["life_id"], "run": operation["run"]}, "collected": False})
        return result

    def collect(self, context, operations):
        case, require, fail = self.case, self.require, self.fail
        case.current, case.human_prefix = "item.watchdog.collection", "itemwatchdog"
        require(not self.collection_started, "watchdog collection stopped at its original gate")
        self.collection_started = True
        require(not any(row.get("refused") for row in case.item_lives), "watchdog collection stopped at an unexpected native refusal")
        observed = []
        for record in reversed(case.item_lives):
            if record.get("collected"):
                continue
            page = case.human.read("wd-last-run", ["lane", "list"], {"life_id": record["target"]["life_id"], "cursor": "", "limit": 200})
            require(not page.get("cursor") and len(page["lanes"]) == 1, "watchdog collector lost its exact life")
            record["target"] = {"life_id": page["lanes"][0]["life_id"], "run": page["lanes"][0]["run"]}
            lane, observation = common.checked(case, record["target"], require)
            if observation["state"] == "running":
                if record.get("relay") is not None:
                    record["relay"].request("fixture exit", {})
                else:
                    reason = case.human.upload("wd-stop-reason", "task", b"Collect the owned watchdog fixture.\n")
                    operation = flow.control(case, "wd-stop", "lane.stop", {"target": record["target"], "expected_generation": lane["generation"], "reason": reason}, lane["life_id"], lane["generation"])
                    self.operations.append(operation["id"])
                    flow.await_operation(case, operation, require, fail, record["target"])
            deadline = time.monotonic()+120
            while True:
                lane, observation = common.checked(case, record["target"], require)
                if observation["state"] == "exited":
                    require(observation.get("survivors") == 0, "watchdog collector found actual survivors")
                    break
                require(time.monotonic() < deadline, "watchdog collector did not reach quiescence")
                time.sleep(0.25)
            record["observation"] = observation
            if not lane.get("cleaned"):
                empty = {"id": "", "sha256": "", "bytes": 0, "class": ""}
                review = {"id": "", "reviewer": {"kind": "", "id": ""}, "diff": empty, "checks": [], "record_inventory": empty, "refusal_resolution": [], "coverage": ""}
                operation = flow.control(case, "wd-abandon", "lane.mark", {"target": record["target"], "expected_generation": lane["generation"], "state": "abandoned", "review": review}, lane["life_id"], lane["generation"])
                self.operations.append(operation["id"])
                flow.await_operation(case, operation, require, fail, record["target"])
                lane = case.human.read("wd-abandoned", ["lane", "status"], record["target"])
                archive = flow.control(case, "wd-archive", "lane.archive", {"target": record["target"], "expected_generation": lane["generation"]}, lane["life_id"], lane["generation"])
                require(archive["archive_sha256"] == archive["read_back_sha256"], "watchdog archive read-back differs")
                lane = case.human.read("wd-archived", ["lane", "status"], record["target"])
                operation = flow.control(case, "wd-clean", "lane.clean", {"target": record["target"], "expected_generation": lane["generation"], "archive_receipt_id": archive["id"]}, lane["life_id"], lane["generation"])
                self.operations.append(operation["id"])
                completed = flow.await_operation(case, operation, require, fail, record["target"])
                native = case.native_cleanup_evidence(record, lane, completed)
                require(native["action"] == "remove_clean", "watchdog native workspace was retained")
            lane = case.human.read("wd-collected", ["lane", "status"], record["target"])
            require(lane.get("cleaned") is True, "watchdog cleanup was not committed")
            releases = [e["payload"] for e in flow.events(case, record, require) if e["kind"] == "helper.released" and e["payload"].get("containment_id") == observation["handle"]["containment_id"]]
            require(len(releases) == 1, "watchdog has no unique measured helper release")
            common.release(releases[0], record["target"], releases[0]["operation_id"], require)
            observed.append({"target": record["target"], "observation": observation, "outside": common.native_zero(case, releases[0], require)})
            record["collected"] = True
        if self.reader is not None:
            require(self.reader.close(success=True) == 0, "independent reader did not exit successfully")
            observed.append({"reader": json.loads((self.reader.root / "sessions.json").read_bytes())})
        if self.controller is not None:
            self.control_done.set()
            self.control_thread.join(timeout=65)
            require(not self.control_thread.is_alive() and self.control_error is None, "watchdog controller did not collect cleanly")
            endpoint = Path(self.listener.getsockname())
            self.listener.close()
            endpoint.unlink()
        if self.provider is not None:
            require(self.provider.poll() is None, "outside usage provider ended unexpectedly")
            before = process(self.provider.pid)
            self.provider.terminate()
            code = self.provider.wait(timeout=15)
            self.provider_out.close(); self.provider_err.close()
            ledger = private(self.provider_dir / "ledger.json", {case.admin["service"]["uid"]})
            ref = io.keep(Path(context["evidence_root"]) / "outside-quota-ledger.json", ledger)
            observed.append({"provider": before, "exit_code": code, "ledger": ref})
            self.provider_socket.unlink()
        if getattr(self, "review_policy", None) is not None:
            require(self.review_policy.stat().st_uid == 0 and
                    self.review_policy.read_bytes() == (case.root / "wd-review-requirements.input.json").read_bytes(),
                    "watchdog review policy changed before collection")
            self.review_policy.unlink()
        ref = io.keep(Path(context["evidence_root"]) / "outside-collection.json", io.encoded({"observations": observed, "operation_ids": list(dict.fromkeys([*operations, *self.operations]))}))
        return {"processes_quiescent": all(row.get("collected") for row in case.item_lives), "temporary_resources_collected": all(row.get("collected") for row in case.item_lives),
                "operation_ids": list(dict.fromkeys([*operations, *self.operations])), "evidence": [ref]}


def prepare(case, require, fail, blocked):
    case.human_prefix, case.current = "itemwatchdog", "item.watchdog.prepare"
    installed = Installed(case, require, fail)
    case.wd_item = installed
    proposal = case.decode_document(case.root_launch_input(case.lane_inputs))["codex"]
    proposal.update(lane="wd-parent-" + uuid.uuid4().hex[:8], level=6, role="supervisor")
    ticket = case.human.ticket(proposal, case.root_grants)
    ceiling = case.human.read("wd-root-grants", ["grants", "get"], {"grant_set_id": ticket["grant_set_id"]})
    proposal["grants"]["profiles"] = [{"parent_grant_id": row["id"], "profile_id": row["profile_id"], "delegate": row["delegate"], "expires_at": row["expires_at"]} for row in ceiling["profiles"]]
    proposal["root_ticket_id"] = ticket["id"]
    proof = case.human.proof("read", "human.session", {}, case.human.public["principal_id"], 0)
    operation = case.checked_cli("wd-parent-start", ["lane", "start"], proposal, idempotency_key=uuid.uuid4().hex, session_proof=str(proof))
    record = {"name": "wd-parent", "target": {"life_id": operation["life_id"], "run": operation["run"]}, "operation": operation, "collected": False}
    case.item_lives.append(record)
    installed.operations.append(operation["id"])
    flow.await_operation(case, operation, require, fail, record["target"])
    relay = Relay(case, record, require, fail)
    installed.relay = record["relay"] = relay
    ready = relay.wait("watchdog.ready")
    raw = base64.b64decode(ready["binding_bytes"], validate=True)
    require(json.loads(raw) == ready["binding"] and ready["metadata_only"] is True and ready["identity"]["actor"]["level"] == 6,
            "watchdog actor did not retain its original sealed L6 identity")
    binding = case.keep("wd-binding.input.json", raw)
    lane = relay.status()
    grants = relay.call("grants get", {"grant_set_id": lane["grant_set_id"]})
    profiles = [row for row in grants["profiles"] if row["driver"] == "claudock-cli"]
    from case_watchdog import selected_profiles
    selected_profiles(grants, [row["id"] for row in profiles])
    require(len(profiles) == 2, "watchdog needs exactly two issued Claudock selectors")
    source = next(row for row in grants["data"] if row["source_object_id"] == case.wd_boot["tree"]["id"])
    delegated = {name: [] for name in FAMILIES}
    delegated["data"] = [{"parent_grant_id": source["id"], "relative_path": ".", "access": "rw", "delivery": "copy", "destination": "/work/main", "delegate": False, "expires_at": source["expires_at"]}]
    delegated["profiles"] = [{"parent_grant_id": row["id"], "profile_id": row["profile_id"], "delegate": False, "expires_at": row["expires_at"]} for row in profiles]
    # A later task is outside the initial publication's selected closure.
    # Commit its retained bytes through the actual parent before naming it.
    task = relay.upload("task", CHILD_TASK)
    case.keep_json("wd-child-task-upload.json", task)
    installed.child = {"lane": "wd-child", "project_id": "wd-child", "level": 3, "role": "executor", "task": task,
        "grants": delegated, "driver": "claudock-cli", "profile_grant_id": profiles[0]["id"], "model": case.agent["version"], "effort": "low",
        "budget": dict(case.wd_boot["budget"], wall_ms=360000), "expected_policy_generation": lane["policy_generation"]}
    installed.controls = case.root / "wd-controls.json"
    requirements = {"schema": "laneboss.review-requirements.v2", "config": case.config,
                    "policy_generation": lane["policy_generation"],
                    "projects": [{"project_id": "wd-child", "checks": ["snapshot-integrity"]}]}
    case.keep_json("wd-review-requirements.input.json", requirements)
    policy_path = Path("/etc/laneboss-v2/review") / (case.config + ".json")
    policy_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    require(not policy_path.exists(), "watchdog review requirements already exist")
    io.keep(policy_path, io.encoded(requirements))
    policy_path.chmod(0o644)
    require(policy_path.read_bytes() == io.encoded(requirements) and policy_path.stat().st_uid == 0,
            "watchdog protected review requirements read-back differs")
    installed.review_policy = policy_path
    installed.start_provider([row["profile_id"] for row in profiles])
    case.current = "item.watchdog.prepare"
    return {"binding_file": binding, "profile_grant_ids": [row["id"] for row in profiles], "controls": str(installed.controls),
            "populate": installed.populate, "transport": installed.transport, "collect": installed.collect}


def abort(case, require, fail):
    installed = getattr(case, "wd_item", None)
    if installed is None:
        return []
    if not installed.collection_started and not any(row.get("refused") for row in case.item_lives):
        case.human_prefix = "itemwatchdog"
        root = case.root / "wd-abort-evidence"
        root.mkdir(mode=0o700)
        receipt = installed.collect({"evidence_root": str(root)}, installed.operations)
        case.keep_json("wd-abort-collection.json", {"collection": receipt, "acceptance": "not credited; original failure retained"})
    return [{"target": row["target"], "reason": "watchdog collection incomplete; preserve its original failure"}
            for row in case.item_lives if not row.get("collected")]
