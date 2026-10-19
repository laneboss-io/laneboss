"""Installed Linux case producer; authority stays outside the tested lane.

The serve owner calls prepare() at its installed checkpoint.  This module
does not install, enroll, authenticate, change kernel policy, or start an AI
request on its own.  Missing native or live inputs are retained owner gates.
"""

from datetime import datetime, timedelta, timezone
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
CASE = ROOT / "e2e/v2/cases/linux"
DRIVERS = ("claudock-cli", "codex")
HOOKS = ("absent", "allow")
REDS = (
    "linux-broad-root", "linux-writable-nested", "linux-inherited-fd",
    "linux-no-landlock", "linux-no-network", "linux-no-cgroup",
    "linux-false-zero", "linux-unmeasured-release",
)


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


io = module("linux_item_context", Path(__file__).with_name("item_context.py"))


class MissingGate(RuntimeError):
    code = "prerequisite_missing"

    def __init__(self, gate, owner):
        self.gate, self.owner = gate, owner
        super().__init__(owner + ": " + gate)

    def record(self):
        return {"schema": "laneboss.linux-wait.v1",
                "code": "prerequisite_missing", "owner": self.owner,
                "gate": self.gate, "completed": False}


def ordinary(path, *, private=False, owner=None, limit=1024 * 1024):
    """Read exact regular bytes without following any path component."""
    path = Path(path)
    require(path.is_absolute(), "input path is not absolute")
    require(path.resolve(strict=True) == path, "input path is not canonical")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    fd = None
    try:
        for component in path.parts[1:-1]:
            info = os.fstat(directory)
            if private:
                require(info.st_uid == owner and not info.st_mode & 0o022,
                        "authority ancestor is writable or foreign")
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        if private:
            require(info.st_uid == owner and not info.st_mode & 0o022,
                    "authority ancestor is writable or foreign")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                     os.O_CLOEXEC, dir_fd=directory)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                0 < before.st_size <= limit,
                "input must be a bounded ordinary file")
        if private:
            require(before.st_uid == owner and
                    stat.S_IMODE(before.st_mode) == 0o600,
                    "authority file must be private to its owner")
        raw = os.read(fd, limit + 1)
        after = os.fstat(fd)
        require(len(raw) == before.st_size and
                (before.st_dev, before.st_ino, before.st_size,
                 before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns),
                "input changed during observation")
        return raw
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def put(path, raw, mode=0o600):
    """Publish once; preserve an existing input or failed attempt."""
    path = Path(path)
    require(path.parent.resolve(strict=True) == path.parent,
            "output parent is not canonical")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return path


def relative(root, name):
    path = Path(name)
    require(bool(path.parts) and not path.is_absolute() and
            ".." not in path.parts, "case path escapes its input scope")
    result = root / path
    require(result.resolve().is_relative_to(root),
            "case path follows a link outside its input scope")
    return result


def live_authorization(raw, context, start, cell, now=None):
    """An explicit supervisor file is necessary, never inferred from a pin."""
    value = json.loads(raw)
    require(value.get("schema") == "laneboss.linux-live.v1" and
            value.get("config") == context["config"] and
            value.get("cell") == cell and
            value.get("allow_model_request") is True,
            "live authorization does not cover this installed cell")
    require(start.get("driver") in DRIVERS and
            start.get("profile_grant_id") in context["profile_grant_ids"],
            "a granted real driver profile is required")
    for name in ("driver", "profile_grant_id", "model", "effort", "budget"):
        require(value.get(name) == start.get(name) and value.get(name) is not None,
                "live authorization differs from start: " + name)
    require(value.get("runtime_sha256") and
            re.fullmatch(r"[a-f0-9]{64}", value["runtime_sha256"]),
            "live authorization lacks an enrolled runtime pin")
    expiry = datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
    require(expiry.tzinfo is not None and
            expiry > (now or datetime.now(timezone.utc)),
            "live authorization has expired")
    return value


def installed_real_runtime(case):
    """Verify the selected real driver, without relabeling the Codex fixture."""
    require(case.real_claudock and case.real_vendor is not None,
            "Linux real-key authorization requires the real vendor runtime")
    reference = case.installed["runtime_manifest"]
    require(reference == case.initial["runtime"],
            "Linux installed runtime differs from the publication")
    path = Path(case.binary).parent / "runtime" / case.config / "manifest.json"
    raw = ordinary(path)
    require(sha(raw) == reference["sha256"] and len(raw) == reference["bytes"],
            "Linux installed runtime bytes differ from enrollment")
    runtime = json.loads(raw)
    require(runtime.get("schema") == "laneboss.runtime.v2" and
            runtime["artifact"]["sha256"] == case.installed["artifact_sha256"],
            "Linux runtime belongs to another installed artifact")
    for name in ("claudock", "claude"):
        pin = case.real_vendor[name]["executable"]
        selected = [row for row in runtime["objects"]
                    if row["id"] == pin["id"] and row["role"] == name]
        require(len(selected) == 1 and selected[0]["mode"] == 0o555 and
                selected[0]["content"]["sha256"] == pin["sha256"],
                "Linux selected real executable differs from its runtime pin")
    enrollment = ordinary(case.root / "launch-enrollment.json.input")
    enrolled_ref = case.installed["launch_enrollment"]
    require(enrolled_ref == case.initial["launch_enrollment"] and
            sha(enrollment) == enrolled_ref["sha256"] and
            len(enrollment) == enrolled_ref["bytes"],
            "Linux launch enrollment differs from the installed publication")
    launch = json.loads(enrollment)
    selected = [row for row in launch["runtimes"] if row["driver"] == "claudock-cli"]
    require(launch["config"] == case.config and len(selected) == 1 and
            selected[0]["manifest"] == reference and
            selected[0]["executable"] == case.real_vendor["claudock"]["executable"] and
            selected[0]["session_executable"] == case.real_vendor["claude"]["executable"],
            "Linux driver does not select the enrolled real vendor")
    return reference["sha256"]


def authorize_real_key(case, plan, now=None):
    """Publish this harness supervisor's bounded installed-cell authority.

    Native fixtures and independent review remain their actual owner gates;
    neither can be invented from the existence of a working API credential.
    """
    require(getattr(case, "real_api_key", False) and
            getattr(getattr(case, "api_key_canary", None), "real", False) and
            case.item_case == "linux", "Linux live authorization requires a consumed real key")
    runtime_sha256 = installed_real_runtime(case)
    records = [record for record in case.lane_records if record["driver"] == "claudock-cli"]
    require(len(records) == 1 and records[0]["quiescent"],
            "Linux live authorization requires the measured baseline driver")
    start = copy.deepcopy(records[0]["request"])
    require(start["driver"] == "claudock-cli" and start.get("profile_grant_id"),
            "Linux start lacks its actual selected profile")
    budget = start["budget"]
    require(budget.get("currency") == "USD" and
            type(budget.get("spend_micros")) is int and 0 < budget["spend_micros"] <= 100000 and
            type(budget.get("wall_ms")) is int and 0 < budget["wall_ms"] <= 60000 and
            start.get("effort") == "low",
            "Linux real-key start exceeds the tiny smoke budget")
    grant_row = case.rows["human.claudock.grants"]
    require(grant_row["result"] == "pass", "Linux baseline root grants were not issued")
    granted = grant_row["observed"]
    grants = case.human.read("linux-root-grants", ["grants", "get"], {"grant_set_id": granted["id"]})
    case.current = "item.linux.prepare"
    require(grants == {key: value for key, value in granted.items() if key != "executed"} and
            not grants.get("revoked") and not grants.get("parent_life_id") and
            any(row["id"] == start["profile_grant_id"] and row["driver"] == start["driver"]
                for row in grants["profiles"]),
            "Linux selected profile differs from actual root grant read-back")
    current = now or datetime.now(timezone.utc)
    expiry = min(current + timedelta(hours=2),
                 datetime.fromisoformat(grants["expires_at"].replace("Z", "+00:00")))
    cell = plan.get("cell", "linux-real-key")
    require(isinstance(cell, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", cell),
            "invalid real-key Linux cell")
    start["lane"] = "linux-real-key"
    start.pop("root_ticket_id", None)  # Producer obtains a fresh ticket for these existing grants.
    context = {"config": case.config, "profile_grant_ids": [start["profile_grant_id"]]}
    authority = {name: copy.deepcopy(start[name]) for name in
                 ("driver", "profile_grant_id", "model", "effort", "budget")}
    authority.update(schema="laneboss.linux-live.v1", config=case.config, cell=cell,
                     allow_model_request=True, runtime_sha256=runtime_sha256,
                     expires_at=expiry.isoformat().replace("+00:00", "Z"))
    live_authorization(encoded(authority), context, start, cell, current)
    result = copy.deepcopy(plan)
    result.update(cell=cell, profile_grant_ids=context["profile_grant_ids"],
                  start_template=str(case.keep_json("linux-live-start.input.json", start)),
                  root_grant_set=str(case.keep_json("linux-live-grants.input.json", grants)),
                  authorization=str(case.keep_json("linux-live-authorization.input.json", authority)))
    case.linux_plan_file = case.keep_json("linux-live-plan.input.json", result)
    require(json.loads(case.linux_plan_file.read_bytes()) == result,
            "Linux generated plan read-back differs")
    return result


def matrix(measured=()):
    """Exact finite obligations; a current ABI above 3 never proves the floor."""
    measured = set(measured)
    rows = []
    for driver in DRIVERS:
        for restriction in (0, 1):
            for hook in HOOKS:
                for abi in ("current", "3"):
                    key = (driver, restriction, hook, abi)
                    rows.append({"driver": driver, "restriction": restriction,
                                 "hook": hook, "abi": abi,
                                 "state": "measured" if key in measured else
                                 "incomplete"})
    return rows


def driver_task(canary, source_sha, inputs, marker, output, input_sha=None):
    """The model must execute the shipped canary, with these exact bytes."""
    require(len(marker) >= 24 and re.fullmatch(r"[a-zA-Z0-9_-]+", marker),
            "unsafe or short process marker")
    for path in (canary, inputs, output):
        require(Path(path).is_absolute() and
                re.fullmatch(r"/[a-zA-Z0-9_./-]+", path) and
                ".." not in Path(path).parts, "unsafe driver task path")
    require(re.fullmatch(r"[a-f0-9]{64}", source_sha),
            "task requires the retained canary source digest")
    if input_sha is not None:
        require(re.fullmatch(r"[a-f0-9]{64}", input_sha),
                "task requires the exact canary input digest")
    handoff = " --wait-input-ms 180000"
    if input_sha is not None:
        handoff += " --input-sha256 " + input_sha
    return ("# Installed Linux boundary canary\n\n"
            "Execute this command once through your real shell tool.\n"
            "Do not replace it with a description or fabricate output.\n"
            "Retain the tool record and report its actual exit.\n"
            "The canary source SHA256 is " + source_sha + ".\n\n"
            "```sh\n/usr/bin/python3 -I -B " + canary +
            " --input " + inputs + " --marker " + marker +
            " --output " + output + handoff + "\n```\n\n"
            "After the command completes, remain available until the "
            "supervisor stops this disposable run. Do not commit or send "
            "network requests yourself.\n").encode()


class ProofCoordinator:
    """Synchronous handoff after the consumer retains each exact request.

    human is the existing installed serve HumanRoot.  No proof is generated
    by this module; human.challenge/confirm and the enrolled signer do that.
    """
    def __init__(self, root, human):
        self.root, self.human = Path(root), human
        self.authority = self.root / "authority"
        self.authority.mkdir(mode=0o700, exist_ok=True)
        info = self.authority.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
                stat.S_IMODE(info.st_mode) == 0o700,
                "unsafe private numbered authority directory")
        self.next_index = 1
        self.generations = {}

    def observed(self, words, body, result):
        if words == ["lane", "status"]:
            require(type(result.get("generation")) is int and
                    result["generation"] > 0,
                    "status lacks an actual generation for human intent")
            self.generations[body["life_id"]] = result["generation"]

    def supply(self, index, words, body):
        require(index == self.next_index, "human proof sequence differs")
        self.next_index += 1
        method = ".".join(words)
        reads = {"operation.get", "lane.status", "event.tail"}
        if method in reads or method == "lane.start":
            method, request = "human.session", {}
            target, generation = self.human.public["principal_id"], 0
        else:
            require(method in {"lane.stop", "lane.check", "lane.archive", "lane.review",
                               "lane.mark", "lane.clean"},
                    "unsupported Linux proof operation")
            request = body
            target = body["life_id"] if method == "lane.check" else body["target"]["life_id"]
            generation = body.get("expected_generation")
            if method in {"lane.review", "lane.check"}:
                generation = self.generations.get(target)
            require(type(generation) is int and generation > 0,
                    "operation lacks a current observed generation")
        label = "read" if method == "human.session" else "control"
        source = self.human.proof(label, method, request, target, generation)
        raw = ordinary(Path(source))
        value = json.loads(raw)
        require(value.get("id") and value.get("request_sha256") and
                value.get("expires_at"), "installed confirmation has no proof")
        path = self.authority / ("%06d.proof.json" % index)
        put(path, raw)
        put(self.authority / ("%06d.intent.json" % index), encoded({
            "method": method, "request": request, "target": target,
            "generation": generation, "proof_sha256": sha(raw)}))
        return path


def native_cell(raw, context, facts):
    """A pre-install fixture describes paths; it cannot predict a run lease."""
    value = json.loads(raw)
    require(value.get("schema") == "laneboss.linux-native.v1" and
            value.get("config") == context["config"] and
            value.get("artifact_sha256") == context["binary_sha256"],
            "native fixture belongs to another installation")
    cell = value["cell"]
    require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", cell["id"]),
            "invalid native cell identifier")
    require(cell["restriction"] == facts["restriction"] and
            cell["abi"] == facts["abi"] and cell["abi"] >= 3 and
            cell["hook"] in HOOKS and cell["inner_sandbox"] == "off",
            "native fixture differs from unchanged host policy")
    require(not any(key in cell for key in
                    ("lane_uid", "lane_gid", "cgroup_relative")) and
            "lease_journal" not in value,
            "a new start cannot use a preselected UID or old lease")
    require(set(value["protected"]) == {"readonly", "nested", "state", "sibling"},
            "native fixture lacks the four actual protected targets")
    for name, entry in value["protected"].items():
        require(entry["area"] in ("workspace", "absolute") and
                re.fullmatch(r"[a-f0-9]{64}", entry["sha256"]),
                "native target mapping or digest is invalid: " + name)
        if entry["area"] == "workspace":
            relative(Path("/"), entry["path"])
        else:
            require(Path(entry["path"]).is_absolute(),
                    "native outside target path is not absolute")
    return value


def plan_for(page, context, target, operation):
    require(page.get("complete") is True, "launch event snapshot is incomplete")
    found = [event for event in page["events"]
             if event.get("kind") == "launch.planned" and
             event.get("operation_id") == operation["id"]]
    require(len(found) == 1, "actual launch plan event is missing or ambiguous")
    event = found[0]
    require(event.get("config") == context["config"] and
            event.get("origin") == "service" and
            event.get("life_id") == target["life_id"] and
            event.get("run") == target["run"] and
            type(event.get("seq")) is int and event["seq"] > 0,
            "launch plan event belongs to another configuration or life")
    plan = event["payload"]["plan"]
    reservation = plan["reservation"]
    require(reservation["target"] == target and
            reservation["config"] == context["config"] and
            reservation["operation_id"] == operation["id"] and
            plan["data"]["target"] == target and
            plan["data"]["lease_id"] == plan["lease"]["id"],
            "planned lease or data differs from the started operation")
    return plan


def join_lease(raw, context, plan, clean_uids):
    value = json.loads(raw)
    lease, request = value["lease"], value["request"]
    reservation = plan["reservation"]
    require(value.get("schema") == "laneboss.helper-lease.v2" and
            value.get("phase") == "active" and value.get("boot_id") and
            lease == plan["lease"] and lease["uid"] in clean_uids and
            request["life_id"] == reservation["target"]["life_id"] and
            request["config"] == context["config"] and
            request["reservation_id"] == reservation["id"] and
            request["cause"]["cause_operation_id"] == reservation["operation_id"],
            "native fixture lease is not the actual started life")
    return value


class Producer:
    """Prepare one host cell using the installed serve authority object."""
    def __init__(self, serve, context):
        self.serve, self.context = serve, context
        self.root = Path(context["test_root"])
        self.consumer = module("linux_consumer", CASE / "run.py")
        self.targets = module("linux_outside_targets", CASE / "targets.py")
        self.proofs = None
        self.network = self.signal = self.echo = None
        self.public = None
        self.clean_uids = set()
        self.closed = False
        self.inputs = {}
        self.publish_inputs = True

    def input(self, name, raw):
        require(re.fullmatch(r"[A-Za-z0-9_.-]{1,39}", name) and
                name not in self.inputs, "duplicate or invalid Linux input")
        self.inputs[name] = raw
        if self.publish_inputs:
            put(self.root / name, raw)

    def wait(self, gate, owner):
        error = MissingGate(gate, owner)
        self.input("linux-wait.json", encoded(error.record()))
        raise error

    def prepare(self, plan, *, publish=True):
        self.publish_inputs = publish
        self.plan = plan
        require(self.context["case_id"] == "linux" and
                self.context["config"] == self.serve.config,
                "producer context differs from installed serve scope")
        require(sha(Path(self.context["binary"]).read_bytes()) ==
                self.context["binary_sha256"], "installed artifact pin differs")
        self.input("matrix-required.json", encoded(matrix()))
        if not self.context["profile_grant_ids"] or not plan.get("authorization"):
            self.wait("real_driver_authorization", "laneboss")
        start = json.loads(ordinary(Path(plan["start_template"])))
        auth_raw = ordinary(Path(plan["authorization"]), private=True, owner=0)
        auth = live_authorization(auth_raw, self.context, start, plan["cell"])
        self.input("live-authorization.json", auth_raw)
        if not plan.get("native_fixture"):
            self.wait("leased_native_fixture", "lb-v2-admin")
        facts = self.consumer.host_facts()
        raw = ordinary(Path(plan["native_fixture"]), private=True, owner=0)
        native = native_cell(raw, self.context, facts)
        self.native, self.auth, self.start = native, auth, start
        self.input("native-fixture.json", raw)
        cell = native["cell"]
        require(cell["id"] == plan["cell"] and
                native.get("runtime_sha256") == auth["runtime_sha256"],
                "cell runtime differs from explicit real-driver authority")
        require(self.serve.human is not None, "installed human coordinator absent")
        prepare_phase = getattr(self.serve, "current", None)
        for label in ("read", "control", "ticket", "grants"):
            for suffix in ("challenge", "confirm"):
                name = self.serve.human.check(label, suffix)
                self.serve.rows.setdefault(name, {
                    "check": name, "result": "fail", "presence": "simulated",
                    "observed": {"executed": False}})
        self.proofs = ProofCoordinator(self.root, self.serve.human)
        source = (CASE / "canary.py").read_bytes()
        logical = native["logical"]
        require(native["canary_sha256"] == sha(source),
                "enrolled canary differs from exact source bytes")
        # The public directory is a new canary fixture, never the private
        # context/proof directory. World traversal must not be denied by DAC.
        self.public = Path(tempfile.mkdtemp(
            prefix="lb-v2-case-linux-", dir=plan.get("public_parent", "/var/tmp"))).resolve()
        self.public.chmod(0o755)
        outside_raw = os.urandom(48)
        self.outside = put(self.public / "outside", outside_raw, mode=0o666)
        self.outside.chmod(0o666)
        self.input("outside-input.bin", outside_raw)
        self.signal = self.targets.SignalTarget()
        self.foreign_identity = self.consumer.process_identity(self.signal.pid)
        permitted = native["permitted"]
        require(type(permitted[1]) is int and 0 < permitted[1] < 65536,
                "permitted endpoint needs its actual enrolled nonzero port")
        self.echo = self.targets.EchoTarget(permitted)
        control = self.echo.control(os.urandom(32))
        self.input("permitted-control.json", encoded(control))
        self.network = self.consumer.NetworkObserver({
            "tcp4": ["127.0.0.1", 0], "udp4": ["127.0.0.1", 0],
            "tcp6": ["::1", 0], "udp6": ["::1", 0],
            "ipc": str(self.public / "foreign.sock")})
        marker = secrets.token_hex(16)
        inputs = {key: logical[key] for key in
                  ("work", "tmp", "home", "readonly", "nested")}
        inputs.update({"payload_hex": os.urandom(48).hex(),
                       "outside": str(self.outside),
                       "inherited_fd": native["inherited_fd"],
                       "foreign": dict(self.network.addresses, pid=self.signal.pid),
                       "permitted": list(self.echo.address)})
        require(type(inputs["inherited_fd"]) is int and inputs["inherited_fd"] >= 3,
                "native inherited descriptor fixture is missing")
        canary_raw = encoded(inputs)
        self.payload_sha = sha(bytes.fromhex(inputs["payload_hex"]))
        cell.update({"native_pending": True, "marker": marker,
                     "canary_input": "canary-input.json", "start_request": "start.json",
                     "outside": "outside", "outside_sha256": sha(outside_raw),
                     "worktree": "pending-worktree", "observation": "pending-output",
                     "protected": {name: {"path": entry["path"], "sha256": entry["sha256"]}
                                   for name, entry in native["protected"].items()}})
        task = driver_task(logical["canary"], sha(source), logical["input"],
                           marker, logical["output"], sha(canary_raw))
        self.input("canary-input.json", canary_raw)
        self.input("canary-source.py", source)
        self.input("driver-task.md", task)
        start["task"] = self.serve.human.upload("linux-task", "task", task)
        cell["stop_reason"] = self.serve.human.upload(
            "linux-stop", "report", b"Stop the installed Linux canary.\n")
        if not plan.get("root_grant_set"):
            self.wait("issued_root_grant_set", "lb-v2-grants")
        root_raw = ordinary(Path(plan["root_grant_set"]))
        root_grants = json.loads(root_raw)
        self.input("root-grant-set.json", root_raw)
        require(root_grants.get("id") and not root_grants.get("revoked") and
                not root_grants.get("parent_life_id") and
                any(row["id"] == start["profile_grant_id"]
                    for row in root_grants["profiles"]),
                "selected real profile is outside the actual root grant set")
        grant_proof = self.serve.human.proof("grants", "human.session", {},
            self.serve.human.public["principal_id"], 0)
        grant_check = self.serve.human.check("grants")
        self.serve.rows.setdefault(grant_check, {"check": grant_check, "result": "fail",
            "presence": "simulated", "observed": {"executed": False}})
        self.serve.current = grant_check
        actual_grants = self.serve.checked_cli("linux-grants-readback", ["grants", "get"],
            {"grant_set_id": root_grants["id"]}, proof=str(grant_proof))
        require(actual_grants == root_grants, "existing root grants differ from service read-back")
        self.serve.passed({"method": "grants.get", "grant_set": actual_grants,
                           "source": "existing committed grants; no grant issuance claimed"})
        expiry = min(datetime.fromisoformat(root_grants["expires_at"].replace("Z", "+00:00")),
                     datetime.now(timezone.utc) + timedelta(seconds=90))
        ticket_request = {"level": start["level"], "role": start["role"],
                          "grant_set_id": root_grants["id"],
                          "expires_at": expiry.isoformat().replace("+00:00", "Z")}
        proof = self.serve.human.proof("ticket", "ticket.issue", ticket_request,
                                       root_grants["id"], root_grants["generation"])
        ticket_check = self.serve.human.check("ticket")
        self.serve.rows.setdefault(ticket_check, {"check": ticket_check, "result": "fail",
            "presence": "simulated", "observed": {"executed": False}})
        self.serve.current = ticket_check
        ticket = self.serve.human.rpc("linux-ticket", ["ticket", "issue"], ticket_request, proof)
        require(ticket.get("id") and ticket.get("config") == self.context["config"] and
                all(ticket.get(key) == value for key, value in ticket_request.items()),
                "issued root ticket differs from its exact confirmed request")
        self.serve.passed(ticket)
        if prepare_phase is not None:
            self.serve.current = prepare_phase
        start["root_ticket_id"] = ticket["id"]
        live_authorization(auth_raw, self.context, start, cell["id"])
        self.input(cell["start_request"], encoded(start))
        fixture = {"schema": "laneboss.linux-case.v2",
                   "service_uid": self.installation()["service"]["uid"], "cells": [cell],
                   "red_controls": list(REDS)}
        require(self.context["phase"] != "red" or
                self.context["mutation_id"] in REDS,
                "unknown installed Linux red control")
        self.input("linux-input.json", encoded(fixture))
        return self

    def before_call(self, index, words, body):
        if self.proofs is None:
            raise MissingGate("human_coordinator", "lb-v2-identity")
        self.proofs.supply(index, words, body)

    def after_call(self, words, body, result):
        self.proofs.observed(words, body, result)

    def installation(self):
        raw = ordinary(Path(self.serve.installation_file), private=True, owner=0)
        value = json.loads(raw)
        require(value.get("schema") == "laneboss.admin.v2" and
                value.get("config") == self.context["config"] and
                value["artifact"]["sha256"] == self.context["binary_sha256"],
                "native installation differs from this case artifact")
        return value

    def before_start(self, case, cell):
        installed = self.installation()
        inventory = {}
        self.accounts = {}
        for account in installed["lanes"]:
            uid = account["uid"]
            require(type(uid) is int and uid > 0 and
                    uid not in (os.geteuid(), installed["service"]["uid"]),
                    "installed lane pool overlaps observer or service")
            inventory[str(uid)] = self.consumer.uid_processes(uid)
            self.accounts[uid] = account["gid"]
            if not inventory[str(uid)]:
                self.clean_uids.add(uid)
        case.keep("native/uid-before.json", encoded(inventory))
        require(bool(self.clean_uids), "installed UID pool has no observed clean account")
        self.check_foreign(case, "before-start")

    def after_start(self, case, record, operation):
        target = record["target"]
        page = case.call(["event", "tail"], {
            "life_id": target["life_id"], "run": target["run"], "since": 0,
            "cursor": "", "follow": False, "until": "", "deadline_ms": 1000})
        plan = plan_for(page, self.context, target, operation)
        case.keep("native/launch-plan.json", encoded(plan))
        require(plan["runner"]["executable"]["sha256"] == self.auth["runtime_sha256"] and
                plan["runner"]["driver"] == self.start["driver"] and
                plan["runner"]["inner_sandbox"] == "off",
                "actual runner differs from authorized real driver or inner-sandbox mode")
        lease_id = plan["lease"]["id"]
        require(re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", lease_id),
                "helper lease selector is invalid")
        helper = Path("/var/lib/laneboss-v2/helper") / self.context["config"]
        lease_raw = ordinary(helper / (lease_id + ".json"), private=True, owner=0)
        lease = join_lease(lease_raw, self.context, plan, self.clean_uids)
        case.keep("native/helper-lease.json", lease_raw)
        selected = lease["lease"]
        require(type(selected["gid"]) is int and selected["gid"] > 0 and
                selected["gid"] == self.accounts[selected["uid"]],
                "actual leased GID differs from the installed clean account")
        cell = record["cell"]
        record["uid"] = cell["lane_uid"] = selected["uid"]
        cell["lane_gid"] = selected["gid"]
        cell["cgroup_relative"] = str(Path("/system.slice") /
            ("laneboss-helper@" + self.context["config"] + ".service") /
            "lanes" / selected["containment_id"])
        case.call(["lane", "status"], target)
        observed = case.call(["lane", "check"], target)
        require(observed["handle"]["containment_id"] ==
                selected["containment_id"],
                "started process differs from retained native lease")
        workspace = plan["data"]["workspace"]
        workspace_id = workspace["id"]
        require(re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", workspace_id),
                "workspace selector is invalid")
        enrollment_raw = ordinary(helper / "workspaces" / (workspace_id + ".json"),
                                  private=True, owner=0)
        enrollment = json.loads(enrollment_raw)
        actual = enrollment["Workspace"]
        require(enrollment.get("Schema") == "laneboss.workspace-native.v2" and
                enrollment.get("Config") == self.context["config"] and
                enrollment.get("LeaseID") == lease_id and
                actual["ID"] == workspace_id and actual["Target"] == target,
                "native workspace enrollment is foreign to this actual run")
        worktree = Path(enrollment["Parent"]) / workspace_id
        require(worktree.resolve(strict=True) == worktree,
                "native workspace path is not canonical")
        info = worktree.lstat()
        require("%d:%d" % (info.st_dev, info.st_ino) == actual["DirectoryIdentity"],
                "native workspace inode differs from its helper enrollment")
        case.keep("native/workspace.json", enrollment_raw)
        paths = {"outside": str(self.outside), "worktree": str(worktree)}
        cwd = Path(workspace["logical_cwd"])
        for name in ("input", "output", "work"):
            subpath = str(Path(self.native["logical"][name]).relative_to(cwd))
            paths["observation" if name == "output" else name] = str(relative(worktree, subpath))
        for name, entry in self.native["protected"].items():
            path = relative(worktree, entry["path"]) if entry["area"] == "workspace" else Path(entry["path"])
            require(path.resolve(strict=True) == path, "delivered protected target is not canonical")
            paths[name] = str(path)
        cell["observer_paths"] = paths
        self.worktree = worktree
        self.descriptor_control(case, selected, target)

    def descriptor_control(self, case, lease, target):
        path = self.plan.get("descriptor_observation")
        if not path or not Path(path).exists():
            raise MissingGate("helper_fd_canary", "lb-v2-admin")
        raw = ordinary(Path(path), private=True, owner=0)
        value = json.loads(raw)
        require(value.get("config") == self.context["config"] and
                value.get("target") == target and value.get("lease_id") == lease["id"] and
                value.get("stage") == "helper_pre_exec" and
                value.get("descriptor") == self.native["inherited_fd"],
                "descriptor observation is not the actual helper pre-exec stage")
        pid = value["host_pid"]
        require(type(pid) is int and pid > 0, "descriptor producer PID is invalid")
        identity = self.consumer.process_identity(pid)
        membership = "/system.slice/laneboss-helper@" + self.context["config"] + ".service/control"
        require(identity is not None and identity["start_time"] == value["start_time"] and
                identity["uids"] == [0] * 4 and "0::" + membership in identity["cgroup"],
                "descriptor control is not held by the actual installed helper")
        info_path = Path("/proc") / str(pid) / "fdinfo" / str(value["descriptor"])
        info = dict(line.split(":", 1) for line in info_path.read_text().splitlines())
        require(not int(info["flags"].strip(), 8) & os.O_CLOEXEC,
                "descriptor control was already close-on-exec before the tested boundary")
        fd = os.open(Path("/proc") / str(pid) / "fd" / str(value["descriptor"]),
                     os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            planted = os.read(fd, 4097)
        finally:
            os.close(fd)
        require(0 < len(planted) <= 4096 and sha(planted) == value["planted_sha256"],
                "real helper descriptor bytes differ from the planted canary")
        case.keep("native/descriptor-control.json", raw)

    def release_input(self, case, record, raw):
        paths = record["cell"]["observer_paths"]
        uid, gid = record["cell"]["lane_uid"], record["cell"]["lane_gid"]
        def directory(path):
            subpath = path.relative_to(self.worktree)
            require(".." not in subpath.parts, "input directory escapes the real workspace")
            fd = os.open(self.worktree, os.O_RDONLY | os.O_DIRECTORY |
                         os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                for part in subpath.parts:
                    created = False
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=fd)
                        created = True
                    except FileExistsError:
                        # An existing directory is checked through its opened
                        # descriptor; it is never chowned through a name.
                        created = False
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                                    os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    os.close(fd)
                    fd = child
                    if created:
                        os.fchown(fd, uid, gid)
                        os.fchmod(fd, 0o700)
                    info = os.fstat(fd)
                    require(info.st_uid == uid and info.st_gid == gid and
                            not info.st_mode & 0o022,
                            "input directory has an unexpected owner or mode")
                return fd
            except Exception:
                os.close(fd)
                raise

        work_fd = directory(Path(paths["work"]))
        os.close(work_fd)
        destination = Path(paths["input"])
        parent = directory(destination.parent)
        pending = destination.name + ".pending"
        try:
            fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
                os.fchown(stream.fileno(), uid, gid)
            # Both names are relative to the held directory. Publication
            # refuses a concurrent destination, including a dangling symlink.
            os.link(pending, destination.name, src_dir_fd=parent,
                    dst_dir_fd=parent, follow_symlinks=False)
            os.unlink(pending, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(parent)
        case.keep("native/input-released.json", encoded({
            "path": str(destination), "sha256": sha(raw), "bytes": len(raw),
            "uid": uid, "gid": gid}))

    def check_foreign(self, case, phase):
        observed = self.signal.snapshot()
        identity = self.consumer.process_identity(self.signal.pid)
        case.keep("observers/foreign-" + phase + ".json", encoded({
            "signal": observed, "identity": identity}))
        if observed["signals"] or identity != self.foreign_identity:
            case.boundary_failures.append("foreign.signal")
            raise RuntimeError("boundary canary succeeded: foreign.signal")
        if phase != "before-start":
            require(self.payload_sha in self.echo.messages,
                    "permitted endpoint did not independently receive the actual canary bytes")

    def review(self, case, target, cell):
        path = self.plan.get("review_input")
        if not path or not Path(path).exists():
            raise MissingGate("independent_review_input", "lb-v2-lifecycle")
        raw = ordinary(Path(path), private=True, owner=0)
        value = json.loads(raw)
        require(value.get("config") == self.context["config"] and
                value.get("target") == target and
                value.get("artifact_sha256") == self.context["binary_sha256"],
                "independent review input belongs to another run or artifact")
        review = value["review"]
        require(review.get("checks") and review.get("diff") and
                review.get("record_inventory") and
                isinstance(review.get("refusal_resolution"), list),
                "independent review lacks its actual committed evidence")
        case.keep("native/review-input.json", raw)
        return review

    def execute(self, context_path, result_path):
        """Run the real consumer in this process, with synchronous authority."""
        require(json.loads(ordinary(Path(context_path))) == self.context,
                "entry context differs from the shared exported context")
        code = None
        try:
            code = self.consumer.main([
                "--context", str(context_path), "--result", str(result_path)],
                coordinator=self)
        finally:
            self.close(result_path)
        measured = []
        result = json.loads(Path(result_path).read_bytes())
        if code == 0 and self.context["phase"] == "candidate":
            require(len(result["assertions"]) == 1 and
                    all(item["id"] == "OS-LINUX" and item["reached"] and
                        item["verdict"] == "pass" for item in result["assertions"]) and
                    result["collection"]["processes_quiescent"] and
                    result["collection"]["temporary_resources_collected"],
                    "zero entry exit lacks the actual installed assertion")
            cell = self.native["cell"]
            abi_cell = self.native.get("abi_cell", "current")
            require(abi_cell in ("current", "3") and
                    (abi_cell != "3" or cell["abi"] == 3),
                    "an ABI floor claim differs from the actual kernel")
            measured.append((self.start["driver"], cell["restriction"], cell["hook"], abi_cell))
        put(self.root / "matrix-observed.json", encoded({
            "rows": matrix(measured), "result_sha256": sha(Path(result_path).read_bytes()),
            "binary_sha256": self.context["binary_sha256"],
            "source_sha256": self.context["source_sha256"]}))
        return code

    def close(self, result_path=None):
        if self.closed:
            raise RuntimeError("outside fixture collection was already attempted")
        self.closed = True
        facts, errors = {}, []
        for name, observer in (("network", self.network), ("signal", self.signal),
                               ("permitted", self.echo)):
            if observer is not None:
                try:
                    facts[name] = observer.close()
                except Exception as failure:
                    errors.append(name + ": " + str(failure))
        result = None
        if result_path is not None and Path(result_path).exists():
            result = json.loads(Path(result_path).read_bytes())
        may_remove = result_path is None or (result is not None and
            result["collection"]["processes_quiescent"] and
            result["collection"]["temporary_resources_collected"])
        if self.public is not None:
            facts["public"] = {"path": str(self.public), "retained": True}
            if may_remove and not errors:
                try:
                    raw, info = self.consumer.read_fenced(self.public, "outside")
                    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid(),
                            "outside canary ownership changed before collection")
                    expected = self.inputs.get("outside-input.bin")
                    if expected is None:
                        expected = (self.root / "outside-input.bin").read_bytes()
                    require(sha(raw) == sha(expected),
                            "outside canary bytes changed before collection")
                    put(self.root / "outside-collected.bin", raw)
                    self.outside.unlink()
                    self.public.rmdir()
                    facts["public"] = {"path": str(self.public),
                        "retained": os.path.lexists(self.public), "sha256": sha(raw)}
                except Exception as failure:
                    errors.append("public: " + str(failure))
        facts["errors"] = errors
        path = put(self.root / "outside-collection.json", encoded(facts))
        if result is not None:
            result_path = Path(result_path)
            evidence = Path(self.context["evidence_root"])
            raw = path.read_bytes()
            retained = put(evidence / "outside-collection.json", raw)
            result["collection"]["evidence"].append({
                "path": retained.name, "sha256": sha(raw), "bytes": len(raw)})
            if errors or facts.get("public", {}).get("retained"):
                result["collection"]["processes_quiescent"] = False
                result["collection"]["temporary_resources_collected"] = False
            self.consumer.atomic_json(result_path, result)
        if errors:
            raise RuntimeError("outside fixture collection failed; retained exact observations")


def prepare_inputs(serve, context, plan):
    """Shared exporter owns context creation; this lane never writes its pins."""
    producer = Producer(serve, context)
    try:
        return producer.prepare(plan)
    except Exception as failure:
        try:
            producer.close()
        except Exception as cleanup:
            raise RuntimeError(str(failure) + "; outside collection: " + str(cleanup)) from failure
        raise


def assets():
    """Bytes for the shared owner's generic pre-install runtime-input hook."""
    path = CASE / "canary.py"
    raw = path.read_bytes()
    return [{"path": "linux/canary.py", "mode": 0o444,
             "sha256": sha(raw), "bytes": len(raw), "content": raw}]


def bound_human(context, plan):
    """Attach the existing serve CLI/signing code to this installed scope.

    No installation, enrollment, publication or profile setup is performed.
    The supervisor supplies references to its already enrolled software human.
    """
    import platform
    require(platform.system() == "Linux" and os.geteuid() == 0,
            "installed Linux coordinator requires the authorized root host")
    if not plan.get("human"):
        raise MissingGate("enrolled_human_handoff", "lb-v2-identity")
    source = module("linux_serve_bridge", Path(__file__).with_name("run.py"))
    provision = source.provision
    selected = plan["human"]

    def pinned(name, private=False, limit=1024 * 1024):
        ref = selected[name]
        path = Path(ref["path"])
        raw = provision.read_protected(path, limit=limit)
        require(len(raw) == ref["bytes"] and sha(raw) == ref["sha256"],
                "enrolled human handoff artifact differs: " + name)
        if private:
            require(stat.S_IMODE(path.lstat().st_mode) == 0o600,
                    "human handoff must retain private mode: " + name)
        return path, raw

    authenticator, _ = pinned("authenticator", limit=128 * 1024 * 1024)
    require(os.access(authenticator, os.X_OK), "pinned human authenticator is not executable")
    private, _ = pinned("private", private=True)
    _, public_raw = pinned("public", private=True)
    binding_file = Path(context["binding_file"])
    binding = json.loads(provision.read_protected(binding_file))
    require(binding.get("class") == "human" and
            binding.get("config") == context["config"] and
            binding.get("artifact_sha256") == context["binary_sha256"],
            "human handoff binding differs from the installed case")
    root = Path(context["evidence_root"]) / "coordinator"
    root.mkdir(mode=0o700)
    serve = source.Case(ROOT, root, config=context["config"])
    serve.binary, serve.stage = Path(context["binary"]), ROOT
    serve.authenticator = authenticator
    serve.installation_file = Path("/etc/laneboss-v2/admin") / (serve.config + ".json")
    serve.installed = dict(binding, binding_file=str(binding_file))
    serve.human = source.human.HumanRoot(serve, private, json.loads(public_raw),
                                        source.require, source.Blocked)
    return serve


def context_file(path):
    """Consume the frozen file emitted by G0; never mint case artifact pins."""
    return io.frozen(ROOT).context_file(path)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    args = parser.parse_args(argv)
    os.umask(0o077)
    context = context_file(args.context)
    require(context["case_id"] == "linux", "Linux producer received another case")
    require(args.result.is_absolute() and
            args.result.resolve().is_relative_to(Path(context["evidence_root"])),
            "result path escapes the exported evidence scope")
    consumer = module("linux_public_entry", CASE / "run.py")
    call = ["--context", str(args.context), "--result", str(args.result)]
    producer = None
    try:
        raw = ordinary(args.plan, private=True, owner=0)
        plan = json.loads(raw)
        put(Path(context["test_root"]) / "linux-plan.json", raw)
        if not context["profile_grant_ids"] or not plan.get("authorization"):
            raise MissingGate("real_driver_authorization", "laneboss")
        serve = bound_human(context, plan)
        producer = prepare_inputs(serve, context, plan)
    except Exception as failure:
        # The normal consumer writes the same frozen failure/result schema,
        # retaining this actual preparation error before attempting any CLI.
        if not isinstance(failure, (MissingGate, OSError, ValueError, KeyError,
                                    TypeError, RuntimeError)):
            failure = RuntimeError("installed coordinator stopped: " + str(failure))
        return consumer.main(call, preparation_error=failure)
    return producer.execute(args.context, args.result)


def boot(case):
    """G0 v1: enroll measured case assets before installation hashes exist."""
    source = case.stage / "e2e/v2/cases/linux/canary.py"
    raw = ordinary(source)
    case.keep("linux-canary.input.py", raw)
    # The exporter selects these bytes through the runtime asset. A separate
    # document would be an orphan in the installer's publication closure.
    bundle = {"documents": []}
    assets = [{"id": "linux-canary", "role": "case-tool",
               "file": str(source), "mode": 0o444}]
    path = getattr(case, "linux_plan_file", None) or os.environ.get("LANEBOSS_LINUX_PLAN")
    case.linux_plan_file = Path(path) if path else None
    if case.linux_plan_file is not None:
        plan_raw = ordinary(case.linux_plan_file, private=True, owner=0)
        plan = json.loads(plan_raw)
        case.keep("linux-plan.input.json", plan_raw)
        extra = plan.get("bundle", {})
        require(isinstance(extra, dict) and set(extra) <= {
            "documents", "sources", "contexts", "projects", "root_grants", "budget"},
            "unknown Linux boot bundle input")
        bundle.update(extra)
        for asset in plan.get("assets", []):
            require(set(asset) == {"id", "role", "file", "mode", "sha256", "bytes"},
                    "Linux runtime asset lacks its exact input pins")
            data = ordinary(Path(asset["file"]), limit=64 << 20)
            require(sha(data) == asset["sha256"] and len(data) == asset["bytes"],
                    "Linux runtime asset bytes differ")
            assets.append({key: asset[key] for key in ("id", "role", "file", "mode")})
    case.linux_boot = {"canary_sha256": sha(raw), "canary_bytes": len(raw),
                       "asset_ids": [asset["id"] for asset in assets]}
    case.keep_json("linux-boot.input.json", case.linux_boot)
    return {"bundle": bundle, "assets": assets}


def prepare(case, require, fail, blocked):
    """G0 v1 checkpoint; the existing installed human keeps its authority."""
    case.human_prefix = "itemlinux"
    case.current = "item.linux.prepare"
    path = getattr(case, "linux_plan_file", None)
    plan = json.loads(ordinary(path, private=True, owner=0)) if path else {}
    real_key = getattr(case, "real_api_key", False)
    if real_key:
        plan = authorize_real_key(case, plan)
    if not plan.get("authorization") or not plan.get("profile_grant_ids"):
        wait = MissingGate("real_driver_authorization", "laneboss")
        case.keep_json("linux-owner-wait.input.json", wait.record())
        case.rows[case.current]["observed"].update(wait.record())
        raise blocked(str(wait))
    profiles = plan["profile_grant_ids"]
    require(isinstance(profiles, list) and profiles and len(set(profiles)) == len(profiles) and
            all(isinstance(value, str) and value for value in profiles),
            "Linux profile handoff is not an actual unique grant list")
    if not real_key and getattr(case, "agent", {}).get("vendor_stood_in") is not False:
        wait = MissingGate("real_driver_runtime", "lb-v2-serve")
        case.keep_json("linux-runtime-wait.input.json", wait.record())
        case.rows[case.current]["observed"].update(wait.record())
        raise blocked(str(wait))
    case.human.session()
    case.current = "item.linux.prepare"
    source = module("linux_g0_adapter", CASE / "g0.py")
    session = source.Session(case, plan, require, fail, Producer, io)
    case.linux_session = session
    return {"binding_file": Path(case.installed["binding_file"]),
            "profile_grant_ids": profiles, "inputs": {},
            "populate": session.populate, "transport": session.transport,
            "collect": session.collect}


def abort(case, require, fail):
    """Report the actual remaining work; a failed guard has no retry route."""
    session = getattr(case, "linux_session", None)
    if session is None:
        return []
    case.human_prefix = "itemlinux"
    return session.abort()


if __name__ == "__main__":
    raise SystemExit(main())
