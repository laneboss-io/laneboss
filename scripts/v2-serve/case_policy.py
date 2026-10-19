"""Installed policy fixture producer. This module never opens the service DB.

G0 supplies the frozen context and the protected pre-install inputs described
in policy/SERVE.md. All authority below comes from actual
CLI replies, native workspace enrollment and fresh human confirmations.
"""

import base64
import copy
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time


STAGES = ("baseline", "skip", "rules", "timeout", "partial", "cost")
AGENT_PACKAGE = "./scripts/v2-serve/policy_agent"
FAMILIES = ("resources", "data", "secrets", "profiles", "network", "channels")
ROLES = {"l6": (6, "supervisor"), "reviewer": (4, "reviewer"),
         "executor": (3, "executor"), "tester": (3, "tester"),
         "fallback": (3, "fallback")}
ORG = ".laneboss/policy.json"
OWN = ".laneboss/L3/policy/executor.json"
HIGHER = ".laneboss/L4/policy/reviewer.json"
LOWER = ".laneboss/L3/policy/tester.json"
SKIP = ".laneboss/L5/policy/skip.json"
MUTATIONS = {"apply", "propose", "start", "begin", "chunk", "commit"}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False) + "\n").encode()


def document(raw):
    def members(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "duplicate JSON member")
            value[key] = item
        return value
    def invalid(_):
        raise ValueError("nonfinite JSON number")
    value = json.loads(raw, object_pairs_hook=members, parse_constant=invalid)
    require(isinstance(value, dict), "JSON object required")
    return value


def sibling(name):
    path = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location("policy_" + name, path)
    require(spec is not None and spec.loader is not None, "installed serve module missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_private(path, owner=None, maximum=16 << 20):
    path = Path(path)
    # Exclusive hard-link publication exposes the name just before unlinking
    # its temporary name. Wait for completion; a lasting alias still refuses.
    deadline = time.monotonic() + 0.2
    while path.lstat().st_nlink == 2 and time.monotonic() < deadline:
        time.sleep(0.001)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600
                and (owner is None or info.st_uid == owner)
                and 0 < info.st_size <= maximum, "unsafe private input")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        require(file_stamp(info) == file_stamp(after) and len(raw) == info.st_size,
                "private input changed during read")
    require(file_stamp(path.lstat()) == file_stamp(after), "private input path changed during read")
    return raw


def file_stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def publish(path, value, owner=None):
    """Never replace an existing input, operation key or observation."""
    path = Path(path)
    require(not os.path.lexists(path), "would overwrite retained input")
    raw = value if isinstance(value, bytes) else encoded(value)
    temporary = path.with_name(path.name + "." + secrets.token_hex(8) + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        if owner is not None and os.geteuid() == 0:
            os.fchown(stream.fileno(), owner, -1)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    # link is exclusive even if another writer races the existence check.
    os.link(temporary, path, follow_symlinks=False)
    temporary.unlink()
    require(read_private(path, owner) == raw, "published input differs")
    return path


def thresholds(match):
    return {"match": match, "uncertain_low": 0.4, "uncertain_high": 0.6,
            "calibration_id": "declared-policy-fixture"}


def source_doc(match, rules):
    return {"schema": "laneboss.policy-source.v2",
            "thresholds": thresholds(match), "rules": rules,
            "skip": [], "settings": []}


def policy_sources(judge):
    """Source data only. Publication and every later change still require D6."""
    names = ("org", "own", "higher", "lower", "cloud", "pr", "plugin",
             "critical", "notice", "read")
    ids = {name: "policy-" + secrets.token_hex(12) for name in names}

    def rule(name, text, match, scoped=False, band="refuse", critical=False):
        return {"id": ids[name], "text": text,
                "instead": "Use the responsible Laneboss operation and retain its receipt.",
                "band": band, "critical": critical,
                "scope": {"levels": [3], "roles": ["executor"]}
                if scoped else {"levels": [], "roles": []},
                "source": {"id": "", "path": "", "sha256": "", "generation": 0},
                "thresholds": thresholds(match)}

    org = source_doc(0.8, [rule("org", "Do not change protected org policy outside D6.", 0.8)])
    org.update(judge=copy.deepcopy(judge), guidance_half_life_seconds=3600,
               guidance_min_relevance=0.5, profile_exclusions=[])
    own = source_doc(0.95, [rule("own", "Do not publish executor output without independent review.", 0.95)])
    high = source_doc(0.85, [
        rule("higher", "Do not abandon the required review responsibility.", 0.85),
        rule("cloud", "Cloud machine creation must use the Laneboss box lifecycle.", 0.85, True),
        rule("pr", "Pull request creation must use the Laneboss review workflow.", 0.85, True),
        rule("plugin", "Restricted org publishing plugins require approved loading.", 0.85, True),
    ])
    low = source_doc(0.95, [rule("lower", "Do not alter another tester's private fixtures.", 0.95)])
    return {"rules": ids, "documents": {ORG: org, OWN: own, HIGHER: high, LOWER: low},
            "outage_rules": [
                rule("critical", "Protect the critical outage canary.", 0.95, True, critical=True),
                rule("notice", "Warn about the public outage canary.", 0.95, True, band="warn", critical=True),
            ], "read_rule": rule("read", "Do not read the newly restricted public-readme.txt.", 0.95, True)}


class Stages:
    def __init__(self, config, generation, nonce):
        require(type(generation) is int and generation > 0, "stage generation missing")
        self.config, self.generation, self.nonce = config, generation, nonce
        self.index = 0

    def check(self, notice):
        require(self.index < len(STAGES) and notice == {
            "config": self.config, "nonce": self.nonce, "stage": STAGES[self.index],
            "expected_generation": None if self.index == 0 else self.generation,
        }, "stale, reordered or foreign stage request")
        return self.generation

    def commit(self, request, receipt):
        require(request["expected_generation"] == self.generation
                and receipt["change_id"] == request["change_id"]
                and receipt["approval_id"] == request["approval_id"]
                and receipt["old_generation"] == self.generation
                and type(receipt["new_generation"]) is int
                and receipt["new_generation"] == self.generation + 1,
                "D6 receipt does not follow its retained stage")
        self.generation = receipt["new_generation"]
        self.index += 1


def decode_reply(reply, job, config, binary):
    require(reply["config"] == config and reply["binary_sha256"] == binary
            and reply["contract_revision"] == "v2.0-draft.4"
            and reply["request"] == job["request"]
            and reply["idempotency_key"] == job["idempotency_key"],
            "worker reply changed artifact, binding or retained input")
    raw = base64.b64decode(reply["request_bytes"], validate=True)
    require(sha(raw) == reply["request_sha256"] and document(raw) == job["request"],
            "worker request bytes changed")
    stderr = base64.b64decode(reply["stderr_bytes"], validate=True)
    require(type(reply["exit"]) is int and reply["exit"] == 0
            and reply["timed_out"] is False and not stderr,
            "worker command failed; preserve its exact stderr and exit")
    return document(base64.b64decode(reply["stdout_bytes"], validate=True))


class Queue:
    def __init__(self, path, config, binary, refused=None):
        self.path, self.config, self.binary = Path(path), config, binary
        info = self.path.lstat()
        require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700,
                "worker queue is not private")
        self.owner, self.index = info.st_uid, 0
        self.last = None
        self.refused = refused

    def submit(self, kind, request):
        stem = "%04d" % self.index
        job = {"kind": kind, "request": request,
               "idempotency_key": secrets.token_urlsafe(24) if kind in MUTATIONS else ""}
        publish(self.path / (stem + ".job.json"), job, self.owner)
        self.index += 1
        return stem, job

    def call(self, kind, request, timeout=40):
        stem, job = self.submit(kind, request)
        path = self.path / (stem + ".reply.json")
        deadline = time.monotonic() + timeout
        while not path.exists():
            require(time.monotonic() < deadline, "authentic worker did not reply")
            time.sleep(0.1)
        reply = document(read_private(path, self.owner))
        self.last = {"job": job, "reply": reply}
        if reply.get("exit") != 0 and self.refused is not None:
            self.refused(reply)
        return decode_reply(reply, job, self.config, self.binary)

    def upload(self, raw, kind="artifact"):
        upload = self.call("begin", {"class": kind, "bytes": len(raw), "sha256": sha(raw)})
        chunk_size = upload["max_chunk_bytes"]
        require(type(chunk_size) is int and 0 < chunk_size <= 262144,
                "upload has an invalid chunk bound")
        for offset in range(0, len(raw), chunk_size):
            chunk = raw[offset:offset + chunk_size]
            self.call("chunk", {"object_id": upload["object_id"], "offset": offset,
                               "data": base64.b64encode(chunk).decode(), "sha256": sha(chunk)})
        ref = self.call("commit", {"object_id": upload["object_id"], "sha256": sha(raw)})
        require(ref == {"id": upload["object_id"], "class": kind,
                        "bytes": len(raw), "sha256": sha(raw)}, "upload commit changed bytes")
        return ref


def collection_result(request, rows):
    actors = request["actors"]
    expected = {(actor["life_id"], actor["run"]) for actor in actors.values()}
    require(len(rows) == len(expected) == len(actors), "collection target count differs")
    seen = set()
    for row in rows:
        target = (row["target"]["life_id"], row["target"]["run"])
        observed, native = row["observation"], row["native_helper"]
        require(target in expected and target not in seen
                and observed["state"] == "exited" and type(observed["survivors"]) is int
                and observed["survivors"] == 0 and observed.get("observed_at")
                and type(observed.get("exit_code")) is int and observed["exit_code"] == 0
                and "signal" not in observed and row["cleaned"] is True
                and native["helper_journal_complete"] is True
                and native["worktree_measured"] is True and native["branch_measured"] is True
                and native["action"] == "remove_clean", "collection lacks measured native release")
        seen.add(target)
    return {"nonce": request["nonce"], "config": request["config"],
            "binary_sha256": request["binary_sha256"], "observations": rows,
            "processes_quiescent": seen == expected,
            "temporary_resources_collected": seen == expected}


def judge_observations(measured, records, judge, reserve, ceiling):
    """Join private HTTP bytes to actual read-back durable egress records."""
    def contents(ref):
        raw = read_private(ref["path"], maximum=32 << 20)
        require(len(raw) == ref["bytes"] and sha(raw) == ref["sha256"], "judge exchange bytes changed")
        return raw
    observed, pairs = {}, {}
    for row in measured["requests"]:
        raw = contents(row["request"])
        response = document(contents(row["response"]))
        digest = sha(raw)
        observed.setdefault(digest, []).append((row, response, len(raw)))
    require({row["stage"] for row in measured["requests"]} >= {"normal", "timeout", "partial", "cost"},
            "judge did not observe every actual HTTP phase")
    for row in records:
        require(row.get("event") in ("sent", "outcome") and row.get("ask"), "invalid native judge egress row")
        pair = pairs.setdefault(row["ask"], {})
        require(row["event"] not in pair, "duplicate native judge egress event")
        pair[row["event"]] = row
    matched, used, result = Counter(), set(), []
    for ask, pair in pairs.items():
        require("sent" in pair, "native judge outcome lacks its original reservation")
        sent = pair["sent"]
        digest = sent["request_sha256"]
        if digest not in observed:
            continue  # An allocated job may have stopped before HTTP.
        choices = observed[digest]
        outcome = pair.get("outcome")
        candidates = [(index, value) for index, value in enumerate(choices)
            if (digest, index) not in used and (not outcome or not outcome.get("request")
                or value[1]["request"] == outcome["request"])]
        require(candidates, "native judge reissued a request or changed its provider response ID")
        index, (row, response, size) = candidates[0]
        used.add((digest, index))
        matched[digest] += 1
        stage = row["stage"]
        require(sent.get("claim_id") and sent.get("attempt_id")
                and type(sent.get("reserved_micros")) is int
                and 0 < sent["reserved_micros"] <= ceiling
                and sent["outcome_reserve"] == sent["reserved_micros"]
                and sent["request_bytes"] == size and sent["cut"] is False and sent["withheld"] is False,
                "native judge reservation differs from complete HTTP input")
        if outcome is None:
            require(stage == "timeout" and row["elapsed_ms"] >= judge["command_deadline_ms"],
                    "native judge lost a non-timeout outcome")
        else:
            require(all(outcome[field] == sent[field] for field in
                        ("claim_id", "attempt_id", "request_sha256", "reserved_micros")),
                    "native judge outcome changed its original reservation")
            if stage == "timeout":
                require(outcome["outcome"] == "unscored" and not outcome.get("probabilities")
                        and outcome["usage_known"] is False
                        and row["elapsed_ms"] >= judge["command_deadline_ms"],
                        "native timeout did not preserve unknown usage")
            else:
                cost = response["usage"]["input_tokens"] + response["usage"]["output_tokens"]
                require(outcome["usage_known"] is True and outcome["cost_micros"] == cost
                        and 0 < cost <= sent["reserved_micros"]
                        and outcome["request"] == response["request"],
                        "native measured price/usage disagrees with actual provider bytes")
                if stage == "normal":
                    require(outcome["outcome"] == "answered" and outcome["probabilities"] == {
                        name: answer["noul"] for name, answer in response["answers"].items()},
                        "native scored output differs from actual provider probabilities")
                else:
                    require(outcome["outcome"] == "unscored" and not outcome.get("probabilities"),
                            "native outage was accounted as scored")
                    require(stage == "partial" and response.get("input_truncated") is True
                            or stage == "cost" and cost > reserve,
                            "actual partial/cost boundary was not reached")
        result.append({"ask": ask, "stage": stage, "request_sha256": digest,
            "claim_id": sent["claim_id"], "attempt_id": sent["attempt_id"],
            "reserved_micros": sent["reserved_micros"], "outcome": outcome or "pending/unknown"})
    require(matched == Counter({digest: len(rows) for digest, rows in observed.items()}),
            "observed HTTP requests lack their unique durable reservations")
    return result


class Producer:
    """Serve-owned launch/human ports are concrete, already installed objects.

    `serve` is scripts/v2-serve/run.py's Case after publication. The public
    human adapter supplies each proof on the actual new CLI connection.
    This producer deliberately imports no unpublished shared exporter.
    """
    def __init__(self, serve, context, inputs):
        self.serve, self.context, self.inputs = serve, context, inputs
        self.root, self.evidence = Path(context["test_root"]), Path(context["evidence_root"])
        require(context["case_id"] == "policy" and context["config"] == serve.config
                and context["binary_sha256"] == sha(Path(context["binary"]).read_bytes()),
                "policy context differs from the installed artifact")
        require(inputs["schema"] == "laneboss.policy-input.v1"
                and inputs["config"] == serve.config, "policy inputs differ from installation")
        self.fixture = policy_sources(inputs["judge"])
        self.docs = {name: base64.b64decode(raw, validate=True)
                     for name, raw in inputs["source_bytes"].items()}
        self.workers, self.records = {}, []
        self.cursor = None
        self.nonce = None
        self.read_index = 0
        self.setup = None
        self.pending = None
        self.receipt = None
        self.operations = []
        serve.human_prefix = "itempolicy"
        serve.current = "item.policy.prepare"

    def keep(self, name, value):
        return publish(self.evidence / name, value)

    def read(self, words, request):
        self.read_index += 1
        return self.serve.human.read("policy-%04d" % self.read_index, words, request)

    def control(self, method, request, target, generation):
        saved = self.serve.current
        proof = self.serve.human.proof("control", method, request, target, generation)
        self.serve.current = saved
        return self.serve.human.rpc("policy-control", method.split("."), request, proof)

    def await_operation(self, value):
        deadline = time.monotonic() + 120
        operation_id = value["id"]
        while value.get("status") in ("pending", "running"):
            require(not value.get("error") and time.monotonic() < deadline,
                    "installed operation failed or expired")
            time.sleep(0.2)
            value = self.read(["operation", "get"], {"operation_id": operation_id})
            require(value["id"] == operation_id, "operation identity changed")
        require(value.get("status") == "succeeded" and not value.get("error"),
                "installed operation refused; inspect retained operation")
        return value

    def native_queue(self, lane):
        # The helper's authenticated registry supplies host paths. Lane JSON,
        # a UID label or a task file cannot select an outside workspace.
        provision = sibling("provision")
        workspace_id = lane["workspace"]["id"]
        require(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", workspace_id), "bad native workspace selector")
        registry = Path("/var/lib/laneboss-v2/helper") / self.serve.config / "workspaces"
        raw = provision.read_protected(registry / (workspace_id + ".json"))
        native = document(raw)
        workspace = native["Workspace"]
        require(native["Schema"] == "laneboss.workspace-native.v2"
                and native["Config"] == self.serve.config and workspace["ID"] == workspace_id
                and workspace["Target"] == {"life_id": lane["life_id"], "run": lane["run"]},
                "native workspace belongs to another run")
        parent = Path(native["Parent"])
        provision.protected(parent)
        info = parent.lstat()
        require("%d:%d" % (info.st_dev, info.st_ino) == workspace["RootIdentity"],
                "native workspace parent changed")
        worktree = parent / workspace_id
        info = worktree.lstat()
        require(stat.S_ISDIR(info.st_mode)
                and "%d:%d" % (info.st_dev, info.st_ino) == workspace["DirectoryIdentity"],
                "native worktree changed")
        self.keep("native-" + lane["life_id"] + ".json", raw)
        lease_id = native["LeaseID"]
        require(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", lease_id), "bad native lease selector")
        lease_raw = provision.read_protected(registry.parent / (lease_id + ".json"), mode=0o600)
        journal = document(lease_raw)
        lease = journal["lease"]
        require(journal["schema"] == "laneboss.helper-lease.v2"
                and lease["id"] == lease_id and journal["request"]["config"] == self.serve.config
                and journal["request"]["life_id"] == lane["life_id"]
                and type(lease["uid"]) is int and lease["uid"] > 0,
                "queue UID is not the native life lease")
        self.keep("native-uid-" + lane["life_id"] + ".json", {"journal_sha256": sha(lease_raw),
            "lease_id": lease_id, "uid": lease["uid"], "target": workspace["Target"]})
        return worktree / ".policy-q", lease["uid"]

    def attach(self, name, operation):
        require(operation.get("life_id") and operation.get("run") == 1,
                "start has no actual reserved run")
        target = {"life_id": operation["life_id"], "run": operation["run"]}
        record = {"name": name, "target": target, "quiescent": False,
                  "collected": False, "stop_attempted": False, "operation": operation}
        self.records.append(record)
        self.serve.item_lives.append(record)
        self.operations.append(operation["id"])
        self.await_operation(operation)
        lane = self.read(["lane", "status"], target)
        level, role = ROLES[name]
        require(lane["state"] == "running" and lane["level"] == level and lane["role"] == role
                and lane["life_id"] == target["life_id"] and lane["run"] == target["run"]
                and lane.get("logical_turn_id") and lane.get("launch_id"),
                "launched worker has another authentic role/run")
        queue, native_uid = self.native_queue(lane)
        deadline = time.monotonic() + 15
        while not (queue / "control").is_dir():
            require(time.monotonic() < deadline, "installed policy worker did not initialize")
            time.sleep(0.1)
        info = queue.lstat()
        require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                and info.st_uid == native_uid, "worker queue differs from its native UID/private directory")
        def refused(reply):
            record["refused"] = True
            self.keep(name + "-refused.reply.json", reply)
            raw = base64.b64decode(reply["stderr_bytes"], validate=True)
            error = document(raw)
            self.serve.rows[self.serve.current]["observed"].update({
                "executed": True, "refusal": error, "exit_code": reply["exit"]})
        control = Queue(queue / "control", self.serve.config, self.context["binary_sha256"], refused)
        require(control.owner == native_uid, "worker control queue differs from its native UID")
        identity = control.call("identity", {})
        actor = identity["actor"]
        require(identity["config"] == self.serve.config and actor["kind"] == "lane"
                and actor["life_id"] == target["life_id"] and actor["level"] == level
                and actor["role"] == role and identity["launch_id"] == lane["launch_id"],
                "role worker did not authenticate inside its original launch")
        status = control.call("status", target)
        require(status == lane, "outside and inside lane status differ")
        self.keep(name + "-identity.json", identity)
        self.keep(name + "-status.json", status)
        (self.root / "queues" / name).symlink_to(queue, target_is_directory=True)
        self.workers[name] = {"queue": queue, "control": control,
                              "lane": lane, "record": record}
        return lane

    def ticket(self, root):
        selectors = self.serve.fixture_profile_selectors
        self.serve.fixture_profile_selectors = {**selectors, root["driver"]: self.inputs["profile_ids"]["l6"]}
        try:
            ticket = self.serve.human.ticket(root, self.inputs["root_grants_file"])
        finally:
            self.serve.fixture_profile_selectors = selectors
        # This selects the issued root template, before the L6 has a Lane/run.
        # grants.get must verify that template's actual issuance ownership.
        grants = self.read(["grants", "get"], {"grant_set_id": ticket["grant_set_id"]})
        require(grants["id"] == ticket["grant_set_id"] and grants["revoked"] is False
                and type(grants.get("generation")) is int and grants["generation"] > 0
                and not grants.get("parent_life_id"), "policy profile root grants are not current")
        # The normal root binder selects one execution profile. L6 also
        # needs each child's separate member so the original parent can
        # delegate it through the unchanged child launch checks.
        root["grants"]["profiles"] = profile_grants(grants, self.inputs["profile_ids"], root["driver"])
        self.keep("l6-profiles.input.json", grants)
        return ticket

    def prepare(self):
        require(os.geteuid() == 0 and sys.platform == "linux",
                "policy producer requires the authorized root Linux installed scope")
        require(self.serve.initial_receipt["generation"] == self.inputs["org_generation"],
                "policy inputs do not bind the actual initial receipt")
        (self.root / "queues").mkdir(mode=0o700)
        root = copy.deepcopy(self.inputs["launches"]["l6"])
        require((root["level"], root["role"]) == ROLES["l6"]
                and not root.get("root_ticket_id") and root["budget"]["spend_micros"] > 0,
                "policy requires a funded unticketed L6 launch selector")
        task_bytes = base64.b64decode(self.inputs["task_bytes"], validate=True)
        root["task"] = self.serve.human.upload("policy-root-task", "task", task_bytes)
        self.keep("l6-task.ref.json", root["task"])
        ticket = self.ticket(root)
        root["root_ticket_id"] = ticket["id"]
        saved = "item.policy.prepare"
        proof = self.serve.human.proof("read", "human.session", {},
                                       self.serve.human.public["principal_id"], 0)
        self.serve.current = saved
        key = secrets.token_urlsafe(24)
        self.keep("l6-start.intent.json", {"request": root, "idempotency_key": key})
        operation = self.serve.checked_cli("policy-start", ["lane", "start"], root,
                                           idempotency_key=key, session_proof=str(proof))
        self.attach("l6", operation)
        parent = self.workers["l6"]["control"]
        grants = parent.call("grants", {"grant_set_id": self.workers["l6"]["lane"]["grant_set_id"]})
        require(grants["life_id"] == self.workers["l6"]["lane"]["life_id"]
                and grants["id"] == self.workers["l6"]["lane"]["grant_set_id"]
                and grants["revoked"] is False, "L6 grant scope is not current")
        self.keep("l6-grants.json", grants)
        # Children consume a task uploaded by their actual original parent,
        # rather than borrowing the human's private root-task object.
        child_task = parent.upload(task_bytes, "task")
        self.keep("child-task.ref.json", child_task)
        for name in ("reviewer", "executor", "tester", "fallback"):
            request = copy.deepcopy(self.inputs["launches"][name])
            request["task"] = child_task
            require((request["level"], request["role"]) == ROLES[name]
                    and not request.get("root_ticket_id") and request["budget"]["spend_micros"] > 0,
                    "child launch selector changes role or budget")
            require(not request.get("profile_grant_id") and all(not items for items in request["grants"].values()),
                    "child template already contains invented issued selectors")
            profiles = [p for p in grants["profiles"]
                        if p["profile_id"] == self.inputs["profile_ids"][name]
                        and p["driver"] == request["driver"] and p["delegate"] is True]
            require(len(profiles) == 1, "exact child profile is not delegated by the L6")
            profile = profiles[0]
            request["profile_grant_id"] = profile["id"]
            request["grants"]["profiles"] = [{"parent_grant_id": profile["id"],
                "profile_id": profile["profile_id"], "delegate": False, "expires_at": profile["expires_at"]}]
            data = [g for g in grants["data"] if g["source_object_id"] == self.inputs["project"]["id"]]
            require(len(data) == 1 and data[0]["delegate"] is True,
                    "exact child project data was not explicitly delegated")
            request["grants"]["data"] = [{"parent_grant_id": g["id"], "delegate": False,
                "destination": "/work/main",
                **{field: g[field] for field in ("relative_path", "access", "delivery", "expires_at")}}
                for g in data]
            operation = parent.call("start", request)
            lane = self.attach(name, operation)
            require(lane["parent_life_id"] == self.workers["l6"]["lane"]["life_id"],
                    "worker is not an authentic child of the actual L6")
        actors = {name: {key: value["lane"][key] for key in
                         ("life_id", "run", "logical_turn_id")}
                  for name, value in self.workers.items()}
        require(len({actor["life_id"] for actor in actors.values()}) == 5,
                "role workers reused a life")
        setup = {"schema": "laneboss.policy-case.v2", "contract_revision": "v2.0-draft.4",
                 "actors": actors, "changes": {name: "change-" + name + ".json" for name in STAGES},
                 "rules": self.fixture["rules"]}
        publish(self.root / "setup.json", setup)
        self.setup = setup
        self.keep("presence-summary.json", {"simulated_presence": True,
                  "presence": "simulated", "human_approval": "not_proven"})
        return setup

    def populate(self, context):
        require(context["case_id"] == "policy" and context["config"] == self.serve.config
                and context["binary_sha256"] == self.context["binary_sha256"],
                "G0 context differs from the actual prepared installation")
        old_root, old_evidence = self.root, self.evidence
        self.root, self.evidence, self.context = Path(context["test_root"]), Path(context["evidence_root"]), context
        (self.root / "queues").mkdir(mode=0o700)
        for name, worker in self.workers.items():
            (self.root / "queues" / name).symlink_to(worker["queue"], target_is_directory=True)
        for source in sorted(old_evidence.iterdir()):
            self.keep(source.name, read_private(source))
        return {"setup.json": read_private(old_root / "setup.json")}

    def finish_pending(self):
        if self.pending is None:
            return
        name, request, documents = self.pending
        receipt = self.applied(request)
        self.keep(name + "-receipt.json", receipt)
        self.docs.update(documents)
        self.pending = None

    def transport(self, event):
        require(event["action"] == "rpc" and event["command"] == "policy stage"
                and event.get("denied") is False and event.get("request_id")
                and event.get("idempotency_key"), "unsupported policy observer request")
        self.serve.current = "item.policy.run"
        self.finish_pending()
        notice = event["request"]
        if self.cursor is None:
            self.nonce = notice["nonce"]
            self.cursor = Stages(self.serve.config, self.inputs["org_generation"], self.nonce)
        request, documents = self.stage(notice["stage"], notice)
        self.pending = (notice["stage"], request, documents)
        return {"exit_code": 0, "stdout": base64.b64encode(encoded(request)).decode(), "stderr": ""}

    def collected(self, context, operations):
        require(context == self.context, "collector context changed")
        if self.receipt is None:
            self.serve.current = "item.policy.collection"
            require(not any(row.get("refused") for row in self.records),
                    "native refusal stops policy mutations; retain its original queue")
            self.finish_pending()
            self.prepare_collection()
            result = self.collect()
            judge = self.serve.policy_judge.close()
            require(judge["closed"] and not judge["errors"], "outside judge fixture was not collected")
            judge_refs = []
            for index, ref in enumerate(judge["evidence"]):
                raw = read_private(ref["path"])
                require(len(raw) == ref["bytes"] and sha(raw) == ref["sha256"],
                        "collected judge HTTP/control evidence changed")
                retained = self.keep("judge-http-%04d.input" % index, raw)
                judge_refs.append({"path": retained.name, "sha256": sha(raw), "bytes": len(raw)})
            retained = self.keep("judge-collection.json", judge)
            raw_judge = read_private(retained)
            judge_refs.append({"path": retained.name, "sha256": sha(raw_judge), "bytes": len(raw_judge)})
            records = self.judge_records()
            enrollment = self.serve.item_inputs["enrollment"]
            matches = judge_observations(judge, records, enrollment["judge"],
                enrollment["judge_worker"]["reserve_micros"], enrollment["policy_max_cost_micros"])
            for name, value in (("judge-egress.input.json", records), ("judge-matches.json", matches)):
                retained = self.keep(name, value)
                raw_ref = read_private(retained)
                judge_refs.append({"path": retained.name, "sha256": sha(raw_ref), "bytes": len(raw_ref)})
            path = self.evidence / "collection.json"
            raw = read_private(path)
            self.receipt = {"processes_quiescent": result["processes_quiescent"],
                "temporary_resources_collected": result["temporary_resources_collected"],
                "operation_ids": list(dict.fromkeys(self.operations)),
                "evidence": [{"path": path.name, "sha256": sha(raw), "bytes": len(raw)}, *judge_refs]}
        require(set(operations) <= set(self.receipt["operation_ids"]), "unknown managed policy operation")
        return self.receipt

    def judge_records(self):
        cursor, seen, values = "", set(), []
        for index in range(128):
            page = self.read(["judge", "egress"], {"collection": "judge_egress", "query": "",
                "search_mode": "keyword", "cursor": cursor, "limit": 200})
            self.keep("judge-page-%03d.json" % index, page)
            for record in page["records"]:
                require(record["id"] not in seen and record["collection"] == "judge_egress"
                        and record["origin"] == "service" and record["actor"]["kind"] == "service",
                        "judge read returned a foreign or duplicate native record")
                seen.add(record["id"])
                raw = self.serve.publication_blob(record["content"])
                self.keep("judge-record-%04d.input" % len(values), raw)
                values.append(document(raw))
            if not page["cursor"]:
                return values
            require(page["cursor"] != cursor, "judge egress cursor stalled")
            cursor = page["cursor"]
        raise ValueError("judge egress exceeded its bounded record inventory")

    def prepare_collection(self):
        """The post-entry callback also stops an entry that never initialized."""
        request = self.evidence / "collection-request.json"
        if request.exists():
            return
        require(len(self.workers) == len(self.records) and self.workers,
                "an unattached native life still needs supervised reconciliation")
        if self.setup is None:
            self.setup = {"actors": {name: {field: worker["lane"][field] for field in
                ("life_id", "run", "logical_turn_id")} for name, worker in self.workers.items()}}
        self.nonce = self.nonce or secrets.token_hex(16)
        for worker in self.workers.values():
            queue = worker["queue"]
            jobs = sorted(queue.glob("*.job.json"))
            if jobs and document(read_private(jobs[-1], queue.stat().st_uid)).get("kind") == "stop":
                continue
            index = 0 if not jobs else int(jobs[-1].name[:4]) + 1
            publish(queue / ("%04d.job.json" % index), {"kind": "stop"}, queue.stat().st_uid)
        # This is a collector request, never a receipt or an exit observation.
        publish(request, {"nonce": self.nonce, "config": self.context["config"],
            "binary_sha256": self.context["binary_sha256"], "actors": self.setup["actors"]})

    def stage_documents(self, name):
        docs = self.fixture["documents"]
        if name == "baseline":
            return copy.deepcopy(docs)
        if name == "skip":
            worker = self.workers["executor"]
            policy = worker["control"].call("list", {"life_id": worker["lane"]["life_id"]})
            request = {"config": self.serve.config, "policy": policy,
                       "org_generation": self.cursor.generation + 1,
                       "policy_generation": policy["generation"] + 1,
                       "command": {"tool": "shell", "command": base64.b64encode(b"cat public-readme.txt").decode(),
                                   "argv": [], "declared_paths": [], "cwd": "/work/main",
                                   "raw_sha256": sha(b"cat public-readme.txt")}}
            source = self.keep("skip-digest.input.json", request)
            raw = self.serve.command("policy-skip-digest", [self.inputs["skip_tool"], "--input", str(source)], clean=True)
            hashes = document(raw)
            skip = source_doc(0.85, [])
            skip["skip"] = [{"id": "skip-" + secrets.token_hex(12),
                             "description": "Exact judged public read optimization.",
                             "rule_set_sha256": hashes["rule_set_sha256"],
                             "context_sha256": hashes["context_sha256"],
                             "source": {"id": "", "path": "", "sha256": "", "generation": 0}}]
            return {SKIP: skip}
        own = document(self.docs[OWN])
        if name == "rules":
            own["rules"].append(self.fixture["read_rule"])
        else:
            # Every outage is a separate approved generation. The fixed
            # outside judge controller changes its real provider/price input;
            # no fault selector is sent to org.hook or any policy RPC.
            own["rules"] = [r for r in own["rules"]
                            if r["id"] not in {self.fixture["rules"]["critical"], self.fixture["rules"]["notice"]}]
            own["rules"].extend(copy.deepcopy(self.fixture["outage_rules"]))
            own["rules"][-1]["text"] += " Observe the " + name + " provider phase."
        return {OWN: own}

    def stage(self, name, notice):
        self.cursor.check(notice)
        documents = self.stage_documents(name)
        l6 = self.workers["l6"]["control"]
        files, expected_bytes = [], {}
        for path, value in sorted(documents.items()):
            raw = encoded(value)
            self.keep(name + "-source-%d.json" % len(files), raw)
            ref = l6.upload(raw)
            delta = {"path": path, "action": "replace" if path in self.docs else "add",
                     "after": ref, "mode": 0o444}
            if path in self.docs:
                delta["before_sha256"] = sha(self.docs[path])
            files.append(delta)
            expected_bytes[ref["id"]] = raw
        reason = l6.upload(("Policy fixture stage " + name + " " + self.nonce + "\n").encode(), "task")
        request = {"org_id": self.serve.config, "base_generation": self.cursor.generation,
                   "files": files, "reason": reason}
        proposed = l6.call("propose", request)
        require(proposed["config"] == self.serve.config and proposed["files"] == files
                and proposed["base_generation"] == self.cursor.generation
                and proposed["requester"]["life_id"] == self.workers["l6"]["lane"]["life_id"]
                and proposed["requester"]["level"] == 6 and proposed["derived"]
                and proposed["diff"]["bytes"] > 0, "proposal lost its actual source/derived review")
        retained = self.read(["org", "change", "get"], {"change_id": proposed["id"]})
        require(retained == proposed, "human review sees another staged change")
        for ref in [retained["reason"], retained["diff"], retained["ownership_manifest"],
                    *[row["after"] for row in retained["files"] if row.get("after")],
                    *[row["after"] for row in retained["derived"] if row.get("after")]]:
            raw = self.serve.publication_blob(ref)
            if ref["id"] in expected_bytes:
                require(raw == expected_bytes[ref["id"]], "human reviewed different source bytes")
            self.keep(name + "-review-" + ref["id"] + ".input", raw)
        approve = {"change_id": retained["id"], "manifest_sha256": retained["manifest_sha256"],
                   "base_generation": retained["base_generation"]}
        approval = self.control("org.change.approve", approve, retained["id"], self.cursor.generation)
        require(approval["change_id"] == retained["id"]
                and approval["manifest_sha256"] == retained["manifest_sha256"]
                and approval["base_generation"] == self.cursor.generation
                and approval["requester_life_id"] == retained["requester"]["life_id"]
                and approval.get("nonce_id") and approval.get("simulated_presence") is True,
                "approval lacks its exact current change or simulated provenance")
        if name in ("timeout", "partial", "cost"):
            provision = sibling("provision")
            require(sha(provision.read_protected(self.inputs["judge_control"], 64 << 20))
                    == self.inputs["judge_control_sha256"], "outside judge controller executable changed")
            control = self.keep(name + "-judge.input.json", {"stage": name, "config": self.serve.config,
                "org_generation": self.cursor.generation + 1, "nonce": self.nonce})
            staged_control = provision.administrator_input(Path(self.inputs["judge_control"]).parent,
                control.name, read_private(control))
            observed = document(self.serve.command("policy-judge-stage",
                [self.inputs["judge_control"], "--request", str(staged_control)], clean=True))
            require(observed.get("stage") == name and observed.get("config") == self.serve.config
                    and observed.get("nonce") == self.nonce
                    and observed.get("org_generation") == self.cursor.generation + 1
                    and observed.get("input_sha256") == sha(read_private(control))
                    and isinstance(observed.get("evidence"), list) and observed["evidence"],
                    "outside judge controller lacks its actual input evidence")
            for index, ref in enumerate(observed["evidence"]):
                require(set(ref) == {"path", "sha256", "bytes"}
                        and type(ref["bytes"]) is int and 0 < ref["bytes"] <= 64 << 20,
                        "outside judge controller evidence has an invalid shape")
                raw = provision.read_protected(ref["path"], ref["bytes"])
                require(len(raw) == ref["bytes"] and sha(raw) == ref["sha256"],
                        "outside judge controller evidence changed")
                self.keep(name + "-judge-%d.input" % index, raw)
            self.keep(name + "-judge.json", observed)
        apply = {"change_id": retained["id"], "approval_id": approval["id"],
                 "expected_generation": self.cursor.generation}
        self.keep(name + "-approval.json", approval)
        publish(self.root / ("change-" + name + ".json"), apply)
        return apply, {path: encoded(value) for path, value in documents.items()}

    def applied(self, request):
        queue = self.workers["l6"]["queue"]
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            for path in sorted(queue.glob("*.job.json")):
                job = document(read_private(path, queue.stat().st_uid))
                reply_path = path.with_name(path.name.replace(".job.json", ".reply.json"))
                if job.get("kind") == "apply" and job.get("request") == request and reply_path.exists():
                    reply = document(read_private(reply_path, queue.stat().st_uid))
                    receipt = decode_reply(reply, job, self.serve.config, self.context["binary_sha256"])
                    self.cursor.commit(request, receipt)
                    return receipt
            time.sleep(0.1)
        raise ValueError("current D6 apply receipt is missing")


    def collect(self):
        path = self.evidence / "collection-request.json"
        deadline = time.monotonic() + 180
        while not path.exists():
            require(time.monotonic() < deadline, "consumer collection request missing")
            time.sleep(0.1)
        request = document(read_private(path))
        if self.nonce is None:
            require(isinstance(request.get("nonce"), str) and re.fullmatch(r"[a-f0-9]{32}", request["nonce"]),
                    "collector lacks the entry's unpredictable request nonce")
            self.nonce = request["nonce"]
        require(request == {"nonce": self.nonce, "config": self.context["config"],
                           "binary_sha256": self.context["binary_sha256"],
                           "actors": self.setup["actors"]}, "foreign collection request")
        # Copy every exact input/reply before asking the original workers to
        # remove their own scratch. No success message stands in for exit.
        for name, worker in self.workers.items():
            queue = worker["queue"]
            owner = queue.stat().st_uid
            stop_jobs = []
            for source in sorted(queue.glob("*.job.json")):
                if document(read_private(source, owner)).get("kind") == "stop":
                    stop_jobs.append(source)
            require(len(stop_jobs) == 1, "collector did not observe one retained stop")
            reply = stop_jobs[0].with_name(stop_jobs[0].name.replace(".job.json", ".reply.json"))
            wait = time.monotonic() + 10
            while not reply.exists():
                require(time.monotonic() < wait, "worker did not acknowledge stop")
                time.sleep(0.1)
            require(document(read_private(reply, owner)) == {"stopped": True},
                    "worker stop acknowledgment changed")
            for source in sorted(queue.rglob("*")):
                if source.is_dir() and source.name == "control":
                    continue
                raw = read_private(source, owner, maximum=32 << 20)
                relative = str(source.relative_to(queue)).replace("/", "-")
                self.keep(name + "-queue-" + relative, raw)
            publish(queue / "release.json", {"nonce": request["nonce"]}, owner)
        rows = []
        # The children are independently checked and collected before their
        # parent. The normal abandon/archive/clean path retains all records.
        for record in reversed(self.records):
            target = record["target"]
            deadline = time.monotonic() + 30
            while True:
                lane = self.read(["lane", "status"], target)
                observed = self.control("lane.check", target, lane["life_id"], lane["generation"])
                require(observed["handle"]["target"] == target and observed["handle"]["containment_id"]
                        == lane["containment"] and observed.get("observed_at"),
                        "collector observed another native containment")
                if observed["state"] == "exited":
                    require(type(observed.get("survivors")) is int and observed["survivors"] == 0
                            and type(observed.get("exit_code")) is int and observed["exit_code"] == 0
                            and "signal" not in observed, "worker lacks a successful native terminal observation")
                    break
                require(observed["state"] == "running" and time.monotonic() < deadline,
                        "worker native containment did not quiesce")
                time.sleep(0.2)
            record["quiescent"] = True
            lane = self.read(["lane", "status"], target)
            empty = {"id": "", "sha256": "", "bytes": 0, "class": ""}
            review = {"id": "", "reviewer": {"kind": "", "id": ""}, "diff": empty,
                      "checks": [], "record_inventory": empty, "refusal_resolution": [], "coverage": ""}
            mark = {"target": target, "expected_generation": lane["generation"],
                    "state": "abandoned", "review": review}
            marked = self.await_operation(self.control("lane.mark", mark, lane["life_id"], lane["generation"]))
            self.operations.append(marked["id"])
            lane = self.read(["lane", "status"], target)
            archive = self.control("lane.archive", {"target": target, "expected_generation": lane["generation"]},
                                   lane["life_id"], lane["generation"])
            require(archive["life_id"] == lane["life_id"] and archive["archive_sha256"]
                    == archive["read_back_sha256"] and archive["archive_sha256"] and archive["manifest"]["id"],
                    "collection archive lacks its actual read-back")
            lane = self.read(["lane", "status"], target)
            clean = {"target": target, "expected_generation": lane["generation"],
                     "archive_receipt_id": archive["id"]}
            completed = self.await_operation(self.control("lane.clean", clean, lane["life_id"], lane["generation"]))
            self.operations.append(completed["id"])
            native = self.serve.native_cleanup_evidence(record, lane, completed)
            final = self.read(["lane", "status"], target)
            record["collected"] = final["cleaned"] is True
            rows.append({"target": target, "observation": observed, "cleaned": final["cleaned"],
                         "archive": archive, "operation": completed, "native_helper": native})
        result = collection_result(request, rows)
        publish(self.evidence / "collection.json", result)
        return result



def role_sources(source):
    """Generic assembler source rows, supplied before initial publication."""
    source = Path(source)
    prompt = (source / "e2e/v2/cases/policy/role.md").read_bytes()
    drivers = (source / "templates/v2/org/drivers.toml").read_bytes()
    rows = []
    for label, (level, role) in ROLES.items():
        root = ".laneboss/L%d/roles/" % level + role
        for suffix, kind, raw in ((".md", "prompt", prompt), (".toml", "drivers", drivers)):
            rows.append({"id": "policy-" + label + "-" + kind, "path": root + suffix,
                         "kind": kind, "data": base64.b64encode(raw).decode()})
    return rows


def profile_grants(grants, ids, driver):
    """Delegate only the independently enrolled policy members actually issued."""
    require(set(ids) == set(ROLES) and all(isinstance(value, str) and value for value in ids.values())
            and len(set(ids.values())) == len(ROLES), "policy profile selectors are not distinct")
    result, issued = [], set()
    for name in ROLES:
        matches = [row for row in grants["profiles"] if row.get("profile_id") == ids[name]]
        require(len(matches) == 1, "policy profile was not issued exactly once: " + name)
        profile = matches[0]
        identifier = profile.get("id")
        require(profile.get("driver") == driver and profile.get("provider") == "serve-fixture"
                and profile.get("paid") is False and profile.get("delegate") is True
                and profile.get("expires_at") and not profile.get("parent_grant_id")
                and isinstance(identifier, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identifier)
                and identifier not in issued, "policy profile differs from issued scope: " + name)
        issued.add(identifier)
        result.append({"parent_grant_id": identifier, "profile_id": profile["profile_id"],
                       "delegate": profile["delegate"], "expires_at": profile["expires_at"]})
    return result


def boot(case):
    """G0 v1: measured source/role/project inputs before any publication."""
    documents = []
    def retain(name, kind, raw):
        ref = {"id": name, "class": kind, "sha256": sha(raw), "bytes": len(raw)}
        documents.append({"ref": ref, "data": base64.b64encode(raw).decode()})
        case.keep(name + ".input", raw)
        return ref
    readme = retain("policy-project-readme", "artifact",
                    b"# Policy fixture workspace\n" + secrets.token_hex(16).encode() + b"\n")
    project = retain("policy-project", "manifest", encoded({"schema": "laneboss.objects.v2",
        "entries": [{"path": "public-readme.txt", "kind": "file", "mode": 0o444, "content": readme}]}))
    # Only the initial L5 task is selected by the initial publication. Keep
    # these later role-task bytes privately until the original actors upload.
    task_bytes = (case.stage / "e2e/v2/cases/policy/role.md").read_bytes()
    case.keep("policy-role-task.input", task_bytes)
    expires = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    root = {name: [] for name in FAMILIES}
    root["schema"] = "laneboss.root-grants.v2"
    root["data"] = [{"id": "", "source_object_id": project["id"], "source_sha256": project["sha256"],
        "relative_path": ".", "access": "rw", "delivery": "copy", "destination": "/work/main",
        "delegate": True, "expires_at": expires, "history_scope": "tree"}]
    root["profiles"] = [{"id": "", "profile_id": "serve-profile-" + driver, "driver": driver,
        "provider": "serve-fixture", "paid": False, "delegate": True, "expires_at": expires}
        for driver in ("claudock-cli", "codex")]
    # Preceding lifecycle rows retain their baseline seats. The installer
    # enrolls each policy ID as a distinct login/source/account before use.
    profiles = {name: "policy-profile-" + name for name in ROLES}
    root["profiles"].extend({"id": "", "profile_id": identifier, "driver": "codex",
        "provider": "serve-fixture", "paid": False, "delegate": True, "expires_at": expires}
        for identifier in profiles.values())
    case.fixture_profile_selectors = {driver: "serve-profile-" + driver
                                      for driver in ("claudock-cli", "codex")}
    budget = {"wall_ms": 300000, "cpu_seconds": 120, "memory_bytes": 536870912,
              "processes": 32, "disk_bytes": 67108864, "spend_micros": 50000000, "currency": "USD"}
    case.policy_boot = {"task_bytes": base64.b64encode(task_bytes).decode(), "project": project,
                        "budget": budget, "profiles": profiles}
    case.keep_json("policy-boot.input.json", case.policy_boot)
    judge_inputs = sibling("policy_judge").boot(case)
    return {**judge_inputs, "bundle": {"documents": documents, "sources": role_sources(case.stage),
        "contexts": [{"level": level, "role": role} for level, role in ROLES.values()],
        "projects": [{"id": "policy-project-enrollment", "generation": 1, "project_id": "policy-project",
                      "object": project, "base": project["sha256"], "history_scope": "tree"}],
        "root_grants": root, "budget": budget}}


def prepare(case, require, fail, blocked):
    """G0 v1: prepare actual lives, then populate the frozen allocated scope."""
    case.human_prefix = "itempolicy"
    case.current = "item.policy.prepare"
    provision = sibling("provision")
    # Boot retained this case-owned fixture handoff before hashing the
    # initial publication. The product supplies the native JudgeWorker.
    handoff = getattr(case, "policy_judge_input", None)
    if handoff is None or not Path(handoff).is_file():
        raise blocked("protected policy-judge.input.json and native fixture worker are required")
    judge = document(provision.read_protected(handoff, mode=0o600))
    require(judge["schema"] == "laneboss.policy-judge.v1" and judge["config"] == case.config,
            "judge fixture handoff belongs to another installation")
    controller = Path(judge["controller"])
    raw_controller = provision.read_protected(controller, 64 << 20)
    require(sha(raw_controller) == judge["controller_sha256"] and controller.stat().st_mode & 0o111,
            "outside judge controller executable changed")
    require(type(case.installed.get("policy_max_cost_micros")) is int
            and case.installed["policy_max_cost_micros"] > 0,
            "installed policy inference has no explicit positive ceiling")
    enrollment = case.item_inputs["enrollment"]
    require(all(case.installed.get(name) == value for name, value in enrollment.items())
            and case.policy_judge.collection is None,
            "installed native judge enrollment differs from boot or fixture already closed")
    policy = document(case.publication_blob(case.initial["policy"]))
    require(policy["judge"] == judge["judge"], "judge fixture differs from the approved deployment")
    snapshot = document(case.publication_blob(case.initial["sources"]))
    source_bytes = {}
    for row in snapshot["Sources"]:
        name = row["Source"]["path"]
        if name == ORG or re.fullmatch(r"\.laneboss/L[3-6]/policy/[A-Za-z0-9_-]+\.json", name):
            raw = case.publication_blob(row["Content"])
            require(sha(raw) == row["Source"]["sha256"], "approved initial source bytes changed")
            source_bytes[name] = base64.b64encode(raw).decode()
    require(ORG in source_bytes, "approved canonical baseline is absent")
    skip_tool = case.stage / "policy-skip"
    case.command("policy-skip-build", ["go", "build", "-trimpath", "-mod=vendor",
                 "-o", str(skip_tool), "./scripts/v2-serve/policy_skip"], seconds=600)
    skip_tool.chmod(0o555)
    case.keep("policy-skip.input", skip_tool.read_bytes())
    base = document(case.root_launch_input(case.lane_inputs))["codex"]
    launches = {}
    for name, (level, role) in ROLES.items():
        request = copy.deepcopy(base)
        request.update(lane="policy-" + name + "-" + secrets.token_hex(4), level=level, role=role,
                       budget=case.policy_boot["budget"])
        if name != "l6":
            request["project_id"] = "policy-project"
        launches[name] = request
    inputs = {"schema": "laneboss.policy-input.v1", "config": case.config,
        "org_generation": case.initial_receipt["generation"], "judge": policy["judge"],
        "source_bytes": source_bytes, "root_grants_file": str(case.root_grants),
        "task_bytes": case.policy_boot["task_bytes"],
        "launches": launches, "project": case.policy_boot["project"],
        "profile_ids": dict(case.policy_boot["profiles"]),
        "skip_tool": str(skip_tool), "judge_control": str(controller),
        "judge_control_sha256": judge["controller_sha256"]}
    area = case.root / "policy-prep"
    area.mkdir(mode=0o700)
    (area / "input").mkdir(mode=0o700)
    (area / "evidence").mkdir(mode=0o700)
    # Private preparation coordinates precede G0 allocation; these values
    # are never serialized as a frozen context or used as native authority.
    coordinates = {"case_id": "policy", "config": case.config, "binary": str(case.binary),
        "binary_sha256": case.installed["artifact_sha256"], "test_root": str(area / "input"),
        "evidence_root": str(area / "evidence")}
    fixture = Producer(case, coordinates, inputs)
    case.policy_fixture = fixture
    fixture.prepare()
    case.current = "item.policy.prepare"
    profiles = sorted({w["lane"]["profile_grant_id"] for w in fixture.workers.values()})
    return {"binding_file": case.installed["binding_file"], "profile_grant_ids": profiles,
            "populate": fixture.populate, "transport": fixture.transport, "collect": fixture.collected}


def abort(case, require, fail):
    """Report every uncollected original life; never change actor after refusal."""
    fixture = getattr(case, "policy_fixture", None)
    if fixture is None:
        judge = getattr(case, "policy_judge", None)
        if judge is not None:
            judge.close()
        return []
    case.human_prefix = "itempolicy"
    refused = any(record.get("refused") for record in fixture.records)
    refused = refused or any(row.get("observed", {}).get("refusal") for name, row in case.rows.items()
                             if name.startswith(("item.policy.", "human.itempolicy.")))
    if not refused and fixture.records and not all(record["collected"] for record in fixture.records):
        try:
            fixture.collected(fixture.context, [])
        except (OSError, ValueError, KeyError, TypeError, fail) as error:
            path = fixture.evidence / "abort-error.json"
            if not path.exists():
                fixture.keep(path.name, {"message": str(error)})
    problems = []
    for record in fixture.records:
        if not record["collected"]:
            problems.append({"target": record["target"], "operation_id": record["operation"]["id"],
                             "reason": "actual policy worker/native collection remains incomplete"})
    if problems:
        for name, worker in fixture.workers.items():
            last = worker["control"].last
            path = fixture.evidence / (name + "-last-control.json")
            if last is not None and not path.exists():
                fixture.keep(path.name, last)
        path = fixture.evidence / "abort.json"
        if not path.exists():
            fixture.keep(path.name, {"remaining": problems})
    judge = getattr(case, "policy_judge", None)
    if judge is not None:
        judge.close()
    return problems


if __name__ == "__main__":
    raise SystemExit("Use the shared serve entry with --item-case policy.")
