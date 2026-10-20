"""Credential-free grants producer using real L5/L3 identities and uploads."""

import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import time
import uuid


AGENT_PACKAGE = "./scripts/v2-serve/grants_actor"
FAMILIES = ("resources", "data", "secrets", "profiles", "network", "channels")
CHILD_TASK = b"Commit the exact child candidate and test plan through the installed CLI.\n"


def sibling(name):
    spec = importlib.util.spec_from_file_location(
        "grants_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


io = sibling("item_context")
flow = sibling("lifecycle")
uploads = sibling("grants_upload")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def boot(case):
    documents = []

    def document(name, kind, raw):
        ref = {"id": name, "class": kind, "sha256": sha(raw), "bytes": len(raw)}
        documents.append({"ref": ref, "data": base64.b64encode(raw).decode()})
        case.keep("grants-" + name + ".input", raw)
        return ref

    def tree(name, entries):
        return document(name, "manifest", io.encoded({
            "schema": "laneboss.objects.v2", "entries": entries}))

    def entry(name, ref):
        return {"path": name, "kind": "file", "mode": 0o444, "content": ref}

    source = case.stage / "e2e" / "v2" / "cases" / "grants"
    case.grants_files = {name: (source / name).read_bytes() for name in
                         ("child_probe.c", "child_task.sh", "pre-commit.sh")}
    input_ref = document("grants-input", "artifact", os.urandom(40).hex().encode() + b"\n")
    canary = os.urandom(48).hex().encode() + b"\n"
    canary_ref = document("grants-canary", "artifact", canary)
    observer = case.keep("grants-canary.input", canary)
    fixed_ref = document("grants-fixed", "artifact", os.urandom(32).hex().encode())
    parent_tree = tree("grants-parent-tree", [entry("child/input.txt", input_ref),
        entry("private/canary", canary_ref), {"path": "alias", "kind": "symlink",
        "mode": 0o777, "link_target": "private/canary"}])
    fixed_tree = tree("grants-fixed-tree", [entry("fixed.txt", fixed_ref)])
    child_tree = tree("grants-child-tree", [entry("input.txt", input_ref)])
    sources = []
    for suffix, kind in (("md", "prompt"), ("toml", "drivers")):
        path = case.stage / "templates" / "v2" / "roles" / "L3" / ("executor." + suffix)
        sources.append({"id": "grants-l3-" + kind,
            "path": ".laneboss/L3/roles/executor." + suffix, "kind": kind,
            "data": base64.b64encode(path.read_bytes()).decode()})
    expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    root = {name: [] for name in FAMILIES}
    root["schema"] = "laneboss.root-grants.v2"
    for ref, destination, delegate in ((parent_tree, "/data/parent", True),
                                       (fixed_tree, "/data/fixed", False)):
        root["data"].append({"id": "", "source_object_id": ref["id"],
            "source_sha256": ref["sha256"], "relative_path": ".", "access": "ro",
            "delivery": "copy", "destination": destination, "delegate": delegate,
            "expires_at": expiry, "history_scope": "snapshot"})
    # These are operator proposals, not enrolled handles or initial grants.
    resource_enrollment = {"provider": "gcp", "regions": ["region-a"], "image_ids": ["image-a"],
        "machine_types": ["small"], "max_active": 1, "max_hourly_micros": 0,
        "total_budget_micros": 0, "delegate": True, "expires_at": expiry}
    root["profiles"] = [{"id": "", "profile_id": "serve-profile-" + driver,
        "driver": driver, "provider": "serve-fixture", "paid": False,
        "delegate": True, "expires_at": expiry} for driver in ("claudock-cli", "codex")]
    # Earlier lifecycle rows retain their baseline seats, including ruling b's
    # rotation gate. The installer enrolls each item actor as its own canonical
    # login/source/account; no profile files belong in a lane's worktree.
    profiles = {name: "grants-profile-" + name for name in ("parent", "child")}
    root["profiles"].extend({"id": "", "profile_id": identifier, "driver": "codex",
        "provider": "serve-fixture", "paid": False, "delegate": True, "expires_at": expiry}
        for identifier in profiles.values())
    case.fixture_profile_selectors = {driver: "serve-profile-" + driver
                                      for driver in ("claudock-cli", "codex")}
    assets, tools = [], {}
    for name in ("sh", "cc", "git"):
        selected = shutil.which(name)
        if name == "cc" and selected is None:
            selected = shutil.which("gcc")
        io.require(selected is not None, "missing: " + name + (
            " or gcc; prep package: gcc and libc6-dev" if name == "cc" else ""))
        path = Path(selected).resolve(strict=True)
        version = case.command("grants-tool-" + name,
            [str(path), "--version"] if name != "sh" else
            ["dpkg-query", "-W", "--showformat=${Version}", "dash"], clean=True)
        tools[name] = {"id": "item-" + name, "sha256": io.sha(path),
                       "version": version.decode("utf-8").splitlines()[0].strip()}
        case.keep("grants-tool-" + name + ".input", path.read_bytes())
        assets.append({"id": "item-" + name, "role": "case-tool",
                       "file": str(path), "mode": 0o555})
    budget = {"wall_ms": 300000, "cpu_seconds": 120, "memory_bytes": 536870912,
              "processes": 32, "disk_bytes": 67108864, "spend_micros": 0, "currency": "USD"}
    case.grants_boot = {"input": input_ref, "canary": canary_ref,
        "observer": str(observer), "parent_tree": parent_tree,
        "fixed_tree": fixed_tree, "child_tree": child_tree,
        "budget": budget, "tools": tools, "resource_enrollment": resource_enrollment,
        "profiles": profiles}
    case.keep_json("grants-boot.input.json", case.grants_boot)
    return {"assets": assets, "bundle": {"documents": documents, "sources": sources,
        "contexts": [{"level": 3, "role": "executor"}], "root_grants": root,
        "budget": budget, "projects": [{"id": "grants-child-enrollment",
            "generation": 1, "project_id": "grants-child", "object": child_tree,
            "base": child_tree["sha256"], "history_scope": "tree"}]}}


def resource_enrollment_input(case):
    return {"resource": copy.deepcopy(case.grants_boot["resource_enrollment"])}


def secret_enrollment_input(imported, expiry):
    return {"secret": {"source_handle": imported["source_handle"], "name": imported["name"],
        "version": imported["version"], "delivery": "file", "target": "grants-canary",
        "delegate": False, "expires_at": expiry}}


def enrolled_record(case, ref, expected):
    io.require(ref.get("class") == "manifest" and type(ref.get("bytes")) is int and
               0 < ref["bytes"] <= 1048576 and ref.get("id"), "enrollment returned an invalid record")
    raw = bytearray()
    while len(raw) < ref["bytes"]:
        chunk = case.human.read("capability-record", ["blob", "read"],
            {"object_id": ref["id"], "offset": len(raw), "limit": min(262144, ref["bytes"] - len(raw))})
        part = base64.b64decode(chunk["data"], validate=True)
        io.require(chunk.get("object_id") == ref["id"] and chunk.get("offset") == len(raw) and
                   0 < len(part) <= ref["bytes"] - len(raw) and chunk.get("sha256") == sha(part),
                   "enrolled capability chunk differs")
        raw.extend(part)
    end = case.human.read("capability-record-end", ["blob", "read"],
        {"object_id": ref["id"], "offset": len(raw), "limit": 1})
    io.require(base64.b64decode(end["data"], validate=True) == b"" and end.get("offset") == len(raw) and
               end.get("object_id") == ref["id"] and end.get("sha256") == sha(b"") and sha(raw) == ref["sha256"],
               "enrolled capability record bytes or exact end differ")
    actual = json.loads(raw)
    io.require(actual == expected and actual["source_handle"] == ref["id"],
               "enrolled capability differs from the exact operator proposal")
    case.keep("capability-" + ref["id"] + ".input.json", bytes(raw))
    return actual


def sealed_canary(case, tool, key, name, version):
    sealing = case.keep_json("grants-sealing.input.json", {
        "config": case.config, "key": key, "name": name, "version": version})
    return json.loads(case.command("grants-seal-canary", [str(tool), "--input", str(sealing)], clean=True))


def secret_import_input(name, version, staged):
    return {"name": name, "version": version, "sealed_upload_id": staged["id"]}


def upload_secret(case):
    saved = case.current
    # Build before issuing the bounded, connection-owned upload key.
    tool = case.stage / "grants-seal.input"
    case.command("grants-seal-build", ["go", "build", "-trimpath", "-mod=vendor", "-o", str(tool),
                 "./scripts/v2-serve/grants_seal"], cwd=case.stage, seconds=600)
    case.keep("grants-seal.input", tool.read_bytes())
    proof = case.human.proof("read", "human.session", {}, case.human.public["principal_id"], 0)
    case.current = saved
    directory = case.root / "grants-upload"
    directory.mkdir(mode=0o700)
    selected = uploads.plan(directory)
    name, version = "grants-canary-" + uuid.uuid4().hex[:12], "v1"
    try:
        with uploads.FileFlow(directory, case.binary, case.config, case.installed["binding_file"],
                              proof, selected) as live:
            key = live.response("task-secret-key")
            sealed = sealed_canary(case, tool, key, name, version)
            live.supply("task-secret-stage", sealed)
            staged = live.response("task-secret-stage")
            io.require(staged.get("name") == name and staged.get("version") == version and staged.get("id"),
                       "secret canary staging differs from its actual sealed request")
            request = secret_import_input(name, version, staged)
            live.supply("task-secret-import", request)
            proof = case.human.proof("control", "secret.import", request, case.config, 0)
            case.current = saved
            live.supply_proof("task-secret-import", proof)
            imported = live.response("task-secret-import")
            live.finish()
    except uploads.Refused as error:
        case.current = saved
        ended = json.loads((directory / "client.exit.json").read_bytes())
        relative = directory.relative_to(case.root)
        case.last = {"label": "grants-secret-upload", "started": ended["started"],
            "exit_code": ended["exit_code"], "stdout": str(relative / "client.stdout"),
            "stderr": str(relative / "client.stderr"), "pid": ended["pid"]}
        case.rows[saved]["observed"].update({"executed": True, "rpc_executed": True,
            "refusal": error.error, "owner": error.error.get("owner"),
            "flow_evidence": str(relative)})
        raise
    io.require(imported.get("name") == name and imported.get("version") == version and
               imported.get("source_handle") and imported.get("revoked") is False,
               "secret import did not return its actual protected source")
    return imported


def enroll_root(case, request):
    """Run installed operator commands before naming handles in a root manifest."""
    if getattr(case, "grants_enrolled_request", None) is not None:
        return copy.deepcopy(case.grants_enrolled_request)
    saved = case.current
    proposal = resource_enrollment_input(case)
    proof = case.human.proof("control", "grants.enroll", proposal, case.config, 0)
    case.current = saved
    resource_ref = case.human.rpc("resource-enroll", ["grants", "enroll"], proposal, proof)
    resource = dict(proposal["resource"], id="", source_handle=resource_ref["id"])
    resource = enrolled_record(case, resource_ref, resource)

    imported = upload_secret(case)
    proposal = secret_enrollment_input(imported, resource["expires_at"])
    proof = case.human.proof("control", "grants.enroll", proposal, case.config, 0)
    case.current = saved
    secret_ref = case.human.rpc("secret-capability-enroll", ["grants", "enroll"], proposal, proof)
    secret = enrolled_record(case, secret_ref, dict(proposal["secret"], id=""))

    approved = case.decode_document((case.root / "initial-inputs" / case.initial["profiles"]["id"]).read_bytes())
    io.require(approved["resources"] == [] and approved["secrets"] == [],
               "initial root already named capabilities before operator enrollment")
    approved["resources"], approved["secrets"] = [resource], [secret]
    raw = io.encoded(approved)
    case.keep("enrolled-root-manifest.input.json", raw)
    manifest_ref = case.human.upload("enrolled-root", "manifest", raw)
    case.grants_enrolled_request = dict(request, manifest=manifest_ref)
    case.grants_enrolled_manifest = approved
    case.keep_json("enrolled-root-request.input.json", case.grants_enrolled_request)
    case.current = saved
    return copy.deepcopy(case.grants_enrolled_request)


class Relay:
    def __init__(self, case, record, require, fail):
        self.case, self.record = case, record
        self.require, self.fail = require, fail
        self.seen, self.pending, self.values = set(), bytearray(), []
        self.report_seen, self.capture_values = set(), []
        self.offset = 0

    def capture_blob(self, ref):
        self.require(ref.get("class") == "capture" and type(ref.get("bytes")) is int and
                     0 < ref["bytes"] <= 64 << 20, "relay capture object has an invalid class or bound")
        raw = bytearray()
        while len(raw) < ref["bytes"]:
            limit = min(262144, ref["bytes"] - len(raw))
            chunk = self.case.human.read("relay-capture", ["blob", "read"],
                {"object_id": ref["id"], "offset": len(raw), "limit": limit})
            part = base64.b64decode(chunk["data"], validate=True)
            self.require(chunk.get("object_id") == ref["id"] and chunk.get("offset") == len(raw) and
                0 < len(part) <= limit and chunk.get("sha256") == sha(part), "relay capture chunk differs")
            raw.extend(part)
        self.require(len(raw) == ref["bytes"] and sha(raw) == ref["sha256"], "relay capture object bytes differ")
        end = self.case.human.read("relay-capture-end", ["blob", "read"],
            {"object_id": ref["id"], "offset": len(raw), "limit": 1})
        self.require(end.get("object_id") == ref["id"] and end.get("offset") == len(raw) and
            base64.b64decode(end["data"], validate=True) == b"" and end.get("sha256") == sha(b""),
            "relay capture object has no exact-end chunk")
        name = "capture-" + sha(raw)[:20] + ".input"
        retained = self.case.root / name
        if retained.exists():
            self.require(retained.read_bytes() == raw, "retained primary capture bytes differ")
        else:
            self.case.keep(name, raw)
        return bytes(raw)

    def captured_now(self):
        case, record = self.case, self.record
        for event in flow.events(case, record, self.require):
            if event["seq"] in self.seen:
                continue
            self.seen.add(event["seq"])
            if event["kind"] != "capture.appended":
                continue
            capture = event["payload"]
            if capture.get("stream") != "stdout":
                continue
            self.require(event["operation_id"] == record["operation"]["id"] and
                capture.get("target") == record["target"] and capture.get("primary") is True and
                capture.get("coverage") == "complete" and capture.get("offset") == self.offset,
                "relay primary capture is uncorrelated or discontinuous")
            if capture.get("eof"):
                continue
            raw = self.capture_blob(capture["data"])
            self.offset += len(raw)
            self.pending.extend(raw)
            while b"\n" in self.pending:
                raw, _, rest = self.pending.partition(b"\n")
                self.pending = bytearray(rest)
                try:
                    value = json.loads(raw)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    raise self.fail("relay primary capture contains a malformed JSON line") from None
                self.require(isinstance(value, dict), "relay primary capture line is not an object")
                self.capture_values.append(value)
                if value.get("type") == "grants.reply" and not value.get("nonce"):
                    self.refusal(value)
        return self.capture_values

    def report_blob(self, ref):
        self.require(ref.get("class") == "report" and type(ref.get("bytes")) is int and
                     0 < ref["bytes"] <= 1 << 20, "relay report has an invalid class or bound")
        raw = bytearray()
        while len(raw) < ref["bytes"]:
            limit = min(262144, ref["bytes"] - len(raw))
            chunk = self.case.human.read("relay-report", ["blob", "read"],
                {"object_id": ref["id"], "offset": len(raw), "limit": limit})
            part = base64.b64decode(chunk["data"], validate=True)
            self.require(chunk.get("object_id") == ref["id"] and chunk.get("offset") == len(raw) and
                0 < len(part) <= limit and chunk.get("sha256") == sha(part), "relay report chunk differs")
            raw.extend(part)
        end = self.case.human.read("relay-report-end", ["blob", "read"],
            {"object_id": ref["id"], "offset": len(raw), "limit": 1})
        self.require(sha(raw) == ref["sha256"] and end.get("object_id") == ref["id"] and
            end.get("offset") == len(raw) and base64.b64decode(end["data"], validate=True) == b"" and
            end.get("sha256") == sha(b""), "relay report bytes or exact end differ")
        name = "report-" + sha(raw)[:20] + ".input"
        retained = self.case.root / name
        if retained.exists():
            self.require(retained.read_bytes() == raw, "retained relay report bytes differ")
        else:
            self.case.keep(name, bytes(raw))
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise self.fail("relay report contains malformed JSON") from None
        self.require(isinstance(value, dict), "relay report is not an object")
        return value

    def values_now(self):
        case, record = self.case, self.record
        for event in flow.events(case, record, self.require):
            if event["seq"] in self.report_seen:
                continue
            self.report_seen.add(event["seq"])
            if event.get("kind") != "blob.committed" or event.get("payload", {}).get("class") != "report":
                continue
            actor = event.get("actor", {})
            self.require(event.get("config") == case.config and event.get("life_id") == record["target"]["life_id"] and
                event.get("run") == record["target"]["run"] and event.get("origin") == "observation" and
                actor.get("kind") == "lane" and actor.get("life_id") == record["target"]["life_id"] and
                event.get("requested_by") == actor, "relay report is not from its authenticated original actor")
            envelope = self.report_blob(event["payload"])
            value = envelope.get("message")
            self.require(envelope.get("schema") == "laneboss.relay-report.v1" and isinstance(value, dict) and
                value.get("target") == record["target"] and value.get("type") in
                ("grants.ready", "grants.reply", "grants.exiting"), "relay report envelope or target differs")
            self.require(value["type"] == "grants.ready" or isinstance(value.get("nonce"), str) and
                re.fullmatch(r"[0-9a-f]{32}", value["nonce"]), "relay report lost its request nonce")
            self.values.append(value)
        return self.values

    def verify_transcript(self):
        # Public capture.appended events are immutable raw partial ranges.
        # Complete framing is an in-process API, so derive completeness here
        # only from the bound producer's two actual capture.closed receipts.
        events = flow.events(self.case, self.record, self.require)
        bindings = [event["payload"] for event in events if event.get("kind") == "capture.bound" and
                    event.get("operation_id") == self.record["operation"]["id"]]
        self.require(len(bindings) == 1, "relay transcript has no unique original capture binding")
        binding = bindings[0]
        self.require(binding.get("status") == "registered" and binding.get("config") == self.case.config and
            binding.get("target") == self.record["target"] and binding.get("operation_id") == self.record["operation"]["id"] and
            {row["stream"] for row in binding["streams"]} == {"stdout", "stderr"} and len(binding["streams"]) == 2,
            "relay transcript capture binding differs from its original run")
        self.require(not any(event.get("kind") == "capture.gap" and
            event.get("payload", {}).get("binding_id") == binding["id"] for event in events),
            "relay transcript retains an incomplete capture gap")
        names = {row["id"]: row["stream"] for row in binding["streams"]}
        offsets, closed, stdout, generation = {name: 0 for name in names.values()}, set(), bytearray(), binding["generation"]
        for event in events:
            if event.get("kind") not in ("capture.appended", "capture.closed"):
                continue
            value = event["payload"]
            if value.get("binding_id") != binding["id"]:
                continue
            self.require(event.get("origin") == "service" and event.get("config") == self.case.config and
                event.get("life_id") == self.record["target"]["life_id"] and event.get("run") == self.record["target"]["run"] and
                event.get("operation_id") == binding["operation_id"] and event.get("request_id") == binding["request_id"] and
                event.get("requested_by") == binding["requested_by"] and event.get("actor", {}).get("kind") == "worker" and
                event["actor"].get("id") == binding["producer_id"], "relay transcript producer or original operation differs")
            if event["kind"] == "capture.appended":
                name = value.get("stream")
                self.require(name in offsets and name not in closed and value.get("id") == event.get("id") and
                    value.get("target") == self.record["target"] and value.get("primary") is True and
                    value.get("coverage") == "partial" and not value.get("replacement_of") and
                    value.get("offset") == offsets[name] and 0 < value["data"].get("bytes", 0) <= 262144,
                    "relay transcript lost its original contiguous primary range")
                raw = self.capture_blob(value["data"])
                offsets[name] += len(raw)
                self.require(sum(offsets.values()) <= 8 << 20, "relay transcript exceeds its native spool bound")
                if name == "stdout":
                    stdout.extend(raw)
            else:
                name = names.get(value.get("stream_id"))
                self.require(name in offsets and name not in closed and value.get("eof") is True and
                    value.get("record_id") == event.get("id") and value.get("last_seq") == event.get("seq") and
                    value.get("offset") == value.get("next_offset") == offsets[name] and
                    value.get("generation") == generation + 1, "relay transcript has no exact original EOF acknowledgement")
                closed.add(name)
            generation += 1
        self.require(closed == {"stdout", "stderr"}, "relay transcript has not reached both actual pipe EOFs")
        self.require(stdout and stdout.endswith(b"\n"), "relay transcript contains an incomplete JSON line")
        try:
            captured = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise self.fail("relay transcript contains malformed JSON") from None
        self.require(self.values and all(
            sum(value == actual for actual in captured) == 1 for value in self.values),
            "live relay reports differ from the original complete primary capture")

    def refusal(self, result):
        if result["exit_code"] != 0:
            raw = base64.b64decode(result["stderr"], validate=True)
            error = json.loads(raw)
            self.case.rows[self.case.current]["observed"].update({
                "executed": True, "refusal": error, "exit_code": result["exit_code"]})
            self.record["refused"] = True
            raise self.fail("installed lane transport refused; retain exact capture bytes")

    def wait(self, kind, nonce=None):
        deadline = time.monotonic() + 120
        while True:
            values = self.values_now()
            # A poll overwrites the case's last command. Retain the actual
            # expected report kind separately so a deadline names its phase.
            self.case.rows[self.case.current]["observed"]["relay_wait"] = {
                "kind": kind, "nonce_required": nonce is not None,
                "seen_kinds": sorted({row["type"] for row in values}),
                "target": self.record["target"],
            }
            matches = [row for row in values if row.get("type") == kind and
                       (nonce is None or row.get("nonce") == nonce)]
            if matches:
                self.require(len(matches) == 1 and matches[0].get("target") == self.record["target"],
                             "relay reply is duplicated or belongs to another run")
                return matches[0]
            self.require(time.monotonic() < deadline, "relay committed report deadline: " + kind)
            time.sleep(0.25)

    def request(self, command, request, *, denied=False, request_id=None, key=None):
        self.require(not self.record.get("refused"), "lane transport stopped at its first refusal")
        case = self.case
        saved = case.current
        nonce = uuid.uuid4().hex
        envelope = {"schema": "laneboss.item-rpc.v1", "nonce": nonce,
            "command": command, "request": request,
            "request_id": request_id or uuid.uuid4().hex,
            "idempotency_key": key or uuid.uuid4().hex}
        case.keep_json("rpc-" + nonce[:24] + ".input", envelope)
        content = case.human.upload("relay-input", "report", io.encoded(envelope))
        mail = {"recipient_life_id": self.record["target"]["life_id"],
                "content": content, "ask": False}
        proof = case.human.proof("control", "mail.send", mail,
            self.record["target"]["life_id"], self.status()["generation"])
        case.current = saved
        accepted = case.human.rpc("relay-mail", ["mail", "send"], mail, proof)
        self.require(accepted.get("id") and accepted.get("content") == content and
                     accepted.get("recipient_life_id") == mail["recipient_life_id"],
                     "relay request was not accepted by actual public mail")
        result = self.wait("grants.exiting" if command == "fixture exit" else "grants.reply", nonce)
        case.current = saved
        if not denied:
            self.refusal(result)
        elif result.get("exit_code") != 2 or json.loads(base64.b64decode(
                result["stderr"], validate=True)).get("code") not in {
                    "forbidden", "invalid_request", "conflict"}:
            self.record["refused"] = True
        return result

    def call(self, command, request):
        response = self.request(command, request)
        return json.loads(base64.b64decode(response["stdout"], validate=True))

    def upload(self, kind, raw):
        digest = sha(raw)
        begun = self.call("blob begin", {"class": kind, "bytes": len(raw), "sha256": digest})
        offset = 0
        while offset < len(raw):
            part = raw[offset:offset + min(262144, begun["max_chunk_bytes"]) ]
            self.call("blob chunk", {"object_id": begun["object_id"], "offset": offset,
                "data": base64.b64encode(part).decode(), "sha256": sha(part)})
            offset += len(part)
        ref = self.call("blob commit", {"object_id": begun["object_id"], "sha256": digest})
        self.require(ref == {"id": begun["object_id"], "class": kind,
                            "sha256": digest, "bytes": len(raw)}, "child upload bytes differ")
        return ref

    def status(self):
        return self.case.human.read("item-status", ["lane", "status"], self.record["target"])


def checked(case, target, require):
    lane = case.human.read("item-status", ["lane", "status"], target)
    observed = flow.control(case, "item-check", "lane.check", target,
                            target["life_id"], lane["generation"])
    require(observed.get("handle", {}).get("target") == target and
            observed["handle"].get("containment_id") and observed.get("observed_at"),
            "item process observation lost its exact containment")
    return lane, observed


def quiescent(case, record, require):
    deadline = time.monotonic() + 120
    while True:
        lane, observed = checked(case, record["target"], require)
        if observed.get("state") == "exited":
            require(observed.get("survivors") == 0 and observed.get("exit_code") == 0,
                    "item fixture did not exit normally with zero survivors")
            record["observation"] = observed
            return case.human.read("item-ended", ["lane", "status"], record["target"])
        require(observed.get("state") == "running" and time.monotonic() < deadline,
                "item fixture containment is unknown or still occupied")
        time.sleep(0.25)


def profile_members(grants, ids, require):
    """Select exact issued actor members; never invent a grant or reuse a seat."""
    require(set(ids) == {"parent", "child"} and all(isinstance(value, str) and
            re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value) for value in ids.values()) and
            len(set(ids.values())) == 2, "grants actor profile selectors are not distinct")
    result, issued = {}, set()
    for name in ("parent", "child"):
        matches = [row for row in grants["profiles"] if row.get("profile_id") == ids[name]]
        require(len(matches) == 1, "grants actor profile was not issued exactly once: " + name)
        profile = matches[0]
        identifier, expiry = profile.get("id"), profile.get("expires_at")
        require(profile.get("driver") == "codex" and profile.get("provider") == "serve-fixture" and
                profile.get("paid") is False and profile.get("delegate") is True and
                isinstance(expiry, str) and expiry and not profile.get("parent_grant_id") and
                isinstance(identifier, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identifier) and
                identifier not in issued, "grants actor profile differs from issued scope: " + name)
        try:
            expires = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
        except ValueError:
            require(False, "grants actor profile expiry is invalid: " + name)
        require(expires.tzinfo is not None and expires > datetime.now(timezone.utc),
                "grants actor profile is expired: " + name)
        issued.add(identifier)
        result[name] = profile
    return result


def reuse_profile(grants, ids, require):
    # This baseline member is delegated solely for the installed must-refuse
    # child. Successful actors keep their independently enrolled item seats.
    return profile_members(grants, {"parent": ids["parent"],
        "child": "serve-profile-codex"}, require)["child"]


def containment_proof(case, require):
    """Read metadata already measured by lane.codex.running/clean, never auth."""
    running, clean = (case.rows[name] for name in ("lane.codex.running", "lane.codex.clean"))
    require(all(row.get("result") == "pass" and row["observed"].get("executed") is True
                for row in (running, clean)), "seat-reuse control lacks the completed Codex lifecycle")
    observed = running["observed"]
    lane, live = observed["lane"], observed["observation"]
    target = {name: lane[name] for name in ("life_id", "run")}
    require(live.get("state") == "running" and type(live.get("survivors")) is int and
            live["survivors"] > 0 and live.get("handle", {}).get("target") == target,
            "seat-reuse source was not a running contained lane")
    raw = (case.root / "codex-cleanup-helper.input.json").read_bytes()
    require(sha(raw) == clean["observed"]["native_helper"]["journal_sha256"],
            "retained Codex helper metadata differs from its native read-back")
    journal = json.loads(raw)
    credentials = journal["credential_projection"]
    record = credentials["Record"]
    authority, withdrawal = record["Authority"], record["Withdrawal"]
    handoff = authority["Request"]["Handoff"]
    profile = handoff["spec"]["runner"]["slot"]["profile_id"]
    reason = credentials.get("local_stop", {}).get("Reason")
    require(journal.get("schema") == "laneboss.helper-lease.v2" and
            credentials.get("State") == record.get("State") == "withdrawn" and
            reason in ("cancelled", "revoked") and record["Fence"].get("Reason") == reason and
            withdrawal.get("RotationRequired") is True and withdrawal.get("AgentExecuted") is True and
            withdrawal.get("ProjectionID") == authority.get("ID") and
            withdrawal.get("HelperLeaseID") == journal["lease"].get("id") and
            withdrawal["Prepared"].get("target") == target and handoff.get("config") == case.config and
            handoff["spec"].get("target") == target and profile == "serve-profile-codex" and
            withdrawal["Prepared"].get("containment_id") == live["handle"].get("containment_id") and
            withdrawal["Observation"].get("handle") == live["handle"] and
            withdrawal["Observation"].get("state") == "exited" and
            type(withdrawal["Observation"].get("survivors")) is int and
            withdrawal["Observation"]["survivors"] == 0,
            "seat-reuse control requires ruling-b live containment, not a natural-exit release")
    return {"target": target, "profile_id": profile, "projection_id": authority["ID"],
            "journal_sha256": sha(raw)}


def reuse_refusal(operation, target, require):
    error = operation.get("error")
    require(operation.get("id") and operation.get("status") == "failed" and
            all(operation.get(name) == value for name, value in target.items()) and
            isinstance(error, dict) and error.get("owner") == "lb-v2-secrets" and
            error.get("code") == "forbidden" and error.get("message") ==
            "canonical credential is quarantined pending protected rotation",
            "quarantined child did not receive the exact canonical-seat refusal")
    return error


def quarantined_reuse(case, relay, lane, grants, source, require):
    case.current = "item.grants.reuse"
    proof = containment_proof(case, require)
    profile = reuse_profile(grants, case.grants_boot["profiles"], require)
    require(profile["profile_id"] == proof["profile_id"], "reuse child selected another seat")
    selected = {name: [] for name in FAMILIES}
    selected["data"] = [{"parent_grant_id": source["id"], "relative_path": "child",
        "access": "ro", "delivery": "copy", "destination": "/work/main",
        "delegate": False, "expires_at": source["expires_at"]}]
    selected["profiles"] = [{"parent_grant_id": profile["id"], "profile_id": profile["profile_id"],
        "delegate": False, "expires_at": profile["expires_at"]}]
    task = relay.upload("task", b"This child must be refused before execution by the quarantined-seat gate.\n")
    request = {"lane": "grants-reuse-" + uuid.uuid4().hex[:8], "project_id": "grants-child",
        "level": 3, "role": "executor", "task": task, "grants": selected,
        "driver": "codex", "profile_grant_id": profile["id"], "model": case.agent["version"],
        "effort": "low", "budget": case.grants_boot["budget"],
        "expected_policy_generation": lane["policy_generation"]}
    case.keep_json("reuse-child.input.json", request)
    operation = relay.call("lane start", request)
    require(operation.get("id") and operation.get("life_id") and operation.get("run") == 1,
            "reuse child has no actual planning reservation")
    target = {name: operation[name] for name in ("life_id", "run")}
    case.grants_reuse = {"target": target, "operation": operation, "collected": False}
    current, deadline = operation, time.monotonic() + 120
    while current.get("status") in ("pending", "running"):
        require(time.monotonic() < deadline, "quarantined-child refusal deadline")
        current = case.human.read("reuse-operation", ["operation", "get"], {"operation_id": operation["id"]})
        require(current.get("id") == operation["id"], "reuse operation identity changed")
        if current.get("status") in ("pending", "running"):
            time.sleep(0.25)
    case.keep_json("reuse-refusal.input.json", current)
    case.rows[case.current]["observed"] = {"executed": True, "operation": current}
    error = reuse_refusal(current, target, require)
    case.passed({"expectation": "must-refuse", "expected_refusal": error,
        "denied_operation": current, "contained_source": proof, "profile_id": profile["profile_id"]})
    case.current = "item.grants.prepare"


def finish_lifecycle(case, record, require, fail):
    if record.get("driver") != "codex":
        return False
    # The baseline seat is the later must-refuse reuse control. Its running
    # Stop must retain ruling-b quarantine. Successful item actors have their
    # own canonical seats; sharing one makes declining this hook unsafe.
    baseline = "serve-profile-codex"
    ids = case.grants_boot["profiles"]
    require(set(ids) == {"parent", "child"} and
            all(isinstance(value, str) and value for value in ids.values()) and
            len(set(ids.values())) == 2 and baseline not in ids.values(),
            "lifecycle stop would quarantine an item seat")
    request = record["request"]
    selected = request["grants"]["profiles"]
    require(len(selected) == 1 and selected[0].get("profile_id") == baseline and
            selected[0].get("parent_grant_id") == request.get("profile_grant_id") and
            bool(request.get("profile_grant_id")) and
            case.fixture_profile_selectors.get("codex") == baseline,
            "lifecycle stop did not select the isolated baseline seat")
    return False


def prepare(case, require, fail, blocked):
    case.human_prefix = "itemgrants"
    case.current = "item.grants.prepare"
    proposal = case.decode_document(case.root_launch_input(case.lane_inputs))["codex"]
    proposal["lane"] = "grants-parent-" + uuid.uuid4().hex[:8]
    selectors = case.fixture_profile_selectors
    case.fixture_profile_selectors = {**selectors, "codex": case.grants_boot["profiles"]["parent"]}
    try:
        ticket = case.human.ticket(proposal, case.root_grants)
    finally:
        case.fixture_profile_selectors = selectors
    root = case.human.read("item-profile-grants", ["grants", "get"], {"grant_set_id": ticket["grant_set_id"]})
    require(root.get("id") == ticket["grant_set_id"] and root.get("revoked") is False and
            type(root.get("generation")) is int and root["generation"] > 0 and not root.get("parent_life_id"),
            "grants actor root grant set is not current")
    members = profile_members(root, case.grants_boot["profiles"], require)
    require(proposal["profile_grant_id"] == members["parent"]["id"],
            "grants parent did not select its own issued execution profile")
    # Root binding selects one execution member. The L5 parent also needs the
    # child's separate member to delegate through the unchanged launch gates.
    proposal["grants"]["profiles"] = [{"parent_grant_id": row["id"], "profile_id": row["profile_id"],
        "delegate": row["delegate"], "expires_at": row["expires_at"]} for row in members.values()]
    baseline = reuse_profile(root, case.grants_boot["profiles"], require)
    proposal["grants"]["profiles"].append({"parent_grant_id": baseline["id"], "profile_id": baseline["profile_id"],
        "delegate": baseline["delegate"], "expires_at": baseline["expires_at"]})
    case.keep_json("grants-profiles.input.json", root)
    proposal["root_ticket_id"] = ticket["id"]
    case.current = "item.grants.prepare"
    proof = case.human.proof("read", "human.session", {}, case.human.public["principal_id"], 0)
    case.current = "item.grants.prepare"
    operation = case.checked_cli("item-parent-start", ["lane", "start"], proposal,
        idempotency_key=uuid.uuid4().hex, session_proof=str(proof))
    parent = {"name": "grants-parent", "target": {"life_id": operation["life_id"], "run": operation["run"]},
              "operation": operation, "collected": False}
    case.item_lives.append(parent)
    flow.await_operation(case, operation, require, fail, parent["target"])
    relay = Relay(case, parent, require, fail)
    parent["relay"] = relay
    ready = relay.wait("grants.ready")
    binding_raw = base64.b64decode(ready["binding_bytes"], validate=True)
    require(json.loads(binding_raw) == ready["binding"], "original sealed binding metadata bytes differ")
    binding = case.keep("grants-binding.input.json", binding_raw)
    lane = relay.status()
    require(ready["metadata_only"] is True and ready["identity"]["actor"]["level"] == 5 and
            lane["life_id"] == parent["target"]["life_id"], "parent metadata differs from original actor")
    grants = relay.call("grants get", {"grant_set_id": lane["grant_set_id"]})
    source = next(row for row in grants["data"] if
                  row["source_object_id"] == case.grants_boot["parent_tree"]["id"])
    fixed = next(row for row in grants["data"] if
                 row["source_object_id"] == case.grants_boot["fixed_tree"]["id"])
    require(len(grants["profiles"]) == 3, "grants parent has an unexpected actor profile inventory")
    quarantined_reuse(case, relay, lane, grants, source, require)
    selected = {name: [] for name in FAMILIES}
    selected["data"] = [{"parent_grant_id": source["id"], "relative_path": "child",
        "access": "ro", "delivery": "copy", "destination": "/work/main",
        "delegate": False, "expires_at": source["expires_at"]}]
    profile = profile_members(grants, case.grants_boot["profiles"], require)["child"]
    selected["profiles"] = [{"parent_grant_id": profile["id"], "profile_id": profile["profile_id"],
                             "delegate": False, "expires_at": profile["expires_at"]}]
    # A later child task is not selected by the initial publication. Commit it
    # through the live parent's normal blob API before that parent starts L3.
    case.keep("grants-child-task.input", CHILD_TASK)
    task = relay.upload("task", CHILD_TASK)
    child_request = {"lane": "grants-child-" + uuid.uuid4().hex[:8], "project_id": "grants-child",
        "level": 3, "role": "executor", "task": task, "grants": selected,
        "driver": "codex", "profile_grant_id": profile["id"], "model": case.agent["version"],
        "effort": "low", "budget": case.grants_boot["budget"],
        "expected_policy_generation": lane["policy_generation"]}
    operation = relay.call("lane start", child_request)
    child = {"name": "grants-child", "target": {"life_id": operation["life_id"], "run": operation["run"]},
             "operation": operation, "collected": False}
    case.item_lives.append(child)
    flow.await_operation(case, operation, require, fail, child["target"])
    actor = Relay(case, child, require, fail)
    child["relay"] = actor
    child_ready = actor.wait("grants.ready")
    require(child_ready["identity"]["actor"]["level"] == 3, "child is not a real L3 actor")
    files = [{"path": name, "kind": "file", "mode": 0o444 if name.endswith(".c") else 0o555,
              "content": actor.upload("artifact", raw)} for name, raw in sorted(case.grants_files.items())]
    files.append({"path": "input.txt", "kind": "file", "mode": 0o444,
                  "content": case.grants_boot["input"]})
    candidate = actor.upload("manifest", io.encoded({"schema": "laneboss.objects.v2", "entries": files}))
    child_lane = actor.status()
    budget = dict(case.grants_boot["budget"], wall_ms=60000, cpu_seconds=30)
    plan = {"schema": "laneboss.worker-plan.v2", "kind": "test", "executable": case.grants_boot["tools"]["sh"],
        "argv": ["sh", "child_task.sh", source["destination"] + "/private/canary"],
        "input": candidate, "grant_set_id": child_lane["grant_set_id"], "budget": budget}
    test_plan = actor.upload("manifest", io.encoded(plan))
    reason = relay.upload("task", b"Revoke the exact child after its bounded compiler and Git probe.\n")
    message = actor.upload("task", b"Resume must refuse after the child grant set is revoked.\n")
    actor.request("fixture exit", {})
    sibling("stopcont").run(case, parent, child, child_request, Relay, require, fail,
                            flow, sibling("provision"))
    child_lane = quiescent(case, child, require)
    child_grants = relay.call("grants get", {"grant_set_id": child_lane["grant_set_id"]})
    fixture = {"parent_life_id": lane["life_id"], "parent_grant_set_id": grants["id"],
        "policy_generation": lane["policy_generation"], "data_grant_id": source["id"],
        "nondelegable_grant_id": fixed["id"], "child": child["target"],
        "candidate": candidate, "test_plan": test_plan,
        "canary_path": source["destination"] + "/private/canary",
        "canary_observer": case.grants_boot["observer"],
        "revocation_request": {"grant_set_id": child_grants["id"],
            "expected_generation": child_grants["generation"], "reason": reason},
        "resume_request": {"target": child["target"], "expected_generation": child_lane["generation"],
            "message": message, "budget": budget}}
    case.current = "item.grants.prepare"

    def transport(request):
        case.current = "item.grants.run"
        try:
            return relay.request(request["command"], request["request"],
                denied=request.get("denied", False), request_id=request["request_id"],
                key=request["idempotency_key"])
        except fail:
            parent["refused"] = True
            raise

    return {"binding_file": binding, "profile_grant_ids": [],
        "inputs": {"grants-fixture.json": io.encoded(fixture)}, "transport": transport,
        "collect": lambda context, operations: collect(case, context, operations, require, fail)}


def release(receipt, target, operation, require):
    require(receipt.get("operation_id") == operation and receipt.get("lease_id") and
        receipt.get("containment_id") and receipt.get("observed_at") and
        receipt.get("quiescence", {}).get("handle", {}).get("target") == target and
        receipt["quiescence"].get("state") == "exited" and
        receipt["quiescence"]["handle"].get("containment_id") == receipt["containment_id"] and
        receipt.get("backend") == "linux-bwrap-landlock" and
        type(receipt["quiescence"].get("survivors")) is int and
        receipt["quiescence"]["survivors"] == 0 and all(
            type(receipt.get(key)) is int and receipt[key] == 0
            for key in ("live_connections", "queued_jobs", "writable_exports")),
        "worker helper release lacks independently measured known-zero facts")


def native_zero(case, receipt, require):
    for field in ("lease_id", "containment_id"):
        require(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", receipt[field]) is not None,
                "native observation has an invalid helper selector")
    helper = Path("/var/lib") / "laneboss-v2" / "helper" / case.config
    if not (helper / (receipt["lease_id"] + ".json")).is_file():
        return sibling("item_test_child").nested_native_zero(case, receipt, sibling("provision").read_protected)
    raw = sibling("provision").read_protected(helper / (receipt["lease_id"] + ".json"), mode=0o600)
    journal = json.loads(raw)
    require(journal.get("schema") == "laneboss.helper-lease.v2" and
            journal.get("lease", {}).get("id") == receipt["lease_id"] and
            journal["lease"].get("containment_id") == receipt["containment_id"] and
            journal.get("receipt") == receipt and journal.get("phase") == "released",
            "outside helper journal differs from its release receipt")
    name = "lease-" + sha(raw)[:20] + ".input.json"
    retained = case.root / name
    if retained.exists():
        require(retained.read_bytes() == raw, "retained helper journal bytes differ")
    else:
        case.keep(name, raw)
    group = (Path("/sys/fs/cgroup/system.slice") /
             ("laneboss-helper@" + case.config + ".service") /
             "lanes" / receipt["containment_id"])
    require(not group.is_symlink(), "outside cgroup observation is linked")
    if group.exists():
        processes = (group / "cgroup.procs").read_bytes()
        events = (group / "cgroup.events").read_bytes()
        fields = dict(line.split() for line in events.decode().splitlines())
        require(not processes.strip() and fields.get("populated") == "0",
                "outside cgroup still has processes")
    else:
        processes, events = b"", b""
    uid = journal["lease"]["uid"]
    require(type(uid) is int and uid > 0 and uid != case.admin["service"]["uid"],
            "outside observation lacks an isolated leased UID")
    survivors = []
    for path in Path("/proc").iterdir():
        if not path.name.isdecimal():
            continue
        try:
            raw_status = (path / "status").read_bytes()
            raw_stat = (path / "stat").read_bytes().rsplit(b")", 1)[1].split()
        except (FileNotFoundError, ProcessLookupError):
            continue
        uids = next(line.split()[1:] for line in raw_status.splitlines() if line.startswith(b"Uid:"))
        if uid in [int(value) for value in uids]:
            live = raw_stat[0] not in (b"Z", b"X")
            if not live:
                for thread in (path / "task").glob("*/stat"):
                    try:
                        state = thread.read_bytes().rsplit(b")", 1)[1].split()[0]
                    except (FileNotFoundError, ProcessLookupError):
                        continue
                    live = live or state not in (b"Z", b"X")
            if live:
                survivors.append({"pid": int(path.name), "start": raw_stat[19].decode()})
    require(not survivors, "outside leased UID still has live processes")
    return {"journal_sha256": sha(raw), "journal_input": name, "cgroup_present": group.exists(),
            "cgroup_procs_sha256": sha(processes), "cgroup_events_sha256": sha(events),
            "uid": uid, "survivors": survivors}


def collect_reuse(case, require):
    record = case.grants_reuse
    events = flow.events(case, record, require)
    require(not any(event.get("kind") in ("lane.started", "identity.bound", "credential.leased")
                    for event in events), "quarantined child crossed the execution gate")
    allocated = [event["payload"] for event in events if event.get("kind") == "helper.allocated" and
                 event.get("operation_id") == record["operation"]["id"]]
    require(len(allocated) == 1, "refused child has no unique original helper allocation")
    lease = allocated[0]
    require(all(isinstance(lease.get(name), str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", lease[name])
                for name in ("id", "containment_id")), "refused child has an invalid helper selector")
    path = Path("/var/lib/laneboss-v2/helper") / case.config / (lease["id"] + ".json")
    deadline = time.monotonic() + 120
    while True:
        raw = sibling("provision").read_protected(path, mode=0o600)
        journal = json.loads(raw)
        require(journal.get("schema") == "laneboss.helper-lease.v2" and journal.get("lease") == lease,
                "refused-child cleanup selected another native helper")
        if journal.get("phase") == "aborted":
            break
        require(time.monotonic() < deadline, "refused-child native abort did not finish")
        time.sleep(0.25)
    request, receipt = journal["abort"], journal["abort_receipt"]
    observation = receipt["quiescence"]
    require(request.get("operation_id") == record["operation"]["id"] and
            request["cause"].get("target") == record["target"] and receipt.get("lease_id") == lease["id"] and
            receipt.get("agent_executed") is False and observation.get("state") == "not_started" and
            type(observation.get("survivors")) is int and observation["survivors"] == 0 and
            observation["handle"].get("target") == record["target"] and
            observation["handle"].get("containment_id") == lease["containment_id"],
            "refused-child abort has no independently measured nonexecution receipt")
    uid = lease["uid"]
    require(type(uid) is int and uid > 0 and uid != case.admin["service"]["uid"],
            "refused-child abort has no isolated leased UID")
    survivors = sibling("secret_observer").uid_processes(uid)
    runtime = Path("/var/lib/laneboss-v2/lanes") / case.config / lease["id"]
    group = (Path("/sys/fs/cgroup/system.slice") / ("laneboss-helper@" + case.config + ".service") /
             "lanes" / lease["containment_id"])
    require(not survivors and not runtime.exists() and not runtime.is_symlink() and
            not group.exists() and not group.is_symlink(), "refused child retained native resources")
    case.keep("reuse-abort.input.json", raw)
    record["collected"] = True
    return {"target": record["target"], "abort": receipt, "uid": uid,
            "survivors": survivors, "journal_sha256": sha(raw)}


def collect(case, context, operations, require, fail):
    case.current = "item.grants.collection"
    case.human_prefix = "itemgrants"
    require(not any(record.get("refused") for record in case.item_lives),
            "item stopped at a native refusal; no alternate collection mutation is authorized")
    observations = []
    worker_operations = []
    for operation_id in operations:
        operation = case.human.read("item-operation", ["operation", "get"], {"operation_id": operation_id})
        require(operation.get("id") == operation_id and operation.get("status") == "succeeded",
                "managed item operation is not complete")
        worker_operations.append(operation)
    # Real test workers must have their own correlated helper release. A
    # revoked grant operation is not falsely credited as a worker allocation.
    child = next(record for record in case.item_lives if record["name"] == "grants-child")
    events = flow.events(case, child, require)
    test_ids = {event["operation_id"] for event in events if event.get("kind") == "worker.completed" and
                event.get("operation_id") in operations}
    require(len(test_ids) == 1, "actual child worker completion is absent or ambiguous")
    for operation_id in test_ids:
        releases = [event["payload"] for event in events if event.get("kind") == "helper.released" and
                    event.get("operation_id") == operation_id]
        require(len(releases) == 1, "worker has no unique actual helper release")
        receipt = releases[0]
        release(receipt, child["target"], operation_id, require)
        observations.append({"worker_release": receipt, "native": native_zero(case, receipt, require)})
    observations.extend(collect_fixtures(case, require, fail))
    observations.append(collect_reuse(case, require))
    case.current = "item.grants.collection"
    ref = io.keep(Path(context["evidence_root"]) / "outside-collection.json",
                  io.encoded({"observations": observations, "operations": worker_operations}))
    return {"processes_quiescent": all(record.get("collected") for record in case.item_lives),
        "temporary_resources_collected": all(record.get("collected") for record in case.item_lives),
        "operation_ids": list(operations), "evidence": [ref]}


def collect_fixtures(case, require, fail):
    observations = []
    for record in reversed(case.item_lives):
        if record.get("collected"):
            continue
        require(not record.get("collection_started"), "fixture collection already stopped at its original gate")
        record["collection_started"] = True
        lane, observed = checked(case, record["target"], require)
        if observed.get("state") == "running":
            if record.get("relay") is not None:
                record["relay"].request("fixture exit", {})
            else:
                reason = case.human.upload("item-stop-reason", "task", b"Collect the owned grants fixture.\n")
                operation = flow.control(case, "item-stop", "lane.stop", {
                    "target": record["target"], "expected_generation": lane["generation"], "reason": reason},
                    lane["life_id"], lane["generation"])
                flow.await_operation(case, operation, require, fail, record["target"])
        lane = quiescent(case, record, require)
        empty = {"id": "", "sha256": "", "bytes": 0, "class": ""}
        review = {"id": "", "reviewer": {"kind": "", "id": ""}, "diff": empty,
                  "checks": [], "record_inventory": empty, "refusal_resolution": [], "coverage": ""}
        request = {"target": record["target"], "expected_generation": lane["generation"],
                   "state": "abandoned", "review": review}
        operation = flow.control(case, "item-abandon", "lane.mark", request, lane["life_id"], lane["generation"])
        flow.await_operation(case, operation, require, fail, record["target"])
        lane = case.human.read("item-abandoned", ["lane", "status"], record["target"])
        archive = flow.control(case, "item-archive", "lane.archive",
            {"target": record["target"], "expected_generation": lane["generation"]}, lane["life_id"], lane["generation"])
        require(archive.get("id") and archive.get("archive_sha256") == archive.get("read_back_sha256") and
                archive.get("life_id") == lane["life_id"], "fixture archive read-back differs")
        if record.get("relay") is not None:
            record["relay"].verify_transcript()
        lane = case.human.read("item-archived", ["lane", "status"], record["target"])
        operation = flow.control(case, "item-clean", "lane.clean", {"target": record["target"],
            "expected_generation": lane["generation"], "archive_receipt_id": archive["id"]}, lane["life_id"], lane["generation"])
        completed = flow.await_operation(case, operation, require, fail, record["target"])
        native = case.native_cleanup_evidence(record, lane, completed)
        require(native.get("action") == "remove_clean", "fixture workspace or branch was retained")
        final = case.human.read("item-collected", ["lane", "status"], record["target"])
        require(final.get("cleaned") is True, "fixture collection was not committed")
        releases = [event["payload"] for event in flow.events(case, record, require)
                    if event.get("kind") == "helper.released" and
                    event["payload"].get("containment_id") == record["observation"]["handle"]["containment_id"]]
        require(len(releases) == 1, "fixture has no unique original helper release")
        release(releases[0], record["target"], releases[0]["operation_id"], require)
        observations.append({"target": record["target"], "observation": record["observation"],
            "archive": archive, "native": native, "status": final,
            "release": releases[0], "outside": native_zero(case, releases[0], require)})
        record["collected"] = True
    return observations


def abort(case, require, fail):
    failed = case.rows.get(case.failed_step, {}).get("observed", {})
    stopped = (failed.get("refusal") or (failed.get("operation") or {}).get("error") or
               any(record.get("refused") or record.get("collection_started") and not record.get("collected")
                   for record in case.item_lives))
    if not stopped and any(not record.get("collected") for record in case.item_lives):
        case.human_prefix = "itemgrants"
        case.current = "item.grants.collection"
        observations = collect_fixtures(case, require, fail)
        case.keep_json("abort-collection.input.json", {"observations": observations,
                       "acceptance": "not credited; original item failure is retained"})
    # A product refusal permits no alternate mutation route. Unit teardown
    # does not become item collection evidence.
    return [{"target": record["target"], "reason": "item collection did not complete; retain original gate"}
            for record in case.item_lives if not record.get("collected")]
