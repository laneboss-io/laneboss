"""Concrete stand-in secrets suite on a fresh, authorized Linux installation."""

import argparse
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import time


ROOT = Path(__file__).resolve().parents[4]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


SERVE = load("secrets_serve", ROOT / "scripts/v2-serve/run.py")
PRODUCER = load("secrets_producer", ROOT / "scripts/v2-serve/case_secrets.py")
OBSERVER = load("secrets_observer", ROOT / "scripts/v2-serve/secret_observer.py")
WIRE = load("secrets_wire", Path(__file__).with_name("wire.py"))
CASE = load("secrets_case", Path(__file__).with_name("run.py"))
DIAGNOSTICS = load("secrets_diagnostics", Path(__file__).with_name("diagnostics.py"))

require, sha = PRODUCER.require, PRODUCER.sha


def archive_revision():
    revision = os.environ.get("LB_SRC_REV", "")
    require(revision, "revision requires Git or LB_SRC_REV")
    require(re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision) is not None,
            "LB_SRC_REV must be a full Git object ID")
    return revision.encode("ascii") + b"\n"


def human_material(case, private=False):
    """Check serve's existing artifact and private files, never create substitutes."""
    tool = Path(case.authenticator)
    retained = case.root / "serve-authenticator.input"
    require(tool.is_file() and retained.is_file() and not tool.is_symlink() and
            tool.stat().st_mode & 0o111 and SERVE.digest(tool) == SERVE.digest(retained),
            "human identity requires the original built software authenticator")
    require(case.auth_info.get("program") == "laneboss-serve-authenticator" and
            case.auth_info.get("hardware_stood_in") is True and case.auth_info.get("presence") == "simulated",
            "human identity requires serve software authenticator provenance")
    if not private:
        return
    require(case.human is not None and case.human.public.get("config") == case.config,
            "human identity must be prepared for this configuration")
    directory = Path(case.human.private)
    info = directory.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.geteuid(),
            "human identity private directory is missing or unprotected")
    for name in ("key.der", "counter", "public.json"):
        info = (directory / name).lstat()
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.geteuid() and
                info.st_nlink == 1 and info.st_size > 0, "human identity private material is missing or unprotected")
    public = json.loads(CASE.read_bounded(directory / "public.json"))
    require(public == case.human.public, "human identity private descriptor differs from serve preparation")


def prepare_identity(case, diagnostics):
    diagnostics.run("human.enroll", human_material, case)
    diagnostics.run("human.enroll", case.prepare_human)
    diagnostics.protect((case.human.public["principal_id"],))
    diagnostics.run("human.enroll", human_material, case, private=True)
    diagnostics.run("human.enroll", case.human.enroll)
    diagnostics.run("initial.publish", case.publish_initial)
    diagnostics.run("human.session", case.human.session)


def human_endpoint(case, timeout=30):
    """A Type=simple start is not the service's native socket publication."""
    # The installed entry requires uid 0; component checks use their own
    # protected ordinary inputs and real Unix sockets under the test uid.
    binding = json.loads(OBSERVER.protected(Path(case.installed["binding_file"]), owner=os.geteuid()))
    require(binding.get("config") == case.config and binding.get("class") == "human" and
            binding.get("socket") == case.installed["socket"] and
            binding.get("service_uid") == case.installed["service_uid"] and
            binding.get("artifact_sha256") == case.installed["artifact_sha256"],
            "human service binding differs from its installed identity")
    deadline = time.monotonic() + timeout
    path = Path(binding["socket"])
    while True:
        try:
            info = path.lstat()
        except FileNotFoundError:
            require(time.monotonic() < deadline, "human service socket publication deadline")
            time.sleep(min(0.1, max(0, deadline - time.monotonic())))
            continue
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == binding["service_uid"] and
                info.st_gid == binding["service_gid"] and stat.S_IMODE(info.st_mode) == 0o660,
                "human service socket identity or mode differs")
        return {"binding_sha256": SERVE.digest(Path(case.installed["binding_file"])),
                "socket_device": info.st_dev, "socket_inode": info.st_ino, "socket_uid": info.st_uid, "socket_gid": info.st_gid}


def hidden_material(case, units=Path("/etc/systemd/system")):
    source = case.root / "hidden-canary.private"
    environment = case.root / "hidden-env.private"
    raw = PRODUCER.read(source, 65536)
    require(re.fullmatch(b"[0-9a-f]{96}", raw) is not None, "hidden environment source is not the retained random canary")
    require(PRODUCER.read(environment, 65536) == b"HIDDEN_TOKEN=" + raw + b"\n",
            "hidden environment differs from its prepared private source")
    fragments = {}
    for role in ("helper", "service"):
        unit = "laneboss-" + role + "@" + case.config + ".service"
        selected = units / (unit + ".d") / "secrets-baseline.conf"
        fragment = OBSERVER.protected(selected, maximum=65536, owner=os.geteuid())
        require(fragment == ("[Service]\nEnvironmentFile=" + str(environment) + "\n").encode(),
                "hidden environment unit does not consume its prepared private source")
        fragments[role] = sha(fragment)
    return {"canary_sha256": sha(raw), "environment_sha256": SERVE.digest(environment), "fragment_sha256": fragments}


def prepare_hidden(case, units=Path("/etc/systemd/system")):
    """Prepare this fresh configuration before serve starts either unit."""
    require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", case.config) is not None,
            "hidden environment requires the isolated installed configuration")
    PRODUCER.put(case.root / "hidden-canary.private", secrets.token_hex(48).encode())
    reporter = getattr(case, "diagnostics", None)
    if reporter is not None:
        reporter.protect((PRODUCER.read(case.root / "hidden-canary.private"),))
    environment = case.root / "hidden-env.private"
    PRODUCER.put(environment, b"HIDDEN_TOKEN=" + PRODUCER.read(case.root / "hidden-canary.private") + b"\n")
    for role in ("helper", "service"):
        parent = units / ("laneboss-" + role + "@" + case.config + ".service.d")
        parent.mkdir(mode=0o755)
        selected = parent / "secrets-baseline.conf"
        PRODUCER.put(selected, ("[Service]\nEnvironmentFile=" + str(environment) + "\n").encode())
        selected.chmod(0o644)
    case.command("hidden-unit-reload", ["systemctl", "daemon-reload"], clean=True)
    case.keep_json("hidden-baseline.setup.json", hidden_material(case, units))


def command_error(root, last):
    if not isinstance(last, dict):
        return None
    for field in ("stderr", "stdout"):
        name = last.get(field)
        if not isinstance(name, str) or Path(name).name != name:
            continue
        try:
            raw = CASE.read_bounded(Path(root) / name, 1048576)
            for line in [raw, *reversed(raw.splitlines()[-32:])]:
                try:
                    value = json.loads(line)
                except ValueError:
                    continue
                if isinstance(value, dict) and any(key in value for key in ("code", "error", "refusal", "result", "response")):
                    return value
        except (OSError, CASE.CaseFailure):
            continue
    return None


def stage_case_inputs(source, stage, archive, inventory):
    selected = list((source / "e2e/v2/cases/secrets").rglob("*"))
    selected.extend(source / "scripts/v2-serve" / name for name in ("case_secrets.py", "secret_observer.py"))
    with tarfile.open(archive, "a") as bundle:
        for path in sorted(selected):
            require(not path.is_symlink(), "linked case build input")
            if path.is_dir() or path.suffix == ".pyc" or "__pycache__" in path.parts:
                continue
            require(path.is_file(), "case build input is not an ordinary file")
            relative = path.relative_to(source)
            target = stage / relative
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            raw = path.read_bytes()
            with target.open("xb") as stream:
                stream.write(raw)
            target.chmod(0o644)
            require(target.read_bytes() == raw, "staged case build input differs")
            inventory.append({"path": str(relative), "sha256": sha(raw), "bytes": len(raw)})
            bundle.add(target, arcname=str(relative), recursive=False)


def archive_parts(connection, job, receipt, config, target, operation_id):
    require(job["Input"]["receipt_id"] == receipt["id"] and job["Input"]["intent"]["Request"]["target"] == target and
            job["Job"]["Intent"]["OperationID"] == operation_id, "native archive belongs to another receipt, operation or run")
    parts = job["Parts"]
    require(isinstance(parts, list) and parts, "actual archive has no retained parts")
    retained = []
    for ref in parts:
        rows = connection.execute("SELECT metadata, data FROM objects WHERE id=?", (ref["id"],)).fetchall()
        require(len(rows) == 1, "native archive part is missing or ambiguous")
        metadata, raw = json.loads(rows[0][0]), bytes(rows[0][1])
        require(metadata["Ref"] == ref and metadata["ACL"]["Config"] == config and metadata["ACL"]["LifeID"] == target["life_id"] and
                metadata["Origin"] == "service" and metadata["SourceOperationID"] == operation_id and
                len(raw) == ref["bytes"] and sha(raw) == ref["sha256"], "native archive part provenance or exact bytes differ")
        retained.append(raw)
        require(sum(map(len, retained)) <= 268435456, "native archive assembly exceeds its bound")
    raw = b"".join(retained)
    require(sha(raw) == receipt["archive_sha256"] == receipt["read_back_sha256"], "actual native archive assembly differs")
    return raw


def native_history(connection, ref, config, target):
    rows = connection.execute("SELECT metadata, data FROM objects WHERE id=?", (ref["id"],)).fetchall()
    require(len(rows) == 1, "actual private history object is missing or ambiguous")
    metadata, raw = json.loads(rows[0][0]), bytes(rows[0][1])
    require(metadata["Ref"] == ref and metadata["ACL"]["Config"] == config and
            target["life_id"] == metadata["ACL"]["LifeID"] and metadata["ACL"]["Owner"]["kind"] == "lane" and
            metadata["ACL"]["Audience"] == "owner" and metadata["SourceOperationID"] and
            0 < len(raw) == ref["bytes"] <= 65536 and ref["sha256"] == sha(raw),
            "actual private history object has another owner or bytes")
    return raw, metadata


class SecretInstall(SERVE.Case):
    """Select case-owned fixture bytes through the existing build protocol."""

    def archive(self):
        archive = super().archive()
        inventory = json.loads((self.root / "source-files.json").read_bytes())
        stage_case_inputs(self.source, self.stage, archive, inventory)
        for row in inventory:
            SERVE.provision.protected(self.stage / row["path"])
        # This is the actual build inventory, extended with case-owned inputs;
        # no shared installer or generated policy source is modified.
        (self.root / "source-files.json").write_bytes(SERVE.encoded(inventory))
        return archive

    def command(self, name, argv, **kwargs):
        reporter = getattr(self, "diagnostics", None)
        if reporter is None:
            return self._command(name, argv, **kwargs)
        with reporter.scope(self.current):
            try:
                return self._command(name, argv, **kwargs)
            except Exception as error:
                response = command_error(self.root, self.last)
                reporter.failure(error, response=response, last=self.last)
                raise

    def _command(self, name, argv, **kwargs):
        if name == "helper-unit-sources":
            require(argv == ["systemctl", "cat", "laneboss-helper@" + self.config + ".service"],
                    "hidden setup must precede serve's original helper policy capture")
            prepare_hidden(self)
        if name in {"start-helper", "start-service"}:
            hidden_material(self)
        if name == "revision" and not os.path.lexists(self.source / ".git"):
            revision = archive_revision()
            self.keep_json("source-revision.origin.json", {"schema": "laneboss.source-revision.v1",
                "origin": "runner.LB_SRC_REV", "git_metadata_present": False, "command_executed": False,
                "sha256": sha(revision), "bytes": len(revision)})
            return revision
        if name == "fixture-inputs":
            require(argv[-1] == "./cmd/laneboss/serve-fixture", "shared fixture build selection changed")
            argv = [*argv, "./e2e/v2/cases/secrets/agent"]
        output = super().command(name, argv, **kwargs)
        if name == "fixture-build":
            require(argv[-1] == "./cmd/laneboss/serve-fixture", "shared fixture build selection changed")
            binary = Path(argv[argv.index("-o") + 1])
            stock = binary.read_bytes()
            self.keep("stock-fixture.input", stock)
            super().command("secret-fixture-build", [*argv[:-1], "./e2e/v2/cases/secrets/agent"], **kwargs)
            self.keep_json("secret-fixture-selection.json", {
                "schema": "laneboss.secret-fixture-build.v1", "stock_sha256": sha(stock),
                "selected_sha256": sha(binary.read_bytes()), "selected_main": "e2e/v2/cases/secrets/agent",
                "scope": "both main packages built; actual union of module/vendor inputs retained"})
        return output


class Authority:
    def __init__(self, case):
        self.case, self.public = case, case.human.public

    def prove(self, method, body, target, generation):
        human_material(self.case, private=True)
        return self.case.human.proof("read", method, body, target, generation)


class Execution:
    def __init__(self, case, context, fixture, seed, sealer, reader):
        self.case, self.context, self.fixture, self.seed = case, context, fixture, seed
        self.root = Path(context["evidence_root"])
        self.inputs = Path(context["test_root"])
        self.authority = Authority(case)
        self.diagnostics = getattr(case, "diagnostics", None)
        self.client = WIRE.Client(context, self.authority, self.root / "wire", self.diagnostics)
        self.sequence, self.steps, self.lives, self.roots = 0, [], [], []
        self.sealer = sealer
        self.native = OBSERVER.NativeView(context, case.installation_file, reader["path"], reader["sha256"], self.retain)
        self.canaries = {name: PRODUCER.read(self.inputs / path, 65536) for name, path in fixture["canary_files"].items()}
        if self.diagnostics is not None:
            self.diagnostics.protect(self.canaries.values())
        self.hidden = OBSERVER.variants(self.canaries)
        self.expected_profiles = {row["profile_id"]: row for row in seed["profiles"]}
        require(context["profile_grant_ids"] and set(context["profile_grant_ids"]) == {row["id"] for row in seed["profiles"]},
                "stand-in scope requires actual nonempty enrolled seed grants")
        self.budget = copy.deepcopy(json.loads(Path(case.root_grants).read_bytes())["budget"])
        self.budget["wall_ms"] = 300000
        self.templates = json.loads(Path(case.lane_inputs).read_bytes())

    def retain(self, name, raw):
        self.sequence += 1
        path = self.root / ("%05d-" % self.sequence + name)
        PRODUCER.put(path, raw)
        return {"path": path.name, "sha256": sha(raw), "bytes": len(raw)}

    def read(self, method, body):
        result, _ = self.client.call("read-%04d" % (self.client.index + 1), method, body)
        return result

    def upload(self, kind, raw):
        begun, _ = self.client.call("upload-begin-%04d" % self.client.index, "blob.begin",
            {"class": kind, "bytes": len(raw), "sha256": sha(raw)}, mutation=True)
        require(begun.get("object_id") and begun.get("max_chunk_bytes", 0) > 0, "actual upload allocation is missing")
        for offset in range(0, len(raw), begun["max_chunk_bytes"]):
            part = raw[offset:offset + begun["max_chunk_bytes"]]
            self.client.call("upload-chunk-%04d" % self.client.index, "blob.chunk", {"object_id": begun["object_id"],
                "offset": offset, "data": base64.b64encode(part).decode(), "sha256": sha(part)}, mutation=True)
        ref, _ = self.client.call("upload-commit-%04d" % self.client.index, "blob.commit",
            {"object_id": begun["object_id"], "sha256": sha(raw)}, mutation=True)
        require(ref == {"id": begun["object_id"], "class": kind, "bytes": len(raw), "sha256": sha(raw)}, "actual upload commit differs")
        return ref

    def completed(self, operation):
        original = operation
        deadline = time.monotonic() + 120
        polls = []
        while operation.get("status") in {"pending", "running"}:
            require(time.monotonic() < deadline, "actual service operation deadline")
            operation, entry = self.client.call("operation-%04d" % self.client.index, "operation.get", {"operation_id": original["id"]})
            polls.append(entry)
            require(operation.get("id") == original["id"], "service operation identity changed")
            time.sleep(0.2)
        require(operation.get("status") in {"succeeded", "failed", "cancelled"}, "actual operation has no terminal outcome")
        return operation, polls

    def operation(self, name, method, body, target=None, generation=0, denial=None, primary=True):
        prepared = self.fixture["steps"][PRODUCER.STEPS.index(name)] if primary else None
        if prepared is not None:
            require(prepared["name"] == name and prepared["method"] == method, "prepared operation invokes another service method")
            PRODUCER.document(self.inputs / prepared["request"], body)
        result, entry = self.client.call(name, method, body, mutation=True, target=target, generation=generation, expected=denial,
            retry_key=prepared["idempotency_key"] if prepared else None,
            proof_record=self.inputs / prepared["proof"] if prepared else None)
        owned = self.own_start(name, body, result) if method == "lane.start" else None
        entry["polls"] = []
        if result.get("status") in {"pending", "running"}:
            result, entry["polls"] = self.completed(result)
        if method == "lane.start":
            current = self.own_start(name, body, result)
            require(owned is None or current is None or current is owned, "completed start changed its reserved life")
        error = result.get("error")
        if denial is None:
            if error or result.get("status") in {"failed", "cancelled"}:
                raise WIRE.RPCFailure("actual service operation failed", result)
        else:
            require(isinstance(error, dict) and error.get("code") in denial, "negative control did not reach its actual boundary")
            if name == "reserved":
                require(error.get("message") == "secret target is a reserved or invalid environment name", "reserved control reached another refusal")
        entry["outcome"] = result
        if primary:
            self.steps.append(entry)
        return result

    def own_start(self, name, body, operation):
        if not operation.get("life_id") or type(operation.get("run")) is not int or operation["run"] < 1:
            return None
        target = {"life_id": operation["life_id"], "run": operation["run"]}
        for record in self.lives:
            if record["target"] == target:
                require(record["operation"]["id"] == operation["id"] and record["request"] == body,
                        "start ownership changed its reserved operation or request")
                record["operation"] = operation
                return record
        record = {"target": target, "operation": operation, "request": body, "name": name, "cleaned": False}
        self.lives.append(record)
        return record

    def root_grants(self, infos=()):
        approved = json.loads((self.case.root / "initial-inputs" / self.case.initial["profiles"]["id"]).read_bytes())
        approved["secrets"] = []
        for info, delivery, target in infos:
            approved["secrets"].append({"id": "", "name": info["name"], "source_handle": info["source_handle"],
                "version": info["version"], "delivery": delivery, "target": target, "delegate": False,
                "expires_at": self.seed["expires_at"]})
        for row in approved["profiles"]:
            expected = self.expected_profiles.get(row["profile_id"])
            require(expected and all(row[key] == expected[key] for key in ("driver", "provider", "paid", "expires_at", "delegate")),
                    "new root manifest selects another enrolled stand-in profile")
        raw = json.dumps(approved, sort_keys=True, separators=(",", ":")).encode()
        body = {"manifest": self.upload("manifest", raw), "budget": self.budget}
        result = self.operation("root-%04d" % self.client.index, "grants.root", body, primary=False)
        require(result.get("id") and len(result["secrets"]) == len(infos), "actual root-secret issuance is incomplete")
        self.roots.append({"request": body, "manifest": approved, "grants": result, "call": self.client.calls[-1]})
        return result

    def request(self, name, plan, grants, driver="codex"):
        selected = [row for row in grants["profiles"] if row["driver"] == driver]
        require(len(selected) == 1, "actual enrolled profile selection is ambiguous")
        profile = selected[0]
        expiry = min(datetime.fromisoformat(grants["expires_at"].replace("Z", "+00:00")), datetime.now(timezone.utc) + timedelta(seconds=90))
        ticket_body = {"level": 5, "role": "supervisor", "grant_set_id": grants["id"], "expires_at": expiry.strftime("%Y-%m-%dT%H:%M:%SZ")}
        ticket = self.operation("ticket-%04d" % self.client.index, "ticket.issue", ticket_body,
                                target=grants["id"], generation=grants["generation"], primary=False)
        require(ticket.get("id") and ticket.get("grant_set_id") == grants["id"], "actual root ticket differs from issued grants")
        selections = {key: [] for key in ("resources", "data", "secrets", "profiles", "network", "channels")}
        for row in grants["data"]:
            selections["data"].append({"parent_grant_id": row["id"], **{key: row[key] for key in
                ("relative_path", "access", "delivery", "destination", "delegate", "expires_at")}})
        for row in grants["secrets"]:
            selections["secrets"].append({"parent_grant_id": row["id"], **{key: row[key] for key in
                ("name", "version", "delivery", "target", "delegate", "expires_at")}})
        selections["profiles"] = [{"parent_grant_id": profile["id"], "profile_id": profile["profile_id"],
                                    "delegate": False, "expires_at": profile["expires_at"]}]
        return {"lane": "secrets-" + name + "-" + secrets.token_hex(4), "project_id": self.templates[driver]["project_id"], "level": 5,
            "role": "supervisor", "task": self.upload("task", json.dumps(plan, sort_keys=True).encode()), "grants": selections,
            "driver": driver, "profile_grant_id": profile["id"], "model": self.case.agent["version"], "effort": "low",
            "budget": self.budget, "root_ticket_id": ticket["id"], "expected_policy_generation": grants["policy_generation"]}

    def events(self, target):
        events, pages = OBSERVER.event_pages(self.read, target, self.context["config"])
        self.retain("event-pages.json", json.dumps(pages).encode())
        return events

    def capture(self, record, stream="stdout", wait=True, lines=1):
        deadline = time.monotonic() + 60
        while True:
            events = self.events(record["target"])
            matches = [event for event in events if event.get("kind") == "capture.appended" and
                       event.get("payload", {}).get("stream") == stream]
            if matches:
                raw, payload = OBSERVER.primary(self.read, events, record["target"], record["operation"], stream)
                if raw.endswith(b"\n") and len(raw.splitlines()) >= lines:
                    return raw, events, payload
            require(wait and time.monotonic() < deadline, "actual primary capture is missing")
            time.sleep(0.2)

    @DIAGNOSTICS.tracked("lane.start")
    def started(self, name, body, primary=True, lines=1):
        operation = self.operation(name, "lane.start", body, primary=primary)
        require(operation.get("life_id") and type(operation.get("run")) is int, "actual start did not reserve a run")
        record = self.own_start(name, body, operation)
        capture, events, payload = self.capture(record, lines=lines)
        native_capture, events, _ = self.capture(record, "stderr")
        facts = [json.loads(line) for line in native_capture.splitlines() if line.startswith(b"{")]
        require(len(facts) == 1, "actual child native facts are absent or ambiguous")
        journal = self.native.measure(record["target"], events, facts[0])
        record.update(capture=capture, facts=facts[0], journal=journal, payload=payload)
        return record

    def status(self, record):
        result = self.read("lane.status", record["target"])
        require(result["life_id"] == record["target"]["life_id"] and result["run"] == record["target"]["run"], "status selected another run")
        return result

    @DIAGNOSTICS.tracked("lane.quiescence", driver=True)
    def quiet(self, record, name, primary=False):
        lane = self.status(record)
        reason = self.upload("task", ("secrets fixture stop " + name).encode())
        request = {"target": record["target"], "expected_generation": lane["generation"], "reason": reason}
        if self.diagnostics is None:
            self.operation(name, "lane.stop", request, target=lane["life_id"], generation=lane["generation"], primary=primary)
        else:
            self.diagnostics.run("lane.stop", self.operation, name, "lane.stop", request,
                                 target=lane["life_id"], generation=lane["generation"], primary=primary)
        deadline = time.monotonic() + 60
        while True:
            lane = self.status(record)
            observed = self.operation("check-%04d" % self.client.index, "lane.check", record["target"],
                target=lane["life_id"], generation=lane["generation"], primary=False)
            if observed.get("state") == "exited":
                require(type(observed.get("survivors")) is int and observed["survivors"] == 0, "actual run has unknown survivors")
                record["quiescent"] = True
                return
            require(time.monotonic() < deadline, "actual run did not become quiescent")
            time.sleep(0.2)

    @DIAGNOSTICS.tracked("lane.archive", driver=True)
    def archive(self, record, name, primary=False):
        lane = self.status(record)
        empty = {"id": "", "sha256": "", "bytes": 0, "class": ""}
        review = {"id": "", "reviewer": {"kind": "", "id": ""}, "diff": empty, "checks": [],
                  "record_inventory": empty, "refusal_resolution": [], "coverage": ""}
        self.operation("abandon-%04d" % self.client.index, "lane.mark", {"target": record["target"],
            "expected_generation": lane["generation"], "state": "abandoned", "review": review},
            target=lane["life_id"], generation=lane["generation"], primary=False)
        lane = self.status(record)
        receipt = self.operation(name, "lane.archive", {"target": record["target"], "expected_generation": lane["generation"]},
            target=lane["life_id"], generation=lane["generation"], primary=primary)
        require(receipt.get("life_id") == lane["life_id"] and receipt.get("archive_sha256") == receipt.get("read_back_sha256"),
                "actual archive did not retain exact verified bytes")
        record["archive"] = receipt
        # Receipt.Manifest is the frozen tree, not the tar. Read the actual
        # committed archive job and its private object bytes independently.
        # Native provenance is checked; no tar is rebuilt from producer data.
        calls = [entry for entry in self.client.calls if entry["name"] == name and entry["method"] == "lane.archive"]
        require(len(calls) == 1, "actual archive call is missing or ambiguous")
        call = calls[0]
        frame = json.loads((self.root / call["directory"] / "selected.json").read_bytes())["request"]
        database = Path(self.case.installed["state_directory"]) / "state.sqlite"
        connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            row = connection.execute("SELECT operation, request FROM receipts WHERE method=? AND key=?",
                ("lane.archive", frame["idempotency_key"])).fetchall()
            require(len(row) == 1 and json.loads(row[0][1])["request_id"] == frame["request_id"], "native archive receipt has no actual request")
            operation = json.loads(row[0][0])
            job = connection.execute("SELECT data FROM projections WHERE kind=? AND id=?", ("archive_job", operation["id"])).fetchall()
            require(len(job) == 1, "native archive job is missing or ambiguous")
            native_job = json.loads(job[0][0])
            raw = archive_parts(connection, native_job, receipt, self.context["config"], record["target"], operation["id"])
        finally:
            connection.close()
        self.retain("archive-job.json", job[0][0].encode() if isinstance(job[0][0], str) else job[0][0])
        OBSERVER.archive_values(raw, self.hidden)
        record["archive_bytes"] = raw
        return receipt

    @DIAGNOSTICS.tracked("lane.clean", driver=True)
    def clean(self, record, name, primary=False):
        lane = self.status(record)
        self.operation(name, "lane.clean", {"target": record["target"], "expected_generation": lane["generation"],
            "archive_receipt_id": record["archive"]["id"]}, target=lane["life_id"], generation=lane["generation"], primary=primary)
        final = self.status(record)
        require(final.get("cleaned") is True, "actual cleanup operation left the lane uncollected")
        record["cleaned"] = True

    @DIAGNOSTICS.tracked("first.eight")
    def first_eight(self):
        try:
            PRODUCER.preparation(self.context, self.fixture, self.authority, self.sealer)
        except Exception as error:
            if self.diagnostics is not None:
                response = command_error(self.root, {"stderr": "human-client.err", "stdout": "human-client.out"})
                self.diagnostics.failure(error, response=response)
            raise
        directory = self.root / "wire" / "persistent"
        directory.mkdir(mode=0o700)
        for source, target in (("human-client.out", "wire.jsonl"), ("human-client.argv.json", "argv.json"),
                               ("human-client.native.json", "native.json"), ("human-client.exit.json", "exit.json")):
            PRODUCER.put(directory / target, PRODUCER.read(self.root / source, 16777216))
        rows = json.loads(PRODUCER.read(self.root / "human-flow.json"))
        receipts = {}
        for index, row in enumerate(rows):
            body = PRODUCER.read(self.inputs / self.fixture["steps"][index]["request"])
            request_path = self.root / "wire" / ("persistent-%02d.request.json" % index)
            PRODUCER.put(request_path, body)
            response = json.loads(PRODUCER.read(self.root / row["response"]["path"]))
            receipts[row["name"]] = response["result"]
            self.steps.append({"name": row["name"], "method": row["method"], "directory": "wire/persistent",
                "request": str(request_path.relative_to(self.root)), "request_sha256": sha(body),
                "wire_sha256": sha((directory / "wire.jsonl").read_bytes()), "exit": 0, "polls": [], "outcome": response["result"]})
        return receipts

    @DIAGNOSTICS.tracked("bad.stage")
    def bad_stage(self):
        directory = self.root / "wire" / "bad-stage"
        paths = {name: self.inputs / ("bad-" + name + ".json") for name in ("key", "stage", "import", "proof")}
        prepared = self.fixture["steps"][PRODUCER.STEPS.index("bad-stage")]
        paths["import"], paths["proof"] = self.inputs / prepared["request"], self.inputs / prepared["proof"]
        PRODUCER.document(paths["key"], {})
        session = self.authority.prove("human.session", {}, self.authority.public["principal_id"], 0)
        steps = [{"name": "bad-key", "method": "secret.key", "request": str(paths["key"])},
                 {"name": "bad-upload", "method": "secret.stage", "request": str(paths["stage"]), "idempotency_key": secrets.token_hex(16)},
                 {"name": "bad-stage", "method": "secret.import", "request": str(paths["import"]), "proof": str(paths["proof"]), "idempotency_key": prepared["idempotency_key"]}]
        callback_state = {}

        def callback(record):
            if record["name"] == "bad-key":
                WIRE.frame(record, self.context, "bad-key", "secret.key", {})
                key = record["response"]["result"]
                metadata = {"config": self.context["config"], "name": "bad-" + secrets.token_hex(8), "version": "v1", "key": key,
                            "material": str(self.inputs / self.fixture["canary_files"]["env"])}
                spec = self.inputs / "bad-seal.json"
                PRODUCER.document(spec, metadata)
                completed = subprocess.run([self.sealer["path"], str(spec)], capture_output=True, check=False, timeout=30)
                self.retain("bad-seal.out", completed.stdout)
                self.retain("bad-seal.err", completed.stderr)
                require(completed.returncode == 0 and sha(Path(self.sealer["path"]).read_bytes()) == self.sealer["sha256"], "actual bad-stage sealer refused or changed")
                sealed = json.loads(completed.stdout)
                ciphertext = bytearray(base64.b64decode(sealed["ciphertext"], validate=True))
                ciphertext[-1] ^= 1
                sealed["ciphertext"] = base64.b64encode(ciphertext).decode()
                callback_state["stage"] = sealed
                PRODUCER.document(paths["stage"], sealed)
            elif record["name"] == "bad-upload":
                WIRE.frame(record, self.context, "bad-upload", "secret.stage", callback_state["stage"])
                staged = record["response"]["result"]
                body = {"name": staged["name"], "version": staged["version"], "sealed_upload_id": staged["id"]}
                proof = self.authority.prove("secret.import", body, self.context["config"], 0)
                PRODUCER.put(paths["proof"], PRODUCER.read(proof))
                PRODUCER.document(paths["import"], body)

        code, records = WIRE.flow(self.context, directory, session, steps, callback)
        selected = [row for row in records if row.get("name") == "bad-stage"]
        require(len(selected) == 1 and code != 0, "bad stage did not reach its actual same-connection import")
        body = PRODUCER.read(paths["import"])
        response = WIRE.frame(selected[0], self.context, "bad-stage", "secret.import", json.loads(body))
        require(response.get("error", {}).get("code") == "integrity", "bad stage failed before actual GCM authentication")
        request = self.root / "wire" / "bad-import.request.json"
        PRODUCER.put(request, body)
        self.steps.append({"name": "bad-stage", "method": "secret.import", "directory": "wire/bad-stage",
            "request": str(request.relative_to(self.root)), "request_sha256": sha(body),
            "wire_sha256": sha((directory / "wire.jsonl").read_bytes()), "exit": code, "polls": [], "outcome": {"error": response["error"]}})

    @DIAGNOSTICS.tracked("unit")
    def unit(self, action, role, expected=0):
        unit = "laneboss-" + role + "@" + self.context["config"] + ".service"
        self.sequence += 1
        command = ["systemctl", "show", "--value", "-p", "MainPID", unit] if action == "show" else ["systemctl", action, unit]
        completed = subprocess.run(command, capture_output=True, timeout=60, check=False)
        self.retain("unit.out", completed.stdout)
        self.retain("unit.err", completed.stderr)
        self.retain("unit.exit.json", json.dumps({"exit": completed.returncode, "role": role, "action": action}).encode())
        require((completed.returncode == 0) if expected == 0 else (completed.returncode != 0), "native unit control did not reach its intended state")
        pid = subprocess.run(["systemctl", "show", "--value", "-p", "MainPID", unit], capture_output=True, timeout=30, check=False)
        require(pid.returncode == 0, "native unit process observation failed")
        return int(pid.stdout.strip())

    def hidden_baseline(self):
        # Serve already started these exact units. Restarting their credential
        # listeners would correctly require administrator recovery.
        require(not self.read("lane.list", {"cursor": "", "limit": 100}).get("lanes"), "native baseline setup requires an empty isolated configuration")
        prepared = hidden_material(self.case)
        require(prepared["canary_sha256"] == sha(self.canaries["undelegated"]),
                "hidden baseline source differs from the original unit input")
        self.retain("hidden-baseline.observed.json", json.dumps(prepared).encode())
        observed = (self.diagnostics.run("human.endpoint", human_endpoint, self.case)
                    if self.diagnostics is not None else human_endpoint(self.case))
        self.retain("human-endpoint.ready.json", json.dumps(observed).encode())
        self.read("identity.self", {})

    @DIAGNOSTICS.tracked("key.controls")
    def key_controls(self, injection_plan, root):
        installed = self.case.installed
        key = Path(installed["secret_directory"]) / "keys" / (installed["secret_key_handle"] + ".key")
        withheld = key.with_name(key.name + ".withheld")
        key_sha = sha(key.read_bytes())
        recovery = self.inputs / "recovery-key.private"
        PRODUCER.put(recovery, secrets.token_bytes(32))
        grants = root["secrets"]
        code, backup = self.native.inspect("backup", grants=grants, recovery=recovery)
        require(code == 0 and backup.get("backup"), "actual native recovery backup failed")
        backup_path = self.inputs / "recovery.sealed"
        PRODUCER.put(backup_path, base64.b64decode(backup["backup"], validate=True))
        locked_request = self.request("restart-locked", injection_plan, root)
        old_pid = self.unit("show", "credential")
        self.unit("stop", "credential")
        require(not withheld.exists(), "preserve previous withheld key evidence")
        key.rename(withheld)
        try:
            self.unit("start", "credential", expected=1)
            code, locked = self.native.inspect("locked", grants=grants)
            require(code != 0 and locked.get("error", {}).get("code") == "prerequisite_missing" and not locked["digests"],
                    "actual native restart used an undisclosed key fallback")
            self.operation("restart-locked", "lane.start", locked_request, denial={"prerequisite_missing", "unavailable"})
            code, recovered = self.native.inspect("recover", grants=grants, recovery=recovery, backup=backup_path)
            require(code == 0 and all(recovered["digests"].get(grant["source_handle"]) == sha(self.canaries["env" if grant["delivery"] == "env" else "file"])
                                     for grant in grants), "native protected recovery returned different selected bytes")
        finally:
            require(not key.exists() and withheld.exists(), "withheld native key identity changed")
            withheld.rename(key)
            require(sha(key.read_bytes()) == key_sha, "restored native key differs")
            require(self.unit("start", "credential") > 1, "recovered native owner did not start")
        recovered_run = self.started("recover", self.request("recover", injection_plan, root), lines=4)
        require(all(OBSERVER.probe_verdicts(recovered_run["capture"]).values()), "actual post-recovery confined injection differs")
        self.quiet(recovered_run, "recover-stop")
        self.archive(recovered_run, "recover-archive")
        self.clean(recovered_run, "recover-clean")
        self.control_evidence = {"locked": locked, "recovered": recovered, "old_broker_pid": old_pid,
                                 "recovery_target": recovered_run["target"]}
        tamper_request = self.request("tamper", injection_plan, root)
        record = Path(installed["secret_directory"]) / "records" / (grants[0]["source_handle"] + ".json")
        original = record.read_bytes()
        original_info = record.stat()
        envelope = json.loads(original)
        changed = bytearray(base64.b64decode(envelope["ciphertext"], validate=True))
        changed[-1] ^= 1
        envelope["ciphertext"] = base64.b64encode(changed).decode()
        altered = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
        broker_pid = self.unit("show", "credential")
        require(broker_pid > 1, "native tamper control requires the actual running broker")
        with record.open("wb") as stream:
            stream.write(altered)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            require(record.stat().st_ino == original_info.st_ino and record.read_bytes() == altered and sha(altered) != sha(original),
                    "encrypted native tamper control did not change its actual record")
            code, tampered = self.native.inspect("journal", grants=grants)
            require(code != 0 and tampered.get("error", {}).get("code") == "integrity", "native GCM tamper was accepted")
            self.operation("tamper", "lane.start", tamper_request, denial={"integrity"})
            self.control_evidence["tampered"] = tampered
        finally:
            with record.open("wb") as stream:
                stream.write(original)
                stream.flush()
                os.fsync(stream.fileno())
            require(record.read_bytes() == original and record.stat().st_ino == original_info.st_ino, "encrypted native record restoration differs")
            require(self.unit("show", "credential") == broker_pid, "native broker generation changed during the tamper control")

    @DIAGNOSTICS.tracked("baseline")
    def baseline(self):
        self.hidden_baseline()
        baseline_root = self.root_grants()
        baseline_plan = {"schema": "laneboss.secret-task.v1", "mode": "baseline", "reserved_env_name": "PATH", "nonce": secrets.token_hex(16)}
        baseline = self.started("baseline", self.request("baseline", baseline_plan, baseline_root, "claudock-cli"), primary=False)
        baseline_value = json.loads(baseline["capture"])
        require(baseline_value.get("own_profile_turn") is True and baseline_value.get("vendor_stood_in") is True,
                "actual baseline did not use its enrolled stand-in credential")
        database = Path(self.case.installed["state_directory"]) / "state.sqlite"
        connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            history, metadata = native_history(connection, baseline_value["history_ref"], self.context["config"], baseline["target"])
        finally:
            connection.close()
        self.retain("baseline-history.native.json", json.dumps(metadata).encode())
        require(sha(history) == baseline_value["history_sha256"], "outside history read differs from actual child-created bytes")
        self.quiet(baseline, "baseline-stop")
        self.archive(baseline, "baseline-archive")
        self.clean(baseline, "baseline-clean")
        self.baseline_value = baseline_value
        self.baseline_archive = baseline["archive"]

    @DIAGNOSTICS.tracked("SECRET-INJECT")
    def secret_phase(self):
        baseline_value = self.baseline_value
        plan = json.loads(PRODUCER.read(self.inputs / "secret-inputs/probe-plan.pending.json"))
        plan["reserved_sha256"] = baseline_value["reserved_sha256"]
        outside = Path(self.native.reader).parent / "hidden-control.private"
        PRODUCER.put(outside, self.canaries["undelegated"])
        outside.chmod(0o444)
        require(outside.read_bytes() == self.canaries["undelegated"] and outside.stat().st_mode & 0o777 == 0o444 and
                outside.parent.stat().st_mode & 0o777 == 0o755, "outside hidden-file control is not readable")
        plan["hidden_file_paths"] = [str(outside)]
        plan.update(schema="laneboss.secret-task.v1", mode="injection", nonce=secrets.token_hex(16))
        PRODUCER.document(self.inputs / "secret-inputs/probe-plan.json", plan)
        receipts = self.first_eight()
        sources = [(receipts["import-env"], "env", plan["env_name"]), (receipts["import-file"], "file", "task.key")]
        root = self.root_grants(sources)
        hidden_root = self.root_grants([(receipts["import-hidden"], "env", "HIDDEN_TOKEN")])
        injection = self.started("start", self.request("start", plan, root), lines=4)
        self.injection = injection
        require(all(OBSERVER.probe_verdicts(injection["capture"]).values()), "actual confined injection comparison failed")
        reserved = self.request("reserved", plan, root)
        reserved["grants"]["secrets"][0]["target"] = "PATH"
        self.operation("reserved", "lane.start", reserved, denial={"forbidden"})
        wider = self.request("wider", plan, root)
        hidden = hidden_root["secrets"][0]
        wider["grants"]["secrets"].append({"parent_grant_id": hidden["id"], **{key: hidden[key] for key in
            ("name", "version", "delivery", "target", "delegate", "expires_at")}})
        self.operation("wider", "lane.start", wider, denial={"forbidden"})
        self.bad_stage()
        self.quiet(injection, "stop", primary=True)
        self.archive(injection, "archive", primary=True)
        self.clean(injection, "injection-clean")
        self.key_controls(plan, root)

    @DIAGNOSTICS.tracked("CREDENTIAL-BOUND")
    def credential_phase(self):
        baseline_value = self.baseline_value
        selected_other = [row for row in self.seed["profiles"] if row["driver"] == "claudock-cli"]
        require(len(selected_other) == 1, "actual other-profile enrollment is ambiguous")
        code, native_profiles = self.native.inspect("journal", profiles=[selected_other[0]["profile_id"]])
        require(code == 0 and len(native_profiles["profiles"]) == 1, "outside enrolled profile observation is missing")
        other = native_profiles["profiles"][0]
        secret_base = Path(self.case.installed["secret_directory"])
        other_path = secret_base / "records" / (other["Source"]["source_handle"] + ".json")
        require(other_path.is_file() and other_path.stat().st_size > 0, "outside other-profile control does not exist")
        credential_plan = {"schema": "laneboss.secret-task.v1", "mode": "credential", "nonce": secrets.token_hex(16),
            "other_profile": str(other_path), "other_history_id": baseline_value["history_ref"]["id"],
            "registry": str(secret_base / "records"), "keyring": str(secret_base / "keys")}
        credential_root = self.root_grants()
        credential = self.started("lease-first", self.request("lease-first", credential_plan, credential_root))
        self.credential = credential
        credential_value = json.loads(credential["capture"])
        self.credential_mounts = OBSERVER.mount_excludes(
            self.native.inventories[(credential["target"]["life_id"], credential["target"]["run"])]["witness"]["pid"],
            [secret_base / "records", secret_base / "keys", other_path])
        slot = credential["journal"]["spec"]["handoff"]["spec"]["runner"]["slot"]
        code, first = self.native.inspect("journal", profiles=[slot["profile_id"]], slots=[slot["id"]])
        require(code == 0 and first["profiles"][0]["Mode"] == "codex-file" and first["profiles"][0]["LoginPresent"] is True and
                first["profiles"][0]["RefreshLocked"] is True, "actual selected login has no exclusive native refresh owner")
        competing = self.request("lease-second", credential_plan, credential_root)
        self.operation("lease-second", "lane.start", competing, denial={"conflict"})
        code, second = self.native.inspect("journal", profiles=[slot["profile_id"]], slots=[slot["id"]])
        require(code == 0 and first["profiles"] == second["profiles"], "competing service lease changed the actual native refresh owner")
        lane = self.status(credential)
        self.operation("release-running", "lane.clean", {"target": credential["target"], "expected_generation": lane["generation"],
            "archive_receipt_id": self.baseline_archive["id"]}, target=lane["life_id"], generation=lane["generation"],
            denial={"conflict", "containment_unknown"})
        code, running = self.native.inspect("journal", profiles=[slot["profile_id"]], slots=[slot["id"]])
        require(code == 0 and running["slots"][0]["Released"] is False and running["slots"][0]["ProjectionID"],
                "actual selected credential was removed before quiescence")
        self.quiet(credential, "credential-stop")
        self.archive(credential, "credential-archive")
        self.clean(credential, "release-quiet", primary=True)
        code, quiet = self.native.inspect("journal", profiles=[slot["profile_id"]], slots=[slot["id"]])
        require(code == 0 and quiet["slots"][0]["Released"] is True and not quiet["profiles"][0]["RefreshLocked"],
                "actual native credential lease survived quiet cleanup")
        self.credential_evidence = {"capture": credential_value, "first": first, "second": second, "running": running, "quiet": quiet,
                                    "other_profile_source": str(other_path), "history_ref": baseline_value["history_ref"],
                                    "history_target": [record["target"] for record in self.lives if record["name"] == "baseline"][0]}

    @DIAGNOSTICS.tracked("collection")
    def collect_owned(self):
        failures = []
        for record in self.lives:
            if record["cleaned"]:
                continue
            try:
                if not record.get("quiescent"):
                    self.quiet(record, "collect-stop-" + record["name"])
                if "archive" not in record:
                    self.archive(record, "collect-archive-" + record["name"])
                self.clean(record, "collect-clean-" + record["name"])
            except (ValueError, OSError, KeyError, TypeError, SERVE.Failed, subprocess.SubprocessError) as error:
                if self.diagnostics is not None:
                    self.diagnostics.failure(error)
                failures.append(record["target"])
        require(not failures, "an owned life could not be collected through the public lifecycle")

    @DIAGNOSTICS.tracked("execute")
    def execute(self, result):
        self.phase_failures = []
        self.baseline()

        def phase(name, action):
            def run(active):
                failed = False
                try:
                    action()
                except (ValueError, OSError, KeyError, TypeError, SERVE.Failed, SERVE.Blocked, subprocess.SubprocessError, sqlite3.Error) as error:
                    failed = True
                    if getattr(self, "diagnostics", None) is not None:
                        self.diagnostics.failure(error)
                    self.retain(name + "-execution.failed.json", json.dumps({"phase": name, "completed": False}).encode())
                try:
                    self.collect_owned()
                except (ValueError, OSError, KeyError, TypeError, SERVE.Failed, subprocess.SubprocessError) as error:
                    failed = True
                    if getattr(self, "diagnostics", None) is not None:
                        self.diagnostics.failure(error)
                    self.retain(name + "-collection.failed.json", json.dumps({"phase": name, "completed": False}).encode())
                if failed:
                    self.phase_failures.append(name)
                    raise ValueError("installed assertion phase failed; dependent work stopped")
            return run

        CASE.independent_assertions(result, (phase("SECRET-INJECT", self.secret_phase), phase("CREDENTIAL-BOUND", self.credential_phase)))
        self.finish()

    @DIAGNOSTICS.tracked("finish")
    def finish(self):
        by_id = {}
        for record in self.lives:
            for event in self.events(record["target"]):
                require(event.get("id") not in by_id or by_id[event["id"]] == event, "actual event was rewritten")
                by_id[event["id"]] = event
        events = sorted(by_id.values(), key=lambda event: event["seq"])
        raw_events = b"".join(json.dumps(event, sort_keys=True, separators=(",", ":")).encode() + b"\n" for event in events)
        inventories = list(self.native.inventories.values())
        all_helpers, collection_failure = None, False
        try:
            self.native.collected(events)
            all_helpers = self.native.all_quiet()
            require(all(record["cleaned"] for record in self.lives), "an owned fixture life was not explicitly collected")
        except (ValueError, OSError, KeyError, TypeError) as error:
            collection_failure = True
            if self.diagnostics is not None:
                self.diagnostics.failure(error)
        retained = [("events.jsonl", raw_events)]
        for record in self.lives:
            if record["name"] == "start":
                if "archive_bytes" in record:
                    retained.append(("archive.tar", record["archive_bytes"]))
                if "capture" in record:
                    retained.append(("injection.capture", record["capture"]))
            if record["name"] == "lease-first" and "capture" in record:
                retained.append(("credential.capture", record["capture"]))
        for name, raw in retained:
            PRODUCER.put(self.root / name, raw)
        PRODUCER.document(self.root / "execution.json", {"schema": "laneboss.secret-execution.v1", "scope": "installed-standin",
            "steps": self.steps, "roots": self.roots, "seed": self.seed, "lives": [{key: record[key] for key in
                ("name", "target", "operation", "request", "facts") if key in record} for record in self.lives],
            "controls": getattr(self, "control_evidence", None), "credential": getattr(self, "credential_evidence", None), "inventories": inventories,
            "all_helpers": all_helpers, "mounts": getattr(self, "credential_mounts", None), "installation": str(self.case.installation_file),
            "phase_failures": self.phase_failures, "collection_failed": collection_failure,
            "agent_sha256": self.case.agent["sha256"]})


def actual_outcome(context, evidence, entry):
    records = [json.loads(line) for line in (Path(evidence) / entry["directory"] / "wire.jsonl").read_bytes().splitlines() if line.strip()]
    selected = [row for row in records if row.get("name") == entry["name"]]
    require(len(selected) == 1, "step has no unique actual service outcome")
    response = selected[0]["response"]
    value = {"error": response["error"]} if "error" in response else response["result"]
    if value.get("status") in {"pending", "running"}:
        operation_id = value["id"]
        require(entry.get("polls"), "pending mutation was never independently read back")
        poll_names = [poll["name"] for poll in entry["polls"]]
        WIRE.audit(context, evidence, entry["polls"], poll_names, {name: "operation.get" for name in poll_names})
        for poll in entry["polls"]:
            rows = [json.loads(line) for line in (Path(evidence) / poll["directory"] / "wire.jsonl").read_bytes().splitlines() if line.strip()]
            selected = [row for row in rows if row.get("name") == poll["name"] and "request" in row]
            require(len(selected) == 1, "asynchronous outcome has no unique service frame")
            raw = selected[0]
            require(raw == json.loads((Path(evidence) / poll["directory"] / "selected.json").read_bytes()),
                    "asynchronous selected outcome differs from its actual wire bytes")
            WIRE.frame(raw, context, raw["name"], "operation.get", {"operation_id": operation_id})
            value = raw["response"]["result"]
            require(value.get("id") == operation_id, "operation read-back belongs to another mutation")
        require(value.get("status") in {"succeeded", "failed", "cancelled"}, "operation read-back never became terminal")
    require(value == entry["outcome"], "producer outcome differs from actual service responses")
    return value


def evidence_privacy(evidence, hidden):
    measured = []
    for path in sorted(Path(evidence).rglob("*")):
        require(not path.is_symlink(), "linked output cannot prove evidence privacy")
        if path.is_file():
            raw = CASE.read_bounded(path, 268435456)
            require(OBSERVER.no_values(raw, hidden), "retained log or result disclosed secret values")
            measured.append({"path": str(path.relative_to(evidence)), "sha256": sha(raw), "bytes": len(raw)})
    require(measured, "actual privacy evidence is absent")
    return measured


def prepared_intents(context, fixture, evidence, entries):
    require([step.get("name") for step in fixture["steps"]] == list(PRODUCER.STEPS), "prepared twenty-one-step plan is incomplete")
    for entry in entries:
        step = fixture["steps"][PRODUCER.STEPS.index(entry["name"])]
        body = CASE.read_bounded(CASE.beneath(Path(context["test_root"]), step["request"]))
        actual = (Path(evidence) / entry["request"]).read_bytes()
        require(json.loads(body) == json.loads(actual), "prepared intent differs from the actual service request")
        records = [json.loads(line) for line in (Path(evidence) / entry["directory"] / "wire.jsonl").read_bytes().splitlines() if line.strip()]
        selected = [row for row in records if row.get("name") == entry["name"] and "request" in row]
        require(len(selected) == 1, "prepared intent has no actual service frame")
        frame = selected[0]["request"]
        if entry["name"] != "key":
            require(frame.get("idempotency_key") == step["idempotency_key"], "prepared mutation retry key was replaced")
        if step.get("proof"):
            proof = json.loads(CASE.read_bounded(CASE.beneath(Path(context["test_root"]), step["proof"])))
            if entry["method"] == "lane.start":
                sessions = [row for row in records if row.get("name") == "human-session" and "request" in row]
                require(len(sessions) == 1 and proof == sessions[0]["request"].get("proof"), "root spawn replaced its prepared human session proof")
            else:
                require(proof == frame.get("proof"), "operation replaced its prepared confirmation proof")


def verify(context, fixture, result, diagnostics=None):
    evidence = Path(context["evidence_root"])
    execution = json.loads(CASE.read_bounded(evidence / "execution.json", 67108864))
    require(execution.get("schema") == "laneboss.secret-execution.v1" and execution.get("scope") == "installed-standin" and
            context["profile_grant_ids"] and set(context["profile_grant_ids"]) == {row["id"] for row in execution["seed"]["profiles"]},
            "stand-in assertion has no actual nonempty authorized enrollment")
    installed = json.loads(OBSERVER.protected(execution["installation"], 1048576))
    require(installed["config"] == context["config"] and installed["binding_file"] == context["binding_file"] and
            installed["artifact_sha256"] == context["binary_sha256"], "execution belongs to another installed binding")
    canaries = {name: CASE.read_bounded(CASE.beneath(Path(context["test_root"]), path), 65536)
                for name, path in fixture["canary_files"].items()}
    hidden = OBSERVER.variants(canaries)
    raw_events = CASE.read_bounded(evidence / "events.jsonl", 67108864)
    events = [json.loads(line) for line in raw_events.splitlines() if line.strip()]
    evidence_files = ["execution.json", "events.jsonl", "archive.tar", "injection.capture", "credential.capture"]

    def group(names):
        entries = [entry for entry in execution["steps"] if entry.get("name") in names]
        WIRE.audit(context, evidence, entries, names, PRODUCER.METHODS)
        prepared_intents(context, fixture, evidence, entries)
        outcomes = {entry["name"]: actual_outcome(context, evidence, entry) for entry in entries}
        for name in names:
            if name in CASE.DENIALS:
                codes = CASE.DENIALS[name] | {"unavailable"} if name == "restart-locked" else CASE.DENIALS[name]
                require(outcomes[name].get("error", {}).get("code") in codes, "a negative step missed its real service boundary")
            else:
                require(not outcomes[name].get("error") and outcomes[name].get("status") not in {"failed", "cancelled"},
                        "required installed service step failed")
        return outcomes

    def target_for(name):
        values = [record for record in execution["lives"] if record["name"] == name]
        require(len(values) == 1, "actual assertion life is missing or ambiguous")
        return values[0]

    def launch(record):
        observation = dict(record["target"], binary_sha256=context["binary_sha256"], operation_id=record["operation"]["id"])
        payload = CASE.correlated_start(events, observation, [record["operation"]], context)
        inventories = [row for row in execution["inventories"] if row["target"] == record["target"]]
        require(len(inventories) == 1, "assertion has no unique native inventory")
        inventory = inventories[0]
        journal = json.loads(OBSERVER.protected(Path("/var/lib/laneboss-v2/helper") / context["config"] / (inventory["lease_id"] + ".json")))
        OBSERVER.retained_binding(context, record["target"], record["facts"], journal, inventory, payload["lane"]["task"]["sha256"])
        require(record["facts"]["ExecutableSHA"] == execution["agent_sha256"] and record["facts"]["TaskSHA"] == payload["lane"]["task"]["sha256"] and
                record["facts"]["UID"] != os.geteuid() and record["facts"]["MountNS"] != os.readlink("/proc/self/ns/mnt"),
                "assertion probe was answered from the author host")
        return payload

    def injection_action(active):
        record = target_for("start")
        payload = launch(record)
        capture = CASE.read_bounded(evidence / "injection.capture")
        observation = dict(record["target"], injection_capture_sha256=sha(capture))
        CASE.observed_capture(events, evidence / "injection.capture", observation, "injection")
        active["reached"] = True
        outcomes = group(PRODUCER.STEPS[:17])
        require(record["operation"] == outcomes["start"] and
                outcomes["reserved"]["error"]["message"] == "secret target is a reserved or invalid environment name",
                "injection does not join its exact service start or reserved diagnostic")
        evidence_privacy(evidence, hidden)
        require(all(OBSERVER.probe_verdicts(capture).values()) and len(payload["secret_grant_ids"]) == 2,
                "actual injection probe or grant subset failed")
        controls = execution["controls"]
        require(controls["locked"].get("error", {}).get("code") == "prerequisite_missing" and not controls["locked"]["digests"] and
                controls["tampered"].get("error", {}).get("code") == "integrity", "actual native key or tamper control is missing")
        recovered = target_for("recover")
        recovery_payload = launch(recovered)
        require(recovered["operation"] == outcomes["recover"] and recovery_payload["secret_grant_ids"] and len(controls["recovered"]["digests"]) == 2 and
                set(controls["recovered"]["digests"].values()) == {sha(canaries["env"]), sha(canaries["file"])},
                "native recovery did not compare the actual selected source bytes")
        OBSERVER.archive_values(CASE.read_bounded(evidence / "archive.tar", 268435456), hidden)
        require("SECRET-INJECT" not in execution["phase_failures"], "installed secret phase retained a failed boundary")
        active.update(verdict="pass", observed_exit=0)

    def credential_action(active):
        record = target_for("lease-first")
        payload = launch(record)
        raw = CASE.read_bounded(evidence / "credential.capture")
        CASE.observed_capture(events, evidence / "credential.capture", dict(record["target"], credential_capture_sha256=sha(raw)), "credential")
        active["reached"] = True
        capture = json.loads(raw)
        require(capture.get("schema") == "laneboss.secret-credential.v1" and capture.get("vendor_stood_in") is True and
                capture.get("profile_grant_id") == payload["lane"]["profile_grant_id"] and
                any(event.get("kind") == "credential.leased" and event.get("life_id") == record["target"]["life_id"] and
                    event.get("run") == record["target"]["run"] and event["payload"]["slot"]["profile_id"] == capture["profile_id"] for event in events),
                "stand-in credential capture has no actual selected lease")
        outcomes = group(PRODUCER.STEPS[17:])
        require(record["operation"] == outcomes["lease-first"], "credential does not join its exact service start")
        evidence_privacy(evidence, hidden)
        require(all(capture.get(name) is True for name in ("own_profile_turn", "other_profile_absent", "other_history_absent", "registry_absent", "keyring_fallback_absent")),
                "actual confined stand-in credential probe failed")
        measured = execution["credential"]
        database = Path(installed["state_directory"]) / "state.sqlite"
        connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            native_history(connection, measured["history_ref"], context["config"], measured["history_target"])
        finally:
            connection.close()
        require(measured["first"]["profiles"] == measured["second"]["profiles"] and measured["first"]["profiles"][0]["Mode"] == "codex-file" and
                measured["first"]["profiles"][0]["LoginPresent"] is True and measured["first"]["profiles"][0]["RefreshLocked"] is True and
                measured["running"]["slots"][0]["Released"] is False and measured["quiet"]["slots"][0]["Released"] is True and
                measured["quiet"]["profiles"][0]["RefreshLocked"] is False and execution["mounts"]["outside_objects"] >= 3,
                "actual canonical refresh or native release observation failed")
        require("CREDENTIAL-BOUND" not in execution["phase_failures"], "installed credential phase retained a failed boundary")
        active.update(verdict="pass", observed_exit=0)

    def observed(name, action):
        def run(active):
            if diagnostics is None:
                return action(active)
            return diagnostics.run(name, action, active)
        return run

    passed = CASE.independent_assertions(result, (observed("SECRET-INJECT", injection_action), observed("CREDENTIAL-BOUND", credential_action)))
    for inventory in execution["inventories"]:
        CASE.helper_release(events, inventory["target"], [event["payload"] for event in events if event.get("kind") == "run.observed" and
            event.get("payload", {}).get("handle", {}).get("target") == inventory["target"]])
        require(not OBSERVER.uid_processes(inventory["uid"]) and not os.path.lexists(inventory["runtime_root"]), "actual fixture containment survived collection")
        for old in inventory["processes"]:
            now = OBSERVER.process(old["pid"])
            require(now is None or now["start_time"] != old["start_time"], "actual old process generation survived")
    require(execution["inventories"] and execution["all_helpers"] and execution["collection_failed"] is False,
            "whole-run collection inventory is missing or failed")
    for old in execution["all_helpers"]:
        path = Path("/var/lib/laneboss-v2/helper") / context["config"] / (old["lease_id"] + ".json")
        journal = json.loads(OBSERVER.protected(path))
        require(journal["lease"]["id"] == old["lease_id"] and journal["lease"]["uid"] == old["uid"] and
                journal["phase"] == old["phase"] and journal["phase"] in {"released", "aborted"} and
                (journal.get("receipt") if journal["phase"] == "released" else journal.get("abort_receipt")) and
                not OBSERVER.uid_processes(old["uid"]) and not os.path.lexists(old["runtime_root"]),
                "native helper collection no longer matches its measured receipt")
    references = [CASE.evidence_ref(evidence, evidence / name) for name in evidence_files if (evidence / name).is_file()]
    for active in result["assertions"]:
        active["evidence"] = references
    result["collection"] = {"processes_quiescent": True, "temporary_resources_collected": True, "evidence": references}
    WIRE.audit(context, evidence, execution["steps"], PRODUCER.STEPS, PRODUCER.METHODS)
    require(passed, "one or more installed stand-in assertions failed")


def installed_run(args, diagnostics):
    require(sys.platform == "linux" and os.geteuid() == 0, "installed secrets suite requires the authorized root Linux box")
    source = args.source.resolve(strict=True)
    evidence = args.evidence.resolve()
    require(not evidence.exists() and not evidence.is_relative_to(source), "installed evidence must be new and outside source")
    os.umask(0o077)
    evidence.mkdir(mode=0o700, parents=True)
    case = SecretInstall(source, evidence, suite="state")
    diagnostics.attach(case.root, case.config)
    case.diagnostics = diagnostics
    context, result, result_path, execution = None, None, None, None
    code = 1
    try:
        diagnostics.run("install", case.install)
        diagnostics.run("observer.controls", case.command, "secret-observer-controls", [sys.executable, "-I", "-B",
            str(source / "e2e/v2/cases/secrets/checks_install.py"), "--controls", str(case.root / "observer-controls")], seconds=180)
        prepare_identity(case, diagnostics)
        case.current = "human.grants"
        body = json.loads(Path(case.root_grants).read_bytes())
        proof = diagnostics.run("human.grants", case.human.proof, "grants", "grants.root", body, case.config, 0)
        case.current = "human.grants"
        seed = diagnostics.run("human.grants", case.human.rpc, "secret-seed-root", ["grants", "root"], body, proof)
        require(seed.get("id") and len(seed["profiles"]) == 2, "actual stand-in root enrollment is missing")
        test, output = case.root / "secret-input", case.root / "secret-evidence"
        test.mkdir(mode=0o700)
        output.mkdir(mode=0o700)
        context = {"schema": "laneboss.e2e-context.v2", "case_id": "secrets", "phase": "candidate", "mutation_id": "",
            "binary": str(case.binary), "binary_sha256": SERVE.digest(case.binary),
            "source_sha256": SERVE.digest(case.root / "source.tar"), "config": case.config,
            "binding_file": case.installed["binding_file"], "test_root": str(test), "evidence_root": str(output),
            "profile_grant_ids": [row["id"] for row in seed["profiles"]]}
        context_path, result_path = test / "context.json", output / "result.json"
        PRODUCER.document(context_path, context)
        tools = Path("/opt") / ("lb-v2-case-secrets-tools-" + secrets.token_hex(6))
        tools.mkdir(mode=0o755)
        tools.chmod(0o755)
        built = {}
        for name, package in (("seal", "seal"), ("native", "native")):
            target = tools / name
            diagnostics.run("tools.build", case.command, "secret-" + name + "-build", ["go", "build", "-mod=vendor", "-trimpath", "-o", str(target),
                "./e2e/v2/cases/secrets/" + package], seconds=600, cwd=case.stage)
            target.chmod(0o555)
            case.keep("secret-" + name + ".input", target.read_bytes())
            built[name] = {"path": str(target), "sha256": SERVE.digest(target)}
        fixture = diagnostics.run("inputs.prepare", PRODUCER.prepare, context, None, {"env_name": "TASK_TOKEN", "file_path": ".laneboss-secrets/task.key",
            "hidden_env_name": "HIDDEN_TOKEN", "reserved_env_name": "PATH"}, defer_baseline=True,
            hidden_source=case.root / "hidden-canary.private")
        execution = diagnostics.run("native.setup", Execution, case, context, fixture, seed, built["seal"], built["native"])
        result = {"schema": "laneboss.e2e-result.v2", "case_id": "secrets",
            **{key: context[key] for key in ("phase", "mutation_id", "binary_sha256", "source_sha256")},
            "assertions": [{"id": name, "reached": False, "verdict": "fail", "observed_exit": 1, "evidence": []}
                for name in CASE.ASSERTIONS], "collection": {"processes_quiescent": False, "temporary_resources_collected": False, "evidence": []}}
        execution.execute(result)
        diagnostics.run("verify", CASE.run_case, context, result, diagnostics=diagnostics)
        code = 0
    except Exception as error:
        diagnostics.failure(error, response=command_error(case.root, case.last), last=case.last)
    finally:
        if execution is not None:
            # Normal cleanup remains public lifecycle operations. An uncertain
            # cleanup leaves the frozen result failing; no forced worktree path.
            try:
                execution.collect_owned()
            except Exception as error:
                diagnostics.failure(error)
                code = 1
        try:
            diagnostics.run("units.cleanup", case.cleanup)
        except Exception as error:
            diagnostics.failure(error)
            code = 1
            if result is not None:
                result["collection"]["processes_quiescent"] = False
                result["collection"]["temporary_resources_collected"] = False
        if execution is not None:
            try:
                # Include the actual installer, proof and unit journal logs in
                # the case's independent privacy scan, retaining exact bytes.
                for path in sorted(case.root.iterdir()):
                    if path.is_file() and path.suffix in {".stdout", ".stderr"}:
                        PRODUCER.put(execution.root / ("suite-" + path.name), CASE.read_bounded(path, 268435456))
                diagnostics.run("privacy", evidence_privacy, execution.root, execution.hidden)
            except Exception as error:
                diagnostics.failure(error)
                code = 1
                if result is not None:
                    for active in result["assertions"]:
                        active["verdict"] = "fail"
        if result is not None:
            diagnostics.run("results.write", PRODUCER.document, result_path, result)
        diagnostics.run("results.write", PRODUCER.document, case.root / "secret-suite.json", {"schema": "laneboss.secret-suite.v1", "scope": "installed-standin",
            "exit": code, "vendor_stood_in": True, "human_presence": "simulated", "human_approval": "not_proven",
            "context": str(context_path) if context is not None else None,
            "result": str(result_path) if result_path is not None else None})
    return code, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    diagnostics = DIAGNOSTICS.Reporter(checks=SERVE.CHECKS)
    result, code = None, 1
    try:
        code, result = diagnostics.run("preflight", installed_run, args, diagnostics)
    except Exception as error:
        diagnostics.failure(error)
    diagnostics.finish(code, result)
    print("secrets installed stand-in: " + ("pass" if code == 0 else "fail"), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
