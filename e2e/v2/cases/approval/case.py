"""Frozen ORG-APPROVAL harness entry; actual CLI and independently observed effects."""

import argparse
import base64
from datetime import datetime, timedelta, timezone
import errno
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import subprocess
import sys

from harness import (CaseFailure, CaseWait, OwnerWait, Controller, digest, dump, evidence_file, execute,
                     protected_json, read_json, require, strict_json)
from cli_canary import METHODS


CONTROL = {
    "stale": ("org.change.apply", {"conflict"}),
    "wrong_hash": ("org.change.approve", {"conflict"}),
    "extra_effect": ("org.change.apply", {"integrity", "conflict"}),
    "expired": ("org.change.apply", {"forbidden"}),
    "replayed": ("org.change.approve", {"forbidden", "conflict"}),
    "no_human": ("org.change.approve", {"forbidden"}),
    "generated_source": ("org.change.propose", {"forbidden"}),
    "policy_shortcut": ("org.change.approve", {"forbidden"}),
}
RED_CELLS = {
    "publish_exact": "apply", "source_catalog": "generated_source", "human_verify": "no_human",
    "live_l6": "l5", "writable_org": "filesystem", "current_base": "stale",
    "render_apply": "extra_effect", "proof_expiry": "expired", "nonce_once": "replayed",
    "policy_bypass": "policy_shortcut", "retry_receipt": "retry", "key_conflict": "retry",
    "approve_hash": "wrong_hash",
}


def instant(value):
    require(isinstance(value, str) and value.endswith("Z"), "non-UTC retained timestamp")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def intent(config, method, params):
    # This case emits only bounded integers and ASCII field/path names; within
    # that frozen input profile Python's sorted compact form is RFC8785.
    body = {"protocol": "laneboss.rpc.v2", "schema": 2, "config": config,
            "method": method, "params": params}
    return digest(json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode())


def result(value):
    require(isinstance(value, dict) and "error" not in value and "result" not in value,
            "CLI did not emit its actual typed result")
    return value


def relative_path(value):
    path = PurePosixPath(value)
    require(isinstance(value, str) and value and value != "." and not path.is_absolute() and
            path.as_posix() == value and ".." not in path.parts and
            "\\" not in value and ":" not in value and
            all(ord(char) >= 32 for char in value), "invalid org-relative effect path")
    return value


def tree(root, boundary=None):
    require(root.is_dir(), "canonical root missing")
    resolved = root.resolve(strict=True)
    if boundary is None:
        require(not root.is_symlink(), "generation pointer requires a protected boundary")
    else:
        boundary = Path(boundary)
        require(boundary.is_absolute() and boundary.is_dir() and
                resolved.is_relative_to(boundary.resolve(strict=True)),
                "canonical generation escaped its protected boundary")
    root = resolved
    files = {".": (stat.S_IMODE(root.stat().st_mode), "directory")}
    for current, dirs, names in os.walk(root, followlinks=False):
        for name in dirs:
            path = Path(current) / name
            require(not path.is_symlink(), "canonical symlink")
            files[path.relative_to(root).as_posix() + "/"] = (
                stat.S_IMODE(path.stat().st_mode), "directory")
        for name in names:
            path = Path(current) / name
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode), "non-file canonical entry")
            files[path.relative_to(root).as_posix()] = (
                stat.S_IMODE(info.st_mode), digest(path.read_bytes()))
    return files


class Case:
    def __init__(self, context):
        self.context = context
        self.baseout = Path(context["evidence_root"]) / "approval"
        require(not self.baseout.exists(), "approval evidence directory already exists")
        self.baseout.mkdir(mode=0o700)
        self.out = self.baseout
        self.count, self.serial, self.summaries = 0, 0, 0
        self.scopes, self.clocks = {}, {}
        self.selected = RED_CELLS[context["mutation_id"]] if context["phase"] == "red" else "all"
        self.active, self.passed, self.observed_cells = "setup", [], set()
        self.processes, self.canaries, self.pending_controls = [], [], set()
        self.job_resources = []
        self.open_uploads = set()
        self.observed_exit = 1
        self.config = context["config"]
        self.simulated_presence = False

    def observe_presence(self, value):
        if isinstance(value, dict):
            self.simulated_presence = self.simulated_presence or value.get("simulated_presence") is True
            for item in value.values():
                self.observe_presence(item)
        elif isinstance(value, list):
            for item in value:
                self.observe_presence(item)

    def keep(self, name, value):
        path = self.out / name
        dump(path, value)
        return path

    def input(self, label, value):
        self.serial += 1
        return self.keep("%04d-%s.json" % (self.serial, label), value)

    def summary(self, status, error=None):
        self.summaries += 1
        self.keep("summary-%04d.json" % self.summaries, {
            "case": "ORG-APPROVAL", "selected_cell": self.selected, "status": status,
            "active": self.active, "passed_cells": self.passed,
            "presence": "simulated" if self.simulated_presence else "not_marked",
            "human_approval": "not_proven",
            "observed_cells": sorted(self.observed_cells),
            "error": None if error is None else (error.failure() if isinstance(error, CaseWait) else
                {"type": type(error).__name__, "message": str(error)})})

    def checkpoint(self, name):
        require(name not in self.passed, "cell was executed twice")
        self.passed.append(name)
        self.summary("running")
        print("CHECK " + name + ": passed", flush=True)

    def command(self, argv, label, expect=0):
        require(isinstance(argv, list) and argv and all(isinstance(x, str) and x for x in argv),
                "invalid owned command")
        self.count += 1
        prefix = "%04d-%s" % (self.count, label)
        self.keep(prefix + "-argv.json", argv)
        run, measured = execute(argv)
        self.processes.append(measured)
        (self.out / (prefix + "-stdout")).write_bytes(run.stdout)
        (self.out / (prefix + "-stderr")).write_bytes(run.stderr)
        self.keep(prefix + "-process.json", measured)
        self.observed_exit = run.returncode
        require(not measured["timed_out"] and measured["group_absent"], label + ": process collection failed")
        if expect is not None:
            require(run.returncode == expect, label + ": unexpected exit")
        return run

    def helper(self, name, args, label):
        if name not in self.f or not self.f[name].get("executable"):
            raise OwnerWait("The owner must review the exact source and derived package and supply the enrolled confirmation helper for " + name + ".")
        helper = self.f[name]
        require(Path(helper["executable"]).is_absolute(), "human UI helper must have an absolute path")
        try:
            executable = Path(helper["executable"]).resolve(strict=True)
        except FileNotFoundError:
            raise OwnerWait("The enrolled confirmation helper is not installed; the owner's fresh exact-operation confirmation remains pending.")
        require(digest(executable.read_bytes()) == helper["sha256"],
                "human UI helper artifact mismatch")
        (self.out / (label + "-helper-%04d" % self.count)).write_bytes(executable.read_bytes())
        observed = self.command([str(executable), *args], label, expect=None)
        if observed.returncode == 69:
            raise OwnerWait("The enrolled confirmation helper is waiting for the owner's fresh exact-operation gesture.")
        require(observed.returncode == 0, label + ": human confirmation helper refused; retain its exact stderr")
        return observed

    def read_proof(self, label):
        request = self.input(label + "-session", {})
        proof_file = self.out / (label + "-read-proof-%04d.json" % self.count)
        self.helper("read_confirm", ["--config", self.config, "--request-file", str(request),
                                     "--proof-file", str(proof_file)], label + "-read-confirm")
        proof = read_json(proof_file)
        self.observe_presence(proof)
        require(proof.get("id") and proof.get("request_sha256") == intent(self.config, "human.session", {}),
                "read proof covers another operation")
        return proof_file

    def confirmation(self, request_file, change_file, review_file, proof_file):
        self.helper("confirm", ["--config", self.config, "--request-file", str(request_file),
                               "--change-file", str(change_file), "--review-file", str(review_file),
                               "--proof-file", str(proof_file)],
                    "human-confirm-%04d" % self.count)
        proof = read_json(proof_file)
        self.observe_presence(proof)
        require(proof.get("id") and proof.get("request_sha256") ==
                intent(self.config, "org.change.approve", read_json(request_file)),
                "confirmation covers another exact request")
        return proof

    def canary(self, actor, canary_id, body, observation_name):
        raw = (json.dumps(body, ensure_ascii=False, indent=2) + "\n").encode()
        input_ref = self.blob("human", raw, "canary-input-%04d" % self.count)
        target = self.f["actors"][actor]["target"]
        token = secrets.token_hex(16)
        self.pending_controls.add(token)
        measured = self.controller.call("run_confined_canary", {
            "target": target, "canary_id": canary_id, "input": input_ref})
        self.pending_controls.remove(token)
        self.canaries.append(measured)
        matches = [ref for ref in measured["evidence"] if Path(ref["path"]).name == observation_name]
        require(len(matches) == 1, "fixed job observation missing or ambiguous")
        observation = read_json(evidence_file(Path(self.context["evidence_root"]), matches[0]))
        require(observation["input_sha256"] == digest(raw) and
                observation["observed_exit"] == measured["observed_exit"] and
                observation["adapter_sha256"] == digest(Path(__file__).with_name("harness.py").read_bytes()),
                "fixed job observation differs from its actual input/exit/adapter")
        return observation

    def lane_cli(self, actor, args):
        prefix = args[:3] if args[:2] == ["org", "change"] else args[:2]
        matches = [method for method, words in METHODS.items() if words == prefix]
        require(len(matches) == 1, "actor job requested a non-enrolled CLI operation")
        method, rest = matches[0], args[len(prefix):]
        require(len(rest) % 2 == 0, "invalid actor CLI options")
        options = {}
        for index in range(0, len(rest), 2):
            name, value = rest[index:index + 2]
            require(name in {"--request", "--request-file", "--request-id", "--idempotency-key"} and
                    name not in options, "non-fixed or duplicate actor CLI option")
            options[name] = value
        request_path = options.get("--request", options.get("--request-file"))
        require(request_path is not None, "actor CLI input missing")
        raw = Path(request_path).read_bytes()
        request = {"schema": "laneboss.approval-cli-input.v2", "method": method,
                   "params": base64.b64encode(raw).decode(),
                   "request_id": options["--request-id"], "idempotency_key": options["--idempotency-key"]}
        actor_data = self.f["actors"][actor]
        observed = self.canary(actor, actor_data["cli_canary_id"], request, "approval-cli.json")
        self.job_resources.append({"input_sha256": observed["input_sha256"],
                                   "temporary_removed": observed["temporary_removed"]})
        require(observed["schema"] == "laneboss.approval-cli-observation.v2" and
                observed["executor_sha256"] == digest(Path(__file__).with_name("cli_canary.py").read_bytes()) and
                observed["binary_sha256"] == self.context["binary_sha256"] and
                observed["config"] == self.config and observed["target"] == actor_data["target"] and
                observed["binding_file"] == actor_data["binding_file"] and
                observed["params_sha256"] == digest(raw), "actor job used a different artifact/binding/input")
        expected = [str(self.binary), *prefix, "--config", self.config,
                    "--binding", actor_data["binding_file"], "--request", observed["request_file"],
                    "--request-id", request["request_id"], "--idempotency-key", request["idempotency_key"]]
        require(observed["argv"] == expected and observed["method"] == method and
                observed["request_id"] == request["request_id"] and
                observed["idempotency_key"] == request["idempotency_key"] and
                observed["process"]["exit"] == observed["observed_exit"] and
                observed["process"]["group_absent"] and not observed["process"]["timed_out"] and
                observed["temporary_removed"], "actor job did not invoke/collect the exact installed CLI")
        return subprocess.CompletedProcess(expected, observed["observed_exit"],
                                           base64.b64decode(observed["stdout"], validate=True),
                                           base64.b64decode(observed["stderr"], validate=True))

    def cli(self, actor, args, label, expect_error=None, cell=None):
        args = list(args)
        if "--idempotency-key" not in args:
            args += ["--idempotency-key", secrets.token_hex(16)]
        if "--request-id" not in args:
            args += ["--request-id", secrets.token_hex(16)]
        if actor == "human":
            if args[:3] != ["org", "change", "approve"]:
                args += ["--proof", str(self.read_proof(label))]
            require(digest(self.binary.read_bytes()) == self.context["binary_sha256"], "installed artifact changed")
            run = self.command([str(self.binary), *args, "--config", self.config,
                                "--binding", self.context["binding_file"]], label, expect=None)
        else:
            run = self.lane_cli(actor, args)
        self.observed_exit = run.returncode
        if expect_error is not None:
            if run.returncode == 0:
                if cell is not None:
                    self.observed_cells.add(cell)
                raise CaseFailure(label + ": forbidden operation succeeded")
            require(run.returncode in {2, 3} and not run.stdout,
                    label + ": dependency/setup failure is not a negative pass")
            failure = strict_json(run.stderr)
            require(isinstance(failure, dict) and failure.get("message") and failure.get("code") in expect_error,
                    label + ": real CLI refused for the wrong reason")
            if cell is not None:
                self.observed_cells.add(cell)
            return failure
        require(run.returncode == 0, label + ": required installed CLI operation failed")
        value = result(strict_json(run.stdout))
        self.observe_presence(value)
        if cell is not None:
            self.observed_cells.add(cell)
        return value

    def artifact(self):
        self.binary = Path(self.context["binary"]).resolve(strict=True)
        data = self.binary.read_bytes()
        require(digest(data) == self.context["binary_sha256"], "installed artifact hash mismatch")
        (self.out / "tested-binary").write_bytes(data)
        for name in ["case.py", "harness.py", "cli_canary.py", "write_job.py", "case.json", "run.sh"]:
            (self.out / ("source-" + name)).write_bytes(Path(__file__).with_name(name).read_bytes())
        binding = protected_json(self.context["binding_file"], {0, self.controller.binding["controller_uid"]})
        require(binding["class"] == "human" and binding["config"] == self.config and
                binding["artifact_sha256"] == self.context["binary_sha256"],
                "case must observe through the installed human endpoint")
        metadata = strict_json(self.command([str(self.binary), "--version"], "version").stdout)
        require(metadata.get("contract_revision") == "v2.0-draft.4" and
                metadata.get("api_protocol") == "laneboss.rpc.v2", "installed contract differs from fixture")

    def filesystem(self, original):
        self.active = "filesystem"
        source = relative_path(self.f["paths"]["script"])
        require(source in original, "canonical canary target missing")
        observer = Path(self.f["writable_observer"])
        require(observer.is_absolute() and observer.is_file() and
                not observer.resolve().is_relative_to(self.root.resolve()),
                "positive canary observer is not an existing workspace file")
        payload = b"approval write canary " + secrets.token_hex(16).encode() + b"\n"
        (self.out / "write-payload.bin").write_bytes(payload)
        job = self.f["actors"]["l6"]["write_canary_id"]
        for target in ["workspace", "canonical"]:
            measured = self.canary("l6", job, {
                "schema": "laneboss.approval-write-input.v2", "target": target,
                "payload": base64.b64encode(payload).decode()}, "approval-write.json")
            require(measured["schema"] == "laneboss.approval-write-observation.v2" and
                    measured["executor_sha256"] == digest(Path(__file__).with_name("write_job.py").read_bytes()) and
                    measured["target"] == target and measured["payload_sha256"] == digest(payload) and
                    measured["target_path"] == self.f["writable_target" if target == "workspace" else "canonical_target"],
                    "native-write job differs from enrolled bytes/selector")
            self.observed_exit = measured["observed_exit"]
            if target == "workspace":
                require(measured["observed_exit"] == 0 and measured["attempted"] is True and
                        measured["written"] is True and measured["errno"] == 0 and observer.read_bytes() == payload,
                        "positive native-write control did not actually write")
            else:
                self.observed_cells.add("filesystem")
                require(measured["observed_exit"] == 1 and measured["attempted"] is True and
                        measured["written"] is False and
                        measured["errno"] in {errno.EACCES, errno.EPERM, errno.EROFS, errno.ENOENT},
                        "protected canary did not hit a real native boundary")
            require(self.snapshot() == original, "native-write canary changed canonical resources")
        self.checkpoint("filesystem")

    def l5(self, proposal, original):
        self.active = "l5"
        body = read_json(proposal)
        # Otherwise-valid authority control: give L5 its own committed objects
        # so an L6-owned object's visibility cannot mask the level decision.
        body["reason"] = self.blob("l5", self.read_blob(body["reason"]), "l5-reason")
        for index, delta in enumerate(body["files"]):
            if delta["action"] != "delete":
                delta["after"] = self.blob("l5", self.read_blob(delta["after"]), "l5-source-%03d" % index)
        own_proposal = self.input("l5-propose", body)
        self.cli("l5", ["org", "change", "propose", "--request", str(own_proposal)], "l5",
                 expect_error={"forbidden"}, cell="l5")
        require(self.snapshot() == original, "L5 changed canonical resources")
        self.checkpoint("l5")

    def blob(self, actor, data, label):
        begin = self.out / (label + "-begin.json")
        dump(begin, {"class": "artifact", "bytes": len(data), "sha256": digest(data)})
        upload = self.cli(actor, ["blob", "begin", "--request", str(begin)],
                          label + "-begin")
        object_id = upload["object_id"]
        self.open_uploads.add(object_id)
        require(isinstance(upload["max_chunk_bytes"], int) and
                0 < upload["max_chunk_bytes"] <= 262144, "invalid blob chunk bound")
        offset = 0
        while offset < len(data):
            part = data[offset:offset + upload["max_chunk_bytes"]]
            chunk = self.out / (label + "-chunk-%d.json" % offset)
            dump(chunk, {"object_id": object_id, "offset": offset,
                         "data": base64.b64encode(part).decode("ascii"),
                         "sha256": digest(part)})
            self.cli(actor, ["blob", "chunk", "--request", str(chunk)], label + "-chunk")
            offset += len(part)
        commit = self.out / (label + "-commit.json")
        dump(commit, {"object_id": object_id, "sha256": digest(data)})
        ref = self.cli(actor, ["blob", "commit", "--request", str(commit)], label + "-commit")
        self.open_uploads.remove(object_id)
        require(ref["class"] == "artifact" and ref["bytes"] == len(data) and ref["sha256"] == digest(data),
                "blob commit did not retain exact bytes")
        return ref

    def blob_chunk(self, ref, offset, limit):
        request = self.out / ("read-%d.json" % self.count)
        dump(request, {"object_id": ref["id"], "offset": offset, "limit": limit})
        chunk = self.cli("human", ["blob", "read", "--request", str(request)], "blob-read")
        part = base64.b64decode(chunk["data"], validate=True)
        require(chunk["object_id"] == ref["id"] and chunk["offset"] == offset and
                len(part) <= limit and digest(part) == chunk["sha256"], "invalid retained blob chunk")
        return part

    def read_blob(self, ref):
        require(isinstance(ref["bytes"], int) and 0 <= ref["bytes"] <= 67108864,
                "retained blob length exceeds bound")
        data = bytearray()
        while True:
            part = self.blob_chunk(ref, len(data), min(262144, max(1, ref["bytes"] - len(data))))
            require(len(part) <= ref["bytes"] - len(data), "blob exceeds declared length")
            require(part or len(data) == ref["bytes"], "blob ended before declared length")
            data.extend(part)
            if len(data) == ref["bytes"]:
                break
        require(digest(data) == ref["sha256"], "retained blob bytes differ")
        if ref["bytes"]:
            require(not self.blob_chunk(ref, ref["bytes"], 1), "blob reference describes a prefix")
        return bytes(data)

    def identities(self, names):
        for name in names:
            request = self.out / ("identity-" + name + ".json")
            dump(request, {})
            scope = self.cli(name, ["identity", "self", "--request", str(request)], "identity-" + name)
            self.scopes[name] = scope
            require(scope["config"] == self.config, "wrong configuration")
            actor = scope["actor"]
            level = {"l6": 6, "l5": 5, "human": None}[name]
            require(actor["kind"] == ("human" if level is None else "lane"),
                    "wrong authentic actor kind")
            if level is not None:
                require(actor["level"] == level and actor["life_id"] and
                        scope["launch_id"], "missing authentic recorded life")

    def snapshot(self):
        return tree(self.root, self.f.get("canonical_boundary"))

    def control_proposal(self, original, kind="note", label="candidate"):
        path = relative_path(self.f["paths"][kind])
        require(path in original, "control source baseline missing")
        baseline = (self.root / path).read_bytes()
        require(digest(baseline) == original[path][1], "control preimage changed")
        authored = self.f.get("candidate_files", {}).get(kind)
        require(kind != "approval_policy" or authored is not None, "policy control needs schema-valid authored bytes")
        data = (Path(authored).read_bytes() if authored else
                baseline + b"\n# approval control " + secrets.token_hex(16).encode() + b"\n")
        require(data != baseline, "control candidate did not change source bytes")
        ref = self.blob("l6", data, label + "-source")
        reason = self.blob("l6", ("Approval control " + label + "\n").encode(), label + "-reason")
        body = {"org_id": self.f["org_id"], "base_generation": self.f["base_generation"], "reason": reason,
                "files": [{"path": path, "action": "replace", "mode": original[path][0],
                           "before_sha256": original[path][1], "after": ref}]}
        return self.input(label + "-propose", body)

    def stage_control(self, request_file, label):
        before = self.snapshot()
        change = self.cli("l6", ["org", "change", "propose", "--request", str(request_file)], label)
        body = read_json(request_file)
        require(change["config"] == self.config and change["org_id"] == body["org_id"] and
                change["base_generation"] == body["base_generation"] and
                change["requester"] == self.scopes["l6"]["actor"] and change["status"] == "proposed" and
                change["files"] == sorted(body["files"], key=lambda item: item["path"]) and
                change["reason"] == body["reason"], "control stage did not retain the actual source request")
        require(change["source_snapshot"] == self.f["source_snapshot"] and
                change["ownership_manifest"] == self.f["ownership_manifest"] and
                change["renderer"] == self.f["renderer"], "control provenance differs from trusted baseline")
        self.check_manifest(change)
        require(self.snapshot() == before, "control staging changed canonical resources")
        return change

    def check_manifest(self, change):
        manifest = {key: change[key] for key in ["org_id", "base_generation", "files", "derived", "renderer"]}
        require(isinstance(change["derived"], list), "renderer did not retain an explicit derived array")
        require(digest(json.dumps(manifest, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()) ==
                change["manifest_sha256"], "control manifest digest mismatch")

    def measured_outputs(self, change):
        outputs = []
        for delta in change["derived"]:
            data = None if delta["action"] == "delete" else self.read_blob(delta["after"])
            outputs.append((delta["path"], delta["action"], delta["mode"], delta.get("before_sha256", ""),
                            None if data is None else digest(data)))
        return sorted(outputs), digest(self.read_blob(change["diff"]))

    def control_review(self, change, label):
        self.check_manifest(change)
        change_file = self.input(label + "-change", change)
        entries = []
        baseline = self.snapshot()
        for index, delta in enumerate(change["files"] + change["derived"]):
            path = relative_path(delta["path"])
            entry = dict(delta)
            if delta["action"] != "add":
                require(path in baseline and baseline[path][1] == delta["before_sha256"], "control preimage differs")
                before_file = self.out / ("%s-before-%03d.bin" % (label, index))
                before_file.write_bytes((self.root / path).read_bytes())
                require(digest(before_file.read_bytes()) == delta["before_sha256"], "control preimage bytes differ")
                entry["before_file"] = before_file.name
            else:
                require(path not in baseline, "control addition targets an existing file")
            if delta["action"] != "delete":
                retained = self.out / ("%s-after-%03d.bin" % (label, index))
                retained.write_bytes(self.read_blob(delta["after"]))
                entry["retained_file"] = retained.name
            entries.append(entry)
        review = {"config": self.config, "change_id": change["id"], "manifest_sha256": change["manifest_sha256"],
                  "source_snapshot": change["source_snapshot"], "renderer": change["renderer"], "entries": entries}
        for field in ["diff", "reason", "ownership_manifest"]:
            retained = self.out / (label + "-" + field + ".bin")
            retained.write_bytes(self.read_blob(change[field]))
            review[field], review[field + "_file"] = change[field], retained.name
        require((self.out / review["diff_file"]).stat().st_size > 0, "control review diff is empty")
        return change_file, self.input(label + "-review", review)

    def control_confirm(self, change, body, label):
        request = self.input(label + "-approve", body)
        change_file, review_file = self.control_review(change, label)
        proof_file = self.out / (label + "-proof.json")
        proof = self.confirmation(request, change_file, review_file, proof_file)
        require(self.current_instant() < instant(proof["expires_at"]), "control proof expired during setup")
        return request, proof_file, proof

    def approve_control(self, change, label):
        body = {"change_id": change["id"], "manifest_sha256": change["manifest_sha256"],
                "base_generation": change["base_generation"]}
        request, proof_file, proof = self.control_confirm(change, body, label)
        approval = self.cli("human", ["org", "change", "approve", "--request", str(request),
                                      "--proof", str(proof_file)], label + "-approve")
        require(approval["change_id"] == change["id"] and approval["manifest_sha256"] == change["manifest_sha256"] and
                approval["base_generation"] == change["base_generation"] and
                approval["requester_life_id"] == change["requester"]["life_id"] and
                approval["approver_key_id"] and approval["nonce_id"], "control approval has different provenance")
        return approval, request, proof_file, proof

    def clock_state(self):
        clock = self.f["clock"]
        require(clock["clock_id"] in self.controller.binding["fixture_clock_ids"], "control Clock is not registered")
        return self.clocks.setdefault(clock["clock_id"], dict(clock))

    def current_instant(self):
        if "clock" in self.f:
            return instant(self.clock_state()["now"])
        return datetime.now(timezone.utc)

    def advance_clock(self, to):
        clock = self.clock_state()
        require(instant(to) > instant(clock["now"]), "fixture clock must advance")
        token = secrets.token_hex(16)
        self.pending_controls.add(token)
        measured = self.controller.call("advance_fixture_clock", {
            "clock_id": clock["clock_id"], "expected_generation": clock["generation"],
            "from": clock["now"], "to": to})
        self.pending_controls.remove(token)
        clock["generation"], clock["now"] = measured["generation"], measured["to"]

    def apply_control(self, change, approval, original, label):
        body = {"change_id": change["id"], "approval_id": approval["id"],
                "expected_generation": change["base_generation"]}
        request = self.input(label + "-apply", body)
        receipt = self.cli("l6", ["org", "change", "apply", "--request", str(request)], label)
        require(receipt["change_id"] == change["id"] and receipt["approval_id"] == approval["id"] and
                receipt["manifest_sha256"] == change["manifest_sha256"] and
                receipt["old_generation"] == change["base_generation"] and
                receipt["new_generation"] == change["base_generation"] + 1, "intervening receipt differs")
        expected = dict(original)
        for delta in change["files"] + change["derived"]:
            path = relative_path(delta["path"])
            parent = PurePosixPath(path).parent
            require(str(parent) == "." or parent.as_posix() + "/" in original,
                    "control effect parent directory must be preseeded")
            if delta["action"] == "delete":
                require(path in expected, "control deletion targets an absent file")
                expected.pop(path)
            else:
                expected[path] = (delta["mode"], digest(self.read_blob(delta["after"])))
        require(self.snapshot() == expected, "intervening publication did not apply exact measured effects")
        return receipt

    def control(self, name, original_main):
        self.active = name + "-setup"
        main_f, main_root, main_out = self.f, self.root, self.out
        cell = main_f["controls"][name]
        require("argv" not in cell and "request_file" not in cell, "negative controls must contain data, not commands")
        require(cell["org_id"] != main_f["org_id"], "control must have its own disposable org")
        self.f = dict(main_f, **cell)
        self.root = Path(cell["canonical_root"])
        require(self.root.is_absolute() and self.root.resolve() != main_root.resolve(), "control root is not isolated")
        self.out = self.baseout / name
        self.out.mkdir(mode=0o700)
        try:
            original = self.snapshot()
            self.keep("canonical-before-setup.json", original)
            kind = "approval_policy" if name == "policy_shortcut" else "note"
            proposal = self.control_proposal(original, kind)
            change = self.stage_control(proposal, "seed")
            body = {"change_id": change["id"], "manifest_sha256": change["manifest_sha256"],
                    "base_generation": change["base_generation"]}
            method, codes = CONTROL[name]
            proof_file = None
            actor = "human"
            if name == "generated_source":
                generated = [delta["path"] for delta in change["derived"] if delta["path"] in original]
                require(generated and not set(generated) & {delta["path"] for delta in change["files"]},
                        "generated-source fixture lacks an existing cataloged generated output")
                path = generated[0]
                data = (self.root / path).read_bytes() + b"\n# generated-source control\n"
                forged = self.blob("l6", data, "generated-source")
                body = {"org_id": change["org_id"], "base_generation": change["base_generation"],
                        "reason": change["reason"], "files": [{"path": path, "action": "replace",
                        "mode": original[path][0], "before_sha256": original[path][1], "after": forged}]}
                request = self.input("generated-source-propose", body)
                actor = "l6"
            elif name in {"wrong_hash", "no_human", "policy_shortcut"}:
                if name == "wrong_hash":
                    value = change["manifest_sha256"]
                    body["manifest_sha256"] = ("0" if value[0] != "0" else "1") + value[1:]
                    require(body["manifest_sha256"] != change["manifest_sha256"], "wrong-hash defect was not constructed")
                request, proof_file, proof = self.control_confirm(change, body, "negative")
                if name in {"no_human", "policy_shortcut"}:
                    unknown = dict(proof, id=secrets.token_hex(16))
                    require(unknown["id"] != proof["id"], "unverified proof control did not change the proof identity")
                    proof_file = self.input("unverified-proof", unknown)
            else:
                approval, approved_request, approved_proof, proof = self.approve_control(change, "first")
                if name == "replayed":
                    probe = self.stage_control(proposal, "current-base-probe")
                    require(probe["base_generation"] == change["base_generation"] and
                            self.snapshot() == original and self.current_instant() < instant(proof["expires_at"]),
                            "nonce replay would be masked by stale base, mutation or expiry")
                    request, proof_file = approved_request, approved_proof
                else:
                    actor = "l6"
                    body = {"change_id": change["id"], "approval_id": approval["id"],
                            "expected_generation": change["base_generation"]}
                    request = self.input("negative-apply", body)
                    if name == "stale":
                        intervening = self.control_proposal(original, "tool", "intervening")
                        staged = self.stage_control(intervening, "intervening-stage")
                        confirmed, _, _, _ = self.approve_control(staged, "intervening")
                        receipt = self.apply_control(staged, confirmed, original, "intervening-apply")
                        require(receipt["new_generation"] > body["expected_generation"], "stale-base defect was not established")
                        require(self.current_instant() < instant(approval["expires_at"]),
                                "stale control would also use an expired approval")
                    elif name == "expired":
                        to = instant(approval["expires_at"]) + timedelta(seconds=1)
                        require(to < instant(change["expires_at"]), "expiry control would also expire its stage")
                        self.advance_clock(to.isoformat().replace("+00:00", "Z"))
                        probe = self.stage_control(proposal, "current-base-probe")
                        require(probe["base_generation"] == change["base_generation"] and
                                self.current_instant() > instant(approval["expires_at"]), "approval was not expired on a current base")
                    elif name == "extra_effect":
                        to = self.current_instant() + timedelta(seconds=1)
                        require(to < instant(approval["expires_at"]), "effect control would expire approval")
                        self.advance_clock(to.isoformat().replace("+00:00", "Z"))
                        probe = self.stage_control(proposal, "new-render-probe")
                        require(probe["files"] == change["files"] and probe["renderer"] == change["renderer"] and
                                probe["source_snapshot"] == change["source_snapshot"] and
                                (self.measured_outputs(probe) != self.measured_outputs(change)),
                                "effect control did not independently observe changed renderer output")
            before = self.snapshot()
            self.keep("canonical-before-refusal.json", before)
            if proof_file is not None:
                require(self.current_instant() < instant(read_json(proof_file)["expires_at"]),
                        "negative control proof expired before its intended operation")
            self.active = name
            words = method.split(".")
            args = words + ["--request", str(request), "--idempotency-key", secrets.token_hex(16)]
            if proof_file is not None:
                args += ["--proof", str(proof_file)]
            self.cli(actor, args, name, expect_error=codes, cell=name)
            require(self.snapshot() == before, name + ": refused operation changed canonical resources")
            self.keep("canonical-after-refusal.json", self.snapshot())
            require(tree(main_root, main_f.get("canonical_boundary")) == original_main,
                    name + ": negative control changed the main org")
            self.checkpoint(name)
        finally:
            self.f, self.root, self.out = main_f, main_root, main_out

    def prepare(self, original):
        self.active = "prepare"
        files, expected = [], {}
        for kind in ["script", "tool", "config", "template", "note"]:
            path = relative_path(self.f["paths"][kind])
            require(path in original, "source baseline missing: " + kind)
            baseline = (self.root / path).read_bytes()
            require(digest(baseline) == original[path][1], "source changed during fixture preparation")
            authored = self.f.get("candidate_files", {}).get(kind)
            if authored is not None:
                data = Path(authored).read_bytes()
            else:
                # Default fixtures use shell/TOML/Markdown/text sources. Keep
                # required schema/template content and append a harmless marker.
                marker = ("# approval " + kind + " " + secrets.token_hex(16) + "\n").encode()
                data = baseline + (b"" if baseline.endswith(b"\n") else b"\n") + marker
            require(data != baseline and len(data) <= 67108864,
                    "candidate must be an actual bounded source change")
            expected[path] = data
            files.append({"path": path, "action": "replace", "mode": original[path][0],
                          "before_sha256": original[path][1], "after": self.blob("l6", data, kind)})
        proposal = self.out / "propose.json"
        dump(proposal, {"org_id": self.f["org_id"], "base_generation": self.f["base_generation"],
                        "files": files,
                        "reason": self.blob("l6", b"D6 exact-change acceptance\n", "reason")})
        return proposal, files, expected

    def positive(self, proposal, files, expected, original):
        self.active = "source"
        change = self.cli("l6", ["org", "change", "propose", "--request", str(proposal)], "propose", cell="source")
        get_request = self.out / "get-change.json"
        dump(get_request, {"change_id": change["id"]})
        viewed = self.cli("human", ["org", "change", "get", "--request", str(get_request)], "read-change")
        require(viewed == change, "human read changed the exact retained proposal")
        require(change["requester"] == self.scopes["l6"]["actor"], "wrong recorded requester")
        require(change["org_id"] == self.f["org_id"] and
                change["base_generation"] == self.f["base_generation"], "wrong staged org or base")
        require(change["config"] == self.config and change["reason"] == read_json(proposal)["reason"],
                "staging lost the original configuration or reason")
        require(change["source_snapshot"] == self.f["source_snapshot"] and
                change["ownership_manifest"] == self.f["ownership_manifest"] and
                change["renderer"] == self.f["renderer"], "staged provenance differs from approved baseline")
        require(change["source_snapshot"]["org_id"] == change["org_id"] and
                change["source_snapshot"]["generation"] == change["base_generation"],
                "snapshot does not bind the staged org and base")
        ownership_file = self.out / "ownership-manifest.bin"
        ownership_file.write_bytes(self.read_blob(change["ownership_manifest"]))
        reason_file = self.out / "reason.bin"
        reason_file.write_bytes(self.read_blob(change["reason"]))
        require(change["files"] == sorted(files, key=lambda x: x["path"]), "staged sources differ")
        require(self.snapshot() == original, "proposal applied resources")
        derived = self.f["expected_derived"]
        require(isinstance(derived, list) and derived and isinstance(change["derived"], list),
                "active template must exercise derived outputs")
        require(sorted(x["path"] for x in change["derived"]) == sorted(derived),
                "missing or unexpected derived effect")
        manifest = {key: change[key] for key in
                    ["org_id", "base_generation", "files", "derived", "renderer"]}
        canonical = json.dumps(manifest, sort_keys=True, ensure_ascii=False,
                               separators=(",", ":")).encode()
        require(digest(canonical) == change["manifest_sha256"], "manifest mismatch")
        retained, review_entries = {}, []
        for index, delta in enumerate(change["files"] + change["derived"]):
            path = relative_path(delta["path"])
            require(path not in retained and delta["action"] in {"add", "replace", "delete"},
                    "duplicate or invalid effect")
            parent = PurePosixPath(path).parent
            require(str(parent) == "." or parent.as_posix() + "/" in original,
                    "fixture must preseed every expected effect parent directory")
            entry = dict(delta)
            if delta["action"] == "add":
                require(path not in original and "before_sha256" not in delta,
                        "addition replaced an existing file or supplied a before hash")
            else:
                require(path in original and original[path][1] == delta["before_sha256"],
                        "effect before hash differs from canonical baseline")
                before_data = (self.root / path).read_bytes()
                require(digest(before_data) == delta["before_sha256"],
                        "canonical preimage changed before review")
                before_file = self.out / ("before-%03d.bin" % index)
                before_file.write_bytes(before_data)
                entry["before_file"] = before_file.name
            if delta["action"] == "delete":
                retained[path] = None
                review_entries.append(entry)
                continue
            data = self.read_blob(delta["after"])
            if path in expected:
                require(data == expected[path], "staged source bytes changed")
            retained[path] = data
            local = self.out / ("review-%03d.bin" % index)
            local.write_bytes(data)
            review_entries.append(dict(entry, retained_file=local.name))
        self.checkpoint("source")
        if self.selected == "source":
            return
        self.active = "review"
        diff = self.read_blob(change["diff"])
        require(diff, "empty retained review diff")
        diff_file = self.out / "review-diff.bin"
        diff_file.write_bytes(diff)
        change_file = self.out / "change.json"
        dump(change_file, change)
        review_file = self.out / "review.json"
        # Diff has no frozen text encoding. Retain exact opaque diff bytes and
        # every referenced output for the real human UI; never substring-match
        # raw multiline files against a formatted unified diff.
        dump(review_file, {"change_id": change["id"], "manifest_sha256": change["manifest_sha256"],
                           "config": change["config"], "source_snapshot": change["source_snapshot"],
                           "renderer": change["renderer"], "reason": change["reason"],
                           "reason_file": reason_file.name, "ownership_manifest": change["ownership_manifest"],
                           "ownership_file": ownership_file.name,
                           "diff": change["diff"], "diff_file": diff_file.name,
                           "entries": review_entries})
        request = self.out / "approve.json"
        dump(request, {"change_id": change["id"], "manifest_sha256": change["manifest_sha256"],
                       "base_generation": change["base_generation"]})
        proof = self.out / "proof.json"
        self.active = "human"
        self.confirmation(request, change_file, review_file, proof)
        require(proof.is_file(), "human UI did not produce a real proof")
        approval = self.cli("human", ["org", "change", "approve", "--request", str(request),
                                      "--proof", str(proof)], "approve", cell="review")
        require(all(approval.get(key) for key in
                    ["id", "approver_key_id", "nonce_id", "requester_life_id"]),
                "missing verified approval provenance")
        require(approval["manifest_sha256"] == change["manifest_sha256"] and
                approval["requester_life_id"] == self.scopes["l6"]["actor"]["life_id"] and
                approval["change_id"] == change["id"] and
                approval["base_generation"] == change["base_generation"],
                "approval changed the requester, change, hash or base")
        require(self.snapshot() == original, "approval prematurely applied")
        self.checkpoint("review")
        self.checkpoint("human")
        if self.selected in {"review", "human"}:
            return
        self.active = "apply"
        apply_file = self.out / "apply.json"
        body = {"change_id": change["id"], "approval_id": approval["id"],
                "expected_generation": change["base_generation"]}
        dump(apply_file, body)
        key = secrets.token_hex(16)
        args = ["org", "change", "apply", "--request", str(apply_file),
                "--idempotency-key", key]
        receipt = self.cli("l6", args, "apply", cell="apply")
        require(receipt["old_generation"] == change["base_generation"] and
                receipt["new_generation"] == change["base_generation"] + 1,
                "application generation mismatch")
        require(receipt["manifest_sha256"] == change["manifest_sha256"] and
                receipt["approval_id"] == approval["id"] and
                receipt["change_id"] == change["id"], "wrong application receipt")
        wanted = dict(original)
        for delta in change["files"] + change["derived"]:
            path = delta["path"]
            if delta["action"] == "delete":
                require(path in wanted, "deletion targeted an absent file")
                wanted.pop(path)
            else:
                # Read back the original retained reference again after apply.
                data = self.read_blob(delta["after"])
                require(data == retained[path], "bytes changed after human review")
                wanted[path] = (delta["mode"], digest(data))
        require(self.snapshot() == wanted, "unapproved or missing resource effects")
        self.checkpoint("apply")
        if self.selected == "apply":
            return
        self.active = "retry"
        retry = self.cli("l6", args, "retry", cell="retry")
        require(retry == receipt, "idempotent retry did not return original receipt")
        require(self.snapshot() == wanted, "retry changed resources")
        changed_file = self.out / "changed-apply.json"
        dump(changed_file, dict(body, expected_generation=receipt["new_generation"]))
        self.cli("l6", ["org", "change", "apply", "--request", str(changed_file),
                        "--idempotency-key", key], "changed-key-intent",
                 expect_error={"idempotency_conflict"}, cell="retry")
        require(self.snapshot() == wanted, "changed-key intent mutated resources")
        self.cli("l6", ["org", "change", "apply", "--request", str(apply_file),
                        "--idempotency-key", secrets.token_hex(16)], "new-key-replay",
                 expect_error={"forbidden", "conflict"}, cell="retry")
        require(self.snapshot() == wanted, "new-key replay changed resources")
        self.checkpoint("retry")
        if self.selected == "retry":
            return
        self.active = "receipts"
        query = self.out / "approval-history.json"
        dump(query, {"cursor": "", "limit": 200})
        history = self.cli("human", ["dashboard", "approvals", "--request", str(query)], "history", cell="receipts")
        require(any(x["id"] == change["id"] for x in history["changes"]), "missing staged history")
        require(approval in history["approvals"], "missing approval history")
        require(receipt in history["applications"], "missing application history")
        self.checkpoint("receipts")

    def run(self):
        require(sys.platform == "linux", "ORG-APPROVAL requires the authorized Linux test box")
        fixture_path = Path(self.context["test_root"]) / "approval-fixture.json"
        self.f = read_json(fixture_path)
        require(self.f["contract_revision"] == "v2.0-draft.4" and self.f["config"] == self.config,
                "fixture differs from context/contract")
        for actor in ["l6", "l5"]:
            require("argv" not in self.f["actors"][actor], "actor must be a registered fixed job, not an argv prefix")
        self.keep("fixture.json", self.f)
        self.controller = Controller(self.context, self.keep)
        self.root = Path(self.f["canonical_root"])
        require(self.root.is_absolute(), "canonical root must be absolute")
        self.artifact()
        self.identities(("l6", "l5", "human"))
        for actor in ["l6", "l5"]:
            require(self.scopes[actor]["actor"]["life_id"] == self.f["actors"][actor]["target"]["life_id"],
                    "registered actor target differs from real identity")
        original = self.snapshot()
        self.keep("canonical-before.json", original)
        if self.selected == "filesystem":
            self.filesystem(original)
            return
        if self.selected in CONTROL:
            self.control(self.selected, original)
            return
        proposal, files, expected = self.prepare(original)
        if self.selected in {"all", "l5"}:
            self.l5(proposal, original)
            if self.selected == "l5":
                return
        if self.selected == "all":
            self.filesystem(original)
            for name in CONTROL:
                self.control(name, original)
        self.positive(proposal, files, expected, original)

    def finish(self, result_path, passed, error):
        self.summary("passed" if passed else "waiting" if isinstance(error, CaseWait) else "failed", error)
        if isinstance(error, CaseWait):
            self.keep("prerequisite-wait.json", error.failure())
        local_quiescent = all(row["exit"] is not None and row["group_absent"] and not row["timed_out"]
                              for row in self.processes)
        remote_quiescent = all(row["containment_state"] == "exited" and row["survivors"] == 0 for row in self.canaries)
        collection = {"cli_processes": self.processes, "controller_canaries": self.canaries,
                      "job_resources": self.job_resources,
                      "pending_controls": sorted(self.pending_controls), "open_upload_ids": sorted(self.open_uploads)}
        collection_path = self.baseout / "collection.json"
        dump(collection_path, collection)
        root = Path(self.context["evidence_root"])
        refs = []
        for path in sorted(root.rglob("*")):
            require(not path.is_symlink(), "result evidence contains a symlink")
            if path.is_file():
                data = path.read_bytes()
                refs.append({"path": path.relative_to(root).as_posix(), "sha256": digest(data), "bytes": len(data)})
        target = self.selected
        reached = (target in self.observed_cells and self.active == target if self.context["phase"] == "red"
                   else passed and set(CONTROL) | {"source", "review", "human", "apply", "retry", "receipts", "l5", "filesystem"} <= set(self.passed))
        if passed and self.context["phase"] == "red":
            reached = target in self.observed_cells
        quiescent = local_quiescent and remote_quiescent and not self.pending_controls
        collected = quiescent and not self.open_uploads and all(row["temporary_removed"] for row in self.job_resources)
        payload = {
            "schema": "laneboss.e2e-result.v2", "case_id": "approval", "phase": self.context["phase"],
            "mutation_id": self.context["mutation_id"], "binary_sha256": self.context["binary_sha256"],
            "source_sha256": self.context["source_sha256"],
            "assertions": [{"id": "ORG-APPROVAL", "reached": reached, "verdict": "pass" if passed else "fail",
                            "observed_exit": self.observed_exit, "evidence": refs}],
            "collection": {"processes_quiescent": quiescent, "temporary_resources_collected": collected,
                           "evidence": [ref for ref in refs if ref["path"] == collection_path.relative_to(root).as_posix()]},
        }
        temporary = result_path.with_name(result_path.name + "." + secrets.token_hex(16) + ".tmp")
        dump(temporary, payload)
        with temporary.open("rb") as stream:
            os.fsync(stream.fileno())
        os.replace(temporary, result_path)
        directory = os.open(result_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return passed and reached and quiescent and collected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    require(args.context.is_absolute() and args.result.is_absolute(), "harness paths must be absolute")
    context = read_json(args.context)
    required = {"schema", "case_id", "phase", "mutation_id", "binary", "binary_sha256", "source_sha256",
                "config", "binding_file", "test_root", "evidence_root", "profile_grant_ids"}
    require(required <= set(context) and set(context) <= required | {"controls"}, "context has missing/unknown fields")
    require(context["schema"] == "laneboss.e2e-context.v2" and context["case_id"] == "approval",
            "wrong frozen harness context")
    require(context["phase"] in {"red", "candidate"} and bool(context["mutation_id"]) == (context["phase"] == "red"),
            "invalid phase/mutation binding")
    require(context["phase"] != "red" or context["mutation_id"] in RED_CELLS, "unknown installed approval mutation")
    for key in ["binary_sha256", "source_sha256"]:
        require(re.fullmatch("[0-9a-f]{64}", context[key]) is not None, "invalid context digest")
    for key in ["binary", "binding_file", "test_root", "evidence_root"]:
        require(Path(context[key]).is_absolute(), "context path must be absolute: " + key)
    if "controls" in context:
        require(Path(context["controls"]).is_absolute(), "control binding path must be absolute")
    test_root = Path(context["test_root"]).resolve(strict=True)
    evidence = Path(context["evidence_root"]).resolve(strict=True)
    require(Path(context["test_root"]).is_absolute() and Path(context["evidence_root"]).is_absolute() and
            args.context.resolve(strict=True).is_relative_to(test_root) and
            args.result.parent.resolve(strict=True).is_relative_to(test_root) and not args.result.exists() and
            not args.result.is_symlink(), "harness input/result escapes its disposable scope")
    facts = evidence.lstat()
    require(stat.S_ISDIR(facts.st_mode) and facts.st_uid == os.geteuid() and not facts.st_mode & 0o077,
            "evidence root is not private and owned")
    require(not evidence.is_relative_to(Path(__file__).resolve().parents[4]), "evidence must be outside checkout")
    case = Case(context)
    error = None
    try:
        case.run()
        passed = True
    except (CaseFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as caught:
        error, passed = caught, False
    success = case.finish(args.result, passed, error)
    if isinstance(error, CaseWait):
        print(json.dumps(error.failure(), sort_keys=True), file=sys.stderr)
        return 69
    if not success:
        print("FAIL: ORG-APPROVAL: " + (str(error) if error is not None else "unreached or uncollected evidence"), file=sys.stderr)
        return 1
    print("PASS: ORG-APPROVAL" + ("" if case.selected == "all" else "." + case.selected))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (CaseFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print("FAIL: ORG-APPROVAL setup/result: " + str(error), file=sys.stderr)
        sys.exit(1)
