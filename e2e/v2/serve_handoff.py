"""Read serve2 179f3f0 evidence. This module never installs or starts a service."""

import base64
from pathlib import Path
import re

from support import (Failure, beneath, bytes_hash, decode, evidence, exact_keys,
                     integer, load, require, sha256, verify_evidence,
                     verify_tar_inventory)


# The actual serve2 catalog, independent of report.required_checks. A shortened
# report cannot turn an unexecuted lifecycle or state row into a successful gate.
COMMON = (
    "platform", "source", "build", "fixture.build", "authenticator.build",
    "root.stage", "boot.inputs", "namespace.install", "namespace.check",
    "admin.install", "admin.check", "installation", "fixture.enrollment",
    "serve", "health", "authenticator.create", "human.enroll.begin",
    "human.enroll.attestation", "human.enroll.complete", "human.enrollment",
    "admin.publish", "admin.publish.retry", "admin.publication",
)
STATE = (
    "human.session.challenge", "human.session.confirm", "human.session",
    "human.grants.challenge", "human.grants.confirm", "human.grants",
    "human.ticket.challenge", "human.ticket.confirm", "human.ticket",
    "human.read.challenge", "human.read.confirm", "human.check.challenge",
    "human.check.confirm", "state.launch", "state.plan", "state.capture",
    "state.collect", "state.authorized", "state.append", "state.read",
    "state.drop-reply", "state.restart", "state.retry", "state.receipt-count",
    "state.event-count", "state.effect-count", "state.changed-bytes",
    "state.exact-retry", "unready.owner", "direct-open", "uid.direct-open", "cleanup",
)
STAGES = {"initial_publish." + name for name in (
    "native_context", "protected_read", "load_validate", "bundle_validate",
    "object_hashes", "policy_validate", "template_validate", "revalidate",
    "plan", "seal", "commit", "read_object", "read_back", "total",
)}
CONFIG = re.compile(r"[a-z0-9][a-z0-9-]{0,31}\Z")


def expected_checks(scope):
    if scope == "serve-state":
        return list(COMMON + STATE)
    require(scope == "installed-lifecycle", "unknown serve report scope")
    result = list(COMMON) + [
        "human.session.challenge", "human.session.confirm", "human.session",
        "human.read.challenge", "human.read.confirm", "uid.direct-open",
    ]
    for driver in ("claudock", "codex"):
        for operation in ("session", "grants", "ticket", "read", "control"):
            result += ["human.%s.%s.%s" % (driver, operation, suffix)
                       for suffix in ("challenge", "confirm")]
        result += ["human.%s.%s" % (driver, operation)
                   for operation in ("session", "grants", "ticket")]
        result += ["lane.%s.%s" % (driver, step) for step in (
            "inputs", "start", "running", "events", "reason", "stop",
            "quiescent", "abandon", "archive", "clean", "collected",
        )]
    return result + ["cleanup"]


def errors(observed):
    found = []
    if observed.get("code"):
        found.append(observed)
    for name in ("refusal", "error"):
        if observed.get(name):
            found.append(observed[name])
    operation = observed.get("operation", {})
    if isinstance(operation, dict) and operation.get("error"):
        found.append(operation["error"])
    for journal in observed.get("journal_refusals", []):
        found += [item["error"] for item in journal["refusals"]]
    return found


def report_rows(report):
    exact_keys(report, ("schema", "config", "scope", "required_checks", "presence",
                        "human_approval", "authenticator_tag", "failure", "checks", "manifest"))
    require(report["schema"] == "laneboss.serve-report.v2" and
            isinstance(report["config"], str) and CONFIG.fullmatch(report["config"]),
            "wrong serve report identity")
    required = expected_checks(report["scope"])
    require(report["required_checks"] == required and
            [row["check"] for row in report["checks"]] == required,
            "serve report shortened or changed its required catalog")
    require(report["presence"] == "simulated" and report["human_approval"] == "not_proven" and
            report["authenticator_tag"] == "laneboss_e2e_authenticator",
            "serve report lost declared software presence")
    return {row["check"]: row for row in report["checks"]}


def require_passed(report, rows):
    for name, row in rows.items():
        observed = row["observed"]
        actual = errors(observed)
        if actual:
            typed = next((item for item in actual if isinstance(item, dict) and
                          item.get("owner") and item.get("code")), None)
            if typed is not None:
                raise Failure("serve stopped at " + name, typed["code"], typed["owner"])
        require(row["result"] == "pass" and observed.get("executed") is True and not actual,
                "serve row failed or did not execute: " + name)
        if name.startswith(("human.", "lane.", "state.")):
            require(row["presence"] == "simulated", "serve row lost simulated presence")
    require(report["failure"] is None, "serve retained an upstream failure")


class Retained:
    def __init__(self, directory, record):
        directory = Path(directory)
        require(directory.is_absolute() and directory.resolve(strict=True) == directory,
                "serve evidence directory must be canonical and absolute")
        report_path = beneath(directory, "report.json")
        self.report = load(report_path)
        record["serve_report"] = dict(evidence(directory, report_path), root=str(directory))
        record["upstream_failure"] = self.report.get("failure")
        self.rows = report_rows(self.report)
        manifest_name = self.report["config"] + "/manifest.json"
        require(self.report["manifest"] == manifest_name, "serve manifest is outside its config directory")
        manifest_path = beneath(directory, manifest_name)
        self.root = manifest_path.parent
        manifest = load(manifest_path)
        require(isinstance(manifest, list) and manifest, "serve evidence manifest is empty")
        self.files = {}
        for item in manifest:
            verify_evidence(self.root, item)
            require(item["path"] not in self.files, "duplicate serve manifest entry")
            self.files[item["path"]] = item
        actual = set()
        for path in self.root.rglob("*"):
            require(not path.is_symlink(), "linked serve evidence")
            if path.is_file():
                actual.add(str(path.relative_to(self.root)))
        require(actual == set(self.files) | {"manifest.json"}, "serve manifest omitted or invented evidence")
        record["serve_manifest"] = dict(evidence(directory, manifest_path), root=str(directory))
        record["config"] = self.report["config"]
        record["presence"] = self.report["presence"]
        record["human_approval"] = self.report["human_approval"]

    def path(self, name):
        require(name in self.files, "serve manifest lacks required input: " + name)
        path = beneath(self.root, name)
        verify_evidence(self.root, self.files[name])
        return path

    def document(self, name):
        return load(self.path(name))

    def command_bytes(self, name):
        require(name.endswith(".stdout"), "command output must name its retained stdout")
        stem = name.removesuffix(".stdout")
        exit_record = self.document(stem + ".exit.json")
        require(type(exit_record.get("exit_code")) is int and exit_record["exit_code"] == 0 and
                exit_record.get("timed_out") is False,
                "serve command failed or timed out: " + stem)
        argv = self.document(stem + ".argv.json")
        require(isinstance(argv, list) and argv and all(isinstance(word, str) for word in argv),
                "serve command lacks exact argv")
        return self.path(name).read_bytes()

    def commands(self, label):
        pattern = re.compile(r"[0-9]{3,}-" + re.escape(label) + r"\.stdout\Z")
        result = []
        for name in sorted(self.files):
            if not pattern.fullmatch(name):
                continue
            result.append(decode(self.command_bytes(name)))
        require(result, "serve command evidence is missing: " + label)
        return result


def stage_timings(retained):
    journals, declared = {}, {}
    for row in retained.rows.values():
        observed = row["observed"]
        for journal in observed.get("unit_journals", []):
            name = journal["stdout"]
            require(name not in journals, "duplicate retained unit journal")
            raw = retained.command_bytes(name)
            require(journal["exit_code"] == 0 and journal["result"] == ("captured" if raw else "empty") and
                    journal["bytes"] == len(raw) and journal["lines"] == len(raw.splitlines()) and
                    journal["sha256"] == bytes_hash(raw), "retained unit journal metadata differs")
            records = []
            for number, line in enumerate(raw.splitlines(), 1):
                if not line.lstrip().startswith(b"{"):
                    continue
                try:
                    value = decode(line)
                except Failure:
                    require(b"initial_publish." not in line, "malformed initial publication timing")
                    continue
                require(isinstance(value, dict), "journal JSON is not an object")
                stage = value.get("stage")
                if not isinstance(stage, str) or not stage.startswith("initial_publish."):
                    continue
                exact_keys(value, ("stage", "elapsed_ms"))
                require(journal["role"] == "service" and stage in STAGES and
                        integer(value["elapsed_ms"]), "invalid initial publication timing")
                records.append(dict(value, line=number))
            journals[name] = {"role": journal["role"], "stdout": name,
                              "sha256": bytes_hash(raw), "records": records, "invalid_lines": []}
        for timing in observed.get("initial_publish_timings", []):
            require(timing["stdout"] not in declared, "duplicate declared stage timing")
            declared[timing["stdout"]] = timing
    actual = {name: item for name, item in journals.items() if item["records"]}
    require(declared == actual, "reported timings differ from exact retained journal lines")
    stages = {row["stage"] for item in actual.values() for row in item["records"]}
    publication = retained.rows["admin.publish"]
    attempted = publication["result"] == "pass" or "publication_input" in publication["observed"]
    if attempted:
        require({"initial_publish.native_context", "initial_publish.total"} <= stages,
                "attempted publication lacks required stage timing")
    if publication["result"] == "pass":
        require(stages == STAGES, "successful publication lacks a required stage family")
    return list(actual.values())


def pinned(retained, name, ref):
    path = retained.path(name)
    exact_keys(ref, ("id", "class", "sha256", "bytes"))
    require(path.stat().st_size == ref["bytes"] and sha256(path) == ref["sha256"],
            "initial publication input pin differs: " + name)
    return path


def public_blob(retained, ref):
    chunks = [item for item in retained.commands("publication-blob") if item.get("object_id") == ref["id"]]
    chunks.sort(key=lambda item: item["offset"])
    result = bytearray()
    for chunk in chunks:
        raw = base64.b64decode(chunk["data"], validate=True)
        require(chunk["offset"] == len(result) and 0 < len(raw) <= 262144 and
                bytes_hash(raw) == chunk["sha256"], "public publication chunk differs")
        result.extend(raw)
    require(len(result) == ref["bytes"] and bytes_hash(result) == ref["sha256"],
            "public publication read-back is incomplete or corrupt")
    return bytes(result)


def publication(retained, record):
    rows, config = retained.rows, retained.report["config"]
    boot = retained.document("boot.json.input")
    initial_path = pinned(retained, "initial-inputs/initial.json", boot["initial_publication"])
    initial = load(initial_path)
    require(initial["schema"] == "laneboss.initial.v2" and initial["config"] == config and
            type(initial["generation"]) is int and initial["generation"] == 1,
            "initial descriptor differs from serve configuration")
    refs = {}
    require(0 < len(initial["objects"]) <= 512, "initial object inventory is empty or unbounded")
    for ref in initial["objects"]:
        require(isinstance(ref["id"], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", ref["id"]) and
                ref["id"] not in refs, "initial object identity is repeated or invalid")
        refs[ref["id"]] = ref
        pinned(retained, "initial-inputs/" + ref["id"], ref)
    require(sum(ref["bytes"] for ref in refs.values()) <= 64 << 20, "initial bundle exceeds byte bound")
    for key in ("runtime", "launch_enrollment", "policy", "sources", "source_manifest", "profiles", "task"):
        require(refs.get(initial[key]["id"]) == initial[key], "initial selector is outside its object closure")
    for name, key in (("runtime.json.input", "runtime"), ("launch-enrollment.json.input", "launch_enrollment")):
        path = pinned(retained, name, initial[key])
        require(path.read_bytes() == retained.path("initial-inputs/" + initial[key]["id"]).read_bytes(),
                "boot copy differs from published object")
    require(boot["runtime_manifest"] == initial["runtime"] and
            boot["launch_enrollment"] == initial["launch_enrollment"], "boot and publication enrollment pins differ")
    runtime = retained.document("runtime.json.input")
    launch = retained.document("launch-enrollment.json.input")
    require(runtime["schema"] == "laneboss.runtime.v2" and
            runtime["artifact"]["sha256"] == sha256(retained.path("laneboss.input")) and
            launch["config"] == config, "published runtime or enrollment differs from installed candidate")
    receipt = rows["admin.publish"]["observed"]["receipt"]
    require(receipt == rows["admin.publish.retry"]["observed"]["receipt"] and
            receipt == retained.document("initial-publication/first/receipt.json") and
            receipt == retained.document("initial-publication/retry/receipt.json"),
            "publication retry or retained durable receipt differs")
    require(receipt["schema"] == "laneboss.initial-receipt.v2" and receipt["config"] == config and
            receipt["manifest"] == boot["initial_publication"] and receipt["id"] == initial["id"] and
            type(receipt["generation"]) is int and receipt["generation"] == 1 and
            integer(receipt["committed_seq"], 1), "publication receipt lost its immutable input or commit")
    for label in ("initial-publish", "initial-publish-retry"):
        outputs = retained.commands(label)
        require(len(outputs) == 1 and outputs[0] == {"verified": True, "published": True, "receipt": receipt},
                "publication raw stdout differs from retained receipt")
    descriptor = public_blob(retained, receipt["manifest"])
    require(descriptor == initial_path.read_bytes(), "public descriptor differs from initial input")
    marker = decode(public_blob(retained, receipt["receipt"]))
    require(marker == {"schema": "laneboss.initial-marker.v2", "config": config,
                       "id": initial["id"], "manifest": receipt["manifest"]}, "public marker differs")
    policy = public_blob(retained, initial["policy"])
    require(policy == retained.path("initial-inputs/" + initial["policy"]["id"]).read_bytes(),
            "public policy differs from initial input")
    operations = retained.commands("publication-operation")
    require(len(operations) == 1, "publication operation read-back is missing or repeated")
    operation = operations[0]
    require(operation == rows["admin.publication"]["observed"]["operation"] and
            operation["id"] == receipt["operation_id"] and operation["status"] == "succeeded" and
            not operation.get("error") and operation["first_seq"] == operation["last_seq"] == receipt["committed_seq"],
            "public publication operation differs from committed receipt")
    record["publication"] = {"manifest": boot["initial_publication"], "receipt": receipt,
                             "objects": len(refs), "bytes": sum(ref["bytes"] for ref in refs.values())}


def fixture_output(retained):
    raw = retained.path("fixture-enrollment.input.json").read_bytes()
    runtime = retained.document("runtime.json.input")
    descriptors = [item for item in runtime["objects"] if item["role"] == "serve-fixture-config"]
    require(len(descriptors) == 1, "fixture output lacks one enrolled descriptor")
    ref = descriptors[0]["content"]
    require(ref["bytes"] == len(raw) and ref["sha256"] == bytes_hash(raw),
            "fixture descriptor pin differs from enrolled runtime")
    declared = decode(raw)
    require(declared.get("schema") == "laneboss.serve-agent.v1" and
            declared.get("config") == retained.report["config"] and
            declared.get("output") == "/home/lane/serve-state",
            "fixture output differs from its enrolled private home contract")
    return declared["output"]


def verify_serve(directory, record):
    retained = Retained(directory, record)
    record["initial_publish_timings"] = stage_timings(retained)
    require_passed(retained.report, retained.rows)
    publication(retained, record)
    record["fixture_output"] = fixture_output(retained)
    source = retained.path("source.tar")
    verify_tar_inventory(source, retained.document("source-files.json"))
    binary = retained.path("laneboss.input")
    installed = retained.document("installation.input.json")
    boot = retained.document("boot.json.input")
    binary_hash = sha256(binary)
    require(installed["config"] == retained.report["config"] and installed["artifact_sha256"] == binary_hash and
            installed["runtime_manifest"] == boot["runtime_manifest"] and
            installed["launch_enrollment"] == boot["launch_enrollment"],
            "installed artifact differs from retained binary")
    health = retained.commands("health")
    observed = {key: value for key, value in retained.rows["health"]["observed"].items() if key != "executed"}
    require(len(health) == 1 and health[0] == observed and health[0]["artifact_sha256"] == binary_hash,
            "raw health differs from installed artifact or report")
    sessions = retained.commands("human-session")
    session = {key: value for key, value in retained.rows["human.session"]["observed"].items()
               if key not in ("executed", "connection_closed")}
    require(session in sessions and session["config"] == installed["config"] and
            session["simulated_presence"] is True, "raw human session differs from report")
    cleanup = retained.rows["cleanup"]["observed"]
    require(cleanup["owned_units_stopped"] is True and cleanup["socket_collected"] is True and
            cleanup["installation_retained"] is True, "serve did not complete owned unit collection")
    record.update(binary_sha256=binary_hash, source_sha256=sha256(source),
                  source_archive=dict(evidence(retained.root, source), root=str(retained.root)),
                  binary_archive=dict(evidence(retained.root, binary), root=str(retained.root)),
                  installation=dict(evidence(retained.root, retained.path("installation.input.json")),
                                    root=str(retained.root)),
                  service_state="stopped by serve cleanup", scope=retained.report["scope"])
    return retained
