#!/usr/bin/env python3
"""Retain one real mutation failure, then its focused green control on Linux."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys


class ProofFailure(Exception):
    pass


SOURCE_SCOPE = "main-module test dependency closure and declared dispatcher runtime inputs"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    pending = path.with_suffix(path.suffix + ".pending")
    pending.write_text(json.dumps(value, indent=2) + "\n")
    pending.replace(path)


def private_directory(path, *, parents=False, exist_ok=False):
    path.mkdir(mode=0o700, parents=parents, exist_ok=exist_ok)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise ProofFailure("evidence directory must be ordinary and owned by the test identity")
    path.chmod(0o700)


def objects(data):
    decoder = json.JSONDecoder()
    value = data.decode("utf-8")
    position = 0
    result = []
    while position < len(value):
        while position < len(value) and value[position].isspace():
            position += 1
        if position == len(value):
            break
        item, position = decoder.raw_decode(value, position)
        result.append(item)
    return result


def owned_path(parts):
    if not isinstance(parts, list) or not parts or any(
            not isinstance(part, str) or part in {"", ".", ".."} or
            "/" in part or "\\" in part for part in parts):
        raise ProofFailure("mutation path is not a component-relative source path")
    path = Path(*parts)
    prefixes = [("internal", "v2", "grants"),
                ("internal", "v2", "dataworker"),
                ("internal", "v2", "store")]
    cli_adapter = tuple(parts) == ("internal", "v2", "cli", "commands_grants.go")
    stage_adapter = tuple(parts) in {
        ("internal", "v2", "service"),
        ("internal", "v2", "secrets"),
        ("internal", "v2", "secrets", "stage_commit.go"),
    }
    if not cli_adapter and not stage_adapter and not any(tuple(parts[:len(prefix)]) == prefix for prefix in prefixes):
        raise ProofFailure("mutation target is outside the lane's source ownership")
    return path


def catalog(path):
    raw = path.read_bytes()
    value = json.loads(raw)
    if value.get("schema") != "laneboss.grants-mutations.v2":
        raise ProofFailure("mutation catalog schema mismatch")
    seen = set()
    deciding = set()
    source_patches = set()
    for entry in value["mutations"]:
        aliases = entry.get("aliases", [])
        if not isinstance(aliases, list):
            raise ProofFailure("mutation aliases must be a list")
        for name in [entry["id"], *aliases]:
            if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,38}", name) or name in seen:
                raise ProofFailure("invalid or duplicate mutation name or alias")
            seen.add(name)
        if not entry.get("test") or not all(isinstance(part, str) and part
                                             for part in entry["test"]):
            raise ProofFailure("mutation has no named target assertion")
        if entry["status"] == "ready":
            if entry["layer"] != "unit" or not entry.get("patches") or not entry.get("failure"):
                raise ProofFailure("ready mutation has no applicable check or assertion")
            owned_path(entry["package"])
            assertion = (tuple(entry["test"]), entry["failure"])
            patches = tuple(sorted((tuple(patch["file"]), patch["before"], patch["after"])
                                   for patch in entry["patches"]))
            if assertion in deciding:
                raise ProofFailure("ready mutations share a deciding test and assertion")
            if patches in source_patches:
                raise ProofFailure("ready mutations share the same source patches")
            deciding.add(assertion)
            source_patches.add(patches)
            for name in entry.get("required_failures", [entry["test"]]):
                if not isinstance(name, list) or not name or any(not isinstance(part, str) or not part for part in name):
                    raise ProofFailure("mutation has an invalid required subcase")
                if name[:len(entry["test"])] != entry["test"]:
                    raise ProofFailure("required subcase is outside the selected test")
            for patch in entry["patches"]:
                owned_path(patch["file"])
                if not patch["before"] or patch["before"] == patch["after"]:
                    raise ProofFailure("mutation does not change a source check")
        elif entry["status"] != "blocked" or not entry.get("blocked_reason"):
            raise ProofFailure("mutation has an unknown or unexplained availability")
    return raw, value["mutations"]


class Runner:
    def __init__(self, source, evidence, tags):
        self.source = source
        self.evidence = evidence
        self.tags = tags
        self.files = []
        self.candidate = None
        self.candidate_digest = None
        self.binaries = {}

    def command(self, args, cwd, directory, name):
        try:
            completed = subprocess.run(args, cwd=cwd, capture_output=True, timeout=600)
        except subprocess.TimeoutExpired as error:
            (directory / (name + ".stdout")).write_bytes(error.stdout or b"")
            (directory / (name + ".stderr")).write_bytes(error.stderr or b"")
            write_json(directory / (name + ".json"), {
                "argv": args, "timed_out": True, "exit": None})
            raise ProofFailure("command exceeded its deadline; no assertion was proved") from error
        (directory / (name + ".stdout")).write_bytes(completed.stdout)
        (directory / (name + ".stderr")).write_bytes(completed.stderr)
        write_json(directory / (name + ".json"), {
            "argv": args, "exit": completed.returncode, "timed_out": False,
            "stdout_sha256": sha(completed.stdout),
            "stderr_sha256": sha(completed.stderr)})
        return completed

    def go_args(self, *parts):
        args = ["go", *parts, "-mod=readonly"]
        if self.tags:
            args.extend(["-tags", self.tags])
        return args

    def dependency_files(self, packages):
        metadata = self.evidence / "metadata"
        private_directory(metadata)
        contract_source = self.source / "internal" / "v2" / "api" / "base.go"
        contract_bytes = contract_source.read_bytes()
        revision = re.search(rb'ContractRevision\s*=\s*"([^"]+)"', contract_bytes)
        if revision is None or revision[1] != b"v2.0-draft.4":
            raise ProofFailure("mutation source does not carry the required draft.4 contracts")
        write_json(metadata / "contract.json", {
            "contract_revision": revision[1].decode("ascii"),
            "source_sha256": sha(contract_bytes)})
        version = self.command(["go", "version"], self.source, metadata, "go-version")
        if version.returncode != 0:
            raise ProofFailure("Go version inspection failed")
        dependencies = set(packages)
        dispatcher_inputs = []
        if Path("internal/v2/service") in dependencies:
            # The real dispatcher regression builds this helper and imports
            # these case producers at runtime from its retained source copy.
            dependencies.add(Path("scripts/v2-serve/grants_seal"))
            dispatcher_inputs = [Path(name) for name in (
                "e2e/v2/cases/grants/dispatcher_input.py",
                "e2e/v2/cases/grants/boot_bundle_input.py",
                "scripts/v2-serve/case_grants.py",
                "scripts/v2-serve/item_context.py",
                "scripts/v2-serve/lifecycle.py",
                "scripts/v2-serve/grants_upload.py",
            )]
        invocation = self.go_args("list", "-deps", "-test", "-json")
        invocation.extend("./" + str(package) for package in sorted(dependencies))
        graph = self.command(invocation, self.source, metadata, "dependencies")
        if graph.returncode != 0:
            raise ProofFailure("dependency discovery failed before any red assertion")
        fields = ("GoFiles", "CgoFiles", "CFiles", "CXXFiles", "MFiles",
                  "HFiles", "FFiles", "SFiles", "SwigFiles", "SwigCXXFiles",
                  "SysoFiles", "TestGoFiles", "XTestGoFiles", "EmbedFiles",
                  "TestEmbedFiles", "XTestEmbedFiles")
        files = {Path("go.mod"), Path("go.sum"), *dispatcher_inputs}
        if (self.source / "vendor/modules.txt").is_file():
            files.add(Path("vendor/modules.txt"))
        for package in objects(graph.stdout):
            if package.get("Error") or package.get("DepsErrors"):
                raise ProofFailure("dependency graph contains a build error")
            if package.get("Name") == "main" and package.get("ImportPath", "").endswith(".test"):
                continue  # Go generates this wrapper from the retained tests.
            directory = package.get("Dir")
            if not directory:
                continue
            directory = Path(directory).resolve()
            if not directory.is_relative_to(self.source):
                continue  # Standard library / pinned external modules remain tool inputs.
            for field in fields:
                for name in package.get(field, []):
                    path = directory / name
                    if path.is_symlink() or not path.resolve().is_relative_to(self.source):
                        raise ProofFailure("dependency source escapes its source snapshot")
                    if not path.is_file():
                        raise ProofFailure("dependency source is missing")
                    files.add(path.relative_to(self.source))
        self.files = sorted(files)
        write_json(metadata / "source-files.json", [str(path) for path in self.files])
        write_json(metadata / "environment.json", {
            "system": platform.system(), "release": platform.release(),
            "architecture": platform.machine(), "tags": self.tags,
            "contract_revision": "v2.0-draft.4",
            "source_scope": SOURCE_SCOPE,
            "external_inputs": "Go toolchain and module versions pinned by go.mod/go.sum"})

    def snapshot(self, name):
        directory = self.evidence / name
        private_directory(directory)
        checkout = directory / "source"
        private_directory(checkout)
        origin_root = self.candidate[1] if self.candidate is not None else self.source
        for relative in self.files:
            origin = origin_root / relative
            target = checkout / relative
            if origin.is_symlink():
                raise ProofFailure("source became a symlink during snapshot")
            private_directory(target.parent, parents=True, exist_ok=True)
            shutil.copy2(origin, target)
        return directory, checkout

    def keep_candidate(self):
        directory, checkout = self.snapshot("candidate")
        self.candidate_digest = self.inventory(directory, checkout)
        self.candidate = directory, checkout

    def inventory(self, directory, checkout):
        rows = []
        for path in sorted(checkout.rglob("*")):
            if path.is_file():
                data = path.read_bytes()
                rows.append({"path": str(path.relative_to(checkout)),
                             "sha256": sha(data), "bytes": len(data)})
        serialized = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
        write_json(directory / "source-manifest.json", {
            "scope": SOURCE_SCOPE, "sha256": sha(serialized),
            "files": rows})
        return sha(serialized)

    def apply(self, entry, directory, checkout):
        changes = []
        for patch in entry["patches"]:
            path = checkout / owned_path(patch["file"])
            if not path.is_file() or path.is_symlink():
                raise ProofFailure("mutation source is absent from the compiled dependency closure")
            before = path.read_bytes()
            needle, replacement = patch["before"].encode(), patch["after"].encode()
            if before.count(needle) != 1:
                raise ProofFailure("mutation does not match exactly one source check")
            after = before.replace(needle, replacement, 1)
            path.write_bytes(after)
            changes.append({"path": str(path.relative_to(checkout)),
                            "before_sha256": sha(before), "after_sha256": sha(after),
                            "before": patch["before"], "after": patch["after"]})
        write_json(directory / "mutation.json", {"id": entry["id"], "changes": changes})

    def build(self, package, directory, checkout):
        binary = directory / ("unit-" + package.name + ".test")
        invocation = self.go_args("test", "-c", "-o", str(binary))
        invocation.append("./" + str(package))
        completed = self.command(invocation, checkout, directory, "build-" + package.name)
        if completed.returncode != 0:
            raise ProofFailure("unit artifact build failed; no mutation was proved")
        data = binary.read_bytes()
        write_json(directory / ("binary-" + package.name + ".json"), {
            "sha256": sha(data), "bytes": len(data)})
        return binary, sha(data)

    def test(self, binary, package, directory, checkout, entry, phase, binary_digest, source_digest):
        parts = entry["test"]
        target = "/".join(parts)
        pattern = "/".join("^" + re.escape(part) + "$" for part in parts)
        invocation = ["go", "tool", "test2json", "-t", "-p", str(package),
                      str(binary), "-test.v=test2json", "-test.run=" + pattern]
        completed = self.command(invocation, checkout, directory, phase + "-" + entry["id"])
        try:
            events = objects(completed.stdout)
        except (ValueError, UnicodeError) as error:
            raise ProofFailure("test output is not the actual Go test event stream") from error
        relevant = [event for event in events if event.get("Test") == target or
                    event.get("Test", "").startswith(target + "/")]
        reached = any(event.get("Action") == "run" for event in relevant)
        failed = sorted({event["Test"] for event in relevant if event.get("Action") == "fail"})
        text = "".join(event.get("Output", "") for event in relevant)
        reason = entry["failure"] in text
        passed = any(event.get("Action") == "pass" and event.get("Test") == target for event in events)
        row = {"phase": phase, "mutation_id": entry["id"], "target": target,
               "package": str(package), "exit": completed.returncode,
               "reached": reached, "failed_tests": failed,
               "expected_failure_seen": reason, "target_passed": passed,
               "binary_sha256": binary_digest, "source_sha256": source_digest}
        required = entry.get("required_failures", [parts])
        required_names = ["/".join(name) for name in required]
        missing = []
        if phase == "red":
            for name in required_names:
                output = "".join(event.get("Output", "") for event in events if event.get("Test") == name)
                if name not in failed or entry["failure"] not in output:
                    missing.append(name)
        row["required_failures"] = required_names
        row["missing_red_failures"] = missing
        unexpected = [name for name in failed if not any(
            name == required_name or required_name.startswith(name + "/")
            for required_name in required_names)]
        row["unexpected_red_failures"] = unexpected if phase == "red" else []
        write_json(directory / (phase + "-" + entry["id"] + "-assertion.json"), row)
        if phase == "red":
            if completed.returncode != 1 or not reached or not failed or not reason or missing or unexpected:
                raise ProofFailure("mutation survived or failed before its named assertion")
        elif completed.returncode != 0 or not reached or not passed or failed:
            raise ProofFailure("unchanged candidate did not pass the same focused assertion")
        return row

    def prove(self, entry):
        package = owned_path(entry["package"])
        directory, checkout = self.snapshot("red-" + entry["id"])
        self.apply(entry, directory, checkout)
        source_digest = self.inventory(directory, checkout)
        binary, binary_digest = self.build(package, directory, checkout)
        red = self.test(binary, package, directory, checkout, entry, "red", binary_digest, source_digest)
        candidate_dir, candidate_checkout = self.candidate
        if package not in self.binaries:
            self.binaries[package] = self.build(package, candidate_dir, candidate_checkout)
        candidate_binary, candidate_binary_digest = self.binaries[package]
        if candidate_binary_digest == binary_digest or self.candidate_digest == source_digest:
            raise ProofFailure("red and green artifacts do not have distinct retained identities")
        green = self.test(candidate_binary, package, candidate_dir, candidate_checkout, entry,
                          "green", candidate_binary_digest, self.candidate_digest)
        return {"id": entry["id"], "rule": entry["rule"], "layer": entry["layer"],
                "verdict": "killed_then_green", "red": red, "green": green}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source")
    parser.add_argument("--evidence")
    parser.add_argument("--mutation", action="append")
    parser.add_argument("--tags", choices=["", "laneboss_faults"], default="")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if platform.system() != "Linux":
        raise ProofFailure("red controls run only on the authorized Linux box")
    catalog_bytes, entries = catalog(Path(__file__).with_name("mutations.json"))
    if args.list:
        for entry in entries:
            print(entry["id"], entry["status"], entry["rule"], "/".join(entry["test"]))
            for alias in entry.get("aliases", []):
                print(alias, entry["status"], entry["rule"], "alias of", entry["id"])
        return 0
    if not args.source or not args.evidence:
        parser.error("--source and --evidence are required for a proof run")
    names = args.mutation or ["all-ready"]
    if "all-ready" in names:
        if names != ["all-ready"]:
            parser.error("all-ready cannot be mixed with individual mutation names")
        selected = [entry for entry in entries if entry["status"] == "ready"]
    else:
        if len(names) != len(set(names)):
            parser.error("each mutation may be selected only once")
        by_name = {name: entry for entry in entries for name in [entry["id"], *entry.get("aliases", [])]}
        if any(name not in by_name for name in names):
            parser.error("unknown mutation name")
        selected = list({by_name[name]["id"]: by_name[name] for name in names}.values())
    source = Path(args.source).resolve(strict=True)
    evidence = Path(args.evidence).resolve()
    if evidence.is_relative_to(source):
        raise ProofFailure("retain mutation copies and binaries outside the checkout")
    private_directory(evidence, parents=True)
    (evidence / "mutations.json").write_bytes(catalog_bytes)
    result = {"schema": "laneboss.grants-red.v2", "status": "running",
              "contract_revision": "v2.0-draft.4",
              "scope": "selected unit mutation prerequisites", "tags": args.tags,
              "catalog_sha256": sha(catalog_bytes), "proofs": [],
              "requested_mutations": names,
              "pending_os": [entry["id"] for entry in entries if entry["status"] == "blocked"],
              "full_os_acceptance": False}
    result_path = evidence / "results.json"
    write_json(result_path, result)
    blocked = [entry for entry in selected if entry["status"] == "blocked"]
    if blocked:
        result["status"] = "not_implemented"
        result["blocked"] = [{"id": entry["id"], "reason": entry["blocked_reason"]} for entry in blocked]
        write_json(result_path, result)
        print("UNAVAILABLE: selected OS mutation requires its missing production contract")
        return 69
    runner = Runner(source, evidence, args.tags)
    try:
        packages = sorted({owned_path(entry["package"]) for entry in selected})
        runner.dependency_files(packages)
        runner.keep_candidate()  # Retain once; execute its tests only after red.
        for entry in selected:
            result["proofs"].append(runner.prove(entry))
            write_json(result_path, result)
            proof = result["proofs"][-1]
            print(entry["id"], "red: " + ", ".join(proof["red"]["failed_tests"]),
                  "green: " + proof["green"]["target"])
    except (ProofFailure, OSError, ValueError, KeyError) as error:
        result["status"] = "failed"
        result["failure"] = str(error) if isinstance(error, ProofFailure) else "source, tool or evidence operation failed"
        write_json(result_path, result)
        print("FAIL: grants unit red controls; " + result["failure"] + "; inspect retained results")
        return 1
    result["status"] = "unit_proved"
    write_json(result_path, result)
    print("PASS: grants unit red controls")
    print("Scope: selected unit mutations; OS acceptance remains pending.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ProofFailure as error:
        print("FAIL: " + str(error), file=sys.stderr)
        raise SystemExit(1) from error
