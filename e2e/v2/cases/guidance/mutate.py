#!/usr/bin/env python3
"""Run one named component mutation on a retained Linux source copy."""

import argparse
from collections import defaultdict
import difflib
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import stat
import subprocess
import sys
import tarfile


CATALOG = Path(__file__).with_name("mutations.json")
PACKAGE = "./internal/v2/guidance"
OWNER = "lb-v2-guidance"
CONTRACT = "v2.0-draft.4"
MAX_SOURCE_BYTES = 512 * 1024 * 1024


class MutationError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def require(condition, code):
    if not condition:
        raise MutationError(code)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)
            + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, data):
    temporary = path.with_name(path.name + ".partial")
    with temporary.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def reference(root, path):
    data = path.read_bytes()
    return {"path": str(path.relative_to(root)),
            "sha256": digest(data), "bytes": len(data)}


def owned_target(name):
    path = PurePosixPath(name)
    return (
        not path.is_absolute() and ".." not in path.parts
        and path.suffix == ".go" and not path.name.endswith("_test.go")
        and (path.parent == PurePosixPath("internal/v2/guidance")
             or str(path) == "internal/v2/cli/commands_guidance.go")
    )


def load_catalog(path=CATALOG):
    catalog = json.loads(path.read_bytes())
    require(catalog["schema"] == "laneboss.guidance-mutations.v1",
            "catalog_schema")
    require(catalog["contract_revision"] == CONTRACT, "catalog_contract")
    require(catalog["mutations"], "empty_catalog")
    names = set()
    for mutation in catalog["mutations"]:
        name = mutation["id"]
        require(re.fullmatch(r"[a-z][a-z0-9-]{0,38}", name) is not None
                and name not in names, "mutation_id")
        names.add(name)
        if mutation["state"] == "ready":
            require(mutation["scope"] == "component"
                    and mutation["test"] and mutation["failure_contains"]
                    and mutation["edits"], "ready_mutation_shape")
            for segment in mutation["test"]:
                require(re.fullmatch(r"[A-Za-z0-9_-]{1,39}", segment)
                        is not None, "test_name")
            for edit in mutation["edits"]:
                require(owned_target(edit["file"]) and edit["before"]
                        and edit["before"] != edit["after"], "mutation_edit")
        else:
            require(mutation["state"] == "not_implemented"
                    and mutation["scope"] == "integration"
                    and not mutation["edits"] and mutation["requires"],
                    "pending_mutation_shape")
            for edit in mutation.get("blocked_edits", []):
                require(owned_target(edit["file"]) and edit["before"]
                        and edit["before"] != edit["after"], "blocked_edit")
    return catalog


def traversal_error(error):
    raise error


def source_manifest(root):
    rows = []
    total = 0
    for directory, names, files in os.walk(root, followlinks=False,
                                          onerror=traversal_error):
        names[:] = sorted(name for name in names
                          if name not in {".git", "__pycache__"})
        for name in names:
            require(not (Path(directory) / name).is_symlink(),
                    "source_directory_link")
        for name in sorted(files):
            if name == ".git":
                continue
            path = Path(directory) / name
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode), "source_not_regular")
            require(info.st_size <= 64 * 1024 * 1024, "source_file_bound")
            data = path.read_bytes()
            total += len(data)
            require(total <= MAX_SOURCE_BYTES, "source_total_bound")
            rows.append({"path": str(path.relative_to(root)),
                         "sha256": digest(data), "bytes": len(data),
                         "mode": stat.S_IMODE(info.st_mode)})
    return sorted(rows, key=lambda row: row["path"])


def copy_snapshot(source, destination, evidence):
    before = source_manifest(source)
    require(before, "empty_source")
    destination.mkdir()
    for row in before:
        origin = source / row["path"]
        target = destination / row["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        data = origin.read_bytes()
        require(digest(data) == row["sha256"], "source_changed_during_copy")
        target.write_bytes(data)
        target.chmod(row["mode"])
    require(source_manifest(destination) == before, "snapshot_copy_differs")
    save(evidence / "source-manifest.json", encode(before))
    # Archive exact input bytes without copying host user/group names.
    with tarfile.open(evidence / "source.tar.gz", "x:gz") as archive:
        for row in before:
            data = (destination / row["path"]).read_bytes()
            info = tarfile.TarInfo(row["path"])
            info.size, info.mode, info.mtime = len(data), row["mode"], 0
            archive.addfile(info, io.BytesIO(data))
    return before


def apply_edits(work, edits, evidence):
    originals = {}
    modified = {}
    for edit in edits:
        require(owned_target(edit["file"]), "mutation_target_scope")
        path = work / edit["file"]
        require(path.is_file() and not path.is_symlink(), "mutation_target")
        if edit["file"] not in originals:
            originals[edit["file"]] = path.read_bytes()
            modified[edit["file"]] = originals[edit["file"]].decode()
        current = modified[edit["file"]]
        require(current.count(edit["before"]) == 1, "mutation_anchor_drift")
        modified[edit["file"]] = current.replace(
            edit["before"], edit["after"], 1)
    changes = []
    diff = []
    for index, (name, text) in enumerate(sorted(modified.items())):
        before = originals[name]
        after = text.encode()
        require(after != before, "mutation_has_no_effect")
        save(evidence / f"edit-{index:02d}.before", before)
        save(evidence / f"edit-{index:02d}.after", after)
        (work / name).write_bytes(after)
        changes.append({"path": name, "before_sha256": digest(before),
                        "after_sha256": digest(after),
                        "before_bytes": len(before), "after_bytes": len(after)})
        diff.extend(difflib.unified_diff(
            before.decode().splitlines(keepends=True),
            text.splitlines(keepends=True), fromfile="a/" + name,
            tofile="b/" + name))
    save(evidence / "mutation.patch", "".join(diff).encode())
    return originals, changes


def parse_events(data):
    summary = {"ran": set(), "failed": set(), "passed": set(),
               "skipped": set(), "package_failed": False,
               "package_passed": False, "build_failed": False}
    outputs = defaultdict(str)
    for line in data.splitlines():
        require(line.strip(), "blank_go_json_line")
        event = json.loads(line)
        require(isinstance(event, dict) and "Action" in event,
                "go_json_shape")
        action, test = event["Action"], event.get("Test")
        if event.get("FailedBuild") or action == "build-fail":
            summary["build_failed"] = True
        if test:
            require(isinstance(test, str), "go_test_name")
            if action in {"run", "fail", "pass", "skip"}:
                field = {"run": "ran", "fail": "failed",
                         "pass": "passed", "skip": "skipped"}[action]
                summary[field].add(test)
            if action == "output":
                outputs[test] += event["Output"]
        elif action == "fail":
            summary["package_failed"] = True
        elif action == "pass":
            summary["package_passed"] = True
    summary["output_by_test"] = dict(outputs)
    return summary


def related(name, expected):
    return name == expected or name.startswith(expected + "/") or expected.startswith(name + "/")


def check_phase(summary, exit_code, mutation, red):
    expected = "/".join(mutation["test"])
    require(not summary["build_failed"], "go_build_failed")
    require(not summary["skipped"], "test_skipped")
    require(expected in summary["ran"], "target_not_reached")
    require(not any(not related(name, expected)
                    for name in summary["ran"]), "unexpected_test_ran")
    if red:
        require(exit_code != 0, "mutation_survived")
        require(exit_code == 1, "unexpected_red_exit")
        require(summary["package_failed"] and expected in summary["failed"],
                "target_did_not_fail")
        require(not any(not related(name, expected)
                        for name in summary["failed"]), "unexpected_test_failed")
        output = "".join(text for name, text in summary["output_by_test"].items()
                         if name == expected or name.startswith(expected + "/"))
        require(mutation["failure_contains"] in output,
                "wrong_failure_reason")
        require("panic:" not in output and "fatal error:" not in output,
                "test_crashed")
    else:
        require(exit_code == 0 and summary["package_passed"]
                and expected in summary["passed"] and not summary["failed"],
                "green_test_failed")


def run_phase(work, evidence, phase, mutation, faults):
    focus = "/".join("^" + re.escape(part) + "$" for part in mutation["test"])
    command = ["go", "test", "-mod=readonly", "-json", "-count=1",
               "-timeout=90s", "-run", focus]
    if faults:
        command += ["-tags", "laneboss_faults"]
    command.append(PACKAGE)
    stdout = evidence / (phase + ".stdout.jsonl")
    stderr = evidence / (phase + ".stderr")
    result = {"argv": command, "cwd": "work", "exit_code": None,
              "timed_out": False}
    with stdout.open("xb") as out, stderr.open("xb") as err:
        try:
            completed = subprocess.run(command, cwd=work, stdout=out, stderr=err,
                                       timeout=240, check=False)
            result["exit_code"] = completed.returncode
        except subprocess.TimeoutExpired:
            result["timed_out"] = True
    result["stdout"] = reference(evidence, stdout)
    result["stderr"] = reference(evidence, stderr)
    save(evidence / (phase + "-command.json"), encode(result))
    if not result["timed_out"]:
        summary = parse_events(stdout.read_bytes())
        for key, value in summary.items():
            if key != "output_by_test":
                result[key] = sorted(value) if isinstance(value, set) else value
        result["summary"] = summary
    return result


def clean_phase(result):
    return {key: value for key, value in result.items() if key != "summary"}


def run_one(source, evidence, mutation, faults):
    report = {
        "schema": "laneboss.guidance-mutation.v1", "owner": OWNER,
        "contract_revision": CONTRACT,
        "mutation_id": mutation["id"], "scope": mutation["scope"],
        "acceptance": mutation["acceptance"], "test": mutation["test"],
        "tags": ["laneboss_faults"] if faults else [],
        "status": "incomplete", "full_guide_turn": "pending_integration",
        "phases": {}, "changed_files": [], "evidence": [],
        "environment": {"os": sys.platform, "arch": platform.machine(),
                        "kernel": platform.release()},
    }
    evidence.mkdir()
    save(evidence / "mutation.json", encode(mutation))
    if mutation["state"] == "not_implemented":
        report["status"] = "not_implemented"
        report["error"] = {"code": "not_implemented", "owner": "lb-v2-integrate",
                           "requires": mutation["requires"]}
        report["evidence"] = [reference(evidence, evidence / "mutation.json")]
        save(evidence / "result.json", encode(report))
        return 69
    try:
        work = evidence / "work"
        original_manifest = copy_snapshot(source, work, evidence)
        report["source_sha256"] = digest(encode(original_manifest))
        version = subprocess.run(["go", "version"], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=30, check=False)
        save(evidence / "go-version.stdout", version.stdout)
        save(evidence / "go-version.stderr", version.stderr)
        save(evidence / "go-version-exit.json", encode({"exit_code": version.returncode}))
        require(version.returncode == 0, "go_version_failed")
        originals, changes = apply_edits(work, mutation["edits"], evidence)
        report["changed_files"] = changes
        red_manifest = source_manifest(work)
        save(evidence / "red-source-manifest.json", encode(red_manifest))
        expected_changes = {row["path"] for row in changes}
        original_rows = {row["path"]: row for row in original_manifest}
        require({row["path"] for row in red_manifest
                 if row != original_rows[row["path"]]} == expected_changes,
                "unintended_source_change")
        red = run_phase(work, evidence, "red", mutation, faults)
        report["phases"]["red"] = clean_phase(red)
        require(not red["timed_out"], "red_timeout")
        check_phase(red["summary"], red["exit_code"], mutation, red=True)
        require(source_manifest(work) == red_manifest,
                "source_changed_during_red")
        for name, data in originals.items():
            (work / name).write_bytes(data)
        require(source_manifest(work) == original_manifest,
                "green_restore_differs")
        green = run_phase(work, evidence, "green", mutation, faults)
        report["phases"]["green"] = clean_phase(green)
        require(not green["timed_out"], "green_timeout")
        check_phase(green["summary"], green["exit_code"], mutation, red=False)
        require(source_manifest(work) == original_manifest,
                "source_changed_during_green")
        require(source_manifest(source) == original_manifest,
                "original_source_changed")
        report["status"] = "killed"
    except MutationError as error:
        report["error"] = {"code": error.code}
        if error.code == "mutation_survived":
            report["status"] = "survived"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["error"] = {"code": "mutation_setup_failed",
                           "category": type(error).__name__}
    report["evidence"] = [reference(evidence, path) for path in sorted(evidence.iterdir())
                          if path.is_file() and path.name != "result.json"]
    save(evidence / "result.json", encode(report))
    return 0 if report["status"] == "killed" else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path)
    parser.add_argument("--evidence", type=Path)
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--mutation")
    selector.add_argument("--components", action="store_true")
    selector.add_argument("--list", action="store_true")
    parser.add_argument("--faults", action="store_true")
    args = parser.parse_args()
    try:
        require(sys.platform == "linux", "linux_test_box_required")
        catalog = load_catalog()
        if args.list:
            print(json.dumps([{key: mutation[key] for key in
                              ("id", "state", "scope", "acceptance", "test")}
                              for mutation in catalog["mutations"]], indent=2))
            return 0
        require(args.source is not None and args.source.is_absolute()
                and args.evidence is not None and args.evidence.is_absolute(),
                "absolute_source_and_evidence_required")
        source, evidence = args.source.resolve(), args.evidence.resolve()
        require(source.is_dir() and (source / "go.mod").is_file()
                and (source / "cmd/laneboss/main.go").is_file(), "source_tree")
        require(not evidence.is_relative_to(source)
                and not source.is_relative_to(evidence), "evidence_source_overlap")
        require(OWNER in str(evidence), "evidence_lane_name")
        require(not evidence.exists() and evidence.parent.is_dir(),
                "fresh_evidence_directory_required")
        if args.components:
            evidence.mkdir()
            save(evidence / "catalog.json", CATALOG.read_bytes())
            results = []
            for mutation in catalog["mutations"]:
                if mutation["state"] != "ready":
                    continue
                code = run_one(source, evidence / mutation["id"], mutation, args.faults)
                result = json.loads((evidence / mutation["id"] / "result.json").read_bytes())
                results.append({"mutation_id": mutation["id"], "exit_code": code,
                                "status": result["status"],
                                "result": reference(evidence,
                                                    evidence / mutation["id"] / "result.json")})
                print(mutation["id"] + ": " + result["status"], flush=True)
                if code != 0:
                    break
            ready = [row for row in catalog["mutations"] if row["state"] == "ready"]
            complete = len(results) == len(ready) and all(row["exit_code"] == 0 for row in results)
            save(evidence / "summary.json", encode({
                "schema": "laneboss.guidance-mutations.v1", "scope": "component",
                "status": "components_killed" if complete else "incomplete",
                "full_guide_turn": "pending_integration", "results": results,
                "not_implemented": [row["id"] for row in catalog["mutations"]
                                    if row["state"] != "ready"],
            }))
            return 0 if complete else 1
        chosen = [row for row in catalog["mutations"] if row["id"] == args.mutation]
        require(len(chosen) == 1, "unknown_mutation")
        code = run_one(source, evidence, chosen[0], args.faults)
        result = json.loads((evidence / "result.json").read_bytes())
        print(chosen[0]["id"] + ": " + result["status"])
        return code
    except (MutationError, OSError, ValueError, KeyError, TypeError) as error:
        code = error.code if isinstance(error, MutationError) else type(error).__name__
        print("mutation runner incomplete: " + code, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
