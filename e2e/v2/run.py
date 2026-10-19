"""Run discovered public-interface cases in an authorized disposable scope."""

import argparse
import os
from pathlib import Path
import shutil
import sys
import tarfile
import uuid

from manifests import discover, presence_file, result_file
from scope import Scope
from support import (Failure, ROOT, Recorder, beneath, bytes_hash, clean_environment,
                     evidence, exact_keys, immutable, load, regular, require,
                     require_linux, save, sha256, verify_evidence)


def archive_matches(path, source):
    """Check retained inputs against the actual checkout used for case execution."""
    files = set()
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            name = member.name.removeprefix("./")
            require(name not in files, "duplicate source archive member")
            target = beneath(source, name)
            if member.isdir():
                require(target.is_dir(), "archive directory differs from source")
                continue
            require(member.isfile() and target.is_file(),
                    "source archive contains a linked/special input")
            stream = archive.extractfile(member)
            require(stream is not None, "unreadable archived source")
            import hashlib
            digest = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
            require(target.stat().st_size == member.size and
                    sha256(target) == digest.hexdigest(),
                    "source archive differs from executed checkout")
            files.add(name)
    required = {str(path.relative_to(source)) for path in
                (source / "e2e" / "v2").rglob("*")
                if path.is_file() and path.suffix in (".py", ".sh", ".json", ".md")}
    require(required <= files, "source archive omits executed harness inputs")
    return files


def keep_inputs(args, root):
    immutable(args.binary)
    immutable(args.binding_file)
    regular(args.source_archive)
    archive_matches(args.source_archive, ROOT)
    retained = [(args.binary, "tested-laneboss"),
                         (args.source_archive, "source.tar"),
                         (args.binding_file, "binding.json")]
    if args.observer is not None:
        immutable(args.observer)
        require(sha256(args.observer) == args.observer_sha256, "observer seal does not match")
        retained.append((args.observer, "tested-observer"))
    if args.controls is not None:
        immutable(args.controls)
        retained.append((args.controls, "controls.json"))
    for source, name in retained:
        target = root / name
        shutil.copyfile(source, target)
        target.chmod(0o600)
        require(sha256(source) == sha256(target), "retained input read-back failed")
    save(root / "inputs.json", {
        "source_revision": args.source_revision, "source_sha256": sha256(args.source_archive),
        "binary_sha256": sha256(args.binary), "binding_sha256": sha256(args.binding_file),
        "scope": "exact supplied archive, installed binary and executed harness",
        "controller_uid": os.geteuid()})


def copy_inputs(source, destination):
    if source is None:
        return
    source = Path(source).resolve(strict=True)
    denied = {".git", ".aws", ".claude", ".codex", "credentials", "auth.json",
              ".env", ".ssh", ".config"}
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        require(not set(relative.parts) & denied, "private runtime input is forbidden")
        checked = beneath(source, str(relative))
        target = destination / relative
        if checked.is_dir():
            target.mkdir(mode=0o700)
        else:
            require(checked.is_file(), "special input file")
            shutil.copyfile(checked, target)
            target.chmod(0o400)
            require(sha256(checked) == sha256(target), "case input read-back differs")


def observation_result(path, context, case):
    value = load(path)
    exact_keys(value, ("schema", "case_id", "phase", "mutation_id",
                       "binary_sha256", "source_sha256", "assertions",
                       "resources_collected", "evidence"))
    require(value["schema"] == "laneboss.e2e-observer.v2", "wrong observer schema")
    for key in ("case_id", "phase", "mutation_id", "binary_sha256", "source_sha256"):
        require(value[key] == context[key], "observer identity mismatch")
    require(value["resources_collected"] is True, "observer found uncollected resources")
    require(isinstance(value["evidence"], list) and value["evidence"],
            "observer did not retain operation evidence")
    for item in value["evidence"]:
        verify_evidence(context["evidence_root"], item)
    assertions = value["assertions"]
    require(isinstance(assertions, list) and len(assertions) == len(case["assertion_ids"]),
            "observer assertion inventory differs")
    seen = set()
    for item in assertions:
        exact_keys(item, ("id", "reached", "verdict"))
        require(item["id"] in case["assertion_ids"] and item["id"] not in seen and
                item["reached"] is True and item["verdict"] in ("pass", "fail"),
                "observer did not reach each assertion")
        seen.add(item["id"])
    return {item["id"]: item["verdict"] for item in assertions}


def execute(args, item, root):
    case, entry, manifest = item
    require("linux" in case["platforms"], "selected case needs another platform",
            "unsupported")
    require(not case["live_auth"] or
            (args.permit_live and bool(args.profile_grant_id)),
            "live case requires explicit authorization and named profile grants",
            "prerequisite_missing")
    scope_name = case["id"] + "-" + uuid.uuid4().hex[:10]
    directory = root / scope_name
    directory.mkdir(mode=0o700)
    inputs = directory / "inputs"
    output = directory / "evidence"
    inputs.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    copy_inputs(args.input_directory, inputs)
    context = {"schema": "laneboss.e2e-context.v2",
               "case_id": case["id"], "phase": args.phase,
               "mutation_id": args.mutation_id, "binary": str(args.binary),
               "binary_sha256": sha256(args.binary), "source_sha256": sha256(args.source_archive),
               "config": args.config, "binding_file": str(args.binding_file),
               "test_root": str(inputs), "evidence_root": str(output),
               "profile_grant_ids": args.profile_grant_id}
    if args.controls is not None:
        context["controls"] = str(immutable(args.controls))
    context_path = directory / "context.json"
    save(context_path, context, mode=0o400)
    shutil.copyfile(manifest, directory / "case.json")
    require(sha256(manifest) == sha256(directory / "case.json"), "case manifest read-back differs")
    result_path = directory / "result.json"
    scope = Scope(args.cgroup_root, scope_name)
    interpreter = sys.executable if entry.suffix == ".py" else "/bin/sh"
    argv = [interpreter, str(entry), "--context", str(context_path),
            "--result", str(result_path)]
    temporary = directory / "tmp"
    home = directory / "home"
    for path in (temporary, home):
        path.mkdir(mode=0o700)
    environment = clean_environment(home, temporary, args.config)
    result = None
    try:
        with (output / "entry.stdout").open("xb") as stdout:
            with (output / "entry.stderr").open("xb") as stderr:
                result = scope.run(argv, cwd=inputs, environment=environment,
                                   stdout=stdout, stderr=stderr,
                                   timeout=case["timeout_seconds"])
        save(output / "entry-command.json", {"argv": argv, **result})
    finally:
        scope.collect(output / "independent-collection.json")
    require(result is not None and not result["timed_out"], "case entry timed out")
    require(sha256(args.binary) == context["binary_sha256"] and
            load(context_path) == context, "artifact or context changed during entry")
    value = result_file(result_path, case, context, result["exit_code"],
                        red_assertion=args.red_assertion, red_check=args.red_check)
    require(args.observer is not None,
            "independent per-case canary/state observer is required",
            "prerequisite_missing")
    observer = immutable(args.observer)
    require(sha256(observer) == args.observer_sha256, "observer seal does not match")
    observed_path = output / "independent-observer.json"
    observer_scope = Scope(args.cgroup_root, scope_name + "-observer")
    try:
        with (output / "observer.stdout").open("xb") as stdout:
            with (output / "observer.stderr").open("xb") as stderr:
                observed = observer_scope.run(
                    [str(observer), "--context", str(context_path), "--result",
                     str(result_path), "--observed-exit", str(result["exit_code"]),
                     "--output", str(observed_path)], cwd=inputs,
                    environment=environment, stdout=stdout, stderr=stderr, timeout=60)
    finally:
        observer_scope.collect(output / "observer-collection.json")
    require(observed["exit_code"] == 0 and not observed["timed_out"],
            "independent observer failed")
    verdicts = observation_result(observed_path, context, case)
    require(all(verdicts[item["id"]] == item["verdict"]
                for item in value["assertions"]), "independent operation verdict differs")
    reported = any(item["path"] == "presence-summary.json" for assertion in value["assertions"]
                   for item in assertion["evidence"])
    return {"case_id": case["id"], "phase": args.phase,
            "presence": presence_file(output / "presence-summary.json") if reported else
                {"simulated_presence": False, "presence": "not_measured", "human_approval": "not_measured"},
            "mutation_id": args.mutation_id, "entry_exit": result["exit_code"],
            "verdict": "mutation-killed" if args.phase == "red" else "pass",
            "result": evidence(root, result_path)}


def manifest(root):
    items = [evidence(root, path) for path in sorted(root.rglob("*"))
             if path.is_file() and path != root / "manifest.json"]
    save(root / "manifest.json", {"schema": "laneboss.e2e-evidence.v2", "files": items})
    for item in load(root / "manifest.json")["files"]:
        verify_evidence(root, item)
    return sha256(root / "manifest.json")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "source-archive", "binding-file", "cgroup-root",
                 "evidence-root"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--phase", choices=("red", "candidate"), default="candidate")
    parser.add_argument("--mutation-id", default="")
    parser.add_argument("--red-assertion")
    parser.add_argument("--red-check")
    parser.add_argument("--candidate-sha256")
    parser.add_argument("--input-directory", type=Path)
    parser.add_argument("--profile-grant-id", action="append", default=[])
    parser.add_argument("--permit-live", action="store_true")
    parser.add_argument("--observer", type=Path)
    parser.add_argument("--observer-sha256")
    parser.add_argument("--controls", type=Path)
    args = parser.parse_args()
    summary = {"schema": "laneboss.e2e-summary.v2", "cases": [], "exit_code": 2}
    root = None
    try:
        require_linux()
        require(bool(args.mutation_id) == (args.phase == "red"),
                "red phase needs a mutation ID")
        if args.phase == "red":
            require(args.red_assertion is not None and args.candidate_sha256 and
                    sha256(args.binary) != args.candidate_sha256,
                    "red phase needs a distinct mutated artifact and target")
            require(args.red_assertion != "E2E-LADDER" or args.red_check is not None,
                    "ladder red phase needs --red-check")
        destination = args.evidence_root
        require(destination.is_absolute() and destination.resolve() == destination and
                not destination.is_relative_to(ROOT), "keep evidence outside the checkout")
        destination.mkdir(mode=0o700, parents=True, exist_ok=False)
        root = destination
        keep_inputs(args, root)
        cases = discover(ROOT / "e2e" / "v2" / "cases")
        selected = args.case or list(cases)
        require(len(set(selected)) == len(selected) and all(name in cases for name in selected),
                "unknown or duplicate selected case")
        # A service smoke runs first for candidate live work, never as a substitute.
        if args.phase == "candidate" and any(cases[name][0]["live_auth"] for name in selected):
            selected = ["e2e-smoke"] + [name for name in selected if name != "e2e-smoke"]
        for name in selected:
            summary["cases"].append(execute(args, cases[name], root))
        simulated = any(case["presence"]["simulated_presence"] for case in summary["cases"])
        summary["presence"] = {"simulated_presence": simulated,
            "presence": "simulated" if simulated else "not_measured",
            "human_approval": "not_proven" if simulated else "not_measured"}
        summary["exit_code"] = 0
    except (Failure, OSError, ValueError, KeyError, TypeError) as error:
        summary["error"] = (error if isinstance(error, Failure) else
                            Failure("harness infrastructure failed")).wire()
        print("E2E failed: " + summary["error"]["code"], file=sys.stderr)
    finally:
        if root is not None and root.is_dir():
            save(root / "summary.json", summary)
            try:
                digest = manifest(root)
                print("E2E evidence manifest sha256: " + digest)
            except (Failure, OSError, ValueError) as error:
                summary["exit_code"] = 2
                summary["collection_error"] = Failure("evidence read-back failed").wire()
                save(root / "summary.json", summary)
                try:
                    manifest(root)
                except (Failure, OSError, ValueError):
                    stale = root / "manifest.json"
                    if stale.exists():
                        stale.unlink()
    print("E2E summary: cases={} exit={}".format(len(summary["cases"]), summary["exit_code"]))
    return summary["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
