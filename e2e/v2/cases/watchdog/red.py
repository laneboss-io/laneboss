"""Run watchdog guarding mutations in retained isolated Linux source copies."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


from mutations import BLOCKED, CATALOG


CASE = Path("e2e") / "v2" / "cases" / "watchdog"
REVISION = "v2.0-draft.4"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def inventory(root):
    paths = [root / "go.mod", root / "go.sum"]
    for package in ("api", "watchdog"):
        paths.extend(sorted((root / "internal" / "v2" / package).rglob("*")))
    paths.extend(sorted((root / CASE).rglob("*")))
    result = {}
    for path in paths:
        if "__pycache__" in path.relative_to(root).parts:
            continue
        if path.is_symlink():
            raise SystemExit("test source contains a link; retain inputs and stop")
        if path.is_file():
            data = path.read_bytes()
            result[path.relative_to(root).as_posix()] = {"sha256": digest(data), "bytes": len(data)}
    return result


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


def inventory_digest(files):
    return digest(json.dumps(files, sort_keys=True, separators=(",", ":")).encode())


def run_tests(root, destination, test, faults, engine):
    destination.mkdir(parents=True, exist_ok=False)
    if engine == "go":
        binary = destination / "watchdog.test"
        build = ["go", "test", "-c", "-o", str(binary)]
        if faults:
            build.extend(["-tags", "laneboss_faults"])
        build.append("./internal/v2/watchdog")
        try:
            compiled = subprocess.run(build, cwd=root, capture_output=True, timeout=180)
        except subprocess.TimeoutExpired as error:
            (destination / "build.stdout").write_bytes(error.stdout or b"")
            (destination / "build.stderr").write_bytes(error.stderr or b"")
            write_json(destination / "build.json", {"argv": build, "deadline_seconds": 180})
            raise SystemExit("unit build timed out; no mutation kill can be credited") from error
        (destination / "build.stdout").write_bytes(compiled.stdout)
        (destination / "build.stderr").write_bytes(compiled.stderr)
        write_json(destination / "build.json", {"argv": build, "exit": compiled.returncode})
        if compiled.returncode:
            (destination / "stdout.jsonl").write_bytes(b"")
            (destination / "stderr.txt").write_bytes(compiled.stderr)
            return compiled.returncode, []
        binary_bytes = binary.read_bytes()
        write_json(destination / "binary.json", {"path": binary.name, "sha256": digest(binary_bytes), "bytes": len(binary_bytes)})
        command = ["go", "tool", "test2json", "-t", "-p", "laneboss.io/laneboss/internal/v2/watchdog",
                   str(binary), "-test.v=true", "-test.count=1"]
        if test:
            command.append("-test.run=" + "/".join("^" + part + "$" for part in test.split("/")))
    else:
        command = [sys.executable, "-B", str(root / CASE / "checks_test.py")]
        if test:
            command.append(test)
    try:
        process = subprocess.run(command, cwd=root, capture_output=True, timeout=180)
    except subprocess.TimeoutExpired as error:
        (destination / "stdout.jsonl").write_bytes(error.stdout or b"")
        (destination / "stderr.txt").write_bytes(error.stderr or b"")
        (destination / "command.json").write_text(json.dumps({"argv": command, "deadline_seconds": 180}) + "\n")
        raise SystemExit("unit command timed out; no mutation kill can be credited") from error
    (destination / "stdout.jsonl").write_bytes(process.stdout)
    (destination / "stderr.txt").write_bytes(process.stderr)
    (destination / "command.json").write_text(json.dumps({"argv": command, "exit": process.returncode}) + "\n")
    if engine == "go" and binary.read_bytes() != binary_bytes:
        raise SystemExit("tested executable changed after its retained hash was recorded")
    events = []
    for line in process.stdout.splitlines():
        events.append(json.loads(line))
    return process.returncode, events


def candidate_checks(source, destination, faults):
    for engine in ("go", "observer"):
        code, events = run_tests(source, destination / engine, "", faults, engine)
        if code or not any(e.get("Action") == "pass" and not e.get("Test") for e in events):
            raise SystemExit("candidate checks failed; retain output and stop")


def mutation_outcome(code, events, test):
    reached = any(e.get("Action") == "run" and e.get("Test") == test for e in events)
    failed = any(e.get("Action") == "fail" and e.get("Test") == test for e in events)
    passed = any(e.get("Action") == "pass" and e.get("Test") == test for e in events)
    crashed = any(e.get("Action") == "error" or (e.get("Action") == "output" and
                  e.get("Output", "").lstrip().startswith(("panic:", "fatal error:"))) for e in events)
    killed = code == 1 and reached and failed and not crashed and not passed
    if killed:
        classification = "killed"
    elif not reached:
        classification = "not_reached"
    elif crashed:
        classification = "crashed"
    elif code == 0 and passed and not failed:
        classification = "survived"
    else:
        classification = "invalid_result"
    return {"reached": reached, "test_failed": failed, "test_passed": passed,
            "crashed": crashed, "killed": killed, "classification": classification,
            "failed_tests": sorted({e["Test"] for e in events if e.get("Action") == "fail" and e.get("Test")})}


def failure_output(destination, outcome):
    reason = outcome["classification"]
    build = destination / "build.json"
    if not outcome["reached"] and build.is_file():
        receipt = json.loads(build.read_text())
        if receipt.get("exit"):
            reason = "build_failed"
    tails = {}
    for name in ("build.stdout", "build.stderr", "stderr.txt", "stdout.jsonl"):
        path = destination / name
        if path.is_file():
            lines = path.read_text(errors="replace").splitlines()
            if lines:
                # The complete original files remain retained. Bound only
                # this console preview, including a single oversized record.
                tails[name] = [line[-2048:] for line in lines[-12:]]
    return {"reason": reason, "last_output_lines": tails}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--faults", action="store_true")
    parser.add_argument("--mutation", default="all")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if sys.platform != "linux":
        raise SystemExit("watchdog tests require the authorized disposable Linux test box")
    if args.list:
        print(json.dumps({"contract_revision": REVISION, "executable": CATALOG, "blocked": BLOCKED}, sort_keys=True))
        return 0
    if args.mutation != "all" and args.mutation not in CATALOG and args.mutation not in BLOCKED:
        raise SystemExit("unknown named mutation")
    source = args.source_root.resolve()
    evidence = args.evidence_root.resolve()
    if evidence.is_relative_to(source) or source.is_relative_to(evidence):
        raise SystemExit("red evidence must be outside the source checkout")
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    if args.mutation in BLOCKED:
        write_json(evidence / "receipt.json", {
            "mutation_id": args.mutation, "reached": False, "killed": False,
            "error": {"code": "not_implemented", "owner": "lb-v2-watchdog",
                      "message": BLOCKED[args.mutation], "retryable": False,
                      "instead": "Resolve the recorded contract/runtime dependency; do not credit a mutation kill."},
        })
        return 69
    baseline_files = inventory(source)
    write_json(evidence / "source-files.json", baseline_files)
    contract = (source / "internal" / "v2" / "api" / "base.go").read_text()
    match = re.search(r'ContractRevision\s*=\s*"([^"]+)"', contract)
    actual = match.group(1) if match else ""
    write_json(evidence / "contract.json", {"expected": REVISION, "actual": actual})
    if actual != REVISION:
        raise SystemExit("source contract differs; no candidate or mutation result can be credited")
    candidate_checks(source, evidence / "candidate", args.faults)
    package_source = source / "internal" / "v2" / "watchdog"
    outcomes = []
    selected = CATALOG if args.mutation == "all" else {args.mutation: CATALOG[args.mutation]}
    for name, spec in selected.items():
        source_name, test, engine = spec["file"], spec["test"], spec["engine"]
        target = (Path("internal") / "v2" / "watchdog" / source_name) if engine == "go" else CASE / source_name
        data = (source / target).read_text()
        changed = data
        for before, after in spec["edits"]:
            if not before or changed.count(before) != 1:
                write_json(evidence / "anchor-failure.json", {"mutation_id": name, "file": str(target)})
                raise SystemExit("mutation anchor changed; no red result can be credited")
            changed = changed.replace(before, after)
        mutation = evidence / name
        tree = mutation / "source"
        package = tree / "internal" / "v2" / "watchdog"
        package.parent.mkdir(parents=True)
        shutil.copytree(source / "internal" / "v2" / "api", package.parent / "api")
        shutil.copytree(package_source, package)
        shutil.copytree(source / CASE, tree / CASE, ignore=shutil.ignore_patterns("__pycache__"))
        for module_name in ("go.mod", "go.sum"):
            shutil.copyfile(source / module_name, tree / module_name)
        if inventory(tree) != baseline_files:
            raise SystemExit("isolated test inputs differ from the retained candidate")
        (tree / target).write_text(changed)
        mutated_files = inventory(tree)
        changed_paths = sorted(path for path in baseline_files.keys() | mutated_files.keys()
                               if baseline_files.get(path) != mutated_files.get(path))
        if changed_paths != [target.as_posix()]:
            raise SystemExit("mutation did not change exactly its intended source; no kill can be credited")
        write_json(mutation / "source-files.json", mutated_files)
        code, red_events = run_tests(tree, mutation / "focused", test, args.faults, engine)
        outcome = mutation_outcome(code, red_events, test)
        receipt = {"mutation_id": name, "file": source_name, "test": test, **outcome,
                   "contract_revision": REVISION,
                   "observed_exit": code,
                   "scope": spec["scope"], "engine": engine,
                   "build_tags": ["laneboss_faults"] if args.faults and engine == "go" else [],
                   "changed_paths": changed_paths,
                   "source_sha256": inventory_digest(baseline_files),
                   "mutation_sha256": inventory_digest(mutated_files),
                   "stdout_sha256": digest((mutation / "focused" / "stdout.jsonl").read_bytes())}
        if not outcome["killed"]:
            receipt.update(failure_output(mutation / "focused", outcome))
        if engine == "go" and (mutation / "focused" / "binary.json").is_file():
            receipt["test_binary"] = json.loads((mutation / "focused" / "binary.json").read_text())
            receipt["test_binary"]["path"] = (Path(name) / "focused" / receipt["test_binary"]["path"]).as_posix()
        (mutation / "receipt.json").write_text(json.dumps(receipt, sort_keys=True) + "\n")
        outcomes.append(receipt)
        report = {"mutation_id": name, "scope": spec["scope"], **outcome, "observed_exit": code}
        if not outcome["killed"]:
            report.update({key: receipt[key] for key in ("reason", "last_output_lines")})
        print(json.dumps(report), flush=True)
        if not outcome["killed"]:
            if outcome["classification"] == "survived":
                raise SystemExit("guarding mutation survived: the named test ran and passed; inspect retained evidence")
            if outcome["classification"] == "not_reached":
                raise SystemExit("guarding mutation did not reach its named test: " + receipt["reason"] + "; inspect retained evidence")
            raise SystemExit("guarding mutation has " + outcome["classification"] + "; no kill credited; inspect retained evidence")
    # Rerun the unchanged candidate after the demonstrated red failures.
    candidate_checks(source, evidence / "candidate-after-red", args.faults)
    if inventory(source) != baseline_files:
        raise SystemExit("candidate inputs changed during the mutation phase")
    write_json(evidence / "summary.json", {"contract_revision": REVISION, "mutations": outcomes, "blocked": BLOCKED,
                                          "scope": "component-and-observer-only", "product_acceptance_complete": False})
    print("PASS: selected guard mutations killed; component/observer candidate checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
