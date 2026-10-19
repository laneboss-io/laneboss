#!/usr/bin/env python3
"""Apply one lifecycle mutation per copy on the authorized Linux test box."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


CATALOG = Path(__file__).with_name("mutations.json")
SOURCE_DIR = Path("internal") / "v2" / "lifecycle"
CASE_DIR = Path("e2e") / "v2" / "cases" / "lifecycle"
CLI_DIR = Path("internal") / "v2" / "cli"
ARCHIVE_READ = Path("internal") / "v2" / "archive" / "read.go"


def save_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def owned_path(relative, fixture_method=None):
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or path.suffix != ".go":
        return False
    if path.name.endswith("_test.go"):
        return (path.parent == SOURCE_DIR and fixture_method is not None and
                (path.name in {"fixtures_test.go", "launchfix_test.go", "credfix_test.go", "failfix_test.go"} or
                 path.name.endswith("_fixture_test.go")))
    if fixture_method is not None:
        return False
    return path.parent == SOURCE_DIR or path == ARCHIVE_READ or path in {
        CLI_DIR / "commands_lifecycle.go", CLI_DIR / "internal_lifecycle.go"}


def load_catalog():
    raw = CATALOG.read_bytes()
    catalog = json.loads(raw)
    if catalog.get("schema") != "lifecycle.mutations.v1":
        raise RuntimeError("unsupported mutation catalog")
    rows = catalog.get("mutations")
    if not rows:
        raise RuntimeError("empty mutation catalog")
    seen = set()
    for row in rows:
        name = row["id"]
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,38}", name) or name in seen:
            raise RuntimeError("invalid or repeated mutation name")
        seen.add(name)
        if row["status"] == "guard":
            if not owned_path(row["file"], row.get("fixture_method")) or not row["before"] or row["before"] == row["after"]:
                raise RuntimeError(name + ": invalid source mutation")
            packages = {"./internal/v2/lifecycle", "./" + CASE_DIR.as_posix()}
            if Path(row["file"]) == ARCHIVE_READ:
                packages = {"./internal/v2/archive"}
            if row["package"] not in packages:
                raise RuntimeError(name + ": unexpected focused package")
            if not re.fullmatch(r"Test[A-Za-z0-9]+(?:/[A-Za-z0-9_-]+)*", row["test"]):
                raise RuntimeError(name + ": invalid focused test")
            if not row["expect"] or row.get("mode", "once") not in {"once", "identifier"}:
                raise RuntimeError(name + ": missing failure evidence")
        elif row["status"] == "blocked":
            if not row["mutation"] or not row["test"] or not row["gaps"] or not row["reason"]:
                raise RuntimeError(name + ": incomplete blocked acceptance row")
        else:
            raise RuntimeError(name + ": unknown mutation status")
    return raw, catalog


def mutate_bytes(original, row):
    before = row["before"].encode()
    after = row["after"].encode()
    method = row.get("fixture_method")
    if method is not None:
        # Fixture controls may alter only one declared receiver method in a
        # fixture-only file. Named Test functions/assertions stay byte-exact.
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", method) or re.search(rb"(?m)^func Test", original):
            raise RuntimeError(row["id"] + ": invalid fixture-only method control")
        matches = list(re.finditer(rb"(?m)^func \([^\n]+\) " + re.escape(method.encode()) + rb"\(", original))
        if len(matches) != 1:
            raise RuntimeError(row["id"] + ": fixture method is not unique")
        start = matches[0].start()
        end = original.find(b"\n}\n", start)
        anchor = original.find(before)
        if end < 0 or anchor < start or anchor + len(before) > end or row.get("mode", "once") != "once":
            raise RuntimeError(row["id"] + ": fixture control escaped its receiver method")
    if row.get("mode", "once") == "identifier":
        pattern = rb"\b" + re.escape(before) + rb"\b"
        changed, count = re.subn(pattern, after, original)
        if count < 2:
            raise RuntimeError(row["id"] + ": identifier declaration/references changed")
    else:
        count = original.count(before)
        if count != 1:
            raise RuntimeError(row["id"] + ": source anchor is not unique")
        changed = original.replace(before, after, 1)
    if changed == original:
        raise RuntimeError(row["id"] + ": mutation changed no source bytes")
    return changed, count


def copy_source(source, destination):
    # The input is the credential-screened candidate source archive. Never
    # traverse symlinks or copy runtime homes or local credential files.
    shutil.copytree(source, destination, symlinks=True,
                    ignore=shutil.ignore_patterns(
                        ".git", ".agents", ".codex", ".claude", ".aws",
                        ".config", ".local", ".env", "__pycache__"))
    destination.chmod(0o700)
    # Retain the copied bytes and a manifest, including the source under test.
    entries = []
    for path in sorted(destination.rglob("*")):
        if path.is_symlink():
            continue
        if path.is_dir():
            path.chmod(0o700)
        if path.is_file():
            entries.append({"path": path.relative_to(destination).as_posix(),
                            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                            "bytes": path.stat().st_size})
    save_json(destination.parent / "source-manifest.json", entries)


def go_run(tree, directory, packages, test=None, faults=False):
    command = ["go", "test", "-json", "-count=1", "-timeout=30s"]
    if faults:
        command.extend(["-tags", "laneboss_faults"])
    if test:
        pattern = "/".join("^" + re.escape(part) + "$" for part in test.split("/"))
        command.extend(["-run", pattern])
    command.extend(packages)
    save_json(directory / "invocation.json", {"argv": command, "scope": "Linux fixture tests"})
    try:
        result = subprocess.run(command, cwd=tree, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, check=False, timeout=300)
    except subprocess.TimeoutExpired as error:
        (directory / "stdout.jsonl").write_bytes(error.stdout or b"")
        (directory / "stderr.log").write_bytes(error.stderr or b"")
        save_json(directory / "exit.json", {"status": "deadline_exceeded"})
        raise
    (directory / "stdout.jsonl").write_bytes(result.stdout)
    (directory / "stderr.log").write_bytes(result.stderr)
    save_json(directory / "exit.json", {"exit_code": result.returncode})
    events = []
    for line in result.stdout.splitlines():
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeError("go test returned non-JSON output; no red result claimed")
        if not isinstance(value, dict):
            raise RuntimeError("go test returned a non-object event")
        events.append(value)
    return result.returncode, events


def named_failure(row, events):
    exact = row["test"]
    failures = sorted({event["Test"] for event in events
                       if event.get("Action") == "fail" and event.get("Test")})
    output = "".join(event.get("Output", "") for event in events
                     if event.get("Test") == exact)
    # A panic or compile failure is not evidence that the specified assertion
    # detected its missing guard. Require this exact test's assertion text.
    detected = (exact in failures and row["expect"] in output
                and "panic:" not in output and "fatal error:" not in output)
    return detected, failures


def mutation_verdict(row, code, events):
    detected, failed = named_failure(row, events)
    exact = row["test"]
    selected = [event for event in events if event.get("Test") == exact]
    output = "".join(event.get("Output", "") for event in events)
    if any(event.get("Action") == "build-fail" or event.get("FailedBuild") for event in events):
        return "invalid_evidence", "mutation failed to build", failed
    if not any(event.get("Action") == "run" for event in selected):
        return "invalid_evidence", "named test did not run", failed
    if "panic:" in output or "fatal error:" in output:
        return "invalid_evidence", "mutation panicked or aborted", failed
    if not any(event.get("Action") in {"pass", "fail"} for event in selected):
        return "invalid_evidence", "named test did not finish", failed
    if code != 0 and detected:
        return "detected", "named assertion detected the mutation", failed
    reason = "named test passed with the mutation" if code == 0 else "named test failed without its expected assertion"
    return "survived", reason, failed


def green_result(code, events, packages):
    passed = {event.get("Package") for event in events
              if event.get("Action") == "pass" and not event.get("Test")}
    failures = [event for event in events if event.get("Action") == "fail"]
    tests = [event for event in events if event.get("Action") == "pass" and event.get("Test")]
    return code == 0 and not failures and len(passed) == len(packages) and bool(tests)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--suite", choices=("all", "guards"), default="all")
    parser.add_argument("--mutation", action="append", default=[])
    parser.add_argument("--faults", action="store_true")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if sys.platform != "linux":
        raise RuntimeError("mutation execution requires the authorized disposable Linux box")
    raw, catalog = load_catalog()
    rows = catalog["mutations"]
    if args.mutation:
        requested = set(args.mutation)
        if not requested <= {row["id"] for row in rows}:
            raise RuntimeError("unknown named mutation")
        rows = [row for row in rows if row["id"] in requested]
    elif args.suite == "guards":
        rows = [row for row in rows if row["status"] == "guard"]
    if args.list:
        for row in rows:
            print(row["id"] + ": " + row["status"] + " -> " + row["test"])
        return 0
    source = args.source.resolve(strict=True)
    evidence = args.evidence.resolve()
    if not (source / "go.mod").is_file():
        raise RuntimeError("source must name the exact candidate repository root")
    if evidence == source or source in evidence.parents or evidence in source.parents:
        raise RuntimeError("mutation evidence must be separate from source")
    evidence.mkdir(parents=True, exist_ok=False, mode=0o700)
    (evidence / "mutations.json").write_bytes(raw)
    summary = {"scope": "Lifecycle guard fixtures; full production acceptance is separate.",
               "catalog_sha256": hashlib.sha256(raw).hexdigest(),
               "faults": args.faults, "mutations": [], "survivors": [], "green": "not_run"}
    summary_path = evidence / "summary.json"
    try:
        guards = [row for row in rows if row["status"] == "guard"]
        for row in guards:
            directory = evidence / row["id"]
            directory.mkdir(mode=0o700)
            tree = directory / "source"
            copy_source(source, tree)
            path = tree / row["file"]
            if path.is_symlink():
                raise RuntimeError(row["id"] + ": mutation target is a symlink")
            original = path.read_bytes()
            changed, count = mutate_bytes(original, row)
            (directory / "before.go").write_bytes(original)
            (directory / "after.go").write_bytes(changed)
            path.write_bytes(changed)
            save_json(directory / "mutation.json", {
                "id": row["id"], "rule": row["rule"], "file": row["file"],
                "fixture_method": row.get("fixture_method"),
                "replacements": count, "before_sha256": hashlib.sha256(original).hexdigest(),
                "after_sha256": hashlib.sha256(changed).hexdigest()})
            code, events = go_run(tree, directory, [row["package"]], row["test"], args.faults)
            status, reason, failed = mutation_verdict(row, code, events)
            summary["mutations"].append({
                "id": row["id"], "rule": row["rule"], "expected_test": row["test"],
                "failed_tests": failed, "exit_code": code,
                "status": status, "reason": reason})
            if status == "survived":
                summary["survivors"].append({"id": row["id"], "reason": reason})
            save_json(summary_path, summary)
            if status == "invalid_evidence":
                raise RuntimeError(row["id"] + ": " + reason)
            if status == "survived":
                print(row["id"] + ": SURVIVED -> " + reason, flush=True)
            else:
                print(row["id"] + ": RED -> " + ", ".join(failed), flush=True)
        if guards:
            green_dir = evidence / "green"
            green_dir.mkdir(mode=0o700)
            baseline = green_dir / "source"
            copy_source(source, baseline)
            packages = sorted({row["package"] for row in guards})
            code, events = go_run(baseline, green_dir, packages, faults=args.faults)
            summary["green"] = "passed" if green_result(code, events, packages) else "failed"
            save_json(summary_path, summary)
            if summary["green"] != "passed":
                raise RuntimeError("unmodified focused tests failed; no mutation gate passed")
        blocked = [row for row in rows if row["status"] == "blocked"]
        for row in blocked:
            summary["mutations"].append({
                "id": row["id"], "rule": row["rule"], "expected_test": row["test"],
                "status": "blocked", "gaps": row["gaps"], "reason": row["reason"]})
            print(row["id"] + ": BLOCKED -> " + row["test"])
        summary["status"] = "survivors" if summary["survivors"] else "incomplete" if blocked else "guard_fixtures_passed"
        save_json(summary_path, summary)
        if summary["survivors"]:
            print("FAIL: lifecycle guard fixtures; " + str(len(summary["survivors"])) + " survivors", flush=True)
            for survivor in summary["survivors"]:
                print(survivor["id"] + ": SURVIVED -> " + survivor["reason"], flush=True)
            return 1
        if blocked:
            return 69
        if not guards:
            raise RuntimeError("no executable guard mutation selected")
        print("PASS: lifecycle guard fixtures; full acceptance remains pending")
        return 0
    except Exception as error:
        summary["status"] = "failed"
        summary["error_type"] = type(error).__name__
        save_json(summary_path, summary)
        raise


if __name__ == "__main__":
    sys.exit(main())
