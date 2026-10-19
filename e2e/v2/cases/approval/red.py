"""Linux-only, one-mutation-per-copy approval sensitivity runner."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

from catalog import BLOCKED_COMPONENTS, CLI_CASE, PENDING, READY, RULES, matrix


class RedFailure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise RedFailure(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def private_directory(path, parents=False):
    path.mkdir(parents=parents, mode=0o700)
    path.chmod(0o700)
    facts = path.lstat()
    require(stat.S_ISDIR(facts.st_mode) and stat.S_IMODE(facts.st_mode) == 0o700 and
            facts.st_uid == os.geteuid(), "test directory is not private, ordinary and owned")


def dump(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def owned(path):
    relative = Path(path)
    return (not relative.is_absolute() and ".." not in relative.parts and
            (relative.parts[:3] == ("internal", "v2", "approval") or
             relative.as_posix() == "internal/v2/cli/commands_approval.go"))


def validate_catalog():
    names = [item["name"] for item in READY + PENDING]
    require(len(names) == len(set(names)), "mutation names are not unique")
    require(set(BLOCKED_COMPONENTS) <= {item["name"] for item in READY},
            "blocked component does not name a retained recipe")
    rule_names = {item["id"] for item in RULES}
    for item in READY:
        require(owned(item["file"]), item["name"] + ": mutation exceeds ownership")
        require(item["test"].startswith("Test") and item["assertion"],
                item["name"] + ": focused test or assertion missing")
        require(set(item["rules"]) <= rule_names,
                item["name"] + ": unknown acceptance rule")
        if item["kind"] == "replace":
            require(item["before"] and item["before"] != item["after"],
                    item["name"] + ": mutation does not change a check")
        else:
            require(item["kind"] == "cli_stub" and item["package"] == CLI_CASE,
                    item["name"] + ": unknown mutation kind")
    for item in PENDING:
        require(item["check"] and item["test"] and item["owner"] and item["needs"],
                item["name"] + ": incomplete pending mutation")
        require(set(item["rules"]) <= rule_names,
                item["name"] + ": unknown pending rule")


def change_once(before, item):
    if item["kind"] == "replace":
        needle = item["before"].encode()
        require(before.count(needle) == 1,
                item["name"] + ": mutation site is absent or ambiguous")
        return before.replace(needle, item["after"].encode(), 1)
    text = before.decode("utf-8")
    signature = "func runOrgChange" + item["handler"] + "("
    require(text.count(signature) == 1, item["name"] + ": CLI site is ambiguous")
    start = text.index(signature)
    body = text.index("{", start)
    end = text.index("\n}\n", body) + len("\n}\n")
    # Only this selected handler becomes a failing stub. The shared helper,
    # other handlers, API and tests remain byte-for-byte original.
    stub = text[start:body] + "{\n" + (
        '\treturn api.NotImplemented("lb-v2-approval", "red CLI stub")\n}\n'
    )
    return (text[:start] + stub + text[end:]).encode("utf-8")


def copy_inputs(source, checkout, item):
    private_directory(checkout)
    for name in ["go.mod", "go.sum"]:
        require((source / name).is_file() and not (source / name).is_symlink(),
                "module inputs must be ordinary retained files")
        shutil.copyfile(source / name, checkout / name)
    paths = ([Path("internal"), Path("e2e") / "v2" / "cases" / "approval"]
             if item["package"] == CLI_CASE else
             [Path("internal") / "v2" / "api", Path("internal") / "v2" / "approval"])
    for relative in paths:
        shutil.copytree(source / relative, checkout / relative, symlinks=True,
                        ignore=shutil.ignore_patterns("__pycache__"))
    return inventory(checkout)


def inventory(root):
    """Record source bytes and link metadata without following directory links."""
    rows = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                rows[relative] = {"kind": "symlink", "target": os.readlink(path)}
            elif path.is_dir():
                rows[relative] = {"kind": "directory", "mode": stat.S_IMODE(path.stat().st_mode)}
            elif path.is_file():
                data = path.read_bytes()
                rows[relative] = {"kind": "file", "bytes": len(data), "mode": stat.S_IMODE(path.stat().st_mode),
                                  "sha256": digest(data)}
    return rows


def parse_go(stdout):
    events = []
    for line in stdout.splitlines():
        require(line, "go test emitted an empty JSON record")
        try:
            event = json.loads(line)
        except (UnicodeError, ValueError) as error:
            raise RedFailure("go test did not emit a JSON event stream") from error
        require(isinstance(event, dict) and isinstance(event.get("Action"), str),
                "go test emitted an invalid event")
        events.append(event)
    return events


def go_test(checkout, item, prefix, tags, timeout):
    # Go splits -run at slash boundaries. Anchor every segment so a similarly
    # named sibling cannot stand in for the selected test or subtest.
    pattern = "/".join("^" + re.escape(part) + "$" for part in item["test"].split("/"))
    binary = Path(str(prefix) + "-test")
    argv = ["go", "test", "-json", "-count=1", "-run", pattern, "-o", str(binary)]
    if tags:
        argv.extend(["-tags", tags])
    argv.append(item["package"])
    dump(str(prefix) + "-command.json", {"argv": argv})
    try:
        result = subprocess.run(argv, cwd=checkout, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        Path(str(prefix) + "-stdout.jsonl").write_bytes(error.stdout or b"")
        Path(str(prefix) + "-stderr.txt").write_bytes(error.stderr or b"")
        dump(str(prefix) + "-result.json", {"status": "timeout"})
        raise RedFailure(item["name"] + ": focused test timed out") from error
    Path(str(prefix) + "-stdout.jsonl").write_bytes(result.stdout)
    Path(str(prefix) + "-stderr.txt").write_bytes(result.stderr)
    record = {"status": "finished", "exit_code": result.returncode}
    if binary.is_file():
        tested_bytes = binary.read_bytes()
        record.update(binary=binary.name, binary_sha256=digest(tested_bytes),
                      binary_bytes=len(tested_bytes))
    # Keep the real exit/output even when event parsing or a later assertion fails.
    dump(str(prefix) + "-result.json", record)
    events = parse_go(result.stdout)
    failed = sorted({e["Test"] for e in events
                     if e["Action"] == "fail" and isinstance(e.get("Test"), str)})
    passed = sorted({e["Test"] for e in events
                     if e["Action"] == "pass" and isinstance(e.get("Test"), str)})
    record.update(failed_tests=failed, passed_tests=passed)
    dump(str(prefix) + "-result.json", record)
    outputs = {}
    for event in events:
        if isinstance(event.get("Output"), str):
            name = event.get("Test", "")
            outputs[name] = outputs.get(name, "") + event["Output"]
    diagnostic = "\n".join(outputs.values()) + result.stderr.decode("utf-8", "replace")
    return record, outputs, diagnostic


def verify_red(item, record, outputs, diagnostic):
    expected = item["test"]
    ancestors = {"/".join(expected.split("/")[:i])
                 for i in range(1, len(expected.split("/")) + 1)}
    require("[build failed]" not in diagnostic and "panic:" not in diagnostic and
            "fatal error:" not in diagnostic,
            item["name"] + ": compile errors and crashes do not count as detection")
    require(record.get("binary_sha256") is not None,
            item["name"] + ": the actual tested red binary was not retained")
    require(record["exit_code"] == 1 and expected in record["failed_tests"],
            item["name"] + ": the selected test did not fail")
    require(set(record["failed_tests"]) <= ancestors,
            item["name"] + ": an unrelated test failed")
    require(item["assertion"] in outputs.get(expected, ""),
            item["name"] + ": failure was not the selected assertion")


def verify_green(item, record):
    require(record["exit_code"] == 0 and not record["failed_tests"] and
            item["test"] in record["passed_tests"],
            item["name"] + ": restored code did not pass the same selected test")
    require(record.get("binary_sha256") is not None,
            item["name"] + ": the actual tested green binary was not retained")


def execute(source, out, item, tags, timeout, report):
    cell = out / item["name"]
    private_directory(cell)
    checkout = cell / "source"
    inputs = copy_inputs(source, checkout, item)
    dump(cell / "inputs.json", inputs)
    target = checkout / item["file"]
    require(not target.is_symlink() and target.resolve().is_relative_to(checkout.resolve()),
            item["name"] + ": source target is not an owned ordinary file")
    original = target.read_bytes()
    changed = change_once(original, item)
    require(changed != original, item["name"] + ": mutation made no change")
    (cell / "original-source.txt").write_bytes(original)
    (cell / "mutated-source.txt").write_bytes(changed)
    dump(cell / "mutation.json", dict(item, original_sha256=digest(original),
                                     mutated_sha256=digest(changed)))
    target.write_bytes(changed)
    mutated = inventory(checkout)
    delta = [name for name in set(inputs) | set(mutated)
             if inputs.get(name) != mutated.get(name)]
    require(delta == [item["file"]], item["name"] + ": mutation changed more than one file")
    record = {"mutation": item["name"], "test": item["test"], "status": "red_running"}
    report["cases"].append(record)
    dump(out / "summary.json", report)
    red, outputs, diagnostic = go_test(checkout, item, cell / "red", tags, timeout)
    record["red"] = red
    dump(out / "summary.json", report)
    verify_red(item, red, outputs, diagnostic)
    print("RED " + item["name"] + ": " + ", ".join(red["failed_tests"]), flush=True)
    # Restore only after the expected semantic failure. A surviving mutant or
    # wrong failure stops here and leaves the actual tested copy as evidence.
    target.write_bytes(original)
    require(inventory(checkout) == inputs,
            item["name"] + ": restored source differs from retained input bytes")
    record["status"] = "green_running"
    dump(out / "summary.json", report)
    green, _, _ = go_test(checkout, item, cell / "green", tags, timeout)
    record["green"] = green
    dump(out / "summary.json", report)
    verify_green(item, green)
    record["status"] = "detected"
    dump(out / "summary.json", report)
    print("GREEN " + item["name"] + ": " + item["test"], flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default=".")
    parser.add_argument("--evidence")
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument("--mutation")
    choice.add_argument("--all", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--tags", choices=["laneboss_faults"])
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    require(sys.platform == "linux", "red controls require the Linux test box")
    require(1 <= args.timeout <= 900, "focused test timeout is outside its bound")
    validate_catalog()
    ready = {item["name"]: item for item in READY}
    pending = {item["name"]: item for item in PENDING}
    if args.list:
        for item in READY:
            state = "BLOCKED component" if item["name"] in BLOCKED_COMPONENTS else "component"
            print(item["name"] + ": " + state + ", " + item["test"])
        for item in PENDING:
            print(item["name"] + ": BLOCKED, " + item["test"] + ", owner " + item["owner"])
        return 0
    require(args.evidence is not None, "an evidence directory is required")
    require(args.mutation is None or args.mutation in ready or args.mutation in pending,
            "unknown named mutation")
    source = Path(args.source).resolve()
    out = Path(args.evidence).resolve()
    require(not out.exists(), "red evidence directory already exists")
    require(not out.is_relative_to(source), "red evidence must be outside checkout")
    private_directory(out, parents=True)
    for name in ["red.py", "catalog.py"]:
        (out / ("input-" + name)).write_bytes(Path(__file__).with_name(name).read_bytes())
    report = {"scope": "approval component mutations", "status": "running",
              "cases": [], "pending": list(PENDING), "acceptance": matrix(),
              "blocked_components": dict(BLOCKED_COMPONENTS)}
    dump(out / "catalog.json", {"ready": list(READY), "pending": list(PENDING),
                               "blocked_components": dict(BLOCKED_COMPONENTS)})
    dump(out / "summary.json", report)
    if args.mutation in pending:
        report.update(status="blocked", selected=pending[args.mutation])
        dump(out / "summary.json", report)
        print("BLOCKED " + args.mutation + ": " + pending[args.mutation]["needs"])
        return 69
    selected = [ready[args.mutation]] if args.mutation else list(READY)
    blocked = [item["name"] for item in selected if item["name"] in BLOCKED_COMPONENTS]
    if blocked:
        report.update(status="blocked", selected_blocked=blocked,
                      needs={name: BLOCKED_COMPONENTS[name] for name in blocked})
        dump(out / "summary.json", report)
        print("BLOCKED: component contracts; selected recipes " + ", ".join(blocked))
        return 69
    try:
        for item in selected:
            execute(source, out, item, args.tags, args.timeout, report)
    except (RedFailure, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report.update(status="failed", error=str(error))
        dump(out / "summary.json", report)
        raise
    if args.require_complete and PENDING:
        report["status"] = "blocked"
        dump(out / "summary.json", report)
        print("BLOCKED: installed-service mutations still require their named ports or owners")
        return 69
    report["status"] = "component_passed"
    dump(out / "summary.json", report)
    print("PASS: approval component mutations")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RedFailure, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print("FAIL: approval mutations: " + str(error), file=sys.stderr)
        sys.exit(1)
