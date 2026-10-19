#!/usr/bin/env python3
"""Run one named mutation, or the matrix, on retained disposable Linux copies.

A killed mutation requires the named test, an assertion failure diagnostic,
and then a passing run of the unchanged candidate. Build/setup failures and
surviving mutations are failures of this runner, never killed mutations.
"""

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile

from mutations import MUTATIONS


class MutationFailure(Exception):
    """An expected mutation proof could not be established."""


def require(condition, message):
    if not condition:
        raise MutationFailure(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def inventory(root):
    require((root / "go.mod").is_file(), "source is not the supplied Go module")
    blocked = {".aws", ".ssh", ".claude", ".codex"}
    require(not any((root / name).exists() for name in blocked),
            "source artifact contains a private/control directory")
    if (root / ".git").exists():
        listing = subprocess.run(["git", "-C", str(root), "ls-files", "-z"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        require(listing.returncode == 0, "cannot read the supplied tracked-source inventory")
        names = {item.decode("utf-8") for item in listing.stdout.split(b"\0") if item}
        # Include the lane's current public source overlay before the
        # supervisor commits it. No arbitrary untracked HOME is copied.
        for directory in (root / "internal" / "v2" / "messaging",
                          root / "e2e" / "v2" / "cases" / "messaging"):
            for path in directory.rglob("*"):
                if "__pycache__" not in path.parts and path.is_file():
                    names.add(path.relative_to(root).as_posix())
    else:
        # A supervisor-supplied, privacy-checked source archive has no index.
        # It is not a host home or vendor profile and must retain all inputs.
        names = {path.relative_to(root).as_posix() for path in root.rglob("*")
                 if path.is_file() and ".git" not in path.parts and "__pycache__" not in path.parts}
    result = []
    for name in sorted(names):
        relative = Path(name)
        require(not relative.is_absolute() and ".." not in relative.parts,
                "source inventory escaped its artifact root")
        path = root / relative
        require(path.resolve().is_relative_to(root) and not path.is_symlink() and
                stat.S_ISREG(path.stat().st_mode), "source inventory is not contained regular-file data")
        data = path.read_bytes()
        if path.suffix == ".go":
            require(not re.search(rb"(?m)^(?:<<<<<<< |=======\r?$|>>>>>>> )", data),
                    "source still contains unresolved merge markers")
        result.append({"path": name, "sha256": sha(data), "bytes": len(data),
                       "mode": stat.S_IMODE(path.stat().st_mode)})
    require(bool(result), "source inventory is empty")
    return result


def materialize(source, destination, entries):
    destination.mkdir(mode=0o700)
    for entry in entries:
        original = source / entry["path"]
        data = original.read_bytes()
        require(sha(data) == entry["sha256"] and len(data) == entry["bytes"],
                "source changed during snapshot")
        target = destination / entry["path"]
        parent = destination
        for name in Path(entry["path"]).parts[:-1]:
            parent = parent / name
            parent.mkdir(mode=0o700, exist_ok=True)
        target.write_bytes(data)
        target.chmod(entry["mode"])


def verify_copy(root, entries, changed=None, changed_sha=None):
    for entry in entries:
        expected = changed_sha if entry["path"] == changed else entry["sha256"]
        require(sha((root / entry["path"]).read_bytes()) == expected,
                "test changed source outside its declared mutation")


def execute(command, cwd, directory, label, timeout):
    stdout_path, stderr_path = directory / (label + ".stdout"), directory / (label + ".stderr")
    record = {"command": command, "cwd": str(cwd), "stdout": stdout_path.name,
              "stderr": stderr_path.name, "timed_out": False}
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        process = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr, start_new_session=True)
        record["pid"] = process.pid
        try:
            record["exit"] = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            record["timed_out"] = True
            # This is the exact process group created above, never a pattern
            # over command lines or a signal to another test's process.
            try:
                os.killpg(process.pid, signal.SIGKILL)
                record["timeout_signal"] = "SIGKILL"
            except ProcessLookupError:
                record["timeout_signal"] = "group_already_exited"
            record["exit"] = process.wait(timeout=15)
    for name, path in (("stdout", stdout_path), ("stderr", stderr_path)):
        data = path.read_bytes()
        record[name + "_sha256"], record[name + "_bytes"] = sha(data), len(data)
    write_json(directory / (label + ".command.json"), record)
    require(not record["timed_out"], "test/build timed out; no mutation was proved")
    return record


def go_phase(root, directory, recipe, tags, timeout):
    require(re.fullmatch(r"Test[A-Za-z0-9_]+", recipe["test"]), "Go focused test name is invalid")
    binary = directory / "messaging.test"
    command = ["go", "test", "-c", "-o", str(binary)]
    if tags:
        command.extend(["-tags", tags])
    command.append("./internal/v2/messaging")
    build = execute(command, root, directory, "build", timeout)
    require(build["exit"] == 0, "focused test binary did not build; no mutation was proved")
    data = binary.read_bytes()
    artifact = {"path": binary.name, "sha256": sha(data), "bytes": len(data)}
    write_json(directory / "artifact.json", artifact)
    command = ["go", "tool", "test2json", "-t", "-p",
               "laneboss.io/laneboss/internal/v2/messaging", str(binary),
               "-test.v=test2json", "-test.count=1", "-test.run=^" + re.escape(recipe["test"]) + "$"]
    run = execute(command, root, directory, "tests", timeout)
    events = []
    for line in (directory / "tests.stdout").read_bytes().splitlines():
        event = json.loads(line)
        require(isinstance(event, dict) and "Action" in event, "test2json output is malformed")
        events.append(event)
    started = {item["Test"] for item in events if item["Action"] == "run" and item.get("Test")}
    failed = {item["Test"] for item in events if item["Action"] == "fail" and item.get("Test")}
    passed = {item["Test"] for item in events if item["Action"] == "pass" and item.get("Test")}
    skipped = {item["Test"] for item in events if item["Action"] == "skip" and item.get("Test")}
    expected = recipe["test"]
    require(expected in started, "the focused test was never reached")
    require(not skipped, "a skipped test cannot prove a mutation")
    require(all(name == expected or name.startswith(expected + "/") for name in started | failed),
            "an unrelated test ran or failed")
    diagnostics = {name: "".join(item.get("Output", "") for item in events if item.get("Test") == name)
                   for name in failed}
    diagnostic = "".join(diagnostics.values())
    require(not any(marker in diagnostic for marker in ("panic:", "fatal error:", "[build failed]")),
            "a panic/build failure cannot replace the targeted assertion")
    result = {"exit": run["exit"], "started": sorted(started), "failed": sorted(failed),
              "passed": sorted(passed), "diagnostic": diagnostic, "test_diagnostics": diagnostics,
              "artifact": artifact}
    write_json(directory / "focused.json", result)
    return result


def python_phase(root, directory, recipe, timeout):
    require(re.fullmatch(r"Observations\.test_[a-z0-9_]+", recipe["test"]),
            "Python focused test name is invalid")
    case = root / "e2e" / "v2" / "cases" / "messaging"
    result_path = directory / "observer-tests.json"
    command = [sys.executable, "-B", str(case / "observer_tests.py"), "--test", recipe["test"], "--json", str(result_path)]
    run = execute(command, root, directory, "tests", timeout)
    require(result_path.is_file(), "observer test produced no structured result")
    observed = json.loads(result_path.read_bytes())
    require(observed["schema"] == "laneboss.msg-observer-tests.v1" and
            observed["started"] == [recipe["test"]] and observed["tests_run"] == 1,
            "observer test selection did not reach exactly its named test")
    require(not observed["errors"] and not observed["skipped"] and
            not observed["expected_failures"] and not observed["unexpected_successes"],
            "observer setup/error/skip cannot prove a mutation")
    result = {"exit": run["exit"], "started": observed["started"], "failed": observed["failed"],
              "passed": observed["started"] if run["exit"] == 0 and not observed["failed"] else [],
              "diagnostic": "\n".join(observed["diagnostics"]),
              "test_diagnostics": {recipe["test"]: "\n".join(observed["diagnostics"])}}
    write_json(directory / "focused.json", result)
    return result


def one(source, work_root, entries, name, tags, timeout):
    recipe = MUTATIONS[name]
    directory = Path(tempfile.mkdtemp(prefix="lb-v2-messaging-" + name + "-", dir=work_root)).resolve()
    report = {"schema": "laneboss.msg-mutation.v1", "mutation": name,
              "scope": recipe["scope"], "assertions": recipe["assertions"],
              "description": recipe["description"], "status": "failed",
              "tests": recipe["test"], "directory": str(directory)}
    try:
        report["stage"] = "source"
        require(recipe["scope"] in ("component", "observer"), "mutation scope is unsupported")
        relative = Path(*recipe["path"])
        require(relative.as_posix() in {entry["path"] for entry in entries}, "mutation target is missing from source")
        write_json(directory / "inputs.json", {"source": str(source), "files": entries, "recipe": recipe, "tags": tags})
        original = (source / relative).read_bytes()
        (directory / "before.source").write_bytes(original)
        changed = original.decode("utf-8")
        anchors = []
        report["stage"] = "anchors"
        for index, edit in enumerate(recipe["edits"]):
            anchors.append({"edit": index, "matches": changed.count(edit["before"]),
                            "before_sha256": sha(edit["before"].encode())})
            write_json(directory / "anchors.json", anchors)
            require(edit["before"] != edit["after"] and anchors[-1]["matches"] == 1,
                    "mutation anchor is absent or ambiguous; refresh its reviewed recipe")
            changed = changed.replace(edit["before"], edit["after"], 1)
        changed_bytes = changed.encode()
        require(changed_bytes != original, "mutation did not change source")
        if recipe["language"] == "python":
            ast.parse(changed, filename=str(relative))
        red_root, green_root = directory / "red-source", directory / "green-source"
        materialize(source, red_root, entries)
        materialize(source, green_root, entries)
        (red_root / relative).write_bytes(changed_bytes)
        report["target"] = relative.as_posix()
        report["before_sha256"], report["after_sha256"] = sha(original), sha(changed_bytes)
        (directory / "after.source").write_bytes(changed_bytes)
        red_dir = directory / "red"
        red_dir.mkdir(mode=0o700)
        phase = (lambda root, out: go_phase(root, out, recipe, tags, timeout)) if recipe["language"] == "go" else (
            lambda root, out: python_phase(root, out, recipe, timeout))
        report["stage"] = "red"
        red = phase(red_root, red_dir)
        report["red"] = red
        report["red_verdict"] = "survived" if red["exit"] == 0 else "assertion_pending"
        require(red["exit"] != 0 and recipe["must_fail"] in red["failed"] and
                recipe["diagnostic"] in red["test_diagnostics"].get(recipe["must_fail"], ""),
                "mutation survived or failed without the targeted assertion diagnostic")
        report["red_verdict"] = "target_assertion_failed"
        verify_copy(red_root, entries, relative.as_posix(), sha(changed_bytes))
        green_dir = directory / "green"
        green_dir.mkdir(mode=0o700)
        report["stage"] = "candidate"
        green = phase(green_root, green_dir)
        report["green"] = green
        require(green["exit"] == 0 and not green["failed"] and recipe["test"] in green["passed"],
                "unchanged candidate did not pass the same focused test")
        verify_copy(green_root, entries)
        verify_copy(source, entries)
        report["stage"] = "complete"
        report["status"] = "killed"
    except (MutationFailure, OSError, ValueError, KeyError, TypeError, SyntaxError, subprocess.SubprocessError) as error:
        report["failure_class"] = type(error).__name__
        report["reason"] = str(error) if isinstance(error, MutationFailure) else "source/build/test setup failed; inspect retained outputs"
    finally:
        write_json(directory / "result.json", report)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--mutation", choices=sorted(MUTATIONS))
    selection.add_argument("--all", action="store_true")
    parser.add_argument("--tags", choices=("laneboss_faults",), default="")
    parser.add_argument("--timeout-seconds", type=int, default=300)
    options = parser.parse_args()
    require(sys.platform == "linux", "mutation execution is authorized only on the disposable Linux box")
    require(options.source.is_absolute() and options.work_root.is_absolute() and options.report.is_absolute(),
            "source/work/report paths must be absolute")
    source, work_root = options.source.resolve(), options.work_root.resolve()
    require(source != work_root and not source.is_relative_to(work_root) and not work_root.is_relative_to(source),
            "work copies must be outside and separate from the supplied source")
    require(1 <= options.timeout_seconds <= 1800, "focused timeout is outside its bound")
    work_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(options.report.parent.resolve().is_relative_to(work_root), "summary must remain in the retained work scope")
    options.report.parent.mkdir(parents=True, exist_ok=True)
    summary = {"schema": "laneboss.msg-matrix.v1", "status": "failed", "mutations": []}
    try:
        entries = inventory(source)
        summary["source_manifest_sha256"] = sha(json.dumps(entries, sort_keys=True).encode())
        names = sorted(MUTATIONS) if options.all else [options.mutation]
        for name in names:
            result = one(source, work_root, entries, name, options.tags, options.timeout_seconds)
            summary["mutations"].append(result)
            print(name + ": " + result["status"], flush=True)
            require(result["status"] == "killed", "mutation phase stopped; preserve its failure evidence")
        summary["status"] = "passed"
    except (MutationFailure, OSError, ValueError, KeyError, TypeError) as error:
        summary["failure_class"] = type(error).__name__
        summary["reason"] = str(error) if isinstance(error, MutationFailure) else "source inventory failed"
    finally:
        write_json(options.report, summary)
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
