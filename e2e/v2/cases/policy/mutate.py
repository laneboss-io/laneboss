"""Run one named red mutation, then its restored green control, on Linux.

The source argument is read-only input. Only inventoried public source files
enter a new copy beneath the supplied evidence directory. Nothing stages Git,
changes the original source, starts a service, or selects a model provider.
"""

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import time


PACKAGE = "laneboss.io/laneboss/internal/v2/policy"
CASE_PATH = Path("e2e/v2/cases/policy")


class CheckFailure(Exception):
    """A setup or verification failure, never a killed mutation."""


def require(condition, message):
    if not condition:
        raise CheckFailure(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def atomic(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    temporary.replace(path)


def reference(root, path):
    resolved = path.resolve(strict=True)
    require(resolved.is_relative_to(root), "evidence path escaped its root")
    data = resolved.read_bytes()
    return {"path": str(resolved.relative_to(root)), "sha256": sha(data), "bytes": len(data)}


def relative_file(value):
    path = PurePosixPath(value)
    require(
        value and not path.is_absolute() and ".." not in path.parts
        and ".git" not in path.parts
        and str(path) == value and not value.startswith("-")
        and "\n" not in value and "\x00" not in value,
        "invalid source inventory path",
    )
    return Path(*path.parts)


def production_file(value):
    path = relative_file(value)
    require(
        value == "internal/v2/cli/commands_policy.go"
        or (path.parts[:3] == ("internal", "v2", "policy")
            and path.suffix == ".go" and not path.name.endswith("_test.go")),
        "mutation target is outside policy production ownership",
    )
    return path


def catalog(path):
    document = json.loads(path.read_bytes())
    require(document["schema"] == "laneboss.policy-mutations.v2", "mutation schema mismatch")
    result = {}
    for item in document["mutations"]:
        name = item["id"]
        require(re.fullmatch(r"[a-z][a-z0-9-]{0,38}", name) is not None, "invalid mutation name")
        require(name not in result and item["rules"] and item["check"], "duplicate or undocumented mutation")
        production_file(item["file"])
        require(item["before"] and item["before"] != item["after"], "empty/no-op mutation")
        require(re.fullmatch(r"Test[A-Za-z0-9_]+", item["test"]) is not None, "invalid focused test")
        require(item["markers"] and all(item["markers"]), "missing intended failure markers")
        subs = item["subtests"]
        require(len(subs) == len(set(subs)), "duplicate focused subtest")
        for sub in subs:
            require(re.fullmatch(r"[A-Za-z0-9_.-]+", sub) is not None, "invalid focused subtest")
        result[name] = item
    require(result, "empty mutation catalog")
    return result


def selected_tests(mutation):
    name = mutation["test"]
    return [name + "/" + sub for sub in mutation["subtests"]] or [name]


def test_filter(mutation):
    pattern = "^" + re.escape(mutation["test"]) + "$"
    if mutation["subtests"]:
        pattern += "/^(" + "|".join(re.escape(sub) for sub in mutation["subtests"]) + ")$"
    return pattern


def observe(raw, mutation, exit_code, timed_out, red, report=None):
    """Require actual test2json run/fail/pass events and intended assertions.

    Build errors, panics, missing tests, skips, wrong assertions, timeout and
    unrelated failures are setup/verification failures. A nonzero exit alone
    cannot kill a mutation. The raw stream is retained by the caller.
    """
    require(not timed_out, "focused test timed out")
    events = []
    for line in raw.decode("utf-8", errors="strict").splitlines():
        event = json.loads(line)
        require(isinstance(event, dict) and event.get("Package") == PACKAGE, "invalid test2json event")
        events.append(event)
    require(events, "missing test2json events")
    started, passed, failed, skipped = set(), set(), set(), set()
    output = {}
    package_actions = []
    for event in events:
        name, action = event.get("Test"), event.get("Action")
        text = event.get("Output", "")
        require("panic:" not in text and "fatal error:" not in text, "test panic is not an assertion kill")
        if name:
            if action == "run":
                started.add(name)
            elif action == "pass":
                passed.add(name)
            elif action == "fail":
                failed.add(name)
            elif action == "skip":
                skipped.add(name)
            output.setdefault(name, []).append(text)
        elif action in ("pass", "fail"):
            package_actions.append(action)
    observation = {"reached": sorted(started), "failed": sorted(failed), "passed": sorted(passed)}
    if report is not None:
        report.update(observation)
    wanted = set(selected_tests(mutation))
    require(not (passed & failed) and not (skipped & (passed | failed)), "contradictory test outcomes")
    require(wanted <= started, "focused operation was not reached")
    require(not skipped, "skipped tests cannot establish mutation coverage")
    if red:
        require(exit_code == 1, "red process did not exit with a test failure")
        require(wanted <= failed, "named guarding assertion did not fail")
        allowed = set(wanted)
        for name in wanted:
            parts = name.split("/")
            allowed.update("/".join(parts[:i]) for i in range(1, len(parts)))
        require(failed <= allowed, "unrelated assertion failed under the mutation")
        for name in wanted:
            text = "".join(output.get(name, []))
            missing = [marker for marker in mutation["markers"] if marker not in text]
            require(not missing, "test failed for an unexpected reason: " + name
                    + "; missing markers: " + json.dumps(missing))
        require(package_actions == ["fail"], "red package outcome missing")
    else:
        require(exit_code == 0 and not failed, "restored candidate failed")
        require(wanted <= passed, "restored guarding assertion did not pass")
        require(package_actions == ["pass"], "green package outcome missing")
    observation["validated"] = True
    if report is not None:
        report.update(observation)
    return observation


class Execution:
    def __init__(self, root, timeout):
        self.root, self.timeout = root, timeout
        self.commands = []
        self.phase = "setup"

    def run(self, name, argv, cwd):
        self.phase = name
        stdout_path = self.root / (name + ".stdout")
        stderr_path = self.root / (name + ".stderr")
        started = time.monotonic()
        # A new process group contains only this owned command and its children.
        # A timeout is a failing phase even after the exact group is collected.
        process = subprocess.Popen(
            argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True,
        )
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=self.timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, 9)
            stdout, stderr = process.communicate(timeout=10)
            timed_out = True
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(stderr)
        receipt = {
            "name": name, "argv": argv, "exit_code": process.returncode,
            "timed_out": timed_out, "elapsed_seconds": time.monotonic() - started,
            "stdout": reference(self.root, stdout_path),
            "stderr": reference(self.root, stderr_path),
        }
        self.commands.append(receipt)
        atomic(self.root / "commands.json", self.commands)
        return stdout, receipt


def inventory(source, filelist, execution):
    if filelist is not None:
        raw = filelist.read_bytes()
        paths = raw.decode("utf-8", errors="strict").splitlines()
        (execution.root / "input-files.txt").write_bytes(raw)
    else:
        raw, receipt = execution.run("git-files", ["git", "ls-files", "-z"], source)
        require(receipt["exit_code"] == 0 and not receipt["timed_out"], "supply --files for a source tree without Git metadata")
        paths = raw.decode("utf-8", errors="strict").split("\x00")
        if paths and paths[-1] == "":
            paths.pop()
    require(paths and len(paths) == len(set(paths)), "empty or duplicate source inventory")
    required = {"go.mod", "go.sum", str(CASE_PATH / "mutations.json"), str(CASE_PATH / "mutate.py")}
    require(required <= set(paths), "source inventory lacks the module or mutation runner")
    return sorted(relative_file(value) for value in paths)


def copy_source(source, destination, paths):
    destination.mkdir(mode=0o700)
    manifest = []
    for relative in paths:
        original = source / relative
        require(original.resolve(strict=True).is_relative_to(source), "source link escaped its input root")
        info = original.lstat()
        require(stat.S_ISREG(info.st_mode) and not original.is_symlink(), "source inventory must contain ordinary files")
        data = original.read_bytes()
        copied = destination / relative
        copied.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        copied.write_bytes(data)
        copied.chmod(stat.S_IMODE(info.st_mode) & 0o777)
        require(copied.read_bytes() == data, "source copy read-back mismatch")
        manifest.append({"path": str(relative), "bytes": len(data), "sha256": sha(data)})
    return manifest


def verify_source(source, manifest, changed_path=None, changed_bytes=None):
    for item in manifest:
        data = (source / item["path"]).read_bytes()
        if item["path"] == changed_path:
            require(data == changed_bytes, "mutant source changed during the red phase")
        else:
            require(len(data) == item["bytes"] and sha(data) == item["sha256"], "input source changed during the mutation phase")


def build_and_run(execution, source, phase, mutation, faults, record):
    binary = execution.root / (phase + ".test")
    command = ["go", "test", "-c", "-trimpath", "-o", str(binary)]
    if faults:
        command.extend(["-tags", "laneboss_faults"])
    command.append("./internal/v2/policy")
    _, build = execution.run(phase + "-build", command, source)
    record["build"] = build
    require(build["exit_code"] == 0 and not build["timed_out"], phase + " compilation failed")
    execution.phase = phase + "-binary"
    require(binary.is_file(), phase + " test binary missing")
    binary_ref = reference(execution.root, binary)
    record["binary"] = binary_ref
    raw, tested = execution.run(phase + "-test", [
        "go", "tool", "test2json", "-t", "-p", PACKAGE, str(binary),
        "-test.v=test2json", "-test.count=1", "-test.run=" + test_filter(mutation),
        "-lb-v2-policy-hook-evidence=" + str(execution.root / (phase + "-cli")),
    ], source)
    record["command"] = tested
    record["observation"] = {}
    execution.phase = phase + "-nested-evidence"
    nested = execution.root / (phase + "-cli")
    if nested.exists():
        record["nested_evidence"] = []
        for directory in sorted(nested.iterdir()):
            require(directory.is_dir() and not directory.is_symlink(), "invalid nested test evidence directory")
            for artifact in sorted(directory.iterdir()):
                require(artifact.is_file() and not artifact.is_symlink(), "invalid nested test artifact")
                record["nested_evidence"].append(reference(execution.root, artifact))
    execution.phase = phase + "-binary-integrity"
    require(reference(execution.root, binary) == binary_ref, "executed test binary changed")
    execution.phase = phase + "-observe"
    observe(raw, mutation, tested["exit_code"], tested["timed_out"], phase == "red", record["observation"])


def output_tail(raw, test_json=False):
    lines = []
    for line in raw.decode("utf-8", errors="replace").splitlines():
        if test_json:
            try:
                event = json.loads(line)
            except ValueError:
                lines.append(line)
                continue
            if isinstance(event, dict) and event.get("Package") == PACKAGE:
                if isinstance(event.get("Output"), str):
                    lines.extend(event["Output"].splitlines())
                continue
        lines.append(line)
    return lines[-20:]


def print_result(result, root):
    print("MUTATION " + result["mutation_id"] + ": " + result["verdict"])
    failed = result.get("red", {}).get("observation", {}).get("failed", [])
    for name in failed:
        print("  RED ASSERTION: " + name)
    if result["verdict"] == "pass":
        return
    print("  PHASE: " + result["failure"]["phase"])
    print("  REASON: " + result["failure"]["reason"])
    commands = result["commands"]
    # Show the latest command (including a failed green build) and the latest
    # test, so post-test integrity failures retain the actual assertion output.
    latest_test = next((item for item in reversed(commands) if item["name"].endswith("-test")), None)
    shown = [item for item in commands if item is latest_test or item is commands[-1]]
    if not shown:
        print("  OUTPUT: no build or test command completed")
    for item in shown:
        print("  OUTPUT: " + item["name"] + "; exit=" + str(item["exit_code"])
              + "; timed_out=" + str(item["timed_out"]))
        for stream in ("stdout", "stderr"):
            path = root / item[stream]["path"]
            print("    " + stream + " tail (last 20 lines):")
            try:
                lines = output_tail(path.read_bytes(), item["name"].endswith("-test") and stream == "stdout")
            except OSError as error:
                print("      unavailable: " + str(error))
                continue
            for line in lines or ["(empty)"]:
                print("      " + line)
    sys.stdout.flush()


def one_mutation(source, paths, mutation, output, timeout, faults):
    output.mkdir(mode=0o700)
    execution = Execution(output, timeout)
    result = {
        "schema": "laneboss.policy-mutation.v2", "mutation_id": mutation["id"],
        "rules": mutation["rules"], "check": mutation["check"],
        "phase_order": [], "verdict": "fail", "faults": faults,
        "input_unchanged": False, "commands": [], "evidence": [],
        "failure": None,
    }
    try:
        execution.phase = "copy-source"
        copied = output / "source"
        manifest = copy_source(source, copied, paths)
        atomic(output / "source-manifest.json", manifest)
        result["evidence"].append(reference(output, output / "source-manifest.json"))
        execution.phase = "runner-source-match"
        for name in ("mutate.py", "mutations.json"):
            require(
                (copied / CASE_PATH / name).read_bytes() == (Path(__file__).parent / name).read_bytes(),
                "executing runner/catalog differs from the copied source artifact",
            )
        execution.phase = "mutate-source"
        relative = production_file(mutation["file"])
        target = copied / relative
        require(target.is_file() and not target.is_symlink(), "mutation target is missing")
        original = target.read_bytes()
        before, after = mutation["before"].encode(), mutation["after"].encode()
        require(original.count(before) == 1, "mutation anchor is missing or ambiguous")
        changed = original.replace(before, after, 1)
        require(changed != original, "mutation did not change the copied source")
        (output / "original.go").write_bytes(original)
        (output / "mutant.go").write_bytes(changed)
        patch = "".join(difflib.unified_diff(
            original.decode().splitlines(keepends=True), changed.decode().splitlines(keepends=True),
            fromfile=str(relative), tofile=str(relative),
        ))
        (output / "mutation.diff").write_text(patch)
        target.write_bytes(changed)
        require(target.read_bytes() == changed, "mutant source read-back mismatch")
        for name in ("original.go", "mutant.go", "mutation.diff"):
            result["evidence"].append(reference(output, output / name))
        result["phase_order"].append("red")
        result["red"] = {}
        build_and_run(execution, copied, "red", mutation, faults, result["red"])
        execution.phase = "red-source-integrity"
        verify_source(copied, manifest, str(relative), changed)
        execution.phase = "restore-source"
        target.write_bytes(original)
        verify_source(copied, manifest)
        result["phase_order"].append("green")
        result["green"] = {}
        build_and_run(execution, copied, "green", mutation, faults, result["green"])
        execution.phase = "green-source-integrity"
        verify_source(copied, manifest)
        execution.phase = "binary-difference"
        require(result["red"]["binary"]["sha256"] != result["green"]["binary"]["sha256"], "red and green test binaries have identical bytes")
        execution.phase = "input-integrity"
        verify_source(source, manifest)
        result["input_unchanged"] = True
        result["verdict"] = "pass"
    except (CheckFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result["failure"] = {"phase": execution.phase, "reason": str(error)}
        (output / "failure.txt").write_text(str(error) + "\n")
        result["evidence"].append(reference(output, output / "failure.txt"))
    finally:
        result["commands"] = execution.commands
        atomic(output / "result.json", result)
    print_result(result, output)
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--files", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--mutation")
    selection.add_argument("--all", action="store_true")
    parser.add_argument("--faults", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()
    require(sys.platform == "linux", "policy mutation execution requires the authorized Linux box")
    require(1 <= args.timeout_seconds <= 600, "invalid phase timeout")
    source = args.source.resolve(strict=True)
    output = args.output.resolve()
    require(source.is_dir() and not output.exists(), "source must exist and output must be new")
    require(not output.is_relative_to(source) and not source.is_relative_to(output), "source and evidence roots overlap")
    require(output.name.startswith("lb-v2-policy-"), "evidence directory must carry the lane name")
    mutations = catalog(Path(__file__).with_name("mutations.json"))
    names = list(mutations) if args.all else [args.mutation]
    require(all(name in mutations for name in names), "unknown mutation")
    output.mkdir(mode=0o700, parents=True)
    execution = Execution(output, args.timeout_seconds)
    paths = inventory(source, args.files, execution)
    version, receipt = execution.run("go-version", ["go", "version"], source)
    require(receipt["exit_code"] == 0 and not receipt["timed_out"], "Go prerequisite failed")
    (output / "go-version.txt").write_bytes(version)
    results = []
    for name in names:
        result = one_mutation(source, paths, mutations[name], output / name, args.timeout_seconds, args.faults)
        results.append({"mutation_id": name, "verdict": result["verdict"], "failure": result["failure"],
                        "result": reference(output, output / name / "result.json")})
        if result["verdict"] != "pass":
            break
    complete = len(results) == len(names) and all(item["verdict"] == "pass" for item in results)
    atomic(output / "results.json", {
        "schema": "laneboss.policy-mutation-set.v2", "verdict": "pass" if complete else "fail",
        "requested": names, "results": results, "commands": execution.commands,
    })
    return 0 if complete else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CheckFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print("FAIL: policy mutation setup: " + str(error), flush=True)
        raise SystemExit(1)
