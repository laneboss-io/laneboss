"""Linux-only package fixtures and source-copy omission controls.

The run-2 brief explicitly authorizes mutation of disposable source copies.
This program never modifies the supplied checkout or writes a Git index.
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import select
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile


CASE = Path("e2e") / "v2" / "cases" / "identity"
PACKAGES = {
    "api": Path("internal") / "v2" / "api",
    "identity": Path("internal") / "v2" / "identity",
    "linux": Path("internal") / "v2" / "peer" / "linux",
    "native": CASE / "native",
    "cli": CASE,
}
MUTATION_PACKAGES = (PACKAGES["identity"], PACKAGES["linux"])
CLI_SOURCE = Path("internal") / "v2" / "cli" / "commands_identity.go"
COMMON_CLI_SOURCE = Path("internal") / "v2" / "cli" / "cli.go"
# The CLI fixture imports assembly plus release/protocol helpers. Retain the
# exact internal source dependencies without copying Git, HOME or credentials.
INPUTS = [Path("go.mod"), Path("go.sum"), Path("internal") / "v2",
          Path("internal") / "identity", Path("internal") / "protocol",
          Path("internal") / "credentialtext", Path("internal") / "jsontext",
          Path("internal") / "typesafe", CASE]
DESCRIPTOR_HELPER = PACKAGES["linux"] / "descriptor_linux_test.go"


class ControlError(Exception):
    """A failed control, setup check, or collection check; never a killed mutant."""

    def __init__(self, message, *, path=None, command=None):
        super().__init__(message)
        self.control_path = path
        self.control_command = command


def failure_details(stage, error, path, argv, operation):
    return {"stage": stage, "type": type(error).__name__, "message": str(error),
            "path": str(getattr(error, "filename", None) or
                        getattr(error, "control_path", None) or path),
            "command": getattr(error, "control_command", None) or
                       getattr(error, "cmd", None) or argv,
            "operation": operation}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def atomic_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix="identity-", dir=path.parent)
    with os.fdopen(fd, "w") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def reference(root, path):
    return {"path": str(path.relative_to(root)),
            "sha256": sha(path.read_bytes()), "bytes": path.stat().st_size}


def inventory(root):
    files = {}
    for item in INPUTS:
        path = root / item
        ancestor = root
        for part in item.parts:
            ancestor /= part
            if ancestor.is_symlink():
                raise ControlError("source input is missing or linked", path=ancestor)
        if not path.exists() or path.is_symlink():
            raise ControlError("source input is missing or linked", path=path)
        entries = sorted(path.rglob("*")) if path.is_dir() else [path]
        for entry in entries:
            if "__pycache__" in entry.relative_to(root).parts or entry.suffix in {".pyc", ".pyo"}:
                continue
            if entry.is_symlink():
                raise ControlError("source input contains a symbolic link", path=entry)
            info = entry.stat()
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ControlError("source input contains a special file", path=entry)
            relative = str(entry.relative_to(root))
            files[relative] = {"sha256": sha(entry.read_bytes()),
                               "bytes": info.st_size,
                               "mode": stat.S_IMODE(info.st_mode)}
    return files


def tree_digest(files):
    return sha(json.dumps(files, sort_keys=True, separators=(",", ":")).encode())


def copy_source(source, destination, expected):
    destination.mkdir(mode=0o700)
    for relative, item in expected.items():
        original = source / relative
        data = original.read_bytes()
        if sha(data) != item["sha256"] or original.is_symlink():
            raise ControlError("source changed during snapshot", path=original)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(item["mode"] & 0o777)
    if inventory(destination) != expected:
        raise ControlError("source snapshot does not match its input manifest", path=destination)


def archive_source(source, path, files):
    with tarfile.open(path, "w:gz") as archive:
        for relative in sorted(files):
            archive.add(source / relative, arcname=relative, recursive=False)


def enable_subreaper():
    # Orphaned test descendants become children of this dedicated runner. No
    # command-line search or signal-by-pattern is used to collect them.
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                          ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise ControlError("Linux child-subreaper setup failed")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise ControlError("Python pidfd support is required for owned-process collection")


def child_ids():
    path = Path("/proc/self/task") / str(os.getpid()) / "children"
    return [int(value) for value in path.read_text().split()]


def collect_children():
    observed, stopped, already_exited = [], [], []
    for _ in range(16):
        children = child_ids()
        if not children:
            return {"observed": observed, "stopped": stopped,
                    "already_exited": already_exited,
                    "remaining": [], "quiescent": True}
        for pid in children:
            observed.append(pid)
            reaped, _ = os.waitpid(pid, os.WNOHANG)
            if reaped:
                continue
            descriptor = os.pidfd_open(pid)
            try:
                status = (Path("/proc") / str(pid) / "status").read_text()
                parents = [line.split()[1] for line in status.splitlines()
                           if line.startswith("PPid:")]
                if parents != [str(os.getpid())]:
                    raise ControlError("owned-process identity changed during collection")
                try:
                    signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                    stopped.append(pid)
                except ProcessLookupError:
                    # It exited after WNOHANG; the same pidfd must still report
                    # exit before waitpid can establish collection.
                    already_exited.append(pid)
                poller = select.poll()
                poller.register(descriptor, select.POLLIN)
                if not poller.poll(2000):
                    raise ControlError("owned process did not reach kernel exit")
                reaped, _ = os.waitpid(pid, 0)
                if reaped != pid:
                    raise ControlError("owned process was not reaped")
            finally:
                os.close(descriptor)
    remaining = child_ids()
    return {"observed": observed, "stopped": stopped, "already_exited": already_exited,
            "remaining": remaining, "quiescent": not remaining}


def command(root, cwd, stem, argv, timeout):
    try:
        result = run_command(root, cwd, stem, argv, timeout)
    except (ControlError, OSError, subprocess.SubprocessError) as error:
        error.control_path = str(cwd)
        error.control_command = list(argv)
        raise
    result["command"], result["path"] = list(argv), str(cwd)
    return result


def run_command(root, cwd, stem, argv, timeout):
    stem.parent.mkdir(parents=True, exist_ok=True)
    stdout = stem.with_suffix(".stdout")
    stderr = stem.with_suffix(".stderr")
    arguments = stem.with_suffix(".argv.json")
    atomic_json(arguments, argv)
    timed_out = False
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen(argv, cwd=cwd, stdout=out, stderr=err)
        descriptor = os.pidfd_open(process.pid)
        try:
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                process.wait(timeout=5)
        finally:
            os.close(descriptor)
    collection = collect_children()
    result = {"exit": process.returncode, "timed_out": timed_out,
              "collection": collection,
              "stdout": reference(root, stdout), "stderr": reference(root, stderr),
              "argv": reference(root, arguments)}
    atomic_json(stem.with_suffix(".result.json"), result)
    if timed_out or not collection["quiescent"] or collection["observed"]:
        raise ControlError("command timed out or left an owned descendant")
    return result


def test_observation(raw, target):
    events = []
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError) as error:
            raise ControlError("test2json produced a malformed event") from error
        if not isinstance(event, dict) or not isinstance(event.get("Action"), str):
            raise ControlError("test2json event has no action")
        events.append(event)
    actions = [event["Action"] for event in events if event.get("Test") == target]
    failed = sorted({event["Test"] for event in events
                     if event["Action"] == "fail" and event.get("Test")})
    skipped = sorted({event.get("Test") or "<package>" for event in events
                      if event["Action"] == "skip"})
    output = "".join(event.get("Output", "") for event in events)
    target_output = "".join(event.get("Output", "") for event in events
                            if event.get("Test") == target)
    if "fixture setup:" in output or "fixture cleanup:" in output or "panic:" in output:
        raise ControlError("test setup, panic or collection failed before a valid control result")
    return {"actions": actions, "failed_tests": failed, "skipped_tests": skipped,
            "target_output": target_output}


def assess_test(result, observation, parts, red=False, diagnostic=""):
    target = "/".join(parts)
    if result["timed_out"] or not result["collection"]["quiescent"] or result["collection"]["observed"]:
        raise ControlError("timeout or leftover descendant is not a test result")
    if observation["skipped_tests"] or "run" not in observation["actions"]:
        raise ControlError("targeted test did not run without skips")
    terminal = [action for action in observation["actions"] if action in {"pass", "fail", "skip"}]
    if red:
        ancestors = {"/".join(parts[:index]) for index in range(1, len(parts) + 1)}
        if result["exit"] != 1 or terminal != ["fail"]:
            raise ControlError("mutation survived: targeted test did not fail")
        if target not in observation["failed_tests"] or set(observation["failed_tests"]) - ancestors:
            raise ControlError("mutation failed in an unexpected test")
        if not diagnostic or diagnostic not in observation["target_output"]:
            raise ControlError("mutation failed for an unexpected reason")
    elif result["exit"] != 0 or terminal != ["pass"] or observation["failed_tests"]:
        raise ControlError("unmodified candidate failed its focused test")


def build(root, source, directory, package, tags):
    directory.mkdir(parents=True, exist_ok=True)
    binary = directory / "package.test"
    argv = ["go", "test", "-mod=readonly", "-trimpath", "-c", "-o", str(binary)]
    if tags == "laneboss_faults":
        argv.extend(["-tags", tags])
    argv.append("./" + str(PACKAGES[package]))
    result = command(root, source, directory / "build", argv, 180)
    if result["exit"] != 0:
        raise ControlError("test binary did not compile; this is not a killed mutation",
                           path=root / result["stderr"]["path"], command=argv)
    if not binary.is_file() or binary.stat().st_size == 0:
        raise ControlError("compiler did not retain a test binary", path=binary, command=argv)
    return {"result": result, "binary": reference(root, binary)}


def run_test(root, source, directory, package, parts, built):
    binary = root / built["binary"]["path"]
    if reference(root, binary) != built["binary"]:
        raise ControlError("test binary changed after compilation")
    expression = "/".join("^" + re.escape(part) + "$" for part in parts)
    package_name = "laneboss.io/laneboss/" + str(PACKAGES[package])
    argv = ["go", "tool", "test2json", "-t", "-p", package_name, str(binary),
            "-test.v=test2json", "-test.timeout=45s", "-test.run=" + expression]
    result = command(root, source, directory / "test", argv, 90)
    raw = (root / result["stdout"]["path"]).read_bytes()
    try:
        observed = test_observation(raw, "/".join(parts))
    except ControlError as error:
        error.control_path = root / result["stdout"]["path"]
        error.control_command = argv
        raise
    result["observation"] = observed
    return result


def validate_case(case):
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,47}", case["id"]):
        raise ControlError("invalid control identifier")
    if case["package"] not in PACKAGES or not case["test"]:
        raise ControlError("invalid control package or test")
    if not case["test"][0].startswith("Test"):
        raise ControlError("control must name a Go test")
    for part in case["test"]:
        if not re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", part):
            raise ControlError("invalid focused test name: " + repr(part))


def apply_mutation(source, spec, files):
    changed = []
    for edit in spec["edits"]:
        parts = files[edit["file"]]
        path = Path(*parts)
        helper = path == DESCRIPTOR_HELPER and spec.get("kind") == "fixture-helper"
        if path.suffix != ".go" or (path.name.endswith("_test.go") and not helper) or ".." in parts:
            raise ControlError("mutation target is not owned production Go source", path=source / path)
        cli = path in {CLI_SOURCE, COMMON_CLI_SOURCE} and spec.get("package") == "cli" and spec.get("kind") == "client"
        if not cli and not any(path.is_relative_to(package) for package in MUTATION_PACKAGES):
            raise ControlError("mutation target is outside identity ownership", path=source / path)
        target = source / path
        original = target.read_bytes()
        if helper and re.search(rb"(?m)^func (?:Test|Example|Fuzz)", original):
            raise ControlError("fixture helper mutation cannot change test assertions", path=target)
        before, after = edit["before"].encode(), edit["after"].encode()
        if not before or before == after or original.count(before) != 1:
            raise ControlError("mutation anchor is absent or ambiguous", path=target)
        modified = original.replace(before, after, 1)
        if helper and re.search(rb"(?m)^func (?:Test|Example|Fuzz)", modified):
            raise ControlError("fixture helper mutation cannot change test assertions", path=target)
        target.write_bytes(modified)
        changed.append({"path": str(path), "before_sha256": sha(original),
                        "after_sha256": sha(modified)})
    if not changed:
        raise ControlError("mutation contains no changed check")
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--work-root", required=True, type=Path)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--mode", choices=["mutations", "fixtures"], default="mutations")
    parser.add_argument("--mutation", default="all")
    parser.add_argument("--tags", choices=["normal", "laneboss_faults", "both"], default="normal")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("run only on the authorized disposable Linux test box")
    source = args.source.resolve(strict=True)
    root = args.work_root.absolute()
    if not root.name.startswith("lb-v2-identity-") or root.exists() or root.is_relative_to(source):
        parser.error("work root must be new, outside the source and carry the lane name")
    if root.parent.resolve(strict=True) != root.parent or root.is_symlink():
        parser.error("work root parent must be physically resolved")
    if not re.fullmatch(r"[a-f0-9]{7,64}", args.revision):
        parser.error("record the actual source revision")
    enable_subreaper()
    root.mkdir(mode=0o700)
    report = {"schema": "laneboss.identity-controls.v1", "scope": "package-fixture",
              "mode": args.mode, "source_revision": args.revision,
              "platform": {"system": sys.platform, "release": platform.release(),
                           "machine": platform.machine(), "python": platform.python_version()},
              "results": [], "status": "incomplete"}
    stage = "snapshot"
    invocation = [sys.executable, *sys.argv]
    phase_path, phase_command, operation = source, invocation, "inventory"
    try:
        inputs = inventory(source)
        snapshot = root / "input-source"
        phase_path, operation = snapshot, "copy_source"
        copy_source(source, snapshot, inputs)
        atomic_json(root / "source-files.json", inputs)
        report["source_sha256"] = tree_digest(inputs)
        phase_path, operation = root / "input-source.tar.gz", "archive_source"
        archive_source(snapshot, phase_path, inputs)
        report["source_archive"] = reference(root, root / "input-source.tar.gz")
        phase_path, phase_command, operation = snapshot, ["go", "version"], "command"
        version = command(root, snapshot, root / "go-version", phase_command, 30)
        if version["exit"] != 0:
            raise ControlError("Go version query failed")
        report["go_version"] = version
        phase_command, operation = invocation, "load_manifest"
        phase_path = snapshot / CASE / "fixture-cases.json"
        fixture_plan = json.loads(phase_path.read_bytes())
        phase_path = snapshot / CASE / "mutations.json"
        mutations = json.loads(phase_path.read_bytes())
        if fixture_plan["schema"] != "laneboss.identity-fixtures.v1" or \
                mutations["schema"] != "laneboss.identity-mutations.v1":
            raise ControlError("unsupported control manifest schema")
        api_source = snapshot / "internal" / "v2" / "api" / "base.go"
        phase_path, operation = api_source, "contract_revision"
        revisions = re.findall(r'ContractRevision\s*=\s*"([^"]+)"', api_source.read_text())
        if len(revisions) != 1 or any(plan.get("contract_revision") != revisions[0]
                                      for plan in [fixture_plan, mutations]):
            raise ControlError("control manifests differ from the frozen API revision")
        report["contract_revision"] = revisions[0]
        report["remaining_acceptance"] = fixture_plan["remaining_acceptance"]
        cases = fixture_plan["cases"] if args.mode == "fixtures" else mutations["mutations"]
        phase_path = snapshot / CASE / ("fixture-cases.json" if args.mode == "fixtures" else "mutations.json")
        operation = "select_cases"
        if args.mode == "fixtures" and args.mutation != "all":
            raise ControlError("fixture mode does not select a source mutation")
        if args.mode == "mutations" and args.mutation != "all":
            cases = [case for case in cases if case["id"] == args.mutation]
        if not cases or len({case["id"] for case in cases}) != len(cases):
            raise ControlError("missing or duplicated control selection")
        for case in cases:
            operation = "validate_case/" + case["id"]
            validate_case(case)
        modes = ["normal", "laneboss_faults"] if args.tags == "both" else [args.tags]
        green_binaries = {}
        for tags in modes:
            for case in cases:
                stage = tags + "/" + case["id"]
                directory = root / tags / case["id"]
                phase_path, phase_command, operation = directory, invocation, "prepare_case"
                directory.mkdir(parents=True)
                row = {"id": case["id"], "rule": case["rule"], "kind": case["kind"],
                       "scope": "package-fixture", "tags": tags,
                       "target": "/".join(case["test"]), "status": "incomplete"}
                report["results"].append(row)
                atomic_json(root / "report.json", report)
                if args.mode == "mutations":
                    red_source = directory / "red-source"
                    phase_path, operation = red_source, "copy_source"
                    copy_source(snapshot, red_source, inputs)
                    operation = "apply_mutation"
                    row["edits"] = apply_mutation(red_source, case, mutations["files"])
                    modified = inventory(red_source)
                    actual_changes = {name for name in inputs if inputs[name] != modified[name]}
                    if modified.keys() != inputs.keys() or \
                            actual_changes != {edit["path"] for edit in row["edits"]}:
                        raise ControlError("mutation changed an unexpected input or test file")
                    atomic_json(directory / "red-source-files.json", modified)
                    archive_source(red_source, directory / "red-source.tar.gz", modified)
                    row["red_archive"] = reference(root, directory / "red-source.tar.gz")
                    phase_path, operation = directory / "red", "build"
                    row["red_build"] = build(root, red_source, directory / "red", case["package"], tags)
                    operation = "run_test"
                    row["red"] = run_test(root, red_source, directory / "red", case["package"],
                                          case["test"], row["red_build"])
                    if inventory(red_source) != modified:
                        raise ControlError("red source changed during its focused test")
                    phase_path = root / row["red"]["stdout"]["path"]
                    phase_command, operation = row["red"]["command"], "assess_red"
                    assess_test(row["red"], row["red"]["observation"], case["test"],
                                red=True, diagnostic=case["diagnostic"])
                    row["status"] = "red-observed"
                    atomic_json(root / "report.json", report)
                else:
                    row["excludes"] = case["excludes"]
                # This run occurs only after the expected red failure. It uses
                # an unchanged snapshot and the identical test source bytes.
                key = (tags, case["package"])
                if key not in green_binaries:
                    green_dir = root / tags / ("candidate-" + case["package"])
                    phase_path, phase_command, operation = green_dir, invocation, "build"
                    green_binaries[key] = build(root, snapshot, green_dir, case["package"], tags)
                row["green_build"] = green_binaries[key]
                phase_path, operation = directory / "green", "run_test"
                row["green"] = run_test(root, snapshot, directory / "green", case["package"],
                                        case["test"], row["green_build"])
                phase_path = root / row["green"]["stdout"]["path"]
                phase_command, operation = row["green"]["command"], "assess_candidate"
                assess_test(row["green"], row["green"]["observation"], case["test"])
                if args.mode == "mutations" and \
                        row["red_build"]["binary"]["sha256"] == row["green_build"]["binary"]["sha256"]:
                    raise ControlError("red and candidate artifacts are identical")
                phase_path, phase_command, operation = snapshot, invocation, "verify_sources"
                if inventory(snapshot) != inputs or inventory(source) != inputs:
                    raise ControlError("unmodified source changed during controls")
                row["status"] = "killed" if args.mode == "mutations" else "fixture-pass"
                atomic_json(root / "report.json", report)
                print(json.dumps({"id": row["id"], "tags": tags, "status": row["status"],
                                  "scope": row["scope"]}), flush=True)
        phase_path, phase_command, operation = root, invocation, "collect_children"
        collection = collect_children()
        report["collection"] = collection
        if not collection["quiescent"] or collection["observed"]:
            raise ControlError("controls left an owned descendant")
        report["status"] = "passed"
    except (ControlError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["status"] = "failed"
        report["failure"] = failure_details(stage, error, phase_path, phase_command, operation)
        print(json.dumps({"status": "failed", "scope": "package-fixture", **report["failure"]}), flush=True)
        try:
            report["collection"] = collect_children()
        except (ControlError, OSError) as collection_error:
            report["collection"] = {"quiescent": False, "error": str(collection_error)}
    atomic_json(root / "report.json", report)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
