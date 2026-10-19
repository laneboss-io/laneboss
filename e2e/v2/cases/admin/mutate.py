"""Apply one reviewed mutation to a disposable source copy and observe tests."""

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
import tarfile
import uuid


ROOTS = (
    "go.mod",
    "go.sum",
    "internal/identity",
    "internal/protocol",
    "internal/jsontext",
    "internal/typesafe",
    "internal/credentialtext",
    "internal/v2",
    "internal/authorship",
    "internal/caller/records",
    "internal/cliargs",
    "internal/config",
    "internal/contextio",
    "internal/decisions/argparse",
    "internal/decisions/jsonout",
    "internal/decisionsrv",
    "internal/eventstore",
    "internal/faults",
    "internal/guardtime",
    "internal/hookblacklist",
    "internal/hookpaths",
    "internal/instancename",
    "internal/jobcatalog",
    "internal/judge",
    "internal/lanesandbox",
    "internal/observation",
    "internal/rolepolicy",
    "internal/runnermodel",
    "internal/selfexec",
    "internal/settings",
    "migration/v2",
    "web/v2",
    "scripts/v2-admin",
    "packaging/v2/linux",
    "e2e/v2/cases/admin",
    "e2e/v2/human_authority.py",
)
OWNED = ("internal/v2/admin/", "internal/v2/fdpath/", "internal/v2/client/wire/",
         "scripts/v2-admin/", "packaging/v2/linux/")
OWNED_FILES = ("internal/v2/cli/commands_admin.go", "internal/v2/policy/initial.go",
               "internal/v2/cli/cli.go",
               "internal/v2/cli/bootstrap_entry.go",
               "internal/v2/peer/linux/native_linux.go",
               "internal/v2/isolation/linux/" "layout_linux.go",
               "internal/v2/isolation/linux/" "export_linux.go",
               "internal/v2/api/human_presence.go",
               "internal/v2/api/json.go", "internal/v2/api/json_diagnostic.go",
               "internal/v2/archive/retire.go",
               "internal/v2/store/arch_retire.go", "internal/v2/store/owned_quiet.go",
               "internal/v2/service/archive.go",
               "internal/v2/service/" "launch_control.go")


class InvalidRun(Exception):
    """A setup, survived mutation or wrong-failure result; never a killed red."""


def require(value, reason):
    if not value:
        raise InvalidRun(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("x") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def inputs(source):
    result = []
    for name in ROOTS:
        root = source / name
        require(root.exists() and not root.is_symlink(), "missing or linked source root")
        paths = [root] if root.is_file() else sorted(root.rglob("*"))
        for path in paths:
            relative = path.relative_to(source)
            if "__pycache__" in relative.parts or path.suffix == ".pyc":
                continue
            require(not path.is_symlink(), "source links are not copied")
            if path.is_dir():
                continue
            require(path.is_file() and not any(part.startswith(".") for part in relative.parts),
                    "unexpected source object")
            data = path.read_bytes()
            result.append({"path": relative.as_posix(), "sha256": sha(data), "bytes": len(data),
                           "mode": stat.S_IMODE(path.stat().st_mode)})
    return sorted(result, key=lambda row: row["path"])


def tree_digest(manifest):
    return sha(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())


def edit_path(edit, evidence_class="product"):
    require(("path" in edit) != ("path_parts" in edit), "mutation path shape is ambiguous")
    name = edit["path"] if "path" in edit else "/".join(edit["path_parts"])
    require((name.startswith(OWNED) or name in OWNED_FILES) and
            ".." not in Path(name).parts and not Path(name).is_absolute(),
            "mutation exceeds lane ownership")
    require(evidence_class in ("product", "fixture-check") and
            name.endswith("_test.go") == (evidence_class == "fixture-check"),
            "mutation evidence class differs from its product or fixture target")
    return name


def copy_inputs(source, destination, manifest):
    destination.mkdir(mode=0o700, parents=True)
    for row in manifest:
        origin, target = source / row["path"], destination / row["path"]
        require(sha(origin.read_bytes()) == row["sha256"], "source changed during copy")
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(origin, target)
        target.chmod(row["mode"])
        require(sha(target.read_bytes()) == row["sha256"], "source copy read-back differs")


def capture(directory, label, command, cwd, seconds, overrides=None):
    write_json(directory / (label + ".command.json"), command)
    environment = None
    if overrides is not None:
        require(overrides == {"CGO_ENABLED": "0"}, "invalid focused command environment override")
        environment = os.environ.copy()
        environment.update(overrides)
        write_json(directory / (label + ".environment-overrides.json"), overrides)
    with (directory / (label + ".stdout")).open("xb") as stdout, \
            (directory / (label + ".stderr")).open("xb") as stderr:
        process = subprocess.Popen(command, cwd=cwd, env=environment, stdout=stdout, stderr=stderr)
        write_json(directory / (label + ".pid.json"), {"pid": process.pid})
        try:
            code = process.wait(timeout=seconds)
        except subprocess.TimeoutExpired as failure:
            process.kill()  # This process ID only; no command-line matching.
            process.wait()
            write_json(directory / (label + ".timeout.json"), {"seconds": seconds})
            raise InvalidRun("deadline expired; descendants require supervisor inspection") from failure
    write_json(directory / (label + ".exit.json"), {"exit_code": code})
    return code


def apply_mutation(source, entry):
    require(len(entry["edits"]) == 1, "exactly one mutation edit is required")
    edit = entry["edits"][0]
    name = edit_path(edit, entry.get("evidence_class", "product"))
    path = source / name
    before, after = edit["before"].encode(), edit["after"].encode()
    data = path.read_bytes()
    require(before != after and data.count(before) == 1, "mutation anchor is stale or ambiguous")
    changed = data.replace(before, after, 1)
    path.write_bytes(changed)
    require(path.read_bytes() == changed, "mutation read-back differs")
    return {"path": name, "before_sha256": sha(data), "after_sha256": sha(changed)}


def go_phase(directory, source, entry, phase, faults):
    binary = directory / "admin.test"
    package = entry.get("package", "./internal/v2/admin")
    require(package in ("./internal/v2/admin", "./internal/v2/api", "./internal/v2/cli", "./internal/v2/service", "./internal/v2/store", "./internal/v2/peer/linux", "./internal/v2/isolation/linux", "./internal/v2/client/wire"),
            "invalid focused test package")
    root_only = entry.get("root_only", False)
    tags = entry.get("tags", [])
    require(isinstance(root_only, bool) and isinstance(tags, list), "invalid root/tag selection")
    require(tags == (["laneboss_root_canary"] if root_only else []), "unsupported root/tag selection")
    require(not root_only or os.geteuid() == 0, "root-only mutation requires the disposable root Linux run")
    command = ["go", "test", "-c", "-trimpath", "-buildvcs=false", "-mod=readonly", "-o", str(binary)]
    gate_tags = entry.get("build_tags", [])
    require(gate_tags in ([], ["laneboss_gate_integration"]), "invalid focused build tags")
    build_tags = list(tags) + list(gate_tags)
    static_fixture = "laneboss_gate_integration" in build_tags
    if static_fixture:
        command.append("-buildmode=exe")
    if faults:
        build_tags.append("laneboss_faults")
    if build_tags:
        command.extend(["-tags", ",".join(build_tags)])
    command.append(package)
    code = capture(directory, "build", command, source, 600,
                   {"CGO_ENABLED": "0"} if static_fixture else None)
    require(code == 0 and binary.is_file(), "build failure is not a killed mutation")
    artifact = {"sha256": sha(binary.read_bytes()), "bytes": binary.stat().st_size}
    write_json(directory / "binary.json", artifact)
    native_inputs = {}
    native_tools = entry.get("native_tools", [])
    require(native_tools in ([], ["bwrap"]), "invalid focused native tool inputs")
    for name in ["true", "printf", *native_tools]:
        path = Path("/usr/bin") / name
        data = path.read_bytes()
        native_inputs[path] = data
        (directory / ("native-" + name + ".input")).write_bytes(data)
    write_json(directory / "native-inputs.json", [
        {"path": str(path), "sha256": sha(data), "bytes": len(data)}
        for path, data in native_inputs.items()])
    target = entry["test"]
    require(re.fullmatch(r"[A-Za-z0-9_./-]{1,128}", target), "invalid focused test name")
    pattern = "/".join("^" + re.escape(part) + "$" for part in target.split("/"))
    command = ["go", "tool", "test2json", "-t", "-p", "laneboss.io/laneboss/" + package[2:],
               str(binary), "-test.v=test2json", "-test.count=1", "-test.timeout=60s", "-test.run=" + pattern]
    code = capture(directory, "test", command, source, 90)
    require(sha(binary.read_bytes()) == artifact["sha256"] and
            all(path.read_bytes() == data for path, data in native_inputs.items()),
            "tested binary or native executable input changed")
    events = []
    for line in (directory / "test.stdout").read_bytes().splitlines():
        events.append(json.loads(line))
    require(events and not any(row.get("Action") == "skip" for row in events), "missing or skipped test events")
    failed = sorted({row["Test"] for row in events if row.get("Action") == "fail" and "Test" in row})
    output = "".join(row.get("Output", "") for row in events if row.get("Test") == target)
    reached = any(row.get("Action") == "run" and row.get("Test") == target for row in events)
    passed = any(row.get("Action") == "pass" and row.get("Test") == target for row in events)
    killed = code != 0 and reached and target in failed and entry["failure_contains"] in output
    result = {"phase": phase, "test": target, "observed_exit": code, "reached": reached,
              "failed_tests": failed, "target_assertion_failed": killed, "binary": artifact,
              "target_passed": passed, "evidence_class": entry.get("evidence_class", "product"),
              "product_mutation_killed": phase == "red" and killed and entry.get("evidence_class", "product") == "product",
              "fixture_check_killed": phase == "red" and killed and entry.get("evidence_class") == "fixture-check"}
    write_json(directory / "observation.json", result)
    require(killed if phase == "red" else code == 0 and reached and passed and not failed,
            "mutation survived or test failed before the intended assertion" if phase == "red" else "candidate focused test failed")
    return result


def namespace_phase(directory, source, entry, phase, context_file):
    require(context_file is not None, "namespace mutation requires a file-backed context")
    original = json.loads(context_file.read_bytes())
    require(original["schema"] == "laneboss.e2e-context.v2" and original["case_id"] == "admin",
            "invalid namespace context")
    fixture = json.loads((Path(original["test_root"]) / "admin-input.json").read_bytes())
    require(fixture["restriction"] == 1, "reload/read-back mutations require the restriction-one cell")
    root, evidence = directory / "case", directory / "evidence"
    root.mkdir(mode=0o700)
    # The unprivileged observer keeps its source/evidence private. Root only
    # executes the exact selected assets after a privileged copy and hash
    # read-back into a separate root-owned, non-writable source tree.
    asset_root = Path("/test/laneboss-admin-assets") / uuid.uuid4().hex
    existing = asset_root.parent
    while not existing.exists():
        existing = existing.parent
    for parent in (existing, *existing.parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "unsafe root asset staging ancestor")
    require(not asset_root.exists() and not asset_root.is_symlink(), "root asset staging already exists")
    code = capture(directory, "root-assets-dir", ["sudo", "-n", "install", "-d", "-o", "root", "-g", "root",
                   "-m", "0755", str(asset_root / "scripts/v2-admin"), str(asset_root / "packaging/v2/linux")], source, 30)
    require(code == 0, "root asset staging failed")
    staged = []
    for index, name in enumerate(("scripts/v2-admin/apparmor.sh", "packaging/v2/linux/laneboss-bwrap.apparmor")):
        origin, target = source / name, asset_root / name
        data = origin.read_bytes()
        code = capture(directory, "root-asset-%d" % index, ["sudo", "-n", "install", "-o", "root", "-g", "root",
                       "-m", "0644", str(origin), str(target)], source, 30)
        require(code == 0 and target.read_bytes() == data, "root asset copy or hash read-back differs")
        for path in (target, *target.parents):
            info = path.lstat()
            require(not path.is_symlink() and info.st_uid == 0 and not info.st_mode & 0o022,
                    "root staged asset ownership differs")
        staged.append({"path": str(target), "sha256": sha(data), "bytes": len(data)})
    write_json(directory / "root-assets.json", staged)
    write_json(root / "admin-input.json", {"restriction": fixture["restriction"], "admin_source": str(asset_root)})
    context = dict(original, test_root=str(root), evidence_root=str(evidence), phase=phase,
                   mutation_id=entry["id"] if phase == "red" else "", source_sha256=tree_digest(inputs(source)))
    write_json(directory / "context.json", context)
    result_file = root / "focus.json"
    command = [sys.executable, "-I", str(source / "e2e/v2/cases/admin/focus.py"),
               "--context", str(directory / "context.json"), "--result", str(result_file)]
    code = capture(directory, "test", command, source, 180)
    require(result_file.is_file(), "missing namespace result is not a killed mutation")
    observed = json.loads(result_file.read_bytes())
    receipt = observed.get("profile_receipt") or {}
    killed = (code != 0 and observed["verdict"] == "fail" and observed["failed_label"] == entry["failure_label"]
              and receipt.get("schema") == "laneboss.admin-step.v2" and
              receipt.get("stage") == entry["failure_stage"] and receipt.get("exit_code") == entry["step_exit"])
    if entry["failure_label"] != "profile-install":
        failed_command = observed.get("failed_command") or {}
        killed = (killed and observed.get("reason") == entry["failure_contains"] and
                  failed_command.get("label") == entry["failure_label"] and
                  failed_command.get("exit_code") == entry["command_exit"])
    result = {"phase": phase, "test": "UBUNTU-USERNS", "observed_exit": code,
              "failed_tests": ["UBUNTU-USERNS"] if code != 0 else [],
              "target_assertion_failed": killed, "profile_receipt": receipt,
              "processes_quiescent": observed["processes_quiescent"]}
    write_json(directory / "observation.json", result)
    require(observed["processes_quiescent"] and observed["switches_unchanged"], "namespace collection or host switches differ")
    require(killed if phase == "red" else code == 0 and observed["verdict"] == "pass",
            "namespace failure was not the intended stopped step" if phase == "red" else "candidate namespace cell failed")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--mutation", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--phase", choices=("pair", "red", "green"), default="pair")
    parser.add_argument("--context", type=Path)
    parser.add_argument("--faults", action="store_true")
    args = parser.parse_args()
    require(sys.platform == "linux", "mutation execution is permitted only on disposable Linux")
    source, output = args.source.resolve(), args.output
    require(output.is_absolute() and not output.exists() and not output.is_symlink(), "new absolute evidence directory required")
    require(output.name.startswith("lb-v2-admin-"), "evidence directory must carry the lane name")
    require(source not in output.resolve().parents, "evidence must be outside source")
    catalog = json.loads(Path(__file__).with_name("mutations.json").read_bytes())
    require(catalog["schema"] == "laneboss.admin-mutations.v2", "invalid mutation catalog")
    entries = [row for row in catalog["mutations"] if row["id"] == args.mutation]
    require(len(entries) == 1, "unknown or duplicate mutation")
    entry = entries[0]
    require(entry["kind"] == "go" or args.phase != "pair", "namespace phases use separate fresh disposable cells")
    output.mkdir(mode=0o700, parents=True)
    code = capture(output, "host", ["uname", "-srm"], source, 10)
    require(code == 0, "host facts could not be retained")
    if entry["kind"] == "go":
        code = capture(output, "go-version", ["go", "version"], source, 30)
        require(code == 0, "Go tool version could not be retained")
    manifest = inputs(source)
    write_json(output / "input-manifest.json", manifest)
    write_json(output / "selected-mutation.json", entry)
    snapshot = output / "inputs"
    copy_inputs(source, snapshot, manifest)
    require(len(entry["edits"]) == 1, "exactly one mutation edit is required")
    edit = entry["edits"][0]
    require(edit["before"] != edit["after"] and
            (snapshot / edit_path(edit, entry.get("evidence_class", "product"))).read_bytes().count(edit["before"].encode()) == 1,
            "baseline mutation anchor is stale or ambiguous")
    with tarfile.open(output / "inputs.tar", "w") as archive:
        for row in manifest:
            data_file = snapshot / row["path"]
            info = archive.gettarinfo(data_file, arcname=row["path"])
            info.uname, info.gname = "", ""
            with data_file.open("rb") as stream:
                archive.addfile(info, stream)
    report = {"schema": "laneboss.admin-mutation-result.v2", "mutation_id": entry["id"],
              "input_sha256": tree_digest(manifest), "scope": entry["scope"], "phases": [], "complete": False,
              "evidence_class": entry.get("evidence_class", "product")}
    phases = ("red", "green") if args.phase == "pair" else (args.phase,)
    try:
        for phase in phases:
            directory = output / phase
            directory.mkdir(mode=0o700)
            copy = directory / "source"
            copy_inputs(snapshot, copy, manifest)
            change = apply_mutation(copy, entry) if phase == "red" else None
            after = inputs(copy)
            changed = [row["path"] for row, baseline in zip(after, manifest) if row != baseline]
            require(len(after) == len(manifest) and changed == ([edit_path(edit, entry.get("evidence_class", "product"))] if phase == "red" else []),
                    "source changes exceed the selected mutation")
            write_json(directory / "source-manifest.json", after)
            write_json(directory / "mutation.json", {"change": change, "source_sha256": tree_digest(after)})
            result = (go_phase(directory, copy, entry, phase, args.faults) if entry["kind"] == "go"
                      else namespace_phase(directory, copy, entry, phase, args.context))
            require(inputs(copy) == after, "phase source changed during execution")
            report["phases"].append(result)
            verdict = ("FIXTURE-CHECK KILLED" if entry.get("evidence_class") == "fixture-check" else "KILLED") if phase == "red" else "PASS"
            print("%s: %s; failed tests: %s" % (verdict, entry["id"],
                                                   ", ".join(result["failed_tests"]) or "none"))
        require(inputs(source) == manifest, "original source changed during mutation run")
        report["complete"] = True
    except (InvalidRun, OSError, ValueError, KeyError, TypeError) as failure:
        report["error"] = str(failure)
        observation = directory / "observation.json"
        if observation.is_file():
            failed_observation = json.loads(observation.read_bytes())
            if not any(row["phase"] == failed_observation["phase"] for row in report["phases"]):
                report["phases"].append(failed_observation)
        failed = sorted({name for row in report["phases"] for name in row["failed_tests"]})
        reason = str(failure) if isinstance(failure, InvalidRun) else type(failure).__name__
        print("FAIL: mutation evidence incomplete; failed tests: " + (", ".join(failed) or "none") +
              "; reason: " + reason, file=sys.stderr)
    write_json(output / "result.json", report)
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
