"""Run a reviewed red/candidate pair only on disposable unprivileged Linux."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile


ROOTS = ("go.mod", "go.sum", "internal/v2/api",
         "internal/v2/isolation/linux", "e2e/v2/cases/linux", "e2e/v2/human_authority.py")
OWNED = "internal/v2/isolation/linux/"


class InvalidRun(Exception):
    """Setup failure, wrong failure or surviving mutation; never a killed red."""


def require(value, reason):
    if not value:
        raise InvalidRun(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def keep_json(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def inputs(source):
    manifest = []
    for name in ROOTS:
        root = source / name
        require(root.exists() and not root.is_symlink(), "missing or linked input root")
        paths = [root] if root.is_file() else sorted(root.rglob("*"))
        for path in paths:
            relative = path.relative_to(source)
            if "__pycache__" in relative.parts or path.suffix == ".pyc":
                continue
            require(not path.is_symlink(), "source links are not copied")
            if path.is_dir():
                continue
            require(path.is_file() and not any(p.startswith(".") for p in relative.parts),
                    "unexpected input object")
            data = path.read_bytes()
            manifest.append({"path": relative.as_posix(), "bytes": len(data),
                             "sha256": sha(data),
                             "mode": stat.S_IMODE(path.stat().st_mode)})
    return sorted(manifest, key=lambda row: row["path"])


def tree_sha(manifest):
    return sha(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())


def module_inputs(root):
    require(root.is_dir() and not root.is_symlink(), "pinned x/sys module source is missing")
    result = []
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), "linked dependency input refused")
        if path.is_dir():
            continue
        require(path.is_file(), "nonregular dependency input refused")
        data = path.read_bytes()
        result.append({"path": path.relative_to(root).as_posix(),
                       "sha256": sha(data), "bytes": len(data)})
    return result


def retain_module(source, module_cache, output):
    versions = re.findall(rb"^\s*golang.org/x/sys\s+(v[0-9.]+)\s*$",
                          (source / "go.mod").read_bytes(), re.MULTILINE)
    require(len(versions) == 1, "pinned x/sys dependency version is ambiguous")
    module = module_cache / "golang.org" / "x" / ("sys@" + versions[0].decode())
    manifest = module_inputs(module)
    keep_json(output / "dependency-manifest.json", manifest)
    with tarfile.open(output / "dependency.tar", "w") as archive:
        for row in manifest:
            path = module / row["path"]
            data = path.read_bytes()
            require(sha(data) == row["sha256"], "dependency changed during retention")
            info = archive.gettarinfo(path, arcname=row["path"])
            info.uname, info.gname, info.size = "", "", len(data)
            archive.addfile(info, io.BytesIO(data))
    return module, manifest


def copy_inputs(source, destination, manifest):
    destination.mkdir(mode=0o700)
    for row in manifest:
        origin, target = source / row["path"], destination / row["path"]
        data = origin.read_bytes()
        require(sha(data) == row["sha256"], "input changed during copy")
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
        target.chmod(row["mode"])
        require(sha(target.read_bytes()) == row["sha256"], "copied input differs")


def capture(directory, label, command, cwd, environment, seconds):
    keep_json(directory / (label + ".command.json"), command)
    with (directory / (label + ".stdout")).open("xb") as stdout, \
            (directory / (label + ".stderr")).open("xb") as stderr:
        process = subprocess.Popen(command, cwd=cwd, env=environment,
                                   stdout=stdout, stderr=stderr)
        keep_json(directory / (label + ".pid.json"), {"pid": process.pid})
        try:
            code = process.wait(timeout=seconds)
        except subprocess.TimeoutExpired as failure:
            process.kill()  # Stop only this process ID; retain unknown descendants.
            process.wait()
            keep_json(directory / (label + ".timeout.json"), {"seconds": seconds})
            raise InvalidRun("deadline expired; supervisor must inspect descendants") from failure
    keep_json(directory / (label + ".exit.json"), {"exit_code": code})
    return code


def mutate(source, entry):
    name = "/".join(entry["path_parts"])
    require(name.startswith(OWNED) and ".." not in Path(name).parts and
            not name.endswith("_test.go"), "mutation exceeds production ownership")
    path = source / name
    original = path.read_bytes()
    before, after = entry["before"].encode(), entry["after"].encode()
    require(before != after and original.count(before) == 1,
            "mutation anchor is stale or ambiguous")
    changed = original.replace(before, after, 1)
    path.write_bytes(changed)
    require(path.read_bytes() == changed, "mutation read-back differs")
    return name


def focused_output(events, test):
    return "".join(row.get("Output", "") for row in events
                   if row.get("Test") == test or row.get("Test", "").startswith(test + "/"))


def phase(directory, source, entry, name, tools, environment, installed_root, faults):
    binary = directory / "linux.test"
    command = [tools["go"], "test", "-c", "-trimpath", "-buildvcs=false",
               "-mod=readonly", "-o", str(binary)]
    if faults:
        command.extend(["-tags", "laneboss_faults"])
    command.append("./internal/v2/isolation/linux")
    code = capture(directory, "build", command, source, environment, 600)
    require(code == 0 and binary.is_file(), "build failure is not a killed mutation")
    artifact = {"sha256": sha(binary.read_bytes()), "bytes": binary.stat().st_size}
    keep_json(directory / "binary.json", artifact)
    require(capture(directory, "build-info", [tools["go"], "version", "-m", str(binary)],
                    source, environment, 30) == 0, "binary build metadata is unavailable")
    target = installed_root / name / "linux.test"
    code = capture(directory, "install-dir", [tools["sudo"], "-n", "install", "-d",
                   "-o", "root", "-g", "root", "-m", "0755", str(target.parent)],
                   source, environment, 30)
    require(code == 0, "root-owned test directory installation failed")
    code = capture(directory, "install", [tools["sudo"], "-n", "install", "-o", "root",
                   "-g", "root", "-m", "0755", str(binary), str(target)],
                   source, environment, 30)
    require(code == 0 and sha(target.read_bytes()) == artifact["sha256"],
            "installed test bytes differ")
    info = target.stat()
    require(info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o755,
            "test bootstrap is not root-owned and immutable to the test identity")
    test = entry["test"]
    require(re.fullmatch(r"Test[A-Za-z0-9_]+", test), "invalid focused test name")
    pattern = "^" + re.escape(test) + "$"
    command = [tools["go"], "tool", "test2json", "-t", "-p", "linux",
               str(target), "-test.v=test2json", "-test.count=1",
               "-test.timeout=10m", "-test.run=" + pattern]
    code = capture(directory, "test", command, source, environment, 660)
    require(sha(target.read_bytes()) == artifact["sha256"] and
            sha(binary.read_bytes()) == artifact["sha256"], "tested binary changed")
    events = [json.loads(line) for line in (directory / "test.stdout").read_bytes().splitlines()]
    require(events and not any(row.get("Action") == "skip" for row in events),
            "missing or skipped observations cannot pass")
    reached = any(row.get("Action") == "run" and row.get("Test") == test for row in events)
    passed = any(row.get("Action") == "pass" and row.get("Test") == test for row in events)
    failed = sorted({row["Test"] for row in events
                     if row.get("Action") == "fail" and "Test" in row})
    output = focused_output(events, test)
    killed = (code != 0 and reached and test in failed and
              entry["failure_contains"] in output)
    observation = {"phase": name, "test": test, "reached": reached,
                   "observed_exit": code, "failed_tests": failed,
                   "target_assertion_failed": killed, "target_passed": passed,
                   "binary": artifact, "installed_binary": str(target)}
    keep_json(directory / "observation.json", observation)
    require(killed if name == "red" else code == 0 and reached and passed and not failed,
            "mutation survived or failed at another assertion" if name == "red"
            else "candidate focused control failed")
    return observation


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--mutation", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--module-cache", required=True, type=Path)
    parser.add_argument("--faults", action="store_true")
    args = parser.parse_args()
    require(sys.platform == "linux" and os.geteuid() != 0,
            "run only as the non-root observer on disposable Linux")
    os.umask(0o077)
    source, output = args.source.resolve(), args.output
    require(args.source.is_absolute() and output.is_absolute() and
            not output.exists() and not output.is_symlink(), "new absolute output required")
    require(output.name.startswith("lb-v2-linux-"), "output must carry the lane name")
    require(source not in output.resolve().parents and output.resolve() not in source.parents,
            "source and output must be disjoint")
    require(args.module_cache.is_absolute() and args.module_cache.is_dir(),
            "the supervisor's populated Go module cache is required")
    catalog = json.loads(Path(__file__).with_name("mutations.json").read_bytes())
    require(catalog["schema"] == "laneboss.linux-mutations.v2", "invalid mutation catalog")
    entries = [row for row in catalog["mutations"] if row["id"] == args.mutation]
    require(len(entries) == 1, "unknown or duplicate mutation")
    entry = entries[0]
    tools = {name: shutil.which(name) for name in ("go", "sudo")}
    require(all(tools.values()), "Go and noninteractive sudo are required")
    output.mkdir(mode=0o700, parents=True)
    home, cache = output / "home", output / "go-cache"
    home.mkdir(mode=0o700)
    cache.mkdir(mode=0o700)
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C",
                   "HOME": str(home), "GOCACHE": str(cache),
                   "GOMODCACHE": str(args.module_cache), "GOPROXY": "off",
                   "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOOS": "linux"}
    manifest = inputs(source)
    keep_json(output / "input-manifest.json", manifest)
    keep_json(output / "selected-mutation.json", entry)
    snapshot = output / "inputs"
    copy_inputs(source, snapshot, manifest)
    with tarfile.open(output / "inputs.tar", "w") as archive:
        for row in manifest:
            path = snapshot / row["path"]
            info = archive.gettarinfo(path, arcname=row["path"])
            info.uname, info.gname = "", ""
            with path.open("rb") as stream:
                archive.addfile(info, stream)
    report = {"schema": "laneboss.linux-mutation-result.v2", "mutation_id": entry["id"],
              "contract_revision": "v2.0-draft.4", "input_sha256": tree_sha(manifest),
              "scope": entry["scope"], "faults": args.faults, "phases": [], "complete": False}
    directory = None
    installed_root = Path("/opt/lb-v2-linux-red") / ("lb-v2-linux-" + secrets.token_hex(12))
    report["retained_installation"] = str(installed_root)
    try:
        module, dependency = retain_module(snapshot, args.module_cache, output)
        report["dependency_sha256"] = tree_sha(dependency)
        require(capture(output, "go-version", [tools["go"], "version"], source,
                        environment, 30) == 0, "Go version observation failed")
        for name in ("red", "green"):
            directory = output / name
            directory.mkdir(mode=0o700)
            copy = directory / "source"
            copy_inputs(snapshot, copy, manifest)
            changed = mutate(copy, entry) if name == "red" else None
            after = inputs(copy)
            differences = [row["path"] for row, baseline in zip(after, manifest) if row != baseline]
            require(len(after) == len(manifest) and differences == ([changed] if changed else []),
                    "source changes exceed the selected mutation")
            keep_json(directory / "source-manifest.json", after)
            observed = phase(directory, copy, entry, name, tools, environment, installed_root, args.faults)
            require(inputs(copy) == after, "phase source changed during execution")
            require(module_inputs(module) == dependency, "dependency source changed during execution")
            report["phases"].append(observed)
            print(("KILLED: " if name == "red" else "PASS: ") + entry["id"])
        require(inputs(source) == manifest, "original source changed during execution")
        require(report["phases"][0]["binary"]["sha256"] != report["phases"][1]["binary"]["sha256"],
                "red and candidate binary digests must differ")
        report["complete"] = True
    except (InvalidRun, OSError, ValueError, KeyError, TypeError) as failure:
        report["error"] = str(failure)
        if directory is not None and (directory / "observation.json").is_file():
            observed = json.loads((directory / "observation.json").read_bytes())
            if not any(row["phase"] == observed["phase"] for row in report["phases"]):
                report["phases"].append(observed)
        print("FAIL: mutation pair incomplete; retain all source and process evidence", file=sys.stderr)
    keep_json(output / "result.json", report)
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
