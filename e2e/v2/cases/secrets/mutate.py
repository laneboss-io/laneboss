#!/usr/bin/env python3
"""Apply one named fault to retained copies; prove red, then green on Linux."""

import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
TRACE = None


class Failure(Exception):
    """Only fixed, value-free diagnostics belong in this exception."""


def require(condition, diagnostic):
    if not condition:
        raise Failure(diagnostic)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    temporary = path.with_name(path.name + ".pending")
    with temporary.open("x", encoding="utf-8") as output:
        os.chmod(temporary, 0o600)
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's message may contain an accidentally supplied credential.
        raise Failure("invalid mutation options; use --help for supported flags")


class Evidence:
    def __init__(self):
        self.root = None
        self.current = {"step": "arguments", "command": None, "exit": None}
        self.report = {"schema": "laneboss.secret-mutation.v2",
                       "contract_revision": "v2.0-draft.4", "mutation": None,
                       "killed": False, "status": "setup_failure"}

    def at(self, name, keep_command=False):
        previous = self.current
        self.current = {"step": name, "command": None, "exit": None}
        if keep_command:
            self.current.update(command=previous["command"], exit=previous["exit"])

    def create(self, output, source):
        self.at("evidence-directory")
        require(output is not None, "mutation and output are required")
        root = output.resolve()
        if source is not None:
            candidate = source.resolve()
            require(not root.is_relative_to(candidate) and not candidate.is_relative_to(root),
                    "source and disposable output scopes must be disjoint")
        require(root != Path("/") and root != Path.home(),
                "output must name a new lane evidence directory")
        require(not root.exists() and not root.is_symlink(),
                "output must be a new disposable directory; existing evidence is preserved")
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.root = root
        write_json(root / "progress.json", self.current)

    def fallback(self):
        previous = self.root
        self.root = Path(tempfile.mkdtemp(prefix="lb-v2-secrets-setup-")).resolve()
        self.root.chmod(0o700)
        if previous is not None:
            self.report["previous_evidence_root"] = str(previous)

    def fail(self, error):
        diagnostic = str(error) if isinstance(error, Failure) else {
            OSError: "filesystem or executable operation failed",
            ValueError: "invalid retained JSON, encoding or catalogue data",
            KeyError: "required catalogue or evidence field is absent",
            TypeError: "catalogue or evidence has an invalid type",
            ImportError: "mutation catalogue could not be loaded",
            SyntaxError: "mutation catalogue contains invalid Python syntax",
            subprocess.SubprocessError: "owned subprocess operation failed",
        }.get(next((kind for kind in (OSError, ValueError, KeyError, TypeError,
                                     ImportError, SyntaxError, subprocess.SubprocessError)
                    if isinstance(error, kind)), None), "mutation setup failed")
        detail = dict(self.current, diagnostic=diagnostic, error_type=type(error).__name__)
        if isinstance(error, OSError):
            detail["errno"] = error.errno
        self.report.update(killed=False, status="setup_failure", failure=detail)
        return detail

    def retain_runner(self):
        directory = self.root / "runner-inputs"
        directory.mkdir(mode=0o700)
        inputs = []
        for name in ("mutate.py", "mutations.py"):
            source = Path(__file__).with_name(name)
            if not source.is_file():
                inputs.append({"path": name, "present": False})
                continue
            target = directory / name
            shutil.copyfile(source, target)
            target.chmod(0o600)
            inputs.append(dict(artifact(target, self.root), present=True))
        self.report["runner_inputs"] = inputs

    def finish(self, code):
        self.report["exit"] = code
        self.report["last_step"] = self.current["step"]
        try:
            if self.root is None:
                self.fallback()
            self.retain_runner()
            write_json(self.root / "result.json", self.report)
        except OSError as error:
            self.fail(error)
            self.report["exit"] = 2
            try:
                self.fallback()
                self.retain_runner()
                write_json(self.root / "result.json", self.report)
            except OSError as final_error:
                print(json.dumps({"status": "setup_failure", "step": "retain-evidence",
                                  "command": self.current["command"],
                                  "exit": self.current["exit"],
                                  "diagnostic": "evidence storage is unavailable",
                                  "errno": final_error.errno}, sort_keys=True), file=sys.stderr)
                return 2
            code = 2
        if self.report["status"] == "setup_failure":
            print(json.dumps(dict(self.report["failure"], status="setup_failure",
                                  evidence=str(self.root / "result.json")),
                             sort_keys=True), file=sys.stderr)
        return code


def step(name, keep_command=False):
    if TRACE is not None:
        TRACE.at(name, keep_command)


def below(root, relative):
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute(),
            "relative source path required")
    require(".." not in Path(relative).parts and ".git" not in Path(relative).parts,
            "unsafe source path")
    path = root / relative
    require(path.parent.resolve().is_relative_to(root.resolve()), "source parent escaped")
    return path


def artifact(path, root):
    data = path.read_bytes()
    return {"path": str(path.relative_to(root)), "sha256": sha(data), "bytes": len(data)}


def environment(root, go, modules, cache):
    # No inherited credentials, proxy settings or host HOME enter a fixture.
    return {"HOME": str(root / "home"), "TMPDIR": str(root / "tmp"),
            "PATH": str(go.parent) + ":/usr/bin:/bin", "LANG": "C.UTF-8",
            "GOCACHE": str(cache), "GOMODCACHE": str(modules),
            "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=readonly",
            "GOTELEMETRY": "off", "GOWORK": "off", "GOOS": "linux", "CGO_ENABLED": "1"}


def public_command(args, root, cwd, label):
    # Exact argv and primary diagnostics stay in private command receipts.
    # The terminal gets the fixed tool family and redacted path arguments.
    basename = Path(args[0]).name
    program = basename if re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", basename) else "<EXECUTABLE>"
    visible = [program]
    for argument in args[1:]:
        if Path(argument).is_absolute():
            if Path(argument).is_relative_to(root):
                visible.append("<EVIDENCE>/" + str(Path(argument).relative_to(root)))
            elif Path(argument).is_relative_to(cwd):
                visible.append("<SOURCE>/" + str(Path(argument).relative_to(cwd)))
            else:
                visible.append("<PATH>")
        else:
            visible.append(argument)
    return {"argv": visible, "receipt": label + ".json",
            "stdout": label + ".out", "stderr": label + ".err"}


def command(args, cwd, env, root, label, seconds):
    step(label)
    out_path, err_path = root / (label + ".out"), root / (label + ".err")
    receipt = {"argv": args, "exit": None, "leader_pid": None, "quiescent": None}
    if TRACE is not None:
        TRACE.current["command"] = public_command(args, root, cwd, label)
        write_json(root / "progress.json", TRACE.current)
    process, timed_out = None, False
    try:
        with out_path.open("xb") as out, err_path.open("xb") as err:
            os.chmod(out_path, 0o600)
            os.chmod(err_path, 0o600)
            process = subprocess.Popen(args, cwd=cwd, env=env, stdout=out, stderr=err,
                                       start_new_session=True)
            receipt["leader_pid"] = process.pid
            write_json(root / (label + "-started.json"), {"leader_pid": process.pid})
            try:
                receipt["exit"] = process.wait(timeout=seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                receipt["exit"] = process.wait()
    except OSError as error:
        receipt["launch_error"] = {"type": type(error).__name__, "errno": error.errno}
        raise
    finally:
        if process is not None:
            if process.poll() is None:
                # A journal/write failure must not orphan our still-running PID.
                os.killpg(process.pid, signal.SIGKILL)
                receipt["exit"] = process.wait()
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                receipt["quiescent"] = True
            else:
                receipt["quiescent"] = False
        receipt["timed_out"] = timed_out
        for name, path in (("stdout", out_path), ("stderr", err_path)):
            if path.is_file():
                receipt[name] = artifact(path, root)
        write_json(root / (label + ".json"), receipt)
        if TRACE is not None:
            TRACE.current["exit"] = receipt["exit"]
            write_json(root / "progress.json", TRACE.current)
    require(not timed_out, "owned command timed out; inspect retained containment")
    require(receipt["quiescent"] is True, "owned command left surviving process-group members")
    return receipt, out_path, err_path


def inventory_error(error):
    raise error


def source_paths(source, supplied, env, root):
    if supplied is not None:
        step("source-manifest")
        paths = json.loads(supplied.read_bytes())
        require(isinstance(paths, list), "source manifest must be a path array")
        inventory = "supplied_manifest"
    elif (source / ".git").exists():
        receipt, output, _ = command(["/usr/bin/git", "ls-files", "-z", "--cached",
                                     "--others", "--exclude-standard"], source, env,
                                    root, "source-list", 30)
        require(receipt["exit"] == 0, "Git source inventory failed; retain its diagnostics")
        paths = [part.decode("utf-8") for part in output.read_bytes().split(b"\0") if part]
        inventory = "git"
    else:
        # Source archives deliberately contain no Git metadata. Inventory the
        # supplied module only, never follow a link into a home/credential tree.
        step("source-inventory")
        paths = []
        for parent, directories, files in os.walk(source, followlinks=False, onerror=inventory_error):
            directories.sort()
            files.sort()
            for name in list(directories):
                path = Path(parent) / name
                if name in {".git", "__pycache__"}:
                    directories.remove(name)
                elif path.is_symlink():
                    directories.remove(name)
                    paths.append(str(path.relative_to(source)))
            for name in files:
                if name != ".git" and not name.endswith((".pyc", ".pyo")):
                    paths.append(str((Path(parent) / name).relative_to(source)))
        inventory = "archive_tree"
    require(paths and len(paths) == len(set(paths)), "source file manifest is empty or duplicated")
    require("go.mod" in paths and "go.sum" in paths, "source module inputs are missing")
    write_json(root / "source-files.json", sorted(paths))
    write_json(root / "source-inventory.json", {"kind": inventory, "files": len(paths)})
    return sorted(paths)

def snapshot(source, destination, paths):
    destination.mkdir(mode=0o700)
    entries = []
    for relative in paths:
        original, target = below(source, relative), below(destination, relative)
        if not original.exists() and not original.is_symlink():
            continue  # Deleted tracked paths are not build inputs.
        mode = original.lstat().st_mode
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if stat.S_ISLNK(mode):
            link = os.readlink(original)
            require(not Path(link).is_absolute() and
                    original.resolve().is_relative_to(source), "source link escapes")
            target.symlink_to(link)
            entries.append({"path": relative, "kind": "symlink", "target": link})
        else:
            require(stat.S_ISREG(mode), "special source input refused")
            shutil.copyfile(original, target)
            target.chmod(stat.S_IMODE(mode))
            entries.append({"path": relative, "kind": "file", "mode": stat.S_IMODE(mode),
                            "sha256": sha(target.read_bytes()), "bytes": target.stat().st_size})
    return entries


def manifest(root):
    entries = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            entries.append({"path": str(path.relative_to(root)), "target": os.readlink(path)})
        elif path.is_file():
            entries.append({"path": str(path.relative_to(root)), "sha256": sha(path.read_bytes()),
                            "bytes": path.stat().st_size})
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {"sha256": sha(encoded), "files": entries}


def apply_one(root, specification):
    changes = []
    for operation in specification["edits"]:
        require((operation["path"].startswith("internal/v2/secrets/") or
                 operation["path"] in {"internal/v2/cli/commands_secrets.go",
                                       "internal/v2/cli/internal_secrets.go"}) and
                operation["path"].endswith(".go") and
                not operation["path"].endswith("_test.go"),
                "mutation may only edit secrets-owned production Go files")
        path = below(root, operation["path"])
        require(not path.is_symlink(), "mutation target must be a regular file")
        data = path.read_text(encoding="utf-8")
        anchor = operation["function"]
        require(data.count(anchor) == 1, "mutation function anchor changed")
        start = data.index(anchor)
        end = data.find("\nfunc ", start + len(anchor))
        if end < 0:
            end = len(data)
        region = data[start:end]
        require(region.count(operation["before"]) == 1, "mutation check anchor changed")
        changed = region.replace(operation["before"], operation["after"], 1)
        result = data[:start] + changed + data[end:]
        require(result != data, "mutation did not alter its input")
        path.write_text(result, encoding="utf-8")
        changes.append({"path": operation["path"], "function": anchor,
                        "before_sha256": sha(data.encode()), "after_sha256": sha(result.encode())})
    return changes


def test_pattern(names):
    components = [name.split("/") for name in names]
    require(len({len(parts) for parts in components}) == 1, "mixed test selector depths")
    return "/".join("^(" + "|".join(re.escape(parts[index]) for parts in components) + ")$"
                    for index in range(len(components[0])))


def execute_phase(phase, tree, specification, args, env, root):
    binary = root / (phase + ".test")
    build = [str(args.go), "test", "-c", "-race", "-o", str(binary)]
    if args.tags:
        build.extend(("-tags", args.tags))
    build.append(specification["package"])
    build_receipt, _, _ = command(build, tree, env, root, phase + "-build", args.timeout_seconds)
    step(phase + "-build-verify", keep_command=True)
    require(build_receipt["exit"] == 0, "test binary did not compile; not a killed mutation")
    require(binary.is_file(), "test build produced no retained binary")
    invocation = [str(args.go), "tool", "test2json", "-p", specification["package"],
                  str(binary), "-test.v", "-test.count=1", "-test.timeout=90s",
                  "-test.run", test_pattern(specification["tests"])]
    receipt, output, _ = command(invocation, tree, env, root, phase + "-tests", args.timeout_seconds)
    step(phase + "-tests-verify", keep_command=True)
    events = [json.loads(line) for line in output.read_bytes().splitlines() if line.strip()]
    require(events, "test runner produced no structured events")
    ran = {event["Test"] for event in events if event.get("Action") == "run" and "Test" in event}
    failed = sorted({event["Test"] for event in events if event.get("Action") == "fail" and "Test" in event})
    passed = {event["Test"] for event in events if event.get("Action") == "pass" and "Test" in event}
    summary = {"binary": artifact(binary, root), "build": build_receipt, "run": receipt,
               "failed_tests": failed, "passed_tests": sorted(passed), "reached_tests": sorted(ran)}
    write_json(root / (phase + "-summary.json"), summary)
    require(not any(event.get("Action") == "skip" for event in events), "focused test skipped")
    require(all(name in ran for name in specification["tests"]), "target test was not reached")
    if phase == "red":
        require(receipt["exit"] != 0 and all(name in failed for name in specification["tests"]),
                "mutation survived or failed outside its target tests")
        for name, expected in specification["failure_text"].items():
            text = "".join(event.get("Output", "") for event in events
                           if event.get("Test") == name or
                           event.get("Test", "").startswith(name + "/"))
            require(expected in text, "target failed for a different reason")
    else:
        require(receipt["exit"] == 0 and not failed and
                all(name in passed for name in specification["tests"]),
                "unmodified focused tests did not pass")
    return summary


def resolve_tools(args, root, source):
    step("tool-discovery")
    discovery = {"go": "explicit", "module_cache": "explicit", "build_cache": "explicit"}
    if args.go is None:
        selected = shutil.which("go")
        require(selected is not None, "Go is not on PATH; supply --go with the pinned tool")
        args.go = Path(selected).resolve(strict=True)
        discovery["go"] = "PATH"
    require(args.go.is_absolute(), "--go must name an absolute executable")
    args.go = args.go.resolve(strict=True)
    require(args.go.is_file() and os.access(args.go, os.X_OK), "selected Go tool is not executable")
    # Read only these named public Go-cache selectors, never enumerate env.
    if args.module_cache is None:
        selected = os.environ.get("GOMODCACHE")
        if selected:
            args.module_cache = Path(selected)
            discovery["module_cache"] = "GOMODCACHE"
        else:
            selected = os.environ.get("GOPATH")
            first = Path(selected.split(os.pathsep)[0]) if selected else Path.home() / "go"
            args.module_cache = first / "pkg" / "mod"
            discovery["module_cache"] = "GOPATH" if selected else "default_go_path"
    if args.build_cache is None:
        args.build_cache = Path(tempfile.gettempdir()) / ("lb-v2-secrets-build-" + str(os.getuid()))
        discovery["build_cache"] = "private_temporary_cache"
    step("cache-scopes")
    require(args.module_cache.is_absolute() and args.build_cache.is_absolute(),
            "Go cache paths must be absolute")
    for cache in (args.module_cache.resolve(), args.build_cache.resolve()):
        require(not cache.is_relative_to(source) and not source.is_relative_to(cache) and
                not cache.is_relative_to(root) and not root.is_relative_to(cache),
                "source, cache and evidence scopes must be disjoint")
    require(args.module_cache.resolve() != args.build_cache.resolve(),
            "module and build caches must be separate")
    require(args.module_cache.is_dir(), "preloaded public module cache is absent; supply --module-cache")
    require(not args.build_cache.is_symlink(), "build cache must not be a symlink")
    args.build_cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = args.build_cache.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o022 == 0,
            "build cache must be an ordinary owned directory without shared writes")
    if discovery["build_cache"] == "private_temporary_cache":
        require(stat.S_IMODE(info.st_mode) == 0o700, "default build cache must remain private")
    args.module_cache, args.build_cache = args.module_cache.resolve(), args.build_cache.resolve()
    write_json(root / "tool-discovery.json", {"sources": discovery,
               "module_cache_available": args.module_cache.is_dir(),
               "build_cache_private": stat.S_IMODE(info.st_mode) == 0o700})
    return environment(root, args.go, args.module_cache, args.build_cache)


def main(argv=None):
    global TRACE
    trace = Evidence()
    TRACE = trace
    code = 2
    try:
        step("catalogue")
        catalogue = importlib.import_module("mutations")
        parser = Parser()
        parser.add_argument("--list", action="store_true")
        parser.add_argument("--mutation", choices=sorted(catalogue.MUTATIONS))
        parser.add_argument("--source", type=Path)
        parser.add_argument("--source-manifest", type=Path)
        parser.add_argument("--output", type=Path)
        parser.add_argument("--go", type=Path)
        parser.add_argument("--module-cache", type=Path)
        parser.add_argument("--build-cache", type=Path)
        parser.add_argument("--tags", choices=("", "laneboss_faults"), default="")
        parser.add_argument("--timeout-seconds", type=int, default=600)
        step("arguments")
        args = parser.parse_args(argv)
        if args.list:
            for row in catalogue.CATALOG:
                print(row["id"] + ": " + ("available" if row["available"] else "blocked") +
                      "; " + ",".join(row["tests"]))
            return 0
        require(args.mutation is not None, "mutation and output are required")
        trace.report.update(mutation=args.mutation, tags=args.tags)
        specification = catalogue.MUTATIONS[args.mutation]
        trace.report.update(scope=specification["scope"], target_tests=specification["tests"])
        trace.create(args.output, args.source)
        root = trace.root
        write_json(root / "invocation.json", {
            "mutation": args.mutation, "source": str(args.source) if args.source is not None else None,
            "go": str(args.go) if args.go is not None else None,
            "module_cache": str(args.module_cache) if args.module_cache is not None else None,
            "build_cache": str(args.build_cache) if args.build_cache is not None else None,
            "source_manifest": str(args.source_manifest) if args.source_manifest is not None else None,
            "tags": args.tags, "timeout_seconds": args.timeout_seconds})
        step("platform")
        require(sys.platform == "linux", "mutation execution requires the authorized disposable Linux box")
        require(1 <= args.timeout_seconds <= 3600, "command timeout must be between 1 and 3600 seconds")
        if not specification["available"]:
            step("blocked-live")
            trace.report.update(status="not_implemented", dependency=specification["dependency"],
                                error={"code": "not_implemented", "owner": "lb-v2-secrets",
                                       "message": specification["dependency"],
                                       "instead": "Complete the named dependency and its live acceptance first."})
            return trace.finish(69)
        step("source-resolution")
        require(args.source is not None, "available mutations require --source")
        source = args.source.resolve(strict=True)
        require(source.is_dir() and source not in {Path("/"), Path.home()},
                "source must be a curated module directory, never an owner home")
        step("contract-revision")
        base = source / "internal" / "v2" / "api" / "base.go"
        require(re.search(rb'ContractRevision\s*=\s*"v2\.0-draft\.4"', base.read_bytes()) is not None,
                "mutation source is not the matched draft.4 contract")
        env = resolve_tools(args, root, source)
        step("tool-snapshot")
        shutil.copyfile(args.go, root / "go-tool")
        trace.report["go_tool"] = artifact(root / "go-tool", root)
        step("fixture-directories")
        for name in ("home", "tmp"):
            (root / name).mkdir(mode=0o700)
        receipt, output, _ = command([str(args.go), "version"], source, env, root, "go-version", 30)
        step("go-version-verify", keep_command=True)
        require(receipt["exit"] == 0 and b"go1.26." in output.read_bytes(), "pinned Go 1.26 tool is unavailable")
        paths = source_paths(source, args.source_manifest, env, root)
        step("green-source-copy")
        snapshot(source, root / "green-src", paths)
        step("red-source-copy")
        snapshot(source, root / "red-src", paths)
        step("source-copy-verify")
        original = manifest(root / "green-src")
        require(manifest(root / "red-src") == original, "source copies differ before mutation")
        write_json(root / "green-source.json", original)
        step("apply-mutation")
        trace.report["changes"] = apply_one(root / "red-src", specification)
        changed = manifest(root / "red-src")
        require(original["sha256"] != changed["sha256"], "red and green source digests match")
        write_json(root / "red-source.json", changed)
        trace.report["source_sha256"] = original["sha256"]
        trace.report["mutant_source_sha256"] = changed["sha256"]
        trace.report["red"] = execute_phase("red", root / "red-src", specification, args, env, root)
        step("red-source-integrity")
        require(manifest(root / "red-src") == changed, "red execution altered retained source inputs")
        require(manifest(root / "green-src") == original, "red execution altered the green source")
        trace.report["green"] = execute_phase("green", root / "green-src", specification, args, env, root)
        step("green-source-integrity")
        require(manifest(root / "green-src") == original, "green execution altered retained source inputs")
        trace.report.update(status="killed_then_green", killed=True)
        print(args.mutation + ": killed; " + ",".join(trace.report["red"]["failed_tests"]))
        code = 0
    except (Failure, OSError, ValueError, KeyError, TypeError, ImportError,
            argparse.ArgumentError, SyntaxError, subprocess.SubprocessError) as error:
        trace.fail(error)
    return trace.finish(code)


if __name__ == "__main__":
    sys.exit(main())
