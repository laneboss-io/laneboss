#!/usr/bin/env python3
"""Linux black-box regressions for mutation setup evidence and defaults."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import stat
import subprocess
import sys

sys.dont_write_bytecode = True


class CheckFailure(Exception):
    """Fixed assertion diagnostics only, never captured values."""


def check(condition, message):
    if not condition:
        raise CheckFailure(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    data = json.dumps(value, sort_keys=True, indent=2).encode() + b"\n"
    with path.open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def load(path):
    check(path.is_file(), "runner did not retain its result")
    return json.loads(path.read_bytes())


def scripts(source, output, fault=None):
    output.mkdir(mode=0o700)
    case = source / "e2e" / "v2" / "cases" / "secrets"
    for name in ("mutate.py", "mutations.py"):
        shutil.copyfile(case / name, output / name)
        (output / name).chmod(0o600)
    path = output / "mutate.py"
    text = path.read_text(encoding="utf-8")
    before = text
    if fault == "diagnostics":
        anchor = "    def finish(self, code):\n"
        check(text.count(anchor) == 1, "runner evidence mutation anchor changed")
        text = text.replace(anchor, anchor + "        return code\n", 1)
    elif fault == "defaults":
        anchor = '    step("tool-discovery")\n'
        check(text.count(anchor) == 1, "runner default mutation anchor changed")
        text = text.replace(anchor, anchor +
            '    require(args.go is not None and args.module_cache is not None and args.build_cache is not None,\n'
            '            "explicit Go and cache flags required")\n', 1)
    if fault is not None:
        check(text != before, "runner fault did not change source")
        path.write_text(text, encoding="utf-8")
    save(output / "inputs.json", {name: sha((output / name).read_bytes())
                                 for name in ("mutate.py", "mutations.py")})
    return path


def invoke(runner, source, root, name, env, arguments):
    command = [sys.executable, str(runner), *arguments]
    out_path, err_path = root / (name + ".out"), root / (name + ".err")
    with out_path.open("xb") as out, err_path.open("xb") as err:
        os.chmod(out_path, 0o600)
        os.chmod(err_path, 0o600)
        process = subprocess.Popen(command, cwd=source, env=env, stdout=out, stderr=err,
                                   start_new_session=True)
        save(root / (name + "-started.json"), {"pid": process.pid, "argv": command})
        try:
            code = process.wait(timeout=1500)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise CheckFailure("runner regression command timed out")
    record = {"argv": command, "exit": code, "stdout": out_path.name,
              "stderr": err_path.name, "stdout_sha256": sha(out_path.read_bytes()),
              "stderr_sha256": sha(err_path.read_bytes())}
    save(root / (name + ".json"), record)
    return record, out_path.read_bytes(), err_path.read_bytes()


def diagnostic(record, stderr, expected_step):
    check(record["exit"] == 2, "setup refusal used an unexpected process exit")
    lines = [line for line in stderr.splitlines() if line.strip()]
    check(len(lines) == 1 and lines[0].startswith(b"{"),
          "setup failure has no structured diagnostic")
    printed = json.loads(lines[0])
    check(printed.get("status") == "setup_failure" and printed.get("step") == expected_step and
          {"command", "exit", "diagnostic", "evidence"} <= set(printed),
          "setup diagnostic lost its step, command, exit or cause")
    report_path = Path(printed["evidence"])
    report = load(report_path)
    check(report["status"] == "setup_failure" and report["killed"] is False and
          report["failure"] == {key: value for key, value in printed.items()
                                if key not in {"status", "evidence"}},
          "printed setup cause differs from retained evidence")
    info = report_path.stat()
    check(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,
          "failure evidence is not private and identity-owned")
    return report_path.parent, report, printed


def scenario(kind, runner, source, root, label, env, modules):
    output = root / (label + "-evidence")
    base = ["--mutation", "directory-mode", "--source", str(source), "--output", str(output)]
    marker = None
    if kind == "missing-source":
        base[3] = str(root / (label + "-absent-source"))
    elif kind == "wrong-tool":
        base += ["--go", "/usr/bin/false", "--module-cache", str(modules),
                 "--build-cache", str(root / "explicit-build-cache")]
    elif kind == "arguments":
        marker = secrets.token_hex(24).encode()
        base += ["--unrecognized=" + marker.decode()]
    elif kind == "existing-output":
        output.mkdir(mode=0o700)
        marker = secrets.token_bytes(64)
        (output / "retained-input").write_bytes(marker)
    elif kind == "blocked":
        base = ["--mutation", "refresh-race", "--output", str(output)]
    record, stdout, stderr = invoke(runner, source, root, label, env, base)
    if kind == "default":
        check(record["exit"] == 0, "minimal invocation did not complete a real red/green mutation")
        report = load(output / "result.json")
        check(report["status"] == "killed_then_green" and report["killed"] is True and
              report["red"]["run"]["exit"] != 0 and report["green"]["run"]["exit"] == 0 and
              "TestDirectoryModeDrift" in report["red"]["failed_tests"] and
              "TestDirectoryModeDrift" in report["green"]["passed_tests"],
              "minimal invocation lacks actual targeted red and green runs")
        for phase in ("red", "green"):
            binary = report[phase]["binary"]
            check(sha((output / binary["path"]).read_bytes()) == binary["sha256"],
                  "minimal invocation lost its tested binary bytes")
        check(report["source_sha256"] != report["mutant_source_sha256"],
              "minimal invocation tested identical source copies")
    elif kind == "blocked":
        report = load(output / "result.json")
        check(record["exit"] == 69 and report["status"] == "not_implemented" and
              report["error"]["code"] == "not_implemented" and report["killed"] is False,
              "blocked live mutation became a killed control")
    else:
        expected_step = {"missing-source": "source-resolution", "wrong-tool": "go-version-verify",
                         "arguments": "arguments", "existing-output": "evidence-directory"}[kind]
        evidence, report, printed = diagnostic(record, stderr, expected_step)
        if kind == "missing-source":
            check(printed["errno"] == 2 and printed["error_type"] == "FileNotFoundError" and
                  printed["command"] is None and printed["exit"] is None,
                  "missing source did not retain its actual filesystem cause")
        elif kind == "wrong-tool":
            command = load(evidence / "go-version.json")
            check(printed["exit"] == 1 and printed["command"]["argv"] == ["false", "version"] and
                  command["argv"] == ["/usr/bin/false", "version"] and command["exit"] == 1,
                  "nonzero tool lost its actual command or exit")
            for channel in ("stdout", "stderr"):
                ref = command[channel]
                data = (evidence / ref["path"]).read_bytes()
                check(sha(data) == ref["sha256"] and len(data) == ref["bytes"],
                      "nonzero command lost primary diagnostics")
        elif kind == "arguments":
            check(marker not in stdout + stderr, "invalid option value leaked into diagnostics")
        elif kind == "existing-output":
            check((output / "retained-input").read_bytes() == marker and
                  evidence != output and not (output / "result.json").exists(),
                  "existing evidence was overwritten")
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    check(sys.platform == "linux", "runner checks require the authorized disposable Linux box")
    source, root = args.source.resolve(strict=True), args.output.resolve()
    check(not root.exists() and not root.is_relative_to(source) and not source.is_relative_to(root),
          "runner checks need a fresh output outside source")
    root.mkdir(mode=0o700, parents=True)
    report = {"schema": "laneboss.secret-runner-checks.v2", "status": "failed", "controls": []}
    try:
        for name in ("home", "tmp"):
            (root / name).mkdir(mode=0o700)
        selected = shutil.which("go")
        check(selected is not None, "pinned Go tool is missing")
        modules = os.environ.get("GOMODCACHE")
        if not modules:
            selected_path = os.environ.get("GOPATH")
            modules = str((Path(selected_path.split(os.pathsep)[0]) if selected_path else
                           Path.home() / "go") / "pkg" / "mod")
        modules = Path(modules).resolve(strict=True)
        env = {"HOME": str(root / "home"), "TMPDIR": str(root / "tmp"),
               "PATH": str(Path(selected).resolve(strict=True).parent) + ":/usr/bin:/bin", "LANG": "C.UTF-8",
               "GOMODCACHE": str(modules)}
        green = scripts(source, root / "green-scripts")
        red_diagnostics = scripts(source, root / "red-diagnostics", "diagnostics")
        for kind in ("missing-source", "wrong-tool", "arguments", "existing-output", "blocked"):
            expected = "runner did not retain its result" if kind == "blocked" else \
                       "setup failure has no structured diagnostic"
            try:
                scenario(kind, red_diagnostics, source, root, "red-" + kind, env, modules)
            except CheckFailure as error:
                observed_failure = str(error)
                check(observed_failure == expected, "diagnostic mutant failed for a different reason")
            else:
                raise CheckFailure("missing-evidence runner mutation survived")
            candidate = scenario(kind, green, source, root, "green-" + kind, env, modules)
            report["controls"].append({"name": kind, "red_failure": observed_failure,
                                       "red": load(root / ("red-" + kind + ".json")), "green": candidate})
        red_defaults = scripts(source, root / "red-defaults", "defaults")
        try:
            scenario("default", red_defaults, source, root, "red-default", env, modules)
        except CheckFailure as error:
            observed_default = str(error)
            check(observed_default == "minimal invocation did not complete a real red/green mutation",
                  "default-option mutant failed for a different reason")
            refusal = load(root / "red-default-evidence" / "result.json")
            check(refusal["status"] == "setup_failure" and refusal["killed"] is False and
                  refusal["failure"]["step"] == "tool-discovery" and
                  refusal["failure"]["diagnostic"] == "explicit Go and cache flags required",
                  "default-option mutant did not reach its intended missing-option check")
        else:
            raise CheckFailure("explicit-options runner mutation survived")
        candidate = scenario("default", green, source, root, "green-default", env, modules)
        report["controls"].append({"name": "default", "red_failure": observed_default,
                                   "red": load(root / "red-default.json"), "green": candidate})
        report["status"] = "red_then_green"
        save(root / "result.json", report)
        print("secrets runner checks: red then green")
        return 0
    except (CheckFailure, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        report["diagnostic"] = str(error) if isinstance(error, CheckFailure) else type(error).__name__
        save(root / "result.json", report)
        print("secrets runner checks: failed; retain evidence", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
