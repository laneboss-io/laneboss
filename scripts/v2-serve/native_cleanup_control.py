"""Installed native-cleanup build control; disposable root Linux only.

The missing-port cell builds a real artifact whose store has no CleanupNative.
It must reach the exact Clean refusal after the real start/stop/archive path.
The candidate cell runs the same installed lifecycle harness, including native
helper-journal and independent workspace/Git readbacks. No port is stubbed.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time


def require(value, message):
    if not value:
        raise RuntimeError(message)


def save(path, data):
    with path.open("xb") as stream:
        require(stream.write(data) == len(data), "short control evidence write")
    require(path.read_bytes() == data, "control evidence readback differs")


def save_json(path, value):
    save(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def error_records(value):
    if isinstance(value, dict):
        if value.get("code") and value.get("owner"):
            yield value
        for child in value.values():
            yield from error_records(child)
    elif isinstance(value, list):
        for child in value:
            yield from error_records(child)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--mode", required=True, choices=("missing", "candidate"))
    args = parser.parse_args()
    require(platform.system() == "Linux" and os.geteuid() == 0,
            "native cleanup build control requires the disposable root Linux host")
    require(args.source.is_absolute() and args.evidence.is_absolute() and not args.evidence.exists(),
            "use an absolute source and fresh absolute evidence directory")
    os.umask(0o077)
    args.evidence.mkdir(mode=0o700, parents=True)
    try:
        verdict = execute(args)
    except BaseException:
        manifest(args.evidence)
        raise
    manifest(args.evidence)
    print(verdict)


def manifest(evidence):
    rows = []
    for path in sorted(evidence.rglob("*")):
        require(not path.is_symlink(), "linked control evidence")
        if path.is_file():
            rows.append(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + str(path.relative_to(evidence)))
    save(evidence / "MANIFEST.sha256", ("\n".join(rows) + "\n").encode())
    for row in rows:
        expected, name = row.split("  ", 1)
        require(hashlib.sha256((evidence / name).read_bytes()).hexdigest() == expected,
                "control evidence manifest differs")


def execute(args):
    harness = Path(__file__).resolve().parent
    save(args.evidence / "control.input.py", Path(__file__).read_bytes())
    target = args.source.resolve(strict=True) / "internal/v2/assembly/assembly.go"
    before = target.read_bytes()
    anchor = b"Clock: clock, CleanupNative: cleanup"
    require(before.count(anchor) == 1, "cleanup build control anchor is missing or ambiguous")
    after = before.replace(anchor, b"Clock: clock, CleanupNative: nil", 1) if args.mode == "missing" else before
    save(args.evidence / "assembly.before.go", before)
    save(args.evidence / "assembly.after.go", after)
    if args.mode == "missing":
        require(after != before, "missing-port build did not change its composition")
    # The harness retains the original archive plus exact before/after bytes,
    # then compiles its protected disposable stage. It never changes input Git.
    command = [sys.executable, "-I", "-B", str(harness / "run.py"), "--source", str(args.source),
               "--evidence", str(args.evidence / "installed"), "--suite", "lifecycle"]
    if args.mode == "missing":
        command.append("--cleanup-native-control")
    save_json(args.evidence / "command.json", command)
    started = time.monotonic()
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    save_json(args.evidence / "process.json", {"pid": process.pid})
    try:
        stdout, stderr = process.communicate(timeout=2400)
    except subprocess.TimeoutExpired:
        # Stop only this owned process by its PID, never by command pattern.
        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=15)
        save(args.evidence / "stdout", stdout)
        save(args.evidence / "stderr", stderr)
        save_json(args.evidence / "exit.json", {"exit_code": process.returncode, "timed_out": True})
        raise RuntimeError("installed cleanup control timed out; preserve the machine and evidence") from None
    save(args.evidence / "stdout", stdout)
    save(args.evidence / "stderr", stderr)
    save_json(args.evidence / "exit.json", {"exit_code": process.returncode, "timed_out": False,
              "elapsed_ms": round((time.monotonic() - started) * 1000)})
    require(target.read_bytes() == before, "installed control changed its input source")
    report = json.loads((args.evidence / "installed/report.json").read_bytes())
    config = report.get("config")
    require(isinstance(config, str) and config and Path(config).name == config,
            "installed report has an invalid evidence selector")
    build_copy = args.evidence / "installed" / config / "cleanup-control.after.go"
    require(build_copy.read_bytes() == after if args.mode == "missing" else not build_copy.exists(),
            "installed harness did not retain the intended build source")
    rows = {row["check"]: row for row in report["checks"]}
    require(report.get("presence") == "simulated" and report.get("human_approval") == "not_proven",
            "installed cleanup control lost its fixture provenance")
    if args.mode == "missing":
        require(process.returncode == 1 and report.get("failure", {}).get("check") == "lane.claudock.clean",
                "missing-port artifact did not reach the intended real Clean control")
        require(all(rows["lane.claudock." + step]["result"] == "pass" for step in
                    ("start", "running", "stop", "quiescent", "abandon", "archive")),
                "missing-port control failed an earlier real lifecycle prerequisite")
        refused = list(error_records(report["failure"]))
        require(any(error.get("code") == "not_implemented" and error.get("owner") == "lb-v2-admin" and
                    error.get("message") == "installed protected cleanup native ports is not implemented" for error in refused),
                "missing-port artifact failed for an unrelated reason")
        verdict = "PASS: missing-port build refused Clean at the native capability gate"
    else:
        require(process.returncode == 0 and report.get("failure") is None and
                all(rows[name]["result"] == "pass" for name in report["required_checks"]),
                "candidate installed lifecycle did not pass every required row")
        for driver in ("claudock", "codex"):
            native = rows["lane." + driver + ".clean"]["observed"].get("native_helper", {})
            require(native.get("helper_journal_complete") is True and native.get("worktree_measured") is True and
                    native.get("branch_measured") is True and native.get("journal_sha256"),
                    "candidate Clean lacks actual native helper and namespace evidence")
        verdict = "PASS: candidate Clean reached the real helper for both installed drivers"
    save_json(args.evidence / "verdict.json", {"mode": args.mode, "verdict": verdict,
              "source_sha256": hashlib.sha256(before).hexdigest(), "build_source_sha256": hashlib.sha256(after).hexdigest(),
              "presence": "simulated", "human_approval": "not_proven"})
    return verdict


if __name__ == "__main__":
    main()
