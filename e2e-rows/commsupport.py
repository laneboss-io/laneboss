"""Detached descendants for Linux boxes and the authorized Darwin-only rows."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from headless_support import require_headless
from reportsupport import run_request


LAUNCHER = '''#!/bin/sh
set -eu
mode=$1
output=$2
shift 2
case "$mode" in
    background) "$@" </dev/null >"$output" 2>&1 & ;;
    nohup) nohup "$@" </dev/null >"$output" 2>&1 & ;;
    setsid) setsid "$@" </dev/null >"$output" 2>&1 & ;;
    double-fork) "$@" </dev/null >"$output" 2>&1 ;;
    fork-session) "$@" </dev/null >"$output" 2>&1 ;;
    *) exit 64 ;;
esac
'''


def wait_file(path, deadline):
    while not path.is_file():
        if time.monotonic() >= deadline:
            raise RuntimeError("detached fixture missed its file handshake deadline")
        time.sleep(0.01)


def process_identity():
    if sys.platform == "darwin":
        from darwin_process_support import require_headless_darwin
        identity = require_headless_darwin()
        identity["hup_ignored"] = signal.getsignal(signal.SIGHUP) == signal.SIG_IGN
        return identity
    require_headless()
    data = Path("/proc/self/stat").read_text(encoding="utf-8")
    fields = data[data.rindex(")") + 1:].split()
    return {"pid": os.getpid(), "ppid": int(fields[1]), "pgid": int(fields[2]),
            "sid": int(fields[3]), "start": fields[19],
            "hup_ignored": signal.getsignal(signal.SIGHUP) == signal.SIG_IGN}


def worker(binary, plan_file, result_file, ready_file, release_file):
    plan = json.loads(plan_file.read_text(encoding="utf-8"))
    # Background and nohup alone keep the original group. Put the helper in a
    # separate group so a group match cannot stand in for adopted ancestry.
    if os.getpgrp() != os.getpid():
        os.setpgid(0, 0)
    ready_temporary = ready_file.with_suffix(".tmp")
    ready_temporary.write_text(json.dumps(process_identity()), encoding="utf-8")
    ready_temporary.replace(ready_file)
    wait_file(release_file, time.monotonic() + plan["release_timeout"])
    identity = process_identity()
    responses = [run_request(request, binary, os.environ, plan_file.parent.parent)
                 for request in plan["requests"]]
    destination = result_file.with_suffix(".tmp")
    destination.write_text(json.dumps({"identity": identity, "responses": responses}), encoding="utf-8")
    destination.replace(result_file)


def run_detached_request(request, binary, environment, directory):
    mode = request["communication_detach"]
    if mode not in ("background", "nohup", "setsid", "double-fork"):
        raise RuntimeError("unknown communication detachment")
    job = Path(directory) / ("detached-" + uuid.uuid4().hex)
    job.mkdir()
    plan, result, ready, release = [job / name for name in
                                    ("plan.json", "result.json", "ready.json", "release")]
    plan.write_text(json.dumps({"requests": request["requests"],
                               "release_timeout": 120 if request.get("communication_park") else 30}),
                    encoding="utf-8")
    launcher = job / "launch.sh"
    launcher.write_text(LAUNCHER, encoding="utf-8")
    child_mode = "--double-fork" if mode == "double-fork" else "--worker"
    launcher_mode = mode
    if mode == "setsid" and sys.platform == "darwin":
        # Darwin has no setsid utility by default. The control calls the actual
        # syscall from a forked non-leader and never invokes a replacement CLI.
        launcher_mode, child_mode = "fork-session", "--setsid-fork"
    command = ["sh", str(launcher), launcher_mode, str(job / "worker.log"),
               sys.executable, "-I", str(Path(__file__).resolve()),
               child_mode, str(binary), str(plan), str(result), str(ready), str(release)]
    # Waiting for this shell's actual exit precedes releasing the worker. The
    # product commands therefore run after reparenting, not merely after '&'.
    started = subprocess.Popen(command, cwd=directory, env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        _stdout, stderr = started.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        started.kill()
        started.communicate(timeout=5)
        raise
    if started.returncode != 0:
        raise RuntimeError("detachment launcher failed: " + stderr)
    wait_file(ready, time.monotonic() + 30)
    if request.get("communication_park"):
        return {"identity": json.loads(ready.read_text(encoding="utf-8")),
                "job": str(job), "launcher_exit": started.returncode, "launcher_pid": started.pid}
    release.touch()
    wait_file(result, time.monotonic() + 190)
    response = json.loads(result.read_text(encoding="utf-8"))
    response["launcher_exit"] = started.returncode
    response["launcher_pid"] = started.pid
    return response


if __name__ == "__main__":
    if len(sys.argv) != 7 or sys.argv[1] not in ("--worker", "--double-fork", "--setsid-fork"):
        raise RuntimeError("the communication helper requires a worker mode and five paths")
    if sys.argv[1] == "--double-fork":
        if os.fork():
            os._exit(0)
        if sys.platform != "darwin":
            os.setsid()
        if os.fork():
            os._exit(0)
    elif sys.argv[1] == "--setsid-fork":
        if os.fork():
            os._exit(0)
        os.setsid()
    worker(sys.argv[2], *map(Path, sys.argv[3:]))
