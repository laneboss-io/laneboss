#!/usr/bin/env python3
"""Codex provider double: real hooks and a real Linux write sandbox for tools.

Only the provider is replaced. Hooks run outside the tool sandbox, as in Codex;
each allowed shell child receives Landlock over cwd and the actual config roots.
No model, credential, product import or binary build is used.
"""

import ctypes
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import tomllib
import uuid


def sandbox(roots):
    if sys.platform != "linux" or platform.machine() not in ("x86_64", "aarch64", "arm64"):
        raise RuntimeError("this row requires Linux Landlock")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    abi = libc.syscall(444, 0, 0, 1)
    if abi < 3:
        raise RuntimeError("Landlock ABI 3 or newer is required")

    class Ruleset(ctypes.Structure):
        _fields_ = [("access", ctypes.c_uint64)]

    class Beneath(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("access", ctypes.c_uint64), ("parent", ctypes.c_int32)]

    # All filesystem mutation rights through ABI 3, including truncate and refer.
    access = sum(1 << bit for bit in (1, *range(4, 15)))
    attribute = Ruleset(access)
    descriptor = libc.syscall(444, ctypes.byref(attribute), ctypes.sizeof(attribute), 0)
    if descriptor < 0:
        raise OSError(ctypes.get_errno(), "Landlock create failed")
    try:
        for path in roots:
            parent = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = Beneath(access, parent)
                if libc.syscall(445, descriptor, 1, ctypes.byref(rule), 0) != 0:
                    raise OSError(ctypes.get_errno(), "Landlock rule failed")
            finally:
                os.close(parent)
        if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.syscall(446, descriptor, 0) != 0:
            raise OSError(ctypes.get_errno(), "Landlock restrict failed")
    finally:
        os.close(descriptor)


def run_request(request, roots):
    cwd = Path.cwd()
    event = {"hook_event_name": "PreToolUse", "cwd": str(cwd),
             "tool_name": request["tool"],
             "tool_input": {request["field"]: request["command"]}}
    hook = subprocess.run(request["hook_command"], input=json.dumps(event),
                          capture_output=True, text=True, timeout=30)
    response = {"hook": {"code": hook.returncode, "stdout": hook.stdout, "stderr": hook.stderr},
                "event": event, "execution": None}
    if hook.returncode == 0:
        output = json.loads(hook.stdout)["hookSpecificOutput"]
        if output["permissionDecision"] == "allow" and request.get("execute", True):
            result = subprocess.run(["/bin/bash", "-c", request["command"]],
                                    input=request.get("stdin", ""), capture_output=True, text=True,
                                    timeout=30, preexec_fn=lambda: sandbox(roots))
            response["execution"] = {"code": result.returncode, "stdout": result.stdout,
                                     "stderr": result.stderr}
    return response


def main():
    arguments = sys.argv[1:]
    home = Path(os.environ["CODEX_HOME"])
    config = tomllib.loads((home / "config.toml").read_text())
    if "--version" in arguments:
        print("codex state-row stand-in 1.0.0")
        return
    if "features" in arguments and "list" in arguments:
        hooks = config.get("features", {}).get("hooks", False)
        hooks = hooks or "features.hooks=true" in arguments
        plugins_off = any(arguments[index:index + 2] == ["--disable", "plugins"]
                          for index in range(len(arguments)))
        print("hooks stable " + str(bool(hooks)).lower())
        print("plugins stable " + str(not plugins_off).lower())
        return
    if "--sandbox" in arguments:
        if arguments[arguments.index("--sandbox") + 1] != "workspace-write":
            raise RuntimeError("the runner's workspace-write sandbox must remain selected")
    # The fixture's initial prompt operand carries the launcher session UUID.
    # Resume uses the real exec-resume shape: resume SESSION - (stdin prompt).
    operands = arguments[arguments.index("--sandbox") + 2:]
    if len(operands) == 1:
        session = operands[0]
    elif len(operands) == 3 and operands[0] == "resume" and operands[2] == "-":
        session = operands[1]
    else:
        raise RuntimeError("the stand-in requires an explicit start or resume session")
    if str(uuid.UUID(session)) != session:
        raise RuntimeError("the stand-in session must be the launcher's canonical UUID")
    sys.stdin.buffer.read()
    roots = [str(Path.cwd()), *config["sandbox_workspace_write"].get("writable_roots", [])]
    print(json.dumps({"type": "system", "subtype": "init", "session_id": session}), flush=True)
    (Path.cwd() / "sandbox-roots.json").write_text(json.dumps(roots))
    (Path.cwd() / "ready.json").write_text(json.dumps({"pid": os.getpid()}))
    if (Path.cwd() / "once").is_file():
        return
    completed = set()
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        for path in sorted(Path.cwd().glob("request-*.json")):
            if path.name in completed:
                continue
            response = run_request(json.loads(path.read_text()), roots)
            destination = path.with_name(path.name.replace("request-", "response-"))
            temporary = destination.with_suffix(".tmp")
            temporary.write_text(json.dumps(response))
            temporary.replace(destination)
            completed.add(path.name)
        time.sleep(0.02)
    raise RuntimeError("the Codex state stand-in exceeded its bounded lifetime")


if __name__ == "__main__":
    main()
