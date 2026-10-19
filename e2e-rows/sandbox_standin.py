#!/usr/bin/env python3
"""Credential-free runner used only by the owner/box sandbox proof rows.

The stand-in parses the same sandbox selectors as the configured runner and
actually applies its own OS sandbox unless the launcher disables it. It runs
real tools and filesystem canaries; it never manufactures launcher output.
"""

import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tomllib


def options(arguments):
    values = {}
    overrides = {}
    enabled = set()
    disabled = set()
    index = 0
    while index < len(arguments):
        word = arguments[index]
        flag, separator, value = word.partition("=")
        if flag in ("-c", "--config", "--sandbox", "-s", "--settings", "--enable", "--disable"):
            if not separator:
                index += 1
                if index >= len(arguments):
                    raise ValueError("incomplete runner option")
                value = arguments[index]
            if flag in ("-c", "--config"):
                key, found, raw = value.partition("=")
                if not found:
                    raise ValueError("incomplete config override")
                try:
                    parsed = tomllib.loads("value=" + raw)["value"]
                except tomllib.TOMLDecodeError:
                    parsed = raw
                overrides[key] = parsed
            elif flag == "--enable":
                enabled.update(value.split(","))
            elif flag == "--disable":
                disabled.update(value.split(","))
            else:
                values[flag] = value
        index += 1
    return values, overrides, enabled, disabled


def restrict_landlock():
    """Apply a genuine independent, write-only Landlock ruleset on Linux."""
    if platform.machine() not in ("x86_64", "aarch64", "arm64"):
        raise RuntimeError("stand-in Landlock row requires amd64 or arm64")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    abi = libc.syscall(444, 0, 0, 1)
    if abi < 1:
        raise OSError(ctypes.get_errno(), "Landlock ABI is unavailable")

    class Ruleset(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64)]

    class Beneath(ctypes.Structure):
        _pack_ = 1
        _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]

    write_file = 1 << 1
    attribute = Ruleset(write_file)
    descriptor = libc.syscall(444, ctypes.byref(attribute), ctypes.sizeof(attribute), 0)
    if descriptor < 0:
        raise OSError(ctypes.get_errno(), "Landlock ruleset creation failed")
    parent = os.open("/", os.O_PATH | os.O_CLOEXEC)
    try:
        rule = Beneath(write_file, parent)
        if libc.syscall(445, descriptor, 1, ctypes.byref(rule), 0) != 0:
            raise OSError(ctypes.get_errno(), "Landlock rule addition failed")
        if libc.prctl(38, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "no_new_privs failed")
        if libc.syscall(446, descriptor, 0) != 0:
            raise OSError(ctypes.get_errno(), "landlock_restrict_self failed")
        return int(abi)
    finally:
        os.close(parent)
        os.close(descriptor)


def call(spec, name, arguments):
    result = subprocess.run(arguments, cwd=spec["worktree"], capture_output=True, timeout=60)
    directory = Path(spec["evidence"])
    (directory / (name + ".stdout")).write_bytes(result.stdout)
    (directory / (name + ".stderr")).write_bytes(result.stderr)
    (directory / (name + ".json")).write_text(json.dumps({"argv": arguments, "exit_code": result.returncode}) + "\n")
    if result.returncode != 0:
        raise RuntimeError(name + " exited " + str(result.returncode))
    return result.stdout


def main():
    arguments = sys.argv[1:]
    values, overrides, enabled, disabled = options(arguments)
    provider = Path(sys.argv[0]).name
    if "--version" in arguments:
        print(provider + " stand-in 1.0.0")
        return 0
    if "features" in arguments and "list" in arguments:
        hooks = overrides.get("features.hooks", False) or "hooks" in enabled
        plugins = "plugins" not in disabled
        print("hooks stable " + str(bool(hooks)).lower())
        print("plugins stable " + str(plugins).lower())
        return 0

    brief = sys.stdin.read()
    marker = "SANDBOX_ROW_SPEC="
    references = [line[len(marker):] for line in brief.splitlines() if line.startswith(marker)]
    if len(references) != 1:
        raise RuntimeError("runner did not receive the actual row brief")
    spec = json.loads(Path(references[0]).read_text())
    result = {"entered": True, "provider": provider, "own_sandbox_disabled": False, "own_landlock_abi": None,
              "protection": {}, "ordinary": {}, "ordinary_failure": None, "errors": []}
    if provider == "codex":
        mode = values.get("--sandbox", values.get("-s", overrides.get("sandbox_mode", "workspace-write")))
        own_off = mode == "danger-full-access"
        vendor_home = Path(os.environ["CODEX_HOME"])
    else:
        settings = json.loads(Path(values["--settings"]).read_text())
        own_off = settings.get("sandbox", {}).get("enabled", False) is False
        vendor_home = Path(values["--settings"]).parent
        if vendor_home.parent.name == ".laneboss-lanes":
            vendor_home = vendor_home.parent.parent
    result["own_sandbox_disabled"] = own_off
    if not own_off:
        if sys.platform == "darwin":
            own = subprocess.run(["/usr/bin/sandbox-exec", "-p", "(version 1) (allow default)", "/usr/bin/true"],
                                 capture_output=True, timeout=10)
            if own.returncode != 0:
                result["errors"].append("runner's own sandbox could not apply")
                print("SANDBOX_ROW_RESULT=" + json.dumps(result, sort_keys=True))
                return 71
        elif sys.platform.startswith("linux"):
            result["own_landlock_abi"] = restrict_landlock()
    print("STANDIN sandbox " + ("off: " if own_off else "on: ") + provider)

    for name, entry in spec["protected"].items():
        target = Path(entry["path"])
        try:
            target.write_bytes(entry["after"].encode())
        except OSError as error:
            if error.errno not in (errno.EACCES, errno.EPERM, errno.EROFS):
                raise
            result["protection"][name] = {"denied": True, "errno": error.errno}
        else:
            result["protection"][name] = {"denied": False, "errno": 0}

    operation = "runner-session"
    try:
        # Ordinary SDK session writes must stay possible even inside a rendered
        # vendor home: these are runner files, not Laneboss policy inputs.
        sessions = vendor_home / "sessions"
        sessions.mkdir(exist_ok=True)
        session = sessions / (str(os.getpid()) + ".jsonl")
        data = json.dumps({"pid": os.getpid(), "provider": provider}).encode()
        session.write_bytes(data)
        if session.read_bytes() != data:
            raise RuntimeError("runner session write differed")
        result["ordinary"]["runner-session"] = True
        operation = "go-test"
        call(spec, "go-test", ["go", "test", "-v", "."])
        proof = (Path(spec["worktree"]) / "ordinary-proof").read_text()
        if int(proof) <= 0:
            raise RuntimeError("Go test did not retain its process id")
        result["ordinary"]["go-test"] = True
        operation = "go-build"
        call(spec, "go-build", ["go", "build", "-trimpath", "-o", "ordinary-program", "."])
        executable = Path(spec["worktree"]) / "ordinary-program"
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise RuntimeError("Go build did not create an executable")
        result["ordinary"]["go-build"] = True
        operation = "git-commit"
        call(spec, "git-add", ["git", "add", "ordinary-proof"])
        call(spec, "git-commit", ["git", "-c", "user.name=Sandbox fixture", "-c", "user.email=fixture.invalid",
                                  "commit", "-m", "Record the actual sandbox worktree proof"])
        head = call(spec, "git-head", ["git", "rev-parse", "HEAD"]).decode().strip()
        if head == spec["initial_head"]:
            raise RuntimeError("Git commit did not advance the worktree branch")
        committed = call(spec, "git-proof", ["git", "show", "HEAD:ordinary-proof"])
        if committed != (Path(spec["worktree"]) / "ordinary-proof").read_bytes():
            raise RuntimeError("Git commit did not retain the actual worktree proof")
        result["ordinary"]["git-commit"] = True
        for name, filename in (("tmp", spec["tmp_file"]), ("cache", spec["cache_file"])):
            operation = name
            path = Path(filename)
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = (spec["nonce"] + ":" + str(os.getpid())).encode()
            path.write_bytes(payload)
            if path.read_bytes() != payload:
                raise RuntimeError(name + " write differed")
            result["ordinary"][name] = True
        operation = "curl-local"
        body = call(spec, "curl-local", ["curl", "--fail", "--silent", "--show-error", spec["url"]])
        if body != Path(spec["curl_source"]).read_bytes():
            raise RuntimeError("local curl did not return the served source bytes")
        result["ordinary"]["curl-local"] = True
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        result["ordinary_failure"] = {"operation": operation, "errno": getattr(error, "errno", None)}
        result["errors"].append(type(error).__name__ + ": " + str(error))
    print("SANDBOX_ROW_RESULT=" + json.dumps(result, sort_keys=True))
    return 0 if not result["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
