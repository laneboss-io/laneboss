#!/usr/bin/env python3
"""Linux-box canaries for the exact deny-only Landlock design constraint.

This is a diagnostic, not a passing Laneboss enforcement row. It compares real
filesystem writes with and without genuine Landlock restrictions and proves
stacking with two successful landlock_restrict_self calls. Never run on macOS.
"""

import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import uuid


class Ruleset(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class Beneath(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def apply(rules):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    abi = libc.syscall(444, 0, 0, 1)
    if abi < 1:
        raise OSError(ctypes.get_errno(), "Landlock is unavailable on the test box")
    attribute = Ruleset(1 << 1)
    descriptor = libc.syscall(444, ctypes.byref(attribute), ctypes.sizeof(attribute), 0)
    if descriptor < 0:
        raise OSError(ctypes.get_errno(), "ruleset creation failed")
    try:
        for path, access in rules:
            parent = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = Beneath(access, parent)
                if libc.syscall(445, descriptor, 1, ctypes.byref(rule), 0) != 0:
                    raise OSError(ctypes.get_errno(), "path rule addition failed")
            finally:
                os.close(parent)
        if libc.prctl(38, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "no_new_privs failed")
        if libc.syscall(446, descriptor, 0) != 0:
            raise OSError(ctypes.get_errno(), "landlock_restrict_self failed")
        return int(abi)
    finally:
        os.close(descriptor)


def write(path, payload):
    try:
        path.write_bytes(payload)
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.EPERM):
            raise
        return {"allowed": False, "errno": error.errno}
    return {"allowed": path.read_bytes() == payload, "errno": 0}


def child(case, root):
    spec = json.loads((root / "input.json").read_text())
    payload = spec["nonce"].encode()
    calls = 0
    abi = None
    if case == "root-grant":
        abi = apply([("/", 1 << 1)])
        calls += 1
    elif case == "complement":
        abi = apply([(str(root / "ordinary-existing"), 1 << 1)])
        calls += 1
    elif case == "stacked":
        abi = apply([("/", 1 << 1)])
        calls += 1
        abi = apply([("/", 1 << 1)])
        calls += 1
    elif case != "control":
        raise ValueError("unknown diagnostic case")
    result = {"case": case, "abi": abi, "restrict_self_calls": calls,
              "protected": write(root / "protected" / "policy", payload),
              "existing_ordinary": write(root / "ordinary-existing" / "proof", payload),
              "future_ordinary": write(root / "ordinary-future", payload)}
    print(json.dumps(result, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--child", choices=("control", "root-grant", "complement", "stacked"))
    parser.add_argument("--root", type=Path)
    arguments = parser.parse_args()
    if not sys.platform.startswith("linux") or platform.machine() not in ("x86_64", "aarch64", "arm64"):
        raise RuntimeError("this diagnostic requires an authorized amd64/arm64 Linux box")
    if arguments.child:
        child(arguments.child, arguments.root)
        return
    evidence = arguments.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    results = {}
    for case in ("control", "root-grant", "complement", "stacked"):
        root = Path(tempfile.mkdtemp(prefix="lb-svc-sandbox-landlock-" + case + "-", dir=evidence))
        (root / "protected").mkdir()
        (root / "ordinary-existing").mkdir()
        (root / "protected/policy").write_bytes(b"before")
        spec = {"nonce": uuid.uuid4().hex}
        (root / "input.json").write_text(json.dumps(spec) + "\n")
        command = [sys.executable, str(Path(__file__).resolve()), "--evidence", str(evidence), "--child", case, "--root", str(root)]
        result = subprocess.run(command, capture_output=True, timeout=30)
        (root / "stdout").write_bytes(result.stdout)
        (root / "stderr").write_bytes(result.stderr)
        (root / "exit.json").write_text(json.dumps({"argv": command, "exit_code": result.returncode}) + "\n")
        if result.returncode != 0:
            raise RuntimeError(case + " setup/syscall failed; retained stderr is required evidence")
        observed = json.loads(result.stdout)
        for name, path in (("protected", root / "protected/policy"), ("existing_ordinary", root / "ordinary-existing/proof"),
                           ("future_ordinary", root / "ordinary-future")):
            actual = path.exists() and path.read_bytes() == spec["nonce"].encode()
            if actual != observed[name]["allowed"]:
                raise RuntimeError(case + " reported a filesystem verdict that differs from retained bytes")
        results[case] = observed
    if not all(results["control"][name]["allowed"] for name in ("protected", "existing_ordinary", "future_ordinary")):
        raise RuntimeError("unsandboxed control did not write every fixture")
    if not results["root-grant"]["protected"]["allowed"]:
        raise RuntimeError("root-grant observation differs; revisit the deny-only design analysis")
    complement = results["complement"]
    if complement["protected"]["allowed"] or not complement["existing_ordinary"]["allowed"] or complement["future_ordinary"]["allowed"]:
        raise RuntimeError("existing-path complement observation differs; revisit the design analysis")
    if results["stacked"]["restrict_self_calls"] != 2 or not results["stacked"]["future_ordinary"]["allowed"]:
        raise RuntimeError("genuine stacked Landlock rulesets did not preserve the ordinary write")
    print("OBSERVED root grant: protected write remains allowed")
    print("OBSERVED existing-path complement: unrelated future write is denied")
    print("PASS stacked Landlock: two restrict_self calls and ordinary write")
    print("DIAGNOSTIC COMPLETE: not a Laneboss enforcement pass")


if __name__ == "__main__":
    main()
