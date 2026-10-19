"""Focused fixture mutations, run before the unchanged candidate on Linux."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


CONTROLS = (
    ("foreign-driver", "case_watchdog.py", 'p["driver"] == "claudock-cli"', "True", "Producer.test_profile_affinity"),
    ("lane-usage", "wd_usage.py", 'peer_uid in self.usage_uids,',
     'peer_uid in self.usage_uids or peer_uid in self.runner_uids,', "Producer.test_quota_state"),
    ("reset-room", "wd_usage.py", 'self.state = parse(private(self.path, {os.getuid()}))',
     'self.state = parse(private(self.path, {os.getuid()}))\n            self.state["used"] = {p: 0 for p in profiles}', "Producer.test_quota_state"),
    ("copy-token", "wd_runner.py", 'history = parse(os.read(descriptor, 65537))',
     'history = parse(os.read(descriptor, 65537))\n                history["nonce"] = re.findall(rb"(?m)^History nonce: ([a-f0-9]{32})$", prompt)[0].decode()',
     "Producer.test_history"),
    ("canned-limit", "wd_runner.py", 'measured["used"] >= measured["capacity"], "provider limit has no observed exhaustion"',
     'True, "provider limit has no observed exhaustion"', "Producer.test_limit_is_observed"),
    ("fake-exit", "wd_control.py", 'exited = bool(poller.poll(45000))', 'exited = True', "Restart.test_old_exit_is_independent"),
    ("loose-file", "wd_usage.py", 'and not info.st_mode & 0o077', 'and True', "Producer.test_exact_empty_evidence"),
)


def keep(path, data):
    with path.open("xb") as stream:
        if stream.write(data) != len(data):
            raise RuntimeError("short mutation evidence write")


def run(root, modules, test):
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(Path.home()), "WD_MODULE_ROOT": str(modules)}
    command = [sys.executable, "-B", "-m", "unittest", "-v", "producer_test." + test]
    result = subprocess.run(command, cwd=Path(__file__).resolve().parent, env=env,
                            capture_output=True, timeout=60, check=False)
    keep(root / "stdout", result.stdout)
    keep(root / "stderr", result.stderr)
    keep(root / "exit.json", json.dumps({"command": command, "exit_code": result.returncode}).encode())
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "linux" or args.evidence.exists():
        raise RuntimeError("use a fresh evidence path on the authorized Linux test host")
    args.evidence.mkdir(mode=0o700)
    source = Path(__file__).resolve().parents[4] / "scripts/v2-serve"
    names = ("case_watchdog.py", "wd_usage.py", "wd_runner.py", "wd_control.py")
    originals = {name: (source / name).read_bytes() for name in names}
    for name, data in originals.items():
        keep(args.evidence / (name + ".input"), data)
    rows = []
    for identity, name, before, after, test in CONTROLS:
        root = args.evidence / identity
        root.mkdir(mode=0o700)
        modules = root / "modules"
        modules.mkdir(mode=0o700)
        for item in names:
            shutil.copyfile(source / item, modules / item)
        data = originals[name]
        if data.count(before.encode()) != 1:
            raise RuntimeError("missing or ambiguous mutation anchor: " + identity)
        changed = data.replace(before.encode(), after.encode(), 1)
        (modules / name).write_bytes(changed)
        result = run(root, modules, test)
        output = result.stdout + result.stderr
        # A compile/import/setup error is not a killed behavior mutation.
        if result.returncode != 1 or b"AssertionError" not in output or b"FAIL:" not in output or b"ERROR:" in output:
            raise RuntimeError("mutation did not fail its reached assertion: " + identity + ": " + output.decode(errors="replace"))
        rows.append({"mutation": identity, "test": test, "exit_code": result.returncode,
                     "before_sha256": hashlib.sha256(data).hexdigest(), "after_sha256": hashlib.sha256(changed).hexdigest()})
        print(json.dumps(rows[-1], sort_keys=True), flush=True)
    root = args.evidence / "candidate"
    root.mkdir(mode=0o700)
    candidate = run(root, source, "Producer")
    if candidate.returncode != 0:
        raise RuntimeError("candidate fixture checks failed: " + candidate.stderr.decode(errors="replace"))
    root = args.evidence / "restart-candidate"
    root.mkdir(mode=0o700)
    candidate = run(root, source, "Restart")
    if candidate.returncode != 0:
        raise RuntimeError("candidate process checks failed: " + candidate.stderr.decode(errors="replace"))
    for name, data in originals.items():
        if (source / name).read_bytes() != data:
            raise RuntimeError("mutation changed its input source")
    keep(args.evidence / "mutations.json", json.dumps(rows, indent=2).encode())
    print("fixture controls: 7 reached mutations killed; candidate passed; installed acceptance unrun")


if __name__ == "__main__":
    main()
