"""Actual R1 hook regression followed by the unchanged G0 wiring candidate."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def require(value, reason):
    if not value:
        raise RuntimeError(reason)


def pin(path):
    raw = path.read_bytes()
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def main():
    require(sys.platform == "linux" and os.geteuid() == 0,
            "wiring controls require the authorized disposable root Linux host")
    base = HERE / "base.py"
    candidate = ROOT / "scripts/v2-serve/case_linux.py"
    before = pin(candidate)
    command = [sys.executable, "-B", str(HERE / "wiring_test.py"), "--producer", str(base),
               "Wiring.test_boot", "Wiring.test_contract"]
    red = subprocess.run(command, capture_output=True, timeout=120, check=False)
    combined = red.stdout + red.stderr
    sys.stdout.buffer.write(red.stdout)
    sys.stderr.buffer.write(red.stderr)
    require(red.returncode == 1 and b"ERROR:" not in combined and
            b"FAIL: test_boot" in combined and b"G0 boot hook is absent" in combined and
            b"FAIL: test_contract" in combined and b"G0 prepare signature differs" in combined and
            b"Ran 2 tests" in combined,
            "R1 did not reach the two deciding G0 hook assertions")
    print(json.dumps({"phase": "red", "base_revision": "b1dfb527", "input": pin(base),
                      "exit_code": red.returncode, "scope": "two G0 hook assertions"}), flush=True)
    green = subprocess.run([sys.executable, "-B", str(HERE / "wiring_test.py")],
                           capture_output=True, timeout=180, check=False)
    sys.stdout.buffer.write(green.stdout)
    sys.stderr.buffer.write(green.stderr)
    require(green.returncode == 0 and b"\nOK\n" in green.stderr and b"skipped" not in green.stderr,
            "G0 wiring candidate failed")
    require(pin(candidate) == before, "candidate source changed during wiring controls")
    print(json.dumps({"phase": "candidate", "input": before, "exit_code": green.returncode,
                      "scope": "G0 wiring units, not installed OS-LINUX"}), flush=True)
    print("PASS: Linux G0 base/candidate wiring", flush=True)


if __name__ == "__main__":
    main()
