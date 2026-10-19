"""Granted test content, run through the real bounded data-worker interface."""

import argparse
import json
import os
from pathlib import Path
import re
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--ack", required=True)
    parser.add_argument("--nonce", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[a-f0-9]{32}", args.nonce):
        raise ValueError("invalid nonce")
    output, acknowledgement = Path(args.out), Path(args.ack)
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
                  if ":" in line)
    facts = {"nonce": args.nonce, "uid": os.getuid(), "gid": os.getgid(),
             "no_new_privs": int(status["NoNewPrivs"].strip()), "cap_eff": status["CapEff"].strip(),
             "cgroup": Path("/proc/self/cgroup").read_text()}
    # The canary reports kernel facts only. The outside observer owns all
    # expected values/verdicts and host-UID/cgroup observations.
    with output.open("x") as stream:
        json.dump(facts, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if acknowledgement.exists():
            if acknowledgement.read_text().strip() != args.nonce:
                raise ValueError("wrong acknowledgement")
            return 0
        time.sleep(0.2)
    raise TimeoutError("outside observer did not acknowledge the live canary")


if __name__ == "__main__":
    raise SystemExit(main())
