"""Real file-write canary, run by the harness inside an authentic L6 lane."""

import argparse
import errno
import json
import os
from pathlib import Path
import stat
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("payload")
    args = parser.parse_args()
    if sys.platform != "linux":
        raise ValueError("write canary requires the Linux test box")
    try:
        with Path(args.payload).open("rb") as payload:
            data = payload.read(262145)
    except OSError as error:
        print(json.dumps({"attempted": False, "written": False, "errno": error.errno}))
        return 2
    if not data or len(data) > 262144:
        raise ValueError("canary payload is empty or oversized")
    # Both targets must already exist. Never create a path because a fixture
    # passed the wrong target, and never follow a final-component symlink.
    try:
        descriptor = os.open(args.target, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "wb") as output:
            if not stat.S_ISREG(os.fstat(output.fileno()).st_mode):
                raise ValueError("canary target is not an ordinary file")
            output.truncate(0)
            written = output.write(data)
            if written != len(data):
                raise OSError(errno.EIO, "canary write was incomplete")
            output.flush()
            os.fsync(output.fileno())
    except OSError as error:
        print(json.dumps({"attempted": True, "written": False, "errno": error.errno}))
        return 1
    print(json.dumps({"attempted": True, "written": True, "errno": 0}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ValueError:
        print(json.dumps({"attempted": False, "written": False, "errno": 0}))
        sys.exit(2)
