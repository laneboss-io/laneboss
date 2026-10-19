"""A real unprivileged open canary, with a separate readable control."""

import argparse
import errno
import hashlib
import json
import os


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--control", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("targets", nargs="+")
    args = parser.parse_args()
    result = {"uid": os.geteuid(), "control": False, "targets": []}
    valid = os.geteuid() == args.uid and args.uid != 0
    descriptor = os.open(args.control, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        result["control"] = hashlib.sha256(stream.read()).hexdigest() == args.sha256
    valid = valid and result["control"]
    for path in args.targets:
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as failure:
            denied = failure.errno in (errno.EACCES, errno.EPERM)
            result["targets"].append({"errno": failure.errno, "denied": denied})
            valid = valid and denied
        else:
            os.close(descriptor)
            result["targets"].append({"errno": 0, "denied": False})
            valid = False
    print(json.dumps(result, sort_keys=True))
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
