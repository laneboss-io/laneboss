#!/usr/bin/env python3
"""Execute inside the real lane, with a granted digest-only probe plan."""

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import sys


def same(data, expected):
    return (isinstance(expected, str) and
            re.fullmatch(r"[0-9a-f]{64}", expected) is not None and
            hashlib.sha256(data).hexdigest() == expected)


def selected_name(name):
    if not isinstance(name, str) or re.fullmatch(r"[A-Z_][A-Z0-9_]*", name) is None:
        raise ValueError("invalid explicit name")
    return name


def probe_outcomes(plan):
    outcomes = {"env": False, "file": False, "undelegated": False, "reserved": False}
    try:
        # Read exactly one selected variable per check; never enumerate or print
        # process environment values, even on a failed comparison.
        value = os.environ.get(selected_name(plan["env_name"]))
        outcomes["env"] = value is not None and same(
            value.encode("utf-8", "surrogateescape"), plan["env_sha256"])
    except (OSError, ValueError, KeyError, TypeError):
        outcomes["env"] = False
    try:
        value = os.environ.get(selected_name(plan["reserved_env_name"]))
        outcomes["reserved"] = value is not None and same(
            value.encode("utf-8", "surrogateescape"), plan["reserved_sha256"])
    except (OSError, ValueError, KeyError, TypeError):
        outcomes["reserved"] = False
    try:
        file_path = Path(plan["file_path"])
        with file_path.open("rb") as stream:
            material = stream.read(65537)
        readonly = False
        try:
            fd = os.open(file_path, os.O_WRONLY | os.O_APPEND)
        except OSError as error:
            readonly = error.errno in (errno.EPERM, errno.EACCES, errno.EROFS)
        else:
            os.close(fd)
        outcomes["file"] = (len(material) <= 65536 and
                            same(material, plan["file_sha256"]) and readonly)
    except (OSError, ValueError, KeyError, TypeError):
        outcomes["file"] = False
    try:
        hidden = plan["hidden_env_names"]
        if not isinstance(hidden, list) or not hidden:
            raise ValueError("missing undelegated controls")
        absent = True
        for selected in hidden:
            missing = os.environ.get(selected_name(selected)) is None
            absent = absent and missing
        paths = plan["hidden_file_paths"]
        if not isinstance(paths, list) or not paths:
            raise ValueError("missing file controls")
        for selected in paths:
            try:
                with Path(selected).open("rb") as stream:
                    stream.read(1)
                absent = False
            except (FileNotFoundError, PermissionError):
                continue  # Actual failed open; the outside observer proves existence.
        outcomes["undelegated"] = absent
    except (OSError, ValueError, KeyError, TypeError):
        outcomes["undelegated"] = False
    return outcomes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True, type=Path)
    args = parser.parse_args()
    try:
        plan = json.loads(args.plan.read_bytes())
    except (OSError, ValueError, TypeError):
        plan = {}
    outcomes = probe_outcomes(plan)
    for name, ok in outcomes.items():
        print(json.dumps({"name": name, "ok": ok}, separators=(",", ":")))
    return 0 if all(outcomes.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
