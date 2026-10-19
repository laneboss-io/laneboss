#!/usr/bin/env python3
"""Run only as a TestChild job through the production isolation launcher."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid


def observe(path, metadata_only=False):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except OSError as error:
        return {"errno": error.errno, "bytes": 0, "sha256": ""}
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("syscall probe requires a regular file")
        content = b"" if metadata_only else os.read(descriptor, 65536)
        return {"errno": 0, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest(),
                "mode": stat.S_IMODE(info.st_mode), "nlink": info.st_nlink, "regular": True}
    except OSError as error:
        return {"errno": error.errno, "bytes": 0, "sha256": ""}
    finally:
        os.close(descriptor)


def transcript_path(directory, session):
    if str(uuid.UUID(session)) != session:
        raise ValueError("syscall probe requires a canonical session")
    matches, count = [], 0
    for parent, directories, files in os.walk(directory, followlinks=False):
        count += len(directories) + len(files)
        if count > 4096:
            raise ValueError("transcript lookup exceeded its bound")
        for name in files:
            if name == session + ".jsonl":
                matches.append(str(Path(parent) / name))
    if len(matches) != 1:
        raise ValueError("syscall probe found no unique transcript")
    return matches[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    data = arguments.input.read_bytes()
    request = json.loads(data)
    supported = [{"own", "sibling-history", "sibling-token"}, {"workspace-write"}, {"transcript"}]
    if request["schema"] != "claudock.probe.v1" or set(request["paths"]) not in supported:
        raise ValueError("unexpected syscall probe input")
    observations = {}
    for label, path in request["paths"].items():
        if label == "transcript":
            path = transcript_path(path, request["session"])
        observations[label] = observe(path, metadata_only=label == "transcript")
    result = {"schema": "claudock.probe-result.v1", "input_sha256": hashlib.sha256(data).hexdigest(), "observations": observations}
    with arguments.output.open("x") as output:
        json.dump(result, output, sort_keys=True)
        output.write("\n")


if __name__ == "__main__":
    main()
