#!/usr/bin/env python3
"""Record the row's real tmux calls and reject another server/socket."""

import json
import os
from pathlib import Path
import sys


def main():
    spec = json.loads(Path(__file__).with_name("tmux-spec.json").read_text())
    arguments = sys.argv[1:]
    if arguments[:4] != ["-S", spec["socket"], "-f", os.devnull]:
        raise RuntimeError("row tmux invocation is not isolated to its declared socket")
    record = {"socket": arguments[1], "config": arguments[3],
              "command": arguments[4] if len(arguments) > 4 else None}
    descriptor = os.open(spec["trace"], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        data = (json.dumps(record) + "\n").encode()
        if os.write(descriptor, data) != len(data):
            raise RuntimeError("tmux trace write was incomplete")
    finally:
        os.close(descriptor)
    os.execv(spec["program"], [spec["program"], *arguments])


if __name__ == "__main__":
    main()
