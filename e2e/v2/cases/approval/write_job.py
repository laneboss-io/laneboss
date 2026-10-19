"""Fixed registered filesystem job; selectors resolve only protected fixture targets."""

import argparse
import base64
import errno
import os
from pathlib import Path
import stat
import sys

from harness import digest, dump, protected_json, read_json, require


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--settings", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    require(sys.platform == "linux", "write job requires Linux")
    settings = protected_json(args.settings, {0})
    require(settings["schema"] == "laneboss.approval-write-job.v2", "invalid registered write job")
    raw = args.input.read_bytes()
    request = read_json(args.input)
    require(set(request) == {"schema", "target", "payload"} and
            request["schema"] == "laneboss.approval-write-input.v2" and
            request["target"] in {"workspace", "canonical"}, "invalid write selector")
    target = settings["targets"][request["target"]]
    require(Path(target).is_absolute(), "registered write target is not absolute")
    data = base64.b64decode(request["payload"], validate=True)
    require(0 < len(data) <= 262144, "invalid native-write payload")
    observation = {"schema": "laneboss.approval-write-observation.v2",
                   "executor_sha256": digest(Path(__file__).read_bytes()),
                   "adapter_sha256": digest(Path(__file__).with_name("harness.py").read_bytes()),
                   "input_sha256": digest(raw), "payload_sha256": digest(data),
                   "target": request["target"], "target_path": target,
                   "attempted": False, "written": False, "errno": 0}
    try:
        observation["attempted"] = True
        descriptor = os.open(target, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "wb") as output:
            require(stat.S_ISREG(os.fstat(output.fileno()).st_mode), "write target is not an ordinary file")
            output.truncate(0)
            written = output.write(data)
            if written != len(data):
                raise OSError(errno.EIO, "incomplete canary write")
            output.flush()
            os.fsync(output.fileno())
        observation["written"] = True
        observed_exit = 0
    except OSError as error:
        observation["errno"] = error.errno
        observed_exit = 1
    observation["observed_exit"] = observed_exit
    dump(args.result, observation)
    return observed_exit


if __name__ == "__main__":
    sys.exit(main())
