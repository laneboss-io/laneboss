"""Fixed registered actor job: invoke only the protected installed CLI artifact."""

import argparse
import base64
import json
import os
from pathlib import Path
import sys
import tempfile

from harness import digest, dump, execute, lane_projection, protected_json, read_json, require

METHODS = {
    "org.change.propose": ["org", "change", "propose"],
    "org.change.get": ["org", "change", "get"],
    "org.change.apply": ["org", "change", "apply"],
    "identity.self": ["identity", "self"],
    "blob.begin": ["blob", "begin"],
    "blob.chunk": ["blob", "chunk"],
    "blob.commit": ["blob", "commit"],
    "blob.read": ["blob", "read"],
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--settings", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args()
    require(sys.platform == "linux", "actor canary requires Linux")
    settings = protected_json(args.settings, {0})
    require(settings["schema"] == "laneboss.approval-cli-job.v2", "invalid registered CLI job")
    binary = Path(settings["binary"]).resolve(strict=True)
    require(binary.is_absolute() and binary.is_file() and digest(binary.read_bytes()) == settings["binary_sha256"],
            "registered CLI artifact mismatch")
    binding, descriptors = lane_projection(settings)
    input_bytes = args.input.read_bytes()
    request = read_json(args.input)
    require(set(request) == {"schema", "method", "params", "request_id", "idempotency_key"} and
            request["schema"] == "laneboss.approval-cli-input.v2" and request["method"] in METHODS,
            "CLI canary input is not one of its fixed operations")
    params = base64.b64decode(request["params"], validate=True)
    require(0 < len(params) <= 1048576, "CLI request exceeds bound")
    # No executable, shell words, binding or authority can be supplied in input.
    with tempfile.TemporaryDirectory(prefix="approval-cli-", dir=settings["scratch_root"]) as scratch:
        temporary = Path(scratch)
        os.chmod(temporary, 0o700)
        request_file = temporary / "request.json"
        request_file.write_bytes(params)
        request_file.chmod(0o600)
        argv = [str(binary), *METHODS[request["method"]], "--config", settings["config"],
                "--binding", settings["binding_file"], "--request", str(request_file),
                "--request-id", request["request_id"], "--idempotency-key", request["idempotency_key"]]
        run, process = execute(argv, pass_fds=descriptors)
        observation = {
            "schema": "laneboss.approval-cli-observation.v2",
            "executor_sha256": digest(Path(__file__).read_bytes()),
            "adapter_sha256": digest(Path(__file__).with_name("harness.py").read_bytes()),
            "binary_sha256": digest(binary.read_bytes()), "config": settings["config"],
            "binding_file": settings["binding_file"], "target": binding["target"],
            "input_sha256": digest(input_bytes), "method": request["method"],
            "request_id": request["request_id"], "idempotency_key": request["idempotency_key"],
            "request_file": str(request_file), "params_sha256": digest(request_file.read_bytes()),
            "argv": argv, "observed_exit": run.returncode,
            "stdout": base64.b64encode(run.stdout).decode(), "stderr": base64.b64encode(run.stderr).decode(),
            "process": process,
        }
    observation["temporary_removed"] = not temporary.exists()
    dump(args.result, observation)
    require(process["group_absent"] and not process["timed_out"] and observation["temporary_removed"],
            "CLI canary process/resource collection failed")
    return run.returncode


if __name__ == "__main__":
    sys.exit(main())
