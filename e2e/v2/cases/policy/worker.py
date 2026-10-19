"""CLI-only observer, run by the harness inside one authenticated life."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from lane_handoff import HandoffRefusal, LANE_BINDING, lane_descriptors


def atomic(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True) + "\n")
    temporary.replace(path)


def hook_command(binary, config, request, command_path):
    data = request["command"]
    if data["argv"] != [] or data["declared_paths"] != []:
        raise RuntimeError("command-file hook cannot discard argv or declared paths")
    raw = base64.b64decode(data["command"], validate=True)
    if hashlib.sha256(raw).hexdigest() != data["raw_sha256"]:
        raise RuntimeError("hook command bytes do not match the retained digest")
    command_path.write_bytes(raw)
    if command_path.read_bytes() != raw:
        raise RuntimeError("hook command file read-back differs")
    return [
        binary, "org", "hook", "--config", config, "--command-file", str(command_path),
        "--life-id", request["target"]["life_id"], "--run", str(request["target"]["run"]),
        "--turn-id", request["logical_turn_id"], "--tool", data["tool"], "--cwd", data["cwd"],
    ], raw


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--queue", required=True)
    parser.add_argument("--deadline", type=int, default=1500)
    args = parser.parse_args()
    queue = Path(args.queue).resolve(strict=True)
    info = queue.stat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.geteuid():
        raise RuntimeError("worker queue must be private and owned by this test identity")
    binary_hash = hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()
    version = subprocess.run([args.binary, "--version"], capture_output=True, check=True, timeout=10)
    metadata = json.loads(version.stdout)
    if metadata["contract_revision"] != "v2.0-draft.4":
        raise RuntimeError("worker binary contract mismatch")
    commands = {
        "list": ["org", "blacklist", "list"],
        "hook": ["org", "hook"],
        "apply": ["org", "change", "apply"],
        "events": ["event", "tail"],
        "blob": ["blob", "read"],
        "brief": ["brief", "start"],
        "status": ["lane", "status"],
    }
    end = time.monotonic() + args.deadline
    index = 0
    while time.monotonic() < end:
        name = f"{index:04d}"
        job_path = queue / (name + ".job.json")
        if not job_path.is_file():
            time.sleep(0.1)
            continue
        job = json.loads(job_path.read_text())
        if job["kind"] == "stop":
            atomic(queue / (name + ".reply.json"), {"stopped": True})
            return 0
        request_path = queue / (name + ".request.json")
        request_path.write_text(json.dumps(job["request"]) + "\n")
        request_bytes = request_path.read_bytes()
        hook_bytes = None
        if job["kind"] == "hook":
            command_path = queue / (name + ".command")
            command, hook_bytes = hook_command(args.binary, args.config, job["request"], command_path)
        else:
            command = [
                args.binary, *commands[job["kind"]], "--config", args.config,
                "--request", str(request_path),
            ]
        key = job["idempotency_key"]
        if job["kind"] in ("hook", "apply"):
            if re.fullmatch(r"[A-Za-z0-9_-]{22,128}", key) is None:
                raise RuntimeError("mutation job lacks its retained key")
            command.extend(["--idempotency-key", key])
        elif key:
            raise RuntimeError("read job unexpectedly claims a mutation key")
        try:
            retained = lane_descriptors(args.config, LANE_BINDING)
        except HandoffRefusal as error:
            atomic(queue / (name + ".wait.json"), error.projection())
            return 69
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, pass_fds=retained
        )
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate(timeout=5)
            timed_out = True
        reply = {
            "exit": process.returncode, "timed_out": timed_out,
            "stdout_bytes": base64.b64encode(stdout).decode(),
            "stderr_bytes": base64.b64encode(stderr).decode(),
            "request_bytes": base64.b64encode(request_bytes).decode(),
            "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
            "request": job["request"], "command": command,
            "binary_sha256": binary_hash, "config": args.config,
            "contract_revision": metadata["contract_revision"],
            "idempotency_key": key,
        }
        if hook_bytes is not None:
            if command_path.read_bytes() != hook_bytes:
                raise RuntimeError("hook command file changed during invocation")
            reply["command_file_bytes"] = base64.b64encode(hook_bytes).decode()
            reply["command_file_sha256"] = hashlib.sha256(hook_bytes).hexdigest()
        atomic(queue / (name + ".reply.json"), reply)
        index += 1
    raise RuntimeError("policy worker deadline exceeded")


if __name__ == "__main__":
    raise SystemExit(main())
