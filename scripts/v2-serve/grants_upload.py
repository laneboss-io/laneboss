"""File handoff to one ordinary installed human-session CLI process."""

import json
import os
from pathlib import Path
import subprocess
import time
import uuid


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def require(value, reason):
    if not value:
        raise ValueError(reason)


def publish(path, raw):
    path = Path(path)
    require(not path.exists(), "upload flow input already exists")
    pending = path.with_name(path.name + ".pending")
    with pending.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    pending.chmod(0o600)
    pending.rename(path)
    require(path.read_bytes() == raw, "upload flow retained bytes differ")


def plan(directory):
    directory = Path(directory)
    steps = [
        {"name": "task-secret-key", "method": "secret.key", "request": str(directory / "key.json")},
        {"name": "task-secret-stage", "method": "secret.stage", "request": str(directory / "stage.json")},
        {"name": "task-secret-import", "method": "secret.import", "request": str(directory / "import.json"),
         "proof": str(directory / "import.proof.json")},
    ]
    for step in steps:
        step.update(request_id=uuid.uuid4().hex, idempotency_key=uuid.uuid4().hex)
    return {"schema": "laneboss.client-flow.v2", "steps": steps}


class Refused(RuntimeError):
    def __init__(self, error):
        super().__init__("installed secret upload flow refused")
        self.error = error


class FileFlow:
    def __init__(self, directory, binary, config, binding, proof, selected):
        self.directory = Path(directory)
        self.config = config
        self.selected = selected
        self.steps = [{"name": "human-session", "method": "human.session"}, *selected["steps"]]
        self.receipts = {}
        self.lines = 0
        self.process = None
        self.completed = False
        self.refusal = None
        self.out = self.directory / "client.stdout"
        self.err = self.directory / "client.stderr"
        publish(self.directory / "flow.json", encoded(selected))
        self.supply("task-secret-key", {})
        self.argv = [str(binary), "human", "session", "--config", config, "--binding", str(binding),
                     "--flow", str(self.directory / "flow.json"), "--proof", str(proof),
                     "--wait", "90s", "--request-id", uuid.uuid4().hex,
                     "--idempotency-key", uuid.uuid4().hex]
        publish(self.directory / "client.argv.json", encoded(self.argv))

    def supply(self, name, value):
        step = next(row for row in self.selected["steps"] if row["name"] == name)
        publish(step["request"], encoded(value))

    def supply_proof(self, name, proof):
        step = next(row for row in self.selected["steps"] if row["name"] == name)
        publish(step["proof"], Path(proof).read_bytes())

    def __enter__(self):
        self.stdout = self.out.open("xb")
        self.stderr = self.err.open("xb")
        try:
            self.process = subprocess.Popen(self.argv, stdin=subprocess.DEVNULL,
                stdout=self.stdout, stderr=self.stderr,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
        except OSError:
            self.stdout.close()
            self.stderr.close()
            publish(self.directory / "client.exit.json", encoded({"started": False, "completed": False}))
            raise
        return self

    def scan(self):
        raw = self.out.read_bytes()
        require(len(raw) <= 4 * 1048576, "upload flow transcript exceeds its bound")
        lines = raw.split(b"\n")[:-1]
        for line in lines[self.lines:]:
            self.lines += 1
            record = json.loads(line)
            if "wait" in record:
                require(record.get("completed") is False and
                        record["wait"].get("code") == "prerequisite_missing" and
                        record.get("step") in ("fixture_preparation", "human_confirmation"),
                        "upload flow wait was credited or lost its prerequisite")
                continue
            require(len(self.receipts) < len(self.steps), "upload flow returned an extra response")
            step = self.steps[len(self.receipts)]
            request, response = record["request"], record["response"]
            require(record.get("name") == step["name"] and request.get("method") == step["method"] and
                    request.get("config") == self.config and request.get("request_id") and
                    response.get("request_id") == request["request_id"],
                    "upload flow response lost its request correlation")
            if step["name"] != "human-session":
                require(request.get("params") == json.loads(Path(step["request"]).read_bytes()) and
                        request.get("request_id") == step["request_id"] and
                        request.get("idempotency_key") == step["idempotency_key"],
                        "upload flow changed the retained request or retry key")
                if step.get("proof"):
                    require(request.get("proof") == json.loads(Path(step["proof"]).read_bytes()),
                            "upload flow changed the exact operation proof")
                else:
                    require("proof" not in request, "upload flow replaced its live session with a proof")
            self.receipts[step["name"]] = record
            if response.get("error"):
                self.refusal = response["error"]
                raise Refused(self.refusal)

    def response(self, name):
        deadline = time.monotonic() + 95
        while True:
            self.scan()
            if name in self.receipts:
                return self.receipts[name]["response"]["result"]
            if self.process.poll() is not None:
                raw = self.err.read_bytes()
                if raw:
                    error = json.loads(raw)
                    if isinstance(error, dict) and error.get("code"):
                        self.refusal = error
                        raise Refused(error)
                raise ValueError("installed upload flow ended before its required response")
            require(time.monotonic() < deadline, "installed upload flow response timed out")
            time.sleep(0.05)

    def finish(self):
        code = self.process.wait(timeout=10)
        self.scan()
        require(code == 0 and len(self.receipts) == len(self.steps),
                "installed upload flow did not complete all selected operations")
        self.completed = True

    def __exit__(self, kind, value, traceback):
        try:
            if self.refusal and self.process.poll() is None:
                try:
                    self.process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    # The following PID-owned termination retains this timeout
                    # and the original typed refusal; it does not retry a call.
                    self.refusal_exit_timed_out = True
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
        finally:
            self.stdout.close()
            self.stderr.close()
            publish(self.directory / "client.exit.json", encoded({"started": True,
                "pid": self.process.pid, "exit_code": self.process.returncode,
                "completed": self.completed, "refusal": self.refusal,
                "refusal_exit_timed_out": getattr(self, "refusal_exit_timed_out", False)}))
