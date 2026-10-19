"""Case-owned G0 client; the original outside human executes product RPCs."""

import base64
import importlib.util
import json
from pathlib import Path
import uuid


spec = importlib.util.spec_from_file_location(
    "linux_observer_wire", Path(__file__).resolve().parent.parent / "grants/observer.py")
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)


def available():
    return wire.available()


class Network:
    def __init__(self, remote, addresses):
        self.remote, self.addresses = remote, addresses

    def positive_control(self, payload):
        return self.remote.hook("network-positive", {"payload_hex": payload.hex()})

    def finish(self):
        return self.remote.hook("network-finish", {})

    def close(self):
        return self.remote.hook("network-close", {})


class Remote:
    def __init__(self, case):
        self.case = case
        self.operations, self.index = [], 0
        inputs = json.loads((case.root / "canary-input.json").read_bytes())
        self.network = Network(self, inputs["foreign"])

    def rpc(self, words, body, request_id, key):
        if self.case.refused:
            raise RuntimeError("Linux observer stopped at its first refusal")
        try:
            result = wire.exchange({"action": "rpc", "command": " ".join(words),
                "request": body, "denied": False, "request_id": request_id,
                "idempotency_key": key})
            if type(result.get("exit_code")) is not int:
                raise RuntimeError("G0 transport omitted its actual CLI exit")
            for name in ("stdout", "stderr"):
                base64.b64decode(result[name], validate=True)
            return result
        except (AssertionError, OSError, ValueError, KeyError, RuntimeError, TypeError) as error:
            self.case.refused = True
            raise RuntimeError("installed Linux observer stopped; retain its original gate") from error

    def after_call(self, words, body, result):
        if words in (["lane", "start"], ["lane", "stop"], ["lane", "mark"], ["lane", "clean"]):
            if not result.get("id") or not result.get("status"):
                raise RuntimeError("managed Linux operation identity is missing")
            if result["id"] not in self.operations:
                self.operations.append(result["id"])

    def hook(self, action, body):
        self.index += 1
        name = "handoff/" + str(self.index)
        self.case.keep(name + ".request.json", json.dumps({"action": action, "request": body}, sort_keys=True).encode())
        result = self.rpc(["linux", action], body, uuid.uuid4().hex, uuid.uuid4().hex)
        raw = base64.b64decode(result["stdout"], validate=True)
        self.case.keep(name + ".stdout", raw)
        self.case.keep(name + ".stderr", base64.b64decode(result["stderr"], validate=True))
        self.case.keep(name + ".exit", (str(result["exit_code"]) + "\n").encode())
        if result["exit_code"] != 0:
            self.case.refused = True
            raise RuntimeError("installed Linux private observer failed")
        value = json.loads(raw)
        known = {ref["path"]: ref for ref in self.case.references}
        for ref in value["evidence"]:
            if ref["path"] in known and known[ref["path"]] != ref:
                raise RuntimeError("outside Linux evidence was rewritten")
            if ref["path"] not in known:
                self.case.references.append(ref)
        return value["data"]

    def before_start(self, case, cell):
        self.hook("before-start", {"cell": cell})

    def after_start(self, case, record, operation):
        value = self.hook("after-start", {"target": record["target"],
            "cell": record["cell"], "operation": operation})
        record["cell"].update(value["cell"])
        record["uid"] = value["uid"]

    def release_input(self, case, record, raw):
        self.hook("release-input", {"cell": record["cell"],
            "input": base64.b64encode(raw).decode()})

    def check_foreign(self, case, phase):
        self.hook("foreign", {"phase": phase})

    def review(self, case, target, cell):
        return self.hook("review", {"target": target})

    def collect(self):
        if self.case.refused:
            raise RuntimeError("independent Linux collection stopped at its original refusal")
        try:
            return wire.exchange({"action": "collect", "operation_ids": self.operations})
        except (AssertionError, OSError, ValueError, KeyError) as error:
            raise RuntimeError("independent Linux collection is incomplete") from error
