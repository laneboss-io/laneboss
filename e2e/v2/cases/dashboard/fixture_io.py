"""Private, file-backed handoff to the independent installed fixture owner.

The handoff requests fresh inputs; it never creates identity authority. All
responses and their exact input bytes remain in the case evidence directory.
"""

import hashlib
import base64
import json
import os
from pathlib import Path
import stat
import socket
import struct
import time
import uuid


class FixtureError(RuntimeError):
    def __init__(self, error):
        self.error = error
        super().__init__(json.dumps(error, sort_keys=True))


def private_read(path, limit=4 * 1024 * 1024):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("private input must have an absolute physical path")
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
            or not 0 < before.st_size <= limit):
        raise ValueError("private input ownership, mode, links or size differs")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(limit + 1)
    after = path.lstat()
    if (not os.path.samestat(before, opened) or not os.path.samestat(before, after)
            or len(raw) != before.st_size or after.st_mtime_ns != before.st_mtime_ns):
        raise ValueError("private input changed during read")
    return raw


def private_dir(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("handoff directory must have an absolute physical path")
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("handoff directory must be private and caller-owned")
    return path


def private_write(path, value):
    raw = value if isinstance(value, bytes) else (
        json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    # A handoff response is immutable. A repeated nonce never replaces it.
    if path.exists() or path.is_symlink():
        raise ValueError("preserve existing handoff input")
    temporary.rename(path)
    return raw


class FixtureInputs:
    def __init__(self, path, config, recorder, timeout=120):
        self.recorder, self.config, self.timeout = recorder, config, timeout
        raw = private_read(path)
        self.document = json.loads(raw)
        if (self.document.get("schema") != "laneboss.dash-inputs.v2"
                or self.document.get("config") != config):
            raise ValueError("dashboard inputs schema or configuration differs")
        targets = self.document.get("targets", [])
        if (not isinstance(targets, list) or len(targets) != 5
                or any(not isinstance(t, dict) or not t.get("life_id")
                       or type(t.get("run")) is not int or t["run"] < 1 for t in targets)
                or len({t["life_id"] for t in targets}) != 5):
            raise ValueError("dashboard inputs require five independent actual action targets")
        self.root = private_dir(self.document["handoff"])
        self.requests = private_dir(self.root / "requests")
        self.responses = private_dir(self.root / "responses")
        self.cache, self.wires = {}, {}
        self.operation_ids = []
        self.recorder.save("inputs/fixture.json", raw)

    def observed_operation(self, operation_id):
        if operation_id not in self.operation_ids:
            self.operation_ids.append(operation_id)

    def observer(self, request):
        """G0's private IPC carries inputs, never product authority."""
        request = dict(request, token=os.environ["LANEBOSS_ITEM_TOKEN"])
        raw = json.dumps(request, separators=(",", ":")).encode()
        if len(raw) > 2 << 20:
            raise ValueError("dashboard observer request exceeds its bound")
        def exact(peer, size):
            result = bytearray()
            while len(result) < size:
                part = peer.recv(size - len(result))
                if not part:
                    raise ValueError("dashboard observer closed before its reply")
                result.extend(part)
            return bytes(result)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
            peer.settimeout(self.timeout)
            peer.connect(os.environ["LANEBOSS_ITEM_SOCKET"])
            peer.sendall(struct.pack("!I", len(raw)) + raw)
            size = struct.unpack("!I", exact(peer, 4))[0]
            if not 0 < size <= 2 << 20:
                raise ValueError("dashboard observer reply exceeds its bound")
            response = exact(peer, size)
        self.recorder.save("handoff/" + uuid.uuid4().hex + ".observer.json", response)
        return json.loads(response)

    def observer_exchange(self, request):
        if request["kind"] == "collect":
            # G0 caches and independently validates this same receipt for its
            # post-entry collection gate. It does not invoke collection twice.
            if request.get("failure"):
                self.observer({"action": "rpc", "command": "dashboard inputs",
                    "request": request, "denied": False, "request_id": request["nonce"],
                    "idempotency_key": request["nonce"]})
                raise FixtureError(request["failure"])
            receipt = self.observer({"action": "collect", "operation_ids": self.operation_ids})
            if (receipt.get("processes_quiescent") is not True
                    or receipt.get("temporary_resources_collected") is not True
                    or not set(self.operation_ids) <= set(receipt.get("operation_ids", []))):
                raise ValueError("G0 collection receipt omitted a managed dashboard operation")
            refs = [ref for ref in receipt.get("evidence", []) if ref.get("path") == "outside-dashboard.json"]
            if len(refs) != 1:
                raise ValueError("G0 collection lacks its exact external dashboard report")
            ref = refs[0]
            raw = private_read(self.recorder.root / ref["path"])
            if len(raw) != ref["bytes"] or hashlib.sha256(raw).hexdigest() != ref["sha256"]:
                raise ValueError("external dashboard report differs from G0 receipt")
            return json.loads(raw)
        reply = self.observer({"action": "rpc", "command": "dashboard inputs", "request": request,
            "denied": False, "request_id": request["nonce"], "idempotency_key": request["nonce"]})
        if reply.get("exit_code") != 0:
            raise FixtureError(json.loads(base64.b64decode(reply["stderr"], validate=True)))
        response = json.loads(base64.b64decode(reply["stdout"], validate=True))
        if any(response.get(field) != request[field] for field in request):
            raise ValueError("G0 input reply differs from its exact dashboard request")
        if response.get("error"):
            raise FixtureError(response["error"])
        return response["result"]

    def exchange(self, kind, key, failure=None):
        nonce = uuid.uuid4().hex
        request = {"schema": "laneboss.dash-handoff.v2", "config": self.config,
                   "nonce": nonce, "kind": kind, "key": key}
        if failure is not None:
            request["failure"] = failure
        if os.environ.get("LANEBOSS_ITEM_SOCKET"):
            self.recorder.save("handoff/" + nonce + ".request.json", request)
            return self.observer_exchange(request)
        raw = private_write(self.requests / (nonce + ".json"), request)
        self.recorder.save("handoff/" + nonce + ".request.json", raw)
        response = self.responses / (nonce + ".json")
        deadline = time.monotonic() + self.timeout
        while not response.exists():
            if time.monotonic() >= deadline:
                raise FixtureError({"code": "deadline_exceeded", "owner": "lb-v2-dashboard",
                                    "message": "installed fixture handoff deadline"})
            time.sleep(0.05)
        raw = private_read(response)
        self.recorder.save("handoff/" + nonce + ".response.json", raw)
        result = json.loads(raw)
        if any(result.get(field) != request[field] for field in request):
            raise ValueError("fixture response differs from its exact request")
        if result.get("error"):
            raise FixtureError(result["error"])
        return result["result"]

    def cli(self, aid):
        value = self.exchange("cli-proof", aid)
        raw = private_read(value["proof_file"])
        proof = json.loads(raw)
        if (not proof.get("id") or not proof.get("expires_at")
                or proof.get("request_sha256") != hashlib.sha256(
                    json.dumps({"config": self.config, "method": "human.session", "params": {},
                                "protocol": "laneboss.rpc.v2", "schema": 2},
                               sort_keys=True, separators=(",", ":")).encode()).hexdigest()):
            raise ValueError("CLI proof does not authorize the empty human.session prelude")
        self.recorder.save("inputs/" + aid.lower() + ".session.json", raw)
        return value["proof_file"]

    def get(self, aid, default=None):
        if aid not in self.cache:
            value = self.exchange("action", aid)
            raw = private_read(value["request_file"])
            self.recorder.save("inputs/" + aid.lower() + ".exact.json", raw)
            self.cache[aid], self.wires[aid] = json.loads(raw), raw
        return self.cache.get(aid, default)

    def wire(self, aid):
        self.get(aid)
        return self.wires[aid]

    def collect(self, failure=None):
        return self.exchange("collect", "external", failure)


def _external_collected(report, required):
    """Check measured read-backs, not the fixture's aggregate success flags."""
    if not isinstance(report, dict) or report.get("schema") != "laneboss.dash-collection.v2":
        return False
    rows = report.get("targets")
    if not isinstance(rows, list) or not rows or not required:
        return False
    seen = set()
    for row in rows:
        target = row.get("target", {})
        key = (target.get("life_id"), target.get("run"))
        check, lane = row.get("check", {}), row.get("status", {})
        archive, operation = row.get("archive", {}), row.get("clean_operation", {})
        native = row.get("native", {})
        if (key in seen or not key[0] or type(key[1]) is not int or key[1] < 1
                or check.get("handle", {}).get("target") != target
                or not check.get("handle", {}).get("containment_id")
                or check.get("state") != "exited" or type(check.get("survivors")) is not int or check.get("survivors") != 0
                or not check.get("observed_at")
                or (type(check.get("exit_code")) is not int and type(check.get("signal")) is not int)
                or lane.get("life_id") != key[0] or lane.get("run") != key[1]
                or lane.get("cleaned") is not True or lane.get("state") not in ("merged", "abandoned")
                or not archive.get("id") or archive.get("life_id") != key[0]
                or not archive.get("archive_sha256")
                or archive.get("archive_sha256") != archive.get("read_back_sha256")
                or operation.get("status") != "succeeded" or operation.get("error")
                or not operation.get("id") or operation.get("last_seq", 0) <= 0
                or operation.get("life_id") != key[0] or operation.get("run") != key[1]
                or lane.get("last_seq", 0) < operation.get("last_seq", 0)
                or native.get("action") != "remove_clean"
                or native.get("helper_journal_complete") is not True
                or native.get("worktree_measured") is not True or native.get("branch_measured") is not True
                or not native.get("journal_sha256") or not native.get("enrollment_sha256")):
            return False
        observations = row.get("observations", [check])
        for observation in observations:
            observed = observation.get("handle", {}).get("target", {})
            observed_key = (observed.get("life_id"), observed.get("run"))
            if (observed_key[0] != key[0] or type(observed_key[1]) is not int
                    or not 1 <= observed_key[1] <= key[1] or observed_key in seen
                    or observation.get("state") != "exited" or type(observation.get("survivors")) is not int
                    or observation.get("survivors") != 0
                    or not observation.get("observed_at")
                    or not observation.get("handle", {}).get("containment_id")
                    or (type(observation.get("exit_code")) is not int
                        and not (type(observation.get("signal")) is int and observation["signal"] > 0))):
                return False
            seen.add(observed_key)
        if key not in seen:
            return False
    https = report.get("https", {})
    return bool(set(required) <= seen
                and https.get("cookie_after_close_status") == 401
                and https.get("listener_errno") == 111
                and type(https.get("listener_pid")) is int and https["listener_pid"] > 0
                and type(https.get("listener_exit")) is int
                and type(https.get("session_pid")) is int and https["session_pid"] > 0
                and type(https.get("session_exit")) is int
                and https.get("session_pid") != https.get("listener_pid")
                and report.get("presence") == "simulated"
                and report.get("human_approval") == "not_proven")


def external_collected(report, required):
    try:
        return _external_collected(report, required)
    except (KeyError, TypeError, AttributeError, ValueError):
        return False
