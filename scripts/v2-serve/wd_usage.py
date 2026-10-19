"""Outside-only, credential-free quota provider. Not a broker or usage writer.

The installed native usage job must query this declared fixture and retain its
own raw TSV, normalized envelope and authenticated producer. A lane gets only
poll/debit; it cannot select a phase, restore room, read the journal, or submit
normalized evidence. This module never creates a product usage_window object.
"""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
from threading import Lock


class Gate(RuntimeError):
    def __init__(self, message, owner="lb-v2-serve", code="prerequisite_missing"):
        super().__init__(message)
        self.owner, self.code = owner, code


def need(value, message):
    if not value:
        raise Gate(message, code="integrity")


def wire(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def parse(data):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, "fixture JSON has duplicate keys")
            result[key] = value
        return result
    return json.loads(data.decode(), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Gate("nonfinite fixture number")))


def closed(value, names):
    need(isinstance(value, dict) and set(value) == set(names.split()), "fixture field map differs")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def private(path, owners, bound=1048576, *, allow_empty=False):
    path = Path(path)
    need(path.is_absolute(), "fixture input path is relative")
    for parent in path.parents:
        info = parent.lstat()
        sticky = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        need(stat.S_ISDIR(info.st_mode) and info.st_uid in owners | {0}
             and (not info.st_mode & 0o022 or sticky), "fixture ancestor is writable or linked")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        need(stat.S_ISREG(info.st_mode) and info.st_uid in owners and not info.st_mode & 0o077
             and info.st_nlink == 1 and 0 <= info.st_size <= bound and (allow_empty or info.st_size > 0),
             "fixture input is not a private ordinary file")
        data = os.read(descriptor, bound + 1)
        need(len(data) == info.st_size, "fixture input bytes changed")
        return data
    finally:
        os.close(descriptor)


def save(path, data):
    path = Path(path)
    temporary = path.with_name(path.name + "." + secrets.token_hex(8))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        need(stream.write(data) == len(data), "short fixture write")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    need(private(path, {0, os.getuid()}, allow_empty=True) == data, "fixture write readback differs")


def receive(connection, peer, length):
    data = bytearray()
    while len(data) < length:
        block, ancillary, flags, _ = connection.recvmsg(length - len(data), socket.CMSG_SPACE(12) + socket.CMSG_SPACE(256))
        credentials, invalid = [], False
        for level, kind, value in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                for fd in struct.unpack(f"{len(value) // 4}i", value[:len(value) // 4 * 4]):
                    os.close(fd)
                invalid = True
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(value) == 12:
                credentials.append(struct.unpack("3i", value))
            else:
                invalid = True
        need(block and not invalid and credentials == [peer]
             and not flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC), "fixture frame writer differs")
        data.extend(block)
    return bytes(data)


def read_frame(connection, peer):
    length, = struct.unpack(">I", receive(connection, peer, 4))
    need(0 < length <= 1048576, "fixture frame exceeds its bound")
    return parse(receive(connection, peer, length))


def send_frame(connection, value):
    data = wire(value)
    need(0 < len(data) <= 1048576, "fixture reply exceeds its bound")
    connection.sendall(struct.pack(">I", len(data)) + data)


CELLS = {"limit", "no-room", "tamper", "stop-race", "resume-race", "restart"}
NEXT = {"seed": {"ready"}, "ready": {"limit", "exhausted", "attacks"},
        "attacks": {"limit"}, "limit": set(), "exhausted": {"restored"}, "restored": set()}


class Ledger:
    def __init__(self, directory, profiles, *, case_uid, runner_uids, usage_uid, capacity=7):
        self.directory = Path(directory)
        info = self.directory.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
             and stat.S_IMODE(info.st_mode) == 0o700, "quota journal directory is not private")
        need(type(case_uid) is int and (usage_uid is None or type(usage_uid) is int) and case_uid != os.getuid()
             and usage_uid not in {case_uid, os.getuid()} and runner_uids
             and all(type(uid) is int and uid not in {0, case_uid, usage_uid, os.getuid()} for uid in runner_uids),
             "quota provider requires separate case, usage and lane principals")
        need(type(capacity) is int and 1 <= capacity <= 100000 and len(profiles) >= 2
             and len(set(profiles)) == len(profiles)
             and all(isinstance(p, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", p) for p in profiles),
             "quota provider profile inventory differs")
        self.profiles, self.case_uid = tuple(profiles), case_uid
        self.runner_uids, self.usage_uid = set(runner_uids), usage_uid
        self.usage_uids = set() if usage_uid is None else {usage_uid}
        self.usage_leases = {}
        self.capacity, self.lock = capacity, Lock()
        self.path = self.directory / "ledger.json"
        if self.path.exists():
            self.state = parse(private(self.path, {os.getuid()}))
            need(self.state["profiles"] == list(profiles) and self.state["capacity"] == capacity,
                 "quota provider reconstruction changed its enrollment")
        else:
            self.state = {"schema": "laneboss.wd-quota.v1", "profiles": list(profiles), "capacity": capacity,
                          "generation": 0, "cell": "", "phase": "", "nonce_sha256": "", "used": {}, "history": []}
            save(self.path, wire(self.state))

    def commit(self, event):
        self.state["generation"] += 1
        self.state["history"].append(dict(event, generation=self.state["generation"],
            observed_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")))
        need(len(self.state["history"]) <= 100000, "quota fixture history exceeds its bound")
        save(self.path, wire(self.state))

    def enroll(self, peer_uid, request):
        closed(request, "schema lease_id uid active")
        need(peer_uid == 0 and request["schema"] == "laneboss.wd-enroll.v1"
             and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", request["lease_id"])
             and type(request["uid"]) is int and type(request["active"]) is bool
             and request["uid"] not in {0, self.case_uid, os.getuid()}, "usage enrollment requires the actual root helper")
        with self.lock:
            lease, uid = request["lease_id"], request["uid"]
            previous = self.usage_leases.get(lease)
            need(previous in {None, uid}, "usage enrollment changed its original allocation")
            if request["active"]:
                need(previous == uid or uid not in self.usage_uids, "usage UID is retained by another lease")
                self.usage_leases[lease] = uid
                self.usage_uids.add(uid)
            else:
                need(previous == uid, "usage collection has no original enrollment")
                self.usage_uids.remove(uid)
                del self.usage_leases[lease]
            self.commit({"kind": "usage-enrollment", **request})
        return {"schema": "laneboss.wd-enrolled.v1", "lease_id": lease, "uid": uid, "active": request["active"]}

    def control(self, path):
        # The G0 adapter mirrors exact root-owned phase bytes into the
        # provider's own private directory. No lane UID owns either path.
        control = parse(private(path, {0, self.case_uid, os.getuid()}))
        closed(control, "cell phase nonce")
        need(control["cell"] in CELLS and control["phase"] in NEXT
             and re.fullmatch(r"[a-f0-9]{32}", control["nonce"]), "quota phase input differs")
        token = digest(control["nonce"].encode())
        with self.lock:
            previous = self.state["phase"]
            if self.state["cell"] == control["cell"] and self.state["nonce_sha256"] == token:
                if control["phase"] == previous:
                    return
                need(control["phase"] in NEXT[previous], "quota phase moved backwards or skipped a fence")
            else:
                need(control["phase"] == "seed", "quota cell did not begin with a fresh seed")
                need(not any(item.get("nonce_sha256") == token for item in self.state["history"]), "quota cell reused its nonce")
                self.state.update(cell=control["cell"], nonce_sha256=token, used={p: 0 for p in self.profiles})
            phase = control["phase"]
            if phase in {"limit", "exhausted"}:
                selected = self.profiles if phase == "exhausted" else self.profiles[:1]
                for profile in selected:
                    self.state["used"][profile] += max(0, self.capacity - self.state["used"][profile])
            elif phase == "restored":
                self.state["used"][self.profiles[1]] = 0
            self.state["phase"] = phase
            self.commit({"kind": "phase", "cell": control["cell"], "phase": phase, "nonce_sha256": token})

    def request(self, peer_uid, request):
        closed(request, "schema op request_id profile_id cell")
        need(request["schema"] == "laneboss.wd-provider.v1" and re.fullmatch(r"[a-f0-9]{32}", request["request_id"]),
             "quota request has another schema or correlation")
        op = request["op"]
        with self.lock:
            if op == "usage":
                need(peer_uid in self.usage_uids, "only the outside usage worker may query usage")
                need(bool(self.state["cell"]) and request["cell"] in {"", self.state["cell"]}
                     and request["profile_id"] in {"", *self.profiles}, "usage query crossed its enrolled inventory")
                reset = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
                rows = ["PROFILE\tPLAN\tWINDOW\tUSED_PERCENT\tRESETS_UTC"]
                for profile in self.profiles:
                    used = self.state["used"][profile] * 100 / self.capacity
                    rows.append(f"{profile}\tfixture\tcurrent\t{used:.8g}\t{reset}")
                data = ("\n".join(rows) + "\n").encode()
                result = {"raw": base64.b64encode(data).decode(), "sha256": digest(data), "bytes": len(data)}
            else:
                need(op == "poll" and peer_uid in self.runner_uids and peer_uid not in self.usage_uids, "quota operation is outside the enrolled runner capability")
                need(request["cell"] == self.state["cell"] and request["profile_id"] in self.profiles,
                     "quota request crossed its active cell or selected profile")
                profile, phase = request["profile_id"], self.state["phase"]
                used = self.state["used"][profile]
                action = "wait"
                if phase == "attacks":
                    action = "attacks"
                elif phase in {"limit", "exhausted", "restored"}:
                    action = "limit" if used >= self.capacity else "complete"
                    if action == "complete":
                        self.state["used"][profile] += 1
                        self.commit({"kind": "debit", "profile_id": profile, "cell": request["cell"]})
                result = {"action": action, "used": self.state["used"][profile], "capacity": self.capacity}
            return {"schema": "laneboss.wd-provider-reply.v1", "request_id": request["request_id"],
                    "generation": self.state["generation"], "result": result}


def serve_one(listener, ledger, control_path):
    connection, _ = listener.accept()
    with connection:
        connection.settimeout(10)
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        peer = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        request = read_frame(connection, peer)
        if request.get("schema") == "laneboss.wd-enroll.v1":
            send_frame(connection, ledger.enroll(peer[1], request))
            return
        ledger.control(control_path)
        send_frame(connection, ledger.request(peer[1], request))


def query(endpoint, provider_uid, profile, cell, op="poll"):
    request = {"schema": "laneboss.wd-provider.v1", "op": op, "profile_id": profile,
               "cell": cell, "request_id": secrets.token_hex(16)}
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(10)
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        connection.connect(str(endpoint))
        peer = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need(peer[0] > 0 and peer[1] == provider_uid, "quota provider kernel peer differs")
        send_frame(connection, request)
        reply = read_frame(connection, peer)
    closed(reply, "schema request_id generation result")
    need(reply["schema"] == "laneboss.wd-provider-reply.v1" and reply["request_id"] == request["request_id"]
         and type(reply["generation"]) is int and reply["generation"] > 0, "quota reply correlation differs")
    return reply["result"]


def main():
    import argparse
    import sys
    parser = argparse.ArgumentParser()
    parser.add_argument("--setup", type=Path, required=True)
    args = parser.parse_args()
    need(sys.platform == "linux", "outside quota fixture requires the disposable Linux host")
    setup = parse(private(args.setup, {0, os.getuid()}))
    closed(setup, "schema directory socket control profiles case_uid runner_uids usage_uid capacity socket_gid")
    need(setup["schema"] == "laneboss.wd-provider-setup.v1", "outside quota setup schema differs")
    ledger = Ledger(setup["directory"], setup["profiles"], case_uid=setup["case_uid"],
                    runner_uids=setup["runner_uids"], usage_uid=setup["usage_uid"], capacity=setup["capacity"])
    endpoint = Path(setup["socket"])
    need(endpoint.is_absolute() and not endpoint.exists(), "quota endpoint must be a new enrolled socket")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(endpoint))
        if os.getuid() == 0:
            os.chown(endpoint, os.getuid(), setup["socket_gid"])
        endpoint.chmod(0o660)
        listener.listen(16)
        while True:
            serve_one(listener, ledger, setup["control"])


if __name__ == "__main__":
    main()
