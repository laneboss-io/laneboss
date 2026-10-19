"""Owned Linux harness adapters; no product responses or authority are simulated."""

import hashlib
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import subprocess


class CaseFailure(Exception):
    pass


class CaseWait(CaseFailure):
    code = "prerequisite_missing"

    def __init__(self, wait_for, message):
        super().__init__(message)
        self.wait_for = wait_for

    def failure(self):
        return {"code": self.code, "owner": "lb-v2-approval", "message": str(self),
                "instead": "Supply the genuine named prerequisite and rerun this isolated case; no approval or effect is recorded by waiting.",
                "wait_for": self.wait_for}


class OwnerWait(CaseWait):
    def __init__(self, message):
        super().__init__("owner_confirmation", message)


def require(condition, message):
    if not condition:
        raise CaseFailure(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data):
    def members(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "duplicate JSON member")
            value[key] = item
        return value
    return json.loads(data, object_pairs_hook=members)


def read_json(path):
    return strict_json(Path(path).read_bytes())


def dump(path, value):
    data = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
    with Path(path).open("xb") as output:
        os.chmod(path, 0o600)
        output.write(data)


def protected_json(path, owners):
    path = Path(path)
    require(path.is_absolute(), "protected file must be absolute")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        facts = os.fstat(stream.fileno())
        require(stat.S_ISREG(facts.st_mode) and not facts.st_mode & 0o022 and facts.st_uid in owners,
                "protected file has untrusted ownership or writable mode")
        data = stream.read(1048577)
        require(len(data) <= 1048576, "protected JSON exceeds its frame bound")
        return strict_json(data)


def lane_projection(settings):
    """Retain only the installed sealed binding and O_PATH endpoint at their FDs.

    These checks establish a safe descriptor handoff. The child CLI still
    authenticates the native service/containment/launch for every RPC.
    """
    require(settings["binding_file"] == "/run/laneboss/binding.json",
            "lane job requires its fixed sealed binding projection")
    bound = os.environ.get("LANEBOSS_CONFIG", "")
    require(not bound or bound == settings["config"], "lane job conflicts with its active configuration")

    def projected(path):
        link = os.readlink(path)
        prefix = "/proc/self/fd/"
        require(link.startswith(prefix), "lane projection is not an inherited descriptor")
        word = link[len(prefix):]
        require(word.isascii() and word.isdecimal(), "lane projection has an invalid descriptor")
        descriptor = int(word)
        require(6 <= descriptor <= 4096 and str(descriptor) == word,
                "lane projection has an invalid descriptor number")
        return descriptor

    binding_fd = projected(settings["binding_file"])
    before = os.fstat(binding_fd)
    seals = fcntl.fcntl(binding_fd, fcntl.F_GET_SEALS)
    required = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
    require(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o444 and
            0 < before.st_size <= 1048576 and seals & required == required,
            "lane binding is not exactly sealed and read-only")
    raw = os.pread(binding_fd, before.st_size + 1, 0)
    require(len(raw) == before.st_size, "lane binding changed its sealed length")
    binding = strict_json(raw)
    require(binding["class"] == "lane" and binding["config"] == settings["config"] and
            binding["artifact_sha256"] == settings["binary_sha256"] and
            binding["target"] == settings["target"] and
            binding["socket"] == "/run/laneboss/service.sock",
            "registered CLI job has a different sealed lane binding")
    socket_fd = projected(binding["socket"])
    endpoint = os.fstat(socket_fd)
    require(socket_fd != binding_fd and stat.S_ISSOCK(endpoint.st_mode) and
            stat.S_IMODE(endpoint.st_mode) == 0o666 and endpoint.st_nlink == 1 and
            endpoint.st_uid == binding["mapped_service_uid"] and endpoint.st_gid == binding["mapped_service_gid"] and
            fcntl.fcntl(socket_fd, fcntl.F_GETFL) & os.O_PATH,
            "lane endpoint is not its inherited protected O_PATH socket")
    def stable(facts):
        # A verified read may update atime. Identity, content metadata and the
        # immutable seals remain the handoff pin.
        return (facts.st_dev, facts.st_ino, facts.st_mode, facts.st_uid, facts.st_gid,
                facts.st_nlink, facts.st_size, facts.st_mtime_ns, facts.st_ctime_ns)

    require(projected(settings["binding_file"]) == binding_fd and projected(binding["socket"]) == socket_fd and
            stable(os.fstat(binding_fd)) == stable(before) and stable(os.fstat(socket_fd)) == stable(endpoint),
            "lane projections changed during child handoff")
    return binding, (binding_fd, socket_fd)


def evidence_file(root, ref):
    require(set(ref) == {"path", "sha256", "bytes"}, "invalid evidence reference")
    relative = Path(ref["path"])
    require(not relative.is_absolute() and relative.parts and ".." not in relative.parts,
            "evidence path escapes its root")
    path = root / relative
    for item in [path, *path.parents]:
        if item == root:
            break
        require(not item.is_symlink(), "evidence reference traverses a symlink")
    require(path.resolve(strict=True).is_relative_to(root.resolve(strict=True)), "evidence escaped its root")
    data = path.read_bytes()
    require(len(data) == ref["bytes"] and digest(data) == ref["sha256"], "evidence hash/size mismatch")
    return path


def group_absent(pid):
    try:
        os.killpg(pid, 0)
        return False
    except ProcessLookupError:
        return True
    except PermissionError:
        return False


def execute(argv, timeout=180, pass_fds=()):
    require(isinstance(pass_fds, tuple) and (not pass_fds or
            len(pass_fds) == 2 and len(set(pass_fds)) == 2 and
            all(type(fd) is int and 6 <= fd <= 4096 for fd in pass_fds)),
            "subprocess may inherit only the two validated lane projections")
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True, close_fds=True, pass_fds=pass_fds)
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=10)
    observation = {"pid": process.pid, "exit": process.returncode,
                   "group_absent": group_absent(process.pid), "timed_out": timed_out}
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr), observation


class Controller:
    """The frozen E2E-owner endpoint, with peer and per-operation correlation."""

    def __init__(self, context, keep):
        self.context, self.keep = context, keep
        if "controls" not in context:
            raise CaseWait("installed_controller", "Protected registered CLI/write jobs and fixture clocks must be enrolled before this case can run.")
        # The binding is installer/controller-owned. Its case UID never grants
        # authority merely by being present in this JSON.
        self.binding = protected_json(context["controls"], {0})
        expected = {"schema", "case_id", "config", "socket", "generation", "controller_uid",
                    "case_uid", "binary_sha256", "source_sha256", "live_auth",
                    "service_ids", "canary_ids", "fixture_clock_ids"}
        require(set(self.binding) == expected, "control binding has unknown/missing fields")
        require(self.binding["schema"] == "laneboss.e2e-control-binding.v2" and
                self.binding["generation"] > 0 and self.binding["case_uid"] == os.geteuid() and
                self.binding["live_auth"] is False, "invalid control binding identity/mode")
        for key in ["case_id", "config", "binary_sha256", "source_sha256"]:
            require(self.binding[key] == context[key], "control binding differs from context: " + key)
        self.calls = 0

    def call(self, action, params):
        require(action in {"run_confined_canary", "advance_fixture_clock"}, "unsupported approval control action")
        if action == "run_confined_canary":
            require(params["canary_id"] in self.binding["canary_ids"], "canary is not enrolled")
        else:
            require(params["clock_id"] in self.binding["fixture_clock_ids"], "fixture clock is not enrolled")
        import secrets
        request = {"schema": "laneboss.e2e-control.v2", "case_id": self.context["case_id"],
                   "phase": self.context["phase"], "mutation_id": self.context["mutation_id"],
                   "binary_sha256": self.context["binary_sha256"], "request_id": secrets.token_hex(16),
                   "nonce": secrets.token_hex(16), "action": action, "params": params}
        self.calls += 1
        label = "control-%03d" % self.calls
        self.keep(label + "-request.json", request)
        raw = json.dumps(request, separators=(",", ":")).encode()
        require(0 < len(raw) <= 1048576, "control input frame exceeds bound")
        endpoint = Path(self.binding["socket"])
        require(endpoint.is_absolute() and not endpoint.is_symlink(), "invalid control socket")
        facts = endpoint.lstat()
        require(stat.S_ISSOCK(facts.st_mode) and facts.st_uid == self.binding["controller_uid"] and
                not facts.st_mode & 0o002, "control socket is unprotected")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(180)
            connection.connect(str(endpoint))
            peer = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            pid, uid, gid = struct.unpack("3i", peer)
            require(pid > 0 and uid == self.binding["controller_uid"], "control peer credentials differ")
            self.keep(label + "-peer.json", {"pid": pid, "uid": uid, "gid": gid})
            connection.sendall(struct.pack(">I", len(raw)) + raw)

            def receive(length):
                data = bytearray()
                while len(data) < length:
                    part = connection.recv(length - len(data))
                    require(part, "control response ended before its frame")
                    data.extend(part)
                return bytes(data)

            size = struct.unpack(">I", receive(4))[0]
            require(0 < size <= 1048576, "invalid control response frame")
            reply = strict_json(receive(size))
        self.keep(label + "-reply.json", reply)
        require(reply.get("schema") == "laneboss.e2e-control-reply.v2", "invalid control response schema")
        for key in ["case_id", "request_id", "nonce", "binary_sha256"]:
            require(reply.get(key) == request[key], "uncorrelated control response: " + key)
        require("error" not in reply, "controller refused dependency: " + str(reply.get("error", {}).get("code")))
        require(set(reply) == {"schema", "case_id", "request_id", "nonce", "binary_sha256", "action", "result"} and
                reply["action"] == action, "invalid control result envelope")
        measured = reply["result"]
        keys = ({"job_id", "target", "observed_exit", "containment_state", "survivors", "input_sha256", "evidence"}
                if action == "run_confined_canary" else {"clock_id", "generation", "from", "to", "evidence"})
        require(set(measured) == keys and measured["evidence"], "invalid/missing control observations")
        for ref in measured["evidence"]:
            evidence_file(Path(self.context["evidence_root"]), ref)
        if action == "run_confined_canary":
            require(measured["job_id"] and measured["target"] == params["target"] and
                    measured["input_sha256"] == params["input"]["sha256"] and
                    measured["containment_state"] == "exited" and type(measured["survivors"]) is int and
                    measured["survivors"] == 0 and type(measured["observed_exit"]) is int,
                    "canary did not observe matching input/target or known quiescence")
        else:
            require(measured["clock_id"] == params["clock_id"] and
                    measured["generation"] == params["expected_generation"] + 1 and
                    measured["from"] == params["from"] and measured["to"] == params["to"],
                    "fixture clock advance was not measured")
        return measured

