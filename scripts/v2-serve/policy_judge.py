#!/usr/bin/python3 -I
"""Credential-free HTTP fixture and private outside controller.

Only Noul provider answers are supplied here. Policy decisions, inheritance,
thresholds, reservations, worker identity and native collection remain in the
installed product. This fixture does not measure model quality or inference.
"""

import argparse
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import tempfile
import threading
import time


OUTAGES = ("timeout", "partial", "cost")
# This declared fake model classifies command/rule pairs, never issued IDs,
# actors, expected policy verdicts or a selector in a public policy request.
CLASSIFIERS = (
    ("Cloud machine creation", r"\b(?:aws\s+ec2\s+run-instances|gcloud\s+compute\s+instances\s+create)\b", .90),
    ("Pull request creation", r"\bgh\s+pr\s+create\b", .99),
    ("Restricted org publishing plugins", r"\brestricted\s+org\s+publishing\s+plugin\b", .99),
    ("Do not read the newly restricted", r"\bcat\s+(?:\./)?public-readme\.txt\b", .99),
)


def require(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def document(raw):
    def members(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON member")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("nonfinite JSON number")
    value = json.loads(raw, object_pairs_hook=members, parse_constant=invalid)
    require(isinstance(value, dict), "JSON object required")
    return value


def private(path, maximum=2 << 20):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
                and 0 < info.st_size <= maximum, "unsafe fixture input")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        stamp = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
        require(stamp(info) == stamp(after) == stamp(path.lstat()) and len(raw) == info.st_size,
                "fixture input changed")
        return raw


def keep(path, value, mode=0o600):
    path = Path(path)
    raw = value if isinstance(value, bytes) else encoded(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    require(private(path) == raw, "retained fixture bytes differ")
    path.chmod(mode)
    return {"path": str(path), "sha256": sha(raw), "bytes": len(raw)}


def receive(peer):
    def exact(size):
        raw = bytearray()
        while len(raw) < size:
            part = peer.recv(size - len(raw))
            require(part, "controller frame ended early")
            raw.extend(part)
        return bytes(raw)
    size = struct.unpack("!I", exact(4))[0]
    require(0 < size <= 2 << 20, "controller frame exceeds bound")
    return document(exact(size))


def send(peer, value):
    raw = encoded(value)
    require(0 < len(raw) <= 2 << 20, "controller reply exceeds bound")
    peer.sendall(struct.pack("!I", len(raw)) + raw)


def score(command, rule):
    return max((value for prefix, expression, value in CLASSIFIERS
                if rule.startswith(prefix) and re.search(expression, command)), default=0.0)


class Fixture:
    def __init__(self, root, config, judge, reserve, staging):
        self.root = Path(root) / "policy-http"
        self.root.mkdir(mode=0o700)
        self.inputs = Path(staging) / "exchanges"
        self.inputs.mkdir(mode=0o700)
        self.config, self.judge, self.reserve = config, judge, reserve
        self.lock = threading.RLock()
        self.idle = threading.Condition(self.lock)
        self.done = threading.Event()
        self.phase, self.generation, self.nonce = "normal", None, None
        self.requests, self.refs, self.errors = [], [], []
        self.active, self.controls = 0, 0
        self.collection = None
        fixture = self
        class Provider(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                fixture.respond(self)
            def log_message(self, *_):
                # Exact HTTP bytes and status live in private files below.
                return
        self.http = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Provider)
        self.http.daemon_threads = False
        self.http.block_on_close = True
        self.endpoint = "http://127.0.0.1:%d" % self.http.server_address[1]
        self.socket_root = Path(tempfile.mkdtemp(prefix="lb-v2-case-policy-",
            dir="/run" if os.geteuid() == 0 else "/tmp"))
        self.socket_root_identity = self.socket_root.lstat().st_ino
        self.path = self.socket_root / "control.sock"
        self.control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.control.bind(str(self.path))
        self.path.chmod(0o600)
        self.socket_identity = self.path.lstat().st_ino
        self.control.listen(1)
        self.control.settimeout(0.2)
        self.threads = [threading.Thread(target=lambda: self.http.serve_forever(poll_interval=0.1),
                                       name="policy-http"),
                        threading.Thread(target=self.serve_control, name="policy-control")]
        for thread in self.threads:
            thread.start()
        self.retain("startup.json", {"config": config, "endpoint": self.endpoint,
            "pid": os.getpid(), "uid": os.geteuid(), "judge": judge,
            "reserve_micros": reserve, "fixture": True, "live_inference": False})

    def retain(self, name, value):
        with self.lock:
            raw = value if isinstance(value, bytes) else encoded(value)
            ref = keep(self.inputs / name, raw)
            keep(self.root / name, raw)
            self.refs.append(ref)
            return ref

    def respond(self, peer):
        with self.lock:
            index = len(self.requests)
            stage, generation = self.phase, self.generation
            row = {"stage": stage, "org_generation": generation, "index": index}
            self.requests.append(row)
            self.active += 1
        stem = "http-%04d" % index
        started = time.monotonic()
        try:
            peer.connection.settimeout(15)
            require(peer.path == "/v1/systemone" and not peer.headers.get("Authorization"),
                    "fixture only accepts credential-free System One")
            size = int(peer.headers["Content-Length"])
            require(0 < size <= self.judge["max_bytes"], "HTTP request exceeds enrollment")
            raw = peer.rfile.read(size)
            require(len(raw) == size, "HTTP input ended early")
            row["request"] = self.retain(stem + ".request", raw)
            root = document(raw)
            require(root["model"] == self.judge["model"]
                    and root["state"]["context"]["config"] == self.config,
                    "provider input belongs to another enrolled model/config")
            state = root["state"]
            candidates = state["rules"] or state["decisions"]
            require(len(candidates) > 0 and len(candidates) <= self.judge["max_questions"]
                    and len({rule["id"] for rule in candidates}) == len(candidates)
                    and set(root["questions"]) == {rule["id"] for rule in candidates},
                    "complete rule/question coverage required")
            commands = state["commands"]
            require(len(commands) <= 1, "fixture accepts one exact command")
            text = commands[0]["command"] if commands else ""
            if commands:
                require(sha(text.encode()) == commands[0]["raw_sha256"], "command bytes lost")
            tokens = 2 * len(raw) + 32
            response = {"model": root["model"], "answers": {
                rule["id"]: {"type": "noul", "noul": score(text, rule["text"])}
                for rule in candidates},
                "usage": {"input_tokens": tokens, "output_tokens": 0},
                "request": "policy-http-%04d" % index}
            if stage == "timeout":
                time.sleep(self.judge["command_deadline_ms"] / 1000 + 0.4)
            elif stage == "partial":
                response["input_truncated"] = True
            elif stage == "cost":
                # At the pinned one micro/token price this is a real
                # provider-reported cost overrun, checked by job.Options.
                response["usage"]["output_tokens"] = self.reserve + 1
            body = encoded(response)
            row["response"] = self.retain(stem + ".response", body)
            row.update(input_tokens=tokens, output_tokens=response["usage"]["output_tokens"],
                       reported_cost_micros=tokens + response["usage"]["output_tokens"])
            try:
                peer.send_response(200)
                peer.send_header("Content-Type", "application/json")
                peer.send_header("Content-Length", str(len(body)))
                peer.end_headers()
                peer.wfile.write(body)
                peer.wfile.flush()
                row["delivery"] = "written"
            except (BrokenPipeError, ConnectionResetError):
                row["delivery"] = "peer_disconnected"
        except (OSError, ValueError, KeyError, TypeError) as error:
            row["error"] = str(error)
            with self.lock:
                self.errors.append(str(error))
        finally:
            row["elapsed_ms"] = int((time.monotonic() - started) * 1000)
            self.retain(stem + ".observed", row)
            with self.idle:
                self.active -= 1
                self.idle.notify_all()

    def stage(self, raw):
        request = document(raw)
        with self.idle:
            require(set(request) == {"stage", "config", "nonce", "org_generation"}
                    and request["config"] == self.config
                    and self.controls < len(OUTAGES) and request["stage"] == OUTAGES[self.controls]
                    and isinstance(request["nonce"], str) and re.fullmatch(r"[a-f0-9]{32}", request["nonce"])
                    and type(request["org_generation"]) is int and request["org_generation"] > 0
                    and (self.nonce is None or request["nonce"] == self.nonce)
                    and (self.generation is None or request["org_generation"] == self.generation + 1),
                    "stale, reordered or foreign judge control")
            require(self.idle.wait_for(lambda: self.active == 0,
                    timeout=self.judge["command_deadline_ms"] / 1000 + 2),
                    "preceding HTTP phase has not quiesced")
            stem = "control-%02d" % self.controls
            evidence = [self.retain(stem + ".request", raw), self.retain(stem + ".before", {
                "phase": self.phase, "requests": self.requests, "errors": self.errors})]
            self.phase, self.generation, self.nonce = request["stage"], request["org_generation"], request["nonce"]
            self.controls += 1
            evidence.append(self.retain(stem + ".applied", {**request, "input_sha256": sha(raw),
                "peer_uid": os.geteuid(), "observed_at_ns": time.time_ns()}))
            return {**request, "input_sha256": sha(raw), "evidence": evidence}

    def serve_control(self):
        try:
            while not self.done.is_set():
                try:
                    peer, _ = self.control.accept()
                except socket.timeout:
                    continue
                with peer:
                    peer.settimeout(30)
                    try:
                        _, uid, _ = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        require(uid == os.geteuid(), "judge controller peer has another UID")
                        frame = receive(peer)
                        raw = base64.b64decode(frame["input"], validate=True)
                        require(set(frame) == {"input", "sha256"} and sha(raw) == frame["sha256"],
                                "judge control input bytes changed")
                        send(peer, self.stage(raw))
                    except (OSError, ValueError, KeyError, TypeError) as error:
                        send(peer, {"error": str(error)})
        except (OSError, ValueError) as error:
            with self.lock:
                self.errors.append(str(error))

    def close(self):
        if self.collection is not None:
            return self.collection
        self.done.set()
        self.http.shutdown()
        self.http.server_close()  # Joins actual non-daemon request threads.
        for thread in self.threads:
            thread.join(timeout=35)
        require(all(not thread.is_alive() for thread in self.threads), "judge fixture serving thread survived")
        self.control.close()
        info = self.path.lstat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_ino == self.socket_identity,
                "judge control socket changed before collection")
        self.path.unlink()
        require(self.socket_root.lstat().st_ino == self.socket_root_identity,
                "judge socket directory changed before collection")
        self.socket_root.rmdir()
        with self.lock:
            require(self.active == 0, "judge HTTP handler survived collection")
            measured = {"closed": self.http.fileno() == -1 and self.control.fileno() == -1
                        and not self.socket_root.exists() and all(not thread.is_alive() for thread in self.threads),
                "config": self.config, "requests": self.requests, "errors": self.errors,
                "evidence": list(self.refs), "threads": [
                    {"name": thread.name, "ident": thread.ident, "alive": thread.is_alive()}
                    for thread in self.threads]}
            keep(self.root / "collection.json", measured)
            self.collection = measured
            require(measured["closed"] and not self.errors, "judge fixture collection found a failed exchange")
            return measured


def boot(case):
    # The service must read the price and tokenizer from protected, traversable
    # source staging. Controller inputs also need protected ancestors: the
    # evidence root can be below /var/tmp, even when its own mode is 0700.
    runtime = case.stage / ("policy-runtime-" + os.urandom(6).hex())
    runtime.mkdir(mode=0o755)
    runtime.chmod(0o755)
    private = runtime / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)

    def retain_input(name, value, mode=0o600):
        raw = value if isinstance(value, bytes) else encoded(value)
        path = private / name
        keep(path, raw, mode)
        keep(case.root / name, raw, mode)
        return path

    program = runtime / "fit"
    # This standalone stdlib program has no module dependencies. Go also
    # honors the installed harness's staged vendor tree when it is present.
    case.command("policy-fit-build", ["go", "build", "-trimpath",
        "-o", str(program), "./e2e/v2/cases/judge/fit"], seconds=600)
    program.chmod(0o555)
    specification = encoded({"schema": "laneboss.fixture-fit.v1",
        "formatter": "complete UTF-8 HTTP body", "input_tokens": "2 * bytes + 32",
        "context_tokens": 262144, "safety_tokens": 32,
        "implementation_sha256": sha((case.stage / "e2e/v2/cases/judge/fit/main.go").read_bytes())})
    controller_raw = Path(__file__).read_bytes()
    controller = retain_input("policy-judge", controller_raw, 0o555)
    deployment = encoded({"schema": "laneboss.fixture-provider.v1", "fixture": True,
        "provider": "clef-sglang", "model": "Cloudflare/clef-flash", "route": "/v1/systemone",
        "implementation_sha256": sha(controller_raw), "classifiers": CLASSIFIERS,
        "outages": list(OUTAGES), "cost_fault": "reported usage exceeds pinned reservation"})
    judge = {"provider": "clef-sglang", "model": "Cloudflare/clef-flash",
        "deployment_sha256": sha(deployment), "tokenizer_sha256": sha(specification),
        "context_tokens": 262144, "max_bytes": 65536, "max_questions": 12,
        "command_deadline_ms": 2000, "guidance_deadline_ms": 5000,
        "cache_ttl_ms": 30000, "outage_policy": "critical-only"}
    price = encoded({"schema": "laneboss.judge-price.v1", "provider": judge["provider"],
        "model": judge["model"], "input_micros_per_million": 1000000,
        "output_micros_per_million": 1000000})
    price_file = runtime / "price.json"
    keep(price_file, price, 0o444)
    worker = {"tokenizer_path": str(program), "tokenizer_args": [judge["tokenizer_sha256"],
        str(judge["context_tokens"])], "tokenizer_executable_sha256": sha(program.read_bytes()),
        "price_file": str(price_file), "price_sha256": sha(price),
        "safety_tokens": 32, "reserve_micros": 1000000}
    for name, raw in (("policy-fit.spec", specification), ("policy-stack.input", deployment),
                      ("policy-fit.input", program.read_bytes())):
        case.keep(name, raw)
    # Keep the server object before returning so abort can collect even a
    # failed boot/publication that never issued a lane life.
    case.policy_judge = Fixture(case.root, case.config, judge, worker["reserve_micros"], private)
    retain_input("policy-judge.config.json", {"config": case.config,
        "socket": str(case.policy_judge.path), "controller_sha256": sha(controller_raw)})
    case.policy_judge_input = retain_input("policy-judge.input.json", {"schema": "laneboss.policy-judge.v1",
        "config": case.config, "controller": str(controller), "controller_sha256": sha(controller_raw),
        "judge": judge})
    return {"assets": [{"id": "policy-fit", "role": "case-tokenizer", "file": str(program), "mode": 0o555}],
        "enrollment": {"judge": judge, "judge_worker": worker, "judge_endpoint": case.policy_judge.endpoint,
                       "policy_max_cost_micros": 2 * worker["reserve_micros"]}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, required=True)
    args = parser.parse_args()
    config = document(private(Path(__file__).with_name("policy-judge.config.json")))
    require(sha(Path(__file__).read_bytes()) == config["controller_sha256"], "fixed controller bytes changed")
    raw = private(args.request)
    require(document(raw)["config"] == config["config"], "controller input has another config")
    path = Path(config["socket"])
    info, parent = path.lstat(), path.parent.lstat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o600
            and stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid()
            and stat.S_IMODE(parent.st_mode) == 0o700, "unsafe judge control socket")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(30)
        peer.connect(config["socket"])
        _, uid, _ = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(uid == os.geteuid(), "controller endpoint has another UID")
        send(peer, {"input": base64.b64encode(raw).decode(), "sha256": sha(raw)})
        response = receive(peer)
    require(not response.get("error"), response.get("error", "judge controller refused"))
    require(response["input_sha256"] == sha(raw), "controller response lost exact input")
    print(encoded(response).decode(), end="")


if __name__ == "__main__":
    main()
