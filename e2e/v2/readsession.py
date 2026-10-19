"""Bounded public-socket reader process; no observer or store authority."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import selectors
import subprocess
import time

from draft4 import KEY, session_proof, typed_reply
from ladder_observer import RemoteFailure
from support import (Failure, atomic_bytes, decode, exact_keys, immutable, load,
                     process_identity, require, save, sha256)


class SessionReader:
    def __init__(self, binary, config, binding, proof_file, root, environment, *, command=()):
        self.binary, self.binding = immutable(binary), immutable(binding)
        self.config, self.proof_file = config, Path(proof_file)
        self.root, self.environment = Path(root), environment
        self.command = tuple(command)
        self.root.mkdir(mode=0o700)
        self.used_proofs, self.child, self.pending = set(), None, b""
        self.session, self.proof_id, self.index = None, "", 0
        self.starts, self.exits = [], []

    def ensure_open(self):
        if self.child is not None:
            expiry = datetime.fromisoformat(self.session["expires_at"])
            if expiry.timestamp() > time.time() + 10:
                return
            self.close()
        proof = session_proof(self.proof_file, self.config, self.used_proofs)
        self.proof_id = proof["id"]
        number = len(self.starts) + 1
        error_path = self.root / ("session-" + str(number) + ".stderr")
        argv = [str(self.binary), *self.command, "--config", self.config, "--binding", str(self.binding),
                "--proof", str(self.proof_file)]
        self.pending = b""
        with error_path.open("xb") as stderr:
            self.child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=stderr, cwd=self.root, env=self.environment,
                                          close_fds=True)
        self.error_path = error_path
        self.starts.append({"argv": argv, "process": process_identity(self.child.pid),
                            "binary_sha256": sha256(self.binary), "proof_id": self.proof_id})
        self.receipt()
        response = self.receive()
        self.session = typed_reply("human.session", response["result"])
        require(self.session["config"] == self.config and
                self.session.get("simulated_presence", False) == proof.get("simulated_presence", False),
                "session result changed configuration or presence provenance")
        expiry = datetime.fromisoformat(self.session["expires_at"])
        require(expiry.tzinfo is not None and expiry > datetime.now(timezone.utc), "session already expired")
        self.receipt()

    def receipt(self):
        save(self.root / "sessions.json", {"config": self.config, "starts": self.starts,
             "exits": self.exits, "proof_count": len(self.used_proofs),
             "session": self.session, "proof_id": self.proof_id})

    def receive(self):
        require(self.child is not None, "read session process is absent")
        end = time.monotonic() + 65
        with selectors.DefaultSelector() as selector:
            selector.register(self.child.stdout, selectors.EVENT_READ)
            while b"\n" not in self.pending:
                remaining = end - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise Failure("public session read exceeded its deadline", "deadline_exceeded")
                block = os.read(self.child.stdout.fileno(), 65536)
                if not block:
                    code = self.close(success=False)
                    try:
                        value = load(self.error_path)
                        failure = RemoteFailure(value.get("error", value), "lb-v2-service")
                    except (Failure, ValueError, TypeError) as error:
                        raise Failure("session process exited " + str(code) + "; receipt " +
                                      str(self.root / "sessions.json")) from error
                    raise failure
                self.pending += block
                require(len(self.pending) <= 1048576, "session reply exceeds frame bound")
        raw, self.pending = self.pending.split(b"\n", 1)
        self.index += 1
        atomic_bytes(self.root / (str(self.index) + ".response"), raw + b"\n", 0o400)
        response = decode(raw)
        exact_keys(response, ("protocol", "schema", "request_id", "last_seq"), ("result", "error"))
        require(response["protocol"] == "laneboss.rpc.v2" and response["schema"] == 2 and
                KEY.fullmatch(response["request_id"]) and (("result" in response) != ("error" in response)),
                "public session reply correlation differs")
        if "error" in response:
            self.close(success=False)
            raise RemoteFailure(response["error"], "lb-v2-service")
        return response

    def call(self, request):
        require(self.child is not None and request["config"] == self.config and "proof" not in request,
                "request differs from its live public session")
        raw = (json.dumps(request, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        require(len(raw) <= 1048576, "session request exceeds frame bound")
        atomic_bytes(self.root / (str(self.index + 1) + ".request"), raw, 0o400)
        self.child.stdin.write(raw)
        self.child.stdin.flush()
        response = self.receive()
        require(response["request_id"] == request["request_id"], "session returned another request")
        return response

    def read(self, method, exact_params, request_id, idempotency_key):
        """Watchdog port, called by the separately enrolled outside reader.

        The installed Go helper prepares the request digest and owns the live
        human.session. Selecting files in the L6 case does not create this port.
        """
        require(method in {"dashboard.tree", "dashboard.raw", "dashboard.decisions",
                           "dashboard.refusals", "dashboard.plugins", "dashboard.resources",
                           "dashboard.lifecycle", "dashboard.approvals"},
                "watchdog reader received a non-dashboard method", "invalid_request")
        require(isinstance(exact_params, bytes) and len(exact_params) <= 1048576 and
                isinstance(request_id, str) and KEY.fullmatch(request_id) and
                isinstance(idempotency_key, str) and KEY.fullmatch(idempotency_key),
                "watchdog reader input or correlation differs", "invalid_request")
        params = decode(exact_params)
        require(isinstance(params, dict), "watchdog dashboard body is not an object", "invalid_request")
        self.ensure_open()
        # Keep the original file bytes separately from the helper's JSON-line
        # transport encoding. Only the common Go client computes the digest.
        atomic_bytes(self.root / (str(self.index + 1) + ".params"), exact_params, 0o400)
        previous = self.index
        try:
            self.call({"protocol": "laneboss.rpc.v2", "schema": 2, "config": self.config,
                       "method": method, "params": params, "request_id": request_id,
                       "idempotency_key": idempotency_key})
        except RemoteFailure:
            require(self.index > previous and bool(self.exits), "reader failed before a retained response")
            code = self.exits[-1]["exit_code"]
            require(code != 0, "refused reader response has no failed process exit")
            return subprocess.CompletedProcess(self.starts[-1]["argv"], code,
                (self.root / (str(self.index) + ".response")).read_bytes(), self.error_path.read_bytes())
        return subprocess.CompletedProcess(self.starts[-1]["argv"], 0,
            (self.root / (str(self.index) + ".response")).read_bytes(), self.error_path.read_bytes())

    def close(self, *, success=True):
        if self.child is None:
            return 0
        child, self.child = self.child, None
        forced = False
        input_error = None
        try:
            try:
                child.stdin.close()
            except OSError as error:
                input_error = error.errno
            try:
                code = child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                forced = True
                child.kill()
                code = child.wait(timeout=10)
        finally:
            child.stdout.close()
        self.exits.append({"pid": child.pid, "exit_code": code, "forced": forced, "input_error": input_error})
        self.receipt()
        require(not forced and (not success or code == 0 and input_error is None), "public session did not close cleanly")
        return code
