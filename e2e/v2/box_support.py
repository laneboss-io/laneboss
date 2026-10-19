"""Unprivileged fixture interface. Tests cannot select the service identity."""

import json
import os
from pathlib import Path
import stat
import subprocess
import time
import unittest
import uuid

from support import (Failure, ROOT, clean_environment, immutable, load,
                     encoded, process_identity, require, save, sha256)
from draft4 import MUTATIONS, retained_key, session_proof


CONTEXT = None


def socket_matches(info, service_uid, rpc_gid, mode):
    require(info.get("present") is True and info["uid"] == service_uid
            and info["gid"] == rpc_gid and info["mode"] == mode,
            "product socket owner/group/mode differs")


class Recorder:
    """Files, not pipes; a switched child's timeout cannot hang communicate()."""

    def __init__(self, directory):
        self.root = Path(directory)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.count = 0
        self.cli_count = 0

    def run(self, argv, *, label, timeout, environment, recorded=None, identity=None, cwd=None):
        self.count += 1
        stem = self.root / ("c-" + uuid.uuid4().hex[:10])
        stdout_path = stem.with_suffix(".out")
        stderr_path = stem.with_suffix(".err")
        receipt_path = stem.with_suffix(".json")
        started = time.monotonic_ns()
        code = None
        timed_out = False
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            switched = Path(argv[0]).name == "sudo"
            command = argv if switched else [
                "/usr/bin/timeout", "--kill-after=5s", str(timeout), *argv]
            child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stdout,
                                     stderr=stderr, env=environment, close_fds=True, cwd=cwd)
            try:
                code = child.wait(timeout=timeout + 10)
            except (subprocess.TimeoutExpired, PermissionError):
                # Every sudo call has an inner root-owned timeout. Never call
                # kill/wait-without-deadline on a switched process from here.
                timed_out = True
                if not switched:
                    child.kill()
                    code = child.wait(timeout=5)
        timed_out = timed_out or code in (124, 137)
        save(receipt_path, {"argv": list(map(str, recorded if recorded is not None else argv)),
                            "identity": identity, "label": label, "exit_code": code,
                            "timed_out": timed_out, "started_ns": started,
                            "ended_ns": time.monotonic_ns()})
        require(not timed_out, "command deadline exceeded; evidence retained", "deadline_exceeded")
        return Result(code, stdout_path.read_bytes(), stderr_path.read_bytes(), receipt_path)


class Result:
    def __init__(self, code, stdout, stderr, receipt):
        self.returncode, self.stdout, self.stderr = code, stdout, stderr
        self.receipt = receipt

    def json(self):
        from support import decode
        return decode(self.stdout)


class Context:
    def __init__(self, directory, kit):
        self.directory = Path(directory)
        self.kit = immutable(kit)
        self.data = load(self.directory / "context.json")
        self.contract = self.data["contract"]
        self.environment = clean_environment(self.directory / "controller-home",
                                             self.directory / "controller-tmp")
        self.recorder = Recorder(self.directory / "evidence" / "cmd")
        self.inputs = self.directory / "requests"
        require(self.inputs.is_dir() and not self.inputs.is_symlink(),
                "fixture request directory is missing/linked")
        self.setup_done = True
        self.used_read_proofs = set()

    def kit_call(self, step, argument=None, *, timeout=180):
        argv = ["sudo", "-n", "/usr/bin/timeout", "--kill-after=5s", str(timeout),
                "/usr/bin/python3", "-I", "-B", str(self.kit), step, str(self.directory)]
        if argument is not None:
            argv.append(str(argument))
        return self.recorder.run(argv, label="kit-" + step, timeout=timeout + 15,
                                 environment=self.environment,
                                 recorded=["kit", step, str(argument or "")])

    def as_user(self, identity, argv, *, input_bytes=None, timeout=60, label="ordinary"):
        require(identity in ("operator", "lane"), "service is setup-only", "forbidden")
        request_id = "r." + uuid.uuid4().hex[:10]
        stdin = ""
        if input_bytes is not None:
            source = self.inputs / (request_id + ".in")
            source.write_bytes(input_bytes)
            stdin = str(source.relative_to(self.directory))
        request = self.inputs / (request_id + ".json")
        save(request, {"role": identity, "argv": list(map(str, argv)),
                       "timeout": timeout, "stdin": stdin}, mode=0o400)
        command = ["sudo", "-n", "/usr/bin/timeout", "--kill-after=5s", str(timeout + 10),
                   "/usr/bin/python3", "-I", "-B", str(self.kit), "run-user",
                   str(self.directory), str(request.relative_to(self.directory))]
        return self.recorder.run(command, label=label, timeout=timeout + 25,
                                 environment=self.environment, recorded=argv, identity=identity)

    def operator(self, *args):
        self.recorder.cli_count += 1
        return self.as_user("operator", [self.data["paths"]["binary"], *args,
                                        "--config", self.data["lane"], "--binding",
                                        str(self.installed_binding("human"))], label="product-cli")

    def lane(self, *args):
        self.recorder.cli_count += 1
        return self.as_user("lane", [self.data["paths"]["binary"], *args,
                                    "--config", self.data["lane"], "--binding",
                                    str(self.installed_binding("lane"))], label="product-cli")

    def installed_binding(self, kind):
        key = "binding" if kind == "human" else "lane_binding"
        if key not in self.data["paths"]:
            raise Failure("administrator-installed client binding is absent", "not_implemented", "lb-v2-admin")
        path = immutable(self.data["paths"][key])
        binding = load(path)
        require(binding["schema"] == "laneboss.binding.v2" and binding["class"] == kind and
                binding["config"] == self.data["lane"] and
                binding["artifact_sha256"] == self.data["binary_sha256"] and
                binding["service_uid"] == self.data["accounts"]["service"]["uid"],
                "installed binding differs from the fixture")
        return path

    def readiness(self):
        return self.operator_request(["health"], {
            "client_version": "", "artifact_sha256": self.data["binary_sha256"]})

    def startup_proof(self):
        path = self.directory / "requests" / "service-read-proof.json"
        if not path.is_file():
            raise Failure("startup human.session proof is absent", "not_implemented", "lb-v2-identity")
        value = load(path)
        require(set(value) == {"config", "proof_file"} and value["config"] == self.data["lane"],
                "startup proof descriptor differs from configuration")
        proof = immutable(value["proof_file"])
        session_proof(proof, self.data["lane"], self.used_read_proofs)
        return proof

    def operator_request(self, words, body, *, key=None, proof=None):
        if ".".join(words) in MUTATIONS:
            retained_key(key)
        name = "api-" + uuid.uuid4().hex[:8] + ".json"
        target = Path(self.data["accounts"]["operator"]["home"]) / name
        written = self.as_user("operator", ["/usr/bin/tee", str(target)],
                               input_bytes=encoded(body), label="request-input")
        require(written.returncode == 0 and written.stdout == encoded(body),
                "exact file-backed CLI request staging failed")
        flags = ["--request", str(target), "--request-id", uuid.uuid4().hex]
        if key is not None:
            flags.extend(("--idempotency-key", key))
        if proof is not None:
            flags.extend(("--proof", str(proof)))
        return self.operator(*words, *flags)

    def outside_read(self, path):
        path = Path(path)
        require(path.is_relative_to(self.directory), "outside read is beyond fixture")
        result = self.kit_call("read-file", str(path.relative_to(self.directory)))
        require(result.returncode == 0, "outside descriptor read failed")
        return result.stdout

    def assert_live(self):
        record = load(self.directory / "admin" / "service.json")
        if record["state"] in ("missing-command", "not-implemented"):
            raise AssertionError("laneboss serve is absent or not implemented")
        require(record["state"] == "starting" and record["process"] is not None,
                "service did not start")
        require(process_identity(record["pid"]) == record["process"] and
                record["process"]["uids"] == [self.data["accounts"]["service"]["uid"]] * 4,
                "real non-root service exited or changed identity")
        info_result = self.kit_call("socket-info")
        require(info_result.returncode == 0, "service socket metadata unavailable")
        socket_matches(info_result.json(), self.data["accounts"]["service"]["uid"],
                       self.data["rpc_gid"], self.contract["socket_mode"])
        require(sha256(self.data["paths"]["binary"]) == self.data["binary_sha256"],
                "installed bytes disappeared or changed")


class BlackBoxCase(unittest.TestCase):
    def setUp(self):
        require(CONTEXT is not None, "run through the disposable-box controller")
        self.box = CONTEXT
        self._calls_before = self.box.recorder.cli_count
        self._commands_before = self.box.recorder.count
        self.addCleanup(self._check_calls)

    def _check_calls(self):
        # An earlier failure is retained. These checks can add failures, never
        # replace the original missing-service diagnostic with a success.
        outcome = self._outcome
        if outcome is not None and outcome.result is not None:
            failed = outcome.result.failures + outcome.result.errors
            if any(test is self for test, _text in failed):
                return
        if self.box.recorder.cli_count <= self._calls_before:
            self.fail("test executed no public product CLI")
        self.box.assert_live()

    def assertExit(self, result, expected=0):
        self.assertEqual(result.returncode, expected, "unexpected command exit")
        return result

    def assertJSON(self, result):
        self.assertExit(result)
        value = result.json()
        self.assertIsInstance(value, dict)
        return value

    def assertServiceLive(self):
        self.box.assert_live()


def audit_service_commands(directory):
    for path in (Path(directory) / "evidence" / "cmd").glob("*.json"):
        require(load(path).get("identity") != "service",
                "test phase acted as the state owner")
