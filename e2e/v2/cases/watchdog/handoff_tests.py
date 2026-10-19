"""Actual child-process handoff checks; they prove no vendor authentication."""

import json
import fcntl
import os
from pathlib import Path
import socket
import select
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.append(str(Path(__file__).resolve().parents[2]))

from run import Case, SetupFailure, atomic, encoded
import run
from readsession import SessionReader
from draft4 import intent_digest
import reader as reader_bridge


class HandoffTests(unittest.TestCase):
    def case(self):
        temporary = tempfile.TemporaryDirectory(prefix="watchdog-handoff-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        return Case({"test_root": str(root), "evidence_root": str(root / "evidence"),
                     "config": "watchdog-case", "binary": "/installed/laneboss",
                     "binding_file": "/installed/lane.json"})

    def test_dashboard_requires_separate_reader(self):
        case = self.case()
        proof_root = case.root / "proofs"
        proof_root.mkdir(mode=0o700)
        atomic(proof_root / "00000001.json", encoded({"id": "inert-input"}))
        case.setup = {"human_reads": {"binding_file": "/installed/human.json", "proofs_dir": "proofs"}}
        # File selection must never cause the L6 process to invoke a human CLI.
        with patch("run.subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"{}", b"")) as cli:
            with self.assertRaises(SetupFailure):
                case.call("dashboard.raw", {"life_id": "life", "run": 1})
            cli.assert_not_called()

    def test_reader_process_bridge(self):
        self.assertTrue(callable(getattr(SessionReader, "read", None)),
                        "installed session reader has no watchdog bridge")
        for fail in (False, True):
            with self.subTest(fail=fail):
                case = self.case()
                program = case.root / "reader"
                program.write_bytes(Path(__file__).with_name("read_probe.py").read_bytes())
                program.chmod(0o500)
                binding, proof = case.root / "human.json", case.root / "proof.json"
                atomic(binding, encoded({"config": case.context["config"]}))
                atomic(proof, encoded({"id": os.urandom(16).hex(), "expires_at": "2099-01-01T00:00:00Z",
                      "request_sha256": intent_digest(case.context["config"], "human.session", {}),
                      "simulated_presence": True}))
                # Only immutable-path setup is substituted. The child, pipes,
                # bytes, correlation, exit and collection are real operations.
                with patch("readsession.immutable", side_effect=Path), patch("draft4.immutable", side_effect=Path):
                    reader = SessionReader(program, case.context["config"], binding, proof,
                                           case.root / "session", {"PATH": "/usr/bin:/bin"},
                                           command=("internal", "reader"))
                    self.addCleanup(reader.close, success=False)
                    body = b'{ "token": "' + os.urandom(16).hex().encode() + b'", "fail": ' + (b"true" if fail else b"false") + b' }'
                    request_id, key = os.urandom(16).hex(), os.urandom(16).hex()
                    completed = reader.read("dashboard.lifecycle", body, request_id, key)
                    self.assertEqual(completed.stdout, (reader.root / (str(reader.index) + ".response")).read_bytes())
                    self.assertTrue(completed.stdout.startswith(b"  {"))
                    sent = (reader.root / "actual-input").read_bytes()
                    self.assertEqual((reader.root / (str(reader.index) + ".params")).read_bytes(), body,
                                     "reader did not retain the exact request body")
                    envelope = json.loads(sent)
                    self.assertEqual(envelope["params"], json.loads(body))
                    self.assertEqual(envelope["request_id"], request_id)
                    self.assertEqual(envelope["idempotency_key"], key)
                    self.assertEqual(len(reader.starts), 1)
                    self.assertEqual(reader.starts[0]["argv"][1:3], ["internal", "reader"])
                    self.assertTrue(reader.session["simulated_presence"])
                    if fail:
                        self.assertEqual(completed.returncode, 13)
                        self.assertEqual(completed.stderr, reader.error_path.read_bytes())
                        self.assertEqual(json.loads(completed.stderr)["code"], "forbidden")
                    else:
                        self.assertEqual(completed.returncode, 0)
                        self.assertEqual(json.loads(completed.stdout)["result"]["echo"], json.loads(body))
                        case.human_reader = reader
                        self.assertEqual(case.call("dashboard.lifecycle", {"other": key})["echo"], {"other": key})
                        self.assertEqual(len(reader.starts), 1)
                    reader.close(success=not fail)

    def test_outside_reader_bridge(self):
        adapter = getattr(reader_bridge, "SocketReader", None)
        self.assertTrue(callable(adapter), "case has no outside reader transport")
        case = self.case()
        program = case.root / "reader"
        program.write_bytes(Path(__file__).with_name("read_probe.py").read_bytes())
        program.chmod(0o500)
        atomic(case.root / "human.json", encoded({"config": case.context["config"]}))
        atomic(case.root / "proof.json", encoded({"id": os.urandom(16).hex(), "expires_at": "2099-01-01T00:00:00Z",
              "request_sha256": intent_digest(case.context["config"], "human.session", {}), "simulated_presence": True}))
        endpoint = case.root / "reader.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(endpoint))
            endpoint.chmod(0o660)
            command = [sys.executable, "-B", str(Path(__file__).with_name("read_probe.py")),
                       "--bridge", str(case.root), str(listener.fileno()), case.context["config"]]
            child = subprocess.Popen(command, pass_fds=(listener.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.addCleanup(lambda: child.kill() if child.poll() is None else None)
            self.assertTrue(select.select([child.stdout], [], [], 10)[0], "outside reader did not listen")
            self.assertEqual(child.stdout.readline(), b"ready\n")
            binding = {"schema": "laneboss.watchdog-reader.v1", "config": case.context["config"],
                       "socket": str(endpoint), "reader_uid": os.getuid(), "case_uid": os.getuid(),
                       "binary_sha256": run.sha(program.read_bytes()), "simulated_presence": True}
            path = case.root / "reader.json"
            atomic(path, encoded(binding))
            case.context["binary_sha256"] = binding["binary_sha256"]
            remote = adapter(case.context, path, case.keep)
            remote.preflight()
            case.human_reader = remote
            body = {"outside_token": os.urandom(16).hex()}
            self.assertEqual(case.call("dashboard.lifecycle", body)["echo"], body)
            self.assertNotEqual(remote.peer_pid, os.getpid())
            self.assertEqual(remote.peer_pid, child.pid)
            self.assertEqual(remote.close(), 0)
            out, err = child.communicate(timeout=10)
            self.assertEqual(child.returncode, 0, (out, err))
            sessions = json.loads((case.root / "session" / "sessions.json").read_bytes())
            self.assertEqual(len(sessions["starts"]), 1)
            self.assertEqual(sessions["proof_count"], 1)
            self.assertTrue(sessions["session"]["simulated_presence"])
            self.assertEqual(sessions["exits"][-1]["exit_code"], 0)
            self.assertFalse(sessions["exits"][-1]["forced"])
            binding["simulated_presence"] = False
            atomic(path, encoded(binding))
            with self.assertRaises(reader_bridge.ReaderWait):
                adapter(case.context, path, case.keep)

    def test_missing_fixture_has_typed_wait(self):
        case = self.case()
        case.failed("WATCHDOG-LIMIT", SetupFailure("outside setup is missing"))
        waits = list(case.evidence.glob("*-wait.json"))
        self.assertEqual(len(waits), 1)
        result = json.loads(waits[0].read_bytes())
        self.assertEqual(result["code"], "prerequisite_missing")
        self.assertFalse(result["passed"])
        self.assertEqual(result["owner_in_person"], [])
        self.assertEqual(result["message"], "outside setup is missing")

    def test_exact_descriptor_handoff(self):
        select = getattr(run, "inherited_lane_descriptors", None)
        self.assertTrue(callable(select), "watchdog has no narrow lane descriptor handoff")
        case = self.case()
        binding_path, socket_path = case.root / "binding.json", case.root / "service.sock"
        actual_socket = case.root / "outside.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(actual_socket))
            actual_socket.chmod(0o666)
            raw_fd = os.memfd_create("watchdog-binding", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
            binding_fd = fcntl.fcntl(raw_fd, fcntl.F_DUPFD_CLOEXEC, 6)
            os.close(raw_fd)
            raw_endpoint = os.open(actual_socket, os.O_PATH | os.O_CLOEXEC)
            endpoint_fd = fcntl.fcntl(raw_endpoint, fcntl.F_DUPFD_CLOEXEC, 6)
            os.close(raw_endpoint)
            extra_fd = fcntl.fcntl(endpoint_fd, fcntl.F_DUPFD_CLOEXEC, 256)
            try:
                binding = {"schema": "laneboss.binding.v2", "config": case.context["config"], "class": "lane",
                           "socket": str(socket_path), "mapped_service_uid": os.getuid(), "mapped_service_gid": os.getgid()}
                data = encoded(binding)
                os.write(binding_fd, data)
                os.fchmod(binding_fd, 0o444)
                seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
                fcntl.fcntl(binding_fd, fcntl.F_ADD_SEALS, seals)
                binding_path.symlink_to(f"/proc/self/fd/{binding_fd}")
                socket_path.symlink_to(f"/proc/self/fd/{endpoint_fd}")
                with patch.object(run, "LANE_BINDING", str(binding_path), create=True), \
                        patch.object(run, "LANE_SOCKET", str(socket_path), create=True):
                    chosen = select(str(binding_path), case.context["config"])
                    self.assertEqual(chosen, (binding_fd, endpoint_fd))
                    probe = case.root / "descriptor-probe"
                    probe.write_bytes(Path(__file__).with_name("handoff_probe.py").read_bytes())
                    probe.chmod(0o500)
                    case.context["binary"], case.context["binding_file"] = str(probe), str(binding_path)
                    try:
                        observed = case.call("probe.descriptors", {"binding_fd": binding_fd, "socket_fd": endpoint_fd, "other_fd": extra_fd})
                    except run.Failure as error:
                        self.fail("actual CLI lost required lane descriptors: " + str(error))
                    self.assertEqual(observed["binding_sha256"], run.sha(data))
                    self.assertTrue(observed["socket"])
                    self.assertTrue(observed["other_closed"])
                    with self.assertRaises(run.Failure):
                        select(str(binding_path), "foreign-config")
                    socket_path.unlink()
                    socket_path.symlink_to(f"/proc/self/fd/{binding_fd}")
                    with self.assertRaises(run.Failure):
                        select(str(binding_path), case.context["config"])
            finally:
                os.close(extra_fd)
                os.close(endpoint_fd)
                os.close(binding_fd)

    def test_reader_wait_precedes_dispatch(self):
        case = self.case()
        program = case.root / "installed-binary"
        program.write_bytes(b"unused native reader preflight input\n")
        binding = case.root / "installed-binding.json"
        binding.write_bytes(encoded({"schema": "laneboss.binding.v2", "contract_revision": run.REVISION,
                                    "protocol": "laneboss.rpc.v2", "api_schema": 2,
                                    "config": case.context["config"], "artifact_sha256": run.sha(program.read_bytes())}))
        setup = {"schema": "laneboss.watchdog-case.v2", "start": {"driver": "claudock-cli", "profile_grant_id": "profile-a"},
                 "control": "control.json", "task_file": "task.md", "mail_file": "mail.md"}
        atomic(case.root / "setup.json", encoded(setup))
        atomic(case.root / "task.md", b"unexecuted fixture task\n")
        atomic(case.root / "mail.md", b"unexecuted fixture mail\n")
        case.context.update(schema="laneboss.e2e-context.v2", case_id="watchdog", phase="candidate", mutation_id="",
                            binary=str(program), binary_sha256=run.sha(program.read_bytes()), binding_file=str(binding),
                            profile_grant_ids=["profile-a", "profile-b"], source_sha256=run.sha(b"component input"))
        calls = []
        def refuse_dispatch(method, *args, **kwargs):
            calls.append(method)
            raise SetupFailure("dispatch reached without its independent reader")
        with patch.object(case, "call", side_effect=refuse_dispatch):
            result, exit_code = case.run()
        self.assertEqual(calls, [], "missing human reader allowed dependent dispatch")
        self.assertEqual(exit_code, 69)
        self.assertTrue(all(row["verdict"] == "fail" and not row["reached"] for row in result["assertions"]))
        waits = list(case.evidence.glob("*-wait.json"))
        self.assertEqual(json.loads(waits[0].read_bytes())["owner_in_person"], ["human.session"])


if __name__ == "__main__":
    unittest.main()
