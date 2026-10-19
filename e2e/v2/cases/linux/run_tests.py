#!/usr/bin/env python3
"""Linux-only component controls; no service/model readiness is claimed."""

import errno
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


subject = module("linux_case", "run.py")
canary = module("linux_canary", "canary.py")
mutations = module("linux_mutations", "mutate.py")


def decision_observation():
    # Decision inputs only. These values are never returned as an OS-LINUX
    # result or substituted for actual canary output in the public case.
    own = ("work.write work.read work.mmap work.link work.build work.git tmp.write home.write "
           "own.signal own.ipc own.tcp4 own.udp4 own.tcp6 own.udp6 permitted.network "
           "readonly.read nested.read detach.double_fork").split()
    denied = ("outside.read outside.write outside.mmap outside.link readonly.write readonly.mmap "
              "readonly.link nested.write inherited.fd foreign.tcp4 foreign.udp4 foreign.tcp6 "
              "foreign.udp6 foreign.ipc foreign.signal escape.unshare").split()
    operations = {name: {"outcome": "ok", "errno": 0} for name in own}
    operations.update({name: {"outcome": "error", "errno": errno.EPERM} for name in denied})
    operations["inherited.fd"]["errno"] = errno.EBADF
    return {"operations": operations, "no_new_privs": 1, "cap_eff": 0}


def decision_case():
    case = subject.Case.__new__(subject.Case)
    case.reached, case.boundary_failures = False, []
    return case


def zero_network():
    return {"foreign." + name: {"bytes": 0, "packets": 0, "connections": 0}
            for name, _, _ in subject.NETWORK_KINDS}


class LinuxCaseControls(unittest.TestCase):
    def test_fresh_cell_resets_reached(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-linux-fresh-") as directory:
            root = Path(directory)
            (root / "stale.json").write_text("{}")
            (root / "stale-link").symlink_to(root / "missing")
            for name in ("stale.json", "stale-link"):
                case = decision_case()
                case.root, case.reached, case.boundary_failures = root, True, ["outside.read"]
                with self.assertRaisesRegex(RuntimeError, "observation path is not fresh"):
                    case.begin_cell({"observation": name})
                self.assertFalse(case.reached)
                self.assertEqual(case.boundary_failures, [])

    def test_mutation_subtest_output(self):
        events = [{"Test": "TestSelected", "Output": "parent\n"},
                  {"Test": "TestSelected/child", "Output": "target assertion\n"},
                  {"Test": "TestSelectedExtra", "Output": "unrelated\n"}]
        self.assertEqual(mutations.focused_output(events, "TestSelected"), "parent\ntarget assertion\n")

    def test_all_denials_retained(self):
        case, observation = decision_case(), decision_observation()
        for name in ("outside.read", "foreign.ipc"):
            observation["operations"][name] = {"outcome": "ok", "errno": 0}
        with self.assertRaises(RuntimeError) as refused:
            case.check_operations(observation, zero_network())
        self.assertEqual(case.boundary_failures, ["outside.read", "foreign.ipc"])
        for mutation in ("linux-broad-root", "linux-no-network"):
            self.assertTrue(subject.red_target_reached(mutation, str(refused.exception), case.boundary_failures))
        self.assertFalse(subject.red_target_reached("linux-broad-root", str(refused.exception), []))

    def test_network_timeout_scope(self):
        for name in ("outside.read", "inherited.fd", "foreign.signal", "escape.unshare"):
            observation = decision_observation()
            observation["operations"][name] = {"outcome": "error", "kind": "timeout", "errno": None}
            with self.assertRaisesRegex(RuntimeError, "unexplained syscall failure"):
                decision_case().check_operations(observation, zero_network())
        observation = decision_observation()
        observation["operations"]["foreign.tcp4"] = {"outcome": "error", "kind": "timeout", "errno": None}
        decision_case().check_operations(observation, zero_network())
        with self.assertRaisesRegex(RuntimeError, "outside network observation is incomplete"):
            decision_case().check_operations(observation, {})

    def test_udp_without_echo(self):
        foreign = {name: ["::1" if family == socket.AF_INET6 else "127.0.0.1", 0]
                   for name, family, _ in subject.NETWORK_KINDS}
        observer = subject.NetworkObserver(foreign)
        try:
            payload = os.urandom(32)
            sent = canary.foreign_datagram(tuple(observer.addresses["udp4"]), socket.AF_INET, payload)
            self.assertEqual(sent["sent_bytes"], len(payload))
            self.assertEqual(sent["receive_kind"], "timeout")
            received = observer.finish()
            self.assertEqual(received["foreign.udp4"]["packets"], 1)
            self.assertEqual(received["foreign.udp4"]["bytes"], len(payload))
            observation = decision_observation()
            observation["operations"]["foreign.udp4"] = {"outcome": "error", "kind": "timeout", "errno": None}
            with self.assertRaisesRegex(RuntimeError, "boundary canary succeeded: foreign.udp4"):
                decision_case().check_operations(observation, received)
        finally:
            observer.close()
        self.assertFalse(any(thread.is_alive() for thread in observer.threads))

    def test_failed_case_stops_tree(self):
        for failure_type in (RuntimeError, TypeError):
            with self.subTest(failure=failure_type.__name__):
                self.cleanup_failure_fixture(failure_type)

    def cleanup_failure_fixture(self, failure_type):
        with tempfile.TemporaryDirectory(prefix="lb-v2-linux-cleanup-") as directory:
            root = Path(directory)
            marker = secrets.token_hex(16)
            heartbeat = root / "heartbeat"
            child = subprocess.Popen([sys.executable, "-I", str(Path(__file__).resolve()),
                                      "--cleanup-child", marker, str(heartbeat)])
            try:
                deadline = time.monotonic() + 10
                while not heartbeat.exists() or len(subject.marked_processes(marker)) < 2:
                    if child.poll() is not None or time.monotonic() >= deadline:
                        self.fail("actual detached child fixture did not start")
                    time.sleep(0.02)
                (root / "binary").write_bytes(os.urandom(32))
                context = {"schema": "laneboss.e2e-context.v2", "case_id": "linux", "phase": "red", "config": "component",
                           "mutation_id": "linux-broad-root", "binary_sha256": subject.digest((root / "binary").read_bytes()),
                           "source_sha256": subject.digest(Path(__file__).read_bytes()),
                           "binary": str(root / "binary"), "binding_file": str(root / "binding"),
                           "test_root": str(root), "evidence_root": str(root / "evidence")}
                case = subject.Case(context)
                record = {"cell": {"id": "cleanup", "marker": marker, "stop_reason": {}},
                          "uid": os.geteuid(), "target": {"life_id": "component", "run": 1}, "observer": None,
                          "started": True, "quiescent": False, "collected": False, "collecting": False}
                case.records.append(record)
                case.owned.append(record)
                case.reached = True
                injected = mock.Mock(side_effect=failure_type("component assertion failure"))
                # Scope this component fixture to its actual child identities,
                # not every process sharing the unit-test account's UID.
                with mock.patch.object(subject, "Case", return_value=case), \
                     mock.patch.object(subject, "load", return_value=context), \
                     mock.patch.object(subject, "uid_processes", side_effect=lambda uid: subject.marked_processes(marker)), \
                     mock.patch.object(case, "run", new=injected), \
                     mock.patch.object(case, "call", side_effect=RuntimeError("no installed service in this component test")), \
                     mock.patch.object(case, "cgroup_observation", side_effect=RuntimeError("no leased cgroup in this component test")), \
                     mock.patch.object(sys, "argv", ["run.py", "--context", str(root / "context.json"),
                                                   "--result", str(case.evidence / "result.json")]):
                    (root / "context.json").write_text(json.dumps(context))
                    self.assertEqual(subject.main(), 1)
                    injected.assert_called_once_with()
                self.assertEqual(subject.marked_processes(marker), {})
                child.wait(timeout=5)
                result = json.loads((case.evidence / "result.json").read_bytes())
                self.assertEqual(result["assertions"][0]["verdict"], "fail")
                self.assertFalse(result["assertions"][0]["reached"])
                self.assertFalse(result["collection"]["processes_quiescent"])
                self.assertFalse(result["collection"]["temporary_resources_collected"])
                self.assertTrue(result["collection"]["evidence"])
                self.assertTrue(case.cleanup_errors)  # No invented service/cgroup collection receipt.
            finally:
                remaining = subject.marked_processes(marker)
                if remaining:
                    subject.terminate_processes(remaining, os.geteuid())
                child.wait(timeout=5)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--cleanup-child":
        canary.detach(sys.argv[3], os.urandom(32))
        while True:
            time.sleep(0.25)
    else:
        unittest.main()
