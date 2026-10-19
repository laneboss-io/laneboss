"""Tests of the public-output observer, not product execution or live auth."""

import copy
import json
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from run import ASSERTIONS, Case, Failure, SetupFailure, atomic, encoded, sha
from controls import ControlError, Controller, verify_reply
from red import failure_output, mutation_outcome


class Observations(Case):
    """Supply CLI observation projections without invoking a product stub.

    These tests prove that the E2E observer rejects bad evidence. They do not
    prove a service can create the good trace, launch, stop, or isolate a lane.
    Only fields consumed by these assertions are projected; this is not a
    complete wire-schema or syscall/canary fixture.
    """

    def __init__(self):
        self.life = "life-observer"
        self.nonce = secrets.token_hex(16)
        self.base = {
            "life_id": self.life, "run": 2, "generation": 3, "state": "running",
            "cancellation_epoch": 2, "profile_grant_id": "grant-a", "task": self.ref("task", b"original task\n"),
            "counters": {"failures": 2, "retries": 1},
            "logical_turn_id": "turn-one",
            "session": {"id": "session-one", "home_id": "home-one", "history_id": "history-one"},
            "workspace": {"id": "workspace-one"},
            "budget_remaining": {"currency": "USD", "wall_ms": 10000,
                                 "cpu_seconds": 10, "memory_bytes": 4096,
                                 "processes": 8, "disk_bytes": 4096, "spend_micros": 100},
        }
        self.current = copy.deepcopy(self.base)
        self.current.update(run=3, generation=4, state="verifying", profile_grant_id="grant-b")
        self.observation = {"target": {"life_id": self.life, "run": 3}, "state": "exited", "survivors": 0}
        self.current["budget_remaining"]["wall_ms"] -= 1000
        self.reason = self.ref("reason", b"collection\n")
        self.manual_message = self.ref("message", b"continue\n")
        self.room_data = b'{"profile_id":"profile-b","available":true}\n'
        self.room_ref = self.ref("room", self.room_data)
        self.limit_bytes = b'{"type":"result","is_error":true,"result":"Usage limit reached"}\n'
        self.capture = {"id": "capture-one", "binding_id":"capture-binding", "primary": True, "coverage": "complete",
                        "data": self.ref("capture-data", self.limit_bytes)}
        self.swap = {
            "from_profile_id": "profile-a", "to_profile_id": "profile-b",
            "causing_run": 2, "continuation_run": 3, "logical_turn_id": "turn-one",
            "operation_id": "operation-one",
            "profile_grant_id": "grant-b", "eligibility_id": "eligibility-b",
            "expected_generation": 4, "cancellation_epoch": 2,
            "limit": {"exit_code": 0, "capture_id": self.capture["id"],
                      "capture_sha256": self.capture["data"]["sha256"]},
            "room": {"profile_id": "profile-b", "available": True,
                     "checked_at": "2026-01-02T03:04:05Z", "expires_at": "2026-01-02T03:04:35Z",
                     "evidence": self.room_ref},
        }
        self.swap["limit"]["usage_evidence"] = self.ref("usage-window", b"normalized usage reference fixture\n")
        self.swap["limit"]["usage_evidence"]["class"] = "usage_window"
        self.trace = [
            self.event("lane.ended", 2, {"reason": "limit", "profile_continuation": True,
                                        "observation": {"exit_code": 0, "survivors": 0}}),
            self.event("watchdog.swapped", 2, {"swap": self.swap}),
            self.event("lane.resumed", 3, {"trigger": {"kind": "profile_limit"},
                                          "profile_continuation_of": 2, "profile_swap": self.swap,
                                          "task": self.base["task"]}),
            self.event("mail.delivered", 3, {"mail_id": "mail-one", "status": "delivered",
                                            "logical_turn_id": "turn-one", "target": {"life_id": self.life, "run": 3},
                                            "prompt_status": "completed"}),
        ]
        for seq, event in enumerate(self.trace, 1):
            event["seq"] = seq
        self.cells = {self.life: {"mail_id": "mail-one", "baseline": self.base}}
        self.results = {name: {"reached": False} for name in ASSERTIONS}
        self.phase = "ready"
        self.wait_reads = 0
        self.bad_wait = False
        self.bad_tamper = False
        self.bad_canary = False
        self.no_real_limit = False
        self.stale_stop = False
        self.double_resume = False
        self.continuations = 0
        self.setup = {"restart": {"service_id": "service-one", "expected_generation": 1}}
        self.restarted = False
        self.bad_restart = False
        self.bad_independent = False
        self.bad_restore = False
        self.operation_reads = []
        self.quiet_reads = []

    @staticmethod
    def ref(name, data):
        return {"id": name, "bytes": len(data), "sha256": sha(data), "class": "capture"}

    def event(self, kind, run, payload):
        return {"kind": kind, "run": run, "seq": 1, "origin": "service",
                "actor": {"kind": "watchdog", "id": "watchdog"},
                "operation_id": "operation-one", "observed_at": "2026-01-02T03:04:06Z",
                "recorded_at": "2026-01-02T03:04:06Z", "payload": payload}

    def start_cell(self, cell):
        return self.life, self.nonce, self.base

    def control(self, cell, phase, nonce):
        if nonce != self.nonce:
            raise RuntimeError("observer fixture received another task's nonce")
        self.phase = phase

    def wait(self, observe, seconds=120):
        result = observe()
        if result is None or result is False:
            raise Failure("observer fixture never reached the required product observation")
        return result

    def status(self, life):
        if life != self.life:
            raise RuntimeError("observer crossed life scope")
        if self.phase == "exhausted":
            current = copy.deepcopy(self.base)
            current["state"] = "profile_wait"
            if self.bad_restore and self.wait_reads >= 3:
                current["run"] += 1
            if self.restarted and self.bad_restart:
                current["session"]["history_id"] = "lost-history"
            return current
        if self.phase == "attacks" and not self.bad_tamper:
            return self.base
        if self.phase == "limit" and self.no_real_limit:
            return self.base
        return self.current

    def events(self, life):
        if life != self.life:
            raise RuntimeError("observer crossed event scope")
        if self.phase == "exhausted":
            self.wait_reads += 1
            first = self.event("watchdog.waiting", 2, {"retry_after_ms": 5000})
            second = self.event("watchdog.waiting", 2, {"retry_after_ms": 10000})
            first["recorded_at"] = "2026-01-02T03:04:00Z"
            second["recorded_at"] = "2026-01-02T03:04:01Z" if self.bad_wait else "2026-01-02T03:04:05Z"
            return [first, second] if self.wait_reads >= 3 else [first]
        if self.phase == "attacks":
            return self.trace if self.bad_tamper else []
        if self.stale_stop:
            stop = self.event("lane.stopping", 2, {})
            stop["seq"] = 10
            resumed = self.event("lane.resumed", 3, {})
            resumed["seq"] = 11
            wait = self.event("watchdog.waiting", 2, {"retry_after_ms": 5000})
            second_stop = self.event("lane.stopping", 3, {})
            second_stop["seq"] = 12
            return [wait, stop, resumed, second_stop]
        if self.double_resume:
            wait = self.event("watchdog.waiting", 2, {"retry_after_ms": 5000})
            return [wait, self.event("lane.resumed", 3, {}), self.event("lane.resumed", 4, {})]
        return self.trace

    def check_quiet(self, life, run):
        self.quiet_reads.append(run)
        if self.observation["target"] != {"life_id": life, "run": run}:
            raise RuntimeError("observer requested another containment")
        return self.observation["state"] == "exited" and self.observation["survivors"] == 0

    def raw(self, life, run, live=False):
        if life != self.life:
            raise RuntimeError("observer crossed capture scope")
        if self.phase == "attacks":
            probes = [{"type": "watchdog_canary", "probe": name, "attempted": True, "errno": 13}
                      for name in ("quote", "forge", "file", "signal")]
            probes[1] = {"type": "watchdog_canary", "probe": "forge", "attempted": True, "code": "forbidden"}
            if self.bad_canary:
                probes[-1]["errno"] = 0
            return b"\n".join(json.dumps(p).encode() for p in probes), [self.capture]
        if run == 2:
            return self.limit_bytes, [self.capture]
        if run == self.current["run"]:
            return ("remembered " + self.nonce).encode(), []
        raise RuntimeError("observer requested an unexpected capture run")

    def blob(self, ref):
        if ref != self.room_ref:
            raise RuntimeError("observer requested a different room object")
        return self.room_data

    def call(self, method, params, allowed=()):
        if method == "dashboard.lifecycle":
            if params["life_id"] != self.life:
                raise RuntimeError("dashboard observation crossed life scope")
            return {"lanes": [self.current]}
        if method in {"lane.stop", "lane.resume"}:
            if params["target"] != {"life_id": self.life, "run": self.base["run"]}:
                raise RuntimeError("manual control targeted a different life/run")
            return {"id": "manual-" + params["target"]["life_id"],
                    "life_id": params["target"]["life_id"], "run": params["target"]["run"]}
        raise RuntimeError("observer fixture did not expect that CLI method")

    def continuation(self, life, baseline, nonce):
        self.continuations += 1
        return super().continuation(life, baseline, nonce)

    def operation(self, operation):
        if not operation.get("id"):
            raise RuntimeError("observer was asked to await an absent operation")
        self.operation_reads.append(operation["id"])
        return dict(operation, status="succeeded")

    def harness_action(self, action, params):
        if action != "restart_service" or params["service_id"] != "service-one":
            raise RuntimeError("observer fixture did not expect that harness action")
        self.restarted = True
        return {"current_generation": params["expected_generation"] + 1}, []

    def independent_canary(self, life, baseline):
        target = {"life_id": life, "run": baseline["run"]}
        report = {"schema": "laneboss.watchdog-canary.v2", "target": target, "nonce": self.nonce,
                  "checks": [{"probe": name, "attempted": True, "confined": True, "target_present": True,
                              "denied": True, "unchanged": True} for name in ("forge", "file", "signal")]}
        if self.bad_independent:
            report["checks"][-1]["target_present"] = False
        self.verify_canary_evidence([json.dumps(report).encode()], target, self.nonce)

    def verify(self):
        self.continuation(self.life, self.base, self.nonce)


class CheckTests(unittest.TestCase):
    def test_red_outcomes(self):
        name = "FocusedGuard"
        run = {"Action":"run", "Test":name}
        passed = {"Action":"pass", "Test":name}
        failed = {"Action":"fail", "Test":name}
        for code, events, classification in (
                (0, [run, passed], "survived"),
                (1, [], "not_reached"),
                (0, [{"Action":"run", "Test":"OtherTest"}, passed], "not_reached"),
                (1, [run, failed], "killed"),
                (0, [run, passed, failed], "invalid_result"),
                (1, [run, passed, failed], "invalid_result"),
                (2, [run, {"Action":"error", "Test":name}], "crashed"),
                (2, [run, failed], "invalid_result")):
            with self.subTest(classification=classification, code=code):
                outcome = mutation_outcome(code, events, name)
                self.assertEqual(outcome["classification"], classification)
                self.assertEqual(outcome["killed"], classification == "killed")
                self.assertEqual(outcome["reached"], run in events)
                self.assertEqual(outcome["test_passed"], passed in events)

    def test_red_failure_output(self):
        case = self.cli_case()
        directory = case.root / "diagnostics"
        directory.mkdir(mode=0o700)
        atomic(directory / "build.json", encoded({"exit":1}))
        diagnostic = b"source.go:42: unused variable\n"
        atomic(directory / "build.stderr", diagnostic)
        outcome = mutation_outcome(1, [], "FocusedGuard")
        result = failure_output(directory, outcome)
        self.assertEqual(result["reason"], "build_failed")
        self.assertEqual(result["last_output_lines"]["build.stderr"], diagnostic.decode().splitlines())
        lines = [str(i) for i in range(20)]
        atomic(directory / "stdout.jsonl", ("\n".join(lines)+"\n").encode())
        survived = mutation_outcome(0, [{"Action":"run", "Test":"FocusedGuard"},
                                       {"Action":"pass", "Test":"FocusedGuard"}], "FocusedGuard")
        result = failure_output(directory, survived)
        self.assertEqual(result["reason"], "survived")
        self.assertEqual(result["last_output_lines"]["stdout.jsonl"], lines[-12:])

    def cli_case(self):
        temporary = tempfile.TemporaryDirectory(prefix="lb-v2-watchdog-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        context = {"test_root": str(root), "evidence_root": str(root / "evidence"),
                   "config": "watchdog-test", "binary": "/installed/laneboss",
                   "binding_file": "/installed/lane.json"}
        return Case(context)

    @staticmethod
    def recording_cli(argv, **options):
        # An input echo for observer plumbing only. This subprocess double
        # supplies no authenticated identity, session, dashboard or OS proof.
        request = Path(argv[argv.index("--request") + 1]).read_bytes()
        return subprocess.CompletedProcess(argv, 0, stdout=encoded({"observed_input": json.loads(request)}), stderr=b"")

    def test_human_cli(self):
        case = self.cli_case()
        directory = case.root / "proofs"
        directory.mkdir(mode=0o700)
        case.setup = {"human_reads": {"binding_file": "/installed/human.json", "proofs_dir": "proofs"}}
        proofs = []
        for index in (1, 2):
            # Inert ProofRef-shaped test bytes, not an enrolled assertion.
            data = encoded({"id": secrets.token_hex(16), "request_sha256": sha(encoded({"method": "human.session"})),
                            "expires_at": "2030-01-01T00:00:00Z"})
            atomic(directory / f"{index:08d}.json", data)
            proofs.append(data)
        query = {"life_id": secrets.token_hex(16), "cursor": "", "limit": 1}
        # This is an argument/byte-selection double for the outside reader.
        # Only the independent installed reader can prove human authentication.
        def read(method, raw, request_id, key):
            binding, proof = case.read_options(method)
            request = case.keep("reader-request.json", raw)
            argv = [case.context["binary"], *method.split("."), "--config", case.context["config"],
                    "--binding", binding, "--request", str(request), "--proof", str(proof),
                    "--request-id", request_id, "--idempotency-key", key]
            return subprocess.run(argv, capture_output=True, timeout=45, check=False)
        case.human_reader = SimpleNamespace(read=read)
        with patch("run.subprocess.run", side_effect=self.recording_cli) as cli:
            for _ in proofs:
                self.assertEqual(case.call("dashboard.raw", query), {"observed_input": query})
            for index, invocation in enumerate(cli.call_args_list):
                argv = invocation.args[0]
                self.assertIn("--proof", argv)
                self.assertEqual(argv[argv.index("--binding") + 1], "/installed/human.json")
                self.assertEqual(Path(argv[argv.index("--proof") + 1]).read_bytes(), proofs[index])
                self.assertEqual(argv[argv.index("--config") + 1], case.context["config"])
            self.assertEqual(case.context["binding_file"], "/installed/lane.json")
            case.call("lane.list", {"life_id": query["life_id"], "cursor": "", "limit": 1})
            lane_argv = cli.call_args_list[-1].args[0]
            self.assertNotIn("--proof", lane_argv)
            self.assertEqual(lane_argv[lane_argv.index("--binding") + 1], "/installed/lane.json")
            with self.assertRaises(Failure) as failure:
                case.read_options("dashboard.raw")
            self.assertFalse(failure.exception.reached)
            self.assertEqual(failure.exception.observed_exit, 69)

    def test_human_fixture_missing(self):
        case = self.cli_case()
        with self.assertRaises(Failure) as failure:
            case.read_options("dashboard.lifecycle")
        self.assertFalse(failure.exception.reached)
        self.assertEqual(failure.exception.observed_exit, 69)

    def test_reached_failures(self):
        for error in (Failure("assertion"), KeyError("profile_swap"), ValueError("time"),
                      TypeError("payload"), AttributeError("shape"), OSError("runtime read")):
            case = self.cli_case()
            active = ASSERTIONS[0]
            case.results[active]["reached"] = True
            self.assertEqual(case.failed(active, error), 1)
            self.assertTrue(case.results[active]["reached"])
            self.assertEqual(case.results[active]["verdict"], "fail")
            self.assertEqual(case.results[active]["observed_exit"], 1)

    def test_runtime_cli_errors(self):
        for code in ("unsupported", "unavailable", "not_implemented", "prerequisite_missing"):
            case = self.cli_case()
            case.results[ASSERTIONS[0]]["reached"] = True
            completed = subprocess.CompletedProcess([], 69, stdout=b"", stderr=encoded({"code": code}))
            with patch("run.subprocess.run", return_value=completed):
                with self.assertRaises(Failure) as failure:
                    case.call("lane.check", {"life_id": "life-one", "run": 2})
            self.assertNotIsInstance(failure.exception, SetupFailure)
            self.assertEqual(case.failed(ASSERTIONS[0], failure.exception), 1)
            self.assertTrue(case.results[ASSERTIONS[0]]["reached"])

    def test_run_error_recording(self):
        for error in (KeyError("omitted payload"), ValueError("timestamp"), TypeError("payload"),
                      Failure("runtime unavailable")):
            case = self.cli_case()
            case.human_reader = SimpleNamespace(read=lambda *args: self.fail("observer unexpectedly invoked a dashboard reader"))
            artifact = b"observer-only artifact bytes\n"
            binary = case.root / "artifact"
            binding = case.root / "binding.json"
            atomic(binary, artifact)
            atomic(binding, encoded({"schema":"laneboss.binding.v2", "contract_revision":"v2.0-draft.4",
                                     "protocol":"laneboss.rpc.v2", "api_schema":2, "config":case.context["config"],
                                     "artifact_sha256":sha(artifact)}))
            atomic(case.root / "task.md", b"task input\n")
            atomic(case.root / "mail.md", b"mail input\n")
            atomic(case.root / "setup.json", encoded({"schema":"laneboss.watchdog-case.v2",
                   "start":{"driver":"claudock-cli", "profile_grant_id":"grant-a"},
                   "control":"control.json", "task_file":"task.md", "mail_file":"mail.md"}))
            case.context.update(schema="laneboss.e2e-context.v2", case_id="watchdog", binary=str(binary),
                                binary_sha256=sha(artifact), binding_file=str(binding),
                                profile_grant_ids=["grant-a", "grant-b"], phase="candidate", mutation_id="",
                                source_sha256=sha(b"observer source"))

            def reached(cell, assertion):
                case.results[assertion]["reached"] = True
                raise error

            def identity(method, params, allowed=()):
                if method != "identity.self" or params:
                    raise AssertionError("observer setup called an unexpected product method")
                return {"config":case.context["config"], "actor":{"kind":"lane", "level":6}}

            with patch("run.sys.platform", "linux"), patch.object(case, "run_cell", side_effect=reached), \
                    patch.object(case, "call", side_effect=identity), \
                    patch.object(case, "upload", side_effect=lambda data, kind: Observations.ref(kind, data)):
                result, code = case.run()
            self.assertEqual(code, 1)
            self.assertTrue(result["assertions"][0]["reached"])
            self.assertEqual(result["assertions"][0]["verdict"], "fail")
            self.assertEqual(result["assertions"][0]["observed_exit"], 1)

    def test_setup_failure_classification(self):
        case = self.cli_case()
        active = ASSERTIONS[0]
        self.assertEqual(case.failed(active, KeyError("setup")), 69)
        self.assertFalse(case.results[active]["reached"])
        case.results[active]["reached"] = True
        self.assertEqual(case.failed(active, SetupFailure("independent human reader missing")), 69)
        self.assertFalse(case.results[active]["reached"])

    def test_missing_controller(self):
        case = self.cli_case()
        with self.assertRaises(SetupFailure):
            case.harness_action("restart_service", {"service_id":"service-one", "expected_generation":1})
        case.context["controls"] = "/installed/controller.json"
        with patch("run.Controller", side_effect=FileNotFoundError("fixture absent")):
            with self.assertRaises(SetupFailure):
                case.harness_action("restart_service", {"service_id":"service-one", "expected_generation":1})
        with patch("run.Controller", side_effect=ControlError("malformed enrolled binding")):
            with self.assertRaises(Failure) as failure:
                case.harness_action("restart_service", {"service_id":"service-one", "expected_generation":1})
        self.assertNotIsInstance(failure.exception, SetupFailure)

    def test_human_peer_refusal(self):
        case = self.cli_case()
        for available in (False, True, None):
            if available is None:
                case.context.pop("human_reader_handoff_available", None)
            else:
                case.context["human_reader_handoff_available"] = available
            for code in ("forbidden", "unauthenticated"):
                case.results[ASSERTIONS[0]]["reached"] = True
                case.human_reader = SimpleNamespace(read=lambda *args: subprocess.CompletedProcess([], 1, stdout=b"", stderr=encoded({"code":code})))
                with patch.object(case, "read_options", return_value=("/installed/human.json", None)), \
                        patch("run.subprocess.run", return_value=subprocess.CompletedProcess([], 1, stdout=b"", stderr=encoded({"code":code}))):
                    with self.assertRaises(Failure) as failure:
                        case.call("dashboard.lifecycle", {"life_id":"life-one"})
                if available is False:
                    self.assertIsInstance(failure.exception, SetupFailure)
                    self.assertEqual(case.failed(ASSERTIONS[0], failure.exception), 69)
                    self.assertFalse(case.results[ASSERTIONS[0]]["reached"])
                else:
                    self.assertNotIsInstance(failure.exception, SetupFailure)
                    self.assertEqual(case.failed(ASSERTIONS[0], failure.exception), 1)
                    self.assertTrue(case.results[ASSERTIONS[0]]["reached"])

    def test_capture_event_reader(self):
        case = self.cli_case()
        target = {"life_id":"life-one", "run":2}
        data = b"captured original stdout\n"
        ref = Observations.ref("capture-one", data)
        record = {"id":"capture-one", "binding_id":"capture-binding", "target":target, "stream":"stdout", "offset":0,
                  "primary":True, "coverage":"complete", "data":ref}
        event = {"kind":"capture.appended", "origin":"service", "run":2,
                 "actor":{"kind":"worker", "id":"capture-worker"}, "payload":record}
        with patch.object(case, "events", return_value=[event]), patch.object(case, "blob", return_value=data) as blob, \
                patch.object(case, "call", side_effect=AssertionError("capture used a dashboard call")):
            actual, records = case.raw("life-one", 2)
            self.assertEqual(actual, data)
            self.assertEqual(records, [record])
            blob.assert_called_once_with(ref)
        for kind, origin in (("capture.gap", "service"), ("capture.appended", "observation")):
            changed = dict(event, kind=kind, origin=origin)
            with patch.object(case, "events", return_value=[changed]), patch.object(case, "blob") as blob:
                if kind == "capture.gap":
                    with self.assertRaises(Failure):
                        case.raw("life-one", 2)
                else:
                    self.assertEqual(case.raw("life-one", 2), (b"", []))
                blob.assert_not_called()

    def test_missing_optional_fields(self):
        edits = [
            lambda o: o.trace[2]["payload"].pop("profile_continuation_of"),
            lambda o: o.trace[2]["payload"].pop("profile_swap"),
            lambda o: o.trace[0]["payload"]["observation"].pop("exit_code"),
            lambda o: o.swap["limit"].pop("exit_code"),
            lambda o: (o.trace[0]["payload"]["observation"].pop("exit_code"), o.swap["limit"].pop("exit_code")),
            lambda o: o.current.pop("logical_turn_id"),
        ]
        for edit in edits:
            observer = Observations()
            edit(observer)
            with self.assertRaises(Failure) as failure:
                observer.verify()
            self.assertTrue(failure.exception.reached)

    def test_valid(self):
        observer = Observations()
        try:
            observer.verify()
        except Failure as error:
            self.fail(str(error))
        self.assertEqual(observer.continuations, 1)

    def test_turn(self):
        observer = Observations()
        observer.current["logical_turn_id"] = "different-turn"
        with self.assertRaises(Failure):
            observer.verify()

    def test_history(self):
        observer = Observations()
        observer.current["session"]["home_id"] = "different-home"
        with self.assertRaises(Failure):
            observer.verify()

    def test_history_id(self):
        observer = Observations()
        observer.current["session"]["history_id"] = "another-history"
        with self.assertRaises(Failure):
            observer.verify()

    def test_counters(self):
        for field in ("failures", "retries"):
            observer = Observations()
            observer.current["counters"][field] += 1
            with self.assertRaises(Failure):
                observer.verify()

    def test_counter_resets(self):
        observer = Observations()
        observer.current["counters"] = {"failures": 0, "retries": 0}
        with self.assertRaises(Failure):
            observer.verify()

    def test_epoch(self):
        observer = Observations()
        observer.current["cancellation_epoch"] += 1
        with self.assertRaises(Failure):
            observer.verify()

    def test_task(self):
        observer = Observations()
        observer.current["task"] = observer.ref("another-task", b"another\n")
        with self.assertRaises(Failure):
            observer.verify()

    def test_eligibility(self):
        observer = Observations()
        observer.swap["eligibility_id"] = ""
        with self.assertRaises(Failure):
            observer.verify()

    def test_usage_evidence(self):
        for missing in (False, True):
            observer = Observations()
            if missing:
                observer.swap["limit"].pop("usage_evidence")
            else:
                observer.swap["limit"]["usage_evidence"]["class"] = "capture"
            with self.assertRaises(Failure):
                observer.verify()

    def test_operation_lineage(self):
        observer = Observations()
        observer.trace[2]["operation_id"] = "other-operation"
        with self.assertRaises(Failure):
            observer.verify()

    def test_live_capture_binding(self):
        observer = Observations()
        observer.capture.pop("binding_id")
        with self.assertRaises(Failure):
            observer.verify()

    def test_run(self):
        observer = Observations()
        observer.current["run"] = 4
        observer.observation["target"]["run"] = 4
        observer.swap["continuation_run"] = 4
        observer.trace[2]["run"] = 4
        observer.trace[3]["payload"]["target"]["run"] = 4
        observer.trace[3]["run"] = 4
        with self.assertRaises(Failure):
            observer.verify()

    def test_budget(self):
        observer = Observations()
        observer.current["budget_remaining"]["wall_ms"] = observer.base["budget_remaining"]["wall_ms"] + 1
        with self.assertRaises(Failure):
            observer.verify()

    def test_quota_failure(self):
        observer = Observations()
        observer.trace[0]["payload"]["profile_continuation"] = False
        with self.assertRaises(Failure):
            observer.verify()

    def test_mail(self):
        observer = Observations()
        duplicate = copy.deepcopy(observer.trace[3])
        duplicate["seq"] += 1
        observer.trace.append(duplicate)
        with self.assertRaises(Failure):
            observer.verify()

    def test_capture(self):
        observer = Observations()
        observer.capture["primary"] = False
        with self.assertRaises(Failure):
            observer.verify()

    def test_room(self):
        observer = Observations()
        observer.swap["room"]["available"] = False
        with self.assertRaises(Failure):
            observer.verify()

    def test_actor(self):
        observer = Observations()
        observer.trace[1]["actor"] = {"kind": "lane", "life_id": "mail-sender"}
        with self.assertRaises(Failure):
            observer.verify()

    def test_wait(self):
        observer = Observations()
        observer.bad_wait = True
        with self.assertRaises(Failure):
            observer.run_cell("no-room", "WATCHDOG-NO-ROOM")

    def test_restore(self):
        observer = Observations()
        observer.bad_restore = True
        with self.assertRaises(Failure):
            observer.run_cell("no-room", "WATCHDOG-NO-ROOM")

    def test_healthy_restore(self):
        observer = Observations()
        try:
            observer.run_cell("no-room", "WATCHDOG-NO-ROOM")
        except Failure as error:
            self.fail(str(error))
        self.assertEqual(observer.continuations, 1)

    def test_tamper(self):
        observer = Observations()
        observer.bad_tamper = True
        with self.assertRaises(Failure):
            observer.run_cell("tamper", "WATCHDOG-TAMPER")

    def test_canary(self):
        observer = Observations()
        observer.bad_canary = True
        with self.assertRaises(Failure):
            observer.run_cell("tamper", "WATCHDOG-TAMPER")

    def test_probe_errors(self):
        for probe, valid in (("forge", {"code":"forbidden"}), ("file", {"errno":13}), ("signal", {"errno":3})):
            self.assertTrue(Case.denied_probe(dict(valid, probe=probe)))
            self.assertFalse(Case.denied_probe({"probe":probe, "errno":2}))
            self.assertFalse(Case.denied_probe({"probe":probe, "errno":0}))
        self.assertFalse(Case.denied_probe({"probe":"forge", "errno":13}))
        self.assertFalse(Case.denied_probe({"probe":"file", "code":"forbidden"}))

    def test_real_limit(self):
        observer = Observations()
        observer.no_real_limit = True
        with self.assertRaises(Failure):
            observer.run_cell("tamper", "WATCHDOG-TAMPER")

    def test_stop(self):
        observer = Observations()
        observer.stale_stop = True
        observer.current["run"] = observer.base["run"]
        observer.observation["target"]["run"] = observer.base["run"]
        ticks = iter(range(100))
        with patch("run.time.monotonic", side_effect=lambda: next(ticks)), patch("run.time.sleep"):
            with self.assertRaises(Failure):
                observer.race("stop-race", observer.life, observer.nonce, observer.base, observer.base)

    def test_resume(self):
        observer = Observations()
        observer.double_resume = True
        observer.current["run"] = 4
        ticks = iter(range(100))
        with patch("run.time.monotonic", side_effect=lambda: next(ticks)), patch("run.time.sleep"):
            with self.assertRaises(Failure):
                observer.race("resume-race", observer.life, observer.nonce, observer.base, observer.base)

    def test_race_receipts_and_quiescence(self):
        for cell in ("stop-race", "resume-race"):
            observer = Observations()
            if cell == "stop-race":
                observer.current["run"] = observer.base["run"]
                observer.observation["target"]["run"] = observer.base["run"]
                observer.trace = [observer.event("lane.stopping", 2, {})]
            wait = observer.event("watchdog.waiting", 2, {"retry_after_ms":5000})
            wait["seq"] = 0
            observer.trace.insert(0, wait)
            ticks = iter(range(100))
            with patch("run.time.monotonic", side_effect=lambda: next(ticks)), patch("run.time.sleep"):
                observer.race(cell, observer.life, observer.nonce, observer.base, observer.base)
            self.assertEqual(observer.operation_reads, ["manual-"+observer.life])
            self.assertIn(2 if cell == "stop-race" else 3, observer.quiet_reads)

    def test_independent_canary(self):
        observer = Observations()
        observer.bad_independent = True
        with self.assertRaises(Failure):
            observer.run_cell("tamper", "WATCHDOG-TAMPER")

    def test_restart(self):
        observer = Observations()
        observer.run_cell("restart", "WATCHDOG-RESTART")
        self.assertTrue(observer.restarted)
        self.assertEqual(observer.continuations, 1)

    def test_restart_loss(self):
        observer = Observations()
        observer.bad_restart = True
        with self.assertRaises(Failure):
            observer.run_cell("restart", "WATCHDOG-RESTART")

    @staticmethod
    def control_pair(action="restart_service"):
        request = {"schema": "laneboss.e2e-control.v2", "case_id": "watchdog", "phase": "candidate",
                   "mutation_id": "", "binary_sha256": sha(b"artifact"), "request_id": secrets.token_hex(16),
                   "nonce": secrets.token_hex(16), "action": action,
                   "params": {"service_id": "service-one", "expected_generation": 1}}
        result = {"service_id": "service-one", "previous_generation": 1, "current_generation": 2,
                  "old_pid": 1001, "new_pid": 1002, "old_exited": True,
                  "evidence": [{"path": "receipt.json", "sha256": sha(b"receipt"), "bytes": 7}]}
        if action == "run_confined_canary":
            request["params"] = {"target": {"life_id": "life-one", "run": 2}, "canary_id": "watchdog-canary",
                                 "input": Observations.ref("input-one", b"canary")}
            result = {"job_id": "job-one", "target": request["params"]["target"], "observed_exit": 0,
                      "containment_state": "exited", "survivors": 0, "input_sha256": sha(b"canary"),
                      "evidence": result["evidence"]}
        reply = {"schema": "laneboss.e2e-control-reply.v2", "result": result}
        for key in ("case_id", "request_id", "nonce", "binary_sha256", "action"):
            reply[key] = request[key]
        return request, reply

    def test_control_reply(self):
        for action in ("restart_service", "run_confined_canary"):
            request, reply = self.control_pair(action)
            self.assertEqual(verify_reply(reply, request), reply["result"])

    def test_control_nonce(self):
        request, reply = self.control_pair()
        reply["nonce"] = secrets.token_hex(16)
        with self.assertRaises(ControlError):
            verify_reply(reply, request)

    def test_control_restart(self):
        for field, value in (("old_exited", False), ("current_generation", 1), ("service_id", "another-service")):
            request, reply = self.control_pair()
            reply["result"][field] = value
            with self.assertRaises(ControlError):
                verify_reply(reply, request)

    def test_control_canary(self):
        for field, value in (("containment_state", "unknown"), ("survivors", None), ("observed_exit", None),
                             ("input_sha256", sha(b"another input"))):
            request, reply = self.control_pair("run_confined_canary")
            reply["result"][field] = value
            with self.assertRaises(ControlError):
                verify_reply(reply, request)

    def test_control_evidence(self):
        for path in ("../escape", "/absolute"):
            request, reply = self.control_pair()
            reply["result"]["evidence"][0]["path"] = path
            with self.assertRaises(ControlError):
                verify_reply(reply, request)

    def test_control_writer(self):
        peer = (1001, 10001, 10001)

        class Fragments:
            def __init__(self, writer):
                self.writer = writer

            def recvmsg(self, size, capacity):
                return b"data", [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, struct.pack("3i", *self.writer))], 0, None

        self.assertEqual(Controller.receive(Fragments(peer), peer, 4), b"data")
        with self.assertRaises(ControlError):
            Controller.receive(Fragments((1002, 10001, 10001)), peer, 4)


class JSONResult(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.events = []

    def startTest(self, test):
        super().startTest(test)
        self.events.append({"Action": "run", "Test": test.id()})

    def addSuccess(self, test):
        super().addSuccess(test)
        self.events.append({"Action": "pass", "Test": test.id()})

    def addFailure(self, test, error):
        super().addFailure(test, error)
        self.events.append({"Action": "fail", "Test": test.id(), "Output": self._exc_info_to_string(error, test)})

    def addError(self, test, error):
        super().addError(test, error)
        self.events.append({"Action": "error", "Test": test.id(), "Output": self._exc_info_to_string(error, test)})


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromName(sys.argv[1]) if len(sys.argv) == 2 else unittest.defaultTestLoader.loadTestsFromTestCase(CheckTests)
    result = JSONResult()
    suite.run(result)
    for event in result.events:
        print(json.dumps(event))
    invalid = result.errors or result.skipped or result.expectedFailures or result.unexpectedSuccesses
    print(json.dumps({"Action": "pass" if result.wasSuccessful() and not invalid else "fail", "tests": result.testsRun}))
    sys.exit(2 if invalid else (0 if result.wasSuccessful() else 1))
