"""Producer red/green controls, never an installed OS-LINUX verdict."""

from datetime import datetime, timedelta, timezone
import copy
import importlib.util
import json
import os
from pathlib import Path
import secrets
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


producer = module("linux_producer", ROOT / "scripts/v2-serve/case_linux.py")
consumer = module("linux_consumer_controls", HERE / "run.py")
dac = module("linux_dac_controls", HERE / "dac.py")
targets = module("linux_targets_controls", HERE / "targets.py")
canary = module("linux_canary_handoff", HERE / "canary.py")


class AuthorityDouble:
    """Only the numbered-file adapter is under test; no authority is claimed."""
    def __init__(self, root):
        self.root = root
        self.public = {"principal_id": "component-human"}
        self.calls = []

    def proof(self, name, method, request, target, generation):
        self.calls.append((method, copy.deepcopy(request), target, generation))
        path = self.root / ("component-%d.json" % len(self.calls))
        producer.put(path, producer.encoded({
            "id": "component-" + secrets.token_hex(12),
            "request_sha256": producer.sha(producer.encoded(request)),
            "expires_at": "2099-01-01T00:00:00Z"}))
        return path


class ProducerControls(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="lb-v2-case-linux-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name).resolve()

    def context(self):
        binary = self.root / "binary"
        producer.put(binary, os.urandom(48))
        evidence = self.root / "out"
        evidence.mkdir(mode=0o700)
        return {"schema": "laneboss.e2e-context.v2", "case_id": "linux",
                "phase": "candidate", "mutation_id": "", "config": "component",
                "test_root": str(self.root), "evidence_root": str(evidence),
                "binary": str(binary), "binary_sha256": producer.sha(binary.read_bytes()),
                "source_sha256": producer.sha(Path(__file__).read_bytes()),
                "binding_file": str(self.root / "missing-binding"),
                "profile_grant_ids": []}

    def authorization(self):
        now = datetime.now(timezone.utc)
        start = {"driver": "codex", "profile_grant_id": "component-profile",
                 "model": "component-full-model", "effort": "high",
                 "budget": {"wall_ms": 1000}}
        context = {"config": "component", "profile_grant_ids": [start["profile_grant_id"]]}
        auth = dict(start, schema="laneboss.linux-live.v1", config="component",
                    cell="component", allow_model_request=True,
                    runtime_sha256=producer.sha(os.urandom(32)),
                    expires_at=(now + timedelta(minutes=5)).isoformat())
        return now, start, context, auth

    def test_live_fields_red_then_green(self):
        now, start, context, auth = self.authorization()
        replacements = {"schema": "other", "config": "other", "cell": "other",
                        "allow_model_request": False, "driver": "stand-in",
                        "profile_grant_id": "other", "model": "other",
                        "effort": "other", "budget": {"wall_ms": 2000},
                        "runtime_sha256": "unknown",
                        "expires_at": (now - timedelta(seconds=1)).isoformat()}
        for name, replacement in replacements.items():
            with self.subTest(field=name):
                changed = dict(auth, **{name: replacement})
                with self.assertRaises(ValueError):
                    producer.live_authorization(producer.encoded(changed), context,
                                                start, "component", now)
                self.assertEqual(producer.live_authorization(
                    producer.encoded(auth), context, start, "component", now), auth)

    def test_empty_profiles_cannot_authorize(self):
        now, start, context, auth = self.authorization()
        context["profile_grant_ids"] = []
        with self.assertRaisesRegex(ValueError, "granted real driver"):
            producer.live_authorization(producer.encoded(auth), context,
                                        start, "component", now)
        context["profile_grant_ids"] = [start["profile_grant_id"]]
        self.assertEqual(producer.live_authorization(
            producer.encoded(auth), context, start, "component", now), auth)

    def test_unbound_start_has_no_authority(self):
        now, start, context, auth = self.authorization()
        for key in ("driver", "model", "profile_grant_id", "effort", "budget"):
            with self.subTest(field=key):
                changed = dict(start)
                del changed[key]
                with self.assertRaises(ValueError):
                    producer.live_authorization(producer.encoded(auth), context,
                                                changed, "component", now)
        self.assertEqual(producer.live_authorization(
            producer.encoded(auth), context, start, "component", now), auth)

    def test_live_gate_precedes_publication(self):
        context = self.context()
        human = mock.Mock()
        serve = SimpleNamespace(config=context["config"], human=human)
        subject = producer.Producer(serve, context)
        with self.assertRaisesRegex(producer.MissingGate, "real_driver_authorization"):
            subject.prepare({})
        human.upload.assert_not_called()
        human.ticket.assert_not_called()
        wait = json.loads((self.root / "linux-wait.json").read_bytes())
        self.assertEqual(wait["code"], "prerequisite_missing")
        self.assertEqual(wait["owner"], "laneboss")
        self.assertFalse(wait["completed"])
        self.assertFalse((self.root / "linux-input.json").exists())
        self.assertTrue(all(row["state"] == "incomplete" for row in
                            json.loads((self.root / "matrix-required.json").read_bytes())))

    def test_changed_binary_precedes_live_gate(self):
        context = self.context()
        Path(context["binary"]).write_bytes(os.urandom(48))
        serve = SimpleNamespace(config=context["config"], human=mock.Mock())
        with self.assertRaisesRegex(ValueError, "artifact pin differs"):
            producer.Producer(serve, context).prepare({})
        serve.human.upload.assert_not_called()
        self.assertFalse((self.root / "linux-wait.json").exists())

    def test_entry_unreached_live_wait(self):
        context = self.context()
        path = producer.put(self.root / "context.json", producer.encoded(context))
        result_path = Path(context["evidence_root"]) / "result.json"
        self.assertEqual(consumer.main(["--context", str(path),
                                        "--result", str(result_path)]), 69)
        result = json.loads(result_path.read_bytes())
        item = result["assertions"][0]
        self.assertEqual(item["id"], "OS-LINUX")
        self.assertEqual(item["verdict"], "fail")
        self.assertFalse(item["reached"])
        self.assertEqual(item["observed_exit"], 69)
        self.assertFalse(result["collection"]["processes_quiescent"])
        self.assertFalse(result["collection"]["temporary_resources_collected"])
        for ref in item["evidence"]:
            raw = (Path(context["evidence_root"]) / ref["path"]).read_bytes()
            self.assertEqual((len(raw), producer.sha(raw)), (ref["bytes"], ref["sha256"]))

    def test_assets_are_actual_canary_bytes(self):
        assets = producer.assets()
        self.assertEqual(len(assets), 1)
        asset = assets[0]
        raw = (HERE / "canary.py").read_bytes()
        self.assertEqual(asset["content"], raw)
        self.assertEqual((asset["bytes"], asset["sha256"]), (len(raw), producer.sha(raw)))
        self.assertEqual(asset["mode"], 0o444)

    def test_task_rejects_shell_injection(self):
        marker = secrets.token_hex(16)
        args = ["/runtime/linux/canary.py", producer.sha(os.urandom(16)),
                "/work/input.json", marker, "/work/output.json"]
        for index in (0, 2, 3, 4):
            with self.subTest(argument=index):
                changed = list(args)
                changed[index] += "; command"
                with self.assertRaises(ValueError):
                    producer.driver_task(*changed)
        task = producer.driver_task(*args).decode()
        self.assertIn("/usr/bin/python3 -I -B " + args[0], task)
        self.assertIn(" --marker " + marker, task)
        self.assertIn(args[1], task)

    def test_one_cell_cannot_claim_matrix(self):
        rows = producer.matrix()
        self.assertEqual(len(rows), 16)
        self.assertEqual(len({tuple(row[key] for key in
                                    ("driver", "restriction", "hook", "abi"))
                              for row in rows}), len(rows))
        self.assertTrue(all(row["state"] == "incomplete" for row in rows))
        key = ("codex", 1, "absent", "current")
        measured = producer.matrix([key])
        self.assertEqual(sum(row["state"] == "measured" for row in measured), 1)
        self.assertTrue(all(row["state"] == "incomplete" for row in measured
                            if row["abi"] == "3"))

    def test_put_preserves_bytes_and_mode(self):
        path = producer.put(self.root / "input", os.urandom(32))
        raw = path.read_bytes()
        with self.assertRaises(FileExistsError):
            producer.put(path, os.urandom(32))
        self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_input_links_and_escape_refuse(self):
        path = producer.put(self.root / "input", os.urandom(32))
        (self.root / "link").symlink_to(path)
        with self.assertRaisesRegex(ValueError, "not canonical"):
            producer.ordinary(self.root / "link")
        os.link(path, self.root / "hardlink")
        with self.assertRaisesRegex(ValueError, "ordinary file"):
            producer.ordinary(path)
        for name in ("../escape", "/outside"):
            with self.subTest(path=name), self.assertRaises(ValueError):
                producer.relative(self.root, name)

    def test_private_input_ancestor_is_checked(self):
        path = producer.put(self.root / "private", os.urandom(24))
        with self.assertRaisesRegex(ValueError, "authority ancestor"):
            producer.ordinary(path, private=True, owner=os.geteuid())
        self.assertEqual(producer.ordinary(path), path.read_bytes())

    def test_proof_sequence_and_bytes(self):
        human = AuthorityDouble(self.root)
        coord = producer.ProofCoordinator(self.root, human)
        with self.assertRaisesRegex(ValueError, "sequence differs"):
            coord.supply(2, ["lane", "status"], {"life_id": "component", "run": 1})
        self.assertEqual(human.calls, [])
        path = coord.supply(1, ["lane", "start"], {"task": {"id": "component"}})
        self.assertEqual(path.read_bytes(), (self.root / "component-1.json").read_bytes())
        self.assertEqual(human.calls, [("human.session", {}, "component-human", 0)])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    def test_review_proof_uses_generation(self):
        human = AuthorityDouble(self.root)
        coord = producer.ProofCoordinator(self.root, human)
        body = {"target": {"life_id": "component", "run": 2}, "checks": []}
        with self.assertRaisesRegex(ValueError, "observed generation"):
            coord.supply(1, ["lane", "review"], body)
        self.assertEqual(human.calls, [])
        # A failed sequence is not retried. A fresh coordinator is isolated.
        other = self.root / "other"
        other.mkdir(mode=0o700)
        coord = producer.ProofCoordinator(other, human)
        coord.observed(["lane", "status"], {"life_id": "component", "run": 2},
                       {"generation": 17})
        coord.supply(1, ["lane", "review"], body)
        self.assertEqual(human.calls[-1], ("lane.review", body, "component", 17))

    def test_wrong_proof_directory_refuses(self):
        directory = self.root / "authority"
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "private numbered authority"):
            producer.ProofCoordinator(self.root, AuthorityDouble(self.root))
        directory.chmod(0o700)
        coord = producer.ProofCoordinator(self.root, AuthorityDouble(self.root))
        self.assertEqual(coord.next_index, 1)

    def test_native_join_rejects_foreign_life(self):
        context = {"config": "component"}
        selected = {"id": "component-lease", "uid": 65431, "gid": 65431,
                    "containment_id": "component-cgroup"}
        plan = {"lease": selected, "reservation": {
            "id": "component-reservation", "operation_id": "component-operation",
            "target": {"life_id": "new-component", "run": 1}}}
        value = {"schema": "laneboss.helper-lease.v2", "phase": "active",
                 "boot_id": "component-boot", "lease": selected, "request": {
                     "life_id": "old-component", "config": "component",
                     "reservation_id": "component-reservation",
                     "cause": {"cause_operation_id": "component-operation"}}}
        with self.assertRaisesRegex(ValueError, "actual started life"):
            producer.join_lease(producer.encoded(value), context, plan, {65431})
        value["request"]["life_id"] = "new-component"
        self.assertEqual(producer.join_lease(producer.encoded(value), context, plan, {65431}), value)
        with self.assertRaisesRegex(ValueError, "actual started life"):
            producer.join_lease(producer.encoded(value), context, plan, {65430})

    def test_refusal_stops_cleanup_calls(self):
        context = self.context()
        case = consumer.Case(context)
        case.refused = True
        record = {"cell": {"id": "component", "marker": secrets.token_hex(16)},
                  "target": {"life_id": "component", "run": 1}, "uid": 12345,
                  "observer": None, "started": True, "quiescent": False,
                  "collected": False, "collecting": False}
        case.records.append(record)
        case.owned.append(record)
        case.call = mock.Mock()
        case.cleanup()
        case.call.assert_not_called()
        self.assertFalse(case.quiescent)
        self.assertFalse(case.collected)
        self.assertIn("supervisor reconciliation", case.cleanup_errors[0])

    def test_network_control_and_actual_delta(self):
        foreign = {name: ["::1" if family == socket.AF_INET6 else "127.0.0.1", 0]
                   for name, family, _ in consumer.NETWORK_KINDS}
        observer = consumer.NetworkObserver(foreign)
        try:
            payload = os.urandom(32)
            actual = observer.positive_control(payload)
            self.assertEqual(set(actual), {"foreign." + key for key in foreign})
            self.assertTrue(all(count["bytes"] == len(payload) for count in actual.values()))
            self.assertTrue(all(not any(count.values()) for count in observer.snapshot().values()))
            with self.assertRaisesRegex(RuntimeError, "not fresh"):
                observer.positive_control(payload)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
                self.assertEqual(stream.sendto(payload, tuple(observer.addresses["udp4"])), len(payload))
            actual = observer.finish()
            self.assertEqual(actual["foreign.udp4"]["bytes"], len(payload))
            self.assertEqual(actual["foreign.udp4"]["packets"], 1)
        finally:
            observer.close()
        self.assertFalse(any(thread.is_alive() for thread in observer.threads))

    def test_real_dac_denial_then_access(self):
        if os.geteuid() != 0:
            self.fail("DAC controls must run through the authorized --root box job")
        self.root.chmod(0o755)
        path = producer.put(self.root / "canary", os.urandom(32))
        expected = {"outside": producer.sha(path.read_bytes())}
        paths = {"outside": str(path)}
        denied = dac.probe(paths, 65431, 65431)
        with self.assertRaisesRegex(RuntimeError, "DAC masks"):
            dac.require_access(denied, expected)
        path.chmod(0o666)
        allowed = dac.probe(paths, 65431, 65431)
        dac.require_access(allowed, expected)
        self.assertEqual(allowed["uid"], 65431)
        self.assertEqual(allowed["groups"], [])
        self.assertEqual(producer.sha(path.read_bytes()), expected["outside"])

    def test_plan_event_red_then_green(self):
        target = {"life_id": "component-life", "run": 1}
        context, operation = {"config": "component"}, {"id": "component-operation"}
        selected = {"id": "component-lease", "uid": 65431}
        plan = {"reservation": {"target": target, "config": "component",
                                "operation_id": operation["id"]},
                "lease": selected, "data": {"target": target, "lease_id": selected["id"]}}
        event = {"kind": "launch.planned", "origin": "service", "config": "component",
                 "life_id": target["life_id"], "run": 1, "seq": 12,
                 "operation_id": operation["id"], "payload": {"plan": plan}}
        page = {"complete": True, "events": [event]}
        for field, replacement in (("origin", "lane"), ("config", "other"),
                                   ("life_id", "other"), ("run", 2), ("seq", 0),
                                   ("operation_id", "other")):
            with self.subTest(field=field):
                changed = copy.deepcopy(page)
                changed["events"][0][field] = replacement
                with self.assertRaises(ValueError):
                    producer.plan_for(changed, context, target, operation)
                self.assertEqual(producer.plan_for(page, context, target, operation), plan)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            producer.plan_for(dict(page, complete=False), context, target, operation)
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            producer.plan_for(dict(page, events=[event, event]), context, target, operation)

    def test_signal_target_observes_delivery(self):
        context = self.context()
        subject = producer.Producer(SimpleNamespace(config="component"), context)
        case = SimpleNamespace(keep=mock.Mock(), boundary_failures=[])
        target = targets.SignalTarget()
        try:
            subject.signal = target
            subject.foreign_identity = consumer.process_identity(target.pid)
            self.assertEqual(target.snapshot()["signals"], 0)
            os.kill(target.pid, signal.SIGUSR1)
            ready, _, _ = select.select([target.reader], [], [], 3)
            self.assertEqual(ready, [target.reader])
            self.assertEqual(target.snapshot()["signals"], 1)
            self.assertIsNotNone(consumer.process_identity(target.pid))
            with self.assertRaisesRegex(RuntimeError, "boundary canary succeeded: foreign.signal"):
                subject.check_foreign(case, "before-start")
            self.assertEqual(case.boundary_failures, ["foreign.signal"])
        finally:
            receipt = target.close()
        self.assertTrue(receipt["collected"])
        self.assertEqual(receipt, target.close())
        self.assertTrue(os.WIFSIGNALED(receipt["wait_status"]))
        fresh = targets.SignalTarget()
        try:
            subject.signal = fresh
            subject.foreign_identity = consumer.process_identity(fresh.pid)
            subject.check_foreign(case, "before-start")
            self.assertEqual(fresh.snapshot()["signals"], 0)
        finally:
            self.assertTrue(fresh.close()["collected"])

    def test_permitted_echo_is_measured(self):
        target = targets.EchoTarget(["127.0.0.1", 0])
        payload = os.urandom(48)
        try:
            control = target.control(payload)
            self.assertEqual(control["echo_bytes"], len(payload))
        finally:
            receipt = target.close()
        self.assertEqual(receipt["bytes"], len(payload))
        self.assertEqual(receipt["messages"], [producer.sha(payload)])
        self.assertFalse(receipt["thread_alive"])
        self.assertEqual(receipt["errors"], [])

    def test_ipc_delivery_cannot_hide(self):
        foreign = {name: ["::1" if family == socket.AF_INET6 else "127.0.0.1", 0]
                   for name, family, _ in consumer.NETWORK_KINDS}
        path = self.root / "outside.sock"
        foreign["ipc"] = str(path)
        observer = consumer.NetworkObserver(foreign)
        try:
            payload = os.urandom(24)
            controls = observer.positive_control(payload)
            self.assertEqual(controls["foreign.ipc"]["connections"], 1)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                stream.connect(str(path))
                stream.sendall(payload)
            actual = observer.finish()
            self.assertEqual(actual["foreign.ipc"]["bytes"], len(payload))
            decisions = module("linux_decision_inputs", HERE / "run_tests.py")
            case = decisions.decision_case()
            with self.assertRaisesRegex(RuntimeError, "boundary canary succeeded: foreign.ipc"):
                case.check_operations(decisions.decision_observation(), actual)
        finally:
            observer.close()
        self.assertFalse(os.path.lexists(path))

    def test_input_release_is_fenced(self):
        context = self.context()
        subject = producer.Producer(SimpleNamespace(config="component"), context)
        worktree = self.root / "worktree"
        worktree.mkdir(mode=0o700)
        os.chown(worktree, 65431, 65431)
        subject.worktree = worktree
        outside = self.root / "foreign"
        outside.mkdir(mode=0o700)
        (worktree / ".linux").symlink_to(outside)
        record = {"cell": {"lane_uid": 65431, "lane_gid": 65431,
                           "observer_paths": {"work": str(worktree / ".linux/work"),
                                              "input": str(worktree / ".linux/input.json")}}}
        case = SimpleNamespace(keep=mock.Mock())
        with self.assertRaises(OSError):
            subject.release_input(case, record, os.urandom(48))
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(outside.stat().st_uid, 0)
        (worktree / ".linux").unlink()
        raw = os.urandom(48)
        subject.release_input(case, record, raw)
        input_path = worktree / ".linux/input.json"
        self.assertEqual(input_path.read_bytes(), raw)
        self.assertEqual((input_path.stat().st_uid, input_path.stat().st_gid), (65431, 65431))
        self.assertEqual(stat.S_IMODE(input_path.stat().st_mode), 0o600)
        self.assertFalse((worktree / ".linux/input.json.pending").exists())

    def test_canary_checks_released_hash(self):
        path = producer.put(self.root / "canary-input", producer.encoded({"component": secrets.token_hex(12)}))
        output = self.root / "canary-output"
        marker = secrets.token_hex(16)
        args = ["--input", str(path), "--output", str(output), "--marker", marker]
        bad = subprocess.run([sys.executable, "-I", "-B", str(HERE / "canary.py"),
                              *args, "--input-sha256", producer.sha(os.urandom(48))],
                             capture_output=True, check=False)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn(b"released different canary bytes", bad.stderr)
        self.assertFalse(output.exists())
        # Only CLI parsing/publication is tested by this double. It is never
        # fed to the public case as a syscall observation.
        with mock.patch.object(sys, "argv", ["canary.py", *args, "--input-sha256",
                                             producer.sha(path.read_bytes())]), \
             mock.patch.object(canary, "run", return_value={"component_only": marker}) as run:
            canary.main()
            run.assert_called_once_with(json.loads(path.read_bytes()), marker)
        kept = json.loads(output.read_bytes())
        self.assertEqual(kept["input_sha256"], producer.sha(path.read_bytes()))
        self.assertEqual(kept["component_only"], marker)

    def test_plan_entry_preserves_live_gate(self):
        context = self.context()
        inputs = self.root / "inputs"
        inputs.mkdir(mode=0o700)
        context["test_root"] = str(inputs)
        binding = producer.put(self.root / "binding", b"{}\n")
        context["binding_file"] = str(binding)
        path = producer.put(inputs / "context.json", producer.encoded(context))
        result_path = Path(context["evidence_root"]) / "result.json"
        with tempfile.TemporaryDirectory(prefix="lb-v2-case-linux-", dir="/opt") as protected:
            plan_path = producer.put(Path(protected) / "plan.json", b"{}\n")
            completed = subprocess.run(["sh", str(HERE / "run.sh"), "--context", str(path),
                                        "--result", str(result_path), "--plan", str(plan_path)],
                                       capture_output=True, check=False)
        self.assertEqual(completed.returncode, 69, completed.stderr.decode())
        result = json.loads(result_path.read_bytes())
        self.assertFalse(result["assertions"][0]["reached"])
        self.assertEqual(result["assertions"][0]["verdict"], "fail")
        wait = json.loads((Path(context["evidence_root"]) / "owner.wait.json").read_bytes())
        self.assertEqual((wait["owner"], wait["gate"]), ("laneboss", "real_driver_authorization"))
        self.assertFalse(result["collection"]["processes_quiescent"])

    def test_public_fixture_collects_real_files(self):
        context = self.context()
        subject = producer.Producer(SimpleNamespace(config="component"), context)
        subject.public = self.root / "public"
        subject.public.mkdir(mode=0o755)
        raw = os.urandom(48)
        subject.outside = producer.put(subject.public / "outside", raw)
        producer.put(self.root / "outside-input.bin", raw)
        subject.outside.write_bytes(os.urandom(48))
        with self.assertRaisesRegex(RuntimeError, "outside fixture collection failed"):
            subject.close()
        self.assertTrue(subject.public.exists())
        failure = json.loads((self.root / "outside-collection.json").read_bytes())
        self.assertIn("outside canary bytes changed", failure["errors"][0])
        fresh_root = self.root / "fresh"
        fresh_root.mkdir(mode=0o700)
        context = dict(context, test_root=str(fresh_root))
        subject = producer.Producer(SimpleNamespace(config="component"), context)
        subject.public = fresh_root / "public"
        subject.public.mkdir(mode=0o755)
        subject.outside = producer.put(subject.public / "outside", raw)
        producer.put(fresh_root / "outside-input.bin", raw)
        subject.close()
        self.assertFalse(subject.public.exists())
        self.assertEqual((fresh_root / "outside-collected.bin").read_bytes(), raw)
        receipt = json.loads((fresh_root / "outside-collection.json").read_bytes())
        self.assertFalse(receipt["public"]["retained"])
        self.assertEqual(receipt["errors"], [])

    def test_review_needs_independent_checks(self):
        target = {"life_id": "component-life", "run": 1}
        review = {"id": "component-review", "coverage": "complete",
                  "reviewer": {"kind": "human", "id": "component-human"},
                  "evidence": {"schema": "laneboss.review.v2", "coverage": "complete",
                               "subject": {"target": target},
                               "verifier_lease_id": "component-verifier",
                               "inventory": {"tool_coverage": "complete",
                                             "tool_records": {"id": "component-records"}},
                               "checks": [{"exit_code": 0, "target": target,
                                           "worker_lease_id": "component-worker",
                                           "operation_id": "component-operation"}]}}
        for field, replacement in (("coverage", "partial"), ("verifier_lease_id", ""),
                                   ("checks", []), ("subject", {"target": dict(target, run=2)})):
            with self.subTest(field=field):
                changed = copy.deepcopy(review)
                changed["evidence"][field] = replacement
                with self.assertRaisesRegex(RuntimeError, "independent verification"):
                    consumer.review_complete(changed, target)
                consumer.review_complete(review, target)
        changed = copy.deepcopy(review)
        changed["evidence"]["checks"][0]["exit_code"] = 1
        with self.assertRaisesRegex(RuntimeError, "independent verification"):
            consumer.review_complete(changed, target)
        consumer.review_complete(review, target)


if __name__ == "__main__":
    unittest.main(verbosity=2)
