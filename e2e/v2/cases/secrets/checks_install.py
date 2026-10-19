"""Installed observer checks on Linux; synthetic frames confer no E2E credit."""

import argparse
import copy
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import socket
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[4]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


INSTALLED = load("secret_installed_checks", Path(__file__).with_name("installed.py"))
WIRE, OBSERVER, PRODUCER = INSTALLED.WIRE, INSTALLED.OBSERVER, INSTALLED.PRODUCER
DIAGNOSTICS = INSTALLED.DIAGNOSTICS


class InstalledChecks(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="lb-v2-secrets-wire-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        binary = Path("/proc/self/exe").resolve()
        self.context = {"config": "secret-unit", "binary": str(binary),
                        "binary_sha256": WIRE.sha(binary.read_bytes()),
                        "binding_file": str(self.root / "binding.json")}
        self.entries = []
        for index, name in enumerate(PRODUCER.STEPS):
            directory = self.root / ("rpc-%02d" % index)
            directory.mkdir()
            body = {"unit_nonce": os.urandom(16).hex()}
            request = self.root / ("intent-%02d.json" % index)
            request.write_text(json.dumps(body), encoding="utf-8")
            frame = self.row(name, PRODUCER.METHODS[name], body, {"id": os.urandom(16).hex()})
            rows = [frame]
            if name == "human-session":
                body = {}
                request.write_text(json.dumps(body), encoding="utf-8")
                frame = self.row(name, "human.session", body, {"id": os.urandom(16).hex(), "config": self.context["config"]})
                rows = [frame]
            if name == "bad-stage":
                key_id, stage_id = os.urandom(16).hex(), os.urandom(16).hex()
                body = {"sealed_upload_id": stage_id}
                request.write_text(json.dumps(body), encoding="utf-8")
                frame = self.row(name, "secret.import", body, None)
                rows = [self.row("bad-key", "secret.key", {}, {"id": key_id}),
                        self.row("bad-upload", "secret.stage", {"key_id": key_id}, {"id": stage_id}), frame]
            if name != "human-session":
                rows.insert(0, self.row("human-session", "human.session", {}, {"id": os.urandom(16).hex(), "config": self.context["config"]}))
            (directory / "wire.jsonl").write_bytes(b"".join(json.dumps(row).encode() + b"\n" for row in rows))
            (directory / "native.json").write_text(json.dumps(WIRE.process(os.getpid())), encoding="utf-8")
            (directory / "argv.json").write_text(json.dumps([str(binary), "human", "session", "--config",
                self.context["config"], "--binding", self.context["binding_file"]]), encoding="utf-8")
            code = 3 if name == "bad-stage" else 0
            (directory / "exit.json").write_text(json.dumps({"exit": code}), encoding="utf-8")
            self.entries.append({"name": name, "method": PRODUCER.METHODS[name], "directory": directory.name,
                "request": request.name, "request_sha256": WIRE.sha(request.read_bytes()),
                "wire_sha256": WIRE.sha((directory / "wire.jsonl").read_bytes()),
                "outcome": {"error": frame["response"]["error"]} if name == "bad-stage" else frame["response"]["result"],
                "polls": [], "exit": code})

    def row(self, name, method, body, result):
        identifier = os.urandom(16).hex()
        response = {"protocol": "laneboss.rpc.v2", "schema": 2, "request_id": identifier}
        response.update({"error": {"code": "integrity", "message": "unit authentication refusal"}}
                        if result is None else {"result": result})
        request = {"protocol": "laneboss.rpc.v2", "schema": 2,
                   "request_id": identifier, "config": self.context["config"], "method": method, "params": body}
        if method != "secret.key":
            request["idempotency_key"] = os.urandom(16).hex()
        if method not in {"secret.key", "secret.stage"}:
            request["proof"] = {"id": os.urandom(16).hex(), "request_sha256": WIRE.sha(json.dumps(body).encode()),
                                "expires_at": "2099-01-01T00:00:00Z"}
        return {"name": name, "request": request, "response": response}

    def audit(self, entries=None):
        WIRE.audit(self.context, self.root, self.entries if entries is None else entries, PRODUCER.STEPS, PRODUCER.METHODS)

    def rejected(self, action, diagnostic):
        try:
            action()
        except ValueError:
            return
        self.fail(diagnostic)

    def test_all_twenty_one(self):
        self.audit()
        for index in range(len(self.entries)):
            self.rejected(lambda: self.audit(self.entries[:index] + self.entries[index + 1:]),
                          "step completeness guard credited missing service work")
        self.rejected(lambda: self.audit(self.entries + [self.entries[-1]]),
                      "step completeness guard credited duplicate service work")

    def diagnostic(self):
        output = io.StringIO()
        return DIAGNOSTICS.Reporter(output=output, checks=INSTALLED.SERVE.CHECKS), output

    def revision_case(self):
        source, evidence = self.root / "archive", self.root / "revision-evidence"
        source.mkdir()
        evidence.mkdir()
        return INSTALLED.SecretInstall(source, evidence, suite="state")

    def revision_input(self, value):
        original = os.environ.get("LB_SRC_REV")
        if value is None:
            os.environ.pop("LB_SRC_REV", None)
        else:
            os.environ["LB_SRC_REV"] = value

        def restore():
            if original is None:
                os.environ.pop("LB_SRC_REV", None)
            else:
                os.environ["LB_SRC_REV"] = original

        self.addCleanup(restore)

    def test_archive_revision(self):
        case = self.revision_case()
        value = os.urandom(20).hex()
        self.revision_input(value)
        output = io.StringIO()
        with patch.object(INSTALLED.SERVE.Case, "command", side_effect=AssertionError("archive source unexpectedly invoked Git")):
            with redirect_stdout(output), redirect_stderr(output):
                raw = case.command("revision", ["git", "rev-parse", "HEAD"], clean=True)
        self.assertTrue(raw == value.encode() + b"\n", "archive revision ignored the actual runner input")
        case.keep("source-revision.txt", raw)
        self.assertTrue((case.root / "source-revision.txt").read_bytes() == value.encode() + b"\n",
                        "archive revision bytes were not retained exactly")
        metadata = json.loads((case.root / "source-revision.origin.json").read_bytes())
        self.assertTrue(metadata["origin"] == "runner.LB_SRC_REV" and metadata["command_executed"] is False and
                        metadata["sha256"] == WIRE.sha(raw) and metadata["bytes"] == len(raw),
                        "archive metadata claimed an unexecuted Git command")
        self.assertTrue(value not in output.getvalue(), "archive revision input was printed")

    def test_archive_revision_missing(self):
        case = self.revision_case()
        reporter, output = self.diagnostic()
        case.diagnostics, case.current = reporter, "source"
        self.revision_input(None)
        with patch.object(INSTALLED.SERVE.Case, "command", side_effect=AssertionError("missing archive revision attempted Git")):
            self.rejected(lambda: case.command("revision", ["git", "rev-parse", "HEAD"]),
                          "archive source accepted missing revision provenance")
        self.assertFalse((case.root / "source-revision.origin.json").exists(), "missing provenance was published")
        row = json.loads(output.getvalue().splitlines()[0])
        self.assertTrue(row["check"] == "source" and row["reason"] == "revision_requires_git_or_lb_src_rev",
                        "missing archive provenance had no clear source diagnostic")

    def test_archive_revision_format(self):
        for value in (os.urandom(20).hex()[:12], "g" * 40, os.urandom(20).hex() + "\n", " " + os.urandom(20).hex()):
            self.revision_input(value)
            self.rejected(INSTALLED.archive_revision, "archive source accepted an invalid revision")
        self.revision_input(os.urandom(32).hex())
        self.assertTrue(len(INSTALLED.archive_revision()) == 65, "full SHA-256 revision was rejected")

    def test_revision_git_priority(self):
        case = self.revision_case()
        self.revision_input(os.urandom(20).hex())
        # This is an ordinary disposable marker, not an initialized repository;
        # the existing Git executor remains the authority for validating it.
        (case.source / ".git").mkdir()
        failure = ValueError("unit Git metadata command failed")
        with patch.object(INSTALLED.SERVE.Case, "command", side_effect=failure) as actual:
            try:
                case.command("revision", ["git", "rev-parse", "HEAD"])
            except ValueError as observed:
                self.assertIs(observed, failure)
            else:
                self.fail("existing Git metadata was replaced by the archive revision")
        self.assertEqual(actual.call_count, 1)
        self.assertFalse((case.root / "source-revision.origin.json").exists(), "failed Git command published archive provenance")

    def test_revision_launch_environment(self):
        script = Path(__file__).with_name("BOX-SUITE.sh").read_text(encoding="utf-8")
        original = "e2e/v2/cases/secrets/installed.py"
        selected = [line.strip() for line in script.splitlines() if line.lstrip().startswith("sudo env -i ") and
                    original in shlex.split(line)]
        self.assertEqual(len(selected), 1, "installed launch command is missing or ambiguous")
        value = os.urandom(20).hex()
        expected = self.root / "expected-revision.private"
        expected.write_bytes(value.encode())
        expected.chmod(0o600)
        probe = self.root / "environment-probe.py"
        probe.write_text('import os, pathlib, sys\n'
            'expected = pathlib.Path(sys.argv[sys.argv.index("--evidence") + 1]).read_bytes()\n'
            'actual = os.environ.get("LB_SRC_REV", "").encode()\n'
            'raise SystemExit(0 if actual == expected and os.environ.get("UNSELECTED_TOKEN") is None else 93)\n', encoding="utf-8")
        self.assertEqual(selected[0].count(original), 1)
        # Exercise the actual empty-environment shell command with an ordinary
        # child probe. No sudo, package install or installed pass is simulated.
        launch = self.root / "launch.sh"
        launch.write_text(selected[0].removeprefix("sudo ").replace(original, shlex.quote(str(probe)), 1) + "\n", encoding="utf-8")
        completed = subprocess.run(["sh", str(launch)], capture_output=True, check=False, timeout=30,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LB_SRC_REV": value, "UNSELECTED_TOKEN": os.urandom(32).hex(),
                 "secret_source": str(self.root), "secret_evidence": str(expected)})
        self.assertEqual(completed.returncode, 0, "installed launch lost the archive revision input")
        self.assertTrue(value.encode() not in completed.stdout + completed.stderr, "installed launch printed an environment value")

    def identity_case(self):
        root = self.root / "identity-evidence"
        root.mkdir(mode=0o700)
        tool = Path("/proc/self/exe").resolve()
        retained = root / "serve-authenticator.input"
        retained.write_bytes(tool.read_bytes())
        private = self.root / "identity-private"
        private.mkdir(mode=0o700)
        public = {"config": "secret-unit", "principal_id": os.urandom(16).hex()}
        for name, raw in (("key.der", os.urandom(96)), ("counter", b"\0\0\0\0"), ("public.json", json.dumps(public).encode())):
            path = private / name
            path.write_bytes(raw)
            path.chmod(0o600)
        return SimpleNamespace(root=root, config="secret-unit", authenticator=tool,
            auth_info={"program": "laneboss-serve-authenticator", "hardware_stood_in": True, "presence": "simulated"},
            human=SimpleNamespace(private=private, public=public))

    def test_human_material(self):
        case = self.identity_case()
        INSTALLED.human_material(case, private=True)
        retained = case.root / "serve-authenticator.input"
        retained.write_bytes(os.urandom(96))
        self.rejected(lambda: INSTALLED.human_material(case), "human setup accepted another authenticator artifact")

    def test_human_private_absent(self):
        case = self.identity_case()
        INSTALLED.human_material(case, private=True)
        original, calls = case.human.private, []
        case.human.private = self.root / "missing-identity"
        case.human.proof = lambda *args: calls.append("proof")
        authority = INSTALLED.Authority(case)
        try:
            authority.prove("human.session", {}, case.human.public["principal_id"], 0)
        except (ValueError, OSError):
            self.assertFalse(calls, "missing private identity still invoked a human ceremony")
        else:
            self.fail("human proof proceeded without its prepared private identity")
        case.human.private = original
        (original / "key.der").chmod(0o644)
        self.rejected(lambda: INSTALLED.human_material(case, private=True), "human setup accepted unprotected private material")

    def test_human_prepare_order(self):
        case = self.identity_case()
        reporter, _ = self.diagnostic()
        calls = []
        case.human.enroll = lambda: calls.append("enroll")
        case.human.session = lambda: calls.append("session")
        case.prepare_human = lambda: calls.append("prepare")
        case.publish_initial = lambda: calls.append("publish")
        INSTALLED.prepare_identity(case, reporter)
        self.assertEqual(calls, ["prepare", "enroll", "publish", "session"],
                         "installed identity did not follow serve preparation and enrollment order")
        source = (SOURCE / "scripts/v2-serve/run.py").read_text(encoding="utf-8")
        self.assertIn('self.prepare_human()\n        self.human.enroll()\n        self.publish_initial()', source)

    def endpoint_case(self):
        path = self.root / "native-control.sock"
        binding = self.root / "human-binding.json"
        value = {"config": "secret-unit", "class": "human", "socket": str(path), "service_uid": os.geteuid(),
                 "service_gid": os.getegid(), "artifact_sha256": WIRE.sha(os.urandom(64))}
        binding.write_text(json.dumps(value), encoding="utf-8")
        binding.chmod(0o600)
        return SimpleNamespace(config="secret-unit", installed={**value, "binding_file": str(binding)}), path

    def test_human_endpoint_wait(self):
        case, path = self.endpoint_case()
        control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(control.close)
        launch, ready = threading.Event(), threading.Event()
        failures, waits = [], []

        def publish():
            try:
                if not launch.wait(10):
                    raise ValueError("unit socket publication was not requested")
                control.bind(str(path))
                path.chmod(0o660)
                control.listen(1)
            except Exception as error:
                failures.append(error)
            finally:
                ready.set()

        thread = threading.Thread(target=publish)
        thread.start()

        def pause(seconds):
            waits.append(seconds)
            launch.set()
            self.assertTrue(ready.wait(10), "actual socket publisher did not complete")

        try:
            with patch.object(INSTALLED.time, "sleep", side_effect=pause):
                try:
                    observed = INSTALLED.human_endpoint(case)
                except FileNotFoundError:
                    self.fail("human proof reached the socket before actual service publication")
            self.assertTrue(waits and not failures)
            self.assertEqual(observed["socket_inode"], path.lstat().st_ino)
        finally:
            launch.set()
            thread.join(timeout=12)
            self.assertFalse(thread.is_alive(), "actual socket publisher survived the test")

    def test_human_endpoint_absent(self):
        case, _ = self.endpoint_case()
        try:
            INSTALLED.human_endpoint(case, timeout=0)
        except ValueError as error:
            self.assertEqual(str(error), "human service socket publication deadline")
        else:
            self.fail("missing service socket received readiness credit")

    def test_human_endpoint_binding(self):
        case, path = self.endpoint_case()
        control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(control.close)
        control.bind(str(path))
        path.chmod(0o660)
        INSTALLED.human_endpoint(case)
        binding = Path(case.installed["binding_file"])
        value = json.loads(binding.read_bytes())
        value["config"] = "different-unit"
        binding.write_text(json.dumps(value), encoding="utf-8")
        self.rejected(lambda: INSTALLED.human_endpoint(case), "human readiness accepted another configuration binding")

    def test_human_endpoint_mode(self):
        case, path = self.endpoint_case()
        control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(control.close)
        control.bind(str(path))
        path.chmod(0o660)
        INSTALLED.human_endpoint(case)
        path.chmod(0o666)
        self.rejected(lambda: INSTALLED.human_endpoint(case), "human readiness accepted a writable public socket")

    def hidden_case(self):
        case = INSTALLED.SecretInstall.__new__(INSTALLED.SecretInstall)
        case.root, case.config = self.root, "secret-unit"
        units = self.root / "unit-inputs"
        units.mkdir()
        return case, units

    def test_hidden_start_order(self):
        case, units = self.hidden_case()
        commands = []
        prepare, material = INSTALLED.prepare_hidden, INSTALLED.hidden_material

        def command(active, name, argv, **options):
            source = case.root / "hidden-env.private"
            fragments = [units / ("laneboss-" + role + "@" + case.config + ".service.d") / "secrets-baseline.conf"
                         for role in ("helper", "service")]
            self.assertTrue(source.is_file() and all(path.is_file() for path in fragments),
                            "hidden input was not staged before serve's original unit start")
            if name == "hidden-unit-reload":
                self.assertEqual(argv, ["systemctl", "daemon-reload"])
            elif name == "helper-unit-sources":
                self.assertTrue(commands and commands[0] == "hidden-unit-reload",
                                "hidden input was not staged before serve's original unit start")
                self.assertEqual(argv, ["systemctl", "cat", "laneboss-helper@" + case.config + ".service"])
            else:
                self.assertTrue(commands and commands[0] == "hidden-unit-reload",
                                "hidden input was not staged before serve's original unit start")
                self.assertEqual(argv, ["systemctl", "start", "laneboss-" + name[6:] + "@" + case.config + ".service"])
            commands.append(name)
            return b""

        with patch.object(INSTALLED, "prepare_hidden", side_effect=lambda active: prepare(active, units)), \
             patch.object(INSTALLED, "hidden_material", side_effect=lambda active, selected=units: material(active, selected)), \
             patch.object(INSTALLED.SERVE.Case, "command", new=command):
            case._command("helper-unit-sources", ["systemctl", "cat", "laneboss-helper@" + case.config + ".service"])
            for role in ("helper", "service"):
                case._command("start-" + role, ["systemctl", "start", "laneboss-" + role + "@" + case.config + ".service"])
        self.assertEqual(commands, ["hidden-unit-reload", "helper-unit-sources", "start-helper", "start-service"])
        raw = PRODUCER.read(case.root / "hidden-canary.private")
        self.assertTrue(raw not in json.dumps(commands).encode(), "startup command retained a hidden environment value")
        self.assertEqual(json.loads((case.root / "hidden-baseline.setup.json").read_bytes())["canary_sha256"], WIRE.sha(raw))

    def prepared_hidden(self):
        case, units = self.hidden_case()
        with patch.object(INSTALLED.SERVE.Case, "command", return_value=b""):
            INSTALLED.prepare_hidden(case, units)
        return case, units

    def test_hidden_material(self):
        case, units = self.prepared_hidden()
        environment = case.root / "hidden-env.private"
        original = environment.read_bytes()
        environment.write_bytes(b"HIDDEN_TOKEN=" + os.urandom(48).hex().encode() + b"\n")
        self.rejected(lambda: INSTALLED.hidden_material(case, units), "hidden environment accepted another canary")
        environment.write_bytes(original)
        selected = units / ("laneboss-service@" + case.config + ".service.d") / "secrets-baseline.conf"
        selected.write_bytes(b"[Service]\nEnvironmentFile=/missing/input\n")
        self.rejected(lambda: INSTALLED.hidden_material(case, units), "hidden unit accepted another environment file")

    def test_hidden_fixture(self):
        case, _ = self.prepared_hidden()
        private = self.root / "fixture-inputs"
        private.mkdir(mode=0o700)
        context = {"test_root": str(private)}
        source = case.root / "hidden-canary.private"
        targets = {"env_name": "TASK_TOKEN", "file_path": ".secrets/key", "hidden_env_name": "HIDDEN_TOKEN", "reserved_env_name": "PATH"}
        fixture = PRODUCER.prepare(context, None, targets, defer_baseline=True, hidden_source=source)
        actual = PRODUCER.read(private / fixture["canary_files"]["undelegated"])
        self.assertTrue(actual == PRODUCER.read(source), "fixture replaced the actual pre-start hidden source")
        self.assertNotIn(actual, json.dumps(fixture).encode())

    def test_hidden_baseline(self):
        case, units = self.prepared_hidden()
        endpoint, path = self.endpoint_case()
        case.installed = endpoint.installed
        control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(control.close)
        control.bind(str(path))
        path.chmod(0o660)
        execution = INSTALLED.Execution.__new__(INSTALLED.Execution)
        execution.case, execution.diagnostics = case, None
        execution.sequence, execution.root = 0, self.root
        execution.canaries = {"undelegated": PRODUCER.read(case.root / "hidden-canary.private")}
        calls = []
        execution.read = lambda method, body: calls.append(method) or {}
        execution.unit = lambda *args, **options: self.fail("hidden baseline restarted an existing credential listener")
        material = INSTALLED.hidden_material
        with patch.object(INSTALLED, "hidden_material", side_effect=lambda active: material(active, units)):
            execution.hidden_baseline()
            self.assertEqual(calls, ["lane.list", "identity.self"])
            execution.canaries["undelegated"] = os.urandom(48).hex().encode()
            self.rejected(execution.hidden_baseline, "hidden baseline credited a different source from the original unit")
        retained = list(self.root.glob("*-human-endpoint.ready.json"))
        self.assertTrue(retained)
        self.assertEqual(json.loads(retained[0].read_bytes())["socket_inode"], path.lstat().st_ino)

    def test_journal_fields(self):
        reporter, _ = self.diagnostic()
        private = os.urandom(48).hex()
        reporter.protect((private,))
        payload = {"event": "scheduler_unavailable", "error": {"code": "conflict", "message": private, "instead": private},
                   "message": private, "owner": private, private: private}
        row = DIAGNOSTICS.journal_line(json.dumps({"MESSAGE": json.dumps(payload)}), reporter.catalog, redact=reporter.redact)
        expected = {"event", "error", "error.code", "error.message", "error.instead", "message", "owner", "*"}
        self.assertEqual(set(row.get("fields", [])), expected, "journal discarded the actual JSON field names")
        self.assertNotIn(private, json.dumps(row), "journal field names printed a private map key or value")

    def test_journal_enums(self):
        reporter, _ = self.diagnostic()
        private = os.urandom(48).hex()
        values = {"event": "scheduler_unavailable", "reason": "dependency_failure", "code": "conflict",
                  "stage": "helper.before_accounts", "method": "identity.self", "outcome": "prepared", "kind": "lane.started"}
        payload = {"result": values, "message": private, "config": private}
        row = DIAGNOSTICS.journal_line(json.dumps({"MESSAGE": json.dumps(payload)}), reporter.catalog)
        self.assertEqual(row.get("enum_fields"), {"result." + key: value for key, value in values.items()},
                         "journal discarded known enum values in nested JSON fields")
        self.assertNotIn(private, json.dumps(row))

    def test_journal_systemd(self):
        reporter, output = self.diagnostic()
        reporter.attach(self.root, "secret-unit")
        private = os.urandom(48).hex()

        def records(unit):
            return [{"_COMM": "systemd", "_PID": "1", "UNIT": unit, "MESSAGE": message} for message in (
                "Started " + private + ".", unit + ": Main process exited, code=exited, status=1/" + private,
                unit + ": Failed with result 'exit-code'.")]

        def query(argv, **options):
            unit = next(word[7:] for word in argv if word.startswith("--unit="))
            raw = b"".join(json.dumps(row).encode() + b"\n" for row in records(unit))
            return subprocess.CompletedProcess(argv, 0, raw, b"")

        reporter.journals("failure", run=query)
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual([row.get("systemd_state") for row in rows], ["Started", "exit-code", "Failed"] * 3,
                         "journal omitted systemd lifecycle state")
        self.assertTrue(all(row.get("systemd_result") == "exit-code" for row in rows[2::3]))
        self.assertNotIn(private, output.getvalue(), "systemd state printed a unit description or exit detail")
        unit = "fixture-journal.service"
        for changed in ({"_COMM": private}, {"_PID": "7"}, {"UNIT": private}):
            row = DIAGNOSTICS.journal_line(json.dumps({**records(unit)[0], **changed}), reporter.catalog, unit=unit)
            self.assertNotIn("systemd_state", row, "journal credited another sender or unit as systemd state")

    def test_diagnostic_checks(self):
        reporter, output = self.diagnostic()
        with self.assertRaises(ValueError):
            with reporter.scope("install"):
                with reporter.scope("build"):
                    INSTALLED.require(False, "actual service operation failed")
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertTrue(len(rows) == 1 and rows[0]["kind"] == "failure", "failing check was discarded by the diagnostic boundary")
        row = rows[0]
        self.assertEqual(row["check"], "build")
        self.assertEqual(row["context"], ["install"])
        self.assertEqual(row["reason"], "actual_service_operation_failed")
        self.assertTrue(row["trace"] and row["trace"][-1]["source"] == "scripts/v2-serve/case_secrets.py" and
                        row["trace"][-1]["line"] > 0, "diagnostic omitted its actual source location")

    def product_refusal(self):
        return {"code": "forbidden", "message": "upload class requires its trusted emitter", "owner": "lb-v2-service",
                "instead": "Preserve the service state and repair the named prerequisite through its supervisor."}

    def test_typed_call_refusal(self):
        reporter, output = self.diagnostic()
        private = os.urandom(48).hex()
        refused = self.product_refusal()

        def fail():
            raise WIRE.RPCFailure("installed service refused", {"error": {**refused, "operation_id": private, "credential": private}}, 2)

        with self.assertRaises(WIRE.RPCFailure):
            reporter.run("blob.begin", fail)
        row = json.loads(output.getvalue())
        self.assertEqual(row.get("refusal"), refused, "call diagnostic discarded the product's typed refusal fields")
        self.assertEqual(row["check"], "blob.begin")
        self.assertNotIn(private, output.getvalue())

    def test_typed_journal_refusal(self):
        reporter, output = self.diagnostic()
        private = os.urandom(48).hex()
        refused = self.product_refusal()
        for value in ({"event": "credential_owner_refused", **refused, "environment": private},
                      {"event": "credential_owner_refused", "code": refused["code"], "owner": refused["owner"],
                       "instead": refused["instead"], "detail": refused["message"], "credential": private}):
            row = DIAGNOSTICS.journal_line(json.dumps({"MESSAGE": json.dumps(value)}), reporter.catalog, redact=reporter.redact)
            self.assertEqual(row.get("refusal"), refused, "journal discarded the actual typed refusal")
            reporter.emit("journal", row)
        self.assertNotIn(private, output.getvalue())

    def test_typed_secret_redaction(self):
        reporter, output = self.diagnostic()
        raw = os.urandom(48)
        reporter.protect((raw,))
        for encoded in OBSERVER.variants({"unit": raw}):
            private = encoded.decode("latin1")
            value = {**self.product_refusal(), "message": "product refusal: " + private, "instead": private,
                     "operation_id": private, "secret": private}
            row = DIAGNOSTICS.error_metadata(value, reporter.catalog, reporter.redact)
            self.assertTrue(row.get("refusal", {}).get("message") == "product refusal: [redacted]" and
                            row["refusal"].get("instead") == "[redacted]",
                            "typed refusal disclosed registered secret material")
            reporter.emit("failure", row)
        self.assertTrue(all(value.decode("latin1") not in output.getvalue() for value in OBSERVER.variants({"unit": raw})))

    def test_typed_refusal_schema(self):
        reporter, _ = self.diagnostic()
        private = os.urandom(48).hex()
        for code in (private, [], {}):
            row = DIAGNOSTICS.error_metadata({"code": code, "message": private, "owner": private, "instead": private}, reporter.catalog)
            self.assertNotIn("refusal", row, "unknown error shape received typed refusal credit")
            self.assertNotIn(private, json.dumps(row))
        row = DIAGNOSTICS.error_metadata({"code": "forbidden", "message": {"secret": private}, "owner": private,
                                          "instead": [private], "retryable": private}, reporter.catalog)
        self.assertTrue(row.get("refusal") == {"code": "forbidden", "owner": "[redacted]"},
                        "typed refusal forwarded a nonproduct field or invalid text")
        for event in ([], {}):
            row = DIAGNOSTICS.journal_line(json.dumps({"event": event, "code": private, "detail": private}), reporter.catalog)
            self.assertNotIn(private, json.dumps(row))

    def test_typed_case_redaction(self):
        reporter, output = self.diagnostic()
        case, units = self.hidden_case()
        case.diagnostics, case.current, case.last = reporter, "serve", None

        def command(active, name, argv, **options):
            raw = PRODUCER.read(case.root / "hidden-canary.private")
            raise WIRE.RPCFailure("installed service refused", {**self.product_refusal(), "message": "private source: " + raw.decode()}, 2)

        with patch.object(INSTALLED.SERVE.Case, "command", new=command):
            with self.assertRaises(WIRE.RPCFailure):
                INSTALLED.prepare_hidden(case, units)
        row = json.loads(output.getvalue())
        self.assertTrue(row.get("refusal", {}).get("message") == "private source: [redacted]",
                        "case diagnosis failed to register actual private source")

    def test_diagnostic_privacy(self):
        reporter, output = self.diagnostic()
        hidden = OBSERVER.variants({"unit": os.urandom(64)})
        for raw in hidden:
            value = raw.decode("latin1")
            with self.assertRaises(ValueError):
                with reporter.scope(value):
                    raise WIRE.RPCFailure(value, {"code": value, "message": value, "owner": value}, 3)
            for code in (value, [], {"nested": value}):
                row = {"MESSAGE": json.dumps({"stage": value, "code": code, "message": value,
                    "reason": {"nested": value}, "environment": value, "event": value, "method": value,
                    "check": value, "peer": value, "result": value, "detail": value, "kind": value,
                    "outcome": value, value: value}), "_HOSTNAME": value}
                reporter.emit("journal", DIAGNOSTICS.journal_line(json.dumps(row), reporter.catalog))
        self.assertTrue(all(raw.decode("latin1") not in output.getvalue() for raw in hidden),
                        "private value escaped through diagnostic output")
        self.assertTrue(all(row["check"] == "unknown_check" for row in reporter.failures),
                        "untrusted check text was printed as a check name")

    def test_diagnostic_first_failure(self):
        reporter, output = self.diagnostic()
        for check, error in (("baseline", ValueError("actual service operation failed")),
                             ("units.cleanup", KeyError(os.urandom(32).hex()))):
            with self.assertRaises(Exception):
                with reporter.scope(check):
                    raise error
        result = {"assertions": [{"id": "SECRET-INJECT", "reached": True, "verdict": "fail"},
                                  {"id": "CREDENTIAL-BOUND", "reached": True, "verdict": "pass"}]}
        reporter.finish(1, result)
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        summary = rows[-1]
        self.assertEqual(summary["first_failure"]["check"], "baseline", "cleanup replaced the original diagnostic failure")
        self.assertEqual(summary["failed_checks"], 2)
        self.assertEqual([row["verdict"] for row in rows if row["kind"] == "assertion"], ["fail", "pass"])

    def test_diagnostic_claudock_stop(self):
        for driver in ("claudock-cli", "codex"):
            reporter, output = self.diagnostic()
            execution = INSTALLED.Execution.__new__(INSTALLED.Execution)
            execution.diagnostics = reporter
            execution.status = lambda record: {"life_id": "unit-life", "generation": 1}
            execution.upload = lambda kind, raw: {"id": "unit-reason"}
            failure = WIRE.RPCFailure("actual service operation failed", {"code": "unauthenticated",
                "message": "credential ancillary count, writer or framing was refused (recv_deadline)"}, 2)

            def failed_operation(*args, **kwargs):
                raise failure

            execution.operation = failed_operation
            with self.assertRaises(WIRE.RPCFailure) as stopped:
                execution.quiet({"request": {"driver": driver}, "target": {"life_id": "unit-life", "run": 1}}, "baseline-stop")
            self.assertIs(stopped.exception, failure, "diagnostics changed the actual stop refusal")
            row = json.loads(output.getvalue().splitlines()[0])
            self.assertEqual(row["reason"], "credential_frame_recv_deadline")
            self.assertEqual(row["code"], "unauthenticated")
            if driver == "claudock-cli":
                self.assertEqual(row["check"], "lane.claudock.stop", "claudock stop failure lost its explicit regression name")
                self.assertEqual(row["known_regression"], "claudock_stop_under_repair")
            else:
                self.assertNotIn("known_regression", row, "Codex failure was mislabeled as a claudock stop")

    def test_diagnostic_stop_attribution(self):
        reporter, output = self.diagnostic()
        execution = INSTALLED.Execution.__new__(INSTALLED.Execution)
        execution.diagnostics = reporter
        calls = []

        def failed_status(record):
            raise WIRE.RPCFailure("actual service operation failed", {"code": "unavailable", "message": "status unavailable"}, 69)

        execution.status = failed_status
        execution.operation = lambda *args, **kwargs: calls.append("stop")
        with self.assertRaises(WIRE.RPCFailure):
            execution.quiet({"request": {"driver": "claudock-cli"}, "target": {"life_id": "unit-life", "run": 1}}, "baseline-stop")
        row = json.loads(output.getvalue().splitlines()[0])
        self.assertTrue(row["check"] != "lane.claudock.stop" and "known_regression" not in row,
                        "pre-stop status failure was mislabeled as the claudock regression")
        self.assertFalse(calls, "failed status was bypassed to attempt a stop")

    def test_diagnostic_journal_tail(self):
        reporter, output = self.diagnostic()
        reporter.attach(self.root, "secret-unit")
        hidden = os.urandom(48).hex()
        messages = [{"MESSAGE": json.dumps({"stage": hidden, "message": hidden, "canary": hidden})} for _ in range(19)]
        messages.append({"MESSAGE": json.dumps({"code": "unauthenticated", "message":
            "credential ancillary count, writer or framing was refused (recv_deadline)", "private": hidden})})
        raw = b"".join(json.dumps(row).encode() + b"\n" for row in messages)
        calls = []

        def query(argv, **kwargs):
            calls.append(argv)
            self.assertIn("--lines=12", argv)
            self.assertIn("--output=json", argv)
            return subprocess.CompletedProcess(argv, 0, raw, hidden.encode())

        reporter.journals("final", run=query)
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(len(calls), 3)
        self.assertEqual(len(rows), 36)
        self.assertEqual(rows[-1]["reason"], "credential_frame_recv_deadline", "diagnostics omitted the actual last journal lines")
        self.assertTrue(hidden not in output.getvalue(), "journal tail printed private values")
        for role in ("helper", "credential", "service"):
            self.assertTrue((self.root / ("journal-final-" + role + ".jsonl")).read_bytes() == raw,
                            "diagnostic replaced exact retained journal bytes")

    def test_diagnostic_journal_failure(self):
        reporter, output = self.diagnostic()
        reporter.config = "secret-unit"
        hidden = os.urandom(48).hex()

        def query(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 3, json.dumps({"MESSAGE": hidden}).encode(), hidden.encode())

        reporter.journals("final", run=query)
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertTrue(len(rows) == 3 and all(row["code"] == "journal_query_failed" and row["exit"] == 3 for row in rows),
                        "failed journal command was credited as a successful tail")
        self.assertTrue(hidden not in output.getvalue(), "failed journal command printed private values")

    def test_diagnostic_journal_format(self):
        reporter, output = self.diagnostic()
        private = os.urandom(32).hex()
        payloads = [
            {"event": "credential_owner_refused", "method": "helper.ObserveGate", "code": "unauthenticated",
             "detail": "credential peer containment changed", "private": private},
            {"event": "credential_owner_dropped", "reason": "read_frame credential-broker.sock", "code": "unauthenticated",
             "detail": "credential ancillary count, writer or framing was refused (recv deadline)", "private": private},
            {"stage": "credential_publication", "peer": "broker", "check": "publication_permission", "result": "refused", "private": private},
        ]
        rows = [DIAGNOSTICS.journal_line(json.dumps({"MESSAGE": json.dumps(value)}), reporter.catalog) for value in payloads]
        self.assertTrue(rows[0].get("event") == "credential_owner_refused" and rows[1].get("event") == "credential_owner_dropped" and
                        {"check", "peer", "result"} <= set(rows[2].get("fields", [])), "journal dropped source-defined failure tokens")
        self.assertFalse(any(key in rows[2] for key in ("check", "peer", "result")), "journal forwarded values outside the named enum fields")
        self.assertEqual(rows[0].get("method"), "helper.ObserveGate")
        self.assertEqual(rows[1]["reason"], "credential_frame_recv_deadline", "journal lost the actual credential receive deadline reason")
        self.assertEqual(rows[0]["reason"], "credential_peer_containment_changed")
        self.assertEqual(rows[2].get("stage"), "credential_publication")
        for row in rows:
            reporter.emit("journal", row)
        self.assertTrue(private not in output.getvalue(), "native journal metadata leaked a private field")

    def test_diagnostic_journal_phases(self):
        reporter, output = self.diagnostic()
        reporter.attach(self.root, "secret-unit")
        queried = []

        def query(argv, **kwargs):
            queried.append(argv)
            return subprocess.CompletedProcess(argv, 0, b'{"MESSAGE":"redacted unit record"}\n', b"")

        with patch.object(DIAGNOSTICS.subprocess, "run", side_effect=query):
            for name in ("baseline", "units.cleanup"):
                with self.assertRaises(ValueError):
                    reporter.run(name, INSTALLED.require, False, "actual service operation failed")
            reporter.finish(1)
        self.assertEqual(len(queried), 6, "first failure and post-cleanup journals were not both captured")
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        phases = [row["phase"] for row in rows if row["kind"] == "journal"]
        self.assertEqual(phases, ["failure"] * 3 + ["final"] * 3)
        self.assertEqual(rows[-1]["first_failure"]["check"], "baseline")

    def test_diagnostic_cli_failure(self):
        private = os.urandom(32).hex()
        process = subprocess.run([sys.executable, "-I", "-B", str(Path(__file__).with_name("installed.py")),
            "--source", str(self.root / private), "--evidence", str(self.root / "absent-evidence")],
            capture_output=True, check=False, timeout=30, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        self.assertEqual(process.returncode, 1, "preflight error was converted to a successful installed run")
        rows = [json.loads(line) for line in process.stderr.splitlines() if line.startswith(b"{")]
        summaries = [row for row in rows if row.get("kind") == "summary"]
        self.assertTrue(len(summaries) == 1 and summaries[0]["exit"] == 1 and summaries[0]["first_failure"]["check"] == "preflight",
                        "installed CLI ended without its failing check summary")
        self.assertTrue(private.encode() not in process.stdout + process.stderr and b"Traceback" not in process.stderr,
                        "installed preflight printed private exception details")

    def test_diagnostic_command_error(self):
        reporter, output = self.diagnostic()
        private = os.urandom(48).hex()
        payload = {"code": "forbidden", "message": "credential native peer differs from installation", "extra": private}
        (self.root / "command.stderr").write_text(json.dumps(payload), encoding="utf-8")
        last = {"stderr": "command.stderr", "exit_code": 2}
        observed = INSTALLED.command_error(self.root, last)
        with reporter.scope("build"):
            reporter.failure(ValueError(private), response=observed, last=last)
        row = json.loads(output.getvalue().splitlines()[0])
        self.assertEqual(row["code"], "forbidden", "command diagnostic discarded the actual typed service error")
        self.assertEqual(row["exit"], 2)
        self.assertTrue(private not in output.getvalue(), "command diagnostic printed private error fields")

    def test_raw_frame(self):
        row = self.row("key", "secret.key", {}, {"id": os.urandom(16).hex()})
        WIRE.frame(row, self.context, "key", "secret.key", {})
        row["request"]["params"] = {"different": os.urandom(16).hex()}
        self.rejected(lambda: WIRE.frame(row, self.context, "key", "secret.key", {}),
                      "raw frame accepted an intent the service never received")

    def test_wire_bytes(self):
        self.audit()
        path = self.root / self.entries[0]["directory"] / "wire.jsonl"
        path.write_bytes(path.read_bytes() + b"\n")
        self.rejected(self.audit, "rewritten wire bytes passed the retained digest")

    def test_actual_exit(self):
        self.audit()
        path = self.root / self.entries[0]["directory"] / "exit.json"
        path.write_text(json.dumps({"exit": 7}), encoding="utf-8")
        self.rejected(self.audit, "failed installed client was credited as exit zero")

    def test_human_session(self):
        self.audit()
        entry = self.entries[8]
        path = self.root / entry["directory"] / "wire.jsonl"
        rows = [json.loads(line) for line in path.read_bytes().splitlines()]
        path.write_bytes(b"".join(json.dumps(row).encode() + b"\n" for row in rows if row["name"] != "human-session"))
        entry["wire_sha256"] = WIRE.sha(path.read_bytes())
        self.rejected(self.audit, "service work passed without its actual connection session")

    def test_confirmation_catalog(self):
        catalog = (SOURCE / "internal/v2/api/write_catalog.go").read_text(encoding="utf-8")
        for method in ("blob.begin", "blob.chunk", "blob.commit", "secret.stage", "grants.root", "ticket.issue",
                       "lane.stop", "lane.mark", "lane.archive", "lane.clean", "lane.check"):
            rows = re.findall(r'"' + re.escape(method) + r'":\s*\{([^\n]*)\}', catalog)
            self.assertEqual(len(rows), 1, "actual service proof catalog is missing or ambiguous")
            expected = "session: true" not in rows[0]
            self.assertEqual(WIRE.needs_confirmation(method), expected,
                             "client requested an operation proof for a session-only write")

    def prepared(self):
        root = self.root / "prepared"
        root.mkdir()
        self.context["test_root"] = str(root)
        steps = []
        for entry in self.entries:
            path = root / (entry["name"] + ".request.json")
            path.write_bytes((self.root / entry["request"]).read_bytes())
            rows = [json.loads(line) for line in (self.root / entry["directory"] / "wire.jsonl").read_bytes().splitlines()]
            frame = [row["request"] for row in rows if row["name"] == entry["name"]][0]
            step = {"name": entry["name"], "request": path.name}
            if entry["name"] != "key":
                step["idempotency_key"] = frame["idempotency_key"]
            if entry["method"] not in {"secret.key", "secret.stage"}:
                proof = frame.get("proof")
                if entry["method"] == "lane.start":
                    proof = [row["request"]["proof"] for row in rows if row["name"] == "human-session"][0]
                proof_path = root / (entry["name"] + ".proof.json")
                proof_path.write_text(json.dumps(proof), encoding="utf-8")
                step["proof"] = proof_path.name
            steps.append(step)
        return {"steps": steps}

    def test_prepared_intents(self):
        fixture = self.prepared()
        INSTALLED.prepared_intents(self.context, fixture, self.root, self.entries)
        path = Path(self.context["test_root"]) / fixture["steps"][0]["request"]
        original = path.read_bytes()
        path.write_text(json.dumps({"changed": os.urandom(16).hex()}), encoding="utf-8")
        self.rejected(lambda: INSTALLED.prepared_intents(self.context, fixture, self.root, self.entries),
                      "prepared operation credited another request file")
        path.write_bytes(original)
        fixture["steps"][0]["idempotency_key"] = os.urandom(16).hex()
        self.rejected(lambda: INSTALLED.prepared_intents(self.context, fixture, self.root, self.entries),
                      "prepared operation silently replaced its retry key")

    def test_canned_client(self):
        self.audit()
        path = self.root / self.entries[0]["directory"] / "native.json"
        native = json.loads(path.read_bytes())
        native["executable_sha256"] = WIRE.sha(os.urandom(64))
        path.write_text(json.dumps(native), encoding="utf-8")
        self.rejected(self.audit, "canned wire passed without the installed executable pin")

    def test_installed_binding(self):
        self.audit()
        path = self.root / self.entries[0]["directory"] / "argv.json"
        argv = json.loads(path.read_bytes())
        argv[argv.index("--binding") + 1] += ".foreign"
        path.write_text(json.dumps(argv), encoding="utf-8")
        self.rejected(self.audit, "wire from another installed binding was credited")

    def test_actual_outcome(self):
        entry = self.entries[8]
        self.assertEqual(INSTALLED.actual_outcome(self.context, self.root, entry), entry["outcome"])
        invented = copy.deepcopy(entry)
        invented["outcome"] = {"id": os.urandom(16).hex(), "status": "succeeded"}
        self.rejected(lambda: INSTALLED.actual_outcome(self.context, self.root, invented),
                      "producer boolean replaced the actual service outcome")
        path = self.root / entry["directory"] / "wire.jsonl"
        row = [json.loads(line) for line in path.read_bytes().splitlines() if json.loads(line)["name"] == entry["name"]][0]
        row["response"]["result"] = {"id": os.urandom(16).hex(), "status": "pending"}
        path.write_text(json.dumps(row), encoding="utf-8")
        self.rejected(lambda: INSTALLED.actual_outcome(self.context, self.root, entry),
                      "pending operation passed without an actual terminal read")

    def test_async_client(self):
        entry, poll = copy.deepcopy(self.entries[8]), copy.deepcopy(self.entries[9])
        operation_id = os.urandom(16).hex()
        outcome = {"id": operation_id, "status": "succeeded"}
        directory = self.root / entry["directory"]
        rows = [json.loads(line) for line in (directory / "wire.jsonl").read_bytes().splitlines()]
        rows[-1]["response"]["result"] = {"id": operation_id, "status": "pending"}
        (directory / "wire.jsonl").write_bytes(b"".join(json.dumps(row).encode() + b"\n" for row in rows))
        poll.update(name="async-read", method="operation.get")
        body = {"operation_id": operation_id}
        request = self.root / poll["request"]
        request.write_text(json.dumps(body), encoding="utf-8")
        directory = self.root / poll["directory"]
        selected = self.row(poll["name"], poll["method"], body, outcome)
        session = self.row("human-session", "human.session", {}, {"id": os.urandom(16).hex(), "config": self.context["config"]})
        (directory / "wire.jsonl").write_bytes(b"".join(json.dumps(row).encode() + b"\n" for row in (session, selected)))
        (directory / "selected.json").write_text(json.dumps(selected), encoding="utf-8")
        poll.update(request_sha256=WIRE.sha(request.read_bytes()), wire_sha256=WIRE.sha((directory / "wire.jsonl").read_bytes()))
        entry.update(polls=[poll], outcome=outcome)
        self.assertEqual(INSTALLED.actual_outcome(self.context, self.root, entry), outcome)
        path = directory / "native.json"
        native = json.loads(path.read_bytes())
        native["executable_sha256"] = WIRE.sha(os.urandom(64))
        path.write_text(json.dumps(native), encoding="utf-8")
        self.rejected(lambda: INSTALLED.actual_outcome(self.context, self.root, entry),
                      "asynchronous result credited an unmeasured client")

    def test_same_connection(self):
        path = self.root / self.entries[11]["directory"] / "wire.jsonl"
        rows = [json.loads(line) for line in path.read_bytes().splitlines()]
        WIRE.same_connection(self.context, rows)
        self.rejected(lambda: WIRE.same_connection(self.context, rows[-1:]),
                      "GCM control passed without its same-connection stage")
        rows[-1]["request"]["params"]["sealed_upload_id"] = os.urandom(16).hex()
        self.rejected(lambda: WIRE.same_connection(self.context, rows),
                      "GCM control consumed a different connection's stage")

    def test_host_probe(self):
        target = {"life_id": "unit-life", "run": 1}
        executable, task, prompt = [WIRE.sha(os.urandom(64)) for _ in range(3)]
        lease = {"uid": os.geteuid(), "gid": os.getegid()}
        journal = {"lease": lease, "spec": {"handoff": {"spec": {"target": target,
            "runner": {"executable": {"sha256": executable}, "prompt": {"sha256": prompt}}}}}}
        facts = {"Schema": "laneboss.secret-native.v1", "Config": self.context["config"],
                 "LifeID": target["life_id"], "Run": 1, "UID": lease["uid"], "GID": lease["gid"],
                 "MountNS": os.readlink("/proc/self/ns/mnt"), "PIDNS": os.readlink("/proc/self/ns/pid"),
                 "ExecutableSHA": executable, "TaskSHA": task, "PromptSHA": prompt}
        self.rejected(lambda: OBSERVER.planned_child(self.context, target, facts, journal, task),
                      "host probe received confined-runtime credit")
        facts["UID"] = lease["uid"] = os.geteuid() + 10000
        facts["MountNS"], facts["PIDNS"] = "mnt:[unit-isolated]", "pid:[unit-isolated]"
        self.assertEqual(OBSERVER.planned_child(self.context, target, facts, journal, task), lease)
        facts["TaskSHA"] = WIRE.sha(os.urandom(64))
        self.rejected(lambda: OBSERVER.planned_child(self.context, target, facts, journal, task),
                      "planned probe accepted another actual launch task")

    def test_mount_alias(self):
        control = self.root / "outside-object"
        control.write_bytes(os.urandom(64))
        observed = OBSERVER.mount_excludes(os.getpid(), [control])
        self.assertEqual(observed["outside_objects"], 1)
        self.rejected(lambda: OBSERVER.mount_excludes(os.getpid(), [Path("/")]),
                      "native mount alias passed the independent inode scan")

    def test_retained_binding(self):
        target = {"life_id": "unit-retained-life", "run": 2}
        task, executable, prompt = [WIRE.sha(os.urandom(64)) for _ in range(3)]
        lease = {"id": "unit-retained-lease", "uid": os.geteuid() + 10000, "gid": os.getegid() + 10000}
        journal = {"lease": lease, "spec": {"handoff": {"spec": {"target": target,
            "runner": {"executable": {"sha256": executable}, "prompt": {"sha256": prompt}}}}}}
        facts = {"Schema": "laneboss.secret-native.v1", "Config": self.context["config"], "LifeID": target["life_id"],
            "Run": 2, "UID": lease["uid"], "GID": lease["gid"], "MountNS": "mnt:[unit-isolated]", "PIDNS": "pid:[unit-isolated]",
            "ExecutableSHA": executable, "TaskSHA": task, "PromptSHA": prompt, "StartTime": "12345"}
        witness = {"pid": 12345, "start_time": facts["StartTime"]}
        inventory = {"lease_id": lease["id"], "target": target, "uid": lease["uid"], "processes": [witness], "witness": witness,
            "runtime_root": str(Path("/var/lib/laneboss-v2/lanes") / self.context["config"] / lease["id"])}
        OBSERVER.retained_binding(self.context, target, facts, journal, inventory, task)
        wrong = dict(inventory, lease_id="different-retained-lease")
        self.rejected(lambda: OBSERVER.retained_binding(self.context, target, facts, journal, wrong, task),
                      "retained probe credited another native lease")
        wrong = dict(inventory, runtime_root=str(self.root / "invented-runtime"))
        self.rejected(lambda: OBSERVER.retained_binding(self.context, target, facts, journal, wrong, task),
                      "retained probe credited an invented runtime path")

    def test_case_build_inputs(self):
        source, stage, archive = self.root / "source", self.root / "stage", self.root / "source.tar"
        stage.mkdir()
        paths = ["e2e/v2/cases/secrets/agent/main.go", "e2e/v2/cases/secrets/native/main.go",
                 "e2e/v2/cases/secrets/seal/main.go", "scripts/v2-serve/case_secrets.py",
                 "scripts/v2-serve/secret_observer.py"]
        contents = {}
        for path in paths:
            selected = source / path
            selected.parent.mkdir(parents=True, exist_ok=True)
            contents[path] = os.urandom(96)
            selected.write_bytes(contents[path])
        with tarfile.open(archive, "w"):
            pass
        inventory = []
        INSTALLED.stage_case_inputs(source, stage, archive, inventory)
        self.assertEqual({row["path"] for row in inventory}, set(paths),
                         "case executable source was omitted from the actual build inputs")
        with tarfile.open(archive) as retained:
            for row in inventory:
                self.assertTrue((stage / row["path"]).read_bytes() == contents[row["path"]], "staged case source bytes differ")
                self.assertTrue(retained.extractfile(row["path"]).read() == contents[row["path"]], "retained case source bytes differ")
                self.assertEqual(row["sha256"], WIRE.sha(contents[row["path"]]))

    def test_independent_phases(self):
        execution = INSTALLED.Execution.__new__(INSTALLED.Execution)
        calls = []
        execution.baseline = lambda: calls.append("baseline")

        def secret():
            calls.append("secret")
            raise ValueError("unit actual secret boundary failed")

        execution.secret_phase = secret
        execution.credential_phase = lambda: calls.append("credential")
        execution.collect_owned = lambda: calls.append("collection")
        execution.finish = lambda: calls.append("finish")
        execution.retain = lambda name, raw: (self.root / name).write_bytes(raw)
        result = {"assertions": [{"verdict": "fail"}, {"verdict": "fail"}]}
        execution.execute(result)
        self.assertIn("credential", calls, "secret failure prevented the independent credential phase")
        self.assertEqual(calls, ["baseline", "secret", "collection", "credential", "collection", "finish"])
        self.assertEqual(execution.phase_failures, ["SECRET-INJECT"])
        self.assertTrue((self.root / "SECRET-INJECT-execution.failed.json").is_file())

    def test_failed_start_collection(self):
        execution = INSTALLED.Execution.__new__(INSTALLED.Execution)
        execution.fixture, execution.lives, execution.steps, execution.diagnostics = {}, [], [], None
        life = os.urandom(16).hex()
        operation = {"id": os.urandom(16).hex(), "status": "pending", "life_id": life, "run": 1}
        execution.client = SimpleNamespace(call=lambda *args, **options: (dict(operation), {}))

        def failed(active):
            raise WIRE.RPCFailure("unit start polling failed", {"code": "unavailable"})

        execution.completed = failed
        with self.assertRaises(WIRE.RPCFailure):
            execution.operation("early-start", "lane.start", {"task": os.urandom(16).hex()}, primary=False)
        self.assertTrue(len(execution.lives) == 1 and execution.lives[0]["target"] == {"life_id": life, "run": 1},
                        "failed start discarded its reserved life before collection")
        calls = []

        def quiet(record, name):
            calls.append(("stop", dict(record["target"])))
            record["quiescent"] = True

        def archive(record, name):
            self.assertTrue(record.get("quiescent"), "collection archived a live failed start")
            calls.append(("archive", dict(record["target"])))
            record["archive"] = {"id": os.urandom(16).hex()}

        def clean(record, name):
            self.assertTrue(record.get("archive"), "collection cleaned without its public archive")
            calls.append(("clean", dict(record["target"])))
            record["cleaned"] = True

        execution.quiet, execution.archive, execution.clean = quiet, archive, clean
        execution.collect_owned()
        self.assertEqual([name for name, _ in calls], ["stop", "archive", "clean"],
                         "failed start collection skipped a public lifecycle step")
        self.assertTrue(execution.lives[0]["cleaned"])
        execution.collect_owned()
        self.assertEqual(len(calls), 3, "collected failed start was collected twice")

        first = execution.lives[0]
        first["cleaned"], first["quiescent"] = False, False
        second = {"target": {"life_id": os.urandom(16).hex(), "run": 1}, "name": "other-owned-start", "cleaned": False}
        execution.lives.append(second)
        calls.clear()

        def refused_stop(record, name):
            if record is first:
                calls.append(("stop", dict(record["target"])))
                raise ValueError("unit public stop refused")
            quiet(record, name)

        execution.quiet = refused_stop
        with self.assertRaisesRegex(ValueError, "an owned life could not be collected"):
            execution.collect_owned()
        self.assertTrue(not first["cleaned"] and second["cleaned"], "one collection failure discarded another owned life")
        self.assertEqual([name for name, _ in calls], ["stop", "stop", "archive", "clean"])

    def test_log_privacy(self):
        evidence = self.root / "observations"
        evidence.mkdir()
        path = evidence / "client.stderr"
        path.write_bytes(os.urandom(128))
        canary = os.urandom(64)
        hidden = OBSERVER.variants({"unit": canary})
        self.assertEqual(len(INSTALLED.evidence_privacy(evidence, hidden)), 1)
        for value in hidden:
            path.write_bytes(b"actual unit diagnostic: " + value)
            self.rejected(lambda: INSTALLED.evidence_privacy(evidence, hidden),
                          "secret bytes in an actual retained log passed the privacy guard")

    def test_native_archive(self):
        connection = sqlite3.connect(self.root / "state.sqlite")
        self.addCleanup(connection.close)
        connection.execute("CREATE TABLE objects(id TEXT PRIMARY KEY, metadata TEXT, data BLOB)")
        raw = os.urandom(512)
        target, operation_id = {"life_id": "unit-archive-life", "run": 2}, os.urandom(16).hex()
        ref = {"id": os.urandom(16).hex(), "bytes": len(raw), "sha256": WIRE.sha(raw), "class": "artifact"}
        receipt = {"id": os.urandom(16).hex(), "archive_sha256": WIRE.sha(raw), "read_back_sha256": WIRE.sha(raw)}
        job = {"Input": {"receipt_id": receipt["id"], "intent": {"Request": {"target": target}}},
               "Job": {"Intent": {"OperationID": operation_id}}, "Parts": [ref]}
        metadata = {"Ref": ref, "ACL": {"Config": self.context["config"], "LifeID": target["life_id"]},
                    "Origin": "service", "SourceOperationID": operation_id}
        connection.execute("INSERT INTO objects VALUES(?,?,?)", (ref["id"], json.dumps(metadata), raw))
        observed = INSTALLED.archive_parts(connection, job, receipt, self.context["config"], target, operation_id)
        self.assertTrue(observed == raw, "native archive bytes differ")
        changed = bytearray(raw)
        changed[-1] ^= 1
        connection.execute("UPDATE objects SET data=?", (changed,))
        self.rejected(lambda: INSTALLED.archive_parts(connection, job, receipt, self.context["config"], target, operation_id),
                      "native archive accepted rewritten service object bytes")
        connection.execute("UPDATE objects SET data=?", (raw,))
        metadata["SourceOperationID"] = os.urandom(16).hex()
        connection.execute("UPDATE objects SET metadata=?", (json.dumps(metadata),))
        self.rejected(lambda: INSTALLED.archive_parts(connection, job, receipt, self.context["config"], target, operation_id),
                      "native archive credited another operation's retained object")

    def test_native_history(self):
        connection = sqlite3.connect(self.root / "history.sqlite")
        self.addCleanup(connection.close)
        connection.execute("CREATE TABLE objects(id TEXT PRIMARY KEY, metadata TEXT, data BLOB)")
        raw = os.urandom(96)
        target = {"life_id": "history-unit-life", "run": 2}
        ref = {"id": os.urandom(16).hex(), "bytes": len(raw), "sha256": WIRE.sha(raw), "class": "record"}
        metadata = {"Ref": ref, "ACL": {"Config": self.context["config"], "LifeID": target["life_id"],
            "Owner": {"kind": "lane", "life_id": target["life_id"]}, "Audience": "owner"},
            "SourceOperationID": os.urandom(16).hex()}
        connection.execute("INSERT INTO objects VALUES(?,?,?)", (ref["id"], json.dumps(metadata), raw))
        observed, _ = INSTALLED.native_history(connection, ref, self.context["config"], target)
        self.assertTrue(observed == raw, "native private history bytes differ")
        metadata["ACL"]["LifeID"] = "different-history-life"
        connection.execute("UPDATE objects SET metadata=?", (json.dumps(metadata),))
        self.rejected(lambda: INSTALLED.native_history(connection, ref, self.context["config"], target),
                      "other history control credited another lane's private object")


FAULTS = (
    ("start-ownership", "installed.py", 'owned = self.own_start(name, body, result) if method == "lane.start" else None',
     'owned = None', "test_failed_start_collection", "failed start discarded its reserved life before collection"),
    ("typed-case", "installed.py", 'reporter.protect((PRODUCER.read(case.root / "hidden-canary.private"),))', 'None',
     "test_typed_case_redaction", "case diagnosis failed to register actual private source"),
    ("typed-call", "diagnostics.py", 'row["refusal"] = refusal', 'None', "test_typed_call_refusal",
     "call diagnostic discarded the product's typed refusal fields"),
    ("typed-journal", "diagnostics.py", 'row.update(error_metadata(value, catalog, redact))', 'None', "test_typed_journal_refusal",
     "journal discarded the actual typed refusal"),
    ("typed-secret", "diagnostics.py", 'value = value.replace(private, "[redacted]")', 'value = value', "test_typed_secret_redaction",
     "typed refusal disclosed registered secret material"),
    ("typed-shape", "diagnostics.py", 'known = isinstance(code, str) and code in CODES', 'known = True', "test_typed_refusal_schema",
     "unknown error shape received typed refusal credit"),
    ("hidden-order", "installed.py", '            prepare_hidden(self)\n', '            pass\n', "test_hidden_start_order",
     "hidden input was not staged before serve's original unit start"),
    ("hidden-env", "installed.py", 'PRODUCER.read(environment, 65536) == b"HIDDEN_TOKEN=" + raw + b"\\n"',
     'True', "test_hidden_material", "hidden environment accepted another canary"),
    ("hidden-fragment", "installed.py", 'fragment == ("[Service]\\nEnvironmentFile=" + str(environment) + "\\n").encode()',
     'True', "test_hidden_material", "hidden unit accepted another environment file"),
    ("hidden-fixture", "scripts/v2-serve/case_secrets.py", 'canaries["undelegated"] = read(hidden_source, 65536)',
     'canaries["undelegated"] = secrets.token_hex(48).encode()', "test_hidden_fixture", "fixture replaced the actual pre-start hidden source"),
    ("hidden-restart", "installed.py", '    def hidden_baseline(self):\n',
     '    def hidden_baseline(self):\n        self.unit("stop", "credential")\n', "test_hidden_baseline",
     "hidden baseline restarted an existing credential listener"),
    ("hidden-binding", "installed.py", 'prepared["canary_sha256"] == sha(self.canaries["undelegated"])',
     'True', "test_hidden_baseline", "hidden baseline credited a different source from the original unit"),
    ("diag-fields", "diagnostics.py", 'row.update(journal_fields(value, catalog))', 'None', "test_journal_fields",
     "journal discarded the actual JSON field names"),
    ("diag-enums", "diagnostics.py", 'catalog.enum(name, content)', 'False', "test_journal_enums",
     "journal discarded known enum values in nested JSON fields"),
    ("diag-enum-private", "diagnostics.py", 'isinstance(value, str) and value in allowed.get(name, ())', 'isinstance(value, str)',
     "test_diagnostic_privacy", "private value escaped through diagnostic output"),
    ("diag-systemd", "diagnostics.py", 'native = systemd_line(envelope, value, unit)', 'native = {}', "test_journal_systemd",
     "journal omitted systemd lifecycle state"),
    ("diag-systemd-unit", "diagnostics.py", 'if unit is None or envelope.get("_COMM") != "systemd" or envelope.get("_PID") != "1" or envelope.get("UNIT") != unit:',
     'if False:', "test_journal_systemd", "journal credited another sender or unit as systemd state"),
    ("human-artifact", "installed.py", 'SERVE.digest(tool) == SERVE.digest(retained)', 'True', "test_human_material",
     "human setup accepted another authenticator artifact"),
    ("human-private", "installed.py", '        human_material(self.case, private=True)\n', '        pass\n', "test_human_private_absent",
     "human proof proceeded without its prepared private identity"),
    ("human-order", "installed.py", '    diagnostics.run("human.enroll", case.prepare_human)\n', '    pass\n', "test_human_prepare_order",
     "installed identity did not follow serve preparation and enrollment order"),
    ("human-wait", "installed.py", '        except FileNotFoundError:\n            require(time.monotonic() < deadline',
     '        except FileNotFoundError:\n            raise\n            require(time.monotonic() < deadline', "test_human_endpoint_wait",
     "human proof reached the socket before actual service publication"),
    ("human-deadline", "installed.py", 'require(time.monotonic() < deadline, "human service socket publication deadline")',
     'return {}', "test_human_endpoint_absent", "missing service socket received readiness credit"),
    ("human-binding", "installed.py", 'binding.get("config") == case.config', 'True', "test_human_endpoint_binding",
     "human readiness accepted another configuration binding"),
    ("human-mode", "installed.py", 'stat.S_IMODE(info.st_mode) == 0o660', 'True', "test_human_endpoint_mode",
     "human readiness accepted a writable public socket"),
    ("archive-launch", "BOX-SUITE.sh", ' LB_SRC_REV="${LB_SRC_REV-}"', '', "test_revision_launch_environment",
     "installed launch lost the archive revision input"),
    ("archive-source", "installed.py", 'if name == "revision" and not os.path.lexists(self.source / ".git"):', 'if False:',
     "test_archive_revision", "archive source unexpectedly invoked Git"),
    ("archive-missing", "installed.py", ('require(revision, "revision requires Git or LB_SRC_REV")',
     're.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision) is not None'),
     ('require(True, "revision requires Git or LB_SRC_REV")', 'True'),
     "test_archive_revision_missing", "archive source accepted missing revision provenance"),
    ("archive-format", "installed.py", 're.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision) is not None', 'True',
     "test_archive_revision_format", "archive source accepted an invalid revision"),
    ("archive-git", "installed.py", 'if name == "revision" and not os.path.lexists(self.source / ".git"):', 'if name == "revision":',
     "test_revision_git_priority", "existing Git metadata was replaced by the archive revision"),
    ("diag-attribution", "installed.py", '@DIAGNOSTICS.tracked("lane.quiescence", driver=True)',
     '@DIAGNOSTICS.tracked("lane.stop", driver=True)', "test_diagnostic_stop_attribution",
     "pre-stop status failure was mislabeled as the claudock regression"),
    ("diag-format", "diagnostics.py", 'for key, allowed in JOURNAL_TOKENS.items():', 'for key, allowed in ():',
     "test_diagnostic_journal_format", "journal dropped source-defined failure tokens"),
    ("diag-detail", "diagnostics.py", 'detail = catalog.reason(value.get("detail"))', 'detail = "unrecognized_message"',
     "test_diagnostic_journal_format", "journal lost the actual credential receive deadline reason"),
    ("diag-phases", "diagnostics.py", 'if not self.first_journal and self.config is not None:', 'if False:',
     "test_diagnostic_journal_phases", "first failure and post-cleanup journals were not both captured"),
    ("diag-check", "diagnostics.py", '            self.failure(error)\n            raise', '            raise', "test_diagnostic_checks",
     "failing check was discarded by the diagnostic boundary"),
    ("diag-private", "diagnostics.py", 'self.messages.get(value, "unrecognized_message")', 'value', "test_diagnostic_privacy",
     "private value escaped through diagnostic output"),
    ("diag-first", "diagnostics.py", 'self.failures[0] if self.failures else None', 'self.failures[-1] if self.failures else None',
     "test_diagnostic_first_failure", "cleanup replaced the original diagnostic failure"),
    ("diag-stop", "diagnostics.py", 'driver == "claudock-cli" and any(label == "lane.stop"', 'False and any(label == "lane.stop"',
     "test_diagnostic_claudock_stop", "claudock stop failure lost its explicit regression name"),
    ("diag-journal", "diagnostics.py", 'enumerate(lines[-12:])', 'enumerate(lines[:12])', "test_diagnostic_journal_tail",
     "diagnostics omitted the actual last journal lines"),
    ("diag-query", "diagnostics.py", 'code != 0 or not lines', 'not lines', "test_diagnostic_journal_failure",
     "failed journal command was credited as a successful tail"),
    ("diag-cli", "installed.py", '    diagnostics.finish(code, result)\n', '    pass\n', "test_diagnostic_cli_failure",
     "installed CLI ended without its failing check summary"),
    ("diag-command", "diagnostics.py", 'row.update(error_metadata(response or getattr(error, "response", None), self.catalog, self.redact))',
     'None', "test_diagnostic_command_error", "command diagnostic discarded the actual typed service error"),
    ("retained-lease", "scripts/v2-serve/secret_observer.py", 'lease["id"] == inventory["lease_id"]', "True", "test_retained_binding",
     "retained probe credited another native lease"),
    ("retained-root", "scripts/v2-serve/secret_observer.py", 'str(expected) == inventory["runtime_root"]', "True", "test_retained_binding",
     "retained probe credited an invented runtime path"),
    ("confirmation", "wire.py", 'SESSION_WRITES = {"blob.begin", "blob.chunk", "blob.commit", "secret.stage"}',
     'SESSION_WRITES = {"blob.chunk", "blob.commit", "secret.stage"}', "test_confirmation_catalog",
     "client requested an operation proof for a session-only write"),
    ("async-client", "installed.py", 'WIRE.audit(context, evidence, entry["polls"], poll_names, {name: "operation.get" for name in poll_names})',
     "None", "test_async_client", "asynchronous result credited an unmeasured client"),
    ("prepared-input", "installed.py", 'json.loads(body) == json.loads(actual)', "True", "test_prepared_intents",
     "prepared operation credited another request file"),
    ("prepared-key", "installed.py", 'frame.get("idempotency_key") == step["idempotency_key"]', "True", "test_prepared_intents",
     "prepared operation silently replaced its retry key"),
    ("human-session", "wire.py", 'def session_round_trip(context, records):\n',
     'def session_round_trip(context, records):\n    return\n', "test_human_session",
     "service work passed without its actual connection session"),
    ("history-owner", "installed.py", 'target["life_id"] == metadata["ACL"]["LifeID"]', "True", "test_native_history",
     "other history control credited another lane's private object"),
    ("archive-bytes", "installed.py", ('sha(raw) == ref["sha256"]', 'sha(raw) == receipt["archive_sha256"] == receipt["read_back_sha256"]'),
     ("True", "True"), "test_native_archive",
     "native archive accepted rewritten service object bytes"),
    ("archive-owner", "installed.py", 'metadata["SourceOperationID"] == operation_id', "True", "test_native_archive",
     "native archive credited another operation's retained object"),
    ("independent", "installed.py", 'phase("CREDENTIAL-BOUND", self.credential_phase)',
     'phase("CREDENTIAL-BOUND", lambda: None)', "test_independent_phases",
     "secret failure prevented the independent credential phase"),
    ("logs", "installed.py", 'OBSERVER.no_values(raw, hidden)', "True", "test_log_privacy",
     "secret bytes in an actual retained log passed the privacy guard"),
    ("build-input", "installed.py", 'selected = list((source / "e2e/v2/cases/secrets").rglob("*"))',
     'selected = []', "test_case_build_inputs", "case executable source was omitted from the actual build inputs"),
    ("steps", "wire.py", '[entry.get("name") for entry in entries] == list(names)', "True", "test_all_twenty_one",
     "step completeness guard credited missing service work"),
    ("intent", "wire.py", 'request.get("params") == body', "True", "test_raw_frame",
     "raw frame accepted an intent the service never received"),
    ("wire", "wire.py", 'sha(wire) == entry["wire_sha256"]', "True", "test_wire_bytes",
     "rewritten wire bytes passed the retained digest"),
    ("exit", "wire.py", 'type(exit_record.get("exit")) is int and exit_record["exit"] == entry.get("exit") and\n                ((exit_record["exit"] != 0) if "error" in response else exit_record["exit"] == 0)',
     "True", "test_actual_exit", "failed installed client was credited as exit zero"),
    ("client", "wire.py", 'native.get("executable_sha256") == context["binary_sha256"]', "True", "test_canned_client",
     "canned wire passed without the installed executable pin"),
    ("binding", "wire.py", 'argv[argv.index("--binding") + 1] == context["binding_file"]', "True", "test_installed_binding",
     "wire from another installed binding was credited"),
    ("outcome", "installed.py", 'value == entry["outcome"]', "True", "test_actual_outcome",
     "producer boolean replaced the actual service outcome"),
    ("connection", "wire.py", 'def same_connection(context, records):\n',
     'def same_connection(context, records):\n    return\n', "test_same_connection",
     "GCM control passed without its same-connection stage"),
    ("host", "scripts/v2-serve/secret_observer.py", '    lease = journal["lease"]\n    require(facts.get("Schema")',
     '    return journal["lease"]\n    lease = journal["lease"]\n    require(facts.get("Schema")', "test_host_probe",
     "host probe received confined-runtime credit"),
    ("mount", "scripts/v2-serve/secret_observer.py", '(info.st_dev, info.st_ino) not in expected', "True", "test_mount_alias",
     "native mount alias passed the independent inode scan"),
)


def controls(output):
    output.mkdir(mode=0o700)
    report = []
    for name, relative, before, after, test, diagnostic in FAULTS:
        for phase in ("red", "green"):
            tree = output / name / phase
            case = tree / "e2e/v2/cases/secrets"
            case.mkdir(mode=0o700, parents=True)
            for source in Path(__file__).parent.glob("*.py"):
                shutil.copyfile(source, case / source.name)
            shutil.copyfile(Path(__file__).with_name("BOX-SUITE.sh"), case / "BOX-SUITE.sh")
            for subdir in ("scripts/v2-serve", "scripts/v2-admin"):
                destination = tree / subdir
                destination.mkdir(parents=True)
                for source in (SOURCE / subdir).glob("*.py"):
                    shutil.copyfile(source, destination / source.name)
            shutil.copyfile(SOURCE / "e2e/v2/human_authority.py", tree / "e2e/v2/human_authority.py")
            catalog = tree / "internal/v2/api/write_catalog.go"
            catalog.parent.mkdir(parents=True)
            shutil.copyfile(SOURCE / "internal/v2/api/write_catalog.go", catalog)
            for go_relative in DIAGNOSTICS.GO:
                selected = tree / go_relative
                selected.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(SOURCE / go_relative, selected)
            target = tree / relative if relative.startswith("scripts/") else case / relative
            original = target.read_text(encoding="utf-8")
            edits = list(zip(before, after, strict=True)) if isinstance(before, tuple) else [(before, after)]
            changed = original
            for anchor, replacement in edits:
                if changed.count(anchor) != 1:
                    raise ValueError("installed control fault anchor changed")
                if phase == "red":
                    changed = changed.replace(anchor, replacement, 1)
            if phase == "red":
                target.write_text(changed, encoding="utf-8")
            command = [sys.executable, "-I", "-B", str(case / "checks_install.py"), "--test", test]
            completed = subprocess.run(command, capture_output=True, timeout=60, check=False,
                                       env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
            stem = output / (name + "-" + phase)
            stem.with_suffix(".out").write_bytes(completed.stdout)
            stem.with_suffix(".err").write_bytes(completed.stderr)
            raw = completed.stdout + completed.stderr
            row = {"id": name, "phase": phase, "exit": completed.returncode,
                   "input_sha256": WIRE.sha(target.read_bytes()), "stdout_sha256": WIRE.sha(completed.stdout),
                   "stderr_sha256": WIRE.sha(completed.stderr), "failure_boundary": diagnostic}
            report.append(row)
            print(json.dumps(row), flush=True)
            if phase == "red":
                if completed.returncode != 1 or diagnostic.encode() not in raw or test.encode() not in raw:
                    raise ValueError("installed control did not reach its intended RED")
            elif completed.returncode != 0 or b"OK" not in raw or test.encode() not in raw:
                raise ValueError("installed candidate did not reach GREEN")
    (output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", default="all")
    parser.add_argument("--controls", type=Path)
    args = parser.parse_args()
    if sys.platform != "linux":
        raise ValueError("installed controls require the disposable Linux test box")
    if args.controls is not None:
        controls(args.controls)
        return 0
    suite = (unittest.defaultTestLoader.loadTestsFromTestCase(InstalledChecks) if args.test == "all" else
             unittest.defaultTestLoader.loadTestsFromName(args.test, InstalledChecks))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() and not result.skipped else 1


if __name__ == "__main__":
    raise SystemExit(main())
