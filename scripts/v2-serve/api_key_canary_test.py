"""Scanner controls, including isolated file/IO doubles with synthetic keys.

The real-key controls are pure Python: only private temporary files change.
Owner and special-bit metadata are simulated, requiring no root or credential.
They establish no installed-service or authenticated-provider result.
"""

from contextlib import contextmanager, redirect_stderr, redirect_stdout
import base64
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("api_key_canary", Path(__file__).with_name("api_key_canary.py"))
canary_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canary_module)


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


serve = module("real_key_serve_controls", "run.py")
linux = module("real_key_linux_controls", "case_linux.py")


@contextmanager
def source_owner(uid=0, permission=None):
    """Double UID/optional mode; open/no-follow/read/unlink remain real.

    Ordinary permission cases use chmod. Special bits are injected explicitly
    because some disposable filesystems remove them when chmod succeeds.
    """
    fstat, stat_path = os.fstat, os.stat

    def owned(info):
        names = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size",
                 "st_mtime_ns", "st_ctime_ns")
        values = {name: uid if name == "st_uid" else getattr(info, name) for name in names}
        if permission is not None:
            values["st_mode"] = stat.S_IFMT(info.st_mode) | permission
        return SimpleNamespace(**values)

    with mock.patch.object(os, "fstat", side_effect=lambda fd: owned(fstat(fd))), \
            mock.patch.object(os, "stat", side_effect=lambda *a, **kw: owned(stat_path(*a, **kw))):
        yield


class RealKeyFiles(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="lb-v2-realkey-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.material = b"sk-ant-" + os.urandom(32).hex().encode("ascii")

    def source(self, name="key", mode=0o400, raw=None):
        path = self.root / name
        path.write_bytes(self.material if raw is None else raw)
        path.chmod(mode)
        return path

    def consume(self, path, uid=0, permission=None):
        with source_owner(uid, permission):
            return canary_module.Canary.from_file(path)

    def assert_private_error(self, path, uid=0, permission=None):
        with self.assertRaises(ValueError) as raised:
            self.consume(path, uid, permission)
        self.assertTrue("real API key file" in str(raised.exception), "source refusal lost its fixed diagnostic")
        self.assertFalse(self.material.decode() in str(raised.exception), "source refusal exposed key material")
        self.assertFalse(self.material[-8:].decode() in str(raised.exception), "source refusal exposed a key suffix")

    def assert_clean(self, root, canary):
        for path in root.rglob("*"):
            if path.is_file():
                self.assertFalse(any(canary.matches(path.read_bytes()).values()),
                                 "retained bytes contain synthetic key material")

    def test_missing_file_refused_before_read(self):
        with mock.patch.object(os, "read", wraps=os.read) as read:
            self.assert_private_error(self.root / "absent")
        read.assert_not_called()

    def test_symlink_refused_before_read(self):
        target = self.source()
        link = self.root / "link"
        link.symlink_to(target)
        with mock.patch.object(os, "read", wraps=os.read) as read:
            self.assert_private_error(link)
        read.assert_not_called()
        self.assertTrue(target.exists() and link.is_symlink())

    def test_symlink_ancestor_refused(self):
        directory = self.root / "directory"
        directory.mkdir()
        path = self.source("directory/key")
        link = self.root / "ancestor"
        link.symlink_to(directory, target_is_directory=True)
        with mock.patch.object(os, "read", wraps=os.read) as read:
            self.assert_private_error(link / "key")
        read.assert_not_called()
        self.assertTrue(path.exists())

    def test_wrong_owner_refused_before_read(self):
        path = self.source()
        with mock.patch.object(os, "read", wraps=os.read) as read:
            self.assert_private_error(path, uid=12345)
        read.assert_not_called()
        self.assertTrue(path.exists())

    def test_wrong_mode_refused_before_read(self):
        for mode in (0o600, 0o440, 0o444, 0o700):
            with self.subTest(mode=oct(mode)):
                path = self.source("mode-" + oct(mode), mode)
                with mock.patch.object(os, "read", wraps=os.read) as read:
                    self.assert_private_error(path)
                read.assert_not_called()
                self.assertTrue(path.exists())
        with self.subTest(mode="special bits in root metadata"):
            path = self.source("special-mode")
            with mock.patch.object(os, "read", wraps=os.read) as read:
                self.assert_private_error(path, permission=0o4400)
            read.assert_not_called()
            self.assertTrue(path.exists())

    def test_nonregular_and_hardlink_refused(self):
        directory = self.root / "not-a-file"
        directory.mkdir(mode=0o400)
        self.addCleanup(directory.chmod, 0o700)
        target = self.source()
        link = self.root / "hardlink"
        os.link(target, link)
        with mock.patch.object(os, "read", wraps=os.read) as read:
            self.assert_private_error(directory)
            self.assert_private_error(link)
        read.assert_not_called()
        self.assertTrue(target.exists())

    def test_consumed_once_and_removed(self):
        path = self.source(raw=self.material + b"\n")
        with mock.patch.object(os, "read", wraps=os.read) as read, \
                mock.patch.object(os, "urandom", side_effect=AssertionError("real mode generated a fake key")):
            canary = self.consume(path)
        self.assertEqual(read.call_count, 1)
        self.assertTrue(canary.real)
        self.assertTrue(canary.key == self.material)
        self.assertFalse(path.exists())
        self.assert_private_error(path)
        self.assertTrue(canary.needles == (canary.key, canary.key[-8:]), "source scan selectors changed")

    def test_invalid_material_removed(self):
        for index, raw in enumerate((b"", b"sk-ant-", b"not-an-api-key", self.material + b"\nextra",
                                     self.material + b"\xff", b"x" * 65537)):
            with self.subTest(input=index):
                path = self.source(str(index), raw=raw)
                self.assert_private_error(path)
                if 7 < len(raw) <= 65536:
                    self.assertFalse(path.exists(), "read invalid material was not removed")

    def test_changed_file_unlink_error(self):
        path = self.source()
        original = os.read

        def changed(fd, size):
            raw = original(fd, size)
            path.chmod(0o600)
            return raw

        with mock.patch.object(os, "read", side_effect=changed):
            self.assert_private_error(path)
        path.chmod(0o400)
        with mock.patch.object(os, "unlink", side_effect=OSError("synthetic unlink failure")):
            self.assert_private_error(path)
        self.assertTrue(path.exists())

    def case(self):
        evidence = self.root / "evidence"
        evidence.mkdir()
        path = self.source()
        with source_owner():
            case = serve.Case(self.root, evidence, config="unit-real-key",
                              real_claudock=True, egress_anthropic=True,
                              real_api_key_file=path)
        self.assertFalse(path.exists())
        self.assertTrue(case.real_api_key and case.api_key_canary.real)
        return case

    def test_evidence_journal_value_free(self):
        case = self.case()
        canary = case.api_key_canary
        case.keep("vendor.stdout", canary.key)
        case.keep_json("vendor.json", {"detail": canary.key[-8:].decode()})
        for needle in canary.needles:
            with self.subTest(whole=needle == canary.key):
                process = mock.Mock(returncode=0)
                process.communicate.return_value = (b"journal: " + needle + b"\n", b"stderr: " + needle)
                with mock.patch.object(serve.subprocess, "Popen", return_value=process):
                    with self.assertRaisesRegex(serve.Failed, "retained unit journal differs"):
                        case.capture_journal("canary-journal.service")
        self.assertTrue(canary.withheld)
        self.assert_clean(case.evidence, canary)

    def test_real_finish_scopes_sqlite(self):
        case = self.case()
        canary = case.api_key_canary
        installed = self.root / "installed"
        helper = self.root / "helper"
        installed.mkdir()
        helper.mkdir()
        case.installed = {"state_directory": str(installed)}
        database = installed / "state.sqlite"
        with sqlite3.connect(database) as connection:
            connection.execute("create table observations(value blob)")
            connection.execute("insert into observations values (?)", (canary.key,))
        original = canary.scan

        def scoped(place, path, required=True):
            return original(place, helper if place == "helper-state" else path, required)

        process = mock.Mock(returncode=0)
        process.communicate.return_value = (b"unit started\n", b"")
        with mock.patch.object(canary, "scan", side_effect=scoped) as scan, \
                mock.patch.object(serve.subprocess, "Popen", return_value=process):
            result = canary.finish(case)
        places = {row["place"] for row in result["places"]}
        self.assertTrue({"helper-state", "service-evidence", "evidence", "evidence-after-journals",
                         "service-journal", "helper-journal", "credential-journal"} <= places)
        scan.assert_any_call("service-evidence", installed)
        hit = next(row for row in result["places"] if row["place"] == "service-evidence")
        self.assertTrue(hit["key"] and hit["last8"] and not hit["unreadable"])
        self.assertEqual(process.communicate.call_count, 3)
        self.assert_clean(case.evidence, canary)

    def test_report_item_result_is_value_free(self):
        case = self.case()
        canary = case.api_key_canary
        case.item_result = {"detail": canary.key.decode(), "tail": canary.key[-8:].decode()}
        with redirect_stderr(io.StringIO()):
            self.assertFalse(case.report(None), "unrun checks must not become a passing report")
        report = json.loads((case.evidence / "report.json").read_bytes())
        self.assertTrue("withheld" in report["item_result"]["detail"], "item result escaped report redaction")
        self.assert_clean(case.evidence, canary)


class RealKeyOptions(unittest.TestCase):
    def args(self, *extra):
        return serve.arguments(["--source", "/unit/source", "--evidence", "/unit/evidence", *extra])

    def test_real_flags_linux_item(self):
        source = ("--real-api-key-file", "/unit/key")
        for flags in ((), ("--real-claudock",), ("--egress-anthropic",)):
            with self.subTest(flags=flags):
                with self.assertRaises(serve.Failed):
                    self.args(*source, *flags)
        flags = ("--real-claudock", "--egress-anthropic")
        parsed = self.args(*source, *flags, "--item-case", "linux")
        self.assertEqual(parsed.real_api_key_file, Path("/unit/key"))
        for extra in (("--item-case", "grants"), ("--suite", "state"),
                      ("--boot", "/unit/boot", "--config", "unit"),
                      ("--item-case", "linux", "--cleanup-native-control")):
            with self.subTest(extra=extra):
                with self.assertRaises(serve.Failed):
                    self.args(*source, *flags, *extra)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            self.args(*source, *flags, "--canary-api-key")
        self.assertEqual(raised.exception.code, 2)

    def test_no_key_fake_options(self):
        ordinary = self.args("--item-case", "linux")
        self.assertIsNone(ordinary.real_api_key_file)
        self.assertFalse(ordinary.canary_api_key)
        fake = self.args("--canary-api-key", "--real-claudock", "--egress-anthropic")
        self.assertTrue(fake.canary_api_key)
        self.assertIsNone(fake.real_api_key_file)
        self.assertFalse(canary_module.Canary().real)
        with self.assertRaises(serve.Failed):
            self.args("--item-case", "linux", "--real-claudock", "--egress-anthropic")


class RealKeyPlan(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="lb-v2-realkey-plan-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.now = datetime.now(timezone.utc)

    def case(self):
        case = SimpleNamespace(root=self.root, config="unit-live-linux", item_case="linux",
            current="item.linux.prepare", real_api_key=True, real_claudock=True,
            api_key_canary=canary_module.Canary(b"sk-ant-" + os.urandom(32).hex().encode()),
            agent={"vendor_stood_in": True}, linux_plan_file=None)
        case.binary = self.root / "laneboss"
        case.binary.write_bytes(os.urandom(32))
        artifact_sha = linux.sha(case.binary.read_bytes())
        case.real_vendor = {name: {"executable": {"id": name,
            "sha256": linux.sha(os.urandom(32)), "version": version}}
            for name, version in (("claudock", "0.1.0"), ("claude", "2.1.296"))}
        runtime = {"schema": "laneboss.runtime.v2", "artifact": {"sha256": artifact_sha},
                   "objects": [{"id": name, "role": name, "mode": 0o555,
                                "content": {"sha256": case.real_vendor[name]["executable"]["sha256"]}}
                               for name in case.real_vendor]}
        raw = linux.encoded(runtime)
        reference = {"id": "unit-runtime", "sha256": linux.sha(raw), "bytes": len(raw), "class": "manifest"}
        runtime_path = case.binary.parent / "runtime" / case.config / "manifest.json"
        runtime_path.parent.mkdir(parents=True)
        runtime_path.write_bytes(raw)
        launch = {"config": case.config, "runtimes": [{"driver": "claudock-cli", "manifest": reference,
            "executable": case.real_vendor["claudock"]["executable"],
            "session_executable": case.real_vendor["claude"]["executable"]}]}
        launch_raw = linux.encoded(launch)
        (case.root / "launch-enrollment.json.input").write_bytes(launch_raw)
        launch_ref = {"id": "unit-launch", "sha256": linux.sha(launch_raw), "bytes": len(launch_raw), "class": "manifest"}
        case.installed = {"runtime_manifest": reference, "launch_enrollment": launch_ref,
                          "artifact_sha256": artifact_sha, "binding_file": str(self.root / "binding")}
        case.initial = {"runtime": reference, "launch_enrollment": launch_ref}
        profile = "profile-" + os.urandom(12).hex()
        grants = {"id": "unit-root", "profiles": [{"id": profile, "driver": "claudock-cli"}],
                  "expires_at": (self.now + timedelta(hours=3)).isoformat()}
        case.rows = {case.current: {"observed": {}}, "human.claudock.grants": {
            "result": "pass", "observed": dict(copy.deepcopy(grants), executed=True)}}
        case.human = SimpleNamespace(read=mock.Mock(return_value=copy.deepcopy(grants)), session=mock.Mock())
        start = {"driver": "claudock-cli", "profile_grant_id": profile,
                 "model": "claude-sonnet-4-6", "effort": "low", "root_ticket_id": "old-ticket",
                 "task": {"id": "unit-short-reply"}, "budget": {"wall_ms": 60000,
                 "spend_micros": 100000, "currency": "USD"}}
        case.lane_records = [{"driver": "claudock-cli", "request": start, "quiescent": True}]

        def keep_json(name, value):
            path = self.root / name
            linux.put(path, linux.encoded(value))
            return path

        case.keep_json = keep_json
        return case

    def generated(self, case, plan=None):
        plan = linux.authorize_real_key(case, plan or {}, self.now)
        start = json.loads(Path(plan["start_template"]).read_bytes())
        raw = Path(plan["authorization"]).read_bytes()
        context = {"config": case.config, "profile_grant_ids": plan["profile_grant_ids"]}
        auth = linux.live_authorization(raw, context, start, plan["cell"], self.now)
        return plan, start, context, auth

    def test_plan_auth_installed_context(self):
        case = self.case()
        original = copy.deepcopy(case.lane_records[0]["request"])
        plan, start, context, auth = self.generated(case, {"cell": "selected-cell", "native_fixture": "/unit/native"})
        self.assertEqual(plan["native_fixture"], "/unit/native")
        self.assertEqual(json.loads(case.linux_plan_file.read_bytes()), plan)
        self.assertEqual(auth["runtime_sha256"], case.installed["runtime_manifest"]["sha256"])
        self.assertTrue(auth["allow_model_request"])
        self.assertEqual((auth["config"], auth["cell"]), (case.config, "selected-cell"))
        for name in ("driver", "profile_grant_id", "model", "effort", "budget"):
            self.assertEqual(auth[name], original[name])
            self.assertEqual(start[name], original[name])
        self.assertEqual(context["profile_grant_ids"], [original["profile_grant_id"]])
        self.assertNotIn("root_ticket_id", start)
        self.assertEqual(case.lane_records[0]["request"], original)
        expiry = datetime.fromisoformat(auth["expires_at"].replace("Z", "+00:00"))
        self.assertTrue(self.now < expiry <= self.now + timedelta(hours=2))
        case.human.read.assert_called_once_with("linux-root-grants", ["grants", "get"], {"grant_set_id": "unit-root"})
        self.assertTrue(case.agent["vendor_stood_in"], "stand-in metadata was relabeled")
        for path in self.root.glob("linux-live-*.json"):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertFalse(any(case.api_key_canary.matches(path.read_bytes()).values()))

    def test_expiry_grant_two_hours(self):
        case = self.case()
        expiry = self.now + timedelta(minutes=2)
        case.rows["human.claudock.grants"]["observed"]["expires_at"] = expiry.isoformat()
        case.human.read.return_value["expires_at"] = expiry.isoformat()
        _, _, _, auth = self.generated(case)
        self.assertEqual(datetime.fromisoformat(auth["expires_at"].replace("Z", "+00:00")), expiry)

    def test_tampered_authorization_refused(self):
        case = self.case()
        plan, start, context, auth = self.generated(case)
        changes = {"config": "foreign", "cell": "foreign", "driver": "codex",
                   "profile_grant_id": "foreign", "model": "other-model", "effort": "high",
                   "budget": {"wall_ms": 60001}, "runtime_sha256": "invalid",
                   "allow_model_request": False,
                   "expires_at": (self.now - timedelta(seconds=1)).isoformat()}
        for name, value in changes.items():
            with self.subTest(field=name), self.assertRaises(ValueError):
                linux.live_authorization(linux.encoded(dict(auth, **{name: value})),
                                         context, start, plan["cell"], self.now)

    def test_no_key_preserves_owner_wait(self):
        case = self.case()
        case.real_api_key = False
        case.api_key_canary = None
        with self.assertRaisesRegex(serve.Blocked, "real_driver_authorization"):
            linux.prepare(case, serve.require, serve.Failed, serve.Blocked)
        wait = json.loads((self.root / "linux-owner-wait.input.json").read_bytes())
        self.assertEqual((wait["owner"], wait["gate"]), ("laneboss", "real_driver_authorization"))
        self.assertFalse(wait["completed"])
        self.assertIsNone(case.linux_plan_file)
        case.human.read.assert_not_called()
        case.human.session.assert_not_called()

    def test_fake_key_cannot_mint_authority(self):
        case = self.case()
        case.api_key_canary = canary_module.Canary()
        with self.assertRaisesRegex(ValueError, "consumed real key"):
            linux.authorize_real_key(case, {}, self.now)
        self.assertFalse(list(self.root.glob("linux-live-*.json")))
        case.human.read.assert_not_called()

    def test_runtime_pin_before_grants(self):
        case = self.case()
        path = case.binary.parent / "runtime" / case.config / "manifest.json"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "runtime bytes differ"):
            linux.authorize_real_key(case, {}, self.now)
        case.human.read.assert_not_called()
        self.assertFalse(list(self.root.glob("linux-live-*.json")))

    def test_launch_pin_before_grants(self):
        case = self.case()
        path = case.root / "launch-enrollment.json.input"
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "launch enrollment differs"):
            linux.authorize_real_key(case, {}, self.now)
        case.human.read.assert_not_called()

    def test_profile_readback_change_refused(self):
        case = self.case()
        case.human.read.return_value["profiles"][0]["id"] = "different-issued-profile"
        with self.assertRaisesRegex(ValueError, "profile differs"):
            linux.authorize_real_key(case, {}, self.now)
        self.assertFalse(list(self.root.glob("linux-live-*.json")))

    def test_tiny_budget_enforced(self):
        case = self.case()
        case.lane_records[0]["request"]["budget"]["spend_micros"] = 100001
        with self.assertRaisesRegex(ValueError, "tiny smoke budget"):
            linux.authorize_real_key(case, {}, self.now)
        case.human.read.assert_not_called()

    def test_prepare_real_runtime_plan(self):
        case = self.case()
        prepared = linux.prepare(case, serve.require, serve.Failed, serve.Blocked)
        self.assertTrue(case.linux_plan_file.is_file())
        self.assertEqual(prepared["profile_grant_ids"], case.linux_session.plan["profile_grant_ids"])
        self.assertTrue(callable(prepared["populate"]))
        case.human.session.assert_called_once_with()


class RealKeyBoundaries(unittest.TestCase):
    def test_real_tiny_task_budget(self):
        class Captured(Exception):
            """Stop at the assembler boundary; never run a native program."""

        with tempfile.TemporaryDirectory(prefix="lb-v2-realkey-publication-") as temporary:
            root = Path(temporary).resolve()
            objects, inputs, output = (root / name for name in ("objects", "inputs", "output"))
            for directory in (objects, inputs, output):
                directory.mkdir()
            runtime = root / "runtime.json"
            runtime.write_bytes(serve.encoded({"objects": []}))
            (objects / "serve-agent.json").write_bytes(serve.encoded({"config": "unit-publication"}))
            task = b"Declared stand-in runtime task; no service request.\n"
            (objects / "serve-task.json").write_bytes(task)
            broad = {"wall_ms": 600000, "spend_micros": 5000000, "currency": "USD"}
            captured = []

            def administrator_input(directory, name, raw):
                path = directory / (str(len(captured)) + name)
                path.write_bytes(raw)
                return path

            def command(_label, argv, **_options):
                captured.append(json.loads(Path(argv[-1]).read_bytes()))
                raise Captured()

            for real in (False, True):
                vendor = {name: {"executable": {"id": name}} for name in ("claudock", "claude")} if real else None
                with mock.patch.object(serve.provision, "read_protected", side_effect=lambda path, **kw: Path(path).read_bytes()), \
                        mock.patch.object(serve.provision, "administrator_input", side_effect=administrator_input), \
                        self.assertRaises(Captured):
                    serve.provision.fixture_initial(inputs, objects,
                        {"runtime_file": str(runtime), "runtime_manifest": {}, "judge": {}},
                        output, {"version": "fixture"}, Path(__file__).resolve().parents[2],
                        root / "never-executed", command, egress_anthropic=real, real_vendor=vendor,
                        item_inputs={"bundle": {"budget": broad}}, real_api_key=real)
            stand_in, real = captured
            self.assertEqual(base64.b64decode(stand_in["task"]), task)
            self.assertEqual(stand_in["budget"], broad)
            self.assertIn(b"one short reply", base64.b64decode(real["task"]))
            self.assertIn(b"Do not use tools", base64.b64decode(real["task"]))
            self.assertTrue(0 < real["budget"]["spend_micros"] <= 100000)
            self.assertTrue(0 < real["budget"]["wall_ms"] <= 60000)
            self.assertEqual(real["budget"]["currency"], "USD")
            self.assertEqual((objects / "serve-task.json").read_bytes(), task)

    def test_home_scan_before_clean_rpc(self):
        path = Path(__file__).resolve().parents[2] / "e2e/v2/cases/linux/g0.py"
        spec = importlib.util.spec_from_file_location("real_key_g0_controls", path)
        g0 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(g0)
        with tempfile.TemporaryDirectory(prefix="lb-v2-realkey-g0-") as temporary:
            root = Path(temporary).resolve()
            (root / "stdout").write_bytes(serve.encoded({"id": "unit-clean", "status": "succeeded"}))
            (root / "stderr").write_bytes(b"")
            target = {"life_id": "unit-life", "run": 1}
            canary = SimpleNamespace(scan_lane=mock.Mock(side_effect=ValueError("synthetic exposure")))
            case = SimpleNamespace(root=root, current="item.linux.run", api_key_canary=canary,
                                   last={"stdout": "stdout", "stderr": "stderr", "exit_code": 0},
                                   checked_cli=mock.Mock())
            session = g0.Session(case, {}, serve.require, serve.Failed, None, None)
            session.producer = SimpleNamespace(root=root, before_call=mock.Mock(), after_call=mock.Mock())
            session.target, session.record = target, {"target": target, "quiescent": True}
            with self.assertRaisesRegex(ValueError, "synthetic exposure"):
                session.invoke("lane clean", {"target": target}, "unit-request", "unit-key")
            canary.scan_lane.assert_called_once_with(case, session.record)
            case.checked_cli.assert_not_called()
            self.assertIsInstance(session.stopped, ValueError)


class CanaryControls(unittest.TestCase):
    def setUp(self):
        self.canary = canary_module.Canary()

    def test_fake_vendor_key_shape(self):
        self.assertTrue(re.fullmatch(rb"sk-ant-api03-[A-Za-z0-9_-]+", self.canary.key) is not None,
                        "fake flag source differs from the vendor API key shape")

    def test_shape_failure_is_private(self):
        with tempfile.TemporaryDirectory(prefix="lb-key-failure-") as directory:
            result = Path(directory) / "result.txt"
            child = subprocess.run(["python3", "-I", "-B", str(Path(__file__).with_name("key_fail.py")),
                                    str(result)], input=self.canary.key, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=20)
            self.assertEqual(child.returncode, 1, "control did not fail its assertion")
            retained = result.read_bytes()
            self.assertTrue(b"FAIL: test_fake_vendor_key_shape" in retained and
                            b"Ran 1 test" in retained and b"AssertionError" in retained,
                            "control did not reach the actual key-shape assertion")
            for surface in (child.stdout, child.stderr, retained):
                self.assertFalse(self.canary.key in surface or self.canary.key[-16:] in surface,
                                 "failing key assertion exposed private input")

    def test_harvest_rejects_key(self):
        with tempfile.TemporaryDirectory(prefix="lb-key-harvest-") as directory:
            for kind in ("clean", "dirty", "store-file"):
                with self.subTest(kind=kind):
                    evidence = Path(directory) / kind
                    evidence.mkdir(mode=0o700)
                    case = serve.Case(Path(directory), evidence, config="key-harvest",
                                      real_claudock=True, egress_anthropic=True, canary_api_key=True)
                    canary = case.api_key_canary
                    artifact = case.root / ("key-store.json" if kind == "store-file" else "harvest.capture")
                    artifact.write_bytes(canary.key if kind == "dirty" else b"ordinary captured result\n")
                    # The grep pattern travels only over stdin; a matching line
                    # or key value can never enter argv or unittest diagnostics.
                    observed = subprocess.run(["grep", "-r", "-l", "-F", "-f", "-", str(evidence)],
                                              input=canary.key, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    self.assertEqual(observed.returncode, 0 if kind == "dirty" else 1,
                                     "harvest grep did not distinguish the planted key")
                    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                        self.assertFalse(case.report(None), "unrun checks cannot pass")
                    value = json.loads((evidence / "report.json").read_bytes())
                    if kind != "clean":
                        self.assertTrue(value.get("failure") is not None and
                                        value["failure"].get("check") == "cleanup" and
                                        value["failure"].get("reason") == "API key harvest contains credential material or an unreadable input",
                                        "harvest exposure was omitted from the failure report")
                    else:
                        self.assertIsNone(value["failure"], "clean harvest fabricated an exposure")

    def test_store_is_not_evidence(self):
        with tempfile.TemporaryDirectory(prefix="lb-key-no-store-") as directory:
            evidence = Path(directory) / "evidence"
            evidence.mkdir(mode=0o700)
            case = serve.Case(Path(directory), evidence, config="key-harvest",
                              real_claudock=True, egress_anthropic=True, canary_api_key=True)
            with self.assertRaisesRegex(serve.Failed, "private credential store cannot be an evidence artifact"):
                case.keep("key-store.json", b"{}\n")
            self.assertFalse((case.root / "key-store.json").exists(), "keeper wrote the forbidden store artifact")

    def test_planted_file_and_clean_control(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-apikey-file-") as directory:
            root = Path(directory)
            path = root / "scratch"
            path.write_bytes(self.canary.key)
            dirty = self.canary.scan("planted", root)
            self.assertTrue(dirty["key"] and dirty["last8"], "scanner missed planted material")
            self.assertFalse(dirty["unreadable"])
            path.write_bytes(b"ordinary input\n")
            clean = self.canary.scan("clean", root)
            self.assertFalse(clean["key"] or clean["last8"] or clean["unreadable"])
            self.assertEqual(clean["files"], 1)

    def test_last8_and_read_boundary(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-apikey-boundary-") as directory:
            root = Path(directory)
            (root / "tail").write_bytes(self.canary.key[-8:])
            tail = self.canary.scan("tail", root)
            self.assertTrue(tail["last8"])
            self.assertFalse(tail["key"])
            (root / "tail").write_bytes(b"x" * ((1 << 20) - 3) + self.canary.key)
            crossing = self.canary.scan("crossing", root)
            self.assertTrue(crossing["key"] and crossing["last8"])

    def test_link_target_without_following(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-apikey-link-") as directory:
            root = Path(directory)
            (root / "link").symlink_to(self.canary.key[-8:].decode("ascii"))
            found = self.canary.scan("link", root)
            self.assertTrue(found["last8"])
            self.assertFalse(found["unreadable"])
            self.assertEqual(found["links"], 1)
            self.assertEqual(found["files"], 0)

    def test_missing_required_scope(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-apikey-missing-") as directory:
            result = self.canary.scan("missing", Path(directory) / "absent")
            self.assertTrue(result["unreadable"])
            self.assertFalse(result["present"])

    def test_evidence_is_withheld(self):
        for material in self.canary.needles:
            result = self.canary.retainable(b"vendor output: " + material)
            self.assertFalse(any(self.canary.matches(result).values()))
            self.assertTrue(self.canary.withheld)
        ordinary = b"ordinary output\n"
        self.assertTrue(self.canary.retainable(ordinary) == ordinary)

    def test_report_is_value_free(self):
        value = {"failure": self.canary.key.decode("ascii"), "nested": [self.canary.key[-8:].decode("ascii")]}
        result = repr(self.canary.redact(value)).encode()
        self.assertFalse(any(self.canary.matches(result).values()))
        self.assertTrue(self.canary.withheld)

    def test_finding_paths_are_value_free(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-apikey-path-") as directory:
            root = Path(directory)
            path = root / "capture"
            path.write_bytes(self.canary.key)
            result = self.canary.scan("evidence", root)
            self.assertEqual(result.get("path"), str(path), "scanner omitted the matching path")
            path.write_bytes(b"ordinary input\n")
            clean = self.canary.scan("evidence", root)
            self.assertFalse(clean["key"] or clean["last8"] or clean["unreadable"])
            self.assertFalse(clean.get("path"))
            path = root / self.canary.key.decode("ascii")
            path.write_bytes(b"ordinary input\n")
            named = self.canary.scan("evidence", root)
            self.assertTrue(named["key"] and named["last8"])
            self.assertTrue(named.get("path"), "scanner omitted the redacted name match")
            encoded = json.dumps(self.canary.rows).encode()
            self.assertFalse(any(self.canary.matches(encoded).values()), "path report exposed material")

    def test_unreadable_path_is_distinct(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-apikey-unreadable-") as directory:
            missing = Path(directory) / "absent"
            result = self.canary.scan("evidence", missing)
            self.assertTrue(result["unreadable"])
            self.assertFalse(result["key"] or result["last8"])
            self.assertEqual(result.get("unreadable_path"), str(missing))

    def test_finish_service_evidence_scan(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-apikey-service-") as directory:
            root = Path(directory)
            evidence, service = root / "harness", root / "installed-service"
            evidence.mkdir()
            service.mkdir()
            case = SimpleNamespace(config="canary-controls", root=evidence, lane_records=[],
                                   installed={"state_directory": str(service)}, last={"exit_code": 0})
            case.command = lambda *args, **kwargs: b"unit started\n"
            retained = {}
            case.keep_json = lambda name, value: retained.update({name: value})
            for planted in (False, True):
                with self.subTest(planted=planted):
                    canary = canary_module.Canary()
                    path = service / "capture"
                    path.write_bytes(canary.key if planted else b"ordinary input\n")
                    result = canary.finish(case)
                    selected = [row for row in result["places"] if row["place"] == "service-evidence"]
                    self.assertEqual(len(selected), 1, "installed service evidence was not scanned")
                    self.assertEqual(selected[0]["key"], planted)
                    self.assertEqual(selected[0]["last8"], planted)
                    self.assertFalse(selected[0]["unreadable"])
                    if planted:
                        self.assertEqual(selected[0].get("path"), str(path))
                    self.assertFalse(any(canary.matches(json.dumps(retained).encode()).values()),
                                     "retained service scan exposed material")


if __name__ == "__main__":
    unittest.main()
