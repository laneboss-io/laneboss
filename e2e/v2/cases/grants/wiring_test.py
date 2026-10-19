"""Harness units. Synthetic schemas never count as installed grants evidence."""

import base64
import copy
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
CORE = Path(os.environ.get("LB_GRANTS_CORE", str(ROOT / "scripts" / "v2-serve")))


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


IO = module("unit_context", CORE / "item_context.py")
DISPATCH = module("unit_dispatch", CORE / "item_dispatch.py")
GRANTS = module("unit_producer", CORE / "case_grants.py")
SUMMARY = module("unit_summary", CORE / "summary.py")
PROVISION = module("unit_provision", CORE / "provision.py")
SERVER = module("unit_server", CORE / "run.py")
CONSUMER = module("unit_consumer", Path(os.environ.get("LB_GRANTS_CONSUMER", str(HERE / "run.py"))))


class Fixture:
    def __init__(self, root):
        self.root = root / "retained"
        self.stage = root / "source"
        self.root.mkdir(mode=0o700)
        self.stage.mkdir(mode=0o700)
        self.config = "unit-grants"
        self.current = "item.grants.run"
        self.rows = {name: {"observed": {}} for name in
                     ("item.grants.run", "item.grants.collection")}
        paths = [Path("e2e") / "v2" / name for name in ("manifests.py", "support.py")]
        paths += [Path("e2e") / "v2" / "cases" / "grants" / name for name in
                  ("case.json", "fixture_entry.py", "observer.py", "child_probe.c",
                   "child_task.sh", "pre-commit.sh")]
        for relative in paths:
            target = self.stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        core_target = self.stage / "scripts" / "v2-serve"
        core_target.mkdir(parents=True)
        shutil.copyfile(CORE / "item_context.py", core_target / "item_context.py")
        for suffix in ("md", "toml"):
            relative = Path("templates") / "v2" / "roles" / "L3" / ("executor." + suffix)
            target = self.stage / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        manifest = self.stage / "e2e" / "v2" / "cases" / "grants" / "case.json"
        value = json.loads(manifest.read_bytes())
        value["entry"] = "fixture_entry.py"
        manifest.write_bytes(IO.encoded(value))
        self.binary = self.root / "unit-binary"
        shutil.copyfile(Path("/bin/true").resolve(), self.binary)
        self.binary.chmod(0o555)
        shutil.copyfile(self.binary, self.root / "laneboss.input")
        self.installed = {"artifact_sha256": IO.sha(self.binary)}
        self.binding = self.keep("binding.json", b'{"unit_metadata_only":true}\n')
        self.archive()
        self.calls, self.collections, self.last = [], [], None

    def archive(self):
        rows = []
        with tarfile.open(self.root / "source.tar", "w") as archive:
            for path in sorted(self.stage.rglob("*")):
                if not path.is_file():
                    continue
                relative = str(path.relative_to(self.stage))
                rows.append({"path": relative, "sha256": IO.sha(path), "bytes": path.stat().st_size})
                archive.add(path, arcname=relative, recursive=False)
        (self.root / "source-files.json").write_bytes(IO.encoded(rows))

    def keep(self, name, raw):
        path = self.root / name
        IO.keep(path, raw)
        return path

    def keep_json(self, name, value):
        return self.keep(name, IO.encoded(value))

    def command(self, label, argv, **options):
        result = subprocess.run(argv, capture_output=True, timeout=options.get("seconds", 30),
                                env=options.get("environment"))
        self.calls.append((argv, result))
        stem = "unit-cmd-%03d" % len(self.calls)
        self.keep(stem + ".stdout", result.stdout)
        self.keep(stem + ".stderr", result.stderr)
        self.last = {"exit_code": result.returncode, "stdout": stem + ".stdout",
                     "stderr": stem + ".stderr"}
        if options.get("expected", 0) is not None and result.returncode != options.get("expected", 0):
            raise ValueError("unit subprocess failed: " + result.stderr.decode())
        return result.stdout

    def collect(self, context, operations):
        output = Path(context["evidence_root"])
        worker = json.loads((output / "worker.json").read_bytes())
        try:
            os.kill(worker["pid"], 0)
        except ProcessLookupError:
            exited = True
        else:
            exited = False
        resource = output / "unit-resource"
        resource.unlink()
        collected = not resource.exists()
        self.collections.append(worker)
        evidence = IO.keep(output / "outside-unit.json", IO.encoded({
            "unit_scope": "cat child and temporary file only", "worker": worker,
            "child_exited": exited, "file_collected": collected}))
        return {"processes_quiescent": exited, "temporary_resources_collected": collected,
                "operation_ids": operations, "evidence": [evidence]}

    def prepared(self, **plan):
        nonce = os.urandom(12).hex()
        return {"binding_file": self.binding, "profile_grant_ids": [],
                "inputs": {"payload.bin": os.urandom(97), "entry-plan.json": IO.encoded(dict(
                    plan, nonce=nonce, assertion_ids=["GRANT-BOUND", "CHILD-CODE"]))},
                "transport": lambda request: {"received": request}, "collect": self.collect}


class Wiring(unittest.TestCase):
    def fixture(self):
        directory = tempfile.TemporaryDirectory(prefix="lb-grants-unit-")
        self.addCleanup(directory.cleanup)
        return Fixture(Path(directory.name).resolve())

    def test_context(self):
        case = self.fixture()
        context, path = IO.create(case, "grants", case.binding, [])
        self.assertEqual(set(context), set(IO.frozen(case.stage).CONTEXT_KEYS))
        self.assertEqual(context["binary_sha256"], IO.sha(case.binary), "binary pin changed")
        self.assertEqual(context["source_sha256"], IO.sha(case.root / "source.tar"))
        self.assertEqual(path.parent, Path(context["test_root"]))
        self.assertNotEqual(path.parent, Path(context["evidence_root"]))
        self.assertEqual(json.loads(path.read_bytes()), context)

    def test_binary_change(self):
        case = self.fixture()
        case.binary.chmod(0o644)
        case.binary.write_bytes(os.urandom(27))
        case.installed["artifact_sha256"] = IO.sha(case.binary)
        with self.assertRaisesRegex(ValueError, "installed item executable differs"):
            IO.create(case, "grants", case.binding, [])

    def test_source_change(self):
        case = self.fixture()
        path = case.stage / "scripts" / "v2-serve" / "item_context.py"
        path.write_bytes(path.read_bytes() + b"\n# changed after retention\n")
        with self.assertRaisesRegex(ValueError, "differs from consumed source bytes"):
            IO.create(case, "grants", case.binding, [])

    def test_inputs(self):
        case = self.fixture()
        context, _ = IO.create(case, "grants", case.binding, [])
        for name in ("../outside", "context.json", "inputs.json"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "invalid item input"):
                IO.retain_inputs(context, {name: b"must not overwrite"})
        raw = os.urandom(43)
        refs = IO.retain_inputs(context, {"retained.bin": raw})
        self.assertEqual((Path(context["test_root"]) / "retained.bin").read_bytes(), raw)
        self.assertEqual(refs[0]["sha256"], hashlib.sha256(raw).hexdigest(), "input evidence pin changed")

    def test_interpreter(self):
        script = ROOT / "e2e" / "v2" / "cases" / "dashboard" / "run.sh"
        self.assertEqual(DISPATCH.entry_argv(script)[:-1], ["/usr/bin/env", "bash"],
                         "declared bash interpreter was changed")
        self.assertEqual(DISPATCH.entry_argv(HERE / "fixture_entry.py")[:3],
                         [sys.executable, "-B", "-E"])

    def test_peer_token(self):
        observer = DISPATCH.Observer(None, {}, {"transport": lambda request: {"received": request}})
        observer.start()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                peer.settimeout(5)
                peer.connect(str(observer.path))
                raw = IO.encoded({"action": "rpc", "token": "different-token", "command": "unit echo"})
                peer.sendall(struct.pack("!I", len(raw)) + raw)
                with self.assertRaisesRegex(ValueError, "connection ended early"):
                    DISPATCH.read_frame(peer)
        finally:
            observer.close()
        self.assertIsInstance(observer.error, ValueError)
        self.assertIn("token differs", str(observer.error))

    def test_dispatch(self):
        case = self.fixture()
        prepared = case.prepared()
        value = DISPATCH.run(case, "grants", prepared)
        self.assertEqual(value["exit_code"], 0)
        self.assertEqual(len(case.collections), 1, "collector was repeated")
        self.assertEqual({row["id"] for row in value["result"]["assertions"]},
                         {"GRANT-BOUND", "CHILD-CODE"})
        raw = (Path(value["context"]).parent / "payload.bin").read_bytes()
        self.assertEqual(case.collections[0]["payload_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertIn("unit child observed", case.calls[-1][1].stdout.decode())

    def test_missing_assertion(self):
        case = self.fixture()
        with self.assertRaisesRegex(RuntimeError, "missing declared assertions"):
            DISPATCH.run(case, "grants", case.prepared(drop="CHILD-CODE"))
        self.assertEqual(len(case.collections), 1)
        self.assertEqual(len(case.item_result["result"]["assertions"]), 1)

    def test_exit_gate(self):
        case = self.fixture()
        with self.assertRaisesRegex(RuntimeError, "candidate entry exited nonzero"):
            DISPATCH.run(case, "grants", case.prepared(exit_code=3))
        self.assertEqual(case.item_result["exit_code"], 3)
        self.assertEqual(len(case.collections), 1)

    def test_collection_failure(self):
        case = self.fixture()
        prepared = case.prepared()
        attempts = []
        def failed(context, operations):
            attempts.append(context["config"])
            raise ValueError("unit collection failed")
        prepared["collect"] = failed
        with self.assertRaisesRegex(ValueError, "unit collection failed"):
            DISPATCH.run(case, "grants", prepared)
        self.assertEqual(len(attempts), 1, "failed collection was retried")
        self.assertIsNone(case.item_result["collection"])

    def test_first_refusal(self):
        case = self.fixture()
        check = "human.itemgrants.control.challenge"
        error = {"owner": "unit-identity", "code": "forbidden", "message": "unit exact refusal"}
        case.rows[check] = {"observed": {"refusal": error, "exit_code": 2}}
        def denied(request):
            case.current = check
            raise ValueError("unit owner refused")
        observer = DISPATCH.Observer(case, {}, {"transport": denied})
        observer.start()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
                peer.settimeout(5)
                peer.connect(str(observer.path))
                raw = IO.encoded({"action": "rpc", "token": observer.token, "command": "unit echo"})
                peer.sendall(struct.pack("!I", len(raw)) + raw)
                with self.assertRaisesRegex(ValueError, "connection ended early"):
                    DISPATCH.read_frame(peer)
        finally:
            observer.close()
        self.assertEqual(observer.failure["check"], check)
        self.assertEqual(observer.failure["observed"]["refusal"], error, "first owner refusal was changed")

    def test_collection_guard(self):
        case = self.fixture()
        context, _ = IO.create(case, "grants", case.binding, [])
        output = Path(context["evidence_root"])
        ref = IO.keep(output / "measurement.json", IO.encoded({"unit": "schema only"}))
        receipt = {"processes_quiescent": True, "temporary_resources_collected": True,
                   "operation_ids": ["op-a"], "evidence": [ref]}
        self.assertEqual(IO.collection(receipt, context), receipt)
        bad = dict(receipt, temporary_resources_collected=False)
        with self.assertRaisesRegex(ValueError, "collection is incomplete"):
            IO.collection(bad, context)
        (output / ref["path"]).write_bytes(b"changed measurement")
        with self.assertRaisesRegex(RuntimeError, "evidence hash or size mismatch"):
            IO.collection(receipt, context)

    def test_entry_scope(self):
        case = self.fixture()
        context, _ = IO.create(case, "grants", case.binding, [])
        scope = DISPATCH.EntryScope(case, context)
        result = subprocess.run(scope.argv(["/bin/sleep", "0.01"]), capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        observed = scope.collect(result.returncode)
        self.assertTrue(observed["processes_quiescent"])
        evidence = json.loads((Path(context["evidence_root"]) / observed["evidence"][0]["path"]).read_bytes())
        self.assertEqual(evidence["unit"], scope.unit, "entry scope identity changed")
        self.assertIn(evidence["cgroup_procs"], ("", None))
        self.assertEqual(evidence["entry_exit_code"], result.returncode)
        self.assertTrue(scope.unit.startswith("lb-item-"))

    def test_entry_removed(self):
        # Inject only the removed-kernfs read, after a real subprocess exit.
        # This is a collector regression, not installed containment evidence.
        result = subprocess.run(["/bin/false"], capture_output=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        for number in (errno.ENODEV, errno.ENOENT):
            for read_number in (1, 2):
                with self.subTest(errno=number, read_number=read_number):
                    case = self.fixture()
                    context, _ = IO.create(case, "grants", case.binding, [])
                    scope = DISPATCH.EntryScope(case, context)
                    real_exists, real_read = Path.exists, Path.read_bytes
                    reads = []
                    def exists(path):
                        return True if path == scope.group else real_exists(path)
                    def read(path):
                        if path == scope.group / "cgroup.procs":
                            return b""
                        if path == scope.group / "cgroup.events":
                            reads.append(path)
                            if len(reads) == read_number:
                                raise OSError(number, "injected removed cgroup")
                            return b"populated 0\nfrozen 0\n"
                        return real_read(path)
                    with patch.object(Path, "exists", exists), patch.object(Path, "read_bytes", read):
                        try:
                            observed = scope.collect(result.returncode)
                        except OSError as error:
                            self.fail("removed cgroup was not collected: errno %s" % error.errno)
                    evidence = json.loads((Path(context["evidence_root"]) / observed["evidence"][0]["path"]).read_bytes())
                    self.assertTrue(observed["processes_quiescent"])
                    self.assertEqual(evidence["entry_exit_code"], result.returncode,
                                     "removed cgroup lost the observed exit")
                    self.assertEqual(evidence["removed_errno"], number,
                                     "removed cgroup lost its native errno")
                    self.assertEqual(evidence["collection"], "collected-after-exit")
                    self.assertIsNone(evidence["cgroup_events"])

    def test_entry_removed_unknown(self):
        for number in (errno.ENODEV, errno.ENOENT):
            for entry_exit in (None, False):
                with self.subTest(errno=number, entry_exit=entry_exit):
                    case = self.fixture()
                    context, _ = IO.create(case, "grants", case.binding, [])
                    scope = DISPATCH.EntryScope(case, context)
                    real_exists, real_read = Path.exists, Path.read_bytes
                    def exists(path):
                        return True if path == scope.group else real_exists(path)
                    def read(path):
                        if path.parent == scope.group:
                            raise OSError(number, "injected removed cgroup")
                        return real_read(path)
                    with patch.object(Path, "exists", exists), patch.object(Path, "read_bytes", read):
                        with self.assertRaisesRegex(ValueError, "entry exit status is unknown"):
                            scope.collect(entry_exit)

    def test_entry_read_error(self):
        result = subprocess.run(["/bin/true"], capture_output=True, timeout=15)
        for number in (errno.EACCES, errno.EIO):
            with self.subTest(errno=number):
                case = self.fixture()
                context, _ = IO.create(case, "grants", case.binding, [])
                scope = DISPATCH.EntryScope(case, context)
                real_exists, real_read = Path.exists, Path.read_bytes
                def exists(path):
                    return True if path == scope.group else real_exists(path)
                def read(path):
                    if path.parent == scope.group:
                        raise OSError(number, "injected unrelated cgroup error")
                    return real_read(path)
                with patch.object(Path, "exists", exists), patch.object(Path, "read_bytes", read):
                    with self.assertRaises(OSError) as caught:
                        scope.collect(result.returncode)
                self.assertEqual(caught.exception.errno, number)

    def test_release(self):
        target = {"life_id": "unit-child", "run": 1}
        receipt = {"operation_id": "unit-operation", "lease_id": "unit-lease",
            "containment_id": "unit-cgroup", "backend": "linux-bwrap-landlock", "observed_at": "unit-time",
            "quiescence": {"handle": {"target": target, "containment_id": "unit-cgroup"},
                "state": "exited", "survivors": 0}, "live_connections": 0, "queued_jobs": 0, "writable_exports": 0}
        GRANTS.release(receipt, target, "unit-operation", IO.require)
        for field, value in (("operation_id", "foreign-operation"), ("live_connections", 1),
                             ("queued_jobs", None), ("writable_exports", False)):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "known-zero facts"):
                GRANTS.release(dict(receipt, **{field: value}), target, "unit-operation", IO.require)
        for value in (None, False, 1):
            bad = copy.deepcopy(receipt)
            bad["quiescence"]["survivors"] = value
            with self.subTest(survivors=value), self.assertRaisesRegex(ValueError, "known-zero facts"):
                GRANTS.release(bad, target, "unit-operation", IO.require)

    def test_abort_boundary(self):
        case = self.fixture()
        case.failed_step = "item.grants.run"
        case.rows[case.failed_step]["observed"] = {"refusal": {
            "owner": "unit-owner", "code": "forbidden", "message": "unit original refusal"}}
        case.item_lives = [{"target": {"life_id": "unit-child", "run": 1}, "collected": False}]
        with patch.object(GRANTS, "collect_fixtures", return_value=[]) as collector:
            problems = GRANTS.abort(case, IO.require, ValueError)
            self.assertEqual(len(problems), 1)
            self.assertEqual(collector.call_count, 0, "alternate collection was attempted")
            self.assertEqual(case.rows[case.failed_step]["observed"]["refusal"]["message"], "unit original refusal")
        case.rows[case.failed_step]["observed"] = {}
        with patch.object(GRANTS, "collect_fixtures", side_effect=ValueError("authorized collection reached")):
            with self.assertRaisesRegex(ValueError, "authorized collection reached"):
                GRANTS.abort(case, IO.require, ValueError)

    def test_boot(self):
        case = self.fixture()
        prepared = GRANTS.boot(case)
        docs = {row["ref"]["id"]: row for row in prepared["bundle"]["documents"]}
        for row in docs.values():
            raw = base64.b64decode(row["data"], validate=True)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), row["ref"]["sha256"])
            self.assertEqual(len(raw), row["ref"]["bytes"])
        tree = json.loads(base64.b64decode(docs[case.grants_boot["parent_tree"]["id"]]["data"]))
        entries = {row["path"]: row for row in tree["entries"]}
        self.assertEqual(entries["alias"]["link_target"], "private/canary", "canary alias differs")
        self.assertEqual(entries["child/input.txt"]["content"], case.grants_boot["input"])
        root = prepared["bundle"]["root_grants"]
        self.assertEqual(root["resources"], [], "initial root names an unenrolled resource")
        self.assertEqual(root["secrets"], [], "initial root names an unenrolled secret")
        self.assertTrue(case.grants_boot["resource_enrollment"]["delegate"], "resource delegation omitted")
        self.assertNotIn("source_handle", case.grants_boot["resource_enrollment"],
                         "resource proposal chose a service handle")
        self.assertNotIn("id", case.grants_boot["resource_enrollment"],
                         "resource proposal included an issued grant ID")
        self.assertEqual([row["delegate"] for row in root["data"]], [True, False])
        for asset in prepared["assets"]:
            path = Path(asset["file"])
            self.assertEqual(IO.sha(path), case.grants_boot["tools"][asset["id"].removeprefix("item-")]["sha256"],
                             "runtime tool bytes differ")
        self.assertEqual(set(case.grants_files), {"child_probe.c", "child_task.sh", "pre-commit.sh"})

    def test_upload_plan(self):
        case = self.fixture()
        selected = GRANTS.uploads.plan(case.root)
        steps = selected["steps"]
        self.assertEqual([step["method"] for step in steps],
                         ["secret.key", "secret.stage", "secret.import"],
                         "secret upload replaced its single-session operation order")
        self.assertNotIn("proof", steps[0], "key acquisition replaced the live session")
        self.assertNotIn("proof", steps[1], "stage replaced the live session")
        self.assertEqual(steps[2].get("proof"), str(case.root / "import.proof.json"),
                         "import lost its independent operation proof")
        identities = [step[key] for step in steps for key in ("request_id", "idempotency_key")]
        self.assertEqual(len(set(identities)), 6, "upload correlation and retry keys were reused")
        for identity in identities:
            self.assertRegex(identity, r"^[0-9a-f]{32}$")
        for step in steps:
            self.assertEqual(Path(step["request"]).parent, case.root)

    def test_runtime_asset(self):
        with tempfile.TemporaryDirectory(prefix="lb-grants-asset-", dir="/opt") as temporary:
            root = Path(temporary).resolve()
            objects = root / "objects"
            objects.mkdir(mode=0o755)
            raw = os.urandom(197)
            source = root / "source.input"
            source.write_bytes(raw)
            source.chmod(0o444)
            asset = {"id": "unit-tool", "role": "case-tool", "file": str(source), "mode": 0o555}
            result = PROVISION.runtime_asset(objects, asset)
            self.assertEqual((objects / asset["id"]).read_bytes(), raw)
            self.assertEqual((objects / asset["id"]).stat().st_mode & 0o777, 0o555, "runtime asset mode changed")
            self.assertEqual(result["mode"], 0o555, "runtime asset mode changed")
            self.assertEqual(result["content"]["sha256"], hashlib.sha256(raw).hexdigest(), "runtime asset pin changed")
            with self.assertRaises(FileExistsError):
                PROVISION.runtime_asset(objects, asset)
            for field, value in (("id", "../outside"), ("mode", 0o777), ("role", "serve-fixture-agent")):
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, "case runtime asset is invalid"):
                    PROVISION.runtime_asset(objects, dict(asset, **{field: value}))

    def test_root_binding(self):
        case = self.fixture()
        approved = GRANTS.boot(case)["bundle"]["root_grants"]
        case.generated_launches = True
        case.initial_receipt = {"generation": 1}
        case.initial = {"profiles": {"id": "unit-approved"}}
        case.egress_anthropic = False
        case.decode_document = json.loads
        directory = case.root / "initial-inputs"
        directory.mkdir()
        (directory / "unit-approved").write_bytes(IO.encoded(approved))
        issued = {name: copy.deepcopy(approved[name]) for name in GRANTS.FAMILIES}
        issued["policy_generation"] = 1
        for family in GRANTS.FAMILIES:
            for index, member in enumerate(issued[family]):
                member["id"] = "unit-" + family + "-" + str(index)
        case.human_prefix = "itemgrants"
        proposal = {"driver": "codex", "grants": {name: [] for name in GRANTS.FAMILIES}}
        SERVER.Case.bind_root_launch(case, proposal, issued)
        self.assertEqual(proposal["grants"]["data"][0]["parent_grant_id"], issued["data"][0]["id"])
        self.assertTrue(any("itemgrants" in path.name for path in case.root.glob("launch-*.input")),
                        "root evidence omitted its caller scope")
        case.human_prefix = "codex"
        next_proposal = {"driver": "codex", "grants": {name: [] for name in GRANTS.FAMILIES}}
        SERVER.Case.bind_root_launch(case, next_proposal, issued)
        self.assertEqual(len(list(case.root.glob("launch-*.input"))), 2)

    def test_capture(self):
        # These inert event pages test parsing only, never actor authority.
        case = self.fixture()
        target = {"life_id": "unit-l5", "run": 1}
        record = {"target": target, "operation": {"id": "unit-start"}}
        raw = json.dumps({"type": "unit-capture", "nonce": os.urandom(17).hex()},
                         separators=(",", ":")).encode() + b"\n"
        ref = {"id": "unit-capture", "class": "capture", "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        event = {"seq": 1, "kind": "capture.appended", "operation_id": "unit-start",
            "payload": {"stream": "stdout", "target": target, "primary": True,
                "coverage": "complete", "offset": 0, "data": ref}}
        pages = [event]
        def read(label, words, request):
            if words == ["event", "tail"]:
                self.assertEqual(request["life_id"], target["life_id"])
                return {"events": copy.deepcopy(pages), "complete": True, "cursor": ""}
            self.assertEqual(words, ["blob", "read"])
            self.assertEqual(request["object_id"], ref["id"])
            part = raw[request["offset"]:request["offset"] + request["limit"]]
            return {"object_id": ref["id"], "offset": request["offset"],
                    "data": base64.b64encode(part).decode(), "sha256": hashlib.sha256(part).hexdigest()}
        case.human = SimpleNamespace(read=read)
        relay = GRANTS.Relay(case, record, IO.require, ValueError)
        self.assertEqual(relay.captured_now(), [json.loads(raw)])
        self.assertEqual(relay.captured_now(), [json.loads(raw)], "replayed capture duplicated bytes")
        for field, value in (("operation_id", "foreign-start"), ("primary", False),
                             ("offset", 1), ("coverage", "missing")):
            changed = copy.deepcopy(event)
            (changed if field == "operation_id" else changed["payload"])[field] = value
            pages[:] = [changed]
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "uncorrelated or discontinuous"):
                GRANTS.Relay(case, record, IO.require, ValueError).captured_now()
        pages[:] = [copy.deepcopy(event)]
        pages[0]["payload"]["data"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "capture object bytes differ"):
            GRANTS.Relay(case, record, IO.require, ValueError).captured_now()
        for malformed in (b"{broken\n", b"\xff\n", b"[]\n"):
            with self.subTest(line=malformed):
                raw = malformed
                ref.update(sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
                pages[:] = [copy.deepcopy(event)]
                message = "line is not an object" if malformed == b"[]\n" else "malformed JSON line"
                with self.assertRaisesRegex(ValueError, message) as caught:
                    GRANTS.Relay(case, record, IO.require, ValueError).captured_now()
                self.assertIs(type(caught.exception), ValueError,
                              "malformed capture escaped the relay failure class")

    def test_summary(self):
        names = list(SUMMARY.with_item(SUMMARY.expected_checks("installed-lifecycle"), "grants"))
        report = {"scope": "installed-lifecycle", "presence": "simulated", "human_approval": "not_proven",
            "required_checks": names, "failure": None, "item_case": "grants",
            "checks": [{"check": name, "result": "pass", "presence": "simulated",
                "observed": {"executed": True}} for name in names],
            "item_result": {"exit_code": 0, "result": {"assertions": [
                {"id": name, "reached": True, "verdict": "pass"}
                for name in ("GRANT-BOUND", "CHILD-CODE")]},
                "collection": {"processes_quiescent": True, "temporary_resources_collected": True,
                    "evidence": [{"unit": "schema-only"}]},
                "entry_collection": {"processes_quiescent": True, "evidence": [{"unit": "schema-only"}]}}}
        self.assertTrue(SUMMARY.describe(report)[0])
        for field in ("collection", "entry_collection"):
            bad = copy.deepcopy(report)
            bad["item_result"][field]["processes_quiescent"] = False
            self.assertFalse(SUMMARY.describe(bad)[0], "incomplete collection was credited")
        report["item_result"]["result"]["assertions"].pop()
        self.assertFalse(SUMMARY.describe(report)[0], "missing declared item was credited")
        report["item_result"]["result"] = None
        self.assertFalse(SUMMARY.describe(report)[0])
        error = {"owner": "unit-owner", "code": "not_implemented", "message": "unit native refusal"}
        report["failure"] = {"check": "item.grants.run", "observed": {"refusal": error}}
        self.assertIn("owner=unit-owner code=not_implemented", SUMMARY.describe(report)[1])

    def test_outside_probe(self):
        for readable in (True, False):
            case = self.fixture()
            output = case.root / "outside-probe"
            output.mkdir(mode=0o700)
            consumer = CONSUMER.Case({"evidence_root": str(output)})
            canary = case.root / "canary"
            if readable:
                canary.write_bytes(os.urandom(33))
                consumer.outside_control(canary)
                self.assertEqual(json.loads((output / "observer-control.json").read_bytes())["exit"], 41)
            else:
                with self.assertRaisesRegex(AssertionError, "outside read control did not execute"):
                    consumer.outside_control(canary)

    def test_child_task(self):
        self.assertEqual(os.geteuid(), 0, "the outside harness requires its authorized root observer")
        child = pwd.getpwnam("nobody")
        self.assertGreater(child.pw_uid, 0, "child task must use an unprivileged UID")
        case = self.fixture()
        case.root.parent.chmod(0o711)
        case.root.chmod(0o711)
        work = case.root / "child-work"
        work.mkdir(mode=0o700)
        os.chown(work, child.pw_uid, child.pw_gid)
        home, temporary = work / "home", work / "tmp"
        for directory in (home, temporary):
            directory.mkdir(mode=0o700)
            os.chown(directory, child.pw_uid, child.pw_gid)
        for name in ("child_task.sh", "pre-commit.sh", "child_probe.c"):
            source = Path(os.environ["LB_GRANTS_TASK"]) if name == "child_task.sh" and "LB_GRANTS_TASK" in os.environ else HERE / name
            shutil.copyfile(source, work / name)
            (work / name).chmod(0o444)
        payload = os.urandom(47)
        (work / "input.txt").write_bytes(payload)
        (work / "input.txt").chmod(0o444)
        canary = case.root / "private-canary"
        original = os.urandom(51)
        canary.write_bytes(original)
        canary.chmod(0o000)
        self.assertEqual(canary.read_bytes(), original)
        result = subprocess.run(["sh", "child_task.sh", str(canary)],
            cwd=work, capture_output=True, timeout=30,
            user=child.pw_uid, group=child.pw_gid, extra_groups=[],
            env={"PATH": "/usr/bin:/bin", "HOME": str(home), "TMPDIR": str(temporary), "LANG": "C"})
        case.keep("child-task.stdout", result.stdout)
        case.keep("child-task.stderr", result.stderr)
        case.keep_json("child-task.exit.json", {"uid": child.pw_uid, "gid": child.pw_gid,
                                                "exit_code": result.returncode})
        self.assertEqual(result.returncode, 0,
                         "child build or Git hook failed: stdout=%r stderr=%r" % (result.stdout, result.stderr))
        records = [json.loads(line) for line in result.stdout.splitlines()]
        probes = [row for row in records if "read_errno" in row]
        self.assertEqual(len(probes), 2,
                         "test and hook must both emit probes: stdout=%r stderr=%r" % (result.stdout, result.stderr))
        for probe in probes:
            self.assertEqual(probe["read_errno"], errno.EACCES)
            self.assertEqual(probe["write_errno"], errno.EACCES)
        self.assertEqual(canary.read_bytes(), original)
        self.assertIn({"build_exit": 0, "git_exit": 0}, records)
        self.assertIn({"input_sha256": hashlib.sha256(payload).hexdigest()}, records)


if __name__ == "__main__":
    unittest.main()
