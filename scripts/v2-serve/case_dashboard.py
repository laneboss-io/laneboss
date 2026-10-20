"""Dashboard producer at the installed serve checkpoint, Linux only.

G0 calls boot/prepare and owns entry execution plus independent collection.
The native owner supplies HTTPSHandoff; this module cannot turn a closed CLI
session receipt into a browser cookie or expose an in-process Go handler.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import errno
import base64
import hashlib
from http.cookies import SimpleCookie
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid


ENTRY_PROTOCOL = "laneboss.dashboard-entry.v1"
AGENT_PACKAGE = "./e2e/v2/cases/dashboard/actor"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def case_modules(source):
    directory = Path(source) / "e2e/v2/cases/dashboard"
    # The frozen entry uses ordinary imports from its own directory. Register
    # those two case-owned modules without importing a speculative exporter.
    for name in ("fixture_io", "view_checks"):
        path = directory / (name + ".py")
        module = sys.modules.get(name)
        if module is None or Path(module.__file__).resolve() != path.resolve():
            load(name, path)
    return load("dashboard_case", directory / "case.py")


def boot(case):
    """Measure the shipped additional role sources before G0 publication."""
    sources = []
    for level, role in ((3, "reviewer"), (6, "supervisor")):
        for suffix, kind in (("md", "prompt"), ("toml", "drivers")):
            path = case.stage / "templates/v2/roles" / ("L%d" % level) / (role + "." + suffix)
            raw = path.read_bytes()
            case.keep("dash-L%d-%s.input" % (level, suffix), raw)
            sources.append({"id": "dash-L%d-%s" % (level, kind),
                "path": ".laneboss/L%d/roles/%s.%s" % (level, role, suffix), "kind": kind,
                "data": base64.b64encode(raw).decode()})
    documents = []
    def document(name, kind, raw):
        ref = {"id": name, "class": kind, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        documents.append({"ref": ref, "data": base64.b64encode(raw).decode()})
        case.keep(name + ".input", raw)
        return ref
    plugin_path = ".laneboss/plugins/dashboard.txt"
    plugin_bytes = b"Dashboard fixture plugin materialization input.\n"
    plugin = document("dash-plugin", "artifact", plugin_bytes)
    readme = document("dash-readme", "artifact", (case.stage / "scripts/v2-serve/fixtures/README.md").read_bytes())
    tree = document("dash-plugin-tree", "manifest", (json.dumps({"schema": "laneboss.objects.v2",
        "entries": [{"path": plugin_path, "kind": "file", "mode": 0o444, "content": plugin},
                    {"path": "README.md", "kind": "file", "mode": 0o444, "content": readme}]}, sort_keys=True) + "\n").encode())
    expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    root = {name: [] for name in ("resources", "data", "secrets", "profiles", "network", "channels")}
    root["schema"] = "laneboss.root-grants.v2"
    root["data"] = [{"id": "", "source_object_id": tree["id"], "source_sha256": tree["sha256"], "relative_path": ".",
        "access": "rw", "delivery": "copy", "destination": "/work/main", "delegate": False,
        "expires_at": expiry, "history_scope": "tree"}]
    root["profiles"] = [{"id": "", "profile_id": "serve-profile-" + driver, "driver": driver, "provider": "serve-fixture",
                         "paid": False, "delegate": False, "expires_at": expiry} for driver in ("claudock-cli", "codex")]
    budget = {"wall_ms": 300000, "cpu_seconds": 120, "memory_bytes": 536870912, "processes": 32,
              "disk_bytes": 67108864, "spend_micros": 0, "currency": "USD"}
    case.dashboard_boot = {"plugin_path": plugin_path, "plugin_bytes": base64.b64encode(plugin_bytes).decode(),
        "budget": budget, "project_id": "dashboard-project", "project_tree": tree, "case_root": root}
    baseline_root = dict(root, data=[])
    judge_file = case.stage / "e2e/v2/cases/dashboard/scored-judge.json"
    return {"assets": [{"id": "dashboard-judge", "role": "dashboard-fake-judge", "file": str(judge_file), "mode": 0o444},
        {"id": "dashboard-check", "role": "tool", "file": str(case.agent["path"]), "mode": 0o555}],
        "bundle": {"sources": sources, "documents": documents, "root_grants": baseline_root, "budget": budget,
        "projects": [{"id": "dashboard-project-enrollment", "generation": 1, "project_id": "dashboard-project",
            "object": tree, "base": tree["sha256"], "history_scope": "tree"}],
        "contexts": [{"level": 3, "role": "reviewer"}, {"level": 6, "role": "supervisor"}]}}


class G0Dashboard:
    """Case-owned adapter; the shared observer caches the final receipt."""

    def __init__(self, case, handoff, data, require, fail):
        self.case, self.handoff, self.data = case, handoff, data
        self.require, self.fail = require, fail
        self.consumer = case_modules(case.stage)
        self.browser, self.context, self.receipt, self.failure = None, None, None, None

    def populate(self, context):
        try:
            return self._populate(context)
        except Exception as error:
            row = self.case.rows.get(self.case.current, {}).get("observed", {})
            self.failure = getattr(error, "error", None) or row.get("refusal") or {
                "owner": "lb-v2-dashboard", "code": "fixture_incomplete", "message": str(error)}
            self.case.rows[self.case.current]["observed"].update({"executed": True, "refusal": self.failure})
            raise

    def _populate(self, context):
        self.context = context
        recorder = self.consumer.EvidenceRecorder(context["evidence_root"])
        self.browser = Browser(self.case, self.consumer, self.handoff, recorder)
        self.browser.bootstrap()
        self.data.bind(self.browser, self.consumer)
        self.data.prepare()
        self.case.verify_other_capture(self.data.records["DASH-MERGED"])
        root = Path(context["test_root"]) / "dashboard"
        root.mkdir(mode=0o700)
        for name in ("requests", "responses"):
            (root / name).mkdir(mode=0o700)
        document = {"schema": "laneboss.dash-inputs.v2", "config": self.case.config,
            "handoff": str(root), "ca_file": str(self.handoff.ca_file),
            "connect_address": self.handoff.connect_address,
            "binary_sha256": context["binary_sha256"], "source_sha256": context["source_sha256"],
            "targets": [record["target"] for aid, record in self.data.records.items() if aid in self.consumer.ASSERTION_IDS]}
        self.environment.update({"LANEBOSS_DASHBOARD_URL": self.browser.origin,
            "LANEBOSS_DASHBOARD_COOKIE": self.browser.cookie,
            "LANEBOSS_DASHBOARD_CONTROLS_FILE": str(Path(context["test_root"]) / "dashboard-inputs.json")})
        return {"dashboard-inputs.json": (json.dumps(document, sort_keys=True, indent=2) + "\n").encode()}

    def transport(self, message):
        from fixture_io import FixtureError
        self.case.human_prefix = "itemdashboard"
        self.case.current = "item.dashboard.run"
        request = message.get("request", {})
        self.require(message.get("action") == "rpc" and message.get("command") == "dashboard inputs"
            and request.get("schema") == "laneboss.dash-handoff.v2" and request.get("config") == self.case.config
            and request.get("nonce") == message.get("request_id") == message.get("idempotency_key"),
            "G0 dashboard transport lost its exact private input correlation")
        response = dict(request)
        try:
            if self.failure:
                raise FixtureError(self.failure)
            if request.get("failure"):
                raise FixtureError(request["failure"])
            if request.get("kind") == "cli-proof":
                self.require(request.get("key") in dict(self.consumer.VIEW_ASSERTIONS), "unknown dashboard CLI proof selector")
                proof = self.case.human.proof("read", "human.session", {}, self.case.human.public["principal_id"], 0)
                self.case.current = "item.dashboard.run"
                response["result"] = {"proof_file": str(proof)}
            elif request.get("kind") == "action":
                response["result"] = {"request_file": str(self.data.action(request["key"]))}
            else:
                raise ValueError("unknown dashboard private input request")
        except Exception as error:
            row = self.case.rows.get(self.case.current, {}).get("observed", {})
            self.failure = getattr(error, "error", None) or row.get("refusal") or {
                "owner": "lb-v2-dashboard", "code": "producer_failed", "message": str(error)}
            self.case.rows["item.dashboard.run"]["observed"].update({"executed": True, "refusal": self.failure})
            response["error"] = self.failure
        return {"exit_code": 0, "stdout": base64.b64encode(
            (json.dumps(response, sort_keys=True) + "\n").encode()).decode(), "stderr": ""}

    def collect(self, context, operation_ids):
        from fixture_io import external_collected
        self.case.human_prefix = "itemdashboard"
        self.case.current = "item.dashboard.collection"
        self.require(not self.failure, "dashboard stopped at its first refused or failed gate; collection remains incomplete")
        if self.receipt is not None:
            self.require(set(operation_ids) <= set(self.receipt["operation_ids"]), "cached dashboard collection omitted an operation")
            return self.receipt
        self.require(self.browser is not None and self.context == context, "dashboard collector lacks its populated live context")
        report = self.data.collect()
        report["https"] = collect_https(self.browser)
        for record in self.case.item_lives:
            if record.get("dashboard_entry"):
                record["collected"] = True
        required = {(record["target"]["life_id"], record["target"]["run"]) for record in self.data.records.values()}
        self.require(external_collected(report, required), "independent dashboard target/session/listener collection is incomplete")
        operations = []
        for operation_id in operation_ids:
            operation = self.data.read("operation.get", {"operation_id": operation_id})
            self.require(operation.get("id") == operation_id and operation.get("status") == "succeeded"
                         and not operation.get("error"), "dashboard action operation did not complete")
            operations.append(operation)
        report["operations"] = operations
        ref = self.browser.recorder.save("outside-dashboard.json", report)
        self.receipt = {"processes_quiescent": True, "temporary_resources_collected": True,
                        "operation_ids": list(operation_ids), "evidence": [ref]}
        return self.receipt

    def prepared(self):
        self.environment = {}
        return {"binding_file": self.case.installed["binding_file"], "profile_grant_ids": [],
            "populate": self.populate, "environment": self.environment,
            "transport": self.transport, "collect": self.collect}


def prepare(case, require, fail, blocked):
    """G0 entry: refuse an absent native handoff before allocating targets."""
    case.human_prefix = "itemdashboard"
    case.current = "item.dashboard.prepare"
    case.prepare_other_human()
    case_modules(case.stage)
    try:
        handoff = start_handoff(case, require)
    except Exception as error:
        refusal = getattr(error, "error", None)
        if refusal:
            case.rows[case.current]["observed"].update({"executed": True, "refusal": refusal})
            raise fail("installed native dashboard entry refused; retain its exact response") from error
        raise
    try:
        check_handoff(handoff)
    except Exception as error:
        refusal = getattr(error, "error", None)
        if refusal:
            case.rows[case.current]["observed"].update({"executed": False, "refusal": refusal})
        raise blocked("installed dashboard HTTPS/bootstrap entry is absent; preserve the owning service handoff gate") from error
    module = load("dashboard_data", Path(__file__).with_name("dash_data.py"))
    data = module.from_checkpoint(case, require, fail)
    adapter = G0Dashboard(case, handoff, data, require, fail)
    case.dashboard_item = adapter
    return adapter.prepared()


def abort(case, require, fail):
    """Do not retry refused mutations or credit unit shutdown as collection."""
    for session in getattr(case, "dashboard_native", []):
        if session.process.poll() is None:
            session.process.terminate()
            session.process.wait(timeout=30)
            session.stdout.close()
            session.stderr.close()
    host = getattr(case, "dashboard_host", None)
    if host is not None and host.poll() is None:
        host.terminate()
        host.wait(timeout=30)
    for stream in getattr(case, "dashboard_host_files", ()):
        if not stream.closed:
            stream.close()
    adapter = getattr(case, "dashboard_item", None)
    if adapter is None:
        return [] if not case.item_lives else [{"reason": "dashboard fixture ownership was not established"}]
    if adapter.receipt is not None:
        return []
    return [{"target": record["target"], "reason": "dashboard collection remains incomplete; preserve the original gate"}
            for record in adapter.data.records.values() if not record.get("collected")]


@dataclass
class HTTPSHandoff:
    origin: str
    ca_file: Path
    bootstrap_file: Path
    session_process: subprocess.Popen
    listener_process: subprocess.Popen
    close_session: object
    close_listener: object
    connect_address: str = "127.0.0.1"
    review_prepare: object = None


class NativeSession:
    """The matched installed CLI retains the real native human connection."""

    def __init__(self, case, label, require):
        self.case, self.require = case, require
        self.directory = case.root / ("dash-native-" + label)
        self.directory.mkdir(mode=0o700)
        self.ready = self.directory / "ready.json"
        self.stdout = (self.directory / "stdout").open("xb")
        self.stderr = (self.directory / "stderr").open("xb")
        arguments = [str(case.binary), "dashboard", "open", "--config", case.config,
            "--binding", case.installed["binding_file"], "--mode", "session", "--directory", str(self.directory),
            "--credential-id", case.human.public["credential_id"],
            "--ready", str(self.ready), "--wait", "30m"]
        case.keep_json("dash-native-" + label + ".argv.json", arguments)
        self.process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=self.stdout, stderr=self.stderr,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
        if not hasattr(case, "dashboard_native"):
            case.dashboard_native = []
        case.dashboard_native.append(self)
        self.wait_file(self.ready)
        reply = json.loads(self.ready.read_bytes())
        self.check(reply)
        self.identity = reply["result"]
        require(self.identity.get("config") == case.config and self.identity.get("connection_id")
            and self.identity.get("actor", {}).get("kind") == "human"
            and self.identity["actor"].get("id") == case.human.public["principal_id"],
            "native dashboard entry authenticated a different principal")

    def check(self, response):
        from fixture_io import FixtureError
        if response.get("error"):
            raise FixtureError(response["error"])
        self.require(isinstance(response.get("result"), dict), "native dashboard reply lacks its actual result")
        return response["result"]

    def wait_file(self, path):
        from fixture_io import FixtureError
        deadline = time.monotonic() + 120
        while not path.exists():
            if self.process.poll() is not None:
                raw = (self.directory / "stderr").read_bytes()
                if raw.strip():
                    raise FixtureError(json.loads(raw))
                raise ValueError("native dashboard process ended before its file reply")
            self.require(time.monotonic() < deadline, "native dashboard file reply deadline")
            time.sleep(0.05)

    def send(self, request):
        from fixture_io import private_write
        nonce = uuid.uuid4().hex[:20]
        path = self.directory / (nonce + ".request.json")
        private_write(path, request)
        response_path = self.directory / (nonce + ".response.json")
        self.wait_file(response_path)
        response = json.loads(response_path.read_bytes())
        if request.get("protocol") == "laneboss.rpc.v2":
            self.require(response.get("request_id") == request.get("request_id"), "native dashboard RPC changed correlation")
        return self.check(response)

    def rpc(self, method, params, proof=None):
        return self.send(case_modules(self.case.stage).build_rpc_envelope(self.case.config, method, params, proof))

    def close(self):
        from fixture_io import private_write
        if self.process.poll() is None:
            private_write(self.directory / "close", b"close\n")
        code = self.process.wait(timeout=30)
        self.stdout.close()
        self.stderr.close()
        self.require(code == 0, "native dashboard session process did not exit zero")


def native_proof(case, session, method, params, target, generation, require):
    operation = case.keep_json("dash-" + uuid.uuid4().hex[:16] + ".operation.json", params)
    arguments = ["--config", case.config, "--operation", str(operation), "--method", method,
                 "--target", target, "--generation", str(generation)]
    intent = json.loads(case.command("dash-intent", [str(case.authenticator), "intent", *arguments], clean=True))
    challenge = session.rpc("human.challenge", intent)
    require(all(challenge.get(field) == intent[field] for field in
        ("method", "target_id", "request_sha256", "base_generation")), "native challenge differs from exact operation")
    challenge_path = case.keep_json("dash-" + uuid.uuid4().hex[:16] + ".challenge.json", challenge)
    assertion = json.loads(case.command("dash-sign", [str(case.authenticator), "sign", *arguments,
        "--private", str(case.human.private), "--challenge", str(challenge_path)], clean=True))
    proof = session.rpc("human.confirm", assertion)
    require(proof.get("id") and proof.get("request_sha256") == intent["request_sha256"]
        and proof.get("expires_at") == challenge.get("expires_at") and proof.get("simulated_presence") is True,
        "native confirmation lacks the actual operation-bound simulated proof")
    return proof


def start_handoff(case, require):
    """Open actual native connections and the installed CLI's HTTPS listener."""
    consumer = case_modules(case.stage)
    case.item_lives.append({"name": "dashboard-native-entry", "dashboard_entry": True, "collected": False})
    issuer = NativeSession(case, "issuer", require)
    proof = native_proof(case, issuer, "human.session", {}, case.human.public["principal_id"], 0, require)
    issuer.rpc("human.session", {}, proof)
    redemption = NativeSession(case, "browser", require)
    proof = native_proof(case, redemption, "human.session", {}, case.human.public["principal_id"], 0, require)
    nonce = os.urandom(32)
    binding = issuer.send({"protocol": ENTRY_PROTOCOL, "action": "bootstrap",
        "redeem_id": redemption.identity["connection_id"], "nonce": base64.b64encode(nonce).decode(),
        "session": consumer.build_rpc_envelope(case.config, "human.session", {}, proof)})
    require(binding.get("connection_id") == redemption.identity["connection_id"] and binding.get("proof") == proof,
            "native bootstrap differs from its actual redemption connection/proof")
    issuer.close()
    from fixture_io import private_write
    bootstrap = case.root / "dash-bootstrap.json"
    private_write(bootstrap, dict(binding, nonce=base64.urlsafe_b64encode(nonce).decode().rstrip("=")))
    private = Path(tempfile.mkdtemp(prefix="lb-dash-tls-", dir="/opt"))
    certificate, key = private / "certificate.pem", private / "key.pem"
    rp = case.human.public["rp_id"]
    case.command("dash-certificate", ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-days", "1", "-keyout", str(key), "-out", str(certificate), "-subj", "/CN=" + rp,
        "-addext", "subjectAltName=DNS:" + rp], clean=True)
    key.chmod(0o600)
    ca = case.keep("dash-ca.pem", certificate.read_bytes())
    ready = case.root / "dash-host-ready.json"
    stdout = (case.root / "dash-host.stdout").open("xb")
    stderr = (case.root / "dash-host.stderr").open("xb")
    origin = case.human.public["origin"]
    arguments = [str(case.binary), "dashboard", "open", "--config", case.config,
        "--binding", case.installed["binding_file"], "--mode", "host", "--origin", origin,
        "--listen", "127.0.0.1:443", "--certificate", str(certificate), "--key", str(key), "--ready", str(ready)]
    case.keep_json("dash-host.argv.json", arguments)
    host = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
    case.dashboard_host = host
    case.dashboard_host_files = (stdout, stderr)
    deadline = time.monotonic() + 30
    while not ready.exists():
        if host.poll() is not None:
            raw = (case.root / "dash-host.stderr").read_bytes()
            raise ValueError("installed HTTPS host ended before readiness: " + raw.decode("utf-8", "replace"))
        require(time.monotonic() < deadline, "installed HTTPS host readiness deadline")
        time.sleep(0.05)
    observed = json.loads(ready.read_bytes())
    require(observed.get("config") == case.config and observed.get("pid") == host.pid and observed.get("origin") == origin,
            "installed HTTPS listener readiness differs from its actual child")
    def close_host():
        host.terminate()
        require(host.wait(timeout=30) == 0, "installed HTTPS host did not exit zero")
        stdout.close()
        stderr.close()
        key.unlink()
        certificate.unlink()
        private.rmdir()
    handoff = HTTPSHandoff(origin, ca, bootstrap, redemption.process, host, redemption.close, close_host)
    handoff.review_prepare = lambda target: redemption.send({"protocol": ENTRY_PROTOCOL, "action": "review-inputs", "target": target})
    case.dashboard_handoff = handoff
    return handoff


class Browser:
    def __init__(self, case, consumer, handoff, recorder):
        self.case, self.consumer, self.handoff, self.recorder = case, consumer, handoff, recorder
        self.origin = handoff.origin.rstrip("/")
        self.opener = consumer.dashboard_opener(self.origin, str(handoff.ca_file), getattr(handoff, "connect_address", None))
        self.opener.evidence_recorder = recorder
        self.cookie = None

    def bootstrap(self):
        from fixture_io import private_read
        raw = private_read(self.handoff.bootstrap_file)
        self.recorder.save("inputs/native-bootstrap.json", raw)
        binding = json.loads(raw)
        if (binding.get("config") != self.case.config or not binding.get("token")
                or not binding.get("connection_id") or not binding.get("nonce")
                or binding.get("actor", {}).get("kind") != "human"
                or binding.get("actor", {}).get("id") != self.case.human.public["principal_id"]):
            raise ValueError("native dashboard bootstrap differs from installed human/configuration")
        request = self.consumer.build_rpc_envelope(self.case.config, "human.session", {}, binding["proof"])
        status, headers, response = self.consumer.http_call(self.opener, self.origin + "/api/v2/rpc",
            method="POST", body=request, headers={"Origin": self.origin,
                "X-Laneboss-Dashboard-Bootstrap": binding["token"],
                "X-Laneboss-Dashboard-Nonce": binding["nonce"]})
        result = self.result(status, response, request)
        cookies = SimpleCookie()
        cookies.load(headers.get("Set-Cookie", ""))
        cookie = cookies.get("laneboss_session")
        if (cookie is None or not cookie.value or cookie.value == result.get("id")
                or not cookie["secure"] or not cookie["httponly"]
                or cookie["samesite"].lower() != "strict" or cookie["path"] != "/"
                or result.get("config") != self.case.config or result.get("simulated_presence") is not True
                or headers.get("X-Laneboss-Presence") != "simulated"
                or headers.get("X-Laneboss-Human-Approval") != "not_proven"):
            raise ValueError("HTTPS did not issue its own protected simulated-session cookie")
        self.cookie = "laneboss_session=" + cookie.value
        self.session = result
        # An actual cookie-authenticated read is required after redemption.
        self.view("tree")
        return result

    def result(self, status, raw, request):
        from fixture_io import FixtureError
        reply = json.loads(raw)
        if reply.get("error"):
            raise FixtureError(reply["error"])
        if (status != 200 or reply.get("request_id") != request["request_id"]
                or not isinstance(reply.get("result"), dict)):
            raise ValueError("installed HTTPS response lost its request/result correlation")
        if reply["result"].get("error"):
            raise FixtureError(reply["result"]["error"])
        return reply["result"]

    def rpc(self, method, params, proof=None):
        request = self.consumer.build_rpc_envelope(self.case.config, method, params, proof)
        status, _, raw = self.consumer.http_call(self.opener, self.origin + "/api/v2/rpc", method="POST",
            headers={"Origin": self.origin, "Cookie": self.cookie}, body=request)
        return self.result(status, raw, request)

    def view(self, name):
        from fixture_io import FixtureError
        status, _, raw = self.consumer.http_call(self.opener,
            self.origin + "/api/v2/" + name + "?limit=200", headers={"Cookie": self.cookie})
        value = json.loads(raw)
        if value.get("error"):
            raise FixtureError(value["error"])
        if status != 200:
            raise ValueError("installed dashboard view failed")
        return value

    def proof(self, method, params, target, generation):
        # Challenge and confirmation travel through the existing cookie's
        # retained native human connection. The software device signs only;
        # the installed identity service issues the ProofRef.
        operation = self.case.keep_json("dash-" + uuid.uuid4().hex[:16] + ".operation.json", params)
        arguments = ["--config", self.case.config, "--operation", str(operation),
                     "--method", method, "--target", target, "--generation", str(generation)]
        intent = json.loads(self.case.command("dash-intent", [str(self.case.authenticator), "intent", *arguments], clean=True))
        challenge = self.rpc("human.challenge", intent)
        if any(challenge.get(field) != intent[field] for field in
               ("method", "target_id", "request_sha256", "base_generation")):
            raise ValueError("browser challenge differs from the current exact operation")
        challenge_path = self.case.keep_json("dash-" + uuid.uuid4().hex[:16] + ".challenge.json", challenge)
        signed = json.loads(self.case.command("dash-sign", [str(self.case.authenticator), "sign", *arguments,
            "--private", str(self.case.human.private), "--challenge", str(challenge_path)], clean=True))
        proof = self.rpc("human.confirm", signed)
        if (not proof.get("id") or proof.get("request_sha256") != intent["request_sha256"]
                or proof.get("expires_at") != challenge.get("expires_at")
                or proof.get("simulated_presence") is not True):
            raise ValueError("browser confirmation did not issue the exact simulated proof")
        return proof


def check_handoff(handoff):
    from fixture_io import FixtureError
    if not isinstance(handoff, HTTPSHandoff):
        raise FixtureError({"code": "prerequisite_missing", "owner": "lb-v2-service",
            "message": "installed native HTTPS listener and dashboard bootstrap handoff absent",
            "instead": "Bind Server.DashboardHandler to the pinned administrator TLS listener and issue the native bootstrap on a live redemption connection."})
    if (not isinstance(handoff.session_process, subprocess.Popen)
            or not isinstance(handoff.listener_process, subprocess.Popen)
            or handoff.session_process.pid == handoff.listener_process.pid
            or handoff.session_process.poll() is not None or handoff.listener_process.poll() is not None
            or not callable(handoff.close_session) or not callable(handoff.close_listener)):
        raise ValueError("HTTPS handoff lacks its two actual live owned child processes")


def collect_https(browser):
    handoff = browser.handoff
    handoff.close_session()
    session_exit = handoff.session_process.wait(timeout=30)
    status, _, raw = browser.consumer.http_call(browser.opener,
        browser.origin + "/api/v2/tree", headers={"Cookie": browser.cookie})
    if status != 401 or not browser.consumer.denied(status, raw, (401,)):
        raise ValueError("cookie retained authority after its native human connection closed")
    handoff.close_listener()
    listener_exit = handoff.listener_process.wait(timeout=30)
    parsed = urllib.parse.urlsplit(browser.origin)
    try:
        connection = socket.create_connection((getattr(handoff, "connect_address", None) or parsed.hostname, parsed.port or 443), timeout=3)
    except OSError as error:
        if error.errno != errno.ECONNREFUSED:
            raise
        listener_errno = error.errno
    else:
        connection.close()
        raise ValueError("HTTPS listener still accepts after collection")
    return {"cookie_after_close_status": status, "listener_errno": listener_errno,
            "listener_pid": handoff.listener_process.pid, "listener_exit": listener_exit,
            "session_pid": handoff.session_process.pid, "session_exit": session_exit}


def run_at_checkpoint(case, context_path, result_path, handoff, data):
    consumer = case_modules(case.source)
    context = json.loads(Path(context_path).read_bytes())
    recorder = consumer.EvidenceRecorder(context["evidence_root"])
    shared_rows, shared_current, shared_prefix = case.rows, case.current, case.human_prefix
    case.rows = {}
    try:
        return _run_checkpoint(case, context_path, result_path, handoff, data)
    except Exception as error:
        failed_row = case.rows.get(case.current, {}).get("observed", {})
        refusal = getattr(error, "error", None) or failed_row.get("refusal") or {
            "owner": "lb-v2-dashboard", "code": "producer_failed", "message": str(error)}
        recorder.save("producer/first-failure.json", {"error": refusal,
            "presence": "simulated", "human_approval": "not_proven"})
        raise
    finally:
        producer_rows, producer_step = case.rows, case.current
        case.rows, case.current, case.human_prefix = shared_rows, shared_current, shared_prefix
        recorder.save("producer/checks.json", {"scope": "dashboard fixture preparation",
            "checks": list(producer_rows.values()), "last_step": producer_step,
            "presence": "simulated", "human_approval": "not_proven"})


def validate_result(result, context, assertion_ids):
    need = (result.get("schema") == "laneboss.e2e-result.v2"
            and result.get("case_id") == context.get("case_id")
            and result.get("binary_sha256") == context.get("binary_sha256")
            and result.get("source_sha256") == context.get("source_sha256")
            and result.get("phase") == context.get("phase", "candidate")
            and result.get("mutation_id") == context.get("mutation_id", ""))
    rows = result.get("assertions", [])
    if (not need or len(rows) != len(assertion_ids) or {r.get("id") for r in rows} != set(assertion_ids)
            or any(r.get("reached") is not True or r.get("verdict") != "pass"
                   or type(r.get("observed_exit")) is not int or r.get("observed_exit") != 0 for r in rows)
            or result.get("collection", {}).get("processes_quiescent") is not True
            or result.get("collection", {}).get("temporary_resources_collected") is not True):
        raise ValueError("installed dashboard result lacks all thirteen exact reached/pass assertions and collection")


def _run_checkpoint(case, context_path, result_path, handoff, data):
    """Run after publication/enrollment, before the shared harness tears down.

    data is DashData prepared with actual launch requests, its L6 actor and
    review inputs. No context fields or installed binary are replaced.
    """
    if sys.platform != "linux":
        raise ValueError("dashboard producer runs only on the isolated Linux install")
    consumer = case_modules(case.source)
    check_handoff(handoff)
    context = json.loads(Path(context_path).read_bytes())
    if (context.get("config") != case.config or context.get("binding_file") != case.installed["binding_file"]
            or Path(context["binary"]) != case.binary
            or consumer.sha256_bytes(case.binary.read_bytes()) != context["binary_sha256"]):
        raise ValueError("dashboard context differs from the installed checkpoint")
    recorder = consumer.EvidenceRecorder(context["evidence_root"])
    browser = Browser(case, consumer, handoff, recorder)
    data.bind(browser, consumer)
    data.stage("bootstrap")
    session = browser.bootstrap()
    case.passed({"session": session, "cookie_verified_by": "actual HTTPS Set-Cookie and authenticated read"})
    data.prepare()
    from fixture_io import private_read, private_write
    root = Path(context["test_root"]) / "dashboard"
    root.mkdir(mode=0o700)
    for name in ("requests", "responses"):
        (root / name).mkdir(mode=0o700)
    controls = root / "controls.json"
    private_write(controls, {"schema": "laneboss.dash-inputs.v2", "config": case.config,
                            "handoff": str(root), "ca_file": str(handoff.ca_file),
                            "binary_sha256": context["binary_sha256"],
                            "source_sha256": context["source_sha256"],
                            "targets": [record["target"] for record in data.records.values()]})
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C",
                   "LANEBOSS_DASHBOARD_URL": browser.origin,
                   "LANEBOSS_DASHBOARD_COOKIE": browser.cookie,
                   "LANEBOSS_DASHBOARD_CONTROLS_FILE": str(controls)}
    entry = Path(case.source) / "e2e/v2/cases/dashboard/run.sh"
    stdout = (root / "case.stdout").open("xb")
    stderr = (root / "case.stderr").open("xb")
    process = subprocess.Popen(["/bin/bash", str(entry), "--context", str(context_path),
        "--result", str(result_path)], stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=environment)
    handled, collected = set(), False
    failure = None
    deadline = time.monotonic() + 1800
    try:
        while process.poll() is None:
            if time.monotonic() >= deadline:
                raise ValueError("dashboard case exceeded its declared deadline")
            for path in sorted((root / "requests").glob("*.json")):
                if path.name in handled:
                    continue
                request = json.loads(private_read(path))
                if (request.get("schema") != "laneboss.dash-handoff.v2"
                        or request.get("config") != case.config
                        or path.stem != request.get("nonce")):
                    raise ValueError("dashboard handoff request differs from its file/configuration")
                response = dict(request)
                try:
                    if request.get("failure"):
                        failure = request["failure"]
                        response["error"] = failure
                    elif failure is not None:
                        response["error"] = failure
                    elif request["kind"] == "cli-proof":
                        proof = case.human.proof("read", "human.session", {}, case.human.public["principal_id"], 0)
                        response["result"] = {"proof_file": str(proof)}
                    elif request["kind"] == "action":
                        response["result"] = {"request_file": str(data.action(request["key"]))}
                    elif request["kind"] == "collect":
                        report = data.collect()
                        report["https"] = collect_https(browser)
                        response["result"], collected = report, True
                    else:
                        raise ValueError("unknown dashboard handoff kind")
                except Exception as error:
                    # No repeat, alternative credential or new mutation follows
                    # a refusal. The exact owner error travels back to the case.
                    failed_row = case.rows.get(case.current, {}).get("observed", {})
                    failure = getattr(error, "error", None) or failed_row.get("refusal") or {"owner": "lb-v2-dashboard",
                        "code": "producer_failed", "message": str(error)}
                    response["error"] = failure
                private_write(root / "responses" / path.name, response)
                handled.add(path.name)
            time.sleep(0.05)
        exit_code = process.wait(timeout=10)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        stdout.close()
        stderr.close()
    recorder.save("producer/summary.json", {"exit": process.returncode, "collected": collected,
        "error": failure, "presence": "simulated", "human_approval": "not_proven"})
    if exit_code != 0 or failure or not collected:
        raise ValueError("dashboard installed case or independent collection failed; preserve exact evidence")
    result = json.loads(Path(result_path).read_bytes())
    validate_result(result, context, consumer.ASSERTION_IDS)
    return result
