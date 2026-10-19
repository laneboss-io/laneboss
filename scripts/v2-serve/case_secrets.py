"""Installed secrets input coordinator; run only on the disposable Linux box.

The serve owner supplies its already enrolled HumanRoot and native setup ports.
There is no alternate identity, proof issuer, vendor login or result generator.
"""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import threading
import time


STEPS = (
    "human-session", "key", "stage-env", "import-env", "stage-file", "import-file",
    "stage-hidden", "import-hidden", "start", "reserved", "wider", "bad-stage",
    "stop", "archive", "restart-locked", "recover", "tamper", "lease-first",
    "lease-second", "release-running", "release-quiet",
)
METHODS = {name: "lane.start" for name in STEPS}
METHODS.update({"human-session": "human.session", "key": "secret.key",
                "stop": "lane.stop", "archive": "lane.archive",
                "release-running": "lane.clean", "release-quiet": "lane.clean"})
for _kind in ("env", "file", "hidden"):
    METHODS["stage-" + _kind] = "secret.stage"
    METHODS["import-" + _kind] = "secret.import"
METHODS["bad-stage"] = "secret.import"


class MissingSetup(RuntimeError):
    """A fixed prerequisite name; its record never claims completion."""

    def __init__(self, step):
        self.step = step
        super().__init__("installed secrets prerequisite is missing")

    def record(self):
        return {"schema": "laneboss.secret-setup-wait.v1", "code": "prerequisite_missing",
                "step": self.step, "completed": False}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path, maximum=1048576):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, "ordinary absolute input required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600 and
                0 < info.st_size <= maximum, "private bounded input required")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        require(len(raw) == info.st_size and info.st_mtime_ns == after.st_mtime_ns and
                info.st_size == after.st_size, "private input changed")
        return raw


def put(path, data):
    path = Path(path)
    pending = path.with_name(path.name + ".pending")
    require(not path.exists() and not path.is_symlink(), "preserve existing case input")
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    # Link publishes atomically without replacing an input raced into place.
    os.link(pending, path, follow_symlinks=False)
    pending.unlink()


def document(path, value):
    put(path, json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n")


def directory(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, "ordinary absolute directory required")
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == 0o700, "private case directory required")
    return path


def prepare(context, baseline, targets, defer_baseline=False, hidden_source=None):
    """Retain private random sources and every retry key before any mutation."""
    require(sys.platform == "linux", "secrets preparation requires disposable Linux")
    require(defer_baseline or isinstance(baseline, bytes) and baseline, "actual reserved baseline is missing")
    root = directory(context["test_root"])
    private = root / "secret-inputs"
    private.mkdir(mode=0o700)
    canaries = {"env": secrets.token_hex(48).encode(), "file": secrets.token_bytes(96),
                "undelegated": secrets.token_hex(48).encode()}
    if hidden_source is not None:
        canaries["undelegated"] = read(hidden_source, 65536)
        require(len(canaries["undelegated"]) >= 32, "prepared hidden source lacks a private random canary")
    files = {}
    for name, data in canaries.items():
        selected = private / (name + ".private")
        put(selected, data)
        files[name] = str(selected.relative_to(root))
    plan = {"env_name": targets["env_name"], "env_sha256": sha(canaries["env"]),
            "file_path": targets["file_path"], "file_sha256": sha(canaries["file"]),
            "hidden_env_names": [targets["hidden_env_name"]],
            "hidden_file_paths": [str(private / "undelegated.private")],
            "reserved_env_name": targets["reserved_env_name"]}
    if not defer_baseline:
        plan["reserved_sha256"] = sha(baseline)
    document(private / ("probe-plan.pending.json" if defer_baseline else "probe-plan.json"), plan)
    probe = Path(__file__).resolve().parents[2] / "e2e/v2/cases/secrets/probe.py"
    source = probe.read_bytes()
    put(private / "probe.py", source)
    document(private / "probe-source.json", {"sha256": sha(source), "bytes": len(source)})
    steps = []
    for index, name in enumerate(STEPS):
        step = {"name": name, "method": METHODS[name],
                "request": "secret-inputs/%02d.request.json" % index}
        if name != "key":
            step["idempotency_key"] = secrets.token_hex(16)
        if name not in {"key", "stage-env", "stage-file", "stage-hidden"}:
            step["proof"] = "secret-inputs/%02d.proof.json" % index
        steps.append(step)
    fixture = {"schema": "laneboss.e2e-secrets.v2", "canary_files": files, "steps": steps,
               "observations": {"injection": "injection.json", "credential": "credential.json",
                   "events": "events.jsonl", "archive": "archive.tar",
                   "injection_capture": "injection.capture", "credential_capture": "credential.capture",
                   "collection": "collection.json"}}
    document(root / "secrets-fixture.json", fixture)
    return fixture


class Coordinator:
    """Release a dependency only after validating its retained actual reply.

    prove(method, body, target, generation) returns a genuine service proof file.
    setup(name, state) performs the suite's native preparation and returns an
    exact request plus its actual target/generation. It never returns verdicts.
    In particular restart/recover/tamper and credential inputs are not guessed.
    """

    def __init__(self, context, fixture, prove, setup, sealer, principal_id=None, sealer_sha256=None):
        self.context, self.fixture = context, fixture
        self.root, self.evidence = directory(context["test_root"]), directory(context["evidence_root"])
        self.prove, self.setup = prove, setup
        self.principal_id = principal_id
        self.sealer = Path(sealer)
        self.sealer_sha256 = sealer_sha256
        self.responses, self.requests, self.done = {}, {}, set()
        self.stopping = threading.Event()
        self.failure = None
        self.thread = None

    def release(self, step, body, target=None, generation=0):
        require(isinstance(body, dict), "setup did not produce a typed request")
        if step.get("proof"):
            if self.prove is None:
                raise MissingSetup("human_confirmation")
            method = "human.session" if step["method"] == "lane.start" else step["method"]
            intent = {} if method == "human.session" else body
            if method == "human.session":
                require(self.principal_id, "actual enrolled human principal is missing")
                target, generation = self.principal_id, 0
            proof = self.prove(method, intent, target, generation)
            raw = read(Path(proof))
            value = json.loads(raw)
            require(value.get("id") and value.get("request_sha256") and value.get("expires_at"),
                    "human confirmation omitted its service proof")
            put(self.root / step["proof"], raw)
        document(self.root / step["request"], body)
        self.requests[step["name"]] = body
        self.done.add(step["name"])

    def seal(self, key, kind):
        if self.sealer_sha256 is None:
            raise MissingSetup("sealed_upload_binary")
        require(self.sealer.is_absolute() and self.sealer.resolve() == self.sealer,
                "sealed upload executable is not canonical")
        info = self.sealer.stat()
        require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o022 and info.st_size <= 16777216,
                "sealed upload executable is mutable or oversized")
        binary = self.sealer.read_bytes()
        require(sha(binary) == self.sealer_sha256, "sealed upload executable digest differs")
        retained = self.evidence / "secret-seal.bin"
        if not retained.exists():
            put(retained, binary)
        require(sha(read(retained, 16777216)) == self.sealer_sha256, "retained sealed upload executable differs")
        source = "undelegated" if kind == "hidden" else kind
        metadata = {"config": self.context["config"], "name": "canary-" + kind,
                    "version": "v1", "key": key,
                    "material": str(self.root / self.fixture["canary_files"][source])}
        path = self.root / ("secret-inputs/seal-" + kind + ".json")
        document(path, metadata)
        completed = subprocess.run([str(self.sealer), str(path)], capture_output=True,
                                   timeout=30, check=False,
                                   env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        put(self.evidence / ("seal-" + kind + ".out"), completed.stdout)
        put(self.evidence / ("seal-" + kind + ".err"), completed.stderr)
        document(self.evidence / ("seal-" + kind + ".exit.json"), {"exit": completed.returncode})
        require(completed.returncode == 0, "sealed upload producer refused")
        result = json.loads(completed.stdout)
        require(result.get("key_id") == key["id"] and result.get("name") == metadata["name"] and
                result.get("version") == metadata["version"] and
                len(base64.b64decode(result["nonce"], validate=True)) == 12 and
                len(base64.b64decode(result["ephemeral_public_key"], validate=True)) == 32,
                "sealed upload differs from the actual advertised key")
        return result

    def observe_flow(self):
        path = self.evidence / "human-flow.json"
        if not path.exists():
            return
        rows = json.loads(read(path))
        require(isinstance(rows, list) and len(rows) <= 8, "invalid persistent flow handoff")
        for index, row in enumerate(rows):
            name = STEPS[index]
            require(row["name"] == name and name in self.done, "flow response precedes its released input")
            retained = {}
            for field in ("request", "response"):
                ref = row[field]
                require(Path(ref["path"]).name == ref["path"], "nonlocal persistent flow evidence")
                raw = read(self.evidence / ref["path"])
                require(sha(raw) == ref["sha256"] and len(raw) == ref["bytes"], "flow handoff hash differs")
                retained[field] = json.loads(raw)
            request, response = retained["request"], retained["response"]
            require(request.get("config") == self.context["config"] and request.get("method") == METHODS[name] and
                    request.get("params") == self.requests[name] and
                    response.get("request_id") == request.get("request_id") and
                    response.get("protocol") == "laneboss.rpc.v2" and response.get("schema") == 2 and
                    "error" not in response and isinstance(response.get("result"), dict),
                    "persistent flow refused or changed its exact request")
            raw_input = read(self.root / self.fixture["steps"][index]["request"])
            require(sha(raw_input) == row["input_sha256"], "flow input changed after release")
            if name in self.responses:
                require(self.responses[name] == response["result"], "persistent response was rewritten")
            self.responses[name] = response["result"]

    def next_flow(self):
        for index in range(8):
            name = STEPS[index]
            if name in self.done:
                continue
            if index and STEPS[index - 1] not in self.responses:
                return
            step = self.fixture["steps"][index]
            if index < 2:
                self.release(step, {}, self.principal_id)
            elif name.startswith("stage-"):
                self.release(step, self.seal(self.responses["key"], name[6:]))
            else:
                stage = self.responses[STEPS[index - 1]]
                require(stage.get("id") and stage.get("name") == "canary-" + name[7:] and stage.get("version") == "v1",
                        "actual stage receipt differs from its import")
                self.release(step, {"name": stage["name"], "version": stage["version"],
                                    "sealed_upload_id": stage["id"]}, self.context["config"])
            return

    def later(self):
        next_path = self.evidence / "next-step.json"
        if not next_path.exists():
            return
        selected = json.loads(read(next_path))
        index = selected.get("index")
        require(type(index) is int and 8 <= index < len(STEPS) and
                selected.get("name") == STEPS[index] and selected.get("method") == METHODS[STEPS[index]],
                "consumer requested an unrelated setup step")
        step = self.fixture["steps"][index]
        name = step["name"]
        if name in self.done:
            return
        path = self.evidence / "cli-transcript.json"
        rows = json.loads(read(path)) if path.exists() else []
        for row in rows:
            if "step" not in row:
                continue
            prior = row["step"]
            require(prior in self.done, "CLI response precedes a released intent")
            number = STEPS.index(prior)
            raw = read(self.evidence / ("cli-%d.out" % number)) if row["exit"] == 0 else read(
                self.evidence / ("cli-%d.err" % number))
            field = "stdout_sha256" if row["exit"] == 0 else "stderr_sha256"
            require(sha(raw) == row[field] and row["method"] == METHODS[prior] and
                    sha(read(self.root / self.fixture["steps"][number]["request"])) == row["request_sha256"],
                    "CLI handoff changed its actual input or output")
            self.responses[prior] = json.loads(raw)
        # Credential setup starts only when the consumer reaches that group,
        # including after a failed secret group; no secret verdict is required.
        if self.setup is None:
            raise MissingSetup("native_" + name)
        prepared = self.setup(name, {"responses": dict(self.responses), "requests": dict(self.requests),
                                     "transcript": rows, "fixture": self.fixture})
        require(isinstance(prepared, dict) and set(prepared) == {"request", "target", "generation"},
                "native setup must return an exact intent, not a verdict")
        self.release(step, prepared["request"], prepared["target"], prepared["generation"])

    def run(self):
        deadline = time.monotonic() + 1500
        try:
            while not self.stopping.is_set():
                require(time.monotonic() < deadline, "secrets coordinator deadline")
                self.observe_flow()
                self.next_flow()
                self.later()
                if len(self.done) == len(STEPS):
                    return
                self.stopping.wait(0.2)
        except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError, MissingSetup) as error:
            self.failure = error
            record = (error.record() if isinstance(error, MissingSetup) else
                      {"schema": "laneboss.secret-coordinator.v1", "completed": False,
                       "code": "integrity", "step": "retained_dependency"})
            document(self.evidence / "coordinator-stop.json", record)

    def start(self):
        self.thread = threading.Thread(target=self.run, name="secret-inputs", daemon=False)
        self.thread.start()

    def stop(self):
        self.stopping.set()
        if self.thread is not None:
            self.thread.join(timeout=35)
            require(not self.thread.is_alive(), "secrets coordinator did not stop")


def run_installed(context_path, result_path, *, sealer, prove=None, setup=None, principal_id=None, sealer_sha256=None):
    """Case-owned suite hook. The shared exporter remains owned by grants."""
    context = json.loads(read(Path(context_path)))
    require(context.get("case_id") == "secrets", "wrong installed case context")
    source = Path(__file__).resolve().parents[2] / "e2e/v2/cases/secrets/run.py"
    command = [sys.executable, "-I", "-B", str(source), "--context", str(context_path), "--result", str(result_path)]
    # Do not turn [] into a fixture profile or relax the live-auth manifest.
    # The consumer writes its exact vendor_authentication owner wait first.
    if not context["profile_grant_ids"]:
        return subprocess.run(command, check=False, timeout=60).returncode
    fixture = json.loads(read(Path(context["test_root"]) / "secrets-fixture.json"))
    coordinator = Coordinator(context, fixture, prove, setup, sealer, principal_id, sealer_sha256)
    coordinator.start()
    try:
        deadline = time.monotonic() + 120
        first = fixture["steps"][0]
        while not all((Path(context["test_root"]) / first[field]).is_file() for field in ("request", "proof")):
            if coordinator.failure is not None:
                raise coordinator.failure
            require(time.monotonic() < deadline, "initial genuine human confirmation deadline")
            coordinator.stopping.wait(0.2)
        code = subprocess.run(command, check=False, timeout=1800).returncode
        require(coordinator.failure is None, "installed secrets coordinator stopped")
        return code
    finally:
        coordinator.stop()


class InstalledHuman:
    """File-backed software-device ceremony through the installed human CLI."""

    def __init__(self, context, enrollment):
        self.context, self.enrollment = context, enrollment
        self.root = directory(context["evidence_root"]) / "secret-authority"
        self.root.mkdir(mode=0o700)
        self.index = 0
        self.public = json.loads(read(Path(enrollment["public"])))
        require(self.public.get("config") == context["config"] and self.public.get("principal_id") and
                self.public.get("credential_id") and self.public.get("presence") == "simulated",
                "actual software-device enrollment descriptor differs")
        binary = Path(enrollment["binary"])
        require(binary.is_absolute() and binary.resolve() == binary and
                sha(binary.read_bytes()) == enrollment["sha256"], "authenticator executable pin differs")

    def command(self, label, argv):
        self.index += 1
        stem = "%04d-%s" % (self.index, label)
        document(self.root / (stem + ".argv.json"), argv)
        completed = subprocess.run(argv, capture_output=True, timeout=60, check=False,
                                   env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        for suffix, raw in (("out", completed.stdout), ("err", completed.stderr)):
            put(self.root / (stem + "." + suffix), raw)
        document(self.root / (stem + ".exit.json"), {"exit": completed.returncode})
        require(completed.returncode == 0, "installed human ceremony refused; retain exact command evidence")
        return json.loads(completed.stdout), self.root / (stem + ".out")

    def rpc(self, method, body):
        path = self.root / ("%04d.request.json" % (self.index + 1))
        document(path, body)
        return self.command(method.replace(".", "-"), [self.context["binary"], *method.split("."),
            "--config", self.context["config"], "--binding", self.context["binding_file"],
            "--request", str(path), "--idempotency-key", secrets.token_hex(16)])

    def prove(self, method, body, target, generation):
        path = self.root / ("%04d.operation.json" % (self.index + 1))
        document(path, body)
        arguments = ["--config", self.context["config"], "--operation", str(path), "--method", method,
                     "--target", target, "--generation", str(generation)]
        intent, _ = self.command("intent", [self.enrollment["binary"], "intent", *arguments])
        challenge, challenge_path = self.rpc("human.challenge", intent)
        require(all(challenge.get(field) == intent.get(field) for field in
                    ("method", "target_id", "request_sha256", "base_generation")) and
                challenge.get("config") == self.context["config"] and challenge.get("id") and
                challenge.get("origin") == self.public["origin"] and challenge.get("rp_id") == self.public["rp_id"],
                "service challenge differs from the exact enrolled intent")
        assertion, _ = self.command("sign", [self.enrollment["binary"], "sign", *arguments,
            "--private", self.enrollment["private"], "--challenge", str(challenge_path)])
        require(assertion.get("challenge_id") == challenge["id"] and
                assertion.get("credential_id") == self.public["credential_id"], "assertion belongs to another challenge")
        proof, proof_path = self.rpc("human.confirm", assertion)
        require(proof.get("id") and proof.get("request_sha256") == intent["request_sha256"] and
                proof.get("expires_at") == challenge["expires_at"] and proof.get("simulated_presence") is True,
                "service confirmation differs from the signed operation")
        return proof_path


def preparation(context, fixture, human, sealer):
    """A separate diagnostic. It cannot evaluate either full-case assertion."""
    consumer_path = Path(__file__).resolve().parents[2] / "e2e/v2/cases/secrets/run.py"
    spec = importlib.util.spec_from_file_location("secret_preparation_consumer", consumer_path)
    consumer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(consumer)
    canaries = {name: read(Path(context["test_root"]) / path, 65536)
                for name, path in fixture["canary_files"].items()}
    coordinator = Coordinator(context, fixture, human.prove, None, sealer["path"],
                              human.public["principal_id"], sealer["sha256"])
    observed = {"assertions": [{"evidence": []}]}
    coordinator.start()
    try:
        first = fixture["steps"][0]
        deadline = time.monotonic() + 120
        while not (Path(context["test_root"]) / first["request"]).exists():
            if coordinator.failure is not None:
                raise coordinator.failure
            require(time.monotonic() < deadline, "initial genuine human confirmation deadline")
            coordinator.stopping.wait(0.2)
        receipts, _ = consumer.human_flow(context, fixture, fixture["steps"], consumer.variants(canaries), observed)
        require(coordinator.failure is None and len(receipts) == 8, "same-connection preparation did not complete")
        document(Path(context["evidence_root"]) / "preparation.json", {
            "schema": "laneboss.secret-preparation.v1", "scope": "same-connection sealed import and metadata only",
            "completed": True, "acceptance_evaluated": False, "simulated_presence": True,
            "human_approval": "not_proven", "evidence": observed["assertions"][0]["evidence"]})
    except consumer.CASE_ERRORS:
        document(Path(context["evidence_root"]) / "preparation.failed.json", {
            "schema": "laneboss.secret-preparation.v1", "completed": False, "acceptance_evaluated": False,
            "observation": observed["assertions"][0]})
        raise ValueError("installed sealed preparation refused; retain primary evidence") from None
    finally:
        coordinator.stop()


def incomplete(context, result_path, step):
    evidence = directory(context["evidence_root"])
    require(result_path.is_absolute() and result_path.parent == evidence, "result must be inside its evidence scope")
    path = evidence / "native-setup.wait.json"
    document(path, MissingSetup(step).record())
    raw = read(path)
    reference = {"path": path.name, "sha256": sha(raw), "bytes": len(raw)}
    document(result_path, {"schema": "laneboss.e2e-result.v2", "case_id": "secrets",
        **{key: context[key] for key in ("phase", "mutation_id", "binary_sha256", "source_sha256")},
        "assertions": [{"id": name, "reached": False, "verdict": "fail", "observed_exit": 69,
                        "evidence": [reference]} for name in ("SECRET-INJECT", "CREDENTIAL-BOUND")],
        "collection": {"processes_quiescent": False, "temporary_resources_collected": False, "evidence": []}})
    return 69


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--prepare-session", action="store_true")
    args = parser.parse_args()
    require(sys.platform == "linux", "installed secrets requires disposable Linux")
    context, inputs = json.loads(read(args.context)), json.loads(read(args.inputs))
    require(context.get("schema") == "laneboss.e2e-context.v2" and context.get("case_id") == "secrets" and
            inputs.get("schema") == "laneboss.secret-inputs.v1" and inputs.get("config") == context["config"] and
            inputs.get("binary_sha256") == context["binary_sha256"], "installed secrets inputs belong to another binding")
    binary = Path(context["binary"])
    require(binary.is_absolute() and binary.resolve() == binary and
            sha(binary.read_bytes()) == context["binary_sha256"], "installed executable pin differs")
    fixture = prepare(context, read(Path(inputs["reserved_baseline"])), inputs["targets"])
    if args.prepare_session:
        human = InstalledHuman(context, inputs["human"])
        preparation(context, fixture, human, inputs["sealer"])
    # This standalone path deliberately has no live native setup authority.
    # A published suite adapter must provide it through run_installed's hook.
    if context["profile_grant_ids"]:
        return incomplete(context, args.result, "native_setup")
    return run_installed(args.context, args.result, sealer=inputs["sealer"]["path"])


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (MissingSetup, ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError):
        print("secrets setup stopped; retain private inputs and exact ceremony evidence", file=sys.stderr)
        sys.exit(69)
