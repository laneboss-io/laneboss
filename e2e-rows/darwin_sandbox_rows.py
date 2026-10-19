#!/usr/bin/env python3
"""Owner-only Terminal.app proof for the macOS option A sandbox composition.

Never execute this sheet from an agent's already-sandboxed process. All clients
are stand-ins; the supplied tagged launcher and ordinary tools are real. Every
row retains its temporary HOME, source inputs, launcher responses and exits.
"""

import argparse
import errno
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid


POLICY = "runner sandbox: replaced by laneboss lane sandbox"
ORDINARY = {"runner-session", "go-test", "go-build", "git-commit", "tmp", "cache", "curl-local"}


class RowFailure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise RowFailure(message)


class Row:
    def __init__(self, binary, evidence, provider, mutation="", external_org=False):
        self.binary = binary
        self.provider = provider
        self.mutation = mutation
        self.native = mutation.startswith("native")
        self.external_org = external_org
        self.root = Path(tempfile.mkdtemp(prefix="lb-svc-sandbox-" + provider + "-", dir=evidence)).resolve()
        self.home = self.root / "home"
        self.home.mkdir()
        self.output = self.root / "evidence"
        self.output.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.real_tmux = shutil.which("tmux")
        require(self.real_tmux is not None, "required ordinary-work tool is unavailable: tmux")
        for name in ("git", "go", "curl", "python3"):
            source = shutil.which(name)
            require(source is not None, "required ordinary-work tool is unavailable: " + name)
            (self.bin / name).symlink_to(source)
        standin = Path(__file__).with_name("sandbox_standin.py")
        tmux = self.bin / "tmux"
        tmux.write_bytes(Path(__file__).with_name("sandbox_tmux.py").read_bytes())
        tmux.chmod(0o755)
        for name in ("codex", "claude", "claudock"):
            destination = self.bin / name
            destination.write_bytes(standin.read_bytes())
            destination.chmod(0o755)
        self.environment = {"HOME": str(self.home), "PATH": str(self.bin) + ":/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                            "LANEBOSS_HOME": str(self.home / "config"), "LANEBOSS_STATE_HOME": str(self.home / "state"),
                            "LANEBOSS_TEST_CLAIMS_DIR": str(self.home / "claims"), "GOTOOLCHAIN": "local",
                            "GOCACHE": str(evidence / "go-cache")}
        self.config = "sandbox-" + uuid.uuid4().hex[:10]
        self.lane = "lb-svc-sandbox-" + uuid.uuid4().hex[:10]
        self.repository = self.home / "repo"
        self.repository.mkdir()
        self.calls = 0
        self.server = None

    def call(self, name, arguments, expected=0, cwd=None):
        self.calls += 1
        stem = self.output / ("%03d-%s" % (self.calls, name))
        result = subprocess.run([str(x) for x in arguments], cwd=cwd or self.repository, env=self.environment,
                                capture_output=True, timeout=90)
        stem.with_suffix(".stdout").write_bytes(result.stdout)
        stem.with_suffix(".stderr").write_bytes(result.stderr)
        stem.with_suffix(".json").write_text(json.dumps({"argv": [str(x) for x in arguments], "exit_code": result.returncode}) + "\n")
        require(result.returncode == expected, name + " exited " + str(result.returncode) + "; retained stderr names the cause")
        return result

    def cli(self, name, *arguments):
        return self.call(name, [self.binary, *arguments])

    def setup(self):
        fixture = Path(__file__).resolve().parent.parent / "internal/lanesandbox" / "testdata/ordinary-go"
        for filename in ("go.mod", "main.go", "main_test.go"):
            (self.repository / filename).write_bytes((fixture / filename).read_bytes())
        self.call("git-init", ["git", "init", "--initial-branch=lb-svc-sandbox-fixture"])
        self.call("git-initial-add", ["git", "add", "go.mod", "main.go", "main_test.go"])
        self.call("git-initial-commit", ["git", "-c", "user.name=Sandbox fixture", "-c", "user.email=fixture.invalid",
                                         "commit", "-m", "Create the disposable sandbox fixture"])
        initial_head = self.call("git-initial-head", ["git", "rev-parse", "HEAD"]).stdout.decode().strip()
        org = (self.root / "external-org" if self.external_org else
               Path(self.environment["LANEBOSS_HOME"]) / "orgs" / "sandbox-fixture")
        org.parent.mkdir(parents=True, exist_ok=True)
        initialized = json.loads(self.cli("org-init", "org", "init", org, "--levels", "3-6", "--name", "sandbox-fixture").stdout)
        require(initialized.get("ok") is True, "org init did not create the fixture")
        instance = org / ".laneboss/instances/L3-lane-example"
        self.source_settings = instance / ".claude/settings.json"
        settings = json.loads(self.source_settings.read_text())
        settings["sandbox"] = {"enabled": True, "allowUnsandboxedCommands": False}
        self.source_settings.chmod(0o600)
        self.source_settings.write_text(json.dumps(settings) + "\n")
        if self.mutation == "native-unconditional":
            self.environment["LANEBOSS_FAULTS"] = json.dumps({"point": "sandbox-unconditional",
                                                            "marker": str(self.output / "unconditional-reached")})
        rendered = json.loads(self.cli("org-render", "org", "render", org).stdout)
        require(rendered.get("ok") is True, "fixture org was not rendered")
        self.source_bytes = self.source_settings.read_bytes()
        self.source_enabled = json.loads(self.source_bytes).get("sandbox", {}).get("enabled")
        if self.provider == "codex":
            command = ["env", "CODEX_HOME=" + str(instance / ".codex"), "codex", "exec", "--model", "{model}"]
        elif self.provider == "claude":
            command = ["claude", "-p", "--settings", str(instance / ".claude/settings.json"), "--model", "{model}"]
        else:
            command = ["claudock", "run", "{account}", "--", "-p", "--settings", str(instance / ".claude/settings.json"), "--model", "{model}"]
        directory = Path(self.environment["LANEBOSS_HOME"]) / "configs" / self.config
        (directory / "projects").mkdir(parents=True)
        extra = [str(self.home)] if self.mutation == "broad-home" else []
        mode = "off" if self.native and sys.platform == "darwin" else "laneboss-files"
        text = "\n".join(["schema_version = 1", "name = " + json.dumps(self.config), "org_dir = " + json.dumps(str(org)),
                            "[lanes]", "sandbox = " + json.dumps(mode), "sandbox_deny_extra = " + json.dumps(extra),
                            "budget_minutes = 2", "[runners.fixture]", "command = " + json.dumps(command), "prompt = \"stdin\"",
                            "accounts = [\"fixture\"]" if self.provider == "claudock" else "accounts = []",
                            "[supervisors.top]", "level = 5", "runner = \"fixture\"", "[[routing.standard]]",
                            "runner = \"fixture\"", "model = \"fixture-model-1\""]) + "\n"
        (directory / "config.toml").write_text(text)
        (directory / "projects/demo.toml").write_text("schema_version = 1\nname = \"demo\"\nrepository = " + json.dumps(str(self.repository)) + "\n")
        validated = json.loads(self.cli("config-validate", "config", "validate", self.config).stdout)
        require(validated.get("valid") is True, "fixture configuration is invalid")
        self.cli("register-parent", "start", "--config", self.config, "--role", "top", "--format", "json")
        paths = json.loads(self.cli("config-path", "config", "path", self.config).stdout)
        self.state = Path(paths["state_dir"])
        expected_socket = Path("/tmp") / ("laneboss-" + str(os.getuid())) / (
            self.config + "-" + hashlib.sha256(str(self.state).encode()).hexdigest()[:12])
        self.socket = str(expected_socket)
        require(paths.get("socket") == self.socket, "config path did not report the isolated row socket")
        self.tmux_trace = self.output / "tmux-trace.jsonl"
        (self.bin / "tmux-spec.json").write_text(json.dumps({"socket": self.socket, "trace": str(self.tmux_trace),
                                                           "program": self.real_tmux}) + "\n")
        self.worktree = Path(str(self.repository) + "-" + self.lane)
        nonce = uuid.uuid4().hex
        settings_file = instance / (".codex/hooks.json" if self.provider == "codex" else ".claude/settings.json")
        targets = {"org-hooks": settings_file, "launcher-state": self.state / "lane-sandbox-canary",
                   "other-state": Path(self.environment["LANEBOSS_STATE_HOME"]) / "another-config" / "lane-sandbox-canary",
                   "launcher-home": Path(self.environment["LANEBOSS_HOME"]) / "another-config-canary"}
        if self.external_org:
            targets.update({"org-definition": org / ".laneboss/org.toml", "instance-definition": instance / "instance.toml"})
        if self.native:
            targets = {}
        protected = {}
        for name, path in targets.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            before = path.read_text() if path.exists() else "before:" + nonce
            after = "after:" + nonce
            path.write_text(before)
            path.chmod(0o600)
            # A same-account unsandboxed control must actually write each target.
            path.write_text(after)
            require(path.read_text() == after, "unsandboxed protected-file control failed")
            path.write_text(before)
            protected[name] = {"path": str(path), "before": before, "after": after}
        class QuietHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, format, *arguments):
                return
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(QuietHandler, directory=str(self.repository)))
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        spec = {"worktree": str(self.worktree), "evidence": str(self.output), "nonce": nonce, "protected": protected,
                "initial_head": initial_head,
                "tmp_file": str(Path("/tmp") / (self.lane + ".proof")), "cache_file": str(self.home / ".cache" / "sandbox-row"),
                "url": "http://127.0.0.1:" + str(self.server.server_port) + "/main.go", "curl_source": str(self.repository / "main.go")}
        self.spec = spec
        spec_path = self.root / "row-spec.json"
        spec_path.write_text(json.dumps(spec, indent=2) + "\n")
        brief = self.root / "brief.md"
        brief.write_text("# Sandbox ordinary work\n\nSANDBOX_ROW_SPEC=" + str(spec_path) + "\n")
        points = {"drop-denies": "sandbox-drop-denies", "drop-home": "sandbox-drop-home", "empty-home": "sandbox-empty-home"}
        if self.mutation in points:
            self.environment["LANEBOSS_FAULTS"] = json.dumps({"point": points[self.mutation], "marker": str(self.output / (self.mutation + "-reached"))})
        self.brief = brief

    def execute(self):
        try:
            self.setup()
            started = json.loads(self.cli("lane-start", "lane", "start", "--config", self.config, "--project", "demo",
                                          "--lane", self.lane, "--role", "executor", "--difficulty", "standard", "--brief", self.brief, "--budget", "2").stdout)
            expected_policy = None if self.native else POLICY
            require(started.get("runner_sandbox") == expected_policy, "start response recorded the wrong sandbox policy")
            deadline = time.monotonic() + 180
            while True:
                status = json.loads(self.cli("lane-status", "lane", "status", "--config", self.config, "--lane", self.lane).stdout)
                live = status.get("live", {})
                supervisor = live.get("supervisor") or {}
                if (status.get("running") is False and supervisor.get("alive") is False
                        and live.get("session_alive") is False and live.get("survivors") == 0):
                    break
                require(time.monotonic() < deadline, "lane did not become quiescent")
                time.sleep(0.25)
            require(status.get("runner_sandbox") == expected_policy, "status recorded the wrong sandbox policy")
            require(status.get("reason") == "exit", "lane did not end by runner exit")
            require(live.get("pending_events") == 0 and live.get("refused_events") == 0, "lane has uncollected or refused events")
            events = self.cli("event-list", "event", "tail", "--config", self.config, "--lane", self.lane).stdout
            parsed = [json.loads(line) for line in events.splitlines() if line]
            starts = [event for event in parsed if event.get("kind") == "lane.started"]
            require(len(starts) == 1 and starts[0]["payload"].get("runner_sandbox") == expected_policy, "start event recorded the wrong sandbox policy")
            require(starts[0]["payload"]["session"]["socket"] == self.socket
                    and live.get("session", {}).get("socket") == self.socket, "lane did not use its isolated tmux socket")
            trace = [json.loads(line) for line in self.tmux_trace.read_text().splitlines()]
            require(trace and all(entry["socket"] == self.socket and entry["config"] == os.devnull for entry in trace)
                    and any(entry["command"] == "new-session" for entry in trace), "real tmux trace did not prove server isolation")
            output = (self.state / "lanes" / self.lane / "output.log").read_text()
            records = [json.loads(line.split("=", 1)[1]) for line in output.splitlines() if line.startswith("SANDBOX_ROW_RESULT=")]
            if self.mutation == "empty-home":
                refused = status.get("exit_code") == 125 and not records and "STANDIN sandbox" not in output
                require((self.output / "empty-home-reached").is_file(), "empty-home input mutation was not reached")
                require(refused, "empty launcher home did not refuse the full-access runner")
                return {"empty_home_refused": refused}
            require(len(records) == 1 and records[0].get("entered") is True, "runner did not execute; this is a setup or sandbox_apply failure")
            result = records[0]
            if self.native:
                ordinary = set(result["ordinary"]) == ORDINARY and all(result["ordinary"].values()) and status.get("exit_code") == 0
                require(ordinary, "native preservation row did not finish ordinary work")
                if self.mutation == "native-unconditional":
                    require((self.output / "unconditional-reached").is_file(), "unconditional-render mutant was not reached")
                if sys.platform.startswith("linux") and result.get("own_sandbox_disabled") is False:
                    require((result.get("own_landlock_abi") or 0) > 0, "Linux native runner did not apply its own Landlock")
                preserved = (self.source_enabled is True and result.get("own_sandbox_disabled") is False
                             and self.source_settings.read_bytes() == self.source_bytes)
                return {"native_preserved": preserved, "ordinary": ordinary,
                        "own_sandbox_disabled": result.get("own_sandbox_disabled"), "tmux_isolated": True}
            require(result.get("own_sandbox_disabled") is True, "runner's own macOS sandbox remained enabled")
            if self.provider in ("claude", "claudock"):
                require(self.source_enabled is True, "org render did not preserve the source sandbox setting")
            if self.mutation == "drop-denies":
                require((self.output / "drop-denies-reached").is_file(), "drop-denies mutant was not reached")
            if self.mutation == "drop-home":
                require((self.output / "drop-home-reached").is_file(), "drop-home mutant was not reached")
            protected = all(result["protection"].get(name, {}).get("denied") is True and Path(entry["path"]).read_text() == entry["before"]
                            for name, entry in self.spec["protected"].items())
            ordinary = set(result["ordinary"]) == ORDINARY and all(result["ordinary"].values()) and status.get("exit_code") == 0
            (self.output / "verdict.json").write_text(json.dumps({"protection": protected, "ordinary": ordinary, "runner_own_sandbox_off": True}, indent=2) + "\n")
            other_configuration = all(result["protection"].get(name, {}).get("denied") is True
                                      and Path(self.spec["protected"][name]["path"]).read_text() == self.spec["protected"][name]["before"]
                                      for name in ("other-state", "launcher-home"))
            written = [name for name, entry in self.spec["protected"].items()
                       if result["protection"].get(name, {}).get("denied") is False
                       and Path(entry["path"]).read_text() == entry["after"]]
            selected_protected = all(result["protection"].get(name, {}).get("denied") is True
                                     and Path(self.spec["protected"][name]["path"]).read_text() == self.spec["protected"][name]["before"]
                                     for name in ("org-hooks", "launcher-state"))
            return {"protection": protected, "ordinary": ordinary, "other_configuration": other_configuration,
                    "written": sorted(written), "selected_protected": selected_protected,
                    "ordinary_failure": result.get("ordinary_failure"), "tmux_isolated": True}
        finally:
            if self.server is not None:
                self.server.shutdown()
                self.server.server_close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True, help="absolute laneboss_faults launcher")
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--case", choices=("codex", "claude", "claudock"), help=argparse.SUPPRESS)
    parser.add_argument("--mutation", choices=("", "drop-denies", "broad-home", "drop-home", "empty-home", "native", "native-unconditional"), default="", help=argparse.SUPPRESS)
    parser.add_argument("--external-org", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--native-only", action="store_true", help="Linux-box Claude preservation control and mutant")
    arguments = parser.parse_args()
    require(sys.platform == "darwin" or (arguments.native_only and sys.platform.startswith("linux")),
            "Darwin owner sheet or authorized Linux native preservation row required")
    require(not os.environ.get("LANEBOSS_CONFIG"), "use a separate unbound owner Terminal session")
    binary = arguments.binary.resolve()
    require(binary.is_file() and os.access(binary, os.X_OK), "supplied launcher is not executable")
    evidence = arguments.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    if arguments.case:
        verdict = Row(binary, evidence, arguments.case, arguments.mutation, arguments.external_org).execute()
        print(json.dumps(verdict))
        return
    inputs = evidence / ("inputs-" + uuid.uuid4().hex[:10])
    inputs.mkdir()
    source = Path(__file__).resolve().parent.parent
    input_files = [Path("e2e-rows") / name for name in ("darwin_sandbox_rows.py", "sandbox_standin.py", "sandbox_tmux.py")]
    input_files.extend(Path("internal/lanesandbox") / "testdata/ordinary-go" / name
                       for name in ("go.mod", "main.go", "main_test.go"))
    manifest = {}
    for relative in input_files:
        destination = inputs / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        data = (source / relative).read_bytes()
        destination.write_bytes(data)
        manifest[str(relative)] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    data = binary.read_bytes()
    binary = inputs / "tested-laneboss"
    binary.write_bytes(data)
    binary.chmod(0o755)
    manifest[binary.name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    (inputs / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    checker = inputs / "e2e-rows/darwin_sandbox_rows.py"

    def isolated(provider, mutation="", external_org=False):
        # Each worker owns one configuration and one registered parent session.
        # The coordinator never registers or changes a live session binding.
        command = [sys.executable, str(checker), "--binary", str(binary), "--evidence", str(evidence),
                   "--case", provider, "--mutation", mutation]
        if external_org:
            command.append("--external-org")
        if arguments.native_only:
            command.append("--native-only")
        result = subprocess.run(command, capture_output=True, timeout=300)
        stem = evidence / (provider + "-" + (mutation or "control") + ("-external" if external_org else ""))
        stem.with_suffix(".stdout").write_bytes(result.stdout)
        stem.with_suffix(".stderr").write_bytes(result.stderr)
        stem.with_suffix(".json").write_text(json.dumps({"argv": command, "exit_code": result.returncode}) + "\n")
        require(result.returncode == 0, "isolated row setup/execution failed: " + provider + "/" + (mutation or "control"))
        verdict = json.loads(result.stdout)
        return verdict

    if arguments.native_only:
        require(sys.platform.startswith("linux"), "native-only rows require an authorized Linux box")
        verdict = isolated("claude", "native")
        require(verdict["native_preserved"], "LINUX PRESERVATION ROW FAILED: claude")
        print("PASS org-sandbox-preserved: linux")
        verdict = isolated("claude", "native-unconditional")
        require(not verdict["native_preserved"] and verdict["own_sandbox_disabled"] is True,
                "unconditional-render mutant did not fail Linux preservation for the right reason")
        print("MUTANT KILLED unconditional-render: Linux preservation row failed")
        print("PASS: Linux Claude preservation rows")
        return
    verdict = isolated("claude", "native")
    require(verdict["native_preserved"], "NON-OPTED MACOS PRESERVATION ROW FAILED: claude")
    print("PASS org-sandbox-preserved: non-opted macOS")
    for provider in ("codex", "claude", "claudock"):
        verdict = isolated(provider)
        protection, ordinary = verdict["protection"], verdict["ordinary"]
        require(protection, "PROTECTION ROW FAILED: " + provider)
        require(ordinary, "ORDINARY WORK ROW FAILED: " + provider)
        print("PASS protection: " + provider)
        print("PASS ordinary-work: " + provider)
        print("PASS runner-own-sandbox-off: " + provider)
        require(verdict["other_configuration"], "OTHER CONFIGURATION ROW FAILED: " + provider)
        print("PASS other-configuration: " + provider)
        require(verdict["tmux_isolated"], "TMUX ISOLATION ROW FAILED: " + provider)
        print("PASS tmux-isolated: " + provider)
    for provider in ("codex", "claude", "claudock"):
        verdict = isolated(provider, external_org=True)
        require(verdict["protection"] and verdict["ordinary"] and verdict["tmux_isolated"],
                "EXTERNAL ORG ROW FAILED: " + provider)
        print("PASS external-org: " + provider)
    verdict = isolated("codex", "drop-denies")
    protection, ordinary = verdict["protection"], verdict["ordinary"]
    require(not protection and ordinary
            and verdict["written"] == ["launcher-home", "launcher-state", "org-hooks", "other-state"],
            "drop-denies mutant did not fail protection for the right reason")
    print("MUTANT KILLED drop-denies: protection row failed")
    verdict = isolated("codex", "broad-home")
    protection, ordinary = verdict["protection"], verdict["ordinary"]
    failure = verdict["ordinary_failure"] or {}
    require(protection and not ordinary and failure.get("operation") == "runner-session"
            and failure.get("errno") in (errno.EACCES, errno.EPERM, errno.EROFS),
            "broad-home mutant did not fail ordinary work for the right reason")
    print("MUTANT KILLED broad-home: ordinary-work row failed")
    verdict = isolated("codex", "drop-home")
    require(not verdict["other_configuration"] and verdict["ordinary"] and verdict["selected_protected"]
            and verdict["written"] == ["launcher-home", "other-state"],
            "drop-home mutant did not fail the other-configuration row for the right reason")
    print("MUTANT KILLED drop-home: other-configuration row failed")
    verdict = isolated("codex", "empty-home")
    require(verdict["empty_home_refused"], "empty-home replacement refusal row failed")
    print("PASS empty-home: full-access runner not started")
    print("PASS: darwin sandbox owner rows")


if __name__ == "__main__":
    try:
        main()
    except (RowFailure, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("FAIL: " + str(error), file=sys.stderr)
        raise SystemExit(1)
