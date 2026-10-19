"""Credential-free Linux capture; invoked only by demo-screenshots.sh.

Persistent control processes register supervisor identities before dispatch.
Held stand-ins populate the live views; the dashboard is a separate human PTY.
"""

from datetime import datetime
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import time
import traceback
from urllib.parse import urlsplit, parse_qs


LARGE = "example-model-large-1"
MEDIUM = "example-model-medium-1"
SMALL = "example-model-small-1"
SPECS = {
    "demo-api": ("shop-api", "executor", 3, "agent", MEDIUM, "instance:stream-lead"),
    "demo-web": ("shop-web", "executor", 3, "held", MEDIUM, "instance:stream-lead"),
    "demo-cart": ("shop-api", "executor", 3, "held", SMALL, "instance:stream-lead"),
    "demo-docs": ("shop-web", "docs", 3, "agent", MEDIUM, "instance:stream-lead"),
    "demo-review": ("shop-api", "reviewer", 3, "agent", LARGE, "instance:stream-lead"),
}
SUPERVISOR_LEVELS = {"bootstrap": 6, "shop-lead": 5, "stream-lead": 4}
LANES = tuple(SPECS)
HELD = tuple(lane for lane, spec in SPECS.items() if spec[3] != "agent")
SHOTS = Path("/tmp/shots")
LAST_FAILURE = None
LAST_COMMAND = None


class Failed(RuntimeError):
    pass


class CommandFailed(Failed):
    def __init__(self, label, code):
        super().__init__(f"{label} exited {code}; exact output is in evidence")
        self.code = code


def require(condition, detail):
    if not condition:
        raise Failed(detail)


def check_capture_text(text, card_names):
    require("No state recorded" not in text and "No model recorded" not in text
            and "[unparsed event]" not in text and "Message text not recorded" not in text
            and "Level not recorded" not in text, "capture contains missing or unparsed data")
    require(card_names, "capture has no visible card names")
    require(len(card_names) == len(set(card_names)), "capture has duplicate card names")


def failed_output(label, stdout, stderr):
    # All commands use the isolated synthetic demo. Dashboard URLs are handled
    # separately and never pass through this reporter.
    global LAST_FAILURE
    LAST_FAILURE = (stdout, stderr)
    print(f"FAIL OUTPUT {label}: stdout", flush=True)
    sys.stdout.buffer.write(stdout)
    sys.stdout.buffer.flush()
    print(f"\nFAIL OUTPUT {label}: stderr", flush=True)
    sys.stdout.buffer.write(stderr)
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(stderr)
    sys.stderr.buffer.flush()


class Demo:
    def __init__(self, work):
        self.work = work
        self.source = work / "source"
        self.home = work / "home"
        self.evidence = work / "evidence"
        self.binary = work / "bin/laneboss"
        self.config = self.home / ".config/laneboss/configs/demo"
        self.org = self.home / ".config/laneboss/orgs/demo"
        self.state = self.home / ".local/state/laneboss/demo"
        self.control = work / "control"
        self.dashboard_pid = None
        self.dashboard_fd = None
        self.last_command = None
        self.controls = []

    def run(self, label, *argv, limit=120, headless=False):
        global LAST_COMMAND
        try:
            result = subprocess.run([str(a) for a in argv], cwd=self.source,
                                    capture_output=True, timeout=limit, start_new_session=headless)
        except subprocess.TimeoutExpired as error:
            (self.evidence / f"{label}.stdout").write_bytes(error.stdout or b"")
            (self.evidence / f"{label}.stderr").write_bytes(error.stderr or b"")
            failed_output(label, error.stdout or b"", error.stderr or b"")
            raise Failed(f"{label} exceeded its hang deadline; partial output is retained") from error
        (self.evidence / f"{label}.stdout").write_bytes(result.stdout)
        (self.evidence / f"{label}.stderr").write_bytes(result.stderr)
        self.last_command = (label, result.stdout, result.stderr)
        LAST_COMMAND = self.last_command
        if result.returncode:
            # Guard refusals are retained and reported verbatim, never retried.
            failed_output(label, result.stdout, result.stderr)
            raise CommandFailed(label, result.returncode)
        return result.stdout

    def cli(self, label, *argv, lines=False):
        output = self.run(label, self.binary, *argv)
        if lines:
            return [json.loads(line) for line in output.splitlines() if line.strip()]
        return json.loads(output)

    def prepare(self):
        version = self.cli("version", "--version")
        require(version.get("program") == "laneboss" and version.get("version") == "0.7.0"
                and version.get("protocol_version") == "1.3.0", "launcher version mismatch")
        for project in ("shop-api", "shop-web"):
            repo = self.work / project
            self.run(f"init-{project}", "git", "init", "-q", repo)
            self.run(f"commit-{project}", "git", "-C", repo, "-c", "user.name=demo",
                     "-c", "user.email=demo", "-c", "commit.gpgsign=false",
                     "commit", "-q", "--allow-empty", "-m", "demo bootstrap")
        runner = self.source / "examples/minimal/bin/example-agent"
        for name in ("example-agent", "claude"):
            target = self.work / "bin" / name
            shutil.copyfile(runner, target)
            target.chmod(0o755)
        # Init only checks this local basename on PATH; it never invokes it.
        # Its real-runner configuration is replaced before doctor or dispatch.
        self.run("init-demo", self.binary, "init", "demo", "--runner", "claude",
                 "--project", self.work / "shop-api", "--project", self.work / "shop-web")
        fixture = self.source / "examples/dashboard-demo"
        self.control.mkdir(mode=0o700)
        provider = self.work / "bin/demo-agent"
        shutil.copyfile(fixture / "demo_agent.py", provider)
        provider.chmod(0o755)
        config_text = (fixture / "config.toml").read_text(encoding="utf-8")
        config_text = config_text.replace('"@WORK@"', json.dumps(str(self.work)))
        (self.config / "config.toml").write_text(config_text, encoding="utf-8")
        template = (fixture / "project.toml.in").read_text(encoding="utf-8")
        for project in ("shop-api", "shop-web"):
            text = template.replace('"@PROJECT@"', json.dumps(project)).replace(
                '"@REPOSITORY@"', json.dumps(str(self.work / project)))
            (self.config / "projects" / f"{project}.toml").write_text(text, encoding="utf-8")
        drivers = fixture / "drivers.toml"
        for relative in ("L3/executor", "L3/docs", "L3/reviewer", "L4/supervisor", "L5/top"):
            level, role = relative.split("/")
            shutil.copyfile(drivers, self.org / ".laneboss" / level / "roles" / f"{role}.toml")
        instances = self.org / ".laneboss/instances"
        placeholders = ("L3-lane-example", "L4-stream", "L5-top", "L6-super-top")
        require(sorted(p.name for p in instances.iterdir()) == sorted(placeholders),
                "unexpected demo instances; preserve the org")
        archive = self.evidence / "placeholder-instances"
        archive.mkdir(mode=0o700)
        for name in placeholders:
            instance = instances / name
            metadata = (instance / "instance.toml").read_bytes()
            require(metadata and instance.is_dir() and not instance.is_symlink(),
                    "placeholder metadata is missing or unsafe")
            shutil.copyfile(fixture / "notes.md", instance / "state/notes.md")
            # Preserve the entire original instance outside the org. The renderer
            # regenerates its own manifest/hooks; no generated file is edited.
            instance.rename(archive / name)
        # CheckHooks rejects an empty instances directory. Use the supported
        # instance command so identity, rule files and mandatory hooks agree.
        for name, level, role in (("shop-lead", 5, "top"), ("stream-lead", 4, "supervisor")):
            added = self.cli("org-instance-" + name, "org", "instance", "add", self.org, name,
                             "--level", str(level), "--role", role)
            require(added.get("ok") is True and added.get("changed", 0) > 0, "demo instance was not created")
            shutil.copyfile(fixture / "notes.md", instances / name / "state/notes.md")
        rendered = self.cli("org-render", "org", "render", self.org)
        require(rendered.get("ok") is True, "org rendering failed")
        valid = self.cli("config-valid", "config", "validate", "demo")
        require(valid.get("valid") is True and valid.get("configs") == ["demo"],
                "demo configuration is invalid")
        roles = self.cli("org-roles", "org", "roles", "list", self.org)
        role_map = {(row["level"], row["role"]): row["drivers"] for row in roles["roles"]}
        require(all("demo-agent" in role_map.get((spec[2], spec[1]), []) for spec in SPECS.values()),
                "a selected (level, role) does not permit demo-agent")
        valid = self.cli("org-valid", "org", "validate", self.org, "--config", "demo", "--format", "json")
        require(valid.get("valid") is True and valid.get("problems") == [], "demo org is invalid")
        hooks = self.cli("org-hooks", "org", "check-hooks", self.org)
        require(hooks.get("ok") is True and hooks.get("checks")
                and all(row.get("ok") is True for row in hooks["checks"]), "demo instance hooks are invalid")
        checks = self.cli("doctor", "doctor", "--config", "demo", lines=True)
        require(checks and all(row.get("ok") is True for row in checks), "doctor check failed")
        require({"tool.git", "tool.tmux", "runner.agent", "runner.held", "runner.top", "runner.stream"}
                <= {row.get("check") for row in checks},
                "doctor omitted a prerequisite check")
        paths = self.cli("paths", "config", "path", "demo")
        require(paths.get("state_dir") == str(self.state), "state escaped the isolated HOME")

    def briefing(self, role=None):
        selection = ("--role", role) if role else ()
        label = "briefing-" + role if role else "briefing"
        text = self.run(label, self.binary, "start", "--config", "demo", *selection)
        # Read and retain the whole human briefing, as well as its checked JSON.
        document = text.decode("utf-8")
        require(document.startswith("# Laneboss session briefing\n"), "missing human briefing")
        value = self.cli(label + "-json", "start", "--config", "demo", *selection, "--format", "json")
        require(value["configuration"]["name"] == "demo" and value["protocol"]["version"] == "1.3.0"
                and value["configuration"]["warnings"] == []
                and all(row["ok"] for row in value["checks"]["read"]), "supervisor briefing failed")
        if role:
            require(value["role"]["selected"] == role
                    and value["role"]["entry"]["level"] == SUPERVISOR_LEVELS[role],
                    "the dispatch supervisor did not register its configured level")
            record = json.loads((self.state / "sessions" / f"{os.getpid()}.json").read_bytes())
            principal = ("supervisor:" if role == "bootstrap" else "instance:") + role
            require(record["config"] == "demo" and record["principal"] == principal
                    and record["pid"] == os.getpid() and record["start"],
                    "the role briefing did not record this persistent controller process")

    def ended(self, lane, run, since=0):
        events = self.cli(f"{lane}-events-{run}", "event", "tail", "--config", "demo",
                          "--lane", lane, "--since", str(since), "--follow",
                          "--until", "lane.ended", lines=True)
        ends = [e["payload"] for e in events if e.get("kind") == "lane.ended"]
        require(len(ends) == 1 and ends[0].get("run") == run and ends[0].get("reason") == "exit"
                and ends[0].get("exit_code") == 0 and ends[0].get("survivors") == 0,
                f"{lane} run {run} did not end successfully")
        deadline = time.monotonic() + 120
        attempt = 0
        while time.monotonic() < deadline:
            status = self.cli(f"{lane}-status-{run}-{attempt}", "lane", "status",
                              "--config", "demo", "--lane", lane)
            live = status["live"]
            require(status["run"] == run and status["state"] == "verifying"
                    and not status["running"] and status["exit_code"] == 0
                    and live["pending_events"] == 0 and live["refused_events"] == 0
                    and live["survivors"] == 0, f"{lane} status is not a successful ended run")
            if not live["session_alive"] and not (live.get("supervisor") or {}).get("alive"):
                return status, events
            attempt += 1
            time.sleep(0.25)
        raise Failed(f"{lane} supervising process did not settle")

    def start_lane(self, lane):
        project, role, level, runner, model, starter = SPECS[lane]
        receipt = self.cli(f"{lane}-start", "lane", "start", "--config", "demo",
                           "--project", project, "--lane", lane, "--brief",
                           self.source / "examples/bootstrap/brief.md", "--role", role,
                           "--level", str(level), "--runner", runner, "--model", model,
                           "--difficulty", "standard", "--budget", "10")
        require(receipt["lane"] == lane and receipt["run"] == 1 and receipt["runner"] == runner
                and receipt["model"] == model and receipt["role"] == role
                and receipt["role_context"]["level"] == level, f"{lane} start receipt mismatch")
        if lane in HELD:
            events = self.cli(f"{lane}-start-events", "event", "tail", "--config", "demo", "--lane", lane,
                              lines=True)
            status = self.cli(f"{lane}-running", "lane", "status", "--config", "demo", "--lane", lane)
            require(status["state"] == "running" and status["running"]
                    and status["live"]["session_alive"], f"{lane} held runner is not running")
        else:
            status, events = self.ended(lane, 1)
        started = [e for e in events if e["kind"] == "lane.started"]
        require(len(started) == 1 and started[0]["payload"]["starter"] == starter
                and started[0]["payload"]["level"] == level
                and started[0]["actor"] == starter, f"{lane} report line was not recorded")
        if lane not in HELD:
            self.check_read(lane, receipt["brief"]["path"], "# Bootstrap lane")
        return receipt, status

    def check_read(self, lane, source, heading):
        records = [json.loads(line) for line in
                   (self.state / "lanes" / lane / "output.log").read_text(encoding="utf-8").splitlines()]
        results = [block for record in records for block in record["message"]["content"]
                   if block["type"] == "tool_result"]
        length = len(Path(source).read_bytes())
        require(any(f"Read {length} bytes" in row["content"] and heading in row["content"]
                    and row.get("is_error") is False for row in results),
                f"{lane} did not record the actual input bytes")

    def mark(self, lane, state):
        result = self.cli(f"{lane}-{state}", "lane", "mark", "--config", "demo",
                          "--lane", lane, "--state", state)
        require(result.get("state") == state and result.get("kind") == "lane.state"
                and result["scan"]["not_covered"] == []
                and result["scan"]["appended"]["refusals"] == 0
                and result["scan"]["appended"]["suspicions"] == 0, f"{lane} mark gate failed")

    def clean(self, lane):
        result = self.cli(f"{lane}-clean", "lane", "clean", "--config", "demo", "--lane", lane)
        require(result.get("pending") is False
                and {item["item"] for item in result["removed"]} == {"branch", "worktree"},
                f"{lane} was not completely collected")
        project = SPECS[lane][0]
        require(not (self.work / f"{project}-{lane}").exists(), f"{lane} worktree remains")
        branch = self.run(f"{lane}-branch", "git", "-C", self.work / project, "branch", "--list", lane)
        require(not branch.strip(), f"{lane} branch remains")
        require((self.state / "lanes" / lane / "output.log").is_file(), f"{lane} record was removed")

    def controller(self, role):
        # Register from this persistent parent before any lane start. Lane
        # runners only read/hold; they never try to mint a supervisor ticket.
        name = "shop-lead" if role == "top" else "stream-lead"
        self.briefing(name)
        if role == "top":
            self.spawn_control("stream")
            self.hold_control(name, "supervisor:bootstrap")
            return
        receipt, status = self.start_lane("demo-api")
        message = self.source / "examples/dashboard-demo/message.md"
        event = {"kind": "supervisor.message.sent", "lane": "demo-api", "actor": "instance:stream-lead",
                 "protocol_version": "1.3.0", "payload": {"from": "instance:stream-lead", "to": "demo-api",
                 "text": message.read_text(encoding="utf-8"), "source": "synthetic resume instruction"}}
        instruction = self.control / "api-message.json"
        instruction.write_text(json.dumps(event) + "\n", encoding="utf-8")
        self.cli("api-message", "event", "append", "--config", "demo", "--file", instruction)
        resumed = self.cli("demo-api-resume", "lane", "resume", "--config", "demo",
                           "--lane", "demo-api", "--message", message, "--budget", "10")
        require(resumed["run"] == 2 and resumed["worktree"] == receipt["worktree"]
                and resumed["branch"] == receipt["branch"], "resume changed the lane directory")
        _, events = self.ended("demo-api", 2, status["last_seq"])
        require(any(e["kind"] == "lane.resumed" and e["payload"]["run"] == 2 for e in events),
                "resume event is missing")
        resumed_event = next(e["payload"] for e in events if e["kind"] == "lane.resumed")
        self.check_read("demo-api", resumed_event["message"]["path"], "# Continue the bootstrap lane")
        self.mark("demo-api", "accepted")
        self.mark("demo-api", "merged")
        self.clean("demo-api")
        self.start_lane("demo-web")
        self.start_lane("demo-cart")
        self.start_lane("demo-docs")
        self.start_lane("demo-review")
        self.mark("demo-review", "accepted")
        statuses = [self.cli(f"{lane}-ready-status", "lane", "status", "--config", "demo", "--lane", lane)
                    for lane in SPECS if SPECS[lane][2] == 3]
        (self.control / "ready.json").write_text(json.dumps(statuses) + "\n", encoding="utf-8")
        self.hold_control(name, "instance:shop-lead")

    def spawn_control(self, mode):
        out = self.evidence / f"dispatch-{mode}.stdout"
        err = self.evidence / f"dispatch-{mode}.stderr"
        with out.open("wb") as stdout, err.open("wb") as stderr:
            process = subprocess.Popen([sys.executable, "-I", str(Path(__file__)), str(self.work), mode],
                                       cwd=self.source, stdout=stdout, stderr=stderr, start_new_session=True)
        self.controls.append((mode, process, out, err))

    def hold_control(self, name, starter):
        started, next_pulse, count = time.monotonic(), 0.0, 0
        try:
            while not (self.control / "release.json").exists():
                now = time.monotonic()
                require(now - started < 480, "capture did not release the supervisor controller")
                self.check_controls(capturing=False)
                if (self.control / "release.json").exists():
                    break
                if now >= next_pulse:
                    count += 1
                    self.control_heartbeat(name, starter, "running", count, now - started)
                    next_pulse = now + 10
                time.sleep(0.25)
            self.wait_controls()
            release = json.loads((self.control / "release.json").read_bytes())
            if release.get("complete") is True:
                self.control_heartbeat(name, starter, "ended", count, time.monotonic() - started)
        except BaseException:
            self.release("supervisor controller failed")
            self.wait_controls()
            raise

    def control_heartbeat(self, name, starter, state, count, duration):
        event = {"kind": "instance.heartbeat", "actor": "instance:" + name, "protocol_version": "1.3.0",
                 "payload": {"instance": name, "model": LARGE, "runner": "controller", "state": state,
                             "starter": starter, "count": count, "duration_seconds": round(duration, 3)}}
        path = self.control / f"{name}-heartbeat.json"
        path.write_text(json.dumps(event) + "\n", encoding="utf-8")
        self.cli(f"{name}-{state}-{count}", "event", "append", "--config", "demo", "--file", path)

    def wait_controls(self):
        controls, self.controls = self.controls, []
        for mode, process, out, err in controls:
            try:
                code = process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                failed_output("dispatch-" + mode, out.read_bytes(), err.read_bytes())
                raise Failed("supervisor controller did not exit after release")
            (self.evidence / f"dispatch-{mode}.exit-code").write_text(str(code) + "\n", encoding="utf-8")
            if code:
                failed_output("dispatch-" + mode, out.read_bytes(), err.read_bytes())
                raise CommandFailed("dispatch-" + mode, code)

    def check_controls(self, capturing=True):
        released = (self.control / "release.json").exists()
        require(not released or not capturing, "demo controllers were released before capture finished")
        if released:
            return
        for mode, child, out, err in self.controls:
            if child.poll() is not None:
                if not capturing and (self.control / "release.json").exists():
                    return
                failed_output("dispatch-" + mode, out.read_bytes(), err.read_bytes())
                raise CommandFailed("dispatch-" + mode, child.returncode or 1)

    def launch_top(self):
        # Register and dispatch in the same persistent headless child. The
        # dashboard remains a sibling human PTY and inherits no role record.
        self.spawn_control("bootstrap")

    def await_activity(self):
        deadline = time.monotonic() + 360
        ready_since = None
        while time.monotonic() < deadline:
            self.check_controls()
            if (self.control / "ready.json").exists() and ready_since is None:
                ready_since = time.monotonic()
            if ready_since is not None and time.monotonic() - ready_since >= 90:
                events = self.cli("activity-events", "event", "tail", "--config", "demo", lines=True)
                for lane in HELD:
                    pulses = [e for e in events if e["kind"] == "demo.heartbeat" and e["lane"] == lane]
                    require(len(pulses) >= 6 and max(e["payload"]["duration_seconds"] for e in pulses) >= 60,
                            f"{lane} has too little measured heartbeat activity")
                for name in ("shop-lead", "stream-lead"):
                    pulses = [e for e in events if e["kind"] == "instance.heartbeat"
                              and e["payload"].get("instance") == name and e["payload"].get("state") == "running"]
                    require(len(pulses) >= 6 and max(e["payload"]["duration_seconds"] for e in pulses) >= 60,
                            "supervisor heartbeat activity is missing")
                    last = pulses[-1]
                    recorded = datetime.fromisoformat(last["recorded_at"].replace("Z", "+00:00")).timestamp()
                    require(0 <= time.time() - recorded <= 20,
                            "supervisor heartbeat is stale")
                statuses = [self.cli(f"{lane}-capture-status", "lane", "status", "--config", "demo", "--lane", lane)
                            for lane in LANES]
                require(sum(row["running"] for row in statuses if SPECS[row["lane"]][2] == 3) >= 2,
                        "fewer than two L3 lanes are actually running")
                return
            for mode in ("top", "stream", "bootstrap"):
                if (self.evidence / f"failure-{mode}.log").exists():
                    out = self.evidence / f"failure-{mode}.stdout"
                    err = self.evidence / f"failure-{mode}.stderr"
                    failed_output("dispatch-" + mode, out.read_bytes() if out.exists() else b"",
                                  err.read_bytes() if err.exists() else b"")
                    raise Failed("demo dispatch failed; inspect the printed output")
            time.sleep(0.5)
        raise Failed("demo lanes did not become ready with 90 seconds of live activity")

    def release(self, reason, complete=False):
        if self.control.is_dir():
            release = self.control / "release.json"
            pending = self.control / ("release-" + str(os.getpid()) + ".pending")
            pending.write_text(json.dumps({"reason": reason, "complete": complete}) + "\n", encoding="utf-8")
            pending.replace(release)

    def failed_lane_output(self):
        # Runner/controller output is synthetic and contains no dashboard URL.
        # Forward it without issuing more CLI commands after a stopped gate.
        for lane in LANES:
            output = self.state / "lanes" / lane / "output.log"
            if output.is_file():
                print(f"FAIL RUNNER OUTPUT {lane}:", flush=True)
                sys.stdout.buffer.write(output.read_bytes())
                sys.stdout.buffer.flush()

    def dashboard(self):
        pid, fd = pty.fork()
        if pid == 0:
            os.execv(str(self.binary), [str(self.binary), "dashboard", "--config", "demo", "--port", "0"])
        self.dashboard_pid, self.dashboard_fd = pid, fd
        deadline, output = time.monotonic() + 30, b""
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], max(0, deadline - time.monotonic()))
            if not ready:
                break
            try:
                data = os.read(fd, 8192)
            except OSError:
                break
            if not data:
                break
            output += data
            (self.evidence / "dashboard-private.log").write_bytes(output)
            for line in output.decode("utf-8", "replace").splitlines():
                if line.startswith("http://127.0.0.1:"):
                    address = urlsplit(line)
                    require(address.scheme == "http" and address.hostname == "127.0.0.1"
                            and address.port and parse_qs(address.fragment).get("t"),
                            "dashboard did not return a token-bearing loopback URL")
                    return line
        # A refusal is safe to print only when no token URL was issued.
        sys.stderr.buffer.write(output)
        raise Failed("human PTY dashboard did not become ready; no dashboard was retried")

    def stop_dashboard(self):
        if self.dashboard_pid is None:
            return
        pid = self.dashboard_pid
        ended, status = os.waitpid(pid, os.WNOHANG)
        if not ended:
            os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if not ended:
                ended, status = os.waitpid(pid, os.WNOHANG)
            if ended:
                self.dashboard_pid = None
                os.close(self.dashboard_fd)
                self.dashboard_fd = None
                require(os.waitstatus_to_exitcode(status) == 0, "dashboard exited unsuccessfully")
                return
            time.sleep(0.1)
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        self.dashboard_pid = None
        os.close(self.dashboard_fd)
        self.dashboard_fd = None
        raise Failed("dashboard needed SIGKILL; capture is incomplete")

    def stop_lanes(self):
        for lane in LANES:
            if not (self.state / "lanes" / lane).exists():
                continue
            status = self.cli(f"{lane}-final-status", "lane", "status", "--config", "demo", "--lane", lane)
            live = status["live"]
            if status["running"] or live["session_alive"] or live["survivors"] \
                    or (live.get("supervisor") or {}).get("alive"):
                result = self.cli(f"{lane}-stop", "lane", "stop", "--config", "demo", "--lane", lane)
                require(result.get("survivors") == 0 and result.get("pending") is False,
                        f"{lane} stop left surviving processes or pending events")

    def collect(self):
        self.stop_dashboard()
        self.release("all four captures and privacy scans completed", complete=True)
        self.wait_controls()
        for lane in reversed(HELD):
            self.ended(lane, 1)
        self.stop_lanes()
        for lane in LANES:
            status = self.cli(f"{lane}-collect-status", "lane", "status", "--config", "demo", "--lane", lane)
            if not status["cleaned"]:
                project = SPECS[lane][0]
                tree = self.work / f"{project}-{lane}"
                dirty = self.run(f"{lane}-diff", "git", "-C", tree, "status", "--porcelain")
                require(not dirty.strip(), f"{lane} unexpectedly modified the demo repository")
                base = self.run(f"{lane}-base", "git", "-C", self.work / project, "rev-parse", "HEAD")
                head = self.run(f"{lane}-head", "git", "-C", tree, "rev-parse", "HEAD")
                require(base == head, f"{lane} has unexpected commits; preserve its worktree")
                self.mark(lane, "merged")
                self.clean(lane)
            final = self.cli(f"{lane}-collected", "lane", "status", "--config", "demo", "--lane", lane)
            live = final["live"]
            require(final["cleaned"] and not final["running"] and live["survivors"] == 0
                    and live["pending_events"] == 0 and live["refused_events"] == 0
                    and not live["session_alive"] and not (live.get("supervisor") or {}).get("alive"),
                    f"{lane} collection is incomplete")
        verified = self.cli("state-verify", "state", "verify", "--config", "demo")
        require(verified.get("ok") is True and verified.get("exists") is True
                and verified.get("lanes") == len(LANES) and verified.get("events", 0) > 0,
                "collected demo state failed integrity verification")


def capture(demo, url):
    from playwright.sync_api import sync_playwright

    SHOTS.mkdir(mode=0o700)
    issues, captures = [], []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            context = browser.new_context(viewport={"width": 1440, "height": 900},
                                          device_scale_factor=1, locale="en-US", timezone_id="UTC",
                                          color_scheme="light", reduced_motion="reduce")
            page = context.new_page()
            page.on("pageerror", lambda error: issues.append(str(error)))
            page.on("console", lambda message: issues.append(message.text) if message.type == "error" else None)
            page.goto(url, wait_until="networkidle", timeout=30000)
            require(urlsplit(page.url).fragment == "", "dashboard token fragment was not cleared")
            page.locator('#org-graph [data-node-id="lane:demo-api"]').wait_for()
            page.locator("#events-content tbody tr").first.wait_for()
            page.wait_for_function("document.documentElement.dataset.loaded === 'true'")
            require(page.locator("#sync").inner_text().startswith("Updated ")
                    and not any(t.strip() for t in page.locator(".error").all_text_contents()),
                    "a dashboard panel reports an error")
            # Use the real search control to capture the populated demo nodes,
            # leaving the transient L6 launch identity outside these frames.
            page.locator("#agent-search").fill("example-model")
            style = demo.source / "examples/dashboard-demo/capture.css"
            page.add_style_tag(content=style.read_text(encoding="utf-8"))
            shutil.copyfile(style, SHOTS / "capture.css")
            page.evaluate("""() => {
                const label = document.createElement('div');
                label.id = 'capture-label';
                label.textContent = 'SYNTHETIC DEMO · shop-api / shop-web · held stand-in · no AI-service requests';
                document.body.prepend(label);
                const drawerLabel = label.cloneNode(true);
                drawerLabel.removeAttribute('id');
                drawerLabel.className = 'drawer-demo-label';
                document.querySelector('#agent-drawer').prepend(drawerLabel);
            }""")
            # Keep the per-run token in memory, outside all publication sources.
            address = urlsplit(url)
            origin = f"{address.scheme}://{address.netloc}"
            token = parse_qs(address.fragment)["t"][0]
            response = context.request.get(origin + "/api/graph", headers={"X-Laneboss-Token": token})
            require(response.status == 200, "authenticated graph read failed")
            (demo.evidence / "graph-response.json").write_bytes(response.body())
            graph = response.json()
            nodes = {n["id"]: n for n in graph["nodes"]}
            require(graph["root"]["id"] == "human" and graph["name"] == "demo", "wrong demo org")
            require(set(nodes) == {f"lane:{lane}" for lane in LANES}
                    | {"instance:shop-lead", "instance:stream-lead", "supervisor:bootstrap"},
                    "unexpected org or supervisor nodes")
            names = [node["name"] for node in nodes.values()]
            require(len(names) == len(set(names)), "duplicate card names are recorded")
            for lane in LANES:
                node = nodes[f"lane:{lane}"]
                _, _, level, runner, model, parent = SPECS[lane]
                require(node["parent"] == parent and node["starter"] == parent
                        and node["level"] == level and node["model"] == model and node["runner"] == runner
                        and node["level_source"] == ("org" if level > 3 else "protocol"),
                        f"{lane} graph report line mismatch")
                card = page.locator(f'#org-graph [data-node-id="lane:{lane}"]')
                require(card.get_attribute("data-parent") == parent, f"{lane} rendered parent mismatch")
                response = context.request.get(origin + f"/api/logs?lane={lane}&tail=200",
                                               headers={"X-Laneboss-Token": token})
                require(response.status == 200, f"{lane} log read failed")
                (demo.evidence / f"{lane}-logs.json").write_bytes(response.body())
                logs = response.json()
                kinds = {entry["kind"] for entry in logs["timeline"]}
                require(logs["available"] and {"thinking", "tool_use", "tool_result", "assistant"} <= kinds
                        and all("[unparsed event]" not in entry["text"] for entry in logs["timeline"]),
                        f"{lane} has an empty or unparsed thinking/tool timeline")
            l3 = [node for node in nodes.values() if node["level"] == 3 and node["kind"] == "lane"]
            require(4 <= len(l3) <= 6 and sum(n["state"] == "running" for n in l3) >= 2
                    and any(n["state"] == "verifying" for n in l3)
                    and any(n["state"] == "ended" for n in l3), "L3 states are not mixed and active")
            populated = [nodes[f"lane:{lane}"] for lane in LANES]
            for role, level, parent in (("shop-lead", 5, "supervisor:bootstrap"),
                                        ("stream-lead", 4, "instance:shop-lead")):
                supervisor = nodes["instance:" + role]
                require(supervisor["level"] == level and supervisor["model"] == LARGE
                        and supervisor["state"] == "running" and supervisor["parent"] == parent
                        and supervisor["starter"] == parent, "a registered supervisor card is not populated")
                populated.append(supervisor)
            require(len({node["model"] for node in populated}) >= 3
                    and all(node["series"] and any(point["value"] > 0 for point in node["series"])
                            for node in populated), "models or recorded sparkline activity are missing")
            page.locator("#watch-pause").click()
            require(page.locator("#watch-pause").get_attribute("aria-pressed") == "true",
                    "live refresh did not pause")
            text = page.locator("body").inner_text()
            names = page.locator("#org-graph .graph-node:not([hidden]) .node-name").all_text_contents()
            for label, changed_text, changed_names, reason in (
                ("duplicate card names", text, names + names[:1], "capture has duplicate card names"),
                ("missing message text", text + "\nMessage text not recorded", names, "capture contains missing or unparsed data"),
                ("verbose unknown level", text + "\nLevel not recorded", names, "capture contains missing or unparsed data"),
            ):
                try:
                    check_capture_text(changed_text, changed_names)
                except Failed as error:
                    require(str(error) == reason, "capture negative control failed for the wrong reason")
                else:
                    raise Failed("capture negative control was accepted: " + label)
                print("NEGATIVE CONTROL: rejected " + label, flush=True)

            def shot(name, selector, caption):
                demo.check_controls()
                target = page.locator(selector)
                if selector != "#agent-drawer":
                    target.evaluate("element => window.scrollTo(0, window.scrollY + element.getBoundingClientRect().top - 54)")
                visible = page.locator("body").inner_text()
                card_names = page.locator("#org-graph .graph-node:not([hidden]) .node-name").all_text_contents()
                check_capture_text(visible, card_names)
                unparented = page.locator('#org-graph .graph-node:not([hidden])').evaluate_all("""cards =>
                    cards.filter(card => card.querySelector('.node-parent').textContent.includes('No recorded supervisor')
                        && card.dataset.nodeId !== 'instance:shop-lead').length""")
                require(unparented == 0, "a non-top card has no recorded supervisor")
                if selector == "#org-live":
                    running = page.locator('#org-graph .graph-node[data-state="running"]').evaluate_all("""cards => {
                        const clip = document.querySelector('#org-graph').getBoundingClientRect();
                        return cards.filter(card => {
                            const r = card.getBoundingClientRect();
                            return r.top >= Math.max(44, clip.top) && r.bottom <= Math.min(innerHeight, clip.bottom);
                        }).length;
                    }""")
                    require(running >= 2, "capture has fewer than two fully visible Running cards")
                if selector in ("#activity", "#agent-drawer"):
                    table_id = "#events-content" if selector == "#activity" else "#drawer-lifecycle"
                    complete = page.locator(table_id).evaluate("""element => {
                        const table = element.querySelector('table');
                        return table && table.getBoundingClientRect().width <= element.clientWidth + 1
                            && [...table.querySelectorAll('td,th')].every(cell => cell.scrollWidth <= cell.clientWidth + 1);
                    }""")
                    require(complete, "lifecycle table columns are horizontally truncated")
                label = page.locator("#capture-label")
                text = label.inner_text() + "\n" + target.inner_text()
                html = label.evaluate("element => element.outerHTML") + "\n" + target.evaluate("element => element.outerHTML")
                require(not re.search(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", text + html, re.I)
                        and not re.search(r"/(?:Users|home|root|tmp|srv)/", text + html)
                        and "#t=" not in text + html, "publication source contains a path, session ID or token")
                (SHOTS / f"{name}.txt").write_text(text, encoding="utf-8")
                (SHOTS / f"{name}.html").write_text(html, encoding="utf-8")
                page.screenshot(path=str(SHOTS / f"{name}.png"), animations="disabled")
                data = (SHOTS / f"{name}.png").read_bytes()
                require(data[:8] == b"\x89PNG\r\n\x1a\n" and data[12:16] == b"IHDR", "invalid PNG")
                width, height = struct.unpack(">II", data[16:24])
                require((width, height) == (1440, 900), "capture dimensions differ from 1440x900")
                captures.append({"file": f"{name}.png", "width": width, "height": height,
                                 "caption": caption})

            page.locator("#org-graph").evaluate("element => { element.scrollTop = 0; }")
            shot("01-org-tree", "#org-live", "Synthetic demo: recorded and running L5/L4 supervisor instances with model names and live activity.")
            page.locator("#org-graph").evaluate("element => { element.scrollTop = element.scrollHeight; }")
            shot("02-lane-tree", "#org-live", "Synthetic demo: five L3 lanes under their L4 stream, with Running, Verifying and Ended states.")
            page.locator('#org-graph [data-node-id="lane:demo-api"]').click()
            page.locator('#drawer-lifecycle tr[data-step="clean"]').wait_for()
            line = page.locator("#drawer-supervisor").inner_text()
            require("instance:stream-lead" in line and "Reports to instance:stream-lead" in line,
                    "drawer omitted the recorded report line")
            steps = page.locator("#drawer-lifecycle tbody tr").evaluate_all(
                "rows => rows.map(row => ({step: row.dataset.step, actor: row.dataset.actor}))")
            require({"start", "resume", "ended", "accepted", "merged", "clean"}
                    <= {row["step"] for row in steps}, "drawer lifecycle is incomplete")
            require(all(row["actor"] == "instance:stream-lead" for row in steps
                        if row["step"] in {"start", "resume", "accepted", "merged", "clean"}),
                    "drawer lifecycle caller mismatch")
            page.locator("#drawer-timeline .thinking-item.thinking").first.wait_for()
            require("review the API edge cases" in page.locator("#drawer-messages").inner_text(),
                    "the delivered demo instruction text is not visible")
            chip = page.locator("#drawer-timeline .tool-chip").last
            chip.locator("summary").click()
            require("Read " in chip.inner_text() and "bytes" in chip.inner_text(), "read call/result was not paired")
            page.locator("#drawer-timeline").evaluate("element => { element.scrollTop = element.scrollHeight; }")
            shot("03-lane-detail", "#agent-drawer", "Synthetic demo: recorded report line, thinking, real brief read/result and assistant message.")
            page.locator("#drawer-close").click()
            page.locator("#watch-pause").click()
            with page.expect_response(lambda response: urlsplit(response.url).path == "/api/events"
                                      and parse_qs(urlsplit(response.url).query).get("lane") == ["demo-api"]) as event_read:
                page.locator("#event-lane").select_option("demo-api")
            require(event_read.value.status == 200, "filtered lifecycle read failed")
            (demo.evidence / "event-response.json").write_bytes(event_read.value.body())
            page.wait_for_function("""() => {
                const rows = [...document.querySelectorAll('#events-content tbody tr')];
                return rows.length > 0 && rows.every(row => row.children[1].textContent === 'demo-api')
                    && document.querySelector('#events-content').innerText.includes('lane.cleaned');
            }""")
            require("lane.resumed" in page.locator("#events-content").inner_text(), "event board omitted resume")
            rows = page.locator("#events-content tbody tr").evaluate_all(
                "rows => rows.map(row => [...row.children].map(cell => cell.textContent))")
            lifecycle = [row for row in rows if row[3] in
                         {"lane.started", "lane.resumed", "lane.ended", "lane.state", "lane.cleaned"}]
            require(lifecycle and all(row[2] == "L3" for row in lifecycle), "lane lifecycle levels were lost")
            require(all(row[2] in {"L3", "—"} for row in rows), "event level labels are not compact")
            page.locator("#watch-pause").click()
            shot("04-lifecycle-events", "#activity", "Demo API lifecycle: real CLI start, resume, acceptance, merge decision and collection events.")
            require(not issues, "browser reported an error; see browser-errors.log")
            (SHOTS / "captures.json").write_text(json.dumps({
                "org": "demo", "runner": "demo-agent", "authenticated_ai_service": False,
                "dashboard_principal": "human", "terminal": "Python pty.fork on disposable Ubuntu",
                "browser": browser.version, "theme": "light", "locale": "en-US", "timezone": "UTC",
                "viewport": {"width": 1440, "height": 900}, "reduced_motion": "reduce",
                "captures": captures}, indent=2) + "\n", encoding="utf-8")
        finally:
            (demo.evidence / "browser-errors.log").write_text("\n".join(issues), encoding="utf-8")
            browser.close()
    for record in captures:
        demo.check_controls()
        name = Path(record["file"]).stem
        output = demo.run(f"{name}-ocr", "tesseract", SHOTS / record["file"], "stdout")
        (SHOTS / f"{name}.ocr.txt").write_bytes(output)
    scan = demo.run("artifact-scan", "bash", "scripts/scan.sh", SHOTS)
    require(b"SCAN PASS:" in scan, "artifact scan omitted its pass line")
    sys.stdout.buffer.write(scan)


def interrupt(signum, frame):
    raise Failed(f"capture interrupted by signal {signum}")


def main():
    require(sys.platform.startswith("linux"), "capture requires a disposable Linux box")
    require(len(sys.argv) in (2, 3), "invalid capture invocation")
    work = Path(sys.argv[1]).resolve()
    require(work.parent == Path("/tmp") and work.name.startswith("lb-dash-shots."), "invalid work directory")
    demo = Demo(work)
    if len(sys.argv) == 3:
        mode = sys.argv[2]
        require(mode in ("bootstrap", "top", "stream"), "invalid demo mode")
        if mode == "bootstrap":
            demo.briefing("bootstrap")
            notice = demo.control / "notice.json"
            notice.write_text(json.dumps({"kind": "demo.notice", "actor": "supervisor:bootstrap",
                                  "protocol_version": "1.3.0", "payload": {"text": "Preparing the synthetic capture"}})
                                  + "\n", encoding="utf-8")
            demo.cli("notice", "event", "append", "--config", "demo", "--file", notice)
            demo.run("dispatch-top", sys.executable, "-I", Path(__file__), work,
                     "top", limit=540, headless=True)
        else:
            demo.controller(mode)
        return
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    failed = None
    try:
        demo.prepare()
        demo.briefing()
        demo.launch_top()
        demo.await_activity()
        capture(demo, demo.dashboard())
        demo.collect()
    except BaseException as error:
        failed = error
        (demo.evidence / "failure.log").write_text(traceback.format_exc(), encoding="utf-8")
        if not isinstance(error, CommandFailed) and LAST_FAILURE is None and demo.last_command:
            failed_output(*demo.last_command)
        demo.failed_lane_output()
        demo.release("capture failed; retain evidence and stop held runners")
        # Only stop processes after failure; preserve worktrees and all evidence.
        # A CLI refusal prevents further CLI operations, including collection.
        if demo.dashboard_pid is not None:
            demo.stop_dashboard()
        demo.wait_controls()
        if not isinstance(error, CommandFailed) or error.code != 2:
            demo.stop_lanes()
        raise
    finally:
        if failed is not None:
            print("FAIL: capture incomplete; no SHOTS archive is emitted", flush=True)
            print("FAIL: capture incomplete; no SHOTS archive is emitted", file=sys.stderr)
    print("PASS: capture checks and collection completed; no authenticated AI-service test")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Playwright exceptions can contain the URL fragment. Keep them only
        # in private evidence, never in the harvested publication transcript.
        if LAST_FAILURE is None and LAST_COMMAND is not None:
            failed_output(*LAST_COMMAND)
        detail = str(error) if isinstance(error, Failed) else type(error).__name__
        print(f"FAIL: {detail}; inspect retained evidence", flush=True)
        print(f"FAIL: {detail}; inspect retained evidence", file=sys.stderr)
        if len(sys.argv) in (2, 3):
            work = Path(sys.argv[1]).resolve()
            if work.parent == Path("/tmp") and work.name.startswith("lb-dash-shots."):
                role = sys.argv[2] if len(sys.argv) == 3 else "capture"
                if LAST_FAILURE is not None:
                    out, err = LAST_FAILURE
                    (work / "evidence" / f"failure-{role}.stdout").write_bytes(out)
                    (work / "evidence" / f"failure-{role}.stderr").write_bytes(err)
                (work / "evidence" / f"failure-{role}.log").write_text(traceback.format_exc(), encoding="utf-8")
        sys.exit(error.code if isinstance(error, CommandFailed) else 1)
