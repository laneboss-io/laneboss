"""Standalone R7/R8/R9 dashboard rows against supplied real launcher binaries.

Run on the disposable Linux box. LANEBOSS_BIN supplies the release binary and
LANEBOSS_FAULTS_BIN supplies the same source built with laneboss_faults. This
file imports no product implementation or private-suite helper. Its provider
double executes real CLI commands from a real lane process; principals, events,
mail, role tickets and HTTP responses are all produced by the launcher.
"""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import pty
import queue
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid

# The provider double runs with -I, so its imports come only from this fixture's own helper directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from orgsupport import ROLES, init_org


def write_json(path, value):
    pending = path.with_name(path.name + ".pending")
    pending.write_text(json.dumps(value), encoding="utf-8")
    pending.replace(path)


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def command_result(argv, environment, directory, stdin=None):
    result = subprocess.run(argv, cwd=directory, env=environment, input=stdin,
                            capture_output=True, text=True, timeout=60)
    return {"code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def dashboard_result(argv, environment, directory, processes):
    process = subprocess.Popen(argv, cwd=directory, env=environment, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, encoding="utf-8")
    processes.append(process)
    first = queue.Queue()
    threading.Thread(target=lambda: first.put(process.stdout.readline()), daemon=True).start()
    try:
        line = first.get(timeout=25).strip()
    except queue.Empty:
        stop_process(process)
        raise AssertionError("dashboard emitted no readiness or refusal line")
    if not line:
        process.wait(timeout=10)
        return {"code": process.returncode, "line": "", "stderr": process.stderr.read()}
    return {"code": process.poll(), "line": line, "pid": process.pid}


def terminal_host(connection, environment, directory):
    """A persistent controlling tty keeps issued role tickets in its ancestry."""
    processes = []
    stream = connection.makefile("rwb")
    try:
        for line in stream:
            request = json.loads(line)
            operation = request["operation"]
            if operation == "close":
                break
            try:
                selected = dict(environment)
                if request.get("fault"):
                    selected["LANEBOSS_FAULTS"] = json.dumps({"point": request["fault"]})
                if operation == "role":
                    # This signal alone grants nothing: the real start command
                    # has already issued this tty's process-bound role ticket.
                    environment["LANEBOSS_ROLE"] = request["role"]
                    answer = {"role": request["role"]}
                elif operation == "dashboard":
                    answer = dashboard_result(request["argv"], selected, directory, processes)
                elif operation == "run":
                    answer = command_result(request["argv"], selected, directory, request.get("stdin"))
                else:
                    raise AssertionError("unknown terminal operation")
            except Exception as error:
                answer = {"error": str(error)}
            stream.write(json.dumps(answer).encode() + b"\n")
            stream.flush()
    finally:
        for process in processes:
            stop_process(process)
            process.stdout.close()
            process.stderr.close()
        stream.close()
        connection.close()


class Terminal:
    def __init__(self, environment, directory, test=None):
        self.delegate = None
        self.closed = False
        if test is not None:
            from ticket_fixture import service_rows
            if service_rows(test, environment):
                from ticket_actors import ServiceActors
                self.delegate = ServiceActors(test, test.binary, environment, directory)
                return
        parent, child = socket.socketpair()
        self.pid, self.tty = pty.fork()
        if self.pid == 0:
            parent.close()
            try:
                terminal_host(child, dict(environment), str(directory))
            except BaseException:
                os._exit(1)
            else:
                os._exit(0)
        child.close()
        parent.settimeout(90)
        self.connection = parent
        self.stream = parent.makefile("rwb")

    def request(self, operation, **arguments):
        if self.delegate is not None:
            if operation == "role":
                self.delegate.select_role(arguments["role"])
                return {"role": self.delegate.default_role}
            argv = arguments["argv"]
            environment = {}
            if arguments.get("fault"):
                environment["LANEBOSS_FAULTS"] = json.dumps({"point": arguments["fault"]})
            result = self.delegate.request(argv[1:], binary=argv[0],
                stdin=arguments.get("stdin", ""), serve=operation == "dashboard", environment=environment)
            if operation == "dashboard":
                return {"code": result["exit"], "line": result.get("stdout", ""),
                        "pid": result.get("pid"), "stderr": result.get("stderr", "")}
            return result
        self.stream.write(json.dumps(dict(operation=operation, **arguments)).encode() + b"\n")
        self.stream.flush()
        line = self.stream.readline()
        if not line:
            raise AssertionError("terminal host closed without a result")
        result = json.loads(line)
        if "error" in result:
            raise AssertionError(result["error"])
        return result

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.delegate is not None:
            self.delegate.close()
            return
        self.stream.write(b'{"operation":"close"}\n')
        self.stream.flush()
        deadline = time.monotonic() + 20
        while True:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                if os.waitstatus_to_exitcode(status) != 0:
                    raise AssertionError("terminal host did not close successfully")
                break
            if time.monotonic() >= deadline:
                os.kill(self.pid, signal.SIGKILL)
                os.waitpid(self.pid, 0)
                raise AssertionError("terminal host did not stop")
            time.sleep(0.05)
        self.stream.close()
        self.connection.close()
        os.close(self.tty)


def provider(arguments):
    """Input-driven provider double; command responses come from real binaries."""
    worktree, lane, session = Path(arguments[0]), arguments[1], arguments[2]
    sys.stdin.buffer.read()
    print(json.dumps({"type": "system", "subtype": "init", "session_id": session}), flush=True)
    control = worktree / "row-control"
    control.mkdir(exist_ok=True)
    write_json(control / "ready.json", {"pid": os.getpid(), "lane": lane})
    if not (control / "live").exists():
        print(json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": "Provider completed its supplied turn."}]}}), flush=True)
        return
    seen = set()
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        for path in sorted(control.glob("request-*.json")):
            if path.name in seen:
                continue
            request = json.loads(path.read_text(encoding="utf-8"))
            if request.get("dashboard"):
                processes = []
                try:
                    result = dashboard_result(request["argv"], None, str(worktree), processes)
                finally:
                    for process in processes:
                        stop_process(process)
                        process.stdout.close()
                        process.stderr.close()
            else:
                result = command_result(request["argv"], None, str(worktree), request.get("stdin"))
            write_json(control / path.name.replace("request-", "result-"), result)
            seen.add(path.name)
        time.sleep(0.05)
    raise AssertionError("provider's bounded live period expired")


class ReportDashboardTest(unittest.TestCase):
    def setUp(self):
        value = os.environ.get("LANEBOSS_BIN")
        self.assertTrue(value and Path(value).is_absolute() and os.access(value, os.X_OK),
                        "LANEBOSS_BIN must name an executable absolute path")
        self.binary = Path(value)
        evidence = os.environ.get("LANEBOSS_ROW_EVIDENCE")
        if evidence:
            retained = Path(evidence)
            self.assertTrue(retained.is_absolute(), "LANEBOSS_ROW_EVIDENCE must be absolute")
            retained.mkdir(parents=True, exist_ok=True)
            self.directory = Path(tempfile.mkdtemp(prefix="lb-report-dashboard-", dir=retained))
            (self.directory / "row.txt").write_text(self._testMethodName + "\n", encoding="utf-8")
        else:
            temporary = tempfile.TemporaryDirectory(prefix="lb-report-dashboard-")
            self.addCleanup(temporary.cleanup)
            self.directory = Path(temporary.name)
        self.config_home = self.directory / "config"
        self.state_home = self.directory / "state"
        self.user_home = self.directory / "user"
        for path in (self.config_home, self.state_home, self.user_home):
            path.mkdir()
        self.environment = {name: os.environ[name] for name in ("PATH", "LANG", "TMPDIR", "USER") if name in os.environ}
        self.environment.update(HOME=str(self.user_home), LANEBOSS_HOME=str(self.config_home),
                                LANEBOSS_STATE_HOME=str(self.state_home), TMUX_TMPDIR=str(self.directory),
                                LANEBOSS_TEST_CLAIMS_DIR=str(self.directory / "claims"))
        # Lane starts enforce the org's role templates: the configuration names an org with the role library.
        init_org(self.binary, self.environment, self.directory, self.config_home, "alpha-org")
        config = self.config_home / "configs" / "alpha"
        (config / "rules").mkdir(parents=True)
        (config / "rules" / "standing.md").write_text("# Fixture policy\nRecord the actual caller.\n", encoding="utf-8")
        source = str(Path(__file__).resolve())
        command = [sys.executable, "-I", source, "--provider", "{worktree}", "{lane}", "{session}"]
        text = ('schema_version = 1\nname = "alpha"\ndescription = "Report dashboard row"\norganisation = "alpha-org"\n'
                'rules = ["rules/standing.md"]\n[lanes]\nbudget_minutes = 10\nquiet_seconds = 600\nstop_grace_seconds = 2\n'
                '[runners.fixture]\ncommand = ' + json.dumps(command) + '\nresume = ' + json.dumps(command) +
                '\nprompt = "stdin"\nquiet_seconds = 900\n'
                'records = [{format = "claude-code", paths = ["{worktree}/.sessions/{session}.jsonl"]}]\n'
                '[[routing.standard]]\nrunner = "fixture"\nmodel = "fixture-model-1"\n')
        for name, level in (("mini-a", 6), ("mini-b", 6)):
            text += '\n[supervisors.' + name + ']\nlevel = ' + str(level) + '\nrunner = "fixture"\n'
        (config / "config.toml").write_text(text, encoding="utf-8")
        self.human = Terminal(self.environment, self.directory, self)
        self.addCleanup(self.human.close)
        self.worktrees = {}
        self.active = set()
        self.adopted = set()
        self.addCleanup(self.collect_lanes)
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def run_cli(self, *arguments, terminal=None, binary=None, code=0, fault=None):
        from ticket_fixture import with_registration
        arguments = with_registration(self, arguments, self.environment)
        result = (terminal or self.human).request("run", argv=[str(binary or self.binary), *map(str, arguments)], fault=fault)
        self.assertEqual(result["code"], code, "launcher command failed: " + result["stderr"])
        return result

    def json_cli(self, *arguments, **options):
        return json.loads(self.run_cli(*arguments, **options)["stdout"])

    def events(self):
        return self.json_cli("state", "events", "--config", "alpha")

    def wait(self, condition, reason):
        deadline = time.monotonic() + 30
        while True:
            result = condition()
            if result:
                return result
            self.assertLess(time.monotonic(), deadline, reason)
            time.sleep(0.1)

    def settled(self, lane, run=1):
        self.wait(lambda: any(event["kind"] == "lane.ended" and event["lane"] == lane and
                              event["payload"]["run"] == run for event in self.events()), "run did not end")
        self.wait(lambda: not self.json_cli("lane", "status", "--config", "alpha", "--lane", lane)["live"]["session_alive"],
                  "ended session did not close")

    def role(self, name):
        terminal = Terminal(self.environment, self.directory, self)
        self.addCleanup(terminal.close)
        self.run_cli("start", "--config", "alpha", "--role", name, terminal=terminal)
        terminal.request("role", role=name)
        return terminal

    def start_lane(self, name, *, terminal=None, level=3, live=False, turns=True):
        worktree = self.directory / "work" / name
        (worktree / "row-control").mkdir(parents=True)
        if live:
            (worktree / "row-control" / "live").write_text("live\n", encoding="utf-8")
        brief = worktree / "brief.md"
        brief.write_text("# Row task\nExecute only the supplied provider inputs.\n", encoding="utf-8")
        arguments = ["lane", "start", "--config", "alpha", "--lane", name, "--runner", "fixture",
                     "--model", "fixture-model-1", "--worktree", worktree, "--brief", brief]
        if turns:
            arguments.append("--turns")
        # --level is the lane's level and --role the org role template at that level (the library's default role).
        arguments += ["--role", ROLES[level]]
        if level != 3:
            arguments += ["--level", str(level)]
        result = self.json_cli(*arguments, terminal=terminal)
        self.worktrees[name] = worktree
        self.active.add(name)
        self.wait(lambda: (worktree / "row-control" / "ready.json").is_file(), "provider did not start")
        if not live:
            self.settled(name)
        return result

    def idle_status(self, name):
        status = self.json_cli("lane", "status", "--config", "alpha", "--lane", name)
        live = status["live"]
        busy = status["running"] or live["session_alive"] or (live["supervisor"] or {}).get("alive")
        return None if busy else status

    def collect_lanes(self):
        # The release build keeps a lane's working-directory claim in the account's registry, keyed by the
        # directory's identity, so it outlives this row's private state. A lane left claimed would refuse a
        # later row whose new directory reuses that identity (one lane works in a directory at a time). Every
        # lane is therefore stopped, abandoned and cleaned through the launcher, which releases its claim.
        # An adopted lane is only stopped: lane clean releases the claim of a lane that was started.
        # unittest runs every registered cleanup even when another one fails.
        # Keep each ordinary collection independent so one refusal cannot leave
        # unrelated lane claims behind; each failure still makes the row red.
        for name in sorted(self.active | self.adopted, reverse=True):
            self.addCleanup(self.collect_lane, name)

    def collect_lane(self, name):
        if self.json_cli("lane", "status", "--config", "alpha", "--lane", name)["running"]:
            self.run_cli("lane", "stop", "--config", "alpha", "--lane", name)
        status = self.wait(lambda: self.idle_status(name), "lane " + name + " did not settle")
        if name in self.adopted or status.get("cleaned"):
            return
        if status.get("reason") == "lost":
            # Lost runs project to state verifying, with reason lost. Their
            # killed supervisor cannot close the output span. The archive
            # contract accepts a reviewed report of the observed run/output.
            directory = self.state_home / "alpha" / "lanes" / name
            output = (directory / "output.log").read_text(encoding="utf-8")
            self.assertTrue(output, "the lost runner must retain real output")
            report = directory / "report.md"
            text = ("# Lost fixture run\n\nObserved lane " + name + ", run " + str(status["run"]) +
                    ", state " + status["state"] + ", reason " + status["reason"] +
                    ".\n\nRetained runner output:\n\n" + output)
            report.write_text(text, encoding="utf-8")
            self.assertEqual(report.read_text(encoding="utf-8"), text,
                             "archive collection must receive the complete observed lost-run report")
        if status["state"] not in ("merged", "abandoned"):
            self.run_cli("lane", "mark", "--config", "alpha", "--lane", name, "--state", "abandoned")
        cleaned = self.json_cli("lane", "clean", "--config", "alpha", "--lane", name)
        self.assertFalse(cleaned["pending"], "fixture collection must release the lane claim now")
        retained = self.json_cli("lane", "status", "--config", "alpha", "--lane", name)
        self.assertTrue(retained["cleaned"], "the ordinary clean must record completed collection")

    def dashboard(self, *, binary=None, fault=None):
        result = self.human.request("dashboard", argv=[str(binary or self.binary), "dashboard", "--config", "alpha", "--port", "0"], fault=fault)
        self.assertIsNone(result["code"], "human dashboard did not start")
        parsed = urllib.parse.urlsplit(result["line"])
        self.assertEqual(parsed.hostname, "127.0.0.1")
        token = urllib.parse.parse_qs(parsed.fragment).get("t", [""])[0]
        self.assertRegex(token, r"^[0-9a-f]{64}$")
        base = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
        return base, token

    def request(self, dashboard, path, *, payload=None, auth=True):
        base, token = dashboard
        headers = {"X-Laneboss-Token": token} if auth else {}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode()
            headers.update({"Origin": base, "Content-Type": "application/json"})
        request = urllib.request.Request(base + path, data=body, headers=headers)
        try:
            with self.http.open(request, timeout=15) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            with error:
                return error.code, error.read()

    def api(self, dashboard, path):
        status, data = self.request(dashboard, path)
        self.assertEqual(status, 200)
        return json.loads(data)

    def lane_action(self, lane, arguments, *, dashboard=False):
        directory = self.worktrees[lane] / "row-control"
        identity = uuid.uuid4().hex
        source = directory / ("request-" + identity + ".json")
        write_json(source, {"argv": [str(self.binary), *map(str, arguments)], "dashboard": dashboard})
        result = directory / ("result-" + identity + ".json")
        self.wait(result.is_file, "lane did not execute its supplied command")
        return json.loads(result.read_text(encoding="utf-8"))

    def send_matrix(self, dashboard, names):
        result = []
        for name in names:
            text = "Human delivery " + uuid.uuid4().hex
            status, body = self.request(dashboard, "/api/messages/send", payload={"to": name, "text": text})
            result.append({"lane": name, "status": status, "body": body, "text": text})
        return result

    def assert_human_delivery(self, rows):
        records = self.events()
        for row in rows:
            self.assertEqual(row["status"], 201, "human could not reach a recorded lane")
            receipt = json.loads(row["body"])["event"]
            matches = [event for event in records if event["id"] == receipt["id"] and event["seq"] == receipt["seq"]]
            self.assertEqual(len(matches), 1)
            event = matches[0]
            self.assertEqual((event["kind"], event["lane"], event["actor"]), ("lane.mailed", row["lane"], "human"))
            self.assertEqual(event["payload"]["sender"], "human")
            self.assertEqual(event["payload"]["sha256"], hashlib.sha256(row["text"].encode()).hexdigest())

    def level_lanes(self):
        names = []
        for level in (3, 4, 5, 6):
            name = "human-level-" + str(level)
            self.start_lane(name, level=level)
            names.append(name)
        records = self.events()
        for level, name in zip((3, 4, 5, 6), names):
            event = next(event for event in records if event["kind"] == "lane.started" and event["lane"] == name)
            self.assertEqual(event["payload"]["level"], level)
            self.assertEqual(event["payload"]["starter"], "human")
            self.assertEqual(event["payload"]["level_source"], "protocol" if level == 3 else "org")
        return names

    def test_r7_human_and_peer_rule(self):
        names = self.level_lanes()
        dashboard = self.dashboard()
        self.assert_human_delivery(self.send_matrix(dashboard, names))
        status, body = self.request(dashboard, "/api/messages/send", auth=False,
                                    payload={"to": names[0], "text": "Unauthenticated control"})
        self.assertEqual((status, body), (401, b""))
        mini_a, mini_b = self.role("mini-a"), self.role("mini-b")
        self.start_lane("a1", terminal=mini_a, live=True)
        self.start_lane("b4", terminal=mini_b, level=4)
        before = [event for event in self.events() if event["kind"] == "lane.mailed" and event["lane"] == "b4"]
        message = self.worktrees["a1"] / "peer-message.md"
        message.write_text("Recorded cross-supervisor control", encoding="utf-8")
        denied = self.lane_action("a1", ["lane", "send", "--config", "alpha", "--lane", "b4", "--file", message])
        self.assertEqual(denied["code"], 2)
        self.assertIn("may not message", denied["stderr"])
        self.assertIn("Instead:", denied["stderr"])
        self.assertIn("supervisor:mini-a", denied["stderr"])
        self.assertIn("supervisor:mini-b", denied["stderr"])
        self.assertEqual([event for event in self.events() if event["kind"] == "lane.mailed" and event["lane"] == "b4"], before)
        denied = self.lane_action("a1", ["dashboard", "--config", "alpha", "--port", "0"], dashboard=True)
        self.assertEqual(denied["code"], 2, "a real lane process opened a dashboard")
        self.assertNotIn("#t=", denied.get("line", ""))

    def test_r7_peers_no_human_exception_mutant(self):
        value = os.environ.get("LANEBOSS_FAULTS_BIN")
        self.assertTrue(value and Path(value).is_absolute() and os.access(value, os.X_OK),
                        "LANEBOSS_FAULTS_BIN must name the tagged executable")
        names = self.level_lanes()
        self.assert_human_delivery(self.send_matrix(self.dashboard(), names))
        before = len([event for event in self.events() if event["kind"] == "lane.mailed"])
        mutant = self.dashboard(binary=Path(value), fault="peers-no-human-exception")
        rows = self.send_matrix(mutant, names)
        self.assertTrue(all(row["status"] != 201 for row in rows), "human-exception mutant did not deny actual delivery")
        self.assertEqual(len([event for event in self.events() if event["kind"] == "lane.mailed"]), before)
        with self.assertRaisesRegex(AssertionError, "human could not reach"):
            self.assert_human_delivery(rows)

    def test_r9_event_level_cells(self):
        """Actual lifecycle rows inherit lane levels; unknown rows stay compact in both locales."""
        from playwright.sync_api import Error as PlaywrightError, sync_playwright

        starter = self.role("mini-a")
        for lane, level in (("level-three", 3), ("level-four", 4)):
            self.start_lane(lane, terminal=starter, level=level, turns=False)
            self.run_cli("lane", "mark", "--config", "alpha", "--lane", lane,
                         "--state", "accepted", terminal=starter)
        notice = self.directory / "notice.json"
        notice.write_text(json.dumps({"kind": "level.notice", "actor": "cli",
                         "protocol_version": "1.3.0", "payload": {"text": "Unscoped level row"}}), encoding="utf-8")
        self.run_cli("event", "append", "--config", "alpha", "--file", notice)
        dashboard = self.dashboard()
        rows = self.api(dashboard, "/api/events?view=board&limit=100")["events"]
        lifecycle = [row for row in rows if row["kind"] in ("lane.started", "lane.ended", "lane.state")]

        def check_lifecycle_levels(records):
            expected = {(lane, kind) for lane in ("level-three", "level-four")
                        for kind in ("lane.started", "lane.ended", "lane.state")}
            self.assertEqual(len(records), len(expected), "a real lifecycle event is missing")
            self.assertEqual({(row["lane"], row["kind"]) for row in records}, expected)
            for row in records:
                self.assertEqual(row["level"], 3 if row["lane"] == "level-three" else 4,
                                 "a real lifecycle event lost its recorded lane level")

        self.assertTrue(lifecycle, "no real lifecycle rows were produced")
        control = [dict(row) for row in lifecycle]
        control[0]["level"] = None
        with self.assertRaisesRegex(AssertionError, "recorded lane level"):
            check_lifecycle_levels(control)
        print("NEGATIVE CONTROL: missing inherited lifecycle level rejected")
        check_lifecycle_levels(lifecycle)
        unknown = next(row for row in rows if row["kind"] == "level.notice")
        self.assertIsNone(unknown["level"], "an unscoped event acquired a level")
        base, token = dashboard
        # Distinguish a server that cannot serve its static page from a stalled
        # renderer. Keep the actual HTML and bounded HTTP timing, never the URL's
        # bearer fragment. A timeout increase requires evidence of a later load.
        probe_started = time.monotonic()
        status, document = self.request(dashboard, "/", auth=False)
        startup = {"http": {"status": status, "bytes": len(document),
                            "elapsed_ms": round((time.monotonic() - probe_started) * 1000),
                            "sha256": hashlib.sha256(document).hexdigest()},
                   "navigation": [], "crashed": False}
        (self.directory / "r9-page.html").write_bytes(document)
        write_json(self.directory / "r9-startup.json", startup)
        self.assertEqual(status, 200, "the dashboard server could not serve its page")
        self.assertIn(b"<!doctype html>", document.lower(), "the dashboard response is not HTML")
        self.assertIn(b'id="events-content"', document, "the event board is absent from the served page")
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            browser_failure = None
            try:
                page = browser.new_page(viewport={"width": 1440, "height": 900}, locale="en-US")
                page_errors = []

                def redact(value):
                    return re.sub(r"[0-9a-f]{64}", "[hash or token withheld]",
                                  str(value).replace(token, "[token withheld]"))[:2000]

                def remember_error(value):
                    page_errors.append(redact(value))
                    del page_errors[:-20]

                page.on("pageerror", remember_error)
                page.on("console", lambda message: remember_error(message.text)
                        if message.type == "error" else None)

                def remember_navigation(response):
                    if response.request.is_navigation_request() and response.frame == page.main_frame:
                        startup["navigation"].append({"status": response.status,
                            "elapsed_ms": round((time.monotonic() - probe_started) * 1000)})

                def remember_crash():
                    startup["crashed"] = True

                page.on("response", remember_navigation)
                page.on("crash", remember_crash)

                def browser_failure(stage, problem):
                    startup["failure"] = stage + ": " + redact(problem)
                    startup["page_errors"] = list(page_errors)
                    startup["browser_connected"] = browser.is_connected()
                    startup["page_closed"] = page.is_closed()
                    write_json(self.directory / "r9-startup.json", startup)
                    details = [stage + ": " + redact(problem),
                               "Root HTTP probe and browser navigation: " + json.dumps(startup),
                               "Page JavaScript/console errors: " +
                               (" | ".join(page_errors) or "[none received]")]
                    for attribute in ("data-loaded", "data-visibility", "lang"):
                        try:
                            value = page.locator("html").get_attribute(attribute, timeout=1000)
                        except PlaywrightError as read_error:
                            details.append(attribute + ": [unreadable: " + type(read_error).__name__ + "]")
                        else:
                            details.append(attribute + ": " + redact(value))
                    # Read only the page's own error/status copy, not records,
                    # settings, storage, request headers or the document source.
                    for selector in ("#events-error", "#sync", "body > p"):
                        try:
                            text = page.locator(selector).first.text_content(timeout=1000)
                        except PlaywrightError as read_error:
                            details.append(selector + ": [unreadable: " + type(read_error).__name__ + "]")
                        else:
                            details.append(selector + ": " + (redact(text) if text else "[empty]"))
                    diagnostic = "\n".join(details)
                    print("\n" + diagnostic, flush=True)
                    raise AssertionError(diagnostic) from None

                # Open the real advertised URL. A navigation failure must not
                # repeat its bearer fragment in the exception transcript.
                try:
                    page.bring_to_front()
                    # This live page polls and deliberately pauses in hidden
                    # tabs. Network idleness and animation-frame polling are
                    # not its readiness contract.
                    page.goto(base + "/#t=" + token, wait_until="domcontentloaded")
                    page.bring_to_front()
                    page.wait_for_function("() => document.visibilityState === 'visible'", polling=100)
                    page.wait_for_function("() => document.documentElement.dataset.loaded === 'true'", polling=100)
                    startup["loaded_ms"] = round((time.monotonic() - probe_started) * 1000)
                    write_json(self.directory / "r9-startup.json", startup)
                except PlaywrightError as problem:
                    browser_failure("authenticated dashboard startup failed", problem)
                self.assertEqual(page.locator("#events-error").inner_text(), "",
                                 "the real event panel failed to load")
                try:
                    page.locator("#events-content tbody tr").first.wait_for()
                except PlaywrightError as problem:
                    browser_failure("the event board did not render", problem)
                page.locator("#watch-pause").click()
                cell = page.locator("#events-content tbody tr").filter(has_text="level.notice").locator("td").nth(2)

                def check_unknown():
                    self.assertEqual(cell.inner_text(), "—", "unknown event level must use a single dash")
                    self.assertEqual(cell.evaluate("element => getComputedStyle(element).whiteSpace"),
                                     "nowrap", "event level can wrap")
                    self.assertLessEqual(cell.evaluate("element => element.scrollWidth"),
                                         cell.evaluate("element => element.clientWidth") + 1)

                original = cell.inner_html()
                cell.evaluate("element => { element.textContent = 'Level not recorded'; }")
                with self.assertRaisesRegex(AssertionError, "single dash"):
                    check_unknown()
                print("NEGATIVE CONTROL: verbose unknown-level cell rejected before the actual cell passes")
                cell.evaluate("(element, html) => { element.innerHTML = html; }", original)
                cell.evaluate("element => { element.style.setProperty('white-space', 'normal', 'important'); }")
                with self.assertRaisesRegex(AssertionError, "event level can wrap"):
                    check_unknown()
                print("NEGATIVE CONTROL: wrapping event-level cell rejected")
                cell.evaluate("element => { element.style.removeProperty('white-space'); }")
                for locale, title in (("en", "Level not recorded"), ("zh-TW", "未記錄層級")):
                    page.locator("#language-choice").select_option(locale)
                    page.wait_for_function("locale => document.documentElement.lang === locale", arg=locale, polling=100)
                    check_unknown()
                    self.assertEqual(cell.locator("span").first.get_attribute("title"), title)
                    rendered = page.locator("#events-content tbody tr").evaluate_all(
                        "rows => rows.map(row => [...row.children].map(cell => cell.textContent))")
                    known = [row for row in rendered if row[3] in ("lane.started", "lane.ended", "lane.state")]
                    self.assertEqual(len(known), len(lifecycle))
                    for row in known:
                        self.assertEqual(row[2], "L3" if row[1] == "level-three" else "L4")
            except PlaywrightError as problem:
                if browser_failure is not None:
                    browser_failure("dashboard browser operation failed", problem)
                raise AssertionError("dashboard page creation failed: " +
                                     str(problem).replace(token, "[token withheld]")) from None
            finally:
                browser.close()

    def test_r8_lifecycle_display(self):
        mini_a = self.role("mini-a")
        principal = "supervisor:mini-a"
        self.start_lane("r8-resume", terminal=mini_a, turns=False)
        self.run_cli("lane", "resume", "--config", "alpha", "--lane", "r8-resume", terminal=mini_a)
        self.settled("r8-resume", 2)
        self.start_lane("r8-turn", terminal=mini_a)
        message = self.directory / "turn-message.md"
        message.write_text("Recorded wake-up", encoding="utf-8")
        self.run_cli("lane", "send", "--config", "alpha", "--lane", "r8-turn", "--file", message, terminal=mini_a)
        self.run_cli("lane", "turn", "--config", "alpha", "--lane", "r8-turn", terminal=mini_a)
        self.settled("r8-turn", 2)
        self.start_lane("r8-stop", terminal=mini_a, live=True, turns=False)
        self.run_cli("lane", "stop", "--config", "alpha", "--lane", "r8-stop")
        self.settled("r8-stop")
        self.start_lane("r8-state", terminal=mini_a, turns=False)
        # The fixture configuration declares no guards, so there is nothing to scan and the launcher refuses
        # --accept-uncovered ("configuration has no guards, so nothing is scanned"). The marks need no flag.
        for state in ("accepted", "merged"):
            self.run_cli("lane", "mark", "--config", "alpha", "--lane", "r8-state", "--state", state, terminal=mini_a)
        self.start_lane("r8-clean", terminal=mini_a, turns=False)
        self.run_cli("lane", "mark", "--config", "alpha", "--lane", "r8-clean", "--state", "abandoned", terminal=mini_a)
        self.run_cli("lane", "clean", "--config", "alpha", "--lane", "r8-clean", terminal=mini_a)
        self.active.remove("r8-clean")
        worktree = self.directory / "work" / "r8-adopt"
        (worktree / ".sessions").mkdir(parents=True)
        session = str(uuid.uuid4())
        recorded = worktree / ".sessions" / (session + ".jsonl")
        recorded.write_text(json.dumps({"type": "assistant", "timestamp": datetime.now(timezone.utc).isoformat(),
                                        "cwd": str(worktree), "message": {"content": []}}) + "\n", encoding="utf-8")
        old = time.time() - 3600
        os.utime(recorded, (old, old))
        brief = worktree / "brief.md"
        brief.write_text("# Adopted row session\nRecord its lifecycle.\n", encoding="utf-8")
        self.run_cli("lane", "adopt", "--config", "alpha", "--lane", "r8-adopt", "--session", session,
                     "--runner", "fixture", "--model", "fixture-model-1", "--worktree", worktree, "--brief", brief,
                     "--role", ROLES[3], terminal=mini_a)
        self.adopted.add("r8-adopt")
        self.start_lane("r8-lost", terminal=mini_a, live=True, turns=False)
        live = self.json_cli("lane", "status", "--config", "alpha", "--lane", "r8-lost")["live"]
        pid = live["supervisor"]["pid"]
        self.assertGreater(pid, 1)
        os.kill(pid, signal.SIGKILL)
        provider_pid = json.loads((self.worktrees["r8-lost"] / "row-control" / "ready.json").read_text())["pid"]
        self.assertGreater(provider_pid, 1)
        os.kill(provider_pid, signal.SIGKILL)
        self.wait(lambda: not self.json_cli("lane", "status", "--config", "alpha", "--lane", "r8-lost")["live"]["session_alive"],
                  "lost session stayed open")
        self.run_cli("lane", "check", "--config", "alpha", terminal=mini_a)
        dashboard = self.dashboard()
        graph = self.api(dashboard, "/api/graph")
        nodes = {node["id"]: node for node in graph["nodes"]}
        self.assertEqual(graph["root"]["id"], "human")
        recorded = self.events()
        steps = set()
        for lane in ("r8-resume", "r8-turn", "r8-stop", "r8-state", "r8-clean", "r8-adopt", "r8-lost"):
            self.assertEqual(nodes["lane:" + lane]["parent"], principal)
            self.assertEqual(nodes["lane:" + lane]["starter"], principal)
            source = {event["seq"]: event for event in recorded if event["lane"] == lane}
            rows = self.api(dashboard, "/api/events?" + urllib.parse.urlencode({"lane": lane, "limit": 1000}))
            self.assertEqual({row["seq"] for row in rows}, set(source))
            for row in rows:
                self.assertEqual(row["actor"], source[row["seq"]]["actor"])
                if row["step"]:
                    steps.add(row["step"])
                    expected = "laneboss" if row["step"] in ("ended", "lost") else "human" if row["step"] == "stop" else principal
                    self.assertEqual(row["actor"], expected, "lifecycle who column would display the wrong principal")
        self.assertTrue({"start", "adopt", "resume", "turn", "stop", "accepted", "merged", "abandoned", "clean", "lost"}.issubset(steps),
                        "a required real lifecycle step is absent from the API")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--provider":
        provider(sys.argv[2:])
    else:
        unittest.main(failfast=True)
