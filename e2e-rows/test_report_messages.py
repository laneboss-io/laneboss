"""Standalone black-box rows R2-R6 for the merged report-lines binary.

Run with LANEBOSS_BIN naming an already built executable. No product package is
imported and no binary is built here. The fixtures follow the private suite's
temporary homes, stand-in runners, controlling-pty humans, and strict local
Discord REST probe conventions. Run these rows only on the test machine. R5
runs against LANEBOSS_FAULTS_BIN, a laneboss_faults binary: the loopback Discord
REST adapter exists only there, and the release build ignores
LANEBOSS_TEST_DISCORD_BASE_URL, so R5 on it would call the real service.

LANEBOSS_REPORT_MUTANT selects one tagged point: peers-allow-all (R2),
mail-actor-fixed-supervisor (R3), caller-trust-env (R4), report-stop-at-failure (R5), or
report-drop-without-supervisor (R6). Select that row with unittest; its normal
assertion must fail, and the supplied fault marker must be present.
"""

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen
import uuid

# A stand-in runner invoked with -I explicitly imports only its own fixtures.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from orgsupport import ROLES, init_org, write_rule_source
from reportsupport import POINT_ROWS, TerminalController, fault_environment, mutation_selection, run_request
from commsupport import run_detached_request

# Rows that need a laneboss_faults binary even in a normal run: R5 sends the report's Discord request to this
# file's loopback probe, which only that build allows. Every other row runs on LANEBOSS_BIN.
FAULT_BINARY_ROWS = ("test_R5_discord_500",)


def executable(variable):
    selected = os.environ.get(variable, "")
    path = Path(selected)
    if not selected or not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(variable + " must name the already built executable by absolute path")
    return path


def runner_main(binary, lane, worktree, session):
    directory = Path(worktree)
    prompt = sys.stdin.buffer.read()
    prompt_file = directory / ("prompt-" + uuid.uuid4().hex + ".txt")
    prompt_file.write_bytes(prompt)
    print(json.dumps({"type": "system", "subtype": "init", "session_id": session}), flush=True)
    ready = directory / "ready.tmp"
    ready.write_text(json.dumps({"pid": os.getpid(), "prompt_file": str(prompt_file)}), encoding="utf-8")
    ready.replace(directory / "ready.json")
    if (directory / "once").is_file():
        return
    # Requests arrive in this lane's own worktree. The child command has the
    # runner as a real ancestor; only the agent program is a stand-in.
    completed = set()
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        if (directory / "fixture-finish").is_file():
            return
        for path in sorted(directory.glob("request-*.json")):
            if path.name in completed:
                continue
            request = json.loads(path.read_text(encoding="utf-8"))
            if request.get("communication_detach"):
                response = run_detached_request(request, binary, os.environ, directory)
            else:
                response = run_request(request, binary, os.environ, directory)
            destination = directory / path.name.replace("request-", "response-")
            temporary = destination.with_suffix(".tmp")
            temporary.write_text(json.dumps(response), encoding="utf-8")
            temporary.replace(destination)
            completed.add(path.name)
        time.sleep(0.02)
    raise RuntimeError("stand-in runner exceeded its bounded fixture lifetime")


class DiscordFailureProbe:
    def __init__(self, token, channel):
        self.requests = []
        self.errors = []
        probe = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_arguments):
                return

            def do_POST(self):
                if self.headers.get("Authorization") != "Bot " + token:
                    probe.errors.append("wrong bot authorization")
                if self.path != "/api/v10/channels/" + channel + "/messages":
                    probe.errors.append("wrong report message endpoint")
                length = int(self.headers.get("Content-Length", "0"))
                document = json.loads(self.rfile.read(length))
                probe.requests.append(document)
                body = b'{"message":"injected report delivery failure"}'
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:{}/api/v10".format(self.server.server_port)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class ReportMessageFixture:
    @classmethod
    def setUpClass(cls):
        selected = os.environ.get("LANEBOSS_BIN", "")
        cls.binary = Path(selected)
        if not selected or not cls.binary.is_absolute() or not cls.binary.is_file() or not os.access(cls.binary, os.X_OK):
            raise RuntimeError("LANEBOSS_BIN must name the already built executable by absolute path")

    def setUp(self):
        if self.id().rsplit(".", 1)[-1] in FAULT_BINARY_ROWS or getattr(self, "requires_fault_binary", False):
            self.binary = executable("LANEBOSS_FAULTS_BIN")
        temporary = tempfile.TemporaryDirectory(prefix=getattr(self, "fixture_prefix", "lb-rl-int-report-messages-"))
        self.addCleanup(self.remove_fixture, temporary)
        self.directory = Path(temporary.name).resolve()
        evidence = os.environ.get("LANEBOSS_ROW_EVIDENCE", "")
        if evidence and getattr(self, "evidence_directory", None) is None:
            self.evidence_directory = Path(evidence)
            self.assertTrue(self.evidence_directory.is_absolute(), "LANEBOSS_ROW_EVIDENCE must be absolute")
            self.evidence_directory.mkdir(parents=True, exist_ok=True)
        self.addCleanup(self.retain_fixture)
        self.home = self.directory / "configs-home"
        self.states = self.directory / "states"
        self.config_dir = self.home / "configs" / "rows"
        self.config_dir.mkdir(parents=True)
        user_home = self.directory / "user-home"
        user_home.mkdir()
        self.tmux_temp = tempfile.TemporaryDirectory(prefix="lb-rl-int-", dir="/tmp")
        self.addCleanup(self.tmux_temp.cleanup)
        self.environment = {
            "PATH": os.environ.get("PATH", os.defpath), "HOME": str(user_home),
            "LANEBOSS_HOME": str(self.home), "LANEBOSS_STATE_HOME": str(self.states),
            "LANEBOSS_CONFIG": "rows", "TMUX_TMPDIR": self.tmux_temp.name,
            "LANEBOSS_TEST_CLAIMS_DIR": str(self.directory / "claims"),
        }
        self.mutant, self.fault_marker = mutation_selection(self.directory)
        # Lane starts enforce the org's role templates: every row's configuration names an org with the role library.
        self.organisation = "fixture"
        init_org(self.binary, self.environment, self.directory, self.home, self.organisation)
        self.worktrees = {}
        self.started_lanes = []
        self.request_number = 0
        self.controllers = {}
        self.write_config()
        self.human = TerminalController(self)
        self.addCleanup(self.stop_lanes)

    def write_config(self, file_channel=False):
        command = [sys.executable, "-I", str(Path(__file__).resolve()), "--runner", str(self.binary),
                   "{lane}", "{worktree}", "{session}", "{brief}"]
        text = 'schema_version = 1\nname = "rows"\n'
        if self.organisation:
            text += 'organisation = ' + json.dumps(self.organisation) + '\n'
        if file_channel:
            text += 'owner_channel = "queue"\n'
        text += ('[lanes]\nbudget_minutes = 3\nquiet_seconds = 120\nstop_grace_seconds = 1\n'
                 '[runners.row-runner]\ncommand = ' + json.dumps(command) + '\nresume = ' +
                 json.dumps(command) + '\nprompt = "stdin"\n')
        supervisors = (("mini-a", 4), ("mini-b", 4), ("top-a", 5)) + getattr(self, "extra_supervisors", ())
        for name, level in supervisors:
            text += '\n[supervisors.{}]\nlevel = {}\nrunner = "row-runner"\n'.format(name, level)
            if file_channel:
                text += 'owner_channel = "queue"\n'
        if file_channel:
            text += '\n[owner_channels.queue]\nkind = "file"\npath = "owner/queue.jsonl"\n'
        from ticket_fixture import service_text
        (self.config_dir / "config.toml").write_text(service_text(self, text), encoding="utf-8")

    def retain_fixture(self):
        destination = getattr(self, "evidence_directory", None)
        if destination is not None:
            shutil.copytree(self.directory, destination / self.directory.name, symlinks=True)

    def remove_fixture(self, temporary):
        # Run after lane collection, controllers and evidence retention. org
        # render makes policy files read-only; restore only this fixture's
        # owner permissions before removal, without following its symlinks.
        root = Path(temporary.name)
        root.chmod(stat.S_IMODE(root.lstat().st_mode) | stat.S_IRWXU)

        def walk_error(error):
            raise error

        for directory, directories, files in os.walk(root, followlinks=False, onerror=walk_error):
            for name in directories + files:
                path = Path(directory) / name
                mode = path.lstat().st_mode
                if stat.S_ISDIR(mode):
                    path.chmod(stat.S_IMODE(mode) | stat.S_IRWXU)
                elif stat.S_ISREG(mode):
                    path.chmod(stat.S_IMODE(mode) | stat.S_IWUSR)
        temporary.cleanup()

    def write_rule_source(self, path, text):
        # The fixture acts as the org owner editing policy data, then restores
        # the installed mode. Generated settings still come from org render.
        write_rule_source(self, path, text)

    def cli(self, *args):
        from ticket_fixture import service_rows, with_registration
        if service_rows(self, self.environment):
            return self.human.request(args)
        args = with_registration(self, args, self.environment)
        return run_request({"args": list(map(str, args))}, self.binary, self.environment, self.directory)

    def assert_code(self, result, code, description):
        self.assertEqual(result["code"], code, description + ": " + result.get("stderr", ""))

    def events(self):
        result = self.cli("state", "events", "--config", "rows")
        self.assert_code(result, 0, "read the real event store")
        return json.loads(result["stdout"])

    def lane_events(self, lane, kind=None):
        return [event for event in self.events() if event.get("lane") == lane and
                (kind is None or event["kind"] == kind)]

    def await_value(self, fn, description):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            value = fn()
            if value:
                return value
            time.sleep(0.05)
        self.fail(description)

    def role(self, name):
        if name not in self.controllers:
            controller = TerminalController(self)
            result = controller.request(["start", "--config", "rows", "--role", name], role=name)
            self.assert_code(result, 0, "create the role ticket through start --role")
            self.controllers[name] = controller
        return self.controllers[name]

    def start_lane(self, lane, supervisor="mini-a", environment=None, legacy=False, level=3, once=False):
        worktree = self.directory / "worktrees" / lane
        worktree.mkdir(parents=True)
        self.worktrees[lane] = worktree
        if once:
            (worktree / "once").write_text("Read the prompt and exit.\n", encoding="utf-8")
        brief = self.directory / (lane + ".md")
        brief.write_text("Wait for the fixture's permitted commands in this worktree.\n", encoding="utf-8")
        controller = self.human if supervisor is None else self.role(supervisor)
        result = controller.request(["lane", "start", "--config", "rows", "--lane", lane,
                                     "--worktree", str(worktree), "--brief", str(brief),
                                     "--runner", "row-runner", "--model", "row-runner-model-1", "--turns",
                                     "--role", ROLES[level], "--level", level], environment=environment or {})
        self.assert_code(result, 0, "start the real turn-based lane")
        self.started_lanes.append(lane)
        ready = self.await_value(lambda: json.loads((worktree / "ready.json").read_text())
                                if (worktree / "ready.json").is_file() else None,
                                "the stand-in runner never started")
        location = self.cli("config", "path", "rows")
        self.assert_code(location, 0, "locate the started lane's real state directory")
        paths = json.loads(location["stdout"])
        run_directory = Path(paths["state_dir"]) / "lanes" / lane / "runs"

        def runner_recorded():
            for path in run_directory.glob("*.json"):
                record = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(record.get("runner"), dict) and record["runner"].get("pid") == ready["pid"]:
                    return record
            return None

        self.await_value(runner_recorded, "the real runner's process identity was never recorded")
        started = self.lane_events(lane, "lane.started")[-1]["payload"]
        if legacy:
            self.assertNotIn("starter", started, "the historical fixture must have no recorded starter")
        else:
            self.assertEqual(started["level"], level, "the fixture must record its selected level")
            self.assertEqual(started["starter"], "human" if supervisor is None else "supervisor:" + supervisor,
                             "the fixture must have the actual recorded supervisor")
        return worktree

    def idle_status(self, lane):
        result = self.human.request(["lane", "status", "--config", "rows", "--lane", lane])
        self.assert_code(result, 0, "read the fixture lane's status")
        status = json.loads(result["stdout"])
        live = status["live"]
        busy = status["running"] or live["session_alive"] or (live["supervisor"] or {}).get("alive")
        return None if busy else status

    def stop_lanes(self):
        # The release build keeps a lane's working-directory claim in the account's registry, keyed by the
        # directory's identity, so it outlives this row's private state. A lane left claimed would refuse a
        # later row whose new directory reuses that identity (one lane works in a directory at a time). Every
        # lane is therefore stopped, abandoned and cleaned through the launcher, which releases its claim.
        for lane in self.started_lanes:
            status = self.human.request(["lane", "status", "--config", "rows", "--lane", lane])
            self.assert_code(status, 0, "inspect the fixture before collection")
            live = json.loads(status["stdout"])
            if live["running"] or live["live"]["session_alive"] or live["live"]["survivors"]:
                result = self.human.request(["lane", "stop", "--config", "rows", "--lane", lane])
                self.assert_code(result, 0, "collect the fixture's live lane")
            status = self.await_value(lambda lane=lane: self.idle_status(lane), "the stopped lane never settled")
            if status["state"] not in ("merged", "abandoned"):
                result = self.human.request(["lane", "mark", "--config", "rows", "--lane", lane, "--state", "abandoned"])
                self.assert_code(result, 0, "abandon the fixture lane")
            result = self.human.request(["lane", "clean", "--config", "rows", "--lane", lane])
            self.assert_code(result, 0, "clean the fixture lane and release its directory claim")
        paths = self.cli("config", "path", "rows")
        self.assert_code(paths, 0, "locate the fixture's tmux socket")
        socket = json.loads(paths["stdout"])["socket"]
        result = subprocess.run(["tmux", "-S", socket, "kill-server"], env=self.environment,
                                capture_output=True, text=True, timeout=10)
        # A server may have ended when the last lane stopped. Both explicit
        # outcomes are checked; other cleanup failures remain failures.
        if result.returncode:
            self.assertTrue("no server running" in result.stderr or "No such file" in result.stderr,
                            "fixture tmux collection failed")

    def lane_request(self, lane, args, **options):
        self.request_number += 1
        basename = "{:04d}".format(self.request_number)
        worktree = self.worktrees[lane]
        destination = worktree / ("request-" + basename + ".json")
        temporary = destination.with_suffix(".tmp")
        temporary.write_text(json.dumps({"args": list(map(str, args)), **options}), encoding="utf-8")
        temporary.replace(destination)
        response = worktree / ("response-" + basename + ".json")
        return self.await_value(lambda: json.loads(response.read_text()) if response.is_file() else None,
                                "the inside-lane command never returned")

    def faults(self, point):
        return fault_environment(point, self.mutant, self.fault_marker)

    def mutation_reached(self, point):
        if point and self.mutant == point:
            self.assertTrue(self.fault_marker.is_file(), "the selected mutation did not reach its product call site")

    def peers_fixture(self):
        for lane, supervisor in (("a1", "mini-a"), ("a2", "mini-a"), ("a3", "mini-a"), ("b1", "mini-b")):
            self.start_lane(lane, supervisor)


class ReportMessages(ReportMessageFixture, unittest.TestCase):
    def test_R2_cross_supervisor_refusal(self):
        self.peers_fixture()
        before = self.lane_events("b1", "lane.mailed")
        result = self.lane_request("a1", ["lane", "send", "--config", "rows", "--lane", "b1", "-"],
                                   stdin="cross-supervisor canary\n", environment=self.faults("peers-allow-all"))
        self.mutation_reached("peers-allow-all")
        self.assert_code(result, 2, "R2: cross-supervisor send must be refused")
        self.assertEqual(result["stderr"],
                         "refused: lane a1 (L3, supervisor supervisor:mini-a) may not message lane b1 "
                         "(L3, supervisor supervisor:mini-b): lanes talk only to lanes of the same level "
                         "under the same supervisor.\nInstead: report up with laneboss report "
                         "(to supervisor:mini-a), or message a2, a3 (L3, supervisor supervisor:mini-a).\n")
        self.assertEqual(self.lane_events("b1", "lane.mailed"), before, "R2: a refused send left mail behind")

    def test_R3_peer_delivery_has_lane_actor(self):
        self.peers_fixture()
        text = "same-supervisor canary " + uuid.uuid4().hex + "\n"
        result = self.lane_request("a1", ["lane", "send", "--config", "rows", "--lane", "a2", "-"],
                                   stdin=text, environment=self.faults("mail-actor-fixed-supervisor"))
        self.mutation_reached("mail-actor-fixed-supervisor")
        self.assert_code(result, 0, "R3: a same-level peer under the same supervisor must receive mail")
        receipt = json.loads(result["stdout"])
        events = self.lane_events("a2", "lane.mailed")
        self.assertEqual(len(events), 1, "R3: a delivered message must have exactly one announcement")
        self.assertEqual(events[0]["actor"], "lane:a1", "R3: the event actor must be the resolved sender")
        self.assertEqual(events[0]["payload"]["sender"], "lane:a1")
        data = text.encode("utf-8")
        self.assertEqual(events[0]["payload"]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(Path(receipt["file"]).read_bytes(), data, "R3: the real mail file must hold the exact bytes")

    def test_R4_message_bypass_refusals(self):
        self.peers_fixture()
        before = self.lane_events("b1", "lane.mailed")
        reserved = self.worktrees["a1"] / "reserved.json"
        reserved.write_text(json.dumps({"kind": "lane.mailed", "lane": "b1", "actor": "human",
                                        "protocol_version": "1.0.0", "payload": {}}), encoding="utf-8")
        message = self.worktrees["a1"] / "resume.md"
        message.write_text("resume bypass canary\n", encoding="utf-8")
        attempts = [
            (["event", "append", "--config", "rows", "--file", str(reserved)], {}),
            (["lane", "send", "--config", "rows", "--lane", "a2", "--from", "human", "-"], {"stdin": "spoof canary\n"}),
            (["lane", "send", "--config", "rows", "--lane", "b1", "-"],
             {"stdin": "unset identity canary\n", "unset": ["LANEBOSS_LANE"], "environment": self.faults("caller-trust-env")}),
            (["lane", "attach", "--config", "rows", "--lane", "b1"], {"stdin": "/exit\n"}),
            (["lane", "resume", "--config", "rows", "--lane", "b1", "--message", str(message)], {}),
        ]
        for args, options in attempts:
            with self.subTest(path=args[0:2]):
                result = self.lane_request("a1", args, **options)
                if "unset" in options:
                    self.mutation_reached("caller-trust-env")
                self.assert_code(result, 2, "R4: the message bypass must be refused")
                self.assertIn("refused:", result["stderr"])
                self.assertIn("Instead:", result["stderr"])
        self.assertEqual(self.lane_events("b1", "lane.mailed"), before, "R4: a bypass left cross-supervisor mail")
        # A positive control proves that unsetting a signal did not turn a
        # known lane into an unrelated unknown identity that refuses all mail.
        control = self.lane_request("a1", ["lane", "send", "--config", "rows", "--lane", "a2", "-"],
                                    stdin="recorded ancestry control\n", unset=["LANEBOSS_LANE"],
                                    environment=self.faults("caller-trust-env"))
        self.assert_code(control, 0, "R4: recorded ancestry must still resolve the allowed peer sender")
        self.assertEqual(self.lane_events("a2", "lane.mailed")[-1]["actor"], "lane:a1")

    def install_discord_failure(self):
        token = uuid.uuid4().hex + "." + uuid.uuid4().hex
        channel = str(uuid.uuid4().int % (10**18) + 1)
        self.organisation = "fixture"
        org = self.home / "orgs" / self.organisation
        instance = org / ".laneboss" / "instances" / "top-a"
        instance.mkdir(parents=True)
        (instance / "instance.toml").write_text('name = "top-a"\nlevel = 5\nrole = "supervisor"\n', encoding="utf-8")
        secrets = self.directory / "private-secrets.toml"
        secrets.write_text("REPORT_BOT = " + json.dumps(token) + "\n", encoding="utf-8")
        secrets.chmod(0o600)
        # The org already holds the role library from setUp. The role gate reads schema_version and levels from
        # this same file; the Discord tables are what the row installs.
        (org / ".laneboss" / "org.toml").write_text(
            'schema_version = 1\nlevels = [3, 4, 5, 6]\n'
            '[services.discord]\nguild_id = "123456789"\ntoken_secret = "REPORT_BOT"\n'
            '[secret_store]\nkind = "file"\npath = ' + json.dumps(str(secrets)) + '\n', encoding="utf-8")
        roles = org / ".laneboss" / "shared" / "services" / "discord-roles.toml"
        roles.parent.mkdir(parents=True, exist_ok=True)
        roles.write_text('schema_version = 1\n[roles.top-a]\ninstance = "top-a"\nchannel_id = ' +
                         json.dumps(channel) + '\nchannel_name = "reports"\nstate_file = "state.json"\n'
                         'events_file = "events.jsonl"\nform_doorbell = "forms.json"\n'
                         'members = [{user_id = "987654321", authority = "decide"}]\n', encoding="utf-8")
        probe = DiscordFailureProbe(token, channel)
        self.addCleanup(probe.close)
        return {"LANEBOSS_TEST_DISCORD_BASE_URL": probe.base}, probe

    def test_R5_discord_500(self):
        environment, probe = self.install_discord_failure()
        self.write_config(file_channel=True)
        self.start_lane("reporter", "top-a")
        environment.update(self.faults("report-stop-at-failure"))
        text = "all-channel report canary " + uuid.uuid4().hex
        result = self.lane_request("reporter", ["report", "--config", "rows", "--file", "-"],
                                   stdin=text, environment=environment)
        self.mutation_reached("report-stop-at-failure")
        self.assert_code(result, 4, "R5: a failed Discord channel with other deliveries must exit 4")
        outcomes = {item["channel"]: item for item in map(json.loads, result["stdout"].splitlines())}
        self.assertEqual({name: item["status"] for name, item in outcomes.items()},
                         {"dashboard": "delivered", "discord": "failed", "file": "delivered", "terminal": "skipped"},
                         "R5: failure must not stop the file channel or drop its outcome")
        self.assertIn("HTTP 500", outcomes["discord"]["reason"])
        self.assertEqual(probe.errors, [], "R5: Discord failure must be reached through a valid authenticated request")
        self.assertEqual(len(probe.requests), 1)
        self.assertEqual(probe.requests[0]["content"], text)
        queue = self.config_dir / "owner" / "queue.jsonl"
        kept = [json.loads(line) for line in queue.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(kept[-1]["text"], text, "R5: the actual file channel must retain the complete text")
        report_id = outcomes["dashboard"]["report_id"]
        events = [event for event in self.events() if event["payload"].get("report_id") == report_id]
        sent = [event for event in events if event["kind"] == "report.sent"]
        self.assertEqual(len(sent), 1)
        self.assertEqual((sent[0]["payload"]["from"], sent[0]["payload"]["to"], sent[0]["payload"]["text"]),
                         ("lane:reporter", "supervisor:top-a", text))
        delivered = [event["payload"] for event in events if event["kind"] == "report.delivered"]
        self.assertEqual({item["channel"]: item for item in delivered}, outcomes,
                         "R5: stored outcomes must exactly match stdout")

    def test_R6_human_fallback_in_dashboard(self):
        self.start_lane("human-child", None)
        ready = self.human.request(["dashboard", "--config", "rows", "--port", "0"], background=True)
        address = urlsplit(ready["ready"].strip())
        token = parse_qs(address.fragment)["t"][0]
        base = "{}://{}".format(address.scheme, address.netloc)
        text = "human fallback canary " + uuid.uuid4().hex
        result = self.lane_request("human-child", ["report", "--config", "rows", "--file", "-"],
                                   stdin=text, environment=self.faults("report-drop-without-supervisor"))
        self.mutation_reached("report-drop-without-supervisor")
        self.assert_code(result, 0, "R6: dashboard delivery must succeed without Discord")
        request = Request(base + "/api/messages", headers={"X-Laneboss-Token": token, "Origin": base})
        with urlopen(request, timeout=15) as response:
            self.assertEqual(response.status, 200)
            document = json.load(response)

        def messages(value):
            if isinstance(value, dict):
                yield value
                for item in value.values():
                    yield from messages(item)
            elif isinstance(value, list):
                for item in value:
                    yield from messages(item)

        delivered = [item for item in messages(document) if item.get("text") == text and item.get("to") == "human"]
        self.assertEqual(len(delivered), 1, "R6: /api/messages must contain the report addressed to human")
        self.assertEqual(delivered[0]["from"], "lane:human-child")
        outcomes = [json.loads(line) for line in result["stdout"].splitlines()]
        self.assertEqual({item["channel"]: item["status"] for item in outcomes},
                         {"dashboard": "delivered", "discord": "skipped", "file": "skipped", "terminal": "skipped"})


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--runner":
        runner_main(*sys.argv[2:6])
    else:
        unittest.main()
