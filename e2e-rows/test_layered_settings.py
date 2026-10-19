"""Built-CLI layered settings rows for the disposable Linux test machine.

Only the runner is doubled. It reads the delivered prompt and prints the names
of its actual environment, never its values. CLI parsing, source reads, event
snapshots, tmux, caller identity and resume are the real product paths.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import traceback
import unittest
import uuid
import tomllib

from orgsupport import assert_hook_deprecation, init_org
from headless_support import HeadlessController
from reportsupport import TerminalController


VENDOR_SOURCE = Path(__file__).resolve().parent / "fixtures/layered_runner.py"
ROOM_SOURCE = Path(__file__).resolve().parent / "fixtures/layered_room.py"
# This row needs sibling instance and human sessions. Recording the test parent
# as a supervisor would also identify its terminal descendants as that role.
HUMAN_FIRST = ("test_removed_instance_starter_resume",)


def toml_value(value):
    if isinstance(value, dict):
        return "{" + ", ".join(json.dumps(key) + " = " + toml_value(item) for key, item in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    return json.dumps(value)


class MutationResult(unittest.TestResult):
    """Keep each actual assertion message as well as unittest's traceback."""

    def __init__(self):
        super().__init__()
        self.failure_details = []

    def record_failure(self, test, err, trace, subtest=None):
        frames = {frame.name for frame in traceback.extract_tb(err[2])}
        phase = "tearDown" if "tearDown" in frames else "setUp" if "setUp" in frames else "test"
        self.failure_details.append({"row": test._testMethodName, "assertion": str(err[1]),
                                     "traceback": trace, "subtest": subtest, "phase": phase})

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.record_failure(test, err, self.failures[-1][1])

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None and issubclass(err[0], test.failureException):
            self.record_failure(test, err, self.failures[-1][1], subtest.id())


def setUpModule():
    if not sys.platform.startswith("linux"):
        raise RuntimeError("layered settings rows require the disposable Linux test machine")
    global RELEASE, FAULTS, EVIDENCE, LEGACY
    names = ("LANEBOSS_SETTINGS_BINARY", "LANEBOSS_SETTINGS_FAULTS_BINARY", "LANEBOSS_SETTINGS_EVIDENCE", "LANEBOSS_SETTINGS_LEGACY_BINARY")
    if any(not os.environ.get(name) for name in names):
        raise RuntimeError("check-layered-settings.sh must supply both built binaries and evidence")
    RELEASE, FAULTS, EVIDENCE, LEGACY = (Path(os.environ[name]).resolve(strict=True) for name in names)
    if not EVIDENCE.is_dir() or not all(os.access(path, os.X_OK) for path in (RELEASE, FAULTS, LEGACY)):
        raise RuntimeError("layered settings evidence or binaries are unavailable")
    if any(shutil.which(name) is None for name in ("git", "tmux")):
        raise RuntimeError("layered settings rows require git and tmux")


class SettingsTest(unittest.TestCase):
    binary_override = None
    fault_point = None

    def setUp(self):
        self.directory = EVIDENCE / (self._testMethodName + "-" + uuid.uuid4().hex[:12])
        self.directory.mkdir()
        self.inputs = self.directory / "inputs"
        self.inputs.mkdir()
        self.home = self.directory / "home"
        self.home.mkdir()
        self.binary = self.binary_override or RELEASE
        self.marker = self.directory / "mutant-reached"
        self.env = {"HOME": str(self.home), "PATH": os.defpath, "LANG": "C.UTF-8", "TERM": "dumb",
                    "TMPDIR": str(self.directory), "LANEBOSS_TEST_CLAIMS_DIR": str(self.directory / "claims"),
                    "LAYERED_ALLOWED": uuid.uuid4().hex, "LAYERED_UNLISTED": uuid.uuid4().hex}
        if self.fault_point:
            self.env["LANEBOSS_FAULTS"] = json.dumps({"point": self.fault_point, "marker": str(self.marker)})
        self.environment = self.env  # The shared real-session helper's input.
        self.cli_controller = None
        self.commands = 0
        self.writes = 0
        self.lanes = []
        self.queued_lanes = {}
        self.calls_file = self.directory / "runner-calls.jsonl"
        self.gate = self.directory / "runner-gate"
        self.write(self.gate, "release")
        self.vendor = self.directory / "runner.py"
        self.write(self.vendor, VENDOR_SOURCE.read_text(encoding="utf-8"))
        self.brief = self.directory / "brief.md"
        self.write(self.brief, "# Layered settings input\n\nRead the actual prompt.\n")
        self.follow = self.directory / "follow-up.md"
        self.write(self.follow, "# Layered settings follow-up\n\nRead the next prompt.\n")
        self.org = init_org(self.binary, self.env, self.directory, self.home / ".config/laneboss", "layered")
        self.org_settings = self.org / ".laneboss/settings.toml"
        self.role_settings = self.org / ".laneboss/L3/roles/executor.toml"
        self.instance = "L3-lane-example"
        self.instance_settings = self.org / ".laneboss/instances" / self.instance / "settings.toml"
        self.configure()
        self.org_values(model="fixture-org-1", effort="high", env_allow=["LAYERED_ALLOWED"])
        self.json_cli("config", "validate", "layered")
        if self._testMethodName in HUMAN_FIRST:
            self.cli_controller = TerminalController(self, self.binary, self.env, self.directory)
        else:
            self.json_cli("start", "--config", "layered", "--role", "top", "--format", "json")

    def write(self, path, text):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            path.chmod(path.stat().st_mode | 0o200)
        path.write_text(text, encoding="utf-8")
        self.writes += 1
        saved = self.inputs / (str(self.writes) + ".input")
        saved.write_bytes(path.read_bytes())
        saved.with_suffix(".json").write_text(json.dumps({"path": str(path), "sha256": hashlib.sha256(saved.read_bytes()).hexdigest()}))

    def configure(self, stdin=False, queue=None, room=None, observe_account=False):
        def command(prompt, resume=False):
            words = [str(getattr(self, "runner_program", sys.executable)), str(self.vendor), "stdin" if stdin else prompt, str(self.calls_file),
                    str(self.gate), "{model}", "{effort}", "{session}"]
            words += [str(queue)] if queue else []
            if observe_account:
                words += ["--account", "{account}"]
            return words
        config_dir = self.home / ".config/laneboss/configs/layered"
        text = ('schema_version = 1\nname = "layered"\norganisation = "layered"\n'
                '[lanes]\nbudget_minutes = 1\nquiet_seconds = 30\nstop_grace_seconds = 1\n'
                '[runners.agent]\ncommand = ' + json.dumps(command("{brief}")) + '\n'
                'resume = ' + json.dumps(command("{message}", resume=True)) + '\n'
                'prompt = ' + json.dumps("stdin" if stdin else "argument") + '\n'
                'accounts = ["fixture-seat-one", "fixture-seat-two"]\n'
                + ('room = ' + json.dumps(room) + '\n' if room is not None else '') +
                '[supervisors.top]\nlevel = 5\nrunner = "agent"\n'
                '[[routing.standard]]\nrunner = "agent"\nmodel = "fixture-route-1"\neffort = "high"\n')
        self.write(config_dir / "config.toml", text)

    def org_values(self, **values):
        self.write(self.org_settings, "".join(key + " = " + json.dumps(value) + "\n" for key, value in values.items()))

    def role_values(self, **values):
        text = "drivers = " + json.dumps([Path(sys.executable).name]) + "\n\n[settings]\n"
        text += "".join(key + " = " + json.dumps(value) + "\n" for key, value in values.items())
        self.write(self.role_settings, text)

    def instance_values(self, **values):
        self.write(self.instance_settings, "".join(key + " = " + json.dumps(value) + "\n" for key, value in values.items()))

    def cli(self, *args, extra=None, stdin=None, controller=None):
        self.commands += 1
        argv = [str(self.binary), *(str(arg) for arg in args)]
        environment = dict(self.env)
        if extra:
            environment.update(extra)
        controller = controller or self.cli_controller
        if controller is None:
            result = subprocess.run(argv, cwd=self.directory, env=environment, capture_output=True,
                                    text=True, encoding="utf-8", timeout=60, start_new_session=True, input=stdin)
        else:
            answer = controller.request(argv[1:], environment=extra or {}, stdin=stdin or "")
            result = subprocess.CompletedProcess(argv, answer["code"], answer["stdout"], answer["stderr"])
        stem = self.directory / ("command-" + str(self.commands))
        stem.with_suffix(".json").write_text(json.dumps({"argv": argv, "exit_code": result.returncode}))
        stem.with_suffix(".stdout").write_text(result.stdout)
        stem.with_suffix(".stderr").write_text(result.stderr)
        if stdin is not None:
            stem.with_suffix(".stdin").write_text(stdin)
        if result.returncode == 0 and len(args) >= 3 and args[:2] in (("org", "render"), ("org", "validate")):
            source = Path(args[2]) / ".laneboss/org.toml"
            if tomllib.loads(source.read_text(encoding="utf-8")).get("hooks", {}).get("mode") == "strict":
                assert_hook_deprecation(self, result)
        return result

    def json_cli(self, *args, **kwargs):
        result = self.cli(*args, **kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def start_lane(self, name="settings-lane", sets=(), instance=False, turns=False, account=None):
        worktree = self.directory / name
        worktree.mkdir()
        args = ["lane", "start", "--config", "layered", "--lane", name, "--brief", self.brief,
                "--worktree", worktree, "--difficulty", "standard", "--role", "executor"]
        if instance:
            args += ["--instance", self.instance]
        if turns:
            args += ["--turns"]
        if account is not None:
            args += ["--account", account]
        for item in sets:
            args += ["--set", item]
        answer = self.json_cli(*args)
        self.lanes.append(name)
        self.assertEqual(answer["run"], 1)
        return answer

    def finish(self, name="settings-lane", run=1):
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            row = self.json_cli("lane", "status", "--config", "layered", "--lane", name)
            if row["run"] == run and not row["running"] and not row["live"]["supervisor"]["alive"] and not row["live"]["session_alive"]:
                self.assertEqual(row["reason"], "exit")
                self.assertEqual(row["exit_code"], 0)
                self.assertEqual(row["live"]["survivors"], 0)
                self.assertEqual(row["live"]["pending_events"], 0)
                self.assertEqual(row["live"]["refused_events"], 0)
                return row
            time.sleep(0.1)
        self.fail("the real lane did not end and quiesce")

    def calls(self):
        self.assertTrue(self.calls_file.is_file(), "the real runner must be reached")
        return [json.loads(line) for line in self.calls_file.read_text().splitlines()]

    def delivered_prompt(self, run):
        result = self.cli("event", "tail", "--config", "layered", "--lane", "settings-lane")
        self.assertEqual(result.returncode, 0, result.stderr)
        rendered = [event["payload"]["output"] for event in map(json.loads, result.stdout.splitlines())
                    if event["kind"] == "brief.rendered"]
        self.assertEqual(len(rendered), run, "each run must retain one real rendered input")
        data = Path(rendered[-1]["path"]).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        self.assertEqual(digest, rendered[-1]["sha256"], "retained prompt must match its recorded bytes")
        self.assertEqual(digest, self.calls()[run - 1]["prompt_sha256"],
                         "the actual runner stdin must match the retained prompt")
        return data

    def assert_task_prompt(self, prompt, payload):
        prefix, heading, body = prompt.partition(b"## Your task\n\n")
        self.assertEqual(heading, b"## Your task\n\n", "the rendered task section is missing")
        self.assertTrue(prefix.startswith(b"## Org protocol: "), "task policy must remain first")
        self.assertIn(b"## Your role: executor (L3)\n", prefix)
        expected = payload if payload.endswith(b"\n") else payload + b"\n"
        self.assertEqual(body[:len(expected)], expected, "original task bytes changed")
        self.assertTrue(body[len(expected):].startswith(b"\n<!-- laneboss launcher block: begin (protocol "),
                        "the launcher block must immediately follow the original task")

    def test_idle_payload_then_policy(self):
        """Fails if loop idle ordering changes, manual idle loses task order, or content selects the order."""
        self.configure(stdin=True)
        config = self.home / ".config/laneboss/configs/layered/config.toml"
        payload = "# Idle input — " + uuid.uuid4().hex + "\r\nKeep these complete bytes."
        idle = payload.encode("utf-8")
        self.write(config.parent / "idle.md", payload)
        self.write(config, config.read_text() + '\n[turns]\nidle_message = "idle.md"\n'
                   'idle_seconds = 2\npoll_seconds = 1\n')
        # Identical task and idle bytes ensure the actual turn kind controls ordering.
        self.write(self.brief, payload)
        self.start_lane(turns=True)
        self.finish()
        self.assert_task_prompt(self.delivered_prompt(1), idle)

        result = self.json_cli("lane", "turn", "--config", "layered", "--lane", "settings-lane", "--idle")
        self.assertEqual(result["turn"], {"kind": "idle", "mail": []})
        self.finish(run=2)
        self.assert_task_prompt(self.delivered_prompt(2), idle)

        # Keep the automatic runner live until the loop is stopped, so this
        # fixture cannot race a second automatic idle turn.
        self.write(self.gate, "hold")
        loop = self.json_cli("lane", "loop", "--config", "layered", "--detach")
        try:
            observed = self.cli("event", "tail", "--config", "layered", "--lane", "settings-lane",
                                "--follow", "--until", "loop.turn")
            self.assertEqual(observed.returncode, 0, observed.stderr)
            turns = [event for event in map(json.loads, observed.stdout.splitlines())
                     if event["kind"] == "loop.turn"]
            self.assertEqual(len(turns), 1, "the actual loop must start exactly one turn")
            self.assertEqual(turns[0]["payload"], {"loop": loop["loop"], "kind": "idle",
                                                  "sequences": [], "run": 3})
        finally:
            try:
                stopped = self.json_cli("lane", "loop", "--config", "layered", "--stop")
                self.assertIs(stopped["stopped"], True)
            finally:
                self.write(self.gate, "release")
        self.assertIs(self.json_cli("lane", "loop", "--config", "layered", "--status")["running"], False)
        self.finish(run=3)
        prompt = self.delivered_prompt(3)
        self.assertTrue(prompt.startswith(idle), "a loop idle turn must start with the byte-exact idle payload")
        self.assertEqual(prompt.count(idle), 1, "the idle payload must be delivered once")
        following = prompt[len(idle):]
        self.assertIn(b"## Org protocol: ", following, "idle policy must follow in the same message")
        self.assertIn(b"## Your role: executor (L3)", following)
        self.assertNotIn(b"## Your task\n\n", following, "idle policy must not introduce a second task")
        for relative in ("shared/protocol/rules.md", "L3/protocol/role.md", "L3/roles/executor.md"):
            source = (self.org / ".laneboss" / relative).read_bytes()
            self.assertIn(source, following, "the idle turn must retain the whole policy source")

        self.write(self.follow, payload)
        self.json_cli("lane", "send", "--config", "layered", "--lane", "settings-lane", "--file", self.follow)
        # Queued mail takes precedence over --idle and is still a task turn.
        result = self.json_cli("lane", "turn", "--config", "layered", "--lane", "settings-lane", "--idle")
        self.assertEqual(result["turn"]["kind"], "mail")
        self.finish(run=4)
        prompt = self.delivered_prompt(4)
        self.assertTrue(prompt.startswith(b"## Org protocol: "), "mail task policy must remain first")
        self.assertLess(prompt.index(b"## Your task\n\n"), prompt.index(idle))
        self.assertEqual(prompt.count(idle), 1, "the actual mailed input must arrive once")

    def test_builtin_l4_reviewer(self):
        """Fails if L4 reviewer needs extra sources or an unknown role bypasses the template gate."""
        org = self.directory / "review-org"
        self.json_cli("org", "init", org, "--name", "review-fixture")
        self.json_cli("org", "roles", "init", org)  # 1.0.0 b1: org init no longer copies the role library
        roles = org / ".laneboss/L4/roles"
        self.assertTrue((roles / "reviewer.md").is_file(), "org init must ship the real L4 reviewer template")
        self.assertTrue((roles / "reviewer.toml").is_file(), "org init must ship the L4 reviewer driver policy")
        template = (roles / "reviewer.md").read_bytes()
        drivers = tomllib.loads((roles / "reviewer.toml").read_text())["drivers"]
        self.assertEqual(drivers, ["codex", "claude", "claudock"], "reviewer needs its own driver policy")
        self.assertIn(b"You only read; you change nothing", template, "L4 reviewer must be read-only")
        result = self.json_cli("org", "instance", "add", org, "L4-review", "--level", "4", "--role", "reviewer",
                               "--secret", "REVIEW_API_KEY", "--secret", "REVIEW_CHAT_TOKEN")
        self.assertTrue(result["ok"])
        self.assertGreater(result["changed"], 0)
        instance = org / ".laneboss/instances/L4-review"
        identity = tomllib.loads((instance / "instance.toml").read_text())
        self.assertEqual((identity["level"], identity["role"]), (4, "reviewer"))
        self.assertEqual(identity["secrets"], ["REVIEW_API_KEY", "REVIEW_CHAT_TOKEN"])
        self.assertIn(template.rstrip(b"\n"), (instance / "AGENTS.md").read_bytes(),
                      "the generated instance must carry the actual reviewer policy")
        listed = self.json_cli("org", "roles", "list", org)
        reviewer = [row for row in listed["roles"] if (row["level"], row["role"]) == (4, "reviewer")]
        self.assertEqual(len(reviewer), 1)
        self.assertEqual(reviewer[0]["drivers"], drivers)
        refused = self.cli("org", "instance", "add", org, "L4-unknown", "--level", "4", "--role", "missing-review-role")
        self.assertEqual(refused.returncode, 2, "roles without a template must still refuse")
        self.assertIn("instance role has no template at L4", refused.stderr)
        self.assertFalse((org / ".laneboss/instances/L4-unknown").exists())
        self.assertTrue(self.json_cli("org", "validate", org, "--format", "json")["valid"])

    def test_builtin_l5_reviewer(self):
        """Fails if L5 reviewer lacks real sources, its driver policy or generated instance policy."""
        org = self.directory / "review-org"
        self.json_cli("org", "init", org, "--name", "review-fixture")
        self.json_cli("org", "roles", "init", org)  # 1.0.0 b1: org init no longer copies the role library
        roles = org / ".laneboss/L5/roles"
        self.assertTrue((roles / "reviewer.md").is_file(), "org init must ship the L5 reviewer template")
        self.assertTrue((roles / "reviewer.toml").is_file(), "org init must ship its driver policy")
        template = (roles / "reviewer.md").read_bytes()
        drivers = tomllib.loads((roles / "reviewer.toml").read_text())["drivers"]
        self.assertEqual(drivers, ["claude", "claudock"], "L5 reviewer needs the L5 driver policy")
        self.assertIn(b"change nothing in the reviewed tree", template, "L5 reviewer must be read-only")
        result = self.json_cli("org", "instance", "add", org, "L5-review", "--level", "5", "--role", "reviewer")
        self.assertIs(result["ok"], True)
        self.assertGreater(result["changed"], 0)
        instance = org / ".laneboss/instances/L5-review"
        identity = tomllib.loads((instance / "instance.toml").read_text())
        self.assertEqual((identity["level"], identity["role"]), (5, "reviewer"))
        self.assertIn(template.rstrip(b"\n"), (instance / "AGENTS.md").read_bytes(),
                      "the instance must carry the complete reviewer policy")
        listed = self.json_cli("org", "roles", "list", org)
        reviewers = [row for row in listed["roles"] if (row["level"], row["role"]) == (5, "reviewer")]
        self.assertEqual(len(reviewers), 1)
        self.assertEqual(reviewers[0]["drivers"], drivers)
        self.assertEqual(reviewers[0]["sha256"], hashlib.sha256(template).hexdigest())
        self.assertTrue(self.json_cli("org", "validate", org, "--format", "json")["valid"])

    def test_org_json_compatibility(self):
        """Fails if default JSON grows keys, warnings vanish, or real problems are hidden."""
        plain = self.json_cli("org", "validate", self.org, "--format", "json")
        self.assertEqual(plain, {"valid": True, "problems": []})
        diagnostic = self.json_cli("org", "validate", self.org, "--format", "json-diagnostics")
        self.assertEqual(set(diagnostic), {"valid", "problems", "warnings"})
        self.assertEqual(diagnostic["problems"], plain["problems"])
        unused = ".laneboss/L3/roles/reviewer.md"
        self.assertTrue(any(item["path"] == unused for item in diagnostic["warnings"]),
                        "unused role warnings must remain available")
        text = self.cli("org", "validate", self.org)
        self.assertEqual(text.returncode, 0, text.stderr)
        self.assertIn("warning: " + unused + ":", text.stderr)
        identity = self.org / ".laneboss" / "instances" / "L3-lane-example" / "instance.toml"
        original = identity.read_text()
        self.assertEqual(original.count('role = "executor"'), 1)
        self.write(identity, original.replace('role = "executor"', "role = []", 1))
        problems = []
        for format in ("json", "json-diagnostics"):
            result = self.cli("org", "validate", self.org, "--format", format)
            self.assertEqual(result.returncode, 2, "invalid role data must fail every JSON format")
            report = json.loads(result.stdout)
            self.assertIs(report["valid"], False)
            self.assertTrue(report["problems"], "real validation problems must be retained")
            self.assertTrue(any(item["path"].endswith("L3-lane-example/instance.toml")
                                for item in report["problems"]))
            self.assertEqual(set(report), {"valid", "problems"} if format == "json"
                             else {"valid", "problems", "warnings"})
            problems.append(report["problems"])
        self.assertEqual(problems[0], problems[1], "diagnostic selection must not alter actual problems")
        self.write(identity, original)

    def test_org_defaults_append_compatibility(self):
        """Fails if an appended default lands in hooks, or table order changes schema requirements."""
        org = self.directory / "defaults-org"
        initialized = self.json_cli("org", "init", org, "--name", "defaults-fixture")
        self.json_cli("org", "roles", "init", org)  # 1.0.0 b1: org init no longer copies the role library
        self.assertIs(initialized["ok"], True)
        self.assertGreater(initialized["changed"], 0)
        source = org / ".laneboss/org.toml"
        text = source.read_text(encoding="utf-8")
        # Install the removed legacy field explicitly for compatibility coverage.
        # Init's final table is defaults, so this appends to that table.
        text += "\nallowed_tools = []\n"
        self.write(self.directory / "org-generated.toml", text)
        original_hooks = tomllib.loads(text)["hooks"]
        values = {"services": ["fixture-gateway-" + uuid.uuid4().hex[:8]],
                  "secrets": ["DEFAULT_FIXTURE_TOKEN"],
                  "writable_repos": ["future-repo", "worktrees/future"],
                  "allowed_tools": ["shell", "file.write"]}
        for key, value in values.items():
            self.assertEqual(text.count(key + " = []"), 1, "the generated default array must be present once")
            text = text.replace(key + " = []", key + " = " + json.dumps(value), 1)
        channel = str(10**17 + uuid.uuid4().int % (9 * 10**17))
        text += "\ndiscord_channel_id = " + json.dumps(channel) + "\n"
        self.write(source, text)
        appended = self.cli("org", "validate", org, "--format", "json")
        self.assertEqual(appended.returncode, 0,
                         "a key appended to generated defaults must validate: " + appended.stdout + appended.stderr)
        self.assertEqual(json.loads(appended.stdout), {"valid": True, "problems": []})
        parsed = tomllib.loads(text)
        self.assertEqual(parsed["defaults"].get("discord_channel_id"), channel,
                         "the appended channel must be a default, not a hook field")
        for key, value in values.items():
            self.assertEqual(parsed["defaults"][key], value)
        self.assertEqual(parsed["hooks"], original_hooks, "moving the hooks table must preserve its content")
        headers = [line for line in text.splitlines() if line.startswith("[")]
        self.assertEqual(headers[-1], "[defaults]", "defaults must be the final generated table")

        prefix, hooks_header, tables = text.partition("\n[hooks]\n")
        hooks, defaults_header, defaults = tables.partition("\n[defaults]\n")
        self.assertEqual(hooks_header, "\n[hooks]\n")
        self.assertEqual(defaults_header, "\n[defaults]\n")
        hooks_last = prefix + defaults_header + defaults + hooks_header + hooks
        self.assertEqual(tomllib.loads(hooks_last), parsed, "both table orders must carry the same data")
        self.write(source, hooks_last)
        self.assertTrue(self.json_cli("org", "validate", org, "--format", "json")["valid"],
                        "existing org files with hooks last must remain valid")

        without_hooks = prefix + defaults_header + defaults
        self.write(source, without_hooks)
        self.assertNotIn("hooks", tomllib.loads(without_hooks))
        self.assertTrue(self.json_cli("org", "validate", org, "--format", "json")["valid"],
                        "hooks must remain optional independently of its output position")
        # With hooks last, an appended scalar belongs to the final blacklist
        # entry emitted by org init, so the diagnostic names that exact entry.
        malformed = (
            (prefix + hooks_header + hooks, "defaults: is required"),
            (hooks_last + "\ndiscord_channel_id = " + json.dumps(channel) + "\n",
             f"hooks.blacklist[{len(original_hooks['blacklist']) - 1}]: contains an unknown field"),
        )
        for invalid, expected in malformed:
            with self.subTest(problem=expected):
                self.write(source, invalid)
                refused = self.cli("org", "validate", org, "--format", "json")
                self.assertEqual(refused.returncode, 2, "invalid org fields must still be refused")
                report = json.loads(refused.stdout)
                self.assertIs(report["valid"], False)
                self.assertTrue(any(item["message"] == expected for item in report["problems"]),
                                "the real schema diagnostic must explain the refusal")
        self.write(source, text)

    def test_top_supervisor_alias(self):
        """Fails if the historical example spelling or either real role source is missing."""
        identity = self.org / ".laneboss/instances/L5-top/instance.toml"
        self.assertEqual(tomllib.loads(identity.read_text())["role"], "top-supervisor")
        roles = self.org / ".laneboss/L5/roles"
        for extension in (".md", ".toml"):
            modern = (roles / ("top" + extension)).read_bytes()
            historic = (roles / ("top-supervisor" + extension)).read_bytes()
            self.assertTrue(modern, "both alias source files must hold real policy")
            self.assertEqual(historic, modern, "historical and modern roles must share real source policy")
        self.assertIn((roles / "top-supervisor.md").read_bytes().rstrip(b"\n"),
                      identity.with_name("AGENTS.md").read_bytes())
        self.json_cli("org", "instance", "add", self.org, "L5-modern", "--level", "5", "--role", "top")
        self.assertTrue(self.json_cli("org", "validate", self.org, "--format", "json")["valid"])

    def get(self, key, *scope, explain=True):
        args = ["settings", "get", "--config", "layered", *scope, key]
        if explain:
            args += ["--explain"]
        return self.json_cli(*args)

    def tearDown(self):
        # Keep every record; collect only a genuinely live fixture lane.
        if hasattr(self, "hook_queue"):
            self.write(self.hook_queue / "stop", "stop")
        if hasattr(self, "child_queue"):
            self.write(self.child_queue / "stop", "stop")
        for name in self.lanes:
            if name in self.queued_lanes:
                # The stop files release these finite runners. Wait for their
                # recorded natural exit instead of racing it with lane stop.
                self.finish(name=name, run=self.queued_lanes[name])
                continue
            result = self.cli("lane", "status", "--config", "layered", "--lane", name)
            self.assertEqual(result.returncode, 0, result.stderr)
            row = json.loads(result.stdout)
            if row["running"] or row["live"]["survivors"]:
                stopped = self.json_cli("lane", "stop", "--config", "layered", "--lane", name)
                self.assertEqual(stopped["survivors"], 0)

    def test_scope_precedence(self):
        org = self.get("model")
        self.assertEqual(org["value"], "fixture-org-1")
        self.assertEqual(org["layers"][org["winner"]]["file"], str(self.org_settings))
        self.assertEqual(org["layers"][org["winner"]]["line"], 1)
        self.role_values(model="fixture-role-2")
        role = self.get("model", "--instance", self.instance)
        self.assertEqual(role["value"], "fixture-role-2")
        self.assertEqual(role["layers"][role["winner"]]["file"], str(self.role_settings))
        self.assertEqual(role["layers"][role["winner"]]["line"], 4)
        self.instance_values(model="fixture-instance-3")
        inst = self.get("model", "--instance", self.instance)
        self.assertEqual(inst["value"], "fixture-instance-3")
        self.assertEqual(inst["layers"][inst["winner"]]["file"], str(self.instance_settings))
        self.assertEqual(inst["layers"][inst["winner"]]["line"], 1)
        started = self.start_lane(sets=["model=fixture-lane-4"], instance=True)
        self.finish()
        lane = self.get("model", "--lane", "settings-lane")
        self.assertEqual(lane["value"], "fixture-lane-4")
        self.assertEqual([layer["scope"] for layer in lane["layers"]], ["org", "role", "instance", "lane"])
        self.assertEqual(lane["winner"], 3)
        self.assertIn("seq=" + str(started["event"]["seq"]), lane["layers"][3]["event"])
        self.assertEqual(self.calls()[0]["model"], lane["value"])
        saved = started["settings"]["sources"]
        for path in (self.org_settings, self.role_settings, self.instance_settings):
            self.assertEqual(saved[str(path)], path.read_text())
        listing = self.json_cli("settings", "list", "--config", "layered", "--lane", "settings-lane", "--explain")
        self.assertEqual(listing["model"]["value"], lane["value"])
        self.assertEqual(set(listing), {"runner", "model", "effort", "budget_minutes", "account", "seat_class",
                                       "env_allow", "tool_allow_add", "tool_deny_add"})

    def test_running_snapshot(self):
        self.write(self.gate, "hold")
        first = self.start_lane()
        status = self.json_cli("lane", "status", "--config", "layered", "--lane", "settings-lane")
        self.assertTrue(status["running"], "the edit must happen during the real run")
        old_bytes = self.org_settings.read_text()
        self.org_values(model="fixture-edited-2", effort="low", env_allow=[])
        fixed = self.get("model", "--lane", "settings-lane")
        self.assertEqual(fixed["value"], "fixture-org-1", "a live lane must keep its start-time model")
        self.assertEqual(first["settings"]["sources"][str(self.org_settings)], old_bytes)
        self.assertEqual(self.get("model", explain=False), "fixture-edited-2")
        self.write(self.gate, "release")
        self.finish()
        self.assertEqual(self.calls()[0]["model"], "fixture-org-1")

    def test_resume_resolves(self):
        first = self.start_lane()
        self.finish()
        self.org_values(model="fixture-resume-2", effort="low", env_allow=[])
        second = self.json_cli("lane", "resume", "--config", "layered", "--lane", "settings-lane", "--message", self.follow)
        self.finish(run=2)
        self.assertEqual(second["run"], 2)
        self.assertEqual(second["model"], "fixture-resume-2", "resume must re-read the changed org source")
        self.assertEqual(second["effort"], "low")
        calls = self.calls()
        self.assertEqual([call["model"] for call in calls], ["fixture-org-1", "fixture-resume-2"])
        self.assertEqual(calls[0]["session"], calls[1]["session"])
        self.assertIn("LAYERED_ALLOWED", calls[0]["names"])
        self.assertNotIn("LAYERED_ALLOWED", calls[1]["names"])
        self.assertEqual(first["settings"]["values"]["model"], "fixture-org-1")
        self.assertEqual(self.get("model", "--lane", "settings-lane")["value"], "fixture-resume-2")
        history = self.cli("event", "tail", "--config", "layered", "--lane", "settings-lane")
        self.assertEqual(history.returncode, 0, history.stderr)
        events = [json.loads(line) for line in history.stdout.splitlines()]
        resumed = next(event for event in events if event["kind"] == "lane.resumed" and event["payload"]["run"] == 2)
        message = resumed["payload"]["message"]
        self.assertEqual(calls[1]["prompt_sha256"], message["sha256"], "the stand-in must read the actual resumed prompt")
        self.assertEqual(hashlib.sha256(Path(message["path"]).read_bytes()).hexdigest(), message["sha256"])

    def test_override_persists(self):
        self.start_lane(sets=["model=fixture-explicit-3", 'env_allow=[]', 'seat_class=subscription',
                              'account=fixture-seat-two', 'budget_minutes=0.75'])
        self.finish()
        self.org_values(model="fixture-edited-4", effort="low", env_allow=["LAYERED_ALLOWED"])
        resumed = self.json_cli("lane", "resume", "--config", "layered", "--lane", "settings-lane", "--message", self.follow)
        self.finish(run=2)
        self.assertEqual(resumed["model"], "fixture-explicit-3")
        self.assertEqual(resumed["account"], "fixture-seat-two")
        self.assertEqual(resumed["budget_minutes"], 0.75)
        self.assertEqual(resumed["settings"]["values"]["seat_class"], "subscription")
        self.assertNotIn("LAYERED_ALLOWED", self.calls()[-1]["names"])

    def test_secret_refused(self):
        shaped = "sk-" + "7" + "a" * 30
        for path in (self.org_settings, self.instance_settings):
            with self.subTest(source=path.name):
                self.write(path, "model = " + json.dumps(shaped) + "\n")
                result = self.cli("config", "validate", "layered")
                self.assertEqual(result.returncode, 2, "secret-shaped settings must fail validation")
                self.assertIn("credential", result.stderr)
                self.assertNotIn(shaped, result.stdout + result.stderr)
                self.write(path, "")
        self.write(self.org_settings, 'model = "\\u0073k-7' + "a" * 30 + '"\n')
        result = self.cli("config", "validate", "layered")
        self.assertEqual(result.returncode, 2, "escaped secret-shaped settings must fail validation")
        self.assertIn("credential", result.stderr)
        self.assertNotIn(shaped, result.stdout + result.stderr)
        self.write(self.org_settings, "")

        self.role_values(model=shaped)
        result = self.cli("config", "validate", "layered")
        self.assertEqual(result.returncode, 2, "secret-shaped role settings must fail validation")
        self.assertIn("credential", result.stderr)
        self.assertNotIn(shaped, result.stdout + result.stderr)
        self.role_values()

    def linked_source(self, scope):
        self.hook_policy()
        self.role_values(model="fixture-role-2")
        self.instance_values(model="fixture-instance-3")
        source = {"org": self.org_settings, "role": self.role_settings, "instance": self.instance_settings}[scope]
        scope_args = [] if scope == "org" else ["--instance", self.instance]
        ordinary = self.get("model", *scope_args)
        self.assertEqual(ordinary["value"], "fixture-org-1" if scope == "org" else "fixture-instance-3",
                         "a regular source must still resolve")
        self.assertEqual(self.hook()["permissionDecision"], "allow", "a regular-source hook is the allowed control")
        target = source.with_name("regular-source.toml")
        source.replace(target)
        source.symlink_to(target.name)
        result = self.cli("settings", "get", "--config", "layered", *scope_args, "model")
        self.assertEqual(result.returncode, 2, "a linked " + scope + " settings source must be refused")
        # A linked role file is refused earlier, by the role-source check of config validation; org and instance
        # sources reach settings.Read's final-component check. Either way the refusal must name the linked source.
        marker = "never links" if scope == "role" else "settings"
        self.assertIn(marker, result.stderr, "the refusal must name the linked " + scope + " source")
        self.assertEqual(self.hook()["permissionDecision"], "deny", "a linked source must fail the live hook closed")
        work = self.directory / "linked-source-lane"
        work.mkdir()
        result = self.cli("lane", "start", "--config", "layered", "--lane", "linked-source-lane",
                          "--brief", self.brief, "--worktree", work, "--difficulty", "standard",
                          "--role", "executor", "--instance", self.instance)
        self.assertEqual(result.returncode, 2, "a linked source must fail lane start closed")
        self.assertFalse(self.calls_file.exists(), "linked sources must not reach a runner")

    def test_linked_org_source(self):
        self.linked_source("org")

    def test_linked_role_source(self):
        self.linked_source("role")

    def test_linked_instance_source(self):
        self.linked_source("instance")

    def test_cli_validation(self):
        conflict = self.cli("settings", "get", "--config", "other", "model", extra={"LANEBOSS_CONFIG": "layered"})
        self.assertEqual(conflict.returncode, 2, "settings reads must retain the configuration binding")
        self.assertEqual(conflict.stderr.strip(),
                         "refused: this session is bound to LANEBOSS_CONFIG=layered; reading configuration other is refused",
                         "the binding guard must refuse the foreign read before inspecting that configuration")
        scopes = self.cli("settings", "list", "--config", "layered", "--lane", "missing", "--instance", self.instance)
        self.assertEqual(scopes.returncode, 2, "lane and instance scopes must be mutually exclusive")
        worktree = self.directory / "rejected"
        worktree.mkdir()
        for sets in (["model=fixture-one-1", "model=fixture-two-2"], ["budget_minutes=true"],
                     ['env_allow=["TMUX_PANE"]'], ["unknown=fixture"]):
            args = ["lane", "start", "--config", "layered", "--lane", "rejected", "--role", "executor",
                    "--difficulty", "standard", "--brief", self.brief, "--worktree", worktree]
            for item in sets:
                args += ["--set", item]
            result = self.cli(*args)
            self.assertEqual(result.returncode, 2, "invalid lane overrides must refuse before execution")
        self.assertFalse(self.calls_file.exists(), "invalid overrides must never reach the runner")

    def test_invalid_types(self):
        invalid = ['budget_minutes = true\n', 'model = "alias"\n', 'env_allow = ["BAD-NAME"]\n',
                   'env_allow = ["TMUX"]\n', 'env_allow = ["LANEBOSS_CONFIG"]\n',
                   'env_allow = ["REPEAT", "REPEAT"]\n', 'unknown = "fixture"\n']
        for text in invalid:
            with self.subTest(key=text.split("=")[0].strip()):
                self.write(self.org_settings, text)
                result = self.cli("config", "validate", "layered")
                self.assertEqual(result.returncode, 2, "wrong settings types/names must be refused")
        self.write(self.org_settings, "")

    def test_environment_names(self):
        self.start_lane()
        self.finish()
        names = self.calls()[0]["names"]
        self.assertIn("LAYERED_ALLOWED", names, "the named variable must reach the runner")
        self.assertNotIn("LAYERED_UNLISTED", names, "unlisted variable reached the runner")
        self.assertNotIn("TMUX", names)
        self.assertNotIn("TMUX_PANE", names)
        permitted = {"PATH", "HOME", "LANG", "TERM", "TMPDIR", "LAYERED_ALLOWED", "LANEBOSS_CONFIG",
                     "LANEBOSS_HOME", "LANEBOSS_STATE_HOME", "LANEBOSS_LANE", "LANEBOSS_RUN",
                     "LANEBOSS_PRINCIPAL", "LANEBOSS_PROCESSES", "LANEBOSS_TEST_CLAIMS_DIR"}
        self.assertEqual(set(names) - permitted, set(), "only the documented base and named variable may arrive")
        output = self.home / ".local/state/laneboss" / "layered/lanes" / "settings-lane" / "output.log"
        self.assertEqual(json.loads(output.read_text().strip()), names)

    def test_turn_environment(self):
        self.configure(stdin=True)
        self.start_lane(turns=True)
        self.finish()
        self.org_values(model="fixture-turn-2", effort="low", env_allow=[])
        self.json_cli("lane", "send", "--config", "layered", "--lane", "settings-lane", "--file", self.follow)
        answer = self.json_cli("lane", "turn", "--config", "layered", "--lane", "settings-lane")
        self.finish(run=2)
        self.assertEqual(answer["model"], "fixture-turn-2")
        self.assertEqual(self.calls()[-1]["model"], "fixture-turn-2")
        self.assertNotIn("LAYERED_ALLOWED", self.calls()[-1]["names"])
        self.assertNotIn("LAYERED_UNLISTED", self.calls()[-1]["names"])

    def test_mutant_fails(self):
        self.check_mutant("settings-inherit-env", {
            "test_environment_names": "unlisted variable reached the runner",
        })

    def hook_policy(self, instance="L3-lane-example", level=3, *, org=None, mode="strict"):
        # The deprecated strict spelling must behave exactly as blacklist.
        # Only explicit denies and the independent lane boundary restrict calls.
        org = org or self.org
        source = org / ".laneboss/org.toml"
        text = source.read_text(encoding="utf-8")
        self.assertEqual(text.count('mode = "blacklist"') + text.count('mode = "strict"'), 1,
                         "the fixture must select exactly one source hook mode")
        if mode is not None:
            self.assertEqual(mode, "strict")
            self.write(source, text.replace('mode = "blacklist"', 'mode = "strict"', 1))
        self.hook_instance = org / ".laneboss/instances" / instance
        shared = org / ".laneboss/shared"
        self.write(shared / "hooks/rules.toml", 'schema_version = 1\n'
                   '[[rules]]\nid = "settings-workspace"\nkind = "write-scope"\n'
                   'paths = ["{laneboss}", ' + json.dumps(str(self.directory)) + ']\ndeny_paths = ["{hook_paths}"]\n')
        for name in ("settings-workspace",):
            self.write(shared / "refusals" / (name + ".toml"), 'schema_version = 1\nid = ' + json.dumps(name) + '\n'
                       'refuses = "Calls outside the declared policy."\nwhy = "Explicit protected paths are fixed."\n'
                       'instead = "Ask the supervising level."\n'
                       'examples_allowed = ["Read a declared fixture input", "Write an instance state file"]\n'
                       'examples_refused = ["Write a protected policy input"]\n'
                       '[applies_to]\nlevels = [3, 4, 5, 6]\nidentities = ["*"]\n')
        self.write(org / (".laneboss/L" + str(level) + "/hooks/rules.toml"), "schema_version = 1\nrules = []\n")
        self.json_cli("org", "render", org)
        valid = self.json_cli("org", "validate", org, "--format", "json-diagnostics")
        self.assertTrue(valid["valid"], "the policy fixture must be a valid org")

    def hook(self, tool="Read", target=None, queue=False, queue_path=None, cwd=None):
        cwd = cwd or (self.directory / "settings-lane" if queue else self.hook_instance)
        target = target or self.brief
        inputs = {"file_path": str(target)}
        if tool == "Write":
            inputs["content"] = "fixture input only"
        event = {"hook_event_name": "PreToolUse", "cwd": str(cwd), "tool_name": tool, "tool_input": inputs}
        argv = [str(self.binary), "org", "hook", "--runner", "claude", "--instance", str(self.hook_instance)]
        if queue:
            answer = self.queued(argv, json.dumps(event), queue=queue_path)
            self.assertEqual(answer["exit_code"], 0, answer["stderr"])
            return json.loads(answer["stdout"])["hookSpecificOutput"]
        answer = self.cli(*argv[1:], stdin=json.dumps(event))
        self.assertEqual(answer.returncode, 0, answer.stderr)
        return json.loads(answer.stdout)["hookSpecificOutput"]

    def queue_lane(self, legacy=False, level=3, role="executor", instance=None, stdin=False):
        self.hook_queue = self.directory / "hook-queue"
        self.hook_queue.mkdir()
        self.configure(stdin=stdin, queue=self.hook_queue)
        selected = self.binary
        if legacy:
            self.binary = LEGACY
        try:
            work = self.directory / "settings-lane"
            work.mkdir()
            args = ["lane", "start", "--config", "layered", "--lane", "settings-lane",
                    "--brief", self.brief, "--worktree", work, "--difficulty", "standard",
                    "--level", level, "--role", role]
            if instance:
                args += ["--instance", instance]
            started = self.json_cli(*args)
        finally:
            self.binary = selected
        self.lanes.append("settings-lane")
        self.queued_lanes["settings-lane"] = 1
        if legacy:
            self.assertNotIn("settings", started, "the historic lane must be started by the actual pre-1.0 CLI")
        self.wait_queue_identity(started)
        return started

    def wait_queue_identity(self, started):
        deadline = time.monotonic() + 20
        record = self.home / ".local/state/laneboss" / "layered/lanes" / "settings-lane" / "runs" / (started["launch"] + ".json")
        while time.monotonic() < deadline:
            ready = self.hook_queue / "ready"
            if ready.exists() and record.exists() and (json.loads(record.read_text()).get("runner") or {}).get("pid") == int(ready.read_text()):
                return
            time.sleep(0.05)
        self.fail("the actual runner identity was not recorded before its descendant hook call")

    def queued(self, argv, stdin=None, queue=None, canary_names=()):
        stem = (queue or self.hook_queue) / ("request-" + uuid.uuid4().hex)
        request = {"argv": [str(arg) for arg in argv], "stdin": stdin}
        if canary_names:
            request["canary_names"] = list(canary_names)
        if self.fault_point:
            request["fault"] = {"point": self.fault_point, "marker": str(self.marker)}
        self.write(stem.with_suffix(".request.json"), json.dumps(request))
        deadline = time.monotonic() + 30
        result = stem.with_suffix(".result.json")
        while time.monotonic() < deadline:
            if result.exists():
                return json.loads(result.read_text())
            time.sleep(0.02)
        self.fail("the real runner descendant did not return its CLI output")

    def as_starter(self, *args):
        argv = [str(self.binary), *(str(arg) for arg in args)]
        answer = self.queued(argv)
        return subprocess.CompletedProcess(argv, answer["exit_code"], answer["stdout"], answer["stderr"])

    def json_as_starter(self, *args):
        result = self.as_starter(*args)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_settings_protected(self):
        self.hook_policy(instance="L5-top", level=5)
        control = self.hook("Write", self.hook_instance / "state/control.txt")
        self.assertEqual(control["permissionDecision"], "allow", "a normal state write in this scope must be allowed")
        for target in (self.org_settings, self.hook_instance / "settings.toml"):
            answer = self.hook("Write", target)
            self.assertEqual(answer["permissionDecision"], "deny", "protected settings file must be refused")
            self.assertEqual(answer["permissionDecisionReason"].splitlines()[0],
                             "[blacklist:laneboss-files] Refuses: Writes to Laneboss's own hook settings, "
                             "registry, org configuration, refusal catalog, records or state.",
                             "the built-in protected-file denial must refuse the call")

    def test_missing_role_allows(self):
        self.hook_policy()
        shutil.move(str(self.org / ".laneboss/L3/roles"), str(self.inputs / "retained-role-sources"))
        self.json_cli("org", "render", self.org)
        valid = self.json_cli("org", "validate", self.org, "--format", "json")
        self.assertTrue(valid["valid"], "a level without a roles directory is documented-valid")
        self.assertEqual(self.hook()["permissionDecision"], "allow", "ordinary call refused without a role settings file")

    def test_long_instance_allows(self):
        self.hook_policy()
        name = "L3-" + "x" * 62
        self.assertEqual(len(name), 65)
        target = self.org / ".laneboss/instances" / name
        target.mkdir()
        identity = tomllib.loads((self.hook_instance / "instance.toml").read_text())
        source = (self.hook_instance / "instance.toml").read_text()
        self.write(target / "instance.toml", source.replace('name = ' + json.dumps(identity["name"]), 'name = ' + json.dumps(name), 1))
        for part in ("inbox", "outbox"):
            (target / "state" / part).mkdir(parents=True)
        for part in ("notes.md", "board.md", "ledger.jsonl"):
            self.write(target / "state" / part, (self.hook_instance / "state" / part).read_text())
        self.hook_instance = target
        self.assertEqual(self.hook()["permissionDecision"], "allow", "ordinary call refused for a valid long instance name")
        self.json_cli("org", "render", self.org)
        self.assertTrue(self.json_cli("org", "validate", self.org, "--format", "json")["valid"])
        self.assertEqual(self.get("model", "--instance", name)["value"], "fixture-org-1")

    def test_hook_tool_deny(self):
        self.hook_policy()
        self.org_values(model="fixture-org-1", effort="high", tool_deny_add=["Read"])
        self.assertEqual(self.hook()["permissionDecision"], "deny", "resolved tool deny must refuse an instance call")

    def test_hook_deny_beats_allow(self):
        self.hook_policy()
        self.org_values(model="fixture-org-1", effort="high", tool_deny_add=["Read"], tool_allow_add=["Read"])
        refused = self.hook()
        self.assertEqual(refused["permissionDecision"], "deny", "a deny must beat a matching allow addition")
        self.assertEqual(refused["permissionDecisionReason"],
                         "refused: resolved settings deny this tool\nInstead: report the tool request to the supervising level.")

    def test_hook_lane_snapshot(self):
        self.hook_policy()
        self.org_values(model="fixture-org-1", effort="high", tool_deny_add=["Read"])
        self.queue_lane()
        self.org_values(model="fixture-edited-2", effort="high", tool_deny_add=[])
        self.assertEqual(self.hook()["permissionDecision"], "allow", "the live instance must see the changed file")
        self.assertEqual(self.hook(queue=True)["permissionDecision"], "deny", "the authenticated lane must retain its recorded deny")

    def test_hook_historic_lane(self):
        self.hook_policy()
        self.queue_lane(legacy=True)
        self.org_values(model="fixture-org-1", effort="high", tool_deny_add=["Read"])
        self.assertEqual(self.hook()["permissionDecision"], "deny", "the live file must actually define a deny")
        self.assertEqual(self.hook(queue=True)["permissionDecision"], "allow", "a historic lane must not acquire unrecorded live settings")

    def test_deny_union(self):
        self.hook_policy()
        self.org_values(model="fixture-org-1", effort="high", tool_deny_add=["Read"])
        self.role_values(tool_deny_add=["Write"])
        self.instance_values(tool_deny_add=[])
        self.assertEqual(self.hook()["permissionDecision"], "deny", "a narrower layer must not clear the org deny")
        self.assertEqual(self.hook("Write", self.hook_instance / "state/union.txt")["permissionDecision"], "deny")
        started = self.start_lane(sets=['tool_deny_add=[]'], instance=True)
        self.finish()
        self.assertEqual(started["settings"]["values"]["tool_deny_add"], ["Read", "Write"])
        merged = self.get("tool_deny_add", "--lane", "settings-lane")
        self.assertEqual(merged["merge"], "union")
        self.assertEqual(merged["value"], ["Read", "Write"])

    def child_grant(self, key, forbidden, overlay=None):
        self.hook_policy()
        self.org_values(model="fixture-org-1", effort="high", env_allow=["LAYERED_ALLOWED"])
        self.queue_lane(level=4, role="supervisor")

        if overlay == "role":
            self.role_values(**{key: [forbidden]})
        elif overlay == "instance":
            self.instance_values(**{key: [forbidden]})

        self.child_queue = self.directory / "child-queue"
        self.child_queue.mkdir()
        self.add_runner("child", queue=self.child_queue)
        work = self.directory / "grant-child"
        work.mkdir()
        args = [str(self.binary), "lane", "start", "--config", "layered", "--lane", "grant-child",
                "--role", "executor", "--difficulty", "standard", "--brief", str(self.brief),
                "--worktree", str(work), "--runner", "child"]
        if overlay == "instance":
            args += ["--instance", self.instance]
        elif overlay is None:
            args += ["--set", key + "=" + json.dumps([forbidden])]
        answer = self.queued(args, canary_names=[forbidden] if key == "env_allow" else [])
        if answer["exit_code"] == 0:
            self.lanes.append("grant-child")
            self.queued_lanes["grant-child"] = 1
            started = json.loads(answer["stdout"])
            self.observed_grant = started["settings"]["values"][key]
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if (self.child_queue / "ready").exists() and len(self.calls()) == 2:
                    break
                time.sleep(0.05)
            self.assertEqual(len(self.calls()), 2, "the child grant must reach the real runner")
            if key == "env_allow":
                self.observed_names = self.calls()[-1]["names"]
                self.assertIn(forbidden, self.observed_names, "the inheritance mutation must actually deliver the canary name")
        self.assertEqual(answer["exit_code"], 2, key + " amplification must be refused")
        self.assertIn("settings." + key, answer["stderr"])
        self.assertIn("lane:settings-lane", answer["stderr"], "the refusal must name the actual starter")

    def test_delegate_env_refused(self):
        self.child_grant("env_allow", "LAYERED_UNLISTED")

    def test_instance_grant_refused(self):
        self.child_grant("env_allow", "LAYERED_UNLISTED", overlay="instance")

    def test_resume_grants_refused(self):
        self.org_values(model="fixture-org-1", effort="high", env_allow=["LAYERED_ALLOWED"])
        self.start_lane()
        self.finish()
        for key, excess in (("env_allow", "LAYERED_UNLISTED"),):
            with self.subTest(key=key):
                self.role_values(**{key: [excess]})
                result = self.cli("lane", "resume", "--config", "layered", "--lane", "settings-lane", "--message", self.follow)
                self.assertEqual(result.returncode, 2, "resume must refuse an inherited excess grant")
                self.assertIn("settings." + key, result.stderr)
                self.assertIn("supervisor:top", result.stderr)
                self.assertEqual(len(self.calls()), 1, "a refused resume must never reach the runner")
        self.role_values()

    def test_turn_grants_refused(self):
        self.configure(stdin=True)
        self.org_values(model="fixture-org-1", effort="high", env_allow=["LAYERED_ALLOWED"])
        self.start_lane(turns=True)
        self.finish()
        self.json_cli("lane", "send", "--config", "layered", "--lane", "settings-lane", "--file", self.follow)
        self.role_values(env_allow=["LAYERED_UNLISTED"])
        result = self.cli("lane", "turn", "--config", "layered", "--lane", "settings-lane")
        self.assertEqual(result.returncode, 2, "turn must refuse an inherited excess grant")
        self.assertIn("settings.env_allow", result.stderr)
        self.assertIn("supervisor:top", result.stderr)
        self.assertEqual(len(self.calls()), 1, "a refused turn must never reach the runner")
        self.role_values()

    def owned_grant_again(self, key, turns):
        operation = "turn" if turns else "resume"
        self.configure(stdin=turns)
        values = {"model": "fixture-org-1", "effort": "high", "env_allow": ["LAYERED_ALLOWED"]}
        added = "LAYERED_UNLISTED"
        self.org_values(**values)
        first = self.start_lane(turns=turns)
        self.finish()
        self.assertNotIn(added, first["settings"]["values"][key])
        for run, widen in ((2, True), (3, False)):
            changed = dict(values)
            changed[key] = values[key] + [added] if widen else values[key]
            self.org_values(**changed)
            if turns:
                self.json_cli("lane", "send", "--config", "layered", "--lane", "settings-lane", "--file", self.follow)
                result = self.cli("lane", "turn", "--config", "layered", "--lane", "settings-lane")
            else:
                result = self.cli("lane", "resume", "--config", "layered", "--lane", "settings-lane", "--message", self.follow)
            reason = operation + " must apply owned " + key + (" widening" if widen else " narrowing")
            self.assertEqual(result.returncode, 0, reason + ": " + result.stderr)
            answer = json.loads(result.stdout)
            self.assertEqual(answer["run"], run)
            self.assertEqual(answer["settings"]["delegation"]["starter"], first["settings"]["delegation"]["starter"])
            self.finish(run=run)
            self.assertEqual(len(self.calls()), run)
            observed = self.calls()[-1]["names"]
            if widen:
                self.assertIn(added, observed, "the newly owned name must reach the actual run")
            else:
                self.assertNotIn(added, observed, "the removed name must be gone from the next run")
            self.assertEqual(self.calls()[0]["session"], self.calls()[-1]["session"])

    def test_resume_env_widened(self):
        self.owned_grant_again("env_allow", turns=False)

    def test_turn_env_widened(self):
        self.owned_grant_again("env_allow", turns=True)

    def revoked_grant(self, turns):
        self.configure(stdin=turns)
        self.org_values(model="fixture-org-1", effort="high", env_allow=["LAYERED_ALLOWED", "LAYERED_UNLISTED"])
        self.start_lane(turns=turns, sets=['env_allow=["LAYERED_UNLISTED"]'])
        self.finish()
        self.assertIn("LAYERED_UNLISTED", self.calls()[0]["names"])
        self.org_values(model="fixture-org-1", effort="high", env_allow=["LAYERED_ALLOWED"])
        if turns:
            self.json_cli("lane", "send", "--config", "layered", "--lane", "settings-lane", "--file", self.follow)
            result = self.cli("lane", "turn", "--config", "layered", "--lane", "settings-lane")
        else:
            result = self.cli("lane", "resume", "--config", "layered", "--lane", "settings-lane", "--message", self.follow)
        if result.returncode == 0:
            self.finish(run=2)
        self.assertEqual(result.returncode, 2, "the next run must refuse a revoked explicit grant")
        self.assertIn("settings.env_allow", result.stderr)
        self.assertIn("supervisor:top", result.stderr)
        self.assertEqual(len(self.calls()), 1, "a revoked grant must not reach a second runner")

    def test_resume_revoke_refused(self):
        self.revoked_grant(turns=False)

    def test_turn_revoke_refused(self):
        self.revoked_grant(turns=True)

    def test_runner_pinned(self):
        config_file = self.home / ".config/laneboss/configs/layered/config.toml"
        original = config_file.read_text()
        section = original.split("[runners.agent]", 1)[1].split("[supervisors.top]", 1)[0]
        self.write(config_file, original + "\n[runners.other]\n" + section)
        self.start_lane()
        self.finish()
        self.org_values(model="fixture-org-1", effort="high", runner="other")
        resumed = self.cli("lane", "resume", "--config", "layered", "--lane", "settings-lane", "--message", self.follow)
        self.assertEqual(resumed.returncode, 2, "an org edit must not switch the recorded runner")
        self.assertIn("recorded runner", resumed.stderr)
        self.assertEqual(len(self.calls()), 1)

    def add_runner(self, name, queue=None, records=None):
        path = self.home / ".config/laneboss/configs/layered/config.toml"
        original = path.read_text()
        runner = tomllib.loads(original)["runners"]["agent"]
        if records is not None:
            runner["records"] = records
        for key in ("command", "resume"):
            if len(runner[key]) == 9:
                runner[key] = runner[key][:-1]
            if queue:
                runner[key].append(str(queue))
        text = original + "\n[runners." + name + "]\n" + "".join(
            key + " = " + toml_value(value) + "\n" for key, value in runner.items())
        self.assertEqual(tomllib.loads(text)["runners"][name], runner,
                         "runner TOML must preserve every command and session-record entry")
        self.write(path, text)

    def test_turn_runner_pinned(self):
        self.configure(stdin=True)
        self.add_runner("other")
        self.start_lane(turns=True)
        self.finish()
        self.org_values(model="fixture-org-1", effort="high", runner="other")
        self.json_cli("lane", "send", "--config", "layered", "--lane", "settings-lane", "--file", self.follow)
        result = self.cli("lane", "turn", "--config", "layered", "--lane", "settings-lane")
        self.assertEqual(result.returncode, 2, "a turn must not switch its recorded runner")
        self.assertIn("recorded runner", result.stderr)
        self.assertEqual(len(self.calls()), 1)

    def delegating_starter(self, turns=False):
        self.hook_policy(instance="L4-stream", level=4)
        starter_instance = self.hook_instance
        self.hook_policy(instance="L5-top", level=5)
        self.org_values(model="fixture-org-1", effort="high", env_allow=["LAYERED_ALLOWED"])
        parent = self.queue_lane(level=4, role="supervisor", instance="L4-stream", stdin=turns)
        self.assertEqual(parent["settings"]["instance"], "L4-stream")
        return starter_instance

    def test_adopted_turn_resolvable_starter(self):
        starter_instance = self.delegating_starter(turns=True)
        records = [{"format": "claude-code", "paths": ["{worktree}/.sessions/{session}.jsonl"]}]
        self.add_runner("child", records=records)
        name = "adopted-child"
        work = self.directory / name
        work.mkdir()
        session = str(uuid.uuid4())
        path = work / ".sessions" / (session + ".jsonl")
        self.write(path, json.dumps({"type": "assistant", "cwd": str(work), "message": {"content": []}}) + "\n")
        old = time.time() - 3600
        os.utime(path, (old, old))
        args = [str(self.binary), "lane", "adopt", "--config", "layered", "--lane", name,
                "--brief", self.brief, "--worktree", work, "--runner", "child", "--model", "fixture-org-1",
                "--effort", "high", "--role", "executor", "--level", "3", "--budget", "1", "--session", session]
        started = self.queued(args)
        self.assertEqual(started["exit_code"], 0, "the real adopter must create the child: " + started["stderr"])
        first = json.loads(started["stdout"])
        self.lanes.append(name)
        self.assertEqual(first["starter"], "lane:settings-lane", "adoption must record its actual caller")
        self.assertEqual(first["settings"]["delegation"]["starter"], first["starter"])
        self.assertEqual(first["session_id"], session)
        for run in (2, 3):
            self.assertTrue((starter_instance / "instance.toml").is_file(), "the adopter's instance must remain attached")
            self.assertEqual(self.get("env_allow", "--instance", "L4-stream")["value"], ["LAYERED_ALLOWED"],
                             "the recorded starter's instance must still resolve")
            self.json_as_starter("lane", "send", "--config", "layered", "--lane", name, "--file", self.follow)
            result = self.as_starter("lane", "turn", "--config", "layered", "--lane", name)
            self.assertEqual(result.returncode, 0, "an adopted lane must resume with its resolvable starter: " + result.stderr)
            answer = json.loads(result.stdout)
            self.assertEqual(answer["run"], run)
            self.assertEqual(answer["how"], "resume")
            self.assertEqual(answer["session_id"], session)
            self.assertEqual(answer["starter"], first["starter"])
            self.assertEqual(answer["settings"]["delegation"], first["settings"]["delegation"])
            self.assertEqual(result.stderr, "", "a resolvable starter must require no fallback notice")
            self.finish(name=name, run=run)
            calls = [call for call in self.calls() if call["session"] == first["session_id"]]
            self.assertEqual(len(calls), run - 1)
            self.assertIn("LAYERED_ALLOWED", calls[-1]["names"], "the resolvable adopter's grant must reach the actual runner")
        before = len(self.calls())
        self.org_values(model="fixture-org-1", effort="high", env_allow=["LAYERED_ALLOWED", "LAYERED_UNLISTED"])
        self.json_as_starter("lane", "send", "--config", "layered", "--lane", name, "--file", self.follow)
        refused = self.as_starter("lane", "turn", "--config", "layered", "--lane", name)
        if refused.returncode == 0:
            self.finish(name=name, run=4)
        self.assertEqual(refused.returncode, 2, "adoption must not skip the resolvable starter's grant check")
        self.assertIn("settings.env_allow", refused.stderr)
        self.assertIn(first["starter"], refused.stderr)
        self.assertEqual(len(self.calls()), before, "an excess adopted grant must not start a runner")

    def missing_starter(self, turns=False):
        starter_instance = self.delegating_starter(turns=turns)
        # The parent keeps its actual run's grant. Neither child's current owner
        # sources grant the name; the named override is delegation alone.
        self.org_values(model="fixture-org-1", effort="high", env_allow=[])
        owner = self.get("env_allow", "--instance", self.instance)
        self.assertEqual(owner["value"], [])
        self.assertEqual([layer["scope"] for layer in owner["layers"]], ["base", "org"],
                         "no role or instance grant may hide the missing owner authority")
        self.add_runner("child")
        self.add_runner("plain")
        children = {}
        for name, runner, names in (("delegated-child", "child", ["LAYERED_ALLOWED"]), ("plain-child", "plain", [])):
            work = self.directory / name
            work.mkdir()
            args = [str(self.binary), "lane", "start", "--config", "layered", "--lane", name,
                    "--brief", self.brief, "--worktree", work, "--runner", runner, "--model", "fixture-org-1",
                    "--effort", "high", "--instance", self.instance, "--budget", "1", "--set", "env_allow=" + json.dumps(names)]
            if turns:
                args += ["--turns"]
            result = self.queued(args)
            self.assertEqual(result["exit_code"], 0, "the real starter must create the child: " + result["stderr"])
            children[name] = json.loads(result["stdout"])
            self.lanes.append(name)
            self.assertEqual(children[name]["starter"], "lane:settings-lane")
            self.finish(name=name)
        shutil.move(str(starter_instance), str(self.inputs / "retired-starter"))
        self.assertFalse(starter_instance.exists())
        name = "delegated-child"
        first = children[name]
        control = self.hook("Write", self.hook_instance / "state/own-write.txt")
        self.assertEqual(control["permissionDecision"], "allow", "removing the starter must not block own-instance writes")
        self.assertIn("LAYERED_ALLOWED", [call for call in self.calls() if call["session"] == first["session_id"]][-1]["names"])
        operation = "turn" if turns else "resume"

        def attempt(lane):
            if turns:
                self.json_as_starter("lane", "send", "--config", "layered", "--lane", lane, "--file", self.follow)
                return self.as_starter("lane", "turn", "--config", "layered", "--lane", lane)
            return self.as_starter("lane", "resume", "--config", "layered", "--lane", lane, "--message", self.follow)

        def require_refusal(count):
            before = len(self.calls())
            result = attempt(name)
            if result.returncode == 0:
                self.finish(name=name, run=json.loads(result.stdout)["run"])
            self.assertEqual(result.returncode, 2, operation + " must refuse delegation from the removed starter")
            expected = ["refused: delegation starter " + first["starter"] +
                        " cannot be resolved; delegated names have no current owner grant",
                        "Instead: re-attach the starter instance, or have the owner grant the names at org, role or instance level, then resume."]
            self.assertEqual(result.stderr.splitlines(), expected, "the refusal must name the starter and its exact recovery route")
            self.assertEqual(result.stdout, "")
            self.assertEqual(len(self.calls()), before, "a missing delegated authority must not reach a runner")
            recorded = self.json_cli("lane", "refusals", "--config", "layered", "--lane", name)["refusals"]
            self.assertEqual(len(recorded), count, "every missing-starter refusal must be recorded")
            refusal = recorded[-1]
            self.assertEqual(refusal["guard"], "settings-delegation")
            self.assertEqual(refusal["kind"], "permission")
            self.assertEqual(refusal["message"]["text"], result.stderr.rstrip("\n"))
            self.assertEqual(Path(refusal["record"]["path"]).read_text(), result.stderr,
                             "the recorded refusal must point to the retained actual launcher output")
            row = self.json_cli("lane", "status", "--config", "layered", "--lane", name)
            self.assertEqual(row["run"], count)
            self.assertFalse(row["running"])
            self.assertEqual(row["live"]["survivors"], 0)
            self.assertEqual(row["live"]["pending_events"], 0)
            self.assertEqual(row["live"]["refused_events"], 0)

        require_refusal(1)
        result = attempt("plain-child")
        self.assertEqual(result.returncode, 0, "non-delegated work must resume with a removed starter: " + result.stderr)
        plain = json.loads(result.stdout)
        self.assertEqual(plain["run"], 2)
        self.assertEqual(plain["starter"], first["starter"])
        self.finish(name="plain-child", run=2)
        plain_calls = [call for call in self.calls() if call["session"] == children["plain-child"]["session_id"]]
        self.assertEqual(len(plain_calls), 2)
        self.assertNotIn("LAYERED_ALLOWED", plain_calls[-1]["names"])
        # This is the sole new authority: the owner's current org file. The
        # starter remains absent, and the child's original override is retained.
        self.org_values(model="fixture-org-1", effort="high", env_allow=["LAYERED_ALLOWED"])
        grant = self.get("env_allow", "--instance", self.instance)
        self.assertEqual(grant["value"], ["LAYERED_ALLOWED"])
        self.assertEqual([layer["scope"] for layer in grant["layers"]], ["base", "org"])
        self.assertEqual(grant["layers"][grant["winner"]]["file"], str(self.org_settings))
        result = attempt(name)
        self.assertEqual(result.returncode, 0, "a fresh owner org grant must recover the refused " + operation + ": " + result.stderr)
        answer = json.loads(result.stdout)
        self.assertEqual(answer["run"], 2)
        self.assertEqual(answer["starter"], first["starter"])
        self.assertEqual(answer["session_id"], first["session_id"])
        self.assertEqual(answer["settings"]["overrides"]["env_allow"], ["LAYERED_ALLOWED"])
        self.assertEqual(answer["settings"]["sources"][str(self.org_settings)], self.org_settings.read_text())
        self.assertFalse(starter_instance.exists(), "recovery must not silently re-attach the old starter")
        self.finish(name=name, run=2)
        calls = [call for call in self.calls() if call["session"] == first["session_id"]]
        self.assertEqual(len(calls), 2)
        self.assertIn("LAYERED_ALLOWED", calls[-1]["names"], "the fresh org grant must reach the actual resumed runner")
        self.org_values(model="fixture-org-1", effort="high", env_allow=[])
        require_refusal(2)

    def test_removed_starter_resume(self):
        self.missing_starter()

    def test_removed_starter_turn(self):
        self.missing_starter(turns=True)

    def test_removed_instance_starter_resume(self):
        # The briefing command accepts lowercase names. Its real caller.Role
        # binding resolves this org instance, not a [supervisors] entry, on both
        # the regression base and current binary.
        starter_name = "stream-starter"
        added = self.json_cli("org", "instance", "add", self.org, starter_name, "--level", "4", "--role", "supervisor")
        self.assertTrue(added["ok"])
        self.assertGreater(added["changed"], 0)
        config_path = self.home / ".config/laneboss/configs/layered/config.toml"
        self.assertNotIn(starter_name, tomllib.loads(config_path.read_text())["supervisors"])
        self.hook_policy(instance=starter_name, level=4)
        starter_instance = self.hook_instance
        self.org_values(model="fixture-org-1", effort="high", env_allow=[])
        self.write(starter_instance / "settings.toml", 'env_allow = ["LAYERED_ALLOWED"]\n')
        owner = self.get("env_allow", "--instance", self.instance)
        self.assertEqual(owner["value"], [])
        self.assertEqual([layer["scope"] for layer in owner["layers"]], ["base", "org"],
                         "the child must have no independent role or instance grant")
        self.assertEqual(self.get("env_allow", "--instance", starter_name)["value"], ["LAYERED_ALLOWED"])
        # The instance's registered parent and the human terminal are siblings.
        # Removing the instance cannot invalidate the human's real identity.
        starter = HeadlessController(self, directory=starter_instance,
                                     environment={**self.env, "LANEBOSS_INSTANCE": starter_name})
        registered = self.json_cli("start", "--config", "layered", "--role", starter_name, "--format", "json",
                                   controller=starter)
        self.assertEqual(registered["role"]["selected"], starter_name)
        self.assertEqual(registered["role"]["entry"]["level"], 4)
        name = "instance-child"
        work = self.directory / name
        work.mkdir()
        first = self.json_cli("lane", "start", "--config", "layered", "--lane", name,
                              "--brief", self.brief, "--worktree", work, "--difficulty", "standard",
                              "--instance", self.instance, "--set", 'env_allow=["LAYERED_ALLOWED"]',
                              controller=starter)
        self.lanes.append(name)
        self.assertEqual(first["starter"], "instance:" + starter_name, "the actual registered instance must be the starter")
        self.assertEqual(first["settings"]["delegation"]["starter"], first["starter"])
        self.assertIn("LAYERED_ALLOWED", first["settings"]["delegation"]["env"])
        self.finish(name=name)
        self.assertEqual(len(self.calls()), 1)
        self.assertIn("LAYERED_ALLOWED", self.calls()[0]["names"], "the instance's delegated name must reach run 1")
        shutil.move(str(starter_instance), str(self.inputs / "retired-instance-starter"))
        self.assertFalse(starter_instance.exists())
        result = self.cli("lane", "resume", "--config", "layered", "--lane", name, "--message", self.follow)
        if result.returncode == 0:
            self.finish(name=name, run=2)
        self.assertEqual(result.returncode, 2, "an instance starter's removed grant must be refused")
        self.assertEqual(result.stderr.splitlines(), [
            "refused: delegation starter instance:" + starter_name + " cannot be resolved; delegated names have no current owner grant",
            "Instead: re-attach the starter instance, or have the owner grant the names at org, role or instance level, then resume.",
        ], "the instance-resolution refusal must reach Bind with its exact recovery route")
        self.assertEqual(result.stdout, "")
        self.assertEqual(len(self.calls()), 1, "the removed instance must not authorize another runner call")
        self.finish(name=name)
        refusals = self.json_cli("lane", "refusals", "--config", "layered", "--lane", name)["refusals"]
        self.assertEqual(len(refusals), 1)
        self.assertEqual(refusals[0]["guard"], "settings-delegation")
        self.assertEqual(refusals[0]["message"]["text"], result.stderr.rstrip("\n"))
        self.assertEqual(Path(refusals[0]["record"]["path"]).read_text(), result.stderr)
        self.org_values(model="fixture-org-1", effort="high", env_allow=["LAYERED_ALLOWED"])
        grant = self.get("env_allow", "--instance", self.instance)
        self.assertEqual(grant["value"], ["LAYERED_ALLOWED"])
        self.assertEqual([layer["scope"] for layer in grant["layers"]], ["base", "org"])
        self.assertEqual(grant["layers"][grant["winner"]]["file"], str(self.org_settings))
        resumed = self.json_cli("lane", "resume", "--config", "layered", "--lane", name, "--message", self.follow)
        self.assertEqual(resumed["run"], 2)
        self.assertEqual(resumed["starter"], first["starter"])
        self.assertEqual(resumed["session_id"], first["session_id"])
        self.assertEqual(resumed["settings"]["overrides"]["env_allow"], ["LAYERED_ALLOWED"])
        self.assertEqual(resumed["settings"]["sources"][str(self.org_settings)], self.org_settings.read_text())
        self.assertFalse(starter_instance.exists(), "only the fresh owner grant may recover this run")
        self.finish(name=name, run=2)
        self.assertEqual(len(self.calls()), 2)
        self.assertEqual(self.calls()[-1]["session"], first["session_id"])
        self.assertIn("LAYERED_ALLOWED", self.calls()[-1]["names"], "the fresh org re-grant must reach the resumed instance child")

    def test_launch_flag_screen(self):
        shaped = "sk-7" + "b" * 30
        work = self.directory / "flag-screen"
        work.mkdir()
        for option in ("runner", "model", "effort", "budget"):
            result = self.cli("lane", "start", "--config", "layered", "--lane", "flag-screen",
                              "--role", "executor", "--difficulty", "standard", "--brief", self.brief,
                              "--worktree", work, "--" + option, shaped)
            self.assertEqual(result.returncode, 2)
            self.assertIn("credential", result.stderr, "every launch choice must pass the credential screen")
            self.assertNotIn(shaped, result.stdout + result.stderr)
        self.start_lane()
        self.finish()

    def account_value_never_echoed(self, turns=False):
        self.configure(stdin=turns)
        config_path = self.home / ".config/laneboss/configs/layered/config.toml"
        accounts = tomllib.loads(config_path.read_text())["runners"]["agent"]["accounts"]
        token = "gh" + "p_" + uuid.uuid4().hex + uuid.uuid4().hex[:6]
        name = "account-child"
        work = self.directory / name
        work.mkdir()
        args = ["lane", "start", "--config", "layered", "--lane", name, "--brief", self.brief,
                "--worktree", work, "--runner", "agent", "--model", "fixture-account-1",
                "--effort", "high", "--role", "executor"]
        if turns:
            args += ["--turns"]
        refused = self.cli(*args, "--account", token)
        self.assertEqual(refused.returncode, 2)
        self.assertNotIn(token, refused.stdout + refused.stderr, "a rejected account must never be echoed")
        self.assertEqual(refused.stderr, "refused: --account: the runner does not list that account; its accounts: " +
                         ", ".join(accounts) + "\n", "account requests must retain the original known-account refusal")
        self.assertFalse(self.calls_file.exists(), "a rejected account must not start a runner")
        first = self.json_cli(*args, "--account", accounts[0])
        self.lanes.append(name)
        self.assertEqual(first["account"], accounts[0])
        self.finish(name=name)
        self.assertEqual(len(self.calls()), 1)
        if turns:
            self.json_cli("lane", "send", "--config", "layered", "--lane", name, "--file", self.follow)
            result = self.cli("lane", "turn", "--config", "layered", "--lane", name, "--account", token)
        else:
            result = self.cli("lane", "resume", "--config", "layered", "--lane", name,
                              "--message", self.follow, "--account", token)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(token, result.stdout + result.stderr)
        for account in accounts:
            self.assertIn(account, result.stderr, "the refused follow-up must list the known accounts")
        self.assertTrue(result.stderr.startswith("refused: --account:"))
        self.assertEqual(len(self.calls()), 1, "a rejected account must not resume a runner")
        self.finish(name=name)
        events = self.cli("event", "tail", "--config", "layered", "--lane", name)
        self.assertEqual(events.returncode, 0, events.stderr)
        recorded = [json.loads(line) for line in events.stdout.splitlines()]
        self.assertTrue(recorded, "the original successful run must have actual events")
        self.assertNotIn("lane.resumed", [event["kind"] for event in recorded])
        self.assertEqual([event["payload"]["run"] for event in recorded if event["kind"] == "lane.started"], [1])
        # Request validation must not disable the screen on real role sources.
        self.role_values(account=token)
        source = self.cli("config", "validate", "layered")
        self.assertEqual(source.returncode, 2)
        self.assertIn("credential", source.stderr, "real role sources must retain their credential screen")
        self.assertNotIn(token, source.stdout + source.stderr)
        self.role_values()
        self.json_cli("config", "validate", "layered")

    def test_account_value_never_echoed(self):
        self.account_value_never_echoed()

    def test_turn_account_value_never_echoed(self):
        self.account_value_never_echoed(turns=True)

    def room_runner(self, turns=True):
        program = self.directory / "room.py"
        self.room_answers = self.directory / "room-answers.json"
        self.room_probes = self.directory / "room-probes.jsonl"
        self.write(program, ROOM_SOURCE.read_text(encoding="utf-8"))
        room = [sys.executable, str(program), "{account}", str(self.room_answers), str(self.room_probes)]
        self.configure(stdin=turns, room=room, observe_account=True)
        path = self.home / ".config/laneboss/configs/layered/config.toml"
        accounts = tomllib.loads(path.read_text())["runners"]["agent"]["accounts"]
        self.assertGreaterEqual(len(accounts), 2, "the room fixture needs two real configured accounts")
        self.write(self.room_answers, json.dumps({
            account: {"room": account == accounts[1], "slots": 1 if account == accounts[1] else 0,
                      "reason": "" if account == accounts[1] else "fixture account has no room"}
            for account in accounts
        }))
        return accounts

    def room_accounts_asked(self):
        self.assertTrue(self.room_probes.is_file(), "the configured room command must actually run")
        return [json.loads(line)["account"] for line in self.room_probes.read_text().splitlines()]

    def test_turn_room_automatic_account(self):
        accounts = self.room_runner()
        first = self.start_lane(turns=True)
        self.finish()
        self.assertEqual(first["account"], accounts[0])
        self.assertNotIn("account", first["settings"]["overrides"], "an automatic account must not be a lane override")
        self.assertEqual(self.calls()[0]["account"], accounts[0])
        self.assertFalse(self.room_probes.exists(), "lane start must not run the room command")
        self.json_cli("lane", "send", "--config", "layered", "--lane", "settings-lane", "--file", self.follow)
        result = self.cli("lane", "turn", "--config", "layered", "--lane", "settings-lane")
        self.assertEqual(result.returncode, 0, "an automatically chosen account must rotate to an account with room: " + result.stderr)
        resumed = json.loads(result.stdout)
        self.finish(run=2)
        self.assertEqual((resumed["account"], resumed["chosen_by"]["account"]), (accounts[1], "room"))
        self.assertEqual(self.room_accounts_asked(), [accounts[0], accounts[1]])
        self.assertEqual(resumed["settings"]["values"]["account"], accounts[1])
        self.assertNotIn("account", resumed["settings"]["overrides"])
        entry = resumed["settings"]["entries"]["account"]
        self.assertEqual(entry["layers"][entry["winner"]]["scope"], "default")
        self.assertEqual(len(self.calls()), 2)
        self.assertEqual(self.calls()[-1]["account"], accounts[1], "the actual resumed runner must receive the room choice")
        self.assertEqual(self.calls()[-1]["session"], first["session_id"])
        # An explicit request for this turn is never allowed to fall through.
        self.json_cli("lane", "send", "--config", "layered", "--lane", "settings-lane", "--file", self.follow)
        refused = self.cli("lane", "turn", "--config", "layered", "--lane", "settings-lane", "--account", accounts[0])
        self.assertEqual(refused.returncode, 2)
        self.assertIn("fixture account has no room", refused.stderr)
        self.assertEqual(self.room_accounts_asked(), [accounts[0], accounts[1], accounts[0]])
        self.assertEqual(len(self.calls()), 2, "an explicit account without room must not resume the runner")
        self.finish(run=2)

    def test_turn_room_explicit_setting(self):
        accounts = self.room_runner()
        first = self.start_lane(turns=True, sets=["account=" + accounts[0]])
        self.finish()
        self.assertEqual(first["settings"]["overrides"]["account"], accounts[0])
        self.json_cli("lane", "send", "--config", "layered", "--lane", "settings-lane", "--file", self.follow)
        result = self.cli("lane", "turn", "--config", "layered", "--lane", "settings-lane")
        self.assertEqual(result.returncode, 2, "a retained explicit account setting must not rotate without room")
        self.assertIn("fixture account has no room", result.stderr)
        self.assertEqual(self.room_accounts_asked(), [accounts[0]])
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.calls()[0]["account"], accounts[0])
        self.finish()

    def room_start_flag(self, turns):
        accounts = self.room_runner(turns=turns)
        first = self.start_lane(turns=turns, account=accounts[0])
        self.finish()
        self.assertEqual(first["account"], accounts[0])
        self.assertEqual(self.calls()[0]["account"], accounts[0])
        self.assertFalse(self.room_probes.exists(), "the start-time account flag applies without a room probe")
        operation = "turn" if turns else "resume"
        if turns:
            self.json_cli("lane", "send", "--config", "layered", "--lane", "settings-lane", "--file", self.follow)
            result = self.cli("lane", "turn", "--config", "layered", "--lane", "settings-lane")
        else:
            result = self.cli("lane", "resume", "--config", "layered", "--lane", "settings-lane", "--message", self.follow)
        self.assertEqual(result.returncode, 0, "an unnamed " + operation +
                         " must rotate after a start-only account flag: " + result.stderr)
        resumed = json.loads(result.stdout)
        self.finish(run=2)
        self.assertEqual((resumed["account"], resumed["chosen_by"]["account"]), (accounts[1], "room"))
        self.assertEqual(self.room_accounts_asked(), [accounts[0], accounts[1]])
        self.assertNotIn("account", first["settings"]["overrides"])
        self.assertNotIn("account", resumed["settings"]["overrides"])
        entry = first["settings"]["entries"]["account"]
        self.assertEqual(entry["layers"][entry["winner"]]["option"], "--account")
        self.assertEqual(resumed["settings"]["values"]["account"], accounts[1])
        self.assertEqual(len(self.calls()), 2)
        self.assertEqual(self.calls()[-1]["account"], accounts[1], "the actual runner must receive the rotated account")
        self.assertEqual(resumed["session_id"], first["session_id"])

    def test_turn_room_start_account(self):
        self.room_start_flag(turns=True)

    def test_resume_room_start_account(self):
        self.room_start_flag(turns=False)

    def test_turn_flag_keeps_set(self):
        accounts = self.room_runner()
        first = self.start_lane(turns=True, sets=["account=" + accounts[0]])
        self.finish()
        self.json_cli("lane", "send", "--config", "layered", "--lane", "settings-lane", "--file", self.follow)
        requested = self.json_cli("lane", "turn", "--config", "layered", "--lane", "settings-lane", "--account", accounts[1])
        self.finish(run=2)
        self.assertEqual(requested["account"], accounts[1])
        self.assertEqual(self.calls()[-1]["account"], accounts[1])
        self.json_cli("lane", "send", "--config", "layered", "--lane", "settings-lane", "--file", self.follow)
        result = self.cli("lane", "turn", "--config", "layered", "--lane", "settings-lane")
        if result.returncode == 0:
            self.finish(run=3)
        self.assertEqual(result.returncode, 2, "a temporary account flag must preserve the persistent account setting")
        self.assertIn("fixture account has no room", result.stderr)
        self.assertEqual(self.room_accounts_asked(), [accounts[1], accounts[0]])
        self.assertEqual(requested["settings"]["overrides"]["account"], accounts[0])
        self.assertEqual(requested["settings"]["values"]["account"], accounts[1])
        self.assertEqual(len(self.calls()), 2)
        self.assertEqual(self.calls()[-1]["session"], first["session_id"])
        self.finish(run=2)

    def test_allowed_child_grant(self):
        self.org_values(model="fixture-org-1", effort="high", env_allow=["LAYERED_ALLOWED"])
        self.queue_lane(level=4, role="supervisor")
        self.add_runner("child")
        work = self.directory / "grant-child"
        work.mkdir()
        answer = self.queued([str(self.binary), "lane", "start", "--config", "layered", "--lane", "grant-child",
                              "--role", "executor", "--difficulty", "standard", "--runner", "child",
                              "--brief", self.brief, "--worktree", work, "--set", 'env_allow=["LAYERED_ALLOWED"]'])
        self.assertEqual(answer["exit_code"], 0, "a child subset must remain allowed: " + answer["stderr"])
        self.lanes.append("grant-child")
        self.finish(name="grant-child")
        self.assertIn("LAYERED_ALLOWED", self.calls()[-1]["names"])
        self.assertEqual(json.loads(answer["stdout"])["settings"]["values"]["env_allow"], ["LAYERED_ALLOWED"])

    def check_mutant(self, point, expected):
        mutants = [SettingsTest(row) for row in expected]
        for mutant in mutants:
            mutant.binary_override, mutant.fault_point = FAULTS, point
        red = MutationResult()
        unittest.TestSuite(mutants).run(red)
        observed_rows = sorted(detail["row"] for detail in red.failure_details)
        expected_rows = sorted(expected)
        self.write(self.directory / (point + "-red.json"), json.dumps({
            "point": point, "expected_failures": expected, "tests_run": red.testsRun,
            "observed_rows": observed_rows, "expected_rows": expected_rows,
            "failures": red.failure_details,
            "errors": [{"row": case.id(), "traceback": trace} for case, trace in red.errors],
            "skipped": [(case.id(), reason) for case, reason in red.skipped],
            "expected_failures_annotations": [{"row": case.id(), "traceback": trace}
                                              for case, trace in red.expectedFailures],
            "unexpected_successes": [case.id() for case in red.unexpectedSuccesses],
            "cases": {case._testMethodName: str(case.directory) if hasattr(case, "directory") else None
                      for case in mutants},
            "markers": {case._testMethodName: {"path": str(case.marker) if hasattr(case, "marker") else None,
                                               "reached": hasattr(case, "marker") and case.marker.is_file()}
                        for case in mutants},
        }))
        self.assertEqual(red.errors, [], "the mutation must fail named assertions rather than its fixture")
        self.assertEqual(red.skipped, [], "every named mutant row must execute")
        self.assertEqual(red.expectedFailures, [], "an expected-failure annotation must not replace a kill")
        self.assertEqual(red.unexpectedSuccesses, [])
        self.assertEqual(red.testsRun, len(expected), "the mutant suite must run every named row")
        self.assertEqual([trace for _, trace in red.failures], [detail["traceback"] for detail in red.failure_details],
                         "every actual failure must be retained in the named verdict")
        # Keep the complete lists in the message, outside unittest's list diff.
        self.assertTrue(observed_rows == expected_rows,
                        "the mutant must fail exactly the named rows once each; duplicate or cleanup failures are not kills"
                        "\nexpected_rows=" + json.dumps(expected_rows) + "\nobserved_rows=" + json.dumps(observed_rows) +
                        "\nfailure_phases=" + json.dumps([{"row": detail["row"], "phase": detail["phase"]}
                                                        for detail in red.failure_details]))
        for detail in red.failure_details:
            self.assertEqual(detail["phase"], "test", "a fixture failure must not count as a named mutant kill")
            self.assertIn(expected[detail["row"]], detail["assertion"],
                          "each mutant row must fail by its own named assertion: " + detail["row"])
        for mutant in mutants:
            self.assertTrue(mutant.marker.is_file(), "the actual mutation boundary must be reached for " + mutant._testMethodName)
            if point == "settings-inherit-env":
                self.assertIn("LAYERED_UNLISTED", mutant.calls()[0]["names"])
            if point == "settings-delegate-env":
                self.assertIn("LAYERED_UNLISTED", mutant.observed_names)

        restored = [SettingsTest(row) for row in expected]
        green = MutationResult()
        unittest.TestSuite(restored).run(green)
        self.write(self.directory / (point + "-green.json"), json.dumps({
            "point": point, "expected_rows": list(expected), "tests_run": green.testsRun,
            "failures": green.failure_details,
            "errors": [{"row": case.id(), "traceback": trace} for case, trace in green.errors],
            "skipped": [(case.id(), reason) for case, reason in green.skipped],
            "expected_failures_annotations": [{"row": case.id(), "traceback": trace}
                                              for case, trace in green.expectedFailures],
            "unexpected_successes": [case.id() for case in green.unexpectedSuccesses],
            "cases": {case._testMethodName: str(case.directory) if hasattr(case, "directory") else None
                      for case in restored},
        }))
        self.assertEqual(green.errors, [])
        self.assertEqual(green.skipped, [], "every restored row must execute")
        self.assertEqual(green.expectedFailures, [])
        self.assertEqual(green.unexpectedSuccesses, [])
        self.assertEqual(green.testsRun, len(expected), "the restored suite must run every named row")
        self.assertEqual(green.failures, [], "the same named rows must pass after restoration")
        for mutant, control in zip(mutants, restored):
            row = mutant._testMethodName
            detail = next(item for item in red.failure_details if item["row"] == row)
            self.write(self.directory / (point + "-" + row + ".json"), json.dumps({
                "point": point, "row": row, "expected_assertion": expected[row], "red": detail["traceback"],
                "assertion": detail["assertion"], "marker": str(mutant.marker), "restored": str(control.directory),
            }))

    def test_hook_mutants(self):
        cases = {
            "settings-frozen-delegation": {
                "test_resume_env_widened": "resume must apply owned env_allow widening",
                "test_turn_env_widened": "turn must apply owned env_allow widening",
                "test_resume_revoke_refused": "the next run must refuse a revoked explicit grant",
                "test_turn_revoke_refused": "the next run must refuse a revoked explicit grant",
            },
            "settings-paths-unprotected": {
                "test_settings_protected": "protected settings file must be refused",
            },
            "settings-role-required": {
                "test_missing_role_allows": "ordinary call refused without a role settings file",
            },
            "settings-short-instance": {
                "test_long_instance_allows": "ordinary call refused for a valid long instance name",
            },
            "settings-tool-deny-skip": {
                "test_hook_tool_deny": "resolved tool deny must refuse an instance call",
                "test_hook_deny_beats_allow": "a deny must beat a matching allow addition",
                "test_hook_lane_snapshot": "the authenticated lane must retain its recorded deny",
            },
            "settings-history-live": {
                "test_hook_historic_lane": "a historic lane must not acquire unrecorded live settings",
            },
            "settings-deny-replace": {
                "test_deny_union": "a narrower layer must not clear the org deny",
            },
            "settings-delegate-env": {
                "test_delegate_env_refused": "env_allow amplification must be refused",
                "test_instance_grant_refused": "env_allow amplification must be refused",
            },
        }
        for point, expected in cases.items():
            with self.subTest(point=point):
                self.check_mutant(point, expected)


if __name__ == "__main__":
    unittest.main()
