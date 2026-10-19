"""Black-box role rows; run check-roles.sh on a disposable Linux test machine.

Only the vendor is doubled. It reads the actual brief delivered by the installed
launcher and records that input. CLI output, events, policy reads, claims, tmux,
resume and turns are real. Every case retains its inputs and command output.
The five fault-tag mutants alter actual decisions or rendered bytes, never a
test result. Each is caught by an ordinary row, followed by the restored row.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import tomllib
import unittest
import uuid

# The human at a controlling terminal is the one caller the launcher authenticates as the human; the rows that need it
# take the shared pty helper of the report rows. Its controller runs with -I, so only this directory is added here.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from reportsupport import TerminalController


ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "internal/rolepolicy/library"
# The [supervisors] entry whose session every row records in setUp (RolesTest.identify).
SUPERVISOR = "fixture-supervisor"
# The rows whose human steps come first and record that session themselves. The human's terminal is a child of the test
# process, so once this process is a recorded supervisor session the terminal's commands resolve as that supervisor.
HUMAN_FIRST = ("test_human_exception",)
EXPECTED_ROLES = {
    3: {"executor", "reviewer", "tester", "docs", "researcher"},
    4: {"supervisor", "reviewer"},
    5: {"top", "top-supervisor", "supervisor", "reviewer"},
    6: {"supervisor"},
}
VENDOR = '''#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys

message, calls, record = sys.argv[1:]
text = sys.stdin.read() if message == "stdin" else Path(message).read_text()
with Path(calls).open("a") as stream:
    stream.write(json.dumps({"argv": sys.argv[1:], "brief": text, "canary": os.environ.get("ROLE_CANARY")}) + "\\n")
Path(record).write_text("session received its actual brief\\n")
print(text, end="")
'''


def setUpModule():
    if not sys.platform.startswith("linux"):
        raise RuntimeError("role E2E rows require the designated disposable Linux machine")
    global RELEASE, FAULTS, EVIDENCE
    names = ("LANEBOSS_ROLES_BINARY", "LANEBOSS_ROLES_FAULTS_BINARY", "LANEBOSS_ROLES_EVIDENCE")
    if any(not os.environ.get(name) for name in names):
        raise RuntimeError("check-roles.sh must supply both builds and an evidence directory")
    RELEASE = Path(os.environ[names[0]]).resolve(strict=True)
    FAULTS = Path(os.environ[names[1]]).resolve(strict=True)
    EVIDENCE = Path(os.environ[names[2]]).resolve(strict=True)
    if not EVIDENCE.is_dir() or not all(os.access(binary, os.X_OK) for binary in (RELEASE, FAULTS)):
        raise RuntimeError("role E2E prerequisites are incomplete")
    for name in ("git", "tmux"):
        if shutil.which(name) is None:
            raise RuntimeError("role E2E needs " + name)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class RolesTest(unittest.TestCase):
    binary_override = None
    fault_point = None

    def setUp(self):
        self.directory = EVIDENCE / (self._testMethodName + "-" + uuid.uuid4().hex[:12])
        self.directory.mkdir()
        self.home = self.directory / "home"
        self.home.mkdir()
        self.org = self.directory / "org"
        self.binary = self.binary_override or RELEASE
        self.marker = self.directory / "mutant-reached"
        self.env = {"HOME": str(self.home), "PATH": os.defpath, "LC_ALL": "C"}
        self.env["LANEBOSS_TEST_CLAIMS_DIR"] = str(self.directory / "claims")
        if self.fault_point:
            self.env["LANEBOSS_FAULTS"] = json.dumps({"point": self.fault_point, "marker": str(self.marker)})
        self.counter = 0
        self.lanes = []
        self.calls_file = self.directory / "vendor-calls.jsonl"
        self.records = self.directory / "records"
        self.records.mkdir()
        self.bin_dir = self.directory / "bin"
        self.bin_dir.mkdir()
        self.driver = "role-agent-" + uuid.uuid4().hex[:12]
        self.second_driver = "role-other-" + uuid.uuid4().hex[:12]
        self.blocked_driver = "role-blocked-" + uuid.uuid4().hex[:12]
        for name in (self.driver, self.second_driver, self.blocked_driver, self.driver + "-wrapper"):
            program = self.bin_dir / name
            program.write_text(VENDOR)
            program.chmod(0o755)
        self.cli_json("org", "init", self.org, "--name", "roles-demo")
        self.cli_json("org", "roles", "init", self.org)
        self.config_dir = self.home / ".config/laneboss/configs/roles-demo"
        self.config_dir.mkdir(parents=True)
        self.brief = self.directory / "brief.md"
        self.task = "# Assigned task\n\nRead canary " + uuid.uuid4().hex[:16] + ".\n"
        self.brief.write_text(self.task)
        self.configure()
        self.observed = {}
        self.terminal = None
        from ticket_fixture import fixture_for, service_rows
        if service_rows(self, self.env):
            fixture_for(self).bind("roles-demo", self.env, policy_drivers=[self.driver])
        # Lane start and adoption refuse a caller that nothing identifies, so each row records this process as the
        # configured supervisor's session before it starts, adopts, resumes, turns or sends.
        if self._testMethodName not in HUMAN_FIRST:
            self.identify()

    def tearDown(self):
        # A failed row must still retain its lane state and collect its processes.
        # Stop only a recorded live lane; never kill by a command-line pattern.
        for lane in self.lanes:
            status = self.cli("lane", "status", "--config", "roles-demo", "--lane", lane)
            if status.returncode != 0:
                raise AssertionError("the retained lane status could not be read: " + status.stderr)
            row = json.loads(status.stdout)
            if row["running"] or row["live"]["survivors"]:
                stopped = self.cli_json("lane", "stop", "--config", "roles-demo", "--lane", lane)
                self.assertEqual(stopped.get("survivors"), 0, "cleanup must leave no survivor")
        # Evidence is deliberately retained outside the source tree.

    def human_terminal(self):
        """The human at a controlling terminal, the one caller that the launcher authenticates as the human."""
        if self.terminal is None:
            self.terminal = TerminalController(self, self.binary, self.env, self.directory)
        return self.terminal

    def cli(self, *args, extra_env=None, human=False):
        from ticket_fixture import service_rows, with_registration
        service = service_rows(self, self.env)
        if not service:
            args = with_registration(self, args, self.env)
        self.counter += 1
        command = [str(self.binary), *(str(arg) for arg in args)]
        env = dict(self.env)
        if extra_env:
            env.update(extra_env)
        if human:
            answer = self.human_terminal().request([str(arg) for arg in args], environment=extra_env or {})
            if service:
                actor = self.human_terminal()
                command = [actor.last_binary, *actor.last_arguments]
            result = subprocess.CompletedProcess(command, answer["code"], answer["stdout"], answer["stderr"])
        elif service and args and args[0] not in ("config", "org", "doctor", "init") and "--help" not in args and "-h" not in args:
            from headless_support import HeadlessController
            if not hasattr(self, "_service_headless"):
                selected = dict(self.env)
                if "--config" in args:
                    selected["LANEBOSS_CONFIG"] = args[args.index("--config") + 1]
                self._service_headless = HeadlessController(self, selected, self.directory, self.binary)
            answer = self._service_headless.request(args, environment=extra_env or {})
            command = [self._service_headless.last_binary, *self._service_headless.last_arguments]
            result = subprocess.CompletedProcess(command, answer["code"], answer["stdout"], answer["stderr"])
        else:
            # An ordinary command runs in a session of its own, without a controlling terminal, so it never
            # resolves as the human, however the rows are started.
            result = subprocess.run(command, cwd=self.directory, env=env, text=True,
                                    capture_output=True, timeout=60, start_new_session=True)
        if service and not human and tuple(args[:3]) == ("org", "instance", "add") and result.returncode == 0:
            self._ticket_fixture.publish_instance("roles-demo", args[3], args[4])
        stem = self.directory / ("command-" + str(self.counter))
        stem.with_suffix(".json").write_text(json.dumps({"argv": command, "exit_code": result.returncode}))
        stem.with_suffix(".stdout").write_text(result.stdout)
        stem.with_suffix(".stderr").write_text(result.stderr)
        return result

    def cli_json(self, *args, **kwargs):
        result = self.cli(*args, **kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def configure(self, driver=None, resume_driver=None, stdin=False, shell=False, prefix=None, session_records=False):
        driver = driver or self.driver
        resume_driver = resume_driver or driver
        message = "stdin" if stdin else "{brief}"
        follow_up = "stdin" if stdin else "{message}"
        record = str(self.records / "{session}.log")
        # The vendor's receipt is separate from the text scanner's run log. Adoption also needs a session record.
        records = '{format = "text", paths = ["{log}"]}'
        if session_records:
            records += ', {format = "claude-code", paths = [' + json.dumps(str(self.records / "{session}.jsonl")) + ']}'
        command = [str(self.bin_dir / driver), message, str(self.calls_file), record]
        resume = [str(self.bin_dir / resume_driver), follow_up, str(self.calls_file), record]
        if shell:
            command = ["/bin/sh", *command]
        if prefix:
            command, resume = [*prefix, *command], [*prefix, *resume]
        text = (
            'schema_version = 1\nname = "roles-demo"\norg_dir = ' + json.dumps(str(self.org)) + '\n'
            '[lanes]\nbudget_minutes = 1\nquiet_seconds = 1\nstop_grace_seconds = 1\n'
            '[runners.agent]\ncommand = ' + json.dumps(command) + '\nresume = ' + json.dumps(resume) + '\n'
            'accounts = []\nquiet_seconds = 1\nprompt = ' + json.dumps("stdin" if stdin else "argument") + '\n'
            'records = [' + records + ']\n'
            '[supervisors.' + SUPERVISOR + ']\nlevel = 5\nrunner = "agent"\n'
        )
        from ticket_fixture import service_text
        (self.config_dir / "config.toml").write_text(service_text(self, text))

    def identify(self):
        """Record this test process as the configured supervisor's session, the way LB-235's rows record theirs.

        Lane start, adoption, resume, turn and send refuse a caller that nothing identifies, and a lane's starter may
        message it, so setUp records the session before a row starts its lane: the lane then records the supervisor
        as its starter. An ordinary command of these rows has no controlling terminal, so `laneboss start --role`
        records a headless session for this process; the role label put in the environment agrees with that record.
        The entry is an L5 so that the row that starts an L4 lane can: a lane must be below its starter's level.
        """
        started = self.cli("start", "--config", "roles-demo", "--role", SUPERVISOR)
        self.assertEqual(started.returncode, 0, started.stderr)
        self.env["LANEBOSS_ROLE"] = SUPERVISOR

    def keep_command_listed(self):
        """Keep the runner's command driver on a role's list while a row narrows the reviewer's list.

        `event tail`, which finished() runs, loads the whole configuration through the caller's identity, and the
        combined launcher refuses a configuration with a runner that no role permits. A row that narrows the
        reviewer's list while the runner's command still names the first driver therefore lists that driver for the
        tester, a role the rows start no lane with. Resume and turn check the recorded role's own list, the
        reviewer's, which is what the row changes.
        """
        self.drivers("tester", [self.driver])

    def role_path(self, name="reviewer", extension=".md", level=3):
        return self.org / ".laneboss" / ("L" + str(level)) / "roles" / (name + extension)

    def test_org_project_code(self):
        """Org reads must accept ordinary project code and still refuse literals."""
        project = self.org / "project"
        project.mkdir()
        python = (
            "self.token" + " = token\n"
            + "password" + " = options.password if options.password is not None else getpass.getpass("
            + json.dumps("Password: ") + ")\n"
        )
        go = (
            "package project\nfunc copyToken(cfg struct{ Token string }) {\n"
            + "token" + " := cfg.Token\n_ = token\n}\n"
        )
        for name, text in (("project.py", python), ("project.go", go)):
            (project / name).write_text(text, encoding="utf-8")
            (self.directory / ("input-" + name)).write_text(text, encoding="utf-8")
        result = self.cli("org", "validate", self.org, "--format", "json")
        self.assertEqual(result.returncode, 0, "org workspace code must pass: " + result.stderr)
        validated = json.loads(result.stdout)
        self.assertIs(validated.get("valid"), True)
        self.assertEqual(validated.get("problems"), [])
        listed = self.cli("org", "roles", "list", self.org)
        self.assertEqual(listed.returncode, 0, "role listing must accept project code: " + listed.stderr)
        own = {(row["level"], row["role"]) for row in json.loads(listed.stdout)["roles"]}
        self.assertEqual(own, {(level, name) for level, names in EXPECTED_ROLES.items() for name in names})
        value = "-".join(("hunter2", "literal", "value"))
        literal = "token" + " = " + json.dumps(value) + "\n"
        (project / "project.py").write_text(literal, encoding="utf-8")
        (self.directory / "input-literal.py").write_text(literal, encoding="utf-8")
        refused = self.cli("org", "validate", self.org, "--format", "json")
        self.assertEqual(refused.returncode, 2, "a quoted project literal must refuse")
        invalid = json.loads(refused.stdout)
        self.assertIs(invalid.get("valid"), False)
        self.assertTrue(any(
            row.get("path") == "project/project.py" and "secret-assignment" in row.get("message", "")
            for row in invalid.get("problems", [])
        ), "the real project literal must be found")
        self.assertNotIn(value, refused.stdout + refused.stderr)

    def test_org_seed_files(self):
        """Validate both complete medium seed files, preserving their bytes."""
        fixtures = ROOT / "internal/orgtree/testdata/orgscan"
        project = self.org / "project"
        for source, relative in (("client.py", "taskforge/client.py"),
                                 ("test_application.py", "tests/test_application.py")):
            data = (fixtures / source).read_bytes()
            target = project / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            (self.directory / ("input-" + source)).write_bytes(data)
            self.assertEqual(target.read_bytes(), data, "the whole seed file must be copied unchanged")
        result = self.cli("org", "validate", self.org, "--format", "json")
        self.assertEqual(result.returncode, 0, "complete medium seed files must pass: " + result.stderr)
        validated = json.loads(result.stdout)
        self.assertIs(validated.get("valid"), True)
        self.assertEqual(validated.get("problems"), [])

    def test_org_all_findings(self):
        """The real workspace reports both flagged lines and their rules."""
        value = "-".join(("hunter2", "literal", "value"))
        assignment = "\n" + "token" + " = " + json.dumps(value) + "\n"
        text = assignment + assignment
        project = self.org / "project"
        project.mkdir()
        (project / "literals.py").write_text(text, encoding="utf-8")
        (self.directory / "input-literals.py").write_text(text, encoding="utf-8")
        result = self.cli("org", "validate", self.org, "--format", "json")
        self.assertEqual(result.returncode, 2, "project literals must refuse")
        validated = json.loads(result.stdout)
        self.assertIs(validated.get("valid"), False)
        self.assertEqual(validated.get("problems"), [
            {"path": "project/literals.py", "message": "secret value detected on line " + str(line)
             + " (secret-assignment); keep secret names only"}
            for line in (2, 4)
        ], "both project literal lines must be reported")
        self.assertNotIn(value, result.stdout + result.stderr)

    def prepare_roles(self):
        body = self.role_path().read_bytes() + ("\nReview canary " + uuid.uuid4().hex[:16] + ".\n").encode()
        self.role_path().write_bytes(body)
        self.drivers("reviewer", [self.driver])
        self.drivers("executor", [self.second_driver])
        return body

    def drivers(self, role, names, level=3):
        self.role_path(role, ".toml", level).write_text("drivers = " + json.dumps(names) + "\n")

    def start(self, role="reviewer", turns=False, extra_env=None, principal=None, level=3, human=False, instance=None):
        lane = "role-" + uuid.uuid4().hex[:12]
        work = self.directory / (lane + "-work")
        work.mkdir()
        args = ["lane", "start", "--config", "roles-demo", "--lane", lane,
                "--brief", self.brief, "--worktree", work, "--runner", "agent",
                "--model", "example-model-medium-1", "--budget", "1", "--level", level]
        if role is not None:
            args += ["--role", role]
        if principal is not None:
            args += ["--principal", principal]
        if turns:
            args += ["--turns"]
        if instance is not None:
            args += ["--instance", instance]
        result = self.cli(*args, extra_env=extra_env, human=human)
        if result.returncode == 0:
            self.lanes.append(lane)
        self.observed = {"exit_code": result.returncode, "stderr": result.stderr,
                         "stdout": result.stdout, "lane": lane, "calls": self.calls()}
        return lane, result

    def calls(self):
        return [json.loads(line) for line in self.calls_file.read_text().splitlines()] if self.calls_file.exists() else []

    def finished(self, lane, run=1, since=0):
        result = self.cli("event", "tail", "--config", "roles-demo", "--lane", lane,
                          "--since", since, "--follow", "--until", "lane.ended")
        self.assertEqual(result.returncode, 0, result.stderr)
        ended = [json.loads(line) for line in result.stdout.splitlines() if json.loads(line)["kind"] == "lane.ended"]
        self.assertEqual(len(ended), 1, "the new run must have one observed end")
        payload = ended[0]["payload"]
        self.assertEqual((payload["run"], payload["reason"], payload["exit_code"], payload["survivors"]),
                         (run, "exit", 0, 0), "the actual vendor run must end successfully")
        return self.wait_quiescent(lane, run)

    def wait_quiescent(self, lane, run=1):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            row = self.cli_json("lane", "status", "--config", "roles-demo", "--lane", lane)
            live = row["live"]
            if not row["running"] and not live["supervisor"]["alive"] and not live["session_alive"]:
                self.assertEqual((row["run"], row["reason"], row["exit_code"]),
                                 (run, "exit", 0), "the actual vendor run must end successfully")
                self.assertEqual((live["survivors"], live["pending_events"], live["refused_events"]), (0, 0, 0))
                return row
            time.sleep(1)
        self.fail("the actual lane worker did not become quiescent")

    def refused(self, result, message):
        if result.returncode == 0:
            lane = self.observed["lane"]
            # These rows deliberately configure a driver no role permits, or
            # an env shape configuration validation rejects. event tail resolves
            # its caller through that whole-config validation, independently of
            # the mutated lane gate. Observe the real lifecycle through status
            # before collecting receipts and failing the intended assertion.
            self.wait_quiescent(lane)
            self.observed["calls"] = self.calls()
        self.assertEqual(result.returncode, 2, message)
        self.assertIn("Instead:", result.stderr, "a role refusal must supply its recovery route")
        self.assertEqual(self.calls(), [], "a refused start must not reach the vendor")

    def test_library_created(self):
        """Fails if explicit roles init omits, changes or misconfigures a shipped source."""
        for level, names in EXPECTED_ROLES.items():
            directory = self.org / ".laneboss" / ("L" + str(level)) / "roles"
            self.assertEqual({p.stem for p in directory.glob("*.md")}, names)
            for name in names:
                for extension in (".md", ".toml"):
                    path = directory / (name + extension)
                    self.assertEqual(path.read_bytes(), (LIBRARY / ("L" + str(level)) / path.name).read_bytes())
                drivers = tomllib.loads((directory / (name + ".toml")).read_text())["drivers"]
                self.assertEqual(drivers, ["codex", "claude", "claudock"]
                                 if level == 3 or (level, name) == (4, "reviewer") else ["claude", "claudock"])
        alias = self.directory / "alias-org"
        self.cli_json("org", "init", alias, "--levels", "3", "--name", "alias-demo")
        self.cli_json("org", "roles", "init", alias)
        self.assertEqual((alias / ".laneboss/L3/roles/reviewer.md").read_bytes(),
                         (LIBRARY / "L3/reviewer.md").read_bytes())

    def test_library_list_and_preserve(self):
        """Fails if list is constant, hashes differ from bytes, or roles init overwrites an edit."""
        body = self.prepare_roles()
        custom = "custom-" + uuid.uuid4().hex[:12]
        self.role_path(custom).write_bytes(body)
        self.drivers(custom, [self.second_driver])
        self.cli_json("org", "roles", "init", self.org)
        self.assertEqual(self.role_path().read_bytes(), body, "existing org role edits must survive roles init")
        listed = self.cli_json("org", "roles", "list", self.org)
        library = {(r["level"], r["role"]): r for r in listed["library"]}
        own = {(r["level"], r["role"]): r for r in listed["roles"]}
        self.assertEqual(set(library), {(level, name) for level, names in EXPECTED_ROLES.items() for name in names})
        self.assertIn((3, custom), own)
        self.assertEqual(own[(3, "reviewer")]["sha256"], sha(body))
        self.assertEqual(own[(3, "reviewer")]["drivers"], [self.driver])
        self.assertEqual(library[(3, "reviewer")]["sha256"], sha((LIBRARY / "L3/reviewer.md").read_bytes()))
        updated = self.cli("org", "roles", "init", self.org, "--update")
        self.assertEqual(updated.returncode, 0, updated.stderr)
        self.assertIn("--- .laneboss/L3/roles/reviewer.md (current)", updated.stderr)
        self.assertIn("+++ .laneboss/L3/roles/reviewer.md (library)", updated.stderr)
        self.assertEqual(self.role_path().read_bytes(), (LIBRARY / "L3/reviewer.md").read_bytes())
        self.assertEqual(self.role_path(custom).read_bytes(), body)

    def test_rendered_role_and_event(self):
        """Fails if the role section/body is absent, misplaced, constant, or recorded under a false hash."""
        body = self.prepare_roles()
        lane, result = self.start()
        self.assertEqual(result.returncode, 0, result.stderr)
        started = json.loads(result.stdout)
        self.finished(lane)
        text = Path(started["brief"]["path"]).read_text()
        self.observed["calls"] = self.calls()
        self.assertIn("## Your role: reviewer (L3)", text, "rendered role heading must be present")
        self.assertIn(body.decode(), text, "rendered role body must use the edited template bytes")
        self.assertLess(text.index(".laneboss/L3/protocol/role.md"), text.index("## Your role:"))
        self.assertLess(text.index("## Your role:"), text.index("## Your task"))
        self.assertIn("## Your task\n\n" + self.task, text)
        self.assertEqual(started["role"], "reviewer")
        self.assertEqual(started["role_context"]["sha256"], sha(body))
        self.assertEqual(started["role_context"]["drivers_sha256"], sha(self.role_path("reviewer", ".toml").read_bytes()))
        events = self.cli("event", "tail", "--config", "roles-demo", "--lane", lane)
        self.assertEqual(events.returncode, 0, events.stderr)
        rows = [json.loads(line) for line in events.stdout.splitlines()]
        event = next(row for row in rows if row["kind"] == "lane.started")
        self.assertEqual(event["payload"]["role_context"], started["role_context"])
        rendered = next(row for row in rows if row["kind"] == "brief.rendered")
        sources = {item.get("path"): item for item in rendered["payload"]["inputs"]}
        kept = sources[".laneboss/L3/roles/reviewer.md"]
        state = self.home / ".local/state/laneboss/roles-demo"
        self.assertEqual((state / kept["copy"]).read_bytes(), body)
        self.assertEqual(self.calls()[0]["brief"], text)
        verified = self.cli_json("state", "verify", "--config", "roles-demo")
        self.assertTrue(verified["ok"], "the new event extension must pass state verification")

    def test_rendered_blacklist_rules(self):
        """The real lane reads its rules before acting; only its vendor is doubled."""
        from orgsupport import write_rule_source
        self.drivers("executor", [self.driver])
        instance = "L3-rule-reader"
        self.cli_json("org", "instance", "add", self.org, instance, "--level", "3", "--role", "executor")
        higher = self.role_path("reviewer", ".toml", level=5)
        write_rule_source(self, higher, higher.read_text() +
                          '\n[[blacklist]]\nid = "domain-lane-rule"\n'
                          'description = "Domain calls require review."\nband = "warn"\n'
                          'argv_prefix = ["printf", "domain-rule"]\npattern_only = true\n'
                          'instead = "Report the domain result for review."\n')
        rules_path = self.directory / "lane-rules.txt"
        json_path = self.directory / "lane-rules.json"
        result_path = self.directory / "lane-rules.exit"
        # This subprocess inherits the actual launched runner's process ancestry.
        # It supplies no level, role, instance or forged caller identity.
        program = self.bin_dir / self.driver
        program.write_text(VENDOR + '\nimport subprocess\n' +
                           'for options, target in [( [], ' + repr(str(rules_path)) +
                           '), (["--format", "json"], ' + repr(str(json_path)) + ')]:\n' +
                           '    result = subprocess.run(' + repr([str(self.binary), "org", "blacklist", "list"]) +
                           ' + options, text=True, capture_output=True, timeout=30)\n' +
                           '    Path(target).write_text(result.stdout)\n' +
                           '    Path(target + ".stderr").write_text(result.stderr)\n' +
                           '    Path(' + repr(str(result_path)) + ').write_text(str(result.returncode) + "\\n")\n' +
                           '    if result.returncode != 0:\n        sys.exit(result.returncode)\n')
        lane, result = self.start(role="executor", instance=instance)
        self.assertEqual(result.returncode, 0, result.stderr)
        started = json.loads(result.stdout)
        self.finished(lane)
        brief = Path(started["brief"]["path"]).read_text()
        self.assertIn("Run `laneboss org blacklist list` first", brief)
        self.assertNotIn("blacklist try", brief)
        self.assertIn(str(self.org / ".laneboss/org.toml"), brief)
        section = brief.split("## What your org hook refuses\n", 1)[1].split("## Your task", 1)[0]
        self.assertNotIn("raw-codex-exec", section, "the prompt points to the rules instead of embedding them")
        self.assertEqual(result_path.read_text(), "0\n")
        text = rules_path.read_text()
        self.assertIn("[raw-codex-exec] Band: refuse", text)
        self.assertIn("Instead: laneboss lane start / laneboss lane resume / laneboss lane turn", text)
        self.assertIn("L3 worktree boundary:", text)
        rules = json.loads(json_path.read_text())
        self.assertEqual((rules["caller"], rules["level"], rules["role"], rules["instance"]),
                         ("lane:" + lane, 3, "executor", instance))
        expected_sources = [self.org / ".laneboss/org.toml", self.role_path("executor", ".toml")]
        for level in (4, 5, 6):
            expected_sources.extend(sorted((self.org / ".laneboss" / ("L" + str(level)) / "roles").glob("*.toml")))
        self.assertEqual(rules["sources"], list(map(str, expected_sources)))
        self.assertNotIn(str(self.role_path("reviewer", ".toml")), rules["sources"])
        pack = tomllib.loads((self.org / ".laneboss/org.toml").read_text())["hooks"]["blacklist"]
        by_id = {row["id"]: row for row in rules["entries"]}
        self.assertEqual(set(by_id), {entry["id"] for entry in pack} | {"domain-lane-rule"})
        for entry in pack:
            self.assertEqual({key: by_id[entry["id"]][key] for key in ("id", "band", "description", "instead")},
                             {key: entry[key] for key in ("id", "band", "description", "instead")})
            self.assertEqual(by_id[entry["id"]]["source"], str(self.org / ".laneboss/org.toml"))
        self.assertEqual(by_id["domain-lane-rule"]["band"], "warn")
        self.assertEqual(by_id["domain-lane-rule"]["source"], str(higher))
        self.assertEqual(by_id["domain-lane-rule"]["instead"], "Report the domain result for review.")
        self.assertEqual(self.calls()[0]["brief"], brief)
        self.assertFalse((self.org / ".laneboss/instances" / instance / "hooks/callbacks.jsonl").exists(),
                         "reading the rules must not create hook callback receipts")

    def test_supervisor_without_role(self):
        """Fails if a supervisor can start without a role, even with the human exception enabled."""
        self.prepare_roles()
        config = self.org / ".laneboss/org.toml"
        config.write_text(config.read_text() + '\n[lane_roles.L3]\nallow_human_without_role = true\n')
        _, result = self.start(role=None)
        self.refused(result, "supervisor starts require a role")
        self.assertIn("a role is required at L3", result.stderr)
        self.assertIn("reviewer", result.stderr)

    def test_unknown_role(self):
        """Fails if an unknown role is guessed or accepted."""
        self.prepare_roles()
        _, result = self.start(role="unknown-" + uuid.uuid4().hex[:12])
        self.refused(result, "unknown roles must refuse")
        self.assertIn("unknown role at L3", result.stderr)
        self.assertIn("reviewer", result.stderr)

    def test_human_exception(self):
        """Fails if a role-free start is accepted for a human, with or without the org setting, or a recorded supervisor session, or a bound session, can claim to be human."""
        self.prepare_roles()
        # Only the human at a controlling terminal is authenticated as the human, so the human's starts run from one,
        # before this process is recorded as a supervisor's session (HUMAN_FIRST): the terminal is its child.
        _, denied = self.start(role=None, principal="human", human=True)
        self.refused(denied, "a human still needs the org's role-free permission")
        config = self.org / ".laneboss/org.toml"
        config.write_text(config.read_text() + '\n[lane_roles.L3]\nallow_human_without_role = true\n')
        # The human's process carries none of LANEBOSS_LANE, LANEBOSS_INSTANCE or LANEBOSS_PRINCIPAL: it passes
        # for a human, and still needs a role.
        _, declared = self.start(role=None, principal="human", human=True)
        self.refused(declared, "the human exception grants nothing until identity binding")
        self.assertIn("a role is required at L3", declared.stderr)
        self.assertIn("reviewer", declared.stderr)
        # From here the row's headless commands run under the supervisor's recorded session, as in every other row.
        self.identify()
        # A headless process is not the human, whatever its environment holds: the launcher resolves it to the
        # supervisor whose session it is, so the declaration is refused before any role is selected, and no unproven
        # human reaches a role_context. (A caller that nothing identifies is refused earlier still: row C1.)
        _, headless = self.start(role=None, principal="human")
        self.refused(headless, "a recorded supervisor session must not select the human principal")
        self.assertEqual(headless.stderr.splitlines()[0],
                         "refused: a supervised session cannot select a human principal")
        # The caller's identity is resolved before the role gate. No recorded lane carries this label, so the
        # start is refused as an unproven identity, with the identity refusal's own first line.
        _, bound = self.start(role=None, principal="human", extra_env={"LANEBOSS_LANE": "supervising-lane"})
        self.assertEqual(bound.returncode, 2, "a bound supervisor must not impersonate a human")
        self.assertEqual(bound.stderr.splitlines()[0],
                         "refused: LANEBOSS_LANE disagrees with the caller's recorded lane identity")
        self.assertEqual(self.calls(), [])

    def test_role_specific_driver(self):
        """Fails if a driver allowed by executor is also accepted for reviewer."""
        self.prepare_roles()
        self.configure(driver=self.second_driver)
        _, result = self.start()
        self.refused(result, "role-specific driver mismatch must refuse before exec")
        self.assertIn("runner driver is not allowed", result.stderr)
        self.assertIn("Instead: use an allowed driver: " + self.driver, result.stderr)

    def test_unlisted_driver(self):
        """Fails if a driver allowed by no role reaches its vendor."""
        self.prepare_roles()
        self.configure(driver=self.blocked_driver)
        _, result = self.start()
        self.refused(result, "unlisted driver must refuse before exec")
        self.assertIn("Instead: use an allowed driver: " + self.driver, result.stderr)

    def test_level_and_custom_role(self):
        """Fails if a role from another level is accepted or an org owner's custom role is ignored."""
        body = self.prepare_roles()
        role = "custom-" + uuid.uuid4().hex[:12]
        self.role_path(role).write_bytes(body)
        self.drivers(role, [self.driver])
        _, missing = self.start(role=role, level=4)
        self.refused(missing, "a role from another level must not be borrowed")
        self.assertIn("unknown role at L4", missing.stderr)
        self.assertIn("supervisor", missing.stderr)
        self.role_path(role, level=4).write_bytes(body)
        self.drivers(role, [self.second_driver], level=4)
        self.configure(driver=self.second_driver)
        lane, custom = self.start(role=role, level=4)
        self.assertEqual(custom.returncode, 0, custom.stderr)
        self.finished(lane)
        payload = json.loads(custom.stdout)
        self.assertEqual(payload["role_context"]["level"], 4)
        self.assertEqual(payload["role_context"]["sha256"], sha(body))
        self.assertIn("## Your role: " + role + " (L4)", self.calls()[0]["brief"])
        self.assertIn(body.decode(), self.calls()[0]["brief"])

    def test_wrapper_and_exact_basename(self):
        """Fails if a shell wrapper or a name containing an allowed basename bypasses the list."""
        self.prepare_roles()
        self.configure(shell=True)
        _, wrapped = self.start()
        self.refused(wrapped, "an unlisted shell wrapper must refuse")
        self.assertIn("Instead: use an allowed driver: " + self.driver, wrapped.stderr)
        self.configure(driver=self.driver + "-wrapper")
        _, substring = self.start()
        self.refused(substring, "basenames must compare exactly")

    ENV_HINT = "a bare env is looked through only when plain NAME=VALUE words alone precede the program"

    def env_refused(self, prefixes, message):
        """Each prefix is put before the program the role allows, so only the env shape can refuse it."""
        self.prepare_roles()
        for words in prefixes:
            self.configure(prefix=words)
            _, result = self.start()
            self.refused(result, message + ": " + " ".join(words))
            self.assertIn(self.ENV_HINT, result.stderr, "the refusal must come from the env rule")
            self.assertIn("Instead: use an allowed driver: " + self.driver, result.stderr)

    def test_env_assignments_allowed(self):
        """Fails if a bare env with plain NAME=VALUE words is refused, drops its assignments, or lets an unlisted program through."""
        self.prepare_roles()
        canary = "canary-" + uuid.uuid4().hex[:16]
        plain = "/opt/role-" + uuid.uuid4().hex[:8] + "/a_b.c:d,e+f@g%h=i-j"
        self.configure(driver=self.blocked_driver, prefix=["env", "ROLE_CANARY=" + canary])
        _, blocked = self.start()
        self.refused(blocked, "an unlisted program behind env must refuse")
        self.assertIn("Instead: use an allowed driver: " + self.driver, blocked.stderr)
        self.assertNotIn(self.ENV_HINT, blocked.stderr, "env was looked through; the program is what is refused")
        self.configure(prefix=["env", "ROLE_CANARY=" + canary, "ROLE_PLAIN=" + plain])
        lane, result = self.start()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.finished(lane)
        calls = self.calls()
        self.assertEqual(len(calls), 1, "the program after env must run once")
        self.assertEqual(calls[0]["canary"], canary, "env must hand its assignments to the program the role allows")
        report = self.cli_json("org", "validate", self.org, "--config", "roles-demo", "--format", "json")
        self.assertEqual((report["valid"], report["problems"]), (True, []), "config validation must look through env too")

    def test_env_options_refused(self):
        """Fails if env with any option, or any word starting with a dash, is looked through to its program."""
        options = (["-i"], ["--ignore-environment"], ["-u", "ROLE_UNSET"], ["--unset=ROLE_UNSET"], ["-C", "/"],
                   ["--chdir=/"], ["-S", "ROLE_SPLIT"], ["--split-string=ROLE_SPLIT"], ["--"], ["-"], ["-x"],
                   ["ROLE_ONE=1", "-i"], ["ROLE_ONE=1", "--"])
        self.env_refused([["env", *words] for words in options], "an env option must stay refused")
        self.configure(prefix=["env", "-i"])
        invalid = self.cli("config", "validate", "roles-demo")
        self.assertEqual(invalid.returncode, 2, "config validation must refuse an env option too")
        self.assertIn("no (level, role) permits its driver", invalid.stderr)

    def test_env_value_refused(self):
        """Fails if an env value with a substitution, quote, backslash, brace, whitespace or dollar is looked through."""
        # In a runner template, {{ and }} are literal braces: ${{ROLE_PROBE}} loads, and the env rule refuses it.
        values = ("$(ROLE_PROBE)", "`ROLE_PROBE`", "${{ROLE_PROBE}}", "$ROLE_PROBE", "$'ROLE_PROBE'", "'ROLE_PROBE'",
                  '"ROLE_PROBE"', "ROLE\\PROBE", "{model}", "{session}", "ROLE PROBE", "ROLE;PROBE", "ROLE*PROBE")
        self.env_refused([["env", "ROLE_VALUE=" + value] for value in values], "an env value that is not plain must stay refused")

    def test_env_chain_refused(self):
        """Fails if an env inside env, by name or by path, is looked through."""
        chains = (["env", "ROLE_ONE=1", "env", "ROLE_TWO=2"], ["env", "ROLE_ONE=1", "/usr/bin/env", "ROLE_TWO=2"],
                  ["env", "ROLE_ONE=1", "env"], ["env", "env", "ROLE_ONE=1"])
        self.env_refused(chains, "an env inside env must stay refused")

    def test_env_shape_refused(self):
        """Fails if env without an assignment, named by a path, or with a word that is not NAME=VALUE is looked through."""
        shapes = (["env"], ["/usr/bin/env", "ROLE_ONE=1"], ["env", "ROLE-ONE=1"], ["env", "=1"], ["env", "1ROLE=1"],
                  ["env", "ROLE_ONE=1", "ROLE-TWO=2"])
        self.env_refused(shapes, "an env that is not a bare run of plain assignments must stay refused")

    def test_env_entry_authorizes_env(self):
        """Fails if an explicit env entry stops authorizing env itself, in the plain form that is looked through or not."""
        self.prepare_roles()
        self.drivers("reviewer", ["env"])
        for count, prefix in enumerate((["env", "ROLE_CANARY=" + uuid.uuid4().hex[:16]], ["env", "-i"]), 1):
            self.configure(prefix=prefix)
            lane, result = self.start()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.finished(lane)
            self.assertEqual(len(self.calls()), count, "an explicit env entry must keep authorizing env")

    def test_validate_instance_and_runners(self):
        """Fails if validation misses an instance without a template or a wholly unsupported runner."""
        self.prepare_roles()
        instance = self.org / ".laneboss" / "instances" / "L3-lane-example" / "instance.toml"
        text = instance.read_text()
        instance.write_text(text.replace('role = "executor"', 'role = "missing-role"'))
        bad = self.cli("org", "validate", self.org, "--format", "json")
        self.assertEqual(bad.returncode, 2)
        report = json.loads(bad.stdout)
        self.assertFalse(report["valid"])
        self.assertTrue(any("role has no template" in item["message"] for item in report["problems"]))
        instance.write_text(text)
        self.configure(driver=self.blocked_driver)
        config = self.cli("config", "validate", "roles-demo")
        self.assertEqual(config.returncode, 2)
        self.assertIn("no (level, role) permits its driver", config.stderr)
        org = self.cli("org", "validate", self.org, "--config", "roles-demo", "--format", "json")
        self.assertEqual(org.returncode, 2)
        self.assertTrue(any("no (level, role) permits" in p["message"] for p in json.loads(org.stdout)["problems"]))

    def test_unused_role_warning_counts_lanes(self):
        """Fails if the unused warning ignores real lane usage in the named configuration."""
        self.prepare_roles()
        before = self.cli_json("org", "validate", self.org, "--config", "roles-demo", "--format", "json-diagnostics")
        plain = self.cli_json("org", "validate", self.org, "--config", "roles-demo", "--format", "json")
        self.assertEqual(plain, {"valid": before["valid"], "problems": before["problems"]},
                         "default JSON must retain the two-key validation contract")
        path = ".laneboss/L3/roles/reviewer.md"
        self.assertTrue(any(p["path"] == path for p in before["warnings"]))
        lane, result = self.start()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.finished(lane)
        after = self.cli_json("org", "validate", self.org, "--config", "roles-demo", "--format", "json-diagnostics")
        self.assertFalse(any(p["path"] == path for p in after["warnings"]))

    def test_legacy_org_migration(self):
        """Unsupported legacy aliases must refuse until explicit migration installs their sources."""
        for level in EXPECTED_ROLES:
            directory = self.org / ".laneboss" / ("L" + str(level)) / "roles"
            directory.rename(self.directory / ("old-roles-L" + str(level)))
        legacy = {4: ("L4-stream", "supervisor", "stream-supervisor"),
                  5: ("L5-top", "top-supervisor", "top-supervisor"),
                  6: ("L6-super-top", "supervisor", "org-supervisor")}
        for _, (name, current, previous) in legacy.items():
            instance = self.org / ".laneboss/instances" / name / "instance.toml"
            text = instance.read_text()
            self.assertIn('role = "' + current + '"', text)
            if current != previous:
                instance.write_text(text.replace('role = "' + current + '"', 'role = "' + previous + '"'))
        refused = self.cli("org", "render", self.org)
        self.assertEqual(refused.returncode, 2, "an alias without org or built-in sources must not render")
        self.assertIn("instance role has no template", refused.stderr)
        report = self.cli("org", "validate", self.org, "--format", "json-diagnostics")
        self.assertEqual(report.returncode, 2)
        self.assertFalse(json.loads(report.stdout)["valid"])
        self.cli_json("org", "roles", "init", self.org)
        for level, (name, _, previous) in legacy.items():
            instance = self.org / ".laneboss/instances" / name / "instance.toml"
            self.assertIn('role = "' + previous + '"', instance.read_text())
            self.assertTrue(self.role_path(previous, level=level).is_file())
            self.assertTrue(self.role_path(previous, ".toml", level).is_file())
        migrated = self.cli_json("org", "validate", self.org, "--format", "json")
        self.assertTrue(migrated["valid"])
        self.prepare_roles()
        lane, result = self.start()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.finished(lane)

    def test_role_path_cannot_escape(self):
        """Fails if a lane can select a path or an org role symlink can read outside roles/."""
        self.prepare_roles()
        outside = self.directory / "outside.md"
        body = self.role_path().read_bytes() + b"\nOutside policy canary.\n"
        outside.write_bytes(body)
        _, path = self.start(role="../outside")
        self.refused(path, "a role must not be a supplied path")
        self.assertEqual(path.stderr,
                         "refused: role must be one safe filename without separators or controls\n"
                         "Instead: choose --role from L3 roles: " + ", ".join(sorted(EXPECTED_ROLES[3])) + "\n")
        self.role_path().rename(self.directory / "saved-reviewer.md")
        self.role_path().symlink_to(outside)
        _, linked = self.start()
        self.assertEqual(linked.returncode, 2, "role sources must not follow an outside link")
        self.assertIn("never links", linked.stderr)
        self.assertEqual(self.calls(), [])

    def test_resume_driver_rechecked(self):
        """Fails if resume runs a disallowed driver or loses the recorded role after recovery."""
        self.prepare_roles()
        lane, first = self.start()
        self.assertEqual(first.returncode, 0, first.stderr)
        row = self.finished(lane)
        self.drivers("reviewer", [self.second_driver])
        self.keep_command_listed()
        denied = self.cli("lane", "resume", "--config", "roles-demo", "--lane", lane)
        self.assertEqual(denied.returncode, 2, "resume must recheck the current role driver file")
        self.assertIn("Instead: use an allowed driver: " + self.second_driver, denied.stderr)
        self.assertEqual(len(self.calls()), 1)
        self.configure(resume_driver=self.second_driver)
        follow_up = self.directory / "follow-up.md"
        follow_up.write_text("# Follow-up\n\n" + uuid.uuid4().hex[:16] + "\n")
        resumed = self.cli_json("lane", "resume", "--config", "roles-demo", "--lane", lane, "--message", follow_up)
        self.finished(lane, 2, row["last_seq"])
        self.assertEqual(resumed["role"], "reviewer")
        self.assertEqual(resumed["role_context"]["drivers_sha256"], sha(self.role_path("reviewer", ".toml").read_bytes()))
        self.assertIn("## Your role: reviewer (L3)", self.calls()[1]["brief"])
        self.assertIn(follow_up.read_text(), self.calls()[1]["brief"])

    def test_turn_driver_rechecked(self):
        """Fails if turn skips the role driver gate, loses mail on refusal, or omits the role on recovery."""
        self.prepare_roles()
        self.configure(stdin=True)
        lane, first = self.start(turns=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        row = self.finished(lane)
        message = self.directory / "mail.md"
        message.write_text("# Mail\n\n" + uuid.uuid4().hex[:16] + "\n")
        # The launcher records the sender it authenticated, the session identify recorded; --from must equal that
        # principal, so a made-up sender name is refused and the row no longer gives one.
        self.cli_json("lane", "send", "--config", "roles-demo", "--lane", lane, "--file", message)
        self.drivers("reviewer", [self.second_driver])
        self.keep_command_listed()
        denied = self.cli("lane", "turn", "--config", "roles-demo", "--lane", lane)
        self.assertEqual(denied.returncode, 2, "turn must recheck the current role driver file")
        self.assertIn("Instead: use an allowed driver: " + self.second_driver, denied.stderr)
        waiting = self.cli_json("lane", "status", "--config", "roles-demo", "--lane", lane)
        self.assertEqual(len(waiting["mail"]["waiting"]), 1)
        self.assertEqual(len(self.calls()), 1)
        self.configure(resume_driver=self.second_driver, stdin=True)
        turn = self.cli_json("lane", "turn", "--config", "roles-demo", "--lane", lane)
        self.finished(lane, 2, row["last_seq"])
        self.assertTrue(turn["started"])
        self.assertEqual(turn["role"], "reviewer")
        self.assertIn("## Your role: reviewer (L3)", self.calls()[1]["brief"])
        self.assertIn(message.read_text(), self.calls()[1]["brief"])

    def loop_event(self, lane, kind, since):
        """Read state without restoring the supervisor removed by the replay."""
        deadline = time.monotonic() + 45
        while True:
            events = self.loop_lane_events(lane)
            matches = [event for event in events if event["seq"] > since and event["kind"] == kind]
            if matches:
                self.assertEqual(len(matches), 1, "the requested new loop event must be observed once")
                return matches[0]
            if time.monotonic() >= deadline:
                output = json.dumps(events, indent=2)
                (self.directory / "loop-timeout.json").write_text(output)
                self.fail("no " + kind + "; retained loop events, with refusal details:\n" + output)
            time.sleep(0.3)

    def loop_lane_events(self, lane):
        return [event for event in self.cli_json("state", "events", "--config", "roles-demo")
                if event["lane"] == lane]

    def loop_configuration(self):
        self.configure(stdin=True)
        path = self.config_dir / "config.toml"
        text = path.read_text() + "\n[turns]\npoll_seconds = 1\nbackoff_seconds = 15\n"
        path.write_text(text)
        return path, text

    def test_loop_org_after_runner_edit(self):
        """Replay a failed turn, missing resume, and repair after an org-less rewrite."""
        self.prepare_roles()
        path, original = self.loop_configuration()
        mode = self.directory / "runner-mode.txt"
        mode.write_text("ok")
        (self.bin_dir / self.driver).write_text(
            VENDOR + "\nsys.exit(1 if Path(" + json.dumps(str(mode)) + ").read_text() == 'fail' else 0)\n")
        lane, first = self.start(turns=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        recorded = json.loads(first.stdout)["role_context"]
        row = self.finished(lane)
        mode.write_text("fail")
        canary = uuid.uuid4().hex[:16]
        # Service mode uses a persistent headless controller created before this
        # point. Deliver this launch-time input explicitly to that request too.
        loop = self.cli_json("lane", "loop", "--config", "roles-demo", "--detach",
                             extra_env={"ROLE_CANARY": canary})
        try:
            message = self.directory / "loop-mail.md"
            message.write_text("# Retried mail\n\n" + uuid.uuid4().hex[:16] + "\n")
            self.cli_json("lane", "send", "--config", "roles-demo", "--lane", lane, "--file", message)
            turn = self.loop_event(lane, "loop.turn", row["last_seq"])
            self.assertEqual((turn["payload"]["loop"], turn["payload"]["run"]), (loop["loop"], 2))
            waiting = self.loop_event(lane, "loop.skipped", turn["seq"])
            self.assertEqual((waiting["payload"]["reason"], waiting["payload"]["after"]),
                             ("backoff", {"run": 2, "reason": "exit"}))
            ended = self.cli("event", "tail", "--config", "roles-demo", "--lane", lane)
            self.assertEqual(ended.returncode, 0, ended.stderr)
            failed = [json.loads(line) for line in ended.stdout.splitlines()
                      if json.loads(line)["kind"] == "lane.ended"][-1]["payload"]
            self.assertEqual((failed["run"], failed["exit_code"], failed["survivors"]), (2, 1, 0))
            self.assertEqual(len(self.calls()), 2)
            self.assertIsNone(self.calls()[-1]["canary"],
                              "the loop must withhold the canary before env_allow is installed")

            # Like the private replay's direct writer, omit the org while the
            # already-running loop reloads the runner on each pass.
            org_line = "org_dir = " + json.dumps(str(self.org)) + "\n"
            self.assertIn(org_line, original)
            without_org = original.replace(org_line, "", 1)
            supervisor = '[supervisors.' + SUPERVISOR + ']\nlevel = 5\nrunner = "agent"\n'
            self.assertIn(supervisor, without_org)
            without_org = without_org.replace(supervisor, "", 1)
            self.assertNotIn("org_dir", tomllib.loads(without_org))
            self.assertNotIn("supervisors", tomllib.loads(without_org))
            broken = "".join(line for line in without_org.splitlines(keepends=True)
                             if not line.startswith("resume = "))
            self.assertNotIn("resume", tomllib.loads(broken)["runners"]["agent"])
            path.write_text(broken)
            (self.directory / "rewritten-without-resume.toml").write_text(broken)
            skip = self.loop_event(lane, "loop.skipped", waiting["seq"])
            self.assertEqual((skip["payload"]["reason"], skip["payload"]["after"]), ("refused", None))
            self.assertIn("resume template", skip["payload"]["detail"])
            self.assertEqual(len(self.calls()), 2, "a refused turn must not reach the vendor")

            # Repair only the runner. Fresh org settings and role bytes must
            # still be enforced, rather than falling back to an old snapshot.
            mode.write_text("ok")
            body = self.role_path().read_bytes() + ("\nRecovery role " + uuid.uuid4().hex[:16] + ".\n").encode()
            self.role_path().write_bytes(body)
            (self.org / ".laneboss/settings.toml").write_text('effort = "high"\nenv_allow = ["ROLE_CANARY"]\n')
            path.write_text(without_org)
            (self.directory / "repaired-without-org.toml").write_text(without_org)
            recovered = self.loop_event(lane, "loop.turn", skip["seq"])
            self.assertEqual((recovered["payload"]["run"], recovered["payload"]["sequences"]), (3, [1]))
            final = self.wait_quiescent(lane, 3)
            self.assertEqual((final["mail"]["waiting"], final["mail"]["delivered"]), ([], 1))
            decoded = self.loop_lane_events(lane)
            latest = [event["payload"] for event in decoded if event["kind"] == "lane.started"][-1]
            self.assertEqual([event["actor"] for event in decoded if event["kind"] == "lane.started"][-1],
                             "supervisor:" + SUPERVISOR)
            self.assertEqual(latest["role_context"]["org_dir"], recorded["org_dir"])
            self.assertEqual(latest["role_context"]["sha256"], sha(body))
            self.assertEqual(latest["effort"], "high")
            self.assertEqual(len(self.calls()), 3)
            self.assertEqual(self.calls()[-1]["canary"], canary)
            self.assertIn(body.decode(), self.calls()[-1]["brief"])
            self.assertEqual(self.calls()[-1]["brief"].count(message.read_text()), 1)
            self.assertEqual([event["kind"] for event in decoded if event["kind"].startswith("loop.")],
                             ["loop.turn", "loop.skipped", "loop.skipped", "loop.turn"])
            self.assertEqual(path.read_text(), without_org, "the turn must not rewrite the configuration")
        finally:
            stopped = self.cli_json("lane", "loop", "--config", "roles-demo", "--stop")
            self.assertIs(stopped["stopped"], True)

    def test_loop_other_org_refused(self):
        """A different valid org cannot replace the launcher's recorded org."""
        self.prepare_roles()
        path, original = self.loop_configuration()
        lane, first = self.start(turns=True)
        self.assertEqual(first.returncode, 0, first.stderr)
        row = self.finished(lane)
        message = self.directory / "other-org-mail.md"
        message.write_text("# Keep this mail queued\n\n" + uuid.uuid4().hex[:16] + "\n")
        self.cli_json("lane", "send", "--config", "roles-demo", "--lane", lane, "--file", message)
        other = self.directory / "other-org"
        self.cli_json("org", "init", other, "--name", "other-demo")
        self.cli_json("org", "roles", "init", other)
        for suffix in (".md", ".toml"):
            (other / ".laneboss/L3/roles" / ("reviewer" + suffix)).write_bytes(self.role_path(extension=suffix).read_bytes())
        changed = original.replace("org_dir = " + json.dumps(str(self.org)), "org_dir = " + json.dumps(str(other)), 1)
        supervisor = '[supervisors.' + SUPERVISOR + ']\nlevel = 5\nrunner = "agent"\n'
        self.assertIn(supervisor, changed)
        changed = changed.replace(supervisor, "", 1)
        self.assertNotIn("supervisors", tomllib.loads(changed))
        self.assertNotEqual(changed, original)
        path.write_text(changed)
        self.cli_json("lane", "loop", "--config", "roles-demo", "--detach")
        try:
            skip = self.loop_event(lane, "loop.skipped", row["last_seq"])
            self.assertEqual(skip["payload"]["reason"], "refused")
            self.assertIn("the lane's recorded org differs from the configuration", skip["payload"]["detail"])
            status = self.cli_json("lane", "status", "--config", "roles-demo", "--lane", lane)
            self.assertEqual((status["run"], status["mail"]["waiting"]), (1, [1]))
            self.assertEqual(len(self.calls()), 1, "another org must never reach the vendor")
            self.assertEqual(path.read_text(), changed)
        finally:
            stopped = self.cli_json("lane", "loop", "--config", "roles-demo", "--stop")
            self.assertIs(stopped["stopped"], True)

    def test_adoption_requires_and_records_role(self):
        """Fails if adoption accepts a supervisor without a template or records invented role bytes."""
        body = self.prepare_roles()
        self.configure(stdin=True, session_records=True)
        session = str(uuid.uuid4())
        work = self.directory / "adopt-work"
        work.mkdir()
        record = self.records / (session + ".jsonl")
        when = time.time() - 10
        record.write_text(json.dumps({
            "type": "user", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(when)),
            "sessionId": session, "cwd": str(work), "message": {"role": "user", "content": self.task},
        }) + "\n")
        os.utime(record, (when, when))
        lane = "role-adopt-" + uuid.uuid4().hex[:12]
        args = ["lane", "adopt", "--config", "roles-demo", "--lane", lane, "--session", session,
                "--runner", "agent", "--model", "example-model-medium-1", "--worktree", work, "--brief", self.brief]
        missing = self.cli(*args)
        self.assertEqual(missing.returncode, 2)
        self.assertIn("a role is required", missing.stderr)
        unknown = self.cli(*args, "--role", "unknown-role")
        self.assertEqual(unknown.returncode, 2)
        self.assertIn("unknown role", unknown.stderr)
        adopted = self.cli_json(*args, "--role", "reviewer")
        self.lanes.append(lane)
        self.assertEqual(adopted["session_id"], session)
        self.assertEqual(adopted["role"], "reviewer")
        self.assertEqual(adopted["role_context"]["sha256"], sha(body))
        self.assertIn(body.decode(), Path(adopted["brief"]["path"]).read_text())
        self.assertEqual(self.calls(), [], "adoption records an idle session without launching its vendor")


class RoleMutantsTest(unittest.TestCase):
    def test_restored_rows_reject_each_mutant(self):
        """Fails unless all five real faults are reached and ordinary rows catch the intended defect."""
        cases = (
            ("roles-omit-section", "test_rendered_role_and_event", "rendered role heading must be present"),
            ("roles-supervisor-optional", "test_supervisor_without_role", "supervisor starts require a role"),
            ("roles-level-only", "test_role_specific_driver", "role-specific driver mismatch must refuse before exec"),
            ("roles-skip-driver", "test_unlisted_driver", "unlisted driver must refuse before exec"),
            # The env mutant skips any word after env; each refusal class of the look-through is caught.
            ("roles-env-skip-any", "test_env_options_refused", "an env option must stay refused"),
            ("roles-env-skip-any", "test_env_value_refused", "an env value that is not plain must stay refused"),
            ("roles-env-skip-any", "test_env_chain_refused", "an env inside env must stay refused"),
            ("roles-env-skip-any", "test_env_shape_refused", "an env that is not a bare run of plain assignments must stay refused"),
        )
        for point, row, reason in cases:
            with self.subTest(mutant=point, row=row):
                mutant = RolesTest(row)
                mutant.binary_override = FAULTS
                mutant.fault_point = point
                red = unittest.TestResult()
                mutant.run(red)
                self.assertEqual(red.errors, [], "the mutant must fail an assertion, not its fixture")
                self.assertEqual(len(red.failures), 1, "an ordinary row must detect the actual mutant")
                self.assertIn(reason, red.failures[0][1].splitlines()[-1],
                              "the intended assertion must fail, not an earlier helper")
                self.assertTrue(mutant.marker.is_file(), "the real mutation boundary must be reached")
                self.assertEqual(mutant.observed["exit_code"], 0, "the mutant must really allow the bad run")
                self.assertEqual(len(mutant.observed["calls"]), 1, "the mutated lane must actually reach its vendor")
                restored = RolesTest(row)
                green = unittest.TestResult()
                restored.run(green)
                self.assertEqual(green.errors, [])
                self.assertEqual(green.failures, [], "the restored row must pass on the installed release")
                print("RESTORED ROLE MUTANT", point, "caught:", reason)


if __name__ == "__main__":
    unittest.main()
