"""Real CLI ticket rows, requiring the integrated service on a disposable Linux box.

The fixture provisions two invented configurations and a separately owned
service on the authorized box. Some rows start credential-free stand-in lanes;
none launch machines or call a model. Missing integration is a failure.
"""

import base64
import json
import os
from pathlib import Path
import re
import shutil
import sys
import subprocess
import tempfile
import time
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ticket_support import TicketController, terminal_run


FIRST = {
    "human": "refused: only the human at a real terminal may issue a registration ticket",
    "required": "refused: supervisor registration requires a human-issued ticket",
    "unknown": "refused: the registration ticket is unknown",
    "used": "refused: the registration ticket has already been used",
    "level": "refused: the registration ticket is for another level",
    "role": "refused: the registration ticket is for another role",
    "config": "refused: the registration ticket is for another configuration",
    "expired": "refused: the registration ticket has expired",
    "scope": "refused: the registration ticket scope is invalid",
    "session": "refused: the supervisor needs a dedicated parent session",
}
NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,31}\Z")
TOKEN = re.compile(r"lbt[12]\.[a-z0-9][a-z0-9-]{0,31}\.(?:[3-6]\.)?[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\.[A-Za-z0-9_-]{43}\Z")


class TicketRows(unittest.TestCase):
    def setUp(self):
        self.assertEqual(sys.platform, "linux", "runtime rows require the disposable Linux box")
        self.assertEqual(os.geteuid(), 0, "ticket rows use the root-owned cross-account fixture")
        self.ticket_rows_explicit = True
        binary = os.environ.get("LANEBOSS_BIN", "")
        self.binary = Path(binary)
        self.assertTrue(binary and self.binary.is_absolute() and self.binary.is_file()
                        and os.access(self.binary, os.X_OK), "an already built real binary is required")
        temporary = tempfile.TemporaryDirectory(prefix="lb-svc-ticket-rows-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.home = self.directory / "config"
        self.states = self.directory / "state"
        self.config, self.other_config = "ticket-example", "ticket-other"
        self.role, self.other_role = "top", "mini"
        self.level = 5
        self.base_environment = {
            "PATH": os.environ.get("PATH", os.defpath), "HOME": str(self.directory),
            "LANEBOSS_HOME": str(self.home), "LANEBOSS_STATE_HOME": str(self.states),
            "LANEBOSS_TEST_CLAIMS_DIR": str(self.directory / "claims"),
        }
        from orgsupport import init_org
        for name in (self.config, self.other_config):
            directory = self.home / "configs" / name
            directory.mkdir(parents=True)
            command = [sys.executable, "-I", str(Path(__file__).with_name("ticket_support.py")),
                       "--runner", "{session}"]
            text = ('schema_version = 1\nname = ' + json.dumps(name) +
                    '\norganisation = "ticket-org"\n[lanes]\nbudget_minutes = 1\nstop_grace_seconds = 1\n'
                    '[runners.demo]\ncommand = ' + json.dumps(command) +
                    '\nresume = ' + json.dumps(command) + '\nprompt = "stdin"\n'
                    'records = [{format = "claude-code", paths = ["{worktree}/.sessions/{session}.jsonl"]}]\n'
                    '[supervisors.top]\nlevel = 5\nrunner = "demo"\n'
                    '[supervisors.supervisor]\nlevel = 4\nrunner = "demo"\n'
                    '[supervisors.mini]\nlevel = 4\nrunner = "demo"\n')
            (directory / "config.toml").write_text(text)
        init_org(self.binary, self.environment(self.config), self.directory, self.home, "ticket-org")
        from ticket_fixture import fixture_for
        self.fixture = fixture_for(self)
        self.fixture.bind(self.config, self.environment(self.config))
        self.fixture.bind(self.other_config, self.environment(self.other_config))
        self.controller = self.new_controller(self.config)
        self.lanes = []
        self.addCleanup(self.collect_lanes)

    def environment(self, config):
        return {**self.base_environment, "LANEBOSS_CONFIG": config}

    def new_controller(self, config):
        return TicketController(self, self.environment(config))

    def issue_args(self, ttl="10m"):
        return ["ticket", "issue", "--config", self.config,
                *self.fixture.level_args(self.config, self.level), "--role", self.role, "--ttl", ttl]

    def issue(self, ttl="10m", level=None, role=None):
        raw = self.fixture.issue(self.config, level if level is not None else self.level,
                                 role or self.role, ttl)
        self.assertTrue(bool(TOKEN.fullmatch(raw)), "the owner did not receive one canonical ticket")
        return raw

    def ticket_file(self, raw):
        path = self.directory / ("handoff-" + os.urandom(8).hex())
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(raw + "\n")
        return path

    def register(self, raw, role=None, level=None, config=None, controller=None):
        name = config or self.config
        return (controller or self.controller).request(
            ["start", "--config", name,
             *self.fixture.level_args(name, self.level if level is None else level), "--role", role or self.role,
             "--ticket-file", self.ticket_file(raw), "--format", "json"])

    def assert_private(self, result, raw):
        combined = result.get("stdout", "") + result.get("stderr", "") + result.get("output", "")
        self.assertFalse(raw in combined, "registration disclosed its bearer ticket")

    def assert_mutation_marker(self, point, message):
        if os.environ.get("LANEBOSS_TICKET_EXPECT_INERT", "") == "1":
            self.assertFalse(self.fixture.mutation_marker.exists(),
                             "the release build executed a fault selector")
            print("\nRELEASE INERT: " + point, flush=True)
        else:
            self.assertTrue(self.fixture.mutation_marker.is_file(), message)
            print("\nMUTATION REACHED: " + point, flush=True)

    def assert_refused(self, result, reason, raw="", assertion="the exact refusal first line changed"):
        combined = result.get("stdout", "") + result.get("stderr", "") + result.get("output", "")
        self.assertFalse(bool(re.search(TOKEN.pattern.removesuffix(r"\Z"), combined)),
                         "a refusal disclosed a bearer ticket")
        if raw:
            self.assert_private(result, raw)
        self.assertEqual(result["code"], 2,
                         "a registration ticket verified twice" if reason == "used"
                         else "the forbidden ticket operation was admitted")
        text = result.get("stderr", result.get("output", ""))
        self.assertEqual(text.splitlines()[:1], [FIRST[reason]], assertion)
        self.assertTrue(any(line.startswith("Instead: ") for line in text.splitlines()),
                        "the refusal lost its recovery route")
        if reason == "human":
            self.assertIn("laneboss ticket issue --config NAME --level LEVEL --role ROLE", text)
            self.assertIn("real terminal", text)
        elif reason == "scope":
            self.assertIn("--level LEVEL --role ROLE", text)
        elif reason == "session":
            self.assertIn("dedicated persistent agent session", text)
        else:
            self.assertIn("fresh ticket", text)
            self.assertIn("--ticket-file PATH", text)
        self.assertEqual(result.get("stdout", ""), "", "a refused operation emitted a success document")

    def assert_registered(self, result, raw):
        self.assert_private(result, raw)
        self.assertEqual(result["code"], 0, "the valid registration did not succeed")
        document = json.loads(result["stdout"])
        self.assertEqual(document["configuration"]["name"], self.config)
        self.assertEqual(document["role"]["selected"], self.role)
        self.assertEqual(document["role"]["entry"]["level"], self.level)

    def prove_identity(self, controller, role=None, level=None, kind="supervisor"):
        # A briefing alone is insufficient. Part 1's real client verifies the
        # service's kernel peer, and its whoami/status path must resolve this
        # persistent caller from the service-owned registration record.
        principal = kind + ":" + (role or self.role)
        result = controller.request(["service", "status", "--config", self.config])
        self.assertEqual(result["code"], 0, "the real service did not resolve the registered caller")
        response = json.loads(result["stdout"])
        self.assertTrue(response["ok"] and response["identified"])
        self.assertEqual(response["service"]["config"], self.config)
        self.assertEqual(response["principal"]["id"], principal)
        self.assertEqual(response["principal"]["level"], self.level if level is None else level,
                         "GrantedLevel: CLI identity differs from the issued level")

    def assert_unregistered(self, controller=None):
        result = (controller or self.controller).request(["service", "status", "--config", self.config])
        self.assertEqual(result["code"], 0, "identity inspection failed after the refusal")
        response = json.loads(result["stdout"])
        self.assertTrue(response["ok"])
        self.assertFalse(response["identified"], "a refused ticket registered an identity")
        self.assertIsNone(response.get("principal"))
        local = self.states / self.config
        self.assertFalse((local / "sessions").exists())
        self.assertFalse((local / "roles").exists())

    def command(self, arguments, controller=None):
        from ticket_fixture import safe_diagnostic
        result = (controller or self.controller).request(arguments)
        self.assertEqual(result["code"], 0, "the registered supervisor's real " +
                         " ".join(map(str, arguments[:2])) + " command failed: " + safe_diagnostic(result))
        return json.loads(result["stdout"])

    def exercise_lanes(self, suffix):
        from orgsupport import ROLES
        brief = self.directory / (suffix + "-brief.md")
        brief.write_text("Read and retain the actual ticket lane prompt.\n")
        name = "ticket-" + suffix
        worktree = self.directory / name
        worktree.mkdir()
        started = self.command(["lane", "start", "--config", self.config, "--lane", name,
                                "--worktree", worktree, "--brief", brief, "--runner", "demo",
                                "--model", "ticket-model-1", "--role", ROLES[3]])
        self.lanes.append(name)
        self.assertEqual(started["starter"], "supervisor:" + self.role)
        self.wait_ended(name)
        self.assertTrue(list((worktree / ".sessions").glob("*.jsonl")), "the real lane runner did not read its prompt")
        adopted_name = name + "-adopt"
        adopted = self.directory / adopted_name
        source = adopted / ".sessions" / (str(uuid.uuid4()) + ".jsonl")
        source.parent.mkdir(parents=True)
        session = source.stem
        source.write_text(json.dumps({"type": "assistant", "timestamp": "2026-01-01T00:00:00Z",
                                      "cwd": str(adopted), "message": {"content": []}}) + "\n")
        # Adoption checks the filesystem mtime, not the JSON timestamp. This
        # models an existing session whose record has stopped growing.
        quiet_since = time.time() - 3600
        os.utime(source, (quiet_since, quiet_since))
        answer = self.command(["lane", "adopt", "--config", self.config, "--lane", adopted_name,
                               "--session", session, "--runner", "demo", "--model", "ticket-model-1",
                               "--worktree", adopted, "--brief", brief, "--role", ROLES[3]])
        self.lanes.append(adopted_name)
        self.assertEqual(answer["starter"], "supervisor:" + self.role)
        self.assertEqual(answer["level"], 3)
        self.assertEqual(answer["session_id"], session)
        self.prove_identity(self.controller)
        follow_up = self.directory / (suffix + "-adopt-follow-up.md")
        follow_up.write_text("Read the continuation for the adopted session and retain it.\n")
        self.command(["lane", "send", "--config", self.config, "--lane", adopted_name,
                      "--file", follow_up])
        resumed = self.command(["lane", "turn", "--config", self.config, "--lane", adopted_name])
        self.assertTrue(resumed["started"], "the adopted session did not execute its first real turn")
        self.assertEqual(resumed["starter"], answer["starter"])
        self.assertEqual(resumed["settings"]["delegation"]["starter"], answer["starter"],
                         "AdoptDelegation: first turn did not derive limits from the recorded starter")
        self.wait_ended(adopted_name)
        retained = json.loads(source.read_text())
        self.assertIn(follow_up.read_text(), retained["message"]["content"][0]["text"],
                      "the actual adopted runner did not read the continuation")
        local = self.states / self.config
        self.assertFalse((local / "sessions").exists(), "service registration wrote a local session")
        self.assertFalse((local / "roles").exists(), "service registration wrote a local role ticket")

    def wait_ended(self, name):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            status = self.command(["lane", "status", "--config", self.config, "--lane", name])
            if not status["running"] and not status["live"]["session_alive"] and not status["live"]["supervisor"]["alive"]:
                self.assertEqual(status["exit_code"], 0)
                log = self.states / self.config / "lanes" / name / "output.log"
                self.assertIn("ticket-runner: read ", log.read_text(),
                              "the runner left no actual receipt for archive collection")
                return status
            time.sleep(0.1)
        self.fail("the actual ticket lane did not settle")

    def collect_lanes(self):
        for name in self.lanes:
            status = self.command(["lane", "status", "--config", self.config, "--lane", name])
            if status["running"]:
                result = self.controller.request(["lane", "stop", "--config", self.config, "--lane", name])
                if result["code"] != 0:
                    # The runner may finish between status and stop. Only this
                    # exact refusal is recoverable, with fresh kernel/status proof.
                    self.assertEqual(result["code"], 2, result["stderr"])
                    self.assertEqual(result["stderr"].splitlines()[:1],
                                     ["refused: lane " + name + " is not running"], result["stderr"])
                    settled = self.wait_ended(name)
                    self.assertFalse(settled["running"])
                    self.assertFalse(settled["live"]["session_alive"])
                    self.assertFalse(settled["live"]["supervisor"]["alive"])
                    self.assertEqual(settled["live"]["survivors"], 0)
            self.command(["lane", "mark", "--config", self.config, "--lane", name, "--state", "abandoned"])
            self.command(["lane", "clean", "--config", self.config, "--lane", name])

    def test_t1_terminal_and_headless_issue(self):
        raw = self.issue()
        self.assert_refused(self.controller.request(self.issue_args()), "human")
        result = self.register(raw)
        self.assert_registered(result, raw)
        self.prove_identity(self.controller)
        self.exercise_lanes("t1")

    def test_t2_single_use(self):
        raw = self.issue()
        self.assert_registered(self.register(raw), raw)
        self.prove_identity(self.controller)
        self.exercise_lanes("t2")
        result = self.register(raw)
        mutant = os.environ.get("LANEBOSS_TICKET_MUTANT", "")
        if mutant:
            self.assertEqual(mutant, "ticket-reuse", "unsupported ticket mutation")
            self.assert_mutation_marker(mutant, "the daemon's single-use mutant did not reach its marker")
        self.assert_refused(result, "used", raw)

    def test_t3_wrong_role(self):
        raw = self.issue()
        self.assert_refused(self.register(raw, role=self.other_role), "role", raw)
        self.assert_registered(self.register(raw), raw)

    def test_t4_wrong_configuration(self):
        raw = self.issue()
        other = self.new_controller(self.other_config)
        self.assert_refused(self.register(raw, config=self.other_config, controller=other), "config", raw)
        self.assert_registered(self.register(raw), raw)

    def test_t5_expired(self):
        raw = self.issue(ttl="1ns")
        self.assert_refused(self.register(raw), "expired", raw)
        control = self.issue()
        self.assert_registered(self.register(control), control)

    def test_t6_unknown_and_required(self):
        scope = "lbt2." + self.config + "." + str(self.level) if self.fixture.level_supported[self.config] else "lbt1." + self.config
        raw = (scope + "." + self.role + "." +
               base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("="))
        self.assert_refused(self.register(raw), "unknown", raw)
        result = self.controller.request(["start", "--config", self.config, "--role", self.role])
        self.assert_refused(result, "required")
        control = self.issue()
        self.assert_registered(self.register(control), control)

    def test_t7_recorded_principal_with_pty(self):
        raw = self.issue()
        self.assert_registered(self.register(raw), raw)
        self.prove_identity(self.controller)
        result = self.controller.request(self.issue_args(), terminal=True)
        self.assert_refused(result, "human")
        # Only the separately attested human terminal supplies the allowed control.
        self.issue()

    def test_t8_detached_lane_pty(self):
        from orgsupport import ROLES
        raw = self.issue()
        self.assert_registered(self.register(raw), raw)
        attack = self.fixture.directory / "detached-lane"
        attack.mkdir(mode=0o755)
        os.chown(attack, self.fixture.human_uid, self.fixture.gid)
        output = attack / "result.json"
        brief = self.directory / "detached.md"
        plan = {"uid": self.fixture.human_uid, "gid": self.fixture.gid,
                "binary": str(self.fixture.binary), "home": str(self.fixture.directory),
                "policy": str(self.fixture.policy_home(self.config)), "state": str(self.fixture.directory / "owner-state"),
                "config": self.config, "result": str(output)}
        brief.write_text("# Detached lane issuance probe\nticket-detach:" + json.dumps(plan) + "\n")
        worktree = self.directory / "detached-work"
        worktree.mkdir()
        result = self.command(["lane", "start", "--config", self.config, "--lane", "ticket-detached",
                               "--worktree", worktree, "--brief", brief, "--runner", "demo",
                               "--model", "ticket-model-1", "--role", ROLES[3]])
        self.lanes.append("ticket-detached")
        self.assertEqual(result["starter"], "supervisor:" + self.role)
        deadline = time.monotonic() + 60
        while not output.is_file():
            if time.monotonic() >= deadline:
                from ticket_fixture import diagnostic_tail, safe_diagnostic
                log = self.states / self.config / "lanes" / "ticket-detached" / "output.log"
                if log.is_file():
                    tail = diagnostic_tail(log)
                else:
                    tail = "[lane output.log is missing]"
                self.fail("the real detached lane did not complete its PTY probe\n"
                          "lane output.log tail:\n" + safe_diagnostic({"output": tail}) +
                          "\ndaemon stderr tail:\n" +
                          safe_diagnostic({"stderr": self.fixture.daemon_stderr(self.config)}))
            time.sleep(0.05)
        observed = json.loads(output.read_text())
        self.assertTrue(observed["parent_exit"])
        self.assertNotEqual(observed["reparented_to"], observed["parent_pid"])
        if os.environ.get("LANEBOSS_TICKET_MUTANT", "") == "ticket-human-pty":
            self.assert_mutation_marker("ticket-human-pty", "the weak human rule was not reached")
        self.assertFalse(observed["issued"], "a detached lane with a PTY minted a registration ticket")
        self.assertEqual(observed["code"], 2)
        self.assertEqual(observed["first"], FIRST["human"])
        self.assertTrue(observed["instead"])
        self.issue()

    def test_r39_issued_scope(self):
        raw = self.issue(level=4, role="supervisor")
        self.fixture.change_role_level(self.config, "supervisor", 5)
        result = self.register(raw, level=4, role="supervisor")
        self.assert_private(result, raw)
        self.assertEqual(result["code"], 0, "issued L4 supervisor did not register after policy reload")
        self.assertEqual(json.loads(result["stdout"])["role"]["selected"], "supervisor")
        self.prove_identity(self.controller, level=4, role="supervisor")

    def test_r39_wrong_level(self):
        raw = self.issue(level=4, role="supervisor")
        result = self.register(raw, level=5, role="top")
        if os.environ.get("LANEBOSS_TICKET_MUTANT", "") == "ticket-level-unchecked":
            self.assert_mutation_marker("ticket-level-unchecked", "the level comparison mutant was not reached")
        self.assert_refused(result, "level", raw, "WrongLevel: L4 ticket requested as L5 top")
        self.assert_unregistered()
        self.assert_refused(self.register(raw, level=5, role="supervisor"), "level", raw,
                            "WrongLevel: role equality cannot bypass the issued level")
        self.assert_unregistered()
        self.assertEqual(self.register(raw, level=4, role="supervisor")["code"], 0,
                         "WrongLevel burned the issued ticket")
        self.prove_identity(self.controller, level=4, role="supervisor")

    def test_r39_wrong_role(self):
        raw = self.issue(level=4, role="supervisor")
        result = self.register(raw, level=4, role="mini")
        self.assert_refused(result, "role", raw, "WrongRole: L4 ticket requested for another L4 role")
        self.assert_unregistered()
        self.assertIn("--level LEVEL --role ROLE", result["stderr"],
                      "WrongRole recovery must issue the desired level and role")
        self.assertEqual(self.register(raw, level=4, role="supervisor")["code"], 0,
                         "WrongRole burned the issued ticket")
        self.prove_identity(self.controller, level=4, role="supervisor")

    def test_r39_reuse_scopes(self):
        raw = self.issue(level=4, role="supervisor")
        self.assertEqual(self.register(raw, level=4, role="supervisor")["code"], 0)
        self.prove_identity(self.controller, level=4, role="supervisor")
        for level, role in ((4, "supervisor"), (5, "top"), (4, "mini")):
            with self.subTest(level=level, role=role):
                stranger = self.new_controller(self.config)
                self.assert_refused(self.register(raw, level=level, role=role, controller=stranger),
                                    "used", raw, "Used: consumed status must precede requested scope")
                self.assert_unregistered(stranger)
                self.prove_identity(self.controller, level=4, role="supervisor")

    def test_r39_explicit_issue_level(self):
        result = self.fixture.owner_call(self.config, ["ticket", "issue", "--config", self.config,
                                                       "--role", "supervisor"])
        self.assertEqual(result["code"], 2, "IssueLevel: omission of the issued level was admitted")
        self.assertEqual(result["stdout"], "", "an incomplete issue printed a bearer")
        self.assertIn("--level", result["stderr"])
        self.assert_unregistered()
        raw = self.issue(level=4, role="supervisor")
        self.assertEqual(self.register(raw, level=4, role="supervisor")["code"], 0)
        self.prove_identity(self.controller, level=4, role="supervisor")

    def assert_policy_refused(self, result, level, role, current=None, state="removed"):
        self.assertEqual(result["code"], 2, "StalePolicy: authority outlived its policy source")
        now = (self.config + " L" + str(current) + " " + role if current is not None else
               state + " " + self.config + " " + role)
        first = ("refused: the registration policy changed: issued " + self.config +
                 " L" + str(level) + " " + role + "; current " + now)
        self.assertEqual(result["stderr"].splitlines()[:1], [first], "PolicyScope: wrong revocation refusal")
        self.assertIn("Instead: ", result["stderr"])
        self.assertIn("current scope", result["stderr"])
        self.assertIn("--ticket-file PATH", result["stderr"])
        self.assertEqual(result["stdout"], "")

    def test_r39_demoted_refused(self):
        self.instance_path = self.prepare_instance()
        raw = self.issue(level=4, role=self.instance)
        original = self.instance_path.read_text()
        changed = original.replace("level = 4\n", "level = 3\n", 1).replace('role = "supervisor"', 'role = "executor"', 1)
        self.assertNotEqual(changed, original)
        self.instance_path.write_text(changed)
        result = self.register(raw, level=4, role=self.instance)
        self.assert_private(result, raw)
        self.assert_policy_refused(result, 4, self.instance, current=3)
        self.assert_unregistered()
        current = self.issue(level=3, role=self.instance)
        self.assertEqual(self.register(current, level=3, role=self.instance)["code"], 0)
        self.prove_identity(self.controller, level=3, role=self.instance, kind="instance")
        self.instance_path.write_text(original)
        control = self.new_controller(self.config)
        self.assertEqual(self.register(raw, level=4, role=self.instance, controller=control)["code"], 0,
                         "a policy refusal consumed the unexpired ticket")
        self.prove_identity(control, level=4, role=self.instance, kind="instance")

    def test_policy_revokes_live_session(self):
        raw = self.issue(level=4, role="supervisor")
        self.assertEqual(self.register(raw, level=4, role="supervisor")["code"], 0)
        self.prove_identity(self.controller, level=4, role="supervisor")
        self.fixture.remove_role(self.config, "supervisor")
        self.assert_policy_refused(self.controller.request(["service", "status", "--config", self.config]), 4, "supervisor")
        brief = self.directory / "revoked.md"
        brief.write_text("This refused lane must never execute.\n")
        work = self.directory / "revoked-work"
        work.mkdir()
        start = self.controller.request(["lane", "start", "--config", self.config, "--lane", "revoked-start",
            "--worktree", work, "--brief", brief, "--runner", "demo", "--model", "ticket-model-1", "--role", "executor"])
        self.assert_policy_refused(start, 4, "supervisor")
        session = str(uuid.uuid4())
        source = work / ".sessions" / (session + ".jsonl")
        source.parent.mkdir()
        source.write_text(json.dumps({"type": "assistant", "timestamp": "2026-01-01T00:00:00Z", "cwd": str(work), "message": {"content": []}}) + "\n")
        old = time.time() - 3600
        os.utime(source, (old, old))
        adopt = self.controller.request(["lane", "adopt", "--config", self.config, "--lane", "revoked-adopt",
            "--session", session, "--worktree", work, "--brief", brief, "--runner", "demo", "--model", "ticket-model-1", "--role", "executor"])
        self.assert_policy_refused(adopt, 4, "supervisor")
        self.assertFalse((self.states / self.config / "lanes" / "revoked-start").exists())

    def test_policy_demotes_live(self):
        raw = self.issue()
        self.assert_registered(self.register(raw), raw)
        self.fixture.change_role_level(self.config, self.role, 4, restart=False)
        self.assert_policy_refused(self.controller.request(["service", "status", "--config", self.config]), 5, self.role, current=4)
        current = self.issue(level=4)
        result = self.register(current, level=4)
        self.assertEqual(result["code"], 0, "a fresh current-scope ticket could not replace revoked authority")
        self.prove_identity(self.controller, level=4)

    def test_briefing_uses_granted_level(self):
        raw = self.issue(level=4, role="supervisor")
        path = self.home / "configs" / self.config / "config.toml"
        original = path.read_text()
        changed = original.replace("[supervisors.supervisor]\nlevel = 4\n", "[supervisors.supervisor]\nlevel = 5\n", 1)
        self.assertNotEqual(changed, original)
        path.write_text(changed)
        result = self.register(raw, level=4, role="supervisor")
        self.assertEqual(result["code"], 0)
        self.assertEqual(json.loads(result["stdout"])["role"]["entry"]["level"], 4,
                         "BriefingLevel: the client policy replaced the granted level")
        self.prove_identity(self.controller, level=4, role="supervisor")

    def test_plugin_ticket_route(self):
        raw = self.issue(level=4, role="supervisor")
        script = Path(__file__).resolve().parents[1] / "plugins" / "claude-code" / "skills" / "laneboss" / "start.sh"
        path = self.ticket_file(raw)
        plugin_environment = {"PATH": str(self.fixture.directory) + os.pathsep + self.base_environment["PATH"]}
        marker = "laneboss plugin: NOT STARTED\n"
        two_arguments = "laneboss plugin: give at most two arguments, a configuration name and optionally a role.\n"
        plain_names = ("laneboss plugin: a configuration name and a role start with a letter or digit and hold only "
                       "letters, digits, dots, underscores and hyphens.\n")
        for arguments, reason in (
                ([self.config, "supervisor", "4", path], two_arguments),
                ([self.config, "supervisor", path], two_arguments),
                ([""], plain_names), ([self.config, ""], plain_names)):
            result = self.controller.request(arguments, program=str(script), environment=plugin_environment)
            self.assert_private(result, raw)
            self.assertEqual(result["code"], 0, "the plugin transport contract changed")
            self.assertEqual(result["stderr"], "")
            self.assertEqual(result["stdout"], marker + reason,
                             "PluginArguments: extra words or empty names lost the exact two-argument refusal")
            self.assert_unregistered()
        result = self.controller.request([self.config, "supervisor"],
                                         program=str(script), environment=plugin_environment)
        self.assert_private(result, raw)
        self.assertEqual(result["code"], 0, "the plugin transport contract changed")
        self.assertEqual(result["stderr"], "")
        self.assertTrue(result["stdout"].startswith(marker + "laneboss start exited with status 2.\n" + FIRST["required"] + "\n"))
        self.assertIn("Instead: ", result["stdout"])
        self.assertIn("laneboss ticket issue --config NAME --level LEVEL --role ROLE", result["stdout"])
        self.assert_unregistered()
        # A real shell parent remains alive to collect the CLI status. Ticket
        # arguments belong to this separate CLI probe, never to the plugin.
        result = self.controller.request(
            ["-c", '"$@"; exit_code=$?; exit "$exit_code"', "ticket-shell-parent", self.binary,
             "start", "--config", self.config, "--level", "4", "--role", "supervisor", "--ticket-file", path],
            program="/bin/sh")
        self.assert_refused(result, "session", raw)
        self.assertIn("owner's attested terminal", result["stderr"])
        self.assertIn("--ticket-file PATH", result["stderr"])
        self.assertIn("Plugin wrappers and shell-tool parents cannot register in service mode.", result["stderr"])
        self.assert_unregistered()
        self.assertEqual(self.register(raw, level=4, role="supervisor")["code"], 0)
        self.prove_identity(self.controller, level=4, role="supervisor")

    def test_service_actors_separate(self):
        from reportsupport import TerminalController
        self.ticket_rows_explicit = False
        human = TerminalController(self, environment=self.environment(self.config))
        registered = human.request(["start", "--config", self.config, "--role", self.role, "--format", "json"])
        self.assertEqual(registered["code"], 0, "the role actor did not perform real ticket registration")
        owner = human.request(["service", "status", "--config", self.config])
        self.assertEqual(owner["code"], 0)
        owner_identity = json.loads(owner["stdout"])
        self.assertTrue(owner_identity.get("human"), "ActorModel: registering a role replaced the human actor")
        self.assertFalse(owner_identity["identified"])
        role = human.request(["service", "status", "--config", self.config], role=self.role)
        self.assertEqual(role["code"], 0)
        self.assertEqual(json.loads(role["stdout"])["principal"]["id"], "supervisor:" + self.role)

    def prepare_instance(self):
        self.instance = "ticket-supervisor"
        org = self.home / "orgs" / "ticket-org"
        created = subprocess.run([str(self.binary), "org", "instance", "add", str(org), self.instance,
                                  "--level", "4", "--role", "supervisor"],
                                 env=self.environment(self.config), cwd=self.directory,
                                 capture_output=True, text=True, timeout=90)
        self.assertEqual(created.returncode, 0, "the real org instance fixture could not be added")
        self.assertTrue(json.loads(created.stdout)["ok"])
        source = org / ".laneboss" / "instances" / self.instance
        target = self.fixture.trusted_orgs[self.config] / ".laneboss" / "instances" / self.instance
        shutil.copytree(source, target)
        for path in [target, *target.rglob("*")]:
            self.assertFalse(path.is_symlink(), "the instance fixture contains a link")
            path.chmod(0o755 if path.is_dir() else 0o644)
        return target / "instance.toml"

    def make_instance_writable(self):
        path = self.instance_path
        original = path.read_text()
        self.assertEqual(original.count("level = 4\n"), 1, "the instance level source is ambiguous")
        changed = original.replace("level = 4\n", "level = 6\n", 1)
        path.chmod(0o666)
        self.fixture.owner_write(self.config, path, changed)
        return path, original

    def test_s1_issue_untrusted_role(self):
        self.instance_path = self.prepare_instance()
        protected = self.issue(level=4, role=self.instance)
        control = self.new_controller(self.config)
        self.assertEqual(self.register(protected, level=4, role=self.instance, controller=control)["code"], 0)
        self.prove_identity(control, level=4, role=self.instance, kind="instance")
        path, original = self.make_instance_writable()
        result = self.fixture.owner_call(self.config, ["ticket", "issue", "--config", self.config,
            *self.fixture.level_args(self.config, 6), "--role", self.instance])
        # Check the exit before any assertion could print an unwanted bearer.
        self.assertEqual(result["code"], 2, "UntrustedIssue: caller-writable instance policy issued a ticket")
        self.assert_refused(result, "scope")
        self.assert_unregistered()
        path.write_text(original)
        path.chmod(0o644)
        raw = self.issue(level=4, role=self.instance)
        self.assertEqual(self.register(raw, level=4, role=self.instance)["code"], 0)
        self.prove_identity(self.controller, level=4, role=self.instance, kind="instance")

    def test_s2_redeem_untrusted_role(self):
        self.instance_path = self.prepare_instance()
        raw = self.issue(level=4, role=self.instance)
        path, original = self.make_instance_writable()
        result = self.register(raw, level=4, role=self.instance)
        self.assertEqual(result["code"], 2, "UntrustedGrant: caller-writable instance policy authorized registration")
        self.assert_refused(result, "scope", raw)
        self.assert_unregistered()
        path.write_text(original)
        path.chmod(0o644)
        self.assertEqual(self.register(raw, level=4, role=self.instance)["code"], 0,
                         "refusing untrusted policy burned the valid ticket")
        self.prove_identity(self.controller, level=4, role=self.instance, kind="instance")

    def test_s3_parent_not_session_leader(self):
        raw = self.issue(level=4, role="supervisor")
        shared = TicketController(self, self.environment(self.config), dedicated=False)
        self.assertNotEqual(os.getsid(shared.process.pid), shared.process.pid,
                            "the non-leader fixture unexpectedly owns an OS session")
        result = self.register(raw, level=4, role="supervisor", controller=shared)
        self.assertEqual(result["code"], 2, "DedicatedParent: a non-leader parent authorized registration")
        self.assert_refused(result, "session", raw)
        self.assert_unregistered(shared)
        self.assertEqual(self.register(raw, level=4, role="supervisor")["code"], 0,
                         "refusing a shared parent burned the valid ticket")
        self.prove_identity(self.controller, level=4, role="supervisor")


class NoServiceTicketRows(unittest.TestCase):
    def test_t0_legacy_open(self):
        self.ticket_rows_explicit = True
        self.binary = Path(os.environ["LANEBOSS_BIN"])
        temporary = tempfile.TemporaryDirectory(prefix="lb-svc-ticket-legacy-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        name = "legacy-" + uuid.uuid4().hex[:12]
        home = self.directory / "config"
        config = home / "configs" / name
        config.mkdir(parents=True)
        (config / "config.toml").write_text(
            'schema_version = 1\nname = ' + json.dumps(name) +
            '\n[runners.demo]\ncommand = ["echo", "{brief}"]\n'
            '[supervisors.top]\nlevel = 5\nrunner = "demo"\n')
        self.environment = {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(self.directory),
                            "LANEBOSS_HOME": str(home), "LANEBOSS_STATE_HOME": str(self.directory / "state"),
                            "LANEBOSS_CONFIG": name}
        controller = TicketController(self, self.environment)
        notice = "notice: no identity service is configured; R25 is not enforced (legacy open registration)."
        for format_name in ("text", "json"):
            refused = controller.request(["start", "--config", name, "--role", "not-defined", "--format", format_name])
            self.assertEqual(refused["code"], 2)
            self.assertEqual(refused["stdout"], "")
            self.assertEqual(refused["stderr"].splitlines(),
                             ["refused: role not-defined is not defined; the defined roles are: top"],
                             "LegacyNotice: a refused briefing lost its exact first line")
            self.assertNotIn(notice, refused["stderr"])
            self.assertFalse((self.directory / "state" / name).exists(),
                             "a refused briefing created registration state")
        answer = controller.request(["start", "--config", name, "--role", "top", "--format", "json"])
        self.assertEqual(answer["code"], 0, "no-service ordinary registration was refused")
        self.assertEqual(json.loads(answer["stdout"])["role"]["selected"], "top")
        self.assertEqual(answer["stderr"].splitlines(), [notice])
        record = self.directory / "state" / name / "sessions" / (str(controller.process.pid) + ".json")
        self.assertEqual(json.loads(record.read_text())["principal"], "supervisor:top")


class BindingTicketRows(unittest.TestCase):
    def setUp(self):
        self.assertEqual(sys.platform, "linux")
        self.assertEqual(os.geteuid(), 0)
        self.ticket_rows_explicit = True
        self.binary = Path(os.environ["LANEBOSS_BIN"])
        temporary = tempfile.TemporaryDirectory(prefix="lb-svc-ticket-binding-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.name = "volatile-" + uuid.uuid4().hex[:12]
        home = self.directory / "config"
        config = home / "configs" / self.name
        config.mkdir(parents=True)
        self.config_file = config / "config.toml"
        self.config_file.write_text('schema_version = 1\nname = ' + json.dumps(self.name) +
            '\n[runners.demo]\ncommand = ["echo", "{brief}"]\n'
            '[supervisors.top]\nlevel = 5\nrunner = "demo"\n')
        self.environment = {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(self.directory),
            "LANEBOSS_HOME": str(home), "LANEBOSS_STATE_HOME": str(self.directory / "state"),
            "LANEBOSS_CONFIG": self.name}
        from ticket_fixture import fixture_for
        self.fixture = fixture_for(self)
        marker_root = Path("/etc/laneboss/identity")
        marker_root.mkdir(parents=True, exist_ok=True, mode=0o755)
        self.marker = marker_root / self.name
        descriptor = os.open(self.marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        os.close(descriptor)
        self.marker.chmod(0o644)
        runtime = Path("/var/run/laneboss")
        runtime.mkdir(parents=True, exist_ok=True, mode=0o755)
        self.binding = runtime / self.name
        self.binding.mkdir(mode=0o750)
        os.chown(self.binding, self.fixture.service_uid, self.fixture.gid)
        self.fixture.runtime = runtime
        # This callback runs after the actual service/owner collection.
        self._cleanups.insert(0, (self.remove_system_paths, (), {}))
        self.fixture.bind(self.name, self.environment)
        text, separator, _ = self.config_file.read_text().partition("\n[identity_service]\n")
        self.assertTrue(separator, "the fixture did not configure its service")
        self.config_file.write_text(text + "\n")
        self.controller = TicketController(self, self.environment)
        raw = self.fixture.issue(self.name, 5, "top")
        path = self.directory / "handoff"
        path.write_text(raw + "\n")
        path.chmod(0o600)
        control = self.controller.request(["start", "--config", self.name, "--level", "5", "--role", "top", "--ticket-file", path])
        self.assertEqual(control["code"], 0, "the binding-only registration control did not succeed")

    def remove_system_paths(self):
        if self.binding.exists():
            shutil.rmtree(self.binding)
        self.marker.unlink()

    def assert_binding_refused(self):
        result = self.controller.request(["start", "--config", self.name, "--role", "top"])
        self.assertEqual(result["code"], 2, "VolatileBinding: service loss enabled legacy registration")
        self.assertEqual(result["stderr"].splitlines()[:1],
            ["refused: the configured identity service binding is unavailable"],
            "BindingRefusal: the missing/unreadable binding lost its exact refusal")
        self.assertIn("Instead: ", result["stderr"])
        self.assertNotIn("legacy open registration).", result["stderr"])
        self.assertEqual(result["stdout"], "")
        state = self.directory / "state" / self.name
        self.assertFalse((state / "sessions").exists())
        self.assertFalse((state / "roles").exists())

    def test_binding_survives_stop(self):
        import signal
        daemon = self.fixture.services[self.name]
        os.kill(daemon.pid, signal.SIGTERM)
        daemon.communicate(timeout=20)
        self.assertEqual(daemon.returncode, 0)
        shutil.rmtree(self.binding)
        self.assertTrue(self.marker.is_file(), "the persistent selection vanished with runtime data")
        self.assert_binding_refused()

    def test_binding_unreadable(self):
        self.binding.chmod(0o000)
        try:
            self.assert_binding_refused()
        finally:
            self.binding.chmod(0o750)


if __name__ == "__main__":
    unittest.main(verbosity=2)
