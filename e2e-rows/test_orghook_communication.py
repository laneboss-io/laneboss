"""Communication rows through the rendered org hook and an already built CLI.

Run only on the authorized disposable Linux test machine. LANEBOSS_BIN names
the supplied executable; LANEBOSS_ROW_EVIDENCE names an absolute evidence
directory. Each L3 stand-in submits the actual Bash/exec_command event to its
rendered hook. Only an allow permits that same shell command to execute. The
fixture uses private, empty homes and contacts no AI or owner service.
"""

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from reportsupport import request_environment, run_request
from test_report_messages import ReportMessages
from orgsupport import assert_hook_deprecation, set_hook_mode
from hookfixtures import install_hook_refusals


SYNTAX = Path(__file__).resolve().parents[1] / "internal" / "cli" / "syntax.json"
PROTECTED_FILES = ("[blacklist:laneboss-files] Refuses: Writes to Laneboss's own hook settings, "
                   "registry, org configuration, refusal catalog, records or state.")


def syntax_nodes(node, prefix=()):
    for child in node.get("commands", []):
        path = prefix + (child["name"],)
        yield path, child
        yield from syntax_nodes(child, path)


def hooked_request(request, binary, environment, cwd):
    if "hook_command" not in request:
        return run_request(request, binary, environment, cwd)
    selected = request_environment(request, environment)
    tool_input = {request["field"]: request["command"]}
    tool_input.update(request.get("tool_options", {}))
    event = {
        "hook_event_name": "PreToolUse", "cwd": str(cwd),
        "tool_name": request["tool"],
        "tool_input": tool_input,
    }
    hook = subprocess.run(
        request["hook_command"], cwd=cwd, env=selected,
        input=json.dumps(event), capture_output=True, text=True,
        encoding="utf-8", timeout=30,
    )
    response = {
        "hook": {"code": hook.returncode, "stdout": hook.stdout, "stderr": hook.stderr},
        "event": event, "execution": None,
    }
    if hook.returncode == 0:
        output = json.loads(hook.stdout)["hookSpecificOutput"]
        if output["permissionDecision"] == "allow" and request.get("execute", True):
            executed = subprocess.run(
                ["/bin/bash", "-c", request["command"]], cwd=cwd, env=selected,
                input=request.get("stdin", ""), capture_output=True, text=True,
                encoding="utf-8", timeout=30,
            )
            response["execution"] = {
                "code": executed.returncode, "stdout": executed.stdout, "stderr": executed.stderr,
            }
    return response


def runner_main(binary, worktree, session):
    directory = Path(worktree)
    sys.stdin.buffer.read()
    print(json.dumps({"type": "system", "subtype": "init", "session_id": session}), flush=True)
    (directory / "ready.json").write_text(json.dumps({"pid": os.getpid()}), encoding="utf-8")
    completed = set()
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        for path in sorted(directory.glob("request-*.json")):
            if path.name in completed:
                continue
            request = json.loads(path.read_text(encoding="utf-8"))
            response = hooked_request(request, binary, os.environ, directory)
            destination = directory / path.name.replace("request-", "response-")
            temporary = destination.with_suffix(".tmp")
            temporary.write_text(json.dumps(response), encoding="utf-8")
            temporary.replace(destination)
            completed.add(path.name)
        time.sleep(0.02)
    raise RuntimeError("hooked stand-in exceeded its bounded fixture lifetime")


class OrgHookCommunicationRows(ReportMessages):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        supplied = os.environ.get("LANEBOSS_ROW_EVIDENCE", "")
        cls.evidence_root = Path(supplied)
        if not supplied or not cls.evidence_root.is_absolute():
            raise RuntimeError("LANEBOSS_ROW_EVIDENCE must name an absolute evidence directory")
        cls.evidence_root.mkdir(parents=True, exist_ok=True)

    def write_config(self, file_channel=False):
        super().write_config(file_channel=file_channel)
        path = self.config_dir / "config.toml"
        before = json.dumps(str(Path(__file__).with_name("test_report_messages.py").resolve()))
        after = json.dumps(str(Path(__file__).resolve()))
        text = path.read_text(encoding="utf-8")
        self.assertEqual(text.count(before), 2, "both runner templates must use the hooked stand-in")
        path.write_text(text.replace(before, after), encoding="utf-8")

    def setUp(self):
        self.syntax = json.loads(SYNTAX.read_text(encoding="utf-8"))
        if self._testMethodName == "test_ask_hook":
            self.require_ask_syntax()
        super().setUp()
        self.evidence = self.evidence_root / (self._testMethodName + "-" + uuid.uuid4().hex)
        self.evidence.mkdir()
        # Preserve exact inputs and outputs before the inherited cleanup removes
        # the isolated home. Product lane stop/mark/clean still collect claims.
        self.addCleanup(self.retain_evidence)
        fixture_bin = self.directory / "bin"
        fixture_bin.mkdir()
        (fixture_bin / "laneboss").symlink_to(self.binary)
        self.environment["PATH"] = str(fixture_bin) + os.pathsep + self.environment["PATH"]
        self.org = self.home / "orgs" / self.organisation
        org_home = self.org / ".laneboss"
        # Individual scope/secret rows install their own rules below; their
        # matching refusal catalog is fixture policy too.
        install_hook_refusals(self, self.org, "shared", "declared-writes", "secret-files")
        self.instance = org_home / "instances" / "L3-lane-example" / "instance.toml"
        # Editable policy sources deliberately permit ordinary tool use. The
        # independent argv adapter and lane boundary must make each decision.
        for layer in [org_home / "shared", *sorted(org_home.glob("L[3-6]"))]:
            self.write_rule_source(layer / "hooks" / "rules.toml", "schema_version = 1\nrules = []\n")
        rendered = self.cli("org", "render", self.org)
        self.assert_code(rendered, 0, "render the isolated hook policy sources")
        self.assertTrue(json.loads(rendered["stdout"])["ok"])
        validated = self.cli("org", "validate", self.org, "--format", "json")
        self.assert_code(validated, 0, "validate the rendered hook policy")
        self.assertEqual((json.loads(validated["stdout"])["valid"],
                          json.loads(validated["stdout"])["problems"]), (True, []))
        self.hooks = self.rendered_hooks(self.instance)
        self.sender = "sender-" + uuid.uuid4().hex[:12]
        self.recipient = "peer-" + uuid.uuid4().hex[:12]
        self.start_lane(self.sender, "mini-a")
        self.start_lane(self.recipient, "mini-a")

    def rendered_hooks(self, instance):
        hooks = {}
        for runner, home, settings in (("claude", ".claude", "settings.json"),
                                       ("codex", ".codex", "hooks.json")):
            data = json.loads((instance.parent / home / settings).read_text(encoding="utf-8"))
            commands = [entry["command"] for row in data["hooks"]["PreToolUse"]
                        for entry in row["hooks"] if entry["type"] == "command"]
            self.assertEqual(len(commands), 1, "each provider must have one installed org hook")
            words = shlex.split(commands[0])
            self.assertEqual(Path(words[0]).resolve(), self.binary.resolve(),
                             "the generated hook must invoke the supplied build")
            self.assertEqual(words[1:], ["org", "hook", "--runner", runner,
                                        "--instance", str(instance)])
            hooks[runner] = words
        return hooks

    def retain_evidence(self):
        shutil.copytree(self.directory, self.evidence / "fixture", symlinks=True)
        shutil.copyfile(self.binary, self.evidence / "tested-laneboss")
        sources = self.evidence / "row-sources"
        sources.mkdir()
        for name in (Path(__file__).name, "reportsupport.py", "orgsupport.py", "hookfixtures.py", "test_report_messages.py"):
            shutil.copyfile(Path(__file__).with_name(name), sources / name)
        shutil.copyfile(SYNTAX, sources / "syntax.json")
        manifest = {
            "row": self.id(), "binary_sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
            "scope": "rendered org hook and actual shell command from recorded lane runner descendants",
            "authenticated_ai_service_test": False,
        }
        (self.evidence / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    def require_ask_syntax(self):
        node = dict(syntax_nodes(self.syntax))[("lane", "send")]
        self.assertTrue(any(argument["name"] == "--ask" and argument.get("flag")
                            for argument in node["args"]),
                        "ASK SYNTAX MISSING: lane send in internal/cli/syntax.json has no --ask flag; "
                        "the decision-guide integration is required")

    def inspect_hook(self, runner, command, execute=False, lane=None, hooks=None, **options):
        tool, field = ("Bash", "command") if runner == "claude" else ("exec_command", "cmd")
        result = self.lane_request(
            self.sender if lane is None else lane, [],
            hook_command=(self.hooks if hooks is None else hooks)[runner], tool=tool, field=field,
            command=command, execute=execute, **options,
        )
        self.assert_code(result["hook"], 0, "invoke the exact rendered hook command")
        hook = json.loads(result["hook"]["stdout"])["hookSpecificOutput"]
        self.assertEqual(hook["hookEventName"], "PreToolUse")
        return hook, result

    def run_hooked(self, runner, args, command=None, **options):
        if command is None:
            command = "laneboss " + shlex.join(list(map(str, args)))
        hook, result = self.inspect_hook(runner, command, execute=True, **options)
        self.assertEqual(hook["permissionDecision"], "allow",
                         "communication command must pass the org hook: " + hook["permissionDecisionReason"])
        self.assertIsNotNone(result["execution"], "an allowed command must actually run")
        self.assert_code(result["execution"], 0, "execute the same shell command after the hook allows it")
        return result["execution"]

    def message_file(self, heading):
        path = self.worktrees[self.sender] / ("message-" + uuid.uuid4().hex[:12] + ".md")
        data = (heading + " " + uuid.uuid4().hex + "\n").encode("utf-8")
        path.write_bytes(data)
        return path, data

    def select_hook_mode(self, mode):
        set_hook_mode(self, self.org / ".laneboss" / "org.toml", mode)
        rendered = self.cli("org", "render", self.org)
        self.assert_code(rendered, 0, "render the explicitly selected hook mode")
        self.assertTrue(json.loads(rendered["stdout"])["ok"])
        if mode == "strict":
            assert_hook_deprecation(self, rendered)

    def test_report_hook(self):
        for runner in ("claude", "codex"):
            with self.subTest(runner=runner):
                path, data = self.message_file("report canary")
                result = self.run_hooked(runner, ["report", "--config", "rows", "--file", path])
                outcomes = {row["channel"]: row for row in map(json.loads, result["stdout"].splitlines())}
                self.assertEqual(outcomes["dashboard"]["status"], "delivered")
                sent = [event for event in self.events() if event["kind"] == "report.sent"
                        and event["payload"]["report_id"] == outcomes["dashboard"]["report_id"]]
                self.assertEqual(len(sent), 1, "one actual report must be recorded")
                self.assertEqual((sent[0]["actor"], sent[0]["payload"]["from"],
                                  sent[0]["payload"]["to"], sent[0]["payload"]["text"]),
                                 ("lane:" + self.sender, "lane:" + self.sender,
                                  "supervisor:mini-a", data.decode("utf-8")))

    def check_send(self, ask=False):
        for runner in ("claude", "codex"):
            with self.subTest(runner=runner, ask=ask):
                path, data = self.message_file("question canary" if ask else "peer canary")
                args = ["lane", "send", "--config", "rows", "--lane", self.recipient, "--file", path]
                if ask:
                    args.append("--ask")
                result = self.run_hooked(runner, args)
                receipt = json.loads(result["stdout"])
                events = [event for event in self.lane_events(self.recipient, "lane.mailed")
                          if event["payload"]["sha256"] == hashlib.sha256(data).hexdigest()]
                self.assertEqual(len(events), 1, "one actual peer message must be recorded")
                self.assertEqual((events[0]["actor"], events[0]["payload"]["sender"]),
                                 ("lane:" + self.sender, "lane:" + self.sender))
                self.assertEqual(Path(receipt["file"]).read_bytes(), data)

    def test_send_hook(self):
        self.check_send()

    def test_supervisor_delegation_hook(self):
        """A real hooked L4 starts L3; an L3 clean still fails at CLI authority."""
        # Syntax annotations describe effects; they never grant tool permission.
        # The real child start and the independent CLI authority are both checked.
        instance_name = "delegate-" + uuid.uuid4().hex[:12]
        added = self.cli("org", "instance", "add", self.org, instance_name,
                         "--level", "4", "--role", "supervisor")
        self.assert_code(added, 0, "add the fixture's L4 hook instance")
        self.assertTrue(json.loads(added["stdout"])["ok"])
        rendered = self.cli("org", "render", self.org)
        self.assert_code(rendered, 0, "render the L4 provider hooks from source")
        self.assertTrue(json.loads(rendered["stdout"])["ok"])
        instance = self.org / ".laneboss" / "instances" / instance_name / "instance.toml"
        hooks = self.rendered_hooks(instance)
        parent = "supervisor-" + uuid.uuid4().hex[:12]
        parent_worktree = self.start_lane(parent, "top-a", level=4)
        for runner in ("claude", "codex"):
            with self.subTest(runner=runner):
                child = "child-" + uuid.uuid4().hex[:12]
                worktree = self.directory / "worktrees" / child
                worktree.mkdir()
                self.worktrees[child] = worktree
                brief = parent_worktree / (child + ".md")
                brief.write_text("Wait for the delegation canary to finish.\n", encoding="utf-8")
                args = ["lane", "start", "--config", "rows", "--lane", child,
                        "--brief", brief, "--worktree", worktree, "--level", "3",
                        "--role", "executor", "--runner", "row-runner",
                        "--instance", self.instance.parent.name,
                        "--set", "model=row-runner-model-1", "--set", "effort=high", "--turns"]
                command = "laneboss " + shlex.join(list(map(str, args)))
                before = self.events()
                hook, result = self.inspect_hook(runner, command, execute=True, lane=parent, hooks=hooks)
                self.assertEqual(hook["permissionDecision"], "allow", hook["permissionDecisionReason"])
                self.assertIsNotNone(result["execution"], "the same literal start must actually execute")
                self.assert_code(result["execution"], 0, "the L4 must really start its L3 child")
                self.started_lanes.append(child)
                started = self.lane_events(child, "lane.started")
                self.assertEqual(len(started), 1)
                self.assertNotIn(started[0], before)
                self.assertEqual((started[0]["actor"], started[0]["payload"]["starter"],
                                  started[0]["payload"]["level"], started[0]["payload"]["run"]),
                                 ("lane:" + parent, "lane:" + parent, 3, 1))
                self.assertEqual(json.loads(result["execution"]["stdout"])["launch"],
                                 started[0]["payload"]["launch"])
                ready = self.await_value(lambda: json.loads((worktree / "ready.json").read_text())
                                        if (worktree / "ready.json").is_file() else None,
                                        "the delegated child's stand-in never started")
                run_directory = self.states / "rows" / "lanes" / child / "runs"

                def child_recorded():
                    for path in run_directory.glob("*.json"):
                        record = json.loads(path.read_text(encoding="utf-8"))
                        if isinstance(record.get("runner"), dict) and record["runner"].get("pid") == ready["pid"]:
                            return record
                    return None

                self.await_value(child_recorded, "the delegated child's actual process was never recorded")

                # The clean row remains refused overall; only the speaking gate
                # changes. Mutant: bypass archivePermission for an unrelated L3.
                clean = "laneboss lane clean --config rows --lane " + child
                hook, result = self.inspect_hook(runner, clean, execute=True)
                self.assertEqual(hook["permissionDecision"], "allow", hook["permissionDecisionReason"])
                self.assertIsNotNone(result["execution"])
                self.assert_code(result["execution"], 2, "L3 must not collect another lane")
                self.assertEqual(result["execution"]["stderr"],
                                 "refused: a lane may collect itself or, as a recorded L4-L6 supervisor, "
                                 "lower-level descendants started directly or through the same recorded lane lives\n")
                self.assertEqual(self.lane_events(child, "lane.cleaned"), [])
                self.assertTrue(worktree.is_dir(), "the refused clean must leave the child worktree")

                attempts = [
                    (command + " --unknown-output output", "no file-effects adapter"),
                    ("nohup " + command, "output files cannot be inspected"),
                    ("env -C /tmp " + command, "changes execution context"),
                    ("env HOOK_CANARY=1 " + command, "environment assignments"),
                    ("HOOK_CANARY=1 " + command, "environment assignments"),
                    ('nice -n "$(printf canary)" ' + command, "substitutions and variables"),
                    (command.replace(shlex.quote(str(brief)), '"$UNRESOLVED"'), "substitutions and variables"),
                ]
                for obscured, detail in attempts:
                    hook, result = self.inspect_hook(runner, obscured, execute=True, lane=parent, hooks=hooks)
                    self.assertEqual(hook["permissionDecision"], "deny")
                    self.assertIn(detail, hook["permissionDecisionReason"])
                    self.assertIsNone(result["execution"], "a refused form must never execute")
                self.assertEqual(self.lane_events(child, "lane.started"), started,
                                 "the obscured calls must not start another run")

    def test_ask_hook(self):
        self.require_ask_syntax()
        self.check_send(ask=True)

    def test_stdin_and_wrappers(self):
        for runner in ("claude", "codex"):
            for wrapper in ("", "command nice -n 0 "):
                with self.subTest(runner=runner, wrapper=wrapper):
                    _, data = self.message_file("stdin canary")
                    command = wrapper + "laneboss report --config=rows --file=-"
                    result = self.run_hooked(runner, [], command=command, stdin=data.decode("utf-8"))
                    outcomes = list(map(json.loads, result["stdout"].splitlines()))
                    report_id = next(row["report_id"] for row in outcomes if row["channel"] == "dashboard")
                    event = next(row for row in self.events() if row["kind"] == "report.sent"
                                 and row["payload"]["report_id"] == report_id)
                    self.assertEqual((event["actor"], event["payload"]["text"]),
                                     ("lane:" + self.sender, data.decode("utf-8")))
                    result = self.run_hooked(runner, ["lane", "send", "--config=rows",
                                             "--lane=" + self.recipient, "-"], stdin=data.decode("utf-8"))
                    receipt = json.loads(result["stdout"])
                    self.assertEqual(Path(receipt["file"]).read_bytes(), data)
                    self.assertEqual(self.lane_events(self.recipient, "lane.mailed")[-1]["actor"],
                                     "lane:" + self.sender)

    def test_managed_state_adapter_and_redirect(self):
        """The validated CLI state effect is allowed; a direct state redirect is not."""
        self.select_hook_mode("blacklist")
        for runner in ("claude", "codex"):
            path, data = self.message_file("managed state canary")
            result = self.run_hooked(runner, ["report", "--config", "rows", "--file", path])
            outcomes = {row["channel"]: row for row in map(json.loads, result["stdout"].splitlines())}
            self.assertEqual(outcomes["dashboard"]["status"], "delivered")
            sent = [event for event in self.events() if event["kind"] == "report.sent"
                    and event["payload"]["report_id"] == outcomes["dashboard"]["report_id"]]
            self.assertEqual(len(sent), 1, "the allowed adapter must store one real report")
            self.assertEqual((sent[0]["actor"], sent[0]["payload"]["text"]),
                             ("lane:" + self.sender, data.decode("utf-8")))
            target = self.states / "rows" / ("direct-state-" + uuid.uuid4().hex[:12])
            hook, result = self.inspect_hook(runner, "printf x > " + shlex.quote(str(target)))
            self.assertEqual(hook["permissionDecision"], "deny")
            self.assertIsNone(result["execution"])
            self.assertIn("[blacklist:laneboss-files] Refuses:", hook["permissionDecisionReason"])
            self.assertFalse(target.exists(), "a direct redirect must not write protected state")

    def decision_fixture(self):
        database = self.states / "rows" / ("decisions-" + uuid.uuid4().hex[:12] + ".sqlite")
        result = self.human.request(["decisions", "init", "--db", database])
        self.assert_code(result, 0, "create the credential-free decision store in the configuration state")
        question = "hook canary " + uuid.uuid4().hex
        record = {
            "id": "D-" + uuid.uuid4().hex, "kind": "decision", "project": "fixture", "area": "hook",
            "topics": ["communication"], "asked_at": "2026-01-01T00:00:00Z",
            "answered_at": "2026-01-01T00:00:01Z", "status": "in_force",
            "question": {"text": question, "background": "Invented hook fixture."},
            "answer": {"verbatim": "Use checked communication.", "channel": "fixture"},
            "scope": {"applies_to": ["fixture"]},
            "provenance": {"recorded_by": "fixture", "recorded_at": "2026-01-01T00:00:02Z", "sources": []},
        }
        source = self.directory / "decision.json"
        source.write_text(json.dumps(record), encoding="utf-8")
        result = self.human.request(["decisions", "add", "--db", database, "--file", source])
        self.assert_code(result, 0, "store the invented decision through the real CLI")
        return database, record

    def test_read_views(self):
        database, record = self.decision_fixture()
        commands = [
            (["lane", "status", "--config", "rows", "--lane", self.sender], "status"),
            (["state", "events", "--config", "rows"], "events"),
            (["decisions", "get", "--db", database, record["id"]], "get"),
            (["decisions", "search", "--db", database, record["question"]["text"]], "search"),
            (["decisions", "stats", "--db", database], "stats"),
            (["decisions", "verify", "--db", database], "verify"),
            (["decisions", "egress", "--db", database, "--list"], "egress"),
        ]
        before = self.events()
        for runner in ("claude", "codex"):
            for args, view in commands:
                with self.subTest(runner=runner, view=view):
                    result = self.run_hooked(runner, args)
                    output = json.loads(result["stdout"])
                    if view == "status":
                        self.assertEqual(output["lane"], self.sender)
                    elif view == "events":
                        self.assertEqual(output, before)
                    elif view == "get":
                        self.assertEqual((output["id"], output["answer"]["verbatim"]),
                                         (record["id"], record["answer"]["verbatim"]))
                    elif view == "search":
                        self.assertEqual([hit["record"]["id"] for hit in output], [record["id"]])
                    elif view in ("stats", "verify"):
                        self.assertEqual(output["records"], 1)
                    elif view == "egress":
                        self.assertEqual(output, [])
        self.assertEqual(self.events(), before, "views must append no lifecycle or communication events")

    def test_help_and_version(self):
        for runner in ("claude", "codex"):
            for args in (["--version"], ["--help"], ["lane", "send", "--help"],
                         ["lane", "start", "--help"], ["decisions", "stats", "--help"]):
                with self.subTest(runner=runner, args=args):
                    result = self.run_hooked(runner, args)
                    if args == ["--version"]:
                        self.assertEqual(json.loads(result["stdout"])["program"], "laneboss")
                    else:
                        self.assertIn("usage:", result["stdout"])

    def minimum_args(self, path, node):
        args = list(path)
        protected = False
        protected_roots = (self.org / ".laneboss" / "org.toml", self.states / "rows")
        for argument in node.get("args", []):
            if not argument.get("required"):
                continue
            name = argument["name"]
            if name.startswith("-"):
                args.append(name)
                if argument.get("flag"):
                    continue
            choices = argument.get("choices", [])
            value = str(choices[0]) if choices else "1" if argument.get("type") else "fixture"
            if name == "--lane":
                value = self.sender
            elif name == "org_dir":
                value = str(self.org)
            elif name == "--db":
                value = str(self.states / "rows" / "opaque.sqlite")
            elif name == "--out":
                value = str(self.worktrees[self.sender] / "ordinary-output")
            elif name == "--subject":
                # Match the CLI's NAME=FILE requirement, including the first
                # equals split in internal/judge/judge.go:130-133.
                value = "fixture=" + value
            if argument.get("hook_path", {}).get("write"):
                destination = (self.worktrees[self.sender] / value).resolve()
                protected = protected or any(destination.is_relative_to(root) or root.is_relative_to(destination)
                                             for root in protected_roots)
            args.append(value)
        if "--config" not in args and any(argument["name"] == "--config" for argument in node.get("args", [])):
            args += ["--config", "rows"]
        return args, protected

    def test_all_other_verbs(self):
        unannotated = [(path, node) for path, node in syntax_nodes(self.syntax) if not node.get("hook")]
        self.assertTrue(unannotated, "the grammar must contribute calls without effect annotations")
        for runner in ("claude", "codex"):
            for path, node in unannotated:
                with self.subTest(runner=runner, verb=" ".join(path)):
                    args, protected = self.minimum_args(path, node)
                    hook, result = self.inspect_hook(runner, "laneboss " + shlex.join(args))
                    self.assertIsNone(result["execution"], "grammar inspection must not execute these calls")
                    if protected:
                        self.assertEqual(hook["permissionDecision"], "deny",
                                         "declared protected writes remain denied without an annotation")
                        self.assertEqual(hook["permissionDecisionReason"].splitlines()[0], PROTECTED_FILES)
                    else:
                        self.assertEqual((hook["permissionDecision"], hook["permissionDecisionReason"]),
                                         ("allow", "org policy permits this tool call"),
                                         "a parsed unannotated verb is allowed with incomplete inspection")
                        receipt = json.loads((self.instance.parent / "hooks" / "callbacks.jsonl")
                                             .read_text(encoding="utf-8").splitlines()[-1])
                        self.assertEqual((receipt["runner"], receipt["decision"]), (runner, "allow"))
                        self.assertIs(receipt["inspection_complete"], False)
                        self.assertEqual(receipt["inspection_notice"],
                                         "file effects were not fully inspected; blacklist mode allowed the call")

    def test_shell_guards(self):
        path, _ = self.message_file("guard canary")
        plain = "laneboss report --config rows --file " + shlex.quote(str(path))
        outside = self.directory / ("outside-" + uuid.uuid4().hex[:12])
        state_output = self.states / "rows" / ("redirect-" + uuid.uuid4().hex[:12])
        attempts = [
            ('laneboss report --config rows --file "$(printf canary)"', "substitutions and variables"),
            ('nice -n "$(printf canary)" ' + plain, "substitutions and variables"),
            ("env -C /tmp " + plain, "changes execution context"),
            ("env HOOK_CANARY=1 " + plain, "environment assignments"),
            ("nohup " + plain, "output files cannot be inspected"),
            (plain + " > " + shlex.quote(str(outside)), "lanes may write only inside"),
            (plain + " > " + shlex.quote(str(state_output)), "[blacklist:laneboss-files] Refuses:"),
            (plain + " --unknown-output " + shlex.quote(str(outside)), "no file-effects adapter"),
        ]
        for runner in ("claude", "codex"):
            for command, detail in attempts:
                with self.subTest(runner=runner, detail=detail):
                    hook, result = self.inspect_hook(runner, command)
                    self.assertEqual(hook["permissionDecision"], "deny")
                    self.assertIn(detail, hook["permissionDecisionReason"])
                    self.assertIsNone(result["execution"])
            hook, _ = self.inspect_hook(runner, plain, tool_options={"env": {"HOOK_CANARY": "1"}})
            self.assertEqual(hook["permissionDecision"], "deny")
            self.assertIn("environment overrides", hook["permissionDecisionReason"])
        self.assertFalse(outside.exists())
        self.assertFalse(state_output.exists(), "a redirect must not inherit the adapter's state scope")

    def test_ordinary_tool(self):
        path, data = self.message_file("ordinary read canary")
        for runner in ("claude", "codex"):
            with self.subTest(runner=runner):
                hook, result = self.inspect_hook(runner, "cat " + shlex.quote(str(path)), execute=True)
                self.assertEqual(hook["permissionDecision"], "allow")
                self.assert_code(result["execution"], 0, "ordinary cat must run")
                self.assertEqual(result["execution"]["stdout"].encode("utf-8"), data)

    def test_external_effects(self):
        self.select_hook_mode("strict")
        path, _ = self.message_file("external effect canary")
        database = self.directory / ("outside-decisions-" + uuid.uuid4().hex[:12] + ".sqlite")
        self.write_config(file_channel=True)
        result = self.cli("config", "validate", "rows")
        self.assert_code(result, 0, "validate the invented configuration with an external file channel")
        for runner in ("claude", "codex"):
            hook, result = self.inspect_hook(runner, "laneboss report --config rows --file " + shlex.quote(str(path)))
            self.assertEqual(hook["permissionDecision"], "deny")
            self.assertIn("lanes may write only inside their recorded worktree", hook["permissionDecisionReason"])
            self.assertIsNone(result["execution"])
            hook, result = self.inspect_hook(runner, "laneboss decisions stats --db " + shlex.quote(str(database)))
            self.assertEqual(hook["permissionDecision"], "deny")
            self.assertIn("lanes may write only inside their recorded worktree", hook["permissionDecisionReason"])
            self.assertIsNone(result["execution"])
        self.assertFalse((self.config_dir / "owner" / "queue.jsonl").exists())
        self.assertFalse(database.exists(), "the outside database must not be created")

    def test_installed_scope(self):
        self.select_hook_mode("strict")
        source = self.org / ".laneboss" / "shared" / "hooks" / "rules.toml"
        self.write_rule_source(source, 'schema_version = 1\n[[rules]]\nid = "declared-writes"\nkind = "write-scope"\n'
                               'paths = []\ndeny_paths = ["{hook_paths}"]\n')
        result = self.cli("org", "render", self.org)
        self.assert_code(result, 0, "render the legacy positive scope and retained protected-path denials")
        assert_hook_deprecation(self, result)
        for runner in ("claude", "codex"):
            path, _ = self.message_file("scope report canary")
            self.run_hooked(runner, ["report", "--config", "rows", "--file", path])
            hook, _ = self.inspect_hook(runner, "touch " + shlex.quote(str(self.worktrees[self.sender] / "ordinary")))
            self.assertEqual((hook["permissionDecision"], hook["permissionDecisionReason"]),
                             ("allow", "org policy permits this tool call"),
                             "legacy positive write scopes do not grant or restrict ordinary work")
            hook, _ = self.inspect_hook(runner, "touch " + shlex.quote(str(source)))
            self.assertEqual(hook["permissionDecision"], "deny")
            self.assertEqual(hook["permissionDecisionReason"].splitlines()[0], PROTECTED_FILES)

    def test_cli_identity(self):
        path, _ = self.message_file("unidentified caller canary")
        before = [event for event in self.events() if event["kind"].startswith("report.")]
        # Give this CLI child no controlling terminal or recorded runner
        # ancestry, even when the outer test harness was invoked from a tty.
        result = run_request({"args": ["report", "--config", "rows", "--file", str(path)], "detach": True},
                             self.binary, self.environment, self.directory)
        self.assert_code(result, 2, "the actual CLI must refuse an unidentified report caller")
        self.assertIn("refused:", result["stderr"])
        self.assertEqual([event for event in self.events() if event["kind"].startswith("report.")], before)

    def test_secret_input(self):
        source = self.org / ".laneboss" / "shared" / "hooks" / "rules.toml"
        self.write_rule_source(source, 'schema_version = 1\n[[rules]]\nid = "secret-files"\nkind = "secret-read"\n'
                               'names = [".env"]\n')
        result = self.cli("org", "render", self.org)
        self.assert_code(result, 0, "install the input secret-file rule")
        protected = self.worktrees[self.sender] / ".env"
        protected.write_text("Invented input, with no credential.\n", encoding="utf-8")
        for runner in ("claude", "codex"):
            hook, result = self.inspect_hook(runner, "laneboss report --config rows --file " + shlex.quote(str(protected)))
            self.assertEqual(hook["permissionDecision"], "deny")
            self.assertIn("[secret-files]", hook["permissionDecisionReason"])
            self.assertIsNone(result["execution"])
            path, _ = self.message_file("public input control")
            self.run_hooked(runner, ["report", "--config", "rows", "--file", path])


def load_tests(loader, standard_tests, pattern):
    # Import the credential-free fixture without collecting its unrelated rows,
    # especially the separate fault-only Discord probe.
    return unittest.TestSuite(
        OrgHookCommunicationRows(name) for name in sorted(OrgHookCommunicationRows.__dict__)
        if name.startswith("test_")
    )


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--runner":
        if len(sys.argv) != 7:
            raise RuntimeError("the stand-in requires binary, lane, worktree, session and brief")
        runner_main(sys.argv[2], sys.argv[4], sys.argv[5])
    else:
        unittest.main(verbosity=2)
