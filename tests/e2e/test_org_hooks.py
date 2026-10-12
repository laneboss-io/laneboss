"""CLI-only org hook canaries. No package imports, mocks, vendor runners or network.

Each decision has an opposite control. These fixtures deliberately use their own
rule data and descriptions, so an implementation keyed on the template's ids or
example command text fails. Tests run on the designated disposable test machine.
"""

import json
import shlex
import subprocess
import sys
import uuid

from . import support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class OrgHookTest(support.LauncherTest):
    def setUp(self):
        super().setUp()
        self.org = self.directory / "example-org"
        self.org.mkdir()
        self.org_home = self.org / ".laneboss"
        self.org_home.mkdir()
        (self.org_home / "org.toml").write_text('name = "example-org"\nlevels = [3, 4, 5, 6]\n', encoding="utf-8")
        self.shared = [
            {"id": "tools-canary", "kind": "tool-allowlist", "tools": ["{allowed_tools}"]},
            {"id": "scope-canary", "kind": "write-scope", "paths": ["{writable_repos}"],
             "deny_paths": ["{hook_paths}"]},
            {"id": "secret-canary", "kind": "secret-read", "names": ["{secret_names}"]},
        ]
        self.write_rules("shared", self.shared)
        for level in (3, 4, 5, 6):
            rules = [{"id": "publish-canary", "kind": "command-pattern", "patterns": [["git", "push"]]}] if level < 5 else []
            self.write_rules("L" + str(level), rules, levels=[level])
        self.instances = {}
        self.workspaces = {}
        for name, level in (("alpha", 3), ("beta", 4)):
            directory = self.org_home / "instances" / name
            (directory / "state" / "nested").mkdir(parents=True)
            workspace = self.org / "worktrees" / name
            workspace.mkdir(parents=True)
            self.instances[name] = directory
            self.workspaces[name] = workspace
            (workspace / "public.txt").write_text("harmless public fixture\n", encoding="utf-8")
            (workspace / (name + ".private")).write_text("harmless protected canary\n", encoding="utf-8")
            self.write_instance(name, level)

    def write_instance(self, name, level, tools=None, tail=""):
        tools = tools if tools is not None else ["Bash", "exec_command", "shell", "shell_command", "Write", "Read", "apply_patch"]
        text = 'name = {}\nlevel = {}\nrole = "executor"\n'.format(json.dumps(name), level)
        text += "writable_repos = {}\nallowed_tools = {}\nsecret_names = {}\n".format(
            json.dumps([str(self.workspaces[name])]), json.dumps(tools), json.dumps([name + ".private"]))
        (self.instances[name] / "instance.toml").write_text(text + tail, encoding="utf-8")

    def write_rules(self, layer, rules, levels=None, identities=None):
        directory = self.org_home / layer
        (directory / "hooks").mkdir(parents=True, exist_ok=True)
        (directory / "refusals").mkdir(exist_ok=True)
        text = "schema_version = 1\n" + ("rules = []\n" if not rules else "")
        for rule in rules:
            text += "\n[[rules]]\n" + "".join(key + " = " + json.dumps(value) + "\n" for key, value in rule.items())
            self.write_refusal(directory, rule["id"], levels=levels, identities=identities)
        (directory / "hooks" / "rules.toml").write_text(text, encoding="utf-8")

    def write_refusal(self, directory, identifier, levels=None, identities=None, why=None):
        (directory / "refusals").mkdir(exist_ok=True)
        description = {"id": identifier, "refuses": "Refusal of " + identifier,
                       "why": why or "Reason for " + identifier, "instead": "Alternative for " + identifier,
                       "examples_allowed": ["A permitted action for " + identifier],
                       "examples_refused": ["A prohibited action for " + identifier]}
        text = "".join(key + " = " + json.dumps(value) + "\n" for key, value in description.items())
        text += "\n[applies_to]\nlevels = {}\nidentities = {}\n".format(
            json.dumps(levels if levels is not None else [3, 4, 5, 6]),
            json.dumps(identities if identities is not None else ["*"]))
        (directory / "refusals" / (identifier + ".toml")).write_text(text, encoding="utf-8")
        return description

    def cli(self, *arguments, stdin=None, code=0, environment=None):
        result = subprocess.run([str(self.command), "org", *map(str, arguments)], cwd=self.org,
                                env=self.environment if environment is None else environment,
                                input=stdin, capture_output=True, text=True, encoding="utf-8", timeout=30)
        self.assertEqual(result.returncode, code, "org CLI exited unexpectedly: " + result.stderr)
        return result

    def event(self, name="alpha", tool="Bash", data=None, cwd=None):
        return {"hook_event_name": "PreToolUse", "cwd": str(cwd or self.instances[name]),
                "tool_name": tool, "tool_input": data if data is not None else {"command": "git status"}}

    def check_decision(self, event, runner="claude", decision="allow", identifier=None, environment=None, pinned=None):
        arguments = ["hook", "--runner", runner]
        if pinned is not None:
            arguments.extend(("--instance", pinned))
        result = self.cli(*arguments, stdin=json.dumps(event), environment=environment)
        envelope = json.loads(result.stdout)
        self.assertEqual(set(envelope), {"hookSpecificOutput"})
        output = envelope["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], "PreToolUse")
        self.assertEqual(output["permissionDecision"], decision)
        self.assertIsInstance(output["permissionDecisionReason"], str)
        if identifier is not None:
            for marker in ("[" + identifier + "]", "Refusal of " + identifier, "Reason for " + identifier,
                           "Alternative for " + identifier):
                self.assertIn(marker, output["permissionDecisionReason"])
        self.assertEqual(result.stderr, "")
        return output["permissionDecisionReason"]

    def shell(self, name, runner, command):
        tool = "Bash" if runner == "claude" else "exec_command"
        key = "command" if runner == "claude" else "cmd"
        return self.event(name, tool, {key: command})

    def matrix(self):
        for level in (3, 4):
            for name in ("alpha", "beta"):
                self.write_instance(name, level)
                for runner in ("claude", "codex"):
                    yield level, name, runner

    def test_write_scope_allowed_and_refused_at(self):
        for level, name, runner in self.matrix():
            with self.subTest(level=level, identity=name, runner=runner):
                allowed = self.workspaces[name] / "new.txt"
                outside = self.org / "worktrees" / (name + "-sibling") / "new.txt"
                self.check_decision(self.shell(name, runner, "touch " + shlex.quote(str(allowed))), runner)
                self.check_decision(self.shell(name, runner, "touch " + shlex.quote(str(outside))), runner,
                                    "deny", "scope-canary")

    def test_command_words_allowed_and_refused(self):
        for level, name, runner in self.matrix():
            with self.subTest(level=level, identity=name, runner=runner):
                root = shlex.quote(str(self.workspaces[name]))
                for allowed in ("git status", "env git status", "printf '%s' 'git push'", "echo push", "git status # git push"):
                    self.check_decision(self.shell(name, runner, allowed), runner)
                for refused in ("git -C " + root + " push origin topic", "/usr/bin/git -C " + root + " 'push'",
                                "env git -C " + root + " push", "git status && git -C " + root + " push",
                                "sh -c 'git -C " + root + " push'"):
                    self.check_decision(self.shell(name, runner, refused), runner, "deny", "publish-canary")

    def test_secret_read_allowed_and_refused_at(self):
        for level, name, runner in self.matrix():
            with self.subTest(level=level, identity=name, runner=runner):
                root = self.workspaces[name]
                self.check_decision(self.shell(name, runner, "cat " + shlex.quote(str(root / "public.txt"))), runner)
                self.check_decision(self.shell(name, runner, "cat " + shlex.quote(str(root / (name + ".private")))),
                                    runner, "deny", "secret-canary")
                self.check_decision(self.shell(name, runner, "echo " + name + ".private"), runner)

    def test_tool_allowlist_allowed_and_refused(self):
        for level, name, runner in self.matrix():
            with self.subTest(level=level, identity=name, runner=runner):
                self.check_decision(self.event(name, "Read", {"file_path": str(self.workspaces[name] / "public.txt")}), runner)
                self.check_decision(self.event(name, "WebFetch", {"url": "https://example.com"}), runner,
                                    "deny", "tools-canary")

    def test_level_five_can_push_and_lower(self):
        for runner in ("claude", "codex"):
            for level, expected in ((3, "deny"), (4, "deny"), (5, "allow"), (6, "allow")):
                self.write_instance("alpha", level)
                self.check_decision(self.shell("alpha", runner, "git -C " + shlex.quote(str(self.workspaces["alpha"])) + " push"),
                                    runner, expected, "publish-canary" if expected == "deny" else None)

    def test_scope_uses_identity_repositories(self):
        for runner in ("claude", "codex"):
            for name, other in (("alpha", "beta"), ("beta", "alpha")):
                self.check_decision(self.event(name, "Write", {"file_path": str(self.workspaces[name] / "file.txt")}), runner)
                self.check_decision(self.event(name, "Write", {"file_path": str(self.workspaces[other] / "file.txt")}),
                                    runner, "deny", "scope-canary")

    def test_secret_policy_applies_at_every(self):
        for level in (3, 4, 5, 6):
            self.write_instance("alpha", level)
            for runner in ("claude", "codex"):
                self.check_decision(self.event(tool="Read", data={"path": str(self.workspaces["alpha"] / "public.txt")}), runner)
                self.check_decision(self.event(tool="Read", data={"path": str(self.workspaces["alpha"] / "alpha.private")}),
                                    runner, "deny", "secret-canary")

    def test_tool_allowlist_uses_each_identity(self):
        self.write_instance("beta", 3, tools=["Read"])
        for runner in ("claude", "codex"):
            self.check_decision(self.event("beta", "Read", {"path": str(self.workspaces["beta"] / "public.txt")}), runner)
            self.check_decision(self.event("alpha", "Write", {"path": str(self.workspaces["alpha"] / "output.txt")}), runner)
            self.check_decision(self.event("beta", "Write", {"path": str(self.workspaces["beta"] / "output.txt")}), runner,
                                "deny", "tools-canary")

    def test_applies_to_filters_level_and(self):
        extra = {"id": "audience-canary", "kind": "command-pattern", "patterns": [["git", "status"]]}
        self.write_rules("shared", self.shared + [extra])
        self.write_refusal(self.org_home / "shared", "audience-canary", levels=[3], identities=["beta"])
        for runner in ("claude", "codex"):
            self.write_instance("alpha", 3)
            self.check_decision(self.shell("alpha", runner, "git status"), runner)
            self.write_instance("beta", 3)
            self.check_decision(self.shell("beta", runner, "git status"), runner, "deny", "audience-canary")
            self.write_instance("beta", 4)
            self.check_decision(self.shell("beta", runner, "git status"), runner)

    def test_shared_then_level_then_instance(self):
        shared = {"id": "shared-order", "kind": "command-pattern", "patterns": [["git", "status"]]}
        level = {"id": "level-order", "kind": "command-pattern", "patterns": [["git", "status"]]}
        self.write_rules("shared", self.shared + [shared])
        self.write_rules("L3", [level], levels=[3])
        self.write_instance("alpha", 3, tail='\n[[hooks.rules]]\nid = "instance-order"\nkind = "command-pattern"\npatterns = [["git", "status"]]\n')
        self.write_refusal(self.instances["alpha"], "instance-order", levels=[3], identities=["alpha"])
        event = self.shell("alpha", "claude", "git status")
        self.check_decision(event, identifier="shared-order", decision="deny")
        self.write_rules("shared", self.shared)
        self.check_decision(event, identifier="level-order", decision="deny")
        self.write_rules("L3", [])
        self.check_decision(event, identifier="instance-order", decision="deny")
        self.write_instance("alpha", 3)
        self.check_decision(event)

    def test_refusal_text_is_read_from_files_on(self):
        event = self.event(tool="Read", data={"file_path": str(self.workspaces["alpha"] / "alpha.private")})
        before = self.check_decision(event, decision="deny", identifier="secret-canary")
        unique_reason = "updated explanation " + uuid.uuid4().hex
        self.write_refusal(self.org_home / "shared", "secret-canary", why=unique_reason)
        after = self.check_decision(event, decision="deny")
        self.assertIn(unique_reason, after)
        self.assertNotEqual(before, after)

    def test_broken_toml_in_every_layer_fails(self):
        for runner in ("claude", "codex"):
            for path in (self.org_home / "shared/hooks/rules.toml", self.org_home / "L3/hooks/rules.toml",
                         self.instances["alpha"] / "instance.toml", self.org_home / "shared/refusals/secret-canary.toml"):
                with self.subTest(runner=runner, file=path.name):
                    saved = path.read_text(encoding="utf-8")
                    self.check_decision(self.shell("alpha", runner, "git status"), runner)
                    path.write_text("broken = [\n", encoding="utf-8")
                    reason = self.check_decision(self.shell("alpha", runner, "git status"), runner, "deny")
                    self.assertIn("broken TOML", reason)
                    self.assertIn("fails closed", reason)
                    path.write_text(saved, encoding="utf-8")
                    self.check_decision(self.shell("alpha", runner, "git status"), runner)

    def test_unknown_instance_and_missing_rules(self):
        for runner in ("claude", "codex"):
            environment = dict(self.environment, LANEBOSS_INSTANCE="absent-agent")
            reason = self.check_decision(self.shell("alpha", runner, "git status"), runner, "deny", environment=environment)
            self.assertIn("instance", reason)
            self.assertIn("fails closed", reason)
        path = self.org_home / "L3/hooks/rules.toml"
        path.unlink()
        for runner in ("claude", "codex"):
            reason = self.check_decision(self.shell("alpha", runner, "git status"), runner, "deny")
            self.assertIn("L3/hooks/rules.toml", reason)
            self.assertIn("missing or unreadable", reason)

    def test_stdin_parse_errors_deny_without(self):
        marker = "untrusted-value-" + uuid.uuid4().hex
        for runner in ("claude", "codex"):
            for broken in (marker, "[]", '{"tool_name":"' + marker + '","tool_name":"Bash"}',
                           '{"value":NaN}'):
                result = self.cli("hook", "--runner", runner, stdin=broken)
                output = json.loads(result.stdout)["hookSpecificOutput"]
                self.assertEqual(output["permissionDecision"], "deny")
                self.assertNotIn(marker, result.stdout + result.stderr)
                self.assertIn("fails closed", output["permissionDecisionReason"])

    def test_instance_discovery_and_pinning(self):
        for runner in ("claude", "codex"):
            self.check_decision(self.event(cwd=self.instances["alpha"] / "state/nested"), runner)
            event = self.event(cwd=self.workspaces["alpha"])
            environment = dict(self.environment, LANEBOSS_INSTANCE="alpha")
            self.check_decision(event, runner, environment=environment)
            self.check_decision(event, runner, pinned=str(self.instances["alpha"] / "instance.toml"))
            bad = dict(self.environment, LANEBOSS_INSTANCE="beta")
            self.assertIn("disagree", self.check_decision(self.event(), runner, "deny", environment=bad))
            self.assertIn("disagree", self.check_decision(event, runner, "deny", pinned=str(self.instances["alpha"] / "instance.toml"), environment=bad))

    def test_symlinks_do_not_escape_write_scope(self):
        outside = self.org / "outside"
        outside.mkdir()
        (self.workspaces["alpha"] / "shortcut").symlink_to(outside, target_is_directory=True)
        (self.workspaces["alpha"] / "innocent.txt").symlink_to(self.workspaces["alpha"] / "alpha.private")
        for runner in ("claude", "codex"):
            self.check_decision(self.event(tool="Write", data={"file_path": str(self.workspaces["alpha"] / "shortcut/file.txt")}),
                                runner, "deny", "scope-canary")
            self.check_decision(self.event(tool="Read", data={"file_path": str(self.workspaces["alpha"] / "innocent.txt")}),
                                runner, "deny", "secret-canary")

    def test_redirections_and_changed_directory(self):
        root = shlex.quote(str(self.workspaces["alpha"]))
        outside = shlex.quote(str(self.org / "outside.txt"))
        for runner in ("claude", "codex"):
            self.check_decision(self.shell("alpha", runner, "cd " + root + " && printf 'x' > public.txt"), runner)
            self.check_decision(self.shell("alpha", runner, "cd " + root + " && printf 'x' > " + outside), runner,
                                "deny", "scope-canary")
            self.check_decision(self.shell("alpha", runner, "cat < " + root + "/alpha.private"), runner,
                                "deny", "secret-canary")

    def test_tool_workdir_is_checked_without(self):
        for runner in ("claude", "codex"):
            for directory, decision in ((self.workspaces["alpha"], "allow"), (self.workspaces["beta"], "deny")):
                event = self.shell("alpha", runner, "touch output.txt")
                event["tool_input"]["workdir"] = str(directory)
                self.check_decision(event, runner, decision, "scope-canary" if decision == "deny" else None)

    def test_directory_search_cannot_print_a(self):
        root = shlex.quote(str(self.workspaces["alpha"]))
        for runner in ("claude", "codex"):
            self.check_decision(self.shell("alpha", runner, "grep harmless " + root + "/public.txt"), runner)
            self.check_decision(self.shell("alpha", runner, "grep -R harmless " + root), runner,
                                "deny", "secret-canary")

    def test_codex_argv_json_arguments_and(self):
        self.check_decision(self.event(tool="functions.exec_command", data=json.dumps({"cmd": "git status"})), "codex")
        self.check_decision(self.event(tool="shell", data={"command": ["git", "status"]}), "codex")
        refused = ["git", "-C", str(self.workspaces["alpha"]), "push"]
        self.check_decision(self.event(tool="shell", data={"command": refused}), "codex", "deny", "publish-canary")
        target = str(self.workspaces["alpha"] / "created.txt")
        patch = "*** Begin Patch\n*** Add File: " + target + "\n+harmless\n*** End Patch\n"
        self.check_decision(self.event(tool="apply_patch", data=patch), "codex")
        moved = "*** Begin Patch\n*** Update File: " + target + "\n*** Move to: " + str(self.org / "outside.txt") + "\n@@\n-x\n+y\n*** End Patch\n"
        self.check_decision(self.event(tool="apply_patch", data={"input": moved}), "codex", "deny", "scope-canary")

    def test_protected_hook_files_cannot_be(self):
        text = (self.instances["alpha"] / "instance.toml").read_text(encoding="utf-8")
        text = text.replace(json.dumps([str(self.workspaces["alpha"])]), json.dumps([str(self.org)]))
        (self.instances["alpha"] / "instance.toml").write_text(text, encoding="utf-8")
        for runner in ("claude", "codex"):
            self.check_decision(self.event(tool="Write", data={"file_path": str(self.org / "public.txt")}), runner)
            for path in (self.org_home / "shared/hooks/rules.toml", self.instances["beta"] / "instance.toml",
                         self.instances["alpha"] / ".codex/hooks.json", self.org_home / "L4/refusals/publish-canary.toml"):
                self.check_decision(self.event(tool="Write", data={"file_path": str(path)}), runner, "deny", "scope-canary")

    def test_opaque_and_malformed_commands_fail(self):
        for runner in ("claude", "codex"):
            self.check_decision(self.shell("alpha", runner, "printf '%s' harmless"), runner)
            for command in ("python3 -c 'print(1)'", "eval 'git push'", "git 'push", "git status &&", "git status &&\n",
                            "touch $DEST", "cat $(echo alpha.private)", "nice env PATH=/tmp git status", "find . -delete",
                            "git --git-dir=" + shlex.quote(str(self.org / "outside")) + " status"):
                self.check_decision(self.shell("alpha", runner, command), runner, "deny")

    def test_refusal_catalog_json_and_text(self):
        result = self.cli("refusals", self.org, "--format", "json")
        records = json.loads(result.stdout)
        sources = {row["source"] for row in records}
        expected = {"shared/refusals/tools-canary.toml", "shared/refusals/scope-canary.toml",
                    "shared/refusals/secret-canary.toml", "L3/refusals/publish-canary.toml", "L4/refusals/publish-canary.toml"}
        self.assertEqual(sources, expected)
        for row in records:
            self.assertTrue({"id", "refuses", "why", "instead", "applies_to", "examples_allowed", "examples_refused"} <= set(row))
            self.assertEqual(set(row["applies_to"]), {"levels", "identities"})
            self.assertEqual(row["why"], "Reason for " + row["id"])
        text = self.cli("refusals", self.org).stdout
        self.assertIn("Alternative for secret-canary", text)

    def install_hook_settings_fixture(self):
        for layer in ("shared", "L3", "L4", "L5", "L6"):
            (self.org_home / layer / "hooks/rules.toml").chmod(0o444)
            for path in (self.org_home / layer / "refusals").glob("*.toml"):
                path.chmod(0o444)
        library = str(self.command.resolve().parents[1] / "lib")
        helper = self.org_home / "shared/hooks/org-hook.py"
        helper.write_text("# Generated by laneboss org render; the implementation lives in the installed package.\n"
                          "import sys\n\nsys.path.insert(0, " + json.dumps(library) + ")\n"
                          "from laneboss.cli import main\n\nraise SystemExit(main(['org', 'hook', *sys.argv[1:]]))\n", encoding="utf-8")
        helper.chmod(0o444)
        for name in self.instances:
            commands = {}
            for runner, relative in (("claude", ".claude/settings.json"), ("codex", ".codex/hooks.json")):
                directory = self.instances[name]
                path = directory / relative
                path.parent.mkdir(exist_ok=True)
                command = shlex.join([sys.executable, "-I", "-B", str(helper), "--runner", runner,
                                      "--instance", str(directory / "instance.toml")])
                document = {"hooks": {"PreToolUse": [{"matcher": "", "hooks": [{"type": "command", "command": command}]}]}}
                path.write_text(json.dumps(document), encoding="utf-8")
                path.chmod(0o444)
                commands[runner] = {"command": ["claude", "--settings", str(path)] if runner == "claude" else
                                    ["env", "CODEX_HOME=" + str(directory / ".codex"), "codex"]}
            (self.instances[name] / "hooks").mkdir(exist_ok=True)
            (self.instances[name] / "hooks/runners.json").write_text(json.dumps(commands), encoding="utf-8")
            (self.instances[name] / "hooks/runners.json").chmod(0o444)

    def test_check_hooks_accepts_settings_and(self):
        self.install_hook_settings_fixture()
        good = json.loads(self.cli("check-hooks", self.org).stdout)
        self.assertTrue(good["ok"])
        self.assertEqual(len(good["checks"]), 4)
        self.assertTrue(all(row["ok"] for row in good["checks"]))
        for runner in ("claude", "codex"):
            tail = '\n[runners.' + runner + ']\ncommand = ["' + runner + '"]\n'
            self.write_instance("alpha", 3, tail=tail)
            report = json.loads(self.cli("check-hooks", self.org, code=1).stdout)
            self.assertFalse(report["ok"])
            row = next(row for row in report["checks"] if row.get("instance") == "alpha")
            self.assertFalse(row["ok"])
            self.assertIn("settings" if runner == "claude" else "CODEX_HOME", row["reason"])
        self.write_instance("alpha", 3)
        self.assertTrue(json.loads(self.cli("check-hooks", self.org).stdout)["ok"])

    def test_check_hooks_rejects_codex_hook(self):
        self.install_hook_settings_fixture()
        prefix = ["env", "CODEX_HOME=" + str(self.instances["alpha"] / ".codex"), "codex"]
        for override in (["-cfeatures.hooks=false"], ["--config", "features={hooks=false}"], ["--disable", "hooks"]):
            self.write_instance("alpha", 3, tail='\n[runners.codex]\ncommand = ' + json.dumps(prefix + override) + '\n')
            report = json.loads(self.cli("check-hooks", self.org, code=1).stdout)
            self.assertFalse(report["ok"])
            self.assertIn("overrides", next(row for row in report["checks"] if row["instance"] == "alpha")["reason"])
        self.write_instance("alpha", 3, tail='\n[runners.codex]\ncommand = ' + json.dumps(prefix + ["-c", 'model="example-model"']) + '\n')
        self.assertTrue(json.loads(self.cli("check-hooks", self.org).stdout)["ok"])

    def test_check_hooks_rejects_modified(self):
        self.install_hook_settings_fixture()
        helper = self.org_home / "shared/hooks/org-hook.py"
        original = helper.read_text(encoding="utf-8")
        helper.chmod(0o644)
        # A tampered helper that emits no decision must fail the launch check.
        helper.write_text("raise SystemExit(0)\n", encoding="utf-8")
        helper.chmod(0o444)
        self.assertFalse(json.loads(self.cli("check-hooks", self.org, code=1).stdout)["ok"])
        helper.chmod(0o644)
        helper.write_text(original, encoding="utf-8")
        helper.chmod(0o444)
        self.assertTrue(json.loads(self.cli("check-hooks", self.org).stdout)["ok"])
        rule_file = self.org_home / "shared/hooks/rules.toml"
        rule_file.chmod(0o644)
        report = json.loads(self.cli("check-hooks", self.org, code=1).stdout)
        self.assertFalse(report["ok"])
        self.assertTrue(all("read-only" in row["reason"] for row in report["checks"]))
        rule_file.chmod(0o444)
        self.assertTrue(json.loads(self.cli("check-hooks", self.org).stdout)["ok"])

    def test_check_hooks_inspects_resume(self):
        self.install_hook_settings_fixture()
        settings = self.instances["alpha"] / ".claude/settings.json"
        command = ["claude", "--settings", str(settings)]
        tail = '\n[runners.claude]\ncommand = ' + json.dumps(command) + '\nresume = ["claude", "--resume", "session"]\n'
        self.write_instance("alpha", 3, tail=tail)
        report = json.loads(self.cli("check-hooks", self.org, code=1).stdout)
        self.assertTrue(next(row for row in report["checks"] if row.get("field") == "command" and row["instance"] == "alpha")["ok"])
        self.assertFalse(next(row for row in report["checks"] if row.get("field") == "resume")["ok"])
        self.write_instance("alpha", 3)
        original = json.loads(settings.read_text(encoding="utf-8"))
        for change in ("disabled", "managed-only", "narrow", "async", "changed-command"):
            document = json.loads(json.dumps(original))
            row = document["hooks"]["PreToolUse"][0]
            if change == "disabled":
                document["disableAllHooks"] = True
            elif change == "managed-only":
                document["allowManagedHooksOnly"] = True
            elif change == "narrow":
                row["matcher"] = "Read"
            elif change == "async":
                row["hooks"][0]["async"] = True
            else:
                row["hooks"][0]["command"] = "true"
            settings.chmod(0o644)
            settings.write_text(json.dumps(document), encoding="utf-8")
            settings.chmod(0o444)
            self.assertFalse(json.loads(self.cli("check-hooks", self.org, code=1).stdout)["ok"])
        settings.chmod(0o644)
        settings.write_text(json.dumps(original), encoding="utf-8")
        settings.chmod(0o444)
        self.assertTrue(json.loads(self.cli("check-hooks", self.org).stdout)["ok"])

    def test_check_hooks_missing_instance_data(self):
        report = json.loads(self.cli("check-hooks", self.org, code=1).stdout)
        self.assertFalse(report["ok"])
        self.assertEqual(len(report["checks"]), 2)
        self.assertTrue(all("missing" in row["reason"] for row in report["checks"]))
