"""Black-box init rows for a disposable Linux box, never the workstation.

Set LANEBOSS_INIT_BINARY and LANEBOSS_INIT_FAULTS to absolute launcher paths.
The second binary must use the laneboss_faults build tag. Runner stand-ins
are executable sentinels, never fake launcher results. Every verdict reads
the CLI exit, TOML/JSON output and the resulting filesystem.
Set LANEBOSS_INIT_EVIDENCE to an absolute directory to keep each row's input
arguments, output bytes, exit codes and temporary HOME after the run.
"""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib
import unittest
import uuid


def binary(variable):
    path = Path(os.environ[variable])
    if not path.is_absolute() or not path.is_file():
        raise RuntimeError(variable + " must name an absolute executable")
    if not os.access(path, os.X_OK):
        raise RuntimeError(variable + " is not executable")
    return path.resolve()


class InitRows(unittest.TestCase):
    def setUp(self):
        evidence = os.environ.get("LANEBOSS_INIT_EVIDENCE")
        if evidence:
            directory = Path(evidence)
            if not directory.is_absolute():
                raise RuntimeError("LANEBOSS_INIT_EVIDENCE must be absolute")
            directory.mkdir(parents=True, exist_ok=True)
            self.root = Path(tempfile.mkdtemp(prefix="lb-init-row-", dir=directory))
        else:
            self.temporary = tempfile.TemporaryDirectory(prefix="lb-init-row-")
            self.addCleanup(self.temporary.cleanup)
            self.root = Path(self.temporary.name)
        (self.root / "row.txt").write_text(self._testMethodName + "\n")
        self.call_count = 0
        self.home = self.root / "home"
        self.home.mkdir()
        self.commands = self.root / "bin"
        self.commands.mkdir()
        self.launcher = binary("LANEBOSS_INIT_BINARY")
        self.faults = binary("LANEBOSS_INIT_FAULTS")
        self.git = shutil.which("git")
        self.tmux = shutil.which("tmux")
        self.env = shutil.which("env")
        self.ps = shutil.which("ps")
        self.assertIsNotNone(self.git, "box requires real git")
        self.assertIsNotNone(self.tmux, "box requires real tmux")
        self.assertIsNotNone(self.env, "box requires real env")
        self.assertIsNotNone(self.ps, "ticket issuance checks its real controlling terminal with ps")
        for name, program in (("git", self.git), ("tmux", self.tmux), ("env", self.env), ("ps", self.ps)):
            (self.commands / name).symlink_to(program)
        # Empty private HOME, explicit private PATH, no copied credentials.
        self.environment = {
            "HOME": str(self.home), "PATH": str(self.commands),
            "LANG": "C", "LC_ALL": "C",
        }
        self.name = "org-" + uuid.uuid4().hex[:10]
        self.config_home = self.home / ".config/laneboss"
        self.config = self.config_home / "configs" / self.name
        self.org = self.config_home / "orgs" / self.name
        self.repo_a = self.repo("alpha-" + uuid.uuid4().hex[:6])
        self.repo_b = self.repo("beta-" + uuid.uuid4().hex[:6])
        self.runner("claude")

    def repo(self, name, parent=None):
        path = (parent or self.root) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            [self.git, "init", "-q", str(path)], env=self.environment,
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return path.resolve()

    def runner(self, name, executable=True):
        path = self.commands / name
        # If init or doctor runs a vendor, the sentinel records that fact.
        text = "#!/bin/sh\n"
        text += 'printf "%s\\n" invoked >> "$HOME/vendor-invoked"\n'
        text += "exit 97\n"
        path.write_text(text)
        path.chmod(0o755 if executable else 0o644)

    def cli(self, *args, launcher=None, environment=None):
        from ticket_fixture import client_environment, service_rows, with_registration
        selected = client_environment(environment or self.environment)
        service = service_rows(self, selected)
        if not service:
            args = with_registration(self, args, selected)
        self.call_count += 1
        record = self.root / ("call-" + str(self.call_count))
        argv = [str(launcher or self.launcher), *map(str, args)]
        if service and args and args[0] == "start" and "--role" in args:
            from headless_support import HeadlessController
            name = args[args.index("--config") + 1]
            selected["LANEBOSS_CONFIG"] = name
            if not hasattr(self, "_service_registration"):
                self._service_registration = HeadlessController(self, selected, self.root, launcher or self.launcher)
            answer = self._service_registration.request(args)
            argv = [self._service_registration.last_binary, *self._service_registration.last_arguments]
            result = subprocess.CompletedProcess(argv, answer["code"], answer["stdout"].encode(), answer["stderr"].encode())
        else:
            result = subprocess.run(argv, cwd=self.root, env=environment or self.environment,
                                    capture_output=True, timeout=90)
        record.with_suffix(".input.json").write_text(json.dumps(argv) + "\n")
        record.with_suffix(".stdout").write_bytes(result.stdout)
        record.with_suffix(".stderr").write_bytes(result.stderr)
        record.with_suffix(".exit").write_text(str(result.returncode) + "\n")
        result.stdout = result.stdout.decode("utf-8")
        result.stderr = result.stderr.decode("utf-8")
        self.assertFalse((self.home / "vendor-invoked").exists(),
                         "init and read checks must never invoke a runner")
        return result

    def start(self, *args, **kwargs):
        return self.cli("init", self.name, *args, **kwargs)

    def clean_destinations(self):
        self.assertFalse(self.config.exists(), "partial configuration remains")
        self.assertFalse(self.org.exists(), "partial org remains")
        self.assertEqual(list(self.config_home.glob(".laneboss-init-*")), [],
                         "staging directories remain")
        self.assertFalse((self.home / ".local/state/laneboss").exists(),
                         "init must not create a state store")

    def refused(self, result, message):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(message, result.stderr)
        self.assertEqual(result.stdout, "", "failed init reported success")

    def snapshot(self, path):
        return {
            str(item.relative_to(path)): item.read_bytes()
            for item in path.rglob("*") if item.is_file()
        }

    def read_toml(self, path):
        return tomllib.loads(path.read_text())

    def check_happy(self, runner, level=5, repositories=None):
        repositories = repositories or [self.repo_a, self.repo_b]
        args = []
        for repository in repositories:
            args += ["--project", repository]
        result = self.start(*args, "--runner", runner, "--top-level", level)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Chosen runner: " + runner, result.stdout)
        self.assertTrue(result.stdout.endswith(
            "Next: laneboss start --config " + self.name + " --role top\n"))
        created = {
            json.loads(line.removeprefix("Created: "))
            for line in result.stdout.splitlines() if line.startswith("Created: ")
        }
        actual = {str(self.config), str(self.org)}
        for root in (self.config, self.org):
            actual.update(str(path) for path in root.rglob("*"))
        self.assertEqual(created, actual, "report must inventory actual created paths")

        data = self.read_toml(self.config / "config.toml")
        names = [path.name for path in repositories]
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual((data["name"], data["organisation"]),
                         (self.name, self.name))
        self.assertEqual(data["supervisors"]["top"], {
            "level": level, "runner": runner, "projects": names,
        })
        self.assertEqual(data["rules"], ["rules/standing.md"])
        self.assertEqual(data["lanes"], {
            "budget_minutes": 60, "quiet_seconds": 900, "stop_grace_seconds": 10,
        })
        self.assertTrue((self.config / "rules/standing.md").read_text().strip())
        self.assertNotIn("secrets", data)
        selected = data["runners"][runner]
        self.assertNotIn("accounts", selected)
        self.assertNotIn("secrets", selected)
        instance = "L5-top" if level == 5 else "L6-super-top"
        identity = self.org / ".laneboss/instances" / instance
        if runner == "codex":
            self.assertEqual(selected["command"][0], "env")
            self.assertEqual(selected["command"][1],
                             "CODEX_HOME=" + str(identity / ".codex"))
            self.assertIn("features.hooks=true", selected["command"])
            self.assertIn("codex", selected["command"])
        else:
            for key in ("command", "resume"):
                self.assertEqual(selected[key][0], runner)
                self.assertIn("{session}", selected[key])
                i = selected[key].index("--settings")
                self.assertEqual(selected[key][i + 1],
                                 str(identity / ".claude/settings.json"))
            if runner == "claudock":
                self.assertEqual(selected["command"][:4],
                                 ["claudock", "run", "{account}", "--"])
                self.assertIn("runners.claudock.accounts", result.stdout)
        for path in repositories:
            project = self.read_toml(self.config / "projects" / (path.name + ".toml"))
            self.assertEqual(project, {
                "schema_version": 1, "name": path.name,
                "repository": str(path), "workers": [runner],
                "landing_authority": "top",
            })
        self.assertEqual(set(data["routing"]),
                         {"mechanical", "standard", "hard", "review"})
        model = "gpt-6.1-sol" if runner == "codex" else "claude-sonnet-5-5"
        for rows in data["routing"].values():
            self.assertEqual(rows, [{"runner": runner, "model": model}])

        for file in ("AGENTS.md", "CLAUDE.md"):
            self.assertTrue((self.org / file).read_text().strip())
            self.assertTrue((identity / file).read_text().strip())
        org_data = self.read_toml(self.org / ".laneboss/org.toml")
        self.assertEqual(org_data["levels"], [3, 4, 5, 6])
        self.assertEqual(org_data["name"], self.name)
        # Read the shipped pack, rather than maintaining a second list of IDs
        # and command words. Its Go rows contain JSON-compatible string literals;
        # fail closed if that source format or the twelve-entry contract changes.
        source = Path(__file__).resolve().parents[1] / "internal/orgtree/rawpack.go"
        entries = re.findall(r'^\s*\{("[^"\n]+"),[^\n]*\[\]any\{([^{}\n]+)\}\},$',
                             source.read_text(encoding="utf-8"), re.MULTILINE)
        self.assertEqual(len(entries), 12, "could not read the twelve source pack entries")
        expected = {json.loads(name): json.loads("[" + words + "]") for name, words in entries}
        self.assertEqual(len(expected), 12, "the source pack has duplicate IDs")

        def check_pack(hooks):
            self.assertEqual(set(hooks), {"mode", "blacklist"}, "extra seeded hook policy")
            self.assertEqual(hooks["mode"], "blacklist")
            self.assertEqual(len(hooks["blacklist"]), 12, "seeded pack count differs")
            self.assertEqual({row["id"]: row["argv_words"] for row in hooks["blacklist"]},
                             expected, "seeded pack IDs or argv_words differ from rawpack.go")
            for row in hooks["blacklist"]:
                self.assertEqual(set(row), {"id", "description", "band", "argv_words", "instead", "pattern_only"})
                self.assertEqual(row["band"], "refuse")
                self.assertIs(row["pattern_only"], True)
                self.assertTrue(row["description"].strip())
                self.assertTrue(row["instead"].strip())

        hooks = org_data["hooks"]
        # The same checks must reject the old empty expectation, altered command
        # words and extra policy before accepting the actual generated files.
        with self.assertRaisesRegex(AssertionError, "extra seeded hook policy"):
            check_pack({"mode": "blacklist"})
        altered = json.loads(json.dumps(hooks))
        altered["blacklist"][0]["argv_words"] = []
        with self.assertRaisesRegex(AssertionError, "argv_words differ"):
            check_pack(altered)
        with self.assertRaisesRegex(AssertionError, "extra seeded hook policy"):
            check_pack({**hooks, "allowed_tools": []})
        check_pack(hooks)
        self.assertNotIn("allowed_tools", org_data["defaults"])
        for layer in ("shared", "L3", "L4", "L5", "L6"):
            for policy in ("hooks/rules.toml", "refusals"):
                target = self.org / ".laneboss" / layer / policy
                self.assertFalse(target.exists() or target.is_symlink(),
                                 "init seeded additional policy: " + layer + "/" + policy)
        refusals = self.cli("org", "refusals", self.org, "--format", "json")
        self.assertEqual(refusals.returncode, 0, refusals.stderr)
        self.assertEqual(json.loads(refusals.stdout), [], "init seeded a refusal catalog")
        self.assertEqual(refusals.stderr, "")
        for name, expected_level in (
            ("L3-lane-example", 3), ("L4-stream", 4),
            ("L5-top", 5), ("L6-super-top", 6),
        ):
            entry = self.org / ".laneboss/instances" / name
            self.assertEqual(self.read_toml(entry / "instance.toml")["level"],
                             expected_level)
            for provider, folder, filename in (
                ("claude", ".claude", "settings.json"),
                ("codex", ".codex", "hooks.json"),
            ):
                settings = json.loads((entry / folder / filename).read_text())
                hooks = settings["hooks"]["PreToolUse"]
                command = hooks[-1]["hooks"][0]["command"]
                self.assertIn(str(entry / "instance.toml"), command)
                self.assertNotIn(".laneboss-init-", command)
                self.assertIn("--runner " + provider, command)
                self.assertEqual((entry / folder / filename).stat().st_mode & 0o222, 0)
        self.assertTrue((self.org / "tools").is_dir())
        self.assertTrue((self.org / "worktrees").is_dir())
        self.assertEqual(list(self.config_home.glob(".laneboss-init-*")), [])

        valid = self.cli("config", "validate", self.name)
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertEqual(json.loads(valid.stdout), {"valid": True, "configs": [self.name]})
        valid = self.cli("org", "validate", self.org, "--format", "json")
        self.assertEqual(valid.returncode, 0, valid.stderr + valid.stdout)
        self.assertEqual(json.loads(valid.stdout), {"valid": True, "problems": []})
        # Explicitly install editable roles before checking unused-source warnings.
        # The default JSON shape stays stable; warnings belong to diagnostics.
        installed = self.cli("org", "roles", "init", self.org)
        self.assertEqual(installed.returncode, 0, installed.stderr + installed.stdout)
        valid = self.cli("org", "validate", self.org, "--format", "json-diagnostics")
        self.assertEqual(valid.returncode, 0, valid.stderr + valid.stdout)
        warnings = [{"path": path,
                     "message": "no instance uses this template; use --config NAME to include lane usage"}
                    for path in (".laneboss/L3/roles/docs.md",
                                 ".laneboss/L3/roles/researcher.md",
                                 ".laneboss/L3/roles/reviewer.md",
                                 ".laneboss/L3/roles/tester.md",
                                 ".laneboss/L4/roles/reviewer.md",
                                 ".laneboss/L5/roles/reviewer.md",
                                 ".laneboss/L5/roles/supervisor.md",
                                 ".laneboss/L5/roles/top.md")]
        self.assertEqual(json.loads(valid.stdout),
                         {"valid": True, "problems": [], "warnings": warnings})
        before = self.snapshot(self.org)
        rendered = self.cli("org", "render", self.org)
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        self.assertEqual(json.loads(rendered.stdout), {"ok": True, "changed": 0})
        self.assertEqual(self.snapshot(self.org), before,
                         "render must already be current after publication")
        doctor = self.cli("doctor", "--config", self.name)
        self.assertEqual(doctor.returncode, 0, doctor.stderr + doctor.stdout)
        checks = [json.loads(line) for line in doctor.stdout.splitlines()]
        self.assertGreater(len(checks), 0)
        self.assertTrue(all(row["ok"] for row in checks), checks)
        kinds = {row["check"] for row in checks}
        self.assertTrue({"tool.git", "tool.tmux", "runner." + runner,
                         "organisation.tools"}.issubset(kinds))
        briefing = self.cli("start", "--config", self.name,
                            "--role", "top", "--format", "json")
        self.assertEqual(briefing.returncode, 0, briefing.stderr)
        data = json.loads(briefing.stdout)
        self.assertEqual(data["role"]["entry"]["level"], level)
        self.assertEqual(data["role"]["entry"]["runner"], runner)
        self.assertEqual(data["configuration"]["warnings"], [])
        self.assertTrue(all(row["ok"] for row in data["checks"]["read"]))

    def test_happy_claude(self):
        """Fails on wrong config, project, hooks, inventory or CLI validation."""
        self.check_happy("claude")

    def test_happy_claudock(self):
        """Fails if Claudock loses session/settings or invents an account."""
        self.runner("claudock")
        self.check_happy("claudock")

    def test_happy_codex_level_six(self):
        """Fails if Codex hooks or L6 supervisor paths are wrong, or the installed roles refuse the env-wrapped Codex runner."""
        self.runner("codex")
        self.check_happy("codex", 6)
        # check_happy passed `config validate`, which runs the role driver check on the runner
        # init wrote (env CODEX_HOME=... codex ...). Prove the roles it ran against are installed,
        # and that the pass is not owed to a library entry that authorizes env itself.
        library = {}
        for level in (3, 4, 5, 6):
            files = sorted((self.org / ".laneboss" / ("L" + str(level)) / "roles").glob("*.toml"))
            self.assertTrue(files, "init must install role driver files at L" + str(level))
            for path in files:
                library[(level, path.stem)] = self.read_toml(path)["drivers"]
        self.assertIn("codex", library[(3, "executor")])
        self.assertTrue(all("env" not in drivers for drivers in library.values()),
                        "the role library must not authorize the env wrapper itself")
        command = self.read_toml(self.config / "config.toml")["runners"]["codex"]["command"]
        self.assertEqual(command[0], "env")
        self.assertEqual(command[command.index("codex") - 1][:11], "CODEX_HOME=")


    def test_nonexecutable_runner(self):
        """Fails if presence without executable permissions wins selection."""
        self.runner("claudock", executable=False)
        result = self.start()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Chosen runner: claude", result.stdout)

    def test_no_runner(self):
        """Fails unless no runner refuses before creating either destination."""
        (self.commands / "claude").unlink()
        result = self.start()
        self.refused(result, "no runner found on PATH: install claudock, claude or codex")
        self.clean_destinations()

    def test_missing_explicit_runner(self):
        """Fails if an explicit absent runner silently falls back."""
        self.refused(self.start("--runner", "claudock"),
                     "selected runner claudock is not executable on PATH")
        self.clean_destinations()

    def test_not_repo(self):
        """Fails if a plain directory is accepted as a project."""
        plain = self.root / "plain"
        plain.mkdir()
        self.refused(self.start("--project", plain), "--project must name a Git work tree")
        self.clean_destinations()

    def test_git_override(self):
        """Fails if inherited Git variables make a plain directory look valid."""
        plain = self.root / "plain"
        plain.mkdir()
        environment = dict(self.environment, GIT_DIR=str(self.repo_a / ".git"),
                           GIT_WORK_TREE=str(self.repo_a))
        result = self.start("--project", plain, environment=environment)
        self.refused(result, "--project must name a Git work tree")
        self.clean_destinations()

    def test_duplicate_repo(self):
        """Fails if the same repository, including subdirectories, appears twice."""
        child = self.repo_a / "subdirectory"
        child.mkdir()
        result = self.start("--project", self.repo_a, "--project", child)
        self.refused(result, "duplicate project")
        self.clean_destinations()

    def test_duplicate_names(self):
        """Fails if two repositories would overwrite one project TOML."""
        other = self.repo(self.repo_a.name, self.root / "other")
        result = self.start("--project", self.repo_a, "--project", other)
        self.refused(result, "duplicate project")
        self.clean_destinations()

    def test_duplicate_alias(self):
        """Fails if a repository symlink evades duplicate detection."""
        alias = self.root / "alias"
        alias.symlink_to(self.repo_a, target_is_directory=True)
        result = self.start("--project", self.repo_a, "--project", alias)
        self.refused(result, "duplicate project")
        self.clean_destinations()

    def test_binding_preserved(self):
        """Fails if init changes a binding or reports its private value."""
        environment = dict(self.environment, LANEBOSS_CONFIG="bound-scope")
        result = self.start(environment=environment)
        self.refused(result, "session is bound to another configuration")
        self.assertNotIn("bound-scope", result.stderr + result.stdout)
        self.assertEqual(environment["LANEBOSS_CONFIG"], "bound-scope")
        self.clean_destinations()

    def test_home_overrides(self):
        """Fails if init ignores explicit configuration or state homes."""
        self.config_home = self.root / "custom-config"
        self.config = self.config_home / "configs" / self.name
        self.org = self.config_home / "orgs" / self.name
        self.environment["LANEBOSS_HOME"] = str(self.config_home)
        self.environment["LANEBOSS_STATE_HOME"] = str(self.root / "custom-state")
        self.check_happy("claude")
        paths = self.cli("config", "path", self.name)
        self.assertEqual(paths.returncode, 0, paths.stderr)
        self.assertEqual(json.loads(paths.stdout)["state_dir"],
                         str(self.root / "custom-state" / self.name))
        self.assertFalse((self.home / ".config/laneboss").exists())

    def test_invalid_level(self):
        """Fails if a non-top level can become a project's landing authority."""
        self.refused(self.start("--top-level", 4), "--top-level must be 5 or 6")
        self.clean_destinations()

    def test_inline_options(self):
        """Fails if documented options lose their equals-sign form."""
        result = self.start("--runner=claude", "--top-level=6",
                            "--project=" + str(self.repo_a))
        self.assertEqual(result.returncode, 0, result.stderr)
        data = self.read_toml(self.config / "config.toml")
        self.assertEqual(data["supervisors"]["top"]["level"], 6)
        self.assertEqual(data["supervisors"]["top"]["projects"], [self.repo_a.name])

    def test_existing_org(self):
        """Fails if init alters a preexisting org or creates its configuration."""
        self.org.mkdir(parents=True)
        sentinel = self.org / "keep.txt"
        sentinel.write_text("kept org bytes\n")
        before = self.snapshot(self.org)
        self.refused(self.start(), "existing org: init refuses to overwrite it")
        self.assertEqual(self.snapshot(self.org), before)
        self.assertFalse(self.config.exists())

    def test_existing_config(self):
        """Fails if init alters a preexisting configuration or creates its org."""
        self.config.mkdir(parents=True)
        sentinel = self.config / "keep.txt"
        sentinel.write_text("kept config bytes\n")
        before = self.snapshot(self.config)
        self.refused(self.start(), "existing configuration: init refuses to overwrite it")
        self.assertEqual(self.snapshot(self.config), before)
        self.assertFalse(self.org.exists())

    def test_existing_empty_org(self):
        """Fails if even an empty destination is silently replaced."""
        self.org.mkdir(parents=True)
        before = self.org.stat()
        self.refused(self.start(), "existing org: init refuses to overwrite it")
        self.assertEqual(self.org.stat().st_ino, before.st_ino)
        self.assertEqual(list(self.org.iterdir()), [])
        self.assertFalse(self.config.exists())

    def test_repeat_preserves_bytes(self):
        """Fails if a repeated init modifies any of its previously made files."""
        result = self.start("--project", self.repo_a)
        self.assertEqual(result.returncode, 0, result.stderr)
        before = (self.snapshot(self.config), self.snapshot(self.org))
        self.refused(self.start("--project", self.repo_b), "existing configuration")
        self.assertEqual((self.snapshot(self.config), self.snapshot(self.org)), before)

    def check_failure(self, point, continuation=""):
        marker = self.root / "fault-marker"
        environment = dict(self.environment)
        environment["LANEBOSS_FAULTS"] = json.dumps({
            "point": point, "marker": str(marker), "continue": continuation,
        })
        result = self.start("--project", self.repo_a, launcher=self.faults,
                            environment=environment)
        self.refused(result, "injected init failure at " + point)
        self.assertTrue(marker.is_file(), "requested transaction boundary was not reached")
        self.clean_destinations()

    def test_stage_failure(self):
        """Fails if a failure after staged config writes leaves output behind."""
        self.check_failure("init-stage")

    def test_publish_failure(self):
        """Fails if a failure between publication renames leaves a partial org."""
        self.check_failure("init-after-org")

    def test_restoring_mutant(self):
        """Fails unless the rollback row catches a tagged partial-org mutant."""
        control = type(self)("test_publish_failure")
        green = unittest.TestResult()
        control.run(green)
        self.assertEqual(green.testsRun, 1)
        self.assertEqual(green.errors, [])
        self.assertEqual(green.failures, [], "rollback control must pass")
        mutant = type(self)("test_publish_failure")
        original = mutant.check_failure
        mutant.check_failure = lambda point: original(point, "keep-org")
        red = unittest.TestResult()
        mutant.run(red)
        self.assertEqual(red.testsRun, 1)
        self.assertEqual(red.errors, [], "a setup error cannot kill the mutant")
        self.assertEqual(len(red.failures), 1)
        self.assertIn("partial org remains", red.failures[0][1])
        print("RESTORING MUTANT: rollback row caught a partial org")


if __name__ == "__main__":
    unittest.main()
