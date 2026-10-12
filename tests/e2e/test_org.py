"""The org template through the installed CLI, with only standard-library helpers.

The tree assertions follow the level selection and the source files on disk. Each
validation row starts with a clean control, then damages one independent rule.
No helper imports the implementation or predicts output from its constants.
"""

import json
import re
import shutil
import tomllib
import unittest

from . import support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


def snapshot(directory):
    return {path.relative_to(directory).as_posix(): path.read_bytes() if path.is_file() else None
            for path in directory.rglob("*")}


def imports(path):
    return re.findall(r"^@(.+)$", path.read_text(encoding="utf-8"), re.MULTILINE)


class OrgTest(support.LauncherTest):
    def setUp(self):
        super().setUp()
        self.org = self.directory / "topic"

    def init(self, *arguments, directory=None):
        target = self.org if directory is None else directory
        self.run_laneboss("org", "init", target, *arguments)
        return target

    def validate(self, directory=None):
        return self.run_laneboss("org", "validate", self.org if directory is None else directory)

    def problem(self, expected, *, json_format=False):
        extra = ("--format", "json") if json_format else ()
        result = self.run_laneboss("org", "validate", self.org, *extra, code=2)
        if json_format:
            report = json.loads(result.stdout)
            self.assertIs(report["valid"], False)
            self.assertGreater(len(report["problems"]), 0)
            self.assertTrue(all(set(item) == {"path", "message"} for item in report["problems"]))
            diagnostic = json.dumps(report)
            self.assertEqual(result.stderr, "")
        else:
            self.assertEqual(result.stdout, "")
            diagnostic = result.stderr
            self.assertTrue(all(": " in line for line in diagnostic.splitlines()))
        self.assertIn(expected, diagnostic)
        return result

    def test_init_tree_and_reinit(self):
        selections = (("3-6", {3, 4, 5, 6}), ("3,5", {3, 5}), ("4-5", {4, 5}), ("6", {6}))
        for index, (selection, levels) in enumerate(selections):
            with self.subTest(levels=selection):
                org = self.directory / ("topic-" + str(index))
                self.init("--levels", selection, "--name", "research", directory=org)
                home = org / ".laneboss"
                self.assertEqual({path.name for path in org.iterdir()},
                                 {"CLAUDE.md", "AGENTS.md", "worktrees", ".laneboss"})
                config = tomllib.loads((home / "org.toml").read_text(encoding="utf-8"))
                self.assertEqual(config["name"], "research")
                self.assertEqual(set(config["levels"]), levels)
                self.assertEqual({path.name for path in home.iterdir()},
                                 {"org.toml", "render-manifest.json", "shared", "instances"}
                                 | {"L" + str(level) for level in levels})
                self.assertEqual({path.name for path in home.iterdir() if re.fullmatch(r"L[0-9]+", path.name)},
                                 {"L" + str(level) for level in levels})
                self.assertEqual({path.name for path in (home / "shared").iterdir()},
                                 {"protocol", "hooks", "tools", "services", "refusals"})
                for level in levels:
                    level_dir = home / ("L" + str(level))
                    self.assertEqual({path.name for path in level_dir.iterdir()},
                                     {"protocol", "hooks", "tools", "refusals", "CLAUDE.md", "AGENTS.md"})
                    sources = list((level_dir / "protocol").glob("*.md"))
                    self.assertGreater(len(sources), 0)
                    self.assertTrue(all(path.read_text(encoding="utf-8").strip() for path in sources))
                instances = list((home / "instances").iterdir())
                self.assertEqual(len(instances), len(levels))
                seen = set()
                for instance in instances:
                    self.assertEqual({path.name for path in instance.iterdir()},
                                     {"instance.toml", "CLAUDE.md", "AGENTS.md", "state", "hooks", ".claude", ".codex"})
                    data = tomllib.loads((instance / "instance.toml").read_text(encoding="utf-8"))
                    self.assertEqual(data["name"], instance.name)
                    seen.add(data["level"])
                    for filename in ("CLAUDE.md", "AGENTS.md", "instance.toml"):
                        self.assertTrue((instance / filename).is_file())
                    self.assertTrue((instance / "state").is_dir())
                self.assertEqual(seen, levels)
                self.assertTrue(list((home / "shared" / "protocol").glob("*.md")))
                self.assertTrue((org / "worktrees").is_dir())
                self.validate(org)
                before = snapshot(org)
                self.run_laneboss("org", "init", org, code=2)
                self.assertEqual(snapshot(org), before)

    def test_defaults_and_existing_repo(self):
        (self.org / ".laneboss").mkdir(parents=True)
        repository = self.org / "project"
        repository.mkdir()
        original = repository / "README.md"
        original.write_text("# A research project\n", encoding="utf-8")
        self.init()
        self.assertEqual(tomllib.loads((self.org / ".laneboss" / "org.toml").read_text())["levels"],
                         [3, 4, 5, 6])
        self.assertEqual(original.read_text(), "# A research project\n")
        self.validate()

    def test_init_refuses_existing_rules(self):
        control = self.init(directory=self.directory / "valid-control")
        self.validate(control)
        for filename in (".laneboss/keep.md", "CLAUDE.md", "AGENTS.md"):
            with self.subTest(filename=filename):
                org = self.directory / ("existing-" + filename.replace("/", "-"))
                target = org / filename
                target.parent.mkdir(parents=True)
                target.write_text("Keep these rules.\n", encoding="utf-8")
                before = snapshot(org)
                self.run_laneboss("org", "init", org, code=2)
                self.assertEqual(snapshot(org), before)

    def test_instance_level_and_secret_names(self):
        self.init()
        shared = self.org / ".laneboss" / "shared" / "protocol"
        for path in shared.glob("*.md"):
            with path.open("a", encoding="utf-8") as stream:
                stream.write("\nShared instruction marker.\n")
        for level in (3, 4, 5, 6):
            source = self.org / ".laneboss" / ("L" + str(level)) / "protocol" / "extra.md"
            source.write_text("Rule for level {} only.\n".format(level), encoding="utf-8")
        self.run_laneboss("org", "render", self.org)
        self.run_laneboss("org", "instance", "add", self.org, "L4-review", "--level", "4", "--role", "reviewer",
                         "--secret", "REVIEW_API_KEY", "--secret", "REVIEW_CHAT_TOKEN")
        instance = self.org / ".laneboss" / "instances" / "L4-review"
        data = tomllib.loads((instance / "instance.toml").read_text())
        self.assertEqual(data["name"], "L4-review")
        self.assertEqual(data["level"], 4)
        self.assertEqual(data["role"], "reviewer")
        self.assertNotIn("discord_channel_id", data)
        self.assertEqual(data["secrets"], ["REVIEW_API_KEY", "REVIEW_CHAT_TOKEN"])
        self.assertEqual(data["services"], [])
        self.assertEqual(data["writable_repos"], [])
        self.assertEqual(data["allowed_tools"], [])
        self.assertTrue((instance / "state").is_dir())
        imported = imports(instance / "CLAUDE.md")
        self.assertEqual(len(imported), 2)
        self.assertIn("../../L4/CLAUDE.md", imported)
        self.assertTrue(all((instance / item).resolve().is_file() for item in imported))
        codex = (instance / "AGENTS.md").read_text()
        self.assertIn("Shared instruction marker.", codex)
        self.assertIn("Rule for level 4 only.", codex)
        for level in (3, 5, 6):
            self.assertNotIn("Rule for level {} only.".format(level), codex)
        self.assertEqual(imports(instance / "AGENTS.md"), [])
        self.validate()
        before = snapshot(self.org)
        self.run_laneboss("org", "instance", "add", self.org, "L4-review", "--level", "4", "--role", "reviewer",
                         code=2)
        self.assertEqual(snapshot(self.org), before)
        # Only L5 and L6 talk to the owner: an L3 or L4 instance with a Discord channel is refused, nothing written.
        for level in ("3", "4"):
            with self.subTest(channel_level=level):
                result = self.run_laneboss("org", "instance", "add", self.org, "L" + level + "-chat", "--level", level,
                                           "--role", "reviewer", "--discord-channel", "123456789012345678", code=2)
                self.assertIn("gets no Discord channel", result.stderr)
                self.assertEqual(snapshot(self.org), before)

    def test_instance_invalid_inputs(self):
        self.init("--levels", "5")
        before = snapshot(self.org)
        for name, level, extra in (("L4-review", "4", ()), ("../escape", "5", ()),
                                   ("review", "5", ("--secret", "not-a-secret-name")),
                                   ("review", "5", ("--discord-channel", "not-an-id"))):
            with self.subTest(name=name, level=level, extra=extra):
                self.run_laneboss("org", "instance", "add", self.org, name, "--level", level, "--role", "reviewer",
                                 *extra, code=2)
                self.assertEqual(snapshot(self.org), before)

    def test_instance_defaults_are_data(self):
        self.init()
        config = self.org / ".laneboss" / "org.toml"
        text = config.read_text()
        values = {"services": ["local-gateway"], "secrets": ["BASE_TOKEN"],
                  "writable_repos": ["future-repo", "worktrees/future"], "allowed_tools": ["shell", "file.write"]}
        for key, value in values.items():
            self.assertIn(key + " = []", text)
            text = text.replace(key + " = []", key + " = " + json.dumps(value))
        text += '\ndiscord_channel_id = "123456789012345678"\n'
        config.write_text(text, encoding="utf-8")
        self.validate()
        self.run_laneboss("org", "instance", "add", self.org, "L5-review", "--level", "5", "--role", "reviewer",
                         "--discord-channel", "234567890123456789", "--secret", "TASK_API_KEY")
        target = self.org / ".laneboss" / "instances" / "L5-review" / "instance.toml"
        data = tomllib.loads(target.read_text())
        self.assertEqual(data["services"], values["services"])
        self.assertEqual(data["secrets"], ["BASE_TOKEN", "TASK_API_KEY"])
        self.assertEqual(data["writable_repos"], values["writable_repos"])
        self.assertEqual(data["allowed_tools"], values["allowed_tools"])
        self.assertEqual(data["discord_channel_id"], "234567890123456789")
        self.assertFalse((self.org / "future-repo").exists())
        self.validate()
        # The org default channel is for L5/L6 only; a new L4 inherits the other defaults but no channel.
        self.run_laneboss("org", "instance", "add", self.org, "L4-check", "--level", "4", "--role", "reviewer")
        lower = tomllib.loads((self.org / ".laneboss" / "instances" / "L4-check" / "instance.toml").read_text())
        self.assertNotIn("discord_channel_id", lower)
        self.assertEqual(lower["services"], values["services"])
        self.validate()

    def test_render_idempotence_and_imports(self):
        self.init()
        before = snapshot(self.org)
        times = {path: (self.org / path).stat().st_mtime_ns for path in before}
        self.run_laneboss("org", "render", self.org)
        self.run_laneboss("org", "render", self.org)
        self.assertEqual(snapshot(self.org), before)
        self.assertEqual({path: (self.org / path).stat().st_mtime_ns for path in before}, times)
        files = list(self.org.rglob("CLAUDE.md"))
        self.assertGreater(len(files), 1)
        for path in files:
            with self.subTest(path=path.relative_to(self.org)):
                self.assertGreater(len(imports(path)), 0)
                for item in imports(path):
                    resolved = (path.parent / item).resolve()
                    self.assertTrue(resolved.is_file(), item)
                    self.assertTrue(resolved.is_relative_to(self.org))
                self.assertEqual(imports(path.with_name("AGENTS.md")), [])
        self.validate()

    def test_render_sources_and_notes(self):
        self.init()
        source = self.org / ".laneboss" / "L5" / "protocol" / "new-rule.md"
        source.write_text("# A new rule\n\nRecord the observation before deciding.\n", encoding="utf-8")
        instance = self.org / ".laneboss" / "instances" / "L5-top"
        notes = instance / "state" / "notes.md"
        notes.write_text("# Notes\n\nTrack the next review here.\n", encoding="utf-8")
        self.run_laneboss("org", "render", self.org)
        self.assertIn("@protocol/new-rule.md", (source.parents[1] / "CLAUDE.md").read_text())
        for target in (source.parents[1] / "AGENTS.md", instance / "AGENTS.md"):
            self.assertIn("Record the observation before deciding.", target.read_text())
        self.assertIn("Track the next review here.", (instance / "AGENTS.md").read_text())
        self.assertNotIn("Track the next review here.", (self.org / "AGENTS.md").read_text())
        self.validate()

    def test_render_content_at_every_scope(self):
        self.init()
        home = self.org / ".laneboss"
        config = tomllib.loads((home / "org.toml").read_text())
        shared = home / "shared" / "protocol" / "custom.md"
        shared.write_text("Apply this shared instruction to every level.\n", encoding="utf-8")
        level_text = {}
        for level in config["levels"]:
            source = home / ("L" + str(level)) / "protocol" / "custom.md"
            level_text[level] = "Apply this instruction only at level {}.\n".format(level)
            source.write_text(level_text[level], encoding="utf-8")
        notes_text = {}
        for instance in (home / "instances").iterdir():
            notes_text[instance.name] = "Keep this context only for instance {}.\n".format(instance.name)
            (instance / "state" / "notes.md").write_text(notes_text[instance.name], encoding="utf-8")
        self.run_laneboss("org", "render", self.org)
        root_text = (self.org / "AGENTS.md").read_text()
        self.assertIn(shared.read_text().strip(), root_text)
        for value in level_text.values():
            self.assertNotIn(value.strip(), root_text)
        for level in config["levels"]:
            directory = home / ("L" + str(level))
            text = (directory / "AGENTS.md").read_text()
            sources = list((home / "shared" / "protocol").glob("*.md")) + list((directory / "protocol").glob("*.md"))
            for source in sources:
                self.assertIn(source.read_text().strip(), text)
            for other, value in level_text.items():
                if other != level:
                    self.assertNotIn(value.strip(), text)
        for instance in (home / "instances").iterdir():
            data = tomllib.loads((instance / "instance.toml").read_text())
            text = (instance / "AGENTS.md").read_text()
            self.assertIn(shared.read_text().strip(), text)
            self.assertIn(level_text[data["level"]].strip(), text)
            self.assertIn(notes_text[instance.name].strip(), text)
            for other, value in level_text.items():
                if other != data["level"]:
                    self.assertNotIn(value.strip(), text)
            for name, value in notes_text.items():
                if name != instance.name:
                    self.assertNotIn(value.strip(), text)
        self.validate()

    def test_render_refuses_hand_edits(self):
        self.init()
        source = self.org / ".laneboss" / "shared" / "protocol" / "pending.md"
        source.write_text("A source change waiting for render.\n", encoding="utf-8")
        targets = ("CLAUDE.md", ".laneboss/L4/AGENTS.md", ".laneboss/instances/L5-top/CLAUDE.md")
        for relative in targets:
            with self.subTest(target=relative):
                target = self.org / relative
                original = target.read_bytes()
                target.write_bytes(original + b"\nHand-written generated rule.\n")
                before = snapshot(self.org)
                result = self.run_laneboss("org", "render", self.org, code=2)
                self.assertIn("hand edit", result.stderr)
                self.assertIn("protocol source", result.stderr)
                self.assertEqual(snapshot(self.org), before)
                target.write_bytes(original)
        self.run_laneboss("org", "render", self.org)
        self.validate()

    def test_render_nested_source_import(self):
        self.init()
        level = self.org / ".laneboss" / "L4"
        extra = level / "tools" / "context.txt"
        extra.write_text("Supporting instruction from an imported source.\n", encoding="utf-8")
        source = level / "protocol" / "context.md"
        source.write_text("Before the import.\n@../tools/context.txt\nAfter the import.\n", encoding="utf-8")
        self.run_laneboss("org", "render", self.org)
        for target in (level / "AGENTS.md", self.org / ".laneboss" / "instances" / "L4-stream" / "AGENTS.md"):
            text = target.read_text()
            self.assertIn("Supporting instruction from an imported source.", text)
            self.assertIn("Before the import.", text)
            self.assertIn("After the import.", text)
            self.assertNotIn("@../tools/context.txt", text)
        self.validate()

    def test_render_checks_expanded_secrets(self):
        self.init()
        home = self.org / ".laneboss" / "shared"
        suffix = "invented-body-" + "Z" * 28 + "1"
        prefix = "sk" + "-"
        (home / "tools" / "part.txt").write_text(suffix, encoding="utf-8")
        (home / "protocol" / "joined.md").write_text(prefix + "@../tools/part.txt\n", encoding="utf-8")
        self.validate()
        before = snapshot(self.org)
        result = self.run_laneboss("org", "render", self.org, code=2)
        self.assertIn("secret", result.stderr)
        self.assertNotIn(prefix + suffix, result.stdout + result.stderr)
        self.assertEqual(snapshot(self.org), before)

    def test_render_removes_deleted_source(self):
        self.init()
        level = self.org / ".laneboss" / "L5"
        source = level / "protocol" / "temporary.md"
        source.write_text("An instruction that will be removed.\n", encoding="utf-8")
        self.run_laneboss("org", "render", self.org)
        self.assertIn("An instruction that will be removed.", (level / "AGENTS.md").read_text())
        source.unlink()
        self.run_laneboss("org", "render", self.org)
        self.assertNotIn("An instruction that will be removed.", (level / "AGENTS.md").read_text())
        self.assertNotIn("protocol/temporary.md", imports(level / "CLAUDE.md"))
        self.validate()

    def test_manifest_and_missing_output(self):
        self.init()
        self.validate()
        target = self.org / "AGENTS.md"
        original = target.read_bytes()
        target.unlink()
        self.problem("required file")
        self.run_laneboss("org", "render", self.org)
        self.assertEqual(target.read_bytes(), original)
        manifest = self.org / ".laneboss" / "render-manifest.json"
        saved = manifest.read_bytes()
        manifest.unlink()
        before = snapshot(self.org)
        self.run_laneboss("org", "render", self.org, code=2)
        self.assertEqual(snapshot(self.org), before)
        self.problem("manifest")
        manifest.write_bytes(saved)
        self.validate()

    def test_init_invalid_inputs(self):
        control = self.init(directory=self.directory / "valid-control")
        self.validate(control)
        for index, selection in enumerate(("2-6", "6-3", "3,7", "3 4", "", "eight")):
            with self.subTest(selection=selection):
                target = self.directory / ("invalid-levels-" + str(index))
                self.run_laneboss("org", "init", target, "--levels", selection, code=2)
                self.assertFalse(target.exists())
        self.run_laneboss("org", "init", self.org, "--name", "../escape", code=2)
        self.assertFalse(self.org.exists())

    def test_validate_missing_level(self):
        self.init()
        self.validate()
        shutil.rmtree(self.org / ".laneboss" / "L4")
        self.problem("level")

    def test_validate_disabled_level(self):
        self.init("--levels", "4")
        self.validate()
        target = self.org / ".laneboss" / "instances" / "L4-stream" / "instance.toml"
        target.write_text(target.read_text().replace("level = 4", "level = 5"), encoding="utf-8")
        self.problem("level")

    def test_validate_broken_imports(self):
        self.init()
        self.validate()
        for target in (self.org / "CLAUDE.md", self.org / ".laneboss" / "L3" / "protocol" / "extra.md"):
            with self.subTest(target=target.relative_to(self.org)):
                existed = target.exists()
                original = target.read_bytes() if existed else b""
                target.write_bytes(original + b"\n" + b"@" + b"missing-rule.md\n")
                self.problem("import")
                if existed:
                    target.write_bytes(original)
                else:
                    target.unlink()
        self.validate()

    def test_validate_secret_values(self):
        self.init()
        self.validate()
        # Assemble an invented recognizable token; the source itself contains no token value.
        invented = "gh" + "p_" + "Z" * 32
        targets = (self.org / ".laneboss" / "org.toml",
                   self.org / ".laneboss" / "instances" / "L5-top" / "instance.toml",
                   self.org / ".laneboss" / "shared" / "services" / "unsafe.toml",
                   self.org / ".laneboss" / "L4" / "protocol" / "unsafe.md",
                   self.org / ".laneboss" / "instances" / "L5-top" / "state" / "unsafe.txt")
        for target in targets:
            with self.subTest(target=target.relative_to(self.org)):
                existed = target.exists()
                original = target.read_bytes() if existed else b""
                if target.name == "instance.toml":
                    text = original.decode("utf-8")
                    self.assertIn("secrets = []", text)
                    text = text.replace("secrets = []", "secrets = [" + json.dumps(invented) + "]")
                elif target.suffix == ".toml":
                    text = original.decode("utf-8") + "\ntoken = " + json.dumps(invented) + "\n"
                else:
                    text = original.decode("utf-8") + "\n" + invented + "\n"
                target.write_text(text, encoding="utf-8")
                for json_format in (False, True):
                    result = self.problem("secret", json_format=json_format)
                    self.assertNotIn(invented, result.stdout + result.stderr)
                if existed:
                    target.write_bytes(original)
                else:
                    target.unlink()
        self.validate()

    def test_validate_literal_service_secret(self):
        self.init()
        self.validate()
        target = self.org / ".laneboss" / "shared" / "services" / "unsafe.toml"
        value = "invented" + "-" + "passphrase"
        target.write_text("token = " + json.dumps(value) + "\n", encoding="utf-8")
        result = self.problem("secret")
        self.assertNotIn(value, result.stdout + result.stderr)

    def test_validate_schema_rows(self):
        self.init()
        org_config = self.org / ".laneboss" / "org.toml"
        instance = self.org / ".laneboss" / "instances" / "L5-top" / "instance.toml"
        rows = ((org_config, "schema_version = 1", "schema_version = 2", "schema_version"),
                (org_config, 'name = "topic"', "name = 4", "name"),
                (org_config, 'company = "topic"', "company = []", "company"),
                (org_config, "levels = [3, 4, 5, 6]", "levels = [3, 3, 9]", "levels"),
                (org_config, "levels = [3, 4, 5, 6]", "levels = []", "levels"),
                (org_config, 'owner_channel = "owner"', "owner_channel = 4", "owner_channel"),
                (org_config, 'kind = "keychain"', 'kind = "unknown"', "secret_store.kind"),
                (org_config, 'path = "laneboss/topic"', "path = 4", "secret_store.path"),
                (org_config, "level = 3", "level = 9", "defaults.level"),
                (org_config, "allowed_tools = []", "allowed_tools = [4]", "defaults.allowed_tools"),
                (instance, 'name = "L5-top"', 'name = "other"', "name"),
                (instance, "level = 5", "level = true", "level"),
                (instance, 'role = "top-supervisor"', "role = 5", "role"),
                (instance, "services = []", 'services = "example"', "services"),
                (instance, "secrets = []", 'secrets = ["lowercase"]', "secrets"),
                (instance, "writable_repos = []", 'writable_repos = ["../outside"]', "writable_repos"),
                (instance, "allowed_tools = []", "allowed_tools = [5]", "allowed_tools"))
        for target, old, new, expected in rows:
            with self.subTest(field=expected):
                self.validate()
                original = target.read_text(encoding="utf-8")
                self.assertIn(old, original)
                target.write_text(original.replace(old, new), encoding="utf-8")
                self.problem(expected)
                target.write_text(original, encoding="utf-8")
        self.validate()

    def test_validate_external_secret_store(self):
        self.init()
        self.validate()
        config = self.org / ".laneboss" / "org.toml"
        original = config.read_text()
        outside = self.directory / "external-store.toml"
        invented = "gh" + "p_" + "Z" * 32
        outside.write_text("REVIEW_API_KEY = " + json.dumps(invented) + "\n", encoding="utf-8")
        outside.chmod(0o600)
        configured = original.replace('kind = "keychain"', 'kind = "file"')
        configured = configured.replace('path = "laneboss/topic"', "path = " + json.dumps(str(outside)))
        config.write_text(configured, encoding="utf-8")
        self.validate()
        before = outside.read_bytes()
        config.write_text(configured.replace(json.dumps(str(outside)), json.dumps(str(self.org / "values.toml"))),
                          encoding="utf-8")
        self.problem("outside the org")
        self.assertEqual(outside.read_bytes(), before)
        config.write_text(original, encoding="utf-8")
        self.validate()

    def test_validate_unknown_and_missing(self):
        self.init()
        paths = (self.org / ".laneboss" / "org.toml",
                 self.org / ".laneboss" / "instances" / "L5-top" / "instance.toml")
        for path in paths:
            with self.subTest(path=path.name):
                self.validate()
                original = path.read_text()
                path.write_text(original + "\nunknown_field = 1\n", encoding="utf-8")
                self.problem("unknown field")
                path.write_text("\n".join(line for line in original.splitlines()
                                         if not line.startswith("schema_version =")) + "\n", encoding="utf-8")
                self.problem("schema_version")
                path.write_text(original, encoding="utf-8")
        self.validate()

    def test_validate_import_cycle_and_escape(self):
        self.init()
        self.validate()
        protocol = self.org / ".laneboss" / "L3" / "protocol"
        first, second = protocol / "first.md", protocol / "second.md"
        first.write_text("@second.md\n", encoding="utf-8")
        second.write_text("@first.md\n", encoding="utf-8")
        self.problem("import cycle")
        before = snapshot(self.org)
        self.run_laneboss("org", "render", self.org, code=2)
        self.assertEqual(snapshot(self.org), before)
        second.write_text("An ordinary source.\n", encoding="utf-8")
        outside = self.directory / "outside.md"
        outside.write_text("Outside the org.\n", encoding="utf-8")
        first.write_text("@../../../../outside.md\n", encoding="utf-8")
        self.problem("escapes the org")

    def test_validate_links_and_nontext(self):
        self.init()
        self.validate()
        tools = self.org / ".laneboss" / "shared" / "tools"
        outside = self.directory / "outside-tools"
        outside.mkdir()
        linked = tools / "linked"
        linked.symlink_to(outside, target_is_directory=True)
        self.problem("symbolic link")
        linked.unlink()
        bad = tools / "invalid.txt"
        bad.write_bytes(b"\xff\xfe")
        self.problem("UTF-8")
        bad.unlink()
        self.validate()

    def test_validate_missing_org_json(self):
        result = self.run_laneboss("org", "validate", self.org, "--format", "json", code=2)
        report = json.loads(result.stdout)
        self.assertIs(report["valid"], False)
        self.assertGreater(len(report["problems"]), 0)
        self.assertEqual(result.stderr, "")

    def test_validate_unreadable_directory(self):
        self.init()
        self.validate()
        target = self.org / ".laneboss" / "L3" / "protocol"
        original_mode = target.stat().st_mode & 0o777
        target.chmod(0)
        try:
            self.problem("read", json_format=True)
        finally:
            target.chmod(original_mode)
        self.validate()

    def test_validate_workspace_secrets(self):
        self.init()
        repository = self.org / "project"
        worktree = self.org / "worktrees" / "review"
        repository.mkdir()
        worktree.mkdir()
        binary = repository / "asset.bin"
        binary.write_bytes(b"\xff\xfe\x00neutral asset\x00")
        self.validate()
        invented = "gh" + "p_" + "Z" * 32
        for target in (repository / "settings.txt", worktree / "notes.md", self.org / "notes.txt"):
            with self.subTest(target=target.relative_to(self.org)):
                target.write_text(invented + "\n", encoding="utf-8")
                result = self.problem("secret")
                self.assertNotIn(invented, result.stdout + result.stderr)
                target.unlink()
                self.validate()
        binary.write_bytes(b"\xff\x00" + invented.encode("ascii") + b"\x00")
        result = self.problem("secret")
        self.assertNotIn(invented, result.stdout + result.stderr)
        binary.write_bytes(b"\x00" * (2 * 1024 * 1024 - 2))
        self.validate()
        with binary.open("ab") as stream:
            stream.write(invented.encode("ascii") + b"\x00")
        result = self.problem("secret")
        self.assertNotIn(invented, result.stdout + result.stderr)

    def test_validate_tree_and_service_toml(self):
        for index, relative in enumerate(("worktrees", ".laneboss/shared/hooks", ".laneboss/L6/tools",
                                          ".laneboss/instances/L5-top/state")):
            with self.subTest(missing=relative):
                org = self.init(directory=self.directory / ("missing-" + str(index)))
                self.validate(org)
                shutil.rmtree(org / relative)
                result = self.run_laneboss("org", "validate", org, code=2)
                self.assertIn(relative, result.stderr)
        self.init()
        self.validate()
        bad = self.org / ".laneboss" / "shared" / "services" / "broken.toml"
        bad.write_text("[broken\n", encoding="utf-8")
        self.problem("TOML")

    def test_json_clean_and_all_problems(self):
        self.init()
        result = self.run_laneboss("org", "validate", self.org, "--format", "json")
        self.assertEqual(json.loads(result.stdout), {"valid": True, "problems": []})
        self.assertEqual(result.stderr, "")
        (self.org / ".laneboss" / "L6" / "tools").rmdir()
        source = self.org / ".laneboss" / "L3" / "protocol" / "bad.md"
        source.write_text("@absent.md\n", encoding="utf-8")
        report = json.loads(self.problem("import", json_format=True).stdout)
        self.assertGreaterEqual(len(report["problems"]), 2)
        self.assertTrue(any(item["path"] == ".laneboss/L6/tools" for item in report["problems"]))
        self.assertTrue(any("import" in item["message"] for item in report["problems"]))


if __name__ == "__main__":
    unittest.main()
