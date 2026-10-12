"""B. Configurations: listing, showing, strict validation with key paths, state directory overlap.

Levels. A `[supervisors]` entry carries a `level`, 4, 5 or 6; `role = "mini"` and `role = "top"` are the old spelling of
4 and 5 and are still read. Exactly one of the two keys is present. `landing_authority` names a supervisor of level 5
or 6.
"""

from pathlib import Path
import re
import shutil

from . import support

# The fixture's one [supervisors] entry, the two lines that the level tests replace.
ENTRY = 'level = 5\nrunner = "local"'
LEVEL_KEY = "config.toml: supervisors.top.level: "
VALID = {"valid": True, "configs": ["alpha"]}
NAMES = ("mini-supervisor", "top supervisor", "super top")


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class ConfigurationTest(support.LauncherTest):
    def refused(self, *arguments):
        return self.run_laneboss("config", "validate", *arguments, code=2)

    def write_supervisor(self, lines):
        """The fixture with the lines before `runner` in its [supervisors.top] entry replaced by `lines`."""
        return self.write_config("alpha", replace=[(ENTRY, (lines + "\n" if lines else "") + 'runner = "local"')])

    def write_second(self, lines):
        """The fixture with a second entry; `top` stays at level 5, which the project's landing_authority needs."""
        return self.write_config("alpha", tail='\n[supervisors.second]\n{}\nrunner = "local"\n'.format(lines))

    def test_list_show_validate_and_path(self):
        self.write_config("alpha")
        self.write_config("beta")
        self.assertEqual(self.laneboss_json("config", "list"), ["alpha", "beta"])
        shown = self.laneboss_json("config", "show", "alpha")
        self.assertEqual(shown["name"], "alpha")
        self.assertEqual(shown["config"]["runners"]["local"]["command"][0], "sh")
        self.assertEqual(shown["config"]["routing"]["standard"][0]["model"], "example-model-2")
        self.assertEqual(shown["projects"]["web"]["landing_authority"], "top")
        self.assertEqual(Path(shown["state_dir"]), self.state_home / "alpha")
        self.assertEqual(self.laneboss_json("config", "show", "beta")["name"], "beta")
        self.assertEqual(self.laneboss_json("config", "validate", "--all"), {"valid": True, "configs": ["alpha", "beta"]})
        self.assertEqual(self.laneboss_json("config", "validate", "beta"), {"valid": True, "configs": ["beta"]})
        paths = self.laneboss_json("config", "path", "beta")
        self.assertEqual(Path(paths["config_dir"]), self.home / "configs" / "beta")
        self.assertEqual(Path(paths["config_file"]), self.home / "configs" / "beta" / "config.toml")
        self.assertEqual(Path(paths["state_dir"]), self.state_home / "beta")
        self.assertEqual(Path(paths["store"]).parent, self.state_home / "beta")
        self.run_laneboss("config", "show", "absent", code=2)
        self.run_laneboss("config", "validate", code=2)

    def test_invalid_values_name_key_path(self):
        cases = [
            ("unknown top-level key", {"top": 'colour = "red"'}, "config.toml: colour"),
            ("unknown nested key", {"replace": [('effort = "max"\n\n[[routing.hard]]',
                                                 'effort = "max"\nspeed = 3\n\n[[routing.hard]]')]},
             "config.toml: routing.standard[0].speed"),
            ("wrong type", {"replace": [('command = ["sh", "-c", "exit 0", "{brief}"]', 'command = "sh"')]},
             "config.toml: runners.local.command"),
            ("wrong item type", {"replace": [('accounts = ["account-one", "account-two"]',
                                              'accounts = ["account-one", 2]')]},
             "config.toml: runners.local.accounts[1]"),
            ("wrong integer type", {"replace": [("max_machines = 1", 'max_machines = "one"')]},
             "config.toml: test_environments.cloud.max_machines"),
            ("unsupported schema version", {"replace": [("schema_version = 1\n", "schema_version = 2\n")]},
             "config.toml: schema_version"),
            ("unknown runner", {"replace": [(ENTRY, 'level = 5\nrunner = "absent"')]},
             "config.toml: supervisors.top.runner"),
            ("short model name", {"replace": [('model = "example-model-2"', 'model = "example"')]},
             "config.toml: routing.standard[0].model"),
            ("unlisted secret", {"replace": [('secrets = ["E2E_TEST_KEY"]\n\n[supervisors',
                                              'secrets = ["E2E_OTHER_KEY"]\n\n[supervisors')]},
             "config.toml: runners.local.secrets[0]"),
            ("bad placeholder", {"replace": [('"{brief}"]', '"{secret}"]')]},
             "config.toml: runners.local.command[3]"),
        ]
        for label, options, key_path in cases:
            with self.subTest(label):
                self.write_config("alpha", **options)
                self.assertIn(key_path, self.refused("alpha").stderr)
                self.assertIn(key_path, self.run_laneboss("config", "show", "alpha", code=2).stderr)

    # Levels.

    def test_levels_4_5_and_6_are_accepted(self):
        for level in (4, 5, 6):
            with self.subTest(level=level):
                self.write_second("level = {}".format(level))
                self.assertEqual(self.laneboss_json("config", "validate", "alpha"), VALID)
                shown = self.laneboss_json("config", "show", "alpha")
                self.assertEqual(shown["config"]["supervisors"]["second"]["level"], level)
                self.assertEqual(shown["config"]["supervisors"]["top"]["level"], 5)

    def test_other_levels_are_refused(self):
        cases = [("zero", "0"), ("three", "3"), ("seven", "7"), ("negative", "-1"), ("string", '"5"'),
                 ("float", "5.0"), ("boolean", "true")]
        for label, literal in cases:
            with self.subTest(label):
                self.write_supervisor("level = " + literal)
                for arguments in (("validate", "alpha"), ("show", "alpha")):
                    message = self.run_laneboss("config", *arguments, code=2).stderr
                    self.assertIn(LEVEL_KEY, message)
                    said = message.split(LEVEL_KEY, 1)[1]
                    self.assertRegex(said, r"\b4\b.*\b5\b.*\b6\b", "the message does not name the three levels")
                    for name in NAMES:
                        self.assertIn(name, said)
                    if literal == "3":
                        self.assertIn("level 3 is a lane", said)
                        self.assertIn("a lane is not a [supervisors] entry", said)
                    else:
                        self.assertNotIn("is a lane", said, "only level 3 is explained as a lane")
                    if literal in ("7", "-1"):
                        self.assertNotIn(literal, said, "a refused value is not repeated")

    def test_role_is_the_old_spelling(self):
        for role, level in (("mini", 4), ("top", 5)):
            with self.subTest(role=role):
                self.write_second('role = "{}"'.format(role))
                self.assertEqual(self.laneboss_json("config", "validate", "alpha"), VALID)
                shown = self.laneboss_json("config", "show", "alpha")
                self.assertEqual(shown["config"]["supervisors"]["second"]["level"], level)
        with self.subTest("the fixture's own entry"):
            self.write_supervisor('role = "top"')
            self.assertEqual(self.laneboss_json("config", "validate", "alpha"), VALID)
            shown = self.laneboss_json("config", "show", "alpha")
            self.assertEqual(shown["config"]["supervisors"]["top"]["level"], 5)
        self.write_second('role = "super"')
        self.assertIn("config.toml: supervisors.second.role", self.refused("alpha").stderr)

    def test_one_of_level_and_role(self):
        entry = "config.toml: supervisors.top: "
        self.write_supervisor('level = 5\nrole = "top"')
        message = self.refused("alpha").stderr
        self.assertIn(entry, message)
        said = message.split(entry, 1)[1]
        self.assertIn("level", said)
        self.assertIn("role", said)
        self.write_supervisor("")
        self.assertIn(LEVEL_KEY + "is required", self.refused("alpha").stderr)

    def test_landing_authority_needs_5_or_6(self):
        refusal = "projects/web.toml: landing_authority: must name a supervisor of level 5 or 6"
        for spelling, accepted in (("level = 4", False), ("level = 5", True), ("level = 6", True),
                                   ('role = "mini"', False), ('role = "top"', True)):
            with self.subTest(spelling):
                self.write_supervisor(spelling)
                if accepted:
                    self.assertEqual(self.laneboss_json("config", "validate", "alpha"), VALID)
                else:
                    self.assertIn(refusal, self.refused("alpha").stderr)
        directory = self.write_supervisor("level = 5")
        project = directory / "projects" / "web.toml"
        project.write_text(project.read_text(encoding="utf-8").replace(
            'landing_authority = "top"', 'landing_authority = "absent"'), encoding="utf-8")
        self.assertIn(refusal, self.refused("alpha").stderr)

    def test_bad_names_are_refused(self):
        self.write_config("Bad_Name")
        self.assertIn("name", self.refused("Bad_Name").stderr)
        self.assertIn("name", self.refused("--all").stderr)
        shutil.rmtree(str(self.home / "configs" / "Bad_Name"))
        self.write_config("delta", directory_name="gamma")
        result = self.refused("gamma")
        self.assertIn("config.toml: name", result.stderr)
        self.assertIn("gamma", result.stderr)
        self.assertIn("config.toml: name", self.refused("--all").stderr)

    def test_credential_values_refused(self):
        key_id = "AK" + "IA" + "EXAMPLE7Q2W3E4R5"
        token = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0" + "K1l2M3n4O5p6Q7r8"
        cases = [
            ("cloud identity", {"replace": [('identity = "example-test-identity"', 'identity = "{}"'.format(key_id))]},
             "config.toml: test_environments", key_id),
            ("description", {"replace": [('description = "Invented configuration',
                                          'description = "{} Invented configuration'.format(token))]},
             "config.toml: description", token),
        ]
        for label, options, key_path, secret in cases:
            with self.subTest(label):
                self.write_config("alpha", **options)
                result = self.refused("alpha")
                self.assertIn(key_path, result.stderr)
                self.assertNotIn(key_path + ".", result.stderr, "no key below the top level is printed")
                self.assertNotIn(secret, result.stdout + result.stderr)
        self.write_config("alpha")
        rules = self.home / "configs" / "alpha" / "rules" / "standing.md"
        rules.write_text("# Rules\n\nUse token " + token + " for pushes.\n", encoding="utf-8")
        result = self.refused("alpha")
        self.assertIn("rules/standing.md", result.stderr)
        self.assertNotIn(token, result.stdout + result.stderr)

    def test_state_directory_overlap(self):
        shared = self.directory / "shared-state"
        self.write_config("alpha", state_path=shared)
        self.write_config("beta", state_path=shared)
        self.laneboss_json("config", "validate", "alpha")
        self.laneboss_json("config", "validate", "beta")
        result = self.refused("--all")
        self.assertIn("state.path", result.stderr)
        self.assertIn("alpha", result.stderr)
        self.assertIn("beta", result.stderr)
        self.write_config("beta", state_path=shared / "inner")
        self.assertIn("state.path", self.refused("--all").stderr)
        self.write_config("beta", state_path=self.state_home)
        self.assertIn("state.path", self.refused("beta").stderr)
        self.write_config("beta", state_path=self.state_home / "alpha" / "inner")
        self.assertIn("state.path", self.refused("beta").stderr)
        self.write_config("beta", state_path="relative/state")
        self.assertIn("state.path", self.refused("beta").stderr)
        self.write_config("beta", state_path=self.directory / "beta-state")
        self.assertEqual(self.laneboss_json("config", "validate", "--all")["configs"], ["alpha", "beta"])
        environment = dict(self.environment)
        environment[support.ENV_PREFIX + "STATE_HOME"] = str(self.home / "state")
        self.write_config("gamma")
        result = self.run_laneboss("config", "validate", "gamma", code=2, environment=environment)
        self.assertIn("state.path", result.stderr)
        self.run_laneboss("event", "tail", "--config", "gamma", code=2, environment=environment)

    def test_project_files_are_validated(self):
        cases = [
            ("unknown key", ("rules = [", 'colour = "red"\nrules = ['), "projects/web.toml: colour"),
            ("name mismatch", ('name = "web"', 'name = "other"'), "projects/web.toml: name"),
            ("unknown environment", ('test_environment = "cloud"', 'test_environment = "absent"'),
             "projects/web.toml: test_environment"),
            ("unknown authority", ('landing_authority = "top"', 'landing_authority = "absent"'),
             "projects/web.toml: landing_authority"),
            ("unknown account", ('excluded_accounts = ["account-one"]', 'excluded_accounts = ["absent"]'),
             "projects/web.toml: excluded_accounts[0]"),
            ("unsafe reserved path", ('reserved_paths = ["docs/release-notes.md"]', 'reserved_paths = ["../up"]'),
             "projects/web.toml: reserved_paths[0]"),
            ("duplicate gate", ('"deploy", "e2e"]', '"deploy", "deploy"]'), "projects/web.toml: gates"),
        ]
        for label, (old, new), key_path in cases:
            with self.subTest(label):
                directory = self.write_config("alpha")
                project = directory / "projects" / "web.toml"
                text = project.read_text(encoding="utf-8")
                self.assertIn(old, text)
                project.write_text(text.replace(old, new), encoding="utf-8")
                self.assertIn(key_path, self.refused("alpha").stderr)

    def test_shipped_example_validates(self):
        shutil.copytree(str(support.ROOT / "examples" / "minimal"), str(self.home / "configs" / "example"))
        self.assertEqual(self.laneboss_json("config", "validate", "example"), {"valid": True, "configs": ["example"]})
        shown = self.laneboss_json("config", "show", "example")
        self.assertEqual(shown["name"], "example")
        self.assertEqual(shown["config"]["supervisors"]["top"]["level"], 5)
        text = (support.ROOT / "examples" / "minimal" / "config.toml").read_text(encoding="utf-8")
        self.assertIn("\nlevel = 5\n", text)
        self.assertIsNone(re.search(r"^role\s*=", text, re.MULTILINE), "the example uses the old spelling")


class ResourcesTest(support.LauncherTest):
    """The `[resources.NAME]` table of adapters in config.toml (docs/architecture.md, "Configuration").

    The key is optional and the schema version stays 1; a configuration without it behaves as it does today. A
    `[resources.NAME]` entry validates strictly, every refusal names the file and the key path and repeats no value,
    and `acquire_bound_minutes` must be at least one minute more than `acquire_seconds` rounded up to whole minutes.
    Every expected key path and bound is a literal of the design's table; nothing is read from the code under test.
    """

    ADAPTER = '["example-adapter", "--config", "adapter.toml"]'

    def refused(self, *arguments):
        return self.run_laneboss("config", "validate", *arguments, code=2)

    def with_resource(self, name="example-machine", **fields):
        """The fixture with one `[resources.NAME]` entry, each value a TOML literal, in the order given."""
        body = "".join("{} = {}\n".format(key, value) for key, value in fields.items())
        return self.write_config("alpha", tail="\n[resources.{}]\n{}".format(name, body))

    def valid(self):
        self.assertEqual(self.laneboss_json("config", "validate", "alpha"), VALID)

    def test_without_resources_is_unchanged(self):
        self.write_config("alpha")
        self.valid()
        shown = self.laneboss_json("config", "show", "alpha")
        self.assertNotIn("resources", shown["config"], "the optional table was added to a configuration that has none")

    def test_a_valid_table_is_accepted(self):
        self.with_resource(command=self.ADAPTER, kind='"machine"', hard_cap_minutes="240")
        self.valid()
        table = self.laneboss_json("config", "show", "alpha")["config"]["resources"]["example-machine"]
        self.assertEqual(table["command"], ["example-adapter", "--config", "adapter.toml"])
        self.assertEqual((table["kind"], table["hard_cap_minutes"]), ("machine", 240))
        self.assertNotIn("acquire_seconds", table, "a default was written into the loaded data")

    def test_optional_keys_may_be_left_out(self):
        # With only the three required keys, the documented defaults are in force: acquire_bound_minutes stays at
        # its default 15, which is at least ceil(300 / 60) + 1 = 6 for the default acquire_seconds 300.
        self.with_resource(command=self.ADAPTER, kind='"credential"', hard_cap_minutes="1")
        self.valid()

    def test_documented_defaults_are_accepted(self):
        self.with_resource(command=self.ADAPTER, kind='"machine"', hard_cap_minutes="10080",
                           acquire_seconds="300", describe_seconds="60", release_seconds="120",
                           acquire_bound_minutes="15", read_back_wait_seconds="240", release_by_itself="false")
        self.valid()
        table = self.laneboss_json("config", "show", "alpha")["config"]["resources"]["example-machine"]
        self.assertEqual([(key, table[key]) for key in ("acquire_seconds", "describe_seconds", "release_seconds",
                                                        "acquire_bound_minutes", "read_back_wait_seconds",
                                                        "release_by_itself")],
                         [("acquire_seconds", 300), ("describe_seconds", 60), ("release_seconds", 120),
                          ("acquire_bound_minutes", 15), ("read_back_wait_seconds", 240),
                          ("release_by_itself", False)])

    def test_credential_keys_are_accepted(self):
        # The design's worked entry (docs/architecture.md, "Configuration"), with a credential_env added: every
        # optional key that names something is a valid value and is read back as written.
        self.with_resource(
            description='"A test machine that the example adapter makes."',
            command='["/opt/example/bin/example-adapter", "--config", "/opt/example/adapter.toml"]',
            kind='"machine"', credential_env='"EXAMPLE_CLOUD_KEY"', credential_profile='"example-profile"',
            hard_cap_minutes="240")
        self.valid()
        table = self.laneboss_json("config", "show", "alpha")["config"]["resources"]["example-machine"]
        self.assertEqual(table["description"], "A test machine that the example adapter makes.")
        self.assertEqual(table["credential_env"], "EXAMPLE_CLOUD_KEY")
        self.assertEqual(table["credential_profile"], "example-profile")

    def test_unknown_key_names_the_path(self):
        self.with_resource(command=self.ADAPTER, kind='"machine"', hard_cap_minutes="240", speed='"fast"')
        message = self.refused("alpha").stderr
        self.assertIn("config.toml: resources.example-machine.speed", message)
        self.assertNotIn("fast", message, "a refused value is repeated")

    def test_wrong_type_names_the_path(self):
        cases = [
            ("kind is not a valid word", {"kind": "3"}, "resources.example-machine.kind"),
            ("command is not an array", {"command": '"example-adapter"'}, "resources.example-machine.command"),
            ("command holds a number", {"command": '["example-adapter", 2]'},
             "resources.example-machine.command[1]"),
            ("release_by_itself is not a boolean", {"release_by_itself": '"true"'},
             "resources.example-machine.release_by_itself"),
            ("acquire_seconds is a string", {"acquire_seconds": '"300"'},
             "resources.example-machine.acquire_seconds"),
        ]
        for label, extra, key_path in cases:
            with self.subTest(label):
                fields = {"command": self.ADAPTER, "kind": '"machine"', "hard_cap_minutes": "240"}
                fields.update(extra)
                self.with_resource(**fields)
                message = self.refused("alpha").stderr
                self.assertIn("config.toml: " + key_path, message)

    def test_kind_outside_its_set(self):
        # `kind` is a closed set of words, so a word that is not one of the two is refused as such, not by a type rule.
        self.with_resource(command=self.ADAPTER, kind='"server"', hard_cap_minutes="240")
        message = self.refused("alpha").stderr
        self.assertIn("config.toml: resources.example-machine.kind", message)
        self.assertNotIn("server", message, "a refused value is repeated")

    def test_a_value_outside_its_bound(self):
        cases = [("acquire_seconds", "901"), ("acquire_seconds", "-1"), ("describe_seconds", "301"),
                 ("describe_seconds", "-1"), ("release_seconds", "601"), ("release_seconds", "-1"),
                 ("acquire_bound_minutes", "1441"), ("hard_cap_minutes", "10081"),
                 ("hard_cap_minutes", "-1"), ("read_back_wait_seconds", "3601"),
                 ("read_back_wait_seconds", "-1")]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                fields = {"command": self.ADAPTER, "kind": '"machine"', "hard_cap_minutes": "240"}
                fields[key] = value
                self.with_resource(**fields)
                message = self.refused("alpha").stderr
                self.assertIn("config.toml: resources.example-machine." + key, message)
                self.assertNotIn(value, message, "a refused value is repeated")

    def test_zero_is_below_the_minimum(self):
        # The four keys whose minimum is 1: 0 is one below it, and is refused by the bound, not by the type rule.
        for key in ("acquire_seconds", "describe_seconds", "release_seconds", "hard_cap_minutes"):
            with self.subTest(key=key):
                fields = {"command": self.ADAPTER, "kind": '"machine"', "hard_cap_minutes": "240"}
                fields[key] = "0"
                self.with_resource(**fields)
                message = self.refused("alpha").stderr
                self.assertIn("config.toml: resources.example-machine." + key, message)
                self.assertIn("must be from 1 to", message)

    def test_values_at_their_maximum(self):
        # Each maximum is accepted, and 0 is accepted for the one key whose minimum is 0: the design gives it a
        # meaning ("With 0 it does not wait").
        for key, value in (("describe_seconds", "300"), ("release_seconds", "600"),
                           ("acquire_bound_minutes", "1440"), ("read_back_wait_seconds", "3600"),
                           ("read_back_wait_seconds", "0")):
            with self.subTest(key=key, value=value):
                fields = {"command": self.ADAPTER, "kind": '"machine"', "hard_cap_minutes": "240"}
                fields[key] = value
                self.with_resource(**fields)
                self.valid()

    def test_missing_required_keys(self):
        complete = {"command": self.ADAPTER, "kind": '"machine"', "hard_cap_minutes": "240"}
        for key in ("command", "kind", "hard_cap_minutes"):
            with self.subTest(missing=key):
                self.with_resource(**{name: value for name, value in complete.items() if name != key})
                self.assertIn("config.toml: resources.example-machine.{}: is required".format(key),
                              self.refused("alpha").stderr)

    def test_empty_command_is_refused(self):
        self.with_resource(command="[]", kind='"machine"', hard_cap_minutes="240")
        message = self.refused("alpha").stderr
        self.assertIn("config.toml: resources.example-machine.command", message)
        self.assertIn("must not be empty", message)

    def test_command_must_be_a_name_or_path(self):
        # A relative path passes the array's own checks and is refused by the name-or-path rule, which is the rule
        # this test is named for; the empty string is refused earlier, by the array's non-emptiness check.
        self.with_resource(command='["bin/example-adapter", "describe"]', kind='"machine"', hard_cap_minutes="240")
        message = self.refused("alpha").stderr
        self.assertIn("config.toml: resources.example-machine.command[0]", message)
        self.assertIn("must be a command name or an absolute path", message)
        # A brace is refused by the placeholder rule, a different one.
        self.with_resource(command='["example-adapter", "-c", "{config}"]', kind='"machine"', hard_cap_minutes="240")
        message = self.refused("alpha").stderr
        self.assertIn("config.toml: resources.example-machine.command[2]", message)
        self.assertIn("must not contain braces", message)

    def test_credential_shape_in_the_table(self):
        token = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0" + "K1l2M3n4O5p6Q7r8"
        for label, fields in (("description", {"description": '"{} value"'.format(token)}),
                              ("a command element", {"command": '["example-adapter", "{}"]'.format(token)}),
                              ("credential_profile", {"credential_profile": '"{}"'.format(token)})):
            with self.subTest(label):
                values = {"command": self.ADAPTER, "kind": '"machine"', "hard_cap_minutes": "240"}
                values.update(fields)
                self.with_resource(**values)
                result = self.refused("alpha")
                self.assertIn("config.toml: resources", result.stderr)
                self.assertIn("looks like a credential", result.stderr)
                self.assertNotIn(token, result.stdout + result.stderr)

    def test_credential_env_must_be_a_name(self):
        cases = [("lower case", '"example-profile"', "example-profile"),
                 ("punctuation", '"EXAMPLE-KEY"', "EXAMPLE-KEY"),
                 ("over 64 characters", '"{}"'.format("A" * 65), "A" * 65)]
        for label, literal, value in cases:
            with self.subTest(label):
                self.with_resource(command=self.ADAPTER, kind='"machine"', hard_cap_minutes="240",
                                   credential_env=literal)
                message = self.refused("alpha").stderr
                self.assertIn("config.toml: resources.example-machine.credential_env", message)
                self.assertIn("must match [A-Z][A-Z0-9_]{0,63}", message)
                self.assertNotIn(value, message, "a refused value is repeated")

    def test_credential_env_holds_a_key(self):
        # A cloud access key id matches the name grammar, so only the credential screen refuses it: the case the
        # test plan names for `credential_env` ("a credential shape in each string member").
        key_id = "AK" + "IA" + "EXAMPLE7Q2W3E4R5"
        self.with_resource(command=self.ADAPTER, kind='"machine"', hard_cap_minutes="240",
                           credential_env='"{}"'.format(key_id))
        result = self.refused("alpha")
        self.assertIn("config.toml: resources", result.stderr)
        self.assertIn("looks like a credential", result.stderr)
        self.assertNotIn(key_id, result.stdout + result.stderr)

    def test_credential_env_reserved_names(self):
        for label, name in (("PATH", "PATH"), ("the launcher's own", "LANEBOSS_CONFIG")):
            with self.subTest(label):
                self.with_resource(command=self.ADAPTER, kind='"machine"', hard_cap_minutes="240",
                                   credential_env='"{}"'.format(name))
                message = self.refused("alpha").stderr
                self.assertIn("config.toml: resources.example-machine.credential_env", message)
                if name != "PATH":
                    self.assertNotIn(name, message, "a refused value is repeated")

    def test_credential_profile_grammar(self):
        # A profile name that does not begin with a letter or a digit is refused by the grammar of the key.
        self.with_resource(command=self.ADAPTER, kind='"machine"', hard_cap_minutes="240",
                           credential_profile='"-example"')
        message = self.refused("alpha").stderr
        self.assertIn("config.toml: resources.example-machine.credential_profile", message)
        self.assertIn("must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}", message)

    def test_command_into_another_org(self):
        other = str(self.home / "orgs" / "other" / "tools" / "adapter.sh")
        for index, vector in ((0, '["{}", "describe"]'.format(other)),
                              (2, '["example-adapter", "--config", "{}"]'.format(other))):
            with self.subTest(index=index):
                self.write_config("alpha", top='organisation = "acme"',
                                  tail=('\n[resources.example-machine]\ncommand = {}\nkind = "machine"\n'
                                        'hard_cap_minutes = 240\n'.format(vector)))
                message = self.refused("alpha").stderr
                self.assertIn("config.toml: resources.example-machine.command[{}]".format(index), message)
                self.assertIn("tools are not shared between organisations", message)
                self.assertNotIn(other, message, "the message repeats the path")

    def test_cross_rule_at_the_boundary(self):
        # acquire_bound_minutes = ceil(acquire_seconds / 60) + 1 is accepted.
        for seconds, bound in ((300, 6), (1, 2), (61, 3), (840, 15), (900, 16)):
            with self.subTest(seconds=seconds, bound=bound):
                self.with_resource(command=self.ADAPTER, kind='"machine"', hard_cap_minutes="240",
                                   acquire_seconds=str(seconds), acquire_bound_minutes=str(bound))
                self.valid()
        # The default acquire_seconds (300) sets the same boundary when the key is left out.
        self.with_resource(command=self.ADAPTER, kind='"machine"', hard_cap_minutes="240",
                           acquire_bound_minutes="6")
        self.valid()
        # The default acquire_bound_minutes (15) is compared with the true acquire_seconds when the bound is left
        # out: ceil(840 / 60) + 1 = 15, so this is exactly at the boundary.
        self.with_resource(command=self.ADAPTER, kind='"machine"', hard_cap_minutes="240", acquire_seconds="840")
        self.valid()

    def test_cross_rule_one_minute_below(self):
        cases = [(300, "5"), (1, "1"), (61, "2"), (900, "15")]
        for seconds, bound in cases:
            with self.subTest(seconds=seconds, bound=bound):
                self.with_resource(command=self.ADAPTER, kind='"machine"', hard_cap_minutes="240",
                                   acquire_seconds=str(seconds), acquire_bound_minutes=bound)
                self.assertIn("config.toml: resources.example-machine.acquire_bound_minutes",
                              self.refused("alpha").stderr)
        # With no acquire_seconds the default 300 applies: the same one minute below is refused.
        self.with_resource(command=self.ADAPTER, kind='"machine"', hard_cap_minutes="240",
                           acquire_bound_minutes="5")
        self.assertIn("config.toml: resources.example-machine.acquire_bound_minutes", self.refused("alpha").stderr)
        # With no acquire_bound_minutes the default 15 applies: ceil(900 / 60) + 1 = 16 is above it.
        self.with_resource(command=self.ADAPTER, kind='"machine"', hard_cap_minutes="240", acquire_seconds="900")
        self.assertIn("config.toml: resources.example-machine.acquire_bound_minutes", self.refused("alpha").stderr)
