"""The configuration keys of refusal detection are validated as strictly as the rest: guards ([[guards]]) and a
runner's session records (records), with key paths in errors and never a value. A guard pattern that is invalid,
matches the empty string or cannot be bounded is refused."""

import re

from . import support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


RUNNER_ANCHOR = 'secrets = ["E2E_TEST_KEY"]\n\n[supervisors'


def runner_key(text):
    return {"replace": [(RUNNER_ANCHOR, 'secrets = ["E2E_TEST_KEY"]\n' + text + '\n\n[supervisors')]}


def guard(text):
    return {"tail": "\n[[guards]]\n" + text + "\n"}


class RefusalConfigurationTest(support.LauncherTest):
    def test_keys_are_validated(self):
        cases = [
            ("guard without a pattern", guard('name = "g"'), "config.toml: guards[0].pattern"),
            ("guard without a name", guard("pattern = '^refused'"), "config.toml: guards[0].name"),
            ("guard with an unknown key", guard('name = "g"\npattern = "^refused"\ncolour = "red"'),
             "config.toml: guards[0].colour"),
            ("guard of an unknown kind", guard('name = "g"\npattern = "^refused"\nkind = "judge"'),
             "config.toml: guards[0].kind"),
            ("guard with a bad name", guard('name = "a guard"\npattern = "^refused"'), "config.toml: guards[0].name"),
            ("invalid pattern", guard('name = "g"\npattern = "(refused"'), "config.toml: guards[0].pattern"),
            ("pattern matching the empty string", guard('name = "g"\npattern = "x*"'), "config.toml: guards[0].pattern"),
            ("pattern with nested repetition", guard('name = "g"\npattern = "^(a+)+$"'),
             "config.toml: guards[0].pattern"),
            ("pattern with a back-reference", guard('name = "g"\npattern = "(ab)c\\\\1"'),
             "config.toml: guards[0].pattern"),
            ("two guards of one name", {"tail": '\n[[guards]]\nname = "g"\npattern = "^a"\n\n[[guards]]\nname = "g"\n'
                                                'pattern = "^b"\n'}, "config.toml: guards[1].name"),
            ("records of an unknown format", runner_key('records = [{format = "other", paths = ["~/x/*.jsonl"]}]'),
             "config.toml: runners.local.records[0].format"),
            ("records without paths", runner_key('records = [{format = "text"}]'),
             "config.toml: runners.local.records[0].paths"),
            ("records with an empty path list", runner_key('records = [{format = "text", paths = []}]'),
             "config.toml: runners.local.records[0].paths"),
            ("a relative record path", runner_key('records = [{format = "claude-code", paths = ["sessions/*.jsonl"]}]'),
             "config.toml: runners.local.records[0].paths[0]"),
            ("an unknown placeholder",
             runner_key('records = [{format = "claude-code", paths = ["~/{unknown}/*.jsonl"]}]'),
             "config.toml: runners.local.records[0].paths[0]"),
            ("the machine placeholder",
             runner_key('records = [{format = "claude-code", paths = ["~/{machine}/*.jsonl"]}]'),
             "config.toml: runners.local.records[0].paths[0]"),
            ("records with an unknown key", runner_key('records = [{format = "text", paths = ["{log}"], deep = 1}]'),
             "config.toml: runners.local.records[0].deep"),
        ]
        for label, options, key_path in cases:
            with self.subTest(label):
                self.write_config("alpha", **options)
                result = self.run_laneboss("config", "validate", "alpha", code=2)
                self.assertIn(key_path, result.stderr)

    def test_keys_are_accepted(self):
        self.write_config("alpha", tail=(
            "\n[[guards]]\nname = \"doc-guard\"\nkind = \"hook\"\n"
            "pattern = '^PreToolUse:[A-Za-z]+ hook error: \\[[^]]*\\]: BLOCKED by doc_guard'\n"
            "\n[[guards]]\nname = \"perm_1\"\nkind = \"permission\"\npattern = '(?i)^permission .* denied'\n"
            "\n[[guards]]\nname = \"harness\"\nkind = \"harness\"\npattern = '^(?:error|refused): [a-z ]+$'\n"),
            **runner_key('records = [{format = "claude-code", paths = ["~/.claude-{account}/projects/*/*.jsonl"]},\n'
                         '           {format = "claude-code", paths = ["/var/sessions/{lane}/**/*.jsonl"]},\n'
                         '           {format = "text", paths = ["{log}"]}]'))
        self.assertEqual(self.laneboss_json("config", "validate", "alpha"), {"valid": True, "configs": ["alpha"]})
        shown = self.laneboss_json("config", "show", "alpha")["config"]
        self.assertEqual([item["name"] for item in shown["guards"]], ["doc-guard", "perm_1", "harness"])
        self.assertEqual([item["format"] for item in shown["runners"]["local"]["records"]],
                         ["claude-code", "claude-code", "text"])

    def test_codex_is_not_offered(self):
        # Decision 2 of fix round 1: the codex format is not supported yet. A configuration that names it is refused
        # with a message that says so and names the way to watch such a runner: text on the run's own log.
        self.write_config("alpha", **runner_key('records = [{format = "codex", paths = ["~/.codex/*.jsonl"]}]'))
        result = self.run_laneboss("config", "validate", "alpha", code=2)
        self.assertIn("config.toml: runners.local.records[0].format", result.stderr)
        self.assertIn("not supported yet", result.stderr)
        self.assertIn("{log}", result.stderr)
        # No code path, fixture or document still offers it: the word appears in the package only in that refusal,
        # nowhere in the stand-in or the refusal tests' support, and in a document only where it says so.
        source = support.ROOT / "src" / "laneboss"
        found = sorted(str(path.relative_to(source)) for path in source.rglob("*.py")
                       if "codex" in path.read_text(encoding="utf-8").lower())
        self.assertEqual(found, ["config.py"])
        for name in ("tests/e2e/sessionstandin.py", "tests/e2e/refusalsupport.py", "examples/minimal/config.toml"):
            self.assertNotIn("codex", (support.ROOT / name).read_text(encoding="utf-8").lower(), name)
        for name in ("docs/architecture.md", "docs/configuration.md", "README.md"):
            for line in (support.ROOT / name).read_text(encoding="utf-8").splitlines():
                if "codex" in line.lower():
                    self.assertIn("not supported", line.lower(), "{}: {}".format(name, line))

    def test_text_reads_only_the_log(self):
        # Fix round 2, ruling R36: format text reads the run's own log and nothing else. A text entry with any other
        # path is refused with a message that says so.
        for paths in ('["{worktree}/guard.log"]', '["{log}", "~/logs/agent.log"]', '["/var/log/{lane}.log"]'):
            with self.subTest(paths):
                self.write_config("alpha", **runner_key('records = [{format = "text", paths = ' + paths + '}]'))
                result = self.run_laneboss("config", "validate", "alpha", code=2)
                self.assertIn("config.toml: runners.local.records[0].paths", result.stderr)
                self.assertIn("{log}", result.stderr)
        self.write_config("alpha", **runner_key('records = [{format = "text", paths = ["{log}"]}]'))
        self.assertEqual(self.laneboss_json("config", "validate", "alpha"), {"valid": True, "configs": ["alpha"]})
        # No document, example or module offers other text files: every text entry they show reads {log}, and none
        # calls text "any log".
        entry = re.compile(r'format\s*=\s*"text"\s*,\s*paths\s*=\s*(\[[^\]]*\])')
        for name in ("README.md", "CHANGELOG.md", "docs/architecture.md", "docs/configuration.md",
                     "examples/minimal/config.toml", "src/laneboss/sessions.py", "src/laneboss/refusals.py",
                     "src/laneboss/config.py", "tests/e2e/sessionstandin.py", "tests/e2e/refusalsupport.py"):
            text = (support.ROOT / name).read_text(encoding="utf-8")
            for paths in entry.findall(text):
                self.assertEqual(paths, '["{log}"]', name)
            self.assertNotIn("any log", text.lower(), name)
