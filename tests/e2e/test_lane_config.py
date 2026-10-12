"""The configuration keys lanes read are validated as strictly as the rest: key paths in errors, never values."""

from . import lanesupport, support


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


RUNNER_ANCHOR = 'secrets = ["E2E_TEST_KEY"]\n\n[supervisors'


def runner_key(text):
    return {"replace": [(RUNNER_ANCHOR, 'secrets = ["E2E_TEST_KEY"]\n' + text + '\n\n[supervisors')]}


class LaneConfigurationTest(support.LauncherTest):
    def test_lane_keys_are_validated(self):
        cases = [
            ("message placeholder in command", {"replace": [('"{brief}"]', '"{brief}", "{message}"]')]},
             "config.toml: runners.local.command[4]"),
            ("unknown placeholder in resume", runner_key('resume = ["sh", "-c", "exit 0", "{answer}"]'),
             "config.toml: runners.local.resume[3]"),
            ("resume program with a placeholder", runner_key('resume = ["{lane}", "x"]'),
             "config.toml: runners.local.resume[0]"),
            ("invalid pattern", runner_key('limit_patterns = ["("]'), "config.toml: runners.local.limit_patterns[0]"),
            ("pattern matching an empty line", runner_key('dropped_patterns = ["a*"]'),
             "config.toml: runners.local.dropped_patterns[0]"),
            ("empty pattern list", runner_key("limit_patterns = []"), "config.toml: runners.local.limit_patterns"),
            ("runner quiet time of zero", runner_key("quiet_seconds = 0"), "config.toml: runners.local.quiet_seconds"),
            ("unknown lanes key", {"tail": "\n[lanes]\ncolour = 1\n"}, "config.toml: lanes.colour"),
            ("negative budget", {"tail": "\n[lanes]\nbudget_minutes = -1\n"}, "config.toml: lanes.budget_minutes"),
            ("budget beyond a week", {"tail": "\n[lanes]\nbudget_minutes = 10081\n"},
             "config.toml: lanes.budget_minutes"),
            ("quiet time as text", {"tail": '\n[lanes]\nquiet_seconds = "ten"\n'}, "config.toml: lanes.quiet_seconds"),
            ("grace of zero", {"tail": "\n[lanes]\nstop_grace_seconds = 0\n"}, "config.toml: lanes.stop_grace_seconds"),
        ]
        for label, options, key_path in cases:
            with self.subTest(label):
                self.write_config("alpha", **options)
                result = self.run_laneboss("config", "validate", "alpha", code=2)
                self.assertIn(key_path, result.stderr)

    def test_lane_keys_are_accepted(self):
        self.write_config("alpha", tail="\n[lanes]\nbudget_minutes = 0.5\nquiet_seconds = 600\nstop_grace_seconds = 5\n",
                          **runner_key('resume = ["sh", "-c", "exit 0", "{message}", "{brief}"]\n'
                                       'limit_patterns = ["^limit reached", "(?i)quota exceeded"]\n'
                                       'dropped_patterns = ["^stream dropped$"]\nquiet_seconds = 1200'))
        self.assertEqual(self.laneboss_json("config", "validate", "alpha"), {"valid": True, "configs": ["alpha"]})
        directory = self.home / "configs" / "beta"
        (directory / "rules").mkdir(parents=True)
        (directory / "projects").mkdir()
        (directory / "config.toml").write_text(lanesupport.lane_config("beta"), encoding="utf-8")
        (directory / "rules" / "standing.md").write_text("# Rules\n", encoding="utf-8")
        (directory / "projects" / "web.toml").write_text(lanesupport.project_text(self.directory), encoding="utf-8")
        self.assertEqual(self.laneboss_json("config", "validate", "beta"), {"valid": True, "configs": ["beta"]})
