"""Fail-closed fallback canaries, controls and real decision mutants.

Run only on disposable Linux with LANEBOSS_BIN, LANEBOSS_ROW_EVIDENCE and
LANEBOSS_ROLE_POLICY_FAULTS_BINARY (the laneboss_faults-tagged binary).
All operations use the public CLI. No runner or service is contacted.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_org_role_fallback as support


SOURCE_REASON = "malformed org role sources must refuse instead of passing"
ENTRY_REASON = "an existing org role entry must block built-in fallback"
CEILING_REASON = "built-in drivers must not exceed the org ceiling"
EMPTY_REASON = "an empty org ceiling must refuse every built-in driver"


class GuardRows(unittest.TestCase):
    cli = support.OrgRoleFallbackRows.cli

    def setUp(self):
        support.OrgRoleFallbackRows.setUp(self)
        shutil.copy2(Path(__file__), self.directory / "guard-row.py")
        self.org = self.directory / "guard-org"
        self.cli("org", "init", self.org, "--levels", "4", "--name", "guard-org")

    def role_pair(self, name="supervisor", drivers=None):
        directory = self.org / ".laneboss/L4/roles"
        directory.mkdir(exist_ok=True)
        body = (support.LIBRARY / "L4" / (name + ".md")).read_bytes()
        body += b"\nOrg instruction canary: preserve this exact source.\n"
        source = directory / (name + ".md")
        source.write_bytes(body)
        source.with_suffix(".toml").write_text("drivers = " + json.dumps(drivers or ["claude"]) + "\n")
        return source, body

    def configuration(self, driver):
        directory = self.home / ".config/laneboss/configs/guards"
        directory.mkdir(parents=True, exist_ok=True)
        text = ('schema_version = 1\nname = "guards"\norg_dir = ' + json.dumps(str(self.org)) + '\n'
                '[runners.agent]\nprompt = "stdin"\ncommand = ' + json.dumps([driver]) + '\naccounts = []\n'
                'records = [{format = "text", paths = ["{log}"]}]\n'
                '[supervisors.top]\nlevel = 5\nrunner = "agent"\n')
        (directory / "config.toml").write_text(text)

    def test_source_error_refused(self):
        source, _ = self.role_pair()
        source.write_text("# Incomplete role source\n\nThis has no required sections.\n")
        result = self.cli("org", "roles", "list", self.org, code=2, reason=SOURCE_REASON)
        self.assertIn(b"role template needs a Scope section", result.stderr)
        rendered = self.cli("org", "render", self.org, code=2)
        self.assertIn(b"role template needs a Scope section", rendered.stderr)

    def test_partial_toml_refused(self):
        source, _ = self.role_pair()
        source.with_suffix(".toml").write_text('drivers = ["claude"]\n[settings\n')
        result = self.cli("org", "roles", "list", self.org, code=2)
        self.assertIn(b".laneboss/L4/roles/supervisor.toml: must be valid TOML", result.stderr)
        self.cli("org", "render", self.org, code=2)

    def test_unreadable_entry_refused(self):
        source, _ = self.role_pair()
        original = self.directory / "saved-source.md"
        source.rename(original)
        source.symlink_to(source.name)
        result = self.cli("org", "roles", "list", self.org, code=2)
        self.assertIn(b"managed files and directories must not be symbolic links", result.stderr)
        self.cli("org", "render", self.org, code=2)

    def test_source_control(self):
        source, body = self.role_pair()
        self.cli("org", "render", self.org)
        listed = json.loads(self.cli("org", "roles", "list", self.org).stdout)
        role = next(row for row in listed["roles"] if (row["level"], row["role"]) == (4, "supervisor"))
        self.assertEqual(role["sha256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(role["path"], ".laneboss/L4/roles/" + source.name)
        rules = self.org / ".laneboss/instances/L4-stream/AGENTS.md"
        self.assertIn(body.rstrip(), rules.read_bytes())

    def test_existing_entry_refused(self):
        directory = self.org / ".laneboss/L4/roles"
        directory.mkdir()
        (directory / "reviewer.toml").write_text('drivers = ["claude"]\n')
        result = self.cli("org", "roles", "list", self.org, code=2, reason=ENTRY_REASON)
        self.assertIn(b"driver file has no Markdown role template", result.stderr)

    def test_absent_entry_control(self):
        listed = json.loads(self.cli("org", "roles", "list", self.org).stdout)
        role = next(row for row in listed["roles"] if (row["level"], row["role"]) == (4, "reviewer"))
        self.assertEqual(role["path"], "builtin/L4/roles/reviewer.md")
        self.assertIn("codex", role["drivers"])
        source, body = self.role_pair("reviewer")
        listed = json.loads(self.cli("org", "roles", "list", self.org).stdout)
        role = next(row for row in listed["roles"] if (row["level"], row["role"]) == (4, "reviewer"))
        self.assertEqual(role["path"], ".laneboss/L4/roles/" + source.name)
        self.assertEqual(role["sha256"], hashlib.sha256(body).hexdigest())

    def test_driver_ceiling_refused(self):
        self.role_pair(drivers=["claude"])
        self.configuration("codex")
        result = self.cli("config", "validate", "guards", code=2, reason=CEILING_REASON)
        self.assertIn(b"no (level, role) permits its driver", result.stderr)

    def test_empty_ceiling_refused(self):
        (self.org / ".laneboss/L4/roles").mkdir()
        self.configuration("claude")
        result = self.cli("config", "validate", "guards", code=2, reason=EMPTY_REASON)
        self.assertIn(b"no (level, role) permits its driver", result.stderr)

    def test_driver_ceiling_control(self):
        self.role_pair(drivers=["claude"])
        self.configuration("claude")
        validated = json.loads(self.cli("config", "validate", "guards").stdout)
        self.assertEqual(validated, {"valid": True, "configs": ["guards"]})
        listed = json.loads(self.cli("org", "roles", "list", self.org).stdout)
        role = next(row for row in listed["roles"] if (row["level"], row["role"]) == (4, "reviewer"))
        self.assertEqual(role["drivers"], ["claude"])


class GuardMutants(unittest.TestCase):
    def test_mutants_fail_at_the_canary(self):
        binary = Path(os.environ["LANEBOSS_ROLE_POLICY_FAULTS_BINARY"])
        self.assertTrue(binary.is_absolute() and binary.is_file() and os.access(binary, os.X_OK))
        cases = (
            ("roles-source-error-open", "test_source_error_refused", "test_source_control", SOURCE_REASON),
            ("roles-entry-fallback-open", "test_existing_entry_refused", "test_absent_entry_control", ENTRY_REASON),
            ("roles-fallback-union", "test_driver_ceiling_refused", "test_driver_ceiling_control", CEILING_REASON),
            ("roles-fallback-union", "test_empty_ceiling_refused", "test_driver_ceiling_control", EMPTY_REASON),
        )
        for point, canary, control, reason in cases:
            with self.subTest(point=point, row=canary):
                mutant = GuardRows(canary)
                mutant.binary_override, mutant.fault_point = str(binary), point
                result = unittest.TestResult()
                mutant.run(result)
                self.assertEqual(result.errors, [], "the mutant must not fail in fixture setup")
                self.assertEqual(len(result.failures), 1, "the actual canary must catch the real fail-open decision")
                self.assertIn(reason, result.failures[0][1].splitlines()[-1],
                              "the mutant must fail for the named reason")
                self.assertTrue(mutant.marker.is_file(), "the actual mutation point must be reached")
                self.assertEqual(mutant.last_result.returncode, 0, "the mutant must actually admit the refused case")
                for row in (control, canary):
                    restored = GuardRows(row)
                    green = unittest.TestResult()
                    restored.run(green)
                    self.assertEqual(green.errors, [])
                    self.assertEqual(green.failures, [], "the release must pass both the control and restored canary")
                (mutant.directory / "mutant-verdict.json").write_text(json.dumps({
                    "point": point, "row": canary, "reason": reason,
                    "failures": [(test.id(), trace) for test, trace in result.failures],
                    "errors": [(test.id(), trace) for test, trace in result.errors],
                }))


if __name__ == "__main__":
    unittest.main()
