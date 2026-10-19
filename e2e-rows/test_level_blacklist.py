"""Role blacklist union through both real hooks; disposable Linux only.

Set LANEBOSS_BIN and LANEBOSS_ROW_EVIDENCE to absolute paths. The row retains
the binary, source inputs, hook requests, stdout, stderr and exits. It starts
no agent, executes none of the sample commands and contacts no model service.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
import uuid

from orgsupport import write_rule_source


class LevelBlacklistRows(unittest.TestCase):
    def test_downward_union_both_runners(self):
        self.assertEqual(sys.platform, "linux", "disposable Linux is required")
        binary = Path(os.environ["LANEBOSS_BIN"])
        evidence = Path(os.environ["LANEBOSS_ROW_EVIDENCE"])
        self.assertTrue(binary.is_absolute() and binary.is_file())
        self.assertTrue(evidence.is_absolute())
        self.directory = evidence / ("lb-level-blacklist-" + uuid.uuid4().hex)
        self.directory.mkdir(parents=True)
        self.binary = self.directory / "laneboss"
        shutil.copy2(binary, self.binary)
        (self.directory / "binary.sha256").write_text(hashlib.sha256(self.binary.read_bytes()).hexdigest() + "\n")
        shutil.copy2(__file__, self.directory / "row.py")
        home = self.directory / "home"
        home.mkdir()
        self.environment = {"HOME": str(home), "PATH": os.defpath, "LC_ALL": "C"}
        self.calls = 0
        self.org = self.directory / "org"
        self.cli("org", "init", self.org, "--name", "level-blacklist")
        self.cli("org", "roles", "init", self.org)
        token = "role-" + uuid.uuid4().hex
        routes = {(5, "reviewer"): ("domain-rule", token),
                  (3, "executor"): ("executor-rule", token + "-executor")}
        for (level, role), (identifier, word) in routes.items():
            source = self.org / ".laneboss" / ("L" + str(level)) / "roles" / (role + ".toml")
            write_rule_source(self, source, source.read_text() +
                              '\n[[blacklist]]\nid = ' + json.dumps(identifier) +
                              '\ndescription = "A role-owned command restriction."\nband = "refuse"\n' +
                              'argv_prefix = ["printf", ' + json.dumps(word) + ']\npattern_only = true\n' +
                              'instead = "Leave this call undone."\n')
        # Preserve the independent org-wide applies_to filter alongside the union.
        org_source = self.org / ".laneboss/org.toml"
        write_rule_source(self, org_source, org_source.read_text() +
                          '\n[[hooks.blacklist]]\nid = "org-scope"\ndescription = "A scoped org restriction."\n' +
                          'band = "refuse"\nargv_prefix = ["printf", ' + json.dumps(token + "-org") + ']\n' +
                          'pattern_only = true\n[hooks.blacklist.applies_to]\nlevels = [4]\n')
        self.cli("org", "render", self.org)
        self.assertTrue(json.loads(self.cli("org", "validate", self.org, "--format", "json").stdout)["valid"])
        pairs = [(3, "executor"), (3, "reviewer"), (4, "supervisor"),
                 (4, "reviewer"), (5, "reviewer"), (5, "top"), (6, "supervisor")]
        for level, role in pairs:
            name = "L" + str(level) + "-row-" + role
            self.cli("org", "instance", "add", self.org, name, "--level", level, "--role", role)
            instance = self.org / ".laneboss/instances" / name
            for runner in ("claude", "codex"):
                for word, deny, identifier, origin in (
                        (token, level < 5 or (level == 5 and role == "reviewer"), "domain-rule", "(L5, reviewer)"),
                        (token + "-executor", level == 3 and role == "executor", "executor-rule", "(L3, executor)"),
                        (token + "-org", level == 4, "org-scope", ""),
                        (token + "-control", False, "", "")):
                    with self.subTest(level=level, role=role, runner=runner, word=word):
                        tool, field = ("Bash", "command") if runner == "claude" else ("functions.exec_command", "cmd")
                        event = {"hook_event_name": "PreToolUse", "cwd": str(instance),
                                 "tool_name": tool, "tool_input": {field: "printf " + word}}
                        result = self.cli("org", "hook", "--runner", runner, "--instance", instance,
                                          stdin=json.dumps(event).encode())
                        output = json.loads(result.stdout)["hookSpecificOutput"]
                        self.assertEqual(output["permissionDecision"], "deny" if deny else "allow")
                        if deny:
                            reason = output["permissionDecisionReason"]
                            self.assertIn("[" + identifier + "] Refuses:", reason)
                            if origin:
                                self.assertIn(origin, reason)
                                self.assertIn("Instead: Leave this call undone.", reason)
        # Validation must reject a malformed role entry before publishing hooks.
        source = self.org / ".laneboss/L5/roles/reviewer.toml"
        good = source.read_text()
        write_rule_source(self, source, good.replace('band = "refuse"', 'band = "allow"'))
        report = json.loads(self.cli("org", "validate", self.org, "--format", "json", code=2).stdout)
        self.assertFalse(report["valid"])
        self.assertTrue(any("band" in problem["message"] for problem in report["problems"]))
        shutil.copy2(source, self.directory / "malformed-role.toml")
        write_rule_source(self, source, good)
        self.cli("org", "render", self.org)

    def cli(self, *arguments, stdin=b"", code=0):
        self.calls += 1
        command = [str(self.binary), *map(str, arguments)]
        result = subprocess.run(command, input=stdin, env=self.environment, cwd=self.directory,
                                capture_output=True, timeout=90)
        record = self.directory / ("call-" + str(self.calls))
        record.with_suffix(".argv.json").write_text(json.dumps(command) + "\n")
        record.with_suffix(".stdin").write_bytes(stdin)
        record.with_suffix(".stdout").write_bytes(result.stdout)
        record.with_suffix(".stderr").write_bytes(result.stderr)
        record.with_suffix(".exit").write_text(str(result.returncode) + "\n")
        self.assertEqual(result.returncode, code, result.stderr.decode() + result.stdout.decode())
        return result


if __name__ == "__main__":
    unittest.main()
