"""Org role fallback rows; run only on a disposable Linux test machine.

Supply LANEBOSS_BIN and LANEBOSS_ROW_EVIDENCE as absolute paths. The rows
retain the supplied binary, every CLI argument/output/exit and the org sources.
They start no agent and contact no service. Only the public CLI is exercised.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib
import unittest
import uuid


LIBRARY = Path(__file__).resolve().parents[1] / "internal/rolepolicy/library"


class OrgRoleFallbackRows(unittest.TestCase):
    def setUp(self):
        self.assertEqual(sys.platform, "linux", "these rows require disposable Linux")
        binary = Path(getattr(self, "binary_override", None) or os.environ["LANEBOSS_BIN"])
        evidence = Path(os.environ["LANEBOSS_ROW_EVIDENCE"])
        self.assertTrue(binary.is_absolute() and binary.is_file() and os.access(binary, os.X_OK))
        self.assertTrue(evidence.is_absolute())
        self.directory = evidence / ("lb-org-role-" + self._testMethodName + "-" + uuid.uuid4().hex[:12])
        self.directory.mkdir(parents=True)
        self.binary = self.directory / "laneboss"
        shutil.copy2(binary, self.binary)
        digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        (self.directory / "binary.sha256").write_text(digest + "\n")
        shutil.copy2(Path(__file__), self.directory / "row.py")
        shutil.copytree(LIBRARY, self.directory / "library")
        self.home = self.directory / "home"
        self.home.mkdir()
        self.environment = {"HOME": str(self.home), "PATH": os.defpath, "LC_ALL": "C"}
        self.marker = self.directory / "mutant-reached"
        if getattr(self, "fault_point", None):
            self.environment["LANEBOSS_FAULTS"] = json.dumps({"point": self.fault_point, "marker": str(self.marker)})
        self.org = self.directory / "org"
        self.calls = 0
        self.cli("org", "init", self.org, "--name", "role-fallback")

    def cli(self, *arguments, code=0, reason=None):
        self.calls += 1
        command = [str(self.binary), *map(str, arguments)]
        result = subprocess.run(command, env=self.environment, cwd=self.directory,
                                capture_output=True, timeout=90)
        record = self.directory / ("call-" + str(self.calls))
        record.with_suffix(".input.json").write_text(json.dumps(command) + "\n")
        record.with_suffix(".stdout").write_bytes(result.stdout)
        record.with_suffix(".stderr").write_bytes(result.stderr)
        record.with_suffix(".exit").write_text(str(result.returncode) + "\n")
        self.last_result = result
        self.assertEqual(result.returncode, code, reason or result.stderr.decode() + result.stdout.decode())
        return result

    def snapshot(self):
        return {str(path.relative_to(self.org)): path.read_bytes()
                for path in self.org.rglob("*") if path.is_file()}

    def test_no_template_refused(self):
        """Fails on the legacy bypass: an absent roles directory admits any role."""
        # A pre-fix binary installs roles during init. Move those fixture-only
        # sources aside so both binaries face the same absent-directory gate.
        for level in (3, 4, 5, 6):
            source = self.org / ".laneboss" / ("L" + str(level)) / "roles"
            if source.exists():
                source.rename(self.directory / ("original-roles-L" + str(level)))
        self.cli("org", "render", self.org)
        before = self.snapshot()
        for level in (4, 5):
            with self.subTest(level=level):
                role = "unshipped-" + uuid.uuid4().hex[:12]
                result = self.cli("org", "instance", "add", self.org,
                                  "L" + str(level) + "-unknown", "--level", level,
                                  "--role", role, code=2)
                self.assertIn(b"instance role has no template", result.stderr)
                self.assertIn(b"Instead:", result.stderr)
                self.assertEqual(self.snapshot(), before, "refusal must preserve every org file")

        # A hand-edited instance cannot bypass the same gate during render or
        # validation. Preserve its invalid input and both refusal transcripts.
        instance = self.org / ".laneboss/instances/L4-stream/instance.toml"
        document = tomllib.loads(instance.read_text())
        instance.write_text(instance.read_text().replace(
            "role = " + json.dumps(document["role"]), 'role = "unshipped-review"', 1))
        before = self.snapshot()
        refused = self.cli("org", "render", self.org, code=2)
        self.assertIn(b"instance role has no template", refused.stderr)
        self.assertEqual(self.snapshot(), before)
        report = json.loads(self.cli("org", "validate", self.org, "--format", "json", code=2).stdout)
        self.assertIs(report["valid"], False)
        self.assertTrue(any("role has no template" in item["message"] for item in report["problems"]))

    def test_builtin_reviewer_fallback(self):
        """Fails if init copies roles, fallback omits real sources, or overrides lose."""
        for level in (3, 4, 5, 6):
            self.assertFalse((self.org / ".laneboss" / ("L" + str(level)) / "roles").exists(),
                             "org init must leave installation to org roles init")
        listed = json.loads(self.cli("org", "roles", "list", self.org).stdout)
        effective = {(row["level"], row["role"]): row for row in listed["roles"]}
        for level in (4, 5):
            name = "L" + str(level) + "-review"
            body = (LIBRARY / ("L" + str(level)) / "reviewer.md").read_bytes()
            drivers = tomllib.loads((LIBRARY / ("L" + str(level)) / "reviewer.toml").read_text())["drivers"]
            self.assertTrue(body and drivers)
            self.assertIn(b"change nothing in the reviewed tree", body)
            row = effective[(level, "reviewer")]
            self.assertEqual(row["sha256"], hashlib.sha256(body).hexdigest())
            self.assertEqual(row["drivers"], drivers)
            self.assertEqual(row["path"], "builtin/L" + str(level) + "/roles/reviewer.md")
            self.cli("org", "instance", "add", self.org, name, "--level", level, "--role", "reviewer")
            instance = self.org / ".laneboss/instances" / name
            for filename in ("CLAUDE.md", "AGENTS.md"):
                self.assertIn(body, (instance / filename).read_bytes(),
                              "the real embedded reviewer body must reach both agent rule files")
            self.assertFalse((self.org / ".laneboss" / ("L" + str(level)) / "roles").exists())
        self.cli("org", "validate", self.org)
        before = self.snapshot()
        rendered = json.loads(self.cli("org", "render", self.org).stdout)
        self.assertEqual(rendered, {"ok": True, "changed": 0})
        self.assertEqual(self.snapshot(), before)

        # Explicit installation creates editable sources. The org's real bytes
        # and driver policy must replace, rather than merge with, the fallback.
        installed = json.loads(self.cli("org", "roles", "init", self.org).stdout)
        self.assertIs(installed["ok"], True)
        self.assertGreater(installed["changed"], 0)
        for level in (4, 5):
            source = self.org / ".laneboss" / ("L" + str(level)) / "roles/reviewer.md"
            body = (LIBRARY / ("L" + str(level)) / "reviewer.md").read_bytes()
            self.assertEqual(source.read_bytes(), body)
            body += ("\nOrg review canary " + uuid.uuid4().hex + ".\n").encode()
            source.write_bytes(body)
            driver = "review-driver-" + uuid.uuid4().hex[:12]
            source.with_suffix(".toml").write_text("drivers = " + json.dumps([driver]) + "\n")
            self.cli("org", "render", self.org)
            rows = json.loads(self.cli("org", "roles", "list", self.org).stdout)["roles"]
            selected = next(row for row in rows if (row["level"], row["role"]) == (level, "reviewer"))
            self.assertEqual(selected["drivers"], [driver])
            self.assertEqual(selected["sha256"], hashlib.sha256(body).hexdigest())
            self.assertEqual(selected["path"], ".laneboss/L" + str(level) + "/roles/reviewer.md")
            instance = self.org / ".laneboss/instances" / ("L" + str(level) + "-review")
            self.assertIn(body.rstrip(), (instance / "AGENTS.md").read_bytes())
            self.assertIn("@../../L" + str(level) + "/roles/reviewer.md", (instance / "CLAUDE.md").read_text())
        self.cli("org", "validate", self.org)


if __name__ == "__main__":
    unittest.main()
