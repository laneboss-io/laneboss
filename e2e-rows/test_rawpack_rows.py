"""Raw-task pack rows through the real rendered Claude and Codex org hooks.

Run only on a disposable Linux test machine with LANEBOSS_BIN pointing at an
already built CLI and LANEBOSS_ROW_EVIDENCE naming an absolute evidence root.
Vector command strings are hook inputs; none is executed. The owner harness
initializes private Git workspaces without committing. No vendor CLI, account,
tmux session, network request, or machine is started by these rows.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tomllib
import unittest
import uuid

from orgsupport import write_rule_source
from hookfixtures import install_hook_refusals, install_hook_rules


ROOT = Path(__file__).resolve().parents[1]
CASES = json.loads(Path(__file__).with_name("rawpack.json").read_text(encoding="utf-8"))
RUNNERS = ("claude", "codex")


class RawpackRows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform != "linux":
            raise RuntimeError("rawpack rows require the disposable Linux test machine")
        supplied = os.environ.get("LANEBOSS_BIN", "")
        evidence = os.environ.get("LANEBOSS_ROW_EVIDENCE", "")
        if not supplied or not Path(supplied).is_absolute() or not Path(supplied).is_file():
            raise RuntimeError("LANEBOSS_BIN must name an absolute, already built CLI")
        if not evidence or not Path(evidence).is_absolute():
            raise RuntimeError("LANEBOSS_ROW_EVIDENCE must name an absolute evidence root")
        cls.evidence_root = Path(evidence) / ("lb-rawpack-" + uuid.uuid4().hex)
        cls.evidence_root.mkdir(parents=True)
        cls.binary = cls.evidence_root / "laneboss"
        shutil.copy2(supplied, cls.binary)
        digest = hashlib.sha256(cls.binary.read_bytes()).hexdigest()
        (cls.evidence_root / "binary.sha256").write_text(digest + "  laneboss\n", encoding="utf-8")
        for path in (Path(__file__), Path(__file__).with_name("rawpack.json"),
                     Path(__file__).with_name("hookfixtures.py"), Path(__file__).with_name("orgsupport.py"),
                     ROOT / "internal" / "cli" / "syntax.json"):
            shutil.copy2(path, cls.evidence_root / path.name)

    def setUp(self):
        # Keep both passing and failing fixtures, source edits, requests and
        # outputs. Empty constructed environments inherit no credentials.
        self.directory = self.evidence_root / self._testMethodName
        self.directory.mkdir()
        home = self.directory / "home"
        home.mkdir()
        self.environment = {
            "HOME": str(home), "PATH": "/usr/local/bin:/usr/bin:/bin",
            "LANEBOSS_HOME": str(self.directory / "config"),
            "LANEBOSS_STATE_HOME": str(self.directory / "state"),
        }
        self.sequence = 0
        self.org = self.directory / "org"
        result = self.cli("org", "init", str(self.org), "--name", "rawpack", "--levels", "3-6")
        self.assertTrue(json.loads(result.stdout)["ok"])
        self.source = self.org / ".laneboss" / "org.toml"
        self.initial = self.source.read_text(encoding="utf-8")
        (self.directory / "org.initial.toml").write_text(self.initial, encoding="utf-8")
        self.workspaces = {}
        for instance in ("L3-lane-example", "L4-stream", "L5-top", "L6-super-top"):
            workspace = self.org / "worktrees" / instance
            self.invoke(["git", "init", "-q", str(workspace)])
            self.workspaces[instance] = workspace
            source = self.org / ".laneboss" / "instances" / instance / "instance.toml"
            text = source.read_text(encoding="utf-8")
            self.assertEqual(text.count("writable_repos = []"), 1)
            write_rule_source(self, source, text.replace(
                "writable_repos = []", "writable_repos = " +
                json.dumps([workspace.relative_to(self.org).as_posix()]), 1))
        self.render()
        self.hooks = {}
        for instance in ("L3-lane-example", "L4-stream", "L5-top", "L6-super-top"):
            directory = self.org / ".laneboss" / "instances" / instance
            for runner, vendor_home, filename in (
                ("claude", ".claude", "settings.json"), ("codex", ".codex", "hooks.json"),
            ):
                settings = json.loads((directory / vendor_home / filename).read_text(encoding="utf-8"))
                commands = [entry["command"] for row in settings["hooks"]["PreToolUse"]
                            for entry in row["hooks"] if entry["type"] == "command"]
                self.assertEqual(len(commands), 1)
                words = shlex.split(commands[0])
                self.assertEqual(Path(words[0]).resolve(), self.binary.resolve())
                self.assertEqual(words[1:], ["org", "hook", "--runner", runner,
                                            "--instance", str(directory / "instance.toml")])
                self.hooks[instance, runner] = words

    def invoke(self, arguments, stdin="", cwd=None):
        self.sequence += 1
        record = self.directory / ("call-{:04d}".format(self.sequence))
        record.with_suffix(".input.json").write_text(
            json.dumps({"argv": arguments, "stdin": stdin, "cwd": str(cwd or self.directory)}, indent=2),
            encoding="utf-8",
        )
        result = subprocess.run(arguments, input=stdin, cwd=cwd or self.directory,
                                env=self.environment, capture_output=True, text=True,
                                encoding="utf-8", timeout=90)
        record.with_suffix(".stdout").write_text(result.stdout, encoding="utf-8")
        record.with_suffix(".stderr").write_text(result.stderr, encoding="utf-8")
        record.with_suffix(".exit").write_text(str(result.returncode) + "\n", encoding="utf-8")
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def cli(self, *arguments):
        return self.invoke([str(self.binary), *arguments])

    def hook(self, runner, command=None, data=None, instance="L3-lane-example"):
        directory = self.workspaces[instance]
        if data is None:
            tool, field = ("Bash", "command") if runner == "claude" else ("exec_command", "cmd")
            data = {"tool_name": tool, "tool_input": {field: command}}
        event = {"hook_event_name": "PreToolUse", "cwd": str(directory), **data}
        result = self.invoke(self.hooks[instance, runner], json.dumps(event), directory)
        output = json.loads(result.stdout)["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], "PreToolUse")
        return output

    def assert_refusal(self, output, entry, instead):
        self.assertEqual(output["permissionDecision"], "deny", output)
        reason = output["permissionDecisionReason"]
        self.assertTrue(reason.startswith("[{}] Refuses: ".format(entry)), reason)
        self.assertEqual(reason.splitlines()[-1], "Instead: " + instead)

    def render(self):
        self.assertTrue(json.loads(self.cli("org", "render", str(self.org)).stdout)["ok"])
        validation = json.loads(self.cli("org", "validate", str(self.org), "--format", "json").stdout)
        self.assertEqual((validation["valid"], validation["problems"]), (True, []))

    def test_fresh_org_refusals_empty(self):
        for layer in ("shared", "L3", "L4", "L5", "L6"):
            self.assertFalse((self.org / ".laneboss" / layer / "refusals").exists(),
                             "the fresh org must not seed a refusal catalog")
        result = self.cli("org", "refusals", str(self.org), "--format", "json")
        self.assertEqual(json.loads(result.stdout), [], "absent catalogs must produce an empty JSON list")
        self.assertEqual(result.stderr, "", "absent catalogs must not warn")
        result = self.cli("org", "refusals", str(self.org))
        self.assertEqual((result.stdout, result.stderr), ("", ""),
                         "the documented text command must succeed silently with no refusals")
        for layer in ("shared", "L3", "L4", "L5", "L6"):
            self.assertFalse((self.org / ".laneboss" / layer / "refusals").exists(),
                             "listing refusals must not create catalogs")
        # A populated control prevents an unconditional empty-list result from passing.
        install_hook_refusals(self, self.org, "shared", "secret-files")
        records = json.loads(self.cli("org", "refusals", str(self.org), "--format", "json").stdout)
        self.assertEqual([(row["id"], row["source"]) for row in records],
                         [("secret-files", "shared/refusals/secret-files.toml")],
                         "an existing owner-authored refusal must still be listed")

    def test_default_pack_rows(self):
        rows = tomllib.loads(self.initial)["hooks"]["blacklist"]
        self.assertEqual(len(rows), len(CASES))
        self.assertEqual({row["id"] for row in rows}, {case["id"] for case in CASES})
        for instance in ("L3-lane-example", "L4-stream", "L5-top", "L6-super-top"):
            for runner in RUNNERS:
                for case in CASES:
                    with self.subTest(instance=instance, runner=runner, entry=case["id"]):
                        for command in case["refused"]:
                            self.assert_refusal(self.hook(runner, command, instance=instance),
                                                case["id"], case["instead"])
                        for command in case["allowed"]:
                            control = self.hook(runner, command, instance=instance)
                            self.assertEqual(control["permissionDecision"], "allow", control)

    def test_exact_prefixes_and_real_routes(self):
        syntax = json.loads((ROOT / "internal" / "cli" / "syntax.json").read_text(encoding="utf-8"))
        for case in CASES:
            for route in case["instead"].split(" / "):
                node = syntax
                for word in shlex.split(route)[1:]:
                    children = {child["name"]: child for child in node.get("commands", [])}
                    self.assertIn(word, children, "Instead names an undeclared CLI verb")
                    node = children[word]
        rows = tomllib.loads(self.initial)["hooks"]["blacklist"]
        expected = {case["id"]: case for case in CASES}
        for row in rows:
            case = expected[row["id"]]
            self.assertEqual(row["argv_words"], case["words"])
            self.assertNotIn("argv_prefix", row)
            self.assertEqual((row["band"], row["instead"]), ("refuse", case["instead"]))
            self.assertIs(row["pattern_only"], True)
            self.assertTrue(row["description"].strip())
            self.assertNotIn("applies_to", row, "the default pack applies at every level")

    def test_existing_org_explicit_opt_in(self):
        legacy, count = re.subn(r"(?ms)^\[\[hooks\.blacklist\]\]\n.*?(?=^\[|\Z)", "", self.initial)
        self.assertEqual(count, len(CASES))
        # A read-only custom canary checks policy retention without declaring
        # writes to the instance directory and its protected policy children.
        custom = ('\n[[hooks.blacklist]]\nid = "fixture-status"\n'
                  'description = "Block fixture status reads."\nband = "refuse"\n'
                  'argv_prefix = ["git", "status"]\ninstead = "Ask the supervisor."\n')
        legacy += custom
        # Policy edits are direct owner-harness actions, never hook submissions.
        write_rule_source(self, self.source, legacy)
        self.render()
        self.assertEqual(self.source.read_text(encoding="utf-8"), legacy,
                         "render must not silently migrate an existing org")
        for runner in RUNNERS:
            for case in CASES:
                with self.subTest(stage="before-opt-in", runner=runner, entry=case["id"]):
                    # Keep the original raw-call control: the old lane boundary
                    # independently refuses explicit tmux socket access.
                    self.assertEqual(self.hook(runner, case["refused"][0])["permissionDecision"], "allow")
            self.assert_refusal(self.hook(runner, "git status", instance="L5-top"),
                                "fixture-status", "Ask the supervisor.")
            self.assertEqual(self.hook(runner, "git log", instance="L5-top")["permissionDecision"], "allow")
        # Copy the active source entries from a fresh org, retaining custom
        # policy, exactly as the documented owner edit describes.
        opted_in = self.initial + custom
        write_rule_source(self, self.source, opted_in)
        (self.directory / "org.opted-in.toml").write_text(opted_in, encoding="utf-8")
        self.render()
        self.assertEqual(self.source.read_text(encoding="utf-8"), opted_in)
        for runner in RUNNERS:
            for case in CASES:
                with self.subTest(stage="after-opt-in", runner=runner, entry=case["id"]):
                    for command in case["refused"]:
                        self.assert_refusal(self.hook(runner, command), case["id"], case["instead"])
                    for command in case["allowed"]:
                        self.assertEqual(self.hook(runner, command)["permissionDecision"], "allow")
            self.assert_refusal(self.hook(runner, "git status", instance="L5-top"),
                                "fixture-status", "Ask the supervisor.")
            self.assertEqual(self.hook(runner, "git log", instance="L5-top")["permissionDecision"], "allow")

    def test_protected_communication_routes(self):
        shared = self.org / ".laneboss" / "shared" / "state"
        cases = (
            (shared / "lanes" / ("peer-" + uuid.uuid4().hex) / "mail" / "input.md", "laneboss lane send"),
            (shared / "reports" / "terminals" / "human.json", "laneboss report"),
            (shared / "owner-discord.events.top.jsonl", "laneboss report"),
        )
        for runner in RUNNERS:
            for target, route in cases:
                with self.subTest(runner=runner, path=target.name):
                    ordinary = self.workspaces["L3-lane-example"] / (uuid.uuid4().hex + ".md")
                    for path, decision in ((ordinary, "allow"), (target, "deny")):
                        patch = "*** Begin Patch\n*** Add File: " + str(path) + "\n+fixture\n*** End Patch\n"
                        data = ({"tool_name": "Write", "tool_input": {"file_path": str(path), "content": "fixture\n"}}
                                if runner == "claude" else
                                {"tool_name": "apply_patch", "tool_input": {"input": patch}})
                        output = self.hook(runner, data=data)
                        self.assertEqual(output["permissionDecision"], decision, output)
                        if decision == "deny":
                            self.assert_refusal(output, "blacklist:laneboss-files", route)
                    self.assert_refusal(self.hook(runner, "touch " + shlex.quote(str(target))),
                                        "blacklist:laneboss-files", route)
                    control = self.hook(runner, "touch " + shlex.quote(str(ordinary)))
                    self.assertEqual(control["permissionDecision"], "allow", control)
                    self.assertFalse(target.exists(), "the hook must never execute a submitted write")

    def test_legacy_broad_rule_needs_edit(self):
        install_hook_rules(self, self.org, "shared", "declared-writes", "secret-files")
        install_hook_refusals(self, self.org, "shared", "runner-launches")
        source = self.org / ".laneboss" / "shared" / "hooks" / "rules.toml"
        original = source.read_text(encoding="utf-8")
        broad = (original + '\n[[rules]]\nid = "runner-launches"\n'
                 'kind = "command-pattern"\npatterns = [["claude"], ["codex"]]\n')
        write_rule_source(self, source, broad)
        self.render()
        self.assertEqual(source.read_text(encoding="utf-8"), broad,
                         "render must preserve a legacy owner's broad rule")
        for runner in RUNNERS:
            output = self.hook(runner, "codex --version")
            self.assertEqual(output["permissionDecision"], "deny", output)
            self.assertTrue(output["permissionDecisionReason"].startswith("[runner-launches] Refuses:"))
        # This source change is an explicit owner opt-in step, never render's
        # side effect. The pack in org.toml remains in force after the edit.
        write_rule_source(self, source, original)
        self.render()
        self.assertEqual(source.read_text(encoding="utf-8"), original)
        for runner in RUNNERS:
            self.assertEqual(self.hook(runner, "codex --version")["permissionDecision"], "allow")
            case = CASES[0]
            for command in case["refused"]:
                self.assert_refusal(self.hook(runner, command), case["id"], case["instead"])


if __name__ == "__main__":
    unittest.main()
