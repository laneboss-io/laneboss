"""Public-CLI row for the Codex state allowance. Run only on disposable Linux.

LANEBOSS_BIN and LANEBOSS_ROW_EVIDENCE are required. The inherited fixture
retains actual inputs, state, transcripts, provider calls and binary bytes.
The positive root assertion must fail on 15a3b71, before communication checks.
"""

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import sys
import tomllib
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_orghook_communication import OrgHookCommunicationRows
from test_report_messages import ReportMessages


class CodexStateRows(OrgHookCommunicationRows):
    fixture_prefix = "lb-codex-state-"

    def retain_evidence(self):
        super().retain_evidence()
        for name in ("test_codex_state.py", "codex_state_standin.py"):
            shutil.copyfile(Path(__file__).with_name(name), self.evidence / "row-sources" / name)

    def write_config(self, file_channel=False):
        ReportMessages.write_config(self, file_channel=file_channel)
        org_home = self.home / "orgs" / self.organisation / ".laneboss"
        vendor = self.directory / "vendor-bin"
        vendor.mkdir(exist_ok=True)
        runner = vendor / "codex"
        if not runner.exists():
            shutil.copyfile(Path(__file__).with_name("codex_state_standin.py"), runner)
            runner.chmod(0o755)
            self.environment["PATH"] = str(vendor) + os.pathsep + self.environment["PATH"]
        for path in org_home.glob("L*/roles/*.toml"):
            path.write_text('drivers = ["codex"]\n')
        home = org_home / "instances" / "L3-lane-example" / ".codex"
        self.safe_path = os.pathsep.join([str(self.directory / "bin"), str(vendor), "/usr/bin", "/bin"])
        prefix = ["env", "CODEX_HOME=" + str(home), "PATH=" + self.safe_path,
                  str(runner), "exec", "--sandbox", "workspace-write"]
        # The provider double takes its initial session as the prompt operand;
        # the real brief still arrives on stdin. Later turns name that session.
        templates = {"command": prefix + ["{session}"],
                     "resume": prefix + ["resume", "{session}", "-"]}
        path = self.config_dir / "config.toml"
        text = path.read_text()
        original = tomllib.loads(text)["runners"]["row-runner"]
        for key in ("command", "resume"):
            before = key + " = " + json.dumps(original[key])
            self.assertEqual(text.count(before), 1, "the original runner template must occur once")
            text = text.replace(before, key + " = " + json.dumps(templates[key]), 1)
        path.write_text(text)

    def test_state_cli_and_guard(self):
        home = self.instance.parent / ".codex"
        state = (self.states / "rows").resolve()
        config = tomllib.loads((home / "config.toml").read_text())
        self.assertEqual(config["sandbox_workspace_write"].get("writable_roots"), [str(state)],
                         "lane preparation must render exactly the configuration state root")
        for lane in (self.sender, self.recipient):
            roots = json.loads((self.worktrees[lane] / "sandbox-roots.json").read_text())
            self.assertEqual(roots, [str(self.worktrees[lane]), str(state)],
                             "the stand-in must consume the actual rendered roots")

        # The state grant must work with the installed protected inventory,
        # including the shared deny expansion, rather than only empty rules.
        source = self.org / ".laneboss" / "shared" / "hooks" / "rules.toml"
        self.write_rule_source(source, 'schema_version=1\n[[rules]]\nid="declared-writes"\n'
                               'kind="write-scope"\npaths=' + json.dumps([str(self.worktrees[self.sender])]) +
                               '\ndeny_paths=["{hook_paths}"]\n')
        rendered = self.cli("org", "render", self.org)
        self.assert_code(rendered, 0, "render the shared protected-state policy")
        path, data = self.message_file("Codex state report " + uuid.uuid4().hex)
        result = self.run_hooked("codex", ["report", "--config", "rows", "--file", path])
        outcomes = list(map(json.loads, result["stdout"].splitlines()))
        report_id = next(row["report_id"] for row in outcomes if row["channel"] == "dashboard")
        sent = [event for event in self.events() if event["kind"] == "report.sent"
                and event["payload"]["report_id"] == report_id]
        self.assertEqual(len(sent), 1, "the sandboxed CLI must store a real report")
        self.assertEqual((sent[0]["actor"], sent[0]["payload"]["text"]),
                         ("lane:" + self.sender, data.decode()))
        result = self.run_hooked("codex", ["lane", "send", "--config", "rows", "--lane", self.recipient,
                                           "--file", path])
        self.assertEqual(Path(json.loads(result["stdout"])["file"]).read_bytes(), data)
        mail = [event for event in self.lane_events(self.recipient, "lane.mailed")
                if event["payload"]["sha256"] == hashlib.sha256(data).hexdigest()]
        self.assertEqual(len(mail), 1, "the sandboxed CLI must store a real peer message")
        self.assertEqual(mail[0]["actor"], "lane:" + self.sender)

        target = state / "lanes" / self.recipient / "output.log"
        before = target.read_bytes()
        command = "printf forged > " + shlex.quote(str(target))
        hook, response = self.inspect_hook("codex", command, execute=True)
        self.assertEqual(hook["permissionDecision"], "deny", "direct writes to another lane must be refused")
        self.assertIsNone(response["execution"], "the refused command must never execute")
        self.assertEqual(target.read_bytes(), before, "the other lane's actual state must be unchanged")

        # Control: a shell write in the recorded worktree really executes under
        # Landlock, rather than every write being refused or every response faked.
        control = self.worktrees[self.sender] / "ordinary-control"
        self.run_hooked("codex", [], command="printf ordinary > " + shlex.quote(str(control)))
        self.assertEqual(control.read_bytes(), b"ordinary")


class CodexPathRows(CodexStateRows):
    def set_runner_path(self, value):
        path = self.config_dir / "config.toml"
        text = path.read_text()
        runner = tomllib.loads(text)["runners"]["row-runner"]
        for key in ("command", "resume"):
            before = key + " = " + json.dumps(runner[key])
            updated = ["PATH=" + value if word.startswith("PATH=") else word for word in runner[key]]
            self.assertEqual(sum(word.startswith("PATH=") for word in runner[key]), 1,
                             "the runner must have exactly one explicit effective PATH")
            self.assertEqual(text.count(before), 1)
            text = text.replace(before, key + " = " + json.dumps(updated), 1)
        path.write_text(text)

    def test_path_start_refused(self):
        # Inherited setup has already started two real Codex lanes with the
        # ordinary PATH, including the installed laneboss directory.
        for kind in ("worktree", "state", "empty", "relative", "symlink"):
            with self.subTest(entry=kind):
                lane = "path-" + kind + "-" + uuid.uuid4().hex[:8]
                worktree = self.directory / "worktrees" / lane
                worktree.mkdir()
                self.worktrees[lane] = worktree
                if kind == "worktree":
                    entry = str(worktree)
                elif kind == "state":
                    entry = str((self.states / "rows").resolve())
                elif kind == "empty":
                    entry = ""
                elif kind == "relative":
                    entry = "."
                else:
                    alias = self.directory / (lane + "-alias")
                    alias.symlink_to(worktree, target_is_directory=True)
                    entry = str(alias)
                self.set_runner_path(entry + os.pathsep + self.safe_path)
                brief = worktree / "brief.md"
                brief.write_text("Exercise the checked Codex PATH launch boundary.\n")
                result = self.role("mini-a").request([
                    "lane", "start", "--config", "rows", "--lane", lane,
                    "--worktree", str(worktree), "--brief", str(brief),
                    "--runner", "row-runner", "--model", "row-runner-model-1",
                    "--turns", "--role", "executor", "--level", 3,
                ])
                if result["code"] == 0:
                    # A base-RED launch must still be collected by the fixture.
                    self.started_lanes.append(lane)
                self.assertEqual(result["code"], 2, "a writable effective PATH must refuse lane start")
                self.assertIn("refused: the Codex lane's PATH contains a directory the lane can write:",
                              result["stderr"])
                self.assertIn("Instead: remove that entry from the runner's PATH", result["stderr"])
                self.assertFalse((worktree / "ready.json").exists(),
                                 "the refused PATH must never reach the provider")
        self.set_runner_path(self.safe_path)

    def test_path_later_refused(self):
        ordinary = "path-resume-" + uuid.uuid4().hex[:8]
        worktree = self.directory / "worktrees" / ordinary
        worktree.mkdir()
        self.worktrees[ordinary] = worktree
        (worktree / "once").write_text("Read the prompt and finish this ordinary run.\n")
        brief = worktree / "brief.md"
        brief.write_text("Finish this ordinary Codex run before its resume check.\n")
        result = self.role("mini-a").request([
            "lane", "start", "--config", "rows", "--lane", ordinary,
            "--worktree", str(worktree), "--brief", str(brief),
            "--runner", "row-runner", "--model", "row-runner-model-1",
            "--role", "executor", "--level", 3,
        ])
        self.assert_code(result, 0, "start the ordinary Codex lane for resume")
        self.started_lanes.append(ordinary)
        ordinary_initial = self.await_value(lambda: self.idle_status(ordinary),
                                           "the ordinary Codex run never finished")
        self.assertEqual((ordinary_initial["reason"], ordinary_initial["exit_code"]), ("exit", 0),
                         "the ordinary resume fixture must finish its real run successfully")
        result = self.human.request(["lane", "stop", "--config", "rows", "--lane", self.sender])
        self.assert_code(result, 0, "stop the safe-PATH control before later launches")
        turn_initial = self.await_value(lambda: self.idle_status(self.sender), "the safe-PATH lane never settled")
        message = self.worktrees[self.sender] / "later.md"
        message.write_text("Continue with the checked runner PATH.\n")
        result = self.role("mini-a").request([
            "lane", "send", "--config", "rows", "--lane", self.sender, "--file", str(message)])
        self.assert_code(result, 0, "queue real mail so the next turn reaches its launch gate")
        for verb in ("resume", "turn"):
            with self.subTest(verb=verb):
                lane = ordinary if verb == "resume" else self.sender
                initial = ordinary_initial if verb == "resume" else turn_initial
                self.set_runner_path(str(self.worktrees[lane]) + os.pathsep + self.safe_path)
                args = ["lane", verb, "--config", "rows", "--lane", lane]
                if verb == "resume":
                    args += ["--message", str(message)]
                result = self.role("mini-a").request(args)
                if result["code"] == 0:
                    # Collect an unexpectedly successful base launch before
                    # checking the next route; a failed assertion stays failed.
                    stopped = self.human.request(["lane", "stop", "--config", "rows", "--lane", lane])
                    self.assert_code(stopped, 0, "collect an unexpectedly permitted later launch")
                    self.await_value(lambda: self.idle_status(lane), "the base launch never settled")
                self.assertEqual(result["code"], 2, "a writable effective PATH must refuse a later launch")
                self.assertIn("the Codex lane's PATH contains a directory the lane can write:", result["stderr"])
                current = self.idle_status(lane)
                self.assertIsNotNone(current, "the refused launch must leave the lane idle")
                self.assertEqual(current["run"], initial["run"], "a PATH refusal must not start another run")
        self.set_runner_path(self.safe_path)


def load_tests(loader, standard_tests, pattern):
    return unittest.TestSuite([CodexStateRows("test_state_cli_and_guard"),
                               CodexPathRows("test_path_start_refused"),
                               CodexPathRows("test_path_later_refused")])


if __name__ == "__main__":
    unittest.main(verbosity=2)
