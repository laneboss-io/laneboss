"""Worktree isolation through supplied public CLIs and a credential-free runner.

Run only on the disposable Linux test machine with LANEBOSS_BIN pointing to an
already built CLI. LANEBOSS_ROW_EVIDENCE retains the inputs, state and outputs.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
import uuid

import test_report_messages as messages
from test_report_messages import ReportMessageFixture


class WorktreeOverlapRows(ReportMessageFixture, unittest.TestCase):
    fixture_prefix = "lb-wt-claims-"

    def write_config(self, file_channel=False):
        super().write_config(file_channel)
        self.records = self.directory / "adopt-records"
        self.records.mkdir(exist_ok=True)
        command = [sys.executable, "-I", str(Path(messages.__file__).resolve()), "--runner", str(self.binary),
                   "{lane}", "{worktree}", "{session}", "{brief}"]
        configuration = self.config_dir / "config.toml"
        configuration.write_text(
            configuration.read_text(encoding="utf-8") +
            '\n[runners.adopt-runner]\ncommand = ' + json.dumps(command) +
            '\nresume = ' + json.dumps(command) + '\nprompt = "stdin"\n' +
            'records = [{format = "text", paths = [' + json.dumps(str(self.records / "{session}.log")) + ']}]\n',
            encoding="utf-8")

    def attempt(self, action, lane, path):
        brief = self.directory / (lane + ".md")
        brief.write_text("# Worktree scope canary " + uuid.uuid4().hex + "\n", encoding="utf-8")
        args = ["lane", action, "--config", "rows", "--lane", lane, "--worktree", path,
                "--brief", brief, "--model", "row-runner-model-1", "--role", "executor", "--level", "3"]
        if action == "adopt":
            session = str(uuid.uuid4())
            record = self.records / (session + ".log")
            record.write_text("Credential-free stand-in session " + session + "\n", encoding="utf-8")
            old = time.time() - 300
            os.utime(record, (old, old))
            args.extend(["--runner", "adopt-runner", "--session", session])
        else:
            args.extend(["--runner", "row-runner", "--turns"])
        result = self.human.request(args)
        (self.directory / (lane + "-result.json")).write_text(json.dumps(result), encoding="utf-8")
        if result["code"] == 0:
            # Preserve genuine success for cleanup even when a negative row fails.
            self.started_lanes.append(lane)
            self.worktrees[lane] = Path(path)
        return result

    def start_at(self, lane, path):
        path.mkdir(parents=True, exist_ok=True)
        (path / "once").write_text("Read the actual prompt and exit.\n", encoding="utf-8")
        result = self.attempt("start", lane, path)
        self.assert_code(result, 0, "a separate or cleaned worktree must start")
        self.assertEqual(Path(json.loads(result["stdout"])["worktree"]), path.resolve())
        status = self.await_value(lambda: self.idle_status(lane), "the stand-in run did not settle")
        self.assertEqual((status["state"], status["reason"], status["exit_code"]), ("verifying", "exit", 0))
        self.assertEqual(status["live"]["survivors"], 0)
        ready = json.loads((path / "ready.json").read_text(encoding="utf-8"))
        self.assertIn((self.directory / (lane + ".md")).read_bytes(), Path(ready["prompt_file"]).read_bytes())

    def refuse_overlap(self, name, path, owner):
        for action in ("start", "adopt"):
            before = self.events()
            result = self.attempt(action, name + "-" + action, path)
            self.assert_code(result, 2, "an overlapping worktree must be refused by " + action)
            self.assertIn("lane " + owner + "'s worktree", result["stderr"])
            self.assertIn("\nInstead: pick a separate directory, or clean lane " + owner + " first\n",
                          result["stderr"])
            self.assertEqual(self.events(), before, "the overlap refusal changed lane events")

    def git(self, repository, *args):
        result = subprocess.run(["git", "-C", str(repository), *map(str, args)], env=self.environment,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, "Git fixture failed: " + result.stderr)

    def test_recorded_worktree_scopes(self):
        owner = self.directory / "worktrees" / "owner"
        self.start_at("owner", owner)
        child = owner / "child"
        child.mkdir()
        canary = child / "canary.txt"
        original = uuid.uuid4().hex.encode("ascii")
        canary.write_bytes(original)
        self.refuse_overlap("plain-child", child, "owner")
        self.refuse_overlap("plain-parent", owner.parent, "owner")
        self.refuse_overlap("plain-equal", owner, "owner")
        alias = self.directory / "alias"
        alias.symlink_to(child, target_is_directory=True)
        self.refuse_overlap("symlink-child", alias, "owner")
        self.assertEqual(canary.read_bytes(), original)
        self.assertFalse((child / "ready.json").exists(), "a refused runner entered the owner's directory")

        # A shared string prefix is not an overlapping directory scope.
        self.start_at("separate", owner.parent / "owner-extra")

        repository = self.directory / "repository"
        repository.mkdir()
        self.git(repository, "init", "-q")
        self.git(repository, "-c", "user.name=fixture", "-c", "user.email=fixture", "-c", "commit.gpgsign=false",
                 "commit", "-q", "--allow-empty", "-m", "bootstrap")
        linked = self.directory / "linked"
        self.git(repository, "worktree", "add", "-q", "-b", "linked", linked, "HEAD")
        self.start_at("git-owner", linked)
        git_child = linked / "child"
        git_child.mkdir()
        self.refuse_overlap("git-child", git_child, "git-owner")

        decision = self.human.request(["lane", "mark", "--config", "rows", "--lane", "owner", "--state", "abandoned"])
        self.assert_code(decision, 0, "record the demo lane's collection decision")
        cleaned = self.human.request(["lane", "clean", "--config", "rows", "--lane", "owner"])
        self.assert_code(cleaned, 0, "clean the original lane through the public CLI")
        self.assertIs(json.loads(cleaned["stdout"])["pending"], False)
        status = self.human.request(["lane", "status", "--config", "rows", "--lane", "owner"])
        self.assert_code(status, 0, "read the cleaned lane")
        self.assertIs(json.loads(status["stdout"])["cleaned"], True)
        self.started_lanes.remove("owner")
        self.assertTrue(owner.is_dir(), "an externally supplied directory must be retained")
        self.start_at("after-clean", owner)
        self.assertEqual(canary.read_bytes(), original)
        verified = self.human.request(["state", "verify", "--config", "rows"])
        self.assert_code(verified, 0, "verify the resulting store")
        self.assertIs(json.loads(verified["stdout"])["ok"], True)


if __name__ == "__main__":
    unittest.main()
