"""LB-235 hook-boundary rows against an already built CLI, on the test box only.

The real launcher starts L3-L6 stand-ins in real sibling Git worktrees. Hook
events are submitted through the installed CLI from that runner's descendants;
git push and curl are inspected inputs and are never executed. The fixture's
installed policy refuses push and permits the other inspected calls, so those
calls must still pass the independent boundary. No product package is imported
and no binary is built here. Select either restoring mutant with
LANEBOSS_REPORT_MUTANT and a laneboss_faults binary in LANEBOSS_BIN; its normal
row must fail and its supplied LANEBOSS_REPORT_MARKER must exist.
"""

import hashlib
import json
from pathlib import Path
import shlex
import sqlite3
import subprocess
import sys
import tomllib
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orgsupport import ROLES, assert_hook_deprecation, set_hook_mode
from hookfixtures import install_hook_refusals
from reportsupport import POINT_ROWS
from test_report_messages import ReportMessages


MUTANTS = {
    name: POINT_ROWS[name] for name in (
        "orghook-boundary-before-policy", "orghook-boundary-repository-path",
    )
}
WORKTREE_REASON = (
    "refused: lanes may write only inside their recorded worktree; shared message files "
    "require the checked message path\nInstead: report up with laneboss report, "
    "or use lane send for a permitted peer."
)
NETWORK_REASON = (
    "refused: lanes may not request dashboard ports or send outbound messages with a raw "
    "network client\nInstead: report up with laneboss report, or use lane send for a permitted peer."
)
IDENTITY_REASON = (
    "refused: lanes may not detach their process identity with setsid or nohup\n"
    "Instead: report up with laneboss report, or use lane send for a permitted peer."
)
TMUX_REASON = (
    "refused: lanes may not access a lane tmux socket directly\n"
    "Instead: report up with laneboss report, or use lane send for a permitted peer."
)


class OrgHookBoundaryRows(ReportMessages):
    def setUp(self):
        super().setUp()
        self.assertTrue(not self.mutant or self.mutant in MUTANTS, "select a hook-boundary mutant")
        self.org = self.directory / ("org-" + uuid.uuid4().hex[:12])
        result = self.cli("org", "init", self.org, "--levels", "3-6", "--name", "boundary-fixture")
        self.assert_code(result, 0, "initialize the isolated hook-policy sources")
        self.assertTrue(json.loads(result["stdout"])["ok"])
        self.org_home = self.org / ".laneboss"
        install_hook_refusals(self, self.org, "L3", "no-push")
        self.instance = self.org_home / "instances" / "L3-lane-example" / "instance.toml"
        self.repository = self.org / ("repository-" + uuid.uuid4().hex[:12])
        self.repository.mkdir()
        self.git("init", "-q")
        # The sole fixture commit is empty, in the new disposable repository.
        self.git("-c", "user.name=demo", "-c", "user.email=demo", "-c", "commit.gpgsign=false",
                 "commit", "-q", "--allow-empty", "-m", "bootstrap")
        # Runner mailboxes are fixture artifacts. Git still checks and removes
        # the unchanged worktree through lane clean, without a force option.
        (self.repository / ".git" / "info" / "exclude").write_text(
            "/ready.json\n/ready.tmp\n/prompt-*.txt\n/fixture-finish\n/once\n"
            "/request-*.json\n/response-*.json\n/request-*.tmp\n/response-*.tmp\n",
            encoding="utf-8",
        )
        instance_text = self.instance.read_text(encoding="utf-8")
        self.assertEqual(instance_text.count("writable_repos = []"), 1)
        self.instance.write_text(instance_text.replace(
            "writable_repos = []", "writable_repos = " + json.dumps([self.repository.name]), 1,
        ), encoding="utf-8")
        # rules.toml is editable policy data. Generated rules/settings/manifests
        # are produced by org render; the test never hand-edits those files.
        self.write_rule_source(self.org_home / "shared" / "hooks" / "rules.toml",
            "schema_version = 1\nrules = []\n",
        )
        self.write_rule_source(self.org_home / "L3" / "hooks" / "rules.toml",
            'schema_version = 1\n[[rules]]\nid = "no-push"\nkind = "command-pattern"\n'
            'patterns = [["git", "push"]]\n',
        )
        result = self.cli("org", "render", self.org)
        self.assert_code(result, 0, "render the edited fixture sources")
        self.assertTrue(json.loads(result["stdout"])["ok"])
        result = self.cli("org", "validate", self.org, "--format", "json")
        self.assert_code(result, 0, "validate the installed fixture policy")
        validation = json.loads(result["stdout"])
        self.assertTrue(validation["valid"])
        self.assertEqual(validation["problems"], [])
        project = self.config_dir / "projects" / "boundary.toml"
        project.parent.mkdir()
        project.write_text('schema_version = 1\nname = "boundary"\nrepository = ' +
                           json.dumps(str(self.repository)) + "\n", encoding="utf-8")
        result = self.cli("config", "validate", "rows")
        self.assert_code(result, 0, "validate the isolated project configuration")
        self.assertTrue(json.loads(result["stdout"])["valid"])

    def git(self, *args):
        result = subprocess.run(["git", "-C", str(self.repository), *args], env=self.environment,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, "prepare the disposable repository: " + result.stderr)
        return result

    def start_worktree_lane(self, level=3):
        # The inherited report fixture registers its supervisors through the
        # real service issuer in the configured-service matrix.
        lane = "hook-" + uuid.uuid4().hex[:12]
        worktree = self.repository.with_name(self.repository.name + "-" + lane)
        brief = self.directory / (lane + ".md")
        brief.write_text("Wait for the isolated fixture's hook inputs.\n", encoding="utf-8")
        result = self.human.request([
            "lane", "start", "--config", "rows", "--lane", lane, "--project", "boundary",
            "--brief", str(brief), "--runner", "row-runner", "--model", "row-runner-model-1",
            "--role", ROLES[level], "--level", str(level),
        ])
        self.assert_code(result, 0, "start the real lane in its own Git worktree")
        self.started_lanes.append(lane)
        self.worktrees[lane] = worktree
        ready = self.await_value(lambda: json.loads((worktree / "ready.json").read_text())
                                if (worktree / "ready.json").is_file() else None,
                                "the runner never started in the recorded worktree")
        payload = self.lane_events(lane, "lane.started")[-1]["payload"]
        self.assertEqual((payload["level"], payload["worktree"], payload["repository"], payload["branch"]),
                         (level, str(worktree), str(self.repository), lane))
        self.assertTrue((worktree / ".git").is_file(), "the lane must use a separate Git worktree")
        self.assertNotEqual(worktree, self.repository)
        record_path = self.states / "rows" / "lanes" / lane / "runs" / (payload["launch"] + ".json")

        def runner_recorded():
            if not record_path.is_file():
                return None
            record = json.loads(record_path.read_text())
            runner = record.get("runner")
            return record if isinstance(runner, dict) and runner.get("pid") == ready["pid"] else None

        record = self.await_value(runner_recorded, "the actual runner's process identity was never recorded")
        self.assertEqual((record["config"], record["lane"], record["launch"]),
                         ("rows", lane, payload["launch"]))
        return lane, worktree

    def event(self, cwd, tool, data):
        return {"hook_event_name": "PreToolUse", "cwd": str(cwd), "tool_name": tool, "tool_input": data}

    def shell(self, cwd, runner, command):
        tool, field = ("Bash", "command") if runner == "claude" else ("exec_command", "cmd")
        return self.event(cwd, tool, {field: command})

    def write_events(self, worktree, target):
        patch = "*** Begin Patch\n*** Add File: " + str(target) + "\n+fixture\n*** End Patch\n"
        return (
            ("claude", self.event(worktree, "Write", {"file_path": str(target), "content": "fixture\n"})),
            ("codex", self.event(worktree, "apply_patch", {"input": patch})),
            ("claude", self.shell(worktree, "claude", "touch " + shlex.quote(str(target)))),
            ("codex", self.shell(worktree, "codex", "touch " + shlex.quote(str(target)))),
        )

    def instance_for_level(self, level):
        candidates = [path for path in self.org_home.glob("instances/*/instance.toml")
                      if tomllib.loads(path.read_text(encoding="utf-8"))["level"] == level]
        self.assertEqual(len(candidates), 1, "one rendered fixture instance must match the level")
        return candidates[0]

    def hook(self, runner, event, lane=None, point="", instance=None, **options):
        args = ["org", "hook", "--runner", runner, "--instance",
                str(self.instance if instance is None else instance)]
        request = dict(stdin=json.dumps(event), environment=self.faults(point), **options)
        result = (self.human.request(args, **request) if lane is None else
                  self.lane_request(lane, args, **request))
        self.assert_code(result, 0, "inspect the actual hook input through the built CLI")
        output = json.loads(result["stdout"])["hookSpecificOutput"]
        self.assertEqual(output["hookEventName"], "PreToolUse")
        self.mutation_reached(point)
        return output

    def test_installed_push_refusal(self):
        """The before-policy mutant must answer with the boundary, failing the stored reason assertion."""
        source = self.org / ".laneboss" / "org.toml"
        set_hook_mode(self, source, "strict")
        rendered = self.cli("org", "render", self.org)
        self.assert_code(rendered, 0, "render the explicit strict precedence fixture")
        assert_hook_deprecation(self, rendered)
        description = tomllib.loads((self.org_home / "L3" / "refusals" / "no-push.toml").read_text())
        expected = ["[{}] Refuses: {}".format(description["id"], description["refuses"]),
                    "Why: " + description["why"]]
        for runner in ("claude", "codex"):
            with self.subTest(runner=runner):
                result = self.hook(runner, self.shell(self.repository, runner, "git push"),
                                   point="orghook-boundary-before-policy")
                self.assertEqual(result["permissionDecision"], "deny")
                self.assertEqual(result["permissionDecisionReason"].splitlines()[:2], expected,
                                 "the installed rule must speak before the boundary")

    def test_recorded_worktree_write_allowed(self):
        """The repository-path mutant must deny these ordinary writes in the real sibling worktree."""
        lane, worktree = self.start_worktree_lane()
        for target in (worktree / ("inside-" + uuid.uuid4().hex[:12]),
                       Path("relative-" + uuid.uuid4().hex[:12])):
            for runner, event in self.write_events(worktree, target):
                for unset in ([], ["LANEBOSS_LANE"]):
                    with self.subTest(runner=runner, tool=event["tool_name"], relative=not target.is_absolute(),
                                      lane_label=not unset):
                        result = self.hook(runner, event, lane=lane,
                                           point="orghook-boundary-repository-path", unset=unset)
                        self.assertEqual(result["permissionDecision"], "allow",
                                         "a recorded lane worktree write must be allowed: " +
                                         result["permissionDecisionReason"])
                        self.assertEqual(result["permissionDecisionReason"], "org policy permits this tool call")

    def test_outside_worktree_write_refused(self):
        """Removing or broadening the boundary must fail, including a write in the original repository."""
        lane, worktree = self.start_worktree_lane()
        targets = (self.repository / ("outside-" + uuid.uuid4().hex[:12]),
                   worktree.with_name(worktree.name + "-other") / "outside",
                   self.org_home / "shared" / ("message-" + uuid.uuid4().hex[:12]))
        for target in targets:
            for runner, event in self.write_events(worktree, target):
                with self.subTest(runner=runner, tool=event["tool_name"], target=target.name):
                    result = self.hook(runner, event, lane=lane, unset=["LANEBOSS_LANE"])
                    self.assertEqual(result["permissionDecision"], "deny")
                    self.assertEqual(result["permissionDecisionReason"], WORKTREE_REASON)
                    self.assertFalse(target.exists(), "hook inspection must never execute the submitted write")

    def test_lane_curl_refused(self):
        """Removing the network boundary or checking opaque commands first must fail the full reason."""
        lane, worktree = self.start_worktree_lane()
        for runner in ("claude", "codex"):
            with self.subTest(runner=runner):
                event = self.shell(worktree, runner, "curl http://127.0.0.1:12345/api/messages")
                result = self.hook(runner, event, lane=lane, unset=["LANEBOSS_LANE"])
                self.assertEqual(result["permissionDecision"], "deny")
                self.assertEqual(result["permissionDecisionReason"], NETWORK_REASON)

    def test_supervisor_writes_and_backstops(self):
        _, worker_tree = self.start_worktree_lane()
        # The submitted Git add is inspection data, never an executed command.
        for level in (4, 5, 6):
            lane, worktree = self.start_worktree_lane(level)
            instance = self.instance_for_level(level)
            target = self.org / "artifacts" / ("issue-" + uuid.uuid4().hex[:12]) / "x.md"
            for runner, event in self.write_events(worktree, target):
                with self.subTest(level=level, runner=runner, tool=event["tool_name"]):
                    output = self.hook(runner, event, lane=lane, instance=instance,
                                       unset=["LANEBOSS_LANE"])
                    self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]),
                                     ("allow", "org policy permits this tool call"))
                    receipt = json.loads((instance.parent / "hooks" / "callbacks.jsonl")
                                         .read_text(encoding="utf-8").splitlines()[-1])
                    self.assertEqual((receipt["runner"], receipt["decision"], receipt["inspection_complete"]),
                                     (runner, "allow", True))
            for runner in ("claude", "codex"):
                if level == 4:
                    output = self.hook(runner, self.shell(worktree, runner,
                                       "git -C " + shlex.quote(str(worker_tree)) + " add f"),
                                       lane=lane, instance=instance)
                    self.assertEqual(output["permissionDecision"], "allow", output["permissionDecisionReason"])
                for command, reason in (
                    ("curl https://example.invalid", NETWORK_REASON),
                    ("nohup true", IDENTITY_REASON),
                    ("setsid true", IDENTITY_REASON),
                    ("tmux -S " + shlex.quote(str(worktree / "socket")) + " list-sessions", TMUX_REASON),
                ):
                    output = self.hook(runner, self.shell(worktree, runner, command),
                                       lane=lane, instance=instance)
                    self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]),
                                     ("deny", reason))
                if level == 5:
                    output = self.hook(runner, self.shell(worktree, runner,
                                       "printf x > " + shlex.quote(str(self.org_home / "org.toml"))),
                                       lane=lane, instance=instance)
                    self.assertEqual(output["permissionDecision"], "deny")
                    self.assertTrue(output["permissionDecisionReason"].startswith("[blacklist:laneboss-files] Refuses:"))
            self.assertFalse(target.exists(), "hook inspection must never execute the artifact write")

    def test_unknown_level_bounded(self):
        lane, worktree = self.start_worktree_lane(4)
        instance = self.instance_for_level(4)
        event = self.lane_events(lane, "lane.started")[-1]
        # Author a historical input only in this disposable fixture. Preserve
        # the genuine running process record, launch, worktree and all other
        # event bytes; earlier writers omitted these optional metadata fields.
        (self.directory / "legacy-start-before.json").write_text(json.dumps(event), encoding="utf-8")
        payload = dict(event["payload"])
        for key in ("level", "level_source"):
            self.assertIn(key, payload)
            del payload[key]
        historical = dict(event, payload=payload)
        del historical["sha256"]
        canonical = lambda value: json.dumps(value, sort_keys=True, ensure_ascii=False,
                                             separators=(",", ":"), allow_nan=False)
        digest = hashlib.sha256(canonical(historical).encode("utf-8")).hexdigest()
        with sqlite3.connect(self.states / "rows" / "events.sqlite", timeout=10) as store:
            updated = store.execute("UPDATE events SET payload = ?, sha256 = ? WHERE seq = ? AND sha256 = ?",
                                    (canonical(payload), digest, event["seq"], event["sha256"]))
            self.assertEqual(updated.rowcount, 1, "replace exactly this fixture's historical start input")
        verified = self.cli("state", "verify", "--config", "rows")
        self.assert_code(verified, 0, "the historical fixture must retain genuine store integrity")
        self.assertTrue(json.loads(verified["stdout"])["ok"])
        stored = self.lane_events(lane, "lane.started")[-1]
        self.assertNotIn("level", stored["payload"])
        self.assertNotIn("level_source", stored["payload"])
        self.assertEqual(stored["payload"]["settings"], event["payload"]["settings"],
                         "historical level input must preserve the actual run's tool settings")
        (self.directory / "legacy-start-after.json").write_text(json.dumps(stored), encoding="utf-8")
        target = self.org / "artifacts" / "legacy-issue" / "x.md"
        for runner in ("claude", "codex"):
            output = self.hook(runner, self.shell(worktree, runner,
                               "printf x > " + shlex.quote(str(target))), lane=lane, instance=instance)
            self.assertEqual((output["permissionDecision"], output["permissionDecisionReason"]),
                             ("deny", WORKTREE_REASON))
        self.assertFalse(target.exists())

    def test_no_lane_keeps_instance_scope(self):
        """An unrecorded L3 hook keeps the old repository fallback; an environment label grants no lane."""
        for target, decision in ((self.repository / "inside", "allow"),
                                 (self.instance.parent / "outside", "deny")):
            event = self.event(self.instance.parent, "Write", {"file_path": str(target), "content": "fixture"})
            result = self.hook("claude", event)
            self.assertEqual(result["permissionDecision"], decision)
            if decision == "deny":
                self.assertEqual(result["permissionDecisionReason"], WORKTREE_REASON)
        event = self.event(self.instance.parent, "Write", {"file_path": str(self.repository / "inside")})
        result = self.human.request(
            ["org", "hook", "--runner", "claude", "--instance", str(self.instance)],
            stdin=json.dumps(event), environment={"LANEBOSS_LANE": "unrecorded-fixture"},
        )
        self.assert_code(result, 0, "inspect a forged lane label through the CLI")
        output = json.loads(result["stdout"])["hookSpecificOutput"]
        self.assertEqual(output["permissionDecision"], "deny")
        self.assertEqual(output["permissionDecisionReason"].splitlines()[0],
                         "org hook fails closed: layered tools cannot resolve their caller")
        self.assertTrue(any(line.startswith("Instead: ")
                            for line in output["permissionDecisionReason"].splitlines()),
                        "an unresolved layered caller must retain its recovery route")

    def test_invalid_drivers_fail_closed(self):
        """A configuration whose role drivers permit no runner makes the hook refuse, naming the field config validate names."""
        lane, worktree = self.start_worktree_lane()
        event = self.event(worktree, "Write", {"file_path": str(worktree / ("inside-" + uuid.uuid4().hex[:12])),
                                               "content": "fixture\n"})
        allowed = self.hook("claude", event, lane=lane)
        self.assertEqual((allowed["permissionDecision"], allowed["permissionDecisionReason"]),
                         ("allow", "org policy permits this tool call"), "the control write must be allowed")
        # A typo in every role's driver list: no role at any level permits the runner's program any more.
        files = sorted((self.home / "orgs" / self.organisation / ".laneboss").glob("L*/roles/*.toml"))
        self.assertTrue(files, "the configured org holds no role driver file")
        saved = {path: path.read_bytes() for path in files}
        try:
            for path in files:
                path.write_text('drivers = ["no-such-driver"]\n', encoding="utf-8")
            refused = self.hook("claude", event, lane=lane)
            self.assertEqual(refused["permissionDecision"], "deny", "an invalid configuration must never allow a call")
            reason = refused["permissionDecisionReason"]
            self.assertTrue(reason.startswith("org hook fails closed: config invalid: "), reason)
            self.assertIn("Instead:", reason)
            field = reason.splitlines()[0][len("org hook fails closed: config invalid: "):]
            validate = self.cli("config", "validate", "rows")
            self.assert_code(validate, 2, "config validate must refuse the same configuration")
            self.assertIn("config.toml: " + field + ": ", validate["stderr"].splitlines()[0],
                          "config validate must name the field the hook names")
            self.assertEqual(field, "runners")
        finally:
            for path, data in saved.items():
                path.write_bytes(data)
        again = self.hook("claude", event, lane=lane)
        self.assertEqual(again["permissionDecision"], "allow", "the restored drivers must allow the write again")


def load_tests(loader, standard_tests, pattern):
    return unittest.TestSuite(
        OrgHookBoundaryRows(name) for name in sorted(OrgHookBoundaryRows.__dict__)
        if name.startswith("test_")
    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
