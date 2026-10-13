"""Refusals B and H. After a refused shell write to notes/plan.md, (1) a later shell redirection to that path, (2) the
same command with the matched words removed and (3) the same command split into two each give
lane.workaround_suspected naming the path and the way; (4) a later file-tool write to that path, (5) a later shell write
to another path and (6) a later read of that path give none. Both structured formats go through it."""

import shlex

from . import refusalsupport, support
from .refusalsupport import REFUSED, REWORDED, SPLIT, expected_path, hook, hooked_steps, refused_steps, shell_steps


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class WorkaroundTest(refusalsupport.RefusalTest):
    def check_workarounds(self, fmt, lane):
        steps = [{"open": {}}] + refused_steps(fmt)
        steps += shell_steps("c2", "printf 'ok\\n' > notes/plan.md")
        steps += shell_steps("c3", REWORDED)
        steps += shell_steps("c4", SPLIT[0]) + shell_steps("c5", SPLIT[1])
        steps += [{"write": {"id": "c6", "path": "notes/plan.md", "content": "# Plan\n\nWritten whole with the file tool.\n"}},
                  {"result": {"id": "c6", "text": "File created successfully at: notes/plan.md"}}]
        steps += shell_steps("c7", "printf 'other\\n' > notes/other.md")
        steps += shell_steps("c8", "cat notes/plan.md", text="# Plan")
        steps += [{"exit": 0}]
        started = self.start_session(lane, fmt, steps)
        self.wait_event("lane.ended", lane)
        refusals = self.kind_events(lane, "lane.refusal")
        self.assertEqual(len(refusals), 1)
        refusal = refusals[0]["payload"]
        target = expected_path(started["worktree"], "notes/plan.md")
        self.assertEqual(refusal["targets"], [target])
        ways = {"c2": "shell-write", "c3": "reworded", "c4": "reworded", "c5": "reworded"}
        suspicions = {}
        for call_id, way in ways.items():
            with self.subTest(call=call_id):
                found = self.suspicion_of(lane, call_id)
                self.assertEqual(len(found), 1, "{}: {}".format(call_id, found))
                payload = found[0]["payload"]
                self.assertEqual((payload["refusal"], payload["run"]), (refusal["refusal"], 1))
                self.assertIn(way, payload["how"])
                self.assertIn(target, payload["paths"])
                self.assertEqual(payload["call"]["id"], call_id)
                self.assertIn(call_id, self.read_line(payload["call"]["record"]))
                self.assertLess(refusals[0]["seq"], found[0]["seq"])
                suspicions[call_id] = payload
        self.assertEqual(suspicions["c2"]["how"], ["shell-write"])
        self.assertIsNone(suspicions["c2"]["similarity"])
        for call_id in ("c3", "c4", "c5"):
            self.assertGreaterEqual(suspicions[call_id]["similarity"]["containment"], 0.8)
        for call_id in ("c6", "c7", "c8"):
            with self.subTest(call=call_id):
                self.assertEqual(self.suspicion_of(lane, call_id), [])
        self.assertEqual(len(self.kind_events(lane, "lane.workaround_suspected")), 4)
        listed = self.refusals(lane)
        self.assertEqual(listed["unreviewed"], [{"refusal": refusal["refusal"], "path": target, "suspicions": sorted(
            item["suspicion"] for item in suspicions.values())}])
        self.assertEqual(sorted(self.status(lane)["refusals"]["suspected"]),
                         sorted(item["suspicion"] for item in suspicions.values()))
        # The live scan recorded everything: scanning again appends nothing.
        count = len(self.events())
        scanned = self.scan(lane)
        self.assertEqual(scanned["appended"], {"refusals": 0, "suspicions": 0})
        self.assertEqual(len(self.events()), count)
        self.assert_sound()

    def test_claude_code(self):
        self.check_workarounds("claude-code", "b-claude")

    def test_unsupported_copier_writes(self):
        lane = "b-copy-backup"
        fmt = "claude-code"
        relative = "notes/blocked.txt"
        copy = "c" + "p"
        refused = "printf '%s' withheld > " + relative
        steps = [{"open": {}}] + refused_steps(fmt, "r1", refused)
        steps += shell_steps("read-control", shlex.join([copy, relative, "elsewhere.txt"]))
        steps += shell_steps("other-control", "cd notes && " + shlex.join([copy, "-b", "../public-source.txt", "other.txt"]))
        retries = (
            ("copy-backup", "cd notes && " + shlex.join([copy, "-b", "../public-source.txt", "blocked.txt"])),
            ("copy-target", shlex.join([copy, "-b", "-t", "notes", "elsewhere/blocked.txt"])),
            ("copy-directory", shlex.join([copy, "-b", "elsewhere/blocked.txt", "notes/"])),
        )
        for call_id, command in retries:
            steps += shell_steps(call_id, command)
        steps += [{"exit": 0}]
        started = self.start_session(lane, fmt, steps)
        self.wait_event("lane.ended", lane)
        refusals = self.kind_events(lane, "lane.refusal")
        self.assertEqual(len(refusals), 1)
        refusal = refusals[0]["payload"]
        target = expected_path(started["worktree"], relative)
        self.assertEqual(refusal["targets"], [target])
        for call_id, _ in retries:
            with self.subTest(call=call_id):
                found = self.suspicion_of(lane, call_id)
                self.assertEqual(len(found), 1)
                payload = found[0]["payload"]
                self.assertEqual(payload["refusal"], refusal["refusal"])
                self.assertEqual(payload["how"], ["shell-write"])
                self.assertEqual(payload["paths"], [target])
                self.assertIsNone(payload["similarity"])
                self.assertEqual(payload["call"]["id"], call_id)
                self.assertLess(refusals[0]["seq"], found[0]["seq"])
        for call_id in ("read-control", "other-control"):
            self.assertEqual(self.suspicion_of(lane, call_id), [])
        self.assertEqual(len(self.kind_events(lane, "lane.workaround_suspected")), len(retries))
        self.assertEqual(self.scan(lane)["appended"], {"refusals": 0, "suspicions": 0})
        self.assert_sound()

    def test_late_terminator_bsd_write(self):
        lane = "b-literal-dashes"
        fmt = "claude-code"
        copy = "c" + "p"
        steps = [{"open": {}}]
        steps += refused_steps(fmt, "r-dashes", "printf '%s' withheld > ./--")
        steps += refused_steps(fmt, "r-child", "printf '%s' withheld > d/--")
        steps += shell_steps("leading-control", shlex.join([copy, "--", "source.txt", "other.txt"]))
        steps += shell_steps("late-dashes", shlex.join([copy, "source.txt", "--"]))
        steps += shell_steps("late-directory", shlex.join([copy, "source.txt", "--", "d/"]))
        steps += [{"exit": 0}]
        started = self.start_session(lane, fmt, steps)
        self.wait_event("lane.ended", lane)
        refusals = {item["payload"]["call"]["id"]: item["payload"]
                    for item in self.kind_events(lane, "lane.refusal")}
        self.assertEqual(set(refusals), {"r-dashes", "r-child"})
        root_target = expected_path(started["worktree"], "--")
        child_target = expected_path(started["worktree"], "d/--")
        self.assertEqual(self.suspicion_of(lane, "leading-control"), [])
        for call, expected in (("late-dashes", {refusals["r-dashes"]["refusal"]: root_target}),
                               ("late-directory", {refusals["r-dashes"]["refusal"]: root_target,
                                                   refusals["r-child"]["refusal"]: child_target})):
            with self.subTest(call=call):
                found = self.suspicion_of(lane, call)
                actual = {}
                for suspicion in found:
                    payload = suspicion["payload"]
                    self.assertEqual(payload["how"], ["shell-write"])
                    self.assertIsNone(payload["similarity"])
                    self.assertEqual(len(payload["paths"]), 1)
                    actual[payload["refusal"]] = payload["paths"][0]
                self.assertEqual(actual, expected)
        self.assertEqual(self.scan(lane)["appended"], {"refusals": 0, "suspicions": 0})
        self.assert_sound()

    def test_gnu_bsd_candidates_combined(self):
        lane = "b-copy-late-flag"
        fmt = "claude-code"
        copy = "c" + "p"
        steps = [{"open": {}}]
        steps += refused_steps(fmt, "r1", "printf '%s' withheld > d/a")
        steps += shell_steps("other-control", shlex.join([copy, "a", "other/", "-v"]))
        steps += shell_steps("late-flag", shlex.join([copy, "a", "d/", "-v"]))
        steps += [{"exit": 0}]
        started = self.start_session(lane, fmt, steps)
        self.wait_event("lane.ended", lane)
        refusal = self.kind_events(lane, "lane.refusal")
        self.assertEqual(len(refusal), 1)
        target = expected_path(started["worktree"], "d/a")
        self.assertEqual(refusal[0]["payload"]["targets"], [target])
        self.assertEqual(self.suspicion_of(lane, "other-control"), [])
        found = self.suspicion_of(lane, "late-flag")
        self.assertEqual(len(found), 1)
        payload = found[0]["payload"]
        self.assertEqual(payload["refusal"], refusal[0]["payload"]["refusal"])
        self.assertEqual(payload["how"], ["shell-write"])
        self.assertEqual(payload["paths"], [target])
        self.assertIsNone(payload["similarity"])
        self.assertLess(refusal[0]["seq"], found[0]["seq"])
        self.assertEqual(self.scan(lane)["appended"], {"refusals": 0, "suspicions": 0})
        self.assert_sound()

    def test_known_limits_of_the_detector(self):
        # Fix round 1, decision 12: the review's six cases, with today's behaviour asserted (each is a known limit in
        # the documents), except the last, which is fixed: a directory change inside a subshell does not move the
        # command after it.
        steps = [{"open": {}}]
        steps += refused_steps("claude-code", "r1", "printf 'halt\\n' > notes/plan.md")
        steps += shell_steps("m1", "python3 -c \"from pathlib import Path; Path('notes/plan.md').write_text('ready')\"")
        steps += shell_steps("m2", "f=notes/plan.md; printf ready > \"$f\"")
        steps += shell_steps("m3", "git restore --source=HEAD -- notes/plan.md")
        steps += refused_steps("claude-code", "r2", "rm reports/weekly/operations/plan.md")
        steps += shell_steps("f1", "cat reports/weekly/operations/plan.md", text="# Plan")
        steps += shell_steps("f2", "rsync --dry-run /tmp/replacement.md notes/plan.md")
        steps += refused_steps("claude-code", "r3", "printf 'x\\n' > docs/notes/plan.md")
        steps += shell_steps("f3", "(cd docs && ls); printf ok > notes/plan.md") + [{"exit": 0}]
        started = self.start_session("b-limits", "claude-code", steps)
        self.wait_event("lane.ended", "b-limits")
        refusals = {item["payload"]["call"]["id"]: item["payload"]["refusal"]
                    for item in self.kind_events("b-limits", "lane.refusal")}
        self.assertEqual(sorted(refusals), ["r1", "r2", "r3"])
        # Three misses: a write by an interpreter's code, a write through a variable, a restore by git.
        for call in ("m1", "m2", "m3"):
            with self.subTest(call=call):
                self.assertEqual(self.suspicion_of("b-limits", call), [])
        # Two false alarms: a read that shares a long path is reworded; a dry run is a shell write.
        read = self.suspicion_of("b-limits", "f1")
        self.assertEqual([(item["payload"]["refusal"], item["payload"]["how"]) for item in read],
                         [(refusals["r2"], ["reworded"])])
        dry = self.suspicion_of("b-limits", "f2")
        self.assertEqual([(item["payload"]["refusal"], item["payload"]["how"]) for item in dry],
                         [(refusals["r1"], ["shell-write"])])
        # Fixed: the write after the subshell is notes/plan.md, refused by r1, not docs/notes/plan.md (r3).
        moved = self.suspicion_of("b-limits", "f3")
        self.assertEqual([(item["payload"]["refusal"], item["payload"]["paths"]) for item in moved],
                         [(refusals["r1"], [expected_path(started["worktree"], "notes/plan.md")])])
        self.assert_sound()

    def test_hook_refused_retry_is_a_refusal(self):
        # Fix round 2, decision 7: a call that a hook refused is a refusal, never also a suspected workaround of an
        # earlier refusal, whether the hook's message comes after the call's result (h1) or before it (h2).
        steps = [{"open": {}}] + refused_steps("claude-code", "r1") + hooked_steps("h1")
        steps += [{"shell": {"id": "h2", "command": REFUSED}},
                  {"hook": {"id": "h2", "kind": "blocking", "text": hook("again"), "event": "PreToolUse",
                            "name": "PreToolUse:Bash"}},
                  {"result": {"id": "h2", "text": "", "error": False}}, {"exit": 0}]
        self.start_session("b-hooked", "claude-code", steps)
        self.wait_event("lane.ended", "b-hooked")
        self.assertEqual(sorted(item["payload"]["call"]["id"] for item in self.kind_events("b-hooked", "lane.refusal")),
                         ["h1", "h2", "r1"])
        for call in ("h1", "h2"):
            with self.subTest(call=call):
                self.assertEqual(self.suspicion_of("b-hooked", call), [])
        self.assertEqual(self.scan("b-hooked")["appended"], {"refusals": 0, "suspicions": 0})
        self.assert_sound()

    def test_many_targets_fit_an_event(self):
        # A refused command that writes 1100 files: the event names 1023 of them and "(77 more)", and a later write to
        # one of the others is still a suspicion that names it.
        names = " ".join("notes/f{:04d}.md".format(number) for number in range(1100))
        steps = [{"open": {}}] + refused_steps("claude-code", command="touch " + names)
        steps += shell_steps("c2", "printf 'x\\n' > notes/f1099.md") + [{"exit": 0}]
        started = self.start_session("b-many", "claude-code", steps)
        self.wait_event("lane.ended", "b-many")
        refusal = self.kind_events("b-many", "lane.refusal")[0]["payload"]
        self.assertEqual(len(refusal["targets"]), 1024)
        self.assertIn("(77 more)", refusal["targets"])
        self.assertNotIn(expected_path(started["worktree"], "notes/f1099.md"), refusal["targets"])
        suspicion = self.suspicion_of("b-many", "c2")[0]["payload"]
        self.assertEqual(suspicion["paths"], [expected_path(started["worktree"], "notes/f1099.md")])
        self.review("b-many", refusal["refusal"], "(77 more)", "clean", code=2)
        self.assertEqual(self.status("b-many")["live"]["refused_events"], 0)
        self.assert_sound()

    def test_refused_retry_is_not_a_workaround(self):
        # The same command sent again and refused again is a second refusal, not a workaround.
        steps = [{"open": {}}] + refused_steps("claude-code") + refused_steps("claude-code", call_id="c2") + [{"exit": 0}]
        self.start_session("b-retry", "claude-code", steps)
        self.wait_event("lane.ended", "b-retry")
        self.assertEqual(len(self.kind_events("b-retry", "lane.refusal")), 2)
        self.assertEqual(self.kind_events("b-retry", "lane.workaround_suspected"), [])
        self.assert_sound()
