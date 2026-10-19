"""Synthetic checker inputs, separate from public CLI/socket evidence."""

import base64
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

import run
import worker


class TestPolicyCaseChecks(unittest.TestCase):
    def test_owner_wait_preserves_actual__6465(self):
        for stage, generation in (("responsibilities", 3), ("skip", 7)):
            wait = run.OwnerWait(stage, generation).projection()
            self.assertEqual(wait["code"], "prerequisite_missing")
            self.assertEqual(wait["owner"], "owner-in-person")
            self.assertEqual(wait["stage"], stage)
            self.assertEqual(wait["expected_generation"], generation)
            self.assertIn("current base", wait["instead"])

    def test_rollover_rejects_bad_pins(self):
        before = {"policy_generation": 2, "generation": 5, "life_id": "life-a", "run": 1,
                  "logical_turn_id": "turn-a", "task": {"id": "task-a"}, "launch_id": "launch-a",
                  "grant_set_id": "grants-a", "cancellation_epoch": 1, "level": 3, "role": "executor",
                  "session": {}, "workspace": {}, "containment": "containment-a"}
        after = {**before, "policy_generation": 3, "generation": 6}
        policy = {"generation": 3, "sha256": "approved-policy-hash"}
        event = {"kind": "lane.policy", "life_id": "life-a", "run": 1, "origin": "service",
                 "actor": {"kind": "service"}, "payload": {
                     "from_generation": 2, "to_generation": 3, "lane_generation": 6,
                     "policy_sha256": policy["sha256"], "grant_set_id": before["grant_set_id"]}}
        run.require_policy_rollover(before, before, after, policy, [event])
        for read, evaluated, approved, events in (
            (before, after, {**policy, "generation": 2}, [event]),
            (after, after, policy, [event]),
            (before, {**after, "launch_id": "replacement"}, policy, [event]),
            (before, before, policy, [event]),
            (before, after, policy, []),
            (before, after, policy, [event, event]),
            (before, after, {**policy, "sha256": "foreign"}, [event]),
        ):
            with self.subTest(read=read, evaluated=evaluated, approved=approved, events=events):
                with self.assertRaises(AssertionError):
                    run.require_policy_rollover(before, read, evaluated, approved, events)

    def test_fresh_skip_rejects_reuse(self):
        warm = {"result": "allow", "rules": [{"probability": 0.0, "judgment_id": "judged"}]}
        run.require_fresh_skip(warm)
        for edit in (
            {"skip_id": "premature"}, {"cache_of": "stale"}, {"result": "warn"},
            {"rules": []}, {"rules": [{"judgment_id": "unscored"}]},
            {"rules": [{"probability": float("nan"), "judgment_id": "bad"}]},
        ):
            with self.subTest(edit=edit):
                with self.assertRaisesRegex(AssertionError, "fresh skip proof"):
                    run.require_fresh_skip({**warm, **edit})

    def test_hook_uses_exact_command_file(self):
        raw = b"read public input\n"
        request = {"target": {"life_id": "life-a", "run": 1}, "logical_turn_id": "turn-a",
                   "command": {"tool": "shell", "cwd": "/work/main", "argv": [], "declared_paths": [],
                               "command": base64.b64encode(raw).decode(),
                               "raw_sha256": hashlib.sha256(raw).hexdigest()}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "command"
            command, observed = worker.hook_command("fixture-binary", "case-policy", request, path)
            self.assertNotIn("--request", command)
            self.assertEqual(command[command.index("--command-file") + 1], str(path))
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(observed, raw)
            for flag, value in (("--life-id", "life-a"), ("--run", "1"), ("--turn-id", "turn-a"),
                                ("--tool", "shell"), ("--cwd", "/work/main")):
                self.assertEqual(command[command.index(flag) + 1], value)
            for field in ("argv", "declared_paths", "raw_sha256"):
                changed = copy.deepcopy(request)
                changed["command"][field] = ["cannot drop"] if field != "raw_sha256" else "bad"
                with self.subTest(field=field):
                    with self.assertRaises(RuntimeError):
                        worker.hook_command("fixture-binary", "case-policy", changed, path)


if __name__ == "__main__":
    unittest.main()
