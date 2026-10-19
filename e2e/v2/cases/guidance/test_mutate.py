"""Mutation-runner unit checks; these are not service acceptance evidence."""

import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import mutate


ROOT = Path(__file__).resolve().parents[4]


def events(outcome="fail", message="expected boundary failure\n"):
    # Explicit parser input fixtures, not fabricated output of a real Go run.
    rows = [
        {"Action": "run", "Test": "TestProbe"},
        {"Action": "run", "Test": "TestProbe/leaf"},
        {"Action": "output", "Test": "TestProbe/leaf", "Output": message},
        {"Action": outcome, "Test": "TestProbe/leaf"},
        {"Action": outcome, "Test": "TestProbe"},
        {"Action": outcome},
    ]
    return ("\n".join(json.dumps(row) for row in rows) + "\n").encode()


class ClassifierTests(unittest.TestCase):
    def setUp(self):
        self.mutation = {"test": ["TestProbe", "leaf"],
                         "failure_contains": "expected boundary failure"}

    def test_reached_red_and_green(self):
        red = mutate.parse_events(events())
        self.assertIsNone(mutate.check_phase(red, 1, self.mutation, red=True))
        green = mutate.parse_events(events("pass", "completed\n"))
        self.assertIsNone(mutate.check_phase(green, 0, self.mutation, red=False))

    def test_success_does_not_kill(self):
        summary = mutate.parse_events(events("pass"))
        with self.assertRaisesRegex(mutate.MutationError, "mutation_survived"):
            mutate.check_phase(summary, 0, self.mutation, red=True)

    def test_other_exit_is_not_a_kill(self):
        summary = mutate.parse_events(events())
        for code in (-9, 2, 69):
            with self.subTest(code=code):
                with self.assertRaisesRegex(mutate.MutationError, "unexpected_red_exit"):
                    mutate.check_phase(summary, code, self.mutation, red=True)

    def test_build_failure_is_not_a_kill(self):
        summary = mutate.parse_events(b'{"Action":"build-fail"}\n')
        with self.assertRaisesRegex(mutate.MutationError, "go_build_failed"):
            mutate.check_phase(summary, 1, self.mutation, red=True)

    def test_no_test_is_not_a_kill(self):
        summary = mutate.parse_events(b'{"Action":"fail"}\n')
        with self.assertRaisesRegex(mutate.MutationError, "target_not_reached"):
            mutate.check_phase(summary, 1, self.mutation, red=True)

    def test_skip_is_not_a_kill(self):
        summary = mutate.parse_events(events("skip"))
        with self.assertRaisesRegex(mutate.MutationError, "test_skipped"):
            mutate.check_phase(summary, 1, self.mutation, red=True)

    def test_wrong_failure_is_not_a_kill(self):
        summary = mutate.parse_events(events(message="unrelated assertion\n"))
        with self.assertRaisesRegex(mutate.MutationError, "wrong_failure_reason"):
            mutate.check_phase(summary, 1, self.mutation, red=True)

    def test_panic_is_not_a_kill(self):
        summary = mutate.parse_events(events(message="expected boundary failure\npanic: fixture\n"))
        with self.assertRaisesRegex(mutate.MutationError, "test_crashed"):
            mutate.check_phase(summary, 1, self.mutation, red=True)

    def test_unrelated_failure_is_not_a_kill(self):
        summary = mutate.parse_events(events())
        summary["ran"].add("TestOther")
        summary["failed"].add("TestOther")
        with self.assertRaisesRegex(mutate.MutationError, "unexpected_test_ran"):
            mutate.check_phase(summary, 1, self.mutation, red=True)

    def test_green_must_pass(self):
        summary = mutate.parse_events(events())
        with self.assertRaisesRegex(mutate.MutationError, "green_test_failed"):
            mutate.check_phase(summary, 1, self.mutation, red=False)

    def test_malformed_stream_is_not_a_kill(self):
        with self.assertRaises(ValueError):
            mutate.parse_events(b"not a JSON event\n")
        with self.assertRaisesRegex(mutate.MutationError, "blank_go_json_line"):
            mutate.parse_events(b"\n")


class SourceTests(unittest.TestCase):
    def test_catalog_anchors_match(self):
        catalog = mutate.load_catalog()
        for mutation in catalog["mutations"]:
            edits = mutation["edits"] or mutation.get("blocked_edits", [])
            if not edits:
                continue
            with self.subTest(mutation=mutation["id"]):
                modified = {}
                for edit in edits:
                    self.assertTrue(mutate.owned_target(edit["file"]))
                    text = modified.get(edit["file"])
                    if text is None:
                        text = (ROOT / edit["file"]).read_text()
                    self.assertEqual(text.count(edit["before"]), 1)
                    changed = text.replace(edit["before"], edit["after"], 1)
                    self.assertNotEqual(text, changed)
                    modified[edit["file"]] = changed

    def test_scope_excludes_tests_and_neighbors(self):
        for name in ("../outside.go", "/tmp/outside.go",
                     "internal/v2/guidance/rank_test.go",
                     "internal/v2/api/interfaces.go",
                     "internal/v2/lifecycle/stub.go"):
            with self.subTest(name=name):
                self.assertFalse(mutate.owned_target(name))

    def test_copy_keeps_bytes_and_original(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-guidance-") as temporary:
            root = Path(temporary)
            source, evidence = root / "source", root / "evidence"
            source.mkdir()
            evidence.mkdir()
            original = source / "input.txt"
            original.write_bytes(b"original\n")
            original.chmod(0o640)
            work = evidence / "work"
            manifest = mutate.copy_snapshot(source, work, evidence)
            self.assertEqual(mutate.source_manifest(work), manifest)
            self.assertEqual(original.read_bytes(), b"original\n")
            self.assertEqual((work / "input.txt").read_bytes(), b"original\n")
            self.assertTrue((evidence / "source.tar.gz").stat().st_size > 0)

    def test_links_are_not_copied(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-guidance-") as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            outside = root / "outside.txt"
            outside.write_bytes(b"outside\n")
            (source / "linked.txt").symlink_to(outside)
            with self.assertRaisesRegex(mutate.MutationError, "source_not_regular"):
                mutate.source_manifest(source)

    def test_edit_and_anchor_drift(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-guidance-") as temporary:
            root = Path(temporary)
            work, evidence = root / "work", root / "evidence"
            evidence.mkdir()
            target = work / "internal/v2/guidance/rank.go"
            target.parent.mkdir(parents=True)
            original = (ROOT / "internal/v2/guidance/rank.go").read_bytes()
            target.write_bytes(original)
            edit = {"file": "internal/v2/guidance/rank.go",
                    "before": "reminderLimit   = 5", "after": "reminderLimit   = 6"}
            originals, changes = mutate.apply_edits(work, [edit], evidence)
            self.assertEqual(originals[edit["file"]], original)
            self.assertNotEqual(changes[0]["before_sha256"], changes[0]["after_sha256"])
            self.assertIn(b"reminderLimit   = 6", target.read_bytes())
            self.assertTrue((evidence / "mutation.patch").is_file())
            with self.assertRaisesRegex(mutate.MutationError, "mutation_anchor_drift"):
                mutate.apply_edits(work, [edit], evidence)

    def test_pending_stays_unimplemented(self):
        catalog = mutate.load_catalog()
        for pending in catalog["mutations"]:
            if pending["state"] != "not_implemented":
                continue
            with self.subTest(mutation=pending["id"]):
                with tempfile.TemporaryDirectory(prefix="lb-v2-guidance-") as temporary:
                    evidence = Path(temporary) / "result"
                    with mock.patch.object(mutate.subprocess, "run",
                                           side_effect=AssertionError("unexpected process")):
                        code = mutate.run_one(Path(temporary), evidence, pending, False)
                    result = json.loads((evidence / "result.json").read_bytes())
                    self.assertEqual(code, 69)
                    self.assertEqual(result["status"], "not_implemented")
                    self.assertEqual(result["phases"], {})
                    self.assertEqual(result["full_guide_turn"], "pending_integration")


if __name__ == "__main__":
    if sys.platform != "linux":
        raise SystemExit("Linux test box required")
    unittest.main()
