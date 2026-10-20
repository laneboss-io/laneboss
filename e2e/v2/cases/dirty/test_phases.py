"""Keep the live/archive and frozen/clean comparisons complete."""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock


source = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location(
    "dirty_phases", source / "scripts/v2-serve/case_dirty.py")
dirty = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dirty)


class DirtyPhases(unittest.TestCase):
    def exercise(self, change=""):
        with tempfile.TemporaryDirectory(prefix="lb-v2-g11-") as directory:
            work = Path(directory).resolve()
            tracked, untracked = work / "README.md", work / "dirty.txt"
            tracked.write_bytes(b"tracked dirty bytes\n")
            tracked.chmod(0o444)
            untracked.write_bytes(b"untracked dirty bytes\n")
            untracked.chmod(0o600)
            enrollment = {"LeaseID": "component-lease", "Workspace": {"Branch": "lane/dirty"}}
            head = "ab" * 20
            git = lambda _enrollment, *args: b"README.md\0" if args[0] == "ls-tree" else head.encode()
            target = {"life_id": "component-life", "run": 1}
            receipt = {"id": "component-archive", "manifest": {"id": "component-tree"}}
            original = {"path": "workspace", "kind": "directory", "mode": 0o700}
            entries = [original] + [{"path": "workspace/" + path.name, "kind": "file",
                "mode": path.stat().st_mode & 0o777,
                "content": {"sha256": dirty.digest(path.read_bytes()), "bytes": path.stat().st_size}}
                for path in (tracked, untracked)]
            journal = {"schema": "laneboss.helper-lease.v2", "lease": {"id": enrollment["LeaseID"]},
                "archive": {"Phase": "frozen", "Intent": {"Request": {"target": target}},
                    "Tree": {"schema": "laneboss.objects.v2", "entries": entries},
                    "Freeze": {"snapshot": receipt["manifest"], "target": target}}}
            kept = {}
            case = SimpleNamespace(lane_inputs=None, root_launch_input=lambda path: b'{"claudock-cli":{}}',
                decode_document=json.loads, challenge="component-nonce", config="component-config",
                keep_json=lambda name, value: kept.update({name: copy.deepcopy(value)}))
            write = {"tracked_path": tracked.name, "untracked_path": untracked.name}

            def archive(_case, record, state):
                # Component inputs model the documented native freeze. The
                # root native canary separately executes the real freezer.
                if change == "archive-bytes":
                    untracked.write_bytes(b"lost dirty bytes\n")
                if change == "archive-mode":
                    entries[2]["mode"] = 0o640
                if change == "archive-name":
                    untracked.rename(work / "moved.txt")
                for path in work.iterdir():
                    path.chmod(path.stat().st_mode & 0o555)
                if change == "freeze-mode":
                    untracked.chmod(0o600)
                return state, receipt

            def clean(_case, record, state, proof, expect_dirty):
                if expect_dirty and change == "clean-bytes":
                    untracked.chmod(0o600)
                    untracked.write_bytes(b"clean changed work\n")
                if expect_dirty and change == "clean-mode":
                    untracked.chmod(0o600)
                if expect_dirty and change == "clean-head":
                    nonlocal head
                    head = "cd" * 20
                if not expect_dirty:
                    for path in work.iterdir():
                        path.unlink()
                    work.rmdir()
                return {"error": {"code": "prerequisite_missing"}}, {}, {}

            with mock.patch.object(dirty, "start", side_effect=lambda _case, request, name: {
                        "target": target, "name": name}), \
                    mock.patch.object(dirty, "status", return_value={}), \
                    mock.patch.object(dirty, "workspace_info", return_value=(enrollment, {}, work)), \
                    mock.patch.object(dirty, "read_dirty_work", return_value=write), \
                    mock.patch.object(dirty, "stop", side_effect=lambda *args: {}), \
                    mock.patch.object(dirty, "archive", side_effect=archive), \
                    mock.patch.object(dirty, "clean", side_effect=clean) as cleaner, \
                    mock.patch.object(dirty, "restore_work", return_value={}), \
                    mock.patch.object(dirty, "branch_exists", return_value=False), \
                    mock.patch.object(dirty, "git_output", side_effect=git), \
                    mock.patch.object(dirty.provision, "read_protected",
                                      side_effect=lambda *args, **kwargs: json.dumps(journal).encode()):
                facts = dirty.DirtyItem(case).run({})
            self.assertEqual(cleaner.call_count, 2, "dirty or clean control was skipped")
            self.assertEqual(facts["dirty"]["before"]["tree_sha256"],
                             facts["dirty"]["after"]["tree_sha256"])
            self.assertEqual(facts["dirty"]["live_before"]["tree_sha256"],
                             facts["dirty"]["archived"]["tree_sha256"])
            self.assertNotEqual(facts["dirty"]["live_before"]["tree_sha256"],
                                facts["dirty"]["before"]["tree_sha256"],
                                "freeze mode transition did not execute")
            self.assertIn("dirty-observation.json", kept)
            return facts

    def test_phases(self):
        self.exercise()

    def test_old_boundary(self):
        path = source / "scripts/v2-serve/case_dirty.py"
        raw = path.read_text()
        anchor = 'dirty["before"] = before'
        self.assertEqual(raw.count(anchor), 1, "phase boundary control moved")
        control = ModuleType("dirty_old_boundary")
        control.__file__ = str(path)
        exec(compile(raw.replace(anchor, 'dirty["before"] = live'), str(path), "exec"),
             control.__dict__)
        with mock.patch.dict(globals(), dirty=control):
            with self.assertRaisesRegex(ValueError, "dirty clean changed the retained worktree or branch"):
                self.exercise()
        print("RED old boundary: live/frozen mode mismatch reproduced", flush=True)

    def test_changes(self):
        for change in ("archive-bytes", "archive-mode", "archive-name", "freeze-mode"):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "dirty archive"):
                self.exercise(change)
        for change in ("clean-bytes", "clean-mode", "clean-head"):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "dirty clean changed"):
                self.exercise(change)

    def test_consumer(self):
        path = Path(__file__).with_name("run.py")
        spec = importlib.util.spec_from_file_location("dirty_entry", path)
        consumer = importlib.util.module_from_spec(spec)
        with mock.patch.dict(sys.modules, {"observer": SimpleNamespace()}):
            spec.loader.exec_module(consumer)
        facts = self.exercise()["dirty"]
        self.assertTrue(consumer.retained_bytes(facts))
        for phase in ("live_before", "archived", "before", "after"):
            for field, value in (("mode", 0o700), ("path", "renamed"),
                                 ("sha256", "unexpected"), ("bytes", 0)):
                changed = copy.deepcopy(facts)
                changed[phase]["entries"][0][field] = value
                with self.subTest(phase=phase, field=field):
                    self.assertFalse(consumer.retained_bytes(changed),
                                     "consumer ignored a retained entry change")
            changed = copy.deepcopy(facts)
            changed[phase]["branch_head"] = "ef" * 20
            self.assertFalse(consumer.retained_bytes(changed), "consumer ignored a branch change")
        changed = copy.deepcopy(facts)
        for phase in ("before", "after"):
            changed[phase]["entries"][1]["mode"] = 0o600
        self.assertFalse(consumer.retained_bytes(changed), "consumer ignored restored frozen write access")


if __name__ == "__main__":
    unittest.main(verbosity=2)
