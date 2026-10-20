"""Real Git worktree selection and the host-write negative control."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock


source = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location(
    "dirty", source / "scripts/v2-serve/case_dirty.py")
dirty = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dirty)


class DirtySelection(unittest.TestCase):
    def git(self, *args):
        result = subprocess.run(["git", *map(str, args)], check=False,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=dirty.clean_env())
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return result.stdout

    def test_worktree_index(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-g11-") as directory:
            root = Path(directory).resolve()
            repo, common, work = root / "source", root / "common", root / "work"
            self.git("init", "--quiet", repo)
            (repo / "README.md").write_bytes(b"real tracked project\n")
            self.git("-C", repo, "add", "README.md")
            self.git("-C", repo, "-c", "user.name=fixture", "-c",
                     "user.email=fixture@invalid", "commit", "--quiet", "-m", "project")
            self.git("clone", "--quiet", "--bare", repo, common)
            self.git("--git-dir=" + str(common), "worktree", "add", "--quiet",
                     "-b", "lane/dirty", work, "HEAD")
            enrollment = {"GitPath": "/usr/bin/git", "Repository": str(common),
                          "Workspace": {"Branch": "lane/dirty"}}
            observed = dirty.tree_snapshot(enrollment, work)
            self.assertEqual(observed["tracked_paths"], ["README.md"],
                             "common repository index hid the lane's tracked file")
            self.assertEqual((work / "README.md").read_bytes(), b"real tracked project\n")

    def test_outside_lane_refused(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-g11-") as directory:
            root = Path(directory).resolve()
            work = root / "work"
            work.mkdir()
            sentinel = root / "outside.txt"
            sentinel.write_bytes(b"outside canary\n")
            # On int22 this calls the old host writer. The candidate reads
            # evidence only; both must reject an escaping selected filename.
            observe = getattr(dirty, "read_dirty_work", None)
            if observe is None:
                observe = dirty.write_dirty_work
            with mock.patch.object(dirty, "tree_snapshot", return_value={
                    "tracked_paths": ["../outside.txt"]}):
                with self.assertRaisesRegex(ValueError, "outside lane"):
                    observe({}, {}, work, "fixture-nonce")
            self.assertEqual(sentinel.read_bytes(), b"outside canary\n")
            self.assertEqual(list(work.iterdir()), [])

    def test_fixture_error(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-g11-") as directory:
            root = Path(directory).resolve()
            work, home = root / "work", root / "home" / "serve-state"
            work.mkdir()
            home.mkdir(parents=True)
            (work / "README.md").write_bytes(b"tracked\n")
            error = "dirty.chmod: chmod README.md: read-only file system"
            (home / "dirty-result.json").write_text(json.dumps({
                "stage": "write", "status": "failed", "error": error}))
            lease = {"launch_storage": {"directories": [
                {"id": "work"}, {"id": "home"}, {"id": "history"}]}}
            with mock.patch.object(dirty, "tree_snapshot", return_value={
                    "tracked_paths": ["README.md"]}), \
                    mock.patch.object(dirty, "git_output", return_value=b"tracked\n"), \
                    mock.patch.object(dirty.time, "monotonic", side_effect=[0, 100]):
                with self.assertRaisesRegex(ValueError, "dirty.chmod"):
                    dirty.read_dirty_work({"Workspace": {"Branch": "lane/dirty"}}, lease, work, "fixture-nonce")
            self.assertEqual((work / "README.md").read_bytes(), b"tracked\n")
            self.assertFalse((work / "g11-dirty-fixture-nonc.txt").exists())

    def observer_probe(self, dispatch):
        spec = importlib.util.spec_from_file_location(
            "dirty_observer", Path(__file__).with_name("observer.py"))
        consumer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(consumer)
        with tempfile.TemporaryDirectory(prefix="lb-v2-g11-") as directory:
            root = Path(directory).resolve()
            work, home = root / "work", root / "home" / "serve-state"
            work.mkdir()
            home.mkdir(parents=True)
            (work / "README.md").write_bytes(b"tracked\n")
            lease = {"launch_storage": {"directories": [
                {"id": "work"}, {"id": "home"}, {"id": "history"}]}}
            case = SimpleNamespace(
                current="item.dirty.run", rows={"item.dirty.run": {"observed": {}}},
                challenge="fixture-nonce", lane_inputs=None, decode_document=json.loads,
                root_launch_input=lambda path: b'{"claudock-cli":{}}')
            producer = dirty.DirtyItem(case)
            # Relocate only this component's listener from /run to its private
            # temporary directory; peer UID, token, mode and framing stay real.
            with mock.patch.object(dispatch, "Path", return_value=root):
                server = dispatch.Observer(case, {}, {"transport": producer.transport})
            environment = server.start()
            try:
                with mock.patch.object(dirty, "start", return_value={"target": {}}), \
                        mock.patch.object(dirty, "status", return_value={}), \
                        mock.patch.object(dirty, "workspace_info", return_value=(
                            {"Workspace": {"Branch": "lane/dirty"}}, lease, work)), \
                        mock.patch.object(dirty, "tree_snapshot", return_value={
                            "tracked_paths": ["README.md"]}), \
                        mock.patch.object(dirty, "git_output", return_value=b"tracked\n"), \
                        mock.patch.object(dirty.time, "monotonic", side_effect=[0, 100]), \
                        mock.patch.dict(os.environ, environment, clear=True):
                    with self.assertRaisesRegex(ValueError, "observer closed before its response"):
                        consumer.exchange({"action": "rpc", "command": "dirty run",
                            "request": {"context": {}}, "request_id": "component-entry",
                            "idempotency_key": "component-entry"})
            finally:
                server.close()
            self.assertIsInstance(server.error, ValueError,
                                  "observer lost its producer failure")
            self.assertEqual(str(server.error), "in-lane fixture did not write its dirty task")
            self.assertEqual(server.failure["check"], "item.dirty.run")
            self.assertFalse(producer.ran, "timeout was counted as a completed item")
            self.assertFalse(server.path.exists(), "observer socket was not collected")
            self.assertEqual((work / "README.md").read_bytes(), b"tracked\n")
            self.assertEqual([path.name for path in work.iterdir()], ["README.md"],
                             "observer wrote dirty work from outside the lane")

    def test_observer_close(self):
        path = source / "scripts/v2-serve/item_dispatch.py"
        raw = path.read_text()
        anchor = "self.error = error"
        self.assertEqual(raw.count(anchor), 1, "observer failure control moved")
        control = ModuleType("dirty_control")
        control.__file__ = str(path)
        exec(compile(raw.replace(anchor, "self.error = None"), str(path), "exec"),
             control.__dict__)
        with self.assertRaisesRegex(AssertionError, "observer lost its producer failure"):
            self.observer_probe(control)
        print("RED observer: lost producer failure was detected", flush=True)
        spec = importlib.util.spec_from_file_location("dirty_dispatch", path)
        dispatch = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dispatch)
        self.observer_probe(dispatch)
        print("GREEN observer: producer timeout causes private socket EOF", flush=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
