"""Third-check consumer and source measurements from the real restore command."""

import importlib.util
import base64
import copy
import json
import os
from pathlib import Path
import sys
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


source = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location("dirty_restore", source / "scripts/v2-serve/case_dirty.py")
dirty = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dirty)
spec = importlib.util.spec_from_file_location("restore_consumer", Path(__file__).with_name("run.py"))
consumer = importlib.util.module_from_spec(spec)
with mock.patch.dict(sys.modules, {"observer": SimpleNamespace()}):
    spec.loader.exec_module(consumer)


def check(paths):
    original, target, before, after = map(Path, paths)
    enrollment = {"GitPath": "/usr/bin/git", "Repository": str(original / ".git"),
                  "Workspace": {"Branch": "HEAD"}}
    # HEAD is resolved separately from tree_snapshot's exact branch selector.
    branch = dirty.git_output(enrollment, "symbolic-ref", "--short", "HEAD").decode().strip()
    enrollment["Workspace"]["Branch"] = branch
    live = dirty.tree_snapshot(enrollment, original, "README.md", "dirty.txt")
    restored = dirty.tree_snapshot({"GitPath": "/usr/bin/git", "Repository": str(target / ".git"),
        "Workspace": {"Branch": "lane/recorded"}}, target, "README.md", "dirty.txt")
    dirty.verify_restore(live, restored, before.read_bytes(), after.read_bytes(), {}, {})
    facts = {"live_before": live, "after": {}, "restore": {"tree": restored,
        "archive_before": before.read_bytes(), "archive_after": after.read_bytes(),
        "frozen_before": {}, "frozen_after": {}, "actual_head": restored["branch_head"]}}
    assert consumer.restored_bytes(facts), "public consumer rejected the real restore"
    for field, value in (("mode", 0o700), ("path", "renamed"), ("bytes", 0), ("sha256", "changed")):
        bad = copy.deepcopy(facts)
        bad["restore"]["tree"]["entries"][0][field] = value
        assert not consumer.restored_bytes(bad), "consumer ignored restored " + field
    for field in ("branch_head", "directories"):
        bad = copy.deepcopy(facts)
        bad["restore"]["tree"][field] = "changed"
        assert not consumer.restored_bytes(bad), "consumer ignored restored " + field
    bad = copy.deepcopy(facts)
    bad["restore"]["archive_after"] += b"changed"
    assert not consumer.restored_bytes(bad), "consumer ignored archive write"


class ArchiveReads(unittest.TestCase):
    def test_host_window(self):
        plan = dirty.boot(SimpleNamespace(challenge="component-nonce"))
        budget = plan["bundle"].get("budget", {})
        self.assertGreaterEqual(budget.get("wall_ms", 0), 300000,
                                "host wait does not cover the restore ceremony")

    def test_host_ended(self):
        host = {"name": "restore", "target": {"life_id": "host-life", "run": 1}}
        record = {"proposal": {"driver": "claudock-cli"}}
        lease = {"phase": "released", "launch_storage": {
            "ready": True, "workspace_native": {"Phase": "published"}}}
        with mock.patch.object(dirty, "start", return_value=host), \
                mock.patch.object(dirty, "status", return_value={"state": "verifying", "containment": "quiescent"}), \
                mock.patch.object(dirty, "workspace_info", return_value=({}, lease, Path("/workspace"))), \
                mock.patch.object(dirty.flow, "observe") as observer, \
                mock.patch.object(dirty, "restore_into") as restorer, \
                mock.patch.object(dirty, "stop") as stopper:
            with self.assertRaisesRegex(ValueError, "host is not an active writable workspace root"):
                dirty.restore_work(SimpleNamespace(), record, {}, {}, {}, Path("/frozen"), {}, {}, {})
        observer.assert_not_called()
        restorer.assert_not_called()
        stopper.assert_called_once_with(mock.ANY, host)

    def test_destination(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-g11-") as directory:
            root = Path(directory).resolve()
            state, workspace = root / "state", root / "workspace"
            state.mkdir(mode=0o700)
            workspace.mkdir(mode=0o700)
            case = SimpleNamespace(installed={"state_directory": str(state)},
                admin={"service": {"uid": os.geteuid(), "gid": os.getegid()}},
                human=SimpleNamespace(proof=lambda *args: "component-proof"))
            record = {"target": {"life_id": "dirty-life", "run": 1}, "proposal": {"driver": "claudock-cli"}}
            receipt = {"id": "component-archive", "manifest": {"id": "component-manifest"}}
            lane = {"generation": 2, "life_id": "dirty-life"}
            live = {"entries": [], "directories": {}, "tree_sha256": "component-tree",
                    "branch_head": "ab" * 20, "tracked_bytes": "tracked", "untracked_bytes": "dirty"}
            write = {"tracked_path": "README.md", "untracked_path": "dirty.txt"}
            enrollment = {"GitPath": "/usr/bin/git", "Workspace": {"Branch": "lane/recorded"}}
            destinations = []

            def restore(label, words, request, **options):
                self.assertEqual(words, ["lane", "restore"])
                path = Path(request["path"])
                if not path.is_relative_to(workspace):
                    raise ValueError("restore_target_scope")
                self.assertFalse(os.path.lexists(path), "restore target was pre-created")
                destinations.append(path)
                return {"target": record["target"], "path": str(path), "head": live["branch_head"],
                        "archive_receipt_id": receipt["id"], "manifest": receipt["manifest"]}

            case.checked_cli = restore
            lease = {"phase": "active", "revoked": False, "launch_storage": {
                "ready": True, "workspace_native": {"Phase": "published"}}}
            with mock.patch.object(dirty, "start", return_value={"name": "restore", "target": {"life_id": "host-life", "run": 1}}), \
                    mock.patch.object(dirty, "status", return_value={}), \
                    mock.patch.object(dirty.flow, "observe", return_value=({}, {"state": "running", "survivors": 1})) as observer, \
                    mock.patch.object(dirty, "stop", return_value={}) as stopper, \
                    mock.patch.object(dirty, "workspace_info", return_value=({}, lease, workspace)), \
                    mock.patch.object(dirty, "archive_bytes", return_value={"sha256": "archive"}), \
                    mock.patch.object(dirty, "tree_snapshot", return_value=live), \
                    mock.patch.object(dirty, "git_output", return_value=live["branch_head"].encode()):
                result = dirty.restore_work(case, record, lane, receipt, enrollment, root, live, live, write)
            self.assertEqual(len(destinations), 1, "authorized restore was skipped")
            self.assertEqual(observer.call_count, 2, "host was not measured running around restore")
            self.assertTrue(all(call.kwargs.get("running") is True for call in observer.call_args_list))
            self.assertEqual(stopper.call_count, 1, "restore host was not stopped")
            self.assertEqual(result["tree"], live)

    def test_parts(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-g11-") as directory:
            root = Path(directory).resolve()
            content = {"manifest": b'{"frozen":"manifest"}', "one": b"first archive part", "two": b"second part"}
            refs = {name: {"id": name, "class": "manifest" if name == "manifest" else "artifact",
                "sha256": dirty.digest(raw), "bytes": len(raw)} for name, raw in content.items()}
            receipt = {"id": "archive-one", "manifest": refs["manifest"],
                "archive_sha256": dirty.digest(content["one"] + content["two"])}
            receipt["read_back_sha256"] = receipt["archive_sha256"]
            target = {"life_id": "dirty-life", "run": 1}
            record = {"Parts": [refs["one"], refs["two"]], "Phase": "verified",
                "Input": {"receipt_id": receipt["id"]}, "Job": {"Intent": {"Request": {"target": target}}}}
            with sqlite3.connect(root / "state.sqlite") as connection:
                connection.execute("CREATE TABLE projections (kind TEXT, data TEXT)")
                connection.execute("INSERT INTO projections VALUES (?, ?)", ("archive_job", json.dumps(record)))
            calls = []

            def read(label, words, request):
                calls.append(request["object_id"])
                self.assertEqual(words, ["blob", "read"])
                raw = content[request["object_id"]][request["offset"]:request["offset"] + request["limit"]]
                return {"object_id": request["object_id"], "offset": request["offset"],
                        "data": base64.b64encode(raw).decode(), "sha256": dirty.digest(raw)}

            case = SimpleNamespace(installed={"state_directory": str(root)}, human=SimpleNamespace(read=read))
            before = dirty.archive_bytes(case, {"target": target}, receipt)
            self.assertEqual(calls, ["manifest", "one", "two"])
            self.assertEqual(before, dirty.archive_bytes(case, {"target": target}, receipt))
            for name in content:
                saved = content[name]
                content[name] = saved[:-1] + b"!"
                with self.subTest(part=name), self.assertRaisesRegex(ValueError, "archive bytes changed"):
                    dirty.archive_bytes(case, {"target": target}, receipt)
                content[name] = saved
            with self.assertRaisesRegex(ValueError, "inventory is foreign"):
                dirty.archive_bytes(case, {"target": {"life_id": "foreign", "run": 1}}, receipt)


if __name__ == "__main__":
    if sys.argv[1:] == ["--bundle"]:
        sys.stdout.buffer.write(dirty.encoded(dirty.boot(SimpleNamespace(challenge="ab" * 16))["bundle"]))
    elif len(sys.argv) == 6 and sys.argv[1] == "--check":
        check(sys.argv[2:])
    else:
        unittest.main(verbosity=2)
