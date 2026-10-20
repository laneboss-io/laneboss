"""Real restore/stop call order with a Go-serialized native journal.

The RPC responses and archive/Git reads are component inputs. restore_work,
restore_into, stop, lifecycle observation and their dispatch order are real.
"""

import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace
from unittest import mock


source = Path(__file__).resolve().parents[4]
path = source / "scripts/v2-serve/case_dirty.py"
spec = importlib.util.spec_from_file_location("order_dirty", path)
dirty = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dirty)


def exercise(journal, module=dirty, refused=False):
    with tempfile.TemporaryDirectory(prefix="lb-v2-g11-") as directory:
        root = Path(directory).resolve()
        lease = copy.deepcopy(journal)
        target = {"life_id": "restore-host", "run": 1}
        host = {"name": "restore", "driver": "claudock-cli", "target": target,
                "request": {"role": "supervisor"}}
        record = {"proposal": {"driver": "claudock-cli"},
                  "target": {"life_id": "retained-life", "run": 1}}
        handle = {"id": "host-handle", "target": target, "containment_id": "host-cgroup"}
        events = []

        def read(label, words, request):
            assert words == ["lane", "status"] and request == target
            active = lease["phase"] == "active"
            events.append("status")
            return {"life_id": target["life_id"], "run": target["run"], "level": 5,
                    "role": "supervisor", "session": {"driver": "claudock-cli"},
                    "root_life_id": target["life_id"], "starter_chain": [], "starter_event_seq": 0,
                    "generation": 1, "launch_id": handle["id"],
                    "state": "running" if active else "verifying",
                    "containment": "running" if active else "quiescent"}

        def rpc(label, words, request, proof):
            if words == ["lane", "stop"]:
                assert request["target"] == target
                events.append("stop")
                lease["phase"] = "released"
                return {"id": "stop-operation", "status": "succeeded"}
            assert words == ["lane", "check"] and request == target
            active = lease["phase"] == "active"
            events.append("running" if active else "exited")
            return {"handle": handle, "observed_at": "component-observation",
                    "state": "running" if active else "exited", "survivors": 1 if active else 0}

        receipt = {"id": "archive-receipt", "manifest": {"id": "archive-manifest"}}
        live = {"entries": [], "directories": {}, "tree_sha256": dirty.digest(b""),
                "branch_head": "ab" * 20, "tracked_bytes": "", "untracked_bytes": ""}

        def restore(label, words, request, **options):
            assert words == ["lane", "restore"] and request["target"] == record["target"]
            events.append("restore")
            assert lease["phase"] == "active" and "stop" not in events, "restore targeted a stopped host"
            destination = Path(request["path"])
            assert destination.is_relative_to(root) and not destination.exists()
            return {"target": request["target"], "path": request["path"], "head": live["branch_head"],
                    "archive_receipt_id": request["archive_receipt_id"], "manifest": receipt["manifest"]}

        human = SimpleNamespace(read=read, rpc=rpc, public={"principal_id": "component-owner"},
            proof=lambda *args: "component-proof",
            upload=lambda label, kind, raw: {"id": dirty.digest(raw)[:16], "class": kind})
        # The installed service never runs as root; a root test run models it as nobody.
        service = {"uid": os.geteuid(), "gid": os.getegid()} if os.geteuid() else {"uid": 65534, "gid": 65534}
        case = SimpleNamespace(human=human, checked_cli=restore, admin={"service": service})
        with mock.patch.object(module, "start", return_value=host), \
                mock.patch.object(module, "workspace_info", return_value=({}, lease, root)), \
                mock.patch.object(module, "archive_bytes", return_value={"sha256": dirty.digest(b"archive")}), \
                mock.patch.object(module, "tree_snapshot", return_value=live), \
                mock.patch.object(module, "git_output", return_value=live["branch_head"].encode()):
            if refused:
                try:
                    module.restore_work(case, record, {}, receipt, {}, root, live, live, {})
                except ValueError as error:
                    assert str(error) == "dirty restore host is not an active writable workspace root"
                else:
                    raise AssertionError("ended host passed the active-root check")
            else:
                module.restore_work(case, record, {"generation": 1, "life_id": "retained-life"},
                    receipt, {"GitPath": "/usr/bin/git", "Workspace": {}}, root, live, live,
                    {"tracked_path": "README.md", "untracked_path": "dirty.txt"})
        assert events.count("stop") == 1, "host was never stopped or stopped twice"
        if refused:
            assert "restore" not in events, "ended host reached restore"
        else:
            assert events.count("restore") == 1, "restore was skipped or duplicated"
            assert events.index("restore") < events.index("stop"), "host stop preceded its last restore"
            print("GREEN order: active check, running, restore, running, stop, exited", flush=True)


if __name__ == "__main__":
    journal = json.loads(Path(sys.argv[1]).read_bytes())
    exercise(journal)
    ended = copy.deepcopy(journal)
    ended["phase"] = "released"
    exercise(ended, refused=True)
    print("RED ended host: exact active-root check refused; host stopped", flush=True)
    raw = path.read_text()
    anchor = "        result = restore_into(case, record, lane, receipt, enrollment, worktree, live, frozen, write, root)"
    assert raw.count(anchor) == 1, "order control anchor moved"
    control = ModuleType("order_control")
    control.__file__ = str(path)
    exec(compile(raw.replace(anchor, "        stop(case, host)\n" + anchor), str(path), "exec"), control.__dict__)
    try:
        exercise(journal, control)
    except AssertionError as error:
        assert str(error) == "restore targeted a stopped host", str(error)
    else:
        raise AssertionError("early stop escaped the real call-order check")
    print("RED order: restore targeted a stopped host", flush=True)
