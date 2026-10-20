"""Installed G11 dirty-work retention producer."""

import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sqlite3
import time
import uuid


AGENT_PACKAGE = "./cmd/laneboss/serve-fixture"


def sibling(name):
    path = Path(__file__).with_name(name + ".py")
    spec = importlib.util.spec_from_file_location("dirty_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


flow = sibling("lifecycle")
provision = sibling("provision")
io = sibling("item_context")


def require(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def clean_env():
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C",
            "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_OPTIONAL_LOCKS": "0"}


def git_output(enrollment, *args):
    command = [enrollment["GitPath"], "--no-optional-locks", "-c", "core.hooksPath=/dev/null",
               "-c", "core.fsmonitor=false", "--git-dir=" + enrollment["Repository"], *args]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=clean_env(), check=False)
    require(result.returncode == 0, "protected Git read failed")
    return result.stdout


def branch_exists(enrollment):
    command = [enrollment["GitPath"], "--no-optional-locks", "-c", "core.hooksPath=/dev/null",
               "-c", "core.fsmonitor=false", "--git-dir=" + enrollment["Repository"],
               "show-ref", "--verify", "--quiet", "refs/heads/" + enrollment["Workspace"]["Branch"]]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=clean_env(), check=False)
    require(result.returncode in (0, 1), "protected Git branch read failed")
    return result.returncode == 0


def workspace_info(case, lane):
    workspace_id = lane.get("workspace", {}).get("id", "")
    require(workspace_id, "lane status lacks its protected workspace")
    root = Path("/var/lib/laneboss-v2/helper") / case.config
    enrollment_raw = provision.read_protected(root / "workspaces" / (workspace_id + ".json"))
    enrollment = provision.document(enrollment_raw)
    lease_id = enrollment.get("LeaseID", "")
    lease_raw = provision.read_protected(root / (lease_id + ".json"), mode=0o600)
    lease = provision.document(lease_raw)
    worktree = Path(enrollment["Parent"]) / workspace_id
    require(worktree.resolve(strict=True) == worktree, "native worktree path is not canonical")
    return enrollment, lease, worktree


def tree_snapshot(enrollment, worktree, tracked_path=None, untracked_path=None):
    tracked_raw = git_output(enrollment, "ls-tree", "-r", "--name-only", "-z",
                             "refs/heads/" + enrollment["Workspace"]["Branch"])
    tracked = {item.decode() for item in tracked_raw.split(b"\0") if item}
    entries = []
    tracked_digest = ""
    untracked_digest = ""
    directories = {".": stat.S_IMODE(worktree.stat().st_mode)}
    for path in sorted(worktree.rglob("*")):
        relative = path.relative_to(worktree)
        if relative == Path(".git") or ".git" in relative.parts:
            continue
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            directories[relative.as_posix()] = stat.S_IMODE(info.st_mode)
            continue
        if stat.S_ISLNK(info.st_mode):
            data = os.readlink(path).encode()
        else:
            require(stat.S_ISREG(info.st_mode), "worktree contains an unsupported file kind")
            data = path.read_bytes()
        mode = stat.S_IMODE(info.st_mode)
        name = relative.as_posix()
        entries.append({"path": name, "mode": mode, "sha256": digest(data), "bytes": len(data),
                        "kind": "symlink" if stat.S_ISLNK(info.st_mode) else "file"})
        if name == tracked_path:
            tracked_digest = digest(data)
        if name == untracked_path:
            untracked_digest = digest(data)
    entries.sort(key=lambda row: row["path"])
    tree = entry_digest(entries)
    head = git_output(enrollment, "rev-parse", "--verify", "refs/heads/" + enrollment["Workspace"]["Branch"]).decode().strip()
    require(len(head) in (40, 64), "protected branch head is malformed")
    return {"tree_sha256": tree, "branch_head": head, "tracked_bytes": tracked_digest,
            "untracked_bytes": untracked_digest, "tracked_paths": sorted(tracked), "entries": entries,
            "directories": directories}


def entry_digest(entries):
    return digest(b"".join(("%s\0%o\0%s\0%d\n" % (
        row["path"], row["mode"], row["sha256"], row["bytes"])).encode()
        for row in sorted(entries, key=lambda row: row["path"])))


def archive_snapshot(case, enrollment, record, receipt, live, frozen):
    lease_id = enrollment["LeaseID"]
    require(lease_id and Path(lease_id).name == lease_id and lease_id not in (".", ".."),
            "dirty archive lease selector is invalid")
    raw = provision.read_protected(Path("/var/lib/laneboss-v2/helper") /
                                   case.config / (lease_id + ".json"), mode=0o600)
    journal = provision.document(raw)
    archive = journal.get("archive", {})
    freeze, tree = archive.get("Freeze", {}), archive.get("Tree", {})
    require(journal.get("schema") == "laneboss.helper-lease.v2" and
            journal.get("lease", {}).get("id") == lease_id and archive.get("Phase") == "frozen" and
            archive.get("Intent", {}).get("Request", {}).get("target") == record["target"] and
            freeze.get("target") == record["target"] and freeze.get("snapshot") == receipt.get("manifest") and
            tree.get("schema") == "laneboss.objects.v2",
            "dirty archive lost its protected frozen manifest")
    entries = []
    for entry in tree["entries"]:
        if not entry["path"].startswith("workspace/") or entry["kind"] == "directory":
            continue
        name = entry["path"][len("workspace/"):]
        if entry["kind"] == "symlink":
            data = entry["link_target"].encode()
            sha, size = digest(data), len(data)
        else:
            require(entry["kind"] == "file", "dirty archive has an unsupported file kind")
            sha, size = entry["content"]["sha256"], entry["content"]["bytes"]
        entries.append({"path": name, "mode": entry["mode"], "sha256": sha,
                        "bytes": size, "kind": entry["kind"]})
    entries.sort(key=lambda row: row["path"])
    require(entries == live["entries"] and entry_digest(entries) == live["tree_sha256"] and
            live["branch_head"] == frozen["branch_head"],
            "dirty archive changed original worktree names, modes, bytes or branch")
    physical = [dict(row, mode=row["mode"] if row["kind"] == "symlink" else row["mode"] & 0o555)
                for row in entries]
    require(physical == frozen["entries"] and entry_digest(physical) == frozen["tree_sha256"],
            "dirty archive changed more than its exact write-mode withdrawal")
    return {"tree_sha256": entry_digest(entries), "entries": entries,
            "branch_head": frozen["branch_head"], "manifest": freeze["snapshot"]}


def selected_file(worktree, name):
    relative = Path(name)
    require(not relative.is_absolute() and relative.parts and
            all(part not in ("..", ".git", ".laneboss") for part in relative.parts),
            "dirty selection points outside lane")
    path = worktree / relative
    require(path.resolve(strict=True) == path and path.is_file() and not path.is_symlink(),
            "dirty selection points outside lane or is not regular")
    return path


def read_dirty_work(enrollment, lease, worktree, nonce):
    tracked = [name for name in tree_snapshot(enrollment, worktree)["tracked_paths"]
               if name != ".git" and not name.startswith(".laneboss/")]
    require(tracked, "project worktree has no tracked file to modify")
    tracked_path = selected_file(worktree, tracked[0])
    require(tracked[0] == "README.md", "dirty fixture project lacks its enrolled README")
    original = git_output(enrollment, "show",
                          "refs/heads/" + enrollment["Workspace"]["Branch"] + ":" + tracked[0])
    untracked_path = worktree / ("g11-dirty-" + nonce[:12] + ".txt")
    untracked = ("G11 dirty untracked %s\n" % nonce).encode()
    expected = original + ("\nG11 dirty tracked %s\n" % nonce).encode()
    deadline = time.monotonic() + 30
    while True:
        fixture_failure(lease, worktree)
        if untracked_path.is_file():
            selected_file(worktree, untracked_path.name)
            if tracked_path.read_bytes() == expected and untracked_path.read_bytes() == untracked:
                break
        require(time.monotonic() < deadline, "in-lane fixture did not write its dirty task")
        time.sleep(0.1)
    uid = lease.get("lease", {}).get("uid")
    require(type(uid) is int and uid > 0 and tracked_path.stat().st_uid == uid and
            untracked_path.stat().st_uid == uid, "dirty files do not belong to the lane UID")
    return {"tracked_path": tracked_path.relative_to(worktree).as_posix(),
            "untracked_path": untracked_path.relative_to(worktree).as_posix(),
            "tracked_content_sha256": digest(tracked_path.read_bytes()),
            "untracked_content_sha256": digest(untracked),
            "tracked_mode": stat.S_IMODE(tracked_path.stat().st_mode),
            "untracked_mode": stat.S_IMODE(untracked_path.stat().st_mode),
            "lease_uid": uid, "writer": "in-lane fixture"}


def fixture_failure(lease, worktree):
    directories = lease.get("launch_storage", {}).get("directories", [])
    require(len(directories) == 3, "dirty fixture has no retained private-home mapping")
    home_id = directories[1].get("id", "")
    require(home_id and Path(home_id).name == home_id and home_id not in (".", ".."),
            "dirty fixture home selector is invalid")
    home = worktree.parent / home_id / "serve-state"
    result = home / "dirty-result.json"
    if result.exists():
        info = result.lstat()
        require(result.resolve(strict=True) == result and stat.S_ISREG(info.st_mode) and
                info.st_nlink == 1 and 0 < info.st_size <= 1048576,
                "dirty fixture result is unsafe")
        measured = json.loads(result.read_bytes())
        if measured.get("status") != "written":
            raise ValueError("in-lane dirty task " + str(measured.get("status")) + " at " +
                             str(measured.get("stage")) + ": " + str(measured.get("error", "")))
        return
    transcript = home / "transcript.json"
    if not transcript.exists():
        return
    info = transcript.lstat()
    require(transcript.resolve(strict=True) == transcript and stat.S_ISREG(info.st_mode) and
            info.st_nlink == 1 and 0 < info.st_size <= 1048576,
            "dirty fixture transcript is unsafe")
    log = json.loads(transcript.read_bytes())
    reason = log.get("stopped_at")
    if reason:
        status = home / "dirty-status.stderr"
        if status.is_file() and status.resolve(strict=True) == status and status.stat().st_size <= 1048576:
            raw = status.read_bytes()
            if raw:
                error = json.loads(raw)
                reason += "; " + str(error.get("code", "")) + ": " + str(error.get("message", ""))
        raise ValueError("in-lane fixture stopped: " + reason)
    raise ValueError("in-lane fixture ended before writing dirty work")


def status(case, record):
    case.current = "item.dirty.run"
    value = case.human.read("dirty-status", ["lane", "status"], record["target"])
    require(value.get("life_id") == record["target"]["life_id"] and
            value.get("run") == record["target"]["run"] and
            value.get("session", {}).get("driver") == "claudock-cli",
            "dirty fixture status changed its target or driver")
    return value


def await_success(case, operation, target):
    selected = operation
    deadline = time.monotonic() + 120
    while True:
        require(selected.get("id") == operation.get("id"), "dirty operation identity changed")
        require(not selected.get("error"), "dirty operation refused unexpectedly")
        if selected.get("status") == "succeeded":
            return selected
        require(selected.get("status") in ("pending", "running") and time.monotonic() < deadline,
                "dirty operation did not complete")
        selected = case.human.read("dirty-operation", ["operation", "get"], {"operation_id": operation["id"]})


def await_dirty_failure(case, operation):
    selected = operation
    deadline = time.monotonic() + 180
    while True:
        require(selected.get("id") == operation.get("id"), "dirty clean operation identity changed")
        if selected.get("status") == "failed":
            error = selected.get("error")
            require(isinstance(error, dict) and error.get("code") == "prerequisite_missing" and
                    "retain_dirty" in error.get("message", "") and
                    "commit" in error.get("instead", "").lower() and
                    "merge" in error.get("instead", "").lower(),
                    "dirty clean did not retain its typed next step")
            return selected
        require(selected.get("status") in ("pending", "running") and time.monotonic() < deadline,
                "dirty clean did not reach its measured refusal")
        selected = case.human.read("dirty-clean-operation", ["operation", "get"], {"operation_id": operation["id"]})


def start(case, request, name):
    # Keep the source proposal separate from the request ticket() binds in
    # place, so another lane receives its own unfilled grant ceremony input.
    proposal = copy.deepcopy(request)
    request = copy.deepcopy(proposal)
    request["lane"] = "g11-" + name
    case.validate_initial_launch(request)
    ticket = case.human.ticket(request, case.root_grants)
    request["root_ticket_id"] = ticket["id"]
    case.current = "item.dirty.run"
    operation = case.checked_cli("dirty-" + name + "-start", ["lane", "start"], request,
                                 idempotency_key="dirty-start-" + name + "-" + uuid.uuid4().hex,
                                 session_proof=str(case.human.proof("read", "human.session", {},
                                                                     case.human.public["principal_id"], 0)))
    require(operation.get("id") and operation.get("life_id") and operation.get("run") == 1,
            "dirty fixture start lacks its real reservation")
    completed = await_success(case, operation, {"life_id": operation["life_id"], "run": operation["run"]})
    record = {"name": name, "driver": request["driver"],
              "target": {"life_id": operation["life_id"], "run": operation["run"]},
              "proposal": proposal, "request": request, "operation": completed}
    lane = status(case, record)
    observed = flow.observe(case, record, require, running=True)[1]
    record["handle"] = observed["handle"]
    record["lane"] = lane
    return record


def stop(case, record):
    lane = status(case, record)
    reason = case.human.upload("dirty-stop-" + record["name"], "task",
                               ("Stop the G11 fixture " + record["name"] + "\n").encode())
    case.current = "item.dirty.run"
    operation = flow.control(case, "dirty-stop", "lane.stop",
                             {"target": record["target"], "expected_generation": lane["generation"], "reason": reason},
                             lane["life_id"], lane["generation"])
    await_success(case, operation, record["target"])
    deadline = time.monotonic() + 120
    while True:
        lane, observed = flow.observe(case, record, require)
        if observed.get("state") == "exited":
            require(observed.get("survivors") == 0, "dirty fixture stop retained survivors")
            record["lane"] = lane
            record["observation"] = observed
            return lane
        require(observed.get("state") == "running" and time.monotonic() < deadline,
                "dirty fixture stop lost its terminal observation")
        time.sleep(0.5)


def archive(case, record, lane):
    empty = {"id": "", "sha256": "", "bytes": 0, "class": ""}
    review = {"id": "", "reviewer": {"kind": "", "id": ""}, "diff": empty,
              "checks": [], "record_inventory": empty, "refusal_resolution": [], "coverage": ""}
    case.current = "item.dirty.run"
    abandoned = flow.control(case, "dirty-abandon", "lane.mark",
                             {"target": record["target"], "expected_generation": lane["generation"],
                              "state": "abandoned", "review": review}, lane["life_id"], lane["generation"])
    await_success(case, abandoned, record["target"])
    lane = status(case, record)
    require(lane.get("state") == "abandoned", "dirty fixture abandonment was not committed")
    archive = flow.control(case, "dirty-archive", "lane.archive",
                           {"target": record["target"], "expected_generation": lane["generation"]},
                           lane["life_id"], lane["generation"])
    require(archive.get("id") and archive.get("archive_sha256") == archive.get("read_back_sha256"),
            "dirty fixture archive lacks its exact read-back")
    return status(case, record), archive


def clean(case, record, lane, archive, expect_dirty):
    request = {"target": record["target"], "expected_generation": lane["generation"],
               "archive_receipt_id": archive["id"]}
    case.current = "item.dirty.run"
    proof = case.human.proof("control", "lane.clean", request, lane["life_id"], lane["generation"])
    case.current = "item.dirty.run"
    operation = case.cli("dirty-clean-" + record["name"], ["lane", "clean"], request,
                         expected=None, idempotency_key="dirty-clean-" + uuid.uuid4().hex,
                         proof=str(proof))
    if case.last["exit_code"] != 0:
        raw = (case.root / case.last["stderr"]).read_bytes()
        raise ValueError("lane.clean refused before its operation: " + raw.decode(errors="replace"))
    require(operation and operation.get("id"), "dirty clean lacks its operation")
    completed = await_dirty_failure(case, operation) if expect_dirty else await_success(case, operation, record["target"])
    native = case.native_cleanup_evidence(record, lane, completed)
    final = status(case, record)
    if expect_dirty:
        require(native["action"] == "retain_dirty" and final.get("cleaned") is False,
                "dirty clean changed the lane or helper disposition")
    else:
        require(native["action"] == "remove_clean" and final.get("cleaned") is True,
                "clean control did not remove its lane")
    return completed, native, final


def archive_bytes(case, record, receipt):
    # Observe only the selected archive's part inventory through a read-only
    # connection. Content itself still goes through the user's blob.read CLI.
    database = Path(case.installed["state_directory"]) / "state.sqlite"
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        rows = connection.execute(
            "SELECT json_extract(data,'$.Parts'), json_extract(data,'$.Phase'), "
            "json_extract(data,'$.Job.Intent.Request.target') FROM projections "
            "WHERE kind='archive_job' AND json_extract(data,'$.Input.receipt_id')=?",
            (receipt["id"],)).fetchall()
    require(len(rows) == 1 and rows[0][1] == "verified" and
            json.loads(rows[0][2]) == record["target"], "dirty restore archive inventory is foreign")
    parts = json.loads(rows[0][0])
    require(0 < len(parts) <= 4096, "dirty restore archive part inventory is incomplete")
    whole = hashlib.sha256()
    measured = []
    total = 0
    for ref in [receipt["manifest"], *parts]:
        require(type(ref["bytes"]) is int and 0 < ref["bytes"] <= 128 << 20,
                "dirty restore archive object exceeds its bound")
        content = hashlib.sha256()
        offset = 0
        while offset < ref["bytes"]:
            size = min(262144, ref["bytes"] - offset)
            chunk = case.human.read("dirty-archive-bytes", ["blob", "read"],
                {"object_id": ref["id"], "offset": offset, "limit": size})
            data = base64.b64decode(chunk["data"], validate=True)
            require(chunk.get("object_id") == ref["id"] and chunk.get("offset") == offset and
                    0 < len(data) <= size and chunk.get("sha256") == digest(data),
                    "dirty restore archive read changed its range or bytes")
            content.update(data)
            if ref != receipt["manifest"]:
                whole.update(data)
            offset += len(data)
        require(content.hexdigest() == ref["sha256"], "dirty restore archive bytes changed from their pin")
        measured.append({"ref": ref, "sha256": content.hexdigest(), "bytes": offset})
        total += offset
        require(total <= 128 << 20, "dirty restore archive exceeds its complete bound")
    require(whole.hexdigest() == receipt["archive_sha256"] == receipt["read_back_sha256"],
            "dirty restore archive parts changed their complete digest")
    return {"manifest": measured[0], "parts": measured[1:], "sha256": whole.hexdigest()}


def verify_restore(live, restored, before, after, frozen, retained):
    require(restored["entries"] == live["entries"] and restored["tree_sha256"] == live["tree_sha256"] and
            restored["directories"] == live["directories"] and
            restored["branch_head"] == live["branch_head"] and
            restored["tracked_bytes"] == live["tracked_bytes"] and
            restored["untracked_bytes"] == live["untracked_bytes"],
            "dirty restore changed pre-stop names, bytes, modes or branch head")
    require(before == after and frozen == retained,
            "dirty restore wrote into the retained archive or frozen worktree")


def restore_work(case, record, lane, receipt, enrollment, worktree, live, frozen, write):
    # Retained storage is deliberately excluded by restoreRoots. Keep a
    # separate owned lane active while its workspace hosts the fresh copy;
    # the independent clean control must still finish with an empty tree.
    host = start(case, record["proposal"], "restore")
    try:
        _, lease, root = workspace_info(case, status(case, host))
        storage = lease.get("launch_storage", {})
        require(lease.get("phase") == "active" and not lease.get("revoked") and not lease.get("archive") and
                storage.get("ready") is True and storage.get("workspace_native", {}).get("Phase") == "published" and
                not any(storage.get(key) for key in ("withdrawn", "withdrawing", "collecting", "collected")),
                "dirty restore host is not an active writable workspace root")
        flow.observe(case, host, require, running=True)
        result = restore_into(case, record, lane, receipt, enrollment, worktree, live, frozen, write, root)
        flow.observe(case, host, require, running=True)
        return result
    finally:
        stop(case, host)


def restore_into(case, record, lane, receipt, enrollment, worktree, live, frozen, write, root):
    before = archive_bytes(case, record, receipt)
    parent = root / ("dirty-restore-" + uuid.uuid4().hex[:12])
    require(parent.parent.resolve(strict=True) == parent.parent, "dirty restore parent is not canonical")
    parent.mkdir(mode=0o700)
    service = case.admin["service"]
    require(type(service["uid"]) is int and service["uid"] > 0, "dirty restore service UID is invalid")
    os.chown(parent, service["uid"], service["gid"])
    target = parent / "work"
    require(not os.path.lexists(target), "dirty restore target already exists")
    request = {"target": record["target"], "expected_generation": lane["generation"],
               "archive_receipt_id": receipt["id"], "path": str(target)}
    case.current = "item.dirty.run"
    proof = case.human.proof("control", "lane.restore", request, lane["life_id"], lane["generation"])
    case.current = "item.dirty.run"
    result = case.checked_cli("dirty-restore", ["lane", "restore"], request,
        proof=str(proof), idempotency_key="dirty-restore-" + uuid.uuid4().hex)
    require(result.get("target") == record["target"] and result.get("path") == str(target) and
            result.get("head") == live["branch_head"] and result.get("manifest") == receipt["manifest"] and
            result.get("archive_receipt_id") == receipt["id"], "dirty restore receipt changed its target or archive")
    restored = tree_snapshot({"GitPath": enrollment["GitPath"], "Repository": str(target / ".git"),
        "Workspace": enrollment["Workspace"]}, target, write["tracked_path"], write["untracked_path"])
    actual_head = git_output({"GitPath": enrollment["GitPath"], "Repository": str(target / ".git")},
                             "rev-parse", "--verify", "HEAD").decode().strip()
    require(actual_head == live["branch_head"], "dirty restore actual HEAD changed")
    after = archive_bytes(case, record, receipt)
    retained = tree_snapshot(enrollment, worktree, write["tracked_path"], write["untracked_path"])
    verify_restore(live, restored, before, after, frozen, retained)
    return {"receipt": result, "tree": restored, "archive_before": before, "archive_after": after,
            "frozen_before": frozen, "frozen_after": retained, "actual_head": actual_head}


class DirtyItem:
    def __init__(self, case):
        self.case = case
        self.facts = None
        self.records = []
        self.ran = False

    def run(self, context):
        case = self.case
        case.human_prefix = "itemdirty"
        proposals = case.decode_document(case.root_launch_input(case.lane_inputs))
        request = proposals.get("claudock-cli")
        require(isinstance(request, dict), "Claude fixture launch proposal is absent")
        dirty = start(case, request, "dirty")
        enrollment, lease, worktree = workspace_info(case, status(case, dirty))
        write = read_dirty_work(enrollment, lease, worktree, case.challenge)
        live = tree_snapshot(enrollment, worktree, write["tracked_path"], write["untracked_path"])
        dirty["worktree"] = str(worktree)
        dirty["live_before"] = live
        dirty["write"] = write
        lane = stop(case, dirty)
        lane, archive_receipt = archive(case, dirty, lane)
        before = tree_snapshot(enrollment, worktree, write["tracked_path"], write["untracked_path"])
        dirty["archived"] = archive_snapshot(case, enrollment, dirty, archive_receipt, live, before)
        dirty["before"] = before
        operation_error, native, final = clean(case, dirty, lane, archive_receipt, True)
        after = tree_snapshot(enrollment, worktree, write["tracked_path"], write["untracked_path"])
        dirty.update({"after": after, "operation_error": operation_error.get("error"),
                      "native": native, "status": final,
                      "tracked_exists": (worktree / write["tracked_path"]).is_file(),
                      "untracked_exists": (worktree / write["untracked_path"]).is_file()})
        case.keep_json("dirty-phases.json", {name: dirty[name] for name in (
            "live_before", "archived", "before", "after")})
        require(dirty["before"]["tree_sha256"] == dirty["after"]["tree_sha256"] and
                dirty["before"]["branch_head"] == dirty["after"]["branch_head"],
                "dirty clean changed the retained worktree or branch")
        dirty["restore"] = restore_work(case, dirty, final, archive_receipt, enrollment,
                                         worktree, live, after, write)
        control = start(case, request, "control")
        control_enrollment, control_lease, control_worktree = workspace_info(case, status(case, control))
        control["before"] = tree_snapshot(control_enrollment, control_worktree)
        lane = stop(case, control)
        lane, control_archive = archive(case, control, lane)
        operation, control_native, control_final = clean(case, control, lane, control_archive, False)
        control["native"], control["status"] = control_native, control_final
        control["worktree_exists"] = control_worktree.exists()
        control["branch_exists"] = branch_exists(control_enrollment)
        require(not control["worktree_exists"] and not control["branch_exists"],
                "clean control retained its worktree or branch")
        self.facts = {"schema": "laneboss.dirty-observation.v1", "dirty": dirty, "control": control,
                      "control_operation": operation}
        case.keep_json("dirty-observation.json", self.facts)
        self.ran = True
        return self.facts

    def transport(self, message):
        require(message.get("action") == "rpc" and message.get("command") == "dirty run" and
                isinstance(message.get("request"), dict) and message.get("request_id") and
                message.get("idempotency_key") and not self.ran,
                "dirty item request is duplicated or malformed")
        facts = self.run(message["request"].get("context", {}))
        return {"exit_code": 0, "stdout": base64.b64encode(encoded(facts)).decode(), "stderr": "",
                "request_id": message["request_id"], "idempotency_key": message["idempotency_key"]}

    def collect(self, context, _operations):
        self.case.human_prefix = "itemdirty"
        require(self.ran and self.facts is not None, "dirty item did not complete its installed flow")
        path = Path(context["evidence_root"]) / "dirty-observation.json"
        require(path.is_file(), "dirty entry did not retain its observation evidence")
        raw = path.read_bytes()
        return {"processes_quiescent": True, "temporary_resources_collected": True,
                "operation_ids": [], "evidence": [{"path": path.name, "sha256": digest(raw), "bytes": len(raw)}]}


def boot(case):
    task = {"schema": "laneboss.dirty-task.v1", "nonce": case.challenge, "lane": "g11-dirty",
            "tracked_path": "README.md", "untracked_path": "g11-dirty-" + case.challenge[:12] + ".txt"}
    # The lifecycle fixture's bounded wait is the actual runner wall budget.
    # Publish the longer window before grants are issued; do not outlive or
    # rewrite a ticket's already approved budget during the restore ceremony.
    budget = {"wall_ms": 300000, "cpu_seconds": 30, "memory_bytes": 268435456,
              "processes": 16, "disk_bytes": 33554432, "spend_micros": 0, "currency": "USD"}
    return {"assets": [], "bundle": {"task": base64.b64encode(encoded(task)).decode(), "budget": budget}}


def prepare(case, require_fn, _fail, _blocked):
    case.human_prefix = "itemdirty"
    runner = DirtyItem(case)
    case.dirty_item = runner
    return {"binding_file": case.installed["binding_file"], "profile_grant_ids": [],
            "transport": runner.transport, "collect": runner.collect}


def abort(case, _require, _fail):
    runner = getattr(case, "dirty_item", None)
    if runner is not None and runner.ran:
        return []
    return [{"reason": "dirty installed flow did not complete; retain its original gate"}]
