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
    tracked_raw = git_output(enrollment, "--work-tree=" + str(worktree), "ls-files", "-z")
    tracked = {item.decode() for item in tracked_raw.split(b"\0") if item}
    entries = []
    tracked_digest = ""
    untracked_digest = ""
    for path in sorted(worktree.rglob("*")):
        relative = path.relative_to(worktree)
        if relative == Path(".git") or ".git" in relative.parts:
            continue
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if stat.S_ISLNK(info.st_mode):
            data = os.readlink(path).encode()
        else:
            require(stat.S_ISREG(info.st_mode), "worktree contains an unsupported file kind")
            data = path.read_bytes()
        mode = stat.S_IMODE(info.st_mode)
        name = relative.as_posix()
        row = "%s\0%o\0%s\0%d\n" % (name, mode, digest(data), len(data))
        entries.append(row.encode())
        if name == tracked_path:
            tracked_digest = digest(data)
        if name == untracked_path:
            untracked_digest = digest(data)
    tree = digest(b"".join(entries))
    head = git_output(enrollment, "rev-parse", "--verify", "refs/heads/" + enrollment["Workspace"]["Branch"]).decode().strip()
    require(len(head) in (40, 64), "protected branch head is malformed")
    return {"tree_sha256": tree, "branch_head": head, "tracked_bytes": tracked_digest,
            "untracked_bytes": untracked_digest, "tracked_paths": sorted(tracked)}


def write_dirty_work(enrollment, lease, worktree, nonce):
    tracked = [name for name in tree_snapshot(enrollment, worktree)["tracked_paths"]
               if name != ".git" and not name.startswith(".laneboss/")]
    require(tracked, "project worktree has no tracked file to modify")
    tracked_path = worktree / tracked[0]
    require(tracked_path.is_file() and not tracked_path.is_symlink(), "tracked fixture file is not regular")
    original = tracked_path.read_bytes()
    tracked_path.write_bytes(original + ("\nG11 dirty tracked %s\n" % nonce).encode())
    tracked_path.chmod(stat.S_IMODE(tracked_path.stat().st_mode))
    untracked_path = worktree / ("g11-dirty-" + nonce[:12] + ".txt")
    untracked = ("G11 dirty untracked %s\n" % nonce).encode()
    untracked_path.write_bytes(untracked)
    untracked_path.chmod(0o640)
    return {"tracked_path": tracked_path.relative_to(worktree).as_posix(),
            "untracked_path": untracked_path.relative_to(worktree).as_posix(),
            "tracked_content_sha256": digest(tracked_path.read_bytes()),
            "untracked_content_sha256": digest(untracked),
            "tracked_original_b64": base64.b64encode(original).decode(),
            "tracked_mode": stat.S_IMODE(tracked_path.stat().st_mode),
            "untracked_mode": stat.S_IMODE(untracked_path.stat().st_mode),
            "lease_uid": lease.get("lease", {}).get("uid")}


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
            require(isinstance(error, dict) and error.get("code") == "prerequisite" and
                    "retain_dirty" in error.get("message", "") and
                    "commit" in error.get("instead", "").lower() and
                    "merge" in error.get("instead", "").lower(),
                    "dirty clean did not retain its typed next step")
            return selected
        require(selected.get("status") in ("pending", "running") and time.monotonic() < deadline,
                "dirty clean did not reach its measured refusal")
        selected = case.human.read("dirty-clean-operation", ["operation", "get"], {"operation_id": operation["id"]})


def start(case, request, name):
    request = copy.deepcopy(request)
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
              "request": request, "operation": completed}
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
        write = write_dirty_work(enrollment, lease, worktree, case.challenge)
        before = tree_snapshot(enrollment, worktree, write["tracked_path"], write["untracked_path"])
        dirty["worktree"] = str(worktree)
        dirty["before"] = before
        dirty["write"] = write
        lane = stop(case, dirty)
        lane, archive_receipt = archive(case, dirty, lane)
        operation_error, native, final = clean(case, dirty, lane, archive_receipt, True)
        after = tree_snapshot(enrollment, worktree, write["tracked_path"], write["untracked_path"])
        dirty.update({"after": after, "operation_error": operation_error.get("error"),
                      "native": native, "status": final,
                      "tracked_exists": (worktree / write["tracked_path"]).is_file(),
                      "untracked_exists": (worktree / write["untracked_path"]).is_file()})
        require(dirty["before"]["tree_sha256"] == dirty["after"]["tree_sha256"] and
                dirty["before"]["branch_head"] == dirty["after"]["branch_head"],
                "dirty clean changed the retained worktree or branch")
        tracked_path = worktree / write["tracked_path"]
        untracked_path = worktree / write["untracked_path"]
        original = base64.b64decode(write["tracked_original_b64"], validate=True)
        tracked_path.write_bytes(original)
        tracked_path.chmod(write["tracked_mode"])
        untracked_path.unlink()
        resolved = tree_snapshot(enrollment, worktree, write["tracked_path"], write["untracked_path"])
        require(resolved["tracked_bytes"] == digest(original) and resolved["untracked_bytes"] == "",
                "dirty work was not discarded before its retry")
        write.pop("tracked_original_b64")
        retry_lane = status(case, dirty)
        retry_record = dict(dirty, name="dirty-retry")
        retry_operation, retry_native, retry_final = clean(case, retry_record, retry_lane, archive_receipt, False)
        require(retry_native["action"] == "remove_clean" and retry_final.get("cleaned") is True,
                "discarded dirty work did not reach a clean retry")
        dirty["retry"] = {"operation": retry_operation, "native": retry_native, "status": retry_final,
                           "worktree_exists": worktree.exists(), "branch_exists": branch_exists(enrollment)}
        require(not dirty["retry"]["worktree_exists"] and not dirty["retry"]["branch_exists"],
                "discarded dirty retry retained its worktree or branch")
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


def boot(_case):
    return {"assets": [], "bundle": {}}


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
