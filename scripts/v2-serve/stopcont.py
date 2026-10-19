"""Installed late-stop item, exercised by the grants suite before revocation."""

import copy
import json
import os
from pathlib import Path
import re
import select
import uuid


def journal(case, record, phase, require, provision):
    lane = record["relay"].status()
    workspace = lane.get("workspace", {}).get("id", "")
    require(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", workspace),
            "late stop has no exact installed workspace")
    root = Path("/var/lib") / "laneboss-v2" / "helper" / case.config
    enrolled = json.loads(provision.read_protected(root / "workspaces" / (workspace + ".json")))
    lease = enrolled.get("LeaseID", "")
    require(enrolled.get("Config") == case.config and
            enrolled.get("Workspace", {}).get("Target") == record["target"] and
            re.fullmatch(r"[A-Za-z0-9_-]{1,128}", lease),
            "late stop selected another native workspace")
    raw = provision.read_protected(root / (lease + ".json"), mode=0o600)
    value = json.loads(raw)
    require(value.get("schema") == "laneboss.helper-lease.v2" and
            value.get("lease", {}).get("id") == lease and
            value.get("gate", {}).get("prepared", {}).get("target") == record["target"],
            "late stop selected another retained native gate")
    case.keep("stop-" + phase + ".input.json", raw)
    return value


def run(case, parent, child, proposal, relay_type, require, fail, flow, provision):
    # Do not LaneCheck here: it would finish the lifecycle before Stop, and
    # terminal Stop would correctly do no helper work. The Stop effect itself
    # must commit ObserveGate's exit before invoking StopGate.
    before = journal(case, child, "before", require, provision)
    require(before.get("gate", {}).get("state") == "opened" and
            not before.get("credential_projection", {}).get("local_stop"),
            "late stop item did not start with an unfenced native gate")
    pid = before["gate"]["pid"]
    try:
        descriptor = os.pidfd_open(pid)
    except ProcessLookupError:
        descriptor = None
    if descriptor is not None:
        try:
            poller = select.poll()
            poller.register(descriptor, select.POLLIN)
            require(poller.poll(120000), "stand-in did not exit before the suite stop")
        finally:
            os.close(descriptor)
    lane = child["relay"].status()
    require(lane.get("state") == "running", "late stop bypassed the native Stop effect")
    reason = case.human.upload("late-stop-reason", "task", b"Stop the independently exited stand-in.\n")
    operation = flow.control(case, "late-stop", "lane.stop", {
        "target": child["target"], "expected_generation": lane["generation"], "reason": reason},
        lane["life_id"], lane["generation"])
    flow.await_operation(case, operation, require, fail, child["target"])
    after = journal(case, child, "after", require, provision)
    gate = after.get("gate", {})
    credentials = after.get("credential_projection", {})
    stop = credentials.get("local_stop", {})
    projection = credentials.get("Record", {})
    withdrawal = projection.get("Withdrawal", {})
    require(gate.get("state") == "ended" and gate.get("observation", {}).get("state") == "exited" and
            gate["observation"].get("survivors") == 0 and not after.get("revoked", False) and
            stop.get("Reason") == "release" and stop.get("note") == "stop arrived after natural exit" and
            credentials.get("State") == "withdrawn" and projection.get("Fence", {}).get("Reason") == "release" and
            withdrawal.get("RotationRequired") is False and credentials.get("Refresh"),
            "late suite stop quarantined the seat or lost its acknowledged refresh")
    # This stand-in enrollment has one canonical login per profile. A new
    # launch with that same profile proves the canonical seat remains usable.
    request = copy.deepcopy(proposal)
    request["lane"] = "stop-next-" + uuid.uuid4().hex[:8]
    started = parent["relay"].call("lane start", request)
    next_child = {"name": "stop-next", "target": {
        "life_id": started["life_id"], "run": started["run"]},
        "operation": started, "collected": False}
    case.item_lives.append(next_child)
    flow.await_operation(case, started, require, fail, next_child["target"])
    next_child["relay"] = relay_type(case, next_child, require, fail)
    ready = next_child["relay"].wait("grants.ready")
    require(ready["identity"]["actor"]["level"] == 3, "same-seat replacement did not launch L3")
    replacement = journal(case, next_child, "next", require, provision)
    original = projection["Authority"]["Request"]["Handoff"]["spec"]["runner"]["slot"]
    renewed = replacement["credential_projection"]["Record"]["Authority"]["Request"]["Handoff"]["spec"]["runner"]["slot"]
    require(renewed["profile_id"] == original["profile_id"] and renewed["id"] != original["id"],
            "replacement changed canonical seat or reused the retired slot")
    refresh = credentials["Refresh"]
    sources = replacement["credential_projection"]["Record"]["Authority"]["Sources"]
    require(any(source["Key"] == renewed["id"] and
                source["Generation"] == refresh["Generation"] and
                source["Version"] == refresh["Version"] for source in sources),
            "replacement did not import the acknowledged refresh source")
    next_child["relay"].request("fixture exit", {})
    case.keep_json("stopcont.json", {"stop": operation, "next": started,
        "durable_exit": gate["observation"], "refresh": credentials["Refresh"],
        "rotation_required": withdrawal["RotationRequired"]})
