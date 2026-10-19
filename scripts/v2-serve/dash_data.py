"""Dashboard fixture operations against the installed public service.

Launch inputs, the L6 actor, org change and review inputs come from the live
exporter checkpoint. These functions never write a store or a service event.
"""

import copy
import base64
import importlib.util
import json
import hashlib
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import time
import uuid


ACTIONS = {
    "DASH-STOP": "lane.stop", "DASH-RESUME": "lane.resume",
    "DASH-MERGED": "lane.mark", "DASH-ABANDONED": "lane.mark", "HUMAN-SEND": "mail.send",
}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def empty_review():
    """Typed zero value for abandonment; it carries no review authority."""
    blob = {"id": "", "sha256": "", "bytes": 0, "class": ""}
    return {"id": "", "reviewer": {"kind": "", "id": ""}, "diff": dict(blob), "checks": [],
            "record_inventory": dict(blob), "refusal_resolution": [], "coverage": ""}


def relay_values(relay, events):
    """Consume actual primary partial chunks; JSON labels confer no authority."""
    for event in events:
        if event["seq"] in relay.seen:
            continue
        relay.seen.add(event["seq"])
        if event.get("kind") != "capture.appended":
            continue
        capture = event["payload"]
        if capture.get("stream") != "stdout":
            continue
        relay.require(event.get("origin") == "service" and event.get("life_id") == relay.record["target"]["life_id"]
            and event.get("run") == relay.record["target"]["run"]
            and event.get("operation_id") == relay.record["operation"]["id"]
            and capture.get("target") == relay.record["target"] and capture.get("primary") is True
            and capture.get("binding_id") and capture.get("coverage") in ("partial", "complete")
            and capture.get("offset") == relay.offset, "dashboard relay primary capture differs from its actual run/range")
        raw = relay.capture_blob(capture["data"])
        relay.offset += len(raw)
        relay.pending.extend(raw)
        while b"\n" in relay.pending:
            raw, _, rest = relay.pending.partition(b"\n")
            relay.pending = bytearray(rest)
            frame = json.loads(raw)
            if frame.get("type") == "system" and frame.get("subtype") == "dashboard-fixture":
                value = frame.get("fixture")
                relay.require(isinstance(value, dict), "dashboard relay fixture frame is malformed")
                relay.values.append(value)
                if value.get("type") == "grants.reply" and not value.get("nonce"):
                    relay.refusal(value)
    return relay.values


def partial_gap_bound(value):
    """The raw gap must be the tail of a real primary partial capture."""
    return any(record.get("primary") is True and record.get("coverage") == "partial"
        and record.get("binding_id") and gap.get("target") == record.get("target")
        and gap.get("stream") == record.get("stream")
        and gap.get("start_offset") == record.get("offset", 0) + record.get("data", {}).get("bytes", 0)
        and gap.get("reason") == "incomplete_coverage:partial"
        for record in value.get("records", []) for gap in value.get("gaps", []))


def review_requirements(case, project, generation, directory=Path("/etc/laneboss-v2/review")):
    need(project and type(generation) is int and generation > 0, "review requirements lack current protected project policy")
    document = {"schema": "laneboss.review-requirements.v2", "config": case.config,
        "policy_generation": generation, "projects": [{"project_id": project, "checks": ["dashboard-workspace"]}]}
    raw = (json.dumps(document, sort_keys=True) + "\n").encode()
    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    need(not directory.is_symlink() and directory.stat().st_mode & 0o022 == 0,
         "protected review requirement directory is writable or redirected")
    directory.chmod(0o755)
    path = directory / (case.config + ".json")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), 0o444)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    need(path.read_bytes() == raw, "protected review requirements failed read-back")
    case.keep("dash-review-requirements.input", raw)
    return document


class DashData:
    def __init__(self, case, launches, l6, change, reviews):
        self.case, self.launches, self.l6 = case, launches, l6
        self.change, self.reviews = change, reviews
        self.records, self.prepared = {}, {}
        self.observations = {}
        self.initial_prefix = case.human_prefix
        self.prefix = self.initial_prefix if self.initial_prefix.startswith("item") else "dashboard"
        self.phase = "prepare"

    def stage(self, name):
        if self.prefix == "itemdashboard":
            self.case.current = "item.dashboard." + self.phase
        else:
            self.case.current = "dashboard." + name
            self.case.rows.setdefault(self.case.current, {"check": self.case.current, "result": "fail",
                "presence": "simulated", "observed": {"executed": False}})
        self.case.human_prefix = self.prefix
        for action in ("session", "read", "grants", "ticket", "control"):
            for suffix in ("challenge", "confirm"):
                key = "human." + self.prefix + "." + action + "." + suffix
                self.case.rows.setdefault(key, {"check": key, "result": "fail", "presence": "simulated",
                                               "observed": {"executed": False}})
            if action in ("session", "grants", "ticket"):
                key = "human." + self.prefix + "." + action
                self.case.rows.setdefault(key, {"check": key, "result": "fail", "presence": "simulated",
                                               "observed": {"executed": False}})

    def bind(self, browser, consumer):
        self.browser, self.consumer = browser, consumer

    def read(self, method, params):
        return self.case.human.read("dashboard-" + method.replace(".", "-"), method.split("."), params)

    def control(self, method, params, target, generation):
        saved = self.case.current
        proof = self.case.human.proof("control", method, params, target, generation)
        self.case.current = saved
        return self.case.human.rpc("dashboard-" + method.replace(".", "-"), method.split("."), params, proof)

    def await_operation(self, operation, target=None):
        from fixture_io import FixtureError
        need(operation.get("id"), "installed mutation did not reserve an operation")
        original, selected = operation["id"], operation
        deadline = time.monotonic() + 120
        while True:
            if selected.get("error"):
                raise FixtureError(selected["error"])
            need(selected.get("id") == original, "operation poll selected another operation")
            if target:
                need(selected.get("life_id") in (None, target["life_id"])
                     and selected.get("run") in (None, target["run"]), "operation selected another life/run")
            if selected.get("status") == "succeeded":
                need(selected.get("last_seq", 0) > 0, "completed operation lacks a commit sequence")
                return selected
            need(selected.get("status") in ("pending", "running") and time.monotonic() < deadline,
                 "operation did not complete before its bound")
            selected = self.read("operation.get", {"operation_id": original})
            if selected.get("status") in ("pending", "running"):
                time.sleep(0.1)

    def lane(self, record):
        lane = self.read("lane.status", {"life_id": record["target"]["life_id"], "run": 0})
        need(lane.get("life_id") == record["target"]["life_id"] and lane.get("run", 0) >= record["target"]["run"],
             "installed lane status selected another life or an older run")
        return lane

    def observe(self, record, running=False):
        lane = self.lane(record)
        target = {"life_id": lane["life_id"], "run": lane["run"]}
        check = self.control("lane.check", target, lane["life_id"], lane["generation"])
        need(check.get("handle", {}).get("target") == target and check.get("handle", {}).get("containment_id")
             and check.get("observed_at"), "lane.check did not measure the actual target")
        if running:
            need(check.get("state") == "running" and check.get("survivors", 0) > 0,
                 "fixture target has no live contained process")
        self.observations[(target["life_id"], target["run"])] = check
        return lane, check

    def quiescent(self, record):
        deadline = time.monotonic() + 120
        while True:
            lane, check = self.observe(record)
            if check.get("state") == "exited":
                need(check.get("survivors") == 0 and
                     (type(check.get("exit_code")) is int or type(check.get("signal")) is int),
                     "fixture target has unknown exit or survivors")
                record["quiescent"] = True
                return self.lane(record), check
            need(check.get("state") == "running" and time.monotonic() < deadline,
                 "fixture target did not become quiescent")
            time.sleep(0.1)

    def stop(self, record):
        lane = self.lane(record)
        if lane.get("state") in ("running", "starting", "stopping"):
            reason = self.case.human.upload("dash-stop-reason", "task", b"Collect disposable dashboard fixture.\n")
            target = {"life_id": lane["life_id"], "run": lane["run"]}
            request = {"target": target, "expected_generation": lane["generation"], "reason": reason}
            record["stop_attempted"] = True
            operation = self.control("lane.stop", request, lane["life_id"], lane["generation"])
            self.await_operation(operation, target)
        return self.quiescent(record)

    def capture_ready(self, record):
        """Wait for the real release/drain journal, not merely process exit."""
        target = record["target"]
        deadline = time.monotonic() + 120
        while True:
            cursor, seen, events = "", set(), []
            while True:
                params = dict(target, since=0, cursor=cursor, follow=False, until="", deadline_ms=1000)
                page = self.read("event.tail", params)
                need(isinstance(page.get("events"), list), "capture readiness has no actual run history")
                events.extend(page["events"])
                if page.get("complete") is True:
                    break
                cursor = page.get("cursor")
                need(cursor and cursor not in seen and len(seen) < 512, "capture readiness cursor did not advance")
                seen.add(cursor)
            binding, streams, closed = None, set(), set()
            for event in events:
                if event.get("origin") != "service" or event.get("life_id") != target["life_id"] or event.get("run") != target["run"]:
                    continue
                payload = event.get("payload", {})
                if event.get("kind") == "capture.bound" and payload.get("target") == target:
                    need(binding is None or binding == payload.get("id"), "capture readiness has ambiguous primary bindings")
                    binding = payload.get("id")
                    streams = {row["id"] for row in payload.get("streams", [])}
                if event.get("kind") == "capture.closed" and payload.get("binding_id") == binding and payload.get("eof") is True:
                    closed.add(payload["stream_id"])
            if streams and streams <= closed:
                return
            need(time.monotonic() < deadline, "capture readiness did not reach every actual committed EOF")
            time.sleep(0.1)

    def launch(self, aid):
        self.stage("launch-" + aid.lower())
        request = copy.deepcopy(self.launches[aid])
        need(request.get("level") in (5, 6) and request.get("role") and not request.get("root_ticket_id"),
             "dashboard action target requires a real unticketed root launch request")
        # The service validates the full supplied role/project/task/grants.
        # Publication may have advanced through the genuine D6 change above;
        # use its observed current policy generation in this new intent.
        identity = self.read("identity.self", {})
        need(identity.get("config") == self.case.config and identity.get("policy_generation", 0) > 0,
             "launch lacks the current authenticated policy generation")
        request["expected_policy_generation"] = identity["policy_generation"]
        ticket = self.root_ticket(request) if hasattr(self, "root_manifest_ref") else self.case.human.ticket(request, self.case.root_grants)
        request["root_ticket_id"] = ticket["id"]
        proof = self.case.human.proof("read", "human.session", {}, self.case.human.public["principal_id"], 0)
        self.stage("launch-" + aid.lower())
        operation = self.case.checked_cli("dashboard-start", ["lane", "start"], request,
            session_proof=str(proof), idempotency_key="dash-start-" + uuid.uuid4().hex)
        need(operation.get("life_id") and operation.get("run") == 1, "fixture start lacks its actual reserved target")
        target = {"life_id": operation["life_id"], "run": operation["run"]}
        need(all(record["target"]["life_id"] != target["life_id"] for record in self.records.values()),
             "dashboard actions share a target life")
        record = {"name": "dash-" + aid.lower(), "driver": request["driver"], "request": request,
                  "target": target, "operation": operation, "stop_attempted": False, "quiescent": False, "collected": False}
        self.records[aid] = record
        self.case.lane_records.append(record)
        if hasattr(self.case, "item_lives"):
            self.case.item_lives.append(record)
        self.await_operation(operation, target)
        lane, observed = self.observe(record, running=True)
        if aid == "DASH-MERGED":
            relay = self.relay_factory(record)
            record["relay"] = relay
            relay.wait("grants.ready")
            runtime = json.loads(self.case.publication_blob(self.case.initial["runtime"]))
            tools = [row for row in runtime["objects"] if row["id"] == "dashboard-check" and row["role"] == "tool"]
            need(len(tools) == 1, "dashboard test fixture executable is not actually enrolled")
            tool = tools[0]
            executable = {"id": tool["id"], "sha256": tool["content"]["sha256"], "version": self.case.agent["version"]}
            record["test_child_request"] = relay.call("fixture snapshot", {"executable": executable, "budget": record["request"]["budget"]})
            need(record["test_child_request"].get("child") == target, "candidate upload selected another actual child")
            relay.request("fixture exit", {})
            lane, observed = self.quiescent(record)
            need(observed.get("exit_code") == 0 and not observed.get("signal"), "review target did not exit successfully")
            self.capture_ready(record)
        elif aid in ("DASH-RESUME", "DASH-ABANDONED"):
            lane, observed = self.stop(record)
        self.case.passed({"lane": lane, "observation": observed, "operation": operation})
        return record

    def root_ticket(self, request):
        """Issue actual case grants/ticket for the one enrolled project tree."""
        params = {"manifest": self.root_manifest_ref, "budget": request["budget"]}
        proof = self.browser.proof("grants.root", params, self.case.config, 0)
        grants = self.browser.rpc("grants.root", params, proof)
        need(grants.get("id") and grants.get("generation", 0) > 0 and not grants.get("parent_life_id")
             and not grants.get("revoked") and grants.get("policy_generation") == request["expected_policy_generation"],
             "case root grants do not match actual current authority")
        tree = self.case.dashboard_boot["project_tree"]
        data = [row for row in grants.get("data", []) if row.get("source_object_id") == tree["id"]
            and row.get("source_sha256") == tree["sha256"] and row.get("destination") == "/work/main"
            and row.get("relative_path") == "." and row.get("history_scope") == "tree"]
        profiles = [row for row in grants.get("profiles", []) if row.get("driver") == request["driver"]]
        need(len(grants.get("data", [])) == len(data) == 1 and len(profiles) == 1,
             "case root grant does not select its one actual project and profile")
        member, profile = data[0], profiles[0]
        need(member.get("id") and profile.get("id") and profile.get("paid") is False,
             "case root members lack actual issued identities or unpaid provenance")
        request["grants"] = {name: [] for name in ("resources", "data", "secrets", "profiles", "network", "channels")}
        request["grants"]["data"] = [{"parent_grant_id": member["id"], **{key: member[key] for key in
            ("relative_path", "access", "delivery", "destination", "delegate", "expires_at")}}]
        request["grants"]["profiles"] = [{"parent_grant_id": profile["id"], "profile_id": profile["profile_id"],
            "delegate": profile["delegate"], "expires_at": profile["expires_at"]}]
        request["profile_grant_id"] = profile["id"]
        expiry = min(datetime.fromisoformat(grants["expires_at"].replace("Z", "+00:00")), datetime.now(timezone.utc) + timedelta(seconds=90))
        params = {"level": request["level"], "role": request["role"], "grant_set_id": grants["id"],
            "expires_at": expiry.isoformat(timespec="microseconds").removesuffix("+00:00").rstrip("0").rstrip(".") + "Z"}
        proof = self.browser.proof("ticket.issue", params, grants["id"], grants["generation"])
        ticket = self.browser.rpc("ticket.issue", params, proof)
        need(ticket.get("id") and ticket.get("principal_id") == self.case.human.public["principal_id"]
            and ticket.get("config") == self.case.config and ticket.get("redeemed") is False
            and all(ticket.get(key) == value for key, value in params.items()), "case ticket differs from actual issued root authority")
        self.case.passed({"root_grants": grants, "root_ticket": ticket})
        return ticket

    def prepare_change(self):
        self.stage("change")
        need(callable(self.l6) and isinstance(self.change, dict),
             "actual L6 actor and exact org proposal input are required")
        identity = self.l6("identity.self", {})
        actor = identity.get("actor", {})
        need(identity.get("config") == self.case.config and actor.get("kind") == "lane"
             and actor.get("level") == 6 and actor.get("life_id"), "org proposal caller is not an authentic L6 lane")
        change = self.l6("org.change.propose", self.change)
        need(change.get("id") and change.get("requester") == actor and change.get("manifest_sha256")
             and change.get("base_generation") == self.change.get("base_generation"),
             "D6 proposal does not match its actual L6 caller/base")
        params = {"change_id": change["id"], "manifest_sha256": change["manifest_sha256"],
                  "base_generation": change["base_generation"]}
        proof = self.browser.proof("org.change.approve", params, change["id"], change["base_generation"])
        approval = self.browser.rpc("org.change.approve", params, proof)
        need(approval.get("id") and approval.get("change_id") == change["id"]
             and approval.get("manifest_sha256") == change["manifest_sha256"], "D6 approval differs from proposal")
        receipt = self.l6("org.change.apply", {"change_id": change["id"], "approval_id": approval["id"],
                                              "expected_generation": change["base_generation"]})
        need(receipt.get("change_id") == change["id"] and receipt.get("approval_id") == approval["id"]
             and receipt.get("new_generation", 0) > change["base_generation"], "D6 change was not actually applied")
        current = self.browser.rpc("org.change.get", {"change_id": change["id"]})
        need(current.get("id") == change["id"] and current.get("status") == "applied", "D6 read-back is not applied")
        self.case.passed({"change": change, "approval": approval, "application": receipt, "readback": current})

    def prepare(self):
        need(set(self.launches) == set(ACTIONS), "all five independent actual launch requests are required")
        if hasattr(self, "setup"):
            self.setup()
        self.stage("decision")
        content = self.case.human.upload("dash-decision", "record", b"Keep dashboard fixture evidence private.\n")
        params = {"action": "add", "content": content, "expected_generation": 0}
        decision = self.control("decisions.mutate", params, "decisions", 0)
        readback = self.read("records.get", {"record_id": decision["id"]})
        need(readback == decision and decision.get("origin") == "service", "canonical decision lacks actual read-back")
        self.case.passed({"decision": decision, "readback": readback})
        # Ended/review targets first; the live stop target is launched last so
        # setup cannot consume its finite wall budget before the view probes.
        for aid in ("DASH-RESUME", "DASH-MERGED", "DASH-ABANDONED", "HUMAN-SEND", "DASH-STOP"):
            self.launch(aid)
        # Complete the launches against the current root grant publication
        # before the D6 generation changes. Each action still signs its current
        # lane generation immediately before dispatch.
        self.prepare_change()
        if hasattr(self, "prepare_accounting"):
            self.prepare_accounting()
        self.stage("mail")
        recipient = self.records["HUMAN-SEND"]["target"]["life_id"]
        content = self.case.human.upload("dash-view-mail", "report", b"Dashboard raw-view fixture mail.\n")
        params = {"recipient_life_id": recipient, "content": content, "ask": False}
        proof = self.browser.proof("mail.send", params, self.case.config, 0)
        mail = self.browser.rpc("mail.send", params, proof)
        need(mail.get("source") == "dashboard" and mail.get("sender", {}).get("kind") == "human",
             "fixture mail lost human/dashboard provenance")
        self.case.passed({"mail": mail})
        self.stage("populated")
        # Capture gaps, refusal accounting, configured-only instances and
        # materialized plugin bytes must come from real publication/capture/
        # launch operations. An unavailable producer is never seeded here.
        for aid, name in self.consumer.VIEW_ASSERTIONS:
            value = self.browser.view(name)
            self.browser.recorder.save("producer/" + name + ".json", value)
            need(self.consumer.populated(aid, value), "real populated fixture is missing: " + aid)
            if aid == "DASH-RAW":
                need(partial_gap_bound(value), "raw-view gap is not bound to an actual partial primary record")
        self.case.passed({"views": [aid for aid, _ in self.consumer.VIEW_ASSERTIONS]})

    def action(self, aid):
        need(aid in ACTIONS and aid not in self.prepared, "unknown or already prepared dashboard action")
        self.phase = "run"
        self.stage("action-" + aid.lower())
        record = self.records[aid]
        lane = self.lane(record)
        method = ACTIONS[aid]
        target = {"life_id": lane["life_id"], "run": lane["run"]}
        params = {"target": target, "expected_generation": lane["generation"]}
        generation, proof_target = lane["generation"], lane["life_id"]
        if aid == "DASH-STOP":
            self.observe(record, running=True)
            params["reason"] = self.case.human.upload("dash-action-stop", "task", b"Stop the dashboard action target.\n")
        elif aid == "DASH-RESUME":
            self.quiescent(record)
            lane = self.lane(record)
            params["expected_generation"], generation = lane["generation"], lane["generation"]
            params["message"] = self.case.human.upload("dash-action-resume", "task", b"Resume the dashboard action target.\n")
            params["budget"] = record["request"]["budget"]
        elif aid == "DASH-MERGED":
            # The genuine service review runs its actual worker/verifier and
            # reads the ended inventory. There is no hand-authored receipt.
            review = copy.deepcopy(self.reviews(aid, target) if callable(self.reviews) else self.reviews[aid])
            need(review.get("target") == target, "review inputs refer to another real target")
            proof = self.browser.proof("lane.review", review, proof_target, generation)
            receipt = self.browser.rpc("lane.review", review, proof)
            need(receipt.get("id") and receipt.get("coverage") == "complete" and receipt.get("evidence"),
                 "actual verified complete review is required before merged")
            lane = self.lane(record)
            acceptance = {"target": target, "state": "accepted", "review": receipt, "expected_generation": lane["generation"]}
            approval = self.browser.proof("lane.mark", acceptance, proof_target, lane["generation"])
            operation = self.await_operation(self.browser.rpc("lane.mark", acceptance, approval), target)
            record["accepted_operation"] = operation
            lane = self.lane(record)
            need(lane.get("state") == "accepted" and lane["generation"] == acceptance["expected_generation"] + 1,
                 "reviewed target has no actual accepted read-back")
            self.case.passed({"acceptance_operation": operation, "accepted_readback": lane})
            params.update({"state": "merged", "review": receipt, "expected_generation": lane["generation"]})
            generation = lane["generation"]
        elif aid == "DASH-ABANDONED":
            params.update({"state": "abandoned", "review": empty_review()})
        else:
            content = self.case.human.upload("dash-action-mail", "report", b"Human dashboard action message.\n")
            params = {"recipient_life_id": lane["life_id"], "content": content, "ask": False}
            generation = 0
            proof_target = self.case.config
        proof = self.browser.proof(method, params, proof_target, generation)
        envelope = self.consumer.build_rpc_envelope(self.case.config, method, params, proof)
        path = self.case.keep_json("dash-" + aid.lower() + ".request.json", envelope)
        path.chmod(0o600)
        self.prepared[aid] = envelope
        self.case.passed({"prepared_request": envelope, "execution": "awaiting case-owned HTTPS mutation"})
        return path

    def collect(self):
        self.phase = "collection"
        self.stage("collection")
        rows = []
        for aid, record in self.records.items():
            lane = self.lane(record)
            record["target"] = {"life_id": lane["life_id"], "run": lane["run"]}
            lane, check = self.stop(record)
            if lane.get("state") not in ("merged", "abandoned"):
                request = {"target": record["target"], "expected_generation": lane["generation"],
                           "state": "abandoned", "review": empty_review()}
                self.await_operation(self.control("lane.mark", request, lane["life_id"], lane["generation"]), record["target"])
            lane = self.lane(record)
            archive = self.control("lane.archive", {"target": record["target"], "expected_generation": lane["generation"]},
                                   lane["life_id"], lane["generation"])
            need(archive.get("id") and archive.get("archive_sha256") == archive.get("read_back_sha256"),
                 "external target archive lacks actual verified read-back")
            lane = self.lane(record)
            params = {"target": record["target"], "expected_generation": lane["generation"], "archive_receipt_id": archive["id"]}
            operation = self.await_operation(self.control("lane.clean", params, lane["life_id"], lane["generation"]), record["target"])
            native = self.case.native_cleanup_evidence(record, lane, operation)
            final = self.lane(record)
            need(final.get("cleaned") is True, "external target was not collected")
            rows.append({"target": record["target"], "check": check, "status": final, "archive": archive,
                         "clean_operation": operation, "native": native,
                         "accepted_operation": record.get("accepted_operation"),
                         "test_operation": record.get("test_operation"),
                         "observations": [value for (life, _), value in self.observations.items() if life == lane["life_id"]]})
            record["collected"] = True
        self.case.human_prefix = self.initial_prefix
        self.case.passed({"targets": rows})
        return {"schema": "laneboss.dash-collection.v2", "targets": rows,
                "presence": "simulated", "human_approval": "not_proven"}


def from_checkpoint(case, require, fail):
    """Construct real requests from G0's installed publication, never IDs."""
    spec = importlib.util.spec_from_file_location("dash_grants_relay", Path(__file__).with_name("case_grants.py"))
    grants = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(grants)
    proposals = case.decode_document(case.root_launch_input(case.lane_inputs))
    require(isinstance(proposals.get("codex"), dict), "dashboard checkpoint lacks the installed launch proposal")
    launches = {}
    for aid in ACTIONS:
        request = copy.deepcopy(proposals["claudock-cli"] if aid == "DASH-MERGED" else proposals["codex"])
        request["lane"] = "dash-" + aid.lower().replace("dash-", "") + "-" + uuid.uuid4().hex[:6]
        request["budget"] = case.dashboard_boot["budget"]
        request["project_id"] = case.dashboard_boot["project_id"]
        launches[aid] = request
    data = DashData(case, launches, None, None, None)

    class Relay(grants.Relay):
        def values_now(self):
            return relay_values(self, grants.flow.events(case, self.record, require))

        def request(self, command, request, *, denied=False, request_id=None, key=None):
            require(not self.record.get("refused"), "dashboard relay stopped at its first owning refusal")
            nonce = uuid.uuid4().hex
            message = {"schema": "laneboss.item-rpc.v1", "nonce": nonce, "command": command, "request": request,
                       "request_id": request_id or uuid.uuid4().hex, "idempotency_key": key or uuid.uuid4().hex}
            content = case.human.upload("dash-relay", "report", grants.io.encoded(message))
            params = {"recipient_life_id": self.record["target"]["life_id"], "content": content, "ask": False}
            proof = data.browser.proof("mail.send", params, case.config, 0)
            accepted = data.browser.rpc("mail.send", params, proof)
            require(accepted.get("id") and accepted.get("content") == content, "dashboard relay mail differs from committed input")
            reply = self.wait("grants.exiting" if command == "fixture exit" else "grants.reply", nonce)
            if not denied:
                self.refusal(reply)
            return reply

    data.relay_factory = lambda record: Relay(case, record, require, fail)

    def setup():
        data.root_manifest_ref = case.human.upload("dash-case-root", "manifest",
            (json.dumps(case.dashboard_boot["case_root"], sort_keys=True) + "\n").encode())
        request = copy.deepcopy(proposals["codex"])
        request.update({"lane": "dash-l6-" + uuid.uuid4().hex[:8], "level": 6, "role": "supervisor",
                        "budget": case.dashboard_boot["budget"], "project_id": case.dashboard_boot["project_id"]})
        data.launches["DASH-L6"] = request
        record = data.launch("DASH-L6")
        relay = Relay(case, record, require, fail)
        record["relay"] = relay
        ready = relay.wait("grants.ready")
        require(ready.get("identity", {}).get("actor", {}).get("level") == 6,
                "dashboard D6 caller is not an actual L6 lane")
        data.l6 = lambda method, params: relay.call(method.replace(".", " "), params)
        plugin = relay.upload("artifact", base64.b64decode(case.dashboard_boot["plugin_bytes"], validate=True))
        configured = relay.upload("artifact", b'level = 3\nrole = "reviewer"\n')
        reason = relay.upload("task", b"Publish the disposable dashboard plugin and configured-only review instance.\n")
        data.change = {"org_id": case.config, "base_generation": case.initial_receipt["generation"], "reason": reason,
            "files": [{"path": case.dashboard_boot["plugin_path"], "action": "add", "mode": 0o444, "after": plugin},
                      {"path": "instances/L3-dashboard.toml", "action": "add", "mode": 0o444, "after": configured}]}
        sources = json.loads(case.publication_blob(case.initial["sources"]))
        canonical = [row for row in sources["sources"] if row["source"]["path"] == ".laneboss/policy.json"]
        require(len(canonical) == 1, "dashboard fixture lacks its actual canonical policy source")
        source = canonical[0]
        document = json.loads(case.publication_blob(source["content"]))
        fake_pin = hashlib.sha256((case.stage / "e2e/v2/cases/dashboard/scored-judge.json").read_bytes()).hexdigest()
        document["judge"].update({"max_bytes": 262144, "max_questions": 12,
            "deployment_sha256": fake_pin, "tokenizer_sha256": fake_pin})
        critical = copy.deepcopy(document["rules"][0])
        critical.update({"id": "dashboard-fixture-critical", "critical": True,
            "text": "An unfunded dashboard fixture evaluation has no scored permission.",
            "instead": "Retain the explicit unscored fixture accounting."})
        document["rules"].append(critical)
        updated = relay.upload("artifact", (json.dumps(document, sort_keys=True) + "\n").encode())
        data.change["files"].append({"path": source["source"]["path"], "action": "replace", "mode": source["mode"],
            "before_sha256": source["source"]["sha256"], "after": updated})
        policy_request = copy.deepcopy(proposals["codex"])
        policy_request.update({"lane": "dash-policy-" + uuid.uuid4().hex[:8],
            "project_id": case.dashboard_boot["project_id"],
            "budget": dict(case.dashboard_boot["budget"], spend_micros=1000000)})
        data.launches["DASH-POLICY"] = policy_request
        data.launch("DASH-POLICY")

    def accounting():
        data.stage("accounting")
        review_lane = data.lane(data.records["DASH-MERGED"])
        identity = data.read("identity.self", {})
        review_requirements(case, review_lane["workspace"]["project_id"], identity["policy_generation"])
        # A true unfunded critical decision remains unscored. Scored results
        # below come only from the explicitly enrolled fake ScopedJudge port.
        for aid, scored in (("DASH-L6", False), ("DASH-POLICY", True)):
            record = data.records[aid]
            lane = data.lane(record)
            for attempt in range(32 if scored else 1):
                raw = ("dashboard accounting " + uuid.uuid4().hex).encode()
                request = {"target": record["target"], "logical_turn_id": lane["logical_turn_id"], "command": {
                    "tool": "shell", "command": base64.b64encode(raw).decode(), "argv": [], "declared_paths": [],
                    "cwd": "/work/main", "raw_sha256": hashlib.sha256(raw).hexdigest()}}
                decision = data.browser.rpc("policy.evaluate", request)
                need(decision.get("audit_complete") is True and decision.get("input", {}).get("id"),
                     "accounting decision has no actual retained policy audit")
                observation = json.loads(case.publication_blob(decision["input"]))
                need(observation.get("request") == request, "policy accounting retained different input")
                data.case.passed({"policy_decision": decision, "source": "dashboard-fake-sha256-question-v1" if scored else "zero-spend policy"})
                matches = [row for row in decision.get("rules", []) if row.get("result") == "refuse"
                    and ((row.get("probability") is not None) if scored else (row.get("probability") is None))]
                if matches:
                    if scored:
                        replies = [batch.get("reply", {}) for batch in observation.get("batches", [])]
                        need(replies and all(reply.get("reported_model") == "dashboard-fake-sha256-question-v1" for reply in replies),
                             "scored accounting did not use the enrolled fake source")
                    break
            else:
                raise ValueError("fake policy fixture did not produce its required refusal band")
    data.setup = setup
    data.prepare_accounting = accounting
    data.reviews = lambda aid, target: review_inputs(data, target)
    return data


def review_inputs(data, target):
    """Prepare from the installed freeze/check producers before lane.review."""
    from fixture_io import FixtureError
    prepare = getattr(getattr(getattr(data, "browser", None), "handoff", None), "review_prepare", None)
    if not callable(prepare):
        raise FixtureError({"owner": "lb-v2-grants", "code": "prerequisite_missing",
            "message": "native review preparation and measured TestChild results are required"})
    result = prepare(target)
    data.case.keep_json("dash-review-prepared.json", result)
    need(result.get("subject", {}).get("target") == target and result.get("required_checks"),
         "native preparation selected another subject or omitted protected check requirements")
    if result.get("missing_checks"):
        records = [record for record in getattr(data, "records", {}).values() if record["target"] == target]
        if len(records) != 1 or not records[0].get("test_child_request"):
            raise FixtureError({"owner": "lb-v2-grants", "code": "prerequisite_missing",
                "message": "measured TestChild output and its actual child-produced candidate are required"})
        record = records[0]
        lane = data.lane(record)
        params = record["test_child_request"]
        need(params.get("child") == target, "test job selected another actual child")
        executor = getattr(data.case, "item_test_child", None)
        if executor is None:
            raise FixtureError({"owner": "lb-v2-grants", "code": "prerequisite_missing",
                "message": "installed TestChild dispatch and result collection are required"})
        proof = data.browser.proof("grants.test-child", params, target["life_id"], lane["generation"])
        measured = executor.execute(params, lambda request: data.browser.rpc("grants.test-child", request, proof),
            subject=result["subject"], required=result["missing_checks"])
        record["test_operation"] = measured["operation"]
        result = prepare(target)
        data.case.keep_json("dash-review-measured.json", result)
        need(result.get("subject", {}).get("target") == target and not result.get("missing_checks"),
             "completed TestChild did not produce the exact frozen subject's required checks")
    request = result["request"]
    need(request.get("diff", {}).get("class") == "diff" and request.get("record_inventory", {}).get("class") == "manifest"
         and request.get("checks") and all(item.get("class") == "check" for item in request["checks"]),
         "worker review input lacks measured diff/check/inventory references")
    return request
