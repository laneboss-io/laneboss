"""Inert verifier-unit inputs. Never imported by a live case or observer."""

import copy
from datetime import datetime, timedelta, timezone
import os

from draft4 import SESSION_MUTATIONS, canonical, intent_digest
from ladder import structure
from ladder_transactions import METHOD_FOR_EVENT
from support import atomic_bytes, bytes_hash, encoded, evidence, sha256


def observation(life, run):
    return {"state": "exited", "exit_code": 0, "survivors": 0,
            "prompt_status": "completed", "handle": {
                "id": "process-" + life, "generation": "unit-generation-" + str(run),
                "containment_id": "containment-" + life.removeprefix("unit-life-"),
                "target": {"life_id": life, "run": run}}}


def make_run(root, seed=7, config="tree-a", empty_stderr=False):
    nodes = structure(seed)
    events, lanes, by_name, inventory, reports = [], [], {}, {}, {}
    created_seqs = {}
    readbacks = []
    expected = {item["name"]: {"path": os.urandom(8).hex() + "/challenge",
                              "token": os.urandom(16).hex()} for item in nodes}
    pings = {item["name"]: os.urandom(16).hex() for item in nodes}
    human = {"kind": "human", "id": "unit-human"}
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    root_ticket = {"principal_id": human["id"], "config": config, "endpoint_generation": 1,
                   "id": "unit-ticket", "level": 6, "role": "supervisor", "grant_set_id": "unit-grants",
                   "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat().replace("+00:00", "Z"),
                   "redeemed": False}
    caller_scope = {"config": config, "actor": human, "endpoint_generation": 1, "policy_generation": 1}
    mutations = []
    session_event = None

    def actor(name):
        return {"kind": "lane", "id": "unit-actor-" + name,
                "life_id": "unit-life-" + name}

    def add(kind, name, run, payload, requester=None, causal=None):
        lane = by_name[name]
        seq = len(events) + 1
        if kind in ("mail.queued", "report.submitted"):
            payload = {"generation": 1, "artifacts": [], "id": "unit-mail-" + str(seq),
                       "source": "cli", "queued_seq": seq, "status": "queued", "ask": False,
                       **payload}
        event = {"schema": 2, "config": config, "id": "unit-event-" + str(seq),
                 "seq": seq, "kind": kind, "origin": "service",
                 "life_id": lane["life_id"], "run": run,
                 "logical_turn_id": "turn-" + name + "-" + str(run),
                 "actor": requester or actor(name),
                 "requested_by": requester or actor(name),
                 "request_id": os.urandom(16).hex(), "operation_id": "unit-op-" + str(seq),
                 "starter_chain": lane["starter_chain"],
                 "root_life_id": lane["root_life_id"],
                 "starter_event_seq": lane["starter_event_seq"], "payload": payload}
        if lane.get("parent_life_id"):
            event["parent_life_id"] = lane["parent_life_id"]
        if kind in ("human.session", "human.proof.used", "ticket.issued", "ticket.redeemed"):
            for field in ("life_id", "run", "logical_turn_id", "parent_life_id", "root_life_id"):
                event.pop(field, None)
        events.append(event)
        if causal is not None:
            event["operation_id"], event["request_id"] = causal["operation_id"], causal["request_id"]
            event["requested_by"] = causal["requested_by"]
            event["actor"] = {"kind": "service", "id": "unit-scheduler"}
            item = next(item for item in mutations if item["request"]["request_id"] == causal["request_id"])
            item["event_ids"].append(event["id"])
        elif kind in METHOD_FOR_EVENT:
            rpc_record(event)
        return event

    def blob(data, category="report"):
        key = "unit-blob-" + str(len(inventory))
        path = root / key
        atomic_bytes(path, data)
        inventory[key] = evidence(root, path)
        return {"id": key, "sha256": bytes_hash(data), "bytes": len(data),
                "class": category}

    def rpc_record(event):
        from ladder import SCENARIO
        from support import load
        kind, payload = event["kind"], event["payload"]
        method = METHOD_FOR_EVENT[kind]
        target = {"life_id": event["life_id"], "run": event["run"]} if "life_id" in event else {}
        result = {"id": event["operation_id"], "status": "succeeded", **target,
                  "first_seq": event["seq"], "last_seq": event["seq"]}
        if kind == "lane.created":
            lane = payload["lane"]
            body = {"lane": lane["name"], "project_id": "unit-project", "level": lane["level"],
                    "role": lane["role"], "task": lane["task"], "driver": lane["session"]["driver"],
                    "profile_grant_id": "unit-profile", "model": "unit-model", "effort": "max",
                    "budget": lane["budget_remaining"], "expected_policy_generation": 1,
                    "grants": {field: [] for field in
                               ("resources", "data", "secrets", "profiles", "network", "channels")}}
            if not event.get("parent_life_id"):
                body["root_ticket_id"] = root_ticket["id"]
        elif kind in ("human.session", "ticket.issued", "blob.committed"):
            body = ({} if kind == "human.session" else
                    {key: payload[key] for key in ("level", "role", "grant_set_id")} if
                    kind == "ticket.issued" else {"object_id": payload["id"]})
            result = payload
        elif kind == "lane.turn":
            body = {"target": target, "expected_generation": event["seq"], "mail_ids": payload["mail_ids"]}
        elif kind == "lane.loop":
            body = {"target": target, "expected_generation": event["seq"], "enabled": True,
                    "backoff_ms": 1000}
        elif kind in ("mail.queued", "report.submitted"):
            body = {"content": payload["content"], "ask": payload["ask"]}
            if kind == "mail.queued":
                body["recipient_life_id"] = payload["recipient_life_id"]
            else:
                body["artifacts"] = payload["artifacts"]
            if "reply_to" in payload:
                body["reply_to"] = payload["reply_to"]
            result = payload
        elif kind == "lane.reviewed":
            body = {"target": target, **{field: payload[field] for field in
                    ("diff", "checks", "record_inventory", "refusal_resolution")}}
            result = payload
        elif kind == "lane.state":
            review = next(item["payload"] for item in events if item["kind"] == "lane.reviewed" and
                          item["life_id"] == event["life_id"])
            body = {"target": target, "expected_generation": event["seq"],
                    "state": payload["to"], "review": review}
        elif kind == "archive.verified":
            body = {"target": target, "expected_generation": event["seq"]}
            result = payload
        else:
            body = {"target": target, "expected_generation": event["seq"],
                    "archive_receipt_id": payload["archive_receipt"]["id"]}
        request = {"protocol": "laneboss.rpc.v2", "schema": 2, "config": config,
                   "request_id": event["request_id"], "idempotency_key": os.urandom(16).hex(),
                   "method": method, "params": copy.deepcopy(body),
                   "request_sha256": intent_digest(config, method, body)}
        if method == "human.session":
            request["proof"] = {"id": "unit-read-proof", "request_sha256": request["request_sha256"],
                                "expires_at": root_ticket["expires_at"]}
        row = load(SCENARIO / "draft4-writes.json")["rows"][method]
        guards = ["Cancellation"] if method in (
            "lane.start", "lane.adopt", "lane.resume", "lane.turn", "grants.revoke",
            "mail.send", "report.submit") else []
        if event["requested_by"]["kind"] == "human" and method not in SESSION_MUTATIONS:
            guards.append("Ticket" if method in ("lane.start", "lane.adopt") else "Proof")
        shape = {"fields": row["fields"].split(), "effects": row["effects"].split(),
                 "events": [kind] if kind in row["events"].split() else [],
                 "guards": guards, "reply": True}
        if method in ("lane.start", "lane.adopt", "lane.resume", "lane.turn"):
            guards = ["Cancellation"] if method in ("lane.resume", "lane.turn") else []
            if event["requested_by"]["kind"] == "human":
                guards.append("Ticket" if method in ("lane.start", "lane.adopt") else "Proof")
            shape = {"kind": "launch_reservation", "fields": ["LaunchPlans"], "events": [],
                     "effects": ["PlanLaunch"], "guards": guards, "reply": True}
        receipt = {"config": config, "actor": event["requested_by"],
                   "policy_generation": 1, "simulated_presence": False,
                   "key": {key: request[key] for key in
                           ("method", "idempotency_key", "request_sha256")},
                   "operation_id": event["operation_id"], "first_seq": event["seq"],
                   "last_seq": event["seq"], "reply": {"result": copy.deepcopy(result)}}
        mutations.append({"request": request, "actor": event["requested_by"], "receipt": receipt,
                          "response": {"protocol": "laneboss.rpc.v2", "schema": 2,
                                       "request_id": request["request_id"], "last_seq": event["seq"],
                                       "result": copy.deepcopy(result)},
                          "transaction": shape, "event_ids": [event["id"]], "replayed": False,
                          "policy_context": {"current_generation": 1, "use": "fresh"}})

    def extend_receipt(original, generated):
        generated["operation_id"] = original["operation_id"]
        generated["request_id"] = original["request_id"]
        item = next(item for item in mutations if item["request"]["request_id"] == original["request_id"])
        item["receipt"]["last_seq"] = generated["seq"]
        item["response"]["last_seq"] = generated["seq"]
        if "last_seq" in item["response"]["result"]:
            item["response"]["result"]["last_seq"] = generated["seq"]
            item["receipt"]["reply"]["result"]["last_seq"] = generated["seq"]
        item["event_ids"].append(generated["id"])

    def capture(name, run):
        for stream in ("stdout", "stderr", "transcript"):
            binding = "capture-" + name + "-" + str(run)
            stream_id = binding + "-" + stream
            data = os.urandom(0 if empty_stderr and stream == "stderr" else 24)
            if data:
                add("capture.appended", name, run, {
                    "target": {"life_id": by_name[name]["life_id"], "run": run},
                    "binding_id": binding, "stream_id": stream_id,
                    "stream": stream, "offset": 0, "data": blob(data, "capture"),
                    "primary": stream != "transcript", "coverage": "complete"})
            add("capture.closed", name, run, {"binding_id": binding, "record_id": "close-" + stream_id,
                "stream_id": stream_id, "offset": len(data), "next_offset": len(data),
                "generation": 2, "last_seq": len(events) + 1, "eof": True, "replayed": False})

    base_budget = {"wall_ms": 10000, "cpu_seconds": 100, "memory_bytes": 1000000,
                   "processes": 32, "disk_bytes": 1000000,
                   "spend_micros": 1000000, "currency": "USD"}
    for index, node in enumerate(nodes):
        parent = by_name.get(node["parent"])
        lane = {"life_id": "unit-life-" + node["name"], "name": node["name"],
                "role": "supervisor" if node["level"] > 3 else "executor",
                "model": "unit-model", "effort": "max", "profile_grant_id": "unit-profile",
                "task": blob(os.urandom(16), "task"),
                "level": node["level"], "run": 2, "state": "merged" if parent else "verifying",
                "counters": {"failures": 0, "retries": 0},
                "cancellation_epoch": 3 if parent else 1,
                "launch_id": "launch-" + node["name"], "generation": 1,
                "grant_set_id": "unit-grants-" + node["name"] if parent else "unit-grants",
                "policy_generation": 1, "last_seq": 1, "containment": "linux-bwrap-landlock",
                "cleaned": bool(parent), "budget_remaining": base_budget,
                "workspace": {"id": "workspace-" + node["name"], "project_id": "unit-project",
                              "base": "unit-base", "branch": node["name"], "logical_cwd": "/workspace",
                              "snapshot": blob(os.urandom(12), "snapshot")},
                "session": {"id": "session-" + node["name"], "vendor_id": "unit-vendor",
                            "vendor_version": "unit-only", "driver": node["driver"],
                            "home_id": "home-" + node["name"],
                            "history_id": "history-" + node["name"]},
                "starter_chain": (parent["starter_chain"] + [parent["life_id"]]
                                  if parent else []),
                "root_life_id": parent["root_life_id"] if parent else "unit-life-l6",
                "starter_event_seq": created_seqs[node["parent"]] if parent else 0}
        if parent:
            lane["parent_life_id"] = parent["life_id"]
        by_name[node["name"]] = lane
        if node["name"] == "l6":
            session_event = add("human.session", "l6", 1, {
                "id": "unit-session", "expires_at": root_ticket["expires_at"],
                "idle_expires_at": root_ticket["expires_at"], "config": config}, human)
            used = add("human.proof.used", "l6", 1, {"proof_id": "unit-read-proof",
                       "credential_id": "unit-credential", "nonce_id": "unit-nonce",
                       "operation_id": session_event["operation_id"], "used_at": now}, human)
            extend_receipt(session_event, used)
            add("ticket.issued", "l6", 1, copy.deepcopy(root_ticket), human)
            redeemed = add("ticket.redeemed", "l6", 1, {**root_ticket, "redeemed": True}, human)
        created_lane = {**copy.deepcopy(lane), "run": 1, "cancellation_epoch": 0}
        event = add("lane.created", node["name"], 1, {"lane": created_lane},
                    actor(node["parent"]) if parent else human)
        created_seqs[node["name"]] = event["seq"]
        if not parent:
            redeemed["operation_id"], redeemed["request_id"] = event["operation_id"], event["request_id"]
            item = mutations[-1]
            item["event_ids"].append(redeemed["id"])
            item["receipt"].update(first_seq=redeemed["seq"], last_seq=redeemed["seq"])
            item["response"]["last_seq"] = redeemed["seq"]
            for result in (item["response"]["result"], item["receipt"]["reply"]["result"]):
                result.update(status="pending", first_seq=redeemed["seq"], last_seq=redeemed["seq"])
        add("helper.allocated", node["name"], 1, {
            "id": "lease-" + node["name"], "uid": 62101 + index,
            "gid": 62101 + index, "containment_id": "containment-" + node["name"],
            "endpoint_generation": 1})
        add("identity.bound", node["name"], 1, {"target": {
            "life_id": lane["life_id"], "run": 1}, "host_uid": 62101 + index,
            "uid_lease_id": "lease-" + node["name"],
            "containment_id": "containment-" + node["name"]})
        add("lane.started", node["name"], 1, {
            "lane": created_lane, "boundary_backend": "linux-bwrap-landlock",
            "trigger": {"mail_ids": []}})
        add("runner.session", node["name"], 1, copy.deepcopy(lane["session"]))
        lanes.append(lane)
    root_loop = add("lane.loop", "l6", 1, {"enabled": True}, actor("l6"))
    for node in nodes:
        name = node["name"]
        capture(name, 1)
        add("lane.ended", name, 1, {
            "observation": observation(by_name[name]["life_id"], 1), "profile_continuation": False,
            "budget_remaining": {**base_budget, "wall_ms": 9000}, "reason": "exit"})
    manual = []
    for node in nodes:
        name, parent = node["name"], node["parent"]
        ping = None
        mail_ids = []
        if name == "l3a":
            sender = actor("l3b")
            sibling = add("mail.queued", "l3a", 2, {
                "id": "unit-sibling-mail", "sender": sender,
                "recipient_life_id": by_name[name]["life_id"],
                "content": blob(encoded({"kind": "NOTE"}))}, sender)
            mail_ids.append(sibling["payload"]["id"])
        if parent:
            ping = add("mail.queued", name, 2, {
                "id": "unit-ping-" + name, "sender": actor(parent),
                "recipient_life_id": by_name[name]["life_id"],
                "content": blob(encoded({"kind": "PING", "nonce": pings[name]}))}, actor(parent))
            mail_ids.append(ping["payload"]["id"])
        if name == "l3a":
            turn = add("lane.turn", name, 2, {"mail_ids": mail_ids}, actor(parent))
            manual.append({"event_id": turn["id"], "requester": actor(parent),
                           "first_mail_sender": actor("l3b")})
        else:
            add("lane.turn", name, 2, {"mail_ids": mail_ids}, actor(parent) if parent else actor("l6"),
                causal=root_loop if not parent else None)
        index = next(index for index, lane in enumerate(lanes) if lane["life_id"] == by_name[name]["life_id"])
        add("identity.bound", name, 2, {"target": {"life_id": by_name[name]["life_id"], "run": 2},
            "host_uid": 62101 + index, "uid_lease_id": "lease-" + name,
            "containment_id": "containment-" + name})
        add("lane.resumed", name, 2, {
            "lane": {**copy.deepcopy(by_name[name]), "cancellation_epoch": 1, "budget_remaining": {
                **base_budget, "wall_ms": 9000}},
            "boundary_backend": "linux-bwrap-landlock", "trigger": {"mail_ids": mail_ids}})
        if parent:
            add("mail.delivered", name, 2, {
                "mail_id": ping["payload"]["id"], "logical_turn_id": "turn-" + name + "-2",
                "target": {"life_id": by_name[name]["life_id"], "run": 2},
                "prompt_status": "completed"})
            add("report.submitted", name, 2, {
                "sender": actor(name), "recipient_life_id": by_name[parent]["life_id"],
                "reply_to": ping["payload"]["id"],
                "content": blob(encoded({"kind": "PONG", "nonce": pings[name]}))})
            add("mail.returned", name, 2, {
                "mail_id": ping["payload"]["id"], "logical_turn_id": "turn-" + name + "-2",
                "target": {"life_id": by_name[name]["life_id"], "run": 2},
                "prompt_status": "completed"})
        capture(name, 2)
    for node in reversed(nodes):
        name, parent = node["name"], node["parent"]
        life = by_name[name]["life_id"]
        descendants = [{"node": item, **answer} for item, answer in expected.items()
                       if item == name or life in by_name[item]["starter_chain"]]
        ref = blob(encoded({"kind": "RESULT", "answers": descendants}))
        reports[name] = ref
        if parent:
            add("report.submitted", name, 2, {
                "sender": actor(name), "recipient_life_id": by_name[parent]["life_id"],
                "content": ref})
        else:
            add("blob.committed", name, 2, ref)
        add("lane.ended", name, 2, {
            "observation": observation(life, 2), "profile_continuation": False,
            "budget_remaining": {**base_budget, "wall_ms": 8000}, "reason": "exit"})
        if parent:
            review = {"id": "review-" + name, "reviewer": actor(parent),
                      "refusal_resolution": [],
                      "coverage": "complete", "checks": [blob(os.urandom(8))],
                      "diff": blob(os.urandom(8)), "record_inventory": blob(os.urandom(8))}
            ended = events[-1]
            capture_id = "capture-" + name + "-2"
            subject = {"target": {"life_id": life, "run": 2}, "launch_id": "launch-" + name + "-2",
                       "generation": 1, "end_event_id": ended["id"], "end_seq": ended["seq"],
                       "snapshot": by_name[name]["workspace"]["snapshot"], "session_id": by_name[name]["session"]["id"],
                       "inventory_seq": ended["seq"], "capture_binding_id": capture_id,
                       "streams": [{"id": capture_id + "-" + stream, "stream": stream, "pipe_id": "pipe-" + stream}
                                   for stream in ("stdout", "stderr")], "refusal_ids": []}
            review["evidence"] = {"schema": "laneboss.review.v2", "subject": subject,
                "verifier_lease_id": "review-worker-" + name, "diff": review["diff"], "coverage": "complete",
                "checks": [{"name": "unit-check", "receipt": review["checks"][0], "target": subject["target"],
                    "end_seq": ended["seq"], "snapshot_sha256": subject["snapshot"]["sha256"], "exit_code": 0,
                    "worker_lease_id": "test-worker-" + name, "operation_id": "test-operation-" + name}],
                "inventory": {"manifest": review["record_inventory"], "through_seq": ended["seq"],
                    "tool_records": blob(os.urandom(8)), "tool_coverage": "complete",
                    "streams": [{"binding_id": capture_id, "stream_id": stream["id"], "start_offset": 0,
                        "end_offset": next(event["payload"]["next_offset"] for event in events if
                            event["kind"] == "capture.closed" and event["payload"]["stream_id"] == stream["id"]),
                        "eof": True, "gap_ids": []} for stream in subject["streams"]]}, "resolutions": []}
            add("lane.reviewed", name, 2, review, actor(parent))
            for state in ("accepted", "merged"):
                marked = add("lane.state", name, 2, {"to": state, "review_id": review["id"]}, actor(parent))
                if state == "merged":
                    cancelled = add("watchdog.cancelled", name, 2, {"reason": "merged",
                        "retry_after_ms": 0, "budget_remaining": by_name[name]["budget_remaining"]}, actor(parent))
                    extend_receipt(marked, cancelled)
            content = blob(os.urandom(24), "archive")
            digest = content["sha256"]
            archive = {"id": "archive-" + name, "archive_sha256": digest,
                       "life_id": life, "verified_at": now,
                       "read_back_sha256": digest, "store_id": "unit-store",
                       "manifest": blob(os.urandom(8))}
            readbacks.append({"life_id": life, "archive_receipt_id": archive["id"],
                              "content": content, "read_back_sha256": digest})
            add("archive.verified", name, 2, archive, actor(parent))
            released = add("helper.released", name, 2, {
                "id": "release-" + name, "lease_id": "lease-" + name,
                "containment_id": "containment-" + name, "backend": "linux-bwrap-landlock",
                "operation_id": "pending", "effect_id": "effect-" + name,
                "quiescence": observation(life, 2), "live_connections": 0,
                "queued_jobs": 0, "writable_exports": 0, "observed_at": now}, actor(parent))
            released["payload"]["operation_id"] = released["operation_id"]
            cleaned = add("lane.cleaned", name, 2, {
                "archive_receipt": archive, "quiescence": observation(life, 2),
                "removed_object_ids": ["workspace-" + name]}, actor(parent))
            cancelled = add("watchdog.cancelled", name, 2, {"reason": "cleaned",
                "retry_after_ms": 0, "budget_remaining": by_name[name]["budget_remaining"]}, actor(parent))
            extend_receipt(cleaned, cancelled)
    waits = [{"life_id": item["life_id"], "run": item["run"],
              "reader_life_id": item["parent_life_id"], "event_id": item["id"],
              "event_seq": item["seq"], "visible": True, "clock_id": "unit-clock",
              "commit_ns": item["seq"]*100, "received_ns": item["seq"]*100 + 1}
             for item in events if item["kind"] == "lane.ended" and item.get("parent_life_id")]
    probes = [{"reader_life_id": left["life_id"], "target_life_id": right["life_id"],
               "own_read": True, "sibling_read": False, "private_mail_read": False,
               "private_session_read": False, "probe_id": "unit-probe",
               "containment_id": "containment-" + left["name"]}
              for left in lanes for right in lanes
              if left["life_id"] != right["life_id"] and left.get("parent_life_id") and
              left.get("parent_life_id") == right.get("parent_life_id")]
    sources = {"unit-source": bytes_hash(os.urandom(16))}
    read_request = {"protocol": "laneboss.rpc.v2", "schema": 2, "config": config,
                    "request_id": os.urandom(16).hex(), "idempotency_key": "",
                    "method": "identity.self", "params": {},
                    "request_sha256": intent_digest(config, "identity.self", {})}
    reads = [{"request": read_request, "actor": human,
              "response": {"protocol": "laneboss.rpc.v2", "schema": 2,
                           "request_id": read_request["request_id"], "last_seq": len(events),
                           "result": caller_scope},
              "transaction": {"fields": [], "events": [], "effects": [], "guards": [], "reply": False},
              "connection_id": "unit-connection",
              "session": {"connection_id": "unit-connection", "proof_id": "unit-read-proof",
                          "event_id": session_event["id"], "generation": 2,
                          "expires_at": root_ticket["expires_at"], "idle_expires_at": root_ticket["expires_at"],
                          "simulated_presence": False}}]
    original = next(item for item in mutations if item["request"]["method"] == "lane.start" and
                    item["actor"]["kind"] == "human")
    mutations.remove(original)
    mutations.insert(0, original)
    replay = copy.deepcopy(original)
    replay["request"]["request_id"] = os.urandom(16).hex()
    replay["response"]["request_id"] = replay["request"]["request_id"]
    replay.update(replayed=True, event_ids=[], transaction={
        "fields": [], "events": [], "effects": [], "guards": [], "reply": True})
    replay["policy_context"]["use"] = "exact_replay"
    mutations.append(replay)
    intents = [{**{key: item["request"][key] for key in
                   ("config", "method", "request_id", "idempotency_key", "request_sha256")},
                "session_proof_id": ""} for item in mutations]
    intents.append({**{key: read_request[key] for key in
                       ("config", "method", "request_id", "idempotency_key", "request_sha256")},
                    "session_proof_id": "unit-read-proof"})
    run = {"config": config, "events": events, "lanes": lanes, "blobs": inventory,
           "root_ticket": root_ticket, "caller_scope": caller_scope, "mutations": mutations,
           "reads": reads,
           "client_intents": intents,
           "root_answers": [{"node": name, **answer} for name, answer in expected.items()],
           "waits": waits, "manual_requests": manual, "privacy": probes,
           "archive_readbacks": readbacks,
           "review_requirements": {lane["life_id"]: ["unit-check"] for lane in lanes if lane.get("parent_life_id")},
           "unresolved": [], "kernel_final": [
               {"life_id": lane["life_id"], "processes": [], "known": True,
                "host_uid": 62101 + index, "containment_id": "containment-" + lane["name"],
                "observed_ns": len(events)*100 + 2}
               for index, lane in enumerate(lanes)],
           "sources_before": sources, "sources_after": copy.deepcopy(sources),
           "presence": {"simulated_presence": False, "presence": "not_measured", "human_approval": "not_measured"}}
    from ladder_audits import fill_audits
    fill_audits(run, blob)
    plan = {"seed": seed, "answers": {config: expected}, "pings": {config: pings}}
    return run, plan, reports


def replace_report(root, run, ref, body):
    path = root / run["blobs"][ref["id"]]["path"]
    data = encoded(body)
    atomic_bytes(path, data)
    updated = {**ref, "sha256": bytes_hash(data), "bytes": len(data)}
    run["blobs"][ref["id"]] = evidence(root, path)

    def visit(value):
        if isinstance(value, dict):
            if value.get("id") == ref["id"] and "sha256" in value:
                value.update(updated)
            else:
                for item in value.values():
                    visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(run["events"])


def live_sample(refs, uid_by_life=None, images=None):
    items = []
    for index, (config, life) in enumerate(sorted(refs), 1):
        uid = uid_by_life[(config, life)] if uid_by_life else 63000 + index
        identity = {"pid": 100 + index, "start": os.urandom(8).hex(), "uids": [uid]*4}
        digest = images[(config, life)] if images else bytes_hash(os.urandom(32))
        items.append({"config": config, "life_id": life, "before": identity,
                      "after": copy.deepcopy(identity), "before_ns": 1, "after_ns": 3,
                      "executable_before_sha256": digest, "executable_after_sha256": digest})
    return {"live_refs": items, "observed_ns": 2, "clock_id": "unit-clock"}


def make_pair(root):
    runs, plan = [], {"seed": 7, "answers": {}, "pings": {}}
    hashes, files = {}, {}
    for name in ("binary", "helper", "claudock-cli", "claude", "codex"):
        source, kept = root / ("source-" + name), root / ("kept-" + name)
        data = os.urandom(32)
        atomic_bytes(source, data)
        atomic_bytes(kept, data)
        hashes[name] = sha256(kept)
        files[name] = {"source": str(source), "kept": kept.name}
    for index, config in enumerate(("tree-a", "tree-b")):
        scope = root / config
        scope.mkdir()
        run, private, _ = make_run(scope, config=config)
        for item in run["blobs"].values():
            item["path"] = config + "/" + item["path"]

        def separate(value):
            if isinstance(value, dict):
                return {key: (number + index*100 if key in ("host_uid", "uid", "gid")
                              else separate(number))
                        for key, number in value.items()}
            if isinstance(value, list):
                return [separate(item) for item in value]
            if isinstance(value, str):
                return value.replace("workspace-", "workspace-" + config + "-").replace(
                    "unit-store", "unit-store-" + config)
            return value

        run = separate(run)
        for audit in run["launch_audits"]:
            audit["identity"]["record_sha256"] = bytes_hash(canonical(audit["record"]).encode("utf-8"))
        run["binding"] = {
            "store_id": "unit-store-" + config, "socket": "/run/unit-" + config,
            "service_uid": 62100 + index*100,
            "lane_uids": list(range(62101 + index*100, 62111 + index*100)),
            "workspace_ids": [lane["workspace"]["id"] for lane in run["lanes"]]}
        run["artifact_hashes"], run["artifact_files"] = hashes, files
        runs.append(run)
        plan["answers"].update(private["answers"])
        plan["pings"].update(private["pings"])
    lives = {(run["config"], lane["life_id"]) for run in runs for lane in run["lanes"]}
    uids = {(run["config"], record["life_id"]): record["host_uid"]
            for run in runs for record in run["kernel_final"]}
    images = {(run["config"], lane["life_id"]): hashes[
        "claude" if lane["session"]["driver"] == "claudock-cli" else "codex"]
        for run in runs for lane in run["lanes"]}
    plan["load_samples"] = [live_sample(lives, uids, images)]
    return runs, plan
