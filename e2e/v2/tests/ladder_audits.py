"""Inert launch-audit projections for verifier units, never installed inputs."""

from draft4 import canonical
from support import bytes_hash, encoded


def fill_audits(run, blob):
    events = run["events"]
    lanes = {lane["life_id"]: lane for lane in run["lanes"]}
    bindings = {(event["payload"]["target"]["life_id"], event["payload"]["target"]["run"]): event
                for event in events if event["kind"] == "identity.bound"}
    launches = [event for event in events if event["kind"] in ("lane.started", "lane.resumed")]
    for launch in launches:
        life, number = launch["life_id"], launch["run"]
        lane = launch["payload"]["lane"]
        lane["launch_id"] = "launch-" + lane["name"] + "-" + str(number)
        if number == lanes[life]["run"]:
            lanes[life]["launch_id"] = lane["launch_id"]
        for event in events:
            if event["kind"] == "lane.ended" and event["life_id"] == life and event["run"] == number:
                event["payload"]["launch_id"] = lane["launch_id"]
            if number == 1 and event["kind"] == "lane.created" and event["life_id"] == life:
                event["payload"]["lane"]["launch_id"] = lane["launch_id"]
        record = bindings[(life, number)]["payload"]
        record.update(kind="agent", id=lane["launch_id"], config=run["config"],
                      root_life_id=lane["root_life_id"], starter_chain=lane["starter_chain"],
                      starter_event_seq=lane["starter_event_seq"],
                      actor={"kind": "lane", "id": "principal-" + lane["name"], "life_id": life,
                             "level": lane["level"], "role": lane["role"]},
                      process_generation="unit-process-" + str(number), grant_set_id=lane["grant_set_id"],
                      grants_sha256=bytes_hash(encoded(lane["grant_set_id"])), policy_generation=1,
                      endpoint_generation=1, revoked=False)
    audits = []
    for launch in launches:
        life, number = launch["life_id"], launch["run"]
        lane = launch["payload"]["lane"]
        if number == 1:
            cause = next(item for item in run["mutations"] if item["request"]["method"] == "lane.start" and
                         item["request"]["params"]["lane"] == lane["name"] and not item["replayed"])
        else:
            turn = next(event for event in events if event["kind"] == "lane.turn" and
                        event["life_id"] == life and event["run"] == number)
            cause = next(item for item in run["mutations"] if turn["id"] in item["event_ids"])
        request, receipt = cause["request"], cause["receipt"]
        record = bindings[(life, number)]["payload"]
        parent = lane.get("parent_life_id")
        if number == 1 and not parent:
            authority = next(event for event in events if event["kind"] == "ticket.redeemed")
            authority_value = {"kind": "ticket", "id": run["root_ticket"]["id"]}
        else:
            authority = bindings[(parent, 1)] if parent else bindings[(life, number - 1)]
            authority_value = {"kind": "starter", "id": authority["payload"]["id"]}
        r = {"id": "reservation-" + lane["name"] + "-" + str(number), "config": run["config"],
             "mode": "start" if number == 1 else "turn", "target": {"life_id": life, "run": number},
             "level": lane["level"], "role": lane["role"], "driver": lane["session"]["driver"],
             "authority": authority_value, "launch_id": record["id"],
             "spec_id": "spec-" + lane["name"] + "-" + str(number), "grant_set_id": lane["grant_set_id"],
             "generation": number, "base_generation": number - 1, "cancellation_epoch": number - 1,
             "policy_generation": 1, "root_life_id": lane["root_life_id"],
             "starter_chain": lane["starter_chain"], "starter_event_seq": lane["starter_event_seq"],
             "operation_id": receipt["operation_id"], "request_id": request["request_id"],
             "request_sha256": request["request_sha256"], "requested_by": cause["actor"],
             "original_request": blob(encoded(request), "launch_request")}
        if parent:
            r["parent_life_id"] = parent
        if number > 1:
            r["previous_launch_id"] = bindings[(life, number - 1)]["payload"]["id"]
        spec = {"id": r["spec_id"], "launch_id": r["launch_id"], "target": r["target"],
                "uid_lease_id": record["uid_lease_id"], "policy_generation": 1,
                "runner": {"driver": r["driver"]}, "grants": {"id": r["grant_set_id"], "policy_generation": 1}}
        raw = canonical(spec).encode("utf-8")
        spec_ref = blob(raw, "launch_spec")
        prepared = {"id": "prepared-" + r["spec_id"], "spec_sha256": bytes_hash(raw), "target": r["target"],
                    "containment_id": record["containment_id"], "process_generation": record["process_generation"],
                    "endpoint_generation": record["endpoint_generation"], "gate_id": "gate-" + r["spec_id"]}
        recovery = {"plan_id": r["id"], "original_request": r["original_request"],
                    "home": {"life_id": life}, "capture": {"status": "registered", "target": r["target"]},
                    "handoff": {"config": r["config"], "spec": spec, "original": spec_ref,
                                "spec_sha256": bytes_hash(raw), "operation_id": r["operation_id"],
                                "request_id": r["request_id"]}}
        bound = bindings[(life, number)]
        audits.append({"reservation": r, "record": record, "prepared": prepared, "recovery": recovery,
                       "identity": {"launch_id": record["id"], "event_id": bound["id"],
                                    "committed_seq": bound["seq"],
                                    "record_sha256": bytes_hash(canonical(record).encode("utf-8"))},
                       "authority_event_id": authority["id"], "policy_at_release": 1})
    run["launch_audits"] = audits
