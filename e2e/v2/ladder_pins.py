"""Checks over retained launch/authority observations from the public reader.

launch_audits is proposed E2E normalization of service-issued retained objects;
it is never a public write or permission to read the management store.
"""

from draft4 import canonical, intent_digest, presence
from ladder import blob, check
from support import bytes_hash, decode, exact_keys, integer


def launch_audits(run, root):
    launches = {(event["life_id"], event["run"]): event for event in run["events"]
                if event["kind"] in ("lane.started", "lane.resumed")}
    events = {event["id"]: event for event in run["events"]}
    rows = run["launch_audits"]
    check(isinstance(rows, list) and len(rows) == len(launches),
          "launch-pins", "every launched run needs its retained reservation/binding")
    seen = set()
    for row in rows:
        exact_keys(row, ("reservation", "record", "prepared", "identity", "recovery",
                         "authority_event_id", "policy_at_release"))
        r, record, prepared, identity = (row[key] for key in ("reservation", "record", "prepared", "identity"))
        target = r["target"]
        key = (target["life_id"], target["run"])
        check(key in launches and key not in seen, "launch-pins", "duplicate or foreign launch audit")
        seen.add(key)
        event = launches[key]
        lane = event["payload"]["lane"]
        check(r["config"] == run["config"] and r["level"] == lane["level"] and
              r["role"] == lane["role"] and r["driver"] == lane["session"]["driver"] and
              r["launch_id"] == record["id"] == lane["launch_id"] and record["kind"] == "agent" and
              record["target"] == prepared["target"] == target and
              record["actor"]["kind"] == "lane" and record["actor"]["life_id"] == target["life_id"] and
              record["actor"]["level"] == r["level"] and record["actor"]["role"] == r["role"],
              "launch-pins", "reservation role/driver or prepared agent identity changed")
        fresh = r["mode"] in ("start", "adopt")
        check(r["mode"] in ("start", "adopt", "resume", "turn", "continue") and
              ((target["run"] == 1 and r["generation"] == 1 and r["base_generation"] == 0 and
                "previous_launch_id" not in r) if fresh else
               (target["run"] >= 2 and integer(r["base_generation"], 1) and
                r["generation"] == r["base_generation"] + 1 and r["previous_launch_id"] != r["launch_id"])) and
              record["config"] == r["config"] and record["revoked"] is False and
              bool(prepared["id"]) and bool(prepared["gate_id"]),
              "launch-pins", "reservation mode/generation or live prepared binding is invalid")
        binding = events.get(identity["event_id"])
        check(binding is not None and binding["kind"] == "identity.bound" and
              binding["origin"] == "service" and binding["payload"] == record and
              binding["seq"] == identity["committed_seq"] < event["seq"] and
              identity["launch_id"] == record["id"] and
              identity["record_sha256"] == bytes_hash(canonical(record).encode("utf-8")) and
              record["containment_id"] == prepared["containment_id"] and
              record["process_generation"] == prepared["process_generation"] and
              record["endpoint_generation"] == prepared["endpoint_generation"],
              "launch-pins", "prepared binding lacks its authentic committed identity")
        recovery = row["recovery"]
        handoff = recovery["handoff"]
        spec = handoff["spec"]
        check(recovery["plan_id"] == r["id"] and recovery["original_request"] == r["original_request"] and
              handoff["config"] == r["config"] and handoff["operation_id"] == r["operation_id"] and
              handoff["request_id"] == r["request_id"] and spec["id"] == r["spec_id"] and
              spec["launch_id"] == r["launch_id"] and spec["target"] == target and
              spec["uid_lease_id"] == record["uid_lease_id"] and
              spec["runner"]["driver"] == r["driver"] and
              recovery["home"]["life_id"] == target["life_id"] and
              recovery["capture"]["status"] == "registered" and recovery["capture"]["target"] == target,
              "launch-pins", "recovery replaced the retained plan/spec/home/capture")
        raw = blob(root, handoff["original"], run["blobs"])
        check(handoff["original"]["class"] == "launch_spec" and
              r["original_request"]["class"] == "launch_request" and
              bytes_hash(raw) == handoff["spec_sha256"] == prepared["spec_sha256"] and
              decode(raw) == spec and bytes_hash(canonical(spec).encode("utf-8")) == handoff["spec_sha256"],
              "launch-pins", "retained launch spec bytes or digest changed")
        request = decode(blob(root, r["original_request"], run["blobs"]))
        check(request["config"] == run["config"] and request["request_id"] == r["request_id"] and
              intent_digest(request["config"], request["method"], request["params"]) == r["request_sha256"],
              "launch-pins", "reservation lost the exact original request")
        check(integer(row["policy_at_release"], 1) and r["policy_generation"] == row["policy_at_release"] ==
              record["policy_generation"] == lane["policy_generation"] == spec["policy_generation"] == spec["grants"]["policy_generation"] and
              r["grant_set_id"] == record["grant_set_id"] == spec["grants"]["id"],
              "policy-generation", "sealed plan opened under changed policy or grant pins")
        authority = events.get(row["authority_event_id"])
        check(authority is not None and authority["origin"] == "service" and authority["seq"] < event["seq"],
              "launch-authority", "launch authority has no prior authentic receipt/binding")
        kind, identifier = r["authority"]["kind"], r["authority"]["id"]
        if kind == "ticket":
            check(r["requested_by"]["kind"] == "human" and r["mode"] in ("start", "adopt") and
                  authority["kind"] == "ticket.redeemed" and authority["payload"]["id"] == identifier and
                  authority["operation_id"] == r["operation_id"],
                  "launch-authority", "root did not retain its consumed ticket")
        elif kind == "proof":
            check(r["requested_by"]["kind"] == "human" and r["mode"] in ("resume", "turn") and
                  authority["kind"] == "human.proof.used" and authority["payload"]["proof_id"] == identifier and
                  authority["operation_id"] == r["operation_id"],
                  "launch-authority", "retained human turn did not consume its exact proof")
        else:
            check(kind == "starter" and r["requested_by"]["kind"] != "human" and
                  authority["kind"] == "identity.bound" and authority["payload"]["id"] == identifier and
                  authority["payload"]["kind"] == "agent" and
                  (authority["payload"]["target"]["life_id"] == r["requested_by"].get("life_id")
                   if r["requested_by"]["kind"] == "lane" else identifier == r["previous_launch_id"]) and
                  (r["mode"] != "continue" or identifier == r["previous_launch_id"]),
                  "launch-authority", "lane/continuation borrowed human authority or another starter")


def presence_report(run):
    marks = [presence(run["root_ticket"])]
    marks += [presence(item["receipt"]) for item in run["mutations"]]
    marks += [presence(event["payload"]) for event in run["events"] if event["kind"] in
              ("ticket.issued", "ticket.redeemed", "human.session", "human.proof.used")]
    simulated = any(marks)
    for event in run["events"]:
        if event["kind"] == "human.proof.used" and event["payload"]["credential_id"] == "laneboss-e2e-software-auth":
            check(presence(event["payload"]), "presence", "declared software credential lost its presence mark")
    report = run["presence"]
    exact_keys(report, ("simulated_presence", "presence", "human_approval"))
    check(presence(report) == simulated and report["presence"] ==
          ("simulated" if simulated else "not_measured") and report["human_approval"] ==
          ("not_proven" if simulated else "not_measured"),
          "presence", "aggregate promoted simulated or unmeasured presence to human approval")
    roots = [item for item in run["mutations"] if item["request"]["method"] == "lane.start" and
             item["actor"]["kind"] == "human"]
    check(all(presence(item["receipt"]) == presence(run["root_ticket"]) for item in roots),
          "presence", "root operation dropped its ticket's simulation mark")
    return report


def policy_history(run):
    for lane in run["lanes"]:
        launches = [event for event in run["events"] if event["kind"] in ("lane.started", "lane.resumed") and
                    event["life_id"] == lane["life_id"]]
        advances = [event for event in run["events"] if event["kind"] == "lane.policy" and
                    event["life_id"] == lane["life_id"]]
        previous = None
        for event in advances:
            value = event["payload"]
            exact_keys(value, ("from_generation", "to_generation", "lane_generation", "policy_sha256", "grant_set_id"))
            from ladder import valid_digest
            check(event["origin"] == "service" and event["actor"]["kind"] == "service" and
                  integer(value["from_generation"], 1) and integer(value["to_generation"], value["from_generation"] + 1) and
                  integer(value["lane_generation"], 1) and valid_digest(value["policy_sha256"]) and
                  bool(value["grant_set_id"]) and (previous is None or value["from_generation"] == previous),
                  "policy-generation", "lane policy history regressed or lacks approved causal pins")
            previous = value["to_generation"]
        known = [event["payload"]["lane"]["policy_generation"] for event in launches]
        known += [event["payload"]["to_generation"] for event in advances]
        for previous_launch, following in zip(launches, launches[1:]):
            before, after = (item["payload"]["lane"]["policy_generation"] for item in (previous_launch, following))
            check(after >= before and (after == before or any(
                  previous_launch["seq"] < event["seq"] < following["seq"] and
                  event["payload"]["to_generation"] == after for event in advances)),
                  "policy-generation", "fresh launch policy advanced without its authenticated projection event")
        check(lane["policy_generation"] == max(known),
              "policy-generation", "lane policy projection lacks its launch or refresh event")
