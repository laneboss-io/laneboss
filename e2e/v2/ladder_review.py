"""Closed live-review evidence correlated with public ended/capture facts."""

from ladder import blob, check
from support import exact_keys, integer


def review_evidence(review, lane, events, required, root, inventory):
    evidence = review.get("evidence")
    check(isinstance(evidence, dict), "cleanup", "historical review without live Evidence cannot authorize a mark")
    exact_keys(evidence, ("schema", "subject", "verifier_lease_id", "diff", "checks", "inventory", "resolutions", "coverage"))
    subject, retained = evidence["subject"], evidence["inventory"]
    exact_keys(subject, ("target", "launch_id", "generation", "end_event_id", "end_seq", "snapshot", "session_id",
                         "inventory_seq", "capture_binding_id", "streams", "refusal_ids"))
    ended = [event for event in events if event["kind"] == "lane.ended" and
             event["life_id"] == lane["life_id"] and event["run"] == lane["run"]]
    check(len(ended) == 1 and subject["target"] == {"life_id": lane["life_id"], "run": lane["run"]} and
          subject["launch_id"] == lane["launch_id"] == ended[0]["payload"]["launch_id"] and
          subject["session_id"] == lane["session"]["id"] and subject["end_event_id"] == ended[0]["id"] and
          subject["end_seq"] == ended[0]["seq"] and integer(subject["generation"], 1) and
          integer(subject["inventory_seq"], subject["end_seq"]) and evidence["schema"] == "laneboss.review.v2" and
          evidence["coverage"] == review["coverage"] == "complete" and bool(evidence["verifier_lease_id"]),
          "cleanup", "review subject differs from the authentic ended run or frozen inventory")
    check(evidence["diff"] == review["diff"] and bool(blob(root, subject["snapshot"], inventory)),
          "cleanup", "review diff or snapshot differs from its frozen evidence")
    facts = evidence["checks"]
    check(required and len(required) == len(set(required)) and len(facts) == len(required) and
          {fact["name"] for fact in facts} == set(required) and
          [fact["receipt"] for fact in facts] == review["checks"],
          "cleanup", "review omitted or replaced a protected required check")
    for fact in facts:
        exact_keys(fact, ("name", "receipt", "target", "end_seq", "snapshot_sha256", "exit_code", "worker_lease_id", "operation_id"))
        check(fact["target"] == subject["target"] and fact["end_seq"] == subject["end_seq"] and
              fact["snapshot_sha256"] == subject["snapshot"]["sha256"] and type(fact["exit_code"]) is int and
              fact["exit_code"] == 0 and bool(fact["worker_lease_id"]) and bool(fact["operation_id"]),
              "cleanup", "review check failed or belongs to another snapshot/run/worker")
        blob(root, fact["receipt"], inventory)
    exact_keys(retained, ("manifest", "through_seq", "streams", "tool_records", "tool_coverage"))
    check(retained["manifest"] == review["record_inventory"] and retained["through_seq"] ==
          subject["inventory_seq"] and retained["tool_coverage"] == "complete" and
          bool(blob(root, retained["tool_records"], inventory)),
          "cleanup", "review inventory or tool coverage is incomplete")
    streams = {stream["id"] for stream in subject["streams"]}
    check(streams and len(streams) == len(subject["streams"]) and
          {fact["stream_id"] for fact in retained["streams"]} == streams and
          len(retained["streams"]) == len(streams), "cleanup", "review lacks a required stream inventory")
    for fact in retained["streams"]:
        exact_keys(fact, ("binding_id", "stream_id", "start_offset", "end_offset", "eof", "gap_ids"))
        closed = [event for event in events if event["kind"] == "capture.closed" and
                  event.get("life_id") == lane["life_id"] and event.get("run") == lane["run"] and
                  event["payload"]["binding_id"] == fact["binding_id"] and
                  event["payload"]["stream_id"] == fact["stream_id"]]
        chunks = sorted((event["payload"] for event in events if event["kind"] == "capture.appended" and
                         event.get("life_id") == lane["life_id"] and event.get("run") == lane["run"] and
                         event["payload"]["binding_id"] == fact["binding_id"] and
                         event["payload"]["stream_id"] == fact["stream_id"]), key=lambda value: value["offset"])
        position = 0
        for chunk in chunks:
            data = blob(root, chunk["data"], inventory)
            check(chunk["offset"] == position, "cleanup", "review stream has a missing or overlapping byte range")
            position += len(data)
        check(fact["binding_id"] == subject["capture_binding_id"] and fact["start_offset"] == 0 and
              integer(fact["end_offset"]) and fact["end_offset"] == position and
              fact["eof"] is True and fact["gap_ids"] == [] and
              len(closed) == 1 and closed[0]["origin"] == "service" and
              closed[0]["seq"] <= subject["inventory_seq"] and closed[0]["payload"]["eof"] is True and
              closed[0]["payload"]["next_offset"] == fact["end_offset"],
              "cleanup", "review stream is undrained, gapped or lacks an authentic EOF")
    resolutions = evidence["resolutions"]
    check({item["refusal_id"] for item in resolutions} == set(subject["refusal_ids"]) ==
          set(review["refusal_resolution"]) and len(resolutions) == len(subject["refusal_ids"]),
          "cleanup", "review has unresolved or repeated refusal evidence")
    for resolution in resolutions:
        check(integer(resolution["event_seq"], 1, subject["inventory_seq"]),
              "cleanup", "refusal resolution falls outside the pinned inventory")
        blob(root, resolution["evidence"], inventory)
