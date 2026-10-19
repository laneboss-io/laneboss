"""Read fix-9 metadata returned by the installed human-authorized event RPC."""


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def merge(existing, incoming):
    """Polling may overlap pages, but cannot rewrite any observed event."""
    result, by_id, by_seq = [], {}, {}
    for event in [*existing, *incoming]:
        identifier, sequence = event.get("id"), event.get("seq")
        require(isinstance(identifier, str) and identifier and type(sequence) is int and sequence > 0,
                "event identity or sequence absent")
        if identifier in by_id:
            require(by_id[identifier] == event, "observed event was rewritten")
        else:
            require(sequence not in by_seq, "event sequence reused by another identity")
            result.append(event)
            by_id[identifier], by_seq[sequence] = event, identifier
    return result


def observe(events, operation, config, pins):
    selected = [event for event in events if event.get("operation_id") == operation["id"]]
    planned = [event for event in selected if event.get("kind") == "launch.planned"]
    require(len(planned) == 1, "one real launch.planned event is required")
    event = planned[0]
    require(event.get("config") == config and event.get("origin") == "service" and
            type(event.get("seq")) is int and event["seq"] > 0, "launch event provenance differs")
    record = event["payload"]
    require(record.get("phase") == "planned" and record.get("generation", 0) > 0 and
            isinstance(record.get("plan"), dict), "launch plan is not sealed")
    plan = record["plan"]
    reservation = record["reservation"]
    target = {"life_id": operation["life_id"], "run": operation["run"]}
    require(plan.get("reservation") == reservation and reservation.get("config") == config and
            reservation.get("operation_id") == operation["id"] and reservation.get("target") == target and
            reservation.get("id") and reservation.get("launch_id") and reservation.get("spec_id"),
            "plan differs from the reserved operation")
    inputs, lease, data, runner = plan["inputs"], plan["lease"], plan["data"], plan["runner"]
    require(inputs["grants"]["id"] == reservation["grant_set_id"] and
            inputs["sources"]["reservation_id"] == reservation["id"] and
            data["reservation_id"] == reservation["id"] and data["target"] == target and
            data["lease_id"] == lease["id"] and data["home"]["life_id"] == target["life_id"] and
            runner["home"] == data["home"]["home"], "plan stage receipts differ")
    runtime = inputs["sources"]["runtime"]
    require(runner.get("driver") == runtime.get("driver") == "codex" and
            runner.get("executable") == runtime.get("executable") and
            runner["executable"]["sha256"] == pins["agent"] and
            runtime["manifest"]["sha256"] == pins["runtime"], "plan selected another enrolled runtime")
    capture = plan["capture"]
    require(capture.get("config") == config and capture.get("target") == target and
            capture.get("reservation_id") == reservation["id"] and
            capture.get("launch_id") == reservation["launch_id"] and
            capture.get("helper_lease_id") == lease["id"] and
            capture.get("operation_id") == reservation["operation_id"] and
            capture.get("request_id") == reservation["request_id"] and
            capture.get("requested_by") == reservation["requested_by"], "capture is from another launch")
    status = capture.get("status")
    require(status in ("registered", "refused"), "capture registration was not disposed before release")
    kind = "capture.bound" if status == "registered" else "capture.refused"
    bound = [row for row in selected if row.get("kind") == kind and row.get("payload") == capture]
    require(len(bound) == 1 and bound[0].get("config") == config and bound[0].get("origin") == "service" and
            bound[0].get("seq", 0) > 0, "capture disposition lacks its service event")
    starts = [row for row in selected if row.get("kind") == "run.started"]
    require(all(max(bound[0]["seq"], event["seq"]) < row["seq"] for row in starts),
            "capture or sealed plan was recorded after release")
    if status == "registered":
        require(capture.get("producer_id") and capture.get("producer_generation") and capture.get("boot_id") and
                capture.get("supervisor", {}).get("sha256") == pins["supervisor"] and
                capture.get("streams") and not capture.get("refusal"), "capture has no real pinned producer")
        streams = capture["streams"]
        require(all(row.get("id") and row.get("pipe_id") for row in streams) and
                len({row["id"] for row in streams}) == len(streams) and
                len({row["pipe_id"] for row in streams}) == len(streams) and
                len({row["stream"] for row in streams}) == len(streams) and
                {row["stream"] for row in streams} >= {"stdout", "stderr"}, "capture streams are incomplete")
    else:
        require(capture.get("refusal", {}).get("code") and capture["refusal"].get("owner"),
                "capture refusal lacks its actual typed owner")
    return {"plan": record, "capture": capture, "planned_seq": event["seq"], "capture_seq": bound[0]["seq"]}
