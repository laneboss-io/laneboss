"""Acceptance assertions shared by red controls and real outside observations.

These functions consume public v2 events/blobs and independent kernel/observer
receipts. They never manufacture a lifecycle event or infer success from text.
"""

from collections import defaultdict
import random

from support import (DIGEST, ROOT, Failure, beneath, decode, exact_keys, integer, load,
                     require, regular, sha256, verify_evidence)


SCENARIO = ROOT / "e2e" / "v2" / "ladder"


class LadderFailure(Failure):
    def __init__(self, check_id, message):
        super().__init__(message)
        self.check_id = check_id

    def wire(self):
        return {**super().wire(), "check_id": self.check_id}


def check(condition, name, message):
    if not condition:
        raise LadderFailure(name, message)


def structure(seed):
    require(integer(seed), "invalid ladder seed")
    scenario = load(SCENARIO / "scenario.json")
    require(scenario["schema"] == "laneboss.ladder-scenario.v2" and
            scenario["contract_revision"] == "v2.0-draft.4",
            "wrong ladder scenario contract")
    drivers = list(scenario["leaf_draw"])
    require(sorted(drivers) == ["claudock-cli", "claudock-cli", "codex", "codex"],
            "ladder needs two leaves of each runner")
    random.Random(seed).shuffle(drivers)
    nodes = []
    for item in scenario["nodes"]:
        exact_keys(item, ("name", "level", "parent", "runner", "brief"))
        driver = drivers.pop() if item["level"] == 3 else item["runner"]
        require(driver in ("claudock-cli", "codex") and
                (item["level"] == 3 or driver == "claudock-cli"),
                "unsupported ladder runner")
        nodes.append({key: item[key] for key in ("name", "level", "parent")}
                     | {"driver": driver, "brief": item["brief"]})
    require(not drivers and len(nodes) == 10 and
            sorted(item["level"] for item in nodes) == [3]*4 + [4]*3 + [5]*2 + [6],
            "invalid ten-instance scenario")
    return nodes


def answers(expected, actual):
    check(isinstance(actual, list), "answers", "answers are not an array")
    values = {}
    for item in actual:
        exact_keys(item, ("node", "path", "token"))
        check(item["node"] not in values, "answers", "duplicate node answer")
        values[item["node"]] = {"path": item["path"], "token": item["token"]}
    check(values == expected, "answers", "wrong/missing token or path")


def zero_exit(value, *, prompt=False):
    return (value.get("state") == "exited" and type(value.get("exit_code")) is int
            and value["exit_code"] == 0 and type(value.get("survivors")) is int
            and value["survivors"] == 0 and "signal" not in value and
            (not prompt or value.get("prompt_status") == "completed"))


def selected_end(event, life_id, run):
    check(event.get("origin") == "service" and event.get("kind") == "lane.ended" and
          event.get("life_id") == life_id and event.get("run") == run,
          "selected-end", "hidden/historical/observation end cannot finish a wait")
    check(event["payload"]["observation"].get("handle", {}).get("target") ==
          {"life_id": life_id, "run": run} and event["payload"].get("reason") == "exit",
          "selected-end", "end observation belongs to another run or a non-exit reason")
    check(zero_exit(event["payload"]["observation"], prompt=True), "survivors",
          "end lacks an actual successful exit with zero survivors")


def actor_matches(event, expected):
    check(event["actor"] == expected and event["requested_by"] == expected,
          "actor", "manual request borrowed a carried sender's identity")


def pinned_file(source, kept, expected):
    try:
        source = regular(source)
        kept = regular(kept)
    except (OSError, Failure) as error:
        raise LadderFailure("artifacts", "immutable executable is absent/unreadable") from error
    check(sha256(source) == sha256(kept) == expected,
          "artifacts", "immutable executable is absent or differs from retained bytes")


def concurrent_sample(lives, samples):
    expected = set().union(*lives)
    check(len(lives) == 2 and all(len(items) == 10 for items in lives)
          and len(expected) == 20, "concurrency", "two disjoint ten-instance trees required")
    for sample in samples:
        refs = sample["live_refs"]
        if {(item["config"], item["life_id"]) for item in refs} != expected:
            continue
        pivot = sample["observed_ns"]
        check(len(refs) == 20 and integer(pivot, 1) and bool(sample["clock_id"]),
              "concurrency", "overlap sample has duplicate lives or no common clock")
        processes = set()
        for item in refs:
            before, after = item["before"], item["after"]
            check(before == after and integer(before["pid"], 1) and before["start"] and
                  len(before["uids"]) == 4 and len(set(before["uids"])) == 1 and
                  integer(item["before_ns"], 1, pivot) and
                  integer(item["after_ns"], pivot),
                  "concurrency", "agent lifetime did not bracket the shared sample")
            check(item["executable_before_sha256"] == item["executable_after_sha256"] and
                  valid_digest(item["executable_before_sha256"]),
                  "artifacts", "vendor process image changed or was not observed")
            processes.add((before["pid"], before["start"]))
        check(len(processes) == 20, "concurrency", "one process impersonated several lives")
        return
    check(False, "concurrency", "no independent twenty-agent simultaneous load observation")


def wait_receipt(receipt, event, parent):
    selected_end(event, receipt["life_id"], receipt["run"])
    check(receipt["reader_life_id"] == parent and receipt["event_id"] == event["id"]
          and receipt["event_seq"] == event["seq"] and receipt["visible"] is True,
          "selected-end", "parent did not receive the authentic selected end")
    check(bool(receipt["clock_id"]), "end-latency", "parent timing has no shared clock domain")
    start, end = receipt["commit_ns"], receipt["received_ns"]
    check(integer(start, 1) and integer(end, start) and end - start <= 2_000_000_000,
          "end-latency", "parent wait exceeded two seconds from durable commit")


def ping_order(queued, delivered, launch, response, nonce):
    check(queued["payload"]["id"] == delivered["payload"]["mail_id"] and
          queued["seq"] < delivered["seq"] < response["seq"] and
          queued["seq"] < launch["seq"] < response["seq"],
          "ping-pong", "PONG preceded its actual queued/delivered turn")
    receipt = delivered["payload"]
    trigger = launch["payload"]["trigger"]
    check(receipt["prompt_status"] in ("written", "completed") and
          receipt["target"] == {"life_id": launch["life_id"], "run": launch["run"]} and
          queued["payload"]["id"] in trigger["mail_ids"] and
          receipt["logical_turn_id"] == launch["logical_turn_id"] and
          response["payload"]["reply_to"] == queued["payload"]["id"],
          "ping-pong", "PONG has no matching causal delivery")
    check(isinstance(nonce, str) and len(nonce) >= 16,
          "ping-pong", "empty/weak challenge nonce")


def ping_body(queued_body, pong_body, nonce):
    check(queued_body == {"kind": "PING", "nonce": nonce} and
          pong_body == {"kind": "PONG", "nonce": nonce},
          "ping-pong", "PING/PONG nonce differs from the planted nonce")


def blob(root, reference, inventory):
    check(reference["id"] in inventory, "transcript", "referenced blob was not retained")
    item = inventory[reference["id"]]
    try:
        verify_evidence(root, item)
    except (Failure, OSError) as error:
        raise LadderFailure("transcript", "retained blob hash/size mismatch or unreadable bytes") from error
    check(item["sha256"] == reference["sha256"] and item["bytes"] == reference["bytes"],
          "transcript", "retained blob does not match the service reference")
    return beneath(root, item["path"]).read_bytes()


def valid_digest(value):
    return isinstance(value, str) and DIGEST.fullmatch(value) is not None


def retained_blobs(run, root):
    for item in run["blobs"].values():
        try:
            verify_evidence(root, item)
        except (Failure, OSError) as error:
            raise LadderFailure("transcript", "retained blob inventory hash/size mismatch") from error

    def visit(value):
        if isinstance(value, dict):
            if set(value) == {"id", "sha256", "bytes", "class"}:
                blob(root, value, run["blobs"])
            else:
                for item in value.values():
                    visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
    for name in ("events", "lanes", "archive_readbacks"):
        visit(run[name])


def result_answers(events, root_life, root, inventory):
    results = []
    for event in events:
        if event["kind"] != "blob.committed" or event["actor"].get("life_id") != root_life:
            continue
        reference = event["payload"]
        if reference["class"] != "report":
            continue
        check(event["origin"] == "service", "answers", "root result is not a service event")
        try:
            body = decode(blob(root, reference, inventory))
        except Failure as error:
            if isinstance(error, LadderFailure):
                raise
            raise LadderFailure("answers", "root report is not a JSON result") from error
        if body.get("kind") == "RESULT":
            results.append(body["answers"])
    check(len(results) == 1, "answers", "L6 did not publish one retained RESULT blob")
    return results[0]


def graph(events, expected):
    created = [event for event in events if event["kind"] == "lane.created"]
    check(len(created) == 10, "graph", "tree does not have ten service-created lives")
    by_name = {}
    by_life = {}
    for event in created:
        check(event["origin"] == "service", "graph", "observation created a false starter")
        lane = event["payload"]["lane"]
        name = lane["name"]
        check(name not in by_name and lane["life_id"] not in by_life,
              "graph", "duplicate lane name/life")
        by_name[name] = event
        by_life[lane["life_id"]] = event
    check(set(by_name) == {node["name"] for node in expected}, "graph", "wrong instance set")
    for node in expected:
        event = by_name[node["name"]]
        lane = event["payload"]["lane"]
        check(event["life_id"] == lane["life_id"] and event["run"] == 1,
              "graph", "created lane envelope does not match its life/run")
        check(lane["level"] == node["level"] and
              lane["session"]["driver"] == node["driver"],
              "graph", "wrong role level or seeded driver")
        parent = by_name.get(node["parent"])
        if parent is None:
            check(node["parent"] == "" and lane["level"] == 6 and
                  not event.get("parent_life_id") and lane["starter_chain"] == [] and
                  lane["root_life_id"] == lane["life_id"] and
                  event["starter_event_seq"] == 0 and event["actor"]["kind"] == "human",
                  "graph", "root was not the authenticated L6 bootstrap")
        else:
            parent_lane = parent["payload"]["lane"]
            chain = parent_lane["starter_chain"] + [parent_lane["life_id"]]
            check(lane["level"] < parent_lane["level"] and
                  event["actor"]["kind"] == "lane" and
                  event["actor"]["life_id"] == parent_lane["life_id"] and
                  event["parent_life_id"] == lane["parent_life_id"] == parent_lane["life_id"] and
                  event["starter_event_seq"] == parent["seq"] < event["seq"] and
                  event["starter_chain"] == lane["starter_chain"] == chain and
                  lane["root_life_id"] == parent_lane["root_life_id"],
                  "graph", "child has an unauthentic/missing direct ancestor")
    return by_name


def report_answers(events, by_name, expected_answers, root, inventory):
    by_life = {event["life_id"]: name for name, event in by_name.items()}
    reports = {}
    pongs = []
    for event in events:
        if event["kind"] != "report.submitted":
            continue
        mail = event["payload"]
        check(event["origin"] == "service" and mail["sender"] == event["actor"],
              "report-line", "report sender is not the authenticated actor")
        sender = event["actor"].get("life_id")
        check(sender in by_life, "report-line", "unknown report sender")
        node = by_name[by_life[sender]]
        check(node.get("parent_life_id") == mail.get("recipient_life_id") and
              bool(mail.get("recipient_life_id")),
              "report-line", "report skipped its direct spawning parent")
        body = decode(blob(root, mail["content"], inventory))
        if body.get("kind") == "PONG":
            pongs.append((event, body))
            continue
        check(body.get("kind") == "RESULT" and sender not in reports,
              "answers", "missing/duplicate final result report")
        descendants = {name: answer for name, answer in expected_answers.items()
                       if sender == by_name[name]["life_id"] or
                       sender in by_name[name]["starter_chain"]}
        answers(descendants, body["answers"])
        reports[sender] = event
    children = {event["life_id"] for event in by_name.values()
                if event.get("parent_life_id")}
    check(set(reports) == children, "answers", "an ancestor omitted descendant answers")
    return pongs


def captures(events, lanes, root, inventory):
    streams = defaultdict(list)
    for event in events:
        check(event["kind"] != "capture.gap", "transcript", "primary capture has a gap")
        if event["kind"] != "capture.appended":
            continue
        capture = event["payload"]
        check(event["origin"] == "service" and capture["coverage"] == "complete" and
              "replacement_of" not in capture, "transcript", "incomplete/replaced capture")
        data = blob(root, capture["data"], inventory)
        key = (capture["target"]["life_id"], capture["target"]["run"], capture["stream"])
        streams[key].append((capture["offset"], data, capture["primary"]))
    for lane in lanes:
        for run in range(1, lane["run"] + 1):
            for category in ("primary", "transcript"):
                candidates = []
                for stream in ("stdout", "stderr", "vendor", "structured") if category == "primary" else ("transcript",):
                    chunks = streams.get((lane["life_id"], run, stream), [])
                    if chunks:
                        offset = 0
                        for start, data, primary in sorted(chunks):
                            check(start == offset and (primary or category == "transcript"),
                                  "transcript", "missing/overlapping primary byte range")
                            offset += len(data)
                        if offset > 0:
                            candidates.append(stream)
                check(bool(candidates), "transcript", "missing primary bytes or raw transcript")


def lifecycle(events, by_name, lanes):
    launches = defaultdict(list)
    sessions = defaultdict(list)
    ends = {}
    for event in events:
        if event["kind"] == "runner.session":
            check(event["origin"] == "service", "runtime", "session mapping is not authentic")
            sessions[event["life_id"]].append(event)
        if event["kind"] in ("lane.started", "lane.resumed"):
            check(event["origin"] == "service" and
                  event["payload"]["boundary_backend"] == "linux-bwrap-landlock",
                  "runtime", "launch did not use the actual Linux backend")
            launches[event["life_id"]].append(event)
        if event["kind"] == "lane.ended":
            key = (event["life_id"], event["run"])
            check(key not in ends, "selected-end", "duplicate end for a selected run")
            ends[key] = event
    by_life = {lane["life_id"]: lane for lane in lanes}
    created_by_life = {event["life_id"]: event for event in by_name.values()}
    check(set(by_life) == {event["life_id"] for event in by_name.values()},
          "runtime", "final lane inventory differs from authentic starters")
    for life, lane in by_life.items():
        runs = sorted(launches[life], key=lambda event: event["run"])
        check([event["run"] for event in runs] == list(range(1, lane["run"] + 1)),
              "runtime", "run history is incomplete")
        check(runs[0]["kind"] == "lane.started" and
              all(event["kind"] == "lane.resumed" for event in runs[1:]),
              "runtime", "run history uses an invalid launch/resume kind")
        turns = {event["logical_turn_id"] for event in runs}
        check(len(turns) >= 2 and "" not in turns,
              "runtime", "second credentialed logical turn is missing")
        mappings = sessions[life]
        check((life, 1) in ends, "selected-end", "first live run has no authentic end")
        check(bool(mappings) and runs[0]["seq"] < mappings[0]["seq"] <
              ends[(life, 1)]["seq"], "runtime", "real first-run session mapping is absent")
        actual = mappings[0]["payload"]
        check(all(item["payload"] == actual for item in mappings) and
              actual["vendor_id"] and actual["vendor_version"] and actual["driver"] ==
              created_by_life[life]["payload"]["lane"]["session"]["driver"],
              "runtime", "vendor session mapping is incomplete or changed")
        session = None
        remaining = None
        for index, event in enumerate(runs):
            launch = event["payload"]
            check(launch["lane"]["counters"] == {"failures": 0, "retries": 0},
                  "runtime", "profile continuation became a task failure or retry")
            current = launch["lane"]["session"]
            check(current["id"] == actual["id"] and
                  current["driver"] == lane["session"]["driver"] == actual["driver"] and
                  (index == 0 and not current["vendor_id"] or current["vendor_id"] == actual["vendor_id"]) and
                  (index == 0 and not current["vendor_version"] or
                   current["vendor_version"] == actual["vendor_version"]) and
                  current["home_id"] == actual["home_id"] and
                  current["history_id"] == actual["history_id"],
                  "runtime", "launch borrowed or changed the actual vendor session")
            identity = (current["id"], actual["vendor_id"], current["home_id"],
                        current["history_id"], current["driver"])
            check(all(identity), "runtime", "session history/driver is absent")
            check(session is None or identity == session, "runtime", "session/history changed")
            session = identity
            budget = launch["lane"]["budget_remaining"]
            check(integer(budget["wall_ms"], 1) and integer(budget["spend_micros"], 1),
                  "runtime", "launch has no real wall/spend budget")
            if remaining is not None:
                check(all(budget[field] <= remaining[field] for field in (
                    "wall_ms", "spend_micros", "cpu_seconds", "memory_bytes",
                    "processes", "disk_bytes")) and budget["currency"] == remaining["currency"],
                      "runtime", "continuation reset budget")
            end = ends.get((life, event["run"]))
            check(end is not None, "selected-end", "selected live run has no authentic end")
            check(end["origin"] == "service", "selected-end", "end is an appended observation")
            result = end["payload"]
            check(result["observation"]["handle"]["target"] == {
                "life_id": life, "run": event["run"]},
                "selected-end", "end carries another run's process observation")
            after = result["budget_remaining"]
            for field in ("wall_ms", "spend_micros", "cpu_seconds",
                          "memory_bytes", "processes", "disk_bytes"):
                check(integer(budget[field], 1) and integer(after[field]) and
                      after[field] <= budget[field],
                      "runtime", "missing budget or increased remaining allowance")
            check(after["wall_ms"] < budget["wall_ms"] and
                  after["currency"] == budget["currency"] and bool(budget["currency"]),
                  "runtime", "run consumed no measured wall budget")
            if result["profile_continuation"]:
                check(index + 1 < len(runs) and result["reason"] == "limit" and
                      result["observation"].get("survivors") == 0 and
                      runs[index + 1]["payload"].get("profile_continuation_of") == event["run"] and
                      runs[index + 1]["logical_turn_id"] == event["logical_turn_id"],
                      "runtime", "quota exit did not continue the same logical turn")
                follow = runs[index + 1]["payload"]
                from ladder_transactions import continuation_swap
                continuation_swap(event, runs[index + 1])
                check(follow["prompt"] == launch["prompt"] and
                      follow["task"] == launch["task"] and
                      follow["trigger"]["mail_ids"] == launch["trigger"]["mail_ids"],
                      "runtime", "quota continuation duplicated or replaced prompt/task/mail")
            else:
                selected_end(end, life, event["run"])
                if index + 1 < len(runs):
                    following = runs[index + 1]["payload"]
                    check("profile_continuation_of" not in following and "profile_swap" not in following,
                          "runtime", "normal exit was followed by an unauthorized profile continuation")
            remaining = after
        check(lane["state"] in (("verifying", "idle", "accepted", "merged") if
                                not lane.get("parent_life_id") else
                                ("verifying", "accepted", "merged")) and
              lane["session"] == actual,
              "runtime", "final lane/session is not quiescent or differs from vendor mapping")
        check(lane["counters"] == {"failures": 0, "retries": 0},
              "runtime", "completed ladder has failed or retried tasks")
    return launches, ends


def cleanup(events, by_name, lanes, root, inventory, readbacks, requirements):
    by_kind = defaultdict(list)
    for event in events:
        by_kind[(event.get("life_id"), event["kind"])].append(event)
    final = {lane["life_id"]: lane for lane in lanes}
    for created in by_name.values():
        parent = created.get("parent_life_id")
        if not parent:
            continue
        life = created["life_id"]
        check(final[life]["cleaned"] is True and final[life]["state"] == "merged",
              "cleanup", "parent did not merge/clean child")
        ordered = []
        for kind in ("lane.reviewed", "archive.verified", "lane.cleaned"):
            values = by_kind[(life, kind)]
            check(len(values) == 1, "cleanup", "missing/duplicate review/archive/clean")
            event = values[0]
            check(event["origin"] == "service" and
                  event["requested_by"].get("life_id") == parent and
                  (event["actor"].get("life_id") == parent and event["actor"]["kind"] == "lane" or
                   kind in ("archive.verified", "lane.cleaned") and
                   event["actor"]["kind"] in ("service", "worker")),
                  "cleanup", "executor or wrong parent reviewed/collected child")
            ordered.append(event["seq"])
        check(ordered == sorted(ordered) and len(set(ordered)) == 3,
              "cleanup", "cleanup preceded parent review/archive")
        review = by_kind[(life, "lane.reviewed")][0]["payload"]
        from ladder_review import review_evidence
        review_evidence(review, final[life], events, requirements.get(life, []), root, inventory)
        check(review["reviewer"].get("life_id") == parent and
              review["coverage"] == "complete" and review["checks"] and review["diff"]
              and review["record_inventory"], "cleanup", "parent review lacks required evidence")
        blob(root, review["diff"], inventory)
        check(bool(blob(root, review["record_inventory"], inventory)) and
              all(blob(root, item, inventory) for item in review["checks"]),
              "cleanup", "parent review inputs were not retained")
        marks = by_kind[(life, "lane.state")]
        marks = [event for event in marks if event["payload"]["to"] in
                 ("accepted", "merged")]
        check([event["payload"]["to"] for event in marks] == ["accepted", "merged"],
              "cleanup", "parent did not record both reviewed marks")
        check(all(event["origin"] == "service" and
                  event["actor"].get("life_id") == parent and
                  event["payload"].get("review_id") == review["id"] and
                  ordered[0] < event["seq"] < ordered[1] for event in marks),
              "cleanup", "marks lack the actual parent review or correct ordering")
        archive = by_kind[(life, "archive.verified")][0]["payload"]
        check(archive["archive_sha256"] == archive["read_back_sha256"] and
              valid_digest(archive["archive_sha256"]),
              "cleanup", "archive was not hash/read-back verified")
        check(bool(blob(root, archive["manifest"], inventory)),
              "cleanup", "archive manifest bytes were not retained")
        observed = [item for item in readbacks if item["life_id"] == life and
                    item["archive_receipt_id"] == archive["id"]]
        check(len(observed) == 1, "cleanup", "independent archive byte read-back is absent")
        content = observed[0]["content"]
        data = blob(root, content, inventory)
        check(bool(data) and content["sha256"] == archive["archive_sha256"] ==
              observed[0]["read_back_sha256"],
              "cleanup", "archive receipt differs from actual public archive bytes")
        clean = by_kind[(life, "lane.cleaned")][0]["payload"]
        check(clean["archive_receipt"]["id"] == archive["id"] and
              zero_exit(clean["quiescence"]) and
              clean["quiescence"]["handle"]["target"] == {
                  "life_id": life, "run": final[life]["run"]} and
              final[life]["workspace"]["id"] in clean["removed_object_ids"],
              "cleanup", "cleanup lacks receipt/owned removal/quiescence")


def privacy(receipts, by_name, events):
    expected = {(left["life_id"], right["life_id"])
                for left in by_name.values() for right in by_name.values()
                if left["life_id"] != right["life_id"] and
                left.get("parent_life_id") and
                left.get("parent_life_id") == right.get("parent_life_id")}
    seen = set()
    for receipt in receipts:
        pair = (receipt["reader_life_id"], receipt["target_life_id"])
        check(pair in expected and pair not in seen,
              "privacy", "privacy probe is duplicate or not an actual sibling")
        check(receipt["own_read"] is True and receipt["sibling_read"] is False and
              receipt["private_mail_read"] is False and
              receipt["private_session_read"] is False and
              bool(receipt["probe_id"]) and any(event["origin"] == "service" and
                  event["payload"]["target"]["life_id"] == receipt["reader_life_id"] and
                  event["payload"]["containment_id"] == receipt["containment_id"]
                  for event in events if event["kind"] == "identity.bound"),
              "privacy", "sibling canary was readable or own-data control failed")
        seen.add(pair)
    check(seen == expected and bool(seen), "privacy", "sibling privacy coverage is absent")


def manual_actors(requests, events):
    check(bool(requests), "actor", "manual actor control is missing")
    by_id = {event["id"]: event for event in events}
    by_mail = {event["payload"]["id"]: event for event in events
               if event["kind"] == "mail.queued"}
    distinct = False
    for request in requests:
        event = by_id[request["event_id"]]
        check(event["origin"] == "service" and event["kind"] == "lane.turn",
              "actor", "manual observation does not name a service turn")
        ids = event["payload"]["mail_ids"]
        check(bool(ids) and ids[0] in by_mail, "actor", "carried first mail is absent")
        sender = by_mail[ids[0]]["actor"]
        check(sender == request["first_mail_sender"], "actor", "first sender was fabricated")
        actor_matches(event, request["requester"])
        target = next((item for item in events if item["kind"] == "lane.created" and
                       item["life_id"] == event["life_id"]), None)
        check(target is not None and request["requester"].get("life_id") ==
              target.get("parent_life_id"), "actor", "manual requester is not the parent")
        distinct = distinct or request["requester"] != sender
    check(distinct, "actor", "mail-sender/requester distinction was not exercised")


def kernel_zero(records, events, lives):
    check(len(records) == 10 and {item["life_id"] for item in records} == set(lives),
          "survivors", "independent containment inventory is incomplete")
    bound = {}
    for event in events:
        if event["kind"] == "identity.bound":
            record = event["payload"]
            life = record["target"]["life_id"]
            check(event["origin"] == "service" and life in lives and
                  integer(record["host_uid"], 1) and
                  (life not in bound or bound[life][0] == record["host_uid"]),
                  "bindings", "process identity is absent or changed UID")
            bound[life] = (record["host_uid"], record["containment_id"])
    check(set(bound) == set(lives) and len({value[0] for value in bound.values()}) == 10,
          "bindings", "actual lane UID inventory is incomplete or shared")
    for record in records:
        check(record["known"] is True and record["processes"] == [] and
              (record["host_uid"], record["containment_id"]) == bound[record["life_id"]] and
              bool(record["containment_id"]) and integer(record["observed_ns"], 1),
              "survivors", "kernel survivor or unknown containment observation")


def resource_binding(run):
    binding = run["binding"]
    workspaces = [lane["workspace"]["id"] for lane in run["lanes"]]
    uids = {event["payload"]["host_uid"] for event in run["events"]
            if event["kind"] == "identity.bound"}
    stores = {event["payload"]["store_id"] for event in run["events"]
              if event["kind"] == "archive.verified"}
    check(len(workspaces) == len(set(workspaces)) == 10 and
          len(uids) == 10 and set(workspaces) == set(binding["workspace_ids"]) and
          uids == set(binding["lane_uids"]) and stores == {binding["store_id"]} and
          binding["service_uid"] not in uids,
          "bindings", "installed binding differs from public resource receipts")


def verify_run(run, plan, root):
    try:
        return _verify_run(run, plan, root)
    except (KeyError, TypeError) as error:
        raise LadderFailure("shape", "verification input has missing or invalid fields") from error
    except Failure as error:
        if error.code != "invalid_request":
            raise
        raise LadderFailure("shape", "verification input fields differ from the contract") from error


def _verify_run(run, plan, root):
    events = run["events"]
    check(events and len({event["seq"] for event in events}) == len(events) and
          len({event["id"] for event in events}) == len(events) and
          [event["seq"] for event in events] == sorted(event["seq"] for event in events),
          "events", "events are missing, duplicated or reordered")
    check(all(event["config"] == run["config"] and event["schema"] == 2 for event in events),
          "bindings", "cross-configuration event contamination")
    check(not any(event["kind"] in ("lane.lost", "launch.failed", "operation.failed", "worker.failed") or
                  event["kind"] == "policy.evaluated" and (event["payload"]["result"] != "allow" or
                      event["payload"]["audit_complete"] is not True) for event in events),
          "events", "ladder includes a failed operation or refused/incomplete policy evaluation")
    expected = structure(plan["seed"])
    by_name = graph(events, expected)
    from draft4 import typed_reply
    for lane in run["lanes"]:
        typed_reply("lane.status", lane)
    launches, ends = lifecycle(events, by_name, run["lanes"])
    captures(events, run["lanes"], root, run["blobs"])
    retained_blobs(run, root)
    expected_answers = plan["answers"][run["config"]]
    check(set(expected_answers) == set(by_name) and
          len({item["token"] for item in expected_answers.values()}) == 10 and
          len({item["path"] for item in expected_answers.values()}) == 10,
          "answers", "planted challenge inventory is incomplete or reused")
    pongs = report_answers(events, by_name, expected_answers, root, run["blobs"])
    answers(expected_answers, run["root_answers"])
    root_life = next(event["life_id"] for event in by_name.values() if not event.get("parent_life_id"))
    check(result_answers(events, root_life, root, run["blobs"]) == run["root_answers"],
          "answers", "root answers differ from the authentic retained RESULT blob")
    for name, created in by_name.items():
        parent = created.get("parent_life_id")
        if not parent:
            continue
        life = created["life_id"]
        for launch in launches[life]:
            ended = ends[(life, launch["run"])]
            if ended["payload"]["profile_continuation"]:
                continue
            waiting = [item for item in run["waits"] if item["life_id"] == life
                       and item["run"] == launch["run"]]
            check(len(waiting) == 1, "selected-end", "parent wait receipt is missing")
            wait_receipt(waiting[0], ended, parent)
        ping = [event for event in events if event["kind"] == "mail.queued" and
                event["payload"].get("recipient_life_id") == life and
                event["actor"].get("life_id") == parent and
                decode(blob(root, event["payload"]["content"], run["blobs"])).get("kind") == "PING"]
        check(len(ping) == 1, "ping-pong", "parent did not send one causal PING")
        ping = ping[0]
        check(ping["origin"] == "service" and ping["payload"]["sender"] == ping["actor"],
              "ping-pong", "PING did not come from its actual parent actor")
        delivery = [event for event in events if event["kind"] == "mail.delivered"
                    and event["payload"]["mail_id"] == ping["payload"]["id"]]
        pong = [(event, body) for event, body in pongs if event["actor"].get("life_id") == life
                and body.get("nonce") == plan["pings"][run["config"]][name]]
        check(len(delivery) == 1 and len(pong) == 1, "ping-pong", "delivery/PONG is missing")
        ping_body(decode(blob(root, ping["payload"]["content"], run["blobs"])),
                  pong[0][1], plan["pings"][run["config"]][name])
        turn = [event for event in launches[life]
                if event["logical_turn_id"] == delivery[0]["payload"]["logical_turn_id"]]
        check(bool(turn), "ping-pong", "delivered logical turn was never launched")
        ping_order(ping, delivery[0], turn[0], pong[0][0], pong[0][1]["nonce"])
        returned = [event for event in events if event["kind"] == "mail.returned" and
                    event["payload"]["mail_id"] == ping["payload"]["id"] and
                    event["payload"]["logical_turn_id"] == turn[0]["logical_turn_id"] and
                    event["payload"]["target"] == {"life_id": life, "run": turn[0]["run"]} and
                    event["payload"]["prompt_status"] == "completed" and
                    event["seq"] > pong[0][0]["seq"]]
        check(len(returned) == 1, "ping-pong", "PONG turn has no completed mail return receipt")
    manual_actors(run["manual_requests"], events)
    privacy(run["privacy"], by_name, events)
    cleanup(events, by_name, run["lanes"], root, run["blobs"], run["archive_readbacks"], run["review_requirements"])
    check(not run["unresolved"],
          "survivors", "unexplained refusal/suspicion or kernel survivor")
    kernel_zero(run["kernel_final"], events, launches)
    check(run["sources_before"] == run["sources_after"] and bool(run["sources_before"]) and
          all(valid_digest(value) for value in run["sources_before"].values()),
          "source-tree", "source tree changed or was never observed")
    from ladder_transactions import verify_draft4
    verify_draft4(run, by_name, root)
    return set(launches)


def verify_pair(runs, plan, root):
    check(len(runs) == 2 and runs[0]["config"] != runs[1]["config"],
          "concurrency", "two independently bound runs are required")
    lives = []
    for run in runs:
        from support import immutable
        files = run["artifact_files"]
        check(set(files) == set(run["artifact_hashes"]), "artifacts",
              "artifact byte inventory does not match pinned hashes")
        for name, item in files.items():
            kept = beneath(root, item["kept"])
            pinned_file(item["source"], kept, run["artifact_hashes"][name])
            try:
                immutable(item["source"])
            except (OSError, Failure) as error:
                raise LadderFailure("artifacts", "executable is not administrator protected") from error
        resource_binding(run)
        lives.append({(run["config"], life) for life in verify_run(run, plan, root)})
    for key in ("store_id", "socket", "service_uid", "workspace_ids", "lane_uids"):
        left, right = runs[0]["binding"][key], runs[1]["binding"][key]
        if isinstance(left, list):
            check(not set(left) & set(right), "bindings", "run resources overlap")
        else:
            check(left != right, "bindings", "run bindings overlap")
    check(runs[0]["artifact_hashes"] == runs[1]["artifact_hashes"] and
          {"binary", "helper", "claudock-cli", "claude", "codex"} <=
          runs[0]["artifact_hashes"].keys(),
          "artifacts", "concurrent trees used different/incomplete artifacts")
    concurrent_sample(lives, plan["load_samples"])
    uid_by_life = {(run["config"], event["payload"]["target"]["life_id"]):
                   event["payload"]["host_uid"] for run in runs for event in run["events"]
                   if event["kind"] == "identity.bound"}
    image_by_life = {(run["config"], lane["life_id"]): run["artifact_hashes"][
        "claude" if lane["session"]["driver"] == "claudock-cli" else "codex"]
        for run in runs for lane in run["lanes"]}
    for sample in plan["load_samples"]:
        for item in sample["live_refs"]:
            key = (item["config"], item["life_id"])
            check(key in uid_by_life and item["before"]["uids"] ==
                  [uid_by_life[key]]*4, "bindings", "sample process has the wrong actual lane UID")
            check(item["executable_before_sha256"] == item["executable_after_sha256"] ==
                  image_by_life[key], "artifacts", "sample counted a stand-in or different vendor executable")
    check(set(plan["answers"][runs[0]["config"]]) == set(plan["answers"][runs[1]["config"]])
          and all(plan["answers"][runs[0]["config"]][name] !=
                  plan["answers"][runs[1]["config"]][name] for name in
                  plan["answers"][runs[0]["config"]]),
          "answers", "two ladders reused their planted challenges")
    planted = [answer for run in runs for answer in plan["answers"][run["config"]].values()]
    check(len({item["token"] for item in planted}) == 20 and
          len({item["path"] for item in planted}) == 20,
          "answers", "two ladders share a planted token or path")
