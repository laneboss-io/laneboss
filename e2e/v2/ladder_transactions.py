"""Check independent draft.4 projections against public CLI/socket facts.

These are harness-normalized observations, not additional production DTOs.
Absent service/observer transport is a named prerequisite, never an empty pass.
"""

from draft4 import (ID, KEY, MUTATIONS, OPERATIONS, READS, REVISION, SESSION_MUTATIONS, blob_ref, intent_digest, presence,
                    ticket_events, typed_reply)
from ladder import SCENARIO, check, valid_digest
from support import Failure, exact_keys, integer, load


def write_shape(method, actor, shape):
    exact_keys(shape, ("fields", "events", "effects", "guards", "reply"))
    check(type(shape["reply"]) is bool, "write-matrix", "reply observation is not boolean")
    for field in ("fields", "events", "effects", "guards"):
        values = shape[field]
        check(isinstance(values, list) and len(values) == len(set(values)) and
              all(isinstance(value, str) for value in values),
              "write-matrix", "transaction inventory is not an exact set")
    if method in READS:
        check(not any(shape[field] for field in ("fields", "events", "effects", "guards")),
              "write-matrix", "read method changed state or consumed a guard")
        return
    if method.startswith("org."):
        raise Failure("deferred completion observation is absent", "not_implemented", "lb-v2-e2e")
    catalog = load(SCENARIO / "draft4-writes.json")
    check(catalog["contract_revision"] == REVISION and method in catalog["rows"],
          "write-matrix", "unmapped transaction method")
    row = catalog["rows"][method]
    check(shape["reply"] is True and all(set(shape[key]) <= set(row[key].split())
          for key in ("fields", "events", "effects")),
          "write-matrix", "missing typed reply or out-of-domain write/event/effect")
    guards = set(shape["guards"])
    check(guards <= {"Proof", "Ticket", "Approval", "Cancellation"},
          "write-matrix", "unknown transaction guard")
    check(actor["kind"] == "human" or not guards & {"Proof", "Ticket"},
          "write-matrix", "lane borrowed human proof or ticket authority")
    check("Approval" not in guards, "write-matrix", "unexpected approval guard on a ladder mutation")
    if method in SESSION_MUTATIONS:
        check(not guards & {"Proof", "Ticket", "Approval"},
              "write-matrix", "session mutation consumed an authority guard")
    elif method in ("lane.start", "lane.adopt") and actor["kind"] == "human":
        check("Ticket" in guards and "Proof" not in guards,
              "write-matrix", "human spawn needs only its ticket authority")
    elif actor["kind"] == "human":
        check("Proof" in guards and "Ticket" not in guards,
              "write-matrix", "human mutation needs only its operation proof authority")
    if method in ("lane.start", "lane.adopt", "lane.resume", "lane.turn", "grants.revoke",
                  "mail.send", "report.submit"):
        check("Cancellation" in guards, "write-matrix", "life-dependent effect omitted cancellation")


def mutation_receipt(item, config):
    exact_keys(item, ("request", "actor", "response", "receipt", "transaction",
                      "event_ids", "replayed", "policy_context"))
    request, response, receipt = item["request"], item["response"], item["receipt"]
    exact_keys(request, ("protocol", "schema", "config", "request_id", "idempotency_key",
                         "request_sha256", "method", "params"), ("proof",))
    method = request["method"]
    check(request["config"] == config and request["protocol"] == "laneboss.rpc.v2" and
          request["schema"] == 2 and method in MUTATIONS and
          KEY.fullmatch(request["idempotency_key"]) and KEY.fullmatch(request["request_id"]),
          "mutation-key", "mutation lost its retained key or configuration")
    digest = intent_digest(config, method, request["params"])
    check(request["request_sha256"] == digest, "mutation-key", "mutation intent digest differs")
    actor = item["actor"]
    check(actor["kind"] in ("human", "lane") and ID.fullmatch(actor["id"]),
          "mutation-actor", "mutation is not bound to an authenticated principal")
    if actor["kind"] == "lane":
        check("proof" not in request and not request["params"].get("root_ticket_id"),
              "mutation-actor", "lane request borrowed human authority")
    exact_keys(receipt, ("config", "key", "actor", "operation_id", "reply", "first_seq", "last_seq",
                         "policy_generation", "simulated_presence"))
    check(receipt["config"] == config and receipt["actor"] == actor and
          receipt["key"] == {key: request[key] for key in
                             ("method", "idempotency_key", "request_sha256")},
          "receipt-config", "foreign configuration/key/principal/life receipt")
    check(ID.fullmatch(receipt["operation_id"]) and integer(receipt["first_seq"], 1) and
          integer(receipt["last_seq"], receipt["first_seq"]),
          "typed-reply", "receipt omitted durable operation/sequence facts")
    exact_keys(response, ("protocol", "schema", "request_id", "last_seq", "result"))
    check(response["protocol"] == request["protocol"] and response["schema"] == 2 and
          response["request_id"] == request["request_id"] and
          response["last_seq"] == receipt["last_seq"] and
          receipt["reply"] == {"result": response["result"]},
          "typed-reply", "response differs from retained typed mutation reply")
    typed_reply(method, response["result"])
    if method in OPERATIONS:
        check(response["result"]["status"] in ("pending", "running", "succeeded") and
              not response["result"].get("error"), "typed-reply", "ladder mutation returned a failed operation")
    if item["replayed"] is True:
        shape = item["transaction"]
        check(isinstance(shape, dict) and set(shape) == {"fields", "events", "effects", "guards", "reply"},
              "mutation-replay", "replay submitted another transaction kind")
        check(shape["reply"] is True and all(shape[field] == [] for field in
              ("fields", "events", "effects", "guards")) and item["event_ids"] == [],
              "mutation-replay", "replay wrote state/events/effects or consumed another guard")
    else:
        if method in ("lane.start", "lane.adopt", "lane.resume", "lane.turn"):
            reservation_shape(method, actor, item["transaction"])
        else:
            write_shape(method, actor, item["transaction"])
    policy = item["policy_context"]
    exact_keys(policy, ("current_generation", "use"))
    retained, current = receipt["policy_generation"], policy["current_generation"]
    historical = item["replayed"] is True or method == "guidance.select" and policy["use"] == "retained_selection"
    check(integer(current, 1) and integer(retained, 1, current) and
          policy["use"] in ("fresh", "exact_replay", "retained_selection") and
          (policy["use"] != "retained_selection" or method == "guidance.select") and
          (policy["use"] == "exact_replay") is (item["replayed"] is True) and
          (historical or retained == current),
          "policy-generation", "fresh work used stale policy or replay changed its retained policy")
    if method in ("guidance.select", "policy.evaluate"):
        check(response["result"]["policy_generation"] == retained,
              "policy-generation", "policy/guidance reply changed its retained generation")
    simulated = presence(receipt)
    if "proof" in request:
        check(presence(request["proof"]) == simulated,
              "presence", "mutation receipt dropped its verified proof mark")
    if method in OPERATIONS or method in ("human.session", "ticket.issue"):
        check(presence(response["result"]) == simulated,
              "presence", "typed reply dropped consumed authority provenance")
    return (config, actor["kind"], actor["id"], actor.get("life_id", ""),
            method, request["idempotency_key"])


def reservation_shape(method, actor, shape):
    exact_keys(shape, ("kind", "fields", "events", "effects", "guards", "reply"))
    check(shape["kind"] == "launch_reservation" and shape["reply"] is True and
          shape["fields"] == ["LaunchPlans"] and shape["events"] == [] and
          shape["effects"] == ["PlanLaunch"],
          "write-matrix", "initial launch reservation wrote a ready lane or bypassed PlanLaunch")
    guards = shape["guards"]
    if method in ("lane.start", "lane.adopt") and actor["kind"] == "lane":
        check(isinstance(guards, list) and len(guards) == len(set(guards)) and
              set(guards) <= {"Cancellation"}, "write-matrix", "lane spawn borrowed human reservation authority")
        return
    expected = []
    if method in ("lane.resume", "lane.turn"):
        expected.append("Cancellation")
        if actor["kind"] == "human":
            expected.append("Proof")
    elif actor["kind"] == "human":
        expected.append("Ticket")
    check(isinstance(guards, list) and len(guards) == len(expected) and set(guards) == set(expected),
          "write-matrix", "reservation consumed the wrong authority or cancellation fence")


METHOD_FOR_EVENT = {
    "lane.created": "lane.start", "lane.reviewed": "lane.review", "lane.state": "lane.mark",
    "archive.verified": "lane.archive", "lane.cleaned": "lane.clean",
    "mail.queued": "mail.send", "report.submitted": "report.submit",
    "lane.turn": "lane.turn", "blob.committed": "blob.commit",
    "human.session": "human.session", "ticket.issued": "ticket.issue", "lane.loop": "lane.loop"}

# Internal lifecycle/worker completions retain their public causal operation.
# The event kind alone is not a claim that a second public RPC was submitted.
CAUSAL_METHODS = {
    "mail.queued": {"mail.send", "report.submit"},
    "lane.turn": {"lane.start", "lane.adopt", "lane.turn", "lane.resume", "lane.loop",
                  "mail.send", "report.submit"},
    "blob.committed": {"blob.commit", "lane.archive", "grants.test-child"}}


def mutation_history(run):
    rows = run["mutations"]
    check(isinstance(rows, list) and bool(rows), "mutation-key", "mutation observations are absent")
    events = {event["id"]: event for event in run["events"]}
    seen, covered, requests = {}, set(), {}
    for item in rows:
        domain = mutation_receipt(item, run["config"])
        request, receipt = item["request"], item["receipt"]
        check(type(item["replayed"]) is bool and
              (item["replayed"] is (domain in seen)),
              "mutation-replay", "replay has no original retained mutation")
        if domain in seen:
            check(receipt == seen[domain], "mutation-replay", "retry changed its original receipt/reply")
        seen[domain] = receipt
        requests[request["request_id"]] = request
        for identifier in item["event_ids"]:
            check(identifier in events, "typed-reply", "mutation names an unobserved public event")
            event = events[identifier]
            check(event["origin"] == "service" and event["operation_id"] == receipt["operation_id"] and
                  event["requested_by"] == item["actor"],
                  "mutation-actor", "event lost its actual causal requester/operation")
            if event["kind"] in METHOD_FOR_EVENT:
                expected = METHOD_FOR_EVENT[event["kind"]]
                check(request["method"] in CAUSAL_METHODS.get(event["kind"], {expected}),
                      "typed-reply", "wrong public cause claimed a lifecycle event")
                params = request["params"]
                if event["kind"] == "lane.created":
                    lane = event["payload"]["lane"]
                    check(all(params[key] == lane[key] for key in ("level", "role", "model", "effort")) and
                          params["lane"] == lane["name"] and params["driver"] == lane["session"]["driver"],
                          "typed-reply", "created lane differs from the exact start request")
                    if item["actor"]["kind"] == "human":
                        check(params["root_ticket_id"] == run["root_ticket"]["id"],
                              "ticket", "root start used a different retained ticket")
                elif event["kind"] in ("lane.reviewed", "lane.state", "archive.verified", "lane.cleaned"):
                    check(params["target"] == {"life_id": event["life_id"], "run": event["run"]},
                          "typed-reply", "mutation completed for another selected life/run")
                elif event["kind"] in ("report.submitted", "mail.queued"):
                    check(params["content"] == event["payload"]["content"],
                          "typed-reply", "committed mail differs from the exact requested content")
                if event["kind"] in ("lane.reviewed", "archive.verified", "report.submitted", "mail.queued",
                                     "human.session", "ticket.issued") or (
                        event["kind"] == "blob.committed" and request["method"] == "blob.commit"):
                    check(item["response"]["result"] == event["payload"],
                          "typed-reply", "synchronous reply differs from committed event")
                covered.add(identifier)
    required = {event["id"] for event in events.values() if event["kind"] in METHOD_FOR_EVENT}
    check(covered == required, "mutation-key", "a ladder mutation has no retained key/reply observation")
    intents = run["client_intents"]
    check(isinstance(intents, list) and bool(intents), "mutation-key", "CLI intent inventory is absent")
    root_rows = [item for item in rows if item["request"]["method"] == "lane.start" and
                 item["request"]["params"].get("root_ticket_id") == run["root_ticket"]["id"]]
    check(len(root_rows) >= 2 and root_rows[0]["replayed"] is False and
          all(item["replayed"] is True for item in root_rows[1:]),
          "mutation-replay", "root start lacks its original and same-key replay")
    check(all(any(intent["request_id"] == item["request"]["request_id"] for intent in intents)
              for item in root_rows), "mutation-key", "root original/replay lacks actual CLI intent")
    for intent in intents:
        if intent["method"] not in MUTATIONS:
            continue
        request = requests.get(intent["request_id"])
        check(request is not None and all(request[field] == intent[field] for field in
              ("config", "method", "idempotency_key", "request_sha256")),
              "mutation-key", "outside receipt differs from the actual CLI invocation")


def read_history(run):
    check(isinstance(run["reads"], list) and bool(run["reads"]),
          "read-auth", "authenticated read observations are absent")
    events = {event["id"]: event for event in run["events"]}
    requests, proofs, sessions, revisions = {}, {}, {}, {}
    for item in run["reads"]:
        exact_keys(item, ("request", "actor", "response", "transaction", "connection_id", "session"))
        request, response = item["request"], item["response"]
        check("proof" not in request, "read-auth", "read carried an ambient mutation proof")
        exact_keys(request, ("protocol", "schema", "config", "request_id", "idempotency_key",
                             "request_sha256", "method", "params"))
        method = request["method"]
        check(method in READS and request["config"] == run["config"] and
              request["protocol"] == "laneboss.rpc.v2" and request["schema"] == 2 and
              KEY.fullmatch(request["request_id"]) and request["request_sha256"] ==
              intent_digest(run["config"], method, request["params"]),
              "read-auth", "read request changed configuration/intent or carried ambient proof")
        write_shape(method, item["actor"], item["transaction"])
        exact_keys(response, ("protocol", "schema", "request_id", "last_seq", "result"))
        check(response["protocol"] == request["protocol"] and response["schema"] == 2 and
              response["request_id"] == request["request_id"] and integer(response["last_seq"]),
              "read-auth", "read response correlation differs")
        typed_reply(method, response["result"])
        session = item["session"]
        if item["actor"]["kind"] == "human" and method != "health":
            exact_keys(session, ("connection_id", "proof_id", "event_id", "generation",
                                 "expires_at", "idle_expires_at", "simulated_presence"))
            event = events.get(session["event_id"])
            check(bool(item["connection_id"]) and session["connection_id"] == item["connection_id"] and
                  event is not None and event["kind"] == "human.session" and event["origin"] == "service" and
                  event["actor"] == item["actor"] and event["payload"]["config"] == run["config"] and
                  event["seq"] <= response["last_seq"],
                  "read-auth", "human.session and read used different connections or principals")
            proof = session["proof_id"]
            proof_binding = (item["connection_id"], event["id"])
            check(bool(proof) and (proof not in proofs or proofs[proof] == proof_binding),
                  "read-auth", "session proof was replayed onto a different connection")
            proofs[proof] = proof_binding
            pair = (item["connection_id"], proof)
            for identifier in (("event", event["id"]), ("session", event["payload"]["id"])):
                check(identifier not in sessions or sessions[identifier] == pair,
                      "read-auth", "human session was attached to another connection/proof")
                sessions[identifier] = pair
            from datetime import datetime
            absolute = datetime.fromisoformat(session["expires_at"])
            idle = datetime.fromisoformat(session["idle_expires_at"])
            prior = revisions.get(event["id"])
            check(integer(session["generation"], 1) and absolute.tzinfo is not None and idle.tzinfo is not None and
                  idle <= absolute and session["expires_at"] == event["payload"]["expires_at"] and
                  presence(session) == presence(event["payload"]) and
                  (prior is None or session["generation"] > prior[0] and idle >= prior[1]),
                  "read-auth", "session refresh regressed, changed absolute expiry or lost presence")
            revisions[event["id"]] = (session["generation"], idle)
            uses = [value for value in events.values() if value["kind"] == "human.proof.used" and
                    value["payload"]["proof_id"] == proof]
            check(len(uses) == 1 and uses[0]["origin"] == "service" and
                  uses[0]["actor"] == item["actor"] and
                  uses[0]["operation_id"] == event["operation_id"] and
                  uses[0]["payload"]["operation_id"] == event["operation_id"] and
                  uses[0]["seq"] <= response["last_seq"],
                  "read-auth", "session lacks its atomic one-use human proof receipt")
            check(presence(uses[0]["payload"]) == presence(event["payload"]),
                  "presence", "read session dropped the consumed proof's simulation mark")
            opens = [mutation for mutation in run["mutations"] if mutation["replayed"] is False and
                     mutation["request"]["method"] == "human.session" and event["id"] in mutation["event_ids"]]
            check(len(opens) == 1 and opens[0]["request"].get("proof", {}).get("id") == proof and
                  opens[0]["request"]["proof"]["request_sha256"] ==
                  intent_digest(run["config"], "human.session", {}) and
                  all(opens[0]["receipt"]["first_seq"] <= value["seq"] <=
                      opens[0]["receipt"]["last_seq"] for value in (event, uses[0])),
                  "read-auth", "read session differs from its original guarded mutation")
        else:
            check(session == {}, "read-auth", "lane read borrowed a human session")
        requests[request["request_id"]] = item
    intents = [intent for intent in run["client_intents"] if intent["method"] in READS - {"health"}]
    check(bool(intents), "read-auth", "CLI read intent inventory is absent")
    for intent in intents:
        if intent["method"] not in READS - {"health"}:
            continue
        observed = requests.get(intent["request_id"])
        check(observed is not None and all(observed["request"][key] == intent[key] for key in
              ("config", "method", "request_sha256")) and observed["session"].get("proof_id", "") ==
              intent["session_proof_id"], "read-auth", "CLI read lacks its actual shared-session observation")


def helper_releases(run):
    allocations = {}
    released = set()
    children = {lane["life_id"] for lane in run["lanes"] if lane.get("parent_life_id")}
    bindings = {}
    for event in run["events"]:
        if event["kind"] != "identity.bound":
            continue
        value = event["payload"]
        key = (value["uid_lease_id"], value["target"]["life_id"], value["target"]["run"])
        check(event["origin"] == "service" and (key not in bindings or all(
              bindings[key]["payload"][field] == value[field] for field in
              ("host_uid", "containment_id", "uid_lease_id", "target"))),
              "release", "conflicting or unauthentic identity binding for a lease/run")
        if key not in bindings:
            bindings[key] = event
    for event in run["events"]:
        value = event["payload"]
        if event["kind"] == "helper.allocated":
            check(event["origin"] == "service" and value["id"] not in allocations,
                  "release", "duplicate or unauthentic helper lease")
            bound = [item for key, item in bindings.items() if key[0] == value["id"]]
            check(bool(bound) and all(value["uid"] == item["payload"]["host_uid"] and
                  value["containment_id"] == item["payload"]["containment_id"] and
                  item["payload"]["target"]["life_id"] == event["life_id"] and
                  event["seq"] < item["seq"] for item in bound),
                  "release", "helper allocation differs from authentic containment binding")
            allocations[value["id"]] = event
        if event["kind"] != "helper.released":
            continue
        exact_keys(value, ("id", "lease_id", "containment_id", "backend", "operation_id",
                           "effect_id", "quiescence", "live_connections", "queued_jobs",
                           "writable_exports", "observed_at"))
        lease = allocations.get(value["lease_id"])
        target = value["quiescence"]["handle"]["target"]
        ended = [item for item in run["events"] if item["kind"] == "lane.ended" and
                 item["life_id"] == target["life_id"] and item["run"] == target["run"]]
        bound_runs = [key[2] for key in bindings if key[:2] == (value["lease_id"], target["life_id"])]
        check(lease is not None and value["lease_id"] not in released and event["origin"] == "service" and
              lease["seq"] < event["seq"] and lease["life_id"] == event["life_id"] and
              lease["payload"]["containment_id"] == value["containment_id"] and
              value["operation_id"] == event["operation_id"] and bool(value["effect_id"]) and
              value["backend"] == "linux-bwrap-landlock" and value["quiescence"]["state"] == "exited" and
              type(value["quiescence"].get("survivors")) is int and value["quiescence"]["survivors"] == 0 and
              value["quiescence"]["handle"]["containment_id"] == value["containment_id"] and
              target == {"life_id": event["life_id"], "run": event["run"]} and
              bool(bound_runs) and target["run"] == max(bound_runs) and
              len(ended) == 1 and ended[0]["origin"] == "service" and ended[0]["seq"] < event["seq"],
              "release", "helper release is unbound or not independently quiescent")
        check(all(type(value[key]) is int and value[key] == 0 for key in
                  ("live_connections", "queued_jobs", "writable_exports")),
              "release", "helper retained live connections/jobs/writable exports")
        released.add(value["lease_id"])
    expected = {key for key, event in allocations.items() if event["life_id"] in children}
    check(bool(expected) and expected <= released and
          {event["life_id"] for event in allocations.values()} >= children,
          "release", "a cleaned child has no measured helper release")
    for event in run["events"]:
        if event["kind"] not in ("lane.started", "lane.resumed") or event["life_id"] not in children:
            continue
        candidates = [key[0] for key in bindings if key[1:] == (event["life_id"], event["run"])]
        check(len(candidates) == 1 and candidates[0] in released,
              "release", "a completed child run has no bound and released helper lease")


def cancellation_history(run):
    for lane in run["lanes"]:
        launches = [event["payload"]["lane"]["cancellation_epoch"] for event in run["events"]
                    if event["kind"] in ("lane.started", "lane.resumed") and
                    event["life_id"] == lane["life_id"]]
        final = lane["cancellation_epoch"]
        check(all(integer(epoch) for epoch in launches) and launches == sorted(launches) and
              integer(final, max(launches)), "cancellation", "life cancellation epoch regressed")
        if lane.get("parent_life_id"):
            causes = [event for event in run["events"] if event.get("life_id") == lane["life_id"] and
                      (event["kind"] == "lane.cleaned" or event["kind"] == "lane.state" and
                       event["payload"]["to"] in ("merged", "abandoned"))]
            check(len(causes) >= 2 and final >= max(launches) + len(causes),
                  "cancellation", "terminal mark/clean did not each advance the cancellation epoch")
            for cause in causes:
                cancelled = [event for event in run["events"] if event["kind"] == "watchdog.cancelled" and
                             event.get("life_id") == lane["life_id"] and
                             event["operation_id"] == cause["operation_id"]]
                check(len(cancelled) == 1 and cancelled[0]["origin"] == "service" and
                      bool(cancelled[0]["payload"]["reason"]),
                      "cancellation", "terminal mark/clean lacks its authentic cancellation event")


def continuation_swap(previous, following):
    swap = following["payload"]["profile_swap"]
    def keys(value, required, optional=()):
        check(isinstance(value, dict) and set(required) <= value.keys() <= set(required) | set(optional),
              "runtime", "profile swap fields differ from the typed contract")
    keys(swap, ("profile_grant_id", "eligibility_id", "expected_generation", "cancellation_epoch",
                      "from_profile_id", "to_profile_id", "causing_run", "continuation_run",
                      "logical_turn_id", "limit", "room", "operation_id"))
    keys(swap["limit"], ("target", "kind", "profile_id", "provider", "capture_id",
                               "capture_sha256", "adapter_version", "observed_at"), ("exit_code", "usage_evidence"))
    keys(swap["room"], ("profile_id", "available", "checked_at", "expires_at", "evidence", "reason"))
    blob_ref(swap["room"]["evidence"])
    if previous["payload"]["lane"].get("session", {}).get("driver") == "claudock-cli":
        check("usage_evidence" in swap["limit"], "runtime", "Claudock limit lacks outside usage evidence")
    if "usage_evidence" in swap["limit"]:
        blob_ref(swap["limit"]["usage_evidence"])
        check(swap["limit"]["usage_evidence"]["class"] == "usage_window", "runtime", "quota evidence has another class")
    check(bool(swap["eligibility_id"]) and integer(swap["expected_generation"], 1) and
          integer(swap["cancellation_epoch"]) and swap["causing_run"] == previous["run"] and
          swap["continuation_run"] == following["run"] and following["run"] == previous["run"] + 1 and
          swap["logical_turn_id"] == previous["logical_turn_id"] == following["logical_turn_id"] and
          swap["cancellation_epoch"] == following["payload"]["lane"]["cancellation_epoch"] and
          swap["cancellation_epoch"] == previous["payload"]["lane"]["cancellation_epoch"] and
          swap["from_profile_id"] != swap["to_profile_id"] and
          valid_digest(swap["limit"]["capture_sha256"]) and
          swap["profile_grant_id"] == following["payload"]["lane"]["profile_grant_id"] and
          swap["limit"]["target"] == {"life_id": previous["life_id"], "run": previous["run"]} and
          swap["limit"]["profile_id"] == swap["from_profile_id"] and
          swap["room"]["profile_id"] == swap["to_profile_id"] and swap["room"]["available"] is True,
          "runtime", "continuation Swap disagrees with the actual turn/epoch/profile fence")


def verify_draft4(run, by_name, root):
    mutation_history(run)
    ticket_events(run, by_name)
    read_history(run)
    helper_releases(run)
    cancellation_history(run)
    from ladder_pins import launch_audits, policy_history, presence_report
    launch_audits(run, root)
    policy_history(run)
    presence_report(run)
