"""Draft.4 CLI and observer assertions; no product imports or state reads."""

from datetime import datetime, timezone
import json
import re

from ladder import check
from support import (DIGEST, Failure, bytes_hash, exact_keys, immutable, integer,
                     load, require)


REVISION = "v2.0-draft.4"
KEY = re.compile(r"[A-Za-z0-9_-]{22,128}\Z")
ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
OPERATIONS = {
    "lane.start", "lane.adopt", "lane.resume", "lane.turn", "lane.stop",
    "lane.mark", "lane.clean", "lane.loop", "grants.test-child", "grants.revoke"}
SESSION_MUTATIONS = {"blob.begin", "blob.chunk", "blob.commit", "secret.stage",
                     "policy.evaluate", "guidance.select", "judge.ask"}
MUTATIONS = OPERATIONS | SESSION_MUTATIONS | {
    "blob.begin", "blob.chunk", "blob.commit", "lane.review", "lane.archive",
    "mail.send", "report.submit", "records.append", "ticket.issue", "human.session"}
READS = {"health", "identity.self", "event.tail", "lane.list", "lane.status",
         "blob.read", "operation.get", "mail.list", "records.get", "grants.get"}


def canonical(value):
    """JCS for these integer-only RPC inputs, with UTF-16 property ordering."""
    if isinstance(value, dict):
        return "{" + ",".join(canonical(key) + ":" + canonical(value[key])
                              for key in sorted(value, key=lambda key: key.encode("utf-16-be"))) + "}"
    if isinstance(value, list):
        return "[" + ",".join(canonical(item) for item in value) + "]"
    require(value is None or isinstance(value, (str, bool)) or integer(value),
            "RPC input is outside the integer-only JCS subset", "invalid_request")
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def intent_digest(config, method, params):
    value = {"protocol": "laneboss.rpc.v2", "schema": 2,
             "config": config, "method": method, "params": params}
    return bytes_hash(canonical(value).encode("utf-8"))


def retained_key(value):
    require(isinstance(value, str) and KEY.fullmatch(value) is not None,
            "mutation needs its retained key", "invalid_request")
    return value


def blob_ref(value):
    exact_keys(value, ("id", "sha256", "bytes", "class"))
    check(isinstance(value["id"], str) and ID.fullmatch(value["id"]) and
          isinstance(value["sha256"], str) and DIGEST.fullmatch(value["sha256"]) and
          integer(value["bytes"], 0, 67108864) and bool(value["class"]),
          "typed-reply", "invalid committed blob reference")


def operation(value):
    exact_keys(value, ("id", "status", "first_seq", "last_seq"),
               ("life_id", "run", "result", "error", "simulated_presence"))
    presence(value)
    check(isinstance(value["id"], str) and ID.fullmatch(value["id"]) and
          value["status"] in ("pending", "running", "succeeded", "failed", "cancelled") and
          integer(value["first_seq"]) and integer(value["last_seq"], value["first_seq"]),
          "typed-reply", "invalid operation reply")
    if "result" in value:
        blob_ref(value["result"])


def typed_reply(method, value):
    try:
        return _typed_reply(method, value)
    except Failure as error:
        if error.code != "invalid_request":
            raise
        check(False, "typed-reply", "reply fields differ from the typed contract")
    except (KeyError, TypeError, ValueError):
        check(False, "typed-reply", "reply contains invalid field types")


def _typed_reply(method, value):
    check(isinstance(value, dict), "typed-reply", "CLI reply is not a typed object")
    if method in OPERATIONS or method == "operation.get":
        operation(value)
    elif method in ("blob.commit",):
        blob_ref(value)
    elif method in ("blob.begin", "blob.chunk"):
        exact_keys(value, ("object_id", "max_chunk_bytes", "expires_at"))
        check(ID.fullmatch(value["object_id"]) and integer(value["max_chunk_bytes"], 1, 262144),
              "typed-reply", "invalid blob upload lease")
    elif method == "blob.read":
        exact_keys(value, ("object_id", "offset", "data", "sha256"))
        check(integer(value["offset"]) and DIGEST.fullmatch(value["sha256"]),
              "typed-reply", "invalid blob chunk reply")
    elif method == "health":
        exact_keys(value, ("protocol", "schema", "service_version", "artifact_sha256",
                           "ready", "capabilities"))
        check(type(value["ready"]) is bool and isinstance(value["capabilities"], list),
              "typed-reply", "health is not a typed readiness reply")
    elif method == "identity.self":
        exact_keys(value, ("config", "actor", "endpoint_generation", "policy_generation"),
                   ("launch_id",))
        check(integer(value["endpoint_generation"], 1) and integer(value["policy_generation"]),
              "typed-reply", "scope has no actual endpoint generation")
    elif method == "event.tail":
        exact_keys(value, ("events", "cursor", "complete"))
        check(isinstance(value["events"], list) and type(value["complete"]) is bool and
              isinstance(value["cursor"], str), "typed-reply", "invalid event page")
    elif method in ("lane.list", "mail.list"):
        key = "lanes" if method == "lane.list" else "messages"
        exact_keys(value, (key, "cursor"))
        check(isinstance(value[key], list) and isinstance(value["cursor"], str),
              "typed-reply", "invalid projection page")
        if method == "lane.list":
            for lane in value["lanes"]:
                typed_reply("lane.status", lane)
    elif method in ("ticket.issue",):
        ticket(value)
    elif method == "human.session":
        exact_keys(value, ("id", "expires_at", "idle_expires_at", "config"), ("simulated_presence",))
        presence(value)
    elif method in ("mail.send", "report.submit"):
        exact_keys(value, ("generation", "artifacts", "id", "sender", "content", "source",
                           "queued_seq", "status", "ask"),
                   ("answer", "recipient_life_id", "channel_grant_id", "logical_turn_id", "reply_to"))
        blob_ref(value["content"])
    elif method == "lane.review":
        exact_keys(value, ("id", "reviewer", "diff", "checks", "record_inventory",
                           "refusal_resolution", "coverage"), ("evidence",))
    elif method == "lane.archive":
        exact_keys(value, ("id", "life_id", "manifest", "archive_sha256",
                           "read_back_sha256", "verified_at", "store_id"))
        blob_ref(value["manifest"])
    elif method in ("records.append", "records.get"):
        exact_keys(value, ("id", "collection", "content", "actor", "origin", "recorded_at",
                           "generation"), ("life_id", "run", "related_ids", "action",
                                           "annotations", "feedback"))
        blob_ref(value["content"])
    elif method == "lane.status":
        exact_keys(value, ("task", "launch_id", "cancellation_epoch", "counters", "profile_grant_id",
                           "model", "effort", "budget_remaining", "life_id", "name", "root_life_id",
                           "starter_chain", "starter_event_seq", "level", "role", "state", "generation",
                           "run", "session", "workspace", "grant_set_id", "policy_generation", "cleaned",
                           "containment", "last_seq"), ("parent_life_id", "logical_turn_id"))
        check(bool(value["life_id"]) and integer(value["run"], 1) and
              integer(value["cancellation_epoch"]) and type(value["cleaned"]) is bool,
              "typed-reply", "invalid typed lane projection")
        blob_ref(value["task"])
    elif method == "grants.get":
        exact_keys(value, ("resources", "id", "life_id", "sha256", "policy_generation", "generation",
                           "data", "secrets", "profiles", "network", "channels", "expires_at", "revoked"),
                   ("parent_life_id",))
        check(ID.fullmatch(value["id"]) and ID.fullmatch(value["life_id"]) and
              DIGEST.fullmatch(value["sha256"]) and type(value["revoked"]) is bool and
              all(isinstance(value[field], list) for field in
                  ("resources", "data", "secrets", "profiles", "network", "channels")),
              "typed-reply", "invalid typed grant projection")
    elif method == "secret.stage":
        exact_keys(value, ("id", "name", "version", "expires_at"))
    elif method == "policy.evaluate":
        exact_keys(value, ("id", "result", "rules", "policy_generation", "input", "latency_ms",
                           "audit_complete"), ("cache_of", "skip_id"))
    elif method == "guidance.select":
        exact_keys(value, ("target", "task", "policy_generation", "candidate_snapshot_id", "reservation_id",
                           "judgment_ids", "id", "logical_turn_id", "as_of", "items", "status", "notice"),
                   ("weighted_score", "judgment_id"))
    elif method == "judge.ask":
        exact_keys(value, ("id", "status", "results", "selected_model", "reported_model", "deployment_sha256",
                           "latency_ms", "input_bytes", "input_tokens", "cost_micros", "unavailable_reason"),
                   ("request", "batch_ids", "raw"))
    else:
        raise Failure("unmapped ladder CLI method", "not_implemented", "lb-v2-e2e")
    return value


def operation_proof(path, config, method, params, used):
    try:
        value = load(immutable(path))
    except FileNotFoundError:
        from support import OwnerWait
        raise OwnerWait("fresh human confirmation for " + method, "lb-v2-identity",
                        "The owner must confirm this exact intent at its enrolled human endpoint and supply the fresh protected proof file.") from None
    exact_keys(value, ("id", "request_sha256", "expires_at"), ("simulated_presence",))
    presence(value)
    require(ID.fullmatch(value["id"]) is not None and value["id"] not in used,
            "human proof was reused", "unauthenticated")
    require(value["request_sha256"] == intent_digest(config, method, params),
            "human proof does not bind the exact intent", "unauthenticated")
    expiry = datetime.fromisoformat(value["expires_at"])
    require(expiry.tzinfo is not None and expiry > datetime.now(timezone.utc),
            "human proof expired", "unauthenticated")
    used.add(value["id"])
    return value


def session_proof(path, config, used):
    return operation_proof(path, config, "human.session", {}, used)


def ticket(value, scope=None, start=None):
    exact_keys(value, ("principal_id", "config", "endpoint_generation", "id", "level",
                       "role", "grant_set_id", "expires_at", "redeemed"), ("simulated_presence",))
    presence(value)
    check(ID.fullmatch(value["principal_id"]) and ID.fullmatch(value["id"]) and
          integer(value["endpoint_generation"], 1) and type(value["redeemed"]) is bool,
          "ticket", "ticket omitted its issuing provenance")
    if scope is not None:
        check(scope["actor"]["kind"] == "human" and value["principal_id"] ==
              scope["actor"]["id"] and value["config"] == scope["config"] and
              value["endpoint_generation"] == scope["endpoint_generation"],
              "ticket", "ticket belongs to another principal/config/endpoint")
    if start is not None:
        check(start["root_ticket_id"] == value["id"] and start["level"] == value["level"] and
              start["role"] == value["role"] and value["redeemed"] is False,
              "ticket", "root start does not match its unredeemed ticket")
        expiry = datetime.fromisoformat(value["expires_at"])
        check(expiry.tzinfo is not None and expiry > datetime.now(timezone.utc),
              "ticket", "root ticket expired before launch")


def ticket_events(run, by_name):
    root = next(event for event in by_name.values() if not event.get("parent_life_id"))
    original = run["root_ticket"]
    ticket(original, run["caller_scope"])
    check(original["redeemed"] is False and original["config"] == run["config"] and
          root["actor"] == run["caller_scope"]["actor"],
          "ticket", "root starter differs from authenticated ticket principal")
    starts = [item for item in run["mutations"] if item["request"]["method"] == "lane.start" and
              item["request"]["params"].get("root_ticket_id") == original["id"] and
              item["replayed"] is False]
    check(len(starts) == 1, "ticket", "root has no unique original lane.start receipt")
    receipt = starts[0]["receipt"]
    lane = root["payload"]["lane"]
    check(lane["role"] == original["role"] and lane["level"] == original["level"] and
          lane["grant_set_id"] == original["grant_set_id"] and
          receipt["operation_id"] == root["operation_id"],
          "ticket", "root lane differs from its ticket or start receipt")
    history = {}
    for kind, redeemed in (("ticket.issued", False), ("ticket.redeemed", True)):
        events = [event for event in run["events"] if event["kind"] == kind and
                  event["payload"].get("id") == original["id"]]
        check(len(events) == 1, "ticket", "root ticket issue/redemption is absent or duplicated")
        event = events[0]
        ticket(event["payload"], run["caller_scope"])
        check(event["origin"] == "service" and event["actor"] == root["actor"] and
              event["payload"] == {**original, "redeemed": redeemed},
              "ticket", "root ticket provenance/history differs")
        history[kind] = event
    issued, redeemed = history["ticket.issued"], history["ticket.redeemed"]
    check(issued["seq"] < redeemed["seq"] < root["seq"] and
          receipt["first_seq"] <= redeemed["seq"] <= receipt["last_seq"] and
          redeemed["operation_id"] == receipt["operation_id"],
          "ticket", "ticket redemption is outside reservation or follows prepared creation")


def presence(value):
    mark = value.get("simulated_presence", False)
    check(type(mark) is bool, "presence", "presence provenance is not boolean")
    return mark
