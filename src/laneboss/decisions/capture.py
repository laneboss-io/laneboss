"""Owner decisions classified by one Choice using the launcher's screened, timed and logged judge machinery."""

from datetime import datetime, timezone
import math
import os
import re
import time
import uuid

from .curated import case
from .orgcontext import append_log, discover, read_regular
from .schema import ID_PATTERN, InvalidInput, canonical, parse_json, render, sha256, timestamp, utc_now
from .store import Store

CHOICES = ("strong-decision", "preference", "question", "other")
QUESTION = "history.owner-decision"
PROMPT = ("Classify the human message as exactly one Choice: strong-decision (an explicit binding decision or "
          "instruction), preference (a nonbinding wish), question (a request for information, including proposals "
          "phrased as questions), or other. Return JSON with choice and score (confidence from 0 to 1), optional "
          "model and request identifiers. Only name an optional supersedes case id from prior_decisions when this "
          "message explicitly overrides it. Preserve the distinction between a question and a decision.")


def choice_answer(data):
    from .. import judges
    value = parse_json(data.decode("utf-8"))
    allowed = {"choice", "score", "model", "request", "supersedes"}
    if not isinstance(value, dict) or set(value) - allowed or value.get("choice") not in CHOICES:
        raise InvalidInput("judge did not return a documented Choice")
    score = value.get("score")
    if type(score) not in (int, float) or not math.isfinite(score) or not 0 <= score <= 1:
        raise InvalidInput("judge Choice score must be between zero and one")
    checked = judges.read_answer(render({"probability": score, "model": value.get("model"),
                                        "request": value.get("request")}).encode("ascii"))
    if checked is None:
        raise InvalidInput("judge Choice identifiers are invalid")
    target = value.get("supersedes")
    if target is not None and (not isinstance(target, str) or ID_PATTERN.fullmatch(target) is None):
        raise InvalidInput("judge supersedes must be a case id")
    return {"choice": value["choice"], "score": checked[0], "model": checked[1], "request": checked[2],
            "supersedes": target}


def ask_choice(configuration, state, name, text, source, prior):
    """Use the same request screening, process bounds, ownership check and durable egress pair as judge ask.

    The original Noul judge contract remains unchanged. A Choice-capable configured adapter gets kind=choice and
    choices, and returns choice/score. Its score is logged in the existing outcome probability field; the complete
    classification is logged separately in the org's classifications.jsonl.
    """
    from .. import events, judges
    judge = judges.judge_named(configuration, name)
    request = judges.build_request(QUESTION, PROMPT, {"message": text, "source": source, "prior_decisions": prior})
    if "message" in request.withheld or "source" in request.withheld or "message" in request.cut:
        raise InvalidInput("owner text/source was withheld or cut by judge screening; nothing is captured")
    body = parse_json(request.data.decode("utf-8"))
    body.update(kind="choice", choices=list(CHOICES))
    request = judges.Request((canonical(body) + "\n").encode("utf-8"), request.withheld, request.cut)
    judges.check_owner(configuration, state)
    judges.record_owner(state)
    directory = judges.open_directory(state)
    where = os.path.join(state.real, judges.EGRESS_DIRECTORY, judges.EGRESS_FILE)
    ask_id = uuid.uuid4().hex
    started = time.monotonic()
    answer, outcome = None, "exit"
    try:
        judges.sync_state(state)
        judges.write_line(directory, judges.sent_line(events.utc_now(), ask_id, name, QUESTION, None, request),
                          judges.NOTHING_ASKED, where, sending=True)
        try:
            reason, status, out, _ = judges.run_command(judge["command"], request.data,
                                                       judge.get("timeout_seconds", judges.DEFAULT_TIMEOUT),
                                                       judges.environment())
            outcome = reason or ("exit" if status != 0 else "answered")
            if outcome == "answered":
                try:
                    answer = choice_answer(out)
                except (InvalidInput, UnicodeError):
                    outcome = "output"
        finally:
            judges.write_line(directory, judges.outcome_line(
                events.utc_now(), ask_id, outcome, answer["score"] if answer else None,
                answer["model"] if answer else None, answer["request"] if answer else None,
                int(round((time.monotonic() - started) * 1000))), judges.OUTCOME_UNLOGGED, where)
    finally:
        os.close(directory)
    return {"outcome": outcome, "ask": ask_id, **(answer or {})}


def source_time(source, path, override=None):
    if override:
        timestamp(override, "source time")
        return override
    # Discord snowflakes carry a timestamp. Terminal adapters should include a timestamp in their source pointer,
    # or supply --at; a file's mtime is the fallback, never the later time when a judge happened to answer.
    snowflake = re.fullmatch(r"discord:[^:]+:([0-9]{17,20})", source)
    if snowflake:
        milliseconds = (int(snowflake[1]) >> 22) + 1420070400000
        return datetime.fromtimestamp(milliseconds / 1000.0, timezone.utc).isoformat(timespec="microseconds")
    found = re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3}(?:\d{3})?)?(?:Z|[+-]\d{2}:\d{2})", source)
    if found:
        timestamp(found[0], "source time")
        return found[0]
    return datetime.fromtimestamp(os.stat(path).st_mtime, timezone.utc).isoformat(timespec="microseconds")


def thresholds(org):
    strong = org.history.get("decision_threshold", 0.85)
    review = org.history.get("review_threshold", 0.6)
    if any(type(value) not in (int, float) or not math.isfinite(value) for value in (strong, review)):
        raise InvalidInput("decision thresholds must be finite numbers")
    if not 0 <= review < strong <= 1:
        raise InvalidInput("decision thresholds must satisfy 0 <= review < strong <= 1")
    return strong, review


def target_reason(store, target, identity, retry_id=None):
    row = store.connection.execute("SELECT * FROM records WHERE id = ?", (target,)).fetchone()
    if row is None:
        return "supersedes did not name an active owner decision"
    previous = store.checked_record(row)
    if previous["kind"] != "owner-decision":
        return "supersedes did not name an active owner decision"
    if not (previous.get("instance") == identity["instance"] or previous.get("level") == identity["level"]):
        return "supersedes target is outside the new decision's scope"
    if previous["status"] != "in_force" and not (retry_id is not None and previous["status"] == "superseded"
                                                and previous.get("superseded_by") == retry_id):
        return "supersedes did not name an active owner decision"
    return None


def capture_decision(arguments):
    from .. import config
    from ..statedir import StateDir
    org, identity, _, _ = discover(org_dir=arguments.org_dir, instance=arguments.instance)
    text = read_regular(arguments.text_file, 64 * 1024)
    if not text.strip():
        raise InvalidInput("owner message is empty")
    if not isinstance(arguments.source, str) or not arguments.source.strip():
        raise InvalidInput("owner message source is empty")
    created = source_time(arguments.source, arguments.text_file, arguments.at)
    strong, review = thresholds(org)
    configuration_name = arguments.config or org.history.get("configuration")
    configuration = config.load(config.bound_name(configuration_name))
    zones = config.Zones(configuration)
    problems = zones.problems()
    if problems:
        raise InvalidInput(problems[0])
    judge = arguments.judge or org.history.get("judge", "owner-decisions")
    identifier = "O-" + sha256(canonical({"source": arguments.source, "text": text, "instance": identity["instance"]}))
    store, state = None, None
    try:
        store = Store(org.db)
        prior = [store.checked_record(row) for row in store.rows() if row["kind"] == "owner-decision"
                 and row["status"] == "in_force"]
        prior.sort(key=lambda value: (timestamp(value["answered_at"], "answered_at"), value["id"]))
        summary = canonical([{"id": value["id"], "text": value["answer"]["verbatim"][:150]}
                             for value in prior[-16:]])
        state = StateDir.open(configuration, zones, create=True)
        verdict = ask_choice(configuration, state, judge, text, arguments.source, summary)
        receipt = {"at": utc_now(), "source": arguments.source, "source_time": created, "text_sha256": sha256(text),
                   "author_authority": arguments.author_authority, **identity, **verdict,
                   "event": "classification", "stored": False, "review": False}
        append_log(org.capture_log, receipt)
        if (verdict.get("choice") == "strong-decision" and arguments.author_authority == "decide"
                and verdict["score"] >= review):
            record = case(identifier, "owner-decision", text, arguments.source, created, identity)
            target = verdict.get("supersedes")
            existing = store.connection.execute("SELECT * FROM records WHERE id = ?", (identifier,)).fetchone()
            if existing is not None and verdict["score"] >= strong:
                old = store.checked_record(existing)
                if (old["answer"]["verbatim"] != text or old["kind"] != "owner-decision"
                        or old.get("level") != identity["level"] or old.get("instance") != identity["instance"]
                        or (target is not None and old.get("supersedes") != target)):
                    raise InvalidInput("owner decision content id conflicts with stored record")
                # A retry's supersession target is already superseded by this very case. Checking active targets
                # first would incorrectly turn that retry into a new review entry.
                reason = target_reason(store, target, identity, retry_id=identifier) if target else None
                if reason:
                    receipt.update(review=True, review_reason=reason)
                    append_log(org.review, {**receipt, "record": record})
                else:
                    receipt.update(stored=True, existing=True, id=identifier)
            else:
                if target:
                    reason = target_reason(store, target, identity)
                    if reason:
                        receipt["review_reason"] = reason
                if verdict["score"] < strong or "review_reason" in receipt:
                    receipt["review"] = True
                    append_log(org.review, {**receipt, "record": record})
                else:
                    if target:
                        store.supersede(target, record)
                    else:
                        store.add(record)
                    receipt.update(stored=True, id=identifier)
        # A second append records the action taken, without editing the classification receipt.
        receipt["event"] = "capture-outcome"
        append_log(org.capture_log, receipt)
        return receipt
    finally:
        if state is not None:
            state.close()
        if store is not None:
            store.close()
