"""Auditable time and outcome weighting shared by CLI and resident searches."""

from datetime import datetime, timezone
import math

from .schema import FEEDBACK_EVENTS, InvalidInput, KINDS, timestamp

DEFAULT_HALF_LIVES = {kind: 60.0 for kind in KINDS}
DEFAULT_HALF_LIVES.update({kind: 14.0 for kind in ("lane_record", "ledger", "report", "board", "bulletin")})
DEFAULT_HALF_LIVES["owner-decision"] = None


def half_lives(overrides):
    values = dict(DEFAULT_HALF_LIVES)
    for given in overrides or ():
        kind, separator, days = given.partition("=")
        if not separator or kind not in values or kind == "owner-decision":
            raise InvalidInput("half-life must be KIND=DAYS; owner-decision never decays")
        try:
            number = float(days)
        except ValueError as error:
            raise InvalidInput("half-life days must be a positive finite number") from error
        if not math.isfinite(number) or number <= 0:
            raise InvalidInput("half-life days must be a positive finite number")
        values[kind] = number
    return values


def weighted(result, eligible, lane_records, feedback, arguments):
    """Weight every candidate before limiting, retaining negative cases with a warning and positive weight."""
    moment = timestamp(arguments.now, "now") if getattr(arguments, "now", None) else datetime.now(timezone.utc)
    lives = half_lives(getattr(arguments, "half_life", None))
    events = {}
    for event in feedback:
        if timestamp(event["at"], "feedback.at") <= moment:
            events.setdefault(event["case_id"], []).append(event)
    details, scores = {}, {}
    for identifier in result.ranking:
        record = (eligible.get(identifier) or lane_records[identifier])[0]
        if record.get("status") == "superseded":
            continue
        kind = record.get("kind", "lane_record")
        created = timestamp(record.get("answered_at", record.get("created_utc")), "case time")
        age = max(0.0, (moment - created).total_seconds() / 86400.0)
        life = lives[kind]
        recency = 1.0 if life is None else 2.0 ** -min(age / life, 1022.0)
        rewards = events.get(identifier, [])
        reward = sum(FEEDBACK_EVENTS[event["event"]] for event in rewards)
        outcome = 2.0 ** max(-8, min(8, reward))
        relevance = max(0.0, result.score(identifier))
        scores[identifier] = relevance * recency * outcome
        negative = any(FEEDBACK_EVENTS[event["event"]] < 0 for event in rewards)
        details[identifier] = {"relevance": relevance, "recency": recency, "outcome": outcome,
                               "half_life_days": life, "as_of": moment.isoformat(timespec="microseconds"),
                               "feedback": rewards, "do_not_repeat": negative}
    return sorted(scores, key=lambda identifier: (-scores[identifier], identifier)), scores, details
