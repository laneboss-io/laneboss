"""What a lane holds outside the machine the launcher runs on: the forms of the five `resource.*` events, the order they
may come in, the fold of them into one record for each resource, and what held means.

Pure code: no input, no output, no clock of its own (the caller passes the time) and no knowledge of any provider. A
resource event is checked when it is appended, whoever appends it, and replay() runs the same checks over a whole store
for `state verify` and `state rebuild` (docs/architecture.md, "Resources and cost"). check() looks at a payload alone,
check_transition() at an event against the lane's row and the fold, check_state() at a lane.state that accepts or
merges. Each raises the failure it is given and never repeats a value.
"""

from datetime import datetime, timedelta, timezone
import re

from . import lanes
from .errors import IntegrityProblem, Refused

KINDS = ("resource.intent", "resource.acquired", "resource.failed", "resource.released", "resource.cost")
# The state a resource must be in for each kind that comes after its intent (a cost also needs that it has none yet).
NEEDS = {"resource.acquired": "intent", "resource.failed": "intent", "resource.released": "acquired",
         "resource.cost": "released"}
HELD = ("intent", "acquired")
ACCEPTING = ("accepted", "merged")
CLOSED = ("merged", "abandoned")
MAX_AMOUNT = 9007199254740991
MAX_CAP_MINUTES = 10080
HOUR_MICROSECONDS = 3600000000
# How long an intent may wait for its acquire before it is listed as unresolved, when the configuration has no adapter.
DEFAULT_ACQUIRE_BOUND_MINUTES = 15
# The protocol version that step A writes: the threshold of the replay's version test (a lane.state that names an older
# version came from a launcher that had no gate). It is fixed here and not read from the shipped protocol.md, which
# step A raises only in the slice that turns its part of the design into description.
GATE_VERSION = "1.3.0"

ID = lanes.RESOURCE_ID
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
KIND_NAME = re.compile(r"[a-z][a-z0-9-]{0,31}")
PROVIDER = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
REGION = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
SIZE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}")
PURPOSE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}")
PROVIDER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,191}")
REASON = re.compile(r"[a-z][a-z-]{0,39}")
CURRENCY = re.compile(r"[A-Z]{3}")

MONEY = lanes.obj({"amount_micros": lanes.integer(0, MAX_AMOUNT), "currency": lanes.grammar(CURRENCY)})
PRICE = lanes.nullable(lanes.obj({"per_hour": MONEY, "source": lanes.one_of("adapter", "configured")}))
READ_BACK = lanes.obj({
    "at": lanes.timestamp, "state": lanes.one_of("terminated"), "provider_state": lanes.grammar(IDENTIFIER),
    "ended_at": lanes.nullable(lanes.timestamp), "request": lanes.nullable(lanes.grammar(IDENTIFIER))})
PAYLOADS = {
    "resource.intent": {
        "resource": lanes.grammar(ID), "run": lanes.RUN, "kind": lanes.grammar(KIND_NAME),
        "provider": lanes.grammar(PROVIDER), "purpose": lanes.grammar(PURPOSE),
        "size": lanes.nullable(lanes.grammar(SIZE)), "region": lanes.nullable(lanes.grammar(REGION)),
        "price": PRICE, "hard_cap_minutes": lanes.integer(1, MAX_CAP_MINUTES)},
    "resource.acquired": {
        "resource": lanes.grammar(ID), "provider_id": lanes.grammar(PROVIDER_ID),
        "found_by": lanes.one_of("acquire", "describe"), "started_at": lanes.nullable(lanes.timestamp),
        "request": lanes.nullable(lanes.grammar(IDENTIFIER))},
    "resource.failed": {
        "resource": lanes.grammar(ID), "how": lanes.one_of("adapter", "release"), "reason": lanes.grammar(REASON),
        "request": lanes.nullable(lanes.grammar(IDENTIFIER))},
    "resource.released": {
        "resource": lanes.grammar(ID), "how": lanes.one_of("release", "by-itself", "observed"),
        "read_back": READ_BACK},
    "resource.cost": {
        "resource": lanes.grammar(ID), "started_at": lanes.timestamp, "ended_at": lanes.timestamp, "price": PRICE,
        "cost": lanes.nullable(MONEY)},
}


def _fail(where, message):
    raise lanes.Invalid("{}: {}".format(where, message))


def _consistent(kind, payload):
    """Rules between the members of one payload."""
    if kind == "resource.cost":
        price, cost = payload["price"], payload["cost"]
        if (price is None) != (cost is None):
            _fail("payload.cost", "is null exactly when payload.price is null: a cost without a price has no amount")
        if price is not None and cost["currency"] != price["per_hour"]["currency"]:
            _fail("payload.cost.currency", "is the currency of payload.price")


def check(kind, lane, payload, failure=Refused):
    """Refuse a resource event whose kind, lane or payload breaks its documented form: a payload alone, no store."""
    if kind not in KINDS:
        raise failure("kind: resource events are " + ", ".join(KINDS))
    if lane is None:
        raise failure("lane: is required for resource events")
    try:
        lanes.obj(PAYLOADS[kind])(payload, "payload")
        _consistent(kind, payload)
    except lanes.Invalid as error:
        raise failure("{} {}".format(kind, error)) from None


def instant(text):
    """The moment of a timestamp as the envelope writes it."""
    return datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)


def start_of(record):
    """The text the held time starts from: the provider's started_at, and else the time of the intent, so that a
    resource whose provider gave no start is held from its intent and never costs less than it ran."""
    return record["intent_at"] if record["started_at"] is None else record["started_at"]


def cap_at(record):
    """When the hard cap passes, written as the store writes recorded_at: the start plus hard_cap_minutes."""
    moment = instant(start_of(record)) + timedelta(minutes=record["hard_cap_minutes"])
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def end_of(record):
    """The text the held time of a released record ends at: the read_back's ended_at when it is not null and not before
    the start, else its at, and the start when even that is before it ("Cost")."""
    start = start_of(record)
    for text in (record["read_back"]["ended_at"], record["read_back"]["at"]):
        if text is not None and instant(text) >= instant(start):
            return text
    return start


def cost_of(record):
    """The cost of a released record: null when it has no price, else the price per hour times the held time rounded up
    to the next micro-unit, with integers only ("Cost")."""
    price = record["price"]
    if price is None:
        return None
    held = instant(end_of(record)) - instant(start_of(record))
    microseconds = (held.days * 86400 + held.seconds) * 1000000 + held.microseconds
    per_hour = price["per_hour"]
    amount = (per_hour["amount_micros"] * microseconds + HOUR_MICROSECONDS - 1) // HOUR_MICROSECONDS
    return {"amount_micros": amount, "currency": per_hour["currency"]}


def held_of(record):
    """The one definition of held: the fold says intent or acquired. Not the state of the lane, not the events of the
    lane that wait in a pending file, not a reading of the provider, not the clock."""
    return record["state"] in HELD


def holding(records, lane):
    """The `held` of a lane.state for what the lane holds: each held resource and its fold state, sorted by resource."""
    return [{"resource": name, "state": records[name]["state"]} for name in sorted(records)
            if records[name]["lane"] == lane and held_of(records[name])]


def apply(records, event):
    """Fold one resource event into the records. The caller has checked that it fits (check_order)."""
    payload = event["payload"]
    at = event["occurred_at"] or event["recorded_at"]
    if event["kind"] == "resource.intent":
        records[payload["resource"]] = {
            "resource": payload["resource"], "lane": event["lane"], "run": payload["run"], "kind": payload["kind"],
            "provider": payload["provider"], "purpose": payload["purpose"], "size": payload["size"],
            "region": payload["region"], "price": payload["price"], "hard_cap_minutes": payload["hard_cap_minutes"],
            "state": "intent", "seq": event["seq"], "intent_at": at,
            "provider_id": None, "started_at": None, "found_by": None, "request": None, "acquired_seq": None,
            "acquired_at": None, "how": None, "reason": None, "failed_seq": None, "failed_at": None,
            "read_back": None, "released_seq": None, "released_at": None,
            "cost": None, "cost_seq": None, "cost_started_at": None, "cost_ended_at": None}
        return
    record = records[payload["resource"]]
    if event["kind"] == "resource.acquired":
        record.update(state="acquired", provider_id=payload["provider_id"], started_at=payload["started_at"],
                      found_by=payload["found_by"], request=payload["request"], acquired_seq=event["seq"],
                      acquired_at=at)
    elif event["kind"] == "resource.failed":
        record.update(state="failed", how=payload["how"], reason=payload["reason"], failed_seq=event["seq"],
                      failed_at=at)
    elif event["kind"] == "resource.released":
        record.update(state="released", how=payload["how"], read_back=payload["read_back"],
                      released_seq=event["seq"], released_at=payload["read_back"]["at"])
    else:
        record.update(cost=payload["cost"], cost_seq=event["seq"], cost_started_at=payload["started_at"],
                      cost_ended_at=payload["ended_at"])


def check_order(records, event, failure):
    """Refuse an event that the order of the kinds has no rule for after what the records hold: an intent for an id
    that is stored, an event for a resource that has no intent or has another lane, or one that is not in the state
    its kind needs (an acquired or failed needs an intent only, a released an acquired, a cost a released one)."""
    kind, lane = event["kind"], event["lane"]
    name = event["payload"]["resource"]
    record = records.get(name)
    if kind == "resource.intent":
        if record is not None:
            raise failure("resource.intent: resource {} is stored already; an id has one intent".format(name))
        return
    if record is None:
        raise failure("{}: no intent of resource {} is stored".format(kind, name))
    if record["lane"] != lane:
        raise failure("{}: resource {} belongs to lane {}, not to lane {}".format(kind, name, record["lane"], lane))
    if record["state"] != NEEDS[kind]:
        raise failure("{}: resource {} is {}, and this kind needs it {}".format(
            kind, name, record["state"], NEEDS[kind]))
    if kind == "resource.cost" and record["cost_seq"] is not None:
        raise failure("resource.cost: resource {} has its cost already".format(name))


def check_transition(row, records, event, failure=Refused):
    """Refuse a resource event that its lane's row and the fold do not allow. `row` is the lane's projection, or None
    when the store has no event of the lane; `records` is the fold of every resource event stored so far."""
    kind, lane, payload = event["kind"], event["lane"], event["payload"]
    if row is None:
        raise failure("{}: lane {} is not known; the store has no lane event of it".format(kind, lane))
    check_order(records, event, failure)
    if kind == "resource.intent":
        # The form says the run is at least 1: it is a run of the lane when it is not beyond the lane's latest.
        if payload["run"] > row["run"]:
            raise failure("resource.intent: lane {} has no run {}".format(lane, payload["run"]))
        if row["state"] in CLOSED:
            raise failure("resource.intent: lane {} is {}, so it takes no new resource".format(lane, row["state"]))
        if len(holding(records, lane)) >= lanes.MAX_HELD:
            raise failure("resource.intent: lane {} holds {} resources already, the most that a lane.state can "
                          "list".format(lane, lanes.MAX_HELD))
    if kind == "resource.cost":
        record = records[payload["resource"]]
        if payload["price"] != record["price"]:
            raise failure("resource.cost: payload.price is not the price of the intent")
        if payload["started_at"] != start_of(record):
            raise failure("resource.cost: payload.started_at is not the start of the held time")
        if payload["ended_at"] != end_of(record):
            raise failure("resource.cost: payload.ended_at is not the end of the held time")
        if payload["cost"] != cost_of(record):
            raise failure("resource.cost: payload.cost is not the price times the held time, rounded up")


def check_state(records, event, failure=Refused):
    """Refuse a lane.state that accepts or merges (the caller has seen that it does) unless its `held` lists exactly
    the resources its lane holds, each with its state, and is left out when the lane holds none."""
    lane = event["lane"]
    if event["payload"].get("held", []) != holding(records, lane):
        raise failure("lane.state: payload.held must list exactly the resources lane {} holds now, each with its "
                      "state, and be left out when it holds none; the held resources changed since they were read, "
                      "or were not read".format(lane))


def fold(events, failure=IntegrityProblem):
    """One record for each resource id, in the order of the intents, from the resource events among `events` taken in
    seq order and nothing else. The checks at append let no store hold an order the fold has no rule for, so an event
    that breaks one is reported with its seq."""
    records = {}
    for event in events:
        if event["kind"].startswith("resource."):
            try:
                check_order(records, event, failure)
            except failure as error:
                raise failure("event seq {}: {}".format(event["seq"], error)) from None
            apply(records, event)
    return records


def standing(record, row, configuration, clock):
    """The reasons for which a held resource is a finding, sorted; none for a resource that is not held, and none for a
    held resource that is simply in use. `row` is the lane's projection, `configuration` the loaded configuration and
    `clock` the launcher's time as a timestamp. The reasons that need a reading of the provider or a cost event belong
    to the commands that have them."""
    if not held_of(record):
        return []
    now = instant(clock)
    reasons = []
    if not row["running"] and row["run"] >= record["run"]:
        reasons.append("lane-ended")
    if now > instant(cap_at(record)):
        reasons.append("held-beyond-cap")
    table = configuration.data.get("resources", {}).get(record["provider"])
    if table is None:
        reasons.append("adapter-missing")
    bound = (table or {}).get("acquire_bound_minutes", DEFAULT_ACQUIRE_BOUND_MINUTES)
    if record["state"] == "intent" and now > instant(record["intent_at"]) + timedelta(minutes=bound):
        reasons.append("unresolved")
    return sorted(reasons)


def numbers(version):
    """A protocol version as its three whole numbers, so that 1.10.0 is after 1.9.0."""
    return tuple(int(part) for part in version.split("."))


def replay(events, failure, gate_version):
    """The checks of append, replayed over every stored event in seq order: a private projection of each lane (the
    checks need only its run and its state) built by lanes.apply() from its lane events, the fold so far,
    check_transition() for each resource event and check_state() for each lane.state that accepts or merges. A
    lane.state that names a protocol version older than `gate_version` (the version that step A's protocol.md carries)
    is left alone: an older launcher had no gate, and an event is not refused for the absence of a gate that its
    producer did not have. The first event that fails is reported with its seq."""
    projections = {}
    records = {}
    for event in events:
        lane = event["lane"]
        try:
            if event["kind"].startswith("resource."):
                check_transition(projections.get(lane), records, event, failure)
                apply(records, event)
            elif lanes.is_lane_event(event):
                if (event["kind"] == "lane.state" and event["payload"]["state"] in ACCEPTING
                        and numbers(event["protocol_version"]) >= numbers(gate_version)):
                    check_state(records, event, failure)
                lanes.apply(projections.setdefault(lane, lanes.empty(lane)), event)
        except failure as error:
            raise failure("event seq {}: {}".format(event["seq"], error)) from None
