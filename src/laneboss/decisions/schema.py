"""Record validation and deterministic text projections for schema version 1."""

import copy
from datetime import datetime, timezone
import hashlib
import json
import re


KINDS = {"decision", "answer", "instruction", "preference", "correction", "question_from_owner",
         "owner-decision", "ledger", "report", "board", "bulletin"}
STATUSES = {"in_force", "superseded", "withdrawn", "fulfilled"}
SIDES = {"q_text": "question", "d_text": "decision"}

# A lane record holds one source of one lane, whole: the lane's final report, its events as text lines, or a file
# the supervisor attached. Its id names the configuration, the lane, the part and the first 16 hex digits of the
# source's SHA-256, so ingesting the same source twice writes one row. Its fields are checked the same way a stored
# row is checked, at write and at read.
LANE_PARTS = ("report", "events", "attachment")
LANE_RECORD_KEYS = {
    "id", "config", "lane", "part", "source_path", "source_sha256", "text", "created_utc", "ingested_utc",
    "level", "instance",
}
CONFIG_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
LANE_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
LANE_RECORD_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,31}/[a-z0-9][a-z0-9._-]{0,63}/(?:report|events|attachment)/[0-9a-f]{16}")

RECORD_KEYS = {
    "id", "kind", "schema_version", "asked_at", "answered_at", "project", "area", "topics",
    "question", "answer", "scope", "status", "supersedes", "superseded_by",
    "status_before_superseded", "outcome", "provenance",
    "level", "instance",
}
QUESTION_KEYS = {"text", "background", "asked_by", "options", "recommendation", "default_if_unanswered"}
OPTION_KEYS = {"label", "text"}
ANSWER_KEYS = {
    "verbatim", "language", "channel", "message_id", "selected_option", "interpreted_as", "ambiguity",
    "sha256", "interpretation_label",
}
SCOPE_KEYS = {"applies_to", "does_not_authorize", "reversible", "valid_until"}
OUTCOME_KEYS = {"actions", "evidence", "followups"}
ACTION_KEYS = {"at", "text"}
PROVENANCE_KEYS = {"recorded_by", "recorded_at", "sources"}
SOURCE_KEYS = {"path", "line", "sha256_of_line", "line_text"}
ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
INSTANCE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
FEEDBACK_EVENTS = {"merged": 1, "accepted": 1, "abandoned": -1, "refusal": -1, "cited": 1}


def validate_scope(value):
    """Unscoped legacy rows remain intact; a new scope must name both its level and instance."""
    level, instance = value.get("level"), value.get("instance")
    if level is None and instance is None:
        return
    if type(level) is not int or level not in (3, 4, 5, 6):
        raise InvalidInput("level must be an integer from 3 to 6")
    if not isinstance(instance, str) or INSTANCE_PATTERN.fullmatch(instance) is None:
        raise InvalidInput("instance must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}")


class InvalidInput(Exception):
    pass


class IntegrityError(Exception):
    pass


class ProviderError(Exception):
    pass


class AccessProblem(Exception):
    """The database file or its directory cannot be read or written with the caller's permissions."""


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def render(result):
    """The text a command prints for its result: one line of JSON. The resident search sends the same bytes."""
    return json.dumps(result, ensure_ascii=True, sort_keys=True, allow_nan=False) + "\n"


def sha256(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def reject_constant(value):
    raise InvalidInput("JSON must contain finite numbers")


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise InvalidInput("JSON contains a duplicate field")
        value[key] = item
    return value


def parse_json(text):
    try:
        return json.loads(text, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise InvalidInput("invalid JSON") from error


def read_json(path):
    try:
        with open(path, encoding="utf-8") as source:
            return parse_json(source.read())
    except (OSError, UnicodeError) as error:
        raise InvalidInput("cannot read JSON file") from error


def timestamp(value, field):
    pattern = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3}(?:[0-9]{3})?)?(?:Z|[+-][0-9]{2}:[0-9]{2})"
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise InvalidInput(field + " must be an ISO 8601 timestamp with offset")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
        if parsed.utcoffset() is None:
            raise ValueError()
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError) as error:
        raise InvalidInput(field + " must be an ISO 8601 timestamp with offset") from error


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def required(value, field):
    target = value
    for part in field.split("."):
        if not isinstance(target, dict) or part not in target or target[part] is None:
            raise InvalidInput("missing required field: " + field)
        target = target[part]
    return target


def reject_unknown(value, allowed, field):
    if not isinstance(value, dict):
        raise InvalidInput(field + " must be an object")
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise InvalidInput("unknown field: " + field + "." + unknown[0])


def text(value, field, allow_empty=False, allow_nul=False):
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise InvalidInput(field + " must be a nonempty string")
    try:
        value.encode("utf-8")
    except UnicodeError as error:
        raise InvalidInput(field + " must be valid UTF-8 text") from error
    if not allow_nul and "\x00" in value:
        raise InvalidInput(field + " cannot contain NUL")


def string_list(value, field, nonempty=False):
    if not isinstance(value, list) or (nonempty and not value):
        raise InvalidInput(field + " must be a list" + (" with at least one item" if nonempty else ""))
    for item in value:
        text(item, field)


def validate_outcome(outcome):
    reject_unknown(outcome, OUTCOME_KEYS, "outcome")
    for field in ("evidence", "followups"):
        if field in outcome:
            string_list(outcome[field], "outcome." + field)
    if "actions" in outcome:
        if not isinstance(outcome["actions"], list):
            raise InvalidInput("outcome.actions must be a list")
        for action in outcome["actions"]:
            reject_unknown(action, ACTION_KEYS, "outcome.actions")
            timestamp(required(action, "at"), "outcome.actions.at")
            text(required(action, "text"), "outcome.actions.text")


def validate_record(original):
    if not isinstance(original, dict):
        raise InvalidInput("record must be an object")
    value = copy.deepcopy(original)
    reject_unknown(value, RECORD_KEYS, "record")
    validate_scope(value)
    for field in ("id", "kind", "asked_at", "answered_at", "project", "area", "topics",
                  "question.text", "question.background", "answer.verbatim", "answer.channel",
                  "scope.applies_to", "status", "provenance", "provenance.recorded_by",
                  "provenance.recorded_at", "provenance.sources"):
        required(value, field)
    value.setdefault("schema_version", 1)
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise InvalidInput("schema_version must be 1")
    for field in ("id", "kind", "project", "area", "status", "question.text", "question.background",
                  "answer.verbatim", "answer.channel", "provenance.recorded_by"):
        text(required(value, field), field, allow_nul=field == "answer.verbatim")
    if ID_PATTERN.fullmatch(value["id"]) is None:
        raise InvalidInput("id must match [A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
    reject_unknown(value["question"], QUESTION_KEYS, "question")
    reject_unknown(value["answer"], ANSWER_KEYS, "answer")
    reject_unknown(value["scope"], SCOPE_KEYS, "scope")
    reject_unknown(value["provenance"], PROVENANCE_KEYS, "provenance")
    if value["kind"] not in KINDS:
        raise InvalidInput("kind is not a supported record kind")
    if value["status"] not in STATUSES:
        raise InvalidInput("status is not a supported record status")
    for field in ("asked_at", "answered_at", "provenance.recorded_at"):
        timestamp(required(value, field), field)
    string_list(value["topics"], "topics", nonempty=True)
    applies_to = value["scope"]["applies_to"]
    if isinstance(applies_to, list):
        string_list(applies_to, "scope.applies_to", nonempty=True)
    else:
        text(applies_to, "scope.applies_to")
    for container, fields in (
        ("question", ("asked_by", "recommendation", "default_if_unanswered")),
        ("answer", ("language", "message_id", "selected_option", "interpreted_as", "ambiguity")),
    ):
        for field in fields:
            if field in value[container] and value[container][field] is not None:
                text(value[container][field], container + "." + field, allow_empty=True)
    if "options" in value["question"]:
        if not isinstance(value["question"]["options"], list):
            raise InvalidInput("question.options must be a list")
        for option in value["question"]["options"]:
            reject_unknown(option, OPTION_KEYS, "question.options")
            for field in ("label", "text"):
                text(required(option, field), "question.options." + field)
    scope = value["scope"]
    if "reversible" in scope and type(scope["reversible"]) is not bool:
        raise InvalidInput("scope.reversible must be a boolean")
    if scope.get("valid_until") is not None:
        timestamp(scope["valid_until"], "scope.valid_until")
    if scope.get("does_not_authorize") is not None:
        if isinstance(scope["does_not_authorize"], list):
            string_list(scope["does_not_authorize"], "scope.does_not_authorize")
        else:
            text(scope["does_not_authorize"], "scope.does_not_authorize", allow_empty=True)
    for field in ("supersedes", "superseded_by"):
        if value.get(field) is not None:
            text(value[field], field)
            if value[field] == value["id"]:
                raise InvalidInput(field + " cannot refer to the record itself")
    if value.get("status_before_superseded") is not None:
        if (value["status"] != "superseded" or not isinstance(value["status_before_superseded"], str)
                or value["status_before_superseded"] not in STATUSES - {"superseded"}):
            raise InvalidInput("status_before_superseded is only valid for a superseded record")
    if value["status"] == "superseded" and not value.get("superseded_by"):
        raise InvalidInput("superseded_by is required for status superseded")
    if value.get("superseded_by") and value["status"] != "superseded":
        raise InvalidInput("superseded_by requires status superseded")
    value.setdefault("outcome", {})
    validate_outcome(value["outcome"])
    sources = value["provenance"]["sources"]
    if not isinstance(sources, list):
        raise InvalidInput("provenance.sources must be a list")
    for source in sources:
        reject_unknown(source, SOURCE_KEYS, "provenance.sources")
        text(required(source, "path"), "provenance.sources.path")
        if type(required(source, "line")) is not int or source["line"] < 1:
            raise InvalidInput("provenance.sources.line must be a positive integer")
        line_hash = required(source, "sha256_of_line")
        if not isinstance(line_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", line_hash):
            raise InvalidInput("provenance.sources.sha256_of_line must be a SHA-256 hex digest")
        if "line_text" in source:
            text(source["line_text"], "provenance.sources.line_text", allow_empty=True, allow_nul=True)
            if sha256(source["line_text"]) != line_hash:
                raise InvalidInput("provenance.sources.sha256_of_line does not match line_text")
    answer = value["answer"]
    answer.setdefault("message_id", None)
    answer_hash = sha256(answer["verbatim"])
    if "sha256" in answer and answer["sha256"] != answer_hash:
        raise InvalidInput("answer.sha256 does not match answer.verbatim")
    answer["sha256"] = answer_hash
    if answer.get("interpreted_as") is not None:
        answer["interpretation_label"] = "supervisor interpretation"
    elif answer.get("interpretation_label") is not None:
        raise InvalidInput("answer.interpretation_label requires interpreted_as")
    try:
        canonical(value).encode("utf-8")
    except (ValueError, UnicodeError, RecursionError) as error:
        raise InvalidInput("record contains invalid JSON text") from error
    return value


def mark_superseding(record, identifier):
    """Check a record that replaces the record `identifier`, and link it to that record."""
    if record.get("supersedes") not in (None, identifier):
        raise InvalidInput("supersedes conflicts with OLD_ID")
    if record["status"] not in ("in_force", "fulfilled") or record.get("superseded_by"):
        raise InvalidInput("new record status must be in_force or fulfilled")
    record["supersedes"] = identifier
    if record["id"] == identifier:
        raise InvalidInput("supersede requires a new id; answer.verbatim is immutable")


def mark_superseded(old, new_id):
    """Turn a stored record into its superseded form, keeping the status it had."""
    if old["status"] == "superseded":
        raise InvalidInput("old record is already superseded")
    old["status_before_superseded"] = old["status"]
    old["status"] = "superseded"
    old["superseded_by"] = new_id


def flatten(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(flatten(item) for item in value)
    if isinstance(value, dict):
        return "\n".join(flatten(value[key]) for key in sorted(value))
    return str(value)


def lane_record_id(config, lane, part, digest):
    """The stable id of one lane record: configuration, lane, part and the first 16 hex digits of the source hash."""
    if CONFIG_PATTERN.fullmatch(config or "") is None:
        raise InvalidInput("config must match [a-z0-9][a-z0-9-]{0,31}")
    if LANE_PATTERN.fullmatch(lane or "") is None:
        raise InvalidInput("lane must match [a-z0-9][a-z0-9._-]{0,63}")
    if part not in LANE_PARTS:
        raise InvalidInput("part must be one of " + ", ".join(LANE_PARTS))
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise InvalidInput("source sha256 must be a SHA-256 hex digest")
    return "{}/{}/{}/{}".format(config, lane, part, digest[:16])


def validate_lane_record(original):
    """Check one lane record and return it with derived values verified. The stored row is checked with this at
    every read, so a row that does not match its own id or hash is an integrity problem."""
    if not isinstance(original, dict):
        raise InvalidInput("lane record must be an object")
    value = copy.deepcopy(original)
    reject_unknown(value, LANE_RECORD_KEYS, "lane record")
    validate_scope(value)
    for field in ("id", "config", "lane", "part", "source_path", "source_sha256", "text", "created_utc",
                  "ingested_utc"):
        required(value, field)
    for field in ("id", "config", "lane", "part", "source_path", "source_sha256", "created_utc", "ingested_utc"):
        text(required(value, field), field)
    text(value["text"], "text", allow_empty=False)
    if LANE_RECORD_ID.fullmatch(value["id"]) is None:
        raise InvalidInput("id is not a lane record id")
    if value["part"] not in LANE_PARTS:
        raise InvalidInput("part is not a supported lane record part")
    if re.fullmatch(r"[0-9a-f]{64}", value["source_sha256"]) is None:
        raise InvalidInput("source_sha256 must be a SHA-256 hex digest")
    if value["id"] != lane_record_id(value["config"], value["lane"], value["part"], value["source_sha256"]):
        raise InvalidInput("id does not name its configuration, lane, part and source hash")
    # The stored text is the source's bytes decoded, and every writer here hashes exactly those bytes (the report
    # and an attachment hash the file's bytes, the events part hashes the encoding of the text it stores), so
    # re-encoding the text must give the hash the row names. Without this, a writer that stored text other than
    # the bytes it hashed would go unnoticed, and source_sha256 is the value an archive check compares against.
    if sha256(value["text"]) != value["source_sha256"]:
        raise InvalidInput("source_sha256 does not name the record's own text")
    timestamp(value["created_utc"], "created_utc")
    timestamp(value["ingested_utc"], "ingested_utc")
    return value


def projections(record):
    question = record["question"]
    answer = record["answer"]
    question_text = "\n".join(flatten(value) for value in (
        question["text"], question["background"], question.get("options"),
        question.get("recommendation"), record["topics"],
    ))
    decision_text = "\n".join(flatten(value) for value in (
        answer["verbatim"], answer.get("interpreted_as"), record["scope"], record["outcome"],
    ))
    return question_text, decision_text
