"""Incremental batch loader: validate a whole JSONL batch first, then apply it in one transaction.

Each line of a batch is one JSON object, either {"op": "add", "record": {...}} or
{"op": "supersede", "target": "<existing id>", "record": {...}}. A batch is a set: its lines may come in any
order. Nothing is written until every line has been read and the whole batch has been planned against the
stored records, so a refused batch leaves the database file untouched.
"""

import copy
import sqlite3

from .schema import (
    ID_PATTERN, InvalidInput, canonical, mark_superseded, mark_superseding, parse_json, sha256, validate_record,
)

OPERATION_KEYS = {"add": {"op", "record"}, "supersede": {"op", "target", "record"}}
OUTCOME_FIELDS = ("actions", "evidence", "followups")
MISSING = object()


def read_batch(path):
    try:
        with open(path, "rb") as source:
            raw = source.read()
    except OSError as error:
        raise InvalidInput("cannot read batch file") from error
    if not raw:
        raise InvalidInput("batch file is empty")
    lines = raw.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    return [parse_operation(number, line) for number, line in enumerate(lines, 1)]


def parse_operation(number, line):
    prefix = "line {}: ".format(number)
    try:
        text = line.decode("utf-8")
    except UnicodeError:
        raise InvalidInput(prefix + "invalid UTF-8") from None
    if not text.strip(" \t\r"):
        raise InvalidInput(prefix + "empty line")
    try:
        operation = build_operation(parse_json(text))
    except InvalidInput as error:
        raise InvalidInput(prefix + str(error)) from None
    operation["line"] = number
    return operation


def build_operation(value):
    if not isinstance(value, dict):
        raise InvalidInput("operation must be a JSON object")
    kind = value.get("op")
    if not isinstance(kind, str) or kind not in OPERATION_KEYS:
        raise InvalidInput('op must be "add" or "supersede"')
    for key in sorted(value):
        if key not in OPERATION_KEYS[kind]:
            raise InvalidInput("unknown field: " + key)
    if "record" not in value:
        raise InvalidInput("missing required field: record")
    target = None
    if kind == "supersede":
        if "target" not in value:
            raise InvalidInput("missing required field: target")
        target = value["target"]
        if not isinstance(target, str) or ID_PATTERN.fullmatch(target) is None:
            raise InvalidInput("target must be the id of an existing record")
    record = validate_record(value["record"])
    if kind == "add":
        for field in ("supersedes", "superseded_by"):
            if record.get(field) is not None:
                raise InvalidInput("record.{} is not allowed with op add; use op supersede".format(field))
    else:
        mark_superseding(record, target)
    # The record exactly as this line writes it; its hash is the record's first-written value.
    return {"op": kind, "target": target, "record": record, "sha256": sha256(canonical(record))}


def comparable(record):
    """A record as it was first written: the status change that supersede makes later is undone."""
    value = copy.deepcopy(record)
    if value["status"] == "superseded":
        value["status"] = value.get("status_before_superseded")
    value.pop("status_before_superseded", None)
    value.pop("superseded_by", None)
    return value


def walk(left, right, path):
    if isinstance(left, dict) and isinstance(right, dict):
        for key in sorted(set(left) | set(right)):
            found = walk(left.get(key, MISSING), right.get(key, MISSING), path + "." + key if path else key)
            if found is not None:
                return found
        return None
    if left is MISSING or right is MISSING:
        return path
    return None if canonical(left) == canonical(right) else path


def same_answer(left, right):
    return left["answer"]["verbatim"].encode("utf-8") == right["answer"]["verbatim"].encode("utf-8")


def outcome_difference(stored, incoming):
    """Compare all but the outcome strictly; each incoming outcome list must start the stored one."""
    left, right = dict(stored), dict(incoming)
    left_outcome, right_outcome = left.pop("outcome", {}), right.pop("outcome", {})
    found = walk(left, right, "")
    if found is not None:
        return found
    for field in OUTCOME_FIELDS:
        wanted = right_outcome.get(field, [])
        if canonical(left_outcome.get(field, [])[:len(wanted)]) != canonical(wanted):
            return "outcome." + field
    return None


def undo_supersession(record):
    """The record as it was before supersede changed it: exactly the inverse of mark_superseded."""
    value = copy.deepcopy(record)
    if value["status"] == "superseded":
        value["status"] = value.pop("status_before_superseded", None)
        value.pop("superseded_by", None)
    return value


def weaker_difference(stored, incoming):
    """The earlier comparison: answer bytes first, then both records as first written. comparable() is applied
    to both sides, so an explicit null superseded_by or status_before_superseded on either side is the same as
    an absent one, and each incoming outcome list only has to start the stored one, because annotate may have
    grown it."""
    if not same_answer(stored, incoming):
        return "answer.verbatim"
    return outcome_difference(comparable(stored), comparable(incoming))


def named_difference(stored, incoming, first_written):
    """The field to name when an incoming record's hash differs from the stored record's first-written value."""
    if not same_answer(stored, incoming):
        return "answer.verbatim"
    original = undo_supersession(stored)
    if sha256(canonical(original)) == first_written:
        # Apart from supersession, the stored record is still exactly as it was first written.
        return walk(original, incoming, "") or "record"
    found = weaker_difference(stored, incoming)
    if found is not None:
        return found
    return ("outcome; the record was annotated after it was first written, and a re-run must carry the record "
            "as it was first written")


def check_existing(operation, stored, first_written):
    """Refuse an incoming record that differs from the stored one; True if the weaker comparison was used."""
    incoming = operation["record"]
    if first_written is not None:
        if operation["sha256"] != first_written:
            raise InvalidInput("id {} already exists with different content ({})".format(
                incoming["id"], named_difference(stored, incoming, first_written)))
        # The hash shows that this line is the record as first written. The stored record must still agree with
        # it, answer bytes first, in everything that supersede and annotate do not change: a hash carried by an
        # import is not evidence on its own.
        field = weaker_difference(stored, incoming)
        if field is not None:
            raise InvalidInput(
                "id {} already exists with different content ({}); its stored first-written hash matches this "
                "line, but the stored record does not".format(incoming["id"], field))
        return False
    if stored["status"] == "superseded" and stored.get("status_before_superseded") is None:
        raise InvalidInput(
            "id {} was superseded by an older release that did not record its earlier status, so this line cannot "
            "be compared with it; leave the line out of the batch".format(incoming["id"]))
    field = weaker_difference(stored, incoming)
    if field is not None:
        raise InvalidInput("id {} already exists with different content ({})".format(incoming["id"], field))
    return True


class Plan:
    def __init__(self):
        self.writes = []  # (line, id, "insert" or "update", record, first-written hash or None), in line order
        self.added = 0
        self.superseded = 0
        self.unchanged = 0
        self.weaker = set()


def make_plan(store, operations):
    plan = Plan()
    stored = {}

    def lookup(identifier):
        if identifier not in stored:
            row = store.connection.execute("SELECT * FROM records WHERE id = ?", (identifier,)).fetchone()
            stored[identifier] = None if row is None else store.checked_record(row)
        return stored[identifier]

    # Every line that writes the same id must write the identical record; later copies change nothing.
    chosen = {}
    for operation in operations:
        identifier = operation["record"]["id"]
        first = chosen.get(identifier)
        if first is None:
            chosen[identifier] = operation
        elif operation["sha256"] != first["sha256"]:
            field = (walk(first["record"], operation["record"], "") if same_answer(first["record"], operation["record"])
                     else "answer.verbatim")
            raise InvalidInput("line {}: id {} is also written on line {} with different content ({})".format(
                operation["line"], identifier, first["line"], field))
    distinct = sorted(chosen.values(), key=lambda operation: operation["line"])
    new = []
    for operation in distinct:
        identifier = operation["record"]["id"]
        current = lookup(identifier)
        if current is None:
            new.append(operation)
            continue
        try:
            if check_existing(operation, current, store.first_written(identifier)):
                plan.weaker.add(identifier)
            if operation["op"] == "supersede":
                target = lookup(operation["target"])
                if target is None or target.get("superseded_by") != identifier:
                    raise InvalidInput("id {} already exists but {} is not superseded by it".format(
                        identifier, operation["target"]))
        except InvalidInput as error:
            raise InvalidInput("line {}: {}".format(operation["line"], error)) from None
    # A supersede line may target a stored record or one that another line of the batch writes, in any order.
    pending = {operation["record"]["id"]: operation for operation in new}
    claims = {}
    for operation in new:
        if operation["op"] != "supersede":
            continue
        target = operation["target"]
        prefix = "line {}: ".format(operation["line"])
        if target in claims:
            raise InvalidInput(prefix + "target {} is also superseded on line {}".format(target, claims[target]["line"]))
        claims[target] = operation
        if target in pending:
            continue
        current = lookup(target)
        if current is None:
            raise InvalidInput(prefix + "target {} does not exist".format(target))
        if current["status"] == "superseded":
            raise InvalidInput(prefix + "target {} is already superseded by {}".format(target, current["superseded_by"]))
    # Records that only this batch writes must not supersede each other in a loop.
    settled = set()
    for operation in new:
        path, seen, current = [], set(), operation
        while current is not None and current["op"] == "supersede" and current["record"]["id"] not in settled:
            identifier = current["record"]["id"]
            if identifier in seen:
                loop = sorted(pending[name]["line"] for name in path[path.index(identifier):])
                raise InvalidInput("lines {} supersede each other in a loop".format(", ".join(map(str, loop))))
            path.append(identifier)
            seen.add(identifier)
            current = pending.get(current["target"])
        settled.update(path)
    final = {identifier: copy.deepcopy(operation["record"]) for identifier, operation in pending.items()}
    updates = {}
    for target, operation in claims.items():
        if target in final:
            mark_superseded(final[target], operation["record"]["id"])
        else:
            updates[target] = copy.deepcopy(lookup(target))
            mark_superseded(updates[target], operation["record"]["id"])
    for operation in new:
        identifier = operation["record"]["id"]
        plan.writes.append((operation["line"], identifier, "insert", final[identifier], operation["sha256"]))
        if operation["op"] == "supersede" and operation["target"] in updates:
            plan.writes.append((operation["line"], operation["target"], "update", updates[operation["target"]], None))
    plan.added = sum(1 for operation in new if operation["op"] == "add")
    plan.superseded = len(new) - plan.added
    plan.unchanged = len(operations) - len(new)
    return plan


def count_records(store):
    return store.connection.execute("SELECT count(*) FROM records").fetchone()[0]


def load_file(store, path, dry_run=False):
    operations = read_batch(path)
    connection = store.connection
    if dry_run:
        # Reads only: the transaction is never written to and is always rolled back.
        connection.execute("BEGIN")
        try:
            before = count_records(store)
            plan = make_plan(store, operations)
        finally:
            connection.rollback()
        after = before + plan.added + plan.superseded
    else:
        with connection:
            connection.execute("BEGIN IMMEDIATE")
            before = count_records(store)
            plan = make_plan(store, operations)
            if plan.writes:
                for line, identifier, kind, record, first_written in plan.writes:
                    try:
                        if kind == "insert":
                            store._insert_record(record, first_written)
                        else:
                            store._update_record(record)
                    except sqlite3.IntegrityError as error:
                        raise InvalidInput("line {}: record {} could not be written: {}".format(
                            line, identifier, error)) from None
                store.verify()
            after = count_records(store)
    result = {"added": plan.added, "superseded": plan.superseded, "unchanged": plan.unchanged,
              "records_before": before, "records_after": after,
              "unchanged_by_weaker_comparison": sorted(plan.weaker)}
    if dry_run:
        result["dry_run"] = True
    return result
