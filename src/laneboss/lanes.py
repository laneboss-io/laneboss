"""Lanes as a projection of `lane.*` events, and the payload and life-cycle rules every lane event must follow.

Each lane has a current state, the time of the most recent event of each kind, three landing facts that are never
merged into one (merged, deployed and landed), and what its runs carried: the run number, whether a run is going on,
the runner, model, effort and account of the latest run, its working directory and branch, the reason and exit code
of the latest end, and how many resumes and lost runs there were. An event's time is its occurred_at when the producer
gave one, else the store's recorded_at. The same apply() builds the projection incrementally inside append() and from
scratch in rebuild(), so both give equal output.

Every lane kind has a documented payload (docs/architecture.md, "Lanes"), checked when the event is appended, whoever
appends it: check() looks at the event alone and check_transition() at the event against the lane's projection (a run
ends only while it is going on, a new run starts only when none is, run numbers follow each other). Both raise the
failure they are given and never repeat a value. The events of the loop (`loop.*`) are not lane events and the
projection ignores them; check_loop() holds their documented forms, which are checked at append and nowhere else.
"""

from datetime import datetime
import math
import re

from .errors import Refused

STATES = ("queued", "running", "verifying", "accepted", "merged", "abandoned", "waiting")
TIMES = ("planned", "started", "ended", "timeout", "stuck", "resumed", "lost", "cleaned")
LANDING = ("merged", "deployed", "landed")
REFUSAL_KINDS = ("lane.refusal", "lane.workaround_suspected", "lane.refusal_reviewed")
MAIL_KINDS = ("lane.mailed", "lane.delivered", "lane.returned")
KINDS = tuple("lane." + name for name in TIMES + LANDING + ("state", "gone", "adopted")) + REFUSAL_KINDS + MAIL_KINDS \
    + ("lane.ingested",)
# The loop's own events (docs/architecture.md, "The `lane loop` command"). They are not lane events: the projection
# ignores them, and they are checked at append and nowhere else. `no-room` is T5's reason for a turn that no account had
# room for: the design's payload table gives `loop.skipped` the reasons `backoff` and `refused` and, from T5, `no-room`.
LOOP_KINDS = ("loop.started", "loop.stopped", "loop.turn", "loop.skipped")
SKIP_REASONS = ("backoff", "refused", "no-room")
STATE_OF = {"planned": "queued", "started": "running", "ended": "verifying", "lost": "verifying", "gone": "verifying"}
# The events that close a run: what settles the messages a turn carried.
CLOSING = ("ended", "lost", "gone")
REASONS = ("exit", "timeout", "stopped", "limit", "dropped")
# Why the end of a run sent its messages back: any reason of lane.ended, a loss, a declaration, or a prompt that was cut.
RETURN_REASONS = REASONS + ("lost", "gone", "cut")
CLASSIFICATIONS = ("matched", "unmatched", "timed-out")
HOW = ("start", "resume", "reuse")
FINISHED = ("merged", "abandoned")
CLEAN_ITEMS = ("worktree", "branch", "session", "lane-directory")
KEPT_WHY = ("not-created", "missing", "not-this-lane", "abandoned", "not-merged", "record")
NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
TOKEN = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
ACCOUNT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+\[\]-]{0,127}")
DIGEST = re.compile(r"[0-9a-f]{64}")
# The lane's own name as the event store takes it, and the id of one lane record in the decision store:
# configuration, lane, part (report, events or attachment) and the first 16 hex digits of the source hash.
LANE_LABEL = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
INGESTED_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,31}/[a-z0-9][a-z0-9._-]{0,63}/(?:report|events|attachment)/[0-9a-f]{16}")
MAX_INGESTED = 4096
COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
LAUNCH = re.compile(r"[0-9a-f]{32}")
SESSION = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
# The lane's session identifier (a runner's {session}): a UUID in its usual lower-case form.
SESSION_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/+_-]{0,254}")
PATTERN = re.compile(r"(limit|dropped)_patterns\[[0-9]{1,4}\]")
MAX_RUN = 1000000
MAX_BUDGET_MINUTES = 10080
MAX_QUIET_SECONDS = 604800
# Mail (docs/architecture.md, "Mail (built by T2)"): the numbers are part of the design and the tests pin them.
MAX_SEQUENCE = 999999999
MAX_MESSAGE_BYTES = 262144
MAX_QUEUE = 1000
MAX_TURN_MESSAGES = 64
MAX_TURN_BYTES = 1048576
MAX_IDLE_SECONDS = 604800
SENDER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
MAIL_NAME = re.compile(r"[0-9]{9}-[0-9a-f]{64}")
FORMATS = ("claude-code", "text")
VIA = ("tool-result", "hook", "log")
GUARD_KINDS = ("hook", "permission", "harness")
HOOK_EVENT = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")
HOOK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/ -]{0,127}")
WAYS = ("reworded", "shell-write")
VERDICTS = ("clean", "workaround")
REFUSAL_ID = re.compile(r"rf-[0-9a-f]{24}")
SUSPICION_ID = re.compile(r"ws-[0-9a-f]{24}")
RESOURCE_ID = re.compile(r"rs-[0-9a-f]{24}")
GUARD = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
TOOL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")
CALL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
WITHHELD_PATH = re.compile(r"\(withheld [0-9a-f]{64}\)")
MORE_PATHS = re.compile(r"\([1-9][0-9]{0,8} more\)")
COMMAND_PATH = "(command)"
REASON = re.compile(r"[a-z][a-z-]{0,39}")
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3}(?:[0-9]{3})?)?"
                       r"(?:Z|[+-][0-9]{2}:[0-9]{2})")
EXCERPT_CHARACTERS = 400
NOTE_CHARACTERS = 4000
MAX_PATHS = 1024
# The most resources one lane holds, and the most that the `held` of a lane.state lists (docs/architecture.md,
# "Resources and cost"): a lane that holds that many can still be accepted.
MAX_HELD = 256


class Invalid(Exception):
    """A payload rule failed; the message names the field, never its value."""


def _fail(where, message):
    raise Invalid("{}: {}".format(where, message))


def nullable(check):
    def run(value, where):
        if value is not None:
            check(value, where)
    return run


def integer(minimum, maximum):
    def run(value, where):
        if type(value) is not int or not minimum <= value <= maximum:
            _fail(where, "must be a whole number from {} to {}".format(minimum, maximum))
    return run


def number(minimum, maximum, above=False):
    def run(value, where):
        if type(value) not in (int, float) or not math.isfinite(value) or value > maximum or value < minimum or (
                above and value <= minimum):
            _fail(where, "must be a number {} {} and at most {}".format("above" if above else "from", minimum, maximum))
    return run


def one_of(*options):
    def run(value, where):
        if not isinstance(value, str) or value not in options:
            _fail(where, "must be one of " + ", ".join(options))
    return run


def grammar(pattern, extra=None):
    def run(value, where):
        if not isinstance(value, str) or pattern.fullmatch(value) is None or (extra and not extra(value)):
            _fail(where, "must match " + pattern.pattern)
    return run


def model_name(value, where):
    grammar(MODEL)(value, where)
    if re.search(r"[0-9]", value) is None:
        _fail(where, "must be a full model name that includes its version")


def absolute(value, where):
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 4096 or any(
            ord(character) < 32 or ord(character) == 127 for character in value):
        _fail(where, "must be an absolute path on one line")


def boolean(value, where):
    if not isinstance(value, bool):
        _fail(where, "must be true or false")


def obj(fields):
    def run(value, where):
        if not isinstance(value, dict) or set(value) != set(fields):
            _fail(where, "must be an object with exactly: " + (", ".join(sorted(fields)) or "no field"))
        for key, check in fields.items():
            check(value[key], where + "." + key)
    return run


def array(item, maximum=64):
    def run(value, where):
        if not isinstance(value, list) or len(value) > maximum:
            _fail(where, "must be a list of at most {} items".format(maximum))
        for index, element in enumerate(value):
            item(element, "{}[{}]".format(where, index))
    return run


def touches(value, where):
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value) or \
            value != sorted(set(value)) or any(item not in ("billing", "deploy") for item in value):
        _fail(where, "must be a sorted list of billing and deploy")


# What became of the prompt of a run whose runner takes it on standard input: `written` when every byte went into the
# pipe, else `cut`, with the number of bytes written and the prompt's length. Written is not read.
PROMPT_FATE = obj({"state": one_of("written", "cut"), "bytes": integer(0, 2 ** 62), "length": integer(1, 2 ** 62)})


def timestamp(value, where):
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        _fail(where, "must be a timestamp such as 2026-10-08T09:00:00.000000Z")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        _fail(where, "is not a valid date and time")


def record_path(value, where):
    """A path in a refusal event: absolute, withheld as `(withheld SHA256)` when it looked like a credential, or
    `(N more)` standing for the paths after the first 63 of a longer list."""
    if isinstance(value, str) and (WITHHELD_PATH.fullmatch(value) or MORE_PATHS.fullmatch(value)):
        return
    absolute(value, where)


def line_text(value, where):
    if not isinstance(value, str) or not value or len(value) > 4096 or any(
            ord(character) < 32 or ord(character) == 127 for character in value):
        _fail(where, "must be a text on one line")


UNCOVERED = obj({"run": integer(1, MAX_RUN), "reason": grammar(REASON), "path": nullable(line_text)})
HELD_ITEM = obj({"resource": grammar(RESOURCE_ID), "state": one_of("intent", "acquired")})
# A lane record ingested into the decision store: its id and the SHA-256 of the source it was read from.
INGESTED_ROW = obj({"id": grammar(INGESTED_ID), "sha256": grammar(DIGEST)})


def held_list(value, where):
    """The resources a lane held when it was accepted or merged, each with its state: sorted by resource, no repeats."""
    array(HELD_ITEM, MAX_HELD)(value, where)
    names = [entry["resource"] for entry in value]
    if names != sorted(set(names)):
        _fail(where, "must be sorted by resource, without repeats")


def suspected_path(value, where):
    """A path of a suspicion: a record path, or `(command)` for a reworded command that writes no file."""
    if value != COMMAND_PATH:
        record_path(value, where)


def sorted_list(item, minimum=0, maximum=MAX_PATHS):
    def run(value, where):
        if not isinstance(value, list) or not minimum <= len(value) <= maximum:
            _fail(where, "must be a list of {} to {} items".format(minimum, maximum))
        for index, element in enumerate(value):
            item(element, "{}[{}]".format(where, index))
        if value != sorted(set(value)):
            _fail(where, "must be sorted, without repeats")
    return run


def excerpt(value, where):
    """The start of a text from a record, or, when the credential detector refused it, only its length and hash."""
    obj({"text": nullable(lambda text, place: None), "withheld": boolean, "length": integer(0, 2 ** 62),
         "sha256": grammar(DIGEST)})(value, where)
    text = value["text"]
    if value["withheld"]:
        if text is not None:
            _fail(where + ".text", "is null when the excerpt is withheld")
    elif not isinstance(text, str) or len(text) > EXCERPT_CHARACTERS or len(text) > value["length"]:
        _fail(where + ".text", "must be the start of the text, at most {} characters".format(EXCERPT_CHARACTERS))


def note(value, where):
    obj({"text": lambda text, place: None, "sha256": grammar(DIGEST)})(value, where)
    if not isinstance(value["text"], str) or not value["text"].strip() or len(value["text"]) > NOTE_CHARACTERS:
        _fail(where + ".text", "must be a text of 1 to {} characters".format(NOTE_CHARACTERS))


POSITION = obj({"path": record_path, "line": integer(1, 2 ** 62), "offset": integer(0, 2 ** 62),
                "item": integer(0, 10 ** 6)})


def chosen(value, where):
    obj({"runner": one_of("routing", "supervisor", "previous"), "model": one_of("routing", "supervisor", "previous"),
         "effort": nullable(one_of("routing", "supervisor", "previous")),
         "account": nullable(one_of("supervisor", "default", "previous", "room"))})(value, where)


def clean_item(kept):
    def run(value, where):
        if not isinstance(value, dict) or "item" not in value:
            _fail(where, "must be an object with an item")
        one_of(*CLEAN_ITEMS)(value["item"], where + ".item")
        detail = "name" if value["item"] in ("branch", "session") else "path"
        fields = {"item": one_of(*CLEAN_ITEMS), detail: absolute if detail == "path" else grammar(BRANCH)}
        if kept:
            fields["why"] = one_of(*KEPT_WHY)
        obj(fields)(value, where)
    return run


RUN = integer(1, MAX_RUN)
FILE = obj({"path": absolute, "sha256": grammar(DIGEST)})
SEQUENCE = integer(1, MAX_SEQUENCE)
# The sequences a turn carries (none for an idle turn and for a first run), and the ones an announcement names.
CARRIED = sorted_list(SEQUENCE, 0, MAX_TURN_MESSAGES)
ANNOUNCED = sorted_list(SEQUENCE, 1, MAX_TURN_MESSAGES)
PAYLOADS = {
    "lane.planned": {},
    "lane.state": {"state": one_of(*STATES)},
    "lane.merged": {},
    "lane.deployed": {},
    "lane.landed": {},
    "lane.started": {
        "run": RUN, "how": one_of(*HOW), "launch": grammar(LAUNCH), "runner": grammar(NAME),
        "model": model_name, "effort": nullable(grammar(TOKEN)), "account": nullable(grammar(ACCOUNT)),
        "chosen_by": chosen, "difficulty": nullable(one_of("mechanical", "standard", "hard", "review")),
        "project": nullable(grammar(NAME)), "worktree": absolute, "branch": nullable(grammar(BRANCH)),
        "base": nullable(grammar(COMMIT)), "repository": nullable(absolute),
        "budget_minutes": number(0, MAX_BUDGET_MINUTES, above=True), "quiet_seconds": integer(1, MAX_QUIET_SECONDS),
        "brief": FILE, "log": absolute, "session": obj({"socket": absolute, "name": grammar(SESSION)}),
        "touches": touches, "claims": nullable(absolute),
    },
    # An adopted lane (T5): the payload of a lane.started without run, how and launch, so that it holds everything a
    # turn reads from the previous run. `session_id` is required, `idle_seconds` is added, `difficulty` is null and
    # every given part of `chosen_by` is supervisor.
    "lane.adopted": {
        "runner": grammar(NAME), "model": model_name, "effort": nullable(grammar(TOKEN)),
        "account": nullable(grammar(ACCOUNT)), "chosen_by": chosen,
        "difficulty": nullable(one_of("mechanical", "standard", "hard", "review")),
        "project": nullable(grammar(NAME)), "worktree": absolute, "branch": nullable(grammar(BRANCH)),
        "base": nullable(grammar(COMMIT)), "repository": nullable(absolute),
        "budget_minutes": number(0, MAX_BUDGET_MINUTES, above=True), "quiet_seconds": integer(1, MAX_QUIET_SECONDS),
        "brief": FILE, "log": absolute, "session": obj({"socket": absolute, "name": grammar(SESSION)}),
        "touches": touches, "claims": nullable(absolute),
        "session_id": grammar(SESSION_ID), "idle_seconds": nullable(integer(1, MAX_IDLE_SECONDS)),
    },
    "lane.resumed": {"run": integer(2, MAX_RUN), "after": nullable(one_of(*(REASONS + ("lost",)))),
                     "message": nullable(FILE)},
    "lane.ended": {"run": RUN, "reason": one_of(*REASONS), "exit_code": nullable(integer(0, 255)),
                   "signal": nullable(integer(1, 127)), "duration_seconds": number(0, 10 ** 9),
                   "pattern": nullable(grammar(PATTERN)),
                   "classification": nullable(one_of(*CLASSIFICATIONS)), "survivors": integer(0, 10 ** 6)},
    "lane.timeout": {"run": RUN, "budget_minutes": number(0, MAX_BUDGET_MINUTES, above=True),
                     "elapsed_seconds": number(0, 10 ** 9)},
    "lane.stuck": {"run": RUN, "quiet_seconds": integer(1, MAX_QUIET_SECONDS), "output_bytes": integer(0, 2 ** 62)},
    "lane.lost": {"run": RUN, "survivors": integer(0, 10 ** 6)},
    "lane.gone": {"run": RUN, "launch": grammar(LAUNCH)},
    "lane.cleaned": {"removed": array(clean_item(False)), "kept": array(clean_item(True))},
    "lane.mailed": {"sequence": SEQUENCE, "sender": grammar(SENDER), "sha256": grammar(DIGEST),
                    "bytes": integer(1, MAX_MESSAGE_BYTES)},
    "lane.delivered": {"run": integer(2, MAX_RUN), "sequences": ANNOUNCED},
    "lane.returned": {"run": integer(2, MAX_RUN), "sequences": ANNOUNCED, "reason": one_of(*RETURN_REASONS)},
    "lane.refusal": {
        "run": RUN, "refusal": grammar(REFUSAL_ID), "guard": grammar(GUARD), "kind": nullable(one_of(*GUARD_KINDS)),
        "format": one_of(*FORMATS), "via": one_of(*VIA),
        "hook": nullable(obj({"event": nullable(grammar(HOOK_EVENT)), "name": nullable(grammar(HOOK_NAME))})),
        "tool": nullable(grammar(TOOL)), "at": nullable(timestamp),
        "command": nullable(excerpt), "message": excerpt, "targets": sorted_list(record_path),
        "call": nullable(obj({"id": nullable(grammar(CALL_ID)), "record": nullable(POSITION)})), "record": POSITION,
        "workarounds_checked": boolean,
    },
    "lane.workaround_suspected": {
        "run": RUN, "suspicion": grammar(SUSPICION_ID), "refusal": grammar(REFUSAL_ID),
        "how": sorted_list(one_of(*WAYS), 1, len(WAYS)), "paths": sorted_list(suspected_path, 1),
        "tool": grammar(TOOL), "at": nullable(timestamp), "command": excerpt,
        "call": obj({"id": nullable(grammar(CALL_ID)), "record": POSITION}),
        "similarity": nullable(obj({"containment": number(0, 1), "coverage": number(0, 1)})),
    },
    "lane.refusal_reviewed": {
        "refusal": grammar(REFUSAL_ID), "path": suspected_path, "verdict": one_of(*VERDICTS),
        "suspicions": sorted_list(grammar(SUSPICION_ID), 1, 4096), "note": nullable(note),
    },
    # A lane's records went into the decision store: the receipt that command printed, kept with the lane so that
    # the store's own history says what was ingested and when. Nothing has left the machine.
    "lane.ingested": {
        "lane": grammar(LANE_LABEL), "rows_added": integer(0, MAX_INGESTED),
        "rows_existing": integer(0, MAX_INGESTED), "rows": array(INGESTED_ROW, MAX_INGESTED),
    },
}


# What a process's start time looks like in a record: the clock ticks that Linux gives, or the text that `ps` gives.
PROCESS_START = re.compile(r"[0-9A-Za-z :.-]{1,64}")
DETAIL_CHARACTERS = 200


def skip_detail(value, where):
    """The one line of a refused turn that a skip carries."""
    if not isinstance(value, str) or not value or len(value) > DETAIL_CHARACTERS or any(
            ord(character) < 32 or ord(character) == 127 for character in value):
        _fail(where, "must be one line of 1 to {} characters".format(DETAIL_CHARACTERS))


LOOP_PAYLOADS = {
    "loop.started": {"loop": grammar(LAUNCH), "pid": integer(1, 2 ** 62), "start": grammar(PROCESS_START),
                     "detached": boolean, "unrecorded_end": nullable(grammar(LAUNCH))},
    "loop.stopped": {"loop": grammar(LAUNCH), "reason": one_of("stop", "error"), "turns": integer(0, 2 ** 62),
                     "skips": integer(0, 2 ** 62)},
    "loop.turn": {"loop": grammar(LAUNCH), "kind": one_of("mail", "idle"), "sequences": CARRIED,
                  "run": integer(2, MAX_RUN)},
    "loop.skipped": {"loop": grammar(LAUNCH), "reason": one_of(*SKIP_REASONS), "until": nullable(timestamp),
                     "after": nullable(obj({"run": RUN, "reason": one_of(*RETURN_REASONS)})),
                     "detail": nullable(skip_detail)},
}


def check_loop(kind, lane, payload, failure=Refused):
    """Refuse an event of the loop whose kind, lane or payload breaks its documented form (docs/architecture.md, "The
    `lane loop` command"). The loop's events are checked here, at append, and nowhere else: `state verify` and `state
    rebuild` do not check them, so a store written before the loop was built that holds one in any form still verifies
    and rebuilds, and the loop reads only the events that are in this form."""
    if kind not in LOOP_KINDS:
        raise failure("kind: loop events are " + ", ".join(LOOP_KINDS))
    about_lane = kind in ("loop.turn", "loop.skipped")
    if about_lane and lane is None:
        raise failure("lane: is required for {}".format(kind))
    if not about_lane and lane is not None:
        raise failure("lane: {} is not about a lane, so it has none".format(kind))
    try:
        obj(LOOP_PAYLOADS[kind])(payload, "payload")
        if kind == "loop.turn" and (payload["kind"] == "idle") != (payload["sequences"] == []):
            _fail("payload.sequences", "is empty exactly when payload.kind is idle")
        if kind == "loop.skipped" and (payload["reason"] == "backoff") != (payload["after"] is not None):
            _fail("payload.after", "is given exactly when payload.reason is backoff")
    except Invalid as error:
        raise failure("{} {}".format(kind, error)) from None


def loop_form(event):
    """True when a stored event of a loop kind is in the documented form. The loop trusts no other, whatever the event's
    actor and its protocol version say."""
    try:
        check_loop(event["kind"], event["lane"], event["payload"])
    except Refused:
        return False
    return True


def _consistent(kind, payload):
    """Rules between the fields of one payload."""
    if kind == "lane.started":
        if (payload["how"] == "start") != (payload["run"] == 1):
            _fail("payload.run", "is 1 exactly when payload.how is start")
        if (payload["effort"] is None) != (payload["chosen_by"]["effort"] is None):
            _fail("payload.chosen_by.effort", "is null exactly when payload.effort is null")
        if (payload["account"] is None) != (payload["chosen_by"]["account"] is None):
            _fail("payload.chosen_by.account", "is null exactly when payload.account is null")
        if (payload["repository"] is None) != (payload["branch"] is None):
            _fail("payload.branch", "is null exactly when payload.repository is null")
        if "mail" in payload:
            if "session_id" not in payload:
                _fail("payload.session_id", "is required when payload.mail is there: a turn needs the lane's session "
                                            "identity")
            if payload["how"] != "resume" and payload["mail"]:
                _fail("payload.mail", "must be empty when payload.how is start or reuse: the brief is not mail")
    if kind == "lane.adopted":
        # A person adopted the lane, so every given part of `chosen_by` is supervisor, and a part that is null (its
        # value not given) stays null, matching payload.effort and payload.account (the consistency rule of
        # lane.started). The command states no difficulty: no routing ran for the session it takes over.
        if (payload["effort"] is None) != (payload["chosen_by"]["effort"] is None):
            _fail("payload.chosen_by.effort", "is null exactly when payload.effort is null")
        if (payload["account"] is None) != (payload["chosen_by"]["account"] is None):
            _fail("payload.chosen_by.account", "is null exactly when payload.account is null")
        if (payload["repository"] is None) != (payload["branch"] is None):
            _fail("payload.branch", "is null exactly when payload.repository is null")
        for part in ("runner", "model"):
            if payload["chosen_by"][part] != "supervisor":
                _fail("payload.chosen_by." + part, "is supervisor: a person adopted the lane, no routing chose a run")
        for part in ("effort", "account"):
            if payload["chosen_by"][part] not in (None, "supervisor"):
                _fail("payload.chosen_by." + part, "is null or supervisor: a person adopted the lane")
        if payload["difficulty"] is not None:
            _fail("payload.difficulty", "is null: an adoption states no difficulty")
    if kind == "lane.ended":
        if payload["exit_code"] is not None and payload["signal"] is not None:
            _fail("payload.exit_code", "at most one of exit_code and signal is set (neither when no runner ran)")
        pattern = payload["pattern"]
        if (pattern is not None) != (payload["reason"] in ("limit", "dropped")) or (
                pattern is not None and not pattern.startswith(payload["reason"] + "_")):
            _fail("payload.pattern", "names the matching pattern exactly when the reason is limit or dropped")
        if (pattern is not None) != (payload["classification"] == "matched"):
            _fail("payload.classification", "is matched exactly when a pattern is named")
        if payload["reason"] in ("timeout", "stopped") and payload["classification"] is not None:
            _fail("payload.classification", "is null for a run that was stopped or timed out")
        fate = payload.get("prompt")
        if fate is not None and ((fate["state"] == "written") != (fate["bytes"] == fate["length"])
                                 or fate["bytes"] > fate["length"]):
            _fail("payload.prompt", "is written exactly when every byte was written (bytes equals length), else cut")
    if kind == "lane.refusal":
        if (payload["format"] == "text") != (payload["via"] == "log"):
            _fail("payload.via", "is log exactly for a text record")
        if (payload["via"] == "hook") != (payload["hook"] is not None):
            _fail("payload.hook", "names the hook's event and name exactly when the refusal came through a hook")
        if payload["format"] == "text":
            if (payload["tool"], payload["command"], payload["call"], payload["targets"],
                    payload["workarounds_checked"]) != (None, None, None, [], False):
                _fail("payload.format", "a text record names no tool, command, call or target, so no workaround is "
                                        "checked")
        elif payload["call"] is None:
            _fail("payload.call", "is required for a refusal in a claude-code record")
    if kind == "lane.workaround_suspected" and (payload["similarity"] is None) == ("reworded" in payload["how"]):
        _fail("payload.similarity", "is given exactly when the way includes reworded")
    if kind == "lane.refusal_reviewed" and MORE_PATHS.fullmatch(payload["path"]):
        _fail("payload.path", "a verdict names one path; (N more) stands for paths no event holds")
    if kind == "lane.state" and "not_covered" in payload and (
            payload["state"] not in ("accepted", "merged") or not payload["not_covered"]):
        _fail("payload.not_covered", "lists what was not covered when a lane is accepted or merged regardless")
    if kind == "lane.state" and "held" in payload and (
            payload["state"] not in ("accepted", "merged") or not payload["held"]):
        _fail("payload.held", "lists the resources a lane holds when it is accepted or merged, and is there only "
                              "when it holds some")


def check(kind, lane, payload, failure=Refused):
    """Refuse a lane event whose kind, lane or payload breaks its documented form."""
    if kind not in KINDS:
        raise failure("kind: lane events are " + ", ".join(KINDS))
    if lane is None:
        raise failure("lane: is required for lane events")
    fields = PAYLOADS[kind]
    if kind == "lane.state" and isinstance(payload, dict) and "not_covered" in payload:
        # accepted or merged although runs were not covered: what the supervisor accepted is recorded with it.
        fields = dict(fields, not_covered=array(UNCOVERED, 4096))
    if kind == "lane.state" and isinstance(payload, dict) and "held" in payload:
        # accepted or merged although the lane holds resources: what it held is recorded with the decision.
        fields = dict(fields, held=held_list)
    if kind == "lane.started" and isinstance(payload, dict) and "session_id" in payload:
        # The lane's identifier is there only when its runner's templates use {session}: a lane an earlier version
        # started, or a runner that does not use the placeholder started, has none. A key that is there must be valid.
        fields = dict(fields, session_id=grammar(SESSION_ID))
    if kind == "lane.started" and isinstance(payload, dict):
        # A turn of a turn-based lane carries `mail` and `idle_seconds`, together or not at all; an event written before
        # turns existed has neither and passes unchanged. A key that is there must be valid.
        if "mail" in payload:
            fields = dict(fields, mail=CARRIED, idle_seconds=nullable(integer(1, MAX_IDLE_SECONDS)))
        elif "idle_seconds" in payload:
            raise failure("lane.started payload.idle_seconds: is there only together with payload.mail")
    if kind == "lane.ended" and isinstance(payload, dict) and "prompt" in payload:
        # Only a run whose runner takes its prompt on standard input has it; an earlier version wrote none.
        fields = dict(fields, prompt=PROMPT_FATE)
    try:
        obj(fields)(payload, "payload")
        _consistent(kind, payload)
    except Invalid as error:
        raise failure("{} {}".format(kind, error)) from None


def session_name(lane):
    """tmux turns . into _ in session names, so the launcher does the same."""
    return lane.replace(".", "_")


def check_binding(event, state_real, socket, failure=Refused):
    """A lane.started or lane.resumed event names this configuration's tmux socket, its lane's session and files in
    its lane's own directory, so an event copied from another configuration or lane is refused at append."""
    lane = event["lane"]
    payload = event["payload"]
    directory = "/".join((state_real.rstrip("/"), "lanes", lane))

    def rendered(item, where):
        if item is not None and item["path"] != "/".join((directory, "rendered", item["sha256"] + ".md")):
            raise failure("{}: {} is not this lane's rendered file in this configuration".format(event["kind"], where))

    if event["kind"] in ("lane.started", "lane.adopted"):
        session = payload["session"]
        if session["socket"] != socket or session["name"] != session_name(lane):
            raise failure("{}: payload.session is not this configuration's session for lane {}".format(
                event["kind"], lane))
        if payload["log"] != directory + "/output.log":
            raise failure("{}: payload.log is not this lane's log in this configuration".format(event["kind"]))
        rendered(payload["brief"], "payload.brief")
    if event["kind"] == "lane.resumed":
        rendered(payload["message"], "payload.message")


def empty(lane):
    return {"lane": lane, "state": None, "state_at": None, "times": {name: None for name in TIMES},
            "landing": {name: None for name in LANDING}, "run": 0, "running": False, "runner": None, "model": None,
            "effort": None, "account": None, "worktree": None, "branch": None, "reason": None, "exit_code": None,
            "resumes": 0, "lost": 0, "cleaned": False, "events": 0, "last_seq": None}


REFUSAL_FIELDS = ("recorded", "suspected", "verdicts", "unreviewed")
MAIL_FIELDS = ("turn_based", "idle_seconds", "last", "waiting", "returned", "in_flight", "delivered", "settled")


def current_form(projection):
    """True when a stored projection row has exactly the fields this version writes. `refusals` is there only once
    the lane has a refusal event, so stores written before refusals existed keep their rows; `mail` only once a run
    start of the lane carried `mail`, so stores written before turns existed keep theirs."""
    if not isinstance(projection, dict) or not isinstance(projection.get("times"), dict) or set(
            projection["times"]) != set(TIMES):
        return False
    base = set(empty(None))
    if not base <= set(projection) or set(projection) - base - {"refusals", "mail"}:
        return False
    if "refusals" in projection and not (isinstance(projection["refusals"], dict) and set(
            projection["refusals"]) == set(REFUSAL_FIELDS)):
        return False
    return "mail" not in projection or (isinstance(projection["mail"], dict) and set(
        projection["mail"]) == set(MAIL_FIELDS) and isinstance(projection["mail"]["turn_based"], bool))


def mail_of(projection):
    """The row's `mail` field, or None for a lane that no run start has ever given one."""
    return (projection or {}).get("mail")


def turn_based(projection):
    mail = mail_of(projection)
    return mail is not None and mail["turn_based"]


def settlement(name, payload):
    """What a closing event of a run (`ended`, `lost` or `gone`, by its name without `lane.`) decides for the messages the
    run carried: ("delivered", None) or ("returned", reason). Delivered only by a lane.ended with reason `exit`, exit code
    0 and a prompt written whole; a prompt that was cut, or that is not recorded, is a loss the launcher can see, and such
    an end returns its messages with the reason `cut`. Any other end gives its own reason."""
    if name in ("lost", "gone"):
        return "returned", name
    fate = payload.get("prompt")
    written = isinstance(fate, dict) and fate.get("state") == "written"
    if payload["reason"] == "exit" and payload["exit_code"] == 0:
        return ("delivered", None) if written else ("returned", "cut")
    return "returned", payload["reason"]


def announcement(projection):
    """(kind, payload) of the announcement that is due for the lane's latest run, or None: the row's `settled` names that
    run, has not been announced, and the lane is not running. Whoever appends it copies the values from `settled`."""
    mail = mail_of(projection)
    settled = mail["settled"] if mail is not None else None
    if settled is None or settled["announced"] or projection["running"] or settled["run"] != projection["run"]:
        return None
    body = {"run": settled["run"], "sequences": list(settled["sequences"])}
    if settled["outcome"] == "delivered":
        return "lane.delivered", body
    return "lane.returned", dict(body, reason=settled["reason"])


def refusal_state(projection):
    """The lane's refusals, suspicions, verdicts and unreviewed paths (empty when it has none)."""
    found = (projection or {}).get("refusals")
    return found if found is not None else {"recorded": {}, "suspected": {}, "verdicts": [], "unreviewed": []}


def unreviewed(found):
    """(refusal, path) pairs of suspicions without a verdict for that path, with the suspicions that name them."""
    reviewed = {(suspicion, verdict["path"]) for verdict in found["verdicts"] for suspicion in verdict["suspicions"]}
    open_paths = {}
    for suspicion, item in found["suspected"].items():
        for path in item["paths"]:
            if (suspicion, path) not in reviewed:
                open_paths.setdefault((item["refusal"], path), []).append(suspicion)
    return [{"refusal": refusal, "path": path, "suspicions": sorted(suspicions)}
            for (refusal, path), suspicions in sorted(open_paths.items())]


def recorded_seq(projection, event):
    """The seq of the stored event that already records this refusal or suspicion, or None: the same refusal or
    suspicion found again by another scan is a duplicate, never a second event."""
    found = refusal_state(projection)
    if event["kind"] == "lane.refusal":
        item = found["recorded"].get(event["payload"]["refusal"])
    elif event["kind"] == "lane.workaround_suspected":
        item = found["suspected"].get(event["payload"]["suspicion"])
    else:
        return None
    return item["seq"] if item is not None else None


def check_transition(projection, event, failure=Refused):
    """Refuse a lane event that its lane's current projection does not allow."""
    kind = event["kind"]
    payload = event["payload"]
    lane = event["lane"]
    current = projection or empty(lane)
    running = current["running"]
    if kind in ("lane.started", "lane.resumed"):
        if running:
            raise failure("{}: lane {} is running run {}; a new run starts only after it ends".format(
                kind, lane, current["run"]))
        if payload["run"] != current["run"] + 1:
            raise failure("{}: payload.run must be {}, the run after the lane's last".format(kind, current["run"] + 1))
        if kind == "lane.started" and payload["how"] == "reuse" and current["state"] not in FINISHED:
            raise failure("lane.started: lane {} can be started again only when it is merged or abandoned".format(
                lane))
    if kind == "lane.adopted" and current["events"]:
        # It is the one command that makes a lane whose first run the launcher did not supervise: a lane that already
        # holds an event (the launcher started it, or it was adopted before) has a run 1 already.
        raise failure("lane.adopted: lane {} already has {} event(s); an adoption is only for a lane that has no event "
                      "yet".format(lane, current["events"]))
    if kind in ("lane.ended", "lane.timeout", "lane.stuck", "lane.lost"):
        if not running or payload["run"] != current["run"]:
            raise failure("{}: lane {} has no run {} going on".format(kind, lane, payload["run"]))
    if kind == "lane.cleaned" and (running or current["state"] not in FINISHED):
        raise failure("lane.cleaned: lane {} must be merged or abandoned and not running".format(lane))
    if kind == "lane.gone" and payload["run"] != current["run"]:
        raise failure("lane.gone: lane {}'s latest run is run {}".format(lane, current["run"]))
    if kind in MAIL_KINDS or kind in ("lane.state", "lane.started", "lane.resumed"):
        check_mail(current, event, failure)
    if kind in REFUSAL_KINDS:
        check_refusal(current, event, failure)


def check_mail(current, event, failure):
    """The rules of turns and mail at append (docs/architecture.md, "Mail events, the new lane state and the
    projection"): a message is mailed to a turn-based lane in sequence, a turn carries the head of the queue, an
    abandoned lane starts no turn, a new life is never sent the mail of the old one, an announcement is due once and
    says what the row's `settled` says, and the state `waiting` is set only by the end of a run."""
    kind, payload, lane = event["kind"], event["payload"], event["lane"]
    mail = mail_of(current)
    based = mail is not None and mail["turn_based"]
    if kind == "lane.mailed":
        if not based:
            raise failure("lane.mailed: lane {} is not turn-based (a lane takes turns when it is started with lane "
                          "start --turns or when it is adopted)".format(lane))
        if current["cleaned"]:
            raise failure("lane.mailed: lane {} was cleaned".format(lane))
        if current["state"] == "abandoned":
            raise failure("lane.mailed: lane {} is abandoned".format(lane))
        if payload["sequence"] != mail["last"] + 1:
            raise failure("lane.mailed: payload.sequence must be {}, the one after the lane's last".format(
                mail["last"] + 1))
        if len(mail["waiting"]) + len(mail["returned"]) >= MAX_QUEUE:
            raise failure("lane.mailed: lane {} already has {} messages that wait or have returned, the most it "
                          "holds".format(lane, MAX_QUEUE))
    if kind in ("lane.resumed", "lane.started") and based and current["state"] == "abandoned" and (
            kind == "lane.resumed" or payload["how"] == "resume"):
        # An abandonment that is recorded while a turn is starting stands: the turn does not start.
        raise failure("{}: lane {} is abandoned, so no turn starts; its messages stay waiting".format(kind, lane))
    if kind == "lane.started":
        if payload["how"] == "reuse" and mail is not None and (mail["waiting"] or mail["returned"]):
            raise failure("lane.started: lane {} has messages that wait or have returned; a new life of the lane is "
                          "never sent mail that was written for the old one".format(lane))
        if "mail" in payload and payload["how"] == "resume":
            if not based:
                raise failure("lane.started: a turn resumes a turn-based lane, and lane {} is not one".format(lane))
            queue = mail["returned"] + mail["waiting"]
            if payload["mail"] != queue[:len(payload["mail"])]:
                raise failure("lane.started: payload.mail must be the head of the queue, the returned messages and "
                              "then the waiting ones, in order")
        elif "mail" not in payload and payload["how"] == "resume" and based:
            raise failure("lane.started: lane {} is turn-based, so a resume carries payload.mail (a turn is started "
                          "with lane turn; lane resume is refused for it)".format(lane))
    if kind in ("lane.delivered", "lane.returned"):
        check_announcement(current, mail, event, failure)
    if kind == "lane.state":
        if payload["state"] == "waiting":
            raise failure("lane.state: waiting is the state of a turn-based lane between turns, and is never set by "
                          "lane.state; the end of a run sets it")
        if based and payload["state"] != "abandoned":
            raise failure("lane.state: lane {} is turn-based, so only abandoned can be recorded, not {}".format(
                lane, payload["state"]))


def check_announcement(current, mail, event, failure):
    """lane.delivered and lane.returned: due once, for the lane's latest run, with the values of the row's `settled`."""
    kind, payload, lane = event["kind"], event["payload"], event["lane"]
    if current["running"]:
        raise failure("{}: lane {} is running run {}, so no announcement is due".format(kind, lane, current["run"]))
    settled = mail["settled"] if mail is not None else None
    if settled is None:
        raise failure("{}: lane {} has no settled messages to announce".format(kind, lane))
    if settled["run"] != current["run"]:
        raise failure("{}: the settled messages are those of run {}, which is no longer the lane's latest run ({}); "
                      "they can no longer be announced".format(kind, settled["run"], current["run"]))
    if settled["announced"]:
        raise failure("{}: the messages of run {} are already announced".format(kind, settled["run"]))
    wanted = "delivered" if kind == "lane.delivered" else "returned"
    if settled["outcome"] != wanted:
        raise failure("{}: the messages of run {} were settled as {}, not {}".format(
            kind, settled["run"], settled["outcome"], wanted))
    if payload["run"] != settled["run"] or payload["sequences"] != settled["sequences"]:
        raise failure("{}: payload.run and payload.sequences must be those of the settled messages (run {})".format(
            kind, settled["run"]))
    if kind == "lane.returned" and payload["reason"] != settled["reason"]:
        raise failure("lane.returned: payload.reason must be {}, the reason the messages were settled with".format(
            settled["reason"]))


def check_refusal(current, event, failure):
    """A refusal belongs to a run that has started; a suspicion to a recorded refusal of its run or an earlier one;
    a verdict to suspicions of that refusal that name its path. Each refusal and suspicion is recorded once."""
    kind, payload, lane = event["kind"], event["payload"], event["lane"]
    found = refusal_state(current)
    if kind in ("lane.refusal", "lane.workaround_suspected") and not 1 <= payload["run"] <= current["run"]:
        raise failure("{}: lane {} has no run {}".format(kind, lane, payload["run"]))
    if kind == "lane.refusal" and payload["refusal"] in found["recorded"]:
        raise failure("lane.refusal: refusal {} of lane {} is recorded already".format(payload["refusal"], lane))
    if kind in ("lane.workaround_suspected", "lane.refusal_reviewed") and payload["refusal"] not in found["recorded"]:
        raise failure("{}: lane {} has no recorded refusal {}".format(kind, lane, payload["refusal"]))
    if kind == "lane.workaround_suspected":
        if payload["suspicion"] in found["suspected"]:
            raise failure("lane.workaround_suspected: suspicion {} of lane {} is recorded already".format(
                payload["suspicion"], lane))
        if payload["run"] < found["recorded"][payload["refusal"]]["run"]:
            raise failure("lane.workaround_suspected: a suspected workaround comes after its refusal, in its run or a "
                          "later one")
    if kind == "lane.refusal_reviewed":
        for suspicion in payload["suspicions"]:
            item = found["suspected"].get(suspicion)
            if item is None or item["refusal"] != payload["refusal"] or payload["path"] not in item["paths"]:
                raise failure("lane.refusal_reviewed: suspicion {} is not a recorded suspicion of refusal {} that names "
                              "the reviewed path".format(suspicion, payload["refusal"]))


def apply_refusal(projection, event):
    found = refusal_state(projection)
    payload = event["payload"]
    if event["kind"] == "lane.refusal":
        found["recorded"][payload["refusal"]] = {"run": payload["run"], "seq": event["seq"], "guard": payload["guard"],
                                                 "tool": payload["tool"]}
    elif event["kind"] == "lane.workaround_suspected":
        found["suspected"][payload["suspicion"]] = {"refusal": payload["refusal"], "run": payload["run"],
                                                    "seq": event["seq"], "how": payload["how"],
                                                    "paths": payload["paths"]}
    else:
        found["verdicts"].append({"refusal": payload["refusal"], "path": payload["path"], "verdict": payload["verdict"],
                                  "suspicions": payload["suspicions"], "seq": event["seq"]})
    found["unreviewed"] = unreviewed(found)
    projection["refusals"] = found


def apply(projection, event):
    at = event["occurred_at"] or event["recorded_at"]
    name = event["kind"][len("lane."):]
    payload = event["payload"]
    if name in TIMES:
        projection["times"][name] = at
    if name in LANDING:
        projection["landing"][name] = at
    state = payload["state"] if name == "state" else STATE_OF.get(name)
    if name == "adopted":
        # A run the launcher never supervised is already over when the lane is adopted, so the lane waits for its
        # first turn: waiting is the state of a turn-based lane between turns.
        state = "waiting"
    mail = projection.get("mail")
    if name in CLOSING and mail is not None:
        # The end of a run of a turn-based lane leaves it waiting for the next turn, and a row that has mail and is
        # abandoned stays abandoned (a lane.gone after an abandonment must not undo it).
        state = None if projection["state"] == "abandoned" else "waiting" if mail["turn_based"] else state
    if state is not None:
        projection["state"] = state
        projection["state_at"] = at
    if name == "started":
        projection.update(run=payload["run"], running=True, reason=None, exit_code=None, cleaned=False,
                          **{key: payload[key] for key in ("runner", "model", "effort", "account", "worktree",
                                                           "branch")})
        if "mail" in payload:
            start_turn(projection, payload)
        elif mail is not None:
            mail["turn_based"] = False
    if name == "adopted":
        # `run` 1 is a number and not a run: it had no supervising process, so no entry of `times` is set. The lane is
        # turn-based from the adoption, with no message in flight, and waits for its first turn (run 2).
        projection.update(run=1, running=False, reason=None, exit_code=None, cleaned=False,
                          **{key: payload[key] for key in ("runner", "model", "effort", "account", "worktree",
                                                           "branch")})
        projection["mail"] = {"turn_based": True, "idle_seconds": payload["idle_seconds"], "last": 0, "waiting": [],
                              "returned": [], "in_flight": None, "delivered": 0, "settled": None}
    if name == "resumed":
        projection["resumes"] += 1
    if name == "ended":
        projection.update(running=False, reason=payload["reason"], exit_code=payload["exit_code"])
    if name == "lost":
        projection.update(running=False, reason="lost", exit_code=None, lost=projection["lost"] + 1)
    if name == "gone":
        projection["running"] = False
    if name == "cleaned":
        projection["cleaned"] = True
    if name == "mailed":
        mail = projection["mail"]
        mail["last"] = payload["sequence"]
        mail["waiting"].append(payload["sequence"])
    if name in CLOSING and mail is not None:
        settle(mail, name, payload)
    if name in ("delivered", "returned"):
        projection["mail"]["settled"]["announced"] = True
    if event["kind"] in REFUSAL_KINDS:
        apply_refusal(projection, event)
    projection["events"] += 1
    projection["last_seq"] = event["seq"]
    return projection


def start_turn(projection, payload):
    """A run start that carries `mail`: the lane is turn-based from now on, the messages it carries leave the queue and
    are in flight until the run ends. A row without `mail` gets the field here, at its starting values."""
    mail = projection.get("mail")
    if mail is None:
        mail = projection["mail"] = {"turn_based": False, "idle_seconds": None, "last": 0, "waiting": [],
                                     "returned": [], "in_flight": None, "delivered": 0, "settled": None}
    carried = payload["mail"]
    mail["turn_based"] = True
    mail["idle_seconds"] = payload["idle_seconds"]
    mail["waiting"] = [number for number in mail["waiting"] if number not in carried]
    mail["returned"] = [number for number in mail["returned"] if number not in carried]
    mail["in_flight"] = {"run": payload["run"], "sequences": list(carried)} if carried else None


def settle(mail, name, payload):
    """The closing event of the run whose messages are in flight settles them (docs/architecture.md, "The derivation",
    step 3): delivered, or back in the queue in sequence order. A closing event with nothing in flight (a run that carried
    no mail, or a second closing event of a run that is already closed) settles nothing."""
    flight = mail["in_flight"]
    if flight is None or flight["run"] != payload["run"]:
        return
    outcome, reason = settlement(name, payload)
    mail["in_flight"] = None
    if outcome == "delivered":
        mail["delivered"] += len(flight["sequences"])
    else:
        mail["returned"] = sorted(set(mail["returned"]) | set(flight["sequences"]))
    mail["settled"] = {"run": flight["run"], "outcome": outcome, "reason": reason,
                       "sequences": list(flight["sequences"]), "announced": False}


def is_lane_event(event):
    return event["kind"].startswith("lane.")


def fold(events, failure=None):
    """The projection of every lane, sorted by lane. With a failure, every event is checked against its lane as
    append() checks it, so a stored sequence that append() would have refused is reported."""
    projections = {}
    for event in events:
        if is_lane_event(event):
            current = projections.get(event["lane"])
            if failure is not None:
                try:
                    check_transition(current, event, failure)
                except failure as error:
                    raise failure("event seq {}: {}".format(event["seq"], error)) from None
            apply(projections.setdefault(event["lane"], empty(event["lane"])), event)
    return [projections[lane] for lane in sorted(projections)]
