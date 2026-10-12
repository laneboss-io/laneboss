"""The launcher's side of the adapter contract: the request of each operation, the call, and the reading of the answer.

An adapter is an external command that a configuration names ([resources.NAME], "Configuration"). The launcher runs it
once for each operation it needs, writes one JSON object to its standard input and reads one JSON object from its
standard output. This module builds that object for the contract's three operations — an acquire, whose boolean member
`dry_run` tells the quote from the acquire, a describe and a release — and turns it into the text the launcher writes,
runs the adapter (call) and reads what it answered (read_answer).

The request is one object in ASCII-safe JSON, on one line, with a final newline and the members in the order of the
table of docs/architecture.md ("The adapter contract", "The request"). Every member the table lists for the operation is
present, in that order, and no other member is sent: no text of a brief or of a lane's work, no other lane's name, no
path and no credential. Each builder takes its members by keyword only, in the table's order, and refuses a value
outside its bound with ValueError, naming the member and never the value; a whole-number bound takes a whole number and
not a boolean. text_for refuses a request that would pass MAX_REQUEST_BYTES: that is the number an adapter may rely on
for how much it must be ready to read, and a request that would pass it is refused before anything is run.

call() resolves the program as doctor does (a name is found on the launcher's own PATH, and the path found is made
absolute), gives the adapter an environment of exactly two things (PATH, fixed, and the variable that the configuration
names, with the value it has in the launcher's environment) and runs it with judges.run_command(), shared and unchanged:
no shell, a session and a process group of its own, the request on standard input, and an end of the whole group at the
operation's time-out. Its result carries one of the four reasons of a judge when there is no answer (timeout, exit,
output, not-found), worded by judges.describe(), and never an answer that was not given.

read_answer() reads standard output strictly ("The adapter contract", "The answer" and "What is no answer"): one JSON
object, and nothing else but white space around it; every member listed for the operation and the state that it reports,
and no other but `request`; each member inside its grammar or bound; a number only as an int; the three price members
null together or set together; and, in a describe, the provider id of the request. There is no default for a member that
is required: whatever is not exactly an answer is no answer, and nothing of it is read or shown.

The credential variable's value is searched for, from MIN_SECRET_CHARACTERS characters, in every string member of an
answer and in the line of standard error that is shown, beside the credential detector's shapes (judges.explanation()
for the line); what holds it is no answer, or is replaced by "[withheld]". Nothing here writes an event or a file.
"""

import json
import os
import re

from . import credentials, events
from .doctor import find_command
from .errors import Refused
from .identity import ENV_PREFIX
from .judges import ANSWERED, STDOUT_LIMIT, WITHHELD, describe, explanation, run_command

REQUEST_VERSION = 1
MAX_REQUEST_BYTES = 16 * 1024
# The contract's own words: the operations a request may name, and the kinds of resource an adapter may serve.
OPERATIONS = ("acquire", "describe", "release")
KINDS = ("machine", "credential")
# The member grammars of the table ("The adapter contract", "The request"). Each is matched whole, so a bound like
# {0,63} is the whole length of the member.
ID = re.compile(r"rs-[0-9a-f]{24}")
LANE = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
PROFILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
PURPOSE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}")
SIZE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,63}")
REGION = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
PROVIDER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,191}")
MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS = 1, 900
MIN_HARD_CAP_MINUTES, MAX_HARD_CAP_MINUTES = 1, 10080
# The environment of the call ("The environment"): the one fixed PATH, and a variable named by the configuration, whose
# name has the grammar of the key `credential_env` and is neither PATH nor one of the launcher's own LANEBOSS_
# variables.
FIXED_PATH = "/usr/local/bin:/usr/bin:/bin"
CREDENTIAL_ENV = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
# The shortest value of the credential variable that is searched for, in an answer and on standard error: a shorter one
# would match common text and make every answer no answer (docs/architecture.md, "Open points", 18).
MIN_SECRET_CHARACTERS = 8
# The member grammars of the table of the answer ("The adapter contract", "The answer"), besides those of the request
# (`provider_id`, `size` and `region` have the same grammar in an answer as in a request).
PROVIDER_STATE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
REASON = re.compile(r"[a-z][a-z-]{0,39}")
CURRENCY = re.compile(r"[A-Z]{3}")
REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
PRICE_SOURCES = ("adapter", "configured")
# A price is a whole number of micro-units an hour, up to 1,000 units: so that a cost cannot pass the bound of
# `amount_micros` in a thousand years.
MAX_PRICE_MICROS = 1000000000
PRICE_MEMBERS = ("price_per_hour_micros", "currency", "price_source")
# What each operation may answer ("The answer"): for each, the states and the members each requires besides `state`.
# An acquire has two forms, told apart by `dry_run`: the quote and the acquire. `request`, which any answer may carry,
# is not in the table.
ANSWERS = {
    ("acquire", True): {"quoted": ("size", "region", "price_per_hour_micros", "currency", "price_source"),
                        "failed": ("reason",)},
    ("acquire", False): {"acquired": ("provider_id", "started_at"), "failed": ("reason",)},
    ("describe", None): {"running": ("provider_id", "provider_state", "started_at"),
                         "terminated": ("provider_id", "provider_state", "started_at", "ended_at"),
                         "absent": ()},
    ("release", None): {"releasing": ()},
}


def _refuse(member, why):
    raise ValueError("{}: {}".format(member, why))


def _grammar(member, value, pattern):
    """A string that matches the member's grammar whole."""
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        _refuse(member, "not a string of the form {}".format(pattern.pattern))
    return value


def _nullable(member, value, pattern):
    """The member's grammar, or the null the table allows where it allows one."""
    if value is None:
        return None
    return _grammar(member, value, pattern)


def _whole(member, value, smallest, largest):
    """A whole number inside its bound. A boolean is not one: `true` would be read as 1, and a bound is a number of
    seconds or of minutes."""
    if isinstance(value, bool) or not isinstance(value, int) or not smallest <= value <= largest:
        _refuse(member, "not a whole number from {} to {}".format(smallest, largest))
    return value


def _one_of(member, value, words):
    """One of the contract's own words."""
    if value not in words:
        _refuse(member, "not one of {}".format(", ".join(words)))
    return value


def _operation(value):
    """The `operation` member: one of the contract's three operations."""
    return _one_of("operation", value, OPERATIONS)


def _dry_run(value):
    """The `dry_run` member: true or false."""
    if not isinstance(value, bool):
        _refuse("dry_run", "not true or false")
    return value


def _acquire(*, operation, dry_run, resource, lane, kind, profile, purpose, size, region, hard_cap_minutes,
             timeout_seconds):
    """The acquire object: the members of the table's acquire row, in the table's order."""
    return {"laneboss_resource": REQUEST_VERSION, "operation": _operation(operation),
            "id": _grammar("id", resource, ID), "lane": _grammar("lane", lane, LANE),
            "kind": _one_of("kind", kind, KINDS), "profile": _nullable("profile", profile, PROFILE),
            "purpose": _grammar("purpose", purpose, PURPOSE), "size": _nullable("size", size, SIZE),
            "region": _nullable("region", region, REGION),
            "hard_cap_minutes": _whole("hard_cap_minutes", hard_cap_minutes, MIN_HARD_CAP_MINUTES,
                                       MAX_HARD_CAP_MINUTES),
            "dry_run": _dry_run(dry_run),
            "timeout_seconds": _whole("timeout_seconds", timeout_seconds, MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS)}


def _read(*, operation, resource, kind, profile, region, provider_id, timeout_seconds):
    """A describe or a release object: the members those two share, in the table's order."""
    return {"laneboss_resource": REQUEST_VERSION, "operation": _operation(operation),
            "id": _grammar("id", resource, ID), "kind": _one_of("kind", kind, KINDS),
            "profile": _nullable("profile", profile, PROFILE), "region": _nullable("region", region, REGION),
            "provider_id": _nullable("provider_id", provider_id, PROVIDER_ID),
            "timeout_seconds": _whole("timeout_seconds", timeout_seconds, MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS)}


def quote_request(*, resource, lane, kind, profile, purpose, size, hard_cap_minutes, timeout_seconds):
    """The acquire request with dry_run true: what the adapter would create and what that costs. A quote names no
    region, because the adapter answers with the one it would create in; `size` is what the caller asked for, or null."""
    return _acquire(operation="acquire", dry_run=True, resource=resource, lane=lane, kind=kind, profile=profile,
                    purpose=purpose, size=size, region=None, hard_cap_minutes=hard_cap_minutes,
                    timeout_seconds=timeout_seconds)


def acquire_request(*, resource, lane, kind, profile, purpose, size, region, hard_cap_minutes, timeout_seconds):
    """The acquire request with dry_run false: `size` and `region` are exactly what the quote answered and what the
    intent records, so that the adapter creates what was recorded."""
    return _acquire(operation="acquire", dry_run=False, resource=resource, lane=lane, kind=kind, profile=profile,
                    purpose=purpose, size=size, region=region, hard_cap_minutes=hard_cap_minutes,
                    timeout_seconds=timeout_seconds)


def describe_request(*, resource, kind, profile, region, provider_id, timeout_seconds):
    """The describe request: what the adapter shows for the resource. `provider_id` is the one of the resource's acquired
    event, or None while the resource has none, and `region` is the intent's."""
    return _read(operation="describe", resource=resource, kind=kind, profile=profile, region=region,
                 provider_id=provider_id, timeout_seconds=timeout_seconds)


def release_request(*, resource, kind, profile, region, provider_id, timeout_seconds):
    """The release request: asks the adapter to end the resource."""
    return _read(operation="release", resource=resource, kind=kind, profile=profile, region=region,
                 provider_id=provider_id, timeout_seconds=timeout_seconds)


def text_for(request):
    """The request as the text the launcher writes: ASCII-safe JSON (a character outside ASCII is escaped), one line, no
    space after a separator, and exactly one final newline. A request that would pass MAX_REQUEST_BYTES is refused
    before anything is run."""
    text = json.dumps(request, ensure_ascii=True, separators=(",", ":"), allow_nan=False) + "\n"
    if len(text.encode("ascii")) > MAX_REQUEST_BYTES:
        raise ValueError("a request must not pass MAX_REQUEST_BYTES ({} bytes)".format(MAX_REQUEST_BYTES))
    return text


class Result:
    """What one call to an adapter came to. `reason` is `answered`, or one of the four reasons of a judge for no answer
    (`timeout`, `exit`, `output`, `not-found`); `answer` is the members of the answer when it was answered, and None
    otherwise; `detail` is the words for the command's own message: empty when answered, else the words of
    judges.describe() and, after a colon, the first line of standard error, screened. The command that made the call
    shows it; it is never written to an event or to a file."""

    def __init__(self, reason, answer, detail):
        self.reason = reason
        self.answer = answer
        self.detail = detail


def _unique(pairs):
    """The members of an object, refused when one is repeated, even with the same value."""
    members = {}
    for name, value in pairs:
        if name in members:
            raise ValueError("a member is repeated")
        members[name] = value
    return members


def _no_fraction(text):
    raise ValueError("a number with a fraction or an exponent")


def _no_constant(text):
    raise ValueError("not a finite number")


def _text(pattern):
    """A check for a string that matches the pattern whole."""
    return lambda value: isinstance(value, str) and pattern.fullmatch(value) is not None


def _or_null(check):
    """The same check, or the null that the table allows."""
    return lambda value: value is None or check(value)


def _timestamp(value):
    """A timestamp in the grammar of the envelope's `occurred_at`, which also has to be a date and a time that exist."""
    try:
        events.check_timestamp(value, "timestamp")
    except Refused:
        return False
    return True


def _price(value):
    """A whole number of micro-units from 0 to MAX_PRICE_MICROS: an int, never a boolean or a float."""
    return type(value) is int and 0 <= value <= MAX_PRICE_MICROS


def _price_source(value):
    return isinstance(value, str) and value in PRICE_SOURCES


# The check of each member of an answer other than `state` ("The answer"): its type and its bound.
ANSWER_MEMBERS = {
    "provider_id": _text(PROVIDER_ID), "provider_state": _text(PROVIDER_STATE),
    "started_at": _or_null(_timestamp), "ended_at": _or_null(_timestamp),
    "size": _or_null(_text(SIZE)), "region": _or_null(_text(REGION)),
    "price_per_hour_micros": _or_null(_price), "currency": _or_null(_text(CURRENCY)),
    "price_source": _or_null(_price_source), "reason": _text(REASON), "request": _or_null(_text(REQUEST_ID)),
}


def _holds(text, secret):
    """True when the text looks like a credential to the detector, or holds the value of the credential variable (which
    is searched for from MIN_SECRET_CHARACTERS characters)."""
    if credentials.find_in_text(text) is not None:
        return True
    return secret is not None and len(secret) >= MIN_SECRET_CHARACTERS and secret in text


def read_answer(data, operation, dry_run, provider_id, secret):
    """The members of the answer that these bytes hold, as a dict, or None when they are no answer ("What is no
    answer"): not exactly one JSON object (white space around it is allowed, nothing else, no second object, UTF-8 and
    at most STDOUT_LIMIT bytes); a member repeated, one that the operation and the state do not list, or a listed one
    that is absent (there is no default for a required member); a member of the wrong type or outside its grammar or
    bound, a number with a fraction or an exponent anywhere; a state that the operation does not allow; three price
    members of which some are null; in a describe, a provider id other than the request's when the request has one; a
    string member that the credential detector refuses or that holds the value of the credential variable. Nothing of
    such an answer is read.

    `operation` and `dry_run` (the acquire's, which tells the quote from the acquire) say which table applies,
    `provider_id` is the request's own (None when it has none), and `secret` is the value of the credential variable
    (None when none is named). `request`, which any answer may carry, is None in the result when it was absent.
    ValueError for an operation that is not one of the contract's, or an acquire whose `dry_run` is not a boolean:
    that is a fault of the caller and not of the adapter."""
    _operation(operation)
    states = ANSWERS[(operation, _dry_run(dry_run) if operation == "acquire" else None)]
    if len(data) > STDOUT_LIMIT:
        return None
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique, parse_float=_no_fraction,
                           parse_constant=_no_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if type(value) is not dict:
        return None
    state = value.get("state")
    if not isinstance(state, str) or state not in states:
        return None
    if set(value) - {"request"} != set(states[state]) | {"state"}:
        return None
    for member, item in value.items():
        if member != "state" and not ANSWER_MEMBERS[member](item):
            return None
    if state == "quoted" and len({value[member] is None for member in PRICE_MEMBERS}) > 1:
        return None
    if operation == "describe" and provider_id is not None and value.get("provider_id", provider_id) != provider_id:
        return None
    if any(isinstance(item, str) and _holds(item, secret) for item in value.values()):
        return None
    answer = dict(value)
    answer.setdefault("request", None)
    return answer


def stderr_line(raw, secret):
    """The first non-empty line that an adapter wrote on standard error, as it may be shown: judges.explanation(),
    shared unchanged (cut to 300 characters, control characters replaced by `?`, "[withheld]" for a credential shape
    in the line as written or as cut), and one screen more: the line as it was written, and the text that would be
    shown, are each searched for the value of the credential variable (from MIN_SECRET_CHARACTERS characters), and
    either one that holds it is replaced by "[withheld]". The raw line is searched too because a value that begins
    before the 300th character and ends after it would otherwise show its beginning."""
    shown = explanation(raw)
    if secret is not None and len(secret) >= MIN_SECRET_CHARACTERS:
        line = next((line for line in raw.decode("utf-8", "replace").splitlines() if line.strip()), "")
        if secret in line or secret in shown:
            return WITHHELD
    return shown


def environment(credential_env=None, secret=None):
    """The adapter's whole environment: `PATH`, set to FIXED_PATH, and the variable that the configuration names, with
    the value it has in the launcher's environment. Nothing else: no LANEBOSS_ variable, no HOME, nothing that the
    launcher's own environment holds (an ambient default profile, a key that a session happens to hold)."""
    variables = {"PATH": FIXED_PATH}
    if credential_env is not None:
        variables[credential_env] = secret
    return variables


def resolve(program):
    """The absolute path of the program that `command[0]` names, by the rule that `doctor` uses: an absolute path to
    an executable file, or a name found on the launcher's own PATH; None when there is none. shutil.which() returns a
    relative path for a relative PATH entry, so the path found is made absolute. Without this resolution a bare name
    would be looked up on the PATH of the environment given to the new process, which is the fixed one."""
    found = find_command(program)
    return None if found is None else os.path.abspath(found)


def call(command, request, seconds, credential_env=None):
    """Run the adapter that `command` names with `request` (one of the four objects the builders make) on its standard
    input, and read what it answers: a Result. It is no answer, with one of the reasons of a judge and never an
    invented answer, for a program that is not found or cannot be started (`not-found`, and nothing is sent), no end
    within `seconds` (`timeout`: the adapter's whole process group is ended), a non-zero exit status or an end by a
    signal even when a valid object was printed (`exit`), and standard output that is not exactly an answer
    (`output`).

    `seconds` is the operation's time-out and has to be the request's own `timeout_seconds`: the deadline that the
    launcher keeps is the one that the adapter was told. `credential_env` is the NAME of the variable that the
    configuration names, or None: the adapter is given that variable with the value it has in the launcher's
    environment, and nothing else but PATH. ValueError for an argument that is not valid, and for a request that would
    pass MAX_REQUEST_BYTES; Refused when the variable is named and is unset or empty in the launcher's environment: the
    adapter is not called at all. The command that calls an adapter refuses the same before it calls
    (`resourcecmd.py`); this is the same rule at the last place that can still avoid a call, and its message never
    repeats the name or a value."""
    if (not isinstance(command, (list, tuple)) or not command
            or not all(isinstance(element, str) for element in command)):
        _refuse("command", "not a list of strings with a program first")
    if not isinstance(request, dict):
        _refuse("request", "not a request object")
    operation = _operation(request.get("operation"))
    dry_run = _dry_run(request.get("dry_run")) if operation == "acquire" else None
    _whole("seconds", seconds, MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS)
    if seconds != request.get("timeout_seconds"):
        _refuse("seconds", "not the request's timeout_seconds: the deadline kept is the one the adapter is told")
    secret = None
    if credential_env is not None:
        if (not isinstance(credential_env, str) or CREDENTIAL_ENV.fullmatch(credential_env) is None
                or credential_env == "PATH" or credential_env.startswith(ENV_PREFIX)):
            _refuse("credential_env", "not the name of a variable that an adapter may be given")
        secret = os.environ.get(credential_env)
        if not secret:
            raise Refused("the variable that credential_env names is not set, or is empty, in the launcher's "
                          "environment: the adapter was not called")
    data = text_for(request).encode("ascii")
    program = resolve(command[0])
    if program is None:
        return Result("not-found", None, describe("not-found", None, seconds))
    reason, status, out, err = run_command([program] + list(command[1:]), data, seconds,
                                           environment(credential_env, secret))
    answer = None
    if reason is None:
        if status != 0:
            reason = "exit"
        else:
            answer = read_answer(out, operation, dry_run, request.get("provider_id"), secret)
            reason = ANSWERED if answer is not None else "output"
    if reason == ANSWERED:
        return Result(reason, answer, "")
    detail = describe(reason, status, seconds)
    line = stderr_line(err, secret)
    return Result(reason, None, detail + ": " + line if line else detail)
