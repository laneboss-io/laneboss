"""Judges: external commands the launcher asks one yes/no question, bounded, logged and without a secret.

A judge is a command a configuration names ([judges.NAME], docs/judges.md). `ask()` writes one JSON request to its
standard input and reads one JSON answer from its standard output. Before anything leaves the machine, every name
and every text goes through the credential detector (a text it refuses is replaced by "[withheld]", a name it
refuses is refused) and a text is cut to 4000 characters and screened again. The command runs without a shell, in a
session of its own, with the launcher's environment minus every LANEBOSS_ variable and a time-out; when it ends or
the time-out passes, its whole process group is ended. Every ask writes two whole lines to judges/egress.jsonl in the
state directory: one before the command is started (the ask was sent) and one after it (its outcome); an ask that
cannot be logged before the command starts is not made. The launcher never invents a verdict: a judge that does not
answer gives an unavailable result with a reason.
"""

from datetime import datetime
from decimal import Decimal
import json
import os
import re
import selectors
import signal
import subprocess
import time
import uuid

from . import config, credentials, events, fsguard
from .errors import LauncherError, Refused
from .identity import ENV_PREFIX
from .jsonutil import sha256_hex

CONTRACT_VERSION = 1
KIND = "noul"
QUESTION = re.compile(r"[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*")
SUBJECT_NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
ASK = re.compile(r"[0-9a-f]{32}")
PROMPT_NAME = "prompt"
MAX_QUESTION = 64
MAX_SUBJECTS = 8
MAX_CHARACTERS = 4000
WITHHELD = "[withheld]"
DEFAULT_TIMEOUT = 10
ANSWERED = "answered"
REASONS = ("timeout", "exit", "output", "not-found")
ANSWER_KEYS = {"probability", "model", "request"}
STDOUT_LIMIT = 64 * 1024
STDERR_LIMIT = 4096
EXPLANATION = 300
CHUNK = 65536
POLL = 0.1
GRACE = 1.0
EGRESS_DIRECTORY = "judges"
EGRESS_FILE = "egress.jsonl"
MAX_EGRESS_BYTES = 64 * 1024 * 1024
# What the log keeps free for the outcome line of every unfinished ask, this one included: an outcome line (at most
# about 500 bytes) is always written inside it, so the log never passes what its own reader accepts.
RESERVE = 1024
SENT = "sent"
OUTCOME = "outcome"
SENT_KEYS = {"at", "ask", "event", "judge", "question", "lane", "request_sha256", "request_bytes", "withheld", "cut"}
OUTCOME_KEYS = {"at", "ask", "event", "outcome", "probability", "model", "request", "duration_ms"}
NOTHING_ASKED = "nothing was asked"
OUTCOME_UNLOGGED = "the ask was sent and its sending is logged, but its outcome could not be logged"


class EgressUnlogged(LauncherError):
    """The egress log cannot be written. Before the judge is run that means nothing is asked; after it, the sending is
    logged and the outcome is not. An unlogged egress is not allowed."""

    exit_code = 7
    prefix = "egress problem"


class Request:
    """The bytes a judge is offered, and what was held back or cut to make them."""

    def __init__(self, data, withheld, cut):
        self.data = data
        self.withheld = withheld
        self.cut = cut
        self.sha256 = sha256_hex(data)


class Result:
    """What one ask came to: the validated answer, or why there is none. It holds no subject or prompt text."""

    def __init__(self, judge, question, outcome, probability, model, request, withheld, cut, duration_ms, detail="",
                 ask=None):
        self.judge = judge
        self.question = question
        self.outcome = outcome
        self.probability = probability
        self.model = model
        self.request = request
        self.withheld = withheld
        self.cut = cut
        self.duration_ms = duration_ms
        self.detail = detail
        self.ask = ask

    @property
    def answered(self):
        return self.outcome == ANSWERED

    @property
    def unavailable(self):
        return not self.answered

    @property
    def reason(self):
        """None for an answer; else one of REASONS."""
        return None if self.answered else self.outcome

    def as_dict(self):
        return {"judge": self.judge, "question": self.question, "outcome": self.outcome,
                "probability": self.probability, "model": self.model, "request": self.request,
                "withheld": self.withheld, "cut": self.cut, "duration_ms": self.duration_ms}


def refuse_credential(value, option):
    """A name the credential detector refuses is never used or repeated: the message says which argument it was."""
    if isinstance(value, str) and credentials.find_in_text(value) is not None:
        raise Refused("{} looks like a credential and is not used (it is not repeated either); {}".format(
            option, NOTHING_ASKED))


def refuse_credential_names(judge, question, lane, names):
    """Every name that reaches a request, a result, a message or the log is screened before anything else is done
    with it."""
    refuse_credential(judge, "--judge")
    refuse_credential(question, "--question")
    refuse_credential(lane, "--lane")
    for name in names:
        refuse_credential(name, "a --subject name")


def judge_named(configuration, name):
    """The configured judge of that name; Refused for a name this configuration does not define."""
    refuse_credential(name, "--judge")
    config.check_name(name, "judge name")
    judges = configuration.data.get("judges", {})
    if name not in judges:
        raise Refused("configuration {} has no judge named {}; {}".format(
            configuration.name, config.shown_name(name),
            "its judges are " + ", ".join(config.shown_name(known) for known in sorted(judges)) if judges else
            "it has no judges"))
    return judges[name]


def build_request(question, prompt, subject, lane=None):
    """Validate an ask and make its request. Names are screened first. Every text is screened as a whole; a text the
    credential detector refuses is replaced by "[withheld]" and listed in `withheld` (the prompt is listed as
    "prompt"); a text longer than 4000 characters is cut to its first 4000, the cut text is screened again, and it is
    listed in `cut`, or replaced and listed in `withheld` when the cut made it a credential."""
    refuse_credential_names(None, question, lane, subject if isinstance(subject, dict) else ())
    if not isinstance(question, str) or len(question) > MAX_QUESTION or QUESTION.fullmatch(question) is None:
        raise Refused("the question must be lower-case words joined by dots and hyphens ({}), at most {} "
                      "characters".format(QUESTION.pattern, MAX_QUESTION))
    events.check_grammar(lane, events.LANE, "--lane", required=False)
    if not isinstance(prompt, str) or not prompt.strip():
        raise Refused("the prompt must be text that is not empty")
    if len(prompt) > MAX_CHARACTERS:
        raise Refused("the prompt must be at most {} characters".format(MAX_CHARACTERS))
    if not isinstance(subject, dict) or not 1 <= len(subject) <= MAX_SUBJECTS:
        raise Refused("the subject must name from 1 to {} texts".format(MAX_SUBJECTS))
    for key, text in subject.items():
        if not isinstance(key, str) or SUBJECT_NAME.fullmatch(key) is None or key == PROMPT_NAME:
            raise Refused('a subject name must match {} and may not be "{}"'.format(SUBJECT_NAME.pattern, PROMPT_NAME))
        if not isinstance(text, str):
            raise Refused("a subject text must be a string")
    withheld, cut = [], []
    if credentials.find_in_text(prompt) is not None:
        prompt = WITHHELD
        withheld.append(PROMPT_NAME)
    texts = {}
    for key, text in subject.items():
        if credentials.find_in_text(text) is not None:
            text = WITHHELD
            withheld.append(key)
        elif len(text) > MAX_CHARACTERS:
            shorter = text[:MAX_CHARACTERS]
            if credentials.find_in_text(shorter) is not None:
                text = WITHHELD
                withheld.append(key)
            else:
                text = shorter
                cut.append(key)
        texts[key] = text
    body = {"laneboss_judge": CONTRACT_VERSION, "question": question, "kind": KIND, "prompt": prompt,
            "subject": texts}
    if cut:
        body["cut"] = cut
    if withheld:
        body["withheld"] = withheld
    try:
        data = (json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    except UnicodeEncodeError:
        raise Refused("every text must be valid Unicode") from None
    return Request(data, withheld, cut)


def environment():
    """The launcher's environment minus every LANEBOSS_ variable."""
    return {key: value for key, value in os.environ.items() if not key.startswith(ENV_PREFIX)}


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("a field is repeated")
        value[key] = item
    return value


def _constant(name):
    raise ValueError("not a finite number")


def read_answer(data):
    """(probability, model, request) of the one answer object these bytes hold, or None when they are not one.

    The probability is read as the number that was written (exactly, as a decimal) and checked against 0 to 1 before
    it is made a float. `model` and `request` are null or an identifier that the credential detector accepts; any
    other value makes the whole answer no answer, so nothing of it is ever shown or logged."""
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_constant,
                           parse_float=Decimal)
    except (UnicodeDecodeError, ValueError, ArithmeticError, RecursionError):
        return None
    if type(value) is not dict or "probability" not in value or not set(value) <= ANSWER_KEYS:
        return None
    probability = value["probability"]
    if type(probability) not in (int, Decimal) or not 0 <= probability <= 1:
        return None
    strings = []
    for key in ("model", "request"):
        item = value.get(key)
        if item is not None and (not isinstance(item, str) or IDENTIFIER.fullmatch(item) is None
                                 or credentials.find_in_text(item) is not None):
            return None
        strings.append(item)
    return float(probability) + 0.0, strings[0], strings[1]


def explanation(raw):
    """The first line a judge wrote on standard error: at most 300 characters, no control characters, and "[withheld]"
    when the whole line, or the 300 characters that would be shown, look like a credential."""
    lines = (line.strip() for line in raw.decode("utf-8", "replace").splitlines())
    line = next((line for line in lines if line), "")
    if credentials.find_in_text(line) is not None:
        return WITHHELD
    shown = "".join(character if character.isprintable() else "?" for character in line)[:EXPLANATION]
    if credentials.find_in_text(shown) is not None:
        return WITHHELD
    return shown


def end_group(process):
    """End the judge's whole process group: SIGTERM, then SIGKILL for what ignores it. Each step waits at most a second,
    so a judge is not waited for beyond two seconds in all."""
    group = process.pid
    for number in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(group, number)
        except OSError:
            break
        limit = time.monotonic() + GRACE
        while time.monotonic() < limit:
            process.poll()
            try:
                os.killpg(group, 0)
            except OSError:
                return
            time.sleep(0.02)
    process.poll()


def end_leftovers(process):
    """The judge has ended by itself: whatever it left in its process group is ended, without waiting."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass


def drain(selector, process, streams, deadline):
    """After the command ended: read what its pipes still hold, without waiting for children that keep them open and
    whatever they keep writing: it stops at the ask's deadline, when standard output passes its bound ("output"), and
    after as many bytes of standard error as standard output may hold."""
    for key in list(selector.get_map().values()):
        stream = key.fileobj
        if stream is process.stdin:
            continue
        buffer = streams[stream]
        taken = 0
        while True:
            try:
                chunk = os.read(stream.fileno(), CHUNK)
            except OSError:
                break
            if not chunk:
                break
            taken += len(chunk)
            if stream is process.stdout:
                buffer += chunk
                if len(buffer) > STDOUT_LIMIT:
                    return "output"
            else:
                if len(buffer) < STDERR_LIMIT:
                    buffer += chunk[:STDERR_LIMIT - len(buffer)]
                if taken >= STDOUT_LIMIT:
                    break
            if time.monotonic() >= deadline:
                break
    return None


def pump(process, selector, data, deadline, out, err):
    """Give the command its request and collect its standard output and error until it ends or a bound passes.
    None when it ended by itself, else "timeout" or "output"."""
    pending = memoryview(data)
    streams = {process.stdout: out, process.stderr: err}
    for stream in (process.stdin, process.stdout, process.stderr):
        os.set_blocking(stream.fileno(), False)
    selector.register(process.stdin, selectors.EVENT_WRITE)
    for stream in streams:
        selector.register(stream, selectors.EVENT_READ)
    while selector.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "timeout"
        for key, _ in selector.select(min(remaining, POLL)):
            stream = key.fileobj
            if stream is process.stdin:
                try:
                    pending = pending[os.write(stream.fileno(), pending[:CHUNK]):]
                except BlockingIOError:
                    continue
                except OSError:
                    pending = pending[len(pending):]
                if not pending:
                    selector.unregister(stream)
                    stream.close()
                continue
            try:
                chunk = os.read(stream.fileno(), CHUNK)
            except BlockingIOError:
                continue
            except OSError:
                chunk = b""
            if not chunk:
                selector.unregister(stream)
                continue
            buffer = streams[stream]
            if stream is process.stdout:
                buffer += chunk
                if len(buffer) > STDOUT_LIMIT:
                    return "output"
            elif len(buffer) < STDERR_LIMIT:
                buffer += chunk[:STDERR_LIMIT - len(buffer)]
        if process.poll() is not None:
            return drain(selector, process, streams, deadline)
    return None


def run_command(argv, data, seconds, variables):
    """Run one judge with `data` on its standard input: (reason, status, standard output, standard error). The reason
    is None when the command ended by itself, else "not-found" (it could not be started), "timeout" or "output"
    (standard output passed its bound); the command's whole process group is ended in every case."""
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=variables, close_fds=True, start_new_session=True)
    except (OSError, ValueError):
        return "not-found", None, b"", b""
    deadline = time.monotonic() + seconds
    out, err = bytearray(), bytearray()
    reason = None
    selector = selectors.DefaultSelector()
    try:
        reason = pump(process, selector, data, deadline, out, err)
        if reason is None:
            try:
                process.wait(timeout=max(deadline - time.monotonic(), 0.0))
            except subprocess.TimeoutExpired:
                reason = "timeout"
    finally:
        if reason is None and process.returncode is not None:
            end_leftovers(process)
        else:
            end_group(process)
        selector.close()
        for stream in (process.stdin, process.stdout, process.stderr):
            try:
                stream.close()
            except OSError:
                pass
    return reason, process.returncode, bytes(out), bytes(err)


def describe(reason, status, seconds):
    if reason == "timeout":
        return "no answer within {} second(s)".format(seconds)
    if reason == "not-found":
        return "the program was not found or could not be started"
    if reason == "output":
        return "standard output is not one answer object"
    return "exit status {}".format(status) if status is not None and status > 0 else "ended by a signal"


def check_owner(configuration, state):
    """The state directory must be the configuration's own: the function is public, and a configuration with another's
    state directory would run its judge and write the other's log."""
    if (state.configuration.name != configuration.name
            or state.real != os.path.realpath(str(configuration.state_dir))):
        raise Refused("the state directory does not belong to configuration {}; {}".format(
            config.shown_name(configuration.name), NOTHING_ASKED))


def record_owner(state):
    """The state directory's ownership marker, made when it is missing, before the first line is written: judge-only
    state belongs to its configuration like all other state, so a copy of it is recognised as another's."""
    try:
        if state.marker() is None:
            with state.lock():
                state.ensure_marker()
    except OSError as error:
        raise EgressUnlogged("{}: the state directory cannot record its owner ({})".format(
            NOTHING_ASKED, error.strerror or "operating system error")) from None


def open_directory(state):
    """The opened judges directory of the state directory, made when it is missing; EgressUnlogged (nothing is asked)
    when it cannot be."""
    try:
        return fsguard.child_directory(state.fd, EGRESS_DIRECTORY, create=True)
    except Refused as error:
        raise EgressUnlogged("{}: {}".format(NOTHING_ASKED, error)) from None
    except OSError as error:
        raise EgressUnlogged("{}: the egress log's directory cannot be made or opened ({})".format(
            NOTHING_ASKED, error.strerror or "operating system error")) from None


def read_directory(state):
    """The opened judges directory for reading, or None when the state directory has none."""
    try:
        return fsguard.child_directory(state.fd, EGRESS_DIRECTORY)
    except FileNotFoundError:
        return None


def read_log(directory):
    """The log's bytes; empty when it does not exist. Refused when it is a link, not a regular file or too large."""
    if fsguard.file_info(directory, EGRESS_FILE) is None:
        return b""
    descriptor = fsguard.open_child(directory, EGRESS_FILE, "the egress log")
    return fsguard.read_descriptor(descriptor, MAX_EGRESS_BYTES, "the egress log")


def sync_state(state):
    """Sync the state directory itself, once, after the ownership marker and the judges directory are made and before
    the sent line is written, so that the entries those two left in it survive the launcher being killed and, after a
    power cut, are there when the file system kept what was synced. Directories above the state directory that the same
    command had to create are not synced here. EgressUnlogged (nothing is asked) when it cannot be done."""
    try:
        os.fsync(state.fd)
    except OSError as error:
        raise EgressUnlogged("{}: the state directory cannot be synced ({})".format(
            NOTHING_ASKED, error.strerror or "operating system error")) from None


def last_line(data):
    """The last line of the log's bytes that is not blank, or None when there is none."""
    end = len(data)
    while end > 0 and data[end - 1] in b" \t\r\n\x0b\x0c":
        end -= 1
    if end == 0:
        return None
    return data[data.rfind(b"\n", 0, end) + 1:end]


def check_line(raw):
    """The record of one line of the log, given as bytes; ValueError when it is not a line of this version."""
    try:
        return parse_log_line(raw.decode("utf-8"))
    except (UnicodeDecodeError, RecursionError):
        raise ValueError("not a line of the log") from None


def unfinished(data):
    """How many asks of the log have a sent line and no outcome line yet. Every field of a line is held to a grammar, so
    the two marks below appear once per line of their kind and nowhere else."""
    return max(data.count(b'"event": "sent"') - data.count(b'"event": "outcome"'), 0)


def check_sendable(data, line, where):
    """Before a sent line is written: the log's last line must be one of this version's, and the log, the line and a
    reserve for the outcome line of every unfinished ask (this one included) must fit what the reader accepts.
    EgressUnlogged (nothing is asked) otherwise, naming the file and saying to move it aside."""
    last = last_line(data)
    if last is not None:
        try:
            check_line(last)
        except ValueError:
            raise EgressUnlogged("{}: the egress log {} was not written by this version of the launcher (its last line "
                                 "is not one of this version's lines); move the file aside (rename it) and ask "
                                 "again".format(NOTHING_ASKED, where)) from None
    needed = len(data) + len(line) + RESERVE * (unfinished(data) + 1)
    if needed > MAX_EGRESS_BYTES:
        raise EgressUnlogged("{}: the egress log {} is full (it holds {} bytes, and a sent line and the room for the "
                             "outcome of each unfinished ask would pass the {} the launcher reads); move the file aside "
                             "(rename it) and ask again".format(NOTHING_ASKED, where, len(data), MAX_EGRESS_BYTES))


def write_line(directory, line, failure, where, sending=False):
    """Add one whole line to the log: under a lock on the directory the log is read, the line is added and the log is
    written anew under a temporary name, synced and renamed over the old one; it is never appended to in place. A sent
    line (`sending`) is checked first (check_sendable); an outcome line never is, because its room was kept for it. When
    writing fails, EgressUnlogged says `failure` first."""
    try:
        with fsguard.Lock(directory):
            info = fsguard.file_info(directory, EGRESS_FILE)
            if sending and info is not None and info.st_size > MAX_EGRESS_BYTES:
                raise EgressUnlogged("{}: the egress log {} is full (it holds {} bytes, more than the {} the launcher "
                                     "reads); move the file aside (rename it) and ask again".format(
                                         NOTHING_ASKED, where, info.st_size, MAX_EGRESS_BYTES))
            data = read_log(directory)
            if data and not data.endswith(b"\n"):
                data += b"\n"
            if sending:
                check_sendable(data, line, where)
            fsguard.write_new(directory, EGRESS_FILE, data + line, replace=True)
            os.fsync(directory)
    except (Refused, OSError) as error:
        raise EgressUnlogged("{}: the egress log cannot be written ({})".format(
            failure, error if isinstance(error, Refused) else error.strerror or "operating system error")) from None


def log_bytes(record):
    return (json.dumps(record, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def sent_line(at, ask, judge, question, lane, request):
    return log_bytes({"at": at, "ask": ask, "event": SENT, "judge": judge, "question": question, "lane": lane,
                      "request_sha256": request.sha256, "request_bytes": len(request.data),
                      "withheld": request.withheld, "cut": request.cut})


def outcome_line(at, ask, outcome, probability, model, identifier, duration):
    return log_bytes({"at": at, "ask": ask, "event": OUTCOME, "outcome": outcome, "probability": probability,
                      "model": model, "request": identifier, "duration_ms": duration})


def moment(stamp):
    return datetime.fromisoformat(stamp[:-1] + "+00:00" if stamp.endswith("Z") else stamp)


def _count(value):
    return type(value) is int and value >= 0


def _names(value, allowed):
    return (isinstance(value, list) and all(isinstance(item, str) and allowed.fullmatch(item) is not None
                                            for item in value))


def parse_log_line(text):
    """The record of one line of the egress log. ValueError when the line is not one of the log's lines: not an object,
    a repeated or missing or extra key, a field of the wrong type or form, or a time that does not exist."""
    record = json.loads(text, object_pairs_hook=_unique, parse_constant=_constant)
    if type(record) is not dict:
        raise ValueError("not an object")
    keys = {SENT: SENT_KEYS, OUTCOME: OUTCOME_KEYS}.get(record.get("event")) if isinstance(record.get("event"), str) \
        else None
    if keys is None or set(record) != keys:
        raise ValueError("not a line of the log")
    at, ask = record["at"], record["ask"]
    if not isinstance(at, str) or config.RECORDED_AT.fullmatch(at) is None:
        raise ValueError("the time is not one the log writes")
    moment(at)
    if not isinstance(ask, str) or ASK.fullmatch(ask) is None:
        raise ValueError("the ask identifier is not one")
    if record["event"] == SENT:
        valid = (isinstance(record["judge"], str) and config.NAME.fullmatch(record["judge"]) is not None
                 and isinstance(record["question"], str) and len(record["question"]) <= MAX_QUESTION
                 and QUESTION.fullmatch(record["question"]) is not None
                 and (record["lane"] is None or (isinstance(record["lane"], str)
                                                 and events.LANE.fullmatch(record["lane"]) is not None))
                 and isinstance(record["request_sha256"], str) and events.DIGEST.fullmatch(record["request_sha256"])
                 and _count(record["request_bytes"])
                 and _names(record["withheld"], re.compile(SUBJECT_NAME.pattern + "|" + PROMPT_NAME))
                 and _names(record["cut"], SUBJECT_NAME))
    else:
        probability, outcome = record["probability"], record["outcome"]
        identifiers = all(item is None or (isinstance(item, str) and IDENTIFIER.fullmatch(item) is not None
                                           and credentials.find_in_text(item) is None)
                          for item in (record["model"], record["request"]))
        number = type(probability) in (int, float) and 0 <= probability <= 1
        valid = (identifiers and _count(record["duration_ms"])
                 and ((outcome == ANSWERED and number)
                      or (outcome in REASONS and probability is None and record["model"] is None
                          and record["request"] is None)))
    if not valid:
        raise ValueError("a field is not one the log writes")
    return record


def ask(configuration, state, name, question, prompt, subject, lane=None):
    """Ask one judge one question: a Result that is either the validated answer or unavailable with a reason (one of
    REASONS), never a made-up probability. Refused for invalid input and for a state directory that is not the
    configuration's own, before anything is run or written. EgressUnlogged (exit 7) when the ask cannot be logged: the
    sending is written before the judge is started (an attempt: a launcher killed between the two leaves a sent line
    for a judge that never ran), so then nothing is asked, and nothing is asked either when the log was not written by
    this version or has no room left (a sent line, and the reserve for the outcome of every unfinished ask, must fit
    what the reader accepts); when the outcome cannot be written after the judge ran, the sending is logged, the outcome
    is not, and no result is returned. The state directory is synced once, after the marker and the judges directory
    exist, before the sent line."""
    judge = judge_named(configuration, name)
    request = build_request(question, prompt, subject, lane)
    check_owner(configuration, state)
    seconds = judge.get("timeout_seconds", DEFAULT_TIMEOUT)
    record_owner(state)
    directory = open_directory(state)
    where = os.path.join(state.real, EGRESS_DIRECTORY, EGRESS_FILE)
    try:
        sync_state(state)
        ask_id = uuid.uuid4().hex
        write_line(directory, sent_line(events.utc_now(), ask_id, name, question, lane, request), NOTHING_ASKED, where,
                   sending=True)
        started = time.monotonic()
        try:
            reason, status, out, err = run_command(judge["command"], request.data, seconds, environment())
        except BaseException:
            # Interrupted while the judge ran: it is ended, and the outcome is logged as no answer when it can be.
            try:
                write_line(directory, outcome_line(events.utc_now(), ask_id, "exit", None, None, None,
                                                   int(round((time.monotonic() - started) * 1000))),
                           OUTCOME_UNLOGGED, where)
            except LauncherError:
                pass
            raise
        answer = None
        if reason is None:
            if status != 0:
                reason = "exit"
            else:
                answer = read_answer(out)
                reason = ANSWERED if answer is not None else "output"
        probability, model, identifier = answer if answer is not None else (None, None, None)
        duration = int(round((time.monotonic() - started) * 1000))
        write_line(directory, outcome_line(events.utc_now(), ask_id, reason, probability, model, identifier, duration),
                   OUTCOME_UNLOGGED, where)
    finally:
        os.close(directory)
    detail = ""
    if reason != ANSWERED:
        detail = describe(reason, status, seconds)
        line = explanation(err)
        if line:
            detail += ": " + line
    return Result(name, question, reason, probability, model, identifier, request.withheld, request.cut, duration,
                  detail, ask_id)
