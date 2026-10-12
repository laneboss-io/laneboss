"""Mail: the messages of a turn-based lane (docs/architecture.md, "Turns, mail, the loop and attach").

A message is one immutable file of the lane, named SEQUENCE-DIGEST (nine digits of sequence, a hyphen, the SHA-256 of
the file's bytes) in the directory mail/ of the lane's directory of the state directory, announced by the event
lane.mailed, which carries the sequence, the sender, the hash and the size and never the text. The launcher writes a
file once and never moves, renames, rewrites or deletes it. Which messages wait, are in flight, are delivered or have
returned follows from the lane's events alone (lanes.py); this module holds the files and what is done with them: the
checks of `lane send`, the file it writes and the checks of `state verify`.
"""

import os
import stat
import sys

from . import brief, config, credentials, events, fsguard, lanes
from .errors import IntegrityProblem, Refused
from .jsonutil import sha256_hex

TEMPORARY = ".tmp-"
DEFAULT_SENDER = "supervisor"


def file_name(sequence, digest):
    """The name of a message's file: its sequence number as nine digits, and the SHA-256 of its bytes."""
    return "{:09d}-{}".format(sequence, digest)


# lane send: what is checked of the message, the sender and the lane's runner before a byte is written, and the file.

def check_path(path, option):
    """A path given on the command line is never repeated when any part of it looks like a credential: the refusal
    names the option, not the value."""
    for candidate in (path, os.path.abspath(path), os.path.realpath(path)):
        for part in [candidate] + candidate.split("/"):
            found = credentials.find_in_text(part)
            if found:
                raise Refused("{}: the path looks like a credential ({}); nothing was read".format(option, found[0]))


def read_message(zones, file, source):
    """The bytes of the message exactly as sent: from the file named (read once, through its checked directory, as --brief
    and --message are), or from standard input when `source` is `-`. Never from an argument, because a shell would expand
    it before the launcher saw it, and never more than a message may hold."""
    if file is not None and source is not None:
        raise Refused("lane send takes the message from --file PATH or from standard input (-), not from both")
    if source is not None and source != "-":
        raise Refused("lane send never takes the message as an argument, because a shell would expand it before the "
                      "launcher saw it: give --file PATH, or - to read it from standard input")
    if file is None and source is None:
        raise Refused("lane send needs the message: give --file PATH, or - to read it from standard input")
    if file is not None:
        check_path(file, "--file")
        data = config.read_external(zones, file, "--file", brief.MAX_BRIEF_BYTES)
    elif sys.stdin is None:
        raise Refused("standard input is closed, so there is no message to read from it")
    else:
        data = sys.stdin.buffer.read(lanes.MAX_MESSAGE_BYTES + 1)
    check_size(data)
    return data


def check_size(data):
    """A message holds at most 262,144 bytes."""
    if len(data) > lanes.MAX_MESSAGE_BYTES:
        raise Refused("the message is larger than {} bytes, the most a message may hold".format(lanes.MAX_MESSAGE_BYTES))


def check_message(data):
    """The refusals of a message, all before anything is stored: at most 262,144 bytes (read_message makes sure of it
    for a message it reads), UTF-8 text with something in it besides white space, and the refusals a brief gets: no
    launcher block of its own and no credential shape (the error names the line and never repeats it). The mandatory
    sections of --touches do not apply."""
    check_size(data)
    text = brief.check_text(data, "the message", "message")
    if not text.strip():
        raise Refused("the message is empty: it holds nothing but white space")
    return text


def check_sender(value):
    """The sender of a message: `--from NAME`, else `supervisor`. Its grammar is the event's, and it goes through the
    credential detector like every value that reaches an event; the value is never repeated."""
    if value is None:
        return DEFAULT_SENDER
    if lanes.SENDER.fullmatch(value) is None:
        raise Refused("--from must match " + lanes.SENDER.pattern)
    found = credentials.find_in_text(value)
    if found:
        raise Refused("--from: looks like a credential ({}); nothing was stored".format(found[0]))
    return value


def turn_problems(name, runner):
    """What keeps a runner from taking turns, as the configuration has it now: one sentence for each missing part, and
    none for a runner that can. A runner takes turns when {session} is in its `command` and in its `resume` template, its
    `prompt` is "stdin" and it has a `resume` template."""
    problems = []
    if not config.uses(runner["command"], "session"):
        problems.append("its command (runners.{}.command) does not use {{session}}".format(name))
    if runner.get("resume") is None:
        problems.append("it has no resume template (runners.{}.resume)".format(name))
    elif not config.uses(runner["resume"], "session"):
        problems.append("its resume template (runners.{}.resume) does not use {{session}}".format(name))
    if runner.get("prompt") != "stdin":
        problems.append('it does not take its prompt on standard input (runners.{}.prompt needs prompt = "stdin")'.format(
            name))
    return problems


def queued(mail):
    """How many messages of a lane's row wait for a turn: the waiting ones and the returned ones."""
    return len(mail["waiting"]) + len(mail["returned"])


def store_file(state, lane, sequence, data):
    """Step 3 of lane send: the message's file in the lane's mail directory, named by its sequence and the SHA-256 of its
    bytes, written once through a temporary name and put in place without replacing anything. A file of that name that
    exists already (left by an interrupted send of the same bytes) is read back: when its bytes hash to its name it is the
    file, otherwise the send is an integrity problem and the file is left as it is. Returns (path, sha256 of the bytes)."""
    digest = sha256_hex(data)
    name = file_name(sequence, digest)
    where = "lanes/{}/mail/{}".format(lane, name)
    directory = state.open_lane(lane, "mail", create=True)
    try:
        written = False
        if fsguard.file_info(directory, name) is None:
            try:
                fsguard.write_new(directory, name, data)
                written = True
            except FileExistsError:
                written = False  # another writer made it since the look above: it is read back like any file of that name
            except OSError as error:
                raise Refused("the message could not be written to {}: {}; nothing was recorded".format(
                    state.lane_path(lane, "mail", name), error.strerror or "error")) from None
        if not written:
            try:
                kept = fsguard.read_descriptor(fsguard.open_child(directory, name, where), lanes.MAX_MESSAGE_BYTES + 1,
                                               where)
            except Refused as error:
                raise IntegrityProblem("{} exists and cannot be read back: {}; nothing was recorded".format(
                    where, error)) from None
            if sha256_hex(kept) != digest:
                raise IntegrityProblem("{} exists and does not hold the bytes its name promises; it was left as it is "
                                       "and nothing was recorded".format(where))
        try:
            os.fsync(directory)
        except OSError as error:
            raise Refused("the message could not be written to {}: {}; nothing was recorded".format(
                state.lane_path(lane, "mail", name), error.strerror or "error")) from None
    finally:
        os.close(directory)
    return state.lane_path(lane, "mail", name), digest


# lane turn: the head of the queue, read and checked, and joined into one message.

def header_line(sequence, sender, at, again):
    """The header line a message has in a turn's prompt: its sequence, its sender and the time of its lane.mailed event,
    and ` (again)` when an earlier turn carried it and did not end well."""
    return "## Message {} from {} at {}{}".format(sequence, sender, at, " (again)" if again else "")


def read_message_file(state, lane, event):
    """The bytes of the message a lane.mailed event announces, read from its file in the lane's mail directory without
    following a link and checked against the name, the hash and the size the event gives. A file that is missing, is
    not a regular file or does not hold what its event says is an integrity problem that names the sequence."""
    payload = event["payload"]
    name = file_name(payload["sequence"], payload["sha256"])
    where = "lane {}: the mail file of sequence {} (event seq {})".format(lane, payload["sequence"], event["seq"])
    try:
        data = state.read_mail(lane, name, lanes.MAX_MESSAGE_BYTES + 1)
    except Refused as error:
        raise IntegrityProblem("{} cannot be read: {}".format(where, error)) from None
    if data is None:
        raise IntegrityProblem("{} is missing: {}".format(where, state.lane_path(lane, "mail", name)))
    if sha256_hex(data) != payload["sha256"] or len(data) != payload["bytes"]:
        raise IntegrityProblem("{} no longer holds the bytes its name and its event give: {}".format(
            where, state.lane_path(lane, "mail", name)))
    return data


def take(state, lane, queue, mailed):
    """What the next turn of a lane carries: the head of `queue` (the returned messages and then the waiting ones, the
    row's `returned` and `waiting`), up to 64 messages and 1,048,576 bytes of joined text, header lines and separators
    included; the first message always goes. `mailed` maps a sequence to its lane.mailed event. Each message is read and
    checked before anything is built, and refused by the renderer's text check with its sequence named (it was accepted
    when it was sent, so this holds only after a change of the launcher). For each message: a header line, an empty line
    and its text, with a final newline added when it has none; an empty line between two messages. Returns (the joined
    bytes, the sequences taken)."""
    returned = set(queue["returned"])
    parts, taken, size = [], [], 0
    for sequence in queue["returned"] + queue["waiting"]:
        if len(taken) == lanes.MAX_TURN_MESSAGES:
            break
        event = mailed.get(sequence)
        if event is None:
            raise IntegrityProblem("lane {}: message {} is in the lane's queue, but no lane.mailed event announces "
                                   "it".format(lane, sequence))
        data = read_message_file(state, lane, event)
        brief.check_text(data, "message {}".format(sequence), "message")
        head = header_line(sequence, event["payload"]["sender"], event["occurred_at"] or event["recorded_at"],
                           sequence in returned)
        part = head.encode("utf-8") + b"\n\n" + (data if data.endswith(b"\n") else data + b"\n")
        added = len(part) + (1 if parts else 0)
        if parts and size + added > lanes.MAX_TURN_BYTES:
            break
        parts.append(part)
        taken.append(sequence)
        size += added
    return b"\n".join(parts), taken


def verify(state, stored):
    """The checks of `state verify` for mail, for every lane that has a mail directory: every name is SEQUENCE-DIGEST or
    starts with `.tmp-` (and is skipped); every entry is a regular file that is not a link, and its bytes hash to the digest
    in its name; every lane.mailed event has its file, of the size it says. A file that no event names is an orphan: it is
    counted, never a problem. Names found on disk are printed only when they match the grammar of a message's name.
    Returns (files checked, orphans)."""
    named = {}
    for event in stored:
        if event["kind"] == "lane.mailed":
            payload = event["payload"]
            named[(event["lane"], file_name(payload["sequence"], payload["sha256"]))] = event
    found = {}
    for lane, name in state.all_mail():
        where = "lanes/{}/mail".format(lane if events.LANE.fullmatch(lane) else "<a lane directory>")
        if name.startswith(TEMPORARY):
            continue
        if lanes.MAIL_NAME.fullmatch(name) is None:
            raise IntegrityProblem("a file under {} is not named SEQUENCE-DIGEST (nine digits of sequence, a hyphen and "
                                   "the SHA-256 of its bytes)".format(where))
        info = state.mail_entry(lane, name)
        if info is None:
            continue
        if not stat.S_ISREG(info.st_mode):
            raise IntegrityProblem("{}/{} is not a regular file (a message is a file that is not a link)".format(
                where, name))
        try:
            data = state.read_mail(lane, name, lanes.MAX_MESSAGE_BYTES)
        except Refused as error:
            raise IntegrityProblem("{}/{} cannot be read as a message: {}".format(where, name, error)) from None
        if data is None:
            continue
        if sha256_hex(data) != name.split("-", 1)[1]:
            raise IntegrityProblem("{}/{} does not match its hash: its name says what its bytes must hash to".format(
                where, name))
        found[(lane, name)] = len(data)
    for (lane, name), event in named.items():
        size = found.get((lane, name))
        if size is None:
            raise IntegrityProblem("lane {}: the mail file of sequence {} (event seq {}) is missing: lanes/{}/mail/{}"
                                   .format(lane, event["payload"]["sequence"], event["seq"], lane, name))
        if size != event["payload"]["bytes"]:
            raise IntegrityProblem("lane {}: the mail file of sequence {} (event seq {}) has {} bytes, and its event says "
                                   "{}".format(lane, event["payload"]["sequence"], event["seq"], size,
                                               event["payload"]["bytes"]))
    return len(found), sum(1 for key in found if key not in named)
