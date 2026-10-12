"""`laneboss judge`: list the configured judges, ask one a question, read the egress log (docs/judges.md).

Every action is bound to one configuration like the other state commands. `ask` takes its texts from files, never
from arguments, and prints one JSON value; `egress` prints the log's lines and creates nothing.
"""

import os
import re
import signal
import sys

from . import config, events, judges
from .errors import IntegrityProblem, Refused
from .jsonutil import output
from .statedir import StateDir

MAX_TEXT_BYTES = 1024 * 1024
OFFSET = re.compile(r"[+-]([0-9]{2}):([0-9]{2})$")


def register(commands, binding):
    judge = commands.add_parser("judge", help="list the configured judges, ask one a question, read the egress log")
    actions = judge.add_subparsers(dest="action", metavar="ACTION", required=True)
    actions.add_parser("list", parents=[binding], help="the configured judges")
    ask = actions.add_parser("ask", parents=[binding], help="ask one judge one question; the texts come from files")
    ask.add_argument("--judge", required=True, metavar="NAME")
    ask.add_argument("--question", required=True, metavar="ID", help="for example refusal.is-refusal")
    ask.add_argument("--prompt-file", required=True, metavar="FILE", help="the question in words")
    ask.add_argument("--subject", action="append", required=True, metavar="NAME=FILE",
                     help="a named text for the judge to read, one to eight times")
    ask.add_argument("--lane", help="the lane the question is about; recorded in the egress log")
    egress = actions.add_parser("egress", parents=[binding], help="print the egress log, one line per sent ask and "
                                                                   "one per outcome")
    egress.add_argument("--since", metavar="TIME", help="only the lines at or after this time")


def emit(value):
    sys.stdout.write(output(value) + "\n")
    sys.stdout.flush()


def listing(configuration):
    emit([{"name": name, "description": judge.get("description"), "program": judge["command"][0],
           "timeout_seconds": judge.get("timeout_seconds", judges.DEFAULT_TIMEOUT)}
          for name, judge in sorted(configuration.data.get("judges", {}).items())])
    return 0


def read_text(zones, path, option):
    data = config.read_external(zones, path, option, MAX_TEXT_BYTES)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("{}: the file must be UTF-8 text".format(option)) from None


def subject_arguments(items):
    """(name, path) of every --subject in order; no file is read yet."""
    found = []
    for item in items:
        name, separator, path = item.partition("=")
        if not separator or not name or not path:
            raise Refused("--subject must be NAME=FILE")
        if any(known == name for known, _ in found):
            raise Refused("--subject names the same text twice")
        found.append((name, path))
    return found


def interrupted(number, frame):
    raise KeyboardInterrupt


def ask(configuration, zones, arguments):
    pairs = subject_arguments(arguments.subject)
    judges.refuse_credential_names(arguments.judge, arguments.question, arguments.lane, [name for name, _ in pairs])
    judges.judge_named(configuration, arguments.judge)
    prompt = read_text(zones, arguments.prompt_file, "--prompt-file")
    subject = {name: read_text(zones, path, "--subject") for name, path in pairs}
    judges.build_request(arguments.question, prompt, subject, arguments.lane)
    state = StateDir.open(configuration, zones, create=True)
    # A terminated launcher ends the judge's process group and logs the outcome when it can, as an interrupt does.
    previous = {number: signal.signal(number, interrupted) for number in (signal.SIGTERM, signal.SIGHUP)}
    try:
        result = judges.ask(configuration, state, arguments.judge, arguments.question, prompt, subject, arguments.lane)
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
        state.close()
    emit(result.as_dict())
    if result.answered:
        return 0
    print("unavailable: judge {} gave no answer ({}): {}".format(result.judge, result.outcome, result.detail),
          file=sys.stderr)
    return 1


def since_moment(text):
    """--since as a time. The timestamp grammar lets an offset such as +00:60 through, and the parser would turn it
    into another one, so an offset whose hours or minutes do not exist is refused here."""
    events.check_timestamp(text, "--since")
    match = OFFSET.search(text)
    if match and (int(match.group(1)) > 23 or int(match.group(2)) > 59):
        raise Refused("--since: the offset is not a time zone")
    return judges.moment(text)


def egress(configuration, zones, arguments):
    since = since_moment(arguments.since) if arguments.since is not None else None
    state = StateDir.open(configuration, zones, create=False)
    if state is None:
        return 0
    try:
        directory = judges.read_directory(state)
        if directory is None:
            return 0
        try:
            data = judges.read_log(directory)
        finally:
            os.close(directory)
    finally:
        state.close()
    lines = []
    for number, raw in enumerate(data.split(b"\n"), 1):
        if not raw.strip():
            continue
        try:
            line = raw.decode("utf-8")
            at = judges.moment(judges.parse_log_line(line)["at"])
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise IntegrityProblem("line {} of the egress log is not a line of the log (docs/judges.md, 'The egress "
                                   "log')".format(number)) from None
        if since is None or at >= since:
            lines.append(line)
    sys.stdout.write("".join(line + "\n" for line in lines))
    sys.stdout.flush()
    return 0


def run(configuration, zones, arguments):
    if arguments.action == "list":
        return listing(configuration)
    if arguments.action == "ask":
        return ask(configuration, zones, arguments)
    return egress(configuration, zones, arguments)
