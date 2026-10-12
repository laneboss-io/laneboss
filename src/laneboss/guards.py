"""Guards: the configuration's patterns that recognise a guard's refusal in the result of a tool call.

A guard has a name, an optional kind (hook, permission or harness) and a Python regular expression. A pattern is refused
when it does not compile, when it matches the empty string, or when a partial rejection rule finds a shape that can make
matching take time exponential in a line's length: a repetition without an upper bound around a part that itself repeats
(`(a+)+`, `(\\w+\\s?)*`) or a back-reference (`\\1`). That rule does not prove an accepted pattern cheap (`^(a|aa)+$`
passes it): the bound is the alarm. Matching sees all of a text up to 128 KiB and, beyond that, its first 64 KiB and the
lines that begin in its last 64 KiB (sessions.bounded), each line cut to its first 4096 characters, every guard tried on
each line in order, and all of it given one second (an
alarm that interrupts the matching, in the main thread of the scanning process); a result whose matching does not
finish in time is counted as not covered, never as "no refusal".
"""

import re
import signal
import threading

KINDS = ("hook", "permission", "harness")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
MAX_LINE = 4096
SECONDS = 1.0
MESSAGE_LINES = 3

try:
    from re import _constants as _sre_constants, _parser as _sre_parser
except ImportError:  # pragma: no cover - a later Python may move them; matching is still bounded by time
    _sre_constants = _sre_parser = None


def unbounded(pattern):
    """Why the partial rejection rule refuses this compiled-valid pattern, or None (which proves nothing: the alarm is
    the bound)."""
    if _sre_parser is None:
        return None
    try:
        parsed = _sre_parser.parse(pattern)
    except Exception:
        return None
    repeats = {_sre_constants.MAX_REPEAT, _sre_constants.MIN_REPEAT, _sre_constants.POSSESSIVE_REPEAT}
    references = {_sre_constants.GROUPREF, _sre_constants.GROUPREF_EXISTS}

    def children(op, value):
        if op in repeats:
            return [value[2]]
        if op == _sre_constants.SUBPATTERN:
            return [value[3]]
        if op == _sre_constants.BRANCH:
            return list(value[1])
        if op in (_sre_constants.ASSERT, _sre_constants.ASSERT_NOT):
            return [value[1]]
        if op == _sre_constants.ATOMIC_GROUP:
            return [value]
        if op == _sre_constants.GROUPREF_EXISTS:
            return [part for part in value[1:] if part is not None]
        return []

    def walk(items, inside):
        for op, value in items:
            if op in references:
                return "it uses a back-reference"
            if op in repeats and value[1] > 1 and inside:
                return "it repeats without bound a part that itself repeats"
            endless = op in repeats and value[1] == _sre_constants.MAXREPEAT
            for child in children(op, value):
                found = walk(child, inside or endless)
                if found:
                    return found
        return None

    return walk(parsed, False)


class Guard:
    def __init__(self, name, kind, pattern):
        self.name = name
        self.kind = kind
        self.pattern = re.compile(pattern)


def configured(configuration, runner=None):
    """True when the configuration has guards and, given a runner's name, that runner names its records. Kept here, in
    a module that imports little, so commands that do not scan need not load the scan."""
    if not configuration.data.get("guards"):
        return False
    if runner is None:
        return True
    return bool(configuration.data["runners"].get(runner, {}).get("records"))


def compile_guards(configuration):
    return [Guard(item["name"], item.get("kind"), item["pattern"]) for item in configuration.data.get("guards", [])]


class Late(Exception):
    pass


def _late(number, frame):
    raise Late()


TIMED_OUT = object()


class Matcher:
    """Finds the first guard that matches a result, line by line, within the time bound."""

    def __init__(self, guards):
        self.guards = guards
        self.bounded = threading.current_thread() is threading.main_thread()

    def search(self, text, tail=None):
        """((guard, message source) of the first line a guard matches, None, or TIMED_OUT; how many lines were cut).
        `text` and `tail` are the parts sessions.bounded() leaves of a text: no line is in both."""
        if not self.guards or not (text or tail):
            return None, 0
        parts = [text.splitlines()] + ([tail.splitlines()] if tail else [])
        cut = sum(1 for lines in parts for line in lines if len(line) > MAX_LINE)
        previous = None
        if self.bounded:
            previous = signal.signal(signal.SIGALRM, _late)
            signal.setitimer(signal.ITIMER_REAL, SECONDS)
        try:
            for lines in parts:
                for index, line in enumerate(lines):
                    line = line[:MAX_LINE]
                    for guard in self.guards:
                        if guard.pattern.search(line):
                            return (guard, "\n".join(lines[index:index + MESSAGE_LINES])), cut
            return None, cut
        except Late:
            return TIMED_OUT, cut
        finally:
            if self.bounded:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, previous)
