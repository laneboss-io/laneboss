"""`laneboss lane attach`: the terminal view of a turn-based lane and a keyboard for it (docs/architecture.md, "The `lane
attach` command and the stream readers").

Attach reads the lane's own log and the store, and writes only the mail and the turns that a typed line asks for. It never
starts an agent and keeps no child process: the tmux commands that `lane turn` runs end before it returns, and the
supervising process it asks for belongs to the lane's tmux session. It signals no process itself and no group: Ctrl-C and
`/stop` are the code of `lane stop --run N`, which signals the run's supervising process (checked by its recorded
identity), and that process stops the run's processes one by one, each by its recorded identity. Leaving attach never
stops a turn, because attach never owned it.

What the runner printed goes through the reader that its `stream` key names (streams.py), and attach prints only what a
reader returns and its own lines; nothing here knows a vendor's format. The main thread reads the keyboard, with the
standard library's line input and `readline` when the interpreter has it; a thread of its own follows the log and the
store. Every byte that reaches the terminal goes through the Console, which holds the follower's output back while a line
is being typed.
"""

import argparse
import os
import signal
import sqlite3
import sys
import threading
import time

from . import credentials, fsguard, lanecmd, lanes, mail, runrecord, streams
from .errors import LauncherError, Refused

PROMPT = "attach> "
CONTINUED = "... "
SENDER = "attach"
LOG_POLL = 0.2  # seconds between two looks at the log, as `event tail --follow` polls the store
STORE_POLL = 0.5  # seconds between two reads of the store
CHUNK = 1024 * 1024
STREAMED_KEPT = 1024 * 1024  # the streamed text that is remembered, to tell a whole line that repeats it
TROUBLE_SECONDS = 10  # one note at most this often when the view cannot read the lane
JOIN_SECONDS = 3
EOF_GRACE = 0.2  # a closed terminal reads as end of input; the SIGHUP that comes with it gets this long to arrive
# Readers whose answer items are whole lines, and that never report a mode or a cost.
LINE_READERS = ("text",)
WARNING = "WARNING: approvals are bypassed: the agent may run any command and change any file it can reach."
NOTICE = "note: this request ran without approval rights."
HELP = ("/turn   start a turn for the messages that wait\n"
        "/stop   stop the turn that this attach started (Ctrl-C does the same)\n"
        "/help   this list\n"
        "/exit   leave attach; a turn that is live goes on")
HINT = "nothing was stopped; leave with /exit or Ctrl-D (Ctrl-C stops only a turn that this attach started)"
KEY_NOTICE = ("Ctrl-C noted: attach acts on it when the lane command now running returns; another Ctrl-C at least "
              "2 seconds after this one leaves attach now, without waiting")
KEY_DELAY = 2.0  # seconds: a key this long after the first counted in a lane command leaves attach; sooner, a double tap


class Leave(BaseException):
    """Raised by the handlers of SIGHUP, SIGTERM and (for a second key during a lane command) SIGINT: attach is left with
    this exit code, and a turn goes on. `note` is a line for the screen, or None."""

    def __init__(self, code, note=None):
        super().__init__(code)
        self.code = code
        self.note = note


def shown(text):
    """Text of any origin for the terminal on one line: every control character becomes a space."""
    return streams.CONTROL.sub(" ", str(text))


def ago(seconds):
    seconds = max(0, int(seconds))
    for limit, unit, size in ((120, "seconds", 1), (7200, "minutes", 60), (172800, "hours", 3600)):
        if seconds < limit:
            return "{} {}".format(seconds // size, unit)
    return "{} days".format(seconds // 86400)


def amount(value):
    return "${:.4f}".format(value)


def exit_text(code, signal_number):
    if code is not None:
        return str(code)
    return "signal {}".format(signal_number) if signal_number else "none"


def mode_lines(mode):
    """The mode as the agent reports it, and on bypass the plain warning (never styled, so it is never dimmed)."""
    text = "permission mode (as the agent reports it): {}\n".format(mode)
    return text + WARNING + "\n" if mode in streams.BYPASS_MODES else text


def status_line(row, now):
    """What a lane that does not run shows: the idle display for a lane between two turns, as `lane status` has it (state
    `waiting`), and the state for any other lane."""
    if row["state"] != "waiting":
        return "not running: state {}".format(row["state"])
    waiting = mail.queued(row["mail"])
    line = "idle: run {} ended with reason {}, exit code {}, {} ago; messages waiting: {}".format(
        row["run"], row["reason"], "none" if row["exit_code"] is None else row["exit_code"],
        ago(now - lanecmd.parse_time(row["state_at"])), waiting)
    return line + "; type /turn to start a turn for them" if waiting else line


def line_editor_is_libedit(module):
    """True when the line editor of this interpreter is libedit with its emulation of readline (the interpreters of
    macOS). Python 3.13 and later say it in `backend` ("editline"); every version says it in the docstring of the module
    ("libedit") and in `_READLINE_LIBRARY_VERSION` ("EditLine wrapper")."""
    if getattr(module, "backend", None) == "editline":
        return True
    doc = getattr(module, "__doc__", None)
    if isinstance(doc, str) and "libedit" in doc:
        return True
    return str(getattr(module, "_READLINE_LIBRARY_VERSION", "")).startswith("EditLine")


def typed_buffer(module):
    """What the line editor `module` says is typed, or None when that cannot be told: there is no line editor, or it is
    libedit, whose `get_line_buffer()` is the buffer of its own line, which it does not clear between two lines (the
    bytes of a line that was entered before are in it at an empty prompt), or it fails."""
    if module is None or line_editor_is_libedit(module):
        return None
    try:
        return module.get_line_buffer()
    except Exception:  # noqa: BLE001 -- a handler of a key must not fail: a buffer that cannot be read is not known
        return None


def typed_state(module):
    """What `typed_buffer` says, in three answers: True when the line editor says that a line is being typed, False when it
    says that the line is empty, None when that cannot be told."""
    buffer = typed_buffer(module)
    return None if buffer is None else buffer != ""


def hint_text(discarded, typed):
    """The hint of a Ctrl-C that stops nothing, with what is true of the line before it. `discarded`: the key came at the
    prompt, and discarded what was there. `typed` is `Attach.something_typed`: True (a line was typed, or a message goes
    on), False (the line editor says that the line was empty), None (it cannot tell). Where it cannot tell, whatever was
    typed was discarded, which holds whether a line was typed or not; where nothing was typed, or nothing was discarded,
    nothing is said of a line."""
    if not discarded or typed is False:
        return HINT
    return ("the line was discarded; " if typed else "anything typed was discarded; ") + HINT


def read_items(name, text):
    """The items of one log line, or None when the reader raised, which no line should make it do."""
    try:
        return streams.read(name, text)
    except Exception:  # noqa: BLE001 -- the guard of the design: the caller says so once for the turn
        return None


def iter_lines(fd, start, end):
    """The lines of the log between two offsets, decoded as UTF-8 with replacement; a last line without a newline counts."""
    carry = b""
    offset = start
    while offset < end:
        data = os.pread(fd, min(CHUNK, end - offset), offset)
        if not data:
            break
        offset += len(data)
        parts = (carry + data).split(b"\n")
        carry = parts.pop()
        for part in parts:
            yield part.decode("utf-8", "replace")
    if carry:
        yield carry.decode("utf-8", "replace")


def open_log(session, lane):
    """The lane's log, opened through the lane's directory without following a link."""
    directory = session.state.open_lane(lane) if session.state is not None else None
    if directory is None:
        raise Refused("lane {} has no directory in the state directory".format(lane))
    try:
        return fsguard.open_child(directory, lanecmd.LOG, "the lane's log")
    finally:
        os.close(directory)


def run_range(session, lane, run, size):
    """(start, end) of the run's part of the log, from the run record of its launch; the end is the start of the next run,
    or the size of the log, when the run has none recorded. None when the run or its range is not known."""
    started = {item["payload"]["run"]: item["payload"] for item in session.store.lane_events(lane, ("lane.started",))}
    if run not in started:
        return None
    record = session.record(lane, started[run]["launch"])
    log = record.get("log") if record else None
    if not log or not isinstance(log.get("start"), int):
        return None
    end = log.get("end")
    if not isinstance(end, int):
        following = started.get(run + 1)
        after = session.record(lane, following["launch"]) if following else None
        later = after.get("log") if after else None
        end = later["start"] if later and isinstance(later.get("start"), int) else size
    return log["start"], end


class Console:
    """The one writer of the terminal. While a line is being typed, what it is given is held, and printed when the line has
    been entered or discarded; when none is being typed and the prompt is shown, it goes above the prompt, which is shown
    again. It never redraws a line that is being typed: a line in the terminal's own line mode belongs to the terminal.
    Without `readline` attach cannot see a typed line and holds nothing back."""

    def __init__(self, out, readline):
        self.out = out
        self.readline = readline
        self.lock = threading.Lock()
        self.pending = ""  # given, not yet written: held while a line is typed, or the unfinished last line
        self.prompt = None  # the prompt on the screen while the line input waits, else None
        self.next_prompt = PROMPT
        self.fresh = True  # the cursor is at the start of a line
        self.dead = False  # the terminal has gone

    def typing(self):
        """True only while the line editor says that a line is being typed. Where it cannot tell (libedit, no line editor,
        a failure: `typed_state` is None) nothing counts as typed, so that output is never held back for good on the stale
        buffer of libedit, and a buffer that cannot be read does not raise in the write of the console."""
        return typed_state(self.readline) is True

    def put(self, text):
        if not text or self.dead:
            return
        try:
            self.out.write(text)
            self.out.flush()
        except (OSError, ValueError):
            self.dead = True
            self.silence()
        else:
            self.fresh = text.endswith("\n")

    def silence(self):
        """The terminal is gone: nothing goes to it any more, and the flush that the interpreter makes at its end finds the
        null device and not a closed terminal."""
        try:
            null = os.open(os.devnull, os.O_WRONLY)
            os.dup2(null, 1)
            os.dup2(null, 2)
            os.close(null)
        except OSError:
            pass  # nothing more can be done for a terminal that is gone

    def show(self):
        """Write what may be written now. The caller holds the lock."""
        if self.prompt is None:
            self.put(self.pending)
            self.pending = ""
        elif self.pending and not self.typing():
            done, newline, rest = self.pending.rpartition("\n")
            if newline:
                # Start a new line, step back up onto the prompt's line and erase it: a terminal shows the output where
                # the prompt was, and a recording of the session (a pipe, a typescript), which keeps what a terminal
                # would have erased, has the output on lines of its own.
                self.put("\n\x1b[A\r\x1b[K" + done + "\n" + self.prompt)
                self.pending = rest

    def emit(self, text):
        with self.lock:
            self.pending += text
            self.show()

    def flush(self):
        """The follower calls this on every pass: a line that has been discarded lets the held output go."""
        with self.lock:
            self.show()

    def end_line(self):
        """Held output goes out whole, and the cursor is moved to the start of a line if it is not at one (after Ctrl-C or
        the end of the input at the prompt)."""
        with self.lock:
            self.put(self.pending)
            self.pending = ""
            if not self.fresh:
                self.put("\n")

    def before_prompt(self, prompt):
        """Held output goes out whole and the cursor is at the start of a line; then the line input prints the prompt."""
        self.next_prompt = prompt
        self.end_line()

    def shown(self):
        """The prompt is on the screen (the hook of `readline`); output that came meanwhile goes above it."""
        with self.lock:
            self.prompt = self.next_prompt
            self.fresh = False
            self.show()

    def hidden(self, fresh):
        """The line input has returned; the cursor is at the start of a line when the line was entered."""
        with self.lock:
            self.prompt = None
            self.fresh = fresh


class Follower:
    """Follows the lane in a thread of its own: it reads the log every 0.2 seconds and the store every 0.5 seconds, shows a
    turn that goes on, and at its end the rest of its range, one line for the end and the idle display. A turn is not
    found by its being live at a look: the follower keeps the number of the last run it has shown, so that a run that
    began and ended between two looks is shown too, after the fact. It opens its own session of the store, which only
    this thread uses."""

    def __init__(self, view):
        self.view = view
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, name="attach-follower", daemon=True)
        self.session = None
        self.fd = None
        self.chunks = []
        self.troubled = float("-inf")
        self.seen = view.seen  # the last run that was shown, or was over before attach began
        self.current = None  # the run that is followed
        self.offset = 0
        self.limit = None
        self.carry = b""
        self.open_line = False  # the last thing written was a piece of an answer without its newline
        self.streamed = ""  # answer text shown as pieces, to tell the whole line that repeats it
        self.result = None
        self.noted = False
        self.key_noted = False  # the notice of a counted key has been written for the lane command that is running

    def start(self):
        self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread.is_alive():
            self.thread.join(JOIN_SECONDS)

    def run(self):
        next_store = 0.0
        try:
            while True:
                try:
                    now = time.monotonic()
                    if now >= next_store:
                        next_store = now + STORE_POLL
                        self.look()
                    self.read()
                except Exception as error:  # noqa: BLE001 -- the view goes on: a traceback would lose the session on screen
                    self.trouble(error)
                self.key_notice()
                self.push()
                self.view.console.flush()
                if self.stop.wait(LOG_POLL):
                    break
        finally:
            self.drop()

    def drop(self):
        """Close what this thread opened; the store is opened again at the next look."""
        session, self.session = self.session, None
        if session is not None:
            try:
                session.close()
            except (sqlite3.Error, OSError):
                pass  # the view is ending or looking again: a store that cannot be closed has nothing left to lose
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def trouble(self, error):
        self.drop()
        now = time.monotonic()
        if now - self.troubled >= TROUBLE_SECONDS:
            self.troubled = now
            self.line_start()
            self.out(shown("note: the view could not read the lane: {}: {}".format(type(error).__name__, error)) + "\n")

    # Output, in pieces that are given to the console once for each pass.

    def out(self, text):
        self.chunks.append(text)

    def push(self):
        if self.chunks:
            text, self.chunks = "".join(self.chunks), []
            self.view.console.emit(text)

    def line_start(self):
        if self.open_line:
            self.out("\n")
            self.open_line = False

    def key_notice(self):
        """Once for each lane command that a key is counted in: the key has been seen, and a second one leaves attach. The
        handler of the key cannot write (it does no I/O and takes no lock), so this thread does."""
        view = self.view
        if view.working and view.during:
            if not self.key_noted:
                self.key_noted = True
                self.line_start()
                self.out(KEY_NOTICE + "\n")
        else:
            self.key_noted = False

    # The store: which run goes on, and when it has ended.

    def look(self):
        view = self.view
        if self.session is None:
            self.session = lanecmd.Session(view.configuration, view.zones)
        else:
            self.session.refresh()
        row = self.session.row(view.lane)
        if row is None:
            return
        if self.current is not None and (row["run"] != self.current or not row["running"]):
            self.finish(row)
        # A run that began and ended between two looks at the store is shown after the fact, each in its turn; then the
        # live run, if there is one, is followed.
        while self.current is None and self.seen < row["run"]:
            if not self.begin(self.seen + 1, row):
                break
            if self.current != row["run"] or not row["running"]:
                self.finish(row)

    def begin(self, run, row):
        """Follow this run from the start of its range of the log. False for a live run whose run record does not say yet
        where its output begins (the next look tries again). A run that is over and has no range recorded is shown by
        its end alone."""
        lane = self.view.lane
        live = row["running"] and row["run"] == run
        if self.fd is None:
            self.fd = open_log(self.session, lane)
        span = run_range(self.session, lane, run, os.fstat(self.fd).st_size)
        if span is None and live:
            return False
        self.current = self.seen = run
        self.offset, self.limit = (span[0], None) if span else (0, 0)
        self.carry = b""
        self.open_line = False
        self.streamed = ""
        self.result = None
        self.noted = False
        self.out("following run {} (live)\n".format(run) if live else "run {} had ended when attach looked\n".format(run))
        return True

    def finish(self, row):
        """The run has ended: the rest of its range, one line for the end and, when it is the lane's latest run, the idle
        display."""
        run = self.current
        lane = self.view.lane
        ended = None
        for item in self.session.store.lane_events(lane, ("lane.ended",)):
            if item["payload"]["run"] == run:
                ended = item["payload"]
        span = run_range(self.session, lane, run, os.fstat(self.fd).st_size) if self.fd is not None else None
        if span:
            self.limit = span[1]
        earlier = self.earlier_total(run)  # read first: whatever can fail does so before anything is shown
        self.read()
        if self.carry:
            self.show(self.carry.decode("utf-8", "replace"))
            self.carry = b""
        self.line_start()
        latest = row["run"] == run
        if ended is None:
            self.out("run {} ended without an end event (reason {})\n".format(
                run, shown(row["reason"]) if latest else "not known"))
        else:
            self.out(self.end_line(run, ended, earlier) + "\n")
        if latest and not row["running"]:
            self.out(status_line(row, time.time()) + "\n")
        self.current = None

    def earlier_total(self, run):
        """The session's total at the end of the turn before: the cost of the last result line in the earlier run's range of
        the log, or None when that range has none (or the run has no earlier run)."""
        if self.view.stream in LINE_READERS or self.fd is None:
            return None
        span = run_range(self.session, self.view.lane, run - 1, os.fstat(self.fd).st_size)
        if span is None:
            return None
        total = None
        for text in iter_lines(self.fd, span[0], span[1]):
            for item in read_items(self.view.stream, text) or ():
                if item.get("kind") == "result":
                    total = item.get("cost")
        return total

    def end_line(self, run, ended, earlier):
        code = exit_text(ended["exit_code"], ended["signal"])
        seconds = "{:.1f} seconds".format(ended["duration_seconds"])
        if self.view.stream in LINE_READERS:
            return "[run {} | exit {} | {}]".format(run, code, seconds)
        total = self.result["cost"] if self.result else None
        turn = total - earlier if total is not None and earlier is not None and total >= earlier else None
        return "[run {} | exit {} | this turn {} | session {} | {}]".format(
            run, code, "unknown" if turn is None else amount(turn), "unknown" if total is None else amount(total), seconds)

    # The log: every complete line goes through the reader.

    def read(self):
        if self.current is None:
            return
        if self.fd is None:
            if self.session is None:
                return  # the next look opens the store, and then the log
            self.fd = open_log(self.session, self.view.lane)
        while True:
            want = CHUNK if self.limit is None else min(CHUNK, self.limit - self.offset)
            if want <= 0:
                break
            data = os.pread(self.fd, want, self.offset)
            if not data:
                break
            self.offset += len(data)
            parts = (self.carry + data).split(b"\n")
            self.carry = parts.pop()
            for part in parts:
                self.show(part.decode("utf-8", "replace"))

    def show(self, text):
        """One line of the log: through the reader, inside the guard that the design asks for."""
        try:
            for item in streams.read(self.view.stream, text):
                self.render(item)
        except Exception:  # noqa: BLE001 -- a reader that raises anyway is caught, with one note for the turn
            if not self.noted:
                self.noted = True
                self.line_start()
                self.out("note: the stream reader failed on a line of this turn; the line was skipped\n")

    def render(self, item):
        kind = item["kind"]
        if kind == "answer":
            self.answer(item)
        elif kind == "tool":
            self.line_start()
            self.out(item["label"] + "\n")
        elif kind == "mode":
            self.mode(item["mode"])
        elif kind == "result":
            self.request_result(item)
        elif kind == "notice":
            self.line_start()
            self.out("notice: " + item["text"] + "\n")
        elif kind == "raw":
            self.line_start()
            self.out(item["text"] + "\n")

    def answer(self, item):
        text = item["text"]
        if item.get("streamed") is False:
            # A whole line of the answer: dropped when the pieces of it were shown already, else shown as a block.
            found = self.streamed.find(text)
            if found >= 0:
                self.streamed = self.streamed[found + len(text):]
                return
            self.line_start()
            self.out(text if text.endswith("\n") else text + "\n")
        elif self.view.stream in LINE_READERS:
            self.out(text + "\n")
        else:
            self.streamed = (self.streamed + text)[-STREAMED_KEPT:]
            self.out(text)
            if text:
                self.open_line = not text.endswith("\n")

    def mode(self, value):
        value = shown(value)  # the reader leaves the mode as the agent wrote it
        if value != self.view.mode_shown:
            self.view.mode_shown = value
            self.line_start()
            self.out(mode_lines(value))

    def request_result(self, item):
        """The result line of a request: its denials, each on a line of its own before the end of the turn."""
        self.result = item
        self.streamed = ""
        self.line_start()
        for label in item["denials"]:
            self.out(label + "\n")
            if not self.view.denial_noted:
                self.view.denial_noted = True
                self.out(NOTICE + "\n")
        if item["error"]:
            self.out("note: the result line says that the request ended in an error.\n")


class Attach:
    """The view and the keyboard of one lane."""

    def __init__(self, configuration, zones, lane):
        self.configuration = configuration
        self.zones = zones
        self.lane = lane
        self.stream = "text"
        self.readline = None
        self.console = None
        self.follower = None
        self.prefill = ""  # a refused line that the next prompt holds for editing
        self.seen = 0  # the last run that was over when attach began; a run that is live then is shown from its start
        self.started = set()  # the runs that this attach started
        self.keys = 0  # Ctrl-C keys that came while attach was busy and could not act on them yet
        self.raises = False  # a key raises KeyboardInterrupt only while this is true (the prompt, the wait of a stop)
        self.working = False  # a lane command of a typed line runs in the main thread (`lane_command`)
        self.kind = None  # which one: "send" (lane send) or "turn" (lane turn)
        self.during = 0  # the keys counted since that command began
        self.first = 0.0  # the monotonic time of the first of them
        self.message = None  # the number of the message of the line being sent, once it is stored
        self.typed = False  # what a key found at the prompt: True typed (or a message goes on), False empty, None unknown
        self.continued = False  # the lines of a message that goes on (a line that ends with a backslash) are being read
        self.mode_shown = None
        self.denial_noted = False

    def say(self, text):
        self.console.emit(text + "\n")

    # Start: what is shown before the first prompt.

    def setup_terminal(self):
        readline = None
        if sys.stdin is not None and sys.stdin.isatty() and sys.stdout.isatty():
            try:
                import readline
            except ImportError:
                readline = None
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(errors="replace")
        self.readline = readline
        self.console = Console(sys.stdout, readline)
        if readline is not None:
            set_hook = getattr(readline, "set_pre_input_hook", None) or readline.set_startup_hook
            set_hook(self.at_prompt)

    def scan_mode(self, session, row):
        """The permission mode of the latest init line found in the log, or None. The runs are looked at from the latest back,
        and the first range with a mode in it decides."""
        if self.stream in LINE_READERS:
            return None
        fd = open_log(session, self.lane)
        try:
            size = os.fstat(fd).st_size
            for run in range(row["run"], 0, -1):
                span = run_range(session, self.lane, run, size)
                if span is None:
                    continue
                found = None
                for text in iter_lines(fd, span[0], span[1]):
                    for item in read_items(self.stream, text) or ():
                        if item.get("kind") == "mode" and isinstance(item.get("mode"), str):
                            found = shown(item["mode"])
                if found is not None:
                    return found
        finally:
            os.close(fd)
        return None

    def start(self):
        """Find the lane and print the lane, its state, the mode, and the idle display or the live run's name. A lane the
        configuration does not know is refused before anything else is done."""
        session = lanecmd.Session(self.configuration, self.zones)
        try:
            row = lanecmd.known_row(session, self.lane)
            self.seen = row["run"] - 1 if row["running"] else row["run"]
            payload, _ = lanecmd.latest(session, self.lane)
            runner = self.configuration.data["runners"].get(payload["runner"] if payload else None, {})
            self.stream = runner.get("stream", "text")
            self.setup_terminal()
            identity = payload.get("session_id") if payload else None
            self.say(shown("lane {}: state {}, run {}, session {}, runner {}, model {}".format(
                self.lane, row["state"], row["run"], identity or "none", row["runner"], row["model"])))
            if not lanes.turn_based(row):
                self.say("this lane is not turn-based: attach is a view only here, and a typed line is refused by lane send")
            try:
                mode = self.scan_mode(session, row)
            except Refused:
                mode = None  # no log yet
            if mode is None:
                self.say("permission mode: not reported yet")
            else:
                self.mode_shown = mode
                self.console.emit(mode_lines(mode))
            if not row["running"]:
                self.say(status_line(row, time.time()))
        finally:
            session.close()

    def at_prompt(self):
        """The hook of `readline`, called when the prompt is on the screen: a refused line is put back for editing. The line
        editor clears an exception that is raised here, so a key that does raise here (`pressed` keeps it from doing so)
        is counted, and the prompt is armed again for the next one."""
        try:
            if self.prefill:
                self.readline.insert_text(self.prefill)
                self.readline.redisplay()
                self.prefill = ""
            self.console.shown()
        except KeyboardInterrupt:
            self.keys += 1
        finally:
            self.raises = True

    def leave(self, number, frame):
        raise Leave(128 + number)

    def pressed(self, number, frame):
        """The handler of SIGINT for the whole life of attach. A key raises KeyboardInterrupt only where `raises` says so
        (at the prompt, and while a stop is waited for), and the first key switches `raises` off before it raises, so that
        a second key that follows at once, a double tap, is counted and does not raise a second exception into whatever
        attach is doing about the first. Anywhere else a key is only counted: a lane command (a line being sent, a turn
        being started, a stop being asked for) is never cut in two by it, and no key is lost. `keyboard` acts on the
        counted keys when the command has returned. The line editor clears an exception that is raised in the hook that
        attach gives it (`at_prompt`), and with it the key and the `raises` that was switched off for it, so a key that
        comes while that hook runs is only counted too: the next key raises as before. While a lane command of a typed
        line runs (`lane_command`), a key that comes KEY_DELAY seconds or more after the first one counted in it leaves
        attach: the command is slow or blocked on a lock, and this is the way out. A key sooner than that is a double tap
        (a person who regrets a line), and is only counted: both keys act as one Ctrl-C when the command returns. The
        stop path is not such a command: there a key is only counted until the request has gone out. The handler
        writes nothing and takes no lock; it reads the monotonic clock."""
        if self.raises and not self.in_hook(frame):
            self.typed = self.something_typed()
            self.raises = False
            raise KeyboardInterrupt
        self.keys += 1
        if self.working:
            now = time.monotonic()
            if not self.during:
                self.first = now
            self.during += 1
            if now - self.first >= KEY_DELAY:
                raise Leave(130, self.leaving_note())

    def something_typed(self):
        """Whether a Ctrl-C discards something, in three answers. True when it certainly does: the lines of a message that
        goes on have been read, or the line editor says that a line is being typed. False when the line editor says that
        the line is empty. None when that cannot be told (`typed_buffer`: no line editor, libedit, a failure), which is
        no False: `hint_text` then says what holds in both cases, and never claims a discard that may not have been."""
        if self.continued:
            return True
        return typed_state(self.readline)

    def leaving_note(self):
        """What is said when a key leaves attach in a lane command: what is not known, and never that a turn began or was
        stopped. In `lane turn` a turn may be starting, and it was not stopped, so the line says how to stop it."""
        if self.kind != "turn":
            return "leaving attach; the lane command that was running may not be finished; see lane status"
        what = "a turn for message {}".format(self.message) if self.message is not None else "a turn"
        return ("leaving attach; {} may be starting, and it was not stopped: see lane status, and lane stop --lane {} "
                "stops it".format(what, self.lane))

    @staticmethod
    def in_hook(frame):
        """True when the frame that a signal interrupted is the hook of the line editor, or was called from it."""
        while frame is not None:
            if frame.f_code is Attach.at_prompt.__code__:
                return True
            frame = frame.f_back
        return False

    def main(self):
        self.start()
        previous = {}
        self.follower = Follower(self)
        try:
            for number, handler in ((signal.SIGHUP, self.leave), (signal.SIGTERM, self.leave),
                                    (signal.SIGINT, self.pressed)):
                previous[number] = signal.signal(number, handler)
            self.follower.start()
            return self.keyboard()
        except Leave as leaving:
            if leaving.note:
                self.say(leaving.note)
            return leaving.code
        finally:
            for number in previous:
                signal.signal(number, signal.SIG_IGN)  # a second signal while attach is leaving changes nothing
            self.follower.close()
            self.console.end_line()
            with self.console.lock:
                self.console.dead = True  # a follower that is still in a long pass when attach returns writes nothing
            for number, handler in previous.items():
                signal.signal(number, handler)

    # The keyboard.

    def read_line(self, prompt):
        self.console.before_prompt(prompt)
        entered = False
        self.raises = True  # a key discards the line being typed, as it does in any terminal program
        try:
            if self.keys:
                # A key came before the prompt was armed (while the held output was being written): it is a Ctrl-C at an
                # empty prompt. Nothing has been drawn, so the cursor is at the start of a line, and nothing is typed
                # (the lines of a message that goes on, if there are any, are discarded).
                self.keys = 0
                self.typed = self.continued
                entered = True
                raise KeyboardInterrupt
            text = input(prompt)
            self.raises = False
            entered = True
            return text
        finally:
            self.raises = False
            self.console.hidden(entered)

    def read_message(self):
        """A message: a line, and the lines after it while a line ends with a backslash. None at the end of the input."""
        lines = []
        prompt = PROMPT
        self.continued = False
        while True:
            try:
                text = self.read_line(prompt)
            except (EOFError, OSError):
                time.sleep(EOF_GRACE)  # a closed terminal reads as the end of the input as well: its SIGHUP gets here first
                return None
            except UnicodeError:
                self.say("not sent: the line is not valid UTF-8 text")
                return ""
            if text.endswith("\\"):
                lines.append(text[:-1])
                prompt = CONTINUED
                self.continued = True
                continue
            lines.append(text)
            self.continued = False
            return "\n".join(lines)

    def keyboard(self):
        """Read messages and commands until something leaves; the exit code. A key that was counted while attach was busy
        (a line being sent and its turn started, for one) is acted on first, as a Ctrl-C that discarded no line."""
        while True:
            code = None
            try:
                if self.keys:
                    self.keys = 0
                    code = self.interrupted(False)
                else:
                    text = self.read_message()
                    if text is None:
                        return 0
                    code = self.handle(text)
            except KeyboardInterrupt:
                code = self.interrupted(True)
            if code is not None:
                return code

    def handle(self, text):
        """A message or a command. An exit code when it leaves attach, else None."""
        self.message = None
        if text == "":
            return None
        if text.startswith("/"):
            return self.command(text.rstrip())
        self.send(text)
        return None

    def command(self, word):
        if word == "/exit":
            return 0
        if word == "/stop":
            return self.interrupted(False)
        if word == "/turn":
            self.start_turn(None)
        elif word == "/help":
            self.say(HELP)
        elif credentials.find_in_text(word):
            # A credential shape is never repeated, not even in the refusal of a line that is no command.
            self.say("not sent: the line is not a command (type /help); it holds a credential shape, which is not "
                     "repeated")
        else:
            self.say("not sent: {} is not a command (type /help)".format(shown(word)[:60]))
        return None

    def lane_command(self, kind, function, *arguments):
        """Run a lane command of a typed line ("send" or "turn") in the main thread. While it runs, the first key that is
        counted is noted on the screen by the follower, and a key KEY_DELAY seconds or more after it leaves attach
        (`pressed`)."""
        self.kind = kind
        self.during = 0
        self.working = True
        try:
            return function(*arguments)
        finally:
            self.working = False

    def call(self, function, *arguments):
        """The code of lane send; a file that vanishes under it is a refusal, as lane commands report it."""
        try:
            return self.lane_command("send", function, *arguments)
        except FileNotFoundError as error:
            raise Refused("{} disappeared while attach ran; nothing more was done".format(
                error.filename or "a file or directory")) from None

    def problem(self, error):
        prefix = error.prefix if isinstance(error, LauncherError) else type(error).__name__
        self.say(shown("note: {}: {}".format(prefix, error)))

    def send(self, text):
        """The typed line is a message: stored with the code of lane send, then a turn is asked for."""
        try:
            data = text.encode("utf-8")
        except UnicodeEncodeError:
            self.not_sent(text, "the line is not valid UTF-8 text")
            return
        try:
            result = self.call(lanecmd.send_message, self.configuration, self.zones, self.lane,
                               mail.check_sender(SENDER), data)
        except Refused as error:
            self.not_sent(text, str(error))
            return
        except (LauncherError, sqlite3.Error, OSError) as error:
            self.problem(error)
            return
        self.message = result["sequence"]
        self.say("message {} sent".format(result["sequence"]))
        self.start_turn(result["sequence"])

    def not_sent(self, text, reason):
        """A line that was refused: the reason, and the line again, held at the next prompt for editing. A line with a
        credential shape in it is not printed again (the failure table says a credential shape is never repeated)."""
        self.say("not sent: " + shown(reason))
        if credentials.find_in_text(text):
            return
        self.say("your line: " + shown(text))
        if "\n" not in text and self.readline is not None:
            self.prefill = text

    def start_turn(self, sequence):
        """lane turn. When a turn is live it is refused by its own check: the message just sent (`sequence`) waits for the
        next turn, which attach does not start."""
        arguments = argparse.Namespace(action="turn", lane=self.lane, idle=False, account=None, budget=None, message=None)
        try:
            result = self.lane_command("turn", lanecmd.run, self.configuration, self.zones, arguments)
        except Refused as error:
            if sequence is None:
                self.say("no turn started: " + shown(error))
            else:
                self.say("message {} queued: {}".format(sequence, shown(error)))
                self.say("it goes with the next turn; attach does not start that turn (type /turn once the live turn "
                         "has ended)")
            return
        except (LauncherError, sqlite3.Error, OSError) as error:
            self.problem(error)
            return
        if not result.get("started"):
            self.say("no turn started: no message waits")
            return
        self.started.add(result["run"])
        self.say("turn started: run {} (messages {})".format(result["run"], ", ".join(map(str, result["turn"]["mail"]))))

    # The stop path.

    def live_run(self):
        """The number of the lane's run that goes on now, or None."""
        session = lanecmd.Session(self.configuration, self.zones)
        try:
            row = session.row(self.lane)
            return row["run"] if row is not None and row["running"] else None
        finally:
            session.close()

    @staticmethod
    def supervisor_gone(wait):
        """True when the supervising process of a stop that has been requested is no longer alive (`wait` is what
        `lanecmd.stop_request` returned: its fourth part is the run record). False when it cannot be told."""
        try:
            return wait is not None and not runrecord.supervisor_alive(wait[3])
        except (LauncherError, sqlite3.Error, OSError):
            return False

    def interrupted(self, discarded):
        """Ctrl-C, and `/stop`, which does what the first Ctrl-C does. With no turn live nothing is stopped; with a turn live
        that this attach started, that run is stopped; with a turn live that it did not start, attach leaves and stops
        nothing. An exit code when attach leaves, else None."""
        try:
            live = self.live_run()
        except (LauncherError, sqlite3.Error, OSError):
            live = None
        if discarded:
            self.console.end_line()  # the line that was typed is left behind, and the cursor is not at the start of a line
        if live is None:
            self.say(hint_text(discarded, self.typed))  # what it says of the line is what is known of it
            return None
        if live in self.started:
            return self.stop(live)
        self.say("leaving attach: run {} was not started by this attach, and goes on".format(live))
        return 130

    def stop(self, run):
        """The code of `lane stop --lane L --run N`, in its two parts: it asks the supervising process, which stops the
        run's processes one by one, and waits for the end. The request (the supervising process is signalled, checked by
        its recorded identity) is made with a key only counted: a key that came before it had gone out lets it go out all
        the same, and then leaves with 130. The wait is made with a key that leaves, and a leave then only stops the
        waiting: the request stands."""
        self.say("stopping run {}".format(run))
        arguments = argparse.Namespace(action="stop", lane=self.lane, run=run)
        session = None
        wait = None
        try:
            session = lanecmd.Session(self.configuration, self.zones)
            result, wait = lanecmd.stop_request(self.configuration, session, arguments)
            if wait is not None:
                self.raises = True  # from here a key leaves
                if self.keys:
                    raise KeyboardInterrupt  # a key came before the request had gone out
                self.say("stop requested for run {}; press Ctrl-C again to stop waiting (the request stands)".format(run))
            result = lanecmd.stop_finish(session, result, wait)
        except KeyboardInterrupt:
            # A key raises here only after the request has gone out (`raises` is switched on after it). If the supervising
            # process has died meanwhile, nobody finishes the stop: attach may have cut its own removal of the run's
            # processes short, and says so.
            if self.supervisor_gone(wait):
                self.say("leaving attach; the supervising process has gone, so the stop may be incomplete: "
                         "run lane stop --lane {}".format(self.lane))
            else:
                self.say("leaving attach; the stop request stands, and the supervising process finishes the stop")
            return 130
        except lanecmd.NotGoingOn:
            # The request found that run N is not going on: the key came as the turn ended, or another run has begun
            # since. Nothing was wrong, and nothing is left. Only these two refusals say so: any other refusal, and any
            # that comes after the request has gone out, is the command's own and is reported as it is (below).
            self.say("run {} had ended; nothing was stopped".format(run))
            return None
        except LauncherError as error:
            for text in str(error).splitlines() or [""]:
                sys.stderr.write("{}: {}\n".format(error.prefix, text))
            sys.stderr.flush()
            return error.exit_code
        except (sqlite3.Error, OSError) as error:
            self.problem(error)
            return None
        finally:
            self.raises = False
            self.keys = 0
            if session is not None:
                session.close()
        self.say("run {} ended with reason {}; survivors {}".format(run, result["reason"] or "none", result["survivors"]))
        return None


def run(configuration, zones, arguments):
    """lane attach; the exit code."""
    return Attach(configuration, zones, lanecmd.lane_name(arguments.lane)).main()
