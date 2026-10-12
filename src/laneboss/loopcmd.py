"""`laneboss lane loop`: the process that decides when a turn starts (docs/architecture.md, "The `lane loop` command").

The loop acts only on the lanes declared turn-based (`lane start --turns`, or `lane adopt`: the row has `mail` with
`turn_based` true) and that are neither abandoned nor cleaned, and only as declared: a turn when mail waits, a turn when
the lane has been idle for its `idle_seconds`, and the wait after an end that was not good. It starts a turn by the
function that `lane turn` uses (lanecmd.turn), and it never accepts, merges, cleans, marks, retries or stops anything and
never signals a process: a turn that it starts belongs to its own supervising process, in the lane's own tmux session.
Every decision is an event (loop.started, loop.stopped, loop.turn and loop.skipped); they are checked at append
(lanes.check_loop) and nowhere else, and the loop reads only the ones that are in that form.

One loop runs for a configuration, under an exclusive lock on STATE_DIR/loop.lock that it asks for without blocking (ten
tries, 50 ms apart, so that the instant lock of a status does not refuse a loop that starts) and holds for as long as it
lives, so that the kernel frees it whatever ends the loop. STATE_DIR/loop.json, written whole under the
lock, names the loop's process by its identity (process id and start time) and keeps the latest failure of a pass
(`last_error`); it is believed only while a process with that identity lives. STATE_DIR/loop.log holds the loop's own
messages, a failure of a pass among them. The turns that the loop starts get the
environment that it captured when it started. It is held in memory only: it is never written to an event, to a log, to
loop.json or to any file, and it reaches a turn through the FIFO of `lane start`, which keeps nothing once it is read.
"""

import argparse
import errno
import fcntl
import json
import os
import select
import signal
import sqlite3
import sys
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone

from . import config, credentials, events, fsguard, lanecmd, lanes, mail, multiplexer, processes, runrecord
from .errors import LauncherError, Refused
from .identity import PROGRAM
from .jsonutil import output
from .protocol import load_protocol
from .statedir import StateDir

LOCK = "loop.lock"
RECORD = "loop.json"
LOG = "loop.log"
# The session of a detached loop. A lane's session is named by lanes.session_name() from a lane name, which the lane
# grammar limits to lower-case letters, digits, `.`, `_` and `-`: the character `+` is not among them, so no lane's
# session can have this name.
SESSION = "laneboss+loop"
DEFAULT_POLL_SECONDS = 10
DEFAULT_BACKOFF_SECONDS = 300
DEFAULT_LIMIT_BACKOFF_SECONDS = 1800
STORE_WAIT_SECONDS = 10
STOP_WAIT_SECONDS = 30
LOCK_TRIES = 10
LOCK_TRY_SECONDS = 0.05
RECORD_BYTES = 64 * 1024
MESSAGE_CHARACTERS = 1000
SLICE = 0.1


def moment(value):
    """A timestamp of the launcher as a datetime."""
    return datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)


def stamp(value):
    """A datetime as the launcher writes a timestamp."""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def when_of(event):
    """The moment an event happened: its occurred_at, else its recorded_at."""
    return moment(event["occurred_at"] or event["recorded_at"])


def first_line(error):
    return (str(error).splitlines() or [""])[0]


def describe(error):
    """What a pass that could not be made says in loop.log: one line, never anything of the loop's environment."""
    if isinstance(error, sqlite3.Error):
        return "the store could not be read or written ({}); the pass is tried again".format(error)
    if isinstance(error, FileNotFoundError):
        return "{} disappeared; the pass is tried again".format(error.filename or "a file or directory")
    return first_line(error)


def screened(text):
    """A line that the loop writes or shows, or `(withheld)` when it looks like a credential: no message repeats a value
    that looks like a credential, and the store would refuse an event that holds one."""
    return "(withheld)" if credentials.find_in_text(text) else text


def detail_of(error):
    """The first line of a refusal as a skip carries it: at most 200 characters, and `(withheld)` when it looks like a
    credential."""
    line = "".join(" " if ord(character) < 32 or ord(character) == 127 else character
                   for character in first_line(error)).strip()
    return (screened(line) or "refused")[:lanes.DETAIL_CHARACTERS]


# The sentence `lane turn` refuses a turn with when no account has room (lanecmd.continue_lane, the design's "No room
# means no turn"): the loop owns the reason `no-room` for that case, and the command's own reason — what the sentence
# carries after this mark — is the skip's `detail`. It is the only thing that tells that refusal apart from every other
# one, and the loop records every other refusal as `refused`.
NO_ROOM_MARK = ": no turn starts, because "


def no_room_of(lane, error):
    """The room command's own reason when `error` is the refusal of a turn that no account had room for, else None."""
    text = first_line(error)
    prefix = "lane " + lane + NO_ROOM_MARK
    return text[len(prefix):] if text.startswith(prefix) else None


def print_json(value):
    sys.stdout.write(output(value) + "\n")
    sys.stdout.flush()


def settings_of(configuration):
    """poll_seconds, backoff_seconds and limit_backoff_seconds of [turns], with the defaults of the design."""
    table = configuration.data.get("turns", {})
    return (table.get("poll_seconds", DEFAULT_POLL_SECONDS), table.get("backoff_seconds", DEFAULT_BACKOFF_SECONDS),
            table.get("limit_backoff_seconds", DEFAULT_LIMIT_BACKOFF_SECONDS))


# What there is to decide about a lane, from its row and its events alone.

def declared(row):
    """A lane the supervisor declared turn-based and that is neither abandoned nor cleaned."""
    queue = lanes.mail_of(row)
    return queue is not None and queue["turn_based"] and row["state"] != "abandoned" and not row["cleaned"]


def due(row, now):
    """What there is to start for a lane that is not running: `mail` when a message waits or has returned, else `idle`
    when the lane has an idle interval and has been idle for it (counted from its last state change), else None."""
    queue = row["mail"]
    if mail.queued(queue):
        return "mail"
    seconds = queue["idle_seconds"]
    if seconds is not None and row["state_at"] is not None and now >= moment(row["state_at"]) + timedelta(
            seconds=seconds):
        return "idle"
    return None


def held(skip, now, backoff):
    """True while the lane's latest skip is a refusal or a no-room wait whose hold is going and ends within `backoff`
    seconds from now. A loop holds a lane for backoff_seconds after a refused attempt and after a no-room skip alike
    (the design's "for `refused` and `no-room`, `backoff_seconds` after the skip"), so the lane is not looked at again,
    and the same wait is not recorded again, on the passes that find the hold; a hold that lies further ahead than
    `backoff` (appended by hand, written while the clock was wrong, or written before backoff_seconds was lowered)
    counts as over, and the lane is tried at the next pass."""
    if skip is None or skip["reason"] not in ("refused", "no-room") or skip["until"] is None:
        return False
    return now < moment(skip["until"]) <= now + timedelta(seconds=backoff)


def closing(session, lane):
    """(name, event) of the lane's latest closing event (lane.ended, lane.lost or lane.gone), or None."""
    found = []
    for name in lanes.CLOSING:
        event = session.last(lane, "lane." + name)
        if event is not None:
            found.append((event["seq"], name, event))
    if not found:
        return None
    _, name, event = max(found, key=lambda item: item[0])
    return name, event


def wait_of(session, lane, backoff, limit_backoff):
    """The wait that the lane's latest closing event makes: (until, {"run", "reason"}), or None when that end was good (a
    run that ended with reason exit, exit code 0 and a prompt written whole) or the lane has no end. The time and the
    reason are the event's own, so a loop that is started again waits exactly as the one before it would have."""
    end = closing(session, lane)
    if end is None:
        return None
    name, event = end
    outcome, reason = lanes.settlement(name, event["payload"])
    if outcome == "delivered":
        return None
    seconds = limit_backoff if reason == "limit" else backoff
    return when_of(event) + timedelta(seconds=seconds), {"run": event["payload"]["run"], "reason": reason}


def bad_ends(session, lane):
    """How many turns in a row ended in a way other than reason exit with exit code 0 and a prompt written whole, whoever
    started them, from the lane's events alone: one for each run, by the first closing event the run has."""
    outcomes = {}
    for event in session.store.lane_events(lane, ("lane.ended", "lane.lost", "lane.gone")):
        run = event["payload"]["run"]
        if run not in outcomes:
            outcomes[run] = lanes.settlement(event["kind"][len("lane."):], event["payload"])[0]
    count = 0
    for run in sorted(outcomes, reverse=True):
        if outcomes[run] == "delivered":
            break
        count += 1
    return count


# What the loop reads of its own events: only those in the documented form.

def latest_skip(store, lane):
    """The reason and `until` of the lane's latest loop.skipped event that is in the documented form, written by any
    loop, or None."""
    for event in store.kind_events("loop.skipped", lane):
        if lanes.loop_form(event):
            return {"reason": event["payload"]["reason"], "until": event["payload"]["until"]}
    return None


def started_of(store, loop_id):
    """The loop.started event of this loop, when it is in the documented form, or None."""
    if store is None:
        return None
    for event in store.kind_events("loop.started"):
        if lanes.loop_form(event) and event["payload"]["loop"] == loop_id:
            return event
    return None


def unrecorded_end(store, own):
    """The id of the most recent earlier loop of the configuration whose loop.started has no loop.stopped, else None."""
    stopped = {event["payload"]["loop"] for event in store.kind_events("loop.stopped") if lanes.loop_form(event)}
    for event in store.kind_events("loop.started"):
        loop_id = event["payload"]["loop"] if lanes.loop_form(event) else None
        if loop_id is not None and loop_id != own and loop_id not in stopped:
            return loop_id
    return None


# The lock and the record of the loop.

def valid_failure(value):
    """The `last_error` of loop.json: null, or the time and the text of the latest failure of a pass."""
    return value is None or (isinstance(value, dict) and set(value) == {"at", "message"}
                             and isinstance(value["at"], str) and isinstance(value["message"], str))


def read_record(state):
    """The record in loop.json when it is one (loop, pid, start, since, detached and last_error), else None."""
    try:
        if fsguard.file_info(state.fd, RECORD) is None:
            return None
        data = fsguard.read_descriptor(fsguard.open_child(state.fd, RECORD, RECORD), RECORD_BYTES, RECORD)
        record = json.loads(data.decode("utf-8"))
    except (Refused, UnicodeDecodeError, ValueError):
        return None
    if (not isinstance(record, dict) or set(record) != {"loop", "pid", "start", "since", "detached", "last_error"}
            or not isinstance(record["loop"], str) or lanes.LAUNCH.fullmatch(record["loop"]) is None
            or type(record["pid"]) is not int or record["pid"] < 1 or not isinstance(record["start"], str)
            or not isinstance(record["since"], str) or type(record["detached"]) is not bool
            or not valid_failure(record["last_error"])):
        return None
    return record


def believed(state):
    """The record of loop.json when a process with the identity it names (process id and start time) lives, else None:
    a record that a kill left, or that names a process id which another process has been given, is believed by nothing."""
    record = read_record(state)
    if record is not None and processes.alive({"pid": record["pid"], "start": record["start"]}):
        return record
    return None


def running_loop(state):
    """The refusal of a second loop: it names the process of the first."""
    record = believed(state)
    if record is None:
        return Refused("another loop holds the lock {}, and its record {} names no live process".format(
            os.path.join(state.real, LOCK), os.path.join(state.real, RECORD)))
    return Refused("another loop runs for configuration {} (process {}); lane loop --stop ends it".format(
        state.configuration.name, record["pid"]))


def take_lock(state):
    """The exclusive lock on loop.lock: its descriptor, or Refused that names the first loop. It is asked for without
    blocking, up to LOCK_TRIES times, LOCK_TRY_SECONDS apart (about half a second in all). `--status`, `--stop` and
    `--detach` look at the lock for an instant with a shared lock (lock_held), and a loop that starts in that instant is
    not another loop; a loop that is another one holds the lock for its whole life, so the tries tell the two apart."""
    descriptor = fsguard.open_creating(LOCK, os.O_RDWR | fsguard.NOFOLLOW | fsguard.CLOEXEC, 0o600, state.fd)
    for attempt in range(LOCK_TRIES):
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return descriptor
        except BlockingIOError:
            if attempt + 1 < LOCK_TRIES:
                time.sleep(LOCK_TRY_SECONDS)
    os.close(descriptor)
    raise running_loop(state)


def lock_held(state):
    """True while a loop holds loop.lock, tried without creating the file and without waiting."""
    try:
        descriptor = os.open(LOCK, os.O_RDWR | fsguard.NOFOLLOW | fsguard.CLOEXEC, dir_fd=state.fd)
    except FileNotFoundError:
        return False
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    finally:
        os.close(descriptor)
    return False


class Loop:
    """The loop of one configuration, from the moment it holds the lock to the moment it ends."""

    def __init__(self, configuration, zones, state, detached, echo, loop_id=None):
        self.configuration = configuration
        self.zones = zones
        self.state = state
        self.detached = detached
        self.echo = echo
        self.id = loop_id or uuid.uuid4().hex
        # The environment that its turns get, held in memory only (see the module's text).
        self.environment = dict(os.environ)
        self.identity = processes.identity(os.getpid())
        if self.identity is None:
            raise Refused("the loop's own process is not in the process table")
        self.poll, self.backoff, self.limit_backoff = settings_of(configuration)
        self.log = os.open(LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT | fsguard.NOFOLLOW | fsguard.CLOEXEC, 0o600,
                           dir_fd=state.fd)
        self.lock = None
        self.since = None
        # The latest failure of a pass, {"at", "message"}: the line that was written to loop.log for it, kept in loop.json.
        self.last_error = None
        self.stopping = False
        self.started = False
        self.turns = 0
        self.skips = 0
        # The turns this pass has started on each account (the choice of the account, "Slots and the choice of the
        # account"): a pass starts no more than the account's own `slots` turns, and the next pass asks the command
        # again. It is reset at the start of every pass and never written down.
        self.pass_started = {}
        # The latest skip of each lane that was looked at: {"reason", "until"}, read from the events when the lane is first
        # looked at, so that a loop that is started again does not repeat a skip.
        self.waits = {}
        self.snapshot = None

    def note(self, message):
        """One line of loop.log, with the time: (the time, the text as written). A line that looks like a credential is
        withheld."""
        at = events.utc_now()
        text = screened(" ".join(message.split()))[:MESSAGE_CHARACTERS]
        try:
            os.write(self.log, "{} {}\n".format(at, text).encode("utf-8", "replace"))
        except OSError as error:
            # The line is not lost: it goes to the loop's standard error instead (the text was screened above).
            sys.stderr.write("{} loop.log could not be written ({}): {}\n".format(at, describe(error), text))
        return at, text

    def fail(self, message):
        """A pass that could not be made, or a step of one: its line goes to loop.log and, as `last_error`, to loop.json,
        where it stays until a later failure replaces it (a good pass does not clear it)."""
        at, text = self.note(message)
        self.last_error = {"at": at, "message": text}
        try:
            self.write_record()
        except OSError as error:
            self.note("loop.json could not be written: {}".format(describe(error)))

    def on_signal(self, number, frame):
        self.stopping = True

    def install_signals(self):
        """SIGTERM, SIGINT and SIGHUP all end the loop the same way: it finishes the step it is in (a turn start is never
        cut in half), records loop.stopped and releases the lock."""
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(number, self.on_signal)

    def wait(self, seconds):
        end = time.monotonic() + seconds
        while not self.stopping:
            left = end - time.monotonic()
            if left <= 0:
                return
            time.sleep(min(SLICE, left))

    def show(self, item):
        """In the foreground, one JSON line for each event the loop appends, as `event tail` prints it."""
        if not self.echo:
            return
        try:
            sys.stdout.write(output(item) + "\n")
            sys.stdout.flush()
        except (BrokenPipeError, ValueError, OSError):
            self.echo = False

    def append(self, kind, lane, payload, at=None):
        """One event of the loop, appended through the store's own function; the event as `event tail` shows it."""
        envelope = {"id": "ev-" + uuid.uuid4().hex, "kind": kind, "lane": lane, "actor": PROGRAM,
                    "occurred_at": at or events.utc_now(), "payload": payload, "protocol_version": load_protocol()[1]}
        with self.state.lock():
            store = events.open_for_write(self.state, timeout=STORE_WAIT_SECONDS)
        try:
            stored = store.append(envelope)
        finally:
            store.close()
        item = dict(envelope, seq=stored["seq"], recorded_at=stored["recorded_at"], sha256=stored["sha256"])
        self.show(item)
        return item

    def write_record(self):
        record = {"loop": self.id, "pid": os.getpid(), "start": self.identity["start"], "since": self.since,
                  "detached": self.detached, "last_error": self.last_error}
        fsguard.write_new(self.state.fd, RECORD, (json.dumps(record, sort_keys=True) + "\n").encode("utf-8"),
                          replace=True)

    def begin(self):
        """loop.started, as soon as the store takes it: no turn starts before the loop has recorded itself."""
        while not self.stopping:
            try:
                session = lanecmd.Session(self.configuration, self.zones)
                try:
                    earlier = unrecorded_end(session.store, self.id) if session.store is not None else None
                finally:
                    session.close()
                self.append("loop.started", None, {"loop": self.id, "pid": os.getpid(), "start": self.identity["start"],
                                                   "detached": self.detached, "unrecorded_end": earlier})
                self.started = True
                return
            except (LauncherError, sqlite3.Error) as error:
                self.fail("loop.started could not be recorded yet: {}".format(describe(error)))
                self.wait(self.poll)

    def close(self, reason):
        """loop.stopped, when the store takes it (a loop that could not record it is found by the next loop as
        `unrecorded_end`)."""
        if not self.started:
            return
        try:
            self.append("loop.stopped", None, {"loop": self.id, "reason": reason, "turns": self.turns,
                                               "skips": self.skips})
        except (LauncherError, sqlite3.Error) as error:
            self.note("loop.stopped could not be recorded: {}".format(describe(error)))

    def run(self):
        """The loop's whole life: the exit status. A second loop is refused here, before anything else is done."""
        self.lock = take_lock(self.state)
        try:
            self.install_signals()
            self.since = events.utc_now()
            self.write_record()
            self.begin()
            try:
                if self.started:
                    self.serve()
            except BaseException:
                # Only an unexpected internal error comes here: loop.stopped says so, and the error goes on to be printed
                # as every command prints it (exit 70).
                self.close("error")
                raise
            self.close("stop")
            return 0
        finally:
            os.close(self.lock)
            os.close(self.log)

    def serve(self):
        """A pass every poll_seconds, until a signal asks the loop to end. A pass that cannot be made (the store is busy for
        10 seconds, the configuration cannot be loaded) is written to loop.log and tried again at the next one."""
        while not self.stopping:
            try:
                self.look()
            except (LauncherError, sqlite3.Error, FileNotFoundError) as error:
                self.fail("the pass could not be made: {}".format(describe(error)))
            self.wait(self.poll)

    def look(self):
        """One pass: the configuration is loaded again (a runner edited since refuses the turn, as `lane turn` would), the
        store is read once and each declared lane is taken in turn."""
        configuration = config.load(self.configuration.name)
        zones = config.Zones(configuration)
        problems = zones.problems()
        if problems:
            raise Refused(problems[0])
        self.poll, self.backoff, self.limit_backoff = settings_of(configuration)
        self.snapshot = None
        # A new pass: no turn has been started on any account yet, and each lane's turn asks the room command again
        # with the count this pass has made (the design's "in one pass the loop starts at most `slots` turns on an
        # account, counting the turns it started in that pass, and asks the command again on the next pass").
        self.pass_started = {}
        session = lanecmd.Session(configuration, zones)
        try:
            for row in session.rows():
                if self.stopping:
                    return
                if not declared(row):
                    continue
                try:
                    self.step(configuration, zones, session, row)
                except LauncherError as error:
                    self.fail("lane {}: {}".format(row["lane"], first_line(error)))
        finally:
            session.close()

    def memo(self, session, lane):
        if lane not in self.waits:
            self.waits[lane] = latest_skip(session.store, lane) if session.store is not None else None
        return self.waits[lane]

    def step(self, configuration, zones, session, row):
        """What the loop decides for one declared lane (the steps of "A pass")."""
        lane = row["lane"]
        if row["running"]:
            self.watch(configuration, zones, session, row)
            return
        now = datetime.now(timezone.utc)
        kind = due(row, now)
        if kind is None:
            return
        if held(self.memo(session, lane), now, self.backoff):
            return
        wait = wait_of(session, lane, self.backoff, self.limit_backoff)
        if wait is not None and now < wait[0]:
            self.skip(lane, "backoff", wait[0], wait[1], None)
            return
        self.start_turn(configuration, zones, lane, kind)

    def watch(self, configuration, zones, session, row):
        """A lane that is running: when its supervising process is seen gone, the check of `lane check` records the loss
        for this lane only (and the return of its messages); a run that is supervised is left alone, with no event."""
        lane = row["lane"]
        payload, record = lanecmd.latest(session, lane)
        if payload is None or record is None or not runrecord.valid_identity(record.get("supervisor")):
            return
        if self.snapshot is None:
            self.snapshot = processes.table()
        if runrecord.supervisor_alive(record, self.snapshot):
            return
        result = lanecmd.check(configuration, zones, argparse.Namespace(lane=lane))
        for entry in result["lost"]:
            self.note("lane {} run {}: its supervising process is gone, so lane.lost is recorded (event seq {})".format(
                entry["lane"], entry["run"], entry["event"]["seq"]))

    def skip(self, lane, reason, until, after, detail, at=None):
        """A skip, once for each wait: it is recorded when the lane's latest skip says another reason or another `until`."""
        until_text = stamp(until)
        if self.waits.get(lane) == {"reason": reason, "until": until_text}:
            return
        self.append("loop.skipped", lane, {"loop": self.id, "reason": reason, "until": until_text, "after": after,
                                           "detail": detail}, at)
        self.skips += 1
        self.waits[lane] = {"reason": reason, "until": until_text}

    def refused(self, lane, error):
        """A turn that cannot start is a skip with reason `refused`, and the lane is not tried again for backoff_seconds."""
        at = events.utc_now()
        self.skip(lane, "refused", moment(at) + timedelta(seconds=self.backoff), None, detail_of(error), at)

    def no_room(self, lane, reason):
        """No account has room, so no turn starts: a skip with reason `no-room`, the room command's own reason as
        `detail`, and the hold a refused turn gets (`until`, `backoff_seconds` after the skip — the design's
        "A back-off is a skip with reason backoff": `until` is `backoff_seconds` after the skip for `refused` and
        `no-room` alike). The mail stays waiting; the hold `held` applies keeps the lane from being looked at, and the
        same wait from being recorded again, on the passes that find it — the command is asked again only when the
        hold ends."""
        at = events.utc_now()
        self.skip(lane, "no-room", moment(at) + timedelta(seconds=self.backoff), None,
                  (screened(reason) or "no-room")[:lanes.DETAIL_CHARACTERS], at)

    def start_turn(self, configuration, zones, lane, kind):
        """The turn is started by the function that `lane turn` uses, with the environment captured at the start and
        this pass's count of the turns already started on each account, so the choice gives no account more than its
        `slots` in this pass; the loop does not wait for the turn."""
        arguments = argparse.Namespace(lane=lane, idle=kind == "idle", account=None, budget=None, message=None)
        try:
            result = lanecmd.turn(configuration, zones, arguments, self.environment, self.pass_started)
        except LauncherError as error:
            # A turn that does not start because no account has room is the design's own reason for the loop, `no-room`
            # (with the command's own reason as `detail`); every other refusal of `lane turn` is `refused`.
            reason = no_room_of(lane, error)
            if reason is None:
                self.refused(lane, error)
            else:
                self.no_room(lane, reason)
            return
        except FileNotFoundError as error:
            self.refused(lane, Refused("{} disappeared while the turn was being started".format(
                error.filename or "a file or directory it used")))
            return
        if not result.get("started"):
            return
        if result.get("account") is not None:
            # This pass started one more turn on that account: it counts against the account's `slots` for the rest of
            # the pass, and the next pass asks the room command again.
            self.pass_started[result["account"]] = self.pass_started.get(result["account"], 0) + 1
        self.waits[lane] = None
        try:
            self.append("loop.turn", lane, {"loop": self.id, "kind": result["turn"]["kind"],
                                            "sequences": result["turn"]["mail"], "run": result["run"]})
        except (LauncherError, sqlite3.Error) as error:
            self.fail("lane {}: run {} started, and loop.turn could not be recorded: {}".format(
                lane, result["run"], describe(error)))
            return
        self.turns += 1


# The forms of the command.

def foreground(configuration, zones):
    """The loop in this process, until a signal or an unexpected internal error ends it."""
    state = StateDir.open(configuration, zones, create=True)
    try:
        return Loop(configuration, zones, state, False, True).run()
    finally:
        state.close()


def loop_argv(fifo):
    library = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    code = ("import sys; sys.path.insert(0, {!r}); from {}.loopcmd import detached; "
            "raise SystemExit(detached(sys.argv[1:]))").format(library, __package__)
    return [sys.executable, "-I", "-B", "-c", code, fifo]


def hand_over(state, name, data, process, deadline):
    """Write the loop's input to the FIFO once the loop's process opens it, then close it (as lanecmd.send does for the
    supervising process of a run)."""
    while True:
        try:
            descriptor = os.open(name, os.O_WRONLY | os.O_NONBLOCK | fsguard.NOFOLLOW | fsguard.CLOEXEC,
                                 dir_fd=state.fd)
            break
        except OSError as error:
            if error.errno == errno.ENOENT:
                raise Refused("the loop's FIFO {} disappeared before the loop read its input".format(
                    os.path.join(state.real, name))) from None
            if error.errno != errno.ENXIO:
                raise
        if time.monotonic() > deadline:
            raise Refused("the loop did not start within {} seconds".format(lanecmd.LAUNCH_SECONDS))
        if not processes.alive(process):
            raise Refused("the loop ended before it read its input; its messages are in {}".format(
                os.path.join(state.real, LOG)))
        time.sleep(0.02)
    try:
        view = memoryview(data)
        while view:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Refused("the loop did not read its input within {} seconds".format(lanecmd.LAUNCH_SECONDS))
            select.select([], [descriptor], [], remaining)
            try:
                view = view[os.write(descriptor, view):]
            except BlockingIOError:
                continue
            except BrokenPipeError:
                raise Refused("the loop stopped reading its input; its messages are in {}".format(
                    os.path.join(state.real, LOG))) from None
    finally:
        os.close(descriptor)


def wait_for(configuration, zones, loop_id, process, deadline):
    """The loop.started event of the loop that was just started, once the loop has appended it."""
    while True:
        living = processes.alive(process)
        session = lanecmd.Session(configuration, zones)
        try:
            event = started_of(session.store, loop_id)
        finally:
            session.close()
        if event is not None:
            return event
        if not living:
            raise Refused("the loop ended before it recorded loop.started; its messages are in {}".format(
                os.path.join(configuration.state_dir, LOG)))
        if time.monotonic() > deadline:
            processes.signal_checked(process, signal.SIGHUP)
            raise Refused("the loop did not record loop.started within {} seconds; it was asked to stop".format(
                lanecmd.LAUNCH_SECONDS))
        time.sleep(lanecmd.POLL)


def detach(configuration, zones):
    """Start the loop in the session `laneboss+loop` of the configuration's own tmux server, hand it the caller's
    environment through a FIFO, and return once its loop.started is stored: loop, pid and session."""
    if not multiplexer.available():
        raise Refused("tmux is not on PATH; a detached loop runs in a tmux session")
    state = StateDir.open(configuration, zones, create=True)
    try:
        if lock_held(state):
            raise running_loop(state)
        socket = multiplexer.socket_path(configuration.name, state.real)
        multiplexer.check_socket(socket)
        if multiplexer.alive(socket, SESSION):
            raise Refused("a tmux session {} is still open at {}".format(SESSION, socket))
        loop_id = uuid.uuid4().hex
        fifo = ".loop-{}.fifo".format(loop_id)
        if os.mkfifo in os.supports_dir_fd:
            os.mkfifo(fifo, 0o600, dir_fd=state.fd)
        else:
            os.mkfifo(os.path.join(state.real, fifo), 0o600)
        deadline = time.monotonic() + lanecmd.LAUNCH_SECONDS
        try:
            multiplexer.new_session(socket, SESSION, state.real, loop_argv(os.path.join(state.real, fifo)))
            pid = multiplexer.pane_pid(socket, SESSION)
            process = processes.identity(pid) if pid is not None else None
            if process is None:
                # Not killed by its name: a session whose pane process has ended goes away by itself.
                raise Refused("the loop ended at once; its messages are in {}".format(os.path.join(state.real, LOG)))
            data = json.dumps({"environment": dict(os.environ), "spec": {"config": configuration.name,
                                                                         "loop": loop_id}},
                              ensure_ascii=True).encode("ascii")
            hand_over(state, fifo, data, process, deadline)
            started = wait_for(configuration, zones, loop_id, process, deadline)
        finally:
            try:
                os.unlink(fifo, dir_fd=state.fd)
            except OSError:
                pass
        return {"loop": loop_id, "pid": started["payload"]["pid"], "session": SESSION}
    finally:
        state.close()


def detached(arguments):
    """The loop process of a detached start, the only process of its session: it reads its environment and what it runs
    from the FIFO that `lane loop --detach` made, and its output goes to loop.log. Returns the exit status: the exit
    status of a launcher error, written to loop.log as every command writes it, or 70 for any other error, with its
    traceback in loop.log, as the foreground loop ends with 70 on an error that nobody expected."""
    from . import supervise  # only a detached loop needs the FIFO reader of a supervising process
    if len(arguments) != 1:
        return 2
    try:
        message = supervise.receive(arguments[0])
    except (OSError, ValueError, TimeoutError):
        return 2
    os.environ.clear()
    os.environ.update(message["environment"])
    spec = message["spec"]
    # The setup: a failure here is a failure of the start, and leaves exit status 2 (or the launcher error's own).
    try:
        configuration = config.load(spec["config"])
        zones = config.Zones(configuration)
        if zones.problems():
            return 2
        state = StateDir.open(configuration, zones, create=True)
        log = os.open(LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT | fsguard.NOFOLLOW | fsguard.CLOEXEC, 0o600,
                      dir_fd=state.fd)
        os.dup2(log, 1)
        os.dup2(log, 2)
        os.close(log)
        sys.stdout = os.fdopen(1, "w", buffering=1, closefd=False)
        sys.stderr = os.fdopen(2, "w", buffering=1, closefd=False)
        loop_id = spec["loop"]
    except LauncherError as error:
        sys.stderr.write("{} {}: {}\n".format(events.utc_now(), error.prefix, first_line(error)))
        return error.exit_code
    except (OSError, KeyError):
        return 2
    # The loop itself. From here what it says goes to loop.log, and no error is swallowed: an OSError or a KeyError met
    # while it runs is an error that nobody expected, like any other.
    try:
        return Loop(configuration, zones, state, True, False, loop_id).run()
    except LauncherError as error:
        sys.stderr.write("{} {}: {}\n".format(events.utc_now(), error.prefix, first_line(error)))
        return error.exit_code
    except BaseException:
        sys.stderr.write("{} internal error:\n{}".format(events.utc_now(), traceback.format_exc()))
        return 70


def status(configuration, zones):
    """The loop and its lanes, from the lock, loop.json (believed only while its process lives) and the events;
    nothing is appended."""
    result = {"running": False, "loop": None, "pid": None, "since": None, "detached": None, "session": None,
              "last_error": None, "unrecorded_end": None, "lanes": []}
    state = StateDir.open(configuration, zones, create=False)
    if state is None:
        return result
    try:
        result["running"] = lock_held(state)
        record = believed(state) if result["running"] else None
        _, backoff, limit_backoff = settings_of(configuration)
        session = lanecmd.Session(configuration, zones)
        try:
            if record is not None:
                failure = record["last_error"]
                result.update(loop=record["loop"], pid=record["pid"], since=record["since"],
                              detached=record["detached"], session=SESSION if record["detached"] else None,
                              last_error=None if failure is None else {"at": failure["at"],
                                                                       "message": screened(failure["message"])})
                event = started_of(session.store, record["loop"])
                result["unrecorded_end"] = event["payload"]["unrecorded_end"] if event is not None else None
            now = datetime.now(timezone.utc)
            for row in session.rows():
                if not declared(row):
                    continue
                running = row["running"]
                wait = None if running else wait_of(session, row["lane"], backoff, limit_backoff)
                holding = wait is not None and now < wait[0]
                # What the loop would start for the lane now (the steps of "A pass"): nothing while it runs, else what is
                # due, which is `backoff` when the lane's latest end makes it wait.
                due_now = None if running else due(row, now)
                result["lanes"].append({"lane": row["lane"], "state": row["state"], "waiting": mail.queued(row["mail"]),
                                        "backoff_until": stamp(wait[0]) if holding else None,
                                        "next": "backoff" if holding and due_now is not None else due_now,
                                        "bad_ends": bad_ends(session, row["lane"])})
        finally:
            session.close()
    finally:
        state.close()
    return result


def stop(configuration, zones):
    """Ask the loop to end: SIGTERM through the checked signal, then wait up to 30 seconds for the lock to be free. The
    loop is never killed, and no turn is stopped."""
    state = StateDir.open(configuration, zones, create=False)
    if state is None or not lock_held(state):
        if state is not None:
            state.close()
        raise Refused("no loop runs for configuration {}".format(configuration.name))
    try:
        record = believed(state)
        if record is None:
            raise Refused("a loop holds the lock {}, but its record {} names no live process, so nothing was "
                          "signalled".format(os.path.join(state.real, LOCK), os.path.join(state.real, RECORD)))
        if not processes.signal_checked({"pid": record["pid"], "start": record["start"]}, signal.SIGTERM):
            raise Refused("the loop's process {} could not be signalled; nothing was stopped".format(record["pid"]))
        deadline = time.monotonic() + STOP_WAIT_SECONDS
        while lock_held(state):
            if time.monotonic() > deadline:
                raise Refused("the loop (process {}) is still running {} seconds after SIGTERM; it is never killed, and "
                              "no turn was stopped".format(record["pid"], STOP_WAIT_SECONDS))
            time.sleep(lanecmd.POLL)
        session = lanecmd.Session(configuration, zones)
        try:
            found = None
            for event in session.store.kind_events("loop.stopped") if session.store is not None else []:
                if lanes.loop_form(event) and event["payload"]["loop"] == record["loop"]:
                    found = {"id": event["id"], "seq": event["seq"]}
                    break
        finally:
            session.close()
        return {"stopped": True, "pid": record["pid"], "event": found}
    finally:
        state.close()


def run(configuration, zones, arguments):
    """lane loop: the loop in the foreground, or --detach, --status or --stop. Returns the exit status."""
    if arguments.status:
        print_json(status(configuration, zones))
        return 0
    if arguments.stop:
        print_json(stop(configuration, zones))
        return 0
    if arguments.detach:
        print_json(detach(configuration, zones))
        return 0
    return foreground(configuration, zones)
