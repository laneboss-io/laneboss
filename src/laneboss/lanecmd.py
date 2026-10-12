"""`laneboss lane`: start, resume, stop, status, check, mark, clean, send and turn (docs/architecture.md, "Lanes").

A lane is one piece of work: one brief, one runner process at a time, one working directory, one time budget. These
commands prepare a run (routing, the working directory and its claim, the rendered brief), start the supervising
process in the configuration's tmux session for the lane, and report what the store says. They never decide for the
supervisor: nothing here retries, resumes, merges, accepts or cleans up on its own. Events are appended through
EventStore.append(), which checks every lane event against its documented payload and the lane's projection.

Start, resume and clean hold the configuration's lanes lock (STATE_DIR/lanes.lock) from their first check to their
last action, so two of them never interleave; a start or resume releases it once the run's session exists and its
run record names the supervising process. The lock is waited for at most [lanes] lock_wait_seconds, then the command
is refused. Every process a command signals is named by a run record and checked by its start time (processes.py);
a command that cannot read the process table, deliver a signal or ask Git says so and does nothing it cannot verify.
No command records an event for a lane while that lane has events waiting in its pending file (pending.py).
"""

import base64
import errno
from datetime import datetime
import fcntl
import json
import os
import re
import select
import signal
import sqlite3
import string
import sys
import time
import traceback
import uuid
from pathlib import Path

from . import accounts, brief, claims, config, credentials, disk, events, fsguard, guards, lanes, mail, multiplexer
from . import pending, processes, refusals
from . import runrecord, worktree
from .errors import IntegrityProblem, Refused
from .identity import PROGRAM, VERSION, env_name
from .jsonutil import sha256_hex
from .protocol import load_protocol
from .statedir import StateDir

SUPERVISOR = "supervisor"
DEFAULT_QUIET_SECONDS = 900
DEFAULT_GRACE_SECONDS = 10
DEFAULT_LOCK_SECONDS = 60
DRAIN_SECONDS = 10
LAUNCH_SECONDS = 30
POLL = 0.1
LOG = "output.log"
WATCH_LOG = "watch.log"
LANES_LOCK = "lanes.lock"
MAIL_LOCK = "mail.lock"
CONTINUE_FILE = Path(__file__).with_name("protocol") / "continue.md"
BUDGET = re.compile(r"[0-9]{1,5}(?:\.[0-9]{1,3})?")
IDLE = re.compile(r"[0-9]{1,6}")
MAX_BRIEF_BYTES = brief.MAX_BRIEF_BYTES


def parse_budget(value, option="--budget"):
    if value is None:
        return None
    if BUDGET.fullmatch(value) is None:
        raise Refused(option + ": must be a number of minutes, for example 30 or 0.5")
    number = float(value) if "." in value else int(value)
    if not 0 < number <= config.MAX_BUDGET_MINUTES:
        raise Refused("{}: must be above 0 and at most {} minutes".format(option, config.MAX_BUDGET_MINUTES))
    return number


def parse_idle(value):
    """`lane start --idle SECONDS`: the idle interval of a turn-based lane, a whole number of seconds up to a week."""
    if value is None:
        return None
    if IDLE.fullmatch(value) is None or not 1 <= int(value) <= lanes.MAX_IDLE_SECONDS:
        raise Refused("--idle: must be a whole number of seconds from 1 to {}".format(lanes.MAX_IDLE_SECONDS))
    return int(value)


def check_text(value, what):
    """Refuse a value that would reach an event when it looks like a credential; the value is never repeated."""
    found = credentials.find_in_text(value)
    if found:
        raise Refused("{}: looks like a credential ({}); nothing was started".format(what, found[0]))


def lane_name(lane):
    events.check_grammar(lane, events.LANE, "--lane")
    return lane


def read_store(state):
    """The store for reading, or None; the caller closes it."""
    if state is None:
        return None
    with state.lock(shared=True):
        return events.open_for_read(state)


class LanesLock:
    """The configuration's lanes lock: a lock file in the state directory, apart from the lock the store's writers
    take, held by start, resume and clean from their first check to their last action, and waited for at most
    [lanes] lock_wait_seconds."""

    def __init__(self, state):
        self.state = state
        self.seconds = lanes_settings(state.configuration).get("lock_wait_seconds", DEFAULT_LOCK_SECONDS)
        self.fd = None

    def __enter__(self):
        self.fd = fsguard.open_creating(LANES_LOCK, os.O_RDWR | fsguard.NOFOLLOW | fsguard.CLOEXEC, 0o600,
                                        self.state.fd)
        deadline = time.monotonic() + self.seconds
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.monotonic() > deadline:
                    os.close(self.fd)
                    raise Refused("another lane command holds the lanes lock {} and did not release it within {} "
                                  "seconds ([lanes] lock_wait_seconds); nothing was done".format(
                                      os.path.join(self.state.real, LANES_LOCK), self.seconds)) from None
                time.sleep(0.05)

    def __exit__(self, *details):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


class MailLock:
    """A lane's mail lock: a lock file `lanes/LANE/mail.lock`, created when it is missing, that lane send holds from the
    read of the lane's last sequence to the append of its event, so that two sends never take one sequence number. It is
    waited for at most [lanes] lock_wait_seconds, like the lanes lock, and then the send is refused and does nothing."""

    def __init__(self, state, lane):
        self.state = state
        self.lane = lane
        self.seconds = lanes_settings(state.configuration).get("lock_wait_seconds", DEFAULT_LOCK_SECONDS)
        self.fd = None

    def __enter__(self):
        directory = self.state.open_lane(self.lane, create=True)
        try:
            self.fd = fsguard.open_creating(MAIL_LOCK, os.O_RDWR | fsguard.NOFOLLOW | fsguard.CLOEXEC, 0o600, directory)
        finally:
            os.close(directory)
        deadline = time.monotonic() + self.seconds
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.monotonic() > deadline:
                    os.close(self.fd)
                    raise Refused("another lane send holds the mail lock {} and did not release it within {} seconds "
                                  "([lanes] lock_wait_seconds); nothing was done".format(
                                      self.state.lane_path(self.lane, MAIL_LOCK), self.seconds)) from None
                time.sleep(0.05)

    def __exit__(self, *details):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        os.close(self.fd)


class Session:
    """The state directory and, when it exists, a store opened for reading, closed together."""

    def __init__(self, configuration, zones, create=False):
        self.configuration = configuration
        self.zones = zones
        self.state = StateDir.open(configuration, zones, create=create)
        self.store = None
        try:
            self.store = read_store(self.state)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.store is not None:
            self.store.close()
            self.store = None
        if self.state is not None:
            self.state.close()
            self.state = None

    def refresh(self):
        if self.store is not None:
            self.store.close()
            self.store = None
        self.store = read_store(self.state)

    def row(self, lane):
        return self.store.lane(lane) if self.store is not None else None

    def rows(self):
        return self.store.lanes() if self.store is not None else []

    def last(self, lane, kind):
        return self.store.last_event(lane, kind) if self.store is not None else None

    def append(self, kind, lane, payload, actor=PROGRAM):
        """Append one event of the lane after its pending events; refused when they cannot be appended first."""
        envelope = {"id": "ev-" + uuid.uuid4().hex, "kind": kind, "lane": lane, "actor": actor, "payload": payload,
                    "occurred_at": events.utc_now(), "protocol_version": load_protocol()[1]}
        return pending.append_after(self.state, lane, envelope, DRAIN_SECONDS)

    def record(self, lane, launch):
        return runrecord.read(self.state, lane, launch) if launch else None


def known_row(session, lane):
    if session.state is None or session.row(lane) is None:
        raise Refused("lane {} is not known to configuration {}".format(lane, session.configuration.name))
    return session.row(lane)


def launcher_run(session, lane):
    """(payload of the lane's last lane.started, its run record), or (None, None): only a run the launcher started. A
    lane whose only event is lane.adopted has no such run — its run 1 is already over and the launcher started and
    ended nothing (docs/architecture.md, "Adopting a session that already runs")."""
    event = session.last(lane, "lane.started")
    if event is None:
        return None, None
    return event["payload"], session.record(lane, event["payload"]["launch"])


def latest(session, lane):
    """The lane's previous run: (payload of its last lane.started, its run record), or, where no lane.started exists,
    (payload of its lane.adopted, None) — an adoption is read as a run 1 that is already over, so it holds no run record
    and no launch (docs/architecture.md, "Adopting a session that already runs") — or (None, None) for a lane with
    neither."""
    payload, record = launcher_run(session, lane)
    if payload is not None:
        return payload, record
    adopted = session.last(lane, "lane.adopted")
    return (adopted["payload"], None) if adopted is not None else (None, None)


def refuse_if_live(session, lane):
    """A launch whose supervising process lives, or whose recorded processes survive it, is still a run: any launch
    of the lane, including one whose lane.started is not stored yet (it is being started by another command). The
    lane's latest launch must also have a run record, unless an end event with no survivor proves its processes are
    gone: without the record nothing shows that they are. A payload with no run is an adoption: the launcher started no
    launch of it, so there is no launch of the lane to check and nothing of the launcher that can be live."""
    payload, record = latest(session, lane)
    if payload is not None and record is None and "run" in payload:
        ended, gone = session.last(lane, "lane.ended"), session.last(lane, "lane.gone")
        if not (ended is not None and ended["payload"]["run"] == payload["run"] and not ended["payload"]["survivors"]
                or gone is not None and gone["payload"]["run"] == payload["run"]):
            raise Refused("lane {}'s run {} has no run record ({}) and no end event that shows its processes are "
                          "gone, so nothing was done; restore the record (lane stop then removes what survives), or "
                          "declare the launch gone with lane mark --gone".format(
                              lane, payload["run"], session.state.lane_path(lane, "runs", payload["launch"] + ".json")))
    snapshot = processes.table()
    for record in runrecord.every(session.state, lane):
        if runrecord.supervisor_alive(record, snapshot):
            raise Refused("lane {}'s run {} is still supervised (its supervising process lives)".format(
                lane, record.get("run")))
        surviving = runrecord.survivors(record, snapshot)
        if surviving:
            raise Refused("{} process(es) of lane {}'s run {} survive their supervising process; lane stop removes "
                          "them".format(len(surviving), lane, record.get("run")))


def drain(session, lane):
    """Append the lane's pending events before this command acts on the lane; refused when some cannot be."""
    if pending.count(session.state, lane):
        left = pending.flush(session.state, lane, DRAIN_SECONDS)[2]
        session.refresh()
        if left:
            raise Refused("lane {} has {} event(s) waiting to be recorded; nothing is done for it before they are; "
                          "lane check records them once the store can be written".format(lane, left))


# Routing and placeholders.

def runner_of(configuration, name):
    runners = configuration.data["runners"]
    if name not in runners:
        raise Refused("runner {} is not defined in configuration {}".format(
            name if config.NAME.fullmatch(name or "") else "<name>", configuration.name))
    return runners[name]


def default_account(runner, excluded):
    for account in runner.get("accounts", []):
        if account not in excluded:
            return account
    return None


def check_account(runner_name, runner, account, excluded, project_name, option="--account"):
    if config.ACCOUNT.fullmatch(account) is None:
        raise Refused(option + " must match " + config.ACCOUNT.pattern)
    if account not in runner.get("accounts", []):
        # The value is not repeated: an account the configuration does not list may be anything, a credential too.
        raise Refused("{}: runner {} does not list that account; its accounts: {}".format(
            option, runner_name, ", ".join(runner.get("accounts", [])) or "none"))
    if account in excluded:
        raise Refused("{}: project {} excludes account {}".format(option, project_name, account))


def choose(configuration, project_name, project, arguments):
    """Runner, model, effort and account of a new lane, and who chose each: routing, the supervisor or the default."""
    runners = configuration.data["runners"]
    workers = project.get("workers") if project is not None else None
    excluded = set(project.get("excluded_accounts", [])) if project is not None else set()
    if arguments.runner is not None:
        runner_of(configuration, arguments.runner)
    if arguments.model is not None and (config.MODEL.fullmatch(arguments.model) is None
                                        or re.search(r"[0-9]", arguments.model) is None):
        raise Refused("--model must be a full model name that includes its version, not a family alias")
    if arguments.effort is not None and config.TOKEN.fullmatch(arguments.effort) is None:
        raise Refused("--effort must match " + config.TOKEN.pattern)

    def usable(name):
        runner = runners[name]
        if workers is not None and name not in workers:
            return False
        if arguments.account is not None:
            return arguments.account in runner.get("accounts", []) and arguments.account not in excluded
        return not runner.get("accounts") or default_account(runner, excluded) is not None

    route = None
    if arguments.difficulty is not None:
        for entry in configuration.data.get("routing", {}).get(arguments.difficulty, []):
            if (arguments.runner is None or entry["runner"] == arguments.runner) and usable(entry["runner"]):
                route = entry
                break
    runner_name = arguments.runner if arguments.runner is not None else (route or {}).get("runner")
    if runner_name is None:
        raise Refused("no runner: give --runner, or --difficulty with a usable entry in [routing]" if
                      arguments.difficulty is None else
                      "no usable [routing] entry for difficulty {}: none of its runners is allowed for this project "
                      "with an account it may use".format(arguments.difficulty))
    runner = runners[runner_name]
    if workers is not None and runner_name not in workers:
        raise Refused("runner {} is not one of project {}'s workers".format(runner_name, project_name))
    model = arguments.model if arguments.model is not None else (route or {}).get("model")
    if model is None:
        raise Refused("no model: a full model name is required, from --model or a [routing] entry; nothing is guessed")
    effort = arguments.effort if arguments.effort is not None else (route or {}).get("effort")
    if arguments.account is not None:
        check_account(runner_name, runner, arguments.account, excluded, project_name)
        account = arguments.account
    else:
        account = default_account(runner, excluded)
        if account is None and runner.get("accounts"):
            raise Refused("project {} excludes every account of runner {}".format(project_name, runner_name))
    chosen = {"runner": "supervisor" if arguments.runner is not None else "routing",
              "model": "supervisor" if arguments.model is not None else "routing",
              "effort": None if effort is None else ("supervisor" if arguments.effort is not None else "routing"),
              "account": None if account is None else ("supervisor" if arguments.account is not None else "default")}
    return runner_name, runner, model, effort, account, chosen


def fields_of(element):
    return [field for _, field, _, _ in string.Formatter().parse(element) if field is not None]


def fill(runner_name, template, values, what):
    """The argument vector: the template with each placeholder replaced; never through a shell."""
    argv = [template[0]]
    for element in template[1:]:
        for field in fields_of(element):
            if field == "machine":
                raise Refused("runner {}'s {} uses {{machine}}; test machines are not built yet".format(runner_name, what))
            if values.get(field) is None:
                raise Refused("runner {}'s {} uses {{{}}}, which this lane does not have{}".format(
                    runner_name, what, field, {"account": " (the runner lists no account)",
                                               "effort": " (give --effort or a routing entry with one)",
                                               "project": " (give --project)"}.get(field, "")))
        argv.append(element.format(**{key: value for key, value in values.items() if value is not None}))
    return argv


def uses(template, field):
    return any(field in fields_of(element) for element in template[1:])


# The working directory and its claim.

def check_directory(zones, path, option):
    """A directory a lane works in: outside every other configuration, the configuration home, the state home and
    the bound configuration's own state directory, judged by identity."""
    zones.check_target(path, option)
    descriptor = fsguard.open_directory(path, option)
    try:
        chain, markers = fsguard.walk_up(descriptor, config.MARKER)
        zones.check_chain(chain, markers, option, write=True)
    finally:
        os.close(descriptor)


def same_directory(first, second):
    if os.path.realpath(first) == os.path.realpath(second):
        return True
    try:
        return fsguard.identity(os.stat(first)) == fsguard.identity(os.stat(second))
    except OSError:
        return False


def working_directory(zones, project_name, project, lane, arguments):
    if arguments.worktree is not None:
        check_text(arguments.worktree, "--worktree")
        path = os.path.realpath(arguments.worktree)
        check_text(path, "--worktree")
        if not os.path.isdir(path):
            raise Refused("--worktree: {} is not an existing directory".format(path))
        check_directory(zones, path, "--worktree")
        return {"worktree": path, "repository": None, "branch": None, "base": None,
                "claim": claims.locate(path, "--worktree", starting=True)}
    if project is None:
        raise Refused("a lane needs a working directory: --project naming a project with a local repository, or "
                      "--worktree PATH")
    repository = project.get("repository")
    if not repository or not repository.startswith("/"):
        raise Refused("project {} names no local repository (an absolute path); pass --worktree PATH".format(
            project_name))
    root = worktree.repository_root(repository)
    if root is None:
        raise Refused("project {}'s repository is not a Git work tree".format(project_name))
    path = os.path.join(os.path.dirname(root), os.path.basename(root) + "-" + lane)
    check_text(path, "the lane's worktree")
    if os.path.lexists(path):
        raise Refused("the lane's worktree {} already exists".format(path))
    check_directory(zones, os.path.dirname(path), "the lane's worktree")
    worktree.check_branch(root, lane)
    return {"worktree": path, "repository": root, "branch": lane, "base": worktree.resolve_base(root, arguments.base),
            "claim": None}


def listing(root):
    """Every entry below a directory, by relative path, without following links."""
    found = []
    for directory, names, files in os.walk(root):
        relative = os.path.relpath(directory, root)
        for name in names + files:
            found.append(os.path.normpath(os.path.join(relative, name)))
    return sorted(found)


def verified_rendered(state, lane, item, what):
    """The rendered brief or message a run is handed: a regular file in the lane's rendered directory whose bytes
    still hash to the recorded value. Anything else is an integrity problem."""
    name = item["sha256"] + ".md"
    if item["path"] != state.lane_path(lane, "rendered", name):
        raise IntegrityProblem("lane {}'s {} is not where the store says it is".format(lane, what))
    directory = state.open_lane(lane, "rendered")
    if directory is None:
        raise IntegrityProblem("lane {}'s rendered {} is missing: {}".format(lane, what, item["path"]))
    try:
        try:
            data = fsguard.read_descriptor(fsguard.open_child(directory, name, "the rendered " + what),
                                           MAX_BRIEF_BYTES + 1024 * 1024, "the rendered " + what)
        except Refused as error:
            raise IntegrityProblem("lane {}'s rendered {} cannot be handed over: {}".format(lane, what, error)) from None
    finally:
        os.close(directory)
    if sha256_hex(data) != item["sha256"]:
        raise IntegrityProblem("lane {}'s rendered {} {} no longer holds the bytes it was rendered with".format(
            lane, what, item["path"]))


# Starting a run: the supervising process in the lane's tmux session, its input through a FIFO.

def supervisor_argv(fifo):
    library = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    code = ("import sys; sys.path.insert(0, {!r}); from {}.supervise import main; "
            "raise SystemExit(main(sys.argv[1:]))").format(library, __package__)
    return [sys.executable, "-I", "-B", "-c", code, fifo]


def send(state, lane, name, data, supervisor, deadline):
    """Write the run's input to the FIFO once the supervising process opens it, then close it."""
    directory = state.open_lane(lane, create=True)
    try:
        while True:
            try:
                descriptor = os.open(name, os.O_WRONLY | os.O_NONBLOCK | fsguard.NOFOLLOW | fsguard.CLOEXEC,
                                     dir_fd=directory)
                break
            except OSError as error:
                if error.errno == errno.ENOENT:
                    raise Refused("the launch's FIFO {} disappeared before the supervising process read its input"
                                  .format(state.lane_path(lane, name))) from None
                if error.errno != errno.ENXIO:
                    raise
            if time.monotonic() > deadline:
                raise Refused("the supervising process did not start within {} seconds".format(LAUNCH_SECONDS))
            if not processes.alive(supervisor):
                raise Refused("the supervising process ended before it read its input; its messages are in "
                              + state.lane_path(lane, WATCH_LOG))
            time.sleep(0.02)
    finally:
        os.close(directory)
    try:
        view = memoryview(data)
        while view:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Refused("the supervising process did not read its input within {} seconds".format(
                    LAUNCH_SECONDS))
            select.select([], [descriptor], [], remaining)
            try:
                view = view[os.write(descriptor, view):]
            except BlockingIOError:
                continue
            except BrokenPipeError:
                raise Refused("the supervising process stopped reading its input; its messages are in "
                              + state.lane_path(lane, WATCH_LOG)) from None
    finally:
        os.close(descriptor)


def begin(session, lane, spec, directory, environment=None):
    """Create the lane's session running the supervising process, write the launch's run record naming it, and hand
    it the caller's environment (or the environment given: the one that the loop captured when it started) and the
    run's description through a FIFO in the lane's directory (never through a file or an argument). Returns the run
    record. The caller holds the lanes lock."""
    state = session.state
    socket, name = spec["started"]["session"]["socket"], spec["started"]["session"]["name"]
    fifo = ".launch-{}.fifo".format(spec["launch"])
    lane_fd = state.open_lane(lane, create=True)
    try:
        if os.mkfifo in os.supports_dir_fd:
            os.mkfifo(fifo, 0o600, dir_fd=lane_fd)
        else:
            os.mkfifo(state.lane_path(lane, fifo), 0o600)
    except FileNotFoundError:
        raise Refused("lane {}'s directory disappeared while the run was being started".format(lane)) from None
    finally:
        os.close(lane_fd)
    deadline = time.monotonic() + LAUNCH_SECONDS
    try:
        multiplexer.new_session(socket, name, directory, supervisor_argv(state.lane_path(lane, fifo)))
        pid = multiplexer.pane_pid(socket, name)
        supervisor = processes.identity(pid) if pid is not None else None
        if supervisor is None:
            # Not killed by its name: a session whose pane process has ended goes away by itself.
            raise Refused("the supervising process ended at once; its messages are in "
                          + state.lane_path(lane, WATCH_LOG))
        record = runrecord.new(session.configuration, lane, spec["run"], spec["launch"], supervisor)
        runrecord.write(state, lane, record)
        data = json.dumps({"environment": dict(os.environ) if environment is None else environment, "spec": spec},
                          ensure_ascii=True).encode("ascii")
        send(state, lane, fifo, data, supervisor, deadline)
        return record
    finally:
        lane_fd = state.open_lane(lane)
        if lane_fd is not None:
            try:
                os.unlink(fifo, dir_fd=lane_fd)
            except OSError:
                pass
            finally:
                os.close(lane_fd)


def wait_started(session, lane, spec, record):
    """The lane.started event of this launch, once its supervising process has appended it."""
    deadline = time.monotonic() + LAUNCH_SECONDS
    checked = 0.0
    while True:
        session.refresh()
        event = session.last(lane, "lane.started")
        if event is not None and event["payload"]["launch"] == spec["launch"]:
            return event
        now = time.monotonic()
        if now - checked > 0.5:
            checked = now
            if not runrecord.supervisor_alive(record):
                session.refresh()
                event = session.last(lane, "lane.started")
                if event is not None and event["payload"]["launch"] == spec["launch"]:
                    return event
                raise Refused("the supervising process ended before the run started; its messages are in "
                              + session.state.lane_path(lane, WATCH_LOG))
        if now > deadline:
            processes.signal_checked(record["supervisor"], signal.SIGHUP)
            raise Refused("the run did not start within {} seconds; its supervising process was stopped".format(
                LAUNCH_SECONDS))
        time.sleep(POLL)


def lanes_settings(configuration):
    return configuration.data.get("lanes", {})


def quiet_of(configuration, runner):
    return runner.get("quiet_seconds", lanes_settings(configuration).get("quiet_seconds", DEFAULT_QUIET_SECONDS))


def validate_planned(state, lane, row, kind, payload):
    """Check an event this command will have appended later, before anything starts."""
    envelope = {"kind": kind, "lane": lane, "actor": PROGRAM, "payload": payload,
                "protocol_version": load_protocol()[1]}
    event = events.validate_envelope(envelope)
    lanes.check_binding(event, state.real, multiplexer.socket_path(state.configuration.name, state.real))
    lanes.check_transition(row, event)


def make_spec(configuration, lane, launch_id, argv, started, resumed, runner, rendered):
    """The run's description. `rendered` is the bytes of the rendered brief (a start) or message (a resume); they go
    to the runner's standard input, in base64 so that the description stays ASCII, when its `prompt` is `stdin`."""
    settings = lanes_settings(configuration)
    return {"config": configuration.name, "lane": lane, "run": started["run"], "launch": launch_id, "argv": argv,
            "cwd": started["worktree"], "started": started, "resumed": resumed,
            "prompt": base64.b64encode(rendered).decode("ascii") if runner.get("prompt") == "stdin" else None,
            "budget_seconds": started["budget_minutes"] * 60, "quiet_seconds": started["quiet_seconds"],
            "grace_seconds": settings.get("stop_grace_seconds", DEFAULT_GRACE_SECONDS),
            "limit_patterns": runner.get("limit_patterns", []), "dropped_patterns": runner.get("dropped_patterns", []),
            "launcher_version": VERSION}


def check_neighbours(session, lane, directory, session_name):
    """No other lane works in this directory (until it is cleaned), and no other lane has this session name."""
    for other in session.rows():
        if other["lane"] == lane:
            continue
        if other["worktree"] and not other["cleaned"] and same_directory(other["worktree"], directory):
            raise Refused("lane {} already works in {}; one lane per working directory".format(other["lane"], directory))
        if multiplexer.session_name(other["lane"]) == session_name:
            raise Refused("lane {}'s tmux session would have the same name as lane {}'s (tmux turns . into _)".format(
                lane, other["lane"]))


def registry_of(claim):
    """The claims registry that holds a claim (lane.started's `claims`), or None for a worktree's own claim."""
    if claim is None or claim.name == claims.LINKED:
        return None
    return claim.holder


def undo(directory, claim, mine, made):
    """Take back what this start made before its run began, and only that: the claim it created, the worktree and
    the branch it created. The worktree is removed and the branch deleted only the way Git allows without force."""
    if made["claim"] and claim is not None:
        claims.release(claim, mine)
    if made["worktree"]:
        worktree.remove(directory["repository"], directory["worktree"])
    if made["branch"]:
        worktree.delete_merged_branch(directory["repository"], directory["branch"])


def start(configuration, zones, arguments):
    lane = lane_name(arguments.lane)
    project_name = arguments.project
    project = None
    if project_name is not None:
        if project_name not in configuration.projects:
            raise Refused("--project: configuration {} has no project file projects/{}.toml".format(
                configuration.name, project_name if config.NAME.fullmatch(project_name) else "<name>"))
        project = configuration.projects[project_name]
        prefix = project.get("lane_prefix")
        if prefix and not lane.startswith(prefix):
            raise Refused("project {}'s lane names start with {}".format(project_name, prefix))
    if arguments.worktree is not None and arguments.base is not None:
        raise Refused("--worktree and --base exclude each other: --base starts a new worktree")
    idle = parse_idle(arguments.idle)
    if idle is not None and not arguments.turns:
        raise Refused("--idle goes with --turns: only a turn-based lane has an idle interval")
    runner_name, runner, model, effort, account, chosen = choose(configuration, project_name, project, arguments)
    if arguments.turns:
        # A lane is turn-based by its start, and only a runner that can resume its session by an identifier and takes
        # its prompt on standard input can take turns: each missing part is named, before anything is made.
        problems = mail.turn_problems(runner_name, runner)
        if problems:
            raise Refused("--turns: runner {} cannot take turns, because {}".format(runner_name, "; ".join(problems)))
        if idle is None:
            idle = configuration.data.get("turns", {}).get("idle_seconds")
    budget = parse_budget(arguments.budget)
    if budget is None:
        budget = lanes_settings(configuration).get("budget_minutes")
    if budget is None:
        raise Refused("no time budget: give --budget MINUTES or set [lanes] budget_minutes")
    if not multiplexer.available():
        raise Refused("tmux is not on PATH; lanes run in tmux sessions")
    touches = sorted(set(arguments.touches))
    data = config.read_external(zones, arguments.brief, "--brief", MAX_BRIEF_BYTES)
    source = os.path.realpath(arguments.brief)
    check_text(source, "--brief")
    composed = brief.compose_for_lane(configuration, lane, project_name, touches, data, "--brief")
    session = Session(configuration, zones, create=True)
    try:
        with LanesLock(session.state):
            session.refresh()
            # The disk line, before anything of this lane is created: in state stop the start is refused here with the
            # reading, and no branch, worktree or lane directory is made for it; in state warn the reading is recorded
            # and one line says so, and the start goes on. The latch is the watched file system's, under the state
            # home and shared with every other configuration of this user watching it, so a stop reading taken in one
            # configuration refuses this one too.
            disk.gate(configuration, session.state)
            row = session.row(lane)
            if row is not None and row["running"]:
                raise Refused("lane {} is running run {}".format(lane, row["run"]))
            if row is not None:
                drain(session, lane)
                row = session.row(lane)
                if row["running"]:
                    raise Refused("lane {} is running run {}".format(lane, row["run"]))
            if row is not None and row["run"] >= 1:
                if not arguments.reuse:
                    raise Refused("lane {} is already known (run {}, state {}); a lane name is never reused silently: "
                                  "once it is merged or abandoned, pass --reuse".format(lane, row["run"], row["state"]))
                if row["state"] not in lanes.FINISHED:
                    raise Refused("--reuse: lane {} is {}; only a merged or abandoned lane is started again".format(
                        lane, row["state"]))
                queue = lanes.mail_of(row)
                if queue is not None and mail.queued(queue):
                    raise Refused("--reuse: lane {} has {} message(s) that wait or have returned; a new life of the "
                                  "lane is never sent mail that was written for the old one (the mail is kept, and "
                                  "what is still needed goes to another lane)".format(lane, mail.queued(queue)))
                # The registry the lane's claim was recorded in, which the lane's previous run names: the lane.started
                # of a run the launcher started, or, where the launcher started none, the adoption that stands for the
                # lane's run 1 (docs/architecture.md, "Adopting a session that already runs"). A lane with a run has
                # one of the two, so this read does not find the run missing; a lane that records no registry has
                # nothing to compare, and same_registry accepts None the same way a worktree's own claim is accepted.
                previous, _ = latest(session, lane)
                claims.same_registry(previous["claims"] if previous is not None else None)
            refuse_if_live(session, lane)
            directory = working_directory(zones, project_name, project, lane, arguments)
            socket = multiplexer.socket_path(configuration.name, session.state.real)
            name = multiplexer.session_name(lane)
            check_neighbours(session, lane, directory["worktree"], name)
            if multiplexer.alive(socket, name):
                raise Refused("a tmux session {} is still open at {}".format(name, socket))
            run = (row["run"] if row is not None else 0) + 1
            rendered = session.state.lane_path(lane, "rendered", sha256_hex(composed[0]) + ".md")
            # The lane's own session identifier, made now and kept in lane.started: every later run of the lane (a
            # resume) has this one, and a start with --reuse makes another. A runner whose start template does not
            # use {session} gets none, and its lane has none.
            session_id = str(uuid.uuid4()) if uses(runner["command"], "session") else None
            values = {"account": account, "brief": rendered, "effort": effort, "lane": lane,
                      "log": session.state.lane_path(lane, LOG), "model": model, "project": project_name,
                      "session": session_id, "worktree": directory["worktree"]}
            argv = fill(runner_name, runner["command"], values, "command")
            launch_id = uuid.uuid4().hex
            started = {"run": run, "how": "start" if run == 1 else "reuse", "launch": launch_id, "runner": runner_name,
                       "model": model, "effort": effort, "account": account, "chosen_by": chosen,
                       "difficulty": arguments.difficulty, "project": project_name, "worktree": directory["worktree"],
                       "branch": directory["branch"], "base": directory["base"],
                       "repository": directory["repository"], "budget_minutes": budget,
                       "quiet_seconds": quiet_of(configuration, runner),
                       "brief": {"path": rendered, "sha256": sha256_hex(composed[0])},
                       "log": values["log"], "session": {"socket": socket, "name": name}, "touches": touches,
                       "claims": registry_of(directory["claim"])}
            if session_id is not None:
                started["session_id"] = session_id
            if arguments.turns:
                # The brief is the lane's first message, not mail: the list is empty for a start and for a reuse.
                started["mail"] = []
                started["idle_seconds"] = idle
            validate_planned(session.state, lane, row, "lane.started", started)
            mine = claims.owner(configuration, session.state.real, lane, launch_id, directory["worktree"])
            claim = directory["claim"]
            made = {"claim": False, "worktree": False, "branch": False}
            if claim is not None:
                # An existing directory: the claim is taken atomically before anything else happens in it.
                made["claim"] = claims.take(claim, mine)
            try:
                if directory["repository"] is not None:
                    worktree.create_branch(directory["repository"], directory["branch"], directory["base"])
                    made["branch"] = True
                    worktree.add(directory["repository"], directory["worktree"], directory["branch"])
                    made["worktree"] = True
                    claim = claims.locate(directory["worktree"], "the lane's worktree", starting=True)
                    made["claim"] = claims.take(claim, mine)
                path, digest = brief.render_for_lane(session.state, lane, project_name, touches, source, data,
                                                     composed)
                if (path, digest) != (rendered, started["brief"]["sha256"]):
                    raise IntegrityProblem("the rendered brief is not where it was expected")
                spec = make_spec(configuration, lane, launch_id, argv, started, None, runner, composed[0])
                record = begin(session, lane, spec, directory["worktree"])
            except BaseException:
                undo(directory, claim, mine, made)
                raise
        try:
            event = wait_started(session, lane, spec, record)
        except BaseException:
            with LanesLock(session.state):
                session.refresh()
                begun = session.last(lane, "lane.started")
                if not (begun and begun["payload"]["launch"] == launch_id):
                    undo(directory, claim, mine, made)
            raise
        return dict(event["payload"], lane=lane, event={"id": event["id"], "seq": event["seq"]})
    finally:
        session.close()


def project_of(configuration, project_name, lane):
    """The project a lane names, checked as lane start checks it, or None when the call names none."""
    if project_name is None:
        return None
    if project_name not in configuration.projects:
        raise Refused("--project: configuration {} has no project file projects/{}.toml".format(
            configuration.name, project_name if config.NAME.fullmatch(project_name) else "<name>"))
    project = configuration.projects[project_name]
    prefix = project.get("lane_prefix")
    if prefix and not lane.startswith(prefix):
        raise Refused("project {}'s lane names start with {}".format(project_name, prefix))
    return project


def adopt_choice(configuration, project_name, project, arguments):
    """The runner, model, effort and account an adoption records, and who chose each: the checks `lane start` makes of
    them (choose), except that a part the call does not give is null rather than a routing or default choice, because an
    adoption runs no routing and takes no default account."""
    workers = project.get("workers") if project is not None else None
    excluded = set(project.get("excluded_accounts", [])) if project is not None else set()
    runner_name = arguments.runner
    runner = runner_of(configuration, runner_name)
    if workers is not None and runner_name not in workers:
        raise Refused("runner {} is not one of project {}'s workers".format(runner_name, project_name))
    if config.MODEL.fullmatch(arguments.model) is None or re.search(r"[0-9]", arguments.model) is None:
        raise Refused("--model must be a full model name that includes its version, not a family alias")
    effort = arguments.effort
    if effort is not None and config.TOKEN.fullmatch(effort) is None:
        raise Refused("--effort must match " + config.TOKEN.pattern)
    account = arguments.account
    if account is not None:
        check_account(runner_name, runner, account, excluded, project_name)
    chosen = {"runner": "supervisor", "model": "supervisor",
              "effort": None if effort is None else "supervisor",
              "account": None if account is None else "supervisor"}
    return runner_name, runner, arguments.model, effort, account, chosen


def template_fields(template):
    """The placeholder names of a path template, in order."""
    return [field for _, field, _, _ in string.Formatter().parse(template) if field is not None]


def session_templates(runner):
    """The runner's records path templates that name {session}: a session's own records are found through them."""
    return [template for entry in runner.get("records", []) for template in entry["paths"]
            if "session" in template_fields(template)]


def session_records(runner, values):
    """(paths, problems): the paths the runner's {session} records templates name for a session with these placeholder
    values, each template expanded (refusals.expand) and its matches listed (refusals.walk), the way the launcher finds
    a run's records; and what kept a template from being looked through: its reason, a directory that could not be
    listed, or more candidates than refusals.MAX_MATCHES."""
    run = {"values": values}
    found, problems = [], []
    for template in session_templates(runner):
        pattern, why = refusals.expand(template, run)
        if why:
            problems.append("{} is {}".format(template, why))
            continue
        matches, errors, overflow = refusals.walk(pattern, refusals.MAX_MATCHES)
        found.extend(matches)
        problems.extend("{} cannot be listed".format(error) for error in errors)
        if overflow:
            problems.append("{} names more than {} candidates".format(template, refusals.MAX_MATCHES))
    return found, problems


def session_lane(session, session_id, lane):
    """The lane of the configuration that already holds this session identifier (from a lane.started or a lane.adopted),
    or None: one session belongs to one lane."""
    store = session.store
    if store is None:
        return None
    for kind in ("lane.started", "lane.adopted"):
        for event in store.kind_events(kind):
            if event["lane"] != lane and event["payload"].get("session_id") == session_id:
                return event["lane"]
    return None


def adopt(configuration, zones, arguments):
    """lane adopt: take a session something outside the launcher started and make it a turn-based lane, so that the next
    turn (run 2) resumes it. Every check runs before anything is recorded or created, and a refusal appends no event,
    takes no claim and renders no brief (docs/architecture.md, "Adopting a session that already runs")."""
    lane = lane_name(arguments.lane)
    project_name = arguments.project
    project = project_of(configuration, project_name, lane)
    session = Session(configuration, zones, create=True)
    try:
        # The lanes lock from the first check of the store to the append, as lane start holds it: two adoptions, or an
        # adoption and a start, never both pass the checks of the lane name, the session and the working directory.
        with LanesLock(session.state):
            session.refresh()
            row = session.row(lane)
            if row is not None:
                raise Refused("lane {} is already known (run {}, state {}); a lane name is never reused silently: an "
                              "adoption is only for a lane that has no event yet".format(
                                  lane, row["run"], row["state"]))
            # A lane of this name that another command is starting has a run record before its lane.started is
            # stored: it is refused here, as lane start refuses it.
            refuse_if_live(session, lane)
            session_id = arguments.session
            # The identifier is checked here, never by an argparse type=: the parser replaces a type's own message
            # (cli.py), and this refusal must carry its own words.
            if lanes.SESSION_ID.fullmatch(session_id) is None:
                raise Refused("--session must be a lower-case UUID")
            owner = session_lane(session, session_id, lane)
            if owner is not None:
                raise Refused("session {} already belongs to lane {} of configuration {}".format(
                    session_id, owner, configuration.name))
            runner_name, runner, model, effort, account, chosen = adopt_choice(configuration, project_name, project,
                                                                              arguments)
            problems = mail.turn_problems(runner_name, runner)
            if problems:
                raise Refused("runner {} cannot take turns, because {}".format(runner_name, "; ".join(problems)))
            # The first turn fills the runner's resume template from this payload (continue_lane), and no later command
            # gives the lane an effort or a project: a template that names one this adoption leaves null is refused
            # now, as lane start refuses a command template it cannot fill.
            for field, value in (("effort", effort), ("project", project_name)):
                if value is None and uses(runner["resume"], field):
                    raise Refused("runner {}'s resume template uses {{{}}}, which no turn of this lane could "
                                  "fill: give --{}".format(runner_name, field, field))
            if not session_templates(runner):
                raise Refused("runner {}'s records name no {{session}}: no records entry uses {{session}}, so nothing "
                              "could show that the session exists or that nothing writes to it".format(runner_name))
            idle = parse_idle(arguments.idle)
            if idle is None:
                idle = configuration.data.get("turns", {}).get("idle_seconds")
            directory = working_directory(zones, project_name, project, lane, arguments)
            socket = multiplexer.socket_path(configuration.name, session.state.real)
            name = multiplexer.session_name(lane)
            check_neighbours(session, lane, directory["worktree"], name)
            if not multiplexer.available():
                raise Refused("tmux is not on PATH; lanes run in tmux sessions")
            if multiplexer.alive(socket, name):
                raise Refused("a tmux session {} is still open at {}".format(name, socket))
            log = session.state.lane_path(lane, LOG)
            values = {"account": account, "effort": effort, "lane": lane, "log": log, "model": model,
                      "project": project_name, "session": session_id, "worktree": directory["worktree"]}
            ages = []
            paths, problems = session_records(runner, values)
            for path in paths:
                try:
                    ages.append(os.stat(path).st_mtime)
                except OSError as error:
                    problems.append("{} cannot be read ({})".format(path, error.strerror or "error"))
            if not ages:
                raise Refused("session {} has no session record: the runner's records entries that use {{session}} "
                              "found none{}".format(session_id, "; " + "; ".join(problems) if problems else ""))
            quiet = quiet_of(configuration, runner)
            if time.time() - max(ages) < quiet:
                raise Refused("session {}'s newest record was written within the runner's quiet seconds ({} s), so it "
                              "is still being written; adopt it when nothing writes to it".format(session_id, quiet))
            budget = parse_budget(arguments.budget)
            if budget is None:
                budget = lanes_settings(configuration).get("budget_minutes")
            if budget is None:
                raise Refused("no time budget: give --budget MINUTES or set [lanes] budget_minutes")
            # Nothing is recorded or created until here: the payload is checked before the claim and the brief are made.
            data = config.read_external(zones, arguments.brief, "--brief", MAX_BRIEF_BYTES)
            source = os.path.realpath(arguments.brief)
            check_text(source, "--brief")
            composed = brief.compose_for_lane(configuration, lane, project_name, [], data, "--brief")
            digest = sha256_hex(composed[0])
            rendered = session.state.lane_path(lane, "rendered", digest + ".md")
            # The payload of a lane.started without `run`, `how` and `launch`: everything a turn reads from the
            # previous run. Every given part of chosen_by is supervisor; difficulty is null; an adoption names no
            # branch, base or repository (it takes a session and a directory that already exist).
            payload = {"runner": runner_name, "model": model, "effort": effort, "account": account,
                       "chosen_by": chosen, "difficulty": None, "project": project_name,
                       "worktree": directory["worktree"], "branch": directory["branch"], "base": directory["base"],
                       "repository": directory["repository"], "budget_minutes": budget, "quiet_seconds": quiet,
                       "brief": {"path": rendered, "sha256": digest}, "log": log,
                       "session": {"socket": socket, "name": name}, "touches": [],
                       "claims": registry_of(directory["claim"]), "session_id": session_id, "idle_seconds": idle}
            validate_planned(session.state, lane, row, "lane.adopted", payload)
            mine = claims.owner(configuration, session.state.real, lane, None, directory["worktree"])
            claim = directory["claim"]
            made = {"claim": False, "worktree": False, "branch": False}
            if claim is not None:
                made["claim"] = claims.take(claim, mine)
            try:
                path, rendered_digest = brief.render_for_lane(session.state, lane, project_name, [], source, data,
                                                              composed)
                if (path, rendered_digest) != (rendered, digest):
                    raise IntegrityProblem("the rendered brief is not where it was expected")
                event = session.append("lane.adopted", lane, payload)
            except BaseException:
                undo(directory, claim, mine, made)
                raise
            return dict(payload, lane=lane, event={"id": event["id"], "seq": event["seq"]})
    finally:
        session.close()


def resume(configuration, zones, arguments):
    return continue_lane(configuration, zones, arguments, False)


def turn(configuration, zones, arguments, environment=None, started=None):
    """lane turn: the next turn of a turn-based lane, which is a resume whose message is taken from the lane's mail.
    The loop starts its turns here too, with the environment it captured when it started (`environment`) and, when it
    runs the loop, the turns it has already started on each account in this pass (`started`, docs/architecture.md,
    "Slots and the choice of the account"); a person's `lane turn` hands over the environment of its own process and
    has no pass, so every account starts with none of its slots taken."""
    return continue_lane(configuration, zones, arguments, True, environment, started)


def refuse_turn(configuration, row, previous):
    """The lanes that take no turn, before anything else is looked at (docs/architecture.md, "What it refuses"): a
    merged lane (it is never turn-based), an abandoned one, and one that is not turn-based: it was neither started
    with --turns nor adopted, or its runner, as the configuration has it now, cannot take turns, and the message says
    what is missing."""
    lane = row["lane"]
    if row["state"] == "merged":
        raise Refused("lane {} is merged, and a merged lane is never turn-based: it takes no turn".format(lane))
    if row["state"] == "abandoned":
        raise Refused("lane {} is abandoned, so no turn starts for it; its mail is kept, and what is still needed goes "
                      "to another lane".format(lane))
    queue = lanes.mail_of(row)
    if queue is None or not queue["turn_based"]:
        raise Refused("lane {} is not turn-based: only a lane started with lane start --turns, or an adopted lane, "
                      "takes turns".format(lane))
    runner_name = previous["runner"]
    problems = mail.turn_problems(runner_name, runner_of(configuration, runner_name))
    if problems:
        raise Refused("lane {}'s runner {} cannot take turns, because {}".format(lane, runner_name,
                                                                                  "; ".join(problems)))


def turn_message(configuration, session, lane, row, arguments):
    """What the turn sends, as (kind, sequences, bytes, source), or None when no message waits or has returned and
    --idle was not given. With mail the message is the head of the queue, joined (mail.take; the source is the real
    path of the lane's mail directory); with none, and --idle, it is the idle message of the configuration as it is
    (the source is its file). --idle with mail sends the mail: the idle message is for a lane that has none."""
    queue = row["mail"]
    if queue["returned"] or queue["waiting"]:
        mailed = {item["payload"]["sequence"]: item for item in session.store.lane_events(lane, ("lane.mailed",))}
        data, taken = mail.take(session.state, lane, queue, mailed)
        return "mail", taken, data, os.path.realpath(session.state.lane_path(lane, "mail"))
    if not arguments.idle:
        return None
    if configuration.idle_message is None:
        raise Refused("lane turn --idle: the configuration has no [turns] idle_message, so there is no idle message to "
                      "send")
    relative, data = configuration.idle_message
    return "idle", [], data, os.path.realpath(str(configuration.config_dir / relative))


def continue_lane(configuration, zones, arguments, by_mail, environment=None, started=None):
    """lane resume and lane turn: continue the lane's session in its working directory with the runner's `resume`
    template. A resume gives it `--message` (or the package's follow-up); a turn gives it the lane's mail, joined, or
    the idle message, and the messages are in flight from the moment lane.started is stored. The run gets the
    environment of this process, or `environment` when the loop gives the one it captured.

    The account the turn takes comes through `accounts.choose_account` when the lane's runner has a `room` command: the
    design's own order (the one `--account` names and only that one, else the previous run's account, else the runner's
    other accounts in the order it lists them, skipping those the project excludes), each candidate asked through its
    room command. `started` is the loop's count of the turns it has already started on each account in the pass it is
    in (none for a person's `lane turn`), so the choice gives no account more than its `slots` in that pass. A runner
    without a `room` command has no room check: the account is the one `--account` named, or the previous run's as
    before, and that one is still checked (check_account), which `choose_account` does not do for it. Nothing that
    cannot take the turn is started: the refusal says why (the command's own reason) and no event is appended."""
    lane = lane_name(arguments.lane)
    budget = parse_budget(arguments.budget)
    session = Session(configuration, zones, create=False)
    try:
        if session.state is None:
            raise Refused("lane {} is not known to configuration {}".format(lane, configuration.name))
        with LanesLock(session.state):
            session.refresh()
            known_row(session, lane)
            drain(session, lane)
            row = known_row(session, lane)
            if row["run"] == 0:
                raise Refused("lane {} has not run yet; start it with lane start{}".format(
                    lane, " --turns" if by_mail else ""))
            if row["running"]:
                raise Refused("lane {} is running run {}; {} is refused".format(
                    lane, row["run"], "a turn while a run goes on" if by_mail else "resuming a running lane"))
            if row["cleaned"]:
                raise Refused("lane {} was cleaned; start it again with lane start --reuse{}".format(
                    lane, " --turns" if by_mail else ""))
            previous, _ = latest(session, lane)
            if by_mail:
                refuse_turn(configuration, row, previous)
            elif "mail" in previous or lanes.turn_based(row):
                # Its own turn-based check. A turn-based lane is never resumed: one whose latest lane.started carried
                # mail, and one the launcher did not start and a person adopted, whose row the projection makes
                # turn-based (docs/architecture.md, "Adopting a session that already runs"). Either way the refusal is
                # this one, naming lane send and lane turn — never the message of an earlier check of the payload.
                reason = ("its latest run start carries mail" if "mail" in previous
                          else "it was adopted, which makes it turn-based")
                raise Refused("lane {} is turn-based ({}), so lane resume is refused for it: send a message with lane "
                              "send and start the turn with lane turn".format(lane, reason))
            refuse_if_live(session, lane)
            sending = turn_message(configuration, session, lane, row, arguments) if by_mail else None
            if by_mail and sending is None:
                return {"lane": lane, "started": False, "reason": "no mail", "waiting": 0}
            runner_name = previous["runner"]
            runner = runner_of(configuration, runner_name)
            template = runner.get("resume")
            if template is None:
                raise Refused("runner {} has no resume template; add runners.{}.resume to the configuration".format(
                    runner_name, runner_name))
            session_id = previous.get("session_id")
            if uses(template, "session") and session_id is None:
                # Resuming by an identifier the lane never had is a wrong resume: refused before anything starts.
                raise Refused("lane {} has no recorded session identity (an earlier version started it, or its "
                              "runner's command did not use {{session}}), so it can only be resumed by a runner whose "
                              "resume template does not use {{session}}; runner {}'s does".format(lane, runner_name))
            if session_id is not None and not uses(template, "session"):
                # The other half of an identity: a resume that does not name the lane's session would continue the
                # newest session of the directory, whichever it is. Refused before anything starts, like the first.
                raise Refused("lane {} has a recorded session identity, but runner {}'s resume template "
                              "(runners.{}.resume) does not use {{session}}, so it would not continue the lane's own "
                              "session; it can only be resumed by a runner whose resume template uses {{session}}"
                              .format(lane, runner_name, runner_name))
            project_name = previous["project"]
            project = configuration.projects.get(project_name) if project_name is not None else None
            excluded = set(project.get("excluded_accounts", [])) if project is not None else set()
            if arguments.account is not None:
                # The account --account names is this command's precondition, whether or not a room command will be
                # asked: it is one the runner lists and the project keeps, or the command is refused here.
                check_account(runner_name, runner, arguments.account, excluded, project_name)
            if runner.get("room") is None:
                # No room command: the design gives this runner no room check, so the account is the one --account
                # named, or the previous run's, exactly as before. choose_account returns the previous run's account
                # unchecked; this command keeps checking it.
                if arguments.account is not None:
                    account, account_by = arguments.account, "supervisor"
                else:
                    account = previous["account"]
                    account_by = None if account is None else "previous"
                    if account is not None:
                        check_account(runner_name, runner, account, excluded, project_name,
                                      "the previous run's account (give --account to use another)")
            else:
                # The room command is the authority on which account can take a turn now: the choice is the design's
                # own order over its checked answers, and the account it answers is the one this turn uses.
                settings = lanes_settings(configuration)
                choice = accounts.choose_account(
                    runner, account=arguments.account, previous=previous["account"], excluded=excluded,
                    timeout_seconds=settings.get("room_timeout_seconds", accounts.DEFAULT_TIMEOUT_SECONDS),
                    grace_seconds=settings.get("stop_grace_seconds", accounts.DEFAULT_GRACE_SECONDS),
                    started=started)
                if choice.account is None:
                    # No room means no turn: this command appends nothing, and the message says why (the command's own
                    # reason). For the loop the same refusal is its skip, and the mail stays waiting.
                    raise Refused("lane {}: no turn starts, because {}".format(lane, choice.reason))
                account, account_by = choice.account, choice.chosen_by
            if budget is None:
                budget = previous["budget_minutes"]
            directory = previous["worktree"]
            if not os.path.isdir(directory):
                raise Refused("lane {}'s working directory {} no longer exists".format(lane, directory))
            check_directory(zones, directory, "the lane's working directory")
            claim = claims.locate(directory, "the lane's working directory", recorded=previous["claims"])
            mine = claims.owner(configuration, session.state.real, lane, None, directory)
            claims.check(claim, mine)
            verified_rendered(session.state, lane, previous["brief"], "brief")
            if not multiplexer.available():
                raise Refused("tmux is not on PATH; lanes run in tmux sessions")
            # A message always reaches a runner that takes its prompt on standard input, whatever its template says.
            takes_message = by_mail or runner.get("prompt") == "stdin" or uses(template, "message")
            if not by_mail and arguments.message is not None and not takes_message:
                raise Refused("runner {}'s resume template has no {{message}}, so a follow-up message would not reach "
                              "the runner".format(runner_name))
            message = None
            if takes_message:
                if by_mail:
                    kind, taken, data, source = sending
                    what = "the message of the turn"
                else:
                    source = arguments.message if arguments.message is not None else str(CONTINUE_FILE)
                    data = (config.read_external(zones, arguments.message, "--message", MAX_BRIEF_BYTES)
                            if arguments.message is not None else CONTINUE_FILE.read_bytes())
                    what = "--message"
                source = os.path.realpath(source)
                check_text(source, what)
                composed = brief.compose_for_lane(configuration, lane, project_name, [], data, what)
                message = {"path": session.state.lane_path(lane, "rendered", sha256_hex(composed[0]) + ".md"),
                           "sha256": sha256_hex(composed[0])}
            socket = multiplexer.socket_path(configuration.name, session.state.real)
            name = multiplexer.session_name(lane)
            if multiplexer.alive(socket, name):
                raise Refused("a tmux session {} is still open at {}".format(name, socket))
            run = row["run"] + 1
            values = {"account": account, "brief": previous["brief"]["path"], "effort": previous["effort"],
                      "lane": lane, "log": previous["log"], "model": previous["model"], "project": project_name,
                      "session": session_id, "worktree": directory, "message": message["path"] if message else None}
            argv = fill(runner_name, template, values, "resume template")
            launch_id = uuid.uuid4().hex
            started = dict(previous, run=run, how="resume", launch=launch_id, account=account, budget_minutes=budget,
                           quiet_seconds=quiet_of(configuration, runner), session={"socket": socket, "name": name},
                           chosen_by={"runner": "previous", "model": "previous",
                                      "effort": None if previous["effort"] is None else "previous",
                                      "account": account_by})
            if by_mail:
                # The messages this turn carries; idle_seconds and session_id are the previous run's, copied above.
                started["mail"] = taken
            resumed = {"run": run, "after": row["reason"], "message": message}
            validate_planned(session.state, lane, row, "lane.resumed", resumed)
            validate_planned(session.state, lane, row, "lane.started", started)
            if message is not None:
                path, digest = brief.render_for_lane(session.state, lane, project_name, [], source, data, composed)
                if (path, digest) != (message["path"], message["sha256"]):
                    raise IntegrityProblem("the rendered message is not where it was expected")
            claims.take(claim, dict(mine, launch=launch_id))
            spec = make_spec(configuration, lane, launch_id, argv, started, resumed, runner,
                             composed[0] if message is not None else b"")
            record = begin(session, lane, spec, directory, environment)
        event = wait_started(session, lane, spec, record)
        marker = session.last(lane, "lane.resumed")
        result = dict(event["payload"], lane=lane, event={"id": event["id"], "seq": event["seq"]},
                      resumed={"id": marker["id"], "seq": marker["seq"]})
        if by_mail:
            result.update(started=True, turn={"kind": kind, "mail": taken})
        return result
    finally:
        session.close()


def find_end(session, lane, run):
    """(event or pending envelope, pending) of the run's lane.ended, or (None, False)."""
    session.refresh()
    ended = session.last(lane, "lane.ended")
    if ended is not None and ended["payload"]["run"] == run:
        return ended, False
    for envelope in pending.waiting(session.state, lane):
        if envelope["kind"] == "lane.ended" and envelope["payload"].get("run") == run:
            return envelope, True
    return None, False


class NotGoingOn(Refused):
    """The refusals of `lane stop` that say that the run is not going on (it ended, or another run has begun). They are
    refusals for everything that prints them; `lane attach` tells them from the others, which it reports as they are."""


def stop(configuration, zones, arguments):
    """lane stop: ask for the stop (stop_request) and wait for the end of the run (stop_finish)."""
    lane_name(arguments.lane)
    session = Session(configuration, zones)
    try:
        result, wait = stop_request(configuration, session, arguments)
        return stop_finish(session, result, wait)
    finally:
        session.close()


def stop_request(configuration, session, arguments):
    """The first part of lane stop, up to and including the checked signal to the supervising process: (result, wait).
    `wait` is None when there is nothing to wait for (the supervising process was gone, and the recorded processes of the
    run that survived it were removed here, by identity); otherwise it holds what stop_finish needs to wait for the end
    that the supervising process records. lane attach calls the two parts apart, so that it knows when the request has
    gone out. Nothing is closed: the caller closes the session."""
    lane = lane_name(arguments.lane)
    row = known_row(session, lane)
    payload, record = launcher_run(session, lane)
    if payload is None:
        raise Refused("lane {} has not run".format(lane))
    run = payload["run"]
    if arguments.run is not None and arguments.run != run:
        raise NotGoingOn("lane {}'s latest run is run {}; run {} is not going on, so nothing was stopped".format(
            lane, run, arguments.run))
    multiplexer.check_socket(payload["session"]["socket"])
    grace = lanes_settings(configuration).get("stop_grace_seconds", DEFAULT_GRACE_SECONDS)
    result = {"lane": lane, "run": run, "launch": payload["launch"], "reason": None, "exit_code": None,
              "signal": None, "event": None, "pending": False, "removed": 0, "survivors": 0,
              "stopped_by": None}
    if record is not None and runrecord.supervisor_alive(record):
        if processes.signal_checked(record["supervisor"], signal.SIGTERM):
            return result, (lane, run, payload, record, grace)
        if runrecord.supervisor_alive(record):
            raise Refused("lane {}'s supervising process (pid {}) could not be signalled; nothing was stopped"
                          .format(lane, record["supervisor"]["pid"]))
    # The supervising process is seen gone: act on the record read after that, never on the one read before.
    record = session.record(lane, payload["launch"])
    if runrecord.survivors(record) or (record is None and row["running"]):
        return remove_survivors(lane, run, record, grace, result, ""), None
    if row["running"]:
        raise Refused("lane {}'s supervising process is gone and no process of run {} survives; lane check records "
                      "the run".format(lane, run))
    raise NotGoingOn("lane {} is not running".format(lane))


def stop_finish(session, result, wait):
    """The second part of lane stop: wait for the end that the supervising process records (stop_supervised), or, when
    stop_request found nothing to wait for, the result as it is."""
    if wait is None:
        return result
    lane, run, payload, record, grace = wait
    return stop_supervised(session, lane, run, payload, record, grace, result)


def stop_supervised(session, lane, run, payload, record, grace, result):
    """After SIGTERM to the supervising process: wait for the end it records once the run's processes are gone."""
    deadline = time.monotonic() + grace + 30
    while True:
        ended, waiting = find_end(session, lane, run)
        if ended is not None:
            break
        if not runrecord.supervisor_alive(record):
            ended, waiting = find_end(session, lane, run)
            break
        if time.monotonic() > deadline:
            current = session.record(lane, payload["launch"]) or record
            stopping = current.get("stopping")
            raise Refused("lane {}'s supervising process did not report the end of run {} in time{}".format(
                lane, run, "; it is still trying to remove {} process(es) it could not stop".format(
                    stopping["survivors"]) if stopping else ""))
        time.sleep(POLL)
    while runrecord.supervisor_alive(record) and time.monotonic() < deadline:
        time.sleep(POLL)
    if ended is not None:
        result.update(reason=ended["payload"]["reason"], exit_code=ended["payload"]["exit_code"],
                      signal=ended["payload"]["signal"], survivors=ended["payload"]["survivors"], pending=waiting,
                      event=None if waiting else {"id": ended["id"], "seq": ended["seq"]}, stopped_by="supervisor")
        return result
    # The supervising process ended without recording the end: the run is a lost run with a record, and its
    # recorded processes are removed here, by identity, or named.
    return remove_survivors(lane, run, session.record(lane, payload["launch"]), grace, result,
                            "the supervising process ended before it had stopped the run; ")


def remove_survivors(lane, run, record, grace, result, why):
    """lane stop removes the recorded processes of a run whose supervising process is gone itself, each by its
    identity, from the run record read after the supervising process was seen gone; whatever survives refuses the
    command and is named, and so does a record that cannot be read."""
    if record is None:
        raise Refused("lane {} run {}: {}its run record cannot be read, so its processes cannot be found; nothing was "
                      "removed".format(lane, run, why))
    surviving = runrecord.survivors(record)
    result["stopped_by"] = "lane-stop"
    if surviving:
        removed, left = processes.stop(surviving, grace)
        if left:
            raise Refused("lane {} run {}: {}{} of {} process(es) removed; {} survive ({}): they could not be "
                          "signalled or did not end; lane stop tries again".format(
                              lane, run, why, len(removed), len(surviving), len(left),
                              ", ".join("pid {}".format(item["pid"]) for item in left)))
        result["removed"] = len(removed)
    return result


def parse_time(value):
    return datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value).timestamp()


def status(configuration, zones, arguments):
    lane = lane_name(arguments.lane) if arguments.lane is not None else None
    session = Session(configuration, zones)
    try:
        rows = session.rows()
        if lane is not None:
            rows = [row for row in rows if row["lane"] == lane]
            if not rows:
                raise Refused("lane {} is not known to configuration {}".format(lane, configuration.name))
        listed = {}
        now = time.time()
        snapshot = processes.table()
        results = []
        for row in rows:
            event = session.last(row["lane"], "lane.started")
            live = {"launch": None, "session": None, "session_alive": None, "supervisor": None, "survivors": None,
                    "stopping": None, "pending_events": pending.count(session.state, row["lane"]),
                    "refused_events": pending.refused(session.state, row["lane"]), "running_seconds": None,
                    "budget_left_seconds": None, "quiet_seconds": None, "log_bytes": None}
            if event is not None:
                payload = event["payload"]
                record = session.record(row["lane"], payload["launch"])
                socket = payload["session"]["socket"]
                if socket not in listed:
                    listed[socket] = multiplexer.sessions(socket)
                live["launch"] = payload["launch"]
                live["session"] = payload["session"]
                live["session_alive"] = payload["session"]["name"] in listed[socket]
                if record is not None and runrecord.valid_identity(record.get("supervisor")):
                    live["supervisor"] = {"pid": record["supervisor"]["pid"],
                                          "alive": runrecord.supervisor_alive(record, snapshot)}
                live["survivors"] = len(runrecord.survivors(record, snapshot)) if record is not None else 0
                if live["supervisor"] and live["supervisor"]["alive"]:
                    live["survivors"] = 0
                    live["stopping"] = record.get("stopping")
                info = None
                lane_fd = session.state.open_lane(row["lane"])
                if lane_fd is not None:
                    try:
                        info = fsguard.file_info(lane_fd, LOG)
                    finally:
                        os.close(lane_fd)
                if info is not None:
                    live["log_bytes"] = info.st_size
                if row["running"]:
                    began = parse_time(event["occurred_at"] or event["recorded_at"])
                    live["running_seconds"] = round(max(0.0, now - began), 3)
                    live["budget_left_seconds"] = round(payload["budget_minutes"] * 60 - (now - began), 3)
                    live["quiet_seconds"] = round(max(0.0, now - max(began, info.st_mtime if info else began)), 3)
            # The lane's session identifier, which every run of the lane carries in lane.started; a lane the launcher
            # did not start carries it in the lane.adopted that stands for its run 1, whose payload is taken where no
            # lane.started exists (docs/architecture.md, "Adopting a session that already runs"). Null for a lane that
            # has none (an earlier version started it, or its runner does not use {session}).
            previous = latest(session, row["lane"])[0]
            identity = previous.get("session_id") if previous is not None else None
            # What became of the latest run's prompt (written or cut, from its lane.ended); null while it runs, once
            # it ended for a runner that takes none, and for a lane that has not run.
            ended = session.last(row["lane"], "lane.ended")
            fate = (ended["payload"].get("prompt") if ended is not None and event is not None
                    and ended["payload"]["run"] == event["payload"]["run"] else None)
            # A turn-based lane between two turns: waiting for the next one, with no run going on.
            results.append(dict(row, live=live, session_id=identity, prompt=fate,
                                idle=row["state"] == "waiting" and not row["running"]))
        return results[0] if lane is not None else results
    finally:
        session.close()


def announce(session, lane):
    """The announcement that is due for the lane's latest run, appended: ({id, seq} of the event, None), or (None, why
    nothing was appended) where the reason is None when none was due. One is due when the lane's row says that the run's
    closing event settled messages and nobody announced them (lanes.announcement), and it carries the values of the
    row's `settled`: run, sequences and, for lane.returned, the reason. It is appended by `laneboss`, as the supervising
    process's own announcement is. A refused announcement (the next run started first, the lane's events wait) or a busy
    store is not a failure of the command that closed the run: the derivation settled the messages at the closing
    event, so they are returned all the same (docs/architecture.md, "The order of `lane.delivered` against
    `lane.ended`"), and the reason goes into the command's output."""
    session.refresh()
    due = lanes.announcement(session.row(lane))
    if due is None:
        return None, None
    kind, payload = due
    try:
        appended = session.append(kind, lane, payload)
    except Refused as error:
        return None, str(error).splitlines()[0]
    except sqlite3.OperationalError as error:
        if "locked" not in str(error):
            raise
        return None, "the store is busy: {} was not appended within {} seconds".format(kind, DRAIN_SECONDS)
    return {"id": appended["id"], "seq": appended["seq"]}, None


def check(configuration, zones, arguments):
    """lane check: every lane, or only the lane that --lane names (the loop runs it for one lane whose supervising
    process it sees gone)."""
    only = lane_name(arguments.lane) if arguments.lane is not None else None
    session = Session(configuration, zones)
    try:
        if only is not None:
            known_row(session, only)

        def rows():
            return [row for row in session.rows() if only is None or row["lane"] == only]

        result = {"checked": [], "alive": [], "lost": [], "recorded": [], "refused": [], "pending": []}
        for row in rows():
            if pending.count(session.state, row["lane"]):
                appended, refusals, left = pending.flush(session.state, row["lane"], DRAIN_SECONDS)
                for key, number in (("recorded", appended), ("refused", refusals), ("pending", left)):
                    if number:
                        result[key].append({"lane": row["lane"], "events": number})
        session.refresh()
        # The lane rows first, then the process table: a run started after the rows were read is not among them,
        # and a supervising process seen gone afterwards really is gone.
        running = [row for row in rows() if row["running"]]
        latest_of = {row["lane"]: latest(session, row["lane"]) for row in running}
        for row in running:
            multiplexer.check_socket(latest_of[row["lane"]][0]["session"]["socket"])
        snapshot = processes.table()
        for row in running:
            result["checked"].append(row["lane"])
            payload, record = latest_of[row["lane"]]
            if record is None or not runrecord.valid_identity(record.get("supervisor")):
                continue
            if runrecord.supervisor_alive(record, snapshot):
                result["alive"].append(row["lane"])
                continue
            if pending.count(session.state, row["lane"]):
                continue
            survivors = len(runrecord.survivors(record, snapshot)) if record is not None else 0
            try:
                appended = session.append("lane.lost", row["lane"], {"run": row["run"], "survivors": survivors})
            except Refused:
                session.refresh()
                current = session.row(row["lane"])
                if current is not None and not (current["running"] and current["run"] == row["run"]):
                    continue
                raise
            # A turn that carried mail has its messages settled by this loss: their return is announced right behind it.
            returned, why = announce(session, row["lane"])
            entry = {"lane": row["lane"], "run": row["run"], "survivors": survivors,
                     "event": {"id": appended["id"], "seq": appended["seq"]}, "returned": returned}
            if why is not None:
                entry["returned_error"] = why
            result["lost"].append(entry)
        return result
    finally:
        session.close()


def declare_gone(session, lane):
    """R28: the payload of the supervisor's statement that the lane's open launch is gone. Only a launch with neither
    an end event nor a readable run record is open in this sense, and only while nothing the launcher can attribute
    to it is seen alive (its tmux session). No end is made up: the launch's end stays unknown."""
    started = session.last(lane, "lane.started")
    if started is None:
        raise Refused("lane {} has not run; nothing was declared".format(lane))
    payload = started["payload"]
    if any(event is not None and event["payload"]["run"] == payload["run"]
           for event in (session.last(lane, "lane.ended"), session.last(lane, "lane.gone"))):
        raise Refused("lane {}'s run {} is not open: its end or its declaration is recorded".format(lane, payload["run"]))
    try:
        record = session.record(lane, payload["launch"])
    except IntegrityProblem:
        record = None
    if record is not None:
        raise Refused("lane {}'s run {} has a readable run record: lane stop removes what survives of it, and resume, "
                      "reuse and clean then go on; nothing was declared".format(lane, payload["run"]))
    if multiplexer.alive(payload["session"]["socket"], payload["session"]["name"]):
        raise Refused("lane {}'s tmux session {} is open, so its supervising process may be alive; nothing was "
                      "declared".format(lane, payload["session"]["name"]))
    return {"run": payload["run"], "launch": payload["launch"]}


def refuse_if_survivors(session, lane):
    """Every run of the lane has ended: no recorded process of any run survives, and the latest launch has a run record
    or an end that shows its processes are gone. A supervising process that is still writing a recorded end down does
    not count: its run's processes are gone."""
    payload, record = launcher_run(session, lane)
    if payload is not None and record is None:
        ended, gone = session.last(lane, "lane.ended"), session.last(lane, "lane.gone")
        if not (ended is not None and ended["payload"]["run"] == payload["run"] and not ended["payload"]["survivors"]
                or gone is not None and gone["payload"]["run"] == payload["run"]):
            raise Refused("lane {}'s run {} has no run record and no end event that shows its processes are gone, so "
                          "its records cannot be scanned to their end; restore the record, or declare the launch gone "
                          "with lane mark --gone".format(lane, payload["run"]))
    launches = {event["payload"]["run"]: event["payload"]["launch"]
                for event in session.store.lane_events(lane, ("lane.started",))}
    ended = {launches.get(event["payload"]["run"])
             for event in session.store.lane_events(lane, ("lane.ended", "lane.lost", "lane.gone"))}
    snapshot = processes.table()
    for record in runrecord.every(session.state, lane):
        if record.get("launch") not in ended and runrecord.supervisor_alive(record, snapshot):
            raise Refused("a run of lane {} is alive (run {}), so its records are not complete; nothing was "
                          "recorded".format(lane, record.get("run")))
        surviving = runrecord.survivors(record, snapshot)
        if surviving:
            raise Refused("{} process(es) of lane {}'s run {} survive, so its records may still grow; lane stop removes "
                          "them".format(len(surviving), lane, record.get("run")))


def gate(session, zones, lane, accept_uncovered):
    """Before accepted or merged: scan every run of the lane to its end, then refuse while a refusal or suspicion
    could not be recorded, while a suspected workaround has a path without a verdict, and while a run that should be
    scanned is not covered, unless the supervisor accepts that with --accept-uncovered. Returns what the scan appended
    and what was not covered; None without guards."""
    if not guards.configured(session.configuration):
        if accept_uncovered:
            raise Refused("--accept-uncovered: configuration {} has no guards, so nothing is scanned".format(
                session.configuration.name))
        return None
    refuse_if_survivors(session, lane)
    from . import refusals  # only the commands that scan load the scan
    scanned = refusals.scan_lane(session, zones, lane, "lane mark")
    if scanned["refused_events"]:
        raise Refused("the store refused {} refusal or suspicion event(s) of lane {} (kept in refused.jsonl in the "
                      "lane's directory), so its refusals cannot be checked; nothing was recorded".format(
                          scanned["refused_events"], lane))
    if scanned["pending_events"]:
        raise Refused("lane {} has {} event(s) waiting to be recorded, so its suspected workarounds cannot be checked; "
                      "lane check records them once the store can be written".format(lane, scanned["pending_events"]))
    if scanned["unreviewed"]:
        raise Refused("lane {} has suspected workarounds without a verdict; review each path with lane review "
                      "--refusal ID --path PATH --verdict clean|workaround:\n{}".format(lane, "\n".join(
                          "refusal {} path {} (suspicion {})".format(item["refusal"], item["path"],
                                                                     ", ".join(item["suspicions"]))
                          for item in scanned["unreviewed"])))
    if scanned["not_covered"] and not accept_uncovered:
        raise Refused("lane {}'s session records were not all scanned, so a refusal may be missing; make them readable "
                      "and mark again, or pass --accept-uncovered to record the decision with what was not covered:\n"
                      "{}".format(lane, "\n".join("run {} {}{}".format(item["run"], item["reason"], " " + item["path"]
                                                                       if item["path"] else "")
                                                  for item in scanned["not_covered"])))
    return {"appended": scanned["appended"], "not_covered": scanned["not_covered"]}


def mark(configuration, zones, arguments):
    lane = lane_name(arguments.lane)
    if [arguments.state is not None, arguments.landing is not None, arguments.gone].count(True) != 1:
        raise Refused("lane mark records one decision: give --state, --landing or --gone")
    if arguments.accept_uncovered and arguments.state not in ("accepted", "merged"):
        raise Refused("--accept-uncovered goes with --state accepted or --state merged")
    session = Session(configuration, zones)
    try:
        if arguments.state in ("accepted", "merged") and session.state is not None:
            # Accepting holds the lanes lock that resume and a reused start hold, from before it reads the lane's runs
            # until its decision is stored: no run can begin between its scan and its decision.
            with LanesLock(session.state):
                session.refresh()
                return decide(session, zones, lane, arguments)
        return decide(session, zones, lane, arguments)
    finally:
        session.close()


def decide(session, zones, lane, arguments):
    known_row(session, lane)
    drain(session, lane)
    row = known_row(session, lane)
    scanned = None
    if arguments.gone:
        kind, payload = "lane.gone", declare_gone(session, lane)
    elif arguments.state is not None:
        if row["running"]:
            raise Refused("lane {} is running; stop it before deciding its state".format(lane))
        kind, payload = "lane.state", {"state": arguments.state}
        if arguments.state in ("accepted", "merged"):
            scanned = gate(session, zones, lane, arguments.accept_uncovered)
            if scanned is not None and scanned["not_covered"]:
                payload["not_covered"] = scanned["not_covered"]
    else:
        kind, payload = "lane." + arguments.landing, {}
    appended = session.append(kind, lane, payload, actor=SUPERVISOR)
    result = {"lane": lane, "kind": kind, "event": {"id": appended["id"], "seq": appended["seq"]}}
    result.update(payload or {"landing": arguments.landing})
    if scanned is not None:
        result["scan"] = scanned
    if arguments.gone:
        # The declaration settles the run's messages, or the loss that came before it did and nobody announced it: the
        # announcement that is due (with the reason of `settled`) is appended now, and none is due for a run that
        # carried no mail or whose loss was announced.
        result["returned"], why = announce(session, lane)
        if why is not None:
            result["returned_error"] = why
    return result


def scan(configuration, zones, arguments):
    """lane scan: read every record of the lane's runs to its end and append what is not recorded yet."""
    from . import refusals
    lane = lane_name(arguments.lane)
    session = Session(configuration, zones)
    try:
        known_row(session, lane)
        drain(session, lane)
        known_row(session, lane)
        return refusals.scan_lane(session, zones, lane, "lane scan")
    finally:
        session.close()


def refusal_listing(configuration, zones, arguments):
    """lane refusals: what is recorded about refusals and what the latest scans covered; read-only."""
    from . import refusals
    lane = lane_name(arguments.lane) if arguments.lane is not None else None
    session = Session(configuration, zones)
    try:
        if lane is not None:
            known_row(session, lane)
            return refusals.listing(session, lane)
        return [refusals.listing(session, row["lane"]) for row in session.rows()]
    finally:
        session.close()


NOTE_BYTES = 16 * 1024


def read_note(zones, path):
    """The note of a verdict, read from a file. Its path, every part of it as given and as it resolves, goes through
    the credential detector before anything is said about it: a wrong variable is never repeated."""
    for candidate in (path, os.path.abspath(path), os.path.realpath(path)):
        for part in [candidate] + candidate.split("/"):
            found = credentials.find_in_text(part)
            if found:
                raise Refused("--note: the path looks like a credential ({}); nothing was read".format(found[0]))
    data = config.read_external(zones, path, "--note", NOTE_BYTES)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("--note: the note must be UTF-8 text") from None
    if not text.strip() or len(text) > lanes.NOTE_CHARACTERS:
        raise Refused("--note: the note must hold 1 to {} characters".format(lanes.NOTE_CHARACTERS))
    found = credentials.find_in_text(text)
    if found:
        raise Refused("--note line {}: looks like a credential ({}); nothing was recorded".format(found[1], found[0]))
    return {"text": text, "sha256": sha256_hex(data)}


def review(configuration, zones, arguments):
    """lane review: the supervisor's verdict on one path of a refusal's suspected workarounds."""
    lane = lane_name(arguments.lane)
    if lanes.REFUSAL_ID.fullmatch(arguments.refusal or "") is None:
        raise Refused("--refusal must be a refusal id ({})".format(lanes.REFUSAL_ID.pattern))
    path = arguments.path
    check_text(path, "--path")
    note = read_note(zones, arguments.note) if arguments.note is not None else None
    session = Session(configuration, zones)
    try:
        known_row(session, lane)
        drain(session, lane)
        row = known_row(session, lane)
        if lanes.MORE_PATHS.fullmatch(path):
            raise Refused("--path {} stands for paths an event could not hold, so it cannot be reviewed; read the "
                          "suspected call in its record (lane refusals names it), and abandon the lane if it cannot be "
                          "accepted".format(path))
        if path != lanes.COMMAND_PATH and not lanes.WITHHELD_PATH.fullmatch(path) and not path.startswith("/"):
            if not row["worktree"]:
                raise Refused("--path is relative, but lane {} has no working directory to read it from".format(lane))
            path = os.path.normpath(os.path.join(row["worktree"], path))
        found = lanes.refusal_state(row)
        if arguments.refusal not in found["recorded"]:
            raise Refused("lane {} has no recorded refusal {}".format(lane, arguments.refusal))
        suspicions = sorted(name for name, item in found["suspected"].items()
                            if item["refusal"] == arguments.refusal and path in item["paths"])
        if not suspicions:
            raise Refused("no suspected workaround of refusal {} names {}; lane refusals lists the paths".format(
                arguments.refusal, path))
        payload = {"refusal": arguments.refusal, "path": path, "verdict": arguments.verdict, "suspicions": suspicions,
                   "note": note}
        appended = session.append("lane.refusal_reviewed", lane, payload, actor=SUPERVISOR)
        session.refresh()
        return dict(payload, lane=lane, event={"id": appended["id"], "seq": appended["seq"]},
                    unreviewed=lanes.refusal_state(session.row(lane))["unreviewed"])
    finally:
        session.close()


def clean(configuration, zones, arguments):
    lane = lane_name(arguments.lane)
    session = Session(configuration, zones)
    try:
        if session.state is None:
            raise Refused("lane {} is not known to configuration {}".format(lane, configuration.name))
        with LanesLock(session.state):
            session.refresh()
            known_row(session, lane)
            drain(session, lane)
            row = known_row(session, lane)
            if row["running"] or row["state"] not in lanes.FINISHED:
                raise Refused("lane clean takes a lane marked merged or abandoned that is not running; lane {} is {}"
                              .format(lane, "running" if row["running"] else row["state"]))
            if row["cleaned"]:
                raise Refused("lane {} was already cleaned".format(lane))
            payload, _ = launcher_run(session, lane)
            refuse_if_live(session, lane)
            removed, kept = [], []
            release = None
            if payload is not None:
                socket, name = payload["session"]["socket"], payload["session"]["name"]
                multiplexer.check_socket(socket)
                mine = claims.owner(configuration, session.state.real, lane, payload["launch"])
                path, repository, branch = payload["worktree"], payload["repository"], payload["branch"]
                claim = (claims.locate(path, "the lane's working directory", recorded=payload["claims"])
                         if os.path.isdir(path) else None)
                value = claims.read(claim) if claim is not None else None
                if value is not None and not claims.same_lane(value, mine):
                    raise Refused("lane {}'s working directory {} is claimed by {}; nothing was removed".format(
                        lane, path, claims.describe(value)))
                if repository is not None:
                    if not remove_created(lane, path, repository, branch, value is not None, removed, kept) and \
                            value is not None:
                        release = claim
                    if branch is not None:
                        if row["state"] == "abandoned":
                            kept.append({"item": "branch", "name": branch, "why": "abandoned"})
                        elif not worktree.branch_exists(repository, branch):
                            kept.append({"item": "branch", "name": branch, "why": "missing"})
                        elif worktree.delete_merged_branch(repository, branch):
                            removed.append({"item": "branch", "name": branch})
                        else:
                            kept.append({"item": "branch", "name": branch, "why": "not-merged"})
                else:
                    kept.append({"item": "worktree", "path": path, "why": "not-created"})
                    if value is not None:
                        release = claim
                    if payload["claims"] is not None:
                        # The lane's claims on this path under another identity: the directory is gone, or was
                        # removed and made again. The directory there now, and its own claim, are left alone.
                        claims.release_stale(payload["claims"], mine, path,
                                             keep=claim.name if claim is not None else None)
                # A session under the lane's name now is not the lane's: its supervising process is gone. It is
                # never killed by its name.
                if multiplexer.alive(socket, name):
                    kept.append({"item": "session", "name": name, "why": "not-this-lane"})
            kept.append({"item": "lane-directory", "path": session.state.lane_path(lane), "why": "record"})
            if release is not None:
                claims.release(release, mine)
            envelope = {"id": "ev-" + uuid.uuid4().hex, "kind": "lane.cleaned", "lane": lane, "actor": PROGRAM,
                        "occurred_at": events.utc_now(), "payload": {"removed": removed, "kept": kept},
                        "protocol_version": load_protocol()[1]}
            stored = pending.record(session.state, lane, envelope, DRAIN_SECONDS)
            session.refresh()
            event = session.last(lane, "lane.cleaned") if stored else None
            return {"lane": lane, "event": {"id": event["id"], "seq": event["seq"]} if event else None,
                    "pending": not stored, "removed": removed, "kept": kept}
    finally:
        session.close()


def remove_created(lane, path, repository, branch, claimed, removed, kept):
    """Remove a worktree the launcher created, without force, only when it still carries this lane's claim and
    branch; True when it is removed. When Git fails, say from the file system what the worktree looks like
    afterwards."""
    if not os.path.isdir(path):
        kept.append({"item": "worktree", "path": path, "why": "missing"})
        return False
    if not claimed or worktree.head_branch(path) != branch:
        kept.append({"item": "worktree", "path": path, "why": "not-this-lane"})
        return False
    status_code, changes, _ = worktree.git(path, "status", "--porcelain")
    if status_code != 0 or changes:
        raise Refused("lane {}'s worktree {} has uncommitted or untracked work, so nothing was removed; commit it, "
                      "move it away or remove it yourself".format(lane, path))
    before = listing(path)
    done, reason = worktree.remove(repository, path)
    if done:
        removed.append({"item": "worktree", "path": path})
        return True
    after = listing(path) if os.path.isdir(path) else []
    if after == before:
        raise Refused("Git refused to remove lane {}'s worktree without force and the worktree is unchanged; nothing "
                      "was removed: {}".format(lane, reason))
    raise Refused("Git failed while removing lane {}'s worktree and it is partly removed: {} of {} entries are gone "
                  "from {}; the branch and the claim were left alone: {}".format(
                      lane, len(set(before) - set(after)), len(before), path, reason))


def mail_target(configuration, session, lane):
    """The lane's row, when the lane can take mail now: it is known, turn-based (its row has `mail` with `turn_based`
    true, which a lane started with --turns has, and so has an adopted lane), not cleaned and not abandoned; its runner,
    as the configuration has it now, takes turns ({session} in `command` and in `resume`, prompt = "stdin", a `resume`
    template); and fewer than 1,000 of its messages wait or have returned. Each refusal says what is wrong."""
    row = known_row(session, lane)
    queue = row.get("mail")
    if queue is None or not queue["turn_based"]:
        raise Refused("lane {} is not turn-based: only a lane started with lane start --turns, or an adopted lane, "
                      "takes mail".format(lane))
    if row["cleaned"]:
        raise Refused("lane {} was cleaned, so it takes no mail".format(lane))
    if row["state"] == "abandoned":
        raise Refused("lane {} is abandoned, so it takes no mail; its mail is kept, and what is still needed goes to "
                      "another lane".format(lane))
    # The lane's previous run: a lane.started, or a lane.adopted where the launcher started no run — its runner, as the
    # person who adopted the lane gave it, is the one the turns use (docs/architecture.md, "Adopting a session that
    # already runs").
    previous, _ = latest(session, lane)
    if previous is None:
        raise Refused("lane {} has not run yet, so it takes no mail".format(lane))
    runner_name = previous["runner"]
    problems = mail.turn_problems(runner_name, runner_of(configuration, runner_name))
    if problems:
        raise Refused("lane {} cannot take mail: runner {} cannot take turns, because {}".format(
            lane, runner_name, "; ".join(problems)))
    if mail.queued(queue) >= lanes.MAX_QUEUE:
        raise Refused("lane {} already has {} messages that wait or have returned, the most a lane holds; a turn takes "
                      "them".format(lane, lanes.MAX_QUEUE))
    return row


def send_mail(configuration, zones, arguments):
    """lane send: one message of a turn-based lane becomes an immutable file in the lane's mail directory and one event,
    lane.mailed, that carries its sequence, sender, hash and size and never its text (docs/architecture.md, "Mail (built by
    T2)"). The file comes first and the event second, and the lane's mail lock orders two sends. Everything is checked
    before a byte is written, and a refusal leaves no file and no event."""
    lane = lane_name(arguments.lane)
    sender = mail.check_sender(arguments.sender)
    data = mail.read_message(zones, arguments.file, arguments.source)
    return send_message(configuration, zones, lane, sender, data)


def send_message(configuration, zones, lane, sender, data):
    """The rest of lane send, for a message that is in memory already: lane attach stores a typed line through it, so
    that the line takes the same checks, the same lock and the same events as a message sent with lane send. The
    caller has checked the lane's name and the sender."""
    mail.check_message(data)
    session = Session(configuration, zones)
    try:
        known_row(session, lane)
        drain(session, lane)
        mail_target(configuration, session, lane)
        with MailLock(session.state, lane):
            session.refresh()
            # The sequence follows the lane's last as it is now: no other send can take one while the lock is held.
            row = mail_target(configuration, session, lane)
            sequence = row["mail"]["last"] + 1
            path, digest = mail.store_file(session.state, lane, sequence, data)
            payload = {"sequence": sequence, "sender": sender, "sha256": digest, "bytes": len(data)}
            try:
                appended = session.append("lane.mailed", lane, payload, actor=SUPERVISOR)
            except sqlite3.OperationalError as error:
                if "locked" not in str(error):
                    raise
                raise Refused("the store is busy: lane.mailed was not appended within {} seconds, so nothing was "
                              "recorded; the message file {} is kept, and sending the same bytes again reuses it".format(
                                  DRAIN_SECONDS, path)) from None
            session.refresh()
            waiting = mail.queued(session.row(lane)["mail"])
        return {"lane": lane, "sequence": sequence, "sender": sender, "sha256": digest, "bytes": len(data), "file": path,
                "event": {"id": appended["id"], "seq": appended["seq"]}, "waiting": waiting}
    finally:
        session.close()


ACTIONS = {"start": start, "adopt": adopt, "resume": resume, "stop": stop, "status": status, "check": check,
           "mark": mark, "clean": clean, "scan": scan, "refusals": refusal_listing, "review": review,
           "send": send_mail, "turn": turn}


def run(configuration, zones, arguments):
    """A file or directory that disappears under a lane command (removed by another process between two steps) is a
    clear refusal, never an internal error; LANEBOSS_DEBUG=1 adds the traceback."""
    try:
        return ACTIONS[arguments.action](configuration, zones, arguments)
    except FileNotFoundError as error:
        if os.environ.get(env_name("DEBUG")):
            traceback.print_exc()
        raise Refused("{} disappeared while lane {} ran; nothing more was done: run the command again".format(
            error.filename or "a file or directory it used", arguments.action)) from None
