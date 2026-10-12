"""The room command of an account: whether an account can take a turn now, and how many turns it can take.

A runner may name a `room` argument vector (docs/architecture.md, "Accounts and adoption", "The room command"), with
`{account}` as its only placeholder, so that one template serves every account of the runner. The launcher runs it
without a shell, with standard input from /dev/null and the caller's environment, once for each account it considers,
and waits at most `[lanes] room_timeout_seconds`. Its standard output must be exactly one JSON object of at most 4 KiB
with the keys `room`, `slots` and `reason`; a non-zero exit, a timeout, or output that is not exactly that object
counts as no room, with the fixed sentence as the reason, and nothing of such output is shown.

After every run — whether it ended in time, timed out, or wrote too much — the command's process and every process of
its tree, group and session are stopped by their identity. Each look is walked to a fixpoint before any signal is
sent: the walk starts from every process already found and still alive, and a process found through the group or
session has its own children walked too, so a command that leaves a member of its own group behind leaves nothing the
walk can still see. After a stop that reports nothing living, one more look is taken and anything it finds alive is a
survivor. When any process the stop found is not seen gone afterwards (or the process table cannot be read to observe
it), the answer is no room as well.

What this does not promise, and what this module does not claim: a descendant outside the command's process group and
session whose parent has ended before a look of the stop walked from it — before the first look, or during the stop,
as when a process the stop found in a session of its own starts a child and ends — is not found, not stopped and not
counted, and the answer can then be room while it runs. That gap is named and kept: the process that runs the room
command does not call `processes.become_subreaper`, so a descendant that left the command's group and session and
whose parent ended is not adopted back into the command's tree. Outside Linux the gap is wider: `ps` reports no
session id, so a process that only left the command's group is missed the same way (processes.py).

The command's tool belongs to the organisation: config.check_tools_not_shared refuses a `room` whose program is an
absolute path into another organisation's tools, exactly as it does for `command` and `resume`.

The core knows no vendor. This module runs the configured program, checks its answer, and gives the account one turn
takes from those answers (`choose_account`, the design's order, "Slots and the choice of the account"); `lane turn`,
`lane resume` and the loop take their account through `choose_account` for a runner with a `room` command
(`lanecmd.continue_lane`), and `lane start` does not ask the room command.
"""

import json
import os
import selectors
import subprocess
import time

from . import credentials, processes

# The documented object: at most 4 KiB of standard output, these three keys and no others, and this range of values.
MAX_OUTPUT_BYTES = 4096
MAX_REASON = 200
MAX_SLOTS = 64
KEYS = ("room", "slots", "reason")
# `[lanes] room_timeout_seconds` defaults to this, and `[lanes] stop_grace_seconds` to DEFAULT_GRACE_SECONDS: the
# caller reads both settings and passes them here.
DEFAULT_TIMEOUT_SECONDS = 20
DEFAULT_GRACE_SECONDS = 10
WITHHELD = "(withheld)"
POLL = 0.1
CHUNK = 65536
REAP_SECONDS = 5.0


class Room:
    """One account's checked answer.

    `room` is whether the account can take a turn now, `slots` how many turns it can take, and `reason` why, for a
    person to read. Every answer that is not the documented object is a Room of no room whose reason is the fixed
    sentence; a reason that carries a credential shape is `(withheld)`."""

    def __init__(self, room, slots, reason):
        self.room = room
        self.slots = slots
        self.reason = reason


def no_room(account):
    """No room, with the one sentence a command that did not answer in the documented form is given. Nothing else of
    such a command's output is ever shown."""
    return Room(False, 0,
                "the room command of account {} did not answer in the documented form".format(account))


def _unique(pairs):
    """A repeated key makes the output not one object; json calls this for every object it reads."""
    found = {}
    for key, item in pairs:
        if key in found:
            raise ValueError("a key is repeated")
        found[key] = item
    return found


def _constant(name):
    raise ValueError("not a finite number")


def read_answer(data):
    """The Room these bytes are, or None when they are not exactly the documented object.

    The reason of an accepted answer is replaced by `(withheld)` when the credential detector refuses it, so a
    credential a command wrote is never returned, never shown and never recorded."""
    if len(data) > MAX_OUTPUT_BYTES:
        return None
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if type(value) is not dict or set(value) != set(KEYS):
        return None
    room, slots, reason = value["room"], value["slots"], value["reason"]
    if type(room) is not bool or type(slots) is not int or not isinstance(reason, str):
        return None
    if not 0 <= slots <= MAX_SLOTS:
        return None
    if room is False and slots != 0:
        return None
    if room is True and slots < 1:
        return None
    if len(reason) > MAX_REASON or any(ord(character) < 32 or ord(character) == 127 for character in reason):
        return None
    if room is False and not reason:
        # The reason may be empty only when the account has room (room is true); a refusal must say why.
        return None
    try:
        reason.encode("utf-8")
    except UnicodeEncodeError:
        # The reason is not text the launcher can write (an unpaired surrogate), so it is not the documented form.
        return None
    if credentials.find_in_text(reason) is not None:
        reason = WITHHELD
    return Room(room, slots, reason)


def _stop_tree(process, grace):
    """Stop the command's process and every process of its tree, group and session, each by its identity: SIGTERM,
    then SIGKILL after `grace`. Never by a group signal and never by a pattern over command lines, as the supervising
    process stops a run (processes.stop). Each look is walked to a fixpoint before any signal: the roots grow from
    every process found and a process found through the group or session has its own children walked too, so a
    descendant the command has already reparented is still found while one of its remembered ancestors lives. After a
    stop that reports nothing living, one more look is taken and anything it finds alive is a survivor.

    Returns the identities still living after the stop, or None when the process table cannot be read and the end
    cannot be observed. The command is this caller's own child: on the path where it ended in time its exit status has
    already been collected by the caller, so there is nothing left to signal and a direct signal is not sent, while on
    the timeout path it is still uncollected and is signalled directly when the table cannot be read, and the stop is
    retried; the failure is not swallowed. The command's own exit status is collected afterwards, so no process of the
    launcher's is left unreaped."""
    known = []
    try:
        root = processes.identity(process.pid)
    except processes.Unobservable:
        root = None
    if root is not None:
        known.append(root)

    def discover():
        """The processes of the command's tree and of its group and session, as the table shows them now: the
        command's tree can grow or reparent while it is being stopped, so the walk starts again from the command and
        from every process already found and still alive, and is looked for again at every step of the stop. Inside
        this one look it is walked to a fixpoint on the same snapshot — every process found is a root of the next
        walk, so a process found only through the group or session has its own children found too — before anything is
        signalled: a first look short of that fixpoint misses a child of a group member whose own parent link to the
        command is already gone, and the signal to that member orphans the child before the next look."""
        snapshot = processes.table()
        roots = [recorded["pid"] for recorded in known if processes.alive(recorded, snapshot)]
        if process.pid not in roots:
            roots.append(process.pid)
        groups = (process.pid,)
        found = processes.descendants(roots, snapshot, groups=groups, sessions=groups)
        while processes.merge(found, processes.descendants([item["pid"] for item in found], snapshot, groups=groups,
                                                           sessions=groups)):
            pass
        processes.merge(known, found)
        return found

    def end():
        """One attempt at the stop: the identities still living, or None when the end cannot be observed."""
        try:
            return processes.stop(known, grace, discover=discover)[1]
        except processes.Unobservable:
            return None

    surviving = end()
    if surviving is None or surviving:
        # This caller's own child is signalled directly even when the table cannot be read: on the timeout path it is
        # still uncollected, so its id cannot have been reused and Popen.kill reaches it; where it ended in time the
        # caller has already collected it, poll() says so and no signal is sent. Then the stop is tried once more.
        # Nothing is swallowed: what still lives, or cannot be observed, is reported to the caller.
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        surviving = end()
    if surviving == []:
        # A stop that reports nothing living can still be one look short: the loop of processes.stop ends on a table
        # read that found nothing living, and a process its own discovery saw a moment earlier can start a child and
        # end in between, so that child is in no look at all. One more look is taken here, after the stop, with the
        # same reach (the command's tree, group and session, grown from every process known) and on a snapshot later
        # than both of the stop's last two reads, so the child that window hid is seen. This closes that window for a
        # child in the command's group or session, or one still held by a living process the stop knows; a child
        # outside them whose parent has ended is the gap this module names. Anything it finds alive is a survivor —
        # counted, not signalled again — and a survivor means no room; a table that cannot be read leaves the end
        # unobserved, which means no room as well.
        try:
            discover()
            surviving = processes.living(known)
        except processes.Unobservable:
            surviving = None
    try:
        process.wait(timeout=REAP_SECONDS)
    except (subprocess.TimeoutExpired, OSError):
        pass
    return surviving


def _collect(process, seconds, grace):
    """(exit status, standard output, stopped) of the command: the status is None when the command could not be
    started, did not end within `seconds`, or wrote more than MAX_OUTPUT_BYTES. In every case the command's process
    and every process of its tree, group and session are stopped before this returns, and nothing of its output is kept
    beyond the bytes this function already read. `stopped` is False when a process of the command is not seen gone
    after the stop, or when the end cannot be observed at all."""
    deadline = time.monotonic() + seconds
    output = bytearray()
    ended = False
    selector = selectors.DefaultSelector()
    try:
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(min(deadline - time.monotonic(), POLL)):
                continue
            try:
                chunk = os.read(process.stdout.fileno(), CHUNK)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                chunk = b""
            if not chunk:
                ended = True
                break
            output += chunk
            if len(output) > MAX_OUTPUT_BYTES:
                break
    finally:
        selector.close()
    status = None
    if ended:
        # Standard output is closed. The command itself may still be ending: it gets what is left of its time.
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        status = process.returncode
    # Whatever the status, the command may have left processes of its own tree or group behind: they are stopped now,
    # not only at the timeout, so a command that ends in time cannot leave one more process at every pass.
    surviving = _stop_tree(process, grace)
    return status, bytes(output), surviving is not None and not surviving


def _run(argv, seconds, grace):
    """Run one room command: (exit status, standard output, stopped). Nothing is added to the argument vector and no
    shell is used; standard input is /dev/null, standard error is discarded (nothing of it is part of the answer) and
    the command gets a session of its own, so that its group is its own to stop."""
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   start_new_session=True, close_fds=True)
    except (OSError, ValueError):
        # The program was not found or could not be started. No status is made up, and there is no process to stop.
        return None, b"", True
    try:
        return _collect(process, seconds, grace)
    finally:
        try:
            process.stdout.close()
        except OSError:
            pass


def room_of(runner, account, timeout_seconds, grace_seconds=DEFAULT_GRACE_SECONDS):
    """Ask one account's room command whether the account can take a turn now: its checked answer, a Room.

    `runner` is a runner of a configuration — only its `room` argument vector is read — `account` the account the
    command is asked about, `timeout_seconds` the time it has (`[lanes] room_timeout_seconds`, 1 to 60, default 20)
    and `grace_seconds` the time SIGTERM has before SIGKILL when the command has to be stopped
    (`[lanes] stop_grace_seconds`). None when the runner names no `room` command: such a runner has no room check.

    This is one call, and it has no input or output of its own beyond running the configured command: every answer
    that is not the documented object is no room, and when a process the stop found is not seen gone after it (or the
    end cannot be observed) the answer is no room as well. What that stop cannot promise is named in this module's
    docstring: a descendant outside the command's process group and session whose parent has ended before a look of the
    stop walked from it — before the first look, or during the stop, as when a process the stop found in a session of
    its own starts a child and ends — is not found, not stopped and not counted, and the answer can then be room while
    it runs."""
    template = runner.get("room")
    if template is None:
        return None
    status, output, stopped = _run([element.format(account=account) for element in template], timeout_seconds,
                                   grace_seconds)
    if status != 0 or not stopped:
        return no_room(account)
    answer = read_answer(output)
    return no_room(account) if answer is None else answer


# The values of `lane.started`'s `chosen_by.account` this module writes: `supervisor` when `--account` named the account,
# `previous` when it is the previous run's account, and `room` when the room command's answer chose it (the value T5
# adds; `default` is the runner's own default account, which `lane start` records and this choice never writes).
CHOSEN_BY_SUPERVISOR = "supervisor"
CHOSEN_BY_PREVIOUS = "previous"
CHOSEN_BY_ROOM = "room"
# The reason of an account that has room but has already taken every turn this pass gives it (the command's own reason
# is empty or says the account has room, so the sentence names what this pass has done).
FULL_REASON = "account {account} has taken its {slots} turn(s) for this pass"

# The outcome of a Choice: `chosen` when an account was chosen, else which "no account" answer this is, so that a
# caller can tell the cases apart without reading the reason's text. `no-check` is a runner without a room command,
# which the design gives no room check — it is not "no room"; `named-no-room` is the account `--account` named;
# `no-room` is the walk of the runner's list finding that no candidate has room; `named-unusable` is an account
# `--account` named that the runner does not list or the project excludes, which this choice never asks about and
# never uses. An outcome is `chosen` exactly when the Choice has an account.
OUTCOME_CHOSEN = "chosen"
OUTCOME_NO_CHECK = "no-check"
OUTCOME_NAMED_NO_ROOM = "named-no-room"
OUTCOME_NO_ROOM = "no-room"
OUTCOME_NAMED_UNUSABLE = "named-unusable"


class Choice:
    """The account one turn takes, who chose it, or why no account was chosen.

    `account` is the account to use, or None when nothing could be chosen. `chosen_by` is the value for `lane.started`'s
    `chosen_by.account`: `supervisor` when `--account` named the account, `previous` when it is the previous run's
    account, `room` when the room command's answer chose it, and None when nothing was chosen. `outcome` tells the
    cases apart (this module's OUTCOME_ constants): `chosen` when an account was chosen, else `no-check`,
    `named-no-room`, `no-room` or `named-unusable`; it is `chosen` exactly when `account` is not None, so an answer
    that names no account must say which outcome it is. `reason` says why nothing was chosen, for a person to read,
    and is None when an account was chosen."""

    def __init__(self, account=None, chosen_by=None, reason=None, outcome=None):
        if account is not None:
            outcome = OUTCOME_CHOSEN
        elif outcome is None:
            raise ValueError("a Choice with no account must say in which outcome nothing was chosen")
        self.account = account
        self.chosen_by = chosen_by
        self.reason = reason
        self.outcome = outcome


def _unusable(accounts, account, excluded):
    """Why the account `--account` named cannot be used: the project excludes it (a name the configuration lists, so
    it is named), or the runner does not list it — and then the name is not repeated, because an account a
    configuration does not list may be anything, a credential too (the caller's own rule, lanecmd.check_account)."""
    if account in excluded:
        return "the project excludes account " + account
    return "runner does not list the account --account named; its accounts: " + (", ".join(accounts) or "none")


def _nothing(asked):
    """Why no account was chosen although every candidate was asked: each account asked, and its own reason (or the
    sentence for an account this pass has filled). `asked` is the list of (account, reason) pairs, in the order they
    were asked; it is empty when the design leaves no account to ask at all."""
    if not asked:
        return "no account is left to ask"
    return "no account has room (" + "; ".join("{}: {}".format(account, reason) for account, reason in asked) + ")"


def choose_account(runner, account=None, previous=None, excluded=(), timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
                   grace_seconds=DEFAULT_GRACE_SECONDS, started=None):
    """Which account one turn takes, in the design's order, and who chose it ("Slots and the choice of the account").

    `runner` is a runner of a configuration — its `room` argument vector and its `accounts` list are read, and no file,
    command or process is touched except through `room_of`; `account` is the name `--account` gave, or None; `previous`
    is the previous run's account, or None; `excluded` are the accounts the project excludes; the timeout and grace are
    `room_of`'s (`[lanes] room_timeout_seconds` and `[lanes] stop_grace_seconds`); and `started` maps an account name to
    the number of turns this pass has already started on it (a name that is absent has none).

    The order: the account `--account` names, and only that one — it is asked, and if it has no room nothing else is
    asked and the answer carries that account's own reason; else the previous run's account; else the runner's other
    accounts in the order the runner lists them, skipping those the project excludes. The first candidate whose checked
    answer is `room` true with `slots` of 1 or more — and that has not already taken `slots` turns in this pass — is
    used, and `chosen_by` says who chose it (`supervisor`, `previous` or `room`). A runner without a `room` command has
    no room check: its choice is the account that was given, or the previous run's account, as before, and no command
    runs. Every malformed answer is no room for that candidate, by `room_of`'s own contract, and the next candidate is
    asked.

    The account `--account` names is the caller's precondition: every caller refuses an account the runner does not
    list or the project excludes before this function is called (`lanecmd.check_account`), so the account this
    function is given is one the runner lists and the project keeps. It never asks about any other named account: when
    an account that is not the runner's or that the project excludes is passed anyway, nothing is asked and the answer
    is `named-unusable`. The previous run's account is asked first only when the runner lists it and the project does
    not exclude it; otherwise it is passed over — it is not one this runner offers — and the runner's own list is
    walked instead.

    Returns a Choice: the account, who chose it and the outcome, or the account None, the outcome and the reason
    nothing was chosen. The outcome is `chosen` when an account was chosen and, for an answer that names no account,
    `named-no-room` (the account `--account` named), `no-room` (the walk of the list), `no-check` (a runner with no
    room command) or `named-unusable`, so the no-room-command case is never read as no room."""
    if started is None:
        started = {}
    excluded = set(excluded)
    accounts = runner.get("accounts", [])

    def usable(answer, name):
        """One candidate's checked answer and this pass's count: the design's clause for "the first with room"."""
        return answer.room and answer.slots >= 1 and started.get(name, 0) < answer.slots

    def why(answer, name):
        """Why one candidate was not chosen: its command's own reason, or the sentence for an account this pass has
        filled."""
        return FULL_REASON.format(account=name, slots=answer.slots) if answer.room else answer.reason

    if account is not None and (account not in accounts or account in excluded):
        # The named account is the caller's precondition (see above): it is one the runner lists and the project
        # keeps. Such an account is never asked about and never used; when one is passed anyway, nothing is asked and
        # the answer says the named account cannot be used.
        return Choice(reason=_unusable(accounts, account, excluded), outcome=OUTCOME_NAMED_UNUSABLE)

    if runner.get("room") is None:
        # No room command: no room check. The choice is the account that was given, or the previous run's account.
        if account is not None:
            return Choice(account, CHOSEN_BY_SUPERVISOR)
        if previous is not None:
            return Choice(previous, CHOSEN_BY_PREVIOUS)
        # Nothing was chosen, and this is not "no room": no room command ran at all.
        return Choice(reason="runner has no room command and the lane has no previous run's account",
                      outcome=OUTCOME_NO_CHECK)

    if account is not None:
        # --account names one account, and only that one: it is asked, and nothing else, whatever its answer.
        answer = room_of(runner, account, timeout_seconds, grace_seconds)
        if usable(answer, account):
            return Choice(account, CHOSEN_BY_SUPERVISOR)
        return Choice(reason=why(answer, account), outcome=OUTCOME_NAMED_NO_ROOM)

    asked = []
    if previous is not None and previous in accounts and previous not in excluded:
        # The previous run's account is asked first — but only when the runner lists it and the project does not
        # exclude it: the design's list skips the project's exclusions, and an account the runner no longer lists is
        # not one of its accounts either, so such an account is passed over, never asked, and the runner's own list is
        # walked instead.
        answer = room_of(runner, previous, timeout_seconds, grace_seconds)
        if usable(answer, previous):
            return Choice(previous, CHOSEN_BY_PREVIOUS)
        asked.append((previous, why(answer, previous)))
    for name in accounts:
        if name == previous or name in excluded:
            continue
        answer = room_of(runner, name, timeout_seconds, grace_seconds)
        if usable(answer, name):
            return Choice(name, CHOSEN_BY_ROOM)
        asked.append((name, why(answer, name)))
    return Choice(reason=_nothing(asked), outcome=OUTCOME_NO_ROOM)
