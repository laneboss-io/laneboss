"""Events that could not be appended yet, kept at STATE_DIR/lanes/LANE/pending.jsonl and appended later in order.

When the store is busy past the wait or cannot be written, an event is not dropped: it is written to the lane's
pending file, one complete envelope per line, with its own id and the time it happened as occurred_at. Once a lane
has pending events, its later events queue behind them, and no command appends an event of that lane directly: it
first appends the pending ones (append_after) or refuses, so the store always receives a lane's events in the order
they happened. Whoever can (the supervising process while it lives, then `lane check`, and any command that appends
an event of the lane) appends them; an id that is already stored with the same content is a duplicate, so appending
twice is harmless. Every change to the pending file happens under a lock on the lane's directory and replaces the
file whole (written under a temporary name, synced and renamed), so a change is made completely or not at all;
readers that do not take the lock read a file that a drainer may remove at any moment as empty.

A supervising process that cannot write the pending file either (it cannot be read) keeps its last events aside when
it exits, in pending-LAUNCH-ID.jsonl next to it, written whole under the same lock. They come after pending.jsonl: a
drainer first moves them to its end, under the lock, then appends the queue in order. Whoever holds the lock goes
first: a direct append that has checked for waiting events is stored before a leftover file published after it.

An event the store refuses (its form or the lane's life cycle does not allow it) can never be appended: it moves to
the lane's refused.jsonl with the store's reason, once per event id, so it is kept and counted as refused, never as
recorded, and no longer blocks the queue. So does a line of a pending file that is not an event at all.
"""

import json
import os
import sqlite3
import stat
import uuid

from . import events, fsguard
from .errors import IntegrityProblem, LauncherError, Refused

PENDING = "pending.jsonl"
REFUSED = "refused.jsonl"
ASIDE = ("pending-", ".jsonl")
MAX_BYTES = 16 * 1024 * 1024


class StoreRefused(Refused):
    """The store refused an event for good; it is kept in refused.jsonl."""


def _lines(directory, name):
    """The non-empty lines of a file in the lane's directory; none when the file does not exist (or was just removed
    by a drainer)."""
    try:
        descriptor = os.open(name, os.O_RDONLY | fsguard.NOFOLLOW | os.O_NONBLOCK | fsguard.CLOEXEC, dir_fd=directory)
    except FileNotFoundError:
        return []
    except OSError as error:
        raise Refused("{}: cannot open {}: {}".format(name, name, error.strerror or "error")) from None
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise Refused("{}: {} is not a regular file".format(name, name))
    data = fsguard.read_descriptor(descriptor, MAX_BYTES, name)
    return [line for line in data.decode("utf-8", "replace").splitlines() if line.strip()]


def _line(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True)


def _aside(directory):
    """The names of events kept aside by supervising processes, oldest first."""
    found = []
    for name in os.listdir(directory):
        if name.startswith(ASIDE[0]) and name.endswith(ASIDE[1]):
            info = fsguard.file_info(directory, name)
            if info is not None and stat.S_ISREG(info.st_mode):
                found.append((info.st_mtime_ns, name))
    return [name for _, name in sorted(found)]


def _merge_aside(directory):
    """Move events kept aside to the end of the pending file, in order: the pending file is written anew with them,
    and only then are their files removed. The caller holds the lane's lock."""
    names = _aside(directory)
    if names:
        _rewrite(directory, PENDING, _queue(directory))
        for name in names:
            os.unlink(name, dir_fd=directory)


def _queue(directory):
    """Every waiting line, in order: the pending file, then what was kept aside."""
    lines = _lines(directory, PENDING)
    for name in _aside(directory):
        lines += _lines(directory, name)
    return lines


def _refuse(directory, envelope, reason, line=None):
    """Keep an event the store refused for good (or a line that is no event), with the reason, once per id."""
    kept = _lines(directory, REFUSED)
    for old in kept:
        try:
            value = json.loads(old)
            if envelope is not None and (value.get("envelope") or {}).get("id") == envelope.get("id"):
                return
        except (ValueError, AttributeError):
            continue
    entry = {"envelope": envelope, "reason": reason}
    if envelope is None:
        entry["line"] = line
    _rewrite(directory, REFUSED, kept + [_line(entry)])


def _rewrite(directory, name, lines):
    """Replace a file with these lines, whole: written under a temporary name, synced, renamed over the old one and
    the directory synced, or not changed at all. A file is never appended to in place."""
    try:
        if lines:
            fsguard.write_new(directory, name, ("\n".join(lines) + "\n").encode("utf-8"), replace=True)
        else:
            os.unlink(name, dir_fd=directory)
        os.fsync(directory)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise Refused("{} could not be written: {}; it is unchanged".format(name, error.strerror or "error")) from None


def count(state, lane):
    """How many events of the lane wait to be appended (pending, and kept aside)."""
    directory = state.open_lane(lane)
    if directory is None:
        return 0
    try:
        return len(_queue(directory))
    finally:
        os.close(directory)


def refused(state, lane):
    """How many events of the lane the store refused for good."""
    directory = state.open_lane(lane)
    if directory is None:
        return 0
    try:
        return len(_lines(directory, REFUSED))
    finally:
        os.close(directory)


def waiting(state, lane):
    """The envelopes of the lane's waiting events, in order."""
    directory = state.open_lane(lane)
    if directory is None:
        return []
    try:
        found = []
        for line in _queue(directory):
            try:
                found.append(json.loads(line))
            except ValueError:
                continue
        return [item for item in found if isinstance(item, dict)]
    finally:
        os.close(directory)


class Store:
    """Appends to the store with a chosen wait for a busy store; a store problem is reported as False, a refusal of
    the event itself is raised. It is the drainer: the store lets it append while the lane has pending events."""

    def __init__(self, state, timeout):
        self.state = state
        self.timeout = timeout

    def append(self, envelope):
        try:
            with self.state.lock():
                store = events.open_for_write(self.state, timeout=self.timeout)
        except (sqlite3.Error, OSError, IntegrityProblem, Refused):
            return False
        try:
            store.append(envelope, draining=True)
            return True
        except Refused:
            raise
        except (sqlite3.Error, OSError, IntegrityProblem):
            return False
        finally:
            store.close()


def _flush(state, directory, store):
    """Append the waiting events in order until one cannot be appended. Returns (appended, refused, still
    pending). The caller holds the lane's lock."""
    _merge_aside(directory)
    lines = _lines(directory, PENDING)
    done = refusals = 0
    while lines:
        try:
            envelope = json.loads(lines[0])
            if not isinstance(envelope, dict):
                raise ValueError("not an object")
        except ValueError:
            _refuse(directory, None, "the line is not an event (not a JSON object)", lines[0])
            refusals += 1
            lines.pop(0)
            continue
        try:
            if not store.append(envelope):
                break
            done += 1
        except LauncherError as error:
            _refuse(directory, envelope, str(error))
            refusals += 1
        lines.pop(0)
    if done or refusals:
        _rewrite(directory, PENDING, lines)
    return done, refusals, len(lines)


def record(state, lane, envelope, timeout):
    """Append an event, or keep it pending when the store cannot take it now (or the lane already has waiting
    events). Returns True when it is stored. Raises StoreRefused when the store refused it (it is then kept in
    refused.jsonl), and any other error when it could be neither appended nor kept pending."""
    directory = state.open_lane(lane, create=True)
    try:
        with fsguard.Lock(directory):
            _merge_aside(directory)
            waiting = _lines(directory, PENDING)
            if waiting:
                _rewrite(directory, PENDING, waiting + [_line(envelope)])
                _flush(state, directory, Store(state, timeout))
                return not _lines(directory, PENDING)
            try:
                if Store(state, timeout).append(envelope):
                    return True
            except LauncherError as error:
                _refuse(directory, envelope, str(error))
                raise StoreRefused(str(error)) from None
            _rewrite(directory, PENDING, [_line(envelope)])
            return False
    finally:
        os.close(directory)


def flush(state, lane, timeout):
    """Append the lane's waiting events in order: (appended, refused, still pending)."""
    directory = state.open_lane(lane)
    if directory is None:
        return 0, 0, 0
    try:
        with fsguard.Lock(directory):
            return _flush(state, directory, Store(state, timeout))
    finally:
        os.close(directory)


def append_after(state, lane, envelope, timeout):
    """Append one event directly, after the lane's waiting events: they are appended first, under the lane's lock,
    and when some cannot be, the event is refused instead of overtaking them. Returns the store's answer."""
    directory = state.open_lane(lane, create=True)
    try:
        with fsguard.Lock(directory):
            if _queue(directory):
                _flush(state, directory, Store(state, timeout))
                left = len(_queue(directory))
                if left:
                    raise Refused("lane {} has {} event(s) waiting to be recorded, so nothing else is recorded for it "
                                  "before them; lane check records them once the store can be written".format(
                                      lane, left))
            with state.lock():
                store = events.open_for_write(state, timeout=timeout)
            try:
                return store.append(envelope, draining=True)
            finally:
                store.close()
    finally:
        os.close(directory)


def keep_aside(state, lane, launch, envelopes):
    """Write events a supervising process could not record to pending-LAUNCH-ID.jsonl, whole, under the lane's lock
    like every other change to its waiting events. Returns the file's path."""
    directory = state.open_lane(lane)
    if directory is None:
        raise Refused("lane {}'s directory does not exist".format(lane))
    name = "{}{}-{}{}".format(ASIDE[0], launch, uuid.uuid4().hex[:8], ASIDE[1])
    try:
        with fsguard.Lock(directory):
            fsguard.write_new(directory, name, "".join(_line(item) + "\n" for item in envelopes).encode("ascii"))
    finally:
        os.close(directory)
    return state.lane_path(lane, name)
