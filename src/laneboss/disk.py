"""The disk line: one file system read the way `df` reads it, the latch between the two lines, and the refusal.

A workstation that fills up corrupts the records, stores and Git objects of every lane at once, so the line is held
in the launcher itself and not in a note. Before a new lane or a new worktree is created, the file system a
configuration watches (its `[disk]` section, `docs/configuration.md`) is read with `os.statvfs` and the reading is
acted on: at `warn_percent` the lane still starts and the launcher says so, and at `stop_percent` the start is refused
until the reading is back under `warn_percent`.

The reading is the kernel's and nothing else: no environment variable, no configuration value and no test hook
supplies a percentage, and a file system that cannot be read, or that reports no usable blocks at all, is refused
rather than taken for an empty one.

The latch is one small file in the user's own launcher state root, named by the watched file system's device id
(`st_dev`), so every configuration of that user that watches the same file system shares one latch and one lock: the
line covers the machine, not one configuration of it. A reading at or above `stop_percent` sets the latch, and only a
reading below `warn_percent` clears it, so between the two lines the state stays `stop` once it has been reached: a
disk that was full when the last lane was refused does not silently look fresh again on the next reading that happens
to fall between the lines. `laneboss disk` prints the same reading the start path acts on, so what a supervisor sees
and what the launcher does can never come from two different measurements.
"""

import json
import os
import sqlite3
import sys
import uuid

from . import config, events, fsguard
from .errors import Refused
from .identity import PROGRAM
from .protocol import load_protocol

OK = "ok"
WARN = "warn"
STOP = "stop"
LATCHES = "disk-latches"
LATCH = "{}.latch"
WARN_EVENT = "disk.warn"
STOP_EVENT = "disk.stop"


def used_percent(blocks, free, available):
    """The used percentage of a file system, computed as `df` computes it: the used blocks (`blocks - bfree`) over
    the blocks a user can address (`blocks - bfree + bavail`). `free` is the filesystem's own free-block count,
    which includes the blocks reserved for root; `available` is what a user can still write. There is no fallback:
    a file system whose two counts make no addressable blocks is refused by `read` before this is called, so no
    number here can be read as a fresh disk."""
    total, free, available = int(blocks), int(free), int(available)
    used = total - free
    return used * 100.0 / (used + available)


def read(path):
    """The reading of the file system that holds `path`: {"used_percent", "free_bytes", "device"}, the device id
    being the identity of the file system itself (`st_dev`), which every path on it shares. Refused when it cannot
    be read, naming the path and the error, and refused when it reports no usable blocks - zero, or fewer free
    blocks than it has, or nothing a user can address at all (a procfs mount is one): such a file system is
    unreadable, not empty, and a start is never let through on it."""
    try:
        stats = os.statvfs(path)
        device = os.stat(path).st_dev
    except OSError as error:
        raise Refused("the disk reading failed: {} cannot be read ({}); no new lane or worktree starts".format(
            path, error.strerror or "operating system error")) from None
    blocks, free, available = int(stats.f_blocks), int(stats.f_bfree), int(stats.f_bavail)
    if free > blocks or (blocks - free) + available <= 0:
        raise Refused(
            "the disk reading failed: {} reports no usable blocks (blocks {}, free {}, available {}); a file system "
            "that cannot be read is never taken for an empty one, and no new lane or worktree starts".format(
                path, blocks, free, available))
    return {"used_percent": used_percent(blocks, free, available),
            "free_bytes": max(0, available * int(stats.f_frsize)), "device": device}


def one(percent):
    """A percentage as the reading prints it: one decimal."""
    return "{:.1f}".format(percent)


def note(text):
    """One line on standard error about the disk's own trouble (a latch that cannot be held or written, a reading
    that could not be recorded). It never replaces the refusal or the warning, which are the reading's own outcome:
    at a full disk the state directory sits on the watched file system, and a write that fails must not turn the
    one line the disk exists for into an internal error or an integrity problem."""
    sys.stderr.write("note: " + text + "\n")
    sys.stderr.flush()


class Latch:
    """One file system's latch and the lock over its read-decide-write.

    The latch lives in the user's launcher state root (`disk-latches/<st_dev>.latch`), not in one configuration's
    state directory, because the hold is the machine's: two configurations watching the same file system share one
    latch, so a stop reading taken while configuration A started still refuses configuration B until the disk is
    under the warn line again. The lock is that directory, held for the whole read, decision and write, so two
    starts at once - in one configuration or in two - cannot race on it. It is an exception to state isolation, and
    the only one: it holds no lane's data, only which file systems are known to have crossed the stop line."""

    def __init__(self, configuration, device):
        self.directory = os.path.join(str(configuration.state_home), LATCHES)
        self.name = LATCH.format(device)
        self.fd = None
        self.lock = None

    def hold(self):
        """Hold the file system's latch: its directory is made and locked, and the lock is kept until `release`.
        `self`, or (None, reason) when it cannot be held at all."""
        try:
            os.makedirs(self.directory, mode=0o700, exist_ok=True)
            self.fd = os.open(self.directory, fsguard.DIRECTORY)
            lock = fsguard.Lock(self.fd)
            lock.__enter__()
        except OSError as error:
            self.release()
            return None, "the disk latch {} cannot be held ({}); a latch that cannot be read never opens the " \
                         "gate".format(os.path.join(self.directory, self.name),
                                       error.strerror or "operating system error")
        self.lock = lock
        return self, None

    def release(self):
        if self.lock is not None:
            try:
                self.lock.__exit__(None, None, None)
            except OSError:
                pass
            self.lock = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def latched(self):
        """True when the latch file is set. It is set when the file exists; a file that cannot be looked at
        (unreadable, a link, a name that is not a regular file) counts as set, so a latch that cannot be read never
        opens the gate."""
        try:
            info = fsguard.file_info(self.fd, self.name)
        except OSError:
            return True
        return info is not None

    def set(self, value):
        fsguard.write_new(self.fd, self.name, (json.dumps(value, sort_keys=True) + "\n").encode("utf-8"),
                          replace=True)

    def clear(self):
        try:
            os.unlink(self.name, dir_fd=self.fd)
        except FileNotFoundError:
            pass


def check(configuration, path, warn_percent, stop_percent):
    """Read `path`, apply the reading to the file system's latch, and return the report: the path, the percentage
    with one decimal, the bytes free, the two lines, the state (`ok`, `warn` or `stop`) and whether the latch is set
    now. A reading at or above `stop_percent` sets the latch; a reading below `warn_percent` clears it; between them
    it is left as it was.

    A latch that cannot be held counts as set, so a trouble with the latch itself never opens the gate; the reading
    still decides the two lines that need no latch, and the trouble is said on standard error in one note line."""
    measuring = read(path)
    percent = measuring["used_percent"]
    latch, problem = Latch(configuration, measuring["device"]).hold()
    if latch is None:
        note(problem)
        was = True
    else:
        was = latch.latched()
    if percent >= stop_percent:
        now = True
    elif percent < warn_percent:
        now = False
    else:
        now = was
    if latch is not None:
        try:
            if now and not was:
                latch.set({"used_percent": round(percent, 1), "stop_percent": stop_percent, "at": events.utc_now()})
            elif was and not now:
                latch.clear()
        except OSError as error:
            note("the disk latch {} could not be written ({}); the reading stands".format(
                os.path.join(latch.directory, latch.name), error.strerror or "operating system error"))
        finally:
            latch.release()
    state_name = STOP if now else (WARN if percent >= warn_percent else OK)
    return {"path": path, "used_percent": round(percent, 1), "free_bytes": measuring["free_bytes"],
            "warn_percent": warn_percent, "stop_percent": stop_percent, "state": state_name, "latched": now}


def examine(configuration):
    """The reading of the configuration's watched file system, with the file system's latch applied to it: what both
    `laneboss disk` and the start of a lane act on. Refused when the file system cannot be read."""
    settings = config.disk_settings(configuration)
    return check(configuration, settings["path"], settings["warn_percent"], settings["stop_percent"])


def warning(report):
    """The one line a start prints when it goes on with a file system at or above the warn line (written to standard
    error, so that the command's JSON on standard output stays one value)."""
    return "warning: disk {} is {}% used (warn line {}%)".format(
        report["path"], one(report["used_percent"]), report["warn_percent"])


def refusal(report):
    """The one line a refused start prints; the launcher's own `refused: ` prefix comes before it."""
    return "disk {} is {}% used (stop line {}%); no new lane or worktree starts until it is under {}%".format(
        report["path"], one(report["used_percent"]), report["stop_percent"], report["warn_percent"])


def event_payload(report):
    """The reading an event keeps: the path, the percentage, the bytes free and the two lines."""
    return {"path": report["path"], "used_percent": report["used_percent"], "free_bytes": report["free_bytes"],
            "warn_percent": report["warn_percent"], "stop_percent": report["stop_percent"]}


def record(state, kind, payload):
    """Append one of the disk's own events, which belongs to no lane, and return the store's answer. It is the one
    write path for events (`events.EventStore.append`), under the state directory's lock, as a lane-less event: no
    lane directory is made for it."""
    envelope = {"id": "ev-" + uuid.uuid4().hex, "kind": kind, "lane": None, "actor": PROGRAM,
                "payload": payload, "occurred_at": events.utc_now(), "protocol_version": load_protocol()[1]}
    with state.lock():
        store = events.open_for_write(state)
    try:
        return store.append(envelope)
    finally:
        store.close()


def keep(state, kind, payload):
    """Record one of the disk's own events, and never lose the reading over it: the state directory sits on the file
    system a full disk is the matter of, so the append (or the latch write before it) is what fails there. The
    trouble goes on standard error in one note line and the reading, its refusal or its warning, stands."""
    try:
        record(state, kind, payload)
    except (OSError, sqlite3.Error) as error:
        note("the disk reading could not be recorded: {}; the reading and its outcome stand".format(
            error.strerror if isinstance(error, OSError) and error.strerror else str(error) or type(error).__name__))


def gate(configuration, state):
    """The disk check of a path that is about to create a lane or a worktree. In state `stop` the reading is recorded
    as `disk.stop` and the caller is refused with the one line; in state `warn` the reading is recorded as `disk.warn`
    and the one warning line is written to standard error. In state `ok` nothing is recorded and nothing is printed.
    A reading that cannot be taken is refused with the error, before anything is created, and a reading that cannot
    be recorded is still refused: the refusal never depends on the store."""
    report = examine(configuration)
    if report["state"] == STOP:
        keep(state, STOP_EVENT, event_payload(report))
        raise Refused(refusal(report))
    if report["state"] == WARN:
        keep(state, WARN_EVENT, event_payload(report))
        sys.stderr.write(warning(report) + "\n")
        sys.stderr.flush()
    return report
