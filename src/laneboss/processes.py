"""Processes of lane runs: identities, the process table, a run's tree, and signals that check identities.

A process is identified by its id AND its start time as the operating system reports it: on Linux the start time in
clock ticks since boot (field 22 of /proc/PID/stat), elsewhere the start time `ps -o lstart` prints, to the second,
read in the C locale and in UTC whatever the caller's LANG, LC_ALL and TZ say. No signal goes to a process unless both
still match an identity the caller recorded. On Linux the check and the signal go through a process file descriptor
(pidfd), so the id cannot pass to another process in between; where a pidfd cannot be opened, and outside Linux,
they are two calls, and a process that ends and whose id is reused within that moment is the remaining gap.

Process groups are used to find processes, never to signal them: every signal goes to one checked identity. Outside
Linux `ps` gives no session ids, so there a run's processes are found by parent links and process groups only.

A failed observation is never a conclusion. When the process table cannot be read (no `ps` on PATH, a `ps` that fails,
prints nothing usable or does not answer within PS_SECONDS, an unreadable /proc), Unobservable is raised and the
caller fails closed instead of taking every process for gone. What stop() reports as removed it has seen gone
afterwards; whatever still lives it reports as surviving.

LANEBOSS_PROCESSES=portable makes Linux use only what every supported system offers (`ps`, check-then-signal, no
adoption of orphans), the way the launcher works on macOS; every command of a configuration must then use it.
"""

import ctypes
import ctypes.util
import errno
import os
import select
import signal
import subprocess
import sys
import time

from .errors import Refused
from .identity import env_name

LINUX = sys.platform.startswith("linux") and os.path.isdir("/proc/self")
PR_SET_CHILD_SUBREAPER = 36
PS_SECONDS = 10
COLUMNS = ["-o", "pid=", "-o", "ppid=", "-o", "pgid=", "-o", "stat=", "-o", "lstart="]


class Unobservable(Refused):
    """The process table could not be read, so nothing may be concluded about any process."""


def native():
    """True when the Linux-only means (/proc, pidfds, a child subreaper) are used."""
    return LINUX and os.environ.get(env_name("PROCESSES")) != "portable"


def _linux_stat(pid):
    """The /proc entry of one process, or None when the process does not exist."""
    try:
        with open("/proc/{}/stat".format(pid), "rb") as handle:
            data = handle.read().decode("ascii", "replace")
    except (FileNotFoundError, ProcessLookupError):
        return None
    except OSError as error:
        raise Unobservable("the process table cannot be read: /proc/{}/stat: {}".format(
            pid, error.strerror or "error")) from None
    fields = data[data.rfind(")") + 2:].split()
    if len(fields) < 20:
        return None
    return {"ppid": int(fields[1]), "pgid": int(fields[2]), "sid": int(fields[3]), "state": fields[0],
            "start": fields[19]}


def _ps(arguments, missing_ok=False):
    """Rows of `ps` read in the C locale and in UTC. With missing_ok, exit status 1 without any output means that
    the process asked for does not exist; every other failure raises Unobservable."""
    environment = dict(os.environ, LC_ALL="C", LANG="C", TZ="UTC0")
    try:
        result = subprocess.run(["ps", *arguments], capture_output=True, text=True, timeout=PS_SECONDS,
                                env=environment, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        raise Unobservable("the process table cannot be read: ps is not on PATH") from None
    except subprocess.TimeoutExpired:
        raise Unobservable("the process table cannot be read: ps did not answer within {} seconds".format(
            PS_SECONDS)) from None
    except OSError as error:
        raise Unobservable("the process table cannot be read: ps cannot be run ({})".format(
            error.strerror or "error")) from None
    rows = []
    for line in result.stdout.splitlines():
        parts = line.split(None, 4)
        if len(parts) == 5 and all(part.isdigit() for part in parts[:3]):
            rows.append((int(parts[0]), {"ppid": int(parts[1]), "pgid": int(parts[2]), "sid": None, "state": parts[3],
                                         "start": " ".join(parts[4].split())}))
    if result.returncode != 0:
        if missing_ok and result.returncode == 1 and not result.stdout.strip() and not result.stderr.strip():
            return []
        raise Unobservable("the process table cannot be read: ps exited with status {}".format(result.returncode))
    if not rows:
        raise Unobservable("the process table cannot be read: ps printed no process")
    return rows


def table():
    """{pid: {ppid, pgid, sid, state, start}} of every process this user can see; Unobservable when it cannot be
    read."""
    if native():
        try:
            names = os.listdir("/proc")
        except OSError as error:
            raise Unobservable("the process table cannot be read: /proc: {}".format(error.strerror or "error")) from None
        found = {}
        for name in names:
            if name.isdigit():
                info = _linux_stat(int(name))
                if info is not None:
                    found[int(name)] = info
        if not found:
            raise Unobservable("the process table cannot be read: /proc shows no process")
        return found
    return dict(_ps(["-A"] + COLUMNS))


def info(pid):
    """The process table entry of one process, or None when it does not exist; Unobservable when it cannot be
    told."""
    if native():
        return _linux_stat(pid)
    rows = _ps(COLUMNS + ["-p", str(pid)], missing_ok=True)
    return rows[0][1] if rows else None


def identity(pid):
    """{pid, start, pgid, sid} of a living process, or None."""
    entry = info(pid)
    if entry is None or entry["state"].startswith("Z"):
        return None
    sid = entry["sid"]
    if sid is None:
        try:
            sid = os.getsid(pid)
        except OSError:
            sid = None
    return {"pid": pid, "start": entry["start"], "pgid": entry["pgid"], "sid": sid}


def matches(entry, recorded):
    if entry is None or entry["state"].startswith("Z"):
        return False
    if entry["start"].isdigit() != str(recorded["start"]).isdigit():
        raise Unobservable("a process identity was recorded with another LANEBOSS_PROCESSES setting than this command "
                           "uses; use the same setting for every command of a configuration")
    return entry["start"] == recorded["start"]


def alive(recorded, snapshot=None):
    """True when the process the identity names still lives (same id, same start time, not a zombie)."""
    entry = snapshot.get(recorded["pid"]) if snapshot is not None else info(recorded["pid"])
    return matches(entry, recorded)


def living(identities, snapshot=None):
    snapshot = table() if snapshot is None else snapshot
    return [recorded for recorded in identities if alive(recorded, snapshot)]


def signal_checked(recorded, number):
    """Send a signal to the process an identity names, only while its id and start time both match. True when the
    signal was sent; whether the process went away is for the caller to observe."""
    pid = recorded["pid"]
    if native() and hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"):
        try:
            descriptor = os.pidfd_open(pid)
        except ProcessLookupError:
            return False
        except OSError:
            descriptor = None
        if descriptor is not None:
            try:
                if not matches(_linux_stat(pid), recorded):
                    return False
                signal.pidfd_send_signal(descriptor, number)
                return True
            except OSError:
                return False
            finally:
                os.close(descriptor)
    if not matches(info(pid), recorded):
        return False
    try:
        os.kill(pid, number)
        return True
    except OSError:
        return False


def become_subreaper():
    """On Linux, make this process the parent of its orphaned descendants (PR_SET_CHILD_SUBREAPER), so a process
    that detaches from the run stays in its tree. False where the system offers nothing like it."""
    if not sys.platform.startswith("linux") or not native():
        return False
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        return libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0
    except (OSError, AttributeError):
        return False


class ExitWatch:
    """Tells when a child process has exited without collecting its exit status, so the zombie keeps its process id,
    and with it the id of its process group, while the run's remaining processes are looked for: waitid(WNOWAIT)
    where Python offers it, a kqueue NOTE_EXIT filter on macOS. Elsewhere it falls back to collecting the status."""

    def __init__(self, process):
        self.process = process
        self.done = False
        self.queue = None
        self.waitid = hasattr(os, "waitid") and hasattr(os, "WNOWAIT")
        if self.waitid or not hasattr(select, "kqueue"):
            return
        self.queue = select.kqueue()
        try:
            self.queue.control([select.kevent(process.pid, filter=select.KQ_FILTER_PROC,
                                              flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                                              fflags=select.KQ_NOTE_EXIT)], 0, 0)
        except OSError as error:
            if error.errno == errno.ESRCH:
                self.done = True
            else:
                self.close()

    def exited(self):
        if self.done or self.process.returncode is not None:
            return True
        if self.waitid:
            try:
                self.done = os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
            except ChildProcessError:
                self.done = True
        elif self.queue is not None:
            self.done = bool(self.queue.control(None, 1, 0))
        else:
            self.done = self.process.poll() is not None
        return self.done

    def close(self):
        if self.queue is not None:
            self.queue.close()
            self.queue = None


def descendants(roots, snapshot, groups=(), sessions=()):
    """Identities of the roots' descendants (by parent links) and of the members of the given process groups and
    sessions, as the snapshot shows them; zombies are left out, they have already ended."""
    children = {}
    for pid, entry in snapshot.items():
        children.setdefault(entry["ppid"], []).append(pid)
    found = set()
    pending = list(roots)
    while pending:
        pid = pending.pop()
        for child in children.get(pid, []):
            if child not in found:
                found.add(child)
                pending.append(child)
    found |= {pid for pid, entry in snapshot.items()
              if entry["pgid"] in groups or (entry["sid"] is not None and entry["sid"] in sessions)}
    found.discard(os.getpid())
    result = []
    for pid in sorted(found):
        entry = snapshot[pid]
        if not entry["state"].startswith("Z"):
            result.append({"pid": pid, "start": entry["start"], "pgid": entry["pgid"], "sid": entry["sid"]})
    return result


def merge(known, found):
    """Add identities that are not known yet; True when something was added."""
    keys = {(item["pid"], item["start"]) for item in known}
    added = False
    for item in found:
        if (item["pid"], item["start"]) not in keys:
            known.append(item)
            keys.add((item["pid"], item["start"]))
            added = True
    return added


def stop(identities, grace, discover=None):
    """Stop every process the identities name: SIGTERM, then SIGKILL to whatever still lives after the grace, each
    signal checked against its identity. `discover`, when given, returns identities found since (a tree that grows
    while it is being stopped). Returns (removed, surviving): the processes that lived and are seen gone afterwards,
    and those that still live. Unobservable when the end cannot be observed."""
    known = list(identities)
    if discover is not None:
        merge(known, discover())
    targets = living(known)
    for recorded in targets:
        signal_checked(recorded, signal.SIGTERM)
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if discover is not None:
            for recorded in discover():
                if merge(known, [recorded]):
                    targets.append(recorded)
                    signal_checked(recorded, signal.SIGTERM)
        if not living(known):
            break
        time.sleep(0.1)
    if living(known):
        if discover is not None:
            for recorded in discover():
                if merge(known, [recorded]):
                    targets.append(recorded)
        for recorded in living(known):
            signal_checked(recorded, signal.SIGKILL)
        deadline = time.monotonic() + 2
        while living(known) and time.monotonic() < deadline:
            time.sleep(0.05)
    surviving = living(known)
    keys = {(item["pid"], item["start"]) for item in surviving}
    removed = [item for item in targets if (item["pid"], item["start"]) not in keys]
    return removed, surviving
