"""The supervising process of one lane run: the launcher's own process in the lane's tmux session.

`laneboss lane start` and `lane resume` start it as the session's only pane process, with one argument: the path of
a FIFO in the lane's directory, through which they hand it the caller's environment and the run's description, after
writing the launch's run record with this process's identity. It then appends lane.resumed (for a resume) and
lane.started (after any events of the lane still waiting in its pending file; when those cannot be appended, nothing
starts), creates the runner (its argument vector, no shell, in the working directory, output appended to the lane's
log, in a process group and session of its own, whose id is the runner's process id from that moment on, with
standard input from /dev/null, or, for a runner whose `prompt` is `stdin`, from a pipe that a thread of its own fills
with the rendered brief or message and closes), adds the runner's identity to the run record, and watches the run:

- every 0.5 seconds it samples the run's process tree with identities: the descendants of the runner and of every
  process it remembers whose identity (process id and start time) it has just seen alive, and the members of the
  runner's process group and session while that group's id is verifiably the runner's (the runner is not yet
  collected, or a remembered member of the group lives). An identity seen ended is no longer a parent, so a reused
  process id leads nowhere. New identities go to the run record, which is written again on every pass until a write
  succeeds. On Linux it is also the parent of the run's orphans (a child subreaper), so a process that detaches
  stays in the tree;
- lane.stuck when the log has been quiet for the quiet time (the run goes on);
- when the budget passes, a stop request (SIGTERM or SIGINT from lane stop) or the runner's own end (noticed without
  collecting its exit status, so its process group cannot pass to another process while the rest of the run is
  looked for), it first makes sure the run's processes are gone (SIGTERM, then SIGKILL after the grace, each signal
  checked against the recorded identity), and only then records lane.timeout and lane.ended. lane.ended is recorded
  only once the runner is seen gone, with its real exit status and the number of the run's other processes that
  survive. While the runner cannot be removed nothing is recorded: the run record says so (lane status shows it as
  `stopping`) and the attempt is repeated every few seconds. A turn that carried mail (the `mail` of its lane.started)
  then queues lane.delivered or lane.returned right behind lane.ended, as that end decides (lanes.settlement);
- SIGHUP means the session itself is going away behind the launcher's back: the run's processes are stopped and no
  event is written, so `lane check` records the run as lost.

Recording never holds up the control loop: the loop only queues the run's events, with the time each was observed,
and a recorder thread beside it, the one owner of those events, appends them in order (pending.py), retrying the
lane's pending events from time to time. Before it exits the process asks the recorder to finish and waits for its
answer; the exit status is 1 when an event could be kept nowhere, and watch.log says how the process exits.
The runner's end is classified by the runner's patterns in a separate process with a time bound. Its own messages go
to the lane's watch.log.
"""

import base64
import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
import traceback
import uuid

from . import config, events, fsguard, guards, lanes, pending, processes, runrecord
from .errors import LauncherError
from .identity import PROGRAM, env_name
from .protocol import load_protocol
from .statedir import StateDir

POLL = 0.2
SAMPLE = 0.5
INPUT_SECONDS = 30
STORE_WAIT = 2.0
OPENING_WAIT = 10.0
RETRY_SECONDS = 10
LEFTOVER_GRACE = 1.0
STOP_RETRY_SECONDS = 2.0
CLASSIFY_SECONDS = 2.0
TAIL_BYTES = 64 * 1024
LINE_CHARACTERS = 4096
LOG = "output.log"
WATCH_LOG = "watch.log"
# The classification process also ends by itself (SIGALRM) one second after its bound, so it never outlives a
# supervising process that was killed while it ran (on macOS the end of the session does not end it).
CLASSIFIER = """import json, re, sys
import signal
signal.alarm(""" + str(int(CLASSIFY_SECONDS) + 1) + """)
job = json.loads(sys.stdin.read())
found = None
for line in job["lines"]:
    for reason, index, pattern in job["patterns"]:
        if re.search(pattern, line):
            found = [reason, index]
            break
    if found:
        break
print(json.dumps(found))
"""


class Flags:
    stop = False
    hangup = False


def on_stop(number, frame):
    Flags.stop = True


def on_hangup(number, frame):
    Flags.hangup = True


def on_alarm(number, frame):
    raise TimeoutError("no input arrived")


def receive(path):
    """The JSON value written to the FIFO by the starting command, read until it closes."""
    signal.signal(signal.SIGALRM, on_alarm)
    signal.alarm(INPUT_SECONDS)
    try:
        descriptor = os.open(path, os.O_RDONLY | fsguard.NOFOLLOW | fsguard.CLOEXEC)
        try:
            chunks = []
            while True:
                chunk = os.read(descriptor, 65536)
                if not chunk:
                    break
                chunks.append(chunk)
        finally:
            os.close(descriptor)
    finally:
        signal.alarm(0)
    return json.loads(b"".join(chunks).decode("ascii"))


def note(message):
    sys.stderr.write("{} {}\n".format(events.utc_now(), message))
    sys.stderr.flush()


class Prompt:
    """The prompt of a run whose runner takes it on standard input: its bytes, decoded before the runner is created,
    and what became of them. A thread of its own writes them into the runner's pipe and closes it, so a runner that
    does not read them (or reads them late) never holds up the control loop, which enforces the budget and a stop
    request; the write ends when everything is written or the runner's end of the pipe is gone. fate() is what
    lane.ended records: `written` when every byte went into the pipe (and the pipe was closed), else `cut`, each with
    the number of bytes written. Written is not read: a prompt that fits what the pipe holds is written whole even
    when the runner never reads it."""

    CHUNK = 16384
    JOIN_SECONDS = 2.0

    def __init__(self, data, run):
        self.data = data
        self.run = run
        self.written = 0
        self.thread = None

    def start(self, stream):
        self.thread = threading.Thread(target=self.write, args=(stream,), name="prompt", daemon=True)
        self.thread.start()

    def write(self, stream):
        try:
            view = memoryview(self.data)
            while self.written < len(view):
                self.written += os.write(stream.fileno(), view[self.written:self.written + self.CHUNK])
            stream.close()
        except (OSError, ValueError) as error:
            note("run {}: the prompt was not written to the runner's standard input in full ({} of {} bytes): {}".format(
                self.run, self.written, len(self.data), described(error)))
        finally:
            # Closed whatever happened, so that nothing is left to flush (and to complain about) when the process ends.
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    def fate(self):
        """What lane.ended records, once the run's processes are gone (a write still going on then is cut)."""
        if self.thread is not None:
            self.thread.join(self.JOIN_SECONDS)
        return {"state": "written" if self.written == len(self.data) else "cut", "bytes": self.written,
                "length": len(self.data)}


def tail_lines(lane_fd, offset):
    """The lines of this run's own output (the bytes it added to the log after offset), its last 64 KiB at most,
    each cut to 4096 characters."""
    descriptor = os.open(LOG, os.O_RDONLY | fsguard.NOFOLLOW | fsguard.CLOEXEC, dir_fd=lane_fd)
    try:
        size = os.fstat(descriptor).st_size
        begin = max(offset, size - TAIL_BYTES)
        data = os.pread(descriptor, size - begin, begin) if size > begin else b""
    finally:
        os.close(descriptor)
    lines = data.decode("utf-8", "replace").splitlines()
    if begin > offset and lines:
        lines = lines[1:]
    return [line[:LINE_CHARACTERS] for line in lines]


def classify(lane_fd, offset, spec):
    """(reason, pattern, classification) of a run that ended by itself: the last line of its output that a limit or
    dropped pattern matches decides, limit patterns first on one line. The matching runs in a separate process that
    is stopped after CLASSIFY_SECONDS; then the reason is exit and the classification timed-out."""
    patterns = [["limit", index, value] for index, value in enumerate(spec["limit_patterns"])]
    patterns += [["dropped", index, value] for index, value in enumerate(spec["dropped_patterns"])]
    if not patterns:
        return "exit", None, None
    # Last line first: the first line that matches is the last matching line of the output.
    job = json.dumps({"lines": tail_lines(lane_fd, offset)[::-1], "patterns": patterns})
    try:
        result = subprocess.run([sys.executable, "-I", "-B", "-c", CLASSIFIER], input=job, capture_output=True,
                                text=True, timeout=CLASSIFY_SECONDS)
        found = json.loads(result.stdout) if result.returncode == 0 else None
    except subprocess.TimeoutExpired:
        note("classification of the run's output timed out after {} seconds".format(CLASSIFY_SECONDS))
        return "exit", None, "timed-out"
    except ValueError:
        found = None
    if not found:
        return "exit", None, "unmatched"
    return found[0], "{}_patterns[{}]".format(found[0], found[1]), "matched"


FINISH = object()


def described(error):
    return getattr(error, "strerror", None) or str(error) or type(error).__name__


class Recorder(threading.Thread):
    """The one owner of the run's events, from the moment the control loop queues them to the supervising process's
    exit. Beside the control loop it appends them in order, each through the store or the lane's pending file
    (pending.record), and the pending ones again when it is idle. An event leaves it only when the store took it,
    the store refused it for good (then it is kept in refused.jsonl) or it is in the pending file; any other failure
    keeps it, and it is tried again every second. finish() only asks and waits: from then on the next failure ends
    the attempts, the event held and every event behind it are kept in pending-LAUNCH-ID.jsonl (under the lane's
    lock), the pending events are retried for a while, and the recorder answers how many events it could keep
    nowhere."""

    def __init__(self, state, lane, run, launch):
        super().__init__(name="recorder", daemon=True)
        self.state = state
        self.lane = lane
        self.run_number = run
        self.launch = launch
        self.queue = queue.Queue()
        self.finishing = threading.Event()
        self.lost = None

    def put(self, envelope):
        self.queue.put(envelope)

    def run(self):
        try:
            held = None
            while True:
                if held is None:
                    try:
                        held = self.queue.get(timeout=1.0)
                    except queue.Empty:
                        self.retry()
                        continue
                    if held is FINISH:
                        break
                if self.record(held):
                    held = None
                elif self.finishing.is_set():
                    break
                else:
                    self.finishing.wait(1.0)
            left = [] if held in (None, FINISH) else [held]
            while not self.queue.empty():
                item = self.queue.get()
                if item is not FINISH:
                    left.append(item)
            self.lost = self.keep(left)
            self.retry(RETRY_SECONDS)
        except BaseException:
            note("run {}: the recorder ended unexpectedly:\n{}".format(self.run_number, traceback.format_exc()))

    def record(self, envelope):
        """True once the event has left the recorder: stored, pending, or refused by the store and kept."""
        kind = envelope["kind"]
        try:
            if not pending.record(self.state, self.lane, envelope, STORE_WAIT):
                note("run {}: {} could not be appended yet; it waits in pending.jsonl".format(self.run_number, kind))
            return True
        except pending.StoreRefused as error:
            note("run {}: {} was refused by the store and kept in refused.jsonl: {}".format(self.run_number, kind, error))
            return True
        except Exception as error:
            note("run {}: {} could not be recorded yet ({})".format(self.run_number, kind, described(error)))
            return False

    def keep(self, left):
        """Keep events that could not be recorded in a file of their own; how many could be kept nowhere."""
        if not left:
            return 0
        kinds = ", ".join(item["kind"] for item in left)
        try:
            name = pending.keep_aside(self.state, self.lane, self.launch, left)
        except Exception as error:
            note("run {}: {} event(s) could not be recorded anywhere ({}): {}".format(self.run_number, len(left),
                                                                                     described(error), kinds))
            return len(left)
        note("run {}: {} event(s) could not be recorded yet ({}); kept in {} for lane check".format(
            self.run_number, len(left), kinds, name))
        return 0

    def retry(self, seconds=0):
        """Append the pending events; with seconds, keep trying that long while some are left."""
        deadline = time.monotonic() + seconds
        while True:
            try:
                if not pending.count(self.state, self.lane):
                    return
                pending.flush(self.state, self.lane, STORE_WAIT)
            except Exception as error:
                note("run {}: pending events could not be retried: {}".format(self.run_number, described(error)))
            if time.monotonic() >= deadline:
                if seconds:
                    note("run {}: events still pending; lane check will append them".format(self.run_number))
                return
            time.sleep(1.0)

    def finish(self):
        """Ask the recorder to finish and wait for its answer: how many events it could keep nowhere, or None when it
        ended unexpectedly."""
        self.finishing.set()
        self.queue.put(FINISH)
        self.join()
        return self.lost


class Run:
    def __init__(self, configuration, state, lane_fd, spec, record):
        self.configuration = configuration
        self.state = state
        self.lane_fd = lane_fd
        self.spec = spec
        self.lane = spec["lane"]
        self.run = spec["run"]
        self.record = record
        self.protocol_version = load_protocol()[1]
        self.process = None
        self.known = []
        self.reaper = False
        self.dirty = False
        self.recorder = Recorder(state, self.lane, self.run, spec["launch"])
        self.prompt = None
        self.scanner = None
        self.helpers = set()

    def envelope(self, kind, payload, at=None):
        return {"id": "ev-" + uuid.uuid4().hex, "kind": kind, "lane": self.lane, "actor": PROGRAM,
                "occurred_at": at or events.utc_now(), "payload": payload, "protocol_version": self.protocol_version}

    def deliver(self, found):
        """A refusal or a suspicion the scanning process found: queued for the recorder like the run's other events,
        with the time the record gives (none for a text record)."""
        if found.get("kind") in lanes.REFUSAL_KINDS[:2] and isinstance(found.get("payload"), dict):
            envelope = self.envelope(found["kind"], found["payload"])
            envelope["occurred_at"] = found.get("at")
            self.recorder.put(envelope)

    def start_scanner(self, offset):
        """The scanning process that follows the run's session records, when the configuration has guards and the
        runner names its records. A scanner that cannot be started is noted; scans after the run cover it."""
        if not guards.configured(self.configuration, self.spec["started"]["runner"]):
            return
        from . import refusals  # loaded only by a run that is scanned
        try:
            self.scanner = refusals.Follower.start({"config": self.configuration.name, "lane": self.lane,
                                                    "run": self.run, "log_start": offset}, self.deliver)
            self.helpers.add(self.scanner.pid)
        except OSError as error:
            note("run {}: the refusal scan could not be started: {}".format(self.run, described(error)))

    def finish_scanner(self, log, ended_at):
        """The scanning process's last pass over the run's records, now that the run's processes are gone, then its
        stop: at most seven seconds together (refusals.FINISH_SECONDS)."""
        if self.record.get("log") is not None:
            try:
                self.record["log"]["end"] = os.fstat(log).st_size
            except OSError:
                pass
            self.save_record()
        if self.scanner is None:
            return
        scanner, self.scanner = self.scanner, None
        if not scanner.finish(ended_at, (self.record.get("log") or {}).get("end")):
            note("run {}: the refusal scan did not finish its last pass in time; lane scan covers the run".format(
                self.run))
        self.abandoned(scanner)

    def stop_scanner(self):
        if self.scanner is not None:
            scanner, self.scanner = self.scanner, None
            scanner.stop()
            self.abandoned(scanner)

    def abandoned(self, scanner):
        if scanner.abandoned:
            note("run {}: the refusal scan (pid {}) did not end when it was killed; it is left behind".format(
                self.run, scanner.pid))

    def append_now(self, kind, payload):
        """The events that open a run (lane.resumed, lane.started) are appended before anything runs, after the
        lane's pending events: when they cannot be, the launch ends and nothing has started."""
        return pending.append_after(self.state, self.lane, self.envelope(kind, payload), OPENING_WAIT)

    def save_record(self):
        """Write the run record; on failure it stays due and is written again on the next pass."""
        try:
            runrecord.write(self.state, self.lane, self.record)
            self.dirty = False
        except (OSError, LauncherError) as error:
            self.dirty = True
            note("run {}: the run record could not be written (it is tried again): {}".format(self.run, error))

    def environment(self, inherited):
        environment = {key: value for key, value in inherited.items() if key not in ("TMUX", "TMUX_PANE")}
        environment[env_name("CONFIG")] = self.configuration.name
        environment[env_name("LANE")] = self.lane
        environment[env_name("RUN")] = str(self.run)
        return environment

    def group_known(self, snapshot):
        """True while a process verified in this very snapshot is in the runner's process group: the runner itself, not
        collected yet, or a remembered process seen alive there now. A remembered group id alone proves nothing."""
        members = ([self.process.pid] if self.process.returncode is None else []) + [
            item["pid"] for item in self.known if processes.alive(item, snapshot)]
        return any(pid in snapshot and snapshot[pid]["pgid"] == self.process.pid for pid in members)

    def sample(self):
        """Identities of the run's processes now (processes.Unobservable when the table cannot be read)."""
        snapshot = processes.table()
        if self.process is None:
            return []
        roots = [item["pid"] for item in self.known if processes.alive(item, snapshot)]
        if self.reaper:
            roots.append(os.getpid())
        found = []
        runner = snapshot.get(self.process.pid)
        if self.process.returncode is None:
            roots.append(self.process.pid)
            if runner is not None and not runner["state"].startswith("Z"):
                found.append({"pid": self.process.pid, "start": runner["start"], "pgid": runner["pgid"],
                              "sid": runner["sid"]})
        group = (self.process.pid,) if self.group_known(snapshot) else ()
        found += processes.descendants(roots, snapshot, groups=group, sessions=group)
        self.reap(snapshot)
        # The launcher's own helper (the refusal scan) is a child of this process, not a process of the run.
        return [item for item in found if item["pid"] not in self.helpers]

    def reap(self, snapshot):
        """Collect the exit status of adopted processes that ended (never the runner's or a helper's: Popen keeps
        those)."""
        runner = self.process.pid if self.process is not None else None
        for pid, entry in snapshot.items():
            if entry["ppid"] == os.getpid() and pid != runner and pid not in self.helpers and entry["state"].startswith(
                    "Z"):
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass

    def remember(self, found):
        if processes.merge(self.known, found):
            self.record["processes"] = list(self.known)
            if self.record.get("runner") is None:
                self.record["runner"] = next((item for item in self.known if item["pid"] == self.process.pid), None)
            self.dirty = True

    def track(self):
        try:
            self.remember(self.sample())
        except processes.Unobservable as error:
            note("run {}: the run's processes could not be sampled: {}".format(self.run, error))
        if self.dirty:
            self.save_record()

    def track_found(self):
        found = self.sample()
        self.remember(found)
        return found

    def collect_runner(self, seconds):
        """True once the runner has ended and its exit status is collected."""
        try:
            self.process.wait(timeout=seconds)
            return True
        except subprocess.TimeoutExpired:
            return False

    def stop_all(self, grace):
        """Make sure every process of the run is gone, with checked signals, before anything is recorded. The runner
        must go: while it cannot be removed (or the process table cannot be read), nothing is recorded, the run record
        says so and the attempt is repeated. Returns how many of the run's other processes survive: counted once the
        runner is gone, after one more attempt to stop them, never from an observation made before."""
        since = None
        last_grace = min(grace, LEFTOVER_GRACE)
        while True:
            try:
                surviving = processes.stop(self.known, grace, discover=self.track_found)[1]
            except processes.Unobservable as error:
                note("run {}: the end of the run's processes cannot be observed: {}".format(self.run, error))
                surviving = None
            if self.collect_runner(2.0) and surviving is not None:
                break
            if since is None:
                since = events.utc_now()
            if surviving is not None:
                self.record["stopping"] = {"since": since, "survivors": len(surviving)}
            elif self.record.get("stopping") is None:
                self.record["stopping"] = {"since": since, "survivors": len(self.known)}
            self.record["processes"] = list(self.known)
            self.save_record()
            note("run {}: the runner could not be removed yet; trying again".format(self.run))
            time.sleep(STOP_RETRY_SECONDS)
            grace = 0
        # The runner is gone and collected. What else of the run lives now gets one more SIGTERM and SIGKILL, and
        # only what survives that counts.
        while True:
            try:
                surviving = processes.stop(self.known, last_grace, discover=self.track_found)[1]
                break
            except processes.Unobservable as error:
                note("run {}: the run's remaining processes cannot be observed: {}".format(self.run, error))
                time.sleep(STOP_RETRY_SECONDS)
        self.record.update(finished=True, stopping=None, processes=list(self.known))
        self.save_record()
        return len(surviving)

    def supervise(self, inherited):
        spec = self.spec
        log = os.open(LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT | fsguard.NOFOLLOW | fsguard.CLOEXEC, 0o600,
                      dir_fd=self.lane_fd)
        offset = os.fstat(log).st_size
        # The run's part of the lane's log, for scans of a text record of it ({log}).
        self.record["log"] = {"start": offset, "end": None}
        self.save_record()
        if spec["resumed"] is not None:
            self.append_now("lane.resumed", spec["resumed"])
        self.append_now("lane.started", spec["started"])
        self.recorder.start()
        try:
            return self.supervise_run(inherited, log, offset)
        finally:
            self.stop_scanner()

    def supervise_run(self, inherited, log, offset):
        spec = self.spec
        self.start_scanner(offset)
        self.reaper = processes.become_subreaper()
        note("run {}: started {} (adopting orphans: {})".format(self.run, spec["argv"][0], self.reaper))
        began = time.monotonic()
        try:
            # The prompt is decoded before anything is created: a description that cannot be decoded runs nothing.
            if spec.get("prompt") is not None:
                self.prompt = Prompt(base64.b64decode(spec["prompt"], validate=True), self.run)
            self.process = subprocess.Popen(spec["argv"], cwd=spec["cwd"], env=self.environment(inherited),
                                            stdin=subprocess.DEVNULL if self.prompt is None else subprocess.PIPE,
                                            stdout=log, stderr=log, start_new_session=True, close_fds=True)
        except (OSError, ValueError) as error:
            # No runner process ran, so there is no exit status: none is made up.
            note("run {}: the runner could not be started: {}".format(self.run, described(error)))
            self.stop_scanner()
            self.record["finished"] = True
            self.record["log"]["end"] = offset
            self.save_record()
            self.end("exit", None, time.monotonic() - began, None, None, None, 0)
            return self.catch_up()
        try:
            runner = processes.identity(self.process.pid)
        except processes.Unobservable:
            runner = None
        self.record["runner"] = runner
        if runner is not None:
            self.known.append(runner)
            self.record["processes"] = list(self.known)
        self.save_record()
        try:
            # The writing thread starts inside the region that stops the run on any error: a runner is never left
            # running unrecorded, with a prompt nobody writes.
            if self.prompt is not None:
                self.prompt.start(self.process.stdin)
            self.watch(log, offset, began)
        except BaseException:
            # Whatever went wrong in the loop, the run's processes do not outlive their supervision.
            self.stop_all(spec["grace_seconds"])
            raise
        return self.catch_up()

    def watch(self, log, offset, began):
        spec = self.spec
        last_size = os.fstat(log).st_size
        last_growth = began
        last_sample = 0.0
        reported = False
        exit_watch = processes.ExitWatch(self.process)
        try:
            while not exit_watch.exited():
                now = time.monotonic()
                if now - last_sample >= SAMPLE:
                    last_sample = now
                    self.track()
                elif self.dirty:
                    self.save_record()
                if Flags.hangup:
                    note("run {}: the session went away; stopping the run without an event".format(self.run))
                    self.stop_all(min(spec["grace_seconds"], 5))
                    self.stop_scanner()
                    return None
                if Flags.stop:
                    note("run {}: stop requested".format(self.run))
                    survivors = self.stop_all(spec["grace_seconds"])
                    ended_at, duration = events.utc_now(), time.monotonic() - began
                    self.finish_scanner(log, ended_at)
                    self.end("stopped", self.process.returncode, duration, None, None, ended_at, survivors)
                    return "stopped"
                if now - began >= spec["budget_seconds"]:
                    at = events.utc_now()
                    elapsed = round(now - began, 3)
                    note("run {}: the budget passed; stopping the run".format(self.run))
                    survivors = self.stop_all(spec["grace_seconds"])
                    ended_at, duration = events.utc_now(), time.monotonic() - began
                    self.finish_scanner(log, ended_at)
                    self.recorder.put(self.envelope("lane.timeout", {
                        "run": self.run, "budget_minutes": spec["started"]["budget_minutes"],
                        "elapsed_seconds": elapsed}, at))
                    self.end("timeout", self.process.returncode, duration, None, None, ended_at, survivors)
                    return "timeout"
                size = os.fstat(log).st_size
                if size != last_size:
                    last_size, last_growth, reported = size, now, False
                elif not reported and now - last_growth >= spec["quiet_seconds"]:
                    self.recorder.put(self.envelope("lane.stuck", {
                        "run": self.run, "quiet_seconds": spec["quiet_seconds"],
                        "output_bytes": max(0, size - offset)}))
                    reported = True
                time.sleep(POLL)
        finally:
            exit_watch.close()
        ended_at = events.utc_now()
        duration = time.monotonic() - began
        # The runner's zombie still holds its process id and group: one more look finds what it left in its group.
        self.track()
        survivors = self.stop_all(min(spec["grace_seconds"], LEFTOVER_GRACE))
        self.finish_scanner(log, ended_at)
        reason, pattern, classification = classify(self.lane_fd, offset, spec)
        self.end(reason, self.process.returncode, duration, pattern, classification, ended_at, survivors)
        return reason

    def end(self, reason, code, duration, pattern, classification, at, survivors):
        """Queue lane.ended with the runner's real exit status (none when no runner process ran)."""
        exit_code = code if code is not None and code >= 0 else None
        signal_number = -code if code is not None and code < 0 else None
        payload = {"run": self.run, "reason": reason, "exit_code": exit_code, "signal": signal_number,
                   "duration_seconds": round(max(duration, 0.0), 3), "pattern": pattern,
                   "classification": classification, "survivors": survivors}
        if self.prompt is not None:
            # Only a run whose runner takes its prompt on standard input has this key: written or cut, and how much.
            payload["prompt"] = self.prompt.fate()
        self.recorder.put(self.envelope("lane.ended", payload, at))
        self.announce(payload)
        note("run {}: ended, reason {}, exit code {}, signal {}, {} other process(es) survive{}".format(
            self.run, reason, exit_code, signal_number, survivors,
            "" if self.prompt is None else ", prompt {} ({} of {} bytes)".format(
                payload["prompt"]["state"], payload["prompt"]["bytes"], payload["prompt"]["length"])))

    def announce(self, ended):
        """A turn that carried mail says what its end decided for the messages, in the queue right behind lane.ended
        (docs/architecture.md, "The derivation"): lane.delivered when it ended with reason exit, exit code 0 and a
        prompt written whole, otherwise lane.returned with the reason of the end (lanes.settlement). The supervising
        process cannot read the lane's row before its own end is stored, so it takes the same decision from its end
        event and from the messages its run carried (the `mail` of its lane.started). A run that carried none
        announces nothing."""
        carried = self.spec["started"].get("mail")
        if not carried:
            return
        outcome, reason = lanes.settlement("ended", ended)
        body = {"run": self.run, "sequences": list(carried)}
        if outcome == "delivered":
            self.recorder.put(self.envelope("lane.delivered", body))
        else:
            self.recorder.put(self.envelope("lane.returned", dict(body, reason=reason)))

    def catch_up(self):
        """Exit status 0 only when every event is in the store, in a pending file or kept as refused."""
        return 0 if self.recorder.finish() == 0 else 1


def main(arguments):
    signal.signal(signal.SIGTERM, on_stop)
    signal.signal(signal.SIGINT, on_stop)
    signal.signal(signal.SIGHUP, on_hangup)
    if len(arguments) != 1:
        return 2
    try:
        message = receive(arguments[0])
    except (OSError, ValueError, TimeoutError):
        return 2
    inherited = message["environment"]
    spec = message["spec"]
    os.environ.clear()
    os.environ.update(inherited)
    try:
        configuration = config.load(spec["config"])
        zones = config.Zones(configuration)
        if zones.problems():
            return 2
        state = StateDir.open(configuration, zones, create=False)
        if state is None:
            return 2
        lane_fd = state.open_lane(spec["lane"], create=True)
        watch_log = os.open(WATCH_LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT | fsguard.NOFOLLOW | fsguard.CLOEXEC,
                            0o600, dir_fd=lane_fd)
        os.dup2(watch_log, 1)
        os.dup2(watch_log, 2)
        os.close(watch_log)
        sys.stdout = os.fdopen(1, "w", buffering=1, closefd=False)
        sys.stderr = os.fdopen(2, "w", buffering=1, closefd=False)
        record = runrecord.read(state, spec["lane"], spec["launch"])
    except (LauncherError, OSError):
        return 2
    if record is None or not runrecord.valid_identity(record.get("supervisor")) or \
            record["supervisor"]["pid"] != os.getpid():
        note("run {}: the run record does not name this process as the supervising process".format(spec["run"]))
        return 2
    run = Run(configuration, state, lane_fd, spec, record)
    try:
        status = run.supervise(inherited)
    except LauncherError as error:
        note("run {}: {}: {}".format(spec["run"], error.prefix, error))
        status = error.exit_code
    except BaseException:
        note("run {}: internal error:\n{}".format(spec["run"], traceback.format_exc()))
        status = 70
    note("run {}: the supervising process exits with status {}".format(spec["run"], status))
    return status
