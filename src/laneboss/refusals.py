"""Refusals: what a lane's raw session records say a guard refused, and what the lane did next (docs/architecture.md,
"Refusals").

The launcher reads each run's raw session records (the runner's `records`: claude-code records found by path templates,
and the run's own log as text), never the executor's summary, and records what a guard refused (`lane.refusal`) and
the later shell calls that look like a way around it (`lane.workaround_suspected`). A refusal or a suspicion is
identified by its record's real path and its call (or its place in the record), so scans can be repeated; what each
covered is merged, under the lane's lock, into STATE_DIR/lanes/LANE/scans/LAUNCH.json with the inventory of every
record ever read for the run. docs/architecture.md, "Refusals", gives the rules.

Three entry points: scan_lane() reads every record of a lane to its end (lane scan, and lane mark before accepted or
merged); listing() reports refusals, suspicions, verdicts and coverage without writing anything (lane refusals); and
follow() is the scanning process the supervising process starts beside its run (Follower), which follows the run's
records while it lives and hands what it finds to the supervising process's recorder.
"""

import errno
import fnmatch
import glob
import hashlib
import heapq
import json
import os
import select
import stat
import string
import subprocess
import sys
import threading
import time
import uuid

from . import config, credentials, events, fsguard, guards as guard_rules, lanes, pending, runrecord, sessions
from . import shellscan
from .errors import LauncherError
from .identity import PROGRAM
from .protocol import load_protocol
from .statedir import StateDir

SLACK = 2.0
AFTER = 5.0
POLL = 0.5
DISCOVER_SECONDS = 1.0
GRACE = 2.0
HOOK_WAIT = 5.0
COVERAGE_SECONDS = 5.0
FINISH_SECONDS = 7.0
STORE_WAIT = 10
MAX_RECORDS = 200
MAX_MATCHES = 10000
MAX_OPEN_CALLS = 4096
MAX_COMPARED = 64
EXCERPT = 240
SCANS = "scans"
LOG = "output.log"
COVERAGE_FORMAT = 1
UNREADABLE = object()
RECORD_VALUES = ("account", "effort", "lane", "log", "model", "project", "worktree")


configured = guard_rules.configured


def digest(*parts):
    return hashlib.sha256("\0".join(str(part) for part in parts).encode("utf-8", "surrogatepass")).hexdigest()


def text_digest(text):
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


# What an event may carry: excerpts and paths the credential detector accepts, or only their length and hash.

def excerpt(text, length=None, sha256=None):
    """The start of a text (240 characters), or only its length and hash when a credential the detector finds in the
    text (its first 64 KiB) begins inside that start."""
    length = len(text) if length is None else length
    sha256 = text_digest(text) if sha256 is None else sha256
    if credentials.begins_before(text, EXCERPT):
        return {"text": None, "withheld": True, "length": length, "sha256": sha256}
    return {"text": text[:EXCERPT], "withheld": False, "length": length, "sha256": sha256}


def safe_path(path):
    if (not isinstance(path, str) or not path.startswith("/") or len(path) > 4096
            or any(ord(character) < 32 or ord(character) == 127 for character in path)
            or credentials.find_in_text(path)):
        return "(withheld {})".format(text_digest(path if isinstance(path, str) else ""))
    return path


MAX_PATH_BYTES = 256 * 1024
MAX_EVENT_BYTES = 512 * 1024


def encoded(text):
    return len(text.encode("utf-8", "surrogatepass")) + 3


def capped(paths, first=()):
    """A sorted list of at most 1024 paths and 256 KiB of UTF-8, so that an event always holds them: the paths in
    `first` (those that matched a refused target) before the others, and `(N more)` for what does not fit. A suspicion
    with such an entry cannot be reviewed whole, so its lane can only be abandoned (lane review refuses the entry)."""
    first = sorted(set(first))
    rest = sorted(set(paths) - set(first))
    kept, size = [], 0
    for path in first + rest:
        if len(kept) >= lanes.MAX_PATHS - 1 or size + encoded(path) > MAX_PATH_BYTES:
            break
        kept.append(path)
        size += encoded(path)
    left = len(first) + len(rest) - len(kept)
    return sorted(kept + (["({} more)".format(left)] if left else []))


def safe_name(value, pattern):
    if isinstance(value, str) and pattern.fullmatch(value) and not credentials.find_in_text(value):
        return value
    return None


def position(item):
    return {"path": safe_path(item["record"].shown), "line": item["line"], "offset": item["offset"],
            "item": item["index"]}


def withhold_all(payload):
    """The payload with every text from a record withheld: the last resort when the detector still finds something."""
    for key in ("command", "message"):
        if payload.get(key) and not payload[key]["withheld"]:
            payload[key] = dict(payload[key], text=None, withheld=True)
    for key in ("targets", "paths"):
        if key in payload:
            payload[key] = capped({value if value == lanes.COMMAND_PATH else "(withheld {})".format(text_digest(value))
                                   for value in payload[key]})
    for item in (payload, payload.get("call") or {}):
        record = item.get("record")
        if record:
            record["path"] = "(withheld {})".format(text_digest(record["path"]))
    if payload.get("call"):
        payload["call"]["id"] = None
    if payload.get("hook"):
        payload["hook"] = {"event": None, "name": None}
    return payload


def checked(payload):
    """The payload as an event can hold it: nothing the credential detector refuses, and well below the store's size
    limit (otherwise every text and path from the record is withheld, which leaves hashes of bounded size)."""
    if credentials.find_in_value(payload) or len(json.dumps(payload, ensure_ascii=False).encode(
            "utf-8", "surrogatepass")) > MAX_EVENT_BYTES:
        payload = withhold_all(payload)
    return payload


# The runs of a lane, from its events and run records.

def event_time(event):
    return sessions.moment(event["occurred_at"] or event["recorded_at"])[0]


def lane_runs(store, state, lane):
    """The lane's runs in order: start and end (the moment its end, loss or declaration was recorded), whether the end
    is known, the runner, the placeholder values of its record templates, and the byte range of its own log when the
    supervising process recorded it."""
    runs = []
    by_number = {}
    kinds = ("lane.started", "lane.ended", "lane.lost", "lane.gone")
    for event in store.lane_events(lane, kinds) if store is not None else []:
        payload = event["payload"]
        if event["kind"] == "lane.started":
            values = {key: payload.get(key) for key in RECORD_VALUES}
            values["lane"] = lane
            # The lane's session identifier: none for a lane an earlier version started, or whose runner's command
            # does not use {session}; a template that names it is then `no-session` for the run (see expand()).
            values["session"] = payload.get("session_id")
            run = {"run": payload["run"], "launch": payload["launch"], "start": event_time(event), "end": None,
                   "ended": False, "ran": True, "worktree": os.path.realpath(payload["worktree"]),
                   "runner": payload["runner"], "values": values, "log": payload["log"], "log_range": None}
            runs.append(run)
            by_number[run["run"]] = run
            continue
        run = by_number.get(payload["run"])
        if run is None:
            continue
        run["ended"] = True
        if run["end"] is None:
            run["end"] = event_time(event)
        if event["kind"] == "lane.ended":
            run["end"] = event_time(event)
            run["ran"] = not (payload["exit_code"] is None and payload["signal"] is None)
    for earlier in runs[:-1]:
        earlier["ended"] = True
    for run in runs:
        try:
            record = runrecord.read(state, lane, run["launch"])
        except (LauncherError, OSError):
            record = None
        log = (record or {}).get("log")
        if isinstance(log, dict) and type(log.get("start")) is int:
            end = log.get("end") if type(log.get("end")) is int else None
            run["log_range"] = (log["start"], end)
    for earlier, later in zip(runs, runs[1:]):
        if earlier["log_range"] and earlier["log_range"][1] is None and later["log_range"]:
            earlier["log_range"] = (earlier["log_range"][0], later["log_range"][0])
    # Recorded ranges never overlap. A range that begins before an earlier run's range ends means the log was removed
    # or cut and written anew: that earlier run keeps only what lies before the beginning, and is truncated.
    ranged = [run for run in runs if run["log_range"]]
    for index, later in enumerate(ranged):
        begins = later["log_range"][0]
        for earlier in ranged[:index]:
            start, end = earlier["log_range"]
            if end is not None and (begins < end or begins < start):
                earlier["log_range"], earlier["log_cut"] = (start, max(start, min(end, begins))), True
    return runs


def recorded_ids(row):
    found = lanes.refusal_state(row)
    return set(found["recorded"]) | set(found["suspected"])


def waiting_ids(state, lane):
    found = set()
    for envelope in pending.waiting(state, lane):
        payload = envelope.get("payload") if isinstance(envelope.get("payload"), dict) else {}
        if envelope.get("kind") == "lane.refusal" and isinstance(payload.get("refusal"), str):
            found.add(payload["refusal"])
        if envelope.get("kind") == "lane.workaround_suspected" and isinstance(payload.get("suspicion"), str):
            found.add(payload["suspicion"])
    return found


def expand(template, run):
    """(the glob a record template names for a run, None), or (None, why it cannot be used): a placeholder the run has
    no value for (`no-session` for {session}: the run's lane has no session identity), or a value that holds a path
    component where only a name may stand ({worktree} and {log} are paths, at the start of a template only)."""
    values = run["values"]
    parsed = list(string.Formatter().parse(template))
    for index, (literal, field, _, _) in enumerate(parsed):
        if field is None:
            continue
        value = values.get(field)
        if value is None:
            return None, "no-session" if field == "session" else "template-unusable"
        at_start = index == 0 and not literal and field in ("worktree", "log")
        if not at_start and ("/" in str(value) or str(value) in (".", "..")):
            return None, "bad-placeholder"
    text = template.format(**{key: glob.escape(str(value)) for key, value in values.items() if value is not None})
    return os.path.expanduser(text), None


def walk(pattern, limit):
    """(paths, directories that could not be listed, whether the bound was hit) of a glob: `*`, `?` and `[...]` within
    a name (not a leading dot), `**` for any depth through links to directories too (each directory once, so a loop
    ends). Unlike glob.glob, a directory that cannot be listed is reported, and so are more than `limit` candidates at
    any stage (the first `limit` are kept)."""
    if not pattern.startswith("/"):
        return [], [], False
    errors, overflow, bases = [], False, ["/"]
    for part in [part for part in pattern.split("/") if part]:
        following = []
        if part == "**":
            visited = set()
            for root, directories, _ in (step for base in bases for step in os.walk(
                    base, followlinks=True, onerror=lambda error: errors.append(error.filename))):
                try:
                    key = fsguard.identity(os.stat(root))
                except OSError:
                    key = root
                directories[:] = [] if key in visited else sorted(name for name in directories if name[0] != ".")
                if key not in visited:
                    visited.add(key)
                    following.append(root)
                if len(following) > limit:
                    break
        elif any(character in part for character in "*?["):
            for base in bases:
                try:
                    with os.scandir(base) as entries:
                        names = sorted(entry.name for entry in entries)
                except (FileNotFoundError, NotADirectoryError):
                    continue
                except OSError:
                    errors.append(base)
                    continue
                following.extend(os.path.join(base, name) for name in names
                                 if (part.startswith(".") or not name.startswith(".")) and fnmatch.fnmatchcase(name, part))
                if len(following) > limit:
                    break
        else:
            following = [os.path.join(base, part) for base in bases]
        if len(following) > limit:
            following, overflow = following[:limit], True
        bases = following
        if not bases:
            break
    found = []
    for path in bases:
        try:
            os.lstat(path)
            found.append(path)
        except (FileNotFoundError, NotADirectoryError):
            pass
        except OSError:
            errors.append(os.path.dirname(path))
    return found, sorted(set(errors)), overflow


def inside(directory, worktree):
    return directory == worktree or directory.startswith(worktree.rstrip("/") + "/")


class Scan:
    """One scan of a lane's records: every run's records discovered, read in time order and checked. `emit` receives
    (kind, payload, at) of each refusal and suspicion not known yet. A live scan is polled again and again; a call then
    waits GRACE seconds for its result. `inventories` are the inventories kept for each launch: what earlier scans
    read of a record (its first line's hash and the offset read to) holds for this one too."""

    def __init__(self, configuration, zones, state, lane, runs, known, emit, live=False, inventories=None):
        self.configuration, self.state, self.lane, self.runs = configuration, state, lane, runs
        self.known, self.emit, self.live = known, emit, live
        self.zones = [fsguard.Location(configuration.home), fsguard.Location(configuration.state_home),
                      zones.own_config, zones.own_state] + [location for _, _, location in zones.others]
        self.matcher = guard_rules.Matcher(guard_rules.compile_guards(configuration))
        self.records, self.before, self.problems, self.open_calls, self.waiting = {}, {}, {}, {}, {}
        self.found = {run["run"]: set() for run in runs}
        self.refused_zone = set()
        self.refusals = []
        # What is saved of each run: (path, state) of every record of its inventory that is not covered.
        self.saved = {run["run"]: {(entry.get("path"), entry.get("state")) for entry in (inventories or {}).get(
            run["launch"], []) if entry.get("state", "covered") != "covered"} for run in runs}
        self.discovered = None
        self.earlier = {}
        for launch, entries in (inventories or {}).items():
            for entry in entries:
                earlier = self.earlier.setdefault(entry.get("path"), {"firsts": set(), "seen": 0, "tail": None,
                                                                      "launches": set()})
                earlier["launches"].add(launch)
                # A record an earlier scan found replaced, or saw with two first lines or two different bytes before
                # one place, compares equal to no file.
                earlier["firsts"].add("replaced" if entry.get("state") == "replaced" else entry.get("first"))
                seen = entry.get("seen") if type(entry.get("seen")) is int else 0
                if seen > earlier["seen"]:
                    earlier["seen"], earlier["tail"] = seen, entry.get("tail")
                elif seen == earlier["seen"] and entry.get("tail") is not None:
                    earlier["tail"] = entry["tail"] if earlier["tail"] in (None, entry["tail"]) else "replaced"

    # Which run a moment belongs to.

    def latest_begun(self, when):
        begun = [run for run in self.runs if run["start"] is not None and when is not None
                 and run["start"] - (SLACK if run is self.runs[0] else 0) <= when]
        return begun[-1] if begun else None

    def run_of(self, when):
        """The run whose window holds the moment: from its start to its end and five seconds more (open while its end
        is not known), or None."""
        run = self.latest_begun(when)
        if run is None or run["end"] is None or when <= run["end"] + AFTER:
            return run
        return None

    def problem(self, run, item):
        listed = self.problems.setdefault(run["run"], [])
        if item not in listed:
            listed.append(item)

    # Discovery.

    def discover(self):
        first = self.runs[0]["start"] if self.runs and self.runs[0]["start"] is not None else None
        for run in self.runs:
            if not configured(self.configuration, run["runner"]):
                continue
            for entry in self.configuration.data["runners"][run["runner"]]["records"]:
                for template in entry["paths"]:
                    if entry["format"] == "text":
                        self.log_record(run, template)
                        continue
                    pattern, why = expand(template, run)
                    if why:
                        self.problem(run, {"reason": why, "path": template})
                        continue
                    matches, errors, overflow = walk(pattern, MAX_MATCHES)
                    for directory in errors:
                        self.problem(run, {"reason": "unreadable", "path": safe_path(directory)})
                    if overflow:
                        self.problem(run, {"reason": "too-many-records", "path": template})
                    for path in matches:
                        self.consider(path, entry["format"], run, template, first)

    def log_record(self, run, template):
        key = (run["log"], run["run"])
        if key in self.records:
            return
        if run["log_range"] is None:
            self.problem(run, {"reason": "log-range-unknown", "path": safe_path(run["log"])})
            return
        record = sessions.Record(run["log"], "text", len(self.records), self.open_log, *run["log_range"], run["run"])
        record.cut, record.launch = run.get("log_cut", False), run["launch"]
        record.templates.add((run["run"], template))
        self.records[key] = record

    def open_log(self):
        """The lane's own log, opened like the launcher's other state files: through the lane's directory, never
        through a link (Refused for a link or anything but a regular file)."""
        directory = self.state.open_lane(self.lane)
        try:
            if directory is None or fsguard.file_info(directory, LOG) is None:
                raise FileNotFoundError(errno.ENOENT, "the lane's log does not exist")
            return fsguard.open_child(directory, LOG, "the lane's log")
        finally:
            if directory is not None:
                os.close(directory)

    def consider(self, path, fmt, run, template, first):
        """A file a template found: read when it changed after the lane's first run began and its real path lies
        outside every directory of the launcher (a file seen older than that is looked at again later)."""
        real = os.path.realpath(path)
        self.found[run["run"]].add(real)
        record = self.records.get(real)
        if record is not None:
            record.templates.add((run["run"], template))
            return
        if real in self.refused_zone:
            return
        try:
            info = os.stat(real)
        except OSError:
            self.problem(run, {"reason": "unreadable", "path": safe_path(path)})
            return
        if not stat.S_ISREG(info.st_mode):
            return
        if first is None or info.st_mtime < first - SLACK:
            self.before[real] = info.st_mtime
            return
        self.before.pop(real, None)
        if any(fsguard.inside(fsguard.Location(real), zone) for zone in self.zones):
            self.refused_zone.add(real)
            self.problem(self.latest_begun(info.st_mtime) or run, {"reason": "refused-zone", "path": safe_path(path)})
            return
        if sum(1 for item in self.records.values() if not item.foreign) >= MAX_RECORDS:
            self.problem(run, {"reason": "too-many-records", "path": safe_path(path)})
            return
        earlier = self.earlier.get(real, {"firsts": {None}, "seen": 0, "tail": None, "launches": set()})
        firsts = earlier["firsts"] - {None}
        record = sessions.Record(real, fmt, len(self.records), seen=earlier["seen"], tail=earlier["tail"],
                                 first=(min(firsts) if len(firsts) == 1 else "replaced") if firsts else None)
        record.launches = earlier["launches"]
        record.mtime = info.st_mtime
        record.shown = path
        record.templates.add((run["run"], template))
        self.records[real] = record

    # Reading.

    def poll(self, final):
        """Read what the records hold now and check it; with final, read every record to its very end and decide every
        call that is still waiting."""
        if final or self.discovered is None or time.monotonic() - self.discovered >= DISCOVER_SECONDS:
            self.discover()
            self.discovered = time.monotonic()
        structured = [record for record in self.records.values()
                      if record.format in sessions.STRUCTURED and not record.foreign]
        for key, item in heapq.merge(*(self.items(record, final) for record in structured), key=lambda pair: pair[0]):
            self.handle(item)
        for record in list(self.records.values()):
            if record.format == "text":
                self.read_text(record, final)
        if final:
            for key in list(self.open_calls):
                call = self.open_calls.pop(key)
                if call["class"] == "shell":
                    self.decide(call)
            self.waiting.clear()
        elif self.live:
            now = time.monotonic()
            for key, deadline in list(self.waiting.items()):
                if deadline <= now:
                    del self.waiting[key]
                    if key in self.open_calls:
                        self.decide(self.open_calls[key])

    def items(self, record, final):
        record.run_of_cursor = lambda: (self.run_of(record.cursor if record.cursor is not None else record.mtime)
                                        or {}).get("run")
        for number, offset, raw in record.lines(final):
            try:
                value = json.loads(raw.decode("utf-8", "replace"))
            except (ValueError, RecursionError):
                value = None
            category, found, directory, at = sessions.parse_claude(value)
            if directory and record.cwd is None:
                record.cwd = directory
                record.real_cwd = os.path.realpath(directory)
                if not any(inside(record.real_cwd, run["worktree"]) for run in self.runs):
                    # Another working directory's record: counted, never read further.
                    record.foreign = True
                    owner = self.latest_begun(record.mtime)
                    if owner is not None:
                        record.other_directory.add(owner["run"])
                    return
            if category == "message":
                record.recognised = True
            elif category == "partial":
                record.partly = True
            when, normal = sessions.moment(at)
            if when is not None:
                record.cursor = when
            else:
                when = record.cursor if record.cursor is not None else record.mtime
            run = self.run_of(when)
            if run is None:
                owner = self.latest_begun(when)
                if owner is not None:
                    record.count(owner["run"], "outside_runs")
                continue
            if record.cwd is not None and not inside(record.real_cwd, run["worktree"]):
                record.other_directory.add(run["run"])
                continue
            record.count(run["run"], "lines")
            if category == "unknown":
                record.count(run["run"], "unknown_lines")
            elif category == "other":
                record.count(run["run"], "other_lines")
            if record.cwd is None:
                continue
            for index, item in enumerate(found):
                item.update(run=run["run"], line=number, offset=offset, index=index, record=record, when=when, at=normal)
                yield (when, record.index, offset, index), item
        # Read to its end by the final read: only from then on is the record judged whole (state_of).
        record.finished = record.finished or final

    def read_text(self, record, final):
        for number, offset, raw in record.lines(final):
            record.count(record.run, "lines")
            found = self.search(dict(sessions.bounded(raw.decode("utf-8", "replace"))), record, record.run)
            if found:
                self.refused_line(record, record.run, number, offset, found)

    def save_seen(self, state, due=None, every=False, unfinished=None):
        """The one place that decides what the live reader saves: the coverage of every run it follows, the current one
        and every earlier one, is written at the look that saw a record of that run in a state other than covered that
        was neither handed to a save before nor held by the run's saved inventory (truncated, replaced, unreadable,
        refused-zone, partly-read, and unrecognised or partly-read once the run has ended and the record has been read
        to its end); also the run whose periodic write is due, and every run when `every`. A run `unfinished` (its last
        pass did not end) is never complete."""
        for run in self.runs:
            coverage = self.coverage(run, "supervising process", run["ended"] and run is not unfinished)
            seen = {(entry["path"], entry["state"]) for entry in coverage["inventory"] if entry["state"] != "covered"}
            if every or run is due or seen - self.saved.get(run["run"], set()):
                kept = write_coverage(state, self.lane, coverage)
                # What was seen and handed to the save stays known as seen, whatever state the merge kept (it keeps a
                # record's first bad state): a record that goes from one bad state to another is written once.
                self.saved[run["run"]] = self.saved.get(run["run"], set()) | seen | {
                    (entry.get("path"), entry.get("state")) for entry in kept.get("inventory", [])
                    if entry.get("state", "covered") != "covered"}

    def search(self, item, record, run):
        found, cut_lines = self.matcher.search(item["text"], item.get("tail"))
        if item.get("cut"):
            record.count(run, "cut_results")
        if cut_lines:
            record.count(run, "cut_lines", cut_lines)
        if found is guard_rules.TIMED_OUT:
            record.count(run, "timed_out")
            return None
        return found

    def handle(self, item):
        record = item["record"]
        key = (record.path, item["id"]) if item["id"] is not None else None
        if item["kind"] == "call":
            if key is None:
                return
            self.open_calls[key] = item
            if len(self.open_calls) > MAX_OPEN_CALLS:
                # The oldest waiting call is decided now rather than dropped, and its deadline goes with it.
                oldest = next(iter(self.open_calls))
                self.waiting.pop(oldest, None)
                if self.open_calls[oldest]["class"] == "shell":
                    self.decide(self.open_calls[oldest])
                del self.open_calls[oldest]
            if self.live and item["class"] == "shell":
                self.waiting[key] = time.monotonic() + GRACE
            return
        found = self.search(item, record, item["run"]) if item["kind"] == "hook" or item["error"] else None
        if found:
            # A refused call is a refusal, not also a workaround: it is no longer waiting to be decided.
            self.waiting.pop(key, None)
            self.refused(item, self.open_calls.pop(key, None), found)
        elif item["kind"] == "result" and "compare" not in self.open_calls.get(key, {"compare": None}):
            # Decided against the refusals before it, once no hook refused it within HOOK_WAIT seconds (or at the end
            # of a scan that reads the records to their end).
            self.open_calls[key]["compare"] = list(self.refusals)
            if self.live and self.open_calls[key]["class"] == "shell":
                self.waiting[key] = time.monotonic() + HOOK_WAIT

    def remember(self, info):
        self.refusals.append(info)
        if len(self.refusals) > MAX_COMPARED:
            self.refusals.pop(0)

    def refused(self, result, call, found):
        guard, message = found
        via = "hook" if result["kind"] == "hook" else "tool-result"
        record = result["record"]
        place = result["id"] if result["id"] is not None else "@{}:{}".format(result["offset"], result["index"])
        refusal = "rf-" + digest(self.lane, record.path, place)[:24]
        info = {"id": refusal, "run": result["run"], "path": record.path, "offset": result["offset"],
                "when": result["when"], "targets": set(), "shingles": None, "checked": False}
        if call is not None:
            if call["class"] == "shell":
                writes, named = shellscan.analyse(call["text"], call["cwd"])
                targets = writes or named
            else:
                targets = call["writes"] or call["named"]
            info.update(targets=set(targets), shingles=shellscan.shingles(call["text"]) or None, checked=True)
        self.remember(info)
        if refusal in self.known:
            return
        hook = {"event": safe_name(result.get("event"), lanes.HOOK_EVENT),
                "name": safe_name(result.get("name"), lanes.HOOK_NAME)} if via == "hook" else None
        payload = {"run": result["run"], "refusal": refusal, "guard": guard.name, "kind": guard.kind,
                   "format": record.format, "via": via, "hook": hook,
                   "tool": safe_name(call["tool"], lanes.TOOL) if call else None, "at": result["at"],
                   "command": excerpt(call["text"], call["length"], call["sha256"]) if call else None,
                   "message": excerpt(message), "targets": capped(safe_path(path) for path in info["targets"]),
                   "call": {"id": safe_name(result["id"], lanes.CALL_ID), "record": position(call) if call else None},
                   "record": position(result), "workarounds_checked": info["checked"]}
        self.known.add(refusal)
        self.emit("lane.refusal", checked(payload), result["at"])

    def refused_line(self, record, run, number, offset, found):
        guard, message = found
        refusal = "rf-" + digest(self.lane, record.path, record.launch, "@{}:0".format(offset))[:24]
        if refusal in self.known:
            return
        payload = {"run": run, "refusal": refusal, "guard": guard.name, "kind": guard.kind, "format": "text",
                   "via": "log", "hook": None, "tool": None, "at": None, "command": None, "message": excerpt(message),
                   "targets": [], "call": None,
                   "record": {"path": safe_path(record.shown), "line": number, "offset": offset, "item": 0},
                   "workarounds_checked": False}
        self.known.add(refusal)
        self.emit("lane.refusal", checked(payload), None)

    def decide(self, call):
        """Suspicions of a later shell call against every earlier refusal of the lane that names what it did."""
        writes = mine = None
        record = call["record"]
        for info in call.get("compare", self.refusals):
            if not info["checked"] or not later(call, info):
                continue
            if writes is None:
                writes = set(shellscan.analyse(call["text"], call["cwd"])[0])
                mine = shellscan.shingles(call["text"])
            ways, paths = [], set()
            hit = writes & info["targets"]
            if hit:
                ways.append("shell-write")
                paths |= hit
            similar = shellscan.reworded(mine, info["shingles"]) if info["shingles"] else None
            if similar:
                ways.append("reworded")
                paths |= writes
            if not ways:
                continue
            place = call["id"] if call["id"] is not None else "@{}:{}".format(call["offset"], call["index"])
            suspicion = "ws-" + digest(info["id"], record.path, place)[:24]
            if suspicion in self.known:
                continue
            payload = {"run": call["run"], "suspicion": suspicion, "refusal": info["id"], "how": sorted(ways),
                       "paths": capped({safe_path(path) for path in paths} or {lanes.COMMAND_PATH},
                                       {safe_path(path) for path in hit}),
                       "tool": safe_name(call["tool"], lanes.TOOL) or "shell", "at": call["at"],
                       "command": excerpt(call["text"], call["length"], call["sha256"]),
                       "call": {"id": safe_name(call["id"], lanes.CALL_ID), "record": position(call)},
                       "similarity": similar}
            self.known.add(suspicion)
            self.emit("lane.workaround_suspected", checked(payload), call["at"])

    # What was covered.

    def belongs(self, record, number, template):
        """True when a record a template found for a run is that run's: a claude-code record with lines of the run,
        or the run's own log."""
        if (number, template) not in record.templates:
            return False
        if record.format != "text":
            return record.counts.get(number, {}).get("lines", 0) > 0
        return record.run == number

    def state_of(self, record, complete):
        """A record's state as its last look found it; once its run is read to its end and the record too (by the final
        read, which also gives a last line without a newline), also partly-read while its first line never ended and
        unrecognised while no assistant or user line was read whole."""
        if record.state != "covered" or record.partly:
            return "partly-read" if record.state == "covered" else record.state
        if complete and record.finished and record.format in sessions.STRUCTURED and (
                record.incomplete or not record.recognised or record.cwd is None):
            return "partly-read" if record.incomplete else "unrecognised"
        return "covered"

    def coverage(self, run, by, complete):
        """What this scan covered of one run, with the inventory of its records (write_coverage merges it into the one
        kept on disk)."""
        number = run["run"]
        configured_run = configured(self.configuration, run["runner"])
        result = {"format": COVERAGE_FORMAT, "lane": self.lane, "run": number, "launch": run["launch"],
                  "scanned_at": events.utc_now(), "by": by, "complete": complete, "configured": configured_run,
                  "covered": False, "records": [], "skipped": {"other_directory": 0, "before_run": 0},
                  "not_covered": [], "inventory": []}
        if not configured_run:
            return result
        not_covered = list(self.problems.get(number, []))
        records, inventory = [], []
        for record in self.records.values():
            counts = record.counts.get(number)
            if record.foreign or (counts is None and number in record.other_directory):
                if number in record.other_directory:
                    result["skipped"]["other_directory"] += 1
                continue
            state = self.state_of(record, complete)
            owned = record.run if record.run is not None else (self.run_of(record.mtime) or {}).get("run")
            if counts is None and run["launch"] not in record.launches and (state == "covered" or owned != number):
                continue
            counts = counts or dict.fromkeys(sessions.COUNTS, 0)
            # A record none of whose lines (an oversized one included) lies in the run's window, read without fault, is not
            # the run's: it is listed for its count of lines outside the runs, and never enters the run's inventory.
            outside = (counts["outside_runs"] and not counts["lines"] and not counts["oversized"]
                       and record.state == "covered" and run["launch"] not in record.launches)
            records.append(dict(counts, path=safe_path(record.shown), format=record.format,
                                state="outside" if outside else state))
            if outside:
                continue
            if counts["oversized"]:
                not_covered.append({"reason": "oversized-line", "path": safe_path(record.shown)})
            if counts["timed_out"]:
                not_covered.append({"reason": "timed-out", "path": safe_path(record.shown)})
            inventory.append({"path": record.path, "shown": safe_path(record.shown), "format": record.format,
                              "first": record.first, "seen": record.seen, "tail": record.tail, "state": state})
        listed = {item["path"] for item in records}
        result["skipped"]["before_run"] = sum(
            1 for path in self.found.get(number, ()) if safe_path(path) not in listed and (
                path in self.before or (path in self.records and self.records[path].mtime is not None
                                        and run["start"] is not None and self.records[path].mtime < run["start"] - SLACK)))
        if run["ran"]:
            runner = self.configuration.data["runners"][run["runner"]]
            for entry in runner.get("records", []):
                for template in entry["paths"]:
                    if any(why["path"] == template for why in not_covered):
                        continue
                    if not any(self.belongs(record, number, template) for record in self.records.values()):
                        not_covered.append({"reason": "no-record", "path": template})
        if not complete:
            not_covered.append({"reason": "running" if not run["ended"] else "not-scanned-to-its-end"})
        result["records"] = sorted(records, key=lambda item: item["path"])
        result["not_covered"] = not_covered
        result["inventory"] = inventory
        return result


def later(call, info):
    """True when the call came after the refusal: in a later run, after the refusal's line in the same record, or after
    the refusal's time in another record."""
    if call["run"] != info["run"]:
        return call["run"] > info["run"]
    if call["record"].path == info["path"]:
        return call["offset"] > info["offset"]
    return call["when"] is not None and info["when"] is not None and call["when"] > info["when"]


def merged(old, new):
    """A scan's coverage of one launch merged into the one kept on disk: every record ever read for the run keeps the
    first state other than covered saved for it (never taken back, a later, different one not added; another first
    line, or other bytes before the same place, than before is replaced), a record whose file is gone is missing and
    one now shorter than what was read is replaced, and the run is covered only when no reason is left."""
    entries = {entry.get("path"): dict({"state": "covered", "seen": 0}, **entry)
               for entry in (old or {}).get("inventory", []) if isinstance(entry, dict)}
    for entry in new["inventory"]:
        before = entries.get(entry["path"], {"state": "covered", "seen": 0})
        state = before["state"]
        if state == "covered" and (before.get("first") not in (None, entry["first"]) and entry["first"] is not None or (
                before["seen"] == entry["seen"] and before.get("tail") not in (None, entry["tail"])
                and entry["tail"] is not None)):
            state = "replaced"
        later = entry if entry["seen"] >= before["seen"] else before
        entries[entry["path"]] = dict(entry, seen=later["seen"], tail=later.get("tail"),
                                      state=entry["state"] if state == "covered" else state)
    for entry in entries.values():
        if entry["state"] == "covered" and entry.get("format") != "text":
            try:
                entry["state"] = "replaced" if os.stat(entry["path"]).st_size < entry["seen"] else "covered"
            except FileNotFoundError:
                entry["state"] = "missing"
            except OSError:
                entry["state"] = "unreadable"
    states = {entry.get("shown"): entry["state"] for entry in entries.values() if entry["state"] != "covered"}
    reasons = new["not_covered"] + [{"reason": state, "path": shown} for shown, state in states.items()]
    not_covered = sorted({json.dumps(item, sort_keys=True): item for item in reasons}.values(),
                         key=lambda item: (item["reason"], item.get("path") or ""))
    return dict(new, inventory=sorted(entries.values(), key=lambda entry: str(entry.get("path"))),
                records=[dict(item, state=states.get(item["path"], item["state"])) for item in new["records"]],
                not_covered=not_covered, covered=new["configured"] and new["complete"] and not not_covered)


def valid_coverage(value, launch):
    """True when a kept coverage carries this format number and launch, and every field a later reader uses has its
    type: the reasons, the records' rows and the inventory's entries included."""
    def text(item, empty=False):
        return isinstance(item, str) or (empty and item is None)

    def rows(items, check):
        return isinstance(items, list) and all(isinstance(item, dict) and check(item) for item in items)

    return (isinstance(value, dict) and value.get("format") == COVERAGE_FORMAT and value.get("launch") == launch
            and text(value.get("lane")) and type(value.get("run")) is int and text(value.get("scanned_at"), True)
            and text(value.get("by"), True) and all(type(value.get(key)) is bool for key in ("complete", "configured",
                                                                                            "covered"))
            and isinstance(value.get("skipped"), dict) and all(type(item) is int for item in value["skipped"].values())
            and rows(value.get("not_covered"), lambda item: text(item.get("reason")) and text(item.get("path"), True))
            and rows(value.get("records"), lambda item: text(item.get("path")) and text(item.get("state")))
            and rows(value.get("inventory"), lambda item: text(item.get("path")) and text(item.get("state"))
                     and type(item.get("seen")) is int and item["seen"] >= 0
                     and all(text(item.get(key), True) for key in ("shown", "format", "first", "tail"))))


def read_coverage_at(directory, launch):
    """The coverage kept for a launch in an opened scans directory: None when there is none, UNREADABLE when the file
    exists but cannot be read, is not valid JSON, does not carry this format number (unreleased builds wrote none) or
    has a field of the wrong type."""
    try:
        if fsguard.file_info(directory, launch + ".json") is None:
            return None
        value = json.loads(fsguard.read_descriptor(fsguard.open_child(directory, launch + ".json", "the scan record"),
                                                   16 * 1024 * 1024, "the scan record").decode("utf-8"))
    except (LauncherError, OSError, UnicodeDecodeError, ValueError, RecursionError):
        return UNREADABLE
    return value if valid_coverage(value, launch) else UNREADABLE


def unreadable(state, lane, coverage):
    """A run's coverage when the file kept for it cannot be read: never covered, the reason naming the file."""
    path = safe_path(state.lane_path(lane, SCANS, coverage["launch"] + ".json"))
    return dict(coverage, not_covered=coverage["not_covered"] + [{"reason": "coverage-unreadable", "path": path}],
                covered=False)


def write_coverage(state, lane, coverage):
    """Merge a scan's coverage of one launch into the one on disk, under the lane's lock; return the merged one. A file
    that exists and cannot be read is never overwritten (the run is then not covered: coverage-unreadable)."""
    directory = state.open_lane(lane, create=True)
    if directory is None:
        # The state directory is gone: nothing can be saved, a failure like any other to write.
        raise FileNotFoundError(errno.ENOENT, "the lane's directory is gone; its scan cannot be saved",
                                safe_path(state.lane_path(lane)))
    try:
        with fsguard.Lock(directory):
            scans = fsguard.child_directory(directory, SCANS, create=True)
            try:
                kept = read_coverage_at(scans, coverage["launch"])
                if kept is UNREADABLE:
                    return unreadable(state, lane, merged(None, coverage))
                result = merged(kept, coverage)
                fsguard.write_new(scans, coverage["launch"] + ".json",
                                  (json.dumps(result, sort_keys=True) + "\n").encode("utf-8"), replace=True)
            finally:
                os.close(scans)
    finally:
        os.close(directory)
    return result


def read_coverage(state, lane, launch):
    directory = state.open_lane(lane, SCANS)
    if directory is None:
        return None
    try:
        return read_coverage_at(directory, launch)
    finally:
        os.close(directory)


def inventories(state, lane, runs):
    """The inventory kept for each launch."""
    found = {}
    for run in runs:
        coverage = read_coverage(state, lane, run["launch"])
        entries = coverage.get("inventory") if isinstance(coverage, dict) else None
        if isinstance(entries, list):
            found[run["launch"]] = [entry for entry in entries if isinstance(entry, dict)]
    return found


def envelope(lane, kind, payload, at, actor=PROGRAM):
    return {"id": "ev-" + uuid.uuid4().hex, "kind": kind, "lane": lane, "actor": actor, "occurred_at": at,
            "payload": payload, "protocol_version": load_protocol()[1]}


def flattened(coverages):
    """Every reason a run is not covered, with its run and the path it is about (or null)."""
    return [{"run": coverage["run"], "reason": item["reason"], "path": item.get("path")}
            for coverage in coverages for item in coverage["not_covered"]]


def scan_lane(session, zones, lane, by):
    """Read every record of every run of the lane to its end, append what is not recorded yet (behind the lane's
    waiting events) and keep what was covered. Returns the scan's result."""
    state = session.state
    runs = lane_runs(session.store, state, lane)
    known = recorded_ids(session.row(lane)) | waiting_ids(state, lane)
    found = []
    # Every record is read from its beginning here, never from a saved offset: a new Scan makes a new sessions.Record
    # for each record, whose offset starts at 0 (at the run's range start for the run's own log); earlier scans give
    # only the anchors that make a changed record `replaced`. lane mark's gate relies on it.
    scan = Scan(session.configuration, zones, state, lane, runs, known,
                lambda kind, payload, at: found.append((kind, payload, at)), inventories=inventories(state, lane, runs))
    if runs and configured(session.configuration):
        scan.poll(final=True)
    appended = {"refusals": 0, "suspicions": 0}
    refused = 0
    for kind, payload, at in found:
        try:
            pending.record(state, lane, envelope(lane, kind, payload, at), STORE_WAIT)
        except pending.StoreRefused:
            # Kept in refused.jsonl with the store's reason; the scan says so, and lane mark refuses to go on.
            refused += 1
            continue
        appended["refusals" if kind == "lane.refusal" else "suspicions"] += 1
    coverages = [write_coverage(state, lane, scan.coverage(run, by, complete=run["ended"])) for run in runs]
    session.refresh()
    current = lanes.refusal_state(session.row(lane))
    return {"lane": lane, "appended": appended, "refused_events": refused,
            "recorded": {"refusals": len(current["recorded"]), "suspicions": len(current["suspected"])},
            "unreviewed": current["unreviewed"], "runs": [shown(item) for item in coverages],
            "not_covered": flattened(coverages), "pending_events": pending.count(state, lane)}


def shown(coverage):
    """A coverage as commands print it: without the inventory, which holds real paths for the next scan."""
    return {key: value for key, value in coverage.items() if key != "inventory"}


def listing(session, lane):
    """The lane's refusals, suspicions, verdicts, unreviewed paths and what the latest scans covered; nothing is
    written."""
    row = session.row(lane)
    current = lanes.refusal_state(row)
    store = session.store
    recorded = store.lane_events(lane, lanes.REFUSAL_KINDS) if store is not None else []
    refusals, suspicions, verdicts = [], [], []
    for event in recorded:
        item = dict(event["payload"], seq=event["seq"])
        if event["kind"] == "lane.refusal":
            refusals.append(item)
        elif event["kind"] == "lane.workaround_suspected":
            suspicions.append(item)
        else:
            verdicts.append(dict(item, actor=event["actor"], occurred_at=event["occurred_at"]))
    latest = {}
    for verdict in verdicts:
        for suspicion in verdict["suspicions"]:
            latest[(suspicion, verdict["path"])] = verdict["verdict"]
    for item in suspicions:
        item["reviewed"] = {path: latest.get((item["suspicion"], path)) for path in item["paths"]}
    for item in refusals:
        item["suspicions"] = [entry["suspicion"] for entry in suspicions if entry["refusal"] == item["refusal"]]
    coverages = []
    for run in lane_runs(store, session.state, lane):
        coverage = read_coverage(session.state, lane, run["launch"])
        if coverage is None or coverage is UNREADABLE:
            configured_run = configured(session.configuration, run["runner"])
            empty = {"format": COVERAGE_FORMAT, "lane": lane, "run": run["run"], "launch": run["launch"],
                     "scanned_at": None, "by": None, "complete": False, "configured": configured_run, "covered": False,
                     "records": [], "skipped": {"other_directory": 0, "before_run": 0},
                     "not_covered": [{"reason": "not-scanned"}] if configured_run and coverage is None else []}
            coverage = empty if coverage is None else unreadable(session.state, lane, empty)
        coverages.append(shown(coverage))
    return {"lane": lane, "guards": len(session.configuration.data.get("guards", [])), "refusals": refusals,
            "suspicions": suspicions, "verdicts": verdicts, "unreviewed": current["unreviewed"], "coverage": coverages,
            "not_covered": flattened(coverages), "pending_events": pending.count(session.state, lane)}


# The scanning process beside a run, and the supervising process's side of it.

FOLLOWER = ("import sys; sys.path.insert(0, {!r}); from {}.refusals import follow; raise SystemExit(follow())")


class Follower:
    """The supervising process's handle on its scanning process: a child that follows the run's records and writes
    what it finds as JSON lines, which a reader thread hands to the recorder as events. Its process id is excluded
    from the run's process tree."""

    def __init__(self, process, deliver):
        self.process = process
        self.pid = process.pid
        self.deliver = deliver
        self.abandoned = False
        self.answered = False
        self.done = threading.Event()
        self.reader = threading.Thread(target=self.read, name="refusals", daemon=True)
        self.reader.start()

    @classmethod
    def start(cls, job, deliver):
        library = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        process = subprocess.Popen([sys.executable, "-I", "-B", "-c", FOLLOWER.format(library, __package__)],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=True)
        follower = cls(process, deliver)
        follower.send(job)
        return follower

    def send(self, value):
        try:
            self.process.stdin.write((json.dumps(value) + "\n").encode("ascii"))
            self.process.stdin.flush()
            return True
        except (OSError, ValueError):
            return False

    def read(self):
        try:
            for line in self.process.stdout:
                try:
                    value = json.loads(line.decode("utf-8"))
                except ValueError:
                    continue
                if isinstance(value, dict) and isinstance(value.get("event"), dict):
                    self.deliver(value["event"])
                elif isinstance(value, dict) and "done" in value:
                    self.answered = True
                    self.done.set()
        except (OSError, ValueError):
            pass
        finally:
            self.done.set()

    def finish(self, ended_at, log_end):
        """Ask for the last pass over the run's records, now that its processes are gone, then stop the scanning
        process: all of it within FINISH_SECONDS (five for the pass, then at most two to stop or kill it, after which it
        is abandoned). True when the last pass was done."""
        deadline = time.monotonic() + FINISH_SECONDS
        if self.send({"final": True, "ended_at": ended_at, "log_end": log_end}):
            self.done.wait(max(0.0, deadline - 2.0 - time.monotonic()))
        self.stop(deadline)
        return self.answered

    def stop(self, deadline=None):
        """Stop the scanning process by the given deadline (two seconds from now by default): it ends when its input
        closes; a second before the deadline it is killed (being this process's own child that has not been
        collected); whatever is left at the deadline is abandoned, never waited for without end."""
        deadline = time.monotonic() + 2.0 if deadline is None else deadline
        try:
            self.process.stdin.close()
        except OSError:
            pass
        try:
            self.process.wait(timeout=max(0.0, deadline - 1.0 - time.monotonic()))
        except subprocess.TimeoutExpired:
            self.process.kill()
            try:
                self.process.wait(timeout=max(0.05, deadline - 0.5 - time.monotonic()))
            except subprocess.TimeoutExpired:
                self.abandoned = True
        self.reader.join(max(0.0, deadline - time.monotonic()))


def follow():
    """The scanning process: reads its job, follows the lane's records until the supervising process asks for the last
    pass (then reads them to their end) or goes away (then stops), and writes events and its answer on stdout."""
    try:
        os.nice(10)
    except OSError:
        pass
    buffered = b""

    def lines():
        nonlocal buffered
        while b"\n" not in buffered:
            ready = select.select([0], [], [], POLL)[0]
            if not ready:
                return None
            data = os.read(0, 65536)
            if not data:
                return False
            buffered += data
        line, buffered = buffered.split(b"\n", 1)
        return json.loads(line.decode("ascii"))

    def emit(kind, payload, at):
        sys.stdout.write(json.dumps({"event": {"kind": kind, "payload": payload, "at": at}}) + "\n")
        sys.stdout.flush()

    try:
        first = None
        while first is None:
            first = lines()
        if first is False:
            return 2
        job = first
        configuration = config.load(job["config"])
        zones = config.Zones(configuration)
        if zones.problems():
            return 2
        state = StateDir.open(configuration, zones, create=False)
        if state is None:
            return 2
        with state.lock(shared=True):
            store = events.open_for_read(state)
        try:
            runs = lane_runs(store, state, job["lane"])
            row = store.lane(job["lane"]) if store is not None else None
        finally:
            if store is not None:
                store.close()
        runs = [run for run in runs if run["run"] <= job["run"]]
        if not runs or runs[-1]["run"] != job["run"]:
            return 2
        current = runs[-1]
        current["ended"] = False
        current["end"] = None
        current["log_range"] = (job["log_start"], None)
        scan = Scan(configuration, zones, state, job["lane"], runs,
                    recorded_ids(row) | waiting_ids(state, job["lane"]), emit, live=True,
                    inventories=inventories(state, job["lane"], runs))
        written = time.monotonic()
        finished = ended = False
        try:
            while True:
                scan.poll(final=False)
                due = time.monotonic() - written >= COVERAGE_SECONDS
                scan.save_seen(state, current if due else None)
                if due:
                    written = time.monotonic()
                command = lines()
                if command is False:
                    ended = True
                    return 0
                if isinstance(command, dict) and command.get("final"):
                    current["ended"] = True
                    current["end"] = sessions.moment(command.get("ended_at"))[0]
                    if type(command.get("log_end")) is int:
                        current["log_range"] = (job["log_start"], command["log_end"])
                        for record in scan.records.values():
                            if record.run == current["run"] and record.format == "text" and record.end is None:
                                record.end = command["log_end"]
                    scan.poll(final=True)
                    finished = True
                    scan.save_seen(state, every=True)
                    sys.stdout.write(json.dumps({"done": True}) + "\n")
                    sys.stdout.flush()
                    ended = True
                    return 0
        finally:
            # What the reader saw is saved however the loop ends, while the lane's state can still be written: the
            # supervising process gone, a broken pipe while emitting, an exception. A last pass that did not end leaves
            # the run not complete. After a normal end a failure to save is reported like any other; after an error it
            # never takes the place of that error, which is the one that goes on.
            try:
                scan.save_seen(state, unfinished=None if finished else current)
            except Exception:
                if ended:
                    raise
    except BrokenPipeError:
        return 0
    except (LauncherError, OSError, ValueError) as error:
        sys.stderr.write("{} refusal scan stopped: {}\n".format(events.utc_now(), error))
        return 1
