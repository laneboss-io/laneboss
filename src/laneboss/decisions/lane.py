"""Ingesting a lane's own records into the decision store, by keyword only.

`ingest-lane` reads a finished lane through the launcher's own records and writes one `lane_records` row for each
source: the lane's final report, its events as text lines, and every file the caller attaches. The rows are kept for
keyword search and for nothing else: they are never embedded and never sent anywhere, because the owner's data table
does not yet name an embedding provider for lane records.

The report is the runner's own output for the lane's latest run. The launcher writes a runner's standard output and
error to `lanes/LANE/output.log` and nothing else does, and the run record of the lane's latest launch
(`lanes/LANE/runs/LAUNCH.json`, written by `runrecord`) records the byte range of that log that belongs to that run
(`log.start`..`log.end`). Those bytes are the runner's final message; the file is named here so the choice is visible.

Nothing is written until every source has been read and built, and a source whose text is empty is refused: an empty
report row is never written. A lane that is running is refused. Ingesting the same source twice writes nothing the
second time, because a lane record's id names the first 16 hex digits of the source's SHA-256. The events source
leaves out `lane.ingested`: those events are this command's own receipts, and the receipt of an earlier ingest names
the very rows this one compares, so keeping them would change the events text on every ingest and the same lane could
never be ingested twice without adding a row.
"""

from datetime import datetime, timezone
import json
import os

from .. import config, events, runrecord, statedir
from ..errors import LauncherError
from ..identity import PROGRAM
from ..protocol import load_protocol
from .schema import InvalidInput, canonical, lane_record_id, sha256, utc_now

REPORT_STREAM = "output.log"
MAX_SOURCE_BYTES = 8 * 1024 * 1024
# The parts a source can have, in the order ingest-lane writes them.
REPORT = "report"
EVENTS = "events"
ATTACHMENT = "attachment"
# The event ingest-lane appends itself: the receipt of an ingest. It is never part of the events source.
INGESTED = "lane.ingested"


def read_text(path, limit=MAX_SOURCE_BYTES):
    """The whole file as UTF-8 text, or an invalid-input error. The byte count is bounded before anything is read."""
    try:
        size = os.stat(path).st_size
    except OSError as error:
        raise InvalidInput("cannot read {}: {}".format(path, error.strerror or "operating system error")) from None
    if size > limit:
        raise InvalidInput("{} is larger than the {} bytes a single source may hold".format(path, limit))
    try:
        with open(path, "rb") as source:
            data = source.read()
    except OSError as error:
        raise InvalidInput("cannot read {}: {}".format(path, error.strerror or "operating system error")) from None
    try:
        return data.decode("utf-8"), data
    except UnicodeDecodeError:
        raise InvalidInput("{} is not UTF-8 text".format(path)) from None


def read_range(path, start, end, limit=MAX_SOURCE_BYTES):
    """The bytes `start`..`end` of a file, exactly, or an invalid-input error."""
    if type(start) is not int or type(end) is not int or start < 0 or end < start:
        raise InvalidInput("the log range of the lane's latest run is not a pair of offsets")
    if end - start > limit:
        raise InvalidInput("the lane's report is larger than the {} bytes a single source may hold".format(limit))
    try:
        with open(path, "rb") as source:
            source.seek(start)
            data = source.read(end - start)
    except OSError as error:
        raise InvalidInput("cannot read {}: {}".format(path, error.strerror or "operating system error")) from None
    if len(data) != end - start:
        raise InvalidInput("{} holds fewer bytes than the lane's latest run recorded".format(path))
    try:
        return data.decode("utf-8"), data
    except UnicodeDecodeError:
        raise InvalidInput("the lane's report at {} is not UTF-8 text".format(path)) from None


def file_time(path):
    try:
        moment = os.stat(path).st_mtime
    except OSError as error:
        raise InvalidInput("cannot read {}: {}".format(path, error.strerror or "operating system error")) from None
    return datetime.fromtimestamp(moment, timezone.utc).isoformat(timespec="microseconds")


def event_time(event):
    return event["occurred_at"] or event["recorded_at"]


def events_text(lane_events):
    """The lane's events as one text line each: the stored envelope exactly as the launcher keeps it."""
    return "".join(canonical(event) + "\n" for event in lane_events)


def source(config, lane, part, path, text, data, created_utc, ingest_time):
    digest = sha256(data)
    return {
        "id": lane_record_id(config, lane, part, digest),
        "config": config,
        "lane": lane,
        "part": part,
        "source_path": path,
        "source_sha256": digest,
        "text": text,
        "created_utc": created_utc,
        "ingested_utc": ingest_time,
    }


def build_report(config, lane, state, run_records, latest_event, ingest_time):
    if not run_records:
        raise InvalidInput(
            "lane {} of configuration {} has no run record, so it has no readable report; nothing was ingested".format(
                lane, config))
    latest = max(run_records, key=lambda record: record["run"])
    span = latest.get("log") or {}
    path = state.lane_path(lane, REPORT_STREAM)
    text, data = read_range(path, span.get("start"), span.get("end"))
    if not text.strip():
        raise InvalidInput(
            "lane {}'s latest run wrote nothing to {}; an empty report is not ingested".format(lane, path))
    created = event_time(latest_event) if latest_event is not None else file_time(path)
    return source(config, lane, REPORT, path, text, data, created, ingest_time)


def build_events(config, lane, lane_events, store_path, latest_event, ingest_time):
    text = events_text(lane_events)
    if not text.strip():
        raise InvalidInput("lane {} has no events; an empty event record is not ingested".format(lane))
    created = event_time(latest_event) if latest_event is not None else utc_now()
    return source(config, lane, EVENTS, store_path, text, text.encode("utf-8"), created, ingest_time)


def build_attachments(config, lane, paths, ingest_time):
    built = []
    for given in paths:
        text, data = read_text(given)
        if not text.strip():
            raise InvalidInput("the attached file {} is empty or holds no text; it is not ingested".format(given))
        built.append(source(config, lane, ATTACHMENT, str(given), text, data, file_time(given), ingest_time))
    return built


def ingest_lane(store, configuration_name, lane, attachments=(), org_dir=None, instance=None):
    """Read the lane's final report, its events and every attached file, write one lane record for each, append
    `lane.ingested` to the launcher's store with the receipt, and return the receipt."""
    identity, org = {}, None
    if org_dir is not None or instance is not None:
        from .orgcontext import discover
        org, identity, _, _ = discover(org_dir=org_dir, instance=instance)
        org.check_store(store.connection.execute("PRAGMA database_list").fetchone()[2])
    configuration = config.load(configuration_name)
    zones = config.Zones(configuration)
    problems = zones.problems()
    if problems:
        raise InvalidInput(problems[0])
    state = statedir.StateDir.open(configuration, zones, create=False)
    if state is None:
        raise InvalidInput("configuration {} has no state directory; nothing was ingested".format(configuration_name))
    try:
        with state.lock(shared=True):
            event_store = events.open_for_read(state)
            if event_store is None:
                raise InvalidInput(
                    "configuration {} has no event store; lane {} has no readable report and nothing was "
                    "ingested".format(configuration_name, lane))
            try:
                projection = event_store.lane(lane)
                if projection is None or not projection["events"]:
                    raise InvalidInput(
                        "lane {} is not in the event store of configuration {}; nothing was ingested".format(
                            lane, configuration_name))
                if projection["running"]:
                    raise InvalidInput(
                        "lane {} is running run {}; a running lane's records are not ingested".format(
                            lane, projection["run"]))
                lane_events = [event for event in event_store.events() if event["lane"] == lane]
                store_path = event_store.path
            finally:
                event_store.close()
        ingest_time = utc_now()
        # Every source is read and built before anything is written, so a refusal leaves the store untouched. The
        # events source holds the lane's own events and not the lane.ingested receipts: the receipt of an earlier
        # ingest names the rows this one is about to compare, so keeping it would change the events text on every
        # ingest and the same lane could never be ingested twice without adding a row.
        history = [event for event in lane_events if event["kind"] != INGESTED]
        runs = runrecord.every(state, lane)
        latest_run = max((record["run"] for record in runs), default=None)
        report_event = next((event for event in reversed(history) if event["kind"] == "lane.ended"
                             and event["payload"].get("run") == latest_run), None)
        # A later ingest receipt or supervisor mark must not make an old report younger.
        history_event = history[-1] if history else None
        sources = [build_report(configuration_name, lane, state, runs, report_event, ingest_time),
                   build_events(configuration_name, lane, history, store_path, history_event, ingest_time)]
        sources += build_attachments(configuration_name, lane, attachments, ingest_time)
        for record in sources:
            record.update(identity)
        rows = []
        added = existing = 0
        with store.history_transaction():
            for record in sources:
                if store.insert_lane_record(record):
                    added += 1
                else:
                    existing += 1
                rows.append({"id": record["id"], "sha256": record["source_sha256"]})
            # Outcome sources identify immutable launcher events, so a repeat ingest never counts one twice.
            for event in history:
                reward = None
                if event["kind"] == "lane.state":
                    reward = event["payload"].get("state")
                elif event["kind"] == "lane.merged":
                    reward = "merged"
                elif event["kind"] == "lane.refusal":
                    reward = "refusal"
                if reward in ("accepted", "merged", "abandoned", "refusal"):
                    reference = "lane:{}/{}:event:{}".format(configuration_name, lane, event["seq"])
                    for record in sources:
                        store.append_feedback(record["id"], reward, reference, event_time(event))
            if org is not None:
                from .curated import citations
                report = sources[0]
                citations(store, org, report["text"], "report:" + report["source_path"] + ":" + report["source_sha256"],
                          report["created_utc"], identity)
        receipt = {"lane": lane, "rows_added": added, "rows_existing": existing, "rows": rows}
        append_ingested(configuration, zones, state, lane, receipt)
        return receipt
    finally:
        state.close()


def lane_end(configuration_name, lane, org_dir=None, instance=None, db=None, directory=None):
    """Launcher seam: call after the log end offset is saved and lane.ended is durably appended, outside locks.

    The caller records this receipt in its watch log, and ignores its `ok` flag for the lane's exit status. Call
    again after accepted/merged/abandoned marks to ingest feedback. This function never raises an ingest failure.
    """
    store = None
    result = None
    try:
        from .orgcontext import discover
        from .store import Store
        org, identity, _, _ = discover(directory=directory, org_dir=org_dir, instance=instance)
        destination = org.db if db is None else db
        org.check_store(destination)
        store = Store(destination)
        receipt = ingest_lane(store, configuration_name, lane, (), str(org.root), identity["instance"])
        result = {"ok": True, **receipt}
    except Exception as error:
        # Explicitly observable failure, as required by the launcher contract; no fabricated success or verdict.
        result = {"ok": False, "lane": lane, "ingest_error": type(error).__name__}
    finally:
        if store is not None:
            try:
                store.close()
            except Exception as error:
                result = {"ok": False, "lane": lane, "ingest_error": type(error).__name__}
    return result


def append_ingested(configuration, zones, state, lane, receipt):
    """Record the receipt with the lane. The lane is checked again under the write lock: a lane that started running
    while its sources were read is refused before the event is appended."""
    with state.lock():
        event_store = events.open_for_write(state)
        try:
            projection = event_store.lane(lane)
            if projection is not None and projection["running"]:
                raise InvalidInput(
                    "lane {} started running while its records were read; the event was not recorded".format(lane))
            event_store.append({"kind": INGESTED, "lane": lane, "actor": PROGRAM, "payload": receipt,
                                "protocol_version": load_protocol()[1]})
        finally:
            event_store.close()
    return receipt


def launcher_failure(error):
    """(message, exit code) for a launcher error a decision-store command met, or None for any other error."""
    if isinstance(error, LauncherError):
        return "{}: {}".format(error.prefix, error), error.exit_code
    return None
