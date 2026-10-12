"""Run records: the identity of every launch's processes, at STATE_DIR/lanes/LANE/runs/LAUNCH.json.

The starting command writes a launch's record when it has created the lane's tmux session, with the identity of the
supervising process (the session's pane process). The supervising process adds the runner's identity when it creates
the runner, every process of the run's tree it samples while the run lives, and marks the record finished once the
run's processes are gone. Commands use the record, never a bare process id, to decide whether a run is supervised,
which of its processes survive, and what may be signalled. Records are written whole through a temporary name and
read through the opened lane directory without following a link.
"""

import json
import os

from . import fsguard, processes
from .errors import IntegrityProblem

RUNS = "runs"
MAX_BYTES = 4 * 1024 * 1024


def new(configuration, lane, run, launch, supervisor):
    return {"config": configuration.name, "lane": lane, "run": run, "launch": launch, "supervisor": supervisor,
            "runner": None, "processes": [], "finished": False}


def write(state, lane, record):
    directory = state.open_lane(lane, RUNS, create=True)
    try:
        fsguard.write_new(directory, record["launch"] + ".json",
                          (json.dumps(record, sort_keys=True) + "\n").encode("utf-8"), replace=True)
    finally:
        os.close(directory)


def read(state, lane, launch):
    """The record of one launch, or None when there is none."""
    directory = state.open_lane(lane, RUNS)
    if directory is None:
        return None
    name = launch + ".json"
    try:
        if fsguard.file_info(directory, name) is None:
            return None
        data = fsguard.read_descriptor(fsguard.open_child(directory, name, "the run record"), MAX_BYTES,
                                       "the run record")
    finally:
        os.close(directory)
    try:
        record = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise IntegrityProblem("the run record of lane {} launch {} is not readable".format(lane, launch)) from None
    if not isinstance(record, dict) or record.get("launch") != launch or not isinstance(record.get("processes"), list):
        raise IntegrityProblem("the run record of lane {} launch {} is not a run record".format(lane, launch))
    return record


def every(state, lane):
    """Every run record of the lane, including a launch whose lane.started is not stored yet."""
    directory = state.open_lane(lane, RUNS)
    if directory is None:
        return []
    try:
        names = sorted(name for name in os.listdir(directory) if name.endswith(".json"))
    except FileNotFoundError:
        names = []
    finally:
        os.close(directory)
    found = []
    for name in names:
        record = read(state, lane, name[:-len(".json")])
        if record is not None:
            found.append(record)
    return found


def valid_identity(value):
    return (isinstance(value, dict) and isinstance(value.get("pid"), int) and value["pid"] > 0
            and isinstance(value.get("start"), str))


def members(record):
    """The recorded identities of the run's processes: the runner and every process sampled from its tree."""
    found = [item for item in record.get("processes", []) if valid_identity(item)]
    runner = record.get("runner")
    if valid_identity(runner) and not any(item["pid"] == runner["pid"] and item["start"] == runner["start"]
                                          for item in found):
        found.insert(0, runner)
    return found


def supervisor_alive(record, snapshot=None):
    supervisor = record.get("supervisor") if record else None
    return valid_identity(supervisor) and processes.alive(supervisor, snapshot)


def survivors(record, snapshot=None):
    """The recorded processes of the run that still live, by identity."""
    if not record:
        return []
    return processes.living(members(record), snapshot)
