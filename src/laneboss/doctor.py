"""`laneboss doctor`: one JSON result line per check and exit 1 when any check fails.

It reads the bound configuration, its state directory, the ownership markers of the directories above
that state directory, and only the name and state location of every other configuration. It also looks
whether the tools directory of the organisation the configuration names is there. It prints
secret names at most, never values. When the state directory is not isolated it creates nothing.
"""

import os
import shutil
import sqlite3
import sys
import uuid

from . import config, events, fsguard, mail, statedir
from .errors import LauncherError
from .identity import PROGRAM
from .jsonutil import output
from .protocol import load_protocol
from .statedir import StateDir


def check_isolated(configuration, zones):
    problems = list(zones.problems())
    problems += ["configuration {} cannot be read ({}), so its state directory cannot be compared".format(name, why)
                 for name, why in zones.unreadable]
    try:
        state = StateDir.open(configuration, zones, create=False)
        if state is None:
            statedir.check_before_create(configuration, zones, str(configuration.state_dir))
        else:
            try:
                chain, markers = fsguard.walk_up(state.fd, config.MARKER)
                known = zones.known_names()
                if any(config.marker_owner(marker, known, configuration.name) == configuration.name
                       for marker in markers[1:]):
                    problems.append("the state directory lies inside another state directory of {}".format(
                        configuration.name))
                for root, _, files in os.walk(state.real):
                    if os.path.realpath(root) != state.real and config.MARKER in files:
                        problems.append("the state directory contains another state directory, {}".format(root))
                        break
            finally:
                state.close()
    except LauncherError as error:
        problems.append(str(error))
    if problems:
        return False, "; ".join(problems)
    return True, "{} is used by configuration {} alone".format(configuration.state_dir, configuration.name)


def check_recorded(configuration, zones):
    """The configuration's real store: when one was ever created it must be the recorded store and verify;
    a store with events that no marker records fails (R11)."""
    try:
        state = StateDir.open(configuration, zones, create=False)
        if state is None:
            return True, "no store has been created yet"
        try:
            with state.lock(shared=True):
                store = events.open_for_read(state)
            if store is None:
                return True, "no store has been created yet"
            try:
                result = store.verify(state)
            finally:
                store.close()
        finally:
            state.close()
    except LauncherError as error:
        return False, str(error)
    except sqlite3.Error as error:
        return False, "the store cannot be read: " + str(error)
    return True, "the recorded store verifies ({} event(s))".format(result["events"])


def check_writable(configuration, zones):
    try:
        state = StateDir.open(configuration, zones, create=True)
        try:
            probe = ".doctor-probe-{}".format(uuid.uuid4().hex)
            os.close(os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL | fsguard.NOFOLLOW, 0o600, dir_fd=state.fd))
            os.unlink(probe, dir_fd=state.fd)
        finally:
            state.close()
    except LauncherError as error:
        return False, str(error)
    except OSError as error:
        return False, "{} is not writable: {}".format(configuration.state_dir, error.strerror or "error")
    return True, "{} is writable".format(configuration.state_dir)


def check_round_trip(configuration, zones):
    scratch = ".doctor-{}".format(uuid.uuid4().hex)
    try:
        state = StateDir.open(configuration, zones, create=False)
        try:
            os.mkdir(scratch, 0o700, dir_fd=state.fd)
            try:
                store = events.EventStore(os.path.join(state.real, scratch, config.STORE_FILE), configuration.name,
                                          "rwc")
                try:
                    store.initialize()
                    appended = store.append({"kind": "doctor.probe", "actor": PROGRAM,
                                             "payload": {"check": "store.round_trip"},
                                             "protocol_version": load_protocol()[1]})
                    read_back = store.events()
                    if [(item["id"], item["sha256"]) for item in read_back] != [(appended["id"], appended["sha256"])]:
                        return False, "the scratch store did not read back the event it appended"
                    store.verify(None)
                finally:
                    store.close()
            finally:
                scratch_fd = fsguard.child_directory(state.fd, scratch)
                try:
                    for name in os.listdir(scratch_fd):
                        os.unlink(name, dir_fd=scratch_fd)
                finally:
                    os.close(scratch_fd)
                os.rmdir(scratch, dir_fd=state.fd)
        finally:
            state.close()
    except (LauncherError, OSError, sqlite3.Error) as error:
        return False, "scratch store failed: " + (str(error) if isinstance(error, LauncherError) else
                                                  getattr(error, "strerror", None) or type(error).__name__)
    return True, "created, appended to, read back, verified and removed a scratch store"


def guarded(check, configuration, zones):
    """A check's (ok, detail). A file-system error inside a check fails that check; doctor goes on."""
    try:
        return check(configuration, zones)
    except OSError as error:
        return False, "a file-system error stopped this check: {}".format(error.strerror or type(error).__name__)


def find_command(command):
    if command.startswith("/"):
        return command if os.path.isfile(command) and os.access(command, os.X_OK) else None
    return shutil.which(command)


def check_organisation_tools(configuration):
    """The tools directory of the organisation the configuration names exists and is a directory. A configuration
    that names none fails when a command of it points into an organisation's directory (it was written before
    organisations: `config validate` accepts it, and the detail names the key path, never the path). Nothing is
    created."""
    if configuration.organisation is None:
        key_path = configuration.command_into_organisation()
        if key_path is None:
            return True, "no organisation is named"
        return False, ("this configuration names no organisation, but {} points into an organisation's directory: add "
                       'organisation = "NAME" to config.toml, with the name of that organisation'.format(key_path))
    tools = str(configuration.organisation_tools)
    if os.path.isdir(tools):
        return True, "{} is the tools directory of organisation {}".format(tools, configuration.organisation)
    return False, "{} {}".format(tools, "is not a directory" if os.path.lexists(tools) else "does not exist")


def turn_limit_warning(configuration):
    """The warning for the runners that can take turns (`{session}` in `command` and in `resume`, `prompt = "stdin"`
    and a `resume` template) and have no `limit_patterns`, or None when there is none. Such a runner is not refused;
    but a turn of it that ends at a usage limit with exit code 0 and a prompt written whole is counted as delivered,
    because nothing else tells the launcher about the limit (docs/architecture.md, "Known limits"). The check is a
    warning: it never fails, and it is reported only when there is a runner to name."""
    names = [name for name, runner in sorted(configuration.data["runners"].items())
             if not mail.turn_problems(name, runner) and not runner.get("limit_patterns")]
    if not names:
        return None
    subject = ("runner {} can take turns and has".format(names[0]) if len(names) == 1 else
               "runners {} can take turns and have".format(", ".join(names)))
    return ("warning: {} no limit_patterns, so a turn that ends at a usage limit with exit code 0 is counted as "
            "delivered; give each of them limit_patterns".format(subject))


def run(name):
    results = []

    def record(check, ok, detail):
        results.append(ok)
        sys.stdout.write(output({"check": check, "ok": bool(ok), "detail": detail}) + "\n")
        sys.stdout.flush()

    try:
        configuration = config.load(name)
    except LauncherError as error:
        configuration = None
        record("config", False, str(error))
    else:
        record("config", True, "configuration {} is valid".format(name))
    if configuration is None:
        for check in ("state.isolated", "store.recorded", "state.writable", "store.round_trip"):
            record(check, False, "not checked: the configuration is invalid")
    else:
        zones = config.Zones(configuration)
        isolated, detail = guarded(check_isolated, configuration, zones)
        record("state.isolated", isolated, detail)
        if not isolated:
            for check in ("store.recorded", "state.writable", "store.round_trip"):
                record(check, False, "not checked: the state directory is not isolated")
        else:
            record("store.recorded", *guarded(check_recorded, configuration, zones))
            writable, detail = guarded(check_writable, configuration, zones)
            record("state.writable", writable, detail)
            if writable:
                record("store.round_trip", *guarded(check_round_trip, configuration, zones))
            else:
                record("store.round_trip", False, "not checked: the state directory is not writable")
    for tool in ("git", "tmux"):
        found = shutil.which(tool)
        record("tool." + tool, found is not None, "found at " + found if found else tool + " is not on PATH")
    if configuration is not None:
        for runner_name, runner in sorted(configuration.data["runners"].items()):
            programs = [runner["command"][0]] + ([runner["resume"][0]] if "resume" in runner else [])
            found = {program: find_command(program) for program in programs}
            missing = [program for program in programs if found[program] is None]
            record("runner." + runner_name, not missing,
                   "; ".join("{} is not found on PATH".format(program) for program in missing) if missing else
                   "; ".join("{} found at {}".format(program, found[program]) for program in sorted(set(programs))))
        warning = turn_limit_warning(configuration)
        if warning is not None:
            record("turns.limit_patterns", True, warning)
        for judge_name, judge in sorted(configuration.data.get("judges", {}).items()):
            program = judge["command"][0]
            found = find_command(program)
            record("judge." + judge_name, found is not None,
                   "{} found at {}".format(program, found) if found else "{} is not found on PATH".format(program))
        # One line per configured adapter, after the judge lines: the program of command[0], never an argument, and
        # never a call to the adapter or a read of the variable credential_env names.
        for resource_name, resource in sorted(configuration.data.get("resources", {}).items()):
            program = resource["command"][0]
            found = find_command(program)
            record("resource." + resource_name, found is not None,
                   "{} found at {}".format(program, found) if found else "{} is not found on PATH".format(program))
        record("organisation.tools", *check_organisation_tools(configuration))
    return 0 if all(results) else 1
