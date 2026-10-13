"""The launcher command: one JSON value on stdout, errors on stderr, explicit exit codes.

Exit codes: 0 success; 1 a doctor check failed; 2 invalid input or a refused request;
3 an integrity problem; 70 an unexpected internal error (set LANEBOSS_DEBUG=1 for the traceback).
`decisions` passes its arguments to the decision store unchanged.
"""

import argparse
from contextlib import redirect_stderr
import io
import os
import re
import sqlite3
import sys
import time

from . import attach, brief, config, disk, doctor, events, judgecmd, lanecmd, loopcmd, mail, orgcmd, orgdiscord
from . import orghook, startcmd
from .errors import LauncherError, Refused
from .identity import PROGRAM, VERSION, env_name
from .jsonutil import output, parse
from .protocol import load_protocol
from .statedir import StateDir

MAX_EVENT_BYTES = 2 * 1024 * 1024
FOLLOW_INTERVAL = 0.2


def non_negative(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number") from None
    if number < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return number


def positive(value):
    number = non_negative(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return number


# The usage errors of argparse that are made of its own words and of the labels of arguments the parser defined, and
# of nothing that was typed. LABELS holds only letters, digits and - _ / , and spaces; a form is matched whole.
USAGE_LABELS = r"[A-Za-z0-9_/, \-]+"
USAGE_FORMS = tuple(re.compile(form.replace("LABELS", USAGE_LABELS)) for form in (
    r"the following arguments are required: LABELS",
    r"argument LABELS: expected (?:one argument|at least one argument|at most one argument|[0-9]+ arguments?)",
    r"argument LABELS: not allowed with argument LABELS",
    r"one of the arguments LABELS is required",
))
USAGE_LABELLED = re.compile("argument (" + USAGE_LABELS + "): ")
USAGE_REFUSED = "not accepted; a typed value is never repeated here, see the usage line above or run with --help"


class ScreeningParser(argparse.ArgumentParser):
    """The parser of the launcher's commands and of `laneboss plugin` (not of `laneboss decisions`, a program of its
    own); sub-commands take this class from their parent. argparse repeats what was typed in many of its usage errors
    ("invalid choice: 'X'", "unrecognized arguments: X", "ignored explicit argument 'X'", "ambiguous option: X could
    match ...", "invalid int value: 'X'"), and a typed value can be a secret of any shape. So a usage error fails
    closed: it is printed unchanged only when all of it is one of USAGE_FORMS, the forms made of the parser's own words
    and of labels it defined itself. Any other message, including one that a later Python adds or rewords, is replaced
    by a fixed sentence that holds at most the label of the argument; nothing else of it is used."""

    def error(self, message):
        if not any(form.fullmatch(message) for form in USAGE_FORMS):
            labelled = USAGE_LABELLED.match(message)
            start = "argument {}: ".format(labelled.group(1)) if labelled else "the command line was "
            message = start + USAGE_REFUSED
        super().error(message)


def build_parser():
    root = ScreeningParser(prog=PROGRAM, description="A launcher for supervised lanes: configurations, "
                                   "an event store, the shared protocol, brief rendering and lanes.")
    root.add_argument("--version", action="store_true", help="print the package and protocol versions")
    commands = root.add_subparsers(dest="command", metavar="COMMAND")
    commands.add_parser("decisions", help="the owner decision store; arguments pass through unchanged")
    commands.add_parser("plugin", help="locate the installed plugin of an agent program (plugin path)")
    org = commands.add_parser("org", help="manage the structured org, its hooks, owner channels and history")
    org_actions = org.add_subparsers(dest="action", metavar="ACTION", required=True)
    orgcmd.register_actions(org_actions)
    orghook.register_actions(org_actions)
    channel = org_actions.add_parser("channel", help="register owner channels for L5/L6 instances")
    channel_actions = channel.add_subparsers(dest="channel_action", metavar="ACTION", required=True)
    channel_add = channel_actions.add_parser("add", help="register a Discord channel and verify its hello")
    channel_add.add_argument("org_dir", metavar="ORG-DIR")
    channel_add.add_argument("instance", metavar="INSTANCE")
    channel_mode = channel_add.add_mutually_exclusive_group(required=True)
    channel_mode.add_argument("--channel-id", metavar="ID", help="a channel created by the owner")
    channel_mode.add_argument("--create", action="store_true", help="create through the bot (Manage Channels)")
    channel_add.add_argument("--member", action="append", default=[], metavar="ID:AUTHORITY",
                             help="a user id with decide or inform authority; repeat for more members")
    channel_add.add_argument("--role-id", action="append", default=[], metavar="ID:AUTHORITY",
                             help="a Discord server role id with decide or inform authority; repeatable")
    channel_add.add_argument("--dry-run", action="store_true", help="print all changes and requests; write and post nothing")
    binding = argparse.ArgumentParser(add_help=False)
    binding.add_argument("--config", metavar="NAME", help="the configuration to bind (or set {})".format(
        env_name("CONFIG")))
    # B2: org history injection and owner-decision capture, in the same org command group.
    history = org_actions.add_parser("hook-history", help="bounded additional context for runner hooks; failure-tolerant")
    history.add_argument("--runner", required=True, choices=("claude", "codex"))
    history.add_argument("--org-dir", help="the org folder; otherwise the LANEBOSS_ORG variable")
    history.add_argument("--instance", help="otherwise use instance.toml or LANEBOSS_INSTANCE")
    history.add_argument("--event", choices=("SessionStart", "UserPromptSubmit"), help="otherwise read the hook input")
    capture = org_actions.add_parser("capture-decision", parents=[binding], help="classify a human message with a judge Choice")
    capture.add_argument("--org-dir", required=True)
    capture.add_argument("--source", required=True, help="channel/message or terminal/session/time pointer")
    capture.add_argument("--text-file", required=True)
    capture.add_argument("--author-authority", required=True, choices=("decide", "inform"))
    capture.add_argument("--instance", help="otherwise use instance.toml or LANEBOSS_INSTANCE")
    capture.add_argument("--judge", help="otherwise use the org history judge")
    capture.add_argument("--at", help="message timestamp; otherwise use the source's time or text file's mtime")

    configs = commands.add_parser("config", help="list, show, validate and locate configurations")
    actions = configs.add_subparsers(dest="action", metavar="ACTION", required=True)
    actions.add_parser("list", help="names of the configurations under the configuration home")
    actions.add_parser("show", help="a validated configuration as JSON").add_argument("name")
    validate = actions.add_parser("validate", help="validate one configuration or all of them")
    target = validate.add_mutually_exclusive_group(required=True)
    target.add_argument("name", nargs="?")
    target.add_argument("--all", action="store_true", help="every configuration, including state overlap")
    actions.add_parser("path", help="the directories and store of a configuration").add_argument("name")

    event = commands.add_parser("event", help="append and read events")
    actions = event.add_subparsers(dest="action", metavar="ACTION", required=True)
    append = actions.add_parser("append", parents=[binding], help="append one event read from a file")
    append.add_argument("--file", required=True, help="the event as a JSON file, or - for stdin")
    tail = actions.add_parser("tail", parents=[binding], help="print events as JSON lines")
    tail.add_argument("--since", type=non_negative, default=0, metavar="SEQ", help="only events after this seq")
    tail.add_argument("--follow", action="store_true", help="keep printing new events as they are appended")
    tail.add_argument("--lane", help="only the events of this lane")
    tail.add_argument("--until", metavar="KIND", help="stop after printing the first event of this kind")

    state = commands.add_parser("state", help="read and check the event store")
    actions = state.add_subparsers(dest="action", metavar="ACTION", required=True)
    actions.add_parser("events", parents=[binding], help="every event as one JSON array")
    actions.add_parser("lanes", parents=[binding], help="the current state and times of every lane")
    actions.add_parser("rebuild", parents=[binding], help="recompute the lane projection from events alone")
    actions.add_parser("verify", parents=[binding], help="recompute every hash and check the store")

    briefs = commands.add_parser("brief", help="render briefs")
    actions = briefs.add_subparsers(dest="action", metavar="ACTION", required=True)
    render = actions.add_parser("render", parents=[binding], help="append the protocol block to a brief")
    render.add_argument("--lane", required=True)
    render.add_argument("--in", dest="source", required=True, metavar="BRIEF")
    render.add_argument("--out", required=True, metavar="RENDERED")
    render.add_argument("--project")
    render.add_argument("--touches", action="append", choices=brief.TOUCHES, default=[])

    lane = commands.add_parser("lane", help="start, resume, stop, watch, mark and clean lanes")
    actions = lane.add_subparsers(dest="action", metavar="ACTION", required=True)
    start = actions.add_parser("start", parents=[binding], help="start a lane's first run in the background")
    start.add_argument("--lane", required=True)
    start.add_argument("--brief", required=True, metavar="FILE", help="the brief, always a file")
    start.add_argument("--project")
    start.add_argument("--difficulty", choices=config.DIFFICULTIES, help="pick the runner and model from [routing]")
    start.add_argument("--runner")
    start.add_argument("--model")
    start.add_argument("--effort")
    start.add_argument("--account")
    start.add_argument("--budget", metavar="MINUTES", help="the time budget; default [lanes] budget_minutes")
    start.add_argument("--touches", action="append", choices=brief.TOUCHES, default=[])
    place = start.add_mutually_exclusive_group()
    place.add_argument("--worktree", metavar="PATH", help="an existing directory to work in")
    place.add_argument("--base", metavar="REF", help="the commit the lane's new branch starts from")
    start.add_argument("--reuse", action="store_true", help="start a merged or abandoned lane's name again")
    start.add_argument("--turns", action="store_true",
                       help="make the lane turn-based: it takes mail (lane send) and one turn at a time (lane turn)")
    start.add_argument("--idle", metavar="SECONDS",
                       help="with --turns: the lane's idle interval (default [turns] idle_seconds)")
    adopt = actions.add_parser("adopt", parents=[binding],
                               help="take a session something outside the launcher started and make it a turn-based lane")
    adopt.add_argument("--lane", required=True)
    adopt.add_argument("--session", required=True, metavar="ID",
                       help="the runner's session identifier (a lower-case UUID)")
    adopt.add_argument("--runner", required=True)
    adopt.add_argument("--model", required=True)
    adopt.add_argument("--effort")
    adopt.add_argument("--account")
    adopt.add_argument("--worktree", required=True, metavar="PATH", help="the existing directory the session works in")
    adopt.add_argument("--brief", required=True, metavar="FILE", help="the lane's standing brief, always a file")
    adopt.add_argument("--project")
    adopt.add_argument("--idle", metavar="SECONDS", help="the idle interval (default [turns] idle_seconds)")
    adopt.add_argument("--budget", metavar="MINUTES", help="the time budget; default [lanes] budget_minutes")
    resume = actions.add_parser("resume", parents=[binding], help="continue a lane in the same directory")
    resume.add_argument("--lane", required=True)
    resume.add_argument("--message", metavar="FILE", help="a follow-up message, always a file")
    resume.add_argument("--account")
    resume.add_argument("--budget", metavar="MINUTES")
    turn = actions.add_parser("turn", parents=[binding], help="start the next turn of a turn-based lane")
    turn.add_argument("--lane", required=True)
    turn.add_argument("--idle", action="store_true", help="with no mail waiting, send the configuration's idle message")
    turn.add_argument("--account")
    turn.add_argument("--budget", metavar="MINUTES")
    send = actions.add_parser("send", parents=[binding], help="store a message for a turn-based lane")
    send.add_argument("--lane", required=True)
    send.add_argument("--file", metavar="PATH", help="the message, always a file")
    send.add_argument("source", nargs="?", metavar="-", help="- reads the message from standard input")
    send.add_argument("--from", dest="sender", metavar="NAME", help="who sends it (default supervisor)")
    watch = actions.add_parser("attach", parents=[binding],
                               help="show a turn-based lane's turns as they run and type messages to it")
    watch.add_argument("--lane", required=True)
    stop = actions.add_parser("stop", parents=[binding], help="stop a lane's run and its whole process tree")
    stop.add_argument("--lane", required=True)
    stop.add_argument("--run", type=positive, metavar="N", help="stop only when run N is the lane's latest run")
    actions.add_parser("status", parents=[binding], help="the projection and what can be seen now").add_argument(
        "--lane")
    check = actions.add_parser("check", parents=[binding], help="record runs whose session vanished as lost")
    check.add_argument("--lane", help="check only this lane")
    loop = actions.add_parser("loop", parents=[binding], help="decide when the turns of the turn-based lanes start")
    form = loop.add_mutually_exclusive_group()
    form.add_argument("--detach", action="store_true", help="run the loop in a tmux session of its own")
    form.add_argument("--status", action="store_true", help="the loop and its lanes; appends nothing")
    form.add_argument("--stop", action="store_true", help="ask the loop to end; no turn is stopped")
    mark = actions.add_parser("mark", parents=[binding], help="record a supervisor's decision about a lane")
    mark.add_argument("--lane", required=True)
    mark.add_argument("--state", choices=("verifying", "accepted", "merged", "abandoned"))
    mark.add_argument("--landing", choices=("merged", "deployed", "landed"))
    mark.add_argument("--gone", action="store_true",
                      help="declare the lane's open launch gone (no end event and no readable run record)")
    mark.add_argument("--accept-uncovered", action="store_true",
                      help="with --state accepted or merged: record the decision although some session records were "
                           "not scanned, and what they were")
    actions.add_parser("clean", parents=[binding], help="remove a merged or abandoned lane's worktree").add_argument(
        "--lane", required=True)
    actions.add_parser("scan", parents=[binding], help="scan a lane's session records again for refusals").add_argument(
        "--lane", required=True)
    actions.add_parser("refusals", parents=[binding], help="refusals, suspected workarounds and what was scanned"
                       ).add_argument("--lane")
    review = actions.add_parser("review", parents=[binding], help="record a verdict on one path of a suspected workaround")
    review.add_argument("--lane", required=True)
    review.add_argument("--refusal", required=True, metavar="ID")
    review.add_argument("--path", required=True, metavar="PATH", help="absolute, or relative to the lane's worktree")
    review.add_argument("--verdict", required=True, choices=("clean", "workaround"))
    review.add_argument("--note", metavar="FILE", help="a note, always a file")

    judgecmd.register(commands, binding)

    commands.add_parser("disk", parents=[binding],
                        help="read the file system the configuration watches (the disk line)")
    commands.add_parser("doctor", parents=[binding], help="check the configuration and its environment")
    startcmd.register(commands, binding)
    return root


def bind(arguments):
    """The bound configuration and its zones; refused when its state overlaps another configuration's."""
    configuration = config.load(config.bound_name(arguments.config))
    zones = config.Zones(configuration)
    problems = zones.problems()
    if problems:
        raise Refused(problems[0])
    return configuration, zones


def emit(value):
    sys.stdout.write(output(value) + "\n")
    sys.stdout.flush()
    return 0


def run_config(arguments):
    if arguments.action == "list":
        return emit(config.list_names())
    if arguments.action == "validate" and arguments.all:
        if os.environ.get(env_name("CONFIG")):
            raise Refused("--all reads every configuration, but {} binds this session to one; unset it first".format(
                env_name("CONFIG")))
        return emit({"valid": True, "configs": config.validate_all()})
    config.guard_named(arguments.name)
    configuration = config.load(arguments.name)
    if arguments.action == "show":
        return emit(configuration.describe())
    if arguments.action == "validate":
        return emit({"valid": True, "configs": [configuration.name]})
    return emit(configuration.paths())


def read_event(zones, argument):
    if argument == "-":
        data = sys.stdin.buffer.read(MAX_EVENT_BYTES + 1)
        if len(data) > MAX_EVENT_BYTES:
            raise Refused("the event is larger than 2 MiB")
    else:
        data = config.read_external(zones, argument, "--file", MAX_EVENT_BYTES)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("the event must be UTF-8 JSON") from None
    return parse(text, "the event")


def open_reader(configuration, zones):
    """(state directory, store) for reading; either may be None when nothing was created yet."""
    state = StateDir.open(configuration, zones, create=False)
    if state is None:
        return None, None
    try:
        with state.lock(shared=True):
            return state, events.open_for_read(state)
    except BaseException:
        state.close()
        raise


def follow_events(configuration, zones, since, follow, lane=None, until=None):
    last = since
    state = store = None
    try:
        while True:
            if store is None:
                if state is not None:
                    state.close()
                state, store = open_reader(configuration, zones)
            if store is not None:
                for item in store.events(last):
                    last = item["seq"]
                    if lane is not None and item["lane"] != lane:
                        continue
                    sys.stdout.write(output(item) + "\n")
                    if item["kind"] == until:
                        sys.stdout.flush()
                        return 0
                sys.stdout.flush()
            if not follow:
                return 0
            time.sleep(FOLLOW_INTERVAL)
    except KeyboardInterrupt:
        return 0
    finally:
        if store is not None:
            store.close()
        if state is not None:
            state.close()


def run_event(arguments):
    configuration, zones = bind(arguments)
    if arguments.action == "tail":
        if arguments.lane is not None:
            events.check_grammar(arguments.lane, events.LANE, "--lane")
        if arguments.until is not None:
            events.check_grammar(arguments.until, events.KIND, "--until")
        return follow_events(configuration, zones, arguments.since, arguments.follow, arguments.lane, arguments.until)
    envelope = read_event(zones, arguments.file)
    event = events.validate_envelope(envelope)
    state = StateDir.open(configuration, zones, create=False)
    if event["kind"] == "brief.rendered":
        # A reserved kind is checked against its kept copies before anything is created. EventStore.append
        # checks it once more, outside the directory lock: that lock ends when the store is open, before
        # append's own write transaction (BEGIN IMMEDIATE) begins.
        try:
            events.check_rendered(event, state, Refused)
        except BaseException:
            if state is not None:
                state.close()
            raise
    if state is None:
        state = StateDir.open(configuration, zones, create=True)
    try:
        with state.lock():
            store = events.open_for_write(state)
        try:
            return emit(store.append(envelope))
        finally:
            store.close()
    finally:
        state.close()


def run_state(arguments):
    configuration, zones = bind(arguments)
    state, store = open_reader(configuration, zones)
    try:
        if store is None:
            if arguments.action == "verify":
                mail_files, mail_orphans = mail.verify(state, []) if state is not None else (0, 0)
                return emit({"ok": True, "exists": False, "config": configuration.name, "events": 0, "lanes": 0,
                             "kept_inputs": events.verify_inputs(state, []) if state is not None else 0,
                             "mail_files": mail_files, "mail_orphans": mail_orphans,
                             "store": str(configuration.store)})
            return emit([])
        if arguments.action == "events":
            return emit(store.events())
        if arguments.action == "lanes":
            return emit(store.lanes())
        if arguments.action == "rebuild":
            return emit(store.rebuild())
        return emit(store.verify(state))
    finally:
        if store is not None:
            store.close()
        if state is not None:
            state.close()


def run_brief(arguments):
    configuration, zones = bind(arguments)
    return emit(brief.render(configuration, zones, arguments.lane, arguments.source, arguments.out,
                             arguments.project, arguments.touches))


def run_disk(arguments):
    """`laneboss disk`: the reading of the file system the bound configuration watches, as one JSON object, with the
    file system's latch applied to it exactly as a start applies it - this command sets and clears that latch too, so
    polling it is never a way around the line. Exit 0 for ok and warn, 3 for stop. A file system that cannot be read
    is refused (exit 2) instead of being reported as empty."""
    configuration, zones = bind(arguments)
    state = StateDir.open(configuration, zones, create=True)
    try:
        report = disk.examine(configuration)
    finally:
        state.close()
    sys.stdout.write(output(report) + "\n")
    sys.stdout.flush()
    return 3 if report["state"] == disk.STOP else 0


def run_doctor(arguments):
    return doctor.run(config.bound_name(arguments.config))


def run_lane(arguments):
    configuration, zones = bind(arguments)
    if arguments.action == "loop":
        # The loop prints for as long as it runs and returns its own exit status: it is not one of the lane commands.
        return loopcmd.run(configuration, zones, arguments)
    if arguments.action == "attach":
        return attach.run(configuration, zones, arguments)  # text for a person, and its own exit code
    return emit(lanecmd.run(configuration, zones, arguments))


def run_judge(arguments):
    configuration, zones = bind(arguments)
    return judgecmd.run(configuration, zones, arguments)


def run_start(arguments):
    return startcmd.run(arguments, bind)


def run_org(arguments):
    """One `org` command: each module owns its actions (A init/instance/render/validate, B1 hook/refusals/check-hooks,
    B2 hook-history/capture-decision, B3 channel)."""
    if arguments.action == "hook-history":
        from .decisions.history import hook_history
        return hook_history(arguments)
    if arguments.action == "capture-decision":
        from .decisions.capture import capture_decision
        from .decisions.cli import failure
        try:
            return emit(capture_decision(arguments))
        except Exception as error:
            known = failure(error, argparse.Namespace(command="capture-decision"), None)
            if known is None:
                raise
            print(known[0], file=sys.stderr)
            return known[1]
    if arguments.action in orgcmd.ACTIONS:
        return orgcmd.run(arguments)
    if arguments.action == "channel":
        return emit(orgdiscord.add_channel(arguments))
    return orghook.run(arguments)


# Command groups with a Go port (cmd/laneboss-<group>); LANEBOSS_<GROUP>_GO_BIN selects it.
GO_GROUPS = ("org", "config", "event", "state", "brief", "doctor", "disk", "lane", "judge", "start", "plugin",
             "decisions")

HANDLERS = {"config": run_config, "event": run_event, "state": run_state, "brief": run_brief, "doctor": run_doctor,
            "disk": run_disk, "lane": run_lane, "judge": run_judge, "start": run_start, "org": run_org}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] and argv[0] in GO_GROUPS and os.environ.get(env_name(argv[0].upper() + "_GO_BIN")):
        # The Go port of one command group: forward the arguments unchanged. There is no fallback to Python
        # here, so a test run that names a group's Go binary tests only that binary.
        variable = env_name(argv[0].upper() + "_GO_BIN")
        binary = os.environ[variable]
        if not os.path.isabs(binary) or not os.access(binary, os.X_OK):
            print(PROGRAM + ": " + variable + " must name an executable file by absolute path", file=sys.stderr)
            return 2
        if argv[0] == "plugin":
            # Preserve the assets of this launcher across exec, also when the Go binary is elsewhere. Installed
            # modules are VERSION/lib/laneboss; checkout modules are REPO/src/laneboss. Both roots are two levels
            # above the module directory. A forwarded call always uses its launcher's own assets.
            module_directory = os.path.dirname(os.path.realpath(__file__))
            os.environ[env_name("PLUGIN_ROOT")] = os.path.dirname(os.path.dirname(module_directory))
        os.execv(binary, [binary, *argv[1:]])
    if argv[:1] == ["decisions"]:
        from .decisions.cli import main as decisions_main
        return decisions_main(argv[1:])
    if argv[:1] == ["plugin"]:
        from .plugincmd import main as plugin_main
        return plugin_main(argv[1:])
    parser = build_parser()
    if argv[:2] == ["org", "hook-history"]:
        # Optional history must not block a prompt on malformed runner configuration. Keep the shared parser and
        # its --help output, but turn this command's usage errors into a quiet successful exit.
        try:
            with redirect_stderr(io.StringIO()):
                arguments = parser.parse_args(argv)
        except SystemExit as error:
            if error.code != 0:
                return 0
            raise
    else:
        arguments = parser.parse_args(argv)
    try:
        if arguments.version:
            return emit({"program": PROGRAM, "version": VERSION, "protocol_version": load_protocol()[1]})
        if arguments.command is None:
            parser.print_usage(sys.stderr)
            print(PROGRAM + ": error: a command is required", file=sys.stderr)
            return 2
        return HANDLERS[arguments.command](arguments)
    except LauncherError as error:
        for line in str(error).splitlines() or [""]:
            print("{}: {}".format(error.prefix, line), file=sys.stderr)
        return error.exit_code
    except sqlite3.Error as error:
        print("integrity problem: SQLite operation failed: " + str(error), file=sys.stderr)
        return 3
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        if os.environ.get(env_name("DEBUG")):
            raise
        print("internal error: " + type(error).__name__, file=sys.stderr)
        return 70
