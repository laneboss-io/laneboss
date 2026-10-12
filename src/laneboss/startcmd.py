"""`laneboss start`: the briefing a supervisor reads when its session begins.

Read-only in the sense of ruling R31: it appends no event, creates no state and changes no recorded fact, also for a
configuration that was never used. It does what every reader of the store does and no more: on a file system where a
directory cannot be locked, the reader's lock file `.lock` is created in a state directory that exists, and SQLite
itself rolls back a write that was cut short when the store is opened.
Without a configuration it lists the ones that exist. With one (`--config` or the environment) it is bound like
every state command and prints, in this order: the configuration, the shared protocol, the standing rules (each file's
hash and text), the role, the checks of `laneboss doctor` that only read, the lanes by what the supervisor has to do
next, and the last events.
`text` is Markdown with exactly those headings; `json` is one value with the same facts under the keys of
BRIEFING_KEYS. A free-text value taken from a configuration is shown only when the credential detector accepts it, and
so are a configuration's name and a role given on the command line. The configuration section also names the
organisation the configuration belongs to (or says none) and where its tools directory is, present or missing.
A role is the name of a `[supervisors]` entry, chosen with `--role`; the role section says the entry's level, 4, 5 or 6,
with the name the configuration module gives it (`- Level: L5 (top supervisor)`; `level` and `level_name` in json).

The store check (`store.recorded`) is always made, on the bound configuration's own store: a store that fails it is not
reported from, the command exits 3 and prints no briefing. So it is when the isolation check (`state.isolated`) fails
for a reason of the bound configuration's own state directory. When it fails only because other configurations cannot
be read, the briefing is printed (ruling R37) with a warning as the first line under `## Configuration` that names
them, and in `configuration.warnings`. The lanes and the recent events come from one read of the store: the events are
read once and the lanes are their projection, so the two always agree. A turn-based lane between two turns (state
`waiting`, no run going on) is in a group of its own, `idle` in json, with the number of messages that wait for a turn;
the text form prints that group only when a lane is idle. The checks include the doctor's warning for a runner that can
take turns and has no `limit_patterns`, when there is one.
"""

import copy
import os
import shutil
import sys
import tomllib

from . import config, credentials, doctor, lanecmd, mail, pending
from .errors import IntegrityProblem, LauncherError, Refused
from .identity import PROGRAM, env_name
from .jsonutil import output, sha256_hex
from .lanes import LANDING, TIMES, fold
from .protocol import load_protocol

FORMATS = ("text", "json")
RECENT = 20
WITHHELD = "[withheld]"
NO_STORE = "no store exists yet"
UNKNOWN = "Open questions to the owner and due dates are not in the store yet."
TITLE = "Laneboss session briefing"
SECTIONS = ("Configuration", "Protocol", "Standing rules", "Role", "Checks", "Lanes", "Recent events",
            "Not known to the launcher")
BRIEFING_KEYS = ("configuration", "protocol", "rules", "role", "checks", "lanes", "events", "unknown")
GROUPS = (("running", "Running"), ("ended", "Ended, waiting for the supervisor"),
          ("accepted", "Accepted or merged, not yet cleaned"), ("lost", "Lost or declared gone"))
# The group of turn-based lanes between two turns (state `waiting`, no run going on); in the text form it is there only
# when a lane is idle.
IDLE_LABEL = "Idle, waiting for a turn"
GONE = "declared gone, no end recorded"
WRITING = ("state.writable", "store.round_trip")
MAX_DESCRIPTION = 1000


def register(commands, binding):
    start = commands.add_parser("start", parents=[binding],
                                help="print the briefing a supervisor session reads when it begins")
    start.add_argument("--role", metavar="ROLE", help="a [supervisors] entry of the configuration")
    start.add_argument("--format", choices=FORMATS, default="text", help="text (Markdown, the default) or json")


def shown(text):
    """A free-text value of a configuration, on one line; [withheld] when the credential detector refuses it. Every
    character that does not print (a line break, an escape) becomes a space."""
    if text is None:
        return None
    if credentials.find_in_text(text):
        return WITHHELD
    return "".join(character if character.isprintable() else " " for character in text[:MAX_DESCRIPTION])


def scrub(text):
    """Text for output with every part that looks like a credential replaced by [withheld]: a name or a path that a
    check quotes, for example. It fails closed: when the detector still finds something after a replacement (the
    replacement changed nothing, or eight rounds were not enough), the whole text is withheld."""
    for _ in range(8):
        found = credentials.find_in_text(text)
        if not found:
            return text
        replaced = text.replace(found[2], WITHHELD) if found[2] else text
        if replaced == text:
            break
        text = replaced
    return WITHHELD


def word(item):
    return "none" if item is None else str(item)


def choose_line(role=None):
    """How to choose a configuration, keeping the role the caller already gave (unless it looks like a credential)."""
    extra = "" if role is None else " --role " + shown(role)
    return "Choose one: run {0} start --config NAME{2}, or export {1}=NAME and run {0} start{2} again.".format(
        PROGRAM, env_name("CONFIG"), extra)


def binding_line(name):
    return ("Keep this session bound to configuration {0}: pass --config {0} on every command, "
            "or export {1}={0}.").format(name, env_name("CONFIG"))


# Without a configuration: the ones that exist.

def found_configurations(home):
    """Name, description and problem of every configuration directory, read the way another configuration's state
    location is read (inside its own directory) and not validated: an unreadable one is listed, never hidden."""
    configs = home / "configs"
    try:
        os.listdir(str(configs))
    except FileNotFoundError:
        pass
    except OSError:
        raise Refused("cannot list " + str(configs)) from None
    found = []
    for name, directory in config.other_config_dirs(home, None):
        description = problem = None
        try:
            data = config.ConfigReader(name, directory).read("config.toml", "config.toml")
        except (LauncherError, OSError):
            problem = "its config.toml cannot be read inside its own directory"
        else:
            try:
                document = tomllib.loads(data.decode("utf-8"))
            except (UnicodeDecodeError, tomllib.TOMLDecodeError):
                problem = "its config.toml cannot be read as TOML"
            else:
                if document.get("name") != name:
                    problem = "its name does not match its directory"
                elif isinstance(document.get("description"), str):
                    description = shown(document["description"])
        withheld = credentials.find_in_text(name) is not None
        found.append({"name": WITHHELD if withheld else name, "name_withheld": withheld, "readable": problem is None,
                      "description": description, "problem": problem})
    return found


def listing(role=None):
    home = config.config_home()
    return {"directory": scrub(str(home / "configs")), "configurations": found_configurations(home),
            "choose": choose_line(role)}


def listing_text(document):
    lines = ["# {}: no configuration chosen".format(PROGRAM.capitalize()), ""]
    if document["configurations"]:
        lines.append("Configurations under {}:".format(document["directory"]))
        lines.append("")
        for item in document["configurations"]:
            detail = ("unreadable ({})".format(item["problem"]) if not item["readable"] else
                      item["description"] or "no description")
            if item["name_withheld"]:
                detail = "its name looks like a credential, so it is not shown; " + detail
            lines.append("- {}: {}".format(item["name"], detail))
    else:
        lines.append("No configuration exists under {}.".format(document["directory"]))
    return lines + ["", document["choose"]]


# With a configuration: the sections.

def role_section(configuration, selected):
    supervisors = configuration.data.get("supervisors", {})
    defined = sorted(supervisors)
    if selected is None:
        return {"selected": None, "defined": defined, "entry": None}
    config.check_name(selected, "role")
    entry = supervisors.get(selected)
    if entry is None:
        raise Refused("role {} is not defined; {}".format(
            shown(selected), "the defined roles are: " + ", ".join(defined) if defined else
            "this configuration defines no role"))
    level = entry["level"]
    return {"selected": selected, "defined": defined,
            "entry": {"level": level, "level_name": config.LEVEL_NAMES[level], "runner": entry["runner"],
                      "projects": list(entry.get("projects", [])), "owner_channel": entry.get("owner_channel"),
                      "description": shown(entry.get("description"))}}


def protocol_section():
    data, version = load_protocol()
    return {"version": version, "sha256": sha256_hex(data), "text": data.decode("utf-8")}


def organisation_section(configuration):
    """The organisation the configuration names, or None: its name, its tools directory and whether that is a
    directory now. Reading it changes nothing on disk."""
    if configuration.organisation is None:
        return None
    tools = configuration.organisation_tools
    return {"name": configuration.organisation, "tools": scrub(str(tools)), "tools_present": os.path.isdir(str(tools))}


def organisation_lines(organisation):
    if organisation is None:
        return ["- Organisation: none"]
    return ["- Organisation: " + organisation["name"], "- Organisation tools: {} ({})".format(
        organisation["tools"], "present" if organisation["tools_present"] else "missing")]


def rules_text(data):
    """A rules file's content as UTF-8, unchanged; [withheld] when the credential detector refuses it (the loader
    refuses such a file before a briefing is built, so this is a second line of defence)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return WITHHELD
    return WITHHELD if credentials.find_in_text(text) else text


def rules_section(configuration, role):
    """The rules files a brief rendered for the role's projects uses, in the order of such a brief: the organisation's
    (each under the label orgs/NAME/<path>), then the configuration's, then each project's, each with the hash of its
    bytes and its text."""
    listed = list(configuration.rules())
    for project in role["entry"]["projects"] if role["entry"] else []:
        known = {relative for relative, _ in listed}
        listed += [(relative, data) for relative, data in configuration.rules(project) if relative not in known]
    return [{"path": relative, "sha256": sha256_hex(data), "text": rules_text(data)} for relative, data in listed]


def unreadable_warning(zones, configuration):
    """The warning of a briefing for a state directory that is isolated except that other configurations cannot be
    read: it names each of them, says that isolation from them cannot be shown, and names `laneboss doctor`."""
    names = [config.shown_name(name) for name, _ in zones.unreadable]
    return "Warning: configuration{} {} cannot be read, so isolation from {} cannot be shown; run {} doctor " \
           "--config {}.".format("s" if len(names) > 1 else "", ", ".join(names),
                                 "them" if len(names) > 1 else "it", PROGRAM, config.shown_name(configuration.name))


def checks_section(configuration, zones):
    """The checks of `laneboss doctor` that only read, with doctor's own functions and wording; the detail of the
    isolation check when the bound configuration's own state directory fails it; the detail of the store check when it
    failed (it is always made); and the warnings. An isolation check that fails only because other configurations
    cannot be read is a warning (ruling R37): the check is made again as if there were none, and when that passes the
    state directory has no problem of its own."""
    results = [("config", True, "configuration {} is valid".format(configuration.name))]
    isolated, detail = doctor.guarded(doctor.check_isolated, configuration, zones)
    results.append(("state.isolated", isolated, detail))
    recorded = tuple(doctor.guarded(doctor.check_recorded, configuration, zones))
    results.append(("store.recorded",) + recorded)
    store_problem = None if recorded[0] else recorded[1]
    isolation_problem, warnings = None, []
    if not isolated:
        without_unreadable = copy.copy(zones)
        without_unreadable.unreadable = []
        if zones.unreadable and doctor.guarded(doctor.check_isolated, configuration, without_unreadable)[0]:
            warnings.append(unreadable_warning(zones, configuration))
        else:
            isolation_problem = detail
    for tool in ("git", "tmux"):
        found = shutil.which(tool)
        results.append(("tool." + tool, found is not None, "found at " + found if found else tool + " is not on PATH"))
    for runner_name, runner in sorted(configuration.data["runners"].items()):
        programs = [runner["command"][0]] + ([runner["resume"][0]] if "resume" in runner else [])
        found = {program: doctor.find_command(program) for program in programs}
        missing = [program for program in programs if found[program] is None]
        results.append(("runner." + runner_name, not missing,
                        "; ".join("{} is not found on PATH".format(program) for program in missing) if missing else
                        "; ".join("{} found at {}".format(program, found[program])
                                  for program in sorted(set(programs)))))
    warning = doctor.turn_limit_warning(configuration)
    if warning is not None:
        results.append(("turns.limit_patterns", True, warning))
    checks = {"read": [{"check": check, "ok": bool(ok), "detail": scrub(detail)} for check, ok, detail in results],
              "not_run": {"checks": list(WRITING),
                          "note": "{} write to the state directory, so this command does not run them; {} doctor "
                                  "runs them.".format(" and ".join(WRITING), PROGRAM)}}
    return checks, isolation_problem, store_problem, warnings


def group_of(row, gone):
    """The one group a lane is in, or None (it is then counted in `others`): running; accepted or merged and not
    cleaned; ended and waiting for the supervisor, or lost or declared gone (state verifying); or idle, a turn-based
    lane between two turns (state waiting, whatever ended its last turn)."""
    if row["running"]:
        return "running"
    if row["cleaned"]:
        return None
    if row["state"] in ("accepted", "merged"):
        return "accepted"
    if row["state"] == "verifying":
        return "lost" if row["reason"] == "lost" or gone else "ended"
    if row["state"] == "waiting":
        return "idle"
    return None


def lane_item(row, last):
    """One lane as the projection of the events read has it. The end or loss shown, and its survivors, are those of the
    lane's latest run, looked up by lane, kind and run. A lane is declared gone when its latest run has a `lane.gone`
    and no `lane.ended`; a recorded loss of that run does not matter, and a run after a resume is not gone."""
    kind = "lane.lost" if row["reason"] == "lost" else "lane.ended" if row["reason"] is not None else None
    event = last.get((row["lane"], kind, row["run"]))
    survivors = event["payload"].get("survivors") if event is not None else None
    gone = (not row["running"] and (row["lane"], "lane.gone", row["run"]) in last
            and (row["lane"], "lane.ended", row["run"]) not in last)
    return {"lane": row["lane"], "run": row["run"], "runner": row["runner"], "model": row["model"],
            "account": row["account"], "state": row["state"], "state_at": row["state_at"], "reason": row["reason"],
            "exit_code": row["exit_code"], "survivors": survivors, "gone": gone, "times": row["times"],
            "landing": row["landing"]}


def store_sections(session):
    """The lanes and the recent events, from the store opened for reading (None when no store exists yet). The events
    are read once, and the lanes are the projection of that list (`lanes.fold`), so the two always agree."""
    section = {"store": session.store is not None, "note": None if session.store is not None else NO_STORE}
    lane_section = dict(section, running=[], ended=[], accepted=[], lost=[], idle=[], others=0, pending_events=0,
                        refused_events=0, pending_lanes=[])
    if session.store is None:
        return lane_section, dict(section, total=0, recent=[])
    stored = session.store.events()
    last = {(event["lane"], event["kind"], event["payload"].get("run")): event for event in stored
            if event["kind"] in ("lane.ended", "lane.lost", "lane.gone")}
    for row in fold(stored):
        item = lane_item(row, last)
        group = group_of(row, item["gone"])
        if group is None:
            lane_section["others"] += 1
        else:
            if group == "idle":
                # How many messages wait for the next turn: the waiting ones and the returned ones.
                item["waiting"] = mail.queued(row["mail"])
            lane_section[group].append(item)
        waiting, refused = pending.count(session.state, row["lane"]), pending.refused(session.state, row["lane"])
        lane_section["pending_events"] += waiting
        lane_section["refused_events"] += refused
        if waiting or refused:
            lane_section["pending_lanes"].append({"lane": row["lane"], "waiting": waiting, "refused": refused})
    recent = [{"seq": event["seq"], "time": event["occurred_at"] or event["recorded_at"], "lane": event["lane"],
               "kind": event["kind"]} for event in stored[-RECENT:]]
    return lane_section, dict(section, total=len(stored), recent=recent)


def briefing(configuration, zones, selected):
    role = role_section(configuration, selected)
    checks, isolation_problem, store_problem, warnings = checks_section(configuration, zones)
    if isolation_problem is not None:
        raise IntegrityProblem("the state.isolated check failed ({}), so no briefing is printed from this state "
                               "directory; run {} doctor --config {}".format(
                                   " ".join(scrub(isolation_problem).split()), PROGRAM, configuration.name))
    if store_problem is not None:
        raise IntegrityProblem("the store.recorded check failed ({}), so no briefing is printed from this store; run "
                               "{} state verify --config {}".format(" ".join(scrub(store_problem).split()), PROGRAM,
                                                                   configuration.name))
    session = lanecmd.Session(configuration, zones)
    try:
        lane_section, event_section = store_sections(session)
    finally:
        session.close()
    return {"configuration": {"name": configuration.name, "description": shown(configuration.data.get("description")),
                              "organisation": organisation_section(configuration),
                              "binding": binding_line(configuration.name), "warnings": warnings},
            "protocol": protocol_section(), "rules": rules_section(configuration, role), "role": role,
            "checks": checks, "lanes": lane_section, "events": event_section, "unknown": UNKNOWN}


# Text.

def lane_line(item, always_landing=False):
    """One lane on one line. A lane declared gone has no end to describe; the lines of the group of lanes that wait
    to be merged or cleaned always say what the landing facts are."""
    times = ", ".join("{} {}".format(name, item["times"][name]) for name in TIMES if item["times"].get(name))
    landing = ", ".join("{} {}".format(name, item["landing"][name]) for name in LANDING if item["landing"].get(name))
    end = GONE if item["gone"] else "reason {}, exit code {}, survivors {}".format(
        word(item["reason"]), word(item["exit_code"]), word(item["survivors"]))
    return "- {}: run {}, runner {}, model {}, account {}; last end: {}; state {} since {}; times: {}{}".format(
        item["lane"], item["run"], word(item["runner"]), word(item["model"]), word(item["account"]), end,
        word(item["state"]), word(item["state_at"]), times or "none",
        "; landing: " + (landing or "none") if landing or always_landing else "")


def indented(text):
    """The lines of a text indented by four spaces, so that none of them starts a heading of the briefing; blank lines
    stay blank. The text is split at every line end (`\\n`, `\\r\\n`, a lone `\\r`, and the others `str.splitlines`
    knows), and the lines are joined with `\\n` alone, so no line end of the file can start a line of the briefing."""
    return [("    " + line) if line.strip() else "" for line in text.splitlines()]


def briefing_text(document):
    lines = ["# " + TITLE, ""]
    configuration, protocol, role = document["configuration"], document["protocol"], document["role"]
    # A warning is the first line under the heading, so that nobody can miss it.
    lines += ["## " + SECTIONS[0]] + configuration["warnings"] + [""]
    lines += ["- Name: " + configuration["name"], "- Description: " + word(configuration["description"])]
    lines += organisation_lines(configuration["organisation"]) + ["- Binding: " + configuration["binding"], ""]
    lines += ["## " + SECTIONS[1], "", "- Version: " + protocol["version"], "- SHA-256: " + protocol["sha256"], "",
              "The protocol text follows, indented by four spaces so that its own headings stay out of this "
              "briefing.", ""]
    lines += indented(protocol["text"])
    lines += ["", "## " + SECTIONS[2], ""]
    if document["rules"]:
        lines += ["The text of each file follows its line, indented by four spaces so that its own headings stay out "
                  "of this briefing.", ""]
        for number, rule in enumerate(document["rules"]):
            lines += [""] if number else []
            lines += ["- {}: sha256 {}".format(rule["path"], rule["sha256"])] + indented(rule["text"])
    else:
        lines.append("No standing rules file is listed.")
    lines += ["", "## " + SECTIONS[3], ""]
    if role["entry"] is None:
        lines.append("No role was chosen. {} Pass --role ROLE to see one.".format(
            "Defined roles: " + ", ".join(role["defined"]) + "." if role["defined"] else
            "No role is defined in this configuration."))
    else:
        entry = role["entry"]
        lines += ["- Role: " + role["selected"], "- Level: L{} ({})".format(entry["level"], entry["level_name"]),
                  "- Runner: " + entry["runner"], "- Projects: " + (", ".join(entry["projects"]) or "none"),
                  "- Owner channel: " + word(entry["owner_channel"]), "- Description: " + word(entry["description"])]
    lines += ["", "## " + SECTIONS[4], ""]
    lines += ["- {} [{}] {}".format(item["check"], "ok" if item["ok"] else "FAILED", " ".join(item["detail"].split()))
              for item in document["checks"]["read"]]
    lines += ["", "Not run: " + document["checks"]["not_run"]["note"], "", "## " + SECTIONS[5], ""]
    section = document["lanes"]
    if not section["store"]:
        lines.append("There are no lanes: {}.".format(section["note"]))
    else:
        for key, label in GROUPS:
            lines.append("{} ({}):".format(label, len(section[key])))
            lines += [lane_line(item, key == "accepted") for item in section[key]]
        if section["idle"]:
            lines.append("{} ({}):".format(IDLE_LABEL, len(section["idle"])))
            lines += ["{}; messages waiting: {}".format(lane_line(item), item["waiting"]) for item in section["idle"]]
        lines += ["", "Events waiting to be recorded: {}".format(section["pending_events"]),
                  "Events the store refused for good: {}".format(section["refused_events"]),
                  "Lanes in none of these groups (queued, merged or abandoned): {}".format(section["others"])]
        if section["pending_lanes"]:
            lines += ["", "Lanes are shown as the store records them; these lanes have events waiting to be recorded "
                      "or refused by the store: {}.".format(", ".join(
                          "{} (waiting {}, refused {})".format(item["lane"], item["waiting"], item["refused"])
                          for item in section["pending_lanes"]))]
    lines += ["", "## " + SECTIONS[6], ""]
    section = document["events"]
    if not section["store"]:
        lines.append("There are no events: {}.".format(section["note"]))
    elif not section["total"]:
        lines.append("There are no events yet.")
    else:
        lines.append("Showing the last {} of {} events, oldest first.".format(len(section["recent"]), section["total"]))
        lines += ["- seq {}, {}, lane {}, {}".format(item["seq"], item["time"], word(item["lane"]), item["kind"])
                  for item in section["recent"]]
    return lines + ["", "## " + SECTIONS[7], "", document["unknown"]]


def emit(document, lines, format_):
    if format_ == "json":
        sys.stdout.write(output(document) + "\n")
    else:
        sys.stdout.flush()
        sys.stdout.buffer.write(("\n".join(lines) + "\n").encode("utf-8", "backslashreplace"))
    sys.stdout.flush()
    return 0


def run(arguments, bind):
    """`bind` is the command line's own binding: the configuration and its zones, refused as for every state command."""
    if arguments.config is None and not os.environ.get(env_name("CONFIG")):
        if arguments.role is not None:
            config.check_name(arguments.role, "role")
        document = listing(arguments.role)
        return emit(document, listing_text(document), arguments.format)
    configuration, zones = bind(arguments)
    document = briefing(configuration, zones, arguments.role)
    return emit(document, briefing_text(document) if arguments.format == "text" else None, arguments.format)
