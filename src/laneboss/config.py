"""Configurations: one directory per company, strictly validated, and the isolation between them.

A configuration is $LANEBOSS_HOME/configs/<name>/ holding config.toml, optional projects/<project>.toml
and optional rules files. Its state lives in $LANEBOSS_STATE_HOME/<name>/ unless the file names another
absolute directory. It may name the organisation it belongs to; the organisation's directory is
$LANEBOSS_HOME/orgs/<name>/, which the launcher only reads. docs/configuration.md describes every field of
schema version 1.
"""

import json
import math
import os
from pathlib import Path
import re
import stat
import string
import tomllib

from . import credentials, fsguard, guards, multiplexer, streams
from .errors import InvalidConfiguration, LauncherError, Refused
from .identity import PROGRAM, env_name

SCHEMA_VERSION = 1
NAME_RULE = "[a-z0-9][a-z0-9-]{0,31}"
NAME = re.compile(NAME_RULE)
SECRET_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
ACCOUNT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
TOKEN = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+\[\]-]{0,127}")
IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}")
HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
SERVICE = re.compile(r"[a-z0-9][a-z0-9.-]{0,63}")
COMMAND_NAME = re.compile(r"[A-Za-z0-9_.+-]+")
CURRENCY = re.compile(r"[A-Z]{3}")
LANE_PREFIX = re.compile(r"[a-z0-9][a-z0-9-]{0,15}")
# The levels of the sessions that exist (docs/architecture.md, "Levels"); a larger number is a higher level. The names
# are written here once: the briefing and the messages take them from this table. Level 3 is a lane, which is not a
# [supervisors] entry; levels 2 and 1 are reserved for what lives inside one session and the launcher does not use
# them.
LANE_LEVEL = 3
LEVEL_NAMES = {LANE_LEVEL: "executor lane", 4: "mini-supervisor", 5: "top supervisor", 6: "super top"}
SUPERVISOR_LEVELS = (4, 5, 6)
LANDING_LEVELS = (5, 6)
# `role` is the old spelling of `level` in a [supervisors] entry, and is still read.
ROLE_LEVELS = {"top": 5, "mini": 4}
DIFFICULTIES = ("mechanical", "standard", "hard", "review")
PLACEHOLDERS = ("account", "brief", "effort", "lane", "log", "machine", "model", "project", "worktree")
# A runner's `command` and `resume` (and a records path) may also name the lane's session identifier; nothing else does.
RUNNER_PLACEHOLDERS = tuple(sorted(PLACEHOLDERS + ("session",)))
PROMPTS = ("argument", "stdin")
MARKER = "." + PROGRAM + "-state"
STORE_FILE = "events.sqlite"
MAX_FILE_BYTES = 1024 * 1024


def join(path, key):
    return key if not path else path + "." + key


class Checker:
    """Raises InvalidConfiguration naming the file and the key path, never the offending value."""

    def __init__(self, label):
        self.label = label

    def fail(self, path, message):
        raise InvalidConfiguration("{}: {}: {}".format(self.label, path or "(top level)", message))


def text(pattern=None, rule=None, max_length=1000):
    def check(checker, value, path):
        if not isinstance(value, str):
            checker.fail(path, "must be a string")
        if not value.strip():
            checker.fail(path, "must not be empty")
        if len(value) > max_length:
            checker.fail(path, "must be at most {} characters".format(max_length))
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            checker.fail(path, "must not contain control characters")
        if pattern is not None and pattern.fullmatch(value) is None:
            checker.fail(path, "must match " + (rule or pattern.pattern))
    return check


def integer(minimum, maximum):
    def check(checker, value, path):
        if type(value) is not int:
            checker.fail(path, "must be an integer")
        if not minimum <= value <= maximum:
            checker.fail(path, "must be from {} to {}".format(minimum, maximum))
    return check


def amount(checker, value, path):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        checker.fail(path, "must be a finite number that is not negative")


MAX_BUDGET_MINUTES = 10080


def budget(checker, value, path):
    """A lane's time budget in minutes: a number above 0 and at most a week; fractions are allowed."""
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= MAX_BUDGET_MINUTES:
        checker.fail(path, "must be a number of minutes above 0 and at most {}".format(MAX_BUDGET_MINUTES))


def choice(*options):
    def check(checker, value, path):
        if not isinstance(value, str) or value not in options:
            checker.fail(path, "must be one of: " + ", ".join(options))
    return check


def array(item, nonempty=False, unique=False):
    def check(checker, value, path):
        if not isinstance(value, list):
            checker.fail(path, "must be an array")
        if nonempty and not value:
            checker.fail(path, "must not be empty")
        for index, element in enumerate(value):
            item(checker, element, "{}[{}]".format(path, index))
        if unique and len({json.dumps(element, sort_keys=True) for element in value}) != len(value):
            checker.fail(path, "must not repeat an item")
    return check


def table(fields, required=(), kind_note=None):
    def check(checker, value, path):
        if not isinstance(value, dict):
            checker.fail(path, "must be a table")
        for key in value:
            if key not in fields:
                checker.fail(join(path, key), kind_note(key) if kind_note and kind_note(key) else "unknown key")
        for key in required:
            if key not in value:
                checker.fail(join(path, key), "is required")
        for key, item in value.items():
            fields[key](checker, item, join(path, key))
    return check


def named_tables(item, minimum=0):
    def check(checker, value, path):
        if not isinstance(value, dict):
            checker.fail(path, "must be a table")
        if len(value) < minimum:
            checker.fail(path, "must define at least {} entry".format(minimum))
        for key, element in value.items():
            if NAME.fullmatch(key) is None:
                checker.fail(path, "has a key that is not a valid name (" + NAME_RULE + ")")
            item(checker, element, join(path, key))
    return check


def relative_path(checker, value, path):
    text(max_length=1024)(checker, value, path)
    parts = value.split("/")
    if value.startswith("/") or "\\" in value or any(part in ("", ".", "..") for part in parts):
        checker.fail(path, "must be a relative path without '..', '.' or empty parts")


def rules_path(checker, value, path):
    """A `rules` entry: a relative path whose first part is not `orgs`, because orgs/NAME/<path> is the label that an
    organisation's rules file has in briefs, events and the briefing, and must mean one thing."""
    relative_path(checker, value, path)
    if value.split("/")[0] == "orgs":
        checker.fail(path, "must not start with orgs: orgs/NAME/<path> is the label of an organisation's rules file")


def absolute_path(checker, value, path):
    text(max_length=4096)(checker, value, path)
    if not value.startswith("/") or any(part in (".", "..") for part in value.split("/")):
        checker.fail(path, "must be an absolute path without '.' or '..' parts")


def model_name(checker, value, path):
    text(MODEL, max_length=128)(checker, value, path)
    if re.search(r"[0-9]", value) is None:
        checker.fail(path, "must be a full model name that includes its version, not a family alias")


def placeholders(checker, value, path, allowed=PLACEHOLDERS):
    try:
        fields = [field for _, field, spec, conversion in string.Formatter().parse(value)
                  if field is not None and (field not in allowed or spec or conversion)]
    except ValueError:
        checker.fail(path, "has an unbalanced brace; write {{ or }} for a literal brace")
    if fields:
        checker.fail(path, "uses an unknown placeholder; allowed: " + ", ".join("{" + name + "}" for name in allowed))


def template(allowed):
    def check(checker, value, path):
        array(text(max_length=4096), nonempty=True)(checker, value, path)
        first = value[0]
        if not (COMMAND_NAME.fullmatch(first) or (first.startswith("/") and "{" not in first and "}" not in first)):
            checker.fail(path + "[0]", "must be a command name or an absolute path, without placeholders")
        for index, element in enumerate(value[1:], 1):
            placeholders(checker, element, "{}[{}]".format(path, index), allowed)
    return check


command_template = template(PLACEHOLDERS)
runner_command = template(RUNNER_PLACEHOLDERS)
resume_template = template(RUNNER_PLACEHOLDERS + ("message",))
# A runner's `room` command: one template that serves every account of the runner, so `{account}` is its only
# placeholder (docs/architecture.md, "Accounts and adoption", "The room command").
room_template = template(("account",))


def uses(value, field):
    """True when an element of a checked command template, after the program, names the placeholder."""
    return any(name == field for element in value[1:] for _, name, _, _ in string.Formatter().parse(element))


def output_pattern(checker, value, path):
    """A regular expression matched against one line of a run's output; it must not match an empty line."""
    text()(checker, value, path)
    try:
        compiled = re.compile(value)
    except (re.error, RecursionError, OverflowError):
        checker.fail(path, "is not a valid regular expression")
    if compiled.search("") is not None:
        checker.fail(path, "must not match an empty line")


def guard_pattern(checker, value, path):
    """A guard's regular expression: it compiles, does not match the empty string and passes the partial rejection rule
    of slow shapes (guards.unbounded); the alarm in guards.Matcher is the bound."""
    text()(checker, value, path)
    try:
        compiled = re.compile(value)
    except (re.error, RecursionError, OverflowError):
        checker.fail(path, "is not a valid regular expression")
    if compiled.search("") is not None:
        checker.fail(path, "must not match the empty string")
    problem = guards.unbounded(value)
    if problem:
        checker.fail(path, "cannot be bounded: " + problem)


GUARD = table({
    "name": text(guards.NAME, "[A-Za-z0-9][A-Za-z0-9._-]{0,63}"),
    "kind": choice(*guards.KINDS),
    "pattern": guard_pattern,
    "description": text(),
}, required=("name", "pattern"))


def guard_list(checker, value, path):
    array(GUARD)(checker, value, path)
    seen = set()
    for index, item in enumerate(value):
        if item["name"] in seen:
            checker.fail("{}[{}].name".format(path, index), "repeats the name of an earlier guard")
        seen.add(item["name"])


RECORD_FORMATS = ("claude-code", "text")
RECORD_PLACEHOLDERS = ("account", "effort", "lane", "log", "model", "project", "session", "worktree")


def record_format(checker, value, path):
    if value == "codex":
        checker.fail(path, "the codex format is not supported yet; watch such a runner with format text on the run's "
                           "own log ({log})")
    choice(*RECORD_FORMATS)(checker, value, path)


def record_template(checker, value, path):
    """Where a runner's session records are: an absolute glob, from `~/`, `{worktree}` or `{log}`."""
    text(max_length=4096)(checker, value, path)
    placeholders(checker, value, path, RECORD_PLACEHOLDERS)
    if not value.startswith(("/", "~/", "{worktree}", "{log}")):
        checker.fail(path, "must be an absolute path or glob, or start with ~/, {worktree} or {log}")


RECORDS = table({
    "format": record_format,
    "paths": array(record_template, nonempty=True, unique=True),
}, required=("format", "paths"))


def record_entry(checker, value, path):
    """One entry of a runner's records. Format text reads the run's own log and nothing else."""
    RECORDS(checker, value, path)
    if value["format"] == "text" and value["paths"] != ["{log}"]:
        checker.fail(join(path, "paths"), "format text reads only the run's own log: its paths must be exactly "
                                          "[\"{log}\"] (a later version may read other text files)")


def schema_version(checker, value, path):
    if type(value) is not int or value != SCHEMA_VERSION:
        checker.fail(path, "unsupported schema version; this launcher reads schema_version = 1")


def secret_names(checker, value, path):
    array(text(SECRET_NAME, "[A-Z][A-Z0-9_]{0,63}"), unique=True)(checker, value, path)


ENVIRONMENT_FIELDS = {
    "kind": choice("cloud", "host", "local"),
    "description": text(),
    "identity": text(IDENTITY),
    "region": text(TOKEN),
    "host": text(HOST),
    "secrets": secret_names,
    "attest": command_template,
    "launch": command_template,
    "collect": command_template,
    "max_machines": integer(1, 64),
    "idle_minutes": integer(1, 1440),
    "hard_minutes": integer(1, 10080),
}
ENVIRONMENT_KINDS = {"cloud": ("identity", "region"), "host": ("host",), "local": ()}
CHANNEL_FIELDS = {
    "kind": choice("chat", "file"),
    "description": text(),
    "service": text(SERVICE),
    "target": text(max_length=200),
    "token_secret": text(SECRET_NAME, "[A-Z][A-Z0-9_]{0,63}"),
    "path": relative_path,
}
CHANNEL_KINDS = {"chat": (("service", "target", "token_secret"), ("service", "target")), "file": (("path",), ("path",))}


def test_environment(checker, value, path):
    if not isinstance(value, dict):
        checker.fail(path, "must be a table")
    if "kind" not in value:
        checker.fail(join(path, "kind"), "is required")
    choice(*ENVIRONMENT_KINDS)(checker, value["kind"], join(path, "kind"))
    kind = value["kind"]
    specific = {key for extras in ENVIRONMENT_KINDS.values() for key in extras}
    allowed = {key: check for key, check in ENVIRONMENT_FIELDS.items()
               if key not in specific or key in ENVIRONMENT_KINDS[kind]}
    required = {"cloud": ("kind", "identity"), "host": ("kind", "host"), "local": ("kind",)}[kind]
    note = lambda key: "is not valid for kind " + kind if key in ENVIRONMENT_FIELDS else None
    table(allowed, required, note)(checker, value, path)
    if value.get("secrets") and "attest" not in value:
        checker.fail(join(path, "attest"), "is required when secrets are listed: a secret goes only to a verified machine")


def owner_channel(checker, value, path):
    if not isinstance(value, dict):
        checker.fail(path, "must be a table")
    if "kind" not in value:
        checker.fail(join(path, "kind"), "is required")
    choice(*CHANNEL_KINDS)(checker, value["kind"], join(path, "kind"))
    kind = value["kind"]
    permitted, required = CHANNEL_KINDS[kind]
    specific = {key for options in CHANNEL_KINDS.values() for key in options[0]}
    allowed = {key: check for key, check in CHANNEL_FIELDS.items() if key not in specific or key in permitted}
    note = lambda key: "is not valid for kind " + kind if key in CHANNEL_FIELDS else None
    table(allowed, ("kind",) + required, note)(checker, value, path)


def levels_text(levels):
    """Levels as a message names them: 4 (mini-supervisor), 5 (top supervisor) or 6 (super top)."""
    named = ["{} ({})".format(number, LEVEL_NAMES[number]) for number in levels]
    return ", ".join(named[:-1]) + " or " + named[-1]


def supervisor_level(checker, value, path):
    """A supervisor's level: the integer 4, 5 or 6. A string, a float or a boolean is not one, and 3 is a lane."""
    if type(value) is int and value in SUPERVISOR_LEVELS:
        return
    note = "; level {} is a lane, and a lane is not a [supervisors] entry".format(LANE_LEVEL) if (
        type(value) is int and value == LANE_LEVEL) else ""
    checker.fail(path, "must be " + levels_text(SUPERVISOR_LEVELS) + note)


SUPERVISOR_FIELDS = {
    "level": supervisor_level,
    "role": choice(*ROLE_LEVELS),
    "runner": text(NAME, NAME_RULE),
    "projects": array(text(NAME, NAME_RULE), unique=True),
    "owner_channel": text(NAME, NAME_RULE),
    "description": text(),
}


def supervisor(checker, value, path):
    """A [supervisors] entry: exactly one of `level` and `role` (the old spelling of a level), then its other keys."""
    if isinstance(value, dict):
        if "level" in value and "role" in value:
            checker.fail(path, "has both level and role: role is the old spelling of level, so give level only")
        if "level" not in value and "role" not in value:
            checker.fail(join(path, "level"), "is required: {} (the old spelling role = \"mini\" or \"top\" is still "
                                              "read)".format(levels_text(SUPERVISOR_LEVELS)))
    table(SUPERVISOR_FIELDS, required=("runner",))(checker, value, path)


def read_levels(data):
    """Gives every [supervisors] entry an integer `level`: `role`, the old spelling, is read as its level here and
    nowhere else, and does not stay in the data."""
    for entry in data.get("supervisors", {}).values():
        if "role" in entry:
            entry["level"] = ROLE_LEVELS[entry.pop("role")]


QUIET_SECONDS = integer(1, 604800)
RUNNER_KEYS = table({
    "command": runner_command,
    "resume": resume_template,
    "prompt": choice(*PROMPTS),
    "stream": choice(*streams.READERS),
    "room": room_template,
    "accounts": array(text(ACCOUNT), unique=True),
    "secrets": secret_names,
    "limit_patterns": array(output_pattern, nonempty=True, unique=True),
    "dropped_patterns": array(output_pattern, nonempty=True, unique=True),
    "quiet_seconds": QUIET_SECONDS,
    "records": array(record_entry, nonempty=True),
    "description": text(),
}, required=("command",))


def runner_entry(checker, value, path):
    """A runner: its keys one by one, then what its templates and `prompt` say together. A brief reaches the runner as
    a file (`{brief}`) unless its prompt is on standard input; and a lane's session identifier is in both templates or
    in neither, because a resume by an identifier the start did not give is a wrong resume."""
    RUNNER_KEYS(checker, value, path)
    command, resume = value["command"], value.get("resume")
    if value.get("prompt", "argument") == "argument" and not uses(command, "brief"):
        checker.fail(join(path, "command"), "must pass the rendered brief with {brief}, or the runner must take its "
                                            "prompt on standard input (prompt = \"stdin\"): a lane's brief always "
                                            "reaches its runner as a file or on standard input")
    if resume is not None and uses(command, "session") != uses(resume, "session"):
        if uses(command, "session"):
            checker.fail(join(path, "resume"), "must use {session} as command does: a resume that does not name the "
                                               "lane's session identifier could continue another session")
        checker.fail(join(path, "command"), "must use {session} as resume does: a lane started without an identifier "
                                            "cannot be resumed by one")


LANES = table({
    "budget_minutes": budget,
    "quiet_seconds": QUIET_SECONDS,
    "stop_grace_seconds": integer(1, 600),
    "lock_wait_seconds": integer(1, 3600),
    # The time a runner's `room` command has before it is stopped; accounts.DEFAULT_TIMEOUT_SECONDS is the default.
    "room_timeout_seconds": integer(1, 60),
})
# The idle message of `lane turn --idle` is read like a standing-rules file, and is at most this long; the idle interval
# of a turn-based lane is at most a week, and so is each wait of the loop (`lane loop`) after an end that was not good.
MAX_IDLE_MESSAGE_BYTES = 64 * 1024
MAX_IDLE_SECONDS = 604800
MAX_WAIT_SECONDS = 604800
TURNS = table({
    "idle_message": relative_path,
    "idle_seconds": integer(1, MAX_IDLE_SECONDS),
    "poll_seconds": integer(1, 3600),
    "backoff_seconds": integer(1, MAX_WAIT_SECONDS),
    "limit_backoff_seconds": integer(1, MAX_WAIT_SECONDS),
})
ROUTE = table({
    "runner": text(NAME, NAME_RULE),
    "model": model_name,
    "effort": text(TOKEN),
}, required=("runner", "model"))

# The disk line (docs/configuration.md, "[disk]"): the file system every new lane and worktree is measured against.
# It applies whether or not the section is written, so its two lines have their defaults here and nowhere else.
DEFAULT_WARN_PERCENT = 85
DEFAULT_STOP_PERCENT = 90
DISK = table({
    "path": absolute_path,
    "warn_percent": integer(1, 99),
    "stop_percent": integer(1, 99),
})


def disk_section(checker, value, path):
    """`[disk]`: its keys one by one, then the two lines against each other. Each line is 1 to 99 and the warn line
    is below the stop line, so a configuration cannot refuse at a reading it would have warned about."""
    DISK(checker, value, path)
    warn = value.get("warn_percent", DEFAULT_WARN_PERCENT)
    stop = value.get("stop_percent", DEFAULT_STOP_PERCENT)
    if warn >= stop:
        checker.fail(join(path, "warn_percent"), "must be below stop_percent")


def judge_command(checker, value, path):
    """A judge's argument vector: a command name or an absolute path, then plain arguments. A judge command has no
    placeholders in version 1, so a brace is refused instead of being passed on as it was written."""
    array(text(max_length=4096), nonempty=True)(checker, value, path)
    if not (COMMAND_NAME.fullmatch(value[0]) or value[0].startswith("/")):
        checker.fail(path + "[0]", "must be a command name or an absolute path")
    for index, element in enumerate(value):
        if "{" in element or "}" in element:
            checker.fail("{}[{}]".format(path, index), "must not contain braces: a judge command has no placeholders "
                                                       "in version 1")


JUDGE = table({
    "description": text(),
    "command": judge_command,
    "timeout_seconds": integer(1, 60),
}, required=("command",))

# A resource is something a lane holds outside this machine, made by an external command (an adapter) that a
# [resources.NAME] entry names. The tabulated bounds and the two defaults are the design's table
# (docs/architecture.md, "Configuration"); nothing here is defaulted into the loaded data.
CREDENTIAL_ENV_RULE = "[A-Z][A-Z0-9_]{0,63}"
CREDENTIAL_PROFILE_RULE = "[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
RESOURCE_KINDS = ("machine", "credential")
DEFAULT_ACQUIRE_SECONDS = 300
DEFAULT_ACQUIRE_BOUND_MINUTES = 15


def boolean(checker, value, path):
    if type(value) is not bool:
        checker.fail(path, "must be true or false")


def adapter_command(checker, value, path):
    """An adapter's argument vector: a command name or an absolute path, then plain arguments. An adapter command
    has no placeholders in version 1, so a brace is refused instead of being passed on as it was written."""
    array(text(max_length=4096), nonempty=True)(checker, value, path)
    if not (COMMAND_NAME.fullmatch(value[0]) or value[0].startswith("/")):
        checker.fail(path + "[0]", "must be a command name or an absolute path")
    for index, element in enumerate(value):
        if "{" in element or "}" in element:
            checker.fail("{}[{}]".format(path, index), "must not contain braces: an adapter command has no "
                                                       "placeholders in version 1")


def credential_env(checker, value, path):
    """The NAME of an environment variable of the launcher's process, never a value. `PATH` is the fixed PATH the
    adapter runs with, and the `LANEBOSS_` names are the launcher's own."""
    text(SECRET_NAME, CREDENTIAL_ENV_RULE)(checker, value, path)
    if value == "PATH":
        checker.fail(path, "must not name the fixed PATH the adapter runs with")
    if value.startswith("LANEBOSS_"):
        checker.fail(path, "must not start with LANEBOSS_: those names are the launcher's own")


RESOURCE = table({
    "description": text(),
    "command": adapter_command,
    "kind": choice(*RESOURCE_KINDS),
    "credential_env": credential_env,
    "credential_profile": text(ACCOUNT, CREDENTIAL_PROFILE_RULE),
    "acquire_seconds": integer(1, 900),
    "describe_seconds": integer(1, 300),
    "release_seconds": integer(1, 600),
    "acquire_bound_minutes": integer(1, 1440),
    "hard_cap_minutes": integer(1, 10080),
    "release_by_itself": boolean,
    "read_back_wait_seconds": integer(0, 3600),
}, required=("command", "kind", "hard_cap_minutes"))


def resource_entry(checker, value, path):
    """An adapter: its keys, then the cross rule. `acquire_bound_minutes` must be at least one minute more than
    `acquire_seconds` rounded up to whole minutes, compared with the true value (its default 300 when the key is
    absent), so that a call still inside its own time-out is never listed as unresolved."""
    RESOURCE(checker, value, path)
    bound = value.get("acquire_bound_minutes", DEFAULT_ACQUIRE_BOUND_MINUTES)
    seconds = value.get("acquire_seconds", DEFAULT_ACQUIRE_SECONDS)
    if bound < math.ceil(seconds / 60) + 1:
        checker.fail(join(path, "acquire_bound_minutes"),
                     "must be at least one minute more than acquire_seconds rounded up to whole minutes")


CONFIG = table({
    "schema_version": schema_version,
    "name": text(NAME, NAME_RULE),
    "description": text(),
    "organisation": text(NAME, NAME_RULE),
    "rules": array(rules_path, unique=True),
    "organisation_rules": array(relative_path, unique=True),
    "secrets": secret_names,
    "owner_channel": text(NAME, NAME_RULE),
    "test_environment": text(NAME, NAME_RULE),
    "state": table({"path": absolute_path}),
    "lanes": LANES,
    "turns": TURNS,
    "disk": disk_section,
    "runners": named_tables(runner_entry, minimum=1),
    "supervisors": named_tables(supervisor),
    "judges": named_tables(JUDGE),
    "resources": named_tables(resource_entry),
    "routing": table({difficulty: array(ROUTE, nonempty=True) for difficulty in DIFFICULTIES}),
    "test_environments": named_tables(test_environment),
    "owner_channels": named_tables(owner_channel),
    "cost": table({"currency": text(CURRENCY, "[A-Z]{3}"), "daily_cap": amount, "per_run_cap": amount,
                   "report_threshold": amount}, required=("currency",)),
    "guards": guard_list,
}, required=("schema_version", "name", "runners"))
PROJECT = table({
    "schema_version": schema_version,
    "name": text(NAME, NAME_RULE),
    "description": text(),
    "repository": text(max_length=1024),
    "lane_prefix": text(LANE_PREFIX),
    "workers": array(text(NAME, NAME_RULE), unique=True),
    "gates": array(text(TOKEN), nonempty=True, unique=True),
    "excluded_accounts": array(text(ACCOUNT), unique=True),
    "test_environment": text(NAME, NAME_RULE),
    "reserved_paths": array(relative_path, unique=True),
    "owner_channel": text(NAME, NAME_RULE),
    "landing_authority": text(NAME, NAME_RULE),
    "rules": array(rules_path, unique=True),
}, required=("schema_version", "name"))


def config_home():
    return _home("HOME", Path.home() / ".config" / PROGRAM)


def state_home():
    return _home("STATE_HOME", Path.home() / ".local" / "state" / PROGRAM)


def _home(suffix, default):
    value = os.environ.get(env_name(suffix))
    if not value:
        return default
    if not value.startswith("/"):
        raise Refused(env_name(suffix) + " must be an absolute path")
    return Path(os.path.normpath(value))


def list_names(home=None):
    configs = (home or config_home()) / "configs"
    try:
        entries = sorted(os.listdir(str(configs)))
    except FileNotFoundError:
        return []
    except OSError:
        raise Refused("cannot list " + str(configs)) from None
    return [name for name in entries if NAME.fullmatch(name) and os.path.isfile(str(configs / name / "config.toml"))]


def describe_names(home=None):
    names = [shown_name(name) for name in list_names(home)]
    return "configurations: " + ", ".join(names) if names else "no configuration exists under " + str(
        (home or config_home()) / "configs")


def check_name(name, what="configuration name"):
    if not isinstance(name, str) or NAME.fullmatch(name) is None:
        raise Refused("the {} must match {}".format(what, NAME_RULE))


def shown_name(name):
    """A configuration name as a binding message may repeat it: the name, or [withheld] when the credential detector
    matches it (a name can pass the grammar and still look like a credential)."""
    return "[withheld]" if credentials.find_in_text(name) else name


def bound_name(cli_value):
    """The one configuration this command is bound to: --config, LANEBOSS_CONFIG, never a guess."""
    variable = env_name("CONFIG")
    environment = os.environ.get(variable) or None
    if cli_value is not None and environment is not None:
        check_name(cli_value, "configuration name given by --config")
        check_name(environment, "configuration name in " + variable)
        if cli_value != environment:
            raise Refused("--config {} conflicts with {}={}; a session is bound to exactly one configuration".format(
                shown_name(cli_value), variable, shown_name(environment)))
    name = cli_value if cli_value is not None else environment
    if name is None:
        raise Refused("no configuration is bound: pass --config NAME or set {}; {}".format(variable, describe_names()))
    check_name(name)
    return name


def guard_named(name):
    """Configuration commands that take a name refuse to read another configuration than the bound one."""
    check_name(name)
    variable = env_name("CONFIG")
    environment = os.environ.get(variable) or None
    if environment is not None and environment != name:
        raise Refused("this session is bound to {}={}; reading configuration {} is refused".format(
            variable, shown_name(environment), shown_name(name)) if NAME.fullmatch(environment) else
            "the configuration name in {} must match {}".format(variable, NAME_RULE))


def parse_toml(data, checker):
    if len(data) > MAX_FILE_BYTES:
        checker.fail("", "is larger than 1 MiB")
    try:
        document = tomllib.loads(data.decode("utf-8"))
    except UnicodeDecodeError:
        checker.fail("", "must be UTF-8 text")
    except tomllib.TOMLDecodeError as error:
        position = re.search(r"\(at line ([0-9]+), column ([0-9]+)\)$", str(error))
        checker.fail("", "TOML syntax error at line {}, column {}".format(*position.groups()) if position else
                     "TOML syntax error at the end of the file")
    found = credentials.find_in_value(document)
    if found:
        checker.fail(found[0], "looks like a credential ({}); configuration files hold secret names, never values"
                     .format(found[1]))
    if "schema_version" not in document:
        checker.fail("schema_version", "is required")
    schema_version(checker, document["schema_version"], "schema_version")
    return document


class ConfigReader:
    """Reads the files of one configuration directory. The directory itself may be a link (R1); every file
    read through it must resolve inside it, so a link to another configuration or outside is refused."""

    KIND = "configuration"

    def __init__(self, name, directory):
        self.name = name
        self.directory = directory
        descriptor = fsguard.open_directory(directory, "{} {}".format(self.KIND, shown_name(name)))
        try:
            self.identity = fsguard.identity(os.fstat(descriptor))
        finally:
            os.close(descriptor)

    def _open_inside(self, target, what):
        descriptor = fsguard.open_directory(target, "{} {}: {}".format(self.KIND, shown_name(self.name), what))
        try:
            chain = fsguard.walk_up(descriptor, None)[0]
            if not fsguard.same_directory(descriptor, target) or self.identity not in chain:
                raise InvalidConfiguration("{} {}: {} leads outside the {} directory".format(
                    self.KIND, shown_name(self.name), what, self.KIND))
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def read(self, relative, what):
        parent, name = os.path.split(os.path.realpath(str(self.directory / relative)))
        directory = self._open_inside(parent, what)
        try:
            descriptor = fsguard.open_child(directory, name, "{} {}: {}".format(self.KIND, shown_name(self.name), what))
        finally:
            os.close(directory)
        return fsguard.read_descriptor(descriptor, MAX_FILE_BYTES + 1,
                                       "{} {}: {}".format(self.KIND, shown_name(self.name), what))

    def list_directory(self, relative):
        directory = self._open_inside(os.path.realpath(str(self.directory / relative)), relative)
        try:
            return sorted(os.listdir(directory))
        finally:
            os.close(directory)


class OrganisationReader(ConfigReader):
    """The same guarded reading inside an organisation's directory, `orgs/NAME/` under the configuration home."""

    KIND = "organisation"


def check_rules_bytes(checker, data, relative, path):
    if len(data) > MAX_FILE_BYTES:
        checker.fail(path, relative + " is larger than 1 MiB")
    try:
        content = data.decode("utf-8")
    except UnicodeDecodeError:
        checker.fail(path, relative + " must be UTF-8 text")
    found = credentials.find_in_text(content)
    if found:
        checker.fail(path, "{} line {}: looks like a credential ({})".format(relative, found[1], found[0]))
    return data


def check_rules_file(checker, reader, relative, path):
    return check_rules_bytes(checker, reader.read(relative, relative), relative, path)


class Configuration:
    """A validated configuration, the bytes of its standing rules, and every path derived from it."""

    def __init__(self, name, home, states, data, projects, rule_bytes, organisation_bytes=None, idle_message=None):
        self.name = name
        self.home = home
        self.state_home = states
        self.config_dir = home / "configs" / name
        self.config_file = self.config_dir / "config.toml"
        self.data = data
        self.projects = projects
        self.rule_bytes = rule_bytes
        # `[turns] idle_message` as (relative path, bytes read when the configuration loaded), or None.
        self.idle_message = idle_message
        self.organisation = data.get("organisation")
        self.organisation_tools = home / "orgs" / self.organisation / "tools" if self.organisation else None
        self.organisation_bytes = organisation_bytes or {}
        custom = data.get("state", {}).get("path")
        self.state_dir = Path(os.path.normpath(custom)) if custom else states / name
        self.store = self.state_dir / STORE_FILE

    def paths(self):
        return {"name": self.name, "config_dir": str(self.config_dir), "config_file": str(self.config_file),
                "state_dir": str(self.state_dir), "store": str(self.store),
                "socket": multiplexer.socket_path(self.name, os.path.realpath(str(self.state_dir)))}

    def describe(self):
        return {"name": self.name, "config_dir": str(self.config_dir), "state_dir": str(self.state_dir),
                "config": self.data, "projects": self.projects}

    def rules(self, project=None):
        """Standing-rules files in order, with the bytes that were validated: the organisation's first, each under
        the label orgs/NAME/<path>, then the configuration's, then the project's."""
        listed = list(self.data.get("rules", []))
        if project is not None:
            listed += [path for path in self.projects[project].get("rules", []) if path not in listed]
        organisation = [("orgs/{}/{}".format(self.organisation, relative), self.organisation_bytes[relative])
                        for relative in self.data.get("organisation_rules", [])]
        return organisation + [(relative, self.rule_bytes[relative]) for relative in listed]

    def command_into_organisation(self):
        """The key path of the first element of a command that points into an organisation's directory, or None:
        what `laneboss doctor` names for a configuration that names no organisation."""
        return next((key_path for key_path, _ in commands_into_organisations(self.home, self.data)), None)


def disk_settings(configuration):
    """`[disk]` with its defaults applied: the file system to watch (the user's home directory), the warn line (85)
    and the stop line (90). The section and each of its keys are optional, so the disk line holds for every
    configuration, written or not."""
    settings = configuration.data.get("disk", {})
    return {"path": settings.get("path") or str(Path.home()),
            "warn_percent": settings.get("warn_percent", DEFAULT_WARN_PERCENT),
            "stop_percent": settings.get("stop_percent", DEFAULT_STOP_PERCENT)}


def load(name, home=None, states=None):
    check_name(name)
    home = home or config_home()
    states = states or state_home()
    directory = home / "configs" / name
    if not os.path.lexists(str(directory / "config.toml")):
        shown = shown_name(name)
        raise Refused("no configuration named {} ({} does not exist); {}".format(
            shown, home / "configs" / shown / "config.toml", describe_names(home)))
    reader = ConfigReader(name, directory)
    checker = Checker("configuration {}: config.toml".format(shown_name(name)))
    data = parse_toml(reader.read("config.toml", "config.toml"), checker)
    CONFIG(checker, data, "")
    read_levels(data)
    if data["name"] != name:
        checker.fail("name", 'must equal the directory name "{}"'.format(shown_name(name)))
    check_tools_not_shared(checker, home, data)
    projects = load_projects(name, reader)
    rule_bytes = cross_check(checker, name, reader, data, projects)
    organisation_bytes = load_organisation_rules(checker, home, data)
    idle_message = load_idle_message(checker, reader, data)
    configuration = Configuration(name, home, states, data, projects, rule_bytes, organisation_bytes, idle_message)
    check_state_location(checker, configuration)
    own = fsguard.Location(directory)
    for other, other_directory in other_config_dirs(home, name):
        if fsguard.overlap(own, fsguard.Location(other_directory)):
            raise InvalidConfiguration("configuration {}: its directory overlaps configuration {}'s directory".format(
                shown_name(name), shown_name(other)))
    return configuration


def load_idle_message(checker, reader, data):
    """The idle message of `[turns]`, (relative path, bytes) or None: a file inside the configuration directory, read
    the way a standing-rules file is (it must resolve inside that directory, be UTF-8 and hold no credential shape)
    and at most 64 KiB. Every refusal names the key path."""
    relative = data.get("turns", {}).get("idle_message")
    if relative is None:
        return None
    path = "turns.idle_message"
    try:
        content = reader.read(relative, relative)
    except Refused as error:
        checker.fail(path, str(error))
    if len(content) > MAX_IDLE_MESSAGE_BYTES:
        checker.fail(path, relative + " is larger than 64 KiB")
    return relative, check_rules_bytes(checker, content, relative, path)


def load_organisation_rules(checker, home, data):
    """The organisation's rules files, {path as listed: bytes}, read inside `orgs/NAME/` the way a configuration's own
    files are (each must resolve inside that directory, at most 1 MiB, UTF-8, no credential shape). Every refusal
    names the key path."""
    listed = data.get("organisation_rules")
    if listed is None:
        return {}
    if "organisation" not in data:
        checker.fail("organisation_rules", "needs the key organisation, which names the organisation whose directory "
                                           "holds these files")
    organisation = data["organisation"]
    reader = None
    found = {}
    for index, relative in enumerate(listed):
        path = "organisation_rules[{}]".format(index)
        try:
            if reader is None:
                reader = OrganisationReader(organisation, home / "orgs" / organisation)
            content = reader.read(relative, relative)
        except Refused as error:
            checker.fail(path, str(error))
        found[relative] = check_rules_bytes(checker, content, relative, path)
    return found


def command_elements(data):
    """(key path, argument vector) of every command the launcher can run for the configuration: a runner's command,
    resume and room, a judge's command, and an adapter's command."""
    for runner_name, runner in data["runners"].items():
        for key in ("command", "resume", "room"):
            if key in runner:
                yield "runners.{}.{}".format(runner_name, key), runner[key]
    for judge_name, judge in data.get("judges", {}).items():
        yield "judges.{}.command".format(judge_name), judge["command"]
    for resource_name, resource in data.get("resources", {}).items():
        yield "resources.{}.command".format(resource_name), resource["command"]


def folded(path):
    """An absolute path with '.', '..' and repeated slashes folded away, as written: no link is followed."""
    result = os.path.normpath(path)
    return "/" + result.lstrip("/") if result.startswith("//") else result


def commands_into_organisations(home, data):
    """(key path, organisation) of every element of a command that is an absolute path inside `orgs/NAME/` of the
    configuration home, in the order of the file. Only whole elements that are absolute paths are looked at, and the
    comparison is of text."""
    root = folded(str(home / "orgs"))
    for key_path, elements in command_elements(data):
        for index, element in enumerate(elements):
            path = folded(element) if element.startswith("/") else ""
            if path.startswith(root + "/"):
                yield "{}[{}]".format(key_path, index), path[len(root) + 1:].split("/", 1)[0]


def check_tools_not_shared(checker, home, data):
    """Tools are not shared between organisations: a configuration that names an organisation may not point a command
    into the directory `orgs/OTHER/` of another one. A configuration that names none is not refused, so that one
    written before organisations keeps working; `laneboss doctor` fails it and says what to add."""
    own = data.get("organisation")
    if own is None:
        return
    for key_path, organisation in commands_into_organisations(home, data):
        if organisation != own:
            checker.fail(key_path, "points into the directory of another organisation; tools are not shared between "
                                   "organisations")


def load_projects(name, reader):
    projects = {}
    if not os.path.lexists(str(reader.directory / "projects")):
        return projects
    for entry in reader.list_directory("projects"):
        if not entry.endswith(".toml"):
            continue
        stem = entry[:-len(".toml")]
        if NAME.fullmatch(stem) is None:
            Checker("configuration {}".format(shown_name(name))).fail(
                "projects", "a project file name does not match " + NAME_RULE + ".toml")
        checker = Checker("configuration {}: projects/{}".format(shown_name(name), entry))
        document = parse_toml(reader.read("projects/" + entry, "projects/" + entry), checker)
        PROJECT(checker, document, "")
        if document["name"] != stem:
            checker.fail("name", 'must equal the file name "{}"'.format(stem))
        projects[stem] = document
    return projects


def cross_check(checker, name, reader, data, projects):
    secrets = set(data.get("secrets", []))
    runners = data["runners"]
    accounts = {account for runner in runners.values() for account in runner.get("accounts", [])}
    channels = data.get("owner_channels", {})
    environments = data.get("test_environments", {})
    supervisors = data.get("supervisors", {})
    rule_bytes = {}

    def known(value, choices, path, what):
        if value not in choices:
            checker.fail(path, "names a {} that is not defined".format(what))

    def listed(value, path):
        if value not in secrets:
            checker.fail(path, "names a secret that is not listed in the top-level secrets")

    for runner_name, runner in runners.items():
        for index, secret in enumerate(runner.get("secrets", [])):
            listed(secret, "runners.{}.secrets[{}]".format(runner_name, index))
    for environment_name, environment in environments.items():
        for index, secret in enumerate(environment.get("secrets", [])):
            listed(secret, "test_environments.{}.secrets[{}]".format(environment_name, index))
    for channel_name, channel in channels.items():
        if "token_secret" in channel:
            listed(channel["token_secret"], "owner_channels.{}.token_secret".format(channel_name))
    for supervisor_name, supervisor in supervisors.items():
        base = "supervisors." + supervisor_name
        known(supervisor["runner"], runners, base + ".runner", "runner")
        for index, project in enumerate(supervisor.get("projects", [])):
            known(project, projects, "{}.projects[{}]".format(base, index), "project file")
        if "owner_channel" in supervisor:
            known(supervisor["owner_channel"], channels, base + ".owner_channel", "owner channel")
    for difficulty, routes in data.get("routing", {}).items():
        for index, route in enumerate(routes):
            known(route["runner"], runners, "routing.{}[{}].runner".format(difficulty, index), "runner")
    if "owner_channel" in data:
        known(data["owner_channel"], channels, "owner_channel", "owner channel")
    if "test_environment" in data:
        known(data["test_environment"], environments, "test_environment", "test environment")
    for index, relative in enumerate(data.get("rules", [])):
        rule_bytes[relative] = check_rules_file(checker, reader, relative, "rules[{}]".format(index))
    for project_name, project in projects.items():
        project_checker = Checker("configuration {}: projects/{}.toml".format(shown_name(name), project_name))
        for index, worker in enumerate(project.get("workers", [])):
            if worker not in runners:
                project_checker.fail("workers[{}]".format(index), "names a runner that is not defined")
        for index, account in enumerate(project.get("excluded_accounts", [])):
            if account not in accounts:
                project_checker.fail("excluded_accounts[{}]".format(index), "names an account no runner lists")
        if "test_environment" in project and project["test_environment"] not in environments:
            project_checker.fail("test_environment", "names a test environment that is not defined")
        if "owner_channel" in project and project["owner_channel"] not in channels:
            project_checker.fail("owner_channel", "names an owner channel that is not defined")
        if "landing_authority" in project:
            authority = supervisors.get(project["landing_authority"])
            if authority is None or authority["level"] not in LANDING_LEVELS:
                project_checker.fail("landing_authority",
                                     "must name a supervisor of level {} or {}".format(*LANDING_LEVELS))
        for index, relative in enumerate(project.get("rules", [])):
            if relative not in rule_bytes:
                rule_bytes[relative] = check_rules_file(project_checker, reader, relative, "rules[{}]".format(index))
    return rule_bytes


def check_state_location(checker, configuration):
    """Checks that need no other configuration: a state directory never overlaps the configuration home."""
    state = fsguard.Location(configuration.state_dir)
    custom = "path" in configuration.data.get("state", {})
    if fsguard.overlap(state, fsguard.Location(configuration.home)):
        checker.fail("state.path", "the state directory must not overlap the configuration home {}{}".format(
            configuration.home, "" if custom else " (it comes from {}; set it elsewhere)".format(
                env_name("STATE_HOME"))))
    if not custom:
        return
    states = fsguard.Location(configuration.state_home)
    if fsguard.inside(states, state):
        checker.fail("state.path", "must not contain the state home, which holds every default state directory")
    if fsguard.inside(state, states) and not fsguard.inside(
            state, fsguard.Location(configuration.state_home / configuration.name)):
        checker.fail("state.path", "must not lie inside another configuration's default state directory")


def other_config_dirs(home, name):
    """(name, directory) of every other entry under the configuration home that has a configuration name and
    is a directory or a link, including one that cannot be entered: it is then reported as unreadable."""
    configs = home / "configs"
    try:
        entries = sorted(os.listdir(str(configs)))
    except OSError:
        return []
    found = []
    for entry in entries:
        if entry == name or NAME.fullmatch(entry) is None:
            continue
        try:
            mode = os.lstat(str(configs / entry)).st_mode
        except OSError:
            continue
        if stat.S_ISDIR(mode) or stat.S_ISLNK(mode):
            found.append((entry, configs / entry))
    return found


def declared_state(name, directory, states):
    """Read only the name and the state location of another configuration: (location, problem). The file is
    read through the same guarded reader as the configuration's own loading, so a config.toml that leaves
    its directory through a link, or a directory that cannot be entered, counts as unreadable."""
    try:
        data = ConfigReader(name, directory).read("config.toml", "config.toml")
    except (LauncherError, OSError):
        return None, "its config.toml cannot be read inside its own directory"
    try:
        document = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None, "its config.toml cannot be read as TOML"
    if document.get("name") != name:
        return None, "its name does not match its directory"
    state = document.get("state", {})
    path = state.get("path") if isinstance(state, dict) else 0
    if path is None:
        return states / name, None
    if not isinstance(path, str) or not path.startswith("/") or any(part in (".", "..") for part in path.split("/")):
        return None, "its state.path is not an absolute path"
    return Path(os.path.normpath(path)), None


UNREADABLE_MARKER = "(unreadable)"
UNKNOWN_OWNER = "(another or an unknown configuration)"
MARKER_FORMAT = 2
STORE_ID = re.compile(r"[0-9a-f]{32}")
RECORDED_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")


def marker_valid(value):
    """The whole marker: exactly config, format and store; config a name, format 2, store None or exactly id
    and created_at, each by its grammar."""
    if not isinstance(value, dict) or set(value) != {"config", "format", "store"}:
        return False
    if not isinstance(value["config"], str) or NAME.fullmatch(value["config"]) is None:
        return False
    if type(value["format"]) is not int or value["format"] != MARKER_FORMAT:
        return False
    store = value["store"]
    if store is None:
        return True
    return (isinstance(store, dict) and set(store) == {"id", "created_at"}
            and isinstance(store["id"], str) and STORE_ID.fullmatch(store["id"]) is not None
            and isinstance(store["created_at"], str) and RECORDED_AT.fullmatch(store["created_at"]) is not None)


def marker_owner(marker, known, own):
    """Who a marker says owns its directory, as something safe to print: None without a marker, `own` when
    it names the bound configuration (compared, never printed; the state directory's own marker is
    validated in full when it is read), the name only when the whole marker is valid and names one of the
    `known` configurations, and otherwise UNREADABLE_MARKER or UNKNOWN_OWNER."""
    if marker is None:
        return None
    if not isinstance(marker, dict):
        return UNREADABLE_MARKER
    if marker.get("config") == own:
        return own
    if marker_valid(marker) and marker["config"] in known:
        return marker["config"]
    return UNKNOWN_OWNER


def foreign_owners(owners, own):
    """Owners other than the bound configuration, the named ones first so a damaged marker never hides a
    known owner."""
    named = [owner for owner in owners if owner not in (None, own, UNREADABLE_MARKER, UNKNOWN_OWNER)]
    return named + [owner for owner in owners if owner in (UNREADABLE_MARKER, UNKNOWN_OWNER)]


class Zones:
    """The bound configuration's own directories and every other configuration's directories, by identity.

    Other configurations are read for their name and state location only. One whose state location cannot
    be read is listed in `unreadable`: bound commands still run, doctor fails."""

    def __init__(self, configuration):
        self.configuration = configuration
        self.own_config = fsguard.Location(configuration.config_dir)
        self.own_state = fsguard.Location(configuration.state_dir)
        self.own_default = fsguard.Location(configuration.state_home / configuration.name)
        self.configs_root = fsguard.Location(configuration.home / "configs")
        self.state_root = fsguard.Location(configuration.state_home)
        self.others = []
        self.unreadable = []
        for name, directory in other_config_dirs(configuration.home, configuration.name):
            self.others.append((name, "configuration directory", fsguard.Location(directory)))
            declared, problem = declared_state(name, directory, configuration.state_home)
            if problem:
                self.unreadable.append((name, problem))
            else:
                self.others.append((name, "state directory", fsguard.Location(declared)))

    def known_names(self):
        """Every configuration that exists under the configuration home, readable or not."""
        return ({self.configuration.name} | {name for name, _, _ in self.others}
                | {name for name, _ in self.unreadable})

    def problems(self):
        """Overlaps that make the bound configuration's state unsafe; both sides of a shared state fail."""
        found = []
        for name, kind, location in self.others:
            if fsguard.overlap(self.own_state, location):
                found.append("the state directory {} is the same as, inside or around configuration {}'s {}".format(
                    self.configuration.state_dir, shown_name(name), kind))
        if fsguard.overlap(self.own_state, self.configs_root) or fsguard.overlap(self.own_state, self.own_config):
            found.append("the state directory {} overlaps the configuration home".format(self.configuration.state_dir))
        return found

    def check_target(self, path, option):
        """Path-based check, which also covers other configurations' state directories that do not exist yet."""
        target = fsguard.Location(path)
        for name, kind, location in self.others:
            if fsguard.inside(target, location):
                raise Refused("{} lies inside configuration {}'s {}; a command bound to {} uses only its own".format(
                    option, shown_name(name), kind, shown_name(self.configuration.name)))

    def check_chain(self, chain, markers, option, write=False):
        """Refuse an opened directory whose real ancestors belong to another configuration."""
        own = self.configuration.name
        known = self.known_names()
        for owner in foreign_owners([marker_owner(marker, known, own) for marker in markers], own):
            if owner == UNREADABLE_MARKER:
                raise Refused("{} lies below a directory whose ownership marker is unreadable".format(option))
            if owner == UNKNOWN_OWNER:
                raise Refused("{} lies inside the state directory of another or an unknown configuration; a "
                              "command bound to {} uses only its own".format(option, shown_name(own)))
            raise Refused("{} lies inside the state directory of configuration {}; a command bound to {} uses "
                          "only its own".format(option, shown_name(owner), shown_name(own)))
        for name, kind, location in self.others:
            if location.exists and location.chain[0] in chain:
                raise Refused("{} lies inside configuration {}'s {}; a command bound to {} uses only its own".format(
                    option, shown_name(name), kind, shown_name(own)))
        if self.configs_root.exists and self.configs_root.chain[0] in chain and not (
                self.own_config.exists and self.own_config.chain[0] in chain):
            raise Refused("{} lies inside the configuration home but outside configuration {}'s directory".format(
                option, shown_name(own)))
        if self.state_root.exists and self.state_root.chain[0] in chain and not any(
                location.exists and location.chain[0] in chain for location in (self.own_state, self.own_default)):
            raise Refused("{} lies inside the state home but outside configuration {}'s state directory".format(
                option, shown_name(own)))
        if write and self.own_state.exists and self.own_state.chain[0] in chain:
            raise Refused("{} lies inside the state directory of {}, which only the store writes".format(
                option, shown_name(own)))


def entered_own(zones, path):
    """Identities of the bound configuration's own directories that the path, as written, passes through."""
    own = {location.chain[0] for location in (zones.own_config, zones.own_state) if location.exists}
    entered = set()
    current = os.path.abspath(str(path))
    while True:
        parent = os.path.dirname(current)
        if parent == current:
            return entered
        current = parent
        try:
            identity = fsguard.identity(os.stat(current))
        except OSError:
            continue
        if identity in own:
            entered.add(identity)


def open_checked_parent(zones, path, option, write):
    """Open the directory that will hold path, check it by identity, and return (fd, final name). A path that
    passes through the bound configuration's own directory and leaves it through a link is refused."""
    zones.check_target(path, option)
    entered = entered_own(zones, path)
    parent, name = os.path.split(os.path.realpath(str(path)))
    descriptor = fsguard.open_directory(parent, option)
    try:
        if not fsguard.same_directory(descriptor, parent):
            raise Refused(option + ": the directory changed while it was being checked")
        chain, markers = fsguard.walk_up(descriptor, MARKER)
        if entered - set(chain):
            raise Refused("{} passes through a directory of configuration {} and leaves it through a link".format(
                option, shown_name(zones.configuration.name)))
        zones.check_chain(chain, markers, option, write)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, name


def read_external(zones, path, option, limit):
    """Read a file given on the command line once: a regular file outside every other configuration."""
    directory, name = open_checked_parent(zones, path, option, write=False)
    try:
        descriptor = fsguard.open_child(directory, name, option)
    finally:
        os.close(directory)
    return fsguard.read_descriptor(descriptor, limit, option)


def open_output(zones, path, option):
    """Open the directory of a new output file; the output itself is written later through that directory."""
    if os.path.lexists(str(path)):
        raise Refused("{} {} already exists; a rendered brief is never replaced".format(option, path))
    directory, name = open_checked_parent(zones, path, option, write=True)
    if fsguard.file_info(directory, name) is not None:
        os.close(directory)
        raise Refused("{} {} already exists; a rendered brief is never replaced".format(option, path))
    return directory, name


def validate_all(home=None, states=None):
    home = home or config_home()
    states = states or state_home()
    configs = home / "configs"
    errors = []
    loaded = []
    try:
        entries = sorted(os.listdir(str(configs)))
    except FileNotFoundError:
        entries = []
    except OSError:
        raise Refused("cannot list " + str(configs)) from None
    for entry in entries:
        try:
            mode = os.lstat(str(configs / entry)).st_mode
        except OSError:
            continue
        if not (stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
            continue
        if NAME.fullmatch(entry) is None:
            errors.append("configs: a configuration directory name does not match " + NAME_RULE)
            continue
        try:
            loaded.append(load(entry, home, states))
        except Refused as error:
            errors.append(str(error))
    for index, first in enumerate(loaded):
        for second in loaded[index + 1:]:
            one, two = fsguard.Location(first.state_dir), fsguard.Location(second.state_dir)
            if fsguard.overlap(one, two):
                errors.append("configurations {} and {}: state.path: their state directories are {}".format(
                    shown_name(first.name), shown_name(second.name),
                    "equal" if fsguard.inside(one, two) and fsguard.inside(two, one) else "nested"))
    if errors:
        raise InvalidConfiguration("\n".join(errors))
    return [configuration.name for configuration in loaded]
