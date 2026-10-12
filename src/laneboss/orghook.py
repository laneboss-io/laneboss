"""The org's one data-driven PreToolUse guard and its render/validate surface.

Phase A calls seed_hook_rules(), render_hook_settings() and check_hooks(). The
standalone CLI owns hook, refusals and check-hooks; register_actions() lets the
org command share Phase A's parser without registering a second `org` group.
See docs/org-hooks.md for schemas and the launch contract.
"""

from dataclasses import dataclass
from fnmatch import fnmatchcase
import json
import os
from pathlib import Path
import re
import shlex
import sys
import tempfile
import tomllib

from .errors import Refused
from . import orgargv


MAX_BYTES = 2 * 1024 * 1024
MAX_RULES = 512
MAX_READ_PATHS = 4096
LEVELS = (3, 4, 5, 6)
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")
KINDS = {"write-scope", "command-pattern", "secret-read", "tool-allowlist"}
SHELL_TOOLS = {"Bash", "exec_command", "shell", "shell_command"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit", "write_file", "edit_file"}
READ_TOOLS = {"Read", "read_file"}
OTHER_TOOLS = {"WebFetch", "WebSearch", "request_user_input"}


class HookError(Refused):
    """A safe, deliberately non-echoing explanation of invalid hook input."""


@dataclass(frozen=True)
class Instance:
    home: Path
    directory: Path
    name: str
    level: int
    data: dict
    writable_repos: tuple
    allowed_tools: tuple
    secret_names: tuple
    worktree: Path


@dataclass(frozen=True)
class Rule:
    data: dict
    refusal: dict
    source: str


@dataclass(frozen=True)
class Action:
    tool: str
    commands: tuple = ()
    writes: tuple = ()
    reads: tuple = ()


def register(commands):
    org = commands.add_parser("org", help="org hook policies, refusal descriptions and mandatory hook checks")
    actions = org.add_subparsers(dest="action", metavar="ACTION", required=True)
    register_actions(actions)


def register_actions(actions):
    hook = actions.add_parser("hook", help="inspect one PreToolUse JSON event from stdin; errors deny")
    hook.add_argument("--runner", required=True, choices=("claude", "codex"))
    hook.add_argument("--instance", metavar="FILE", help="pin the caller to an instance.toml (used by rendered hooks)")
    refusals = actions.add_parser("refusals", help="read all structured refusal descriptions of an org")
    refusals.add_argument("org", metavar="ORG")
    refusals.add_argument("--format", choices=("text", "json"), default="text")
    actions.add_parser("check-hooks", help="exit 1 if any configured runner would start without its org hook"
                       ).add_argument("org", metavar="ORG")


def _json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise HookError("JSON has duplicate object fields")
        result[key] = value
    return result


def parse_json(data, label):
    try:
        value = json.loads(data, object_pairs_hook=_json_pairs,
                           parse_constant=lambda _: _bad_json_number())
    except (ValueError, UnicodeError, RecursionError):
        raise HookError(label + " must be valid UTF-8 JSON") from None
    if not isinstance(value, dict):
        raise HookError(label + " must be a JSON object")
    return value


def _bad_json_number():
    raise HookError("JSON has a nonfinite number")


def read_bytes(path, label):
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_BYTES + 1)
    except OSError:
        raise HookError(label + " is missing or unreadable") from None
    if len(data) > MAX_BYTES:
        raise HookError(label + " exceeds the input limit")
    return data


def read_toml(path, label):
    try:
        return tomllib.loads(read_bytes(path, label).decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        raise HookError(label + " is broken TOML") from None


def strings(value, label, empty=True):
    if not isinstance(value, list) or len(value) > MAX_RULES or (not empty and not value) or not all(
            isinstance(word, str) and word and not any(ord(c) < 32 for c in word) for word in value):
        raise HookError(label + " must be an array of nonempty strings")
    return tuple(value)


def org_home(org):
    try:
        root = Path(org).resolve()
        home = root if root.name == ".laneboss" else root / ".laneboss"
        read_toml(home / "org.toml", "org.toml")
        return home
    except (OSError, RuntimeError, ValueError):
        raise HookError("the org path cannot be resolved") from None


def _home_from_directory(directory):
    for parent in (directory, *directory.parents):
        if parent.name == ".laneboss" and (parent / "org.toml").is_file():
            return parent
        if (parent / ".laneboss" / "org.toml").is_file():
            return parent / ".laneboss"
    raise HookError("no org was found from the working directory")


def _instance_from_directory(directory):
    for parent in (directory, *directory.parents):
        if parent.parent.name == "instances" and parent.parent.parent.name == ".laneboss":
            return parent
    return None


def load_instance(directory):
    directory = Path(directory)
    if directory.name == "instance.toml":
        directory = directory.parent
    if not NAME.fullmatch(directory.name) or directory.is_symlink() or directory.parent.name != "instances" or (
            directory.parent.parent.name != ".laneboss"):
        raise HookError("unknown instance: expected .laneboss/instances/NAME/instance.toml")
    home = org_home(directory.parent.parent)
    data = read_toml(directory / "instance.toml", "instance.toml")
    name, level = data.get("name"), data.get("level")
    if not isinstance(name, str) or name != directory.name or not NAME.fullmatch(name):
        raise HookError("instance.toml name does not match its directory")
    if type(level) is not int or level not in LEVELS:
        raise HookError("instance.toml level must be 3, 4, 5 or 6")
    if not isinstance(data.get("role"), str) or not data["role"].strip():
        raise HookError("instance.toml needs a role")
    repos = strings(data.get("writable_repos"), "instance writable_repos")
    tools = strings(data.get("allowed_tools"), "instance allowed_tools")
    secrets = strings(data.get("secret_names", data.get("secrets")), "instance secret_names")
    roots = tuple(orgargv.path_at(word, home.parent) for word in repos)
    worktree = orgargv.path_at(data["worktree"], home.parent) if "worktree" in data else (
        roots[0] if len(roots) == 1 else directory)
    return Instance(home, directory, name, level, data, roots, tools, secrets, worktree)


def find_instance(cwd, pinned=None):
    directory = orgargv.path_at(cwd, Path.cwd())
    inferred = _instance_from_directory(directory)
    explicit = os.environ.get("LANEBOSS_INSTANCE")
    chosen = pinned or explicit
    if chosen:
        if NAME.fullmatch(chosen):
            candidate = _home_from_directory(directory) / "instances" / chosen
        else:
            candidate = Path(chosen)
            if not candidate.is_absolute():
                raise HookError("LANEBOSS_INSTANCE must be a name or an absolute instance path")
            if candidate.name == "instance.toml":
                candidate = candidate.parent
        if candidate.is_symlink():
            raise HookError("an instance directory may not be a symlink")
        candidate = candidate.resolve()
    else:
        candidate = inferred
    if candidate is None:
        raise HookError("unknown instance: start in an instance directory or set LANEBOSS_INSTANCE")
    instance = load_instance(candidate)
    if inferred is not None and inferred.resolve() != instance.directory:
        raise HookError("the working directory and the selected instance disagree")
    if pinned and explicit and explicit not in {instance.name, str(instance.directory),
                                               str(instance.directory / "instance.toml")}:
        raise HookError("LANEBOSS_INSTANCE disagrees with the pinned instance")
    return instance


def validate_refusal(data, label):
    if not isinstance(data.get("id"), str) or not NAME.fullmatch(data["id"]):
        raise HookError(label + " needs a valid refusal id")
    for key in ("refuses", "why", "instead"):
        if not isinstance(data.get(key), str) or not data[key].strip():
            raise HookError(label + " needs " + key)
    applies = data.get("applies_to")
    if not isinstance(applies, dict) or set(applies) != {"levels", "identities"}:
        raise HookError(label + " needs applies_to levels and identities")
    levels = applies["levels"]
    if not isinstance(levels, list) or not levels or not all(type(n) is int and n in LEVELS for n in levels):
        raise HookError(label + " has invalid applicable levels")
    strings(applies["identities"], label + " applicable identities", empty=False)
    for key in ("examples_allowed", "examples_refused"):
        strings(data.get(key), label + " " + key)
    return data


def _load_rule_rows(rows, layer, source):
    if not isinstance(rows, list) or len(rows) > MAX_RULES or not all(isinstance(row, dict) for row in rows):
        raise HookError(source + " rules must be an array of tables")
    result, seen = [], set()
    for row in rows:
        identifier, kind = row.get("id"), row.get("kind")
        if not isinstance(identifier, str) or not NAME.fullmatch(identifier) or identifier in seen:
            raise HookError(source + " has an invalid or duplicate rule id")
        seen.add(identifier)
        if not isinstance(kind, str) or kind not in KINDS:
            raise HookError(source + " has an unknown rule kind")
        allowed_keys = {"id", "kind", "applies_to"} | {
            "write-scope": {"paths", "deny_paths"}, "secret-read": {"names"},
            "tool-allowlist": {"tools"}, "command-pattern": {"patterns"}}[kind]
        if set(row) - allowed_keys:
            raise HookError(source + " has an unknown rule field")
        if kind == "command-pattern":
            patterns = row.get("patterns")
            if not isinstance(patterns, list) or not patterns or len(patterns) > MAX_RULES:
                raise HookError(source + " command patterns must be arrays of argv words")
            for words in patterns:
                strings(words, source + " command pattern", empty=False)
        else:
            key = {"write-scope": "paths", "secret-read": "names", "tool-allowlist": "tools"}[kind]
            strings(row.get(key), source + " " + key)
            if kind == "write-scope":
                strings(row.get("deny_paths", []), source + " deny_paths")
        refusal = validate_refusal(read_toml(layer / "refusals" / (identifier + ".toml"),
                                             source + " refusal " + identifier), source + " refusal " + identifier)
        if refusal["id"] != identifier or ("applies_to" in row and row["applies_to"] != refusal["applies_to"]):
            raise HookError(source + " rule and refusal description disagree")
        result.append(Rule(row, refusal, source))
    return result


def load_rules(instance):
    rules = []
    for layer in (instance.home / "shared", instance.home / ("L" + str(instance.level))):
        source = layer.name + "/hooks/rules.toml"
        data = read_toml(layer / "hooks" / "rules.toml", source)
        if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
            raise HookError(source + " needs schema_version = 1")
        if set(data) - {"schema_version", "rules"}:
            raise HookError(source + " has an unknown policy field")
        rules.extend(_load_rule_rows(data.get("rules"), layer, source))
    hooks = instance.data.get("hooks", {})
    if not isinstance(hooks, dict):
        raise HookError("instance hooks must be a table")
    if set(hooks) - {"rules"}:
        raise HookError("instance hooks has an unknown policy field")
    rules.extend(_load_rule_rows(hooks.get("rules", []), instance.directory, "instance.toml hooks"))
    if len(rules) > MAX_RULES:
        raise HookError("the combined policy exceeds the rule limit")
    return rules


def refusal_text(refusal, detail=None):
    message = "[{id}] Refuses: {refuses}\nWhy: {why}\nInstead: {instead}".format(**refusal)
    return message + ("\nInspection: " + detail if detail else "")


def _applies(rule, instance):
    applies = rule.refusal["applies_to"]
    return instance.level in applies["levels"] and any(
        fnmatchcase(instance.name, name) for name in applies["identities"])


def _policy_paths(instance):
    home = instance.home
    paths = [home / "org.toml", home / "shared" / "hooks", home / "shared" / "refusals",
             Path(__file__).resolve().parent]
    for level in LEVELS:
        paths.extend((home / ("L" + str(level)) / "hooks", home / ("L" + str(level)) / "refusals"))
    for directory in (home / "instances").iterdir():
        paths.extend((directory / "instance.toml", directory / ".claude", directory / ".codex",
                      directory / "hooks", directory / "refusals"))
    return tuple(paths)


def _paths(words, instance):
    paths = []
    replacements = {"org": str(instance.home.parent), "laneboss": str(instance.home),
                    "instance": str(instance.directory), "level": str(instance.home / ("L" + str(instance.level))),
                    "worktree": str(instance.worktree)}
    for word in words:
        if word == "{writable_repos}":
            paths.extend(instance.writable_repos)
        elif word == "{hook_paths}":
            paths.extend(_policy_paths(instance))
        else:
            try:
                expanded = word.format_map(replacements)
            except (KeyError, ValueError, IndexError):
                raise HookError("a write-scope path has an unknown placeholder") from None
            paths.append(orgargv.path_at(expanded, instance.home.parent))
    return tuple(path.resolve() for path in paths)


def _words(words, instance, key):
    result = []
    for word in words:
        if word == "{" + key + "}":
            result.extend(getattr(instance, key))
        elif "{" in word or "}" in word:
            raise HookError("a policy value has an unknown placeholder")
        else:
            result.append(word)
    return result


def _inside(path, root):
    return path == root or root in path.parents


def _secret_read(word, directory, names, instance):
    path = orgargv.path_at(word, directory)

    def matches(original, resolved):
        if resolved.is_file() and resolved.stat().st_nlink > 1:
            raise HookError("a multiply linked file cannot be checked by a secret-name policy")
        return any(fnmatchcase(original.name, name) or fnmatchcase(resolved.name, name) or (
            "/" in name and resolved == orgargv.path_at(name, instance.home.parent)) for name in names)

    if matches(Path(word), path):
        return True
    if not path.is_dir():
        return False
    seen = 0

    def unreadable(_):
        raise HookError("a directory read cannot be inspected")

    # Only names and filesystem metadata are inspected, never file contents.
    # Symlink directories cannot be safely enumerated without following them.
    for root, directories, files in os.walk(path, followlinks=False, onerror=unreadable):
        for name in directories + files:
            seen += 1
            if seen > MAX_READ_PATHS:
                raise HookError("a directory read exceeds the inspection limit")
            child = Path(root) / name
            resolved = child.resolve()
            if child.is_symlink() and resolved.is_dir():
                raise HookError("a directory read contains a symlink directory")
            if matches(child, resolved):
                return True
    return False


def _patch_paths(text):
    if not isinstance(text, str) or len(text) > MAX_BYTES or not text.startswith("*** Begin Patch\n") or (
            not text.rstrip().endswith("*** End Patch")):
        raise HookError("apply_patch must contain a complete patch")
    paths = []
    active = False
    for line in text.rstrip().splitlines()[1:-1]:
        match = re.fullmatch(r"\*\*\* (Add File|Update File|Delete File|Move to): (.+)", line)
        if match:
            if match[1] == "Move to" and not active:
                raise HookError("apply_patch has a move without an update")
            paths.append(match[2])
            active = True
        elif line.startswith("*** ") and line != "*** End of File":
            raise HookError("apply_patch has an unsupported file operation")
        elif line and not active:
            raise HookError("apply_patch has content without a file operation")
    if not paths:
        raise HookError("apply_patch has no file operations")
    return tuple(paths)


def action_from_event(event, runner, cwd):
    if event.get("hook_event_name") != "PreToolUse":
        raise HookError("the hook only accepts PreToolUse events")
    tool = event.get("tool_name")
    if not isinstance(tool, str) or not tool:
        raise HookError("the hook event needs tool_name")
    tool = tool.removeprefix("functions.") if runner == "codex" else tool
    data = event.get("tool_input")
    if runner == "codex" and isinstance(data, str):
        # Custom tools pass raw input; function tools may pass JSON arguments.
        data = {"input": data} if tool == "apply_patch" else parse_json(data, "tool_input")
    if not isinstance(data, dict):
        raise HookError("the hook event needs an object tool_input")
    if tool in SHELL_TOOLS:
        if "env" in data or "additional_env" in data:
            raise HookError("a shell tool's environment overrides cannot be inspected")
        if "shell" in data and data["shell"] not in {"sh", "bash", "zsh", "/bin/sh", "/bin/bash", "/bin/zsh"}:
            raise HookError("a shell tool needs a standard system shell")
        fields = [key for key in ("cmd", "command", "argv") if key in data]
        if len(fields) != 1:
            raise HookError("a shell tool needs exactly one command or argv field")
        if "workdir" in data and "cwd" in data:
            raise HookError("a shell tool has ambiguous working directories")
        directory = orgargv.path_at(data.get("workdir", data.get("cwd", str(cwd))), cwd)
        command = data[fields[0]]
        inspected = orgargv.inspect_shell(command, directory) if isinstance(command, str) else (
            orgargv.inspect_argv(command, directory))
        return Action(tool, tuple(inspected))
    if tool in WRITE_TOOLS or tool in READ_TOOLS:
        fields = [key for key in ("file_path", "notebook_path", "path") if key in data]
        if len(fields) != 1 or not isinstance(data[fields[0]], str):
            raise HookError("a file tool needs exactly one file path")
        paths = (data[fields[0]],)
        return Action(tool, writes=paths if tool in WRITE_TOOLS else (), reads=paths if tool in READ_TOOLS else ())
    if tool == "apply_patch":
        fields = [key for key in ("input", "patch", "command") if key in data]
        if len(fields) != 1:
            raise HookError("apply_patch needs exactly one patch field")
        return Action(tool, writes=_patch_paths(data[fields[0]]))
    if tool in OTHER_TOOLS:
        return Action(tool)
    # The allowlist still gives an explanation if this tool is not allowed.
    return Action(tool, commands=(orgargv.Command((tool,), cwd, opaque=True),))


def decide(event, runner, pinned=None):
    cwd = orgargv.path_at(event.get("cwd", str(Path.cwd())), Path.cwd())
    instance = find_instance(str(cwd), pinned)
    rules = load_rules(instance)  # Validate ALL layers before any allow decision.
    action = action_from_event(event, runner, cwd)
    writes = [(word, cwd) for word in action.writes]
    reads = [(word, cwd) for word in action.reads]
    for command in action.commands:
        writes.extend((word, command.directory) for word in command.writes)
        reads.extend((word, command.directory) for word in command.reads)
    # Malformed file effects are errors even when a policy has no applicable
    # file rule. Keep original words for secret-name/symlink comparisons.
    for word, directory in writes + reads:
        orgargv.path_at(word, directory)
    opaque = any(command.opaque for command in action.commands)
    for rule in rules:
        if not _applies(rule, instance):
            continue
        data, kind = rule.data, rule.data["kind"]
        detail = None
        if kind == "tool-allowlist":
            allowed = _words(data["tools"], instance, "allowed_tools")
            if not any(fnmatchcase(action.tool, name) for name in allowed):
                detail = "the requested tool is outside this instance's allowlist"
        elif kind == "command-pattern":
            for command in action.commands:
                if any(len(command.argv) >= len(pattern) and all(fnmatchcase(word, expected)
                       for word, expected in zip(command.argv, pattern)) for pattern in data["patterns"]):
                    detail = "the parsed command words match a refused command pattern"
                    break
        elif kind == "write-scope":
            allowed, denied = _paths(data["paths"], instance), _paths(data.get("deny_paths", []), instance)
            for word, directory in writes:
                path = orgargv.path_at(word, directory)
                if path.is_file() and path.stat().st_nlink > 1:
                    raise HookError("a multiply linked file cannot be checked by a write-scope policy")
                if any(_inside(path, root) or _inside(root, path) for root in denied) or not any(
                        _inside(path, root) for root in allowed):
                    detail = "the write is outside the allowed paths or touches protected hook settings"
                    break
            if opaque and detail is None:
                detail = "the command's writes cannot be inspected"
        elif kind == "secret-read":
            names = _words(data["names"], instance, "secret_names")
            for word, directory in reads:
                if _secret_read(word, directory, names, instance):
                    detail = "the read names a protected secret file"
                    break
            if opaque and detail is None:
                detail = "the command's reads cannot be inspected"
        if detail:
            return False, refusal_text(rule.refusal, detail)
    if opaque:
        raise HookError("the tool or command has no file-effects adapter")
    return True, "org policy permits this tool call"


def runner_output(runner, allowed, reason):
    # Current Claude and Codex command hooks consume the same PreToolUse
    # permission envelope. Do not emit a Stop-style decision:block envelope.
    if runner not in {"claude", "codex"}:
        raise HookError("unknown hook runner")
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow" if allowed else "deny",
                                  "permissionDecisionReason": reason}}


def run_hook(runner, pinned=None):
    try:
        data = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise HookError("the hook event exceeds 2 MiB")
        allowed, reason = decide(parse_json(data, "the hook event"), runner, pinned)
    except (HookError, orgargv.InspectionError) as error:
        allowed, reason = False, "org hook fails closed: " + str(error)
    except Exception as error:
        # No payload, argv, environment value, path contents or exception text
        # is repeated. Even unforeseen failures produce a blocking decision.
        allowed, reason = False, "org hook fails closed: internal " + type(error).__name__
    print(json.dumps(runner_output(runner, allowed, reason), ensure_ascii=True, sort_keys=True))
    return 0  # A decision envelope, including a deny, is a successful hook run.


def list_refusals(org):
    home = org_home(org)
    layers = [home / "shared"] + sorted(path for path in home.iterdir() if re.fullmatch(r"L[3-6]", path.name))
    instances = home / "instances"
    if instances.is_dir():
        layers.extend(path for path in sorted(instances.iterdir()) if (path / "refusals").is_dir())
    records = []
    for layer in layers:
        directory = layer / "refusals"
        if not directory.is_dir():
            raise HookError("a required refusals directory is missing")
        for path in sorted(directory.glob("*.toml")):
            data = validate_refusal(read_toml(path, "refusal description"), "refusal description")
            if path.stem != data["id"]:
                raise HookError("a refusal id does not match its filename")
            records.append({**data, "source": path.relative_to(home).as_posix()})
            if len(records) > MAX_RULES:
                raise HookError("the refusal catalog exceeds the record limit")
    return records


def helper_source():
    library = str(Path(__file__).resolve().parent.parent)
    return ("# Generated by laneboss org render; the implementation lives in the installed package.\n"
            "import sys\n\nsys.path.insert(0, " + json.dumps(library) + ")\n"
            "from laneboss.cli import main\n\nraise SystemExit(main(['org', 'hook', *sys.argv[1:]]))\n")


def hook_command(instance, runner):
    return shlex.join([sys.executable, "-I", "-B", str(instance.home / "shared" / "hooks" / "org-hook.py"),
                       "--runner", runner, "--instance", str(instance.directory / "instance.toml")])


def settings_document(instance, runner):
    return {"hooks": {"PreToolUse": [{"matcher": "", "hooks": [
        {"type": "command", "command": hook_command(instance, runner)}]}]}}


def settings_path(instance, runner):
    return instance.directory / (".claude/settings.json" if runner == "claude" else ".codex/hooks.json")


def runner_command(instance, runner):
    if runner == "claude":
        return ["claude", "--settings", str(settings_path(instance, runner))]
    if runner == "codex":
        return ["env", "CODEX_HOME=" + str(instance.directory / ".codex"), "codex"]
    raise HookError("unknown hook runner")


def _write_generated(path, text, mode=0o444):
    path = Path(path)
    if path.is_symlink():
        raise HookError("a generated hook file may not replace a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.resolve() != path.parent:
        raise HookError("a generated hook directory may not be a symlink")
    data = text.encode("utf-8")
    if path.is_file() and (path.stat().st_mode & 0o777) == mode and path.read_bytes() == data:
        return   # unchanged: render is idempotent, timestamps included
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".org-hook-", delete=False) as stream:
        temporary = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), mode)
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()


def render_hook_settings(org):
    """Render one helper and settings for both runners. Return mandatory launch prefixes.

    Existing unrelated settings and hooks are kept. A changed generated hook
    registration is replaced; other PreToolUse hooks continue to run.
    """
    home = org_home(org)
    instances = [load_instance(path) for path in sorted((home / "instances").iterdir()) if path.is_dir()]
    for instance in instances:
        load_rules(instance)
    generated_files = [(home / "shared" / "hooks" / "org-hook.py", helper_source())]
    result = {}
    for instance in instances:
        commands = {}
        for runner in ("claude", "codex"):
            path = settings_path(instance, runner)
            document = parse_json(read_bytes(path, "hook settings"), "hook settings") if path.exists() else {}
            hooks = document.setdefault("hooks", {})
            if not isinstance(hooks, dict):
                raise HookError("hook settings hooks must be an object")
            rows = hooks.setdefault("PreToolUse", [])
            if not isinstance(rows, list):
                raise HookError("hook settings PreToolUse must be an array")
            generated = settings_document(instance, runner)["hooks"]["PreToolUse"][0]
            # Keep only unrelated rows. Own rows are recognised by the helper
            # path in parsed argv, rather than by a raw substring.
            retained = []
            for row in rows:
                if not isinstance(row, dict) or not isinstance(row.get("hooks"), list):
                    raise HookError("hook settings has a malformed registration")
                kept = []
                for hook in row["hooks"]:
                    if not isinstance(hook, dict):
                        raise HookError("hook settings has a malformed command hook")
                    try:
                        words = shlex.split(hook.get("command", "")) if hook.get("type") == "command" else []
                    except (ValueError, TypeError, AttributeError):
                        raise HookError("hook settings has invalid command words") from None
                    if str(home / "shared" / "hooks" / "org-hook.py") not in words:
                        kept.append(hook)
                if kept:
                    retained.append({**row, "hooks": kept})
            hooks["PreToolUse"] = retained + [generated]
            document["disableAllHooks"] = False
            if document.get("allowManagedHooksOnly", False):
                raise HookError("managed-only hook settings exclude the org hook")
            generated_files.append((path, json.dumps(document, sort_keys=True, indent=2) + "\n"))
            commands[runner] = {"command": runner_command(instance, runner)}
        generated_files.append((instance.directory / "hooks" / "runners.json", json.dumps(commands, sort_keys=True, indent=2) + "\n"))
        result[instance.name] = commands
    policy_files = set()
    for instance in instances:
        policy_files.update(_policy_files(instance))
    for path in policy_files:
        if path.is_symlink() or path.resolve() != path:
            raise HookError("a policy file may not be a symlink")
    # Settings parsing and policy validation precede every mutation.
    for path, text in generated_files:
        _write_generated(path, text)
    for path in policy_files:
        path.chmod(0o444)
    return result


def _policy_files(instance):
    layers = (instance.home / "shared", instance.home / ("L" + str(instance.level)), instance.directory)
    paths = set()
    for layer in layers:
        if layer != instance.directory:
            paths.add(layer / "hooks" / "rules.toml")
        paths.update((layer / "refusals").glob("*.toml"))
    return paths


def _runner_rows(instance):
    runners = instance.data.get("runners")
    if runners is None:
        path = instance.directory / "hooks" / "runners.json"
        runners = parse_json(read_bytes(path, "rendered runner registry"), "rendered runner registry")
    if not isinstance(runners, dict) or not runners:
        raise HookError("the instance has no runner commands")
    for name, row in sorted(runners.items()):
        if name not in {"claude", "codex"} or not isinstance(row, dict) or "command" not in row:
            raise HookError("an instance runner needs a known name and a command")
        if set(row) - {"command", "resume"}:
            raise HookError("an instance runner has unsupported launch fields")
        for field in ("command", "resume"):
            if field in row:
                yield name, field, row[field]


def _check_runner(instance, runner, command):
    if runner not in {"claude", "codex"}:
        raise HookError("unknown hook runner")
    words = shlex.split(command) if isinstance(command, str) else list(strings(command, "runner command", empty=False))
    if any("$" in word or "`" in word or word in {";", "&&", "||", "|", "&"} for word in words):
        raise HookError("a runner command needs literal argv")
    codex_home = None
    if words and os.path.basename(words[0]) == "env":
        words = words[1:]
        while words and "=" in words[0] and not words[0].startswith("-"):
            key, value = words.pop(0).split("=", 1)
            if key == "CODEX_HOME":
                if codex_home is not None:
                    raise HookError("a runner command overrides CODEX_HOME more than once")
                codex_home = value
            else:
                raise HookError("a runner command has an unreviewed environment override")
    if not words or os.path.basename(words[0]) != runner:
        raise HookError("the runner command does not directly start its declared runner")
    arguments = words[1:]
    if any(word.split("=", 1)[0] in {"--disable-hooks", "--no-hooks", "--bare"} for word in arguments):
        raise HookError("the runner command disables hooks")
    if runner == "claude":
        settings = []
        for index, word in enumerate(arguments):
            if word == "--settings":
                if index + 1 >= len(arguments):
                    raise HookError("the Claude settings argument has no path")
                settings.append(arguments[index + 1])
            elif word.startswith("--settings="):
                settings.append(word.split("=", 1)[1])
        if len(settings) != 1 or orgargv.path_at(settings[0], instance.directory) != settings_path(instance, runner):
            raise HookError("Claude must pass exactly the instance's org hook settings")
    else:
        if codex_home is None or orgargv.path_at(codex_home, instance.directory) != instance.directory / ".codex":
            raise HookError("Codex must start with CODEX_HOME pointing to the instance's hooks config")
        for index, word in enumerate(arguments):
            override = None
            if word in {"-c", "--config", "--disable"}:
                if index + 1 >= len(arguments):
                    raise HookError("a Codex config argument has no value")
                override = arguments[index + 1]
            elif word.startswith(("--config=", "--disable=")):
                override = word.split("=", 1)[1]
            elif word.startswith("-c") and len(word) > 2:
                override = word[2:].lstrip("=")
            if override is not None and "hook" in override.split("=", 1)[0].lower():
                raise HookError("the Codex command overrides its mandatory hooks")
            if override is not None and "=" in override:
                try:
                    configuration = tomllib.loads(override)
                except ValueError:
                    raise HookError("a Codex config override is broken TOML") from None
                if _has_hook_config(configuration):
                    raise HookError("the Codex command overrides its mandatory hooks")
        config_path = instance.directory / ".codex" / "config.toml"
        if config_path.exists():
            configuration = read_toml(config_path, "Codex config.toml")
            if _has_hook_config(configuration, allow_enabled_feature=True):
                raise HookError("Codex config.toml changes its mandatory hooks")
    document = parse_json(read_bytes(settings_path(instance, runner), "runner hook settings"), "runner hook settings")
    if document.get("disableAllHooks", False) is not False:
        raise HookError("the runner settings disable all hooks")
    if document.get("allowManagedHooksOnly", False):
        raise HookError("managed-only hook settings exclude the org hook")
    expected = settings_document(instance, runner)["hooks"]["PreToolUse"][0]
    hooks = document.get("hooks")
    rows = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
    if not isinstance(rows, list) or expected not in rows:
        raise HookError("the runner settings do not register the mandatory synchronous hook for every tool")
    helper = instance.home / "shared" / "hooks" / "org-hook.py"
    if read_bytes(helper, "shared org hook") != helper_source().encode("utf-8"):
        raise HookError("the shared org hook differs from the installed generator")
    protected = {helper, settings_path(instance, runner), *_policy_files(instance)}
    if "runners" not in instance.data:
        protected.add(instance.directory / "hooks" / "runners.json")
    for path in protected:
        if path.is_symlink() or path.resolve() != path or not path.is_file() or path.stat().st_mode & 0o222:
            raise HookError("the shared hook, rule data, refusals and runner settings must be read-only regular files")


def _has_hook_config(configuration, allow_enabled_feature=False, parent=""):
    for key, value in configuration.items():
        if "hook" in key.lower():
            if not (allow_enabled_feature and parent == "features" and key == "hooks" and value is True):
                return True
        if isinstance(value, dict) and _has_hook_config(value, allow_enabled_feature, key):
            return True
    return False


def check_runner_command(instance, runner, command):
    """Fail before a launch/resume without the mandatory settings; return no command text."""
    instance = instance if isinstance(instance, Instance) else load_instance(Path(instance))
    load_rules(instance)
    _check_runner(instance, runner, command)


def check_hooks(org):
    home = org_home(org)
    reports = []
    directory = home / "instances"
    if not directory.is_dir():
        return {"ok": False, "checks": [{"ok": False, "reason": "the org has no instances directory"}]}
    paths = sorted(directory.iterdir())
    if not paths:
        return {"ok": False, "checks": [{"ok": False, "reason": "the org has no instances"}]}
    for path in paths:
        try:
            instance = load_instance(path)
            load_rules(instance)
            rows = list(_runner_rows(instance))
        except (HookError, orgargv.InspectionError, OSError, ValueError) as error:
            reason = str(error) if isinstance(error, (HookError, orgargv.InspectionError)) else "runner data cannot be inspected"
            reports.append({"instance": path.name if NAME.fullmatch(path.name) else "invalid-name", "ok": False,
                            "reason": reason})
            continue
        except Exception as error:
            reports.append({"instance": path.name if NAME.fullmatch(path.name) else "invalid-name", "ok": False,
                            "reason": "runner inspection failed: " + type(error).__name__})
            continue
        for runner, field, command in rows:
            report = {"instance": instance.name, "runner": runner, "field": field, "ok": True}
            try:
                _check_runner(instance, runner, command)
            except (HookError, orgargv.InspectionError, OSError, ValueError) as error:
                report.update(ok=False, reason=str(error) if isinstance(error, (HookError, orgargv.InspectionError)) else
                              "runner settings cannot be inspected")
            except Exception as error:
                report.update(ok=False, reason="runner inspection failed: " + type(error).__name__)
            reports.append(report)
    return {"ok": all(row["ok"] for row in reports), "checks": reports}


def seed_hook_rules(org, levels=LEVELS):
    """The Phase A init integration. Return/write generic rule data, never overwrite policy."""
    from .orgexamples import example_files
    home = org_home(org)
    for relative, text in example_files(levels).items():
        path = home / relative
        if not path.exists():
            _write_generated(path, text)


def run(arguments):
    if arguments.action == "hook":
        return run_hook(arguments.runner, arguments.instance)
    if arguments.action == "refusals":
        records = list_refusals(arguments.org)
        if arguments.format == "json":
            print(json.dumps(records, ensure_ascii=True, sort_keys=True))
        else:
            for record in records:
                print(record["source"] + "\n" + refusal_text(record) + "\n")
        return 0
    if arguments.action == "check-hooks":
        try:
            report = check_hooks(arguments.org)
        except (HookError, orgargv.InspectionError, OSError, ValueError) as error:
            report = {"ok": False, "checks": [{"ok": False, "reason": str(error) if isinstance(
                error, (HookError, orgargv.InspectionError)) else "the org hook data cannot be inspected"}]}
        except Exception as error:
            report = {"ok": False, "checks": [{"ok": False, "reason": "org hook inspection failed: " + type(error).__name__}]}
        print(json.dumps(report, ensure_ascii=True, sort_keys=True))
        return 0 if report["ok"] else 1
    raise HookError("unknown org hook action")
