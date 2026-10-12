"""Bounded inspection of tool commands; nothing is executed or expanded.

The refusal scanner's lexer preserves the difference between quoted words and
operators. Here we additionally reject broken syntax, dynamic paths, truncation
and commands whose file effects we cannot describe. This is a policy inspector,
not a shell sandbox. Unsupported programs need a dedicated tool adapter before
they can be used under a file policy.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import shlex

from . import shellscan


class InspectionError(ValueError):
    """An input cannot be inspected without running it."""


@dataclass(frozen=True)
class Command:
    argv: tuple
    directory: Path
    writes: tuple = ()
    reads: tuple = ()
    opaque: bool = False


LITERAL_COMMANDS = {"echo", "printf", "pwd", "true", "false", ":"}
READERS = {"cat", "head", "tail", "wc", "sort", "uniq", "cut", "grep", "rg", "find", "ls", "stat", "file",
           "readlink", "realpath", "diff", "cmp", "od", "xxd", "base64", "sha256sum", "shasum"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
GIT_GLOBAL_VALUES = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env"}
GIT_GLOBAL_FLAGS = {"--no-pager", "--paginate", "--bare", "--no-replace-objects", "--literal-pathspecs",
                    "--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs"}
GIT_READONLY = {"status", "log", "rev-parse", "rev-list", "ls-files", "ls-tree", "show", "diff", "grep",
                "describe", "remote"}
GIT_WRITERS = {"add", "commit", "checkout", "switch", "restore", "reset", "clean", "merge", "rebase",
               "cherry-pick", "revert", "fetch", "pull", "push", "stash", "tag", "branch", "init"}
REDIRECTS = {"<", ">", ">>", ">|", "<>", "&>", "&>>", "<&", ">&"}
SEPARATORS = {"\n", ";", "&", "&&", "||", "|", "|&", "(", ")"}
ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*", re.DOTALL)
SEARCH_OPTIONS = {"-e", "--regexp", "-f", "--file", "-g", "--glob", "--iglob", "--type", "-t", "--type-not",
                  "-T", "--encoding", "--threads", "--max-count", "-m", "--context", "-A", "-B", "-C",
                  "--after-context", "--before-context", "--exclude", "--include", "--exclude-dir"}
READER_OPTIONS = {
    "head": {"-n", "-c", "--lines", "--bytes"}, "tail": {"-n", "-c", "--lines", "--bytes", "--pid", "-s"},
    "sort": {"-o", "--output", "-k", "--key", "-t", "--field-separator", "-S", "--buffer-size", "--parallel", "-T"},
    "uniq": {"-f", "-s", "-w", "--skip-fields", "--skip-chars", "--check-chars"},
    "cut": {"-b", "-c", "-d", "-f", "--bytes", "--characters", "--delimiter", "--fields", "--output-delimiter"},
    "rg": SEARCH_OPTIONS, "grep": SEARCH_OPTIONS,
    "stat": {"-c", "--format", "--printf"}, "file": {"-f", "--files-from", "-m", "--magic-file", "-F", "-e"},
    "od": {"-A", "-j", "-N", "-t", "-w"}, "xxd": {"-c", "-g", "-l", "-s", "-o"},
    "shasum": {"-a", "--algorithm"},
}


def _peel_wrapper(argv, name):
    takes = shellscan.WRAPPERS[name]
    index = 1
    while index < len(argv) and argv[index].startswith("-"):
        option = argv[index]
        index += 1
        if option == "--":
            break
        if option in takes:
            if index >= len(argv):
                raise InspectionError("a command wrapper option has no value")
            index += 1
    if name == "timeout":
        index += 1
    return argv[index:]


def path_at(word, directory):
    if not isinstance(word, str) or not word or any(ord(c) < 32 for c in word):
        raise InspectionError("a file path is empty or contains control characters")
    if any(c in word for c in "$`*?[]{}") or word.startswith("~") or "://" in word:
        raise InspectionError("a file path needs expansion; use a literal path")
    candidate = Path(word)
    try:
        return (candidate if candidate.is_absolute() else directory / candidate).resolve()
    except (OSError, RuntimeError, ValueError):
        raise InspectionError("a file path cannot be resolved") from None


def normalise(argv, directory, depth):
    """Peel only wrappers with understood arguments, then Git's global options."""
    argv = list(argv)
    if argv and ASSIGNMENT.fullmatch(argv[0]):
        # Assignments can change Git's worktree, the shell and runner settings.
        raise InspectionError("command environment assignments cannot be inspected")
    for _ in range(8):
        if not argv:
            raise InspectionError("a command has no executable")
        name = os.path.basename(argv[0])
        if name not in shellscan.WRAPPERS:
            break
        if "/" in argv[0] and str(Path(argv[0]).parent) not in {"/bin", "/usr/bin"}:
            raise InspectionError("a command wrapper is not a standard system executable")
        wrapped = _peel_wrapper(argv, name)
        options = argv[1:len(argv) - len(wrapped)]
        if name == "env" and wrapped and ASSIGNMENT.fullmatch(wrapped[0]):
            raise InspectionError("command environment assignments cannot be inspected")
        if name in {"env", "sudo", "doas"} and any(
                word in {"-C", "-D", "-S", "--chdir", "--split-string"} or
                word.startswith(("--chdir=", "--split-string=")) for word in options):
            raise InspectionError("a command wrapper changes execution context")
        if name == "nohup" or (name == "time" and any(word == "-o" or word.startswith("--output") for word in options)):
            raise InspectionError("a command wrapper's output files cannot be inspected")
        if name in {"sudo", "doas"} and any(word in {"-i", "--login", "-s", "--shell", "-E", "--preserve-env"} for word in options):
            raise InspectionError("a command wrapper changes execution context")
        if wrapped == argv:
            raise InspectionError("a command wrapper cannot be inspected")
        argv = wrapped
    if not argv or os.path.basename(argv[0]) in shellscan.WRAPPERS:
        raise InspectionError("a command has too many wrappers")
    # A slash names an exact executable. Only standard system executable
    # locations are recognised; a worktree script named `git` is still opaque.
    executable = argv[0]
    if "/" in executable and str(Path(executable).parent) not in {"/bin", "/usr/bin"}:
        return argv, directory, None
    argv[0] = os.path.basename(executable)
    if any("$" in word or "`" in word for word in argv):
        raise InspectionError("command substitutions and variables cannot be inspected")
    if argv[0] in SHELLS:
        if depth >= 4:
            raise InspectionError("a command has too many nested shells")
        # A nested shell without exactly -c/-lc and a literal script is opaque.
        if len(argv) != 3 or argv[1] not in {"-c", "-lc", "-cl"}:
            return argv, directory, None
        return argv, directory, inspect_shell(argv[2], directory, depth + 1)
    if argv[0] == "git":
        index = 1
        while index < len(argv) and argv[index].startswith("-"):
            option = argv[index]
            if option in GIT_GLOBAL_VALUES:
                if index + 1 >= len(argv):
                    raise InspectionError("a Git global option has no value")
                if option in {"-c", "--config-env"}:
                    raise InspectionError("Git configuration overrides can execute uninspectable programs")
                if option in {"--git-dir", "--work-tree"}:
                    raise InspectionError("alternate Git repository paths cannot be inspected")
                if option == "-C":
                    directory = path_at(argv[index + 1], directory)
                index += 2
            elif option in GIT_GLOBAL_FLAGS:
                index += 1
            elif option.startswith(("--config-env=", "-c")):
                raise InspectionError("Git configuration overrides can execute uninspectable programs")
            elif option.startswith(("--git-dir=", "--work-tree=")):
                raise InspectionError("alternate Git repository paths cannot be inspected")
            elif option.startswith("--namespace="):
                index += 1
            elif option.startswith("-C") and len(option) > 2:
                directory = path_at(option[2:], directory)
                index += 1
            else:
                raise InspectionError("an unsupported Git global option cannot be inspected")
        argv = ["git"] + argv[index:]
    return argv, directory, None


def inspect_argv(argv, directory, depth=0):
    if not isinstance(argv, (list, tuple)) or not argv or len(argv) > shellscan.MAX_TOKENS or not all(
            isinstance(word, str) and word and "\0" not in word for word in argv):
        raise InspectionError("command argv must be a nonempty array of words")
    if sum(len(word) for word in argv) > shellscan.MAX_COMMAND:
        raise InspectionError("a command exceeds the inspection limit")
    argv, directory, nested = normalise(argv, Path(directory), depth)
    if nested is not None:
        return [Command(tuple(argv), directory)] + nested
    name, arguments = argv[0], argv[1:]
    writes = shellscan.written_by(name, arguments, str(directory))
    reads = []
    known = name in LITERAL_COMMANDS or name in READERS or name in shellscan.OPERAND_WRITERS or name in shellscan.COPIERS
    known = known or name in {"dd", "mkdir", "rmdir", "chmod", "chown", "chgrp", "cd", "pushd"}
    # ln can create a hardlink whose later writes evade path-based scopes.
    if name == "ln":
        known = False
    if name == "mv":
        writes.extend(shellscan.operands(arguments, shellscan.COPIERS[name])[:-1])
    if name == "sort":
        writes.extend(shellscan.option_values(arguments, "-o", "--output"))
        writes.extend(word[2:] for word in arguments if word.startswith("-o") and len(word) > 2)
        writes.extend(shellscan.option_values(arguments, "-T", "--temporary-directory"))
        if any(word == "--compress-program" or word.startswith("--compress-program=") for word in arguments):
            known = False
    if name == "uniq":
        files = shellscan.operands(arguments, {"-f", "-s", "-w"})
        if len(files) > 1:
            writes.append(files[1])
    if name == "xxd" and ("-r" in arguments or len(shellscan.operands(arguments)) > 1):
        known = False
    if name == "find" and any(word in {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprintf",
                                      "-fls", "-fprint0"} for word in arguments):
        known = False
    if name == "rg" and any(word == "--pre" or word.startswith("--pre=") for word in arguments):
        known = False
    if name == "file" and any(word in {"-C", "--compile"} for word in arguments):
        known = False
    if name in {"mkdir", "rmdir", "chmod", "chown", "chgrp"}:
        writes = shellscan.operands(arguments)
        if name in {"chmod", "chown", "chgrp"}:
            writes = writes[1:]
            if any(word.startswith("--reference") for word in arguments):
                known = False
    if name == "git":
        subcommand = arguments[0] if arguments else ""
        known = subcommand in GIT_READONLY or subcommand in GIT_WRITERS
        if subcommand in GIT_WRITERS:
            repository = next((parent for parent in (directory, *directory.parents)
                               if (parent / ".git").exists()), directory)
            writes.append(str(repository))
            if (repository / ".git").is_file():
                # A worktree's gitdir/commondir writes are outside its folder.
                # A dedicated Git adapter must account for those paths.
                known = False
        if subcommand in {"diff", "show", "grep"}:
            # Rev:path is also a file read, and no path means an unbounded read.
            candidates = shellscan.operands(arguments[1:])
            reads.extend(word.split(":", 1)[-1] for word in candidates if "/" in word or "." in word)
            known = known and bool(reads)
        if subcommand == "remote" and len(arguments) > 1:
            known = arguments[1] in {"get-url", "show"}
        # These options can turn otherwise read-only commands into execution
        # or change which repository is mutated. They need a dedicated adapter.
        if any(word in {"--exec", "--textconv", "--ext-diff", "--output", "--upload-pack", "--receive-pack"} or
               word.startswith(("--exec=", "--output=", "--upload-pack=", "--receive-pack=")) for word in arguments):
            known = False
    if name in READERS:
        files = shellscan.operands(arguments, READER_OPTIONS.get(name, set()))
        if name in {"rg", "grep"}:
            supplied_pattern = any(word in {"-e", "--regexp", "-f", "--file"} or word.startswith(
                ("--regexp=", "--file=")) for word in arguments)
            if not supplied_pattern:
                files = files[1:]
            reads.extend(shellscan.option_values(arguments, "-f", "--file"))
            if not files:
                files = [str(directory)]
        if name == "file":
            reads.extend(shellscan.option_values(arguments, "-f", "--files-from"))
            reads.extend(shellscan.option_values(arguments, "-m", "--magic-file"))
        if name == "find":
            if any(word.startswith("-") and word not in {"-H", "-L", "-P"} for word in arguments):
                known = False
            if not files:
                files = [str(directory)]
        reads.extend(word for word in files if word != "-" and "://" not in word)
    elif name in shellscan.COPIERS:
        files = shellscan.operands(arguments, shellscan.COPIERS[name])
        reads.extend(files if shellscan.option_values(arguments, "-t", "--target-directory") else files[:-1])
    elif name == "dd":
        reads.extend(word[3:] for word in arguments if word.startswith("if="))
    return [Command(tuple(argv), directory, tuple(writes), tuple(reads), not known)]


def inspect_shell(text, directory, depth=0):
    if not isinstance(text, str) or not text.strip() or len(text) > shellscan.MAX_COMMAND or "\0" in text:
        raise InspectionError("a shell command is empty, invalid or exceeds the inspection limit")
    text = text.rstrip()
    try:
        shlex.split(text, posix=True)
    except ValueError:
        raise InspectionError("a shell command has broken quoting") from None
    tokens = shellscan.tokens(text)
    if len(tokens) >= shellscan.MAX_TOKENS:
        raise InspectionError("a shell command exceeds the token limit")
    commands, current, stack = [], [], []
    directory = Path(directory)
    needs_command = False
    changed_directory = False
    connectors = []

    def finish():
        nonlocal directory, changed_directory
        if not current:
            return
        argv, writes, reads = [], [], []
        index = 0
        while index < len(current):
            kind, word = current[index]
            if kind == "word":
                argv.append(word)
                index += 1
                continue
            operator = word.lstrip("0123456789")
            if operator not in REDIRECTS or index + 1 >= len(current) or current[index + 1][0] != "word":
                raise InspectionError("a shell redirection cannot be inspected")
            target = current[index + 1][1]
            if operator in {">", ">>", ">|", "<>", "&>", "&>>"}:
                writes.append(target)
            elif operator == ">&" and not (target.isdigit() or target == "-"):
                writes.append(target)
            if operator in {"<", "<>"}:
                reads.append(target)
            index += 2
        if argv:
            inspected = inspect_argv(argv, directory, depth)
            # The outer shell opens redirections before a command changes cwd.
            commands.append(Command(inspected[0].argv, directory, tuple(writes), tuple(reads)))
            commands.extend(inspected)
            if inspected[0].argv[0] in {"cd", "pushd"}:
                operands = shellscan.operands(list(inspected[0].argv[1:]))
                if len(operands) != 1:
                    raise InspectionError("a directory change needs one literal directory")
                directory = path_at(operands[0], directory)
                if not directory.is_dir():
                    raise InspectionError("a directory change needs an existing directory")
                changed_directory = True
        else:
            commands.append(Command((), directory, tuple(writes), tuple(reads)))
        current.clear()

    for kind, value in tokens:
        if kind == "op" and value in SEPARATORS:
            if value == "\n" and current:
                connectors.append(value)
            if value in {"&&", "||", "|", "|&", "&", ";"}:
                if not current:
                    raise InspectionError("a shell operator has no preceding command")
                connectors.append(value)
            if value == "(" and current:
                raise InspectionError("a subshell must start at a command boundary")
            if value == ")" and needs_command:
                raise InspectionError("a subshell has an incomplete command")
            finish()
            if value != "\n":
                needs_command = value in {"&&", "||", "|", "|&", "("}
            if value == "(":
                stack.append(directory)
            elif value == ")":
                if not stack:
                    raise InspectionError("a shell command has unmatched parentheses")
                directory = stack.pop()
        else:
            current.append((kind, value))
            needs_command = False
    finish()
    if stack or not commands or needs_command:
        raise InspectionError("a shell command is incomplete")
    if changed_directory and any(operator != "&&" for operator in connectors):
        raise InspectionError("directory changes are supported only in an && chain")
    return commands
