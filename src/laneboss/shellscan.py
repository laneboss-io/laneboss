"""Shell commands as the refusal scan reads them (docs/architecture.md, "Refusals"): which files a command writes,
which paths it names, and how much of one command's text another one repeats. Everything is cheap and bounded: only the
first 64 KiB of a command and its first 10,000 tokens are read, and no command is run.

A command is cut into tokens outside quotes (single and double quotes, `$'...'`, backslashes, `$(...)`, `${...}` and
backticks stay inside a word, here-document bodies are skipped, `#` starts a comment), and the tokens into simple
commands at newlines, `;`, `;;`, `&`, `&&`, `||`, `|`, `|&`, `(` and `)`. A simple command writes:

- the target of every output redirection: `>`, `>>`, `>|`, `<>`, `&>`, `&>>`, the same with a descriptor number in front
  (`2>`), and `>&FILE` (`>&2` duplicates a descriptor and writes nothing); /dev/null and the other device files do not
  count;
- by its name, after leading assignments (`NAME=value`) and the wrappers sudo, doas, env, nohup, time, command, builtin,
  exec, nice, timeout, stdbuf and noglob: every operand of tee; the destination of cp, mv, install, ln and rsync (the
  last operand, or `-t DIR`; inside it, when the destination is a directory, several sources are given or it ends with
  `/`); dd's `of=`; the files of `sed -i` and `perl -i`; the operands of touch, truncate, rm, unlink and shred; curl's
  `-o`/`--output` and wget's `-O`/`--output-document`.

`cd DIR` and `pushd DIR` change the directory that later relative paths of the same command are read from, until the
end of the parentheses (a subshell) they are in. A path is
made absolute from that directory and normalised; `~` and `$HOME` are expanded, and a path with any other variable or a
command substitution is not read. Writes made by an interpreter's own code (`python -c`, a script) are not recognised.

The paths a command names are what it writes, its input redirections (`<`) and every operand that looks like a path
(it contains `/`, starts with `~`, or ends with a dot and one to eight letters or digits).

Similarity works on the command's squashed text: lower case, only letters and digits (so quoting, escaping, spacing and
splitting a word with quotes make no difference), at most 16,384 characters, cut into shingles of five consecutive
characters (the whole text when it is shorter). For a later command L and a refused command R, shared is the number of
shingles both have, containment shared/|L| and coverage shared/|R|. L repeats R in other words when containment is at
least 0.8 and coverage is at least 0.8, or coverage at least 0.2 with at least 20 shared shingles, or at least 200
shingles are shared.
"""

import os
import re

MAX_COMMAND = 64 * 1024
MAX_TOKENS = 10000
MAX_SQUASHED = 16384
SHINGLE = 5
OPERATOR = re.compile(r"&>>|&>|&&|\|\||;;|\|&|<<<|<<-|<<|<>|<&|>>|>\||>&|[<>&|;()]")
DELIMITER = re.compile(r"[ \t]*([^\s<>&|;()]+)")
SEPARATORS = {"\n", ";", ";;", "&", "&&", "||", "|", "|&", "(", ")"}
ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")
DEVICES = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/stdin", "/dev/tty", "/dev/zero", "/dev/random",
           "/dev/urandom", "/dev/full"}
WRAPPERS = {"sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-T", "-U"}, "doas": {"-u", "-C"},
            "env": {"-u", "-C", "-S", "--unset", "--chdir", "--split-string"}, "nohup": set(), "time": {"-f", "-o"},
            "command": set(), "builtin": set(), "exec": {"-a"}, "nice": {"-n", "--adjustment"},
            "timeout": {"-s", "-k", "--signal", "--kill-after"}, "stdbuf": {"-i", "-o", "-e"}, "noglob": set()}
COPIERS = {"cp": {"-t", "-S", "--target-directory", "--suffix"}, "mv": {"-t", "-S", "--target-directory", "--suffix"},
           "ln": {"-t", "-S", "--target-directory", "--suffix"},
           "install": {"-m", "-o", "-g", "-t", "-S", "--mode", "--owner", "--group", "--target-directory"},
           "rsync": {"-e", "--rsh", "--exclude", "--include", "--filter", "-f"}}
# Only options with understood file effects are supported. Backup, suffix,
# parents, hardlink and external-program modes need dedicated adapters.
COPIER_OPTIONS = {
    "cp": {
        "flags": "adfHiLnPpRrTuvxZ",
        "long_flags": {"--archive", "--attributes-only", "--copy-contents", "--dereference", "--force",
                       "--interactive", "--no-clobber", "--no-dereference", "--no-target-directory",
                       "--one-file-system", "--recursive", "--remove-destination", "--strip-trailing-slashes",
                       "--verbose", "--help", "--version", "--debug"},
        "values": {"--target-directory", "--no-preserve", "--sparse"},
        "optional_values": {"--context", "--preserve", "--reflink", "--update"},
    },
    "mv": {
        "flags": "finTuvZ",
        "long_flags": {"--force", "--interactive", "--no-clobber", "--no-target-directory",
                       "--strip-trailing-slashes", "--verbose", "--help", "--version", "--context",
                       "--no-copy", "--debug"},
        "values": {"--target-directory"},
        "optional_values": {"--update"},
    },
    "install": {
        "flags": "cpvZ",
        "long_flags": {"--preserve-timestamps", "--verbose", "--help", "--version", "--no-target-directory"},
        "values": {"-m", "-o", "-g", "--target-directory", "--mode", "--owner", "--group"},
        "optional_values": {"--context"},
    },
}
# GNU: the coreutils declarations in COPIERS and the original COPIER_OPTIONS.
# BSD: getopt strings from macOS /usr/bin/{cp,mv,install}, supplied by the review.
# A short value option is inspectable only when both vendors require its value.
COPIER_SHORT_ARITY = {
    "cp": {"gnu_flags": "adfHiLnPpRrTuvxZ", "gnu_values": "St", "bsd_getopt": "HLPRacfilNnprSsvXx"},
    "mv": {"gnu_flags": "finTuvZ", "gnu_values": "St", "bsd_getopt": "fhinv"},
    "install": {"gnu_flags": "cDpvTZ", "gnu_values": "gmotS", "bsd_getopt": "B:bCcD:df:g:h:l:M:m:N:o:pSsT:Uv"},
}


def copier_short_value_arity(name, letter):
    source = COPIER_SHORT_ARITY[name]
    position = source["bsd_getopt"].find(letter)
    bsd_value = position >= 0 and source["bsd_getopt"][position + 1:position + 2] == ":"
    return letter in source["gnu_values"], bsd_value


def copier_file_candidates(arguments, takes):
    """Conservative BSD operands, including '--' and option words after a file."""
    found = []
    index = 0
    options = True
    while index < len(arguments):
        argument = arguments[index]
        index += 1
        if options and not found and argument == "--":
            options = False
        elif options and not found and argument.startswith("-") and argument != "-":
            if argument in takes:
                index += 1
        else:
            found.append(argument)
            options = False
    return found
OPERAND_WRITERS = {"touch": {"-d", "-t", "-r", "--date", "--reference"}, "truncate": {"-s", "-r", "--size", "--reference"},
                   "rm": set(), "unlink": set(), "shred": {"-n", "-s", "--iterations", "--size"},
                   "tee": set()}
PATH_LIKE = re.compile(r"[^\s=:]+\.[A-Za-z0-9]{1,8}")
LETTERS = re.compile(r"[^\W_]+")


def tokens(text, *, reject_ansi_c=False):
    """The command's tokens; strict callers refuse ANSI-C quoting rather than misread escapes."""
    text = text[:MAX_COMMAND]
    found = []
    word = []
    in_word = False
    heredocs = []
    i, n = 0, len(text)

    def flush():
        nonlocal in_word
        if in_word:
            found.append(("word", "".join(word)))
            word.clear()
            in_word = False

    while i < n and len(found) < MAX_TOKENS:
        c = text[i]
        if c == "\\":
            if i + 1 < n and text[i + 1] != "\n":
                word.append(text[i + 1])
                in_word = True
            i += 2
            continue
        if c == "'" or (c == "$" and text[i + 1:i + 2] == "'"):
            if c == "$" and reject_ansi_c:
                raise ValueError("ANSI-C shell quoting cannot be inspected")
            start = i + (2 if c == "$" else 1)
            end = text.find("'", start)
            end = n if end < 0 else end
            word.append(text[start:end])
            in_word = True
            i = end + 1
            continue
        if c == '"':
            j = i + 1
            part = []
            while j < n and text[j] != '"':
                if text[j] == "\\" and j + 1 < n and text[j + 1] in '"\\$`\n':
                    if text[j + 1] != "\n":
                        part.append(text[j + 1])
                    j += 2
                    continue
                part.append(text[j])
                j += 1
            word.append("".join(part))
            in_word = True
            i = j + 1
            continue
        if c == "$" and text[i + 1:i + 2] in ("(", "{"):
            opening = text[i + 1]
            closing = ")" if opening == "(" else "}"
            depth = 0
            j = i + 1
            while j < n:
                if text[j] == opening:
                    depth += 1
                elif text[j] == closing:
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            word.append(text[i:j + 1])
            in_word = True
            i = j + 1
            continue
        if c == "`":
            end = text.find("`", i + 1)
            end = n - 1 if end < 0 else end
            word.append(text[i:end + 1])
            in_word = True
            i = end + 1
            continue
        if c == "#" and not in_word:
            end = text.find("\n", i)
            i = n if end < 0 else end
            continue
        if c in " \t\r":
            flush()
            i += 1
            continue
        if c == "\n":
            flush()
            found.append(("op", "\n"))
            i += 1
            for delimiter, strip in heredocs:
                while i < n:
                    end = text.find("\n", i)
                    line = text[i:] if end < 0 else text[i:end]
                    i = n if end < 0 else end + 1
                    if (line.lstrip("\t") if strip else line) == delimiter:
                        break
            heredocs.clear()
            continue
        if c in "<>&|;()":
            prefix = ""
            if c in "<>" and in_word and "".join(word).isdigit():
                prefix = "".join(word)
                word.clear()
                in_word = False
            flush()
            operator = OPERATOR.match(text, i).group(0)
            found.append(("op", prefix + operator))
            i += len(operator)
            if operator in ("<<", "<<-"):
                match = DELIMITER.match(text, i)
                if match:
                    delimiter = match.group(1).replace("'", "").replace('"', "").replace("\\", "")
                    heredocs.append((delimiter, operator == "<<-"))
                    found.append(("word", delimiter))
                    i = match.end()
            continue
        word.append(c)
        in_word = True
        i += 1
    flush()
    return found



def resolve(word, directory):
    """An absolute, normalised path for a word, or None when it cannot be known without running anything."""
    if not word or "\0" in word or "://" in word or any(ord(character) < 32 for character in word):
        return None
    for home in ("$HOME", "${HOME}"):
        if word == home or word.startswith(home + "/"):
            word = "~" + word[len(home):]
    if "$" in word or "`" in word:
        return None
    if word.startswith("~"):
        word = os.path.expanduser(word)
        if word.startswith("~"):
            return None
    if not word.startswith("/"):
        if not directory:
            return None
        word = os.path.join(directory, word)
    path = os.path.normpath(word)
    if path in DEVICES or path.startswith(("/dev/fd/", "/proc/self/fd/")):
        return None
    return path


def operands(arguments, takes=()):
    """The arguments that are not options (and not the values of options that take one)."""
    found = []
    index = 0
    options = True
    while index < len(arguments):
        argument = arguments[index]
        if options and argument == "--":
            options = False
        elif options and argument.startswith("-") and argument != "-":
            if argument in takes:
                index += 1
        else:
            found.append(argument)
        index += 1
    return found


def option_values(arguments, short, long, *, joined=False):
    """Option values; callers can also recognise a joined short value such as `-tDIR`."""
    found = []
    for index, argument in enumerate(arguments):
        if joined and argument == "--":
            break
        if argument in (short, long) and index + 1 < len(arguments):
            found.append(arguments[index + 1])
        elif argument.startswith(long + "="):
            found.append(argument[len(long) + 1:])
        elif joined and len(short) == 2 and argument.startswith(short) and len(argument) > 2:
            found.append(argument[2:])
    return found


def copier_operands(name, arguments):
    """(files, target, supported) from one literal copier-option grammar.

    A value-taking short option may be separate or first with a joined value.
    Flag-only clusters are supported; clusters mixing flags and values are
    opaque. Long options must match an exact supported name. Consumed values
    are never reinterpreted as options or as the option terminator. A terminator
    must precede the first operand; positional copies need a source and destination.
    """
    spec = COPIER_OPTIONS.get(name)
    if spec is None:  # ln and rsync already need dedicated file-effects adapters.
        return [], [], False
    files, target = [], []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        index += 1
        if argument == "--":
            if files:
                return [], [], False
            files.extend(arguments[index:])
            break
        # BSD getopt stops at the first operand; GNU may permute later options.
        if files and argument.startswith("-"):
            return [], [], False
        if argument.startswith("--"):
            option, joined, value = argument.partition("=")
            if option in spec["long_flags"]:
                if joined:
                    return [], [], False
                continue
            if option in spec["optional_values"]:
                if not joined:
                    continue
            elif option not in spec["values"]:
                return [], [], False
            elif not joined:
                if index >= len(arguments):
                    return [], [], False
                value = arguments[index]
                index += 1
        elif argument.startswith("-") and argument != "-":
            option, value = argument[:2], argument[2:]
            gnu_value, bsd_value = copier_short_value_arity(name, argument[1])
            if gnu_value != bsd_value:
                return [], [], False
            if option not in spec["values"]:
                if any(flag not in spec["flags"] or any(copier_short_value_arity(name, flag))
                       for flag in argument[1:]):
                    return [], [], False
                continue
            if len(argument) == 2:
                if index >= len(arguments):
                    return [], [], False
                value = arguments[index]
                index += 1
        else:
            files.append(argument)
            continue
        if not value or any(c in value for c in "$`*?[]{}") or value.startswith("~") or any(ord(c) < 32 for c in value):
            return [], [], False
        if option in {"-t", "--target-directory"}:
            if target:
                return [], [], False
            target.append(value)
    if not target and len(files) < 2:
        return [], [], False
    sources = files if target else files[:-1]
    # BSD cp copies a slash-ended directory's contents, unlike GNU cp.
    if name == "cp" and any(source.endswith("/") for source in sources):
        return [], [], False
    return files, target, True


def unwrap(argv):
    for _ in range(8):
        if not argv or os.path.basename(argv[0]) not in WRAPPERS:
            break
        name = os.path.basename(argv[0])
        takes = WRAPPERS[name]
        argv = argv[1:]
        while argv and (argv[0].startswith("-") or (name == "env" and ASSIGNMENT.match(argv[0]))):
            option = argv.pop(0)
            if option == "--":
                break
            if option in takes and argv:
                argv.pop(0)
        if name == "timeout" and argv:
            argv = argv[1:]
    return argv


def in_place(arguments, perl=False):
    for argument in arguments:
        if argument == "--in-place" or argument.startswith("--in-place="):
            return True
        if argument.startswith("-") and not argument.startswith("--") and "i" in argument[1:].split(".")[0]:
            if perl or argument[1:2] != "e":
                return True
    return False


def written_by(name, arguments, directory):
    """The words a command of this name writes, by its arguments."""
    if name in OPERAND_WRITERS:
        return operands(arguments, OPERAND_WRITERS[name])
    if name in COPIERS:
        if name in COPIER_OPTIONS:
            found, target, supported = copier_operands(name, arguments)
            if not supported:
                # The org hook treats this command as opaque. The
                # workaround detector has no opaque outcome: retain possible
                # source and destination writes instead of silently losing them.
                gnu_files = operands(arguments, COPIERS[name])
                bsd_files = copier_file_candidates(arguments, COPIERS[name])
                found = list(dict.fromkeys(gnu_files + bsd_files))
                target = option_values(arguments, "-t", "--target-directory", joined=True)
                writes = list(found)
                for destination in dict.fromkeys(target):
                    writes.extend(os.path.join(destination, os.path.basename(source.rstrip("/")))
                                  for source in found)
                # Each interpretation has its own positional destination.
                for files in (gnu_files, bsd_files):
                    if len(files) < 2:
                        continue
                    destination, sources = files[-1], files[:-1]
                    resolved = resolve(destination, directory)
                    if len(sources) > 1 or destination.endswith("/") or (resolved and os.path.isdir(resolved)):
                        writes.extend(os.path.join(destination, os.path.basename(source.rstrip("/")))
                                      for source in sources)
                return writes or [directory]
        else:
            target = option_values(arguments, "-t", "--target-directory", joined=True) if name != "rsync" else []
            found = operands(arguments, COPIERS[name])
        if target:
            return [os.path.join(target[0], os.path.basename(source.rstrip("/"))) for source in found]
        if len(found) < 2:
            return []
        destination, sources = found[-1], found[:-1]
        resolved = resolve(destination, directory)
        if len(sources) > 1 or destination.endswith("/") or (resolved and os.path.isdir(resolved)):
            return [os.path.join(destination, os.path.basename(source.rstrip("/"))) for source in sources]
        return [destination]
    if name == "dd":
        return [argument[3:] for argument in arguments if argument.startswith("of=")]
    if name in ("sed", "gsed", "perl"):
        perl = name == "perl"
        if not in_place(arguments, perl):
            return []
        scripts = {"-e", "-f", "--expression", "--file", "-E"} if not perl else {"-e", "-E", "-M", "-I"}
        files = operands(arguments, scripts | ({"-l"} if not perl else set()))
        given = any(argument in scripts or argument.startswith(("--expression=", "--file=")) for argument in arguments)
        return files if given else files[1:]
    if name == "curl":
        return option_values(arguments, "-o", "--output")
    if name == "wget":
        return option_values(arguments, "-O", "--output-document")
    return []


def analyse(command, directory):
    """(writes, named): the absolute paths the command writes and the ones it names, each sorted without repeats."""
    writes, named = set(), set()

    def add(where, word, here):
        path = resolve(word, here)
        if path is not None:
            where.add(path)
            named.add(path)

    def simple(words, here):
        """One simple command; returns the directory the commands after it are read from."""
        argv = []
        index = 0
        redirects = []
        while index < len(words):
            kind, value = words[index]
            if kind == "op":
                target = words[index + 1][1] if index + 1 < len(words) and words[index + 1][0] == "word" else None
                index += 2 if target is not None else 1
                if target is not None:
                    redirects.append((value.lstrip("0123456789"), target))
                continue
            argv.append(value)
            index += 1
        for operator, target in redirects:
            if operator in (">", ">>", ">|", "&>", "&>>", "<>") or (
                    operator == ">&" and not (target.isdigit() or target == "-")):
                add(writes, target, here)
            elif operator == "<":
                add(named, target, here)
        while argv and ASSIGNMENT.match(argv[0]):
            argv.pop(0)
        argv = unwrap(argv)
        if not argv:
            return here
        name = os.path.basename(argv[0])
        if name in ("cd", "pushd"):
            target = next((argument for argument in argv[1:] if not argument.startswith("-")), "~")
            return resolve(target, here) or here
        for word in written_by(name, argv[1:], here):
            add(writes, word, here)
        for word in operands(argv[1:]):
            if not word.startswith("-") and "://" not in word and (
                    "/" in word or word.startswith("~") or PATH_LIKE.fullmatch(word)):
                add(named, word, here)
        return here

    # A directory changed inside parentheses (a subshell) is restored after them.
    outer = []
    current = []
    for kind, value in tokens(command) + [("op", "\n")]:
        if kind == "op" and value in SEPARATORS:
            if current:
                directory = simple(current, directory)
                current = []
            if value == "(":
                outer.append(directory)
            elif value == ")" and outer:
                directory = outer.pop()
        else:
            current.append((kind, value))
    return sorted(writes), sorted(named)


def shingles(text):
    squashed = "".join(LETTERS.findall(text[:MAX_COMMAND].lower()))[:MAX_SQUASHED]
    if len(squashed) < SHINGLE:
        return frozenset([squashed]) if squashed else frozenset()
    return frozenset(squashed[index:index + SHINGLE] for index in range(len(squashed) - SHINGLE + 1))


def reworded(later, refused):
    """{"containment", "coverage"} when the later command's shingles repeat the refused command's in other words, else
    None."""
    if not later or not refused:
        return None
    shared = len(later & refused)
    containment = shared / len(later)
    coverage = shared / len(refused)
    if containment >= 0.8 and (coverage >= 0.8 or (coverage >= 0.2 and shared >= 20) or shared >= 200):
        return {"containment": round(containment, 3), "coverage": round(coverage, 3)}
    return None
