#!/usr/bin/env python3
"""with_identity.py: run ONE command under ONE named identity, with an environment built from scratch.

The identity comes from a TOML file the person keeps (see README.md). The command gets only the identity's
own variables and, of the caller's environment, only PATH, HOME, TMPDIR, LANG and TERM, so the machine's
ambient identity cannot reach it. A problem is always one line starting `refused:` on standard error and
exit 2; when everything checks out the program replaces itself with the command (os.execve), so the
command's exit status is the wrapper's and no wrapper process is left behind.
"""
import os
import re
import signal
import stat
import sys

try:
    import tomllib  # Python 3.11 or newer
except ModuleNotFoundError:  # an interpreter older than the specification allows
    print("internal error", file=sys.stderr)
    sys.exit(70)

MAX_BYTES = 64 * 1024
NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")
PROJECT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")
KEYS = ("config_dir", "project", "key_file")
COPIED = ("PATH", "HOME", "TMPDIR", "LANG", "TERM")
FALLBACK_PATH = "/usr/bin:/bin"
DENIED = (("auth", "login"), ("auth", "activate-service-account"), ("auth", "application-default"),
          ("config", "set"), ("config", "configurations"))
USAGE = ("usage: with_identity.py --identities FILE NAME -- COMMAND [ARGUMENT ...]\n"
         "\n"
         "Run COMMAND under the identity NAME of the identities file FILE, with an environment built from\n"
         "scratch: of the caller's environment only PATH, HOME, TMPDIR, LANG and TERM are copied. Every\n"
         "refusal is one line starting `refused:` on standard error and exit 2.")


def refuse(reason):
    """The one shape a refusal has: one line naming the key and the rule, never a value, and exit 2."""
    print("refused: " + reason, file=sys.stderr)
    raise SystemExit(2)


def status(path):
    """The file's status, or None when it cannot be reached. Only its status is read, never its content."""
    try:
        return os.stat(path)
    except (OSError, ValueError):
        return None


def parse(argv):
    """(FILE, NAME, COMMAND, ARGUMENTS) from the command line, or a refusal. -h and --help print usage."""
    if argv and argv[0] in ("-h", "--help"):
        print(USAGE)
        raise SystemExit(0)
    if len(argv) < 5 or argv[0] != "--identities" or argv[3] != "--" or not argv[4]:
        refuse("the command line must be --identities FILE NAME -- COMMAND [ARGUMENT ...]")
    return argv[1], argv[2], argv[4], argv[5:]


def load(path):
    """The identities file parsed as TOML, or a refusal."""
    info = status(path)
    if info is None:
        refuse("the identities file was not found")
    if not stat.S_ISREG(info.st_mode):
        refuse("the identities file is not a regular file")
    if info.st_size > MAX_BYTES:
        refuse("the identities file is larger than 64 KiB")
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        refuse("the identities file could not be read")
    try:
        return tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError):
        refuse("the identities file is not valid TOML")


def check(data, name):
    """The validated table of NAME, or a refusal. Every rule of the specification, in its order."""
    version = data.get("schema_version")
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        refuse("schema_version must be the integer 1")
    for key in data:
        if key not in ("schema_version", "identities"):
            refuse("only schema_version and identities are allowed at the top level")
    identities = data.get("identities")
    if not isinstance(identities, dict):
        refuse("identities must be a table")
    table = identities.get(name)
    if not isinstance(table, dict):
        refuse("identities.%s is not a table" % name)
    for key in table:
        if key not in KEYS:
            refuse("identities.%s has a key that is not allowed (only config_dir, project and key_file)" % name)
    if "config_dir" not in table:
        refuse("identities.%s.config_dir is required" % name)
    config_dir = table["config_dir"]
    if not isinstance(config_dir, str):
        refuse("identities.%s.config_dir must be a string" % name)
    if not config_dir.startswith("/"):
        refuse("identities.%s.config_dir must be an absolute path" % name)
    info = status(config_dir)
    if info is None or not stat.S_ISDIR(info.st_mode):
        refuse("identities.%s.config_dir is not an existing directory" % name)
    if "project" in table:
        project = table["project"]
        if not isinstance(project, str) or not PROJECT.fullmatch(project):
            refuse("identities.%s.project must match [a-z][a-z0-9-]{4,28}[a-z0-9]" % name)
    if "key_file" in table:
        key_file = table["key_file"]
        if not isinstance(key_file, str) or not key_file.startswith("/"):
            refuse("identities.%s.key_file must be an absolute path" % name)
        info = status(key_file)
        if info is None or not stat.S_ISREG(info.st_mode):
            refuse("identities.%s.key_file is not an existing regular file" % name)
    return table


def base_environment():
    """The command's starting environment: the caller's five allowed variables, and nothing else."""
    return {key: os.environ[key] for key in COPIED if key in os.environ}


def identity_variables(name, table):
    """The variables the identity brings. An absent key brings nothing: no empty value, no fallback."""
    variables = {"CLOUDSDK_CONFIG": table["config_dir"], "WITH_IDENTITY_NAME": name}
    if "project" in table:
        variables["CLOUDSDK_CORE_PROJECT"] = table["project"]
    if "key_file" in table:
        variables["GOOGLE_APPLICATION_CREDENTIALS"] = table["key_file"]
    return variables


def executable(command, env):
    """The file COMMAND runs, or None when it is not there. A shell is never used."""
    if "/" in command:
        candidates = [command]
    else:
        directories = (env.get("PATH") or FALLBACK_PATH).split(":")
        candidates = [os.path.join(directory, command) for directory in directories if directory]
    for candidate in candidates:
        info = status(candidate)
        if info is not None and stat.S_ISREG(info.st_mode) and os.access(candidate, os.X_OK):
            return candidate
    return None


def denied(command, arguments):
    """True for the plain login and configuration forms that this wrapper refuses."""
    return os.path.basename(command) == "gcloud" and tuple(arguments[:2]) in DENIED


def main(argv):
    path, name, command, arguments = parse(argv)
    if not NAME.fullmatch(name):
        refuse("NAME must match [a-z0-9][a-z0-9-]{0,31}")
    table = check(load(path), name)
    env = base_environment()
    found = executable(command, env)
    if found is None:
        refuse("the command was not found")
    if denied(found, arguments):
        refuse("this wrapper does not log in or change the configuration")
    env.update(identity_variables(name, table))
    # A caller may have left SIGPIPE or SIGXFSZ ignored: reset them so that a broken pipe or a write past the
    # file-size limit fails with the signal instead of becoming an error exit.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    signal.signal(signal.SIGXFSZ, signal.SIG_DFL)
    os.execve(found, [command] + arguments, env)


def run():
    try:
        main(sys.argv[1:])
    except Exception:  # anything the specification does not name: one line, never a traceback
        print("internal error", file=sys.stderr)
        return 70
    print("internal error", file=sys.stderr)
    return 70


if __name__ == "__main__":
    sys.exit(run())
