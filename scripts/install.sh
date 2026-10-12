#!/bin/sh
# Install the launcher from this checkout or unpacked archive into PREFIX/share/laneboss/versions/VERSION
# and point PREFIX/bin/laneboss at it. No administrator rights, no network and no pip are needed.
# Installed versions are immutable: installing another version switches the link and keeps the old
# version's directory, so a rollback is a relink. LANEBOSS_PYTHON chooses the interpreter (3.11 or newer).
# The checkout's plugins/ directory, when it has one, is copied to VERSION/plugins/ and listed in the manifest like
# the package's files; laneboss plugin path prints where it is. Nothing is installed into any agent program.
set -eu
usage="usage: install.sh [--prefix DIR]   (default prefix: ~/.local)"
prefix=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --prefix)
            if [ "$#" -lt 2 ] || [ -z "$2" ]; then
                echo "install: --prefix needs a directory; $usage" >&2
                exit 2
            fi
            prefix=$2
            shift 2
            ;;
        --prefix=?*)
            prefix=${1#--prefix=}
            shift
            ;;
        -h|--help)
            echo "$usage"
            exit 0
            ;;
        *)
            echo "install: unknown argument; $usage" >&2
            exit 2
            ;;
    esac
done
if [ -z "$prefix" ]; then
    if [ -z "${HOME:-}" ]; then
        echo "install: HOME is not set; pass --prefix DIR" >&2
        exit 2
    fi
    prefix=$HOME/.local
fi
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
probe='import sqlite3, sys, tomllib; sys.exit(0 if sys.version_info >= (3, 11) else 1)'
python=""
if [ -n "${LANEBOSS_PYTHON:-}" ]; then
    if "$LANEBOSS_PYTHON" -I -c "$probe" >/dev/null 2>&1; then
        python=$LANEBOSS_PYTHON
    else
        echo "install: LANEBOSS_PYTHON does not run Python 3.11 or newer with sqlite3 and tomllib" >&2
        exit 2
    fi
else
    for candidate in python3.14 python3.13 python3.12 python3.11 python3; do
        if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -I -c "$probe" >/dev/null 2>&1; then
            python=$candidate
            break
        fi
    done
    if [ -z "$python" ]; then
        echo "install: no Python 3.11 or newer with sqlite3 and tomllib on PATH (tried python3.14," \
            "python3.13, python3.12, python3.11 and python3); install one or set LANEBOSS_PYTHON" >&2
        exit 2
    fi
fi
exec "$python" -I - "$root" "$prefix" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import sys
import tempfile

root = Path(sys.argv[1])
prefix = Path(os.path.abspath(os.path.expanduser(sys.argv[2])))
source = root / "src" / "laneboss"


def fail(message):
    print("install: " + message, file=sys.stderr)
    raise SystemExit(2)


if not (source / "identity.py").is_file() or not (source / "cli.py").is_file():
    fail("no launcher package at " + str(source))
sys.dont_write_bytecode = True
sys.path.insert(0, str(root / "src"))
from laneboss import identity  # noqa: E402

program, version, package = identity.PROGRAM, identity.VERSION, source.name
if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]+)?", version) is None or ".." in version:
    fail("the package version must look like 1.2.3 or 1.2.3-label")
files = sorted(path for path in source.rglob("*") if path.is_file()
               and "__pycache__" not in path.relative_to(source).parts and path.suffix not in (".pyc", ".pyo"))
plugins = root / "plugins"
plugin_files = sorted(path for path in plugins.rglob("*") if path.is_file()) if plugins.is_dir() else []
# A plugin file the checkout marks executable (a script the plugin runs) is executable in the installed copy too.
plugin_programs = sorted("plugins/" + path.relative_to(plugins).as_posix() for path in plugin_files
                         if path.stat().st_mode & 0o111)
versions = prefix / "share" / program / "versions"
target = versions / version
bindir = prefix / "bin"
link = bindir / program
if os.path.lexists(str(link)) and not link.is_symlink():
    fail("{} exists and is not a link; move it away first".format(link))
try:
    versions.mkdir(parents=True, exist_ok=True)
    bindir.mkdir(parents=True, exist_ok=True)
except OSError as error:
    fail("cannot create directories under {}: {}".format(prefix, error.strerror))


bootstrap = (
    '"""Start the launcher from this version directory; written by scripts/install.sh."""\n'
    "import os\nimport sys\n\n"
    "sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))\n\n"
    "from {}.cli import main  # noqa: E402\n\n"
    "raise SystemExit(main())\n"
).format(package)
launcher = ("#!/bin/sh\n# {} {}: written by scripts/install.sh; this directory is never changed.\n"
            'exec {} -I -B {} "$@"\n').format(program, version, shlex.quote(sys.executable),
                                             shlex.quote(str(target / "lib" / (program + "-launch.py"))))
# Every installed file, the launcher and its bootstrap included, with the bytes it must hold.
contents = {"lib/{}/{}".format(package, path.relative_to(source).as_posix()): path.read_bytes() for path in files}
contents.update(("plugins/" + path.relative_to(plugins).as_posix(), path.read_bytes()) for path in plugin_files)
contents["lib/{}-launch.py".format(program)] = bootstrap.encode("utf-8")
contents["bin/" + program] = launcher.encode("utf-8")
expected = {relative: hashlib.sha256(data).hexdigest() for relative, data in contents.items()}
manifest = "version {}\n".format(version) + "".join(
    "{}  {}\n".format(expected[relative], relative) for relative in sorted(expected))


def installed_problem():
    """Why the installed directory differs from its manifest, or None. Links and extra files count."""
    try:
        if (target / "MANIFEST").read_text(encoding="utf-8") != manifest:
            return "its manifest describes other content"
    except OSError:
        return "its manifest cannot be read"
    found = {}
    for path in sorted(target.rglob("*")):
        relative = path.relative_to(target).as_posix()
        if path.is_symlink():
            return relative + " is a link"
        if path.is_dir() or relative == "MANIFEST":
            continue
        try:
            found[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            return relative + " cannot be read"
    for relative in sorted(set(expected) | set(found)):
        if relative not in found:
            return relative + " is missing"
        if relative not in expected:
            return relative + " is not part of the version"
        if found[relative] != expected[relative]:
            return relative + " was changed"
    # A mode is part of a plugin file's content, as a changed file is: a program of the checkout is mode 755 in the
    # installed copy and no other plugin file has an executable bit, whatever the files hold.
    for relative in sorted(expected):
        if relative.startswith("plugins/"):
            mode = stat.S_IMODE((target / relative).stat().st_mode)
            if (mode != 0o755) if relative in plugin_programs else (mode & 0o111 != 0):
                return relative + " has another mode (mode 755 for a program, no executable bit for any other file)"
    return None


if not target.exists():
    stage = Path(tempfile.mkdtemp(prefix=".stage-", dir=str(versions)))
    try:
        for relative in sorted(contents):
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(contents[relative])
        (stage / "bin" / program).chmod(0o755)
        for relative in plugin_programs:
            (stage / relative).chmod(0o755)
        (stage / "MANIFEST").write_text(manifest, encoding="utf-8")
        os.rename(str(stage), str(target))
    except OSError:
        if not target.exists():
            fail("cannot write {}".format(target))
    finally:
        if stage.exists():
            shutil.rmtree(str(stage))
problem = installed_problem()
if problem is not None:
    fail("version {} is already installed at {} and differs from this content: {}; installed versions are "
         "immutable, so give new content a new version, or remove the damaged version directory by hand".format(
             version, target, problem))
temporary = bindir / ".{}.{}.link".format(program, os.getpid())
os.symlink(os.path.relpath(str(target / "bin" / program), str(bindir)), str(temporary))
os.replace(str(temporary), str(link))
print(json.dumps({"installed": version, "directory": str(target), "link": str(link), "python": sys.executable},
                 sort_keys=True))
PY
