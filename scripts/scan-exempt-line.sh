#!/bin/sh
# Print an entry only; the gate supplies the list kept beside its pinned scanner.
# Add the reason/approval comment before using the entry.
set -eu
if [ "$#" -ne 2 ]; then
    printf 'usage: scripts/scan-exempt-line.sh <path> <line number>\n' >&2
    exit 2
fi
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
exec python3 - "$root" "$1" "$2" <<'PY'
import hashlib
from pathlib import Path
import re
import sys


def error(message):
    print("scan-exempt-line: " + message, file=sys.stderr)
    raise SystemExit(2)


root = Path(sys.argv[1])
relative = sys.argv[2]
if (any(part in {"", ".", ".."} for part in relative.split("/"))
        or any(char in relative for char in "\t\r\n\0\\")):
    error("path must be a canonical repo-relative path")
if re.fullmatch(r"[1-9][0-9]*", sys.argv[3]) is None:
    error("line number must be a positive integer")
try:
    number = int(sys.argv[3])
    path = root / relative
    path.resolve(strict=True).relative_to(root)
    content = path.read_bytes()
except (OSError, ValueError, RuntimeError):
    error("cannot read a file inside the repository")
lines = content.split(b"\n")
if not content or content.endswith(b"\n"):
    lines.pop()
if number > len(lines):
    error("line number is outside the file")
print(relative + "\t" + hashlib.sha256(lines[number - 1]).hexdigest()[:32])
PY
