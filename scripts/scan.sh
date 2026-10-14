#!/bin/sh
# Publication scan: fails on private-key headers, long secret-like tokens, non-loopback IPv4
# addresses and email addresses and, when LANEBOSS_SCAN_DENYLIST names a file, on its case-insensitive
# regular expressions (one per line; '#' starts a comment). It reports path, line and rule only,
# never the matched text. --staged scans the content staged for commit instead of the files.
set -eu
staged=0
if [ "${1:-}" = "--staged" ]; then
    staged=1
    shift
fi
scanner_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
root=${1:-$scanner_root}
exec python3 - "$root" "$staged" "${LANEBOSS_SCAN_DENYLIST:-}" "$scanner_root" <<'PY'
import bisect
import json
import os
from pathlib import Path
import re
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
staged = sys.argv[2] == "1"
denylist_file = sys.argv[3]
scanner_root = Path(sys.argv[4])
vendor_layouts = None


def layouts():
    global vendor_layouts
    if vendor_layouts is None:
        source = scanner_root / "internal/orghook/vendor-files.json"
        if not source.is_file():
            source = scanner_root / "scripts/vendor-files.json"
        try:
            rows = json.loads(source.read_text())
            result = {}
            for row in rows:
                home = row["home"]
                names = [row["settings"]] + ([row["config"]] if row["config"] else [])
                if not home.startswith(".") or home.casefold() in result:
                    raise ValueError("invalid vendor home")
                for name in [home] + names:
                    if name in {"", ".", ".."} or Path(name).name != name:
                        raise ValueError("invalid vendor file")
                result[home.casefold()] = {(name.casefold(),) for name in names}
            if not result:
                raise ValueError("empty vendor layout")
        except (OSError, UnicodeError, ValueError, TypeError, KeyError):
            error("renderer vendor layout is missing or invalid")
        vendor_layouts = result
    return vendor_layouts


def vendor_entry(path):
    parts = Path(path).parts
    for index in range(len(parts) - 3):
        if tuple(part.casefold() for part in parts[index:index + 2]) == (".laneboss", "instances"):
            owned = layouts().get(parts[index + 3].casefold())
            if owned is not None:
                return tuple(part.casefold() for part in parts[index + 4:]), owned
    return None


def runtime_file(path):
    entry = vendor_entry(path)
    if entry is None:
        return False
    suffix, owned = entry
    return bool(suffix) and suffix not in owned


def fallback_paths(root):
    for directory, names, files in os.walk(root, followlinks=False):
        def allowed(name):
            path = Path(directory) / name
            if runtime_file(path) or (vendor_entry(path) is not None and path.is_symlink()):
                runtime_paths.append(str(path.relative_to(root)))
                return False
            return name not in {".git", "__pycache__"} and not name.endswith((".pyc", ".pyo"))
        names[:] = [name for name in names if allowed(name)]
        for name in files:
            if allowed(name):
                yield Path(directory) / name


patterns = {
    "private-key-header": re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    "long-secret-like-token": re.compile(rb"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/=-]{40,}(?![A-Za-z0-9_+/=-])"),
    "email-address": re.compile(rb"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"),
    "non-loopback-ipv4": re.compile(rb"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])"),
}


def error(message):
    print("SCAN ERROR: " + message, file=sys.stderr)
    raise SystemExit(2)


denylist = []
if denylist_file:
    try:
        lines = Path(denylist_file).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        error("cannot read the denylist file named by LANEBOSS_SCAN_DENYLIST")
    for number, line in enumerate(lines, 1):
        rule = line.strip()
        if not rule or rule.startswith("#"):
            continue
        try:
            compiled = re.compile(rule, re.IGNORECASE)
        except re.error:
            error("denylist line {}: invalid regular expression".format(number))
        if compiled.search("") is not None:
            error("denylist line {}: invalid regular expression: it matches the empty string".format(number))
        denylist.append((number, compiled))
    if not denylist:
        error("the denylist file named by LANEBOSS_SCAN_DENYLIST holds no rule")


def git(*arguments, **options):
    return subprocess.run(["git", "-C", str(root), *arguments], capture_output=True, check=True, **options).stdout


items = []
runtime_paths = []
if staged:
    try:
        listing = git("ls-files", "-s", "-z")
    except (OSError, subprocess.CalledProcessError):
        error("--staged needs a Git work tree")
    entries = []
    for entry in listing.split(b"\0"):
        if entry:
            meta, name = entry.split(b"\t", 1)
            mode, blob = meta.split()[:2]
            relative = name.decode("utf-8", "surrogateescape")
            if runtime_file(relative) or (mode == b"120000" and vendor_entry(relative) is not None):
                runtime_paths.append(relative)
            elif mode != b"160000":
                entries.append((relative, blob))
    if entries:
        batch = git("cat-file", "--batch", input=b"".join(blob + b"\n" for _, blob in entries))
        position = 0
        for name, blob in entries:
            end = batch.index(b"\n", position)
            size = int(batch[position:end].split()[2])
            items.append((name, batch[end + 1:end + 1 + size]))
            position = end + 1 + size + 1
else:
    if not root.is_dir():
        error("the scan root is missing or is not a directory")
    paths = []
    try:
        git_root = Path(subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"], stderr=subprocess.DEVNULL
        ).decode("utf-8").strip()).resolve()
        tracked = subprocess.check_output(
            ["git", "-C", str(git_root), "ls-files", "-z"], stderr=subprocess.DEVNULL
        ).split(b"\0")
        for name in tracked:
            if not name:
                continue
            path = git_root / name.decode("utf-8")
            try:
                path.relative_to(root)
            except ValueError:
                continue
            if runtime_file(path) or (path.is_symlink() and vendor_entry(path) is not None):
                runtime_paths.append(str(path.relative_to(root)))
            else:
                paths.append(path)
    except (OSError, subprocess.CalledProcessError, UnicodeError):
        for path in fallback_paths(root):
            relative = path.relative_to(root)
            if ".git" in relative.parts or "__pycache__" in relative.parts or path.suffix == ".pyc":
                continue
            paths.append(path)
    for path in sorted(paths):
        if not path.is_file():
            continue
        try:
            content = path.read_bytes()
        except OSError:
            content = None
        items.append((str(path.relative_to(root)), content))

SHOWN = 200
problems = [(relative, 0, "vendor-runtime-not-publishable") for relative in runtime_paths]
checked = 0
for relative, content in sorted(items, key=lambda item: item[0]):
    checked += 1
    if content is None:
        problems.append((relative, 0, "unreadable-file"))
        continue
    newlines = [match.start() for match in re.finditer(b"\n", content)]
    for rule, pattern in patterns.items():
        # go.sum holds the published checksums of public Go modules ("h1:" plus base64), which the token rule
        # cannot tell from a secret; only that rule skips it, and only for that exact file name.
        if rule == "long-secret-like-token" and relative.rsplit("/", 1)[-1] == "go.sum":
            continue
        for match in pattern.finditer(content):
            if rule == "non-loopback-ipv4":
                address = match.group()
                if address == b"127.0.0.1" or any(int(part) > 255 for part in address.split(b".")):
                    continue
            problems.append((relative, bisect.bisect_left(newlines, match.start()) + 1, rule))
    if denylist:
        text = content.decode("utf-8", "replace")
        text_newlines = [match.start() for match in re.finditer("\n", text)]
        for number, pattern in denylist:
            for match in pattern.finditer(text):
                if match.end() == match.start():
                    error("denylist line {}: invalid regular expression: it produced an empty match".format(number))
                problems.append((relative, bisect.bisect_left(text_newlines, match.start()) + 1,
                                 "denylist-line-{}".format(number)))
if problems:
    for path, line, rule in problems[:SHOWN]:
        print("SCAN FAIL {}:{} {}".format(path, line, rule))
    if len(problems) > SHOWN:
        print("SCAN FAIL: {} more issue(s) not shown".format(len(problems) - SHOWN))
    print("SCAN FAIL: {} issue(s), {} file(s)".format(len(problems), checked))
    raise SystemExit(1)
if not staged and checked == 0:
    error("the scan checked no file")
print("SCAN PASS: {} file(s); no private-key headers, long tokens, non-loopback IPv4 or email addresses{}".format(
    checked, "; no match for {} denylist rule(s)".format(len(denylist)) if denylist_file else ""))
PY
