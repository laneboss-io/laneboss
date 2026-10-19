"""Shared black-box primitives; no imports from the product.

Process lifetime, clean child environments and read-back evidence preserve the
intent of the wave-zero harness. Runtime entry points require Ubuntu 24.04.
"""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import shutil
import tarfile
import time
import uuid


ROOT = Path(__file__).resolve().parents[2]
MAX_JSON = 16 * 1024 * 1024
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}\Z")


class Failure(RuntimeError):
    """A typed failure, never a successful empty observation."""

    def __init__(self, message, code="integrity", owner="lb-v2-e2e"):
        super().__init__(message)
        self.code = code
        self.owner = owner

    def wire(self):
        return {"code": self.code, "message": str(self),
                "instead": "Retain evidence and repair the named dependency.",
                "retryable": False, "owner": self.owner}


class OwnerWait(Failure):
    """An unperformed owner ceremony; never an approval or a passed row."""

    def __init__(self, step, owner, instead):
        super().__init__("waiting for owner: " + step, "prerequisite_missing", owner)
        self.instead = instead

    def wire(self):
        return {**super().wire(), "instead": self.instead}


def require(condition, message, code="integrity"):
    if not condition:
        raise Failure(message, code)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key", "invalid_request")
        result[key] = value
    return result


def bad_number(_value):
    raise Failure("nonfinite JSON number", "invalid_request")


def decode(data):
    require(len(data) <= MAX_JSON, "JSON input exceeds bound", "invalid_request")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=bad_number)
    except (UnicodeError, ValueError) as error:
        raise Failure("invalid UTF-8 JSON", "invalid_request") from error


def load(path):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode), "JSON input is not a regular file")
    require(info.st_size <= MAX_JSON, "JSON input exceeds bound")
    return decode(path.read_bytes())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)
            + "\n").encode("utf-8")


def atomic_bytes(path, data, mode=0o600):
    path = Path(path)
    temporary = path.with_name("." + path.name + "-" + uuid.uuid4().hex[:12])
    with temporary.open("xb") as output:
        os.fchmod(output.fileno(), mode)
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def save(path, value, mode=0o600):
    atomic_bytes(path, encoded(value), mode)


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def bytes_hash(data):
    return hashlib.sha256(data).hexdigest()


def copy_verified(source, target):
    expected = sha256(source)
    shutil.copyfile(source, target)
    require(sha256(source) == sha256(target) == expected, "copied input read-back differs")


def verify_tar_inventory(path, inventory):
    expected = {item["path"]: item for item in inventory}
    require(len(expected) == len(inventory), "duplicate archive input")
    seen, members = set(), set()
    with tarfile.open(path, "r:*") as archive:
        for member in archive:
            require(member.name not in members, "duplicate archive member")
            members.add(member.name)
            require(member.isdir() or member.isfile(), "linked/special archive member")
            if member.isdir():
                continue
            require(member.name in expected, "archive member has no retained input digest")
            source = archive.extractfile(member)
            require(source is not None, "unreadable archive member")
            digest, size = hashlib.sha256(), 0
            with source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(block)
                    size += len(block)
            require(size == member.size == expected[member.name]["bytes"] and
                    digest.hexdigest() == expected[member.name]["sha256"],
                    "archive member read-back differs")
            seen.add(member.name)
    require(seen == set(expected), "archive omitted retained input bytes")


def exact_keys(value, required, optional=()):
    require(isinstance(value, dict), "expected JSON object", "invalid_request")
    require(set(required) <= value.keys() <= set(required) | set(optional),
            "missing or unknown JSON field", "invalid_request")


def integer(value, minimum=0, maximum=2**53 - 1):
    return type(value) is int and minimum <= value <= maximum


def beneath(root, relative, *, exists=True):
    """Reject every link component, traversal and noncanonical evidence name."""
    root = Path(root).resolve(strict=True)
    require(isinstance(relative, str) and relative != "", "empty relative path")
    parts = PurePosixPath(relative)
    require(not parts.is_absolute() and str(parts) == relative
            and all(part not in ("", ".", "..") for part in parts.parts),
            "noncanonical relative path")
    path = root
    for part in parts.parts:
        path = path / part
        require(not path.is_symlink(), "linked evidence or input path")
    require(path.resolve(strict=exists).is_relative_to(root), "path escapes scope")
    return path


def regular(path):
    path = Path(path)
    require(path.is_absolute(), "absolute file path required")
    require(path.resolve(strict=True) == path, "file path is not canonical")
    require(stat.S_ISREG(path.lstat().st_mode), "regular file required")
    return path


def immutable(path):
    path = regular(path)
    for component in (path, *path.parents):
        info = component.stat()
        require(info.st_uid == 0 and info.st_mode & 0o022 == 0,
                "installed artifact path is not administrator protected")
    require(path.stat().st_mode & 0o222 == 0, "installed file is writable")
    return path


def evidence(root, path):
    root = Path(root).resolve(strict=True)
    path = beneath(root, str(Path(path).relative_to(root)))
    require(path.is_file(), "missing evidence file")
    return {"path": str(path.relative_to(root)), "sha256": sha256(path),
            "bytes": path.stat().st_size}


def verify_evidence(root, item):
    exact_keys(item, ("path", "sha256", "bytes"))
    require(isinstance(item["sha256"], str) and DIGEST.fullmatch(item["sha256"]),
            "invalid evidence digest")
    require(integer(item["bytes"]), "invalid evidence size")
    require(evidence(root, beneath(root, item["path"])) == item,
            "evidence hash or size mismatch")


def require_linux():
    require(sys.platform == "linux" and os.geteuid() != 0,
            "run as a non-root controller on the authorized Linux box",
            "unsupported")
    release = dict(line.split("=", 1) for line in
                   Path("/etc/os-release").read_text().splitlines() if "=" in line)
    require(release.get("ID", "").strip('"') == "ubuntu" and
            release.get("VERSION_ID", "").strip('"') == "24.04",
            "Ubuntu 24.04 is required", "unsupported")


def clean_environment(home, temporary, config=None):
    # Construct a new child's environment. Never inspect the active session's.
    result = {"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
              "HOME": str(home), "TMPDIR": str(temporary), "LANG": "C.UTF-8",
              "PYTHONDONTWRITEBYTECODE": "1"}
    if config is not None:
        result["LANEBOSS_CONFIG"] = config
    return result


def process_identity(pid):
    """Kernel lifetime and UIDs only; never arguments or environment."""
    prefix = Path("/proc") / str(int(pid))
    try:
        data = (prefix / "stat").read_bytes()
        fields = data[data.rindex(b")") + 1:].split()
        if fields[0] in (b"Z", b"X"):
            tasks = list((prefix / "task").glob("*/stat"))
            alive = False
            for item in tasks:
                try:
                    task_state = item.read_bytes().rsplit(b")", 1)[1].split()[0]
                except FileNotFoundError:
                    continue
                alive = alive or task_state not in (b"Z", b"X")
            if not alive:
                return None
        uids = next(line.split()[1:] for line in
                    (prefix / "status").read_bytes().splitlines()
                    if line.startswith(b"Uid:"))
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        return {"pid": int(pid), "start": boot + ":" + fields[19].decode("ascii"),
                "uids": [int(value) for value in uids]}
    except (FileNotFoundError, ProcessLookupError):
        return None


@dataclass(frozen=True)
class Command:
    exit_code: int
    stdout: Path
    stderr: Path
    receipt: Path

    def json(self):
        require(self.exit_code == 0, "command failed; retain its receipt")
        return load(self.stdout)


class Recorder:
    def __init__(self, root, environment):
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.environment = environment

    def run(self, argv, label, *, cwd=None, timeout=60, stdin=None):
        require(NAME.fullmatch(label) is not None, "invalid command label")
        stem = self.root / (label + "-" + uuid.uuid4().hex[:12])
        out = stem.with_suffix(".stdout")
        err = stem.with_suffix(".stderr")
        receipt = stem.with_suffix(".json")
        started = time.monotonic_ns()
        with out.open("xb") as stdout, err.open("xb") as stderr:
            with (Path(stdin).open("rb") if stdin else open(os.devnull, "rb")) as source:
                child = subprocess.Popen(list(map(str, argv)), cwd=cwd,
                                         env=self.environment, stdin=source,
                                         stdout=stdout, stderr=stderr,
                                         close_fds=True)
                identity = process_identity(child.pid)
                timed_out = False
                try:
                    exit_code = child.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    child.kill()
                    exit_code = child.wait(timeout=10)
        save(receipt, {"argv": list(map(str, argv)), "exit_code": exit_code,
                       "timed_out": timed_out, "process": identity,
                       "started_ns": started, "ended_ns": time.monotonic_ns(),
                       "stdin_sha256": sha256(stdin) if stdin else ""})
        require(not timed_out, "command deadline exceeded; retain receipt",
                "deadline_exceeded")
        return Command(exit_code, out, err, receipt)
