"""One org's history settings and instance identity, with paths confined to that org."""

import fcntl
import os
from pathlib import Path
import stat
import time

from .schema import InvalidInput, canonical, parse_json, validate_scope

MAX_CONFIG_BYTES = 64 * 1024
MAX_TEXT_BYTES = 8 * 1024 * 1024


def read_regular(path, limit=MAX_TEXT_BYTES):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise InvalidInput("source must be a regular file within the byte limit")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            data = source.read(limit + 1)
        if len(data) > limit:
            raise InvalidInput("source exceeds the byte limit")
        return data.decode("utf-8")
    finally:
        os.close(descriptor)


def read_toml(path):
    # Org commands belong to the Python 3.11 launcher. Import lazily to preserve the standalone store on 3.9/3.10.
    import tomllib
    return tomllib.loads(read_regular(path, MAX_CONFIG_BYTES))


def within(path, root):
    resolved = Path(path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise InvalidInput("history path leaves its org") from error
    return resolved


class Org:
    def __init__(self, directory):
        given = Path(directory).resolve()
        self.home = given if given.name == ".laneboss" else given / ".laneboss"
        self.root = self.home.parent
        within(self.home, self.root)
        self.data = read_toml(within(self.home / "org.toml", self.home))
        history = self.data.get("history", {})
        if not isinstance(history, dict):
            raise InvalidInput("org history settings must be a table")
        self.history = dict(history)
        service = within(self.home / "shared/services/history.toml", self.home)
        if service.is_file():
            self.history.update(read_toml(service))
        self.db = self.path(self.history.get("db", "shared/services/decisions.sqlite"))
        self.socket = self.path(self.history.get("socket", "shared/services/history.sock"))
        self.log = self.path("shared/state/history/injections.jsonl")
        self.capture_log = self.path("shared/state/history/classifications.jsonl")
        self.review = self.path("shared/state/history/review.jsonl")

    def path(self, value):
        if not isinstance(value, str) or not value or "\x00" in value:
            raise InvalidInput("history path must be nonempty text")
        return within(self.home / value, self.home)

    def check_store(self, path):
        if Path(path).resolve() != self.db:
            raise InvalidInput("--db must name this org's configured history store")

    def instance(self, name):
        # Check the label before constructing a path, then check the resolved folder and the identity within it.
        validate_scope({"level": 3, "instance": name})
        directory = within(self.home / "instances" / name, self.home / "instances")
        data = read_toml(within(directory / "instance.toml", directory))
        metadata = data.get("instance", data)
        if not isinstance(metadata, dict):
            raise InvalidInput("instance metadata must be a table")
        identity = {"level": metadata.get("level"), "instance": metadata.get("name", name)}
        validate_scope(identity)
        if identity["instance"] != name:
            raise InvalidInput("instance.toml name does not match its directory")
        return identity, directory, metadata


def discover(directory=None, org_dir=None, instance=None):
    """Bind an explicit trusted org; never discover an org configuration inside a checkout."""
    bound = org_dir or os.environ.get("LANEBOSS_ORG")
    if not bound:
        raise InvalidInput("org-dir or LANEBOSS_ORG is required")
    org = Org(bound)
    selected = instance or os.environ.get("LANEBOSS_INSTANCE")
    start = Path(directory or os.getcwd()).resolve()
    if selected and ("/" in selected or selected.endswith(".toml")):
        candidate = Path(selected).expanduser().resolve()
        within(candidate, org.home / "instances")
        start = candidate.parent if candidate.name == "instance.toml" else candidate
        selected = start.name
    if not selected:
        # Only the trusted org's actual instance tree may supply identity; a checkout cannot plant instance.toml.
        within(start, org.home / "instances")
        for parent in (start, *start.parents):
            if parent.parent == org.home / "instances":
                selected = parent.name
                break
    if not selected:
        raise InvalidInput("no org instance could be found")
    identity, path, metadata = org.instance(selected)
    return org, identity, path, metadata


def append_log(path, value):
    """One append under a nonblocking lock; failure is reported to the caller before it claims a logged action."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise InvalidInput("history log must be a regular file")
        deadline = time.monotonic() + 0.08
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise
                time.sleep(min(0.005, remaining))
        data = (canonical(value) + "\n").encode("utf-8")
        if len(data) > 64 * 1024:
            raise InvalidInput("history log entry exceeds the byte limit")
        with os.fdopen(descriptor, "ab", closefd=False) as stream:
            stream.write(data)
            stream.flush()
    finally:
        os.close(descriptor)


def recent_injections(org):
    """A bounded tail of injection receipts. A partial first line is omitted when the log exceeds the bound."""
    try:
        descriptor = os.open(org.log, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return []
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise InvalidInput("history log must be a regular file")
        start = max(0, info.st_size - MAX_TEXT_BYTES)
        os.lseek(descriptor, start, os.SEEK_SET)
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(MAX_TEXT_BYTES)
        lines = data.splitlines()
        if start:
            lines = lines[1:]
        return [parse_json(line.decode("utf-8")) for line in lines]
    finally:
        os.close(descriptor)
