"""File identity and guarded file access.

Containment is decided by identity (device and inode), never by path text, so a stale or copied symbolic
link, an aliased directory or a different letter case does not move a path into or out of a configuration's
directories. A file is opened through its directory: the directory is opened first, its real ancestors are
read back through "..", the caller checks them, and only then is the final name opened relative to that
directory without following a link.

This guards against mistakes, not against another process of the same account that moves or swaps files
while the launcher runs (docs/architecture.md, "What isolation covers"). A hard link to another
configuration's file cannot be recognised: it is the same file under a second name.
"""

import errno
import fcntl
import json
import os
import stat
import time
import uuid

from .errors import Refused

DIRECTORY = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
CLOEXEC = getattr(os, "O_CLOEXEC", 0)
LINK_AT = os.link in os.supports_dir_fd


def identity(info):
    return (info.st_dev, info.st_ino)


def open_creating(name, flags, mode, directory_fd, attempts=50):
    """os.open with O_CREAT inside an opened directory. On macOS two processes creating the same name at the same
    moment can make one open fail with ENOENT although the directory exists; that open is tried again, a bounded
    number of times."""
    for attempt in range(attempts):
        try:
            return os.open(name, flags | os.O_CREAT, mode, dir_fd=directory_fd)
        except FileNotFoundError:
            if attempt == attempts - 1:
                raise
            time.sleep(0.01)


class Location:
    """Where a path lives: the identities of its deepest existing ancestor and of every directory above it,
    and the components below that ancestor that do not exist yet (compared without letter case)."""

    def __init__(self, path):
        self.path = str(path)
        real = os.path.realpath(self.path)
        existing = real
        remainder = []
        while not os.path.exists(existing):
            parent = os.path.dirname(existing)
            if parent == existing:
                break
            remainder.insert(0, os.path.basename(existing).casefold())
            existing = parent
        chain = []
        current = existing
        while True:
            try:
                chain.append(identity(os.stat(current)))
            except OSError:
                pass
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
        self.chain = tuple(chain)
        self.remainder = tuple(remainder)

    @property
    def exists(self):
        return not self.remainder and bool(self.chain)


def inside(child, parent):
    """True when the location child is parent or lies below it."""
    if not parent.chain or not child.chain:
        return False
    if not parent.remainder:
        return parent.chain[0] in child.chain
    return child.chain[0] == parent.chain[0] and child.remainder[:len(parent.remainder)] == parent.remainder


def overlap(first, second):
    return inside(first, second) or inside(second, first)


def read_marker_at(directory_fd, name):
    """None when absent, the parsed marker when readable, the string "unreadable" otherwise."""
    try:
        descriptor = os.open(name, os.O_RDONLY | NOFOLLOW | os.O_NONBLOCK | CLOEXEC, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    except OSError:
        return "unreadable"
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return "unreadable"
        data = os.read(descriptor, 65536)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return "unreadable"
    return value if isinstance(value, dict) else "unreadable"


def walk_up(directory_fd, marker_name):
    """Identities and markers of an opened directory and of every directory above it, read through '..'."""
    chain = []
    markers = []
    current = os.dup(directory_fd)
    try:
        while True:
            info = os.fstat(current)
            chain.append(identity(info))
            markers.append(read_marker_at(current, marker_name) if marker_name else None)
            try:
                parent = os.open("..", DIRECTORY, dir_fd=current)
            except OSError as error:
                raise Refused("cannot read a directory above a checked path ({}); the launcher must be able to read "
                              "every directory above its files to check who owns them".format(
                                  error.strerror or "error")) from None
            if identity(os.fstat(parent)) == chain[-1]:
                os.close(parent)
                break
            os.close(current)
            current = parent
    finally:
        os.close(current)
    return chain, markers


def open_directory(path, what):
    """Open an existing directory, following links in its path; refuse anything that is not a directory."""
    try:
        return os.open(str(path), DIRECTORY)
    except FileNotFoundError:
        raise Refused("{}: the directory {} does not exist".format(what, path)) from None
    except NotADirectoryError:
        raise Refused("{}: {} is not a directory".format(what, path)) from None
    except OSError as error:
        raise Refused("{}: cannot open {}: {}".format(what, path, error.strerror or "error")) from None


def same_directory(fd, path):
    """True when the directory still at path is the directory that fd holds."""
    try:
        return identity(os.stat(str(path))) == identity(os.fstat(fd))
    except OSError:
        return False


def open_child(directory_fd, name, what, flags=os.O_RDONLY):
    """Open a regular file by name inside an opened directory, refusing links, FIFOs, devices and directories."""
    try:
        descriptor = os.open(name, flags | NOFOLLOW | os.O_NONBLOCK | CLOEXEC, dir_fd=directory_fd)
    except FileNotFoundError:
        raise Refused("{}: {} does not exist".format(what, name)) from None
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.EMLINK):
            raise Refused("{}: {} is a symbolic link".format(what, name)) from None
        raise Refused("{}: cannot open {}: {}".format(what, name, error.strerror or "error")) from None
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise Refused("{}: {} is not a regular file".format(what, name))
    return descriptor


def read_descriptor(descriptor, limit, what):
    chunks = []
    total = 0
    try:
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise Refused("{}: larger than {} bytes".format(what, limit))
            chunks.append(chunk)
    finally:
        os.close(descriptor)
    return b"".join(chunks)


def child_directory(directory_fd, name, create=False, mode=0o700):
    """Open (and optionally create) a subdirectory by name without following a link."""
    for attempt in range(50 if create else 1):
        if create:
            try:
                os.mkdir(name, mode, dir_fd=directory_fd)
            except FileExistsError:
                pass
        try:
            return os.open(name, DIRECTORY | NOFOLLOW, dir_fd=directory_fd)
        except FileNotFoundError:
            # Created a moment ago by this or another process: on macOS the name can briefly be missing.
            if not create or attempt == 49:
                raise
            time.sleep(0.01)
        except OSError as error:
            if error.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
                raise Refused("{} inside the state directory is a symbolic link or not a directory".format(
                    name)) from None
            raise


def file_info(directory_fd, name):
    """lstat of a name inside an opened directory, or None."""
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def write_new(directory_fd, name, data, replace=False, mode=0o600):
    """Write a complete file under name through a temporary name. Without replace, never overwrite. A temporary file
    that disappears before it is put in place (another process cleaned the directory) is written once more."""
    try:
        _write_new(directory_fd, name, data, replace, mode)
    except FileNotFoundError:
        _write_new(directory_fd, name, data, replace, mode)


def _write_new(directory_fd, name, data, replace, mode):
    temporary = ".tmp-{}-{}".format(os.getpid(), uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW | CLOEXEC, mode,
                         dir_fd=directory_fd)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if replace:
            os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        elif LINK_AT:
            os.link(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        else:
            if file_info(directory_fd, name) is not None:
                raise FileExistsError(errno.EEXIST, "File exists", name)
            os.rename(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        raise


class Lock:
    """An exclusive (or, for readers, shared) lock on an opened directory, held for one critical section.
    Where a directory cannot be locked, a lock file inside it (opened without following a link) is locked
    instead."""

    LOCK_FILE = ".lock"

    def __init__(self, directory_fd, shared=False):
        self.directory = directory_fd
        self.mode = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
        self.fd = None

    def __enter__(self):
        try:
            fcntl.flock(self.directory, self.mode)
            self.fd = self.directory
        except OSError:
            self.fd = open_creating(self.LOCK_FILE, os.O_RDWR | NOFOLLOW | CLOEXEC, 0o600, self.directory)
            fcntl.flock(self.fd, self.mode)
        return self

    def __exit__(self, *details):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        if self.fd != self.directory:
            os.close(self.fd)
