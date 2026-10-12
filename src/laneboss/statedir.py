"""The bound configuration's state directory, opened and checked by identity, and its ownership marker.

The marker names the owning configuration and, once the store exists, records it (its id and creation
time): a store that existed is never silently recreated. Everything inside the state directory is reached
through the opened directory without following a link; the launcher never creates a link there and
refuses one it finds.
"""

import json
import os
import stat
import time

from . import config, fsguard
from .errors import IntegrityProblem, Refused
from .jsonutil import sha256_hex

MARKER_FORMAT = config.MARKER_FORMAT
MAX_INPUT_BYTES = 8 * 1024 * 1024


class StateDir:
    def __init__(self, configuration, fd, real):
        self.configuration = configuration
        self.fd = fd
        self.real = real

    @classmethod
    def open(cls, configuration, zones, create):
        """The checked state directory; None when it does not exist and create is False."""
        path = str(configuration.state_dir)
        if create:
            check_before_create(configuration, zones, path)
            try:
                os.makedirs(path, mode=0o700, exist_ok=True)
            except OSError as error:
                raise Refused("cannot create the state directory {}: {}".format(
                    path, error.strerror or "operating system error")) from None
        descriptor = None
        for attempt in range(50 if create else 1):
            try:
                descriptor = os.open(path, fsguard.DIRECTORY)
                break
            except FileNotFoundError:
                # Just created, by this or another process: on macOS the name can briefly be missing.
                if create:
                    time.sleep(0.01)
            except OSError as error:
                raise Refused("cannot open the state directory {}: {}".format(
                    path, error.strerror or "operating system error")) from None
        if descriptor is None:
            if create:
                raise Refused("the state directory {} disappeared while it was being created".format(path))
            return None
        try:
            real = os.path.realpath(path)
            if not fsguard.same_directory(descriptor, real):
                raise Refused("the state directory {} changed while it was being checked".format(path))
            chain, markers = fsguard.walk_up(descriptor, config.MARKER)
            check_chain(configuration, zones, chain, markers)
        except BaseException:
            os.close(descriptor)
            raise
        return cls(configuration, descriptor, real)

    def close(self):
        os.close(self.fd)

    def lock(self, shared=False):
        """Writers that create the marker or the store hold the exclusive lock; readers hold the shared one
        while they read the marker and open the store, so they never see a creation half done."""
        return fsguard.Lock(self.fd, shared)

    def marker(self):
        """The validated marker, or None. Every field is checked by its grammar; nothing from a marker that
        fails is printed."""
        value = fsguard.read_marker_at(self.fd, config.MARKER)
        if value is None:
            return None
        if not valid_marker(value, self.configuration.name):
            raise IntegrityProblem("the ownership marker {} is not a valid marker of configuration {}".format(
                os.path.join(self.real, config.MARKER), self.configuration.name))
        return value

    def ensure_marker(self):
        """The marker, written complete under its final name on first use. The caller holds the lock."""
        value = self.marker()
        if value is None:
            value = {"config": self.configuration.name, "format": MARKER_FORMAT, "store": None}
            try:
                fsguard.write_new(self.fd, config.MARKER, (json.dumps(value, sort_keys=True) + "\n").encode())
            except FileExistsError:
                value = self.marker()
        return value

    def record_store(self, store_id, created_at):
        """Record in the marker that the store exists. The caller holds the lock."""
        value = {"config": self.configuration.name, "format": MARKER_FORMAT,
                 "store": {"id": store_id, "created_at": created_at}}
        fsguard.write_new(self.fd, config.MARKER, (json.dumps(value, sort_keys=True) + "\n").encode(), replace=True)

    def store_info(self):
        info = fsguard.file_info(self.fd, config.STORE_FILE)
        if info is not None and not stat.S_ISREG(info.st_mode):
            raise Refused("{} is a symbolic link or not a regular file; the store is a regular file inside the "
                          "state directory".format(os.path.join(self.real, config.STORE_FILE)))
        return info

    def store_path(self):
        if not fsguard.same_directory(self.fd, self.real):
            raise Refused("the state directory {} changed while it was in use".format(self.real))
        return os.path.join(self.real, config.STORE_FILE)

    def _inputs(self, lane, create):
        """The opened lanes/<lane>/inputs directory, or None when it does not exist and create is False."""
        return self.open_lane(lane, "inputs", create=create)

    def open_lane(self, lane, *names, create=False):
        """The opened lanes/<lane>[/<name>...] directory, reached without following a link, or None when it does
        not exist and create is False."""
        opened = []
        try:
            current = self.fd
            for name in ("lanes", lane) + names:
                try:
                    current = fsguard.child_directory(current, name, create)
                except FileNotFoundError:
                    return None
                opened.append(current)
            return os.dup(current)
        finally:
            for descriptor in opened:
                os.close(descriptor)

    def lane_path(self, lane, *names):
        """The absolute path of a file or directory in lanes/<lane>, below the state directory's real path."""
        return os.path.join(self.real, "lanes", lane, *names)

    def keep_input(self, lane, data):
        """Keep consumed bytes at lanes/<lane>/inputs/<sha256>. Returns (relative path, digest, created)."""
        digest = sha256_hex(data)
        relative = "lanes/{}/inputs/{}".format(lane, digest)
        inputs = self._inputs(lane, create=True)
        try:
            if fsguard.file_info(inputs, digest) is not None:
                kept = fsguard.read_descriptor(fsguard.open_child(inputs, digest, relative), MAX_INPUT_BYTES, relative)
                if sha256_hex(kept) != digest:
                    raise IntegrityProblem("kept input {} does not match its hash".format(relative))
                return relative, digest, False
            fsguard.write_new(inputs, digest, data)
            return relative, digest, True
        finally:
            os.close(inputs)

    def remove_input(self, lane, digest):
        inputs = self._inputs(lane, create=False)
        if inputs is None:
            return
        try:
            os.unlink(digest, dir_fd=inputs)
        except FileNotFoundError:
            pass
        finally:
            os.close(inputs)

    def read_input(self, lane, digest):
        """The kept bytes, or None when the copy is missing."""
        inputs = self._inputs(lane, create=False)
        if inputs is None:
            return None
        try:
            if fsguard.file_info(inputs, digest) is None:
                return None
            relative = "lanes/{}/inputs/{}".format(lane, digest)
            return fsguard.read_descriptor(fsguard.open_child(inputs, digest, relative), MAX_INPUT_BYTES, relative)
        finally:
            os.close(inputs)

    def all_inputs(self):
        """(lane, name) of every kept input, refusing links anywhere below lanes/."""
        return self.all_files("inputs")

    def all_mail(self):
        """(lane, name) of every entry of every lane's mail directory, refusing links anywhere below lanes/."""
        return self.all_files("mail")

    def all_files(self, directory):
        """(lane, name) of every entry of lanes/<lane>/<directory> for every lane that has one."""
        try:
            lanes = fsguard.child_directory(self.fd, "lanes")
        except FileNotFoundError:
            return []
        found = []
        try:
            for lane in sorted(os.listdir(lanes)):
                lane_fd = fsguard.child_directory(lanes, lane)
                try:
                    try:
                        inside = fsguard.child_directory(lane_fd, directory)
                    except FileNotFoundError:
                        continue
                    try:
                        found.extend((lane, name) for name in sorted(os.listdir(inside)))
                    finally:
                        os.close(inside)
                finally:
                    os.close(lane_fd)
        finally:
            os.close(lanes)
        return found

    def mail_entry(self, lane, name):
        """The stat of a name in lanes/<lane>/mail, without following a link, or None."""
        directory = self.open_lane(lane, "mail")
        if directory is None:
            return None
        try:
            return fsguard.file_info(directory, name)
        finally:
            os.close(directory)

    def read_mail(self, lane, name, limit):
        """The bytes of a message file (a regular file, not a link, at most `limit` bytes), or None when it is missing."""
        directory = self.open_lane(lane, "mail")
        if directory is None:
            return None
        try:
            if fsguard.file_info(directory, name) is None:
                return None
            relative = "lanes/{}/mail/{}".format(lane, name)
            return fsguard.read_descriptor(fsguard.open_child(directory, name, relative), limit, relative)
        finally:
            os.close(directory)


def valid_marker(value, name):
    return config.marker_valid(value) and value["config"] == name


def check_before_create(configuration, zones, path):
    """Before creating any directory, check the deepest existing ancestor of the state directory."""
    existing = os.path.realpath(path)
    while not os.path.exists(existing):
        parent = os.path.dirname(existing)
        if parent == existing:
            return
        existing = parent
    if not os.path.isdir(existing):
        raise Refused("cannot create the state directory {}: {} is not a directory".format(path, existing))
    descriptor = fsguard.open_directory(existing, "the state directory")
    try:
        chain, markers = fsguard.walk_up(descriptor, config.MARKER)
    finally:
        os.close(descriptor)
    if existing != os.path.realpath(path):
        markers = [None] + markers
    check_chain(configuration, zones, chain, markers, creating=True)


def check_chain(configuration, zones, chain, markers, creating=False):
    """The state directory's real ancestors: no marker of another configuration anywhere above it, no
    other configuration's directory around it, and its own marker (if any) naming this configuration."""
    own = configuration.name
    state = configuration.state_dir
    known = zones.known_names()
    above = [config.marker_owner(marker, known, own) for marker in markers[1:]]
    for owner in config.foreign_owners(above, own)[:1]:
        if owner == config.UNREADABLE_MARKER:
            raise Refused("the state directory {} lies below a directory whose ownership marker is unreadable".format(
                state))
        if owner != config.UNKNOWN_OWNER:
            raise Refused("the state directory {} lies inside the state directory of configuration {}".format(
                state, config.shown_name(owner)))
    for name, kind, location in zones.others:
        if location.exists and location.chain[0] in chain:
            raise Refused("the state directory {} lies inside configuration {}'s {}".format(
                state, config.shown_name(name), kind))
    if config.UNKNOWN_OWNER in above:
        raise Refused("the state directory {} lies inside the state directory of another or an unknown "
                      "configuration".format(state))
    if markers and markers[0] is not None and not creating:
        owner = config.marker_owner(markers[0], known, own)
        if owner == config.UNREADABLE_MARKER:
            raise Refused("the ownership marker of the state directory {} is unreadable, a link or not a regular "
                          "file".format(state))
        if owner == config.UNKNOWN_OWNER:
            raise Refused("the state directory {} belongs to another or an unknown configuration".format(state))
        if owner != own:
            raise Refused("the state directory {} belongs to configuration {}".format(state, config.shown_name(owner)))
