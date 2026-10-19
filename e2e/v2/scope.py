"""Independent cgroup-v2 observation for harness-owned entry processes."""

import os
from pathlib import Path
import signal
import stat
import subprocess
import time

from support import Failure, NAME, process_identity, require, save


def cgroup_path(path):
    path = Path(path)
    root = Path("/sys/fs/cgroup")
    require(path.is_absolute() and path.resolve(strict=True) == path and
            path != root and path.is_relative_to(root), "invalid containment path")
    require((root / "cgroup.controllers").is_file(),
            "cgroup v2 is unavailable", "prerequisite_missing")
    require((path / "cgroup.procs").is_file(), "missing cgroup process inventory")
    return path


def members(path):
    path = cgroup_path(path)
    found = set()
    files = [path / "cgroup.procs", *path.glob("**/cgroup.procs")]
    for source in files:
        for line in source.read_text(encoding="ascii").splitlines():
            require(line.isdigit() and int(line) > 0, "invalid kernel PID inventory")
            found.add(int(line))
    return sorted(found)


def observation(path):
    path = cgroup_path(path)
    before = members(path)
    identities = [process_identity(pid) for pid in before]
    after = members(path)
    # A churned snapshot is unknown; never assert zero from a permission error.
    require(before == after and all(item is not None for item in identities),
            "containment changed during observation", "containment_unknown")
    info = path.stat()
    return {"path": str(path), "device": info.st_dev, "inode": info.st_ino,
            "observed_ns": time.monotonic_ns(), "processes": identities}


def signal_identity(identity, number):
    if identity is None:
        return
    require(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
            "PID-lifetime signalling is unavailable", "prerequisite_missing")
    try:
        handle = os.pidfd_open(identity["pid"])
    except ProcessLookupError:
        return
    try:
        if process_identity(identity["pid"]) == identity:
            signal.pidfd_send_signal(handle, number)
    except ProcessLookupError:
        return
    finally:
        os.close(handle)


class Scope:
    def __init__(self, delegated, name):
        root = cgroup_path(delegated)
        require(NAME.fullmatch(name) is not None, "invalid harness scope name")
        require(os.access(root, os.W_OK), "supply an administrator-delegated cgroup",
                "prerequisite_missing")
        self.path = root / name
        self.path.mkdir()
        self.identity = self.path.stat()
        self.root = root
        self.baseline = observation(root)["processes"]
        require(not members(self.path), "new scope already has processes")

    def run(self, argv, *, cwd, environment, stdout, stderr, timeout):
        descriptor = os.open(self.path / "cgroup.procs", os.O_WRONLY)

        def enter():
            os.write(descriptor, b"0")
            os.close(descriptor)

        started = time.monotonic_ns()
        try:
            child = subprocess.Popen(argv, cwd=cwd, env=environment,
                                     stdin=subprocess.DEVNULL, stdout=stdout,
                                     stderr=stderr, close_fds=True,
                                     pass_fds=(descriptor,), preexec_fn=enter)
        finally:
            os.close(descriptor)
        timed_out = False
        try:
            exit_code = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            # The finally collection observes every member, including detachers.
            signal_identity(process_identity(child.pid), signal.SIGTERM)
            try:
                exit_code = child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                signal_identity(process_identity(child.pid), signal.SIGKILL)
                exit_code = child.wait(timeout=5)
        return {"exit_code": exit_code, "timed_out": timed_out,
                "started_ns": started, "ended_ns": time.monotonic_ns()}

    def collect(self, target):
        current = self.path.stat()
        require((current.st_dev, current.st_ino) ==
                (self.identity.st_dev, self.identity.st_ino), "scope identity changed")
        initial = observation(self.path)
        for identity in initial["processes"]:
            signal_identity(identity, signal.SIGTERM)
        deadline = time.monotonic() + 10
        while members(self.path) and time.monotonic() < deadline:
            time.sleep(0.1)
        remaining = members(self.path)
        for pid in remaining:
            identity = process_identity(pid)
            if identity is not None:
                signal_identity(identity, signal.SIGKILL)
        final = observation(self.path)
        outside = observation(self.root)
        escaped = [item for item in outside["processes"]
                   if item not in self.baseline and item not in final["processes"]]
        receipt = {"before_collection": initial, "after_collection": final,
                   "processes_quiescent": not initial["processes"],
                   "escaped_processes": escaped, "temporary_resources_collected": False,
                   "collected": False}
        if not final["processes"] and not escaped:
            try:
                self.path.rmdir()
                receipt["temporary_resources_collected"] = True
                receipt["collected"] = True
            except OSError as error:
                receipt["resource_error"] = type(error).__name__
        save(target, receipt)
        # The receipt retains the inventory; do not leave the kernel scope.
        require(receipt["collected"], "owned process survived collection")
        require(receipt["processes_quiescent"], "entry left a surviving owned process")
        return receipt
