#!/usr/bin/env python3
"""Public-CLI acceptance; never infer a boundary from a success message."""

import argparse
import base64
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import secrets
import select
import signal
import socket
import stat
import subprocess
import sys
import time
import threading


_authority_spec = importlib.util.spec_from_file_location(
    "laneboss_human_authority", Path(__file__).resolve().parents[2] / "human_authority.py")
AUTHORITY = importlib.util.module_from_spec(_authority_spec)
_authority_spec.loader.exec_module(AUTHORITY)
_dac_spec = importlib.util.spec_from_file_location(
    "linux_dac_control", Path(__file__).with_name("dac.py"))
DAC = importlib.util.module_from_spec(_dac_spec)
_dac_spec.loader.exec_module(DAC)
_handoff_spec = importlib.util.spec_from_file_location(
    "linux_g0_handoff", Path(__file__).with_name("handoff.py"))
HANDOFF = importlib.util.module_from_spec(_handoff_spec)
_handoff_spec.loader.exec_module(HANDOFF)


PUBLIC_REDS = {
    "linux-broad-root": ("boundary canary succeeded: outside.",),
    "linux-writable-nested": ("boundary canary succeeded: nested.write",),
    "linux-inherited-fd": ("boundary canary succeeded: inherited.fd",),
    "linux-no-landlock": ("boundary canary succeeded: nested.write",),
    "linux-no-network": ("boundary canary succeeded: foreign.tcp",
                         "boundary canary succeeded: foreign.udp",
                         "boundary canary succeeded: foreign.ipc"),
    "linux-no-cgroup": ("run cgroup was not observed populated",
                        "canary cgroup membership did not match"),
    "linux-false-zero": ("observer found a surviving run process",),
    "linux-unmeasured-release": ("helper release receipt is missing or incomplete",
                                 "helper release receipt has unknown or nonzero counts",
                                 "helper release receipt binding differs"),
}

NETWORK_KINDS = (("tcp4", socket.AF_INET, socket.SOCK_STREAM),
                 ("udp4", socket.AF_INET, socket.SOCK_DGRAM),
                 ("tcp6", socket.AF_INET6, socket.SOCK_STREAM),
                 ("udp6", socket.AF_INET6, socket.SOCK_DGRAM))


def red_target_reached(mutation, reason, succeeded):
    for prefix in PUBLIC_REDS.get(mutation, ()):
        if prefix.startswith("boundary canary succeeded: "):
            if any(("boundary canary succeeded: " + name).startswith(prefix) for name in succeeded):
                return True
        elif reason.startswith(prefix):
            return True
    return False


def review_complete(review, target):
    evidence = review.get("evidence", {})
    reviewer = review.get("reviewer", {})
    inventory = evidence.get("inventory", {})
    checks = evidence.get("checks", [])
    if (not review.get("id") or review.get("coverage") != "complete" or
            evidence.get("schema") != "laneboss.review.v2" or
            evidence.get("coverage") != "complete" or
            evidence.get("subject", {}).get("target") != target or
            not evidence.get("verifier_lease_id") or
            inventory.get("tool_coverage") != "complete" or
            not inventory.get("tool_records", {}).get("id") or
            reviewer.get("kind") not in ("human", "lane") or
            not reviewer.get("id") or reviewer.get("life_id") == target["life_id"] or
            not checks or any(check.get("exit_code") != 0 or
                              check.get("target") != target or
                              not check.get("worker_lease_id") or
                              not check.get("operation_id") for check in checks)):
        raise RuntimeError("collection review lacks complete independent verification")


class NetworkObserver:
    """Actual listeners outside the lane; zero is measured, never supplied."""
    def __init__(self, foreign):
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.sockets = []
        self.threads = []
        self.failures = []
        self.counts = {}
        self.addresses = {}
        self.closed = False
        self.baseline = {}
        self.ipc = None
        self.kinds = list(NETWORK_KINDS)
        if "ipc" in foreign:
            self.kinds.append(("ipc", socket.AF_UNIX, socket.SOCK_STREAM))
        try:
            for name, family, kind in self.kinds:
                listener = socket.socket(family, kind)
                self.sockets.append(listener)
                if family == socket.AF_INET6:
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                address = foreign[name] if family == socket.AF_UNIX else tuple(foreign[name])
                listener.bind(address)
                if family == socket.AF_UNIX:
                    path = Path(address)
                    path.chmod(0o666)
                    info = path.lstat()
                    self.ipc = (path, info.st_dev, info.st_ino)
                listener.settimeout(0.2)
                if kind == socket.SOCK_STREAM:
                    listener.listen(8)
                self.addresses[name] = (listener.getsockname() if family == socket.AF_UNIX
                                        else list(listener.getsockname()[:2]))
                self.counts["foreign." + name] = {"bytes": 0, "packets": 0, "connections": 0}
                thread = threading.Thread(target=self.serve, args=(name, listener, kind))
                thread.start()
                self.threads.append(thread)
        except BaseException:
            self.close()
            raise

    def serve(self, name, listener, kind):
        while not self.stop.is_set():
            try:
                if kind == socket.SOCK_DGRAM:
                    data, _ = listener.recvfrom(65535)
                    with self.lock:
                        count = self.counts["foreign." + name]
                        count["packets"] += 1
                        count["bytes"] += len(data)
                    # Deliberately no echo: a lost reply must not hide exfiltration.
                else:
                    connection, _ = listener.accept()
                    with self.lock:
                        self.counts["foreign." + name]["connections"] += 1
                    with connection:
                        connection.settimeout(0.2)
                        try:
                            while True:
                                data = connection.recv(65536)
                                if not data:
                                    break
                                with self.lock:
                                    self.counts["foreign." + name]["bytes"] += len(data)
                        except ConnectionResetError:
                            continue  # The independently counted connection still reached the host.
            except TimeoutError:
                continue
            except OSError as failure:
                if not self.stop.is_set():
                    with self.lock:
                        self.failures.append(type(failure).__name__)
                return
            except Exception as failure:
                with self.lock:
                    self.failures.append(type(failure).__name__)
                return

    def close(self):
        if self.closed:
            return self.snapshot()
        self.stop.set()
        for listener in self.sockets:
            try:
                listener.close()
            except OSError as failure:
                with self.lock:
                    self.failures.append(type(failure).__name__)
        for thread in self.threads:
            thread.join(timeout=2)
        if any(thread.is_alive() for thread in self.threads):
            raise RuntimeError("outside network observer did not stop")
        if self.ipc is not None:
            path, device, inode = self.ipc
            info = path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or (info.st_dev, info.st_ino) != (device, inode):
                raise RuntimeError("outside IPC socket identity changed before collection")
            path.unlink()
        self.closed = True
        return self.snapshot()

    def snapshot(self):
        with self.lock:
            if self.failures:
                raise RuntimeError("outside network observer failed")
            return {name: {key: value - self.baseline.get(name, {}).get(key, 0)
                           for key, value in count.items()}
                    for name, count in self.counts.items()}

    def positive_control(self, payload):
        """Reach each actual listener before the lane; retain the baseline."""
        if self.baseline or not payload:
            raise RuntimeError("network positive control is not fresh")
        for name, family, kind in self.kinds:
            with socket.socket(family, kind) as stream:
                stream.settimeout(2)
                address = self.addresses[name]
                stream.connect(address if family == socket.AF_UNIX else tuple(address))
                stream.sendall(payload)
        deadline = time.monotonic() + 3
        while True:
            actual = self.snapshot()
            if all(count["bytes"] == len(payload) and
                   count["packets" if name.split(".")[1].startswith("udp")
                         else "connections"] == 1
                   for name, count in actual.items()):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("outside listener positive control failed")
            self.stop.wait(0.01)
        with self.lock:
            self.baseline = {name: dict(count) for name, count in self.counts.items()}
        return actual

    def finish(self):
        # Drain after the canary has completed its bounded socket attempts.
        self.stop.wait(2)
        return self.close()


def process_identity(pid):
    directory = Path("/proc") / str(pid)
    raw = (directory / "stat").read_text()
    fields = raw[raw.rfind(")") + 2:].split()
    if fields[0] == "Z":
        return None
    status = {}
    for line in (directory / "status").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in ("Uid", "Gid", "Groups"):
            status[key] = [int(item) for item in value.split()]
    return {"start_time": fields[19], "uids": status["Uid"],
            "gids": status["Gid"], "groups": status["Groups"],
            "cgroup": (directory / "cgroup").read_text().splitlines()}


def uid_processes(uid):
    result = {}
    for directory in Path("/proc").iterdir():
        if directory.name.isdigit():
            try:
                identity = process_identity(directory.name)
                if identity and identity["uids"] == [uid] * 4:
                    result[directory.name] = identity
            except (FileNotFoundError, ProcessLookupError):
                continue
    return result


def terminate_processes(identities, uid):
    """Signal exact kernel process identities through pidfds, never patterns."""
    descriptors = []
    failures = []
    try:
        for pid, identity in sorted(identities.items(), key=lambda item: int(item[0])):
            if int(pid) == os.getpid() or identity["uids"] != [uid] * 4:
                failures.append("refusing to signal a process outside the owned UID lease")
                continue
            try:
                descriptor = os.pidfd_open(int(pid), 0)
            except ProcessLookupError:
                continue
            except OSError as failure:
                failures.append("pidfd open: " + str(failure))
                continue
            descriptors.append(descriptor)
            try:
                current = process_identity(pid)
            except (FileNotFoundError, ProcessLookupError):
                continue
            if current is None:
                continue
            if current["start_time"] != identity["start_time"] or current["uids"] != identity["uids"]:
                failures.append("process identity changed before cleanup signal")
                continue
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
            except ProcessLookupError:
                continue
            except OSError as failure:
                failures.append("pidfd signal: " + str(failure))
        deadline = time.monotonic() + 10
        poll = select.poll()
        for descriptor in descriptors:
            poll.register(descriptor, select.POLLIN)
        waiting = set(descriptors)
        while waiting and time.monotonic() < deadline:
            for descriptor, _ in poll.poll(100):
                waiting.discard(descriptor)
                poll.unregister(descriptor)
        if waiting:
            failures.append("owned process identity did not terminate")
        if failures:
            raise RuntimeError("; ".join(failures))
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    return json.loads(path.read_bytes())


def beneath(root, relative):
    value = Path(relative)
    if value.is_absolute() or ".." in value.parts:
        raise ValueError("case input must be a relative path")
    result = (root / value).resolve()
    result.relative_to(root.resolve())
    return result


def read_fenced(root, relative):
    """Observer reads use descriptors; a lane cannot redirect a later open."""
    value = Path(relative)
    if value.is_absolute() or ".." in value.parts or not value.parts:
        raise ValueError("observer path must be relative and beneath its scope")
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                        os.O_CLOEXEC)
    descriptor = None
    try:
        for component in value.parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                            os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(value.parts[-1], os.O_RDONLY | os.O_NOFOLLOW |
                             os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise RuntimeError("observer refuses a non-regular input")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            data = stream.read(1024 * 1024 + 1)
            info = os.fstat(stream.fileno())
        if len(data) > 1024 * 1024:
            raise RuntimeError("observer input exceeds its bounded size")
        if (before.st_ino, before.st_mtime_ns, before.st_ctime_ns) != (
                info.st_ino, info.st_mtime_ns, info.st_ctime_ns):
            raise RuntimeError("observer input changed while it was read")
        return data, info
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def atomic_json(path, value):
    data = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    pending = path.with_name(path.name + ".pending")
    with pending.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    pending.replace(path)


def private_directory(path):
    """Create observer evidence private; refuse a shared or foreign directory."""
    if not path.is_absolute():
        raise RuntimeError("evidence directory must be absolute")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
            stat.S_IMODE(info.st_mode) != 0o700):
        raise RuntimeError("evidence directory must be private to the observer")


def host_facts():
    if platform.system() != "Linux":
        raise RuntimeError("this case requires Linux")
    if platform.machine() not in ("aarch64", "arm64", "x86_64"):
        raise RuntimeError("unsupported syscall architecture")
    libc = ctypes.CDLL(None, use_errno=True)
    abi = libc.syscall(444, 0, 0, 1)
    if abi < 0:
        raise OSError(ctypes.get_errno(), "Landlock ABI probe failed")
    switch = Path("/proc/sys/kernel")
    restricted = int((switch / (
        "apparmor_restrict_" + "unprivileged_userns")).read_text().strip())
    version = subprocess.run(
        ["/usr/bin/bwrap", "--version"], check=True,
        capture_output=True, text=True, env={}).stdout.strip()
    return {"restriction": restricted, "abi": abi,
            "kernel": platform.release(), "bwrap_version": version}


def marked_processes(marker):
    """Independent observer: retain identities, never print command lines."""
    result = {}
    needle = marker.encode()
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit():
            continue
        try:
            arguments = (directory / "cmdline").read_bytes().split(b"\0")
            if needle not in arguments:
                continue
            raw = (directory / "stat").read_text()
            fields = raw[raw.rfind(")") + 2:].split()
            if fields[0] != "Z":
                status = {}
                for line in (directory / "status").read_text().splitlines():
                    key, _, value = line.partition(":")
                    if key in ("Uid", "Gid", "Groups"):
                        status[key] = [int(item) for item in value.split()]
                result[directory.name] = {
                    "start_time": fields[19], "uids": status["Uid"],
                    "gids": status["Gid"], "groups": status["Groups"],
                    "cgroup": (directory / "cgroup").read_text().splitlines(),
                }
        except FileNotFoundError:
            continue  # A process actually disappeared during the observation.
    return result


class Case:
    def __init__(self, context, coordinator=None):
        self.context = context
        self.root = Path(context["test_root"]).resolve()
        self.evidence = Path(context["evidence_root"])
        private_directory(self.evidence)
        self.references = []
        self.reached = False
        self.exit = 1
        self.quiescent = False
        self.collected = False
        self.index = 0
        self.owned = []
        self.records = []
        self.cleanup_errors = []
        self.boundary_failures = []
        self.coordinator = coordinator
        if coordinator is None and HANDOFF.available():
            self.coordinator = HANDOFF.Remote(self)
        self.refused = False

    def cleanup(self):
        """Always run, including assertion failures, type errors and interrupts."""
        logs = []
        for record in list(self.owned):
            target, cell = record["target"], record["cell"]
            errors = []
            facts = {"pid_batches": [], "uid_after": None, "marker_after": None, "cgroup_after": None}
            try:
                if self.refused:
                    raise RuntimeError("public refusal stopped further lane operations; supervisor reconciliation required")
                if not record["started"]:
                    record["quiescent"] = record["collected"] = True
                else:
                    if target is None and record.get("operation"):
                        try:
                            operation = self.call(["operation", "get"], {"operation_id": record["operation"]["id"]})
                            if operation.get("life_id") and operation.get("run"):
                                target = record["target"] = {"life_id": operation["life_id"], "run": operation["run"]}
                        except Exception as failure:
                            errors.append("start reconciliation: " + str(failure))
                    if target is not None and not record["quiescent"]:
                        try:
                            status = self.call(["lane", "status"], target)
                            stop = self.call(["lane", "stop"], {"target": target,
                                "expected_generation": status["generation"], "reason": cell["stop_reason"]})
                            self.wait_operation(stop)
                        except Exception as failure:
                            errors.append("stop: " + str(failure))
                    if not record["quiescent"]:
                        if record["uid"] is None:
                            raise RuntimeError("native lease is unknown; supervisor reconciliation required")
                        deadline = time.monotonic() + 15
                        while True:
                            live = uid_processes(record["uid"])
                            if not live:
                                facts["uid_after"] = live
                                break
                            if time.monotonic() >= deadline:
                                raise RuntimeError("owned UID process tree did not quiesce")
                            facts["pid_batches"].append(live)
                            terminate_processes(live, record["uid"])
                        remaining = marked_processes(cell["marker"])
                        facts["marker_after"] = remaining
                        containment = self.cgroup_observation(cell)
                        facts["cgroup_after"] = containment
                        if remaining or containment["pids"] or containment["events"].get("populated") != 0:
                            raise RuntimeError("cleanup observer found surviving containment")
                        record["quiescent"] = True
                    if target is None:
                        record["quiescent"] = False  # An unknown start may still be pending.
                        raise RuntimeError("start target is unknown; retain request/operation for reconciliation")
                    if record["collecting"]:
                        raise RuntimeError("collection already attempted; retain its failed receipt without blind retry")
                    observed = self.call(["lane", "check"], target)
                    if observed["state"] != "exited" or observed.get("survivors") != 0:
                        raise RuntimeError("cleanup service observation is not terminal zero")
                    record["collecting"] = True
                    self.collect(target, cell, observed["handle"])
                    record["collected"] = True
            except Exception as failure:
                errors.append("collection: " + str(failure))
            finally:
                if record["observer"] is not None:
                    try:
                        network = record["observer"].close()
                        logs.append(("cleanup/" + cell["id"] + ".network.json", network))
                    except Exception as failure:
                        record["collected"] = False
                        errors.append("network observer: " + str(failure))
            self.cleanup_errors.extend(errors)
            logs.append(("cleanup/" + cell["id"] + ".json", {
                "target": target, "quiescent": record["quiescent"],
                "collected": record["collected"], "errors": errors, "observations": facts}))
            if record["collected"]:
                self.owned.remove(record)
        self.quiescent = bool(self.records) and all(record["quiescent"] for record in self.records)
        self.collected = bool(self.records) and all(record["collected"] for record in self.records)
        for name, value in logs:
            try:
                self.keep(name, json.dumps(value).encode())
            except OSError as failure:
                self.cleanup_errors.append("cleanup evidence: " + str(failure))
                self.collected = False

    def keep(self, name, data):
        path = beneath(self.evidence, name)
        private_directory(path.parent)
        with path.open("xb") as stream:
            stream.write(data)
        self.references.append({"path": name, "sha256": digest(data),
                                "bytes": len(data)})

    def call(self, words, body):
        self.index += 1
        prefix = "cli/" + str(self.index)
        request = beneath(self.evidence, prefix + ".request.json")
        self.keep(prefix + ".request.json",
                  (json.dumps(body, sort_keys=True) + "\n").encode())
        if self.coordinator is not None and hasattr(self.coordinator, "rpc"):
            request_id, key = secrets.token_hex(16), secrets.token_hex(16)
            self.keep(prefix + ".transport.json", json.dumps({
                "command": " ".join(words), "request_id": request_id,
                "idempotency_key": key, "transport": "original installed human"}).encode())
            reply = self.coordinator.rpc(words, body, request_id, key)
            output = base64.b64decode(reply["stdout"], validate=True)
            error = base64.b64decode(reply["stderr"], validate=True)
            return self.response(words, body, prefix, reply["exit_code"], output, error)
        if self.coordinator is not None:
            try:
                self.coordinator.before_call(self.index, words, body)
            except Exception as failure:
                self.refused = True
                raise RuntimeError("human coordination stopped: " + str(failure)) from failure
        args = [self.context["binary"], *words,
                "--config", self.context["config"],
                "--binding-file", self.context["binding_file"],
                "--request", str(request),
                "--request-id", secrets.token_hex(16),
                "--idempotency-key", secrets.token_hex(16)]
        try:
            args.extend(AUTHORITY.proof_arguments(self.root, self.context["binding_file"],
                self.context["config"], self.index, words))
        except AUTHORITY.OwnerWait as wait:
            self.keep(prefix + ".wait.json", (json.dumps(wait.record()) + "\n").encode())
            raise
        self.keep(prefix + ".argv.json",
                  (json.dumps(args) + "\n").encode())
        try:
            completed = subprocess.run(args, capture_output=True,
                                       timeout=120, check=False)
        except subprocess.TimeoutExpired as failure:
            self.keep(prefix + ".stdout", failure.stdout or b"")
            self.keep(prefix + ".stderr", failure.stderr or b"")
            self.keep(prefix + ".exit", b"unknown: CLI deadline expired\n")
            raise
        return self.response(words, body, prefix, completed.returncode,
                             completed.stdout, completed.stderr)

    def response(self, words, body, prefix, code, output, error):
        self.exit = code
        self.keep(prefix + ".stdout", output)
        self.keep(prefix + ".stderr", error)
        self.keep(prefix + ".exit", (str(self.exit) + "\n").encode())
        if self.exit != 0:
            self.refused = True
            raise RuntimeError("public CLI refused; retained exact stdout/stderr/exit")
        response = json.loads(output)
        # Operation.result is a legitimate BlobRef, not an envelope to unwrap.
        if not isinstance(response, dict) or "request_id" in response:
            raise RuntimeError("public CLI did not return its typed result object")
        if response.get("error") is not None:
            self.refused = True
            raise RuntimeError("public CLI operation returned an error")
        if self.coordinator is not None:
            self.coordinator.after_call(words, body, response)
        return response

    def wait_operation(self, operation):
        deadline = time.monotonic() + 120
        while operation["status"] in ("pending", "running"):
            if time.monotonic() >= deadline:
                raise TimeoutError("operation did not complete")
            time.sleep(0.5)
            operation = self.call(["operation", "get"],
                                  {"operation_id": operation["id"]})
        if operation["status"] != "succeeded" or operation.get("error"):
            raise RuntimeError("operation did not succeed")
        return operation

    def observer_path(self, cell, name, fallback):
        if "observer_paths" not in cell:
            return beneath(self.root, fallback)
        path = Path(cell["observer_paths"][name])
        if not path.is_absolute() or path == Path("/") or path.resolve() != path:
            raise RuntimeError("native observer path is not canonical")
        return path

    def observer_read(self, path):
        return read_fenced(Path(path.anchor), str(path.relative_to(path.anchor)))

    def unchanged(self, cell):
        data, info = self.observer_read(self.observer_path(cell, "outside", cell["outside"]))
        if not stat.S_ISREG(info.st_mode) or not info.st_mode & stat.S_IROTH:
            raise RuntimeError("outside read canary is not world-readable")
        if digest(data) != cell["outside_sha256"]:
            raise RuntimeError("outside canary changed or was not planted")
        return {"device": info.st_dev, "inode": info.st_ino,
                "mode": info.st_mode, "uid": info.st_uid, "gid": info.st_gid,
                "links": info.st_nlink, "mtime_ns": info.st_mtime_ns,
                "ctime_ns": info.st_ctime_ns, "sha256": digest(data)}

    def dac_controls(self, cell):
        paths = {"outside": str(self.observer_path(cell, "outside", cell["outside"]))}
        expected = {"outside": cell["outside_sha256"]}
        for name in ("readonly", "nested"):
            entry = cell["protected"][name]
            paths[name] = str(self.observer_path(cell, name, entry["path"]))
            expected[name] = entry["sha256"]
        result = DAC.probe(paths, cell["lane_uid"], cell["lane_gid"])
        self.keep("observers/" + cell["id"] + ".dac-control.json",
                  json.dumps(result, sort_keys=True).encode())
        DAC.require_access(result, expected)

    def protected_files(self, cell):
        files = cell["protected"]
        if not {"readonly", "nested", "state", "sibling"} <= set(files):
            raise RuntimeError("protected observer files are missing")
        result = {}
        for name, entry in files.items():
            data, info = self.observer_read(self.observer_path(cell, name, entry["path"]))
            if not stat.S_ISREG(info.st_mode) or digest(data) != entry["sha256"]:
                raise RuntimeError("protected file changed: " + name)
            result[name] = {
                "device": info.st_dev, "inode": info.st_ino,
                "mode": info.st_mode, "uid": info.st_uid, "gid": info.st_gid,
                "links": info.st_nlink, "mtime_ns": info.st_mtime_ns,
                "ctime_ns": info.st_ctime_ns, "sha256": digest(data),
            }
        return result

    def cgroup_observation(self, cell):
        relative = Path(cell["cgroup_relative"])
        if not relative.is_absolute() or ".." in relative.parts or relative == Path("/"):
            raise RuntimeError("expected run cgroup must be beneath the v2 root")
        root = Path("/sys/fs/cgroup").resolve()
        path = (root / str(relative).lstrip("/")).resolve()
        path.relative_to(root)
        events = {}
        event_bytes, _ = read_fenced(root, str(relative).lstrip("/") + "/cgroup.events")
        process_bytes, _ = read_fenced(root, str(relative).lstrip("/") + "/cgroup.procs")
        for line in event_bytes.decode().splitlines():
            name, value = line.split()
            events[name] = int(value)
        processes = [int(value) for value in process_bytes.split()]
        return {"relative": str(relative), "events": events, "pids": processes}

    def release_receipt(self, target, process, operation, since):
        page = self.call(["event", "tail"], {
            "life_id": target["life_id"], "run": target["run"], "since": since,
            "cursor": "", "follow": False, "until": "", "deadline_ms": 1000})
        if page.get("complete") is not True:
            raise RuntimeError("release event snapshot is incomplete")
        releases = [event for event in page["events"] if event["kind"] == "helper.released"
                    and event.get("life_id") == target["life_id"]
                    and event.get("run") == target["run"]]
        self.keep("release/" + target["life_id"] + ".json",
                  (json.dumps(releases, sort_keys=True) + "\n").encode())
        if len(releases) != 1:
            raise RuntimeError("helper release receipt is missing or incomplete")
        event, receipt = releases[0], releases[0]["payload"]
        observation = receipt.get("quiescence", {})
        counts = [observation.get("survivors"), receipt.get("live_connections"),
                  receipt.get("queued_jobs"), receipt.get("writable_exports")]
        if any(type(count) is not int or count != 0 for count in counts):
            raise RuntimeError("helper release receipt has unknown or nonzero counts")
        if (not receipt.get("id") or not receipt.get("lease_id") or
                not receipt.get("observed_at") or not receipt.get("effect_id") or
                receipt.get("backend") != "linux-bwrap-landlock" or
                receipt.get("operation_id") != operation or event["operation_id"] != operation or
                receipt.get("containment_id") != process["containment_id"] or
                observation.get("state") != "exited" or observation.get("handle") != process):
            raise RuntimeError("helper release receipt binding differs")

    def collect(self, target, cell, process):
        worktree = self.observer_path(cell, "worktree", cell["worktree"])
        outside = self.observer_path(cell, "outside", cell["outside"])
        if outside == worktree or worktree in outside.parents:
            raise RuntimeError("observer canary is inside the collected worktree")
        if not worktree.is_dir():
            raise RuntimeError("worktree was not observed before collection")
        receipt = self.call(["lane", "archive"], {
            "target": target,
            "expected_generation": self.call(
                ["lane", "status"], target)["generation"]})
        if (not receipt.get("id") or not receipt.get("verified_at") or
                receipt["archive_sha256"] != receipt["read_back_sha256"]):
            raise RuntimeError("archive read-back receipt is incomplete")
        status = self.call(["lane", "status"], target)
        if self.coordinator is not None:
            cell["review"] = self.coordinator.review(self, target, cell)
        review = self.call(["lane", "review"], {
            "target": target, "diff": cell["review"]["diff"],
            "checks": cell["review"]["checks"],
            "record_inventory": cell["review"]["record_inventory"],
            "refusal_resolution": cell["review"]["refusal_resolution"]})
        review_complete(review, target)
        status = self.call(["lane", "status"], target)
        marked = self.call(["lane", "mark"], {
            "target": target, "expected_generation": status["generation"],
            "state": "abandoned", "review": review})
        self.wait_operation(marked)
        status = self.call(["lane", "status"], target)
        before_clean = status["last_seq"]
        cleaned = self.call(["lane", "clean"], {
            "target": target, "expected_generation": status["generation"],
            "archive_receipt_id": receipt["id"]})
        self.wait_operation(cleaned)
        status = self.call(["lane", "status"], target)
        if status.get("cleaned") is not True or os.path.lexists(worktree):
            raise RuntimeError("CLI or independent worktree collection failed")
        self.release_receipt(target, process, cleaned["id"], before_clean)

    def check_operations(self, observation, network):
        internet = {"foreign." + name for name, _, _ in NETWORK_KINDS}
        if set(network) not in (internet, internet | {"foreign.ipc"}):
            raise RuntimeError("outside network observation is incomplete")
        successes = (
            "work.write", "work.read", "work.mmap", "work.link",
            "work.build", "work.git", "tmp.write", "home.write",
            "own.signal", "own.ipc", "own.tcp4", "own.udp4",
            "own.tcp6", "own.udp6", "permitted.network",
            "readonly.read", "nested.read", "detach.double_fork",
        )
        denials = (
            "outside.read", "outside.write", "outside.mmap",
            "outside.link", "readonly.write", "readonly.mmap",
            "readonly.link", "nested.write", "inherited.fd",
            "foreign.tcp4", "foreign.udp4", "foreign.tcp6",
            "foreign.udp6", "foreign.ipc", "foreign.signal",
            "escape.unshare",
        )
        operations = observation["operations"]
        if set(operations) != set(successes + denials):
            raise RuntimeError("missing or unexpected syscall observations")
        for name in successes:
            if operations[name]["outcome"] != "ok":
                raise RuntimeError("own-resource control failed: " + name)
        if observation["no_new_privs"] != 1 or observation["cap_eff"] != 0:
            raise RuntimeError("privilege dropping was not observed")
        self.reached = True
        succeeded, unexplained = [], []
        for name in denials:
            got = operations[name]
            if name in network:
                counters = network[name]
                if set(counters) != {"bytes", "packets", "connections"} or any(
                        type(value) is not int or value < 0 for value in counters.values()):
                    raise RuntimeError("outside network observation is incomplete")
                if any(counters.values()):
                    succeeded.append(name)
                    continue
                if (name.startswith("foreign.udp") and got["outcome"] == "ok" and
                        type(got.get("sent_bytes")) is int and got["sent_bytes"] > 0):
                    continue  # Outside listener independently observed no delivered datagram.
                if name in internet and got["outcome"] == "error" and got.get("kind") == "timeout":
                    continue  # Only these measured network attempts may time out.
            if got["outcome"] != "error":
                succeeded.append(name)
                continue
            allowed = {errno.EACCES, errno.EPERM, errno.EROFS}
            if name.startswith("outside.") or name == "foreign.ipc":
                allowed |= {errno.ENOENT}
            if name in network or name == "foreign.ipc":
                allowed |= {errno.ECONNREFUSED, errno.ENETUNREACH, errno.EHOSTUNREACH}
            if name == "foreign.signal":
                allowed |= {errno.ESRCH}
            if name == "inherited.fd":
                allowed = {errno.EBADF}
            if got.get("kind") == "timeout" or got.get("errno") not in allowed:
                unexplained.append(name)
        self.boundary_failures = succeeded
        if succeeded:
            raise RuntimeError("; ".join("boundary canary succeeded: " + name for name in succeeded))
        if unexplained:
            raise RuntimeError("unexplained syscall failure: " + ", ".join(unexplained))

    def begin_cell(self, cell):
        self.reached = False
        self.boundary_failures = []
        if "observer_paths" not in cell and os.path.lexists(self.root / cell["observation"]):
            raise RuntimeError("canary observation path is not fresh")
        observation_path = self.observer_path(cell, "observation", cell["observation"])
        if os.path.lexists(observation_path):
            raise RuntimeError("canary observation path is not fresh")
        return observation_path

    def run(self):
        binary = Path(self.context["binary"])
        if digest(binary.read_bytes()) != self.context["binary_sha256"]:
            raise RuntimeError("tested artifact digest mismatch")
        if not self.context.get("profile_grant_ids"):
            wait = AUTHORITY.OwnerWait("vendor_authentication")
            self.keep("live.wait.json", (json.dumps(wait.record()) + "\n").encode())
            raise wait
        binding_bytes = Path(self.context["binding_file"]).read_bytes()
        self.keep("inputs/binding.json", binding_bytes)
        binding = json.loads(binding_bytes)
        if (binding["contract_revision"] != "v2.0-draft.4" or
                binding["backend"] != "linux-bwrap-landlock" or
                binding["config"] != self.context["config"] or
                binding.get("artifact_sha256") != self.context["binary_sha256"]):
            raise RuntimeError("installed binding does not match this draft.4 Linux case")
        if not (self.root / "linux-input.json").is_file():
            wait = AUTHORITY.OwnerWait("fixture_preparation")
            self.keep("setup.wait.json", (json.dumps(wait.record()) + "\n").encode())
            raise wait
        fixture_bytes = (self.root / "linux-input.json").read_bytes()
        self.keep("inputs/linux-input.json", fixture_bytes)
        fixture = json.loads(fixture_bytes)
        if fixture["schema"] != "laneboss.linux-case.v2" or not fixture["cells"]:
            raise RuntimeError("missing Linux input cells")
        if (self.context["phase"] == "red" and
                self.context["mutation_id"] not in fixture["red_controls"]):
            raise RuntimeError("fixture does not name this boundary mutation")
        before_host = host_facts()
        self.keep("host-observed.json", json.dumps(before_host).encode())
        for cell in fixture["cells"]:
            deferred = cell.get("native_pending") is True
            if deferred and self.coordinator is None:
                raise RuntimeError("deferred native fixture requires its outside coordinator")
            observation_path = None if deferred else self.begin_cell(cell)
            if (cell["restriction"] != before_host["restriction"] or
                    cell["abi"] != before_host["abi"] or
                    cell["hook"] not in ("absent", "allow") or
                    cell["inner_sandbox"] != "off"):
                raise RuntimeError("cell does not match the actual host/mode")
            before = None if deferred else self.unchanged(cell)
            protected_before = None if deferred else self.protected_files(cell)
            if fixture["service_uid"] == 0:
                raise RuntimeError("the service must run under its dedicated non-root UID")
            marker = cell["marker"]
            if len(marker) < 24 or marked_processes(marker):
                raise RuntimeError("process marker is not fresh")
            uid = None if deferred else cell["lane_uid"]
            if deferred:
                self.coordinator.before_start(self, cell)
            else:
                if (type(uid) is not int or not 0 < uid < 2**32 or
                        uid in (os.geteuid(), fixture["service_uid"]) or uid_processes(uid)):
                    raise RuntimeError("fixture must reserve a fresh dedicated lane UID for cleanup")
                self.dac_controls(cell)
            record = {"cell": cell, "uid": uid, "target": None, "observer": None,
                      "started": False, "quiescent": False, "collected": False, "collecting": False}
            self.records.append(record)
            self.owned.append(record)
            input_bytes, _ = read_fenced(self.root, cell["canary_input"])
            self.keep("inputs/" + cell["id"] + ".canary.json", input_bytes)
            canary_input = json.loads(input_bytes)
            record["observer"] = (self.coordinator.network if deferred else
                                  NetworkObserver(canary_input["foreign"]))
            for name, _, _ in NETWORK_KINDS:
                if record["observer"].addresses[name] != canary_input["foreign"][name]:
                    raise RuntimeError("foreign listener address differs from the canary input")
            controls = record["observer"].positive_control(
                bytes.fromhex(canary_input["payload_hex"]))
            self.keep("observers/" + cell["id"] + ".network-control.json",
                      json.dumps(controls).encode())
            start_bytes = beneath(self.root, cell["start_request"]).read_bytes()
            self.keep("inputs/" + cell["id"] + ".start.json", start_bytes)
            start = json.loads(start_bytes)
            if start["driver"] not in ("claudock-cli", "codex"):
                raise RuntimeError("a real supported driver is required")
            if start.get("profile_grant_id") not in self.context["profile_grant_ids"]:
                raise RuntimeError("start profile is outside the authorized real-driver grant set")
            auth_name = cell.get("authorization", "live-authorization.json")
            if not (self.root / auth_name).exists():
                raise AUTHORITY.OwnerWait("vendor_authentication")
            auth_raw, auth_info = read_fenced(self.root, auth_name)
            if (auth_info.st_uid != os.geteuid() or
                    stat.S_IMODE(auth_info.st_mode) != 0o600 or auth_info.st_nlink != 1):
                raise RuntimeError("live authorization is not private to the observer")
            self.keep("inputs/" + cell["id"] + ".authorization.json", auth_raw)
            source = Path(__file__).resolve().parents[4] / "scripts/v2-serve/case_linux.py"
            spec = importlib.util.spec_from_file_location("linux_live_authorization", source)
            live = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(live)
            live.live_authorization(auth_raw, self.context, start, cell["id"])
            record["started"] = True
            operation = self.call(["lane", "start"], start)
            record["operation"] = operation
            if operation.get("life_id") and operation.get("run"):
                record["target"] = {"life_id": operation["life_id"], "run": operation["run"]}
            operation = self.wait_operation(operation)
            target = {"life_id": operation["life_id"], "run": operation["run"]}
            record["target"] = target
            if self.coordinator is not None:
                self.coordinator.after_start(self, record, operation)
            if deferred:
                uid = record["uid"]
                before = self.unchanged(cell)
                protected_before = self.protected_files(cell)
                self.dac_controls(cell)
                observation_path = self.begin_cell(cell)
                self.coordinator.release_input(self, record, input_bytes)
            deadline = time.monotonic() + 180
            while not observation_path.exists():
                if time.monotonic() >= deadline:
                    raise TimeoutError("agent never produced syscall observations")
                time.sleep(0.5)
            observation_bytes, _ = self.observer_read(observation_path)
            self.keep("observations/" + cell["id"] + ".json", observation_bytes)
            observation = json.loads(observation_bytes)
            if observation["marker_sha256"] != digest(marker.encode()):
                raise RuntimeError("canary observation has the wrong marker")
            if observation["input_sha256"] != digest(input_bytes):
                raise RuntimeError("canary used different syscall inputs")
            network = record["observer"].finish()
            self.keep("observers/" + cell["id"] + ".network.json", json.dumps(network).encode())
            self.check_operations(observation, network)
            if self.coordinator is not None:
                self.coordinator.check_foreign(self, "after-canary")
            if self.unchanged(cell) != before:
                raise RuntimeError("outside inode/mode/content changed")
            if self.protected_files(cell) != protected_before:
                raise RuntimeError("protected inode/mode/content changed")
            identities = marked_processes(marker)
            if not identities:
                raise RuntimeError("no real detached canary was observed")
            containment = self.cgroup_observation(cell)
            if containment["events"].get("populated") != 1:
                raise RuntimeError("run cgroup was not observed populated")
            for pid, identity in identities.items():
                if (not identity["uids"] or len(set(identity["uids"])) != 1 or
                        identity["uids"][0] != uid or
                        identity["gids"] != [cell["lane_gid"]] * 4 or
                        identity["groups"]):
                    raise RuntimeError("canary UID/groups confinement did not match")
                if (int(pid) not in containment["pids"] or
                        "0::" + containment["relative"] not in identity["cgroup"]):
                    raise RuntimeError("canary cgroup membership did not match")
            status = self.call(["lane", "status"], target)
            session = status["session"]
            if (session["driver"] != start["driver"] or not session["vendor_id"] or
                    not session["vendor_version"] or not session["home_id"] or
                    not session["history_id"]):
                raise RuntimeError("the real vendor session mapping was not retained")
            stop = self.call(["lane", "stop"], {
                "target": target, "expected_generation": status["generation"],
                "reason": cell["stop_reason"]})
            self.wait_operation(stop)
            observed = self.call(["lane", "check"], target)
            if observed["state"] != "exited" or observed.get("survivors") != 0:
                raise RuntimeError("stop did not establish known zero survivors")
            survivors = marked_processes(marker)
            ended_containment = self.cgroup_observation(cell)
            protected_after = self.protected_files(cell)
            self.keep("observers/" + cell["id"] + ".json", json.dumps({
                "before": identities, "after": survivors,
                "cgroup_before": containment, "cgroup_after": ended_containment,
                "outside": self.unchanged(cell), "protected_before": protected_before,
                "protected_after": protected_after}).encode())
            if (survivors or ended_containment["pids"] or
                    ended_containment["events"].get("populated") != 0):
                raise RuntimeError("observer found a surviving run process")
            if uid_processes(uid):
                raise RuntimeError("observer found a surviving owned UID process")
            if self.coordinator is not None:
                self.coordinator.check_foreign(self, "after-stop")
            record["quiescent"] = True
            if (self.unchanged(cell) != before or protected_after != protected_before):
                raise RuntimeError("observer found changed canary bytes or metadata")
            record["collecting"] = True
            self.collect(target, cell, observed["handle"])
            record["collected"] = True
            self.owned.remove(record)
        if host_facts() != before_host:
            raise RuntimeError("host restrictions changed during acceptance")
        self.quiescent = not self.owned
        self.collected = not self.owned
        self.reached = True
        self.exit = 0


def main(argv=None, coordinator=None, preparation_error=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--plan", type=Path)
    args = parser.parse_args(argv)
    if args.plan is not None:
        source = Path(__file__).resolve().parents[4] / "scripts/v2-serve/case_linux.py"
        spec = importlib.util.spec_from_file_location("linux_installed_producer", source)
        producer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(producer)
        return producer.main(["--context", str(args.context), "--result", str(args.result),
                              "--plan", str(args.plan)])
    context = load(args.context)
    resolved_result = args.result.resolve()
    if (not args.result.is_absolute() or args.result != resolved_result or
            (not resolved_result.is_relative_to(Path(context["evidence_root"])) and
             resolved_result != Path(context["test_root"]).resolve() / "result.json")):
        raise RuntimeError("result path escapes the frozen case scopes")
    case = Case(context, coordinator=coordinator)
    message = ""
    reason = ""
    owner_wait = False
    try:
        if (context["schema"] != "laneboss.e2e-context.v2" or
                context["case_id"] != "linux" or
                context["phase"] not in ("candidate", "red")):
            raise RuntimeError("context schema mismatch")
        if bool(context["mutation_id"]) != (context["phase"] == "red"):
            raise RuntimeError("mutation identity does not match the phase")
        if context["phase"] == "red" and context["mutation_id"] not in PUBLIC_REDS:
            raise RuntimeError("unknown Linux boundary mutation identity")
        for field in ("binary", "binding_file", "test_root", "evidence_root"):
            if not Path(context[field]).is_absolute():
                raise RuntimeError("context paths must be absolute")
        if not args.result.is_absolute():
            raise RuntimeError("result path must be absolute")
        result_path = args.result.resolve()
        if not result_path.is_relative_to(case.evidence):
            if result_path != case.root / "result.json":
                raise RuntimeError("result path escapes the frozen case scopes")
        case.keep("inputs/context.json", args.context.read_bytes())
        if preparation_error is not None:
            raise preparation_error
        case.run()
    except (OSError, ValueError, KeyError, TypeError, RuntimeError,
            subprocess.SubprocessError) as failure:
        reason = str(failure)
        owner_wait = (isinstance(failure, AUTHORITY.OwnerWait) or
                      getattr(failure, "code", None) == "prerequisite_missing")
        if owner_wait:
            case.exit = 69
            case.keep("owner.wait.json", (json.dumps(failure.record()) + "\n").encode())
        message = type(failure).__name__ + ": " + reason
        case.keep("failure.txt", (message + "\n").encode())
    finally:
        case.cleanup()
        if isinstance(case.coordinator, HANDOFF.Remote):
            try:
                receipt = case.coordinator.collect()
                if (receipt.get("processes_quiescent") is not True or
                        receipt.get("temporary_resources_collected") is not True or
                        not receipt.get("evidence")):
                    raise RuntimeError("independent Linux collection receipt is incomplete")
                case.references.extend(ref for ref in receipt["evidence"] if ref not in case.references)
                case.keep("observers/installed-collection.json", json.dumps(receipt, sort_keys=True).encode())
            except (RuntimeError, OSError, ValueError, KeyError) as failure:
                case.quiescent = case.collected = False
                case.cleanup_errors.append(str(failure))
    if case.cleanup_errors and not message:
        reason = "cleanup failed: " + "; ".join(case.cleanup_errors)
        message = reason
        case.keep("cleanup-failure.txt", (message + "\n").encode())
    if context["phase"] == "red":
        expected = PUBLIC_REDS.get(context["mutation_id"], ())
        targeted = case.reached and red_target_reached(context["mutation_id"], reason, case.boundary_failures)
        case.keep("mutation-observed.json", json.dumps({
            "mutation_id": context["mutation_id"], "expected_failure": expected,
            "target_assertion_failed": targeted, "reason": reason,
            "succeeded_denials": case.boundary_failures}).encode())
        if message and not targeted:
            case.reached = False
    verdict = "fail" if message else "pass"
    result = {
        "schema": "laneboss.e2e-result.v2", "case_id": "linux",
        "phase": context["phase"], "mutation_id": context["mutation_id"],
        "binary_sha256": context["binary_sha256"],
        "source_sha256": context["source_sha256"],
        "assertions": [{"id": "OS-LINUX", "reached": case.reached,
                        "verdict": verdict, "observed_exit": case.exit,
                        "evidence": case.references}],
        "collection": {"processes_quiescent": case.quiescent,
                       "temporary_resources_collected": case.collected,
                       "evidence": [reference for reference in case.references
                                    if reference["path"].startswith(("cleanup/", "observers/", "release/"))]},
    }
    atomic_json(args.result, result)
    return (69 if owner_wait else 1) if message else 0


if __name__ == "__main__":
    sys.exit(main())
