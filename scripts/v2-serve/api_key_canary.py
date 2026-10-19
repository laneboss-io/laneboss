"""One-shot key source and value-free exposure observations for the Linux harness.

After source consumption, the key exists only in memory and the authenticated
local socket transfer.
This module neither authenticates a provider nor grants launch compatibility.
"""

import hashlib
import os
from pathlib import Path
import re
import socket
import stat
import struct
import threading


class Canary:
    def __init__(self, key=None, real=None):
        self.real = key is not None if real is None else real
        self.key = self.fake_material() if key is None else key
        self.needles = (self.key, self.key[-8:])
        self.rows = []
        self.socket = None
        self.thread = None
        self.done = threading.Event()
        self.source_error = False
        self.transfers = 0
        self.withheld = False
        self.lane_scans = 0

    @classmethod
    def from_file(cls, path):
        return cls(cls.read_file(path), real=True)

    @staticmethod
    def fake_material():
        return b"sk-ant-api03-" + os.urandom(32).hex().encode("ascii")

    @classmethod
    def read_file(cls, path):
        """Consume a root-owned 0400 file once, without retaining its path/value.

        Walk using directory descriptors so neither the source nor an ancestor
        can be a symlink. All errors are fixed text: even a source filename may
        contain material that must never reach a traceback or evidence.
        """
        directory = descriptor = None
        try:
            path = Path(path)
            if not path.is_absolute() or ".." in path.parts or not path.name:
                raise ValueError("real API key file requires an absolute ordinary path")
            directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            for component in path.parts[1:-1]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                os.close(directory)
                directory = child
            descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW |
                                 os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                    before.st_uid != 0 or stat.S_IMODE(before.st_mode) != 0o400 or
                    not 7 < before.st_size <= 65536):
                raise ValueError("real API key source must be a root-owned single-link 0400 regular file")
            # One bounded read, followed immediately by identity check/unlink.
            # No command, environment variable, evidence file or log sees it.
            raw = os.read(descriptor, 65537)
            after = os.fstat(descriptor)
            named = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            identity = lambda info: (info.st_dev, info.st_ino, info.st_mode,
                                     info.st_uid, info.st_nlink, info.st_size,
                                     info.st_mtime_ns, info.st_ctime_ns)
            if identity(before) != identity(after) or identity(after) != identity(named):
                raise ValueError("real API key source changed during consumption")
            os.unlink(path.name, dir_fd=directory)
            if len(raw) != before.st_size:
                raise ValueError("real API key source was not read completely")
            key = raw.removesuffix(b"\n")
            if re.fullmatch(rb"sk-ant-[A-Za-z0-9_-]+", key) is None or len(key) <= 8:
                raise ValueError("real API key source has invalid material")
            return key
        except (OSError, ValueError):
            raise ValueError("real API key file is missing, unsafe, changed or invalid") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if directory is not None:
                os.close(directory)

    def matches(self, data):
        return {name: needle in data for name, needle in zip(("key", "last8"), self.needles)}

    def retainable(self, data):
        """Never write material to evidence, even if the vendor prints it."""
        found = self.matches(data)
        if any(found.values()):
            self.withheld = True
            self.rows.append(dict(place="evidence-input", **found))
            return b"[API key canary material withheld; exposure found]\n"
        return data

    def start(self, config, service_uid, binary):
        path = Path("/run/laneboss-v2") / config / "api-key-canary.sock"
        if os.path.lexists(path):
            raise ValueError("preserve existing API key canary endpoint")
        parent = path.parent.stat()
        if parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) & 0o022:
            raise ValueError("API key canary endpoint parent is not protected")
        self.socket_path = path
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.bind(str(path))
        os.chown(path, service_uid, -1)
        path.chmod(0o600)
        self.socket.listen(4)
        self.socket.settimeout(0.5)
        expected = hashlib.sha256(binary.read_bytes()).digest()

        def serve():
            while not self.done.is_set():
                try:
                    connection, _ = self.socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if not self.done.is_set():
                        self.source_error = True
                    return
                with connection:
                    try:
                        pid, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                        if uid != service_uid or hashlib.sha256((Path("/proc") / str(pid) / "exe").read_bytes()).digest() != expected:
                            self.source_error = True
                            continue
                        connection.settimeout(5)
                        connection.sendall(self.key)
                        self.transfers += 1
                    except OSError:
                        self.source_error = True

        self.thread = threading.Thread(target=serve, name="real-api-key-source" if self.real else "fake-api-key-source", daemon=True)
        self.thread.start()

    def scan(self, place, root, required=True):
        """Read regular files to EOF without following links; report no values."""
        root = Path(root)
        result = {"place": place, "key": False, "last8": False, "files": 0, "links": 0,
                  "special": 0, "unreadable": False, "present": os.path.lexists(root)}
        if place == "harvest":
            result["credential_file"] = False
        if not result["present"]:
            result["unreadable"] = required
            if required:
                result["unreadable_path"] = self.safe_path(root)
            self.rows.append(result)
            return result

        def observe(data, path):
            found = self.matches(data)
            for key, value in found.items():
                result[key] |= value
            if any(found.values()) and "path" not in result:
                result["path"] = self.safe_path(path)

        def inspect(path):
            info = path.lstat()
            name = os.fsencode(path.name)
            observe(name, path)
            if place == "harvest" and path.name == "key-store.json":
                result["credential_file"] = True
                return  # Refuse this class by name, without opening its bytes.
            if stat.S_ISDIR(info.st_mode):
                for child in path.iterdir():
                    visit(child)
            elif stat.S_ISREG(info.st_mode):
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(descriptor, "rb") as stream:
                    actual = os.fstat(stream.fileno())
                    if not stat.S_ISREG(actual.st_mode) or (info.st_dev, info.st_ino) != (actual.st_dev, actual.st_ino):
                        raise ValueError("API key scan input changed")
                    # Keep a boundary overlap so arbitrarily placed matches
                    # cannot disappear between read chunks.
                    tail = b""
                    while chunk := stream.read(1 << 20):
                        data = tail + chunk
                        observe(data, path)
                        tail = data[-len(self.key):]
                    result["files"] += 1
            elif stat.S_ISLNK(info.st_mode):
                observe(os.fsencode(os.readlink(path)), path)
                result["links"] += 1
            elif stat.S_ISSOCK(info.st_mode):
                result["special"] += 1
            else:
                raise ValueError("API key scan encountered a non-searchable file")

        def visit(path):
            try:
                inspect(path)
            except (OSError, ValueError):
                result.setdefault("unreadable_path", self.safe_path(path))
                raise

        try:
            visit(root)
        except (OSError, ValueError):
            result["unreadable"] = True
        self.rows.append(result)
        return result

    def scan_lane(self, case, record):
        """Use the native helper's retained home binding, before lane clean."""
        import json
        from pathlib import Path

        journals = Path("/var/lib/laneboss-v2/helper") / case.config
        selected = []
        for path in journals.glob("*.json"):
            value = json.loads(path.read_bytes())
            if value.get("launch_storage", {}).get("binding", {}).get("target") == record["target"]:
                selected.append(value)
        if len(selected) != 1:
            raise ValueError("API key scan cannot identify its exact helper lease")
        journal = selected[0]
        # The helper's registered storage inventory supplies identities; no
        # lane-authored path is accepted as the home root.
        storage = journal.get("launch_storage", {})
        binding = storage.get("binding", {})
        home = binding.get("home", {})
        root_id = home.get("root_id", "")
        lease_id = journal.get("lease", {}).get("id", "")
        if not root_id or not lease_id or any("/" in item or item in (".", "..") for item in (root_id, lease_id)):
            raise ValueError("API key scan lacks native home selectors")
        base = Path("/var/lib/laneboss-v2/lanes") / case.config / lease_id
        lane_home = base / root_id
        identity = [item for item in storage.get("directories", []) if item.get("id") == root_id]
        actual = lane_home.lstat()
        if len(identity) != 1 or str(actual.st_dev) != identity[0].get("device") or str(actual.st_ino) != identity[0].get("inode"):
            raise ValueError("API key scan native home identity changed")
        self.scan("lane-home", lane_home)
        self.scan("claude-config", lane_home / ".claude", required=False)
        self.scan("claudock-registry", lane_home / ".config/claudock/profiles.json", required=False)
        self.scan("claudock-credential-store", lane_home / ".config/claudock/credential-store.json", required=False)
        self.lane_scans += 1
        record["api_key_scanned"] = True
        if any(row.get("key") or row.get("last8") or row.get("unreadable") for row in self.rows):
            raise ValueError("API key stopped-lane scan found material or unreadable input")

    def finish(self, case):
        for record in case.lane_records:
            if record["driver"] == "claudock-cli" and record["quiescent"] and not record.get("api_key_scanned"):
                try:
                    self.scan_lane(case, record)
                except (OSError, ValueError, KeyError, TypeError):
                    self.rows.append({"place": "stopped-lane", "unreadable": True})
        if self.socket is not None:
            self.done.set()
            self.socket.close()
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                self.source_error = True
            self.socket_path.unlink()
        self.scan("helper-state", Path("/var/lib/laneboss-v2/helper") / case.config)
        # The harness case root and the product's installed service evidence
        # are distinct scopes. Measure both; neither is an exemption.
        installed = getattr(case, "installed", {})
        state = installed.get("state_directory")
        if isinstance(state, str) and Path(state).is_absolute():
            self.scan("service-evidence", Path(state))
        else:
            self.rows.append({"place": "service-evidence", "unreadable": True, "present": False})
        self.scan("evidence", case.root)
        for role in ("service", "helper", "credential"):
            unit = "laneboss-" + role + "@" + case.config + ".service"
            result = case.command("api-key-journal-" + role,
                ["journalctl", "--quiet", "--no-pager", "--output=cat", "_SYSTEMD_UNIT=" + unit,
                 "+", "UNIT=" + unit], clean=True, expected=None)
            found = self.matches(result)
            self.rows.append(dict(place=role + "-journal", **found,
                bytes=len(result), unreadable=case.last["exit_code"] != 0 or not result.strip()))
        self.scan("evidence-after-journals", case.root)
        observations = {"source_transfers": self.transfers, "source_error": self.source_error,
                        "lane_scans": self.lane_scans, "evidence_withheld": self.withheld,
                        "places": self.rows}
        case.keep_json("api-key-canary.json", observations)
        return observations

    def safe_path(self, path):
        value = self.redact(os.fsdecode(path))
        if any(self.matches(os.fsencode(value)).values()):
            return "<path>"
        return value

    def redact(self, value):
        if isinstance(value, str):
            for needle in self.needles:
                text = needle.decode("ascii")
                if text in value:
                    self.withheld = True
                    value = value.replace(text, "[canary material withheld]")
            return value
        if isinstance(value, list):
            return [self.redact(item) for item in value]
        if isinstance(value, dict):
            return {self.redact(key): self.redact(item) for key, item in value.items()}
        return value
