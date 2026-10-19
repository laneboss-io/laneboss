"""Sealed, self-contained Ubuntu fixture administration, invoked with -I -B.

The supervisor installs this file and its two companion inputs in a protected
kit before authorizing a box run. This module imports no checkout code.
"""

import argparse
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time


class KitError(RuntimeError):
    pass


def check(condition, message):
    if not condition:
        raise KitError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def clean_env(home="/", temporary="/tmp", config=None):
    value = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home),
             "TMPDIR": str(temporary), "LANG": "C.UTF-8"}
    if config is not None:
        value["LANEBOSS_CONFIG"] = config
    return value


def no_links(root, relative, *, directory=False):
    """Open beneath an already-open directory; never reopen a checked path."""
    parts = relative.split("/")
    check(parts and all(part not in ("", ".", "..") for part in parts),
          "invalid relative fixture path")
    descriptor = os.dup(root)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_fd
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY
        if directory:
            flags |= os.O_DIRECTORY
        result = os.open(parts[-1], flags, dir_fd=descriptor)
        info = os.fstat(result)
        if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
            os.close(result)
            raise KitError("fixture read requires a regular file or directory")
        return result
    finally:
        os.close(descriptor)


def read_at(root, relative, maximum=64 * 1024 * 1024):
    descriptor = no_links(root, relative)
    try:
        metadata = os.fstat(descriptor)
        check(metadata.st_size <= maximum and metadata.st_nlink == 1,
              "fixture read exceeds bound or is hardlinked")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            value = source.read(maximum + 1)
        check(len(value) <= maximum, "fixture read grew beyond bound")
        return value
    finally:
        os.close(descriptor)


def write_at(root, name, data, *, uid=0, gid=0, mode=0o644, replace=False):
    check("/" not in name and name not in ("", ".", ".."), "invalid output name")
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
    if not replace:
        flags |= os.O_EXCL
    descriptor = os.open(name, flags, mode, dir_fd=root)
    try:
        info = os.fstat(descriptor)
        check(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
              "linked or special output refused")
        if replace:
            os.ftruncate(descriptor, 0)
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(data)
            output.flush()
            os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        retained = hashlib.sha256()
        size = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            retained.update(block)
            size += len(block)
        check(size == len(data) and retained.hexdigest() == digest(data),
              "written input read-back differs")
    finally:
        os.close(descriptor)


def json_at(root, name, value, **options):
    write_at(root, name, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode(),
             **options)


def verify_archive(descriptor, inventory):
    seen = set()
    with os.fdopen(os.dup(descriptor), "rb") as source:
        with tarfile.open(fileobj=source, mode="r:gz") as archive:
            for member in archive:
                check(member.name not in seen and member.name in inventory,
                      "unexpected or duplicate fixture archive member")
                expected = inventory[member.name]
                if member.isdir():
                    actual = {"kind": "directory"}
                elif member.issym():
                    actual = {"kind": "symlink", "target": member.linkname}
                else:
                    check(member.isfile(), "special fixture archive member")
                    stream = archive.extractfile(member)
                    check(stream is not None, "unreadable fixture archive member")
                    checksum, size = hashlib.sha256(), 0
                    with stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b""):
                            checksum.update(block)
                            size += len(block)
                    actual = {"kind": "file", "bytes": size, "sha256": checksum.hexdigest()}
                check(actual == expected, "fixture archive member read-back differs")
                seen.add(member.name)
    check(seen == set(inventory), "fixture archive omitted bytes")


def process(pid):
    prefix = Path("/proc") / str(pid)
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
        uids = next(line.split()[1:] for line in (prefix / "status").read_bytes().splitlines()
                    if line.startswith(b"Uid:"))
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        return {"pid": int(pid), "start": boot + ":" + fields[19].decode("ascii"),
                "uids": [int(value) for value in uids]}
    except (FileNotFoundError, ProcessLookupError):
        return None


def processes():
    result = []
    for item in Path("/proc").iterdir():
        if item.name.isdigit():
            identity = process(int(item.name))
            if identity is not None:
                result.append(identity)
    return result


def snapshot():
    return {"accounts": {item.pw_name: [item.pw_uid, item.pw_gid] for item in pwd.getpwall()},
            "groups": {item.gr_name: item.gr_gid for item in grp.getgrall()},
            "process_uids": sorted({uid for item in processes() for uid in item["uids"]})}


def owned_mkdir(root, name, uid, gid, mode):
    check("/" not in name and name not in ("", ".", ".."), "invalid directory name")
    os.mkdir(name, mode, dir_fd=root)
    descriptor = no_links(root, name, directory=True)
    os.fchown(descriptor, uid, gid)
    os.fchmod(descriptor, mode)
    return descriptor


def checked(argv, *, timeout=60, **options):
    # timeout runs at this root authority, so it can reap switched descendants.
    command = ["/usr/bin/timeout", "--kill-after=5s", str(timeout), *argv]
    result = subprocess.run(command, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=clean_env(), check=False, **options)
    if result.returncode != 0:
        sys.stdout.buffer.write(result.stdout)
        sys.stderr.buffer.write(result.stderr)
        raise KitError("administrator step failed: " + Path(argv[0]).name)
    return result


class Kit:
    def __init__(self, directory):
        check(sys.platform == "linux" and os.geteuid() == 0,
              "administrator step requires root on Linux")
        release = Path("/etc/os-release").read_text()
        check('VERSION_ID="24.04"' in release and
              re.search(r"(?m)^ID=ubuntu$", release), "Ubuntu 24.04 is required")
        self.directory = Path(directory)
        check(self.directory.parent == Path("/var/tmp") and
              re.fullmatch(r"lb-[a-z0-9-]+-[a-z0-9]{8}", self.directory.name),
              "invalid lane/run directory")
        parent = os.open("/var/tmp", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self.fd = no_links(parent, self.directory.name, directory=True)
        finally:
            os.close(parent)
        info = os.fstat(self.fd)
        self.controller = pwd.getpwnam("ubuntu").pw_uid
        check(info.st_uid in (0, self.controller) and info.st_mode & 0o022 == 0,
              "unsafe fixture directory owner/mode")
        self.lock = os.open(".kit-lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                            0o600, dir_fd=self.fd)
        check(os.fstat(self.lock).st_nlink == 1, "linked kit lock")
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        kit_dir = Path(__file__).resolve().parent
        for name in ("privileged.py", "contract.json", "bwrap.apparmor"):
            path = kit_dir / name
            for component in (path, *path.parents):
                metadata = component.lstat()
                check(metadata.st_uid == 0 and metadata.st_mode & 0o022 == 0
                      and not stat.S_ISLNK(metadata.st_mode), "kit is not sealed")
        self.contract = json.loads((kit_dir / "contract.json").read_bytes())
        check(self.contract["schema"] == 2 and
              self.contract["serve"] == ["serve", "--config", "{config}",
                                         "--installation", "{installation}", "--binding", "{binding}"],
              "invalid frozen fixture contract")
        self.kit_dir = kit_dir

    def resources(self):
        descriptor = no_links(self.fd, "resources.json")
        try:
            info = os.fstat(descriptor)
            check(info.st_uid == 0 and info.st_mode & 0o022 == 0,
                  "resource record is not protected")
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                result = json.load(source)
        finally:
            os.close(descriptor)
        check(result["controller_uid"] == self.controller, "controller changed")
        return result

    def store(self, resources):
        json_at(self.fd, "resources.json", resources, replace=True)

    def admin(self):
        return no_links(self.fd, "admin", directory=True)

    def record(self, name, value):
        descriptor = self.admin()
        try:
            json_at(descriptor, name, value, replace=True)
        finally:
            os.close(descriptor)

    def provision(self):
        request = json.loads(read_at(self.fd, "provision.json"))
        check(set(request) == {"lane", "run_id", "binary_sha256"}, "invalid provision request")
        lane = request["lane"]
        run_id = request["run_id"]
        check(re.fullmatch(r"lb-[a-z0-9-]{1,24}", lane) and
              re.fullmatch(r"[a-z0-9]{8}", run_id) and
              self.directory.name == lane + "-" + run_id, "invalid lane/run binding")
        build_fd = no_links(self.fd, "build", directory=True)
        try:
            check(os.fstat(build_fd).st_uid == self.controller, "invalid build owner")
            binary_fd = no_links(build_fd, "laneboss")
            try:
                info = os.fstat(binary_fd)
                check(info.st_uid == self.controller and info.st_nlink == 1,
                      "invalid binary input owner/link")
                with os.fdopen(binary_fd, "rb", closefd=False) as source:
                    binary_bytes = source.read()
            finally:
                os.close(binary_fd)
        finally:
            os.close(build_fd)
        check(digest(binary_bytes) == request["binary_sha256"], "binary hash changed")
        baseline = snapshot()
        os.fchown(self.fd, 0, 0)
        os.fchmod(self.fd, 0o755)
        os.fchown(self.lock, 0, 0)
        os.fchmod(self.lock, 0o600)
        resources = {"schema": 2, "controller_uid": self.controller, "baseline": baseline,
                     "lane": lane, "run_id": run_id, "users": [], "groups": [],
                     "profile_loaded": False, "teardown_complete": False}
        json_at(self.fd, "resources.json", resources)
        admin = owned_mkdir(self.fd, "admin", 0, 0, 0o755)
        json_at(admin, "platform.json", {
            "kernel": platform.release(), "architecture": platform.machine(),
            "python": platform.python_version(),
            "os_release_sha256": digest(Path("/etc/os-release").read_bytes()),
            "cgroup_v2": Path("/sys/fs/cgroup/cgroup.controllers").is_file()})
        os.close(admin)
        rpc = "lbrpc" + run_id
        checked(["/usr/sbin/groupadd", rpc])
        resources["groups"].append(rpc)
        self.store(resources)
        rpc_gid = grp.getgrnam(rpc).gr_gid
        accounts = {}
        for role, prefix in (("service", "lbsvc"), ("operator", "lbop"), ("lane", "lblane")):
            name = prefix + run_id
            home = self.directory / (role + "-home")
            args = ["/usr/sbin/useradd", "--no-create-home", "--user-group",
                    "--home-dir", str(home), "--shell", "/usr/sbin/nologin"]
            if role in ("service", "operator"):
                args.extend(["--groups", rpc])
            checked([*args, name])
            user = pwd.getpwnam(name)
            check(user.pw_uid not in (0, self.controller), "unsafe fixture UID")
            account = {"name": name, "uid": user.pw_uid, "gid": user.pw_gid,
                       "home": str(home), "temporary": str(home / "tmp")}
            resources["users"].append(account)
            resources["groups"].append(name)
            self.store(resources)
            home_fd = owned_mkdir(self.fd, role + "-home", user.pw_uid, user.pw_gid, 0o700)
            temporary = owned_mkdir(home_fd, "tmp", user.pw_uid, user.pw_gid, 0o700)
            os.close(temporary)
            os.close(home_fd)
            accounts[role] = account
        service = accounts["service"]
        for name, gid, mode in (("state", service["gid"], 0o700),
                                ("org", service["gid"], 0o700),
                                ("secrets", service["gid"], 0o700),
                                ("runtime", service["gid"], 0o700)):
            descriptor = owned_mkdir(self.fd, name, service["uid"], gid, mode)
            os.close(descriptor)
        binary_dir = owned_mkdir(self.fd, "bin", 0, 0, 0o755)
        try:
            write_at(binary_dir, "laneboss", binary_bytes, mode=0o555)
        finally:
            os.close(binary_dir)
        paths = {name: str(self.directory / name) for name in ("state", "org", "secrets", "runtime")}
        paths["binary"] = str(self.directory / "bin" / "laneboss")
        paths["socket"] = str(self.directory / "runtime" / "service.sock")
        resources.update({"accounts": accounts, "paths": paths, "rpc_gid": rpc_gid,
                          "binary_sha256": digest(binary_bytes),
                          "contract": self.contract})
        self.store(resources)
        json_at(self.fd, "context.json", resources)
        print("provision: protected paths and three distinct non-root users")

    def account(self, role):
        check(role in ("service", "operator", "lane"), "unknown fixture account")
        account = self.resources()["accounts"][role]
        actual = pwd.getpwnam(account["name"])
        check(actual.pw_uid == account["uid"] != 0 and
              actual.pw_gid == account["gid"], "fixture account changed")
        return account

    def run_user(self, role, argv, *, timeout=60, input_bytes=None):
        account = self.account(role)
        groups = [self.resources()["rpc_gid"]] if role in ("service", "operator") else []
        with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as out:
            with tempfile.TemporaryFile() as err:
                source.write(input_bytes or b"")
                source.seek(0)
                child = subprocess.Popen(
                    ["/usr/bin/timeout", "--kill-after=5s", str(timeout), *argv],
                    user=account["uid"], group=account["gid"], extra_groups=groups,
                    cwd=account["home"],
                    env=clean_env(account["home"], account["temporary"],
                                  self.resources()["lane"]),
                    stdin=source, stdout=out, stderr=err, umask=0o022, close_fds=True)
                try:
                    code = child.wait(timeout=timeout + 10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
                    code = 124
                out.seek(0)
                err.seek(0)
                return subprocess.CompletedProcess(argv, code, out.read(), err.read())

    def socket_info(self, path=None):
        resources = self.resources()
        relative = "runtime/service.sock" if path is None else path
        descriptor = no_links(self.fd, relative.rsplit("/", 1)[0], directory=True)
        try:
            name = relative.rsplit("/", 1)[-1]
            try:
                info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                return {"present": False}
            check(stat.S_ISSOCK(info.st_mode), "service endpoint is not a socket")
            return {"present": True, "uid": info.st_uid, "gid": info.st_gid,
                    "mode": stat.S_IMODE(info.st_mode), "inode": info.st_ino}
        finally:
            os.close(descriptor)

    def controls(self):
        """Actual fixture controls before invoking any product service."""
        resources = self.resources()
        service = self.account("service")
        lane = self.account("lane")
        rpc_gid = resources["rpc_gid"]
        observed = {}
        for role in ("service", "operator", "lane"):
            account = self.account(role)
            result = self.run_user(role, ["/usr/bin/id", "-u"])
            check(result.returncode == 0 and int(result.stdout.strip()) == account["uid"],
                  "kernel UID control failed")
            memberships = os.getgrouplist(account["name"], account["gid"])
            check(account["gid"] != rpc_gid, "RPC group became a private primary group")
            check((rpc_gid in memberships) == (role in ("service", "operator")),
                  "unexpected fixture RPC membership")
            try:
                sudo_gid = grp.getgrnam("sudo").gr_gid
            except KeyError:
                sudo_gid = -1
            check(sudo_gid not in memberships, "fixture account gained sudo membership")
            observed[role] = {"uid": account["uid"], "gid": account["gid"],
                              "groups": memberships}
        socket_path = str(self.directory / "runtime" / "control.sock")
        code = ("import socket,sys; "
                "s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.close()")
        result = self.run_user("service", ["/usr/bin/python3", "-I", "-c", code, socket_path])
        check(result.returncode == 0, "plain socket control failed")
        metadata = self.socket_info("runtime/control.sock")
        check(metadata["present"] and metadata["uid"] == service["uid"] and metadata["gid"] == service["gid"]
              and metadata["gid"] != rpc_gid and metadata["mode"] == 0o755,
              "fixture manufactured production socket permissions")
        began = time.monotonic()
        expired = self.run_user("lane", ["/usr/bin/sleep", "10"], timeout=1)
        duration = time.monotonic() - began
        check(expired.returncode in (124, 137) and duration < 8,
              "switched timeout did not fail within its bound")
        check(not any(lane["uid"] in item["uids"] for item in processes()),
              "switched timeout left a process")
        admin = self.admin()
        lane_home = no_links(self.fd, "lane-home", directory=True)
        canary = os.urandom(24)
        errors = {}
        created = []
        try:
            write_at(admin, "read-canary", canary, mode=0o600)
            write_at(lane_home, "read-control", canary, uid=lane["uid"], gid=lane["gid"])
            check(read_at(lane_home, "read-control") == canary, "read control differs")
            os.symlink("../admin/read-canary", "read-link", dir_fd=lane_home)
            created.append("read-link")
            os.mkfifo("read-fifo", 0o600, dir_fd=lane_home)
            created.append("read-fifo")
            os.link("read-canary", "read-hardlink", src_dir_fd=admin, dst_dir_fd=lane_home)
            created.append("read-hardlink")
            for name in ("read-link", "read-fifo", "read-hardlink"):
                try:
                    read_at(lane_home, name)
                except (OSError, KitError) as error:
                    errors[name] = type(error).__name__
                else:
                    raise KitError("unsafe read control was not rejected")
        finally:
            for name in reversed(created):
                os.unlink(name, dir_fd=lane_home)
            canary_fd = no_links(admin, "read-canary")
            try:
                # This synthetic canary is exported only after the root-only
                # read controls. It is not a login or a task secret.
                os.fchmod(canary_fd, 0o644)
            finally:
                os.close(canary_fd)
            os.close(lane_home)
            os.close(admin)
        self.record("fixture-controls.json", {
            "accounts": observed, "plain_socket": metadata, "timeout_exit": expired.returncode,
            "timeout_seconds": duration, "descriptor_refusals": errors})

    def start_stubborn(self):
        """Deliberate collection mutation, never a production runner."""
        resources = self.resources()
        check("stubborn_control" not in resources, "stubborn control is single-use")
        lane = self.account("lane")
        code = ("import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                "print('ready',flush=True); time.sleep(120)")
        child = subprocess.Popen(
            ["/usr/bin/python3", "-I", "-c", code], user=lane["uid"], group=lane["gid"],
            extra_groups=[], cwd=lane["home"],
            env=clean_env(lane["home"], lane["temporary"], resources["lane"]),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True, umask=0o022)
        identity = process(child.pid)
        resources["stubborn_control"] = identity
        self.store(resources)
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            check(selector.select(timeout=3), "stubborn control did not reach readiness")
            ready = child.stdout.readline()
        child.stdout.close()
        check(ready == b"ready\n" and identity is not None and
              process(child.pid) == identity, "stubborn control is not live")
        self.record("stubborn-control.json", {"process": identity, "reached": True})

    def start_service(self):
        # This kit owns synthetic canaries and their collection only. Reusing
        # its service account as a substitute installation would bypass the
        # administrator's protected boot/binding ceremony.
        raise KitError("service boot requires admin install.sh --install/--boot")

    def sysctls(self):
        names = ("apparmor_restrict_unprivileged_userns", "unprivileged_userns_clone")
        result = {}
        for name in names:
            path = Path("/proc/sys/kernel") / name
            value = path.read_text().strip() if path.exists() else "absent"
            check(value in ("0", "1", "absent"), "unexpected userns sysctl")
            result[name] = value
        return result

    def namespace(self, binary):
        account = self.account("lane")
        return self.run_user("lane", [
            binary, "--die-with-parent", "--unshare-user", "--uid", str(account["uid"]),
            "--gid", str(account["gid"]), "--unshare-pid", "--unshare-net",
            "--ro-bind", "/", "/", "--proc", "/proc", "--dev", "/dev",
            "/usr/bin/id", "-u"])

    def apparmor(self):
        resources = self.resources()
        before = self.sysctls()
        check(before["unprivileged_userns_clone"] != "0", "unprivileged userns disabled")
        bwrap = Path("/usr/bin/bwrap")
        info = bwrap.lstat()
        check(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o6000,
              "bubblewrap must be ordinary non-setid bytes")
        admin = self.admin()
        try:
            write_at(admin, "bwrap", bwrap.read_bytes(), mode=0o644)
            version = self.run_user("lane", [str(bwrap), "--version"])
            check(version.returncode == 0, "bwrap version failed")
            write_at(admin, "bwrap-version.txt", version.stdout)
            package = self.run_user("lane", [
                "/usr/bin/dpkg-query", "-W", "-f",
                "$" "{Package} $" "{Version} $" "{Architecture}\n", "bubblewrap"])
            write_at(admin, "bwrap-package.txt", package.stdout)
            check(package.returncode == 0 and package.stdout.strip(),
                  "bubblewrap package identity is unavailable")
            restriction = before["apparmor_restrict_unprivileged_userns"]
            pre = self.namespace(str(bwrap))
            record = {"before": before, "pre_exit": pre.returncode}
            write_at(admin, "bwrap-before.stderr", pre.stderr)
            if restriction == "1":
                check(pre.returncode != 0 and pre.returncode not in (124, 137),
                      "unprofiled bwrap was not refused")
                name = "lb-e2e-" + resources["run_id"]
                path = Path("/etc/apparmor.d") / name
                source = (self.kit_dir / "bwrap.apparmor").read_bytes()
                source = source.replace(b"@PROFILE@", name.encode("ascii"))
                directory = os.open("/etc/apparmor.d",
                                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    write_at(directory, name, source)
                finally:
                    os.close(directory)
                resources.update({"profile_file": str(path), "profile_sha256": digest(source)})
                resources["profile_attempted"] = True
                self.store(resources)
                checked(["/usr/sbin/apparmor_parser", "-r", str(path)])
                resources["profile_loaded"] = True
                self.store(resources)
                copied = self.directory / "bin" / "unprofiled-bwrap"
                bin_fd = no_links(self.fd, "bin", directory=True)
                try:
                    write_at(bin_fd, copied.name, bwrap.read_bytes(), mode=0o555)
                finally:
                    os.close(bin_fd)
                negative = self.namespace(str(copied))
                record["unprofiled_after_exit"] = negative.returncode
                write_at(admin, "unprofiled-after.stderr", negative.stderr)
                check(negative.returncode != 0 and negative.returncode not in (124, 137),
                      "profile broadened the unprofiled namespace control")
            else:
                check(pre.returncode == 0, "restriction-off namespace control failed")
            positive = self.namespace(str(bwrap))
            record.update({"after": self.sysctls(), "positive_exit": positive.returncode,
                           "bwrap_sha256": digest(bwrap.read_bytes())})
            write_at(admin, "bwrap-after.stdout", positive.stdout)
            check(positive.returncode == 0 and
                  int(positive.stdout.strip()) == self.account("lane")["uid"],
                  "profiled non-root namespace control failed")
            check(record["after"] == before, "host userns switches changed")
            json_at(admin, "apparmor.json", record)
        finally:
            os.close(admin)

    def signal_process(self, identity, number):
        try:
            handle = os.pidfd_open(identity["pid"])
        except ProcessLookupError:
            return
        try:
            if process(identity["pid"]) == identity:
                signal.pidfd_send_signal(handle, number)
        except ProcessLookupError:
            return
        finally:
            os.close(handle)

    def drift(self, resources):
        now = snapshot()
        users = {item["name"] for item in resources["users"]}
        groups = set(resources["groups"])
        unknown_users = set(now["accounts"]) - set(resources["baseline"]["accounts"]) - users
        unknown_groups = set(now["groups"]) - set(resources["baseline"]["groups"]) - groups
        permitted = set(resources["baseline"]["process_uids"]) | {
            item["uid"] for item in resources["users"]}
        unknown_uids = set(now["process_uids"]) - permitted
        self.record("drift.json", {"new_accounts": sorted(unknown_users),
                                   "new_groups": sorted(unknown_groups),
                                   "new_process_uids": sorted(unknown_uids)})
        return not (unknown_users or unknown_groups or unknown_uids)

    def teardown(self):
        resources = self.resources()
        if resources["teardown_complete"]:
            check(resources.get("cleanup_ok") is True, "prior cleanup failed")
            return
        failures = []
        uids = {item["uid"] for item in resources["users"]}
        for account in resources["users"]:
            current = pwd.getpwnam(account["name"])
            check(current.pw_uid == account["uid"] and current.pw_gid == account["gid"],
                  "account identity changed; preserve it")
        owned = [item for item in processes() if set(item["uids"]) & uids]
        for item in owned:
            self.signal_process(item, signal.SIGTERM)
        deadline = time.monotonic() + self.contract["shutdown_timeout_seconds"]
        while time.monotonic() < deadline:
            owned = [item for item in processes() if set(item["uids"]) & uids]
            if not owned:
                break
            time.sleep(0.1)
        if owned:
            failures.append("process needed SIGKILL")
            for item in owned:
                self.signal_process(item, signal.SIGKILL)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                owned = [item for item in processes() if set(item["uids"]) & uids]
                if not owned:
                    break
                time.sleep(0.1)
        if owned:
            failures.append("process survived SIGKILL")
        drift_ok = self.drift(resources)
        if not drift_ok:
            failures.append("unregistered resource drift")
        # Finish independent safe collection even when forced termination failed.
        profile_name = resources.get("profile_file")
        if profile_name:
            profile = Path(profile_name)
            try:
                check(profile.parent == Path("/etc/apparmor.d") and
                      profile.name == "lb-e2e-" + resources["run_id"], "profile binding changed")
                parent = os.open(str(profile.parent),
                                 os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    data = read_at(parent, profile.name)
                    check(digest(data) == resources["profile_sha256"], "profile bytes changed")
                    admin = self.admin()
                    try:
                        write_at(admin, "bwrap.apparmor", data)
                    finally:
                        os.close(admin)
                    if resources["profile_loaded"] or resources.get("profile_attempted"):
                        listing = Path("/sys/kernel/security/apparmor/profiles")
                        loaded = any(line.split(" ", 1)[0] == profile.name
                                     for line in listing.read_text().splitlines())
                        if loaded:
                            checked(["/usr/sbin/apparmor_parser", "-R", str(profile)])
                        check(not any(line.split(" ", 1)[0] == profile.name for line in
                                      listing.read_text().splitlines()),
                              "per-run AppArmor policy survived unload")
                    os.unlink(profile.name, dir_fd=parent)
                    resources["profile_loaded"] = False
                    resources["profile_attempted"] = False
                    self.store(resources)
                finally:
                    os.close(parent)
            except (OSError, KitError) as error:
                failures.append("profile collection: " + str(error))
        if not owned:
            for item in reversed(resources["users"]):
                try:
                    checked(["/usr/sbin/userdel", item["name"]])
                except KitError as error:
                    failures.append(str(error))
            for name in reversed(resources["groups"]):
                try:
                    grp.getgrnam(name)
                except KeyError:
                    continue
                try:
                    checked(["/usr/sbin/groupdel", name])
                except KitError as error:
                    failures.append(str(error))
        resources["teardown_complete"] = not owned
        resources["cleanup_ok"] = not failures
        self.store(resources)
        self.record("teardown.json", {"ok": not failures, "failures": failures,
                                      "survivors": len(owned), "drift_ok": drift_ok})
        # Archive only after all writers, including unknown UIDs, are accounted for.
        if not owned and drift_ok:
            self.archive(resources)
        check(not failures, "fixture collection failed; retain teardown evidence")

    def archive_tree(self, archive, descriptor, prefix, inventory):
        for name in sorted(os.listdir(descriptor)):
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            entry = tarfile.TarInfo(prefix + "/" + name)
            entry.mode, entry.uid, entry.gid = stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid
            if stat.S_ISDIR(info.st_mode):
                child = no_links(descriptor, name, directory=True)
                try:
                    entry.type = tarfile.DIRTYPE
                    archive.addfile(entry)
                    inventory[entry.name] = {"kind": "directory"}
                    self.archive_tree(archive, child, entry.name, inventory)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                source = no_links(descriptor, name)
                try:
                    actual = os.fstat(source)
                    check(actual.st_nlink == 1 and actual.st_ino == info.st_ino,
                          "archive input linked or changed")
                    entry.size = actual.st_size
                    with os.fdopen(source, "rb", closefd=False) as stream:
                        checksum = hashlib.sha256()
                        for block in iter(lambda: stream.read(1024 * 1024), b""):
                            checksum.update(block)
                        stream.seek(0)
                        archive.addfile(entry, stream)
                    inventory[entry.name] = {"kind": "file", "bytes": actual.st_size,
                                             "sha256": checksum.hexdigest()}
                    after = os.fstat(source)
                    check((actual.st_size, actual.st_mtime_ns) ==
                          (after.st_size, after.st_mtime_ns), "archive input changed")
                finally:
                    os.close(source)
            elif stat.S_ISLNK(info.st_mode):
                entry.type = tarfile.SYMTYPE
                entry.linkname = os.readlink(name, dir_fd=descriptor)
                archive.addfile(entry)
                inventory[entry.name] = {"kind": "symlink", "target": entry.linkname}
            elif not stat.S_ISSOCK(info.st_mode):
                raise KitError("special archive input refused")

    def archive(self, resources):
        check(resources["teardown_complete"], "archive requires completed quiescence")
        admin = self.admin()
        try:
            try:
                existing = no_links(admin, "fixture.tar.gz")
            except FileNotFoundError:
                existing = None
            if existing is not None:
                try:
                    verify_archive(existing, json.loads(read_at(admin, "fixture-manifest.json")))
                finally:
                    os.close(existing)
                return
            descriptor = os.open("fixture.tar.partial", os.O_WRONLY | os.O_CREAT |
                                 os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=admin)
            try:
                inventory = {}
                with os.fdopen(descriptor, "wb", closefd=False) as stream:
                    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
                        for name in ("state", "org", "runtime", "service-home",
                                     "operator-home", "lane-home"):
                            child = no_links(self.fd, name, directory=True)
                            try:
                                self.archive_tree(archive, child, name, inventory)
                            finally:
                                os.close(child)
                    stream.flush()
                    os.fsync(descriptor)
                os.fchown(descriptor, self.controller, pwd.getpwuid(self.controller).pw_gid)
            finally:
                os.close(descriptor)
            retained = no_links(admin, "fixture.tar.partial")
            try:
                verify_archive(retained, inventory)
            finally:
                os.close(retained)
            json_at(admin, "fixture-manifest.json", inventory)
            os.rename("fixture.tar.partial", "fixture.tar.gz", src_dir_fd=admin,
                      dst_dir_fd=admin)
        finally:
            os.close(admin)

    def close(self):
        os.close(self.lock)
        os.close(self.fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("step", choices=("provision", "controls", "apparmor", "start-service",
                                        "start-stubborn",
                                        "teardown", "run-user", "read-file", "socket-info"))
    parser.add_argument("directory")
    parser.add_argument("argument", nargs="?")
    args = parser.parse_args()
    kit = Kit(args.directory)
    try:
        if args.step == "run-user":
            request = json.loads(read_at(kit.fd, args.argument))
            check(set(request) == {"role", "argv", "timeout", "stdin"},
                  "invalid switched command request")
            check(request["role"] in ("operator", "lane"), "service is setup-only")
            check(isinstance(request["argv"], list) and request["argv"] and
                  all(isinstance(word, str) and "\x00" not in word for word in request["argv"]),
                  "invalid switched command argv")
            check(type(request["timeout"]) is int and 1 <= request["timeout"] <= 3600,
                  "invalid switched command deadline")
            input_bytes = read_at(kit.fd, request["stdin"]) if request["stdin"] else None
            result = kit.run_user(request["role"], request["argv"],
                                  timeout=request["timeout"], input_bytes=input_bytes)
            sys.stdout.buffer.write(result.stdout)
            sys.stderr.buffer.write(result.stderr)
            return result.returncode
        if args.step == "read-file":
            check(isinstance(args.argument, str) and args.argument.startswith("lane-home/"),
                  "live read-back is limited to lane-probe data")
            sys.stdout.buffer.write(read_at(kit.fd, args.argument))
        elif args.step == "socket-info":
            print(json.dumps(kit.socket_info()))
        else:
            getattr(kit, args.step.replace("-", "_"))()
        return 0
    finally:
        kit.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, KitError) as error:
        print("kit step failed: " + str(error), file=sys.stderr)
        sys.exit(2)
