"""Outside acceptance observer; execute only on the authorized Ubuntu box."""

import argparse
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import time


_authority_spec = importlib.util.spec_from_file_location(
    "laneboss_human_authority", Path(__file__).resolve().parents[2] / "human_authority.py")
AUTHORITY = importlib.util.module_from_spec(_authority_spec)
_authority_spec.loader.exec_module(AUTHORITY)


ASSERTIONS = ("UBUNTU-USERNS", "HELPER-PEER", "HELPER")
RESTRICT = Path("/proc/sys/kernel") / "apparmor_restrict_unprivileged_userns"
CLONE = Path("/proc/sys/kernel") / "unprivileged_userns_clone"
PROFILE = Path("/etc/apparmor.d/laneboss-bwrap")
MAX_FRAME = 1048576
REVISION = "v2.0-draft.4"


class Failed(Exception):
    """An observable acceptance failure, never an implicit skip."""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(path):
    return json.loads(Path(path).read_bytes())


def require(condition, reason):
    if not condition:
        raise Failed(reason)


def beneath(path, root):
    path = Path(path)
    require(path.is_absolute() and not path.is_symlink(), "unsafe harness path")
    path.resolve().relative_to(root.resolve())
    return path


class Observer:
    def __init__(self, context, fixture, result_path):
        self.context = context
        self.fixture = fixture
        self.result_path = result_path
        self.root = Path(context["test_root"])
        self.evidence = Path(context["evidence_root"])
        self.evidence.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.rows = {}
        self.refs = []
        self.current = "UBUNTU-USERNS"
        self.last_exit = 1
        self.command_index = 0
        self.started = False
        self.collected = False
        self.child = None
        self.lease = None
        self.operation = None
        self.temporary_artifacts = []
        self.restore_binary = None
        self.commands_quiescent = True
        self.last_label = "setup"
        self.last_command = None
        self.profile_evidence = None

    def keep(self, name, data):
        path = self.evidence / name
        require(not path.exists() and not path.is_symlink(), "evidence must not be overwritten")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(data)
        reference = {"path": name, "sha256": digest(data), "bytes": len(data)}
        self.refs.append(reference)
        return reference

    def keep_json(self, name, value):
        return self.keep(name, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())

    def command(self, label, argv, expected=None, seconds=30):
        self.last_label = label
        self.command_index += 1
        stem = "%03d-%s" % (self.command_index, label)
        # This is a command vector authored by this case, never an environment
        # dump or inspection of another process's command line.
        self.keep_json(stem + ".command.json", argv)
        try:
            completed = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       timeout=seconds, check=False)
        except subprocess.TimeoutExpired as failure:
            self.commands_quiescent = False
            self.keep(stem + ".stdout", failure.stdout or b"")
            self.keep(stem + ".stderr", failure.stderr or b"")
            self.keep_json(stem + ".timeout.json", {"timeout_seconds": seconds})
            self.last_exit = 124
            raise Failed("command deadline expired; containment requires inspection") from failure
        self.last_exit = completed.returncode
        self.keep(stem + ".stdout", completed.stdout)
        self.keep(stem + ".stderr", completed.stderr)
        self.keep_json(stem + ".exit.json", {"exit_code": completed.returncode})
        self.last_command = {"label": label, "exit_code": completed.returncode,
                             "stdout": stem + ".stdout", "stderr": stem + ".stderr"}
        if expected is not None:
            require(completed.returncode == expected, label + " exit mismatch")
        return completed

    def cli(self, label, command, request):
        name = "request-%03d.json" % (self.command_index + 1)
        path = self.root / name
        require(not path.exists(), "request input already exists")
        data = (json.dumps(request, sort_keys=True) + "\n").encode()
        path.write_bytes(data)
        self.keep("inputs/" + name, data)
        proof = self.authority(command)
        completed = self.command(label, [self.context["binary"], *command,
                                 "--config", self.context["config"], "--binding", self.context["binding_file"],
                                 "--request", str(path), "--idempotency-key", os.urandom(16).hex(), *proof],
                                 expected=None)
        if completed.returncode != 0:
            raise Failed(label + " dependency refused: " + self.error_code(completed.stderr))
        value = json.loads(completed.stdout)
        # Feature adapters print typed results. A result-shaped error or a
        # pending operation must never be mistaken for completion.
        require(isinstance(value, dict) and "error" not in value, label + " invalid result")
        return value

    def authority(self, command):
        try:
            return AUTHORITY.proof_arguments(self.root, self.context["binding_file"],
                self.context["config"], self.command_index + 1, command)
        except AUTHORITY.OwnerWait as wait:
            self.keep_json("authority-%06d.wait.json" % (self.command_index + 1), wait.record())
            raise

    @staticmethod
    def error_code(data):
        try:
            value = json.loads(data)
        except (UnicodeError, ValueError):
            return "unparseable refusal"
        return value.get("code", "untyped refusal") if isinstance(value, dict) else "untyped refusal"

    def switches(self):
        return {"restriction": RESTRICT.read_bytes().decode(),
                "clone": CLONE.read_bytes().decode() if CLONE.exists() else None}

    def userns(self):
        release = {}
        for line in Path("/etc/os-release").read_text().splitlines():
            key, separator, value = line.partition("=")
            if separator:
                release[key] = value.strip('"')
        require(release.get("ID") == "ubuntu" and release.get("VERSION_ID") == "24.04",
                "Ubuntu 24.04 is the required administrator cell")
        before = self.switches()
        self.keep_json("sysctls.before.json", before)
        restriction = int(before["restriction"].strip())
        require(type(self.fixture["restriction"]) is int and restriction in (0, 1),
                "unknown measured restriction")
        require(restriction == self.fixture["restriction"], "actual switch differs from requested cell")
        bwrap_info = Path("/usr/bin/bwrap").lstat()
        require(stat.S_ISREG(bwrap_info.st_mode) and bwrap_info.st_uid == 0 and
                not bwrap_info.st_mode & (stat.S_ISUID | stat.S_ISGID | 0o022),
                "bwrap is linked, writable or setuid")
        self.keep("inputs/bwrap", Path("/usr/bin/bwrap").read_bytes())
        capabilities = self.command("bwrap-capabilities", ["getcap", "/usr/bin/bwrap"], expected=0)
        require(not capabilities.stdout.strip(), "bwrap has file capabilities")
        self.command("bwrap-version", ["/usr/bin/bwrap", "--version"], expected=0)
        probe = ["/usr/bin/bwrap", "--die-with-parent", "--unshare-user", "--unshare-pid",
                 "--ro-bind", "/", "/", "--", "/usr/bin/true"]
        # A private copy avoids a distro's unrelated executable-specific
        # unshare profile. Its baseline denial is still observed before setup.
        control_path = self.root / "unprofiled-unshare"
        control_bytes = Path("/usr/bin/unshare").read_bytes()
        with control_path.open("xb") as stream:
            stream.write(control_bytes)
        control_path.chmod(0o500)
        self.keep("inputs/unshare-control", control_bytes)
        unprofiled = [str(control_path), "--user", "--map-root-user", "--mount", "--", "/usr/bin/true"]
        profile_before = PROFILE.read_bytes() if PROFILE.exists() else None
        original = self.command("bwrap-before", probe)
        control = self.command("unshare-before", unprofiled)
        if restriction == 1:
            require(original.returncode != 0 and control.returncode != 0,
                    "restricted unprofiled namespace control unexpectedly succeeded")
            diagnostic = original.stderr.lower()
            require(any(text in diagnostic for text in
                        (b"permission denied", b"operation not permitted", b"no permissions")),
                    "bwrap failure did not reach the namespace permission boundary")
            require(any(text in control.stderr.lower() for text in
                        (b"permission denied", b"operation not permitted", b"no permissions")),
                    "unprofiled mount control did not reach a permission refusal")
            repository = Path(self.fixture.get("admin_source", Path(__file__).resolve().parents[4])).resolve(strict=True)
            source = repository / "scripts/v2-admin/apparmor.sh"
            admin_evidence = Path("/var/tmp") / ("lb-v2-admin-profile-" + os.urandom(16).hex())
            self.profile_evidence = admin_evidence
            self.keep_json("profile-evidence-path.json", {"path": str(admin_evidence)})
            self.command("profile-install", ["sudo", "-n", "bash", str(source),
                         "--evidence", str(admin_evidence)], expected=0)
            expected = (repository / "packaging/v2/linux" / "laneboss-bwrap.apparmor").read_bytes()
            require(PROFILE.read_bytes() == expected, "bwrap-only profile read-back differs")
            self.keep("profile.readback", PROFILE.read_bytes())
            self.command("profile-install-evidence", ["sudo", "-n", "tar", "-c",
                         "-C", str(admin_evidence), "."], expected=0)
            self.command("bwrap-after", probe, expected=0)
            after_control = self.command("unshare-after", unprofiled)
            require(after_control.returncode != 0, "unprofiled namespace control became permitted")
            require(any(text in after_control.stderr.lower() for text in
                        (b"permission denied", b"operation not permitted", b"no permissions")),
                    "unprofiled mount control failed for an unrelated reason")
        else:
            require(profile_before is None, "restriction-off cell needs a fresh host without an unnecessary Laneboss profile")
            require(original.returncode == 0 and control.returncode == 0,
                    "restriction-off unprivileged namespace control failed")
            profile_after = PROFILE.read_bytes() if PROFILE.exists() else None
            require(profile_before == profile_after, "restriction-off cell changed the profile")
            self.keep_json("profile.not-needed.json", {"installed": False, "restriction": restriction})
        after = self.switches()
        self.keep_json("sysctls.after.json", after)
        require(before == after, "host namespace switches changed")
        self.keep_json("host.json", {"os": release["ID"], "version": release["VERSION_ID"],
                       "kernel": os.uname().release, "architecture": os.uname().machine,
                       "restriction": restriction, "uid": os.geteuid()})

    def helper_denials(self):
        helper_binding = load(self.fixture["helper_binding"])
        self.binding = helper_binding
        require(helper_binding["config"] == self.context["config"], "helper configuration mismatch")
        require(helper_binding["contract_revision"] == REVISION, "helper contract revision differs")
        require(re.fullmatch(r"[0-9][A-Za-z0-9._-]{0,31}", helper_binding["release"]["version"]),
                "unsafe helper release version")
        require(helper_binding["artifact"]["sha256"] == self.context["binary_sha256"], "helper artifact binding differs")
        self.keep("inputs/helper-binding.json", Path(self.fixture["helper_binding"]).read_bytes())
        endpoint = Path("/run/laneboss-v2") / self.context["config"] / "helper.sock"
        self.command("helper-endpoint", ["sudo", "-n", "test", "-S", str(endpoint)], expected=0)
        require(helper_binding["service"]["uid"] != os.geteuid(), "negative peer is the service UID")
        base = {"protocol": "laneboss.helper.v2", "config": self.context["config"],
                "contract_revision": REVISION,
                "generation": helper_binding["generation"],
                "artifact_sha256": helper_binding["artifact"]["sha256"],
                "nonce": "negative-" + os.urandom(16).hex(), "method": "probe", "params": {}}
        for index, extra in enumerate(({}, {"argv": ["/usr/bin/true"]}, {"path": "/root"})):
            request = dict(base, **extra)
            data = json.dumps(request, sort_keys=True).encode()
            self.keep("peer-%d.request" % index, struct.pack("!I", len(data)) + data)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(5)
                try:
                    connection.connect(str(endpoint))
                    connection.sendall(struct.pack("!I", len(data)) + data)
                    header = self.receive(connection, 4)
                    size = struct.unpack("!I", header)[0]
                    require(0 < size <= MAX_FRAME, "invalid helper refusal frame")
                    response = self.receive(connection, size)
                except PermissionError as failure:
                    self.keep_json("peer-%d.denied.json" % index, {"errno": failure.errno,
                                   "boundary": "socket ACL", "refused": True})
                    require(failure.errno in (errno.EACCES, errno.EPERM), "unexpected socket ACL error")
                else:
                    self.keep("peer-%d.response" % index, response)
                    value = json.loads(response)
                    require(value.get("contract_revision") == REVISION, "helper refusal revision differs")
                    require("result" not in value and value.get("error", {}).get("code") in
                            ("forbidden", "unauthenticated"), "nonservice helper peer was not refused")
        for label, args in (("root-argv", ["--", "/usr/bin/true"]),
                            ("root-path", ["--path", "/root"])):
            completed = self.command(label, [self.context["binary"], "internal", "helper",
                                     "--config", self.context["config"], *args])
            require(completed.returncode != 0 and self.error_code(completed.stderr) == "forbidden",
                    "arbitrary root argv/path did not receive a typed refusal")
        source = Path(__file__).resolve().with_name("peer_probe.py")
        negative = self.command("helper-root-peer", ["sudo", "-n", "/usr/bin/python3", "-I", "-B", str(source),
                                "--config", self.context["config"]], expected=0)
        proof = json.loads(negative.stdout)
        require(proof["connected"] is True and proof["service_uid"] != 0 and len(proof["rows"]) == 3 and
                all(row["connected"] is True and row["uid"] == 0 and row["response"]["error"]["code"] == "forbidden"
                    for row in proof["rows"]), "HELPER-PEER did not reach the socket peer check")
        try:
            self.artifact_controls()
        finally:
            last = self.last_exit, self.last_label, self.last_command
            self.collect_artifact_controls()
            self.last_exit, self.last_label, self.last_command = last

    @staticmethod
    def receive(connection, size):
        data = bytearray()
        while len(data) < size:
            part = connection.recv(size - len(data))
            require(bool(part), "helper closed before a complete refusal frame")
            data.extend(part)
        return bytes(data)

    def events(self, since=0):
        require(isinstance(self.child, dict) and isinstance(self.child.get("life_id"), str) and
                self.child["life_id"] and type(self.child.get("run")) is int and self.child["run"] > 0,
                "event observer requires its actual prepared child/run")
        result, cursor, cursors, sequences = [], "", set(), set()
        for _ in range(64):
            page = self.cli("events", ["event", "tail"], {**self.child, "since": since if not cursor else 0,
                            "cursor": cursor, "follow": False, "until": "", "deadline_ms": 1000})
            require(type(page["complete"]) is bool and isinstance(page["events"], list), "invalid event page")
            for event in page["events"]:
                require(event["config"] == self.context["config"] and event["schema"] == 2 and
                        event.get("life_id") == self.child["life_id"] and event.get("run") == self.child["run"] and
                        type(event["seq"]) is int and event["seq"] > since and event["seq"] not in sequences,
                        "event page contains a foreign, repeated or stale sequence")
                require(not result or event["seq"] > result[-1]["seq"], "event sequence moved backwards")
                sequences.add(event["seq"])
                result.append(event)
            if page["complete"]:
                return result
            cursor = page["cursor"]
            require(isinstance(cursor, str) and cursor and cursor not in cursors, "event cursor did not advance")
            cursors.add(cursor)
        raise Failed("event snapshot exceeded its bounded collection; incomplete is not empty")

    def production(self):
        doctor = self.cli("doctor", ["doctor"], {})
        require(doctor.get("ready") is True, "doctor is not ready")
        require(doctor.get("artifact_sha256") == self.context["binary_sha256"], "doctor artifact differs")
        ergonomic = self.command("doctor-format", [self.context["binary"], "doctor", "--config",
                                  self.context["config"], "--binding", self.context["binding_file"], "--format", "json",
                                  *self.authority(["doctor"])], expected=0)
        ergonomic_result = json.loads(ergonomic.stdout)
        require(ergonomic_result["ready"] is True and all(check["available"] is True
                for check in ergonomic_result["capabilities"]) and
                ergonomic_result["artifact_sha256"] == doctor["artifact_sha256"] and
                ergonomic_result["protocol"] == doctor["protocol"] and
                ergonomic_result["schema"] == doctor["schema"], "doctor CLI forms disagree on readiness or release")
        capabilities = {check["name"]: check for check in doctor["capabilities"]}
        for name in ("helper.artifact", "helper.service_account", "helper.lane_accounts",
                     "helper.cgroup_v2", "helper.prepare", "helper.egress", "isolation.linux-bwrap-landlock"):
            require(capabilities.get(name, {}).get("available") is True, "missing helper capability: " + name)
        pid = self.fixture["helper_pid"]
        require(type(pid) is int and pid > 1, "invalid helper PID fixture")
        actual = self.command("helper-executable", ["sudo", "-n", "readlink", "/proc/%d/exe" % pid], expected=0)
        expected_path = "/usr/lib/laneboss-v2/%s/laneboss" % self.binding["release"]["version"]
        require(actual.stdout.decode().strip() == expected_path, "helper does not execute its fixed installed path")
        hashed = self.command("helper-digest", ["sudo", "-n", "sha256sum", "/proc/%d/exe" % pid], expected=0)
        require(hashed.stdout.decode().split()[0] == self.context["binary_sha256"], "executing helper bytes differ")
        request_path = beneath(self.fixture["launch_request"], self.root)
        request = load(request_path)
        self.child = request["child"]
        old_events = self.events()
        since = max((event["seq"] for event in old_events), default=0)
        # grants.test-child is the existing confined, bounded worker interface.
        # This does not create a third driver or authenticate an AI service.
        self.started = True
        operation = self.cli("worker-launch", ["grants", "test-child"], request)
        self.operation = operation["id"]
        canary = beneath(self.fixture["canary_file"], self.root)
        acknowledgement = beneath(self.fixture["ack_file"], self.root)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            events = self.events(since)
            allocated = [event for event in events if event["kind"] == "helper.allocated" and
                         event["operation_id"] == self.operation]
            if allocated and canary.exists():
                require(len(allocated) == 1, "operation allocated multiple helper leases")
                require(allocated[0]["origin"] == "service" and allocated[0]["actor"]["kind"] == "service" and
                        allocated[0]["request_id"] and allocated[0]["requested_by"]["id"],
                        "helper allocation event lost authenticated service causality")
                self.lease = allocated[0]["payload"]
                self.allocation_event = allocated[0]
                break
            if operation["status"] in ("failed", "cancelled", "succeeded"):
                raise Failed("worker ended before its real kernel canary and lease observation")
            time.sleep(1)
            operation = self.cli("worker-operation", ["operation", "get"], {"operation_id": self.operation})
        require(self.lease is not None, "production helper allocation or canary was not observed")
        self.keep("canary.json", canary.read_bytes())
        observed = load(canary)
        require(observed["nonce"] == self.fixture["nonce"] and observed["no_new_privs"] == 1 and
                int(observed["cap_eff"], 16) == 0, "worker canary is stale, privileged or unconfined")
        lease = self.lease
        require(lease["uid"] not in (0, self.binding["service"]["uid"]), "lane shares root/service UID")
        require(lease["endpoint_generation"] == self.binding["generation"], "helper lease generation differs")
        cgroup = (Path("/sys/fs/cgroup/system.slice") /
                  ("laneboss-helper@%s.service" % self.context["config"]) / "lanes" / lease["containment_id"])
        actual = self.command("lane-cgroup", ["sudo", "-n", "cat", str(cgroup / "cgroup.procs")], expected=0)
        pids = [int(value) for value in actual.stdout.split()]
        require(bool(pids), "production cgroup contains no canary process")
        host_observations = []
        for child_pid in pids:
            actual = self.command("lane-identity", ["sudo", "-n", "cat", "/proc/%d/status" % child_pid], expected=0)
            status = dict(line.split(":", 1) for line in actual.stdout.decode().splitlines() if ":" in line)
            uids = [int(uid) for uid in status["Uid"].split()]
            require(uids == [lease["uid"]] * 4 and int(status["CapEff"].strip(), 16) == 0,
                    "host-side lane identity or capability dropping failed")
            host_observations.append({"pid": child_pid, "uids": uids, "cap_eff": status["CapEff"].strip()})
        self.keep_json("kernel-observations.json", host_observations)
        require(not acknowledgement.exists(), "stale worker acknowledgement")
        acknowledgement.write_text(self.fixture["nonce"] + "\n")
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            operation = self.cli("worker-operation", ["operation", "get"], {"operation_id": self.operation})
            if operation["status"] in ("succeeded", "failed", "cancelled"):
                break
            time.sleep(1)
        require(operation["status"] == "succeeded", "worker did not complete successfully")
        released = [event for event in self.events(since) if event["kind"] == "helper.released" and
                    event["operation_id"] == self.operation and event["payload"]["lease_id"] == lease["id"]]
        require(len(released) == 1, "helper release event is absent or duplicated")
        receipt = released[0]["payload"]
        require(receipt["containment_id"] == lease["containment_id"] and receipt["quiescence"]["survivors"] == 0 and
                all(type(receipt[name]) is int and receipt[name] == 0 for name in
                    ("live_connections", "queued_jobs", "writable_exports")), "release lacks measured zero counts")
        require(released[0]["origin"] == "service" and released[0]["actor"]["kind"] == "service" and
                released[0]["requested_by"] == self.allocation_event["requested_by"] and
                released[0]["request_id"] == self.allocation_event["request_id"],
                "helper release event changed the original requester or request")
        require(not cgroup.exists(), "released cgroup remains present")
        self.collected = True

    def artifact_controls(self):
        changed = beneath(self.fixture["changed_binary"], self.root)
        candidate_bytes = Path(self.context["binary"]).read_bytes()
        changed_bytes = changed.read_bytes()
        require(candidate_bytes[:4] == b"\x7fELF" and len(changed_bytes) == len(candidate_bytes) and
                changed_bytes[:15] == candidate_bytes[:15] and changed_bytes[16:] == candidate_bytes[16:] and
                changed_bytes[15] != candidate_bytes[15],
                "changed artifact must differ only in unused ELF identification padding")
        self.keep("inputs/changed-artifact", changed_bytes)
        installed = Path("/usr/lib/laneboss-v2") / self.binding["release"]["version"] / "laneboss"
        require(digest(installed.read_bytes()) == self.context["binary_sha256"], "installed candidate differs")
        # Root runs the pinned candidate outside its unit as the positive
        # artifact control. It must pass artifact verification and reach the
        # distinct systemd-identity refusal. No agent code is executed.
        baseline = self.command("root-unit-control", ["sudo", "-n", str(installed),
                                "internal", "helper", "--config", self.context["config"]])
        require(baseline.returncode == 2 and self.error_code(baseline.stderr) == "forbidden" and
                "systemd unit" in json.loads(baseline.stderr)["message"],
                "valid artifact did not reach the unit identity control")
        backup = installed.parent / ("admin-" + self.context["config"] + "-original")
        target_setuid = installed.parent / ("admin-" + self.context["config"] + "-setuid")
        for target in (backup, target_setuid):
            self.command("artifact-absent", ["sudo", "-n", "test", "!", "-e", str(target)], expected=0)
            self.command("artifact-unlinked", ["sudo", "-n", "test", "!", "-L", str(target)], expected=0)
        # Keep the exact fixed path and byte count while changing a harmless
        # ELF padding byte. Removing only the digest check must kill this row;
        # a copied-path refusal or size mismatch cannot masquerade as coverage.
        self.restore_binary = installed, backup
        self.temporary_artifacts.append(backup)
        self.command("artifact-retain", ["sudo", "-n", "mv", "-T", "--", str(installed), str(backup)], expected=0)
        self.command("changed-install", ["sudo", "-n", "install", "-o", "root", "-g", "root",
                     "-m", "0555", "--", str(changed), str(installed)], expected=0)
        require(installed.read_bytes() == changed_bytes, "changed artifact read-back differs")
        altered = self.command("changed-artifact", ["sudo", "-n", str(installed),
                               "internal", "helper", "--config", self.context["config"]])
        require(altered.returncode == 3 and not altered.stdout and
                self.error_code(altered.stderr) == "integrity", "changed fixed-path bytes did not reach digest refusal")
        self.keep_json("controls/changed-artifact.json", {"sha256": digest(installed.read_bytes()),
                       "bytes": installed.stat().st_size, "path": str(installed)})
        self.command("artifact-restore", ["sudo", "-n", "mv", "-T", "--", str(backup), str(installed)], expected=0)
        require(digest(installed.read_bytes()) == self.context["binary_sha256"] and not backup.exists(),
                "exact original artifact was not restored")
        self.temporary_artifacts.remove(backup)
        self.temporary_artifacts.append(target_setuid)
        self.command("setuid-install", ["sudo", "-n", "install", "-o", "root", "-g", "root",
                     "-m", "4755", "--", str(installed), str(target_setuid)], expected=0)
        metadata = target_setuid.lstat()
        require(metadata.st_uid == 0 and metadata.st_mode & stat.S_ISUID and
                digest(target_setuid.read_bytes()) == self.context["binary_sha256"], "setuid control preparation failed")
        elevated = self.command("setuid-refusal", [str(target_setuid), "internal", "helper",
                                "--config", self.context["config"]])
        require(elevated.returncode == 2 and not elevated.stdout and
                self.error_code(elevated.stderr) == "forbidden" and
                json.loads(elevated.stderr)["message"] == "setuid or setgid helper invocation is refused",
                "setuid control did not reach changed real/effective UID check; nosuid is not a passing control")
        for target in (target_setuid,):
            self.keep_json("controls/" + target.name + ".json", {"sha256": digest(target.read_bytes()),
                           "mode": stat.S_IMODE(target.lstat().st_mode), "uid": target.lstat().st_uid})
            self.command("artifact-collect", ["sudo", "-n", "unlink", str(target)], expected=0)
            require(not target.exists() and not target.is_symlink(), "temporary root artifact remains")
            self.temporary_artifacts.remove(target)

    def collect_artifact_controls(self):
        errors = []
        # These are the two independent safety cleanups authorized for the
        # artifact controls. A failed cleanup is retained and fails the case;
        # it does not suppress the other safety cleanup or retry a refusal.
        for target in list(self.temporary_artifacts):
            if self.restore_binary is not None and target == self.restore_binary[1]:
                continue
            try:
                require(target.name == "admin-" + self.context["config"] + "-setuid" and not target.is_symlink(),
                        "unknown or linked root artifact retained")
                if target.exists():
                    self.command("setuid-finally-disarm", ["sudo", "-n", "chmod", "0755", str(target)], expected=0)
                    self.command("setuid-finally-collect", ["sudo", "-n", "unlink", str(target)], expected=0)
                require(not target.exists(), "setuid control remains installed")
                self.temporary_artifacts.remove(target)
            except (Failed, OSError) as failure:
                errors.append(str(failure))
        if self.restore_binary is not None:
            installed, backup = self.restore_binary
            try:
                if backup.exists():
                    require(not backup.is_symlink() and digest(backup.read_bytes()) == self.context["binary_sha256"],
                            "retained artifact cannot be safely restored")
                    self.command("artifact-finally-restore", ["sudo", "-n", "mv", "-T", "--", str(backup), str(installed)], expected=0)
                require(digest(installed.read_bytes()) == self.context["binary_sha256"], "candidate restoration failed")
                if backup in self.temporary_artifacts:
                    self.temporary_artifacts.remove(backup)
            except (Failed, OSError) as failure:
                errors.append(str(failure))
        require(not errors, "artifact safety cleanup failed: " + "; ".join(errors))

    def run_assertion(self, identifier, function):
        self.current = identifier
        start = len(self.refs)
        try:
            function()
        except (Failed, OSError, ValueError, KeyError, TypeError, AUTHORITY.OwnerWait) as failure:
            self.keep_json(identifier + ".failure.json", {"reason": str(failure)})
            self.rows[identifier] = {"id": identifier, "reached": not isinstance(failure, AUTHORITY.OwnerWait), "verdict": "fail",
                                     "observed_exit": self.last_exit, "evidence": self.refs[start:]}
            raise
        self.rows[identifier] = {"id": identifier, "reached": True, "verdict": "pass",
                                 "observed_exit": self.last_exit, "evidence": self.refs[start:]}

    def finish(self):
        for identifier in ASSERTIONS:
            if identifier not in self.rows:
                self.rows[identifier] = {"id": identifier, "reached": False, "verdict": "fail",
                                         "observed_exit": 1, "evidence": []}
        quiet = self.commands_quiescent and (not self.started or self.collected)
        collected = quiet and not self.temporary_artifacts
        collection_ref = self.keep_json("collection.json", {"started": self.started,
                                       "collected": self.collected, "operation_id": self.operation,
                                       "lease_id": self.lease["id"] if self.lease else None})
        result = {"schema": "laneboss.e2e-result.v2", "case_id": "admin",
                  "phase": self.context["phase"], "mutation_id": self.context["mutation_id"],
                  "binary_sha256": self.context["binary_sha256"], "source_sha256": self.context["source_sha256"],
                  "assertions": [self.rows[identifier] for identifier in ASSERTIONS],
                  "collection": {"processes_quiescent": quiet, "temporary_resources_collected": collected,
                                 "evidence": [collection_ref]}}
        temporary = self.result_path.with_suffix(".pending")
        with temporary.open("x") as stream:
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(self.result_path)
        return all(row["reached"] and row["verdict"] == "pass" for row in self.rows.values()) and quiet and collected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--context", required=True)
    parser.add_argument("--result", required=True)
    args = parser.parse_args()
    require(sys.platform == "linux" and os.geteuid() != 0, "run only as an unprivileged disposable Linux observer")
    context = load(args.context)
    require(context["schema"] == "laneboss.e2e-context.v2" and context["case_id"] == "admin", "invalid case context")
    require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", context["config"]), "unsafe configuration")
    root = Path(context["test_root"])
    result = beneath(args.result, root)
    fixture = load(root / "admin-input.json") if (root / "admin-input.json").is_file() else {}
    observer = Observer(context, fixture, result)
    try:
        if not fixture:
            wait = AUTHORITY.OwnerWait("fixture_preparation")
            observer.keep_json("setup.wait.json", wait.record())
            raise wait
        observer.keep("inputs/context.json", Path(args.context).read_bytes())
        observer.keep("inputs/admin-input.json", (root / "admin-input.json").read_bytes())
        require(digest(Path(context["binary"]).read_bytes()) == context["binary_sha256"], "candidate artifact digest differs")
        observer.run_assertion("UBUNTU-USERNS", observer.userns)
        observer.run_assertion("HELPER-PEER", observer.helper_denials)
        observer.run_assertion("HELPER", observer.production)
    except (Failed, OSError, ValueError, KeyError, TypeError, AUTHORITY.OwnerWait) as failure:
        print("FAIL: admin acceptance: " + str(failure), file=sys.stderr)
    passed = observer.finish()
    if passed:
        print("PASS: admin acceptance")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
