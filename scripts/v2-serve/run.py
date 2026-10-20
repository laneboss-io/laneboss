"""Installed serve probe; run on the authorized Ubuntu box only.

This is a stopped acceptance gate while REQUESTS.md remains unresolved.
Unreached assertions remain failures, including all SERVE-STATE assertions.
It deliberately supplies no fake identity, runtime enrollment or receipt.
"""

import argparse
import base64
import copy
from contextlib import contextmanager
import importlib.util
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import uuid


spec = importlib.util.spec_from_file_location("serve_provision", Path(__file__).with_name("provision.py"))
provision = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provision)
audit_spec = importlib.util.spec_from_file_location("serve_agent_evidence", Path(__file__).with_name("agent_evidence.py"))
agent_evidence = importlib.util.module_from_spec(audit_spec)
audit_spec.loader.exec_module(agent_evidence)
human_spec = importlib.util.spec_from_file_location("serve_human", Path(__file__).with_name("human.py"))
human = importlib.util.module_from_spec(human_spec)
human_spec.loader.exec_module(human)
launch_spec = importlib.util.spec_from_file_location("serve_launch", Path(__file__).with_name("launch_evidence.py"))
launch_evidence = importlib.util.module_from_spec(launch_spec)
launch_spec.loader.exec_module(launch_evidence)
flow_spec = importlib.util.spec_from_file_location("serve_lifecycle", Path(__file__).with_name("lifecycle.py"))
flow = importlib.util.module_from_spec(flow_spec)
flow_spec.loader.exec_module(flow)
summary_spec = importlib.util.spec_from_file_location("serve_summary", Path(__file__).with_name("summary.py"))
summary = importlib.util.module_from_spec(summary_spec)
summary_spec.loader.exec_module(summary)
item_spec = importlib.util.spec_from_file_location(
    "serve_items", Path(__file__).with_name("item_dispatch.py"))
items = importlib.util.module_from_spec(item_spec)
item_spec.loader.exec_module(items)
canary_spec = importlib.util.spec_from_file_location("serve_api_key_canary", Path(__file__).with_name("api_key_canary.py"))
api_key_canary = importlib.util.module_from_spec(canary_spec)
canary_spec.loader.exec_module(api_key_canary)


CHECKS = flow.STATE_CHECKS


def presence(check):
    dependent = check.startswith(("authenticator.", "human.", "state.", "lane.", "capture.other.")) or check in ("unready.owner", "direct-open", "admin.publication")
    return "simulated" if dependent else "not_applicable"


class Blocked(Exception):
    """A required owner handoff is absent; no assertion ran."""


class Failed(Exception):
    """The named step failed; dependent work stops."""


def require(condition, reason):
    if not condition:
        raise Failed(reason)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


class Case:
    decode_document = staticmethod(agent_evidence.document)
    checks = CHECKS
    scope = "serve-state"

    def __init__(self, source, evidence, launch_request=None, agent_output=None, root_grants=None,
                 suite="lifecycle", lane_inputs=None, config=None, boot_input=None, cleanup_native_control=False,
                 egress_anthropic=False, real_claudock=False, item_case=None, canary_api_key=False,
                 real_api_key_file=None, source_snapshot=False):
        require(not (canary_api_key and real_api_key_file is not None),
                "fake and real API key sources are mutually exclusive")
        require(real_api_key_file is None or (real_claudock and egress_anthropic),
                "--real-api-key-file requires --real-claudock and --egress-anthropic")
        self.api_key_canary = provision.key_source(api_key_canary.Canary, canary_api_key, real_api_key_file)
        self.real_api_key = real_api_key_file is not None
        self.source = source
        self.source_snapshot = source_snapshot
        self.evidence = evidence
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        self.config = config or "e2e-serve-" + stamp + "-" + uuid.uuid4().hex[:4]
        self.root = evidence / self.config
        self.root.mkdir(mode=0o700)
        self.suite = suite
        self.real_claudock = real_claudock
        self.real_vendor = None
        self.scope = "installed-lifecycle" if suite == "lifecycle" else "serve-state"
        self.reply_mode = ("real-key" if self.real_api_key else "fake-key") if self.api_key_canary is not None else None
        self.checks = flow.checks(CHECKS, reply=self.reply_mode is not None,
                                 fake=self.reply_mode == "fake-key") if suite == "lifecycle" else CHECKS
        self.item_case = item_case
        self.item_module = items.producer(item_case) if item_case else None
        self.item_inputs = None
        self.item_result = None
        self.item_lives = []
        if item_case:
            self.checks = summary.with_item(self.checks, item_case)
        self.rows = {
            name: {"check": name, "result": "fail", "presence": presence(name),
                   "observed": {"executed": False, "reason": "prerequisite pending", "owner_request": summary.owners(name)}}
            for name in self.checks
        }
        self.current = "platform"
        self.index = 0
        self.active = None
        self.cleanup_ok = True
        self.socket = None
        self.stage = None
        self.units = []
        self.receipts = []
        self.reservation = None
        self.last = None
        self.challenge = uuid.uuid4().hex
        self.launch_request = launch_request
        self.agent_output = agent_output
        self.root_grants = root_grants
        self.human = None
        self.human_prefix = ""
        self.lane_inputs = lane_inputs
        self.lane_records = []
        self.failed_step = None
        self.admin_inputs = None
        self.boot_input = boot_input
        self.cleanup_native_control = cleanup_native_control
        self.egress_anthropic = egress_anthropic
        self.egress_forward = None
        self.generated_launches = boot_input is None and (
            (suite == "lifecycle" and lane_inputs is None) or (suite == "state" and launch_request is None))
        self.initial = None
        self.initial_ref = None
        self.initial_receipt = None

    def keep(self, name, value):
        if self.api_key_canary is not None:
            require(Path(name).name != "key-store.json", "private credential store cannot be an evidence artifact")
            value = self.api_key_canary.retainable(value)
        path = self.root / name
        with path.open("xb") as stream:
            stream.write(value)
        return path

    def keep_json(self, name, value):
        return self.keep(name, encoded(value))

    def passed(self, observed):
        require(not summary.errors(observed) and not observed.get("error"),
                "a product refusal cannot satisfy a required step")
        if getattr(self, "reply_mode", None) == "fake-key":
            if self.current.startswith("lane.claudock.lifecycle."):
                observed = dict(observed, purpose=flow.LIFECYCLE_ONLY)
            require(flow.fake_row_passed(self.current, observed), flow.AGENT_NOT_STARTED)
        self.rows[self.current] = {
            "check": self.current, "result": "pass", "presence": presence(self.current),
            "observed": dict(observed, executed=True),
        }

    def command(self, name, argv, seconds=60, clean=False, expected=0, cwd=None, environment=None):
        run_deadline = getattr(self, "command_deadline", None)
        scoped = getattr(self, "reply_read", None)
        in_read = (isinstance(scoped, dict) and self.current == scoped.get("row") == "lane.claudock.reply" and
                   name == scoped.get("label") and
                   self.rows.get(self.current, {}).get("observed", {}).get("diagnostics", {}).get("phase") == "read")
        deadline = scoped["deadline"] if in_read else None
        if in_read:
            seconds = min(seconds, flow.REPLY_COMMAND_SECONDS)
            require(deadline - time.monotonic() >= seconds, "reply command lacks its full reserved window")
        if run_deadline is not None:
            remaining = run_deadline - time.monotonic()
            require(remaining > 0, "run budget exhausted before vendor result")
            require(not in_read or remaining >= seconds, "reply command lacks its full reserved window")
            if not in_read:
                seconds = min(seconds, remaining)
        self.index += 1
        stem = "%03d-%s" % (self.index, name)
        self.keep_json(stem + ".argv.json", argv)
        if environment is None and clean:
            environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"}
        started = time.monotonic()
        if in_read:
            require(deadline - time.monotonic() >= seconds, "reply command lacks its full reserved window")
        if run_deadline is not None:
            remaining = run_deadline - time.monotonic()
            require(remaining > 0, "run budget exhausted before vendor result")
            require(not in_read or remaining >= seconds, "reply command lacks its full reserved window")
            if not in_read:
                seconds = min(seconds, remaining)
        try:
            process = subprocess.Popen(
                argv, cwd=cwd or self.stage or self.source, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=environment,
            )
        except OSError:
            self.keep(stem + ".stdout", b"")
            self.keep(stem + ".stderr", b"")
            self.last = {"label": name, "started": False, "exit_code": None,
                         "elapsed_ms": int((time.monotonic() - started) * 1000),
                         "stdout": stem + ".stdout", "stderr": stem + ".stderr"}
            self.keep_json(stem + ".exit.json", self.last)
            raise Failed("command did not start") from None
        self.active = process
        expired = False
        try:
            stdout, stderr = process.communicate(timeout=seconds)
        except subprocess.TimeoutExpired:
            expired = True
            self.cleanup_ok = False
            process.kill()
            stdout, stderr = process.communicate(timeout=10)
        self.active = None
        elapsed = int((time.monotonic() - started) * 1000)
        private_output = getattr(self, "private_output", False) and name == getattr(self, "private_label", name)
        self.command_stderr = stderr if private_output else None
        self.keep(stem + ".stdout", b"" if private_output else stdout)
        self.keep(stem + ".stderr", b"" if private_output else stderr)
        self.keep_json(stem + ".exit.json", {
            "exit_code": process.returncode,
            "timed_out": expired,
            "elapsed_ms": elapsed,
        })
        self.last = {"label": name, "started": True, "exit_code": process.returncode,
                     "elapsed_ms": elapsed,
                     "stdout": stem + ".stdout", "stderr": stem + ".stderr"}
        if private_output:
            self.last["output_withheld"] = True
            self.keep_json(stem + ".output.json", {"withheld": True,
                "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stdout_bytes": len(stdout),
                "stderr_sha256": hashlib.sha256(stderr).hexdigest(), "stderr_bytes": len(stderr)})
        require(not expired, name + " timed out")
        if expected is not None:
            require(process.returncode == expected, name + " failed; inspect " + stem)
        return stdout

    def archive(self):
        self.stage = provision.stage(self.source, self.root)
        if self.cleanup_native_control:
            # Build the negative control from the actual installed composition.
            # Only the protected disposable build copy changes; input Git and
            # the product's helper/cleanup implementations stay untouched.
            target = self.stage / "internal/v2/assembly/assembly.go"
            before = target.read_bytes()
            anchor = b"Clock: clock, CleanupNative: cleanup"
            require(before.count(anchor) == 1, "cleanup build control anchor is missing or ambiguous")
            after = before.replace(anchor, b"Clock: clock, CleanupNative: nil", 1)
            self.keep("cleanup-control.before.go", before)
            self.keep("cleanup-control.after.go", after)
            self.keep_json("cleanup-control.input.json", {
                "path": "internal/v2/assembly/assembly.go", "source_archive": "source.tar",
                "input_sha256": hashlib.sha256(before).hexdigest(),
                "build_sha256": hashlib.sha256(after).hexdigest(), "control": "missing_native_port"})
            target.write_bytes(after)
            require(target.read_bytes() == after, "cleanup control source differs after writeback")
        return self.root / "source.tar"

    def cli(self, label, command, request=None, expected=0, **options):
        self.last = None
        self.rows[self.current]["observed"].update({"rpc_executed": False,
            "phase": "installed human endpoint metadata"})
        binding_file = Path(self.installed["binding_file"])
        binding = self.decode_document(provision.read_protected(binding_file))
        socket = Path(binding["socket"])
        socket_info = socket.lstat()
        evidence_name = "connection-%03d.input.json" % (self.index + 1)
        self.keep_json(evidence_name, {
            "caller": {"uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(),
                       "egid": os.getegid(), "groups": os.getgroups()},
            "binding_sha256": digest(binding_file),
            "socket_matches_installation": binding["socket"] == self.installed["socket"],
            "config_matches_installation": binding.get("config") == self.config,
            "artifact_matches_installation": binding.get("artifact_sha256") == self.installed["artifact_sha256"],
            "paths": {name: provision.path_metadata(path) for name, path in (
                ("binding", binding_file), ("socket", socket), ("binary", self.binary))},
            "native_connection_probe": "not performed; the actual CLI performs its sole connection attempt"})
        self.rows[self.current]["observed"]["connection_evidence"] = evidence_name
        require(binding.get("class") == "human" and binding.get("config") == self.config and
                binding["socket"] == self.installed["socket"] and
                binding.get("artifact_sha256") == self.installed["artifact_sha256"] and
                stat.S_ISSOCK(socket_info.st_mode) and socket_info.st_uid == binding["service_uid"] and
                socket_info.st_gid == binding["service_gid"] and stat.S_IMODE(socket_info.st_mode) == 0o660,
                "installed human binding, socket identity or mode differs; retain connection evidence")
        argv = [str(self.binary), *command, "--config", self.config,
                "--binding", self.installed["binding_file"]]
        if request is not None:
            path = self.keep_json("request-%03d.json" % (self.index + 1), request)
            argv.extend(("--request", str(path)))
        for name, value in options.items():
            argv.extend(("--" + name.replace("_", "-"), value))
        data = self.command(label, argv, clean=True, expected=expected)
        self.last["connection_evidence"] = evidence_name
        self.rows[self.current]["observed"]["rpc_executed"] = self.last.get("started") is True
        # A failed command's retained stderr is parsed by checked_cli, even
        # when stdout is absent or malformed. Preserve its actual typed error.
        return self.decode_document(data) if self.last["exit_code"] == 0 and data else None

    def checked_cli(self, label, command, request=None, **options):
        result = self.cli(label, command, request, expected=None, **options)
        if self.last["exit_code"] != 0:
            raw = self.command_stderr if self.last.get("output_withheld") else (self.root / self.last["stderr"]).read_bytes()
            try:
                refusal = agent_evidence.document(raw)
            except ValueError:
                self.rows[self.current]["observed"] = {"executed": True, "owner": None,
                    "reason": "CLI refusal is not a typed JSON error", "command": self.last}
                raise Failed("installed CLI returned an untyped refusal") from None
            self.rows[self.current]["observed"] = {"executed": True, "owner": refusal.get("owner"),
                "refusal": refusal, "exit_code": self.last["exit_code"], "command": self.last}
            raise Failed("installed " + ".".join(command) + " refused")
        return result

    @contextmanager
    def budget_scope(self, deadline):
        missing = object()
        previous = getattr(self, "command_deadline", missing)
        self.command_deadline = deadline if previous is missing or previous is None else min(previous, deadline)
        try:
            yield
        finally:
            if previous is missing:
                del self.command_deadline
            else:
                self.command_deadline = previous

    @contextmanager
    def reply_scope(self):
        """Restore transient read state even if a row exits by BaseException."""
        absent = object()
        names = ("reply_read", "private_output", "private_label", "command_stderr")
        previous = {name: getattr(self, name, absent) for name in names}
        self.reply_read = None
        try:
            yield
        finally:
            for name, value in previous.items():
                if value is absent:
                    if hasattr(self, name):
                        delattr(self, name)
                else:
                    setattr(self, name, value)

    def capture_read(self, label, words, request, deadline):
        """Keep public capture contents in memory, including on CLI failure.

        Only the actual read in the reply row has a reserved window. Human
        challenge/confirm commands keep their normal timeout.
        """
        previous = (getattr(self, "reply_read", None), getattr(self, "private_output", False),
                    getattr(self, "private_label", None))
        saved_check = self.current
        saved_observed = self.rows[saved_check]["observed"]
        self.reply_read = {"deadline": deadline, "row": saved_check, "label": label}
        self.private_output, self.private_label = True, label
        try:
            return self.human.read(label, words, request)
        except Failed:
            refusal = self.rows.get(self.current, {}).get("observed", {}).get("refusal")
            if (words == ["blob", "read"] and self.current == saved_check and
                    self.last and self.last.get("label") == label and isinstance(refusal, dict) and
                    refusal.get("code") == "not_found" and refusal.get("owner") == "lb-v2-service"):
                self.rows[saved_check]["observed"] = saved_observed
                raise flow.CaptureNotVisible(flow.CAPTURE_NOT_VISIBLE) from None
            raise
        finally:
            self.reply_read, self.private_output, self.private_label = previous
            self.command_stderr = None

    def native_cleanup_evidence(self, record, lane, operation):
        """Independently read the real helper journal and Git namespaces.

        This runs only in the disposable root Linux harness. No native port is
        replaced, and a successful service reply alone cannot pass this row.
        """
        workspace_id = lane.get("workspace", {}).get("id", "")
        require(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", workspace_id) is not None and
                re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", self.config) is not None,
                "native cleanup evidence has an invalid protected selector")
        enrollment_raw = provision.read_protected(
            Path("/var/lib/laneboss-v2/helper") / self.config / "workspaces" / (workspace_id + ".json"))
        enrollment = provision.document(enrollment_raw)
        self.keep(record["name"] + "-cleanup-enrollment.input.json", enrollment_raw)
        workspace = enrollment.get("Workspace", {})
        lease_id = enrollment.get("LeaseID", "")
        require(enrollment.get("Schema") == "laneboss.workspace-native.v2" and
                enrollment.get("Config") == self.config and workspace.get("ID") == workspace_id and
                workspace.get("Target") == record["target"] and
                re.fullmatch(r"[A-Za-z0-9_-]{1,128}", lease_id) is not None,
                "native cleanup enrollment belongs to another workspace or run")
        journal_raw = provision.read_protected(
            Path("/var/lib/laneboss-v2/helper") / self.config / (lease_id + ".json"), mode=0o600)
        journal = provision.document(journal_raw)
        # The private helper record contains selectors and metadata; credential
        # bytes remain outside this journal in their protected native channel.
        self.keep(record["name"] + "-cleanup-helper.input.json", journal_raw)
        require(journal.get("schema") == "laneboss.helper-lease.v2" and journal.get("lease", {}).get("id") == lease_id,
                "native cleanup journal belongs to another helper lease")
        cleanup = journal.get("cleanup", {})
        job, removal = cleanup.get("Job", {}), cleanup.get("Removal", {})
        intent, claim = job.get("Intent", {}), job.get("Claim", {})
        cause = intent.get("Cause", {})
        require(cleanup.get("Phase") == "complete" and intent.get("Workspace") == workspace and
                cause.get("config") == self.config and cause.get("target") == record["target"] and
                cause.get("cause_operation_id") == operation.get("id") and
                removal.get("IntentID") == intent.get("ID") and removal.get("ClaimID") == claim.get("ClaimID") and
                removal.get("Unforced") is True and removal.get("Synced") is True,
                "clean did not reach its actual completed native helper journal")
        before, after = removal.get("Before", {}), removal.get("After", {})
        action = removal.get("Action")
        require(action in ("remove_clean", "retain_dirty") and before.get("ID") and after.get("ID") and
                before["ID"] != after["ID"] and before.get("WorkspaceID") == workspace_id and
                after.get("WorkspaceID") == workspace_id and before.get("WorktreeState") == "present" and
                before.get("BranchState") == "present" and type(before.get("Dirty")) is bool,
                "native cleanup lost its measured workspace decision")
        retained = action == "retain_dirty"
        require(before["Dirty"] is retained and
                after.get("WorktreeState") == ("present" if retained else "absent") and
                after.get("BranchState") == ("present" if retained else "absent"),
                "native cleanup journal disagrees with its dirty-work decision")
        parent, repository = Path(enrollment["Parent"]), Path(enrollment["Repository"])
        provision.protected(parent)
        provision.protected(repository)
        for path, key in ((parent, "RootIdentity"), (repository, "GitIdentity")):
            observed = path.lstat()
            require("%d:%d" % (observed.st_dev, observed.st_ino) == workspace.get(key),
                    "native cleanup observer root identity changed")
        worktree = parent / workspace_id
        if retained:
            observed = worktree.lstat()
            require(stat.S_ISDIR(observed.st_mode) and
                    "%d:%d" % (observed.st_dev, observed.st_ino) == workspace.get("DirectoryIdentity"),
                    "native cleanup journal disagrees with the retained worktree identity")
        else:
            require(not os.path.lexists(worktree),
                    "native cleanup journal disagrees with the actual worktree namespace")
        git = Path(enrollment["GitPath"])
        artifact = enrollment["GitArtifact"]
        git_bytes = provision.read_protected(git, 256 << 20)
        require(len(git_bytes) == artifact.get("bytes") and hashlib.sha256(git_bytes).hexdigest() == artifact.get("sha256"),
                "native cleanup observer Git artifact changed")
        self.command("cleanup-native-branch", [str(git), "--no-optional-locks", "-c", "core.hooksPath=/dev/null",
                     "-c", "core.fsmonitor=false", "--git-dir=" + str(repository),
                     "show-ref", "--verify", "--quiet", "refs/heads/" + workspace["Branch"]],
                     clean=True, expected=0 if retained else 1)
        return {"journal_sha256": hashlib.sha256(journal_raw).hexdigest(),
                "enrollment_sha256": hashlib.sha256(enrollment_raw).hexdigest(),
                "action": action, "helper_journal_complete": True, "worktree_measured": True, "branch_measured": True}

    def admin_call(self, mode, request):
        self.last = None
        self.rows[self.current]["observed"] = {"executed": False, "rpc_executed": False,
            "phase": "protected helper input", "owner_request": ["lb-v2-serve"]}
        require(mode in ("enroll-begin", "enroll-complete", "invite-begin", "invite-complete", "spend-reconcile"),
                "unknown administrator input mode")
        name = "%s-%03d.input.json" % (mode, self.index + 1)
        retained = self.keep_json(name, request)
        if self.admin_inputs is None:
            self.admin_inputs = provision.evidence_root("lb-v2-serve-admin-", "/opt")
            self.receipts.append((self.admin_inputs, "administrator-inputs"))
        # Evidence may be below /var/tmp. The helper requires protected
        # ancestors for its actual input, independently of the file's mode.
        path = provision.administrator_input(self.admin_inputs, name, retained.read_bytes())
        path_evidence = name + ".paths.json"
        helper_runtime = Path("/run/laneboss-v2") / self.config
        helper_control = Path("/sys/fs/cgroup/system.slice") / ("laneboss-helper@" + self.config + ".service") / "control"
        self.keep_json(path_evidence, {"input_sha256": digest(path), "retained_sha256": digest(retained),
            "paths": {label: provision.path_metadata(selected) for label, selected in (
                ("helper", self.binary), ("installation", self.installation_file),
                ("admin_binding", Path("/etc/laneboss-v2/admin") / (self.config + ".json")),
                ("human_binding", Path(self.installed["binding_file"])),
                ("helper_socket", helper_runtime / "helper.sock"), ("helper_control", helper_control),
                ("helper_process_inventory", helper_control / "cgroup.procs"),
                ("retained_request", retained), ("helper_request", path))}})
        self.rows[self.current]["observed"]["path_evidence"] = path_evidence
        require(path.read_bytes() == retained.read_bytes(), "helper and retained request bytes differ")
        argv = [str(self.binary), "internal", "helper", "--config", self.config,
                "--installation", str(self.installation_file), "--" + mode, str(path)]
        data = self.command(mode, argv, clean=True, expected=None)
        self.rows[self.current]["observed"]["rpc_executed"] = True
        if self.last["exit_code"] != 0:
            refusal = self.decode_document((self.root / self.last["stderr"]).read_bytes())
            self.rows[self.current]["observed"] = {"executed": True, "owner": refusal.get("owner"),
                "refusal": refusal, "exit_code": self.last["exit_code"], "command": self.last,
                "path_evidence": path_evidence,
                "dependency_refusal": refusal.get("code") == "not_implemented"}
            raise Failed("installed administrator enrollment refused")
        return self.decode_document(data)

    def prepare_human(self):
        self.current = "authenticator.create"
        endpoint = self.installed.get("admin_enrollment")
        if not endpoint:
            self.rows[self.current]["observed"].update({"executed": False, "owner_request": ["lb-v2-admin"]})
            raise Blocked("lb-v2-admin: installed protected administrator enrollment endpoint is absent")
        private = provision.authenticator_private()
        public = json.loads(self.command("auth-create", [str(self.authenticator), "create", "--private", str(private),
            "--config", self.config, "--origin", endpoint["origin"], "--rp-id", endpoint["rp_id"]], clean=True))
        require(public.get("hardware_stood_in") is True and public.get("enrolled") is False and
                public.get("presence") == "simulated" and public.get("credential_id") == self.auth_info["credential_id"] and
                public.get("attestation_marker") == self.auth_info["attestation_marker"] and
                public.get("aaguid") == self.auth_info["aaguid"] and
                public.get("config") == self.config and public.get("public_key_der") and public.get("credential_id"),
                "software authenticator declaration differs")
        self.keep_json("human-enrollment.proposal.json", public)
        self.human = human.HumanRoot(self, private, public, require, Blocked)
        self.passed({"hardware_stood_in": True, "gesture": public["gesture"], "private_directory_retained": True,
                     "credential_id": public["credential_id"], "enrollment_claimed": False})
        self.rows["human.enrollment"]["observed"] = {"executed": False, "reason": "awaiting actual administrator commit receipt"}

    def prepare_other_human(self):
        saved = self.current, self.human_prefix
        self.current, self.human_prefix = "capture.other.enroll", "itemdashboard"
        endpoint = self.installed["admin_enrollment"]
        private = provision.authenticator_private()
        public = json.loads(self.command("auth-create-other", [str(self.authenticator), "create", "--invited",
            "--private", str(private), "--config", self.config, "--origin", endpoint["origin"], "--rp-id", endpoint["rp_id"]], clean=True))
        require(public.get("principal_id") != self.human.public["principal_id"] and
                public.get("credential_id") != self.human.public["credential_id"] and
                public.get("public_key_der") != self.human.public["public_key_der"] and
                public.get("presence") == "simulated", "second human does not own a distinct declared test key")
        self.other_human = human.HumanRoot(self, private, public, require, Blocked)
        self.other_human.enroll(self.human)
        self.current, self.human_prefix = saved

    def verify_other_capture(self, record):
        saved = self.current, self.human_prefix
        self.current, self.human_prefix = "capture.other.read", "itemdashboard"
        retained = flow.events(self, record, require)
        captures = [event["payload"]["data"] for event in retained
                    if event.get("kind") == "capture.appended" and event.get("origin") == "service" and
                    event.get("config") == self.config and event.get("life_id") == record["target"]["life_id"] and
                    event.get("run") == record["target"]["run"] and event.get("payload", {}).get("primary") is True]
        require(captures, "isolation check has no actual capture to read")
        ref = captures[0]
        request = {"object_id": ref["id"], "offset": 0, "limit": min(ref["bytes"], 4096)}
        owner = self.human.read("capture-owner-control", ["blob", "read"], request)
        data = base64.b64decode(owner["data"], validate=True)
        require(data and len(data) == request["limit"] and hashlib.sha256(data).hexdigest() == owner["sha256"],
                "capture owner control did not read the actual bytes")
        self.human_prefix = "other"
        identity = self.other_human.read("capture-other-identity", ["identity", "self"], {})
        require(identity.get("actor", {}).get("id") == self.other_human.public["principal_id"],
                "second human did not authenticate with its approved own key")
        proof = self.other_human.proof("read", "human.session", {}, self.other_human.public["principal_id"], 0)
        self.current = "capture.other.read"
        self.cli("capture-other-read", ["blob", "read"], request, expected=2, proof=str(proof))
        denied = self.decode_document((self.root / self.last["stderr"]).read_bytes())
        require(denied.get("code") == "not_found" and not (self.root / self.last["stdout"]).read_bytes(),
                "approved second human read the first human's capture or missed the actual visibility check")
        self.passed({"reader": identity["actor"], "object_id": ref["id"], "owner_bytes_read": len(data),
                     "denied_code": denied["code"], "denied_exit": self.last["exit_code"]})
        self.current, self.human_prefix = saved

    def publication_call(self, name, output):
        data = self.command(name, ["bash", str(self.stage / "scripts/v2-admin/install.sh"),
            "--publish", "--config", self.config, "--evidence", str(output)], clean=True, expected=None)
        self.rows[self.current]["observed"].update({"rpc_executed": True, "command": self.last})
        if self.last["exit_code"] != 0:
            helper_error = output / "publication.stderr"
            if helper_error.is_file():
                raw = provision.read_protected(helper_error, mode=0o600)
                try:
                    refusal = self.decode_document(raw)
                except ValueError:
                    self.rows[self.current]["observed"]["reason"] = "helper refusal is not typed JSON; retain raw stderr"
                else:
                    require(refusal.get("code") and refusal.get("owner"), "publication helper error has no typed owner")
                    self.rows[self.current]["observed"].update({"refusal": refusal, "owner": refusal["owner"]})
            raise Failed("installed initial publication failed; retain installer and helper evidence")
        result = self.decode_document(data)
        require(set(result) == {"verified", "published", "receipt"} and result["verified"] is True and
                result["published"] is True, "publication installer did not return its actual receipt")
        receipt = result["receipt"]
        retained = self.decode_document(provision.read_protected(output / "receipt.json", mode=0o600))
        require(receipt == retained, "publication response differs from retained helper receipt")
        provision.fields(receipt, ("schema", "config", "id", "manifest", "receipt", "operation_id",
                                   "event_id", "committed_seq", "generation"))
        require(receipt["schema"] == "laneboss.initial-receipt.v2" and receipt["config"] == self.config and
                receipt["id"] == self.initial["id"] and receipt["manifest"] == self.initial_ref and
                type(receipt["generation"]) is int and receipt["generation"] == 1 and
                receipt["operation_id"] == "initial-op-" + self.initial["id"] and
                receipt["event_id"] == "initial-event-" + self.initial["id"] and
                type(receipt["committed_seq"]) is int and 0 < receipt["committed_seq"] < 1 << 53,
                "publication receipt changed its input, operation or committed event")
        ref = receipt["receipt"]
        provision.fields(ref, ("id", "class", "sha256", "bytes"))
        require(ref["id"] == "initial-receipt-" + self.config and ref["class"] == "manifest" and
                isinstance(ref["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", ref["sha256"]) and
                type(ref["bytes"]) is int and 0 < ref["bytes"] <= 1048576,
                "publication receipt lacks its exact immutable marker pin")
        return receipt

    def publication_blob(self, ref):
        content = bytearray()
        require(type(ref.get("bytes")) is int and 0 < ref["bytes"] <= 1048576,
                "publication read-back document exceeds its bound")
        while len(content) < ref["bytes"]:
            limit = min(262144, ref["bytes"] - len(content))
            chunk = self.human.read("publication-blob", ["blob", "read"],
                {"object_id": ref["id"], "offset": len(content), "limit": limit})
            data = base64.b64decode(chunk["data"], validate=True)
            require(chunk.get("object_id") == ref["id"] and chunk.get("offset") == len(content) and
                    0 < len(data) <= limit and chunk.get("sha256") == provision.sha(data),
                    "publication read-back changed its object, range or bytes")
            content.extend(data)
        raw = bytes(content)
        provision.pinned(ref, raw)
        return raw

    def publish_initial(self):
        self.current = "admin.publish"
        if self.initial is None:
            self.rows[self.current]["observed"].update({"executed": False,
                "owner_request": ["lb-v2-serve", "lb-v2-admin"], "reason": "protected first-install boot bundle was not supplied"})
            raise Blocked("protected initial publication input is absent; retain boot.inputs evidence")
        self.rows[self.current]["observed"]["publication_input"] = {
            "objects": len(self.initial["objects"]),
            "bytes": sum(ref["bytes"] for ref in self.initial["objects"]),
            "largest_object_bytes": max(ref["bytes"] for ref in self.initial["objects"])}
        output = provision.evidence_root("lb-v2-serve-publication-", "/opt")
        self.receipts.append((output, "initial-publication"))
        first = self.publication_call("initial-publish", output / "first")
        self.passed({"receipt": first, "event_verified_by": "native publisher exact first event and marker read-back"})
        self.current = "admin.publish.retry"
        retry = self.publication_call("initial-publish-retry", output / "retry")
        require(retry == first, "identical publication retry changed its durable receipt")
        self.passed({"receipt": retry, "identical": True})
        self.initial_receipt = first
        self.current = "admin.publication"
        # The public stream selects a real life/run, so it cannot be used to
        # invent an org-event query. The protected publisher checks the exact
        # first event at committed_seq; public reads independently bind the
        # marker, descriptor, published policy bytes and completed operation.
        marker_raw = self.publication_blob(first["receipt"])
        marker = self.decode_document(marker_raw)
        require(marker == {"schema": "laneboss.initial-marker.v2", "config": self.config,
                           "id": self.initial["id"], "manifest": self.initial_ref},
                "retained marker differs from the supplied publication")
        descriptor = self.publication_blob(self.initial_ref)
        require(descriptor == (self.root / "initial-inputs/initial.json").read_bytes(),
                "retained descriptor differs from the exact protected boot input")
        operation = self.human.read("publication-operation", ["operation", "get"],
                                    {"operation_id": first["operation_id"]})
        require(operation.get("id") == first["operation_id"] and operation.get("status") == "succeeded" and
                not operation.get("error") and type(operation.get("first_seq")) is int and
                type(operation.get("last_seq")) is int and
                operation["first_seq"] == operation["last_seq"] == first["committed_seq"],
                "publication receipt differs from the completed single-event operation")
        policy_raw = self.publication_blob(self.initial["policy"])
        expected = (self.root / "initial-inputs" / self.initial["policy"]["id"]).read_bytes()
        policy = self.decode_document(policy_raw)
        require(policy_raw == expected and type(policy.get("generation")) is int and policy["generation"] == 1,
                "published policy bytes differ from the supplied generation-one input")
        org_validation = self.human.read("publication-org-validate", ["org", "validate"],
                                         {"generation": first["generation"]})
        require(set(org_validation) == {"valid", "problems"} and org_validation["valid"] is True and
                org_validation["problems"] == [],
                "published org failed full validation at its exact committed generation")
        self.passed({"receipt": first, "operation": operation, "marker_sha256": provision.sha(marker_raw),
                     "input_sha256": provision.sha(descriptor), "policy_sha256": policy["sha256"],
                     "org_validation": org_validation, "org_generation": first["generation"],
                     "current_policy_verified_by": "native publisher rereads current typed policy before each receipt",
                     "event_verification": "native exact kind, config, ID, operation, sequence and marker check"})

    def root_grant_input(self, path):
        raw = provision.read_protected(path)
        request = self.decode_document(raw)
        require(self.initial is not None and self.initial_receipt is not None and
                request.get("manifest") == self.initial["profiles"],
                "root grant request does not select the committed initial profile manifest")
        if getattr(self, "item_module", None) is not None and hasattr(self.item_module, "enroll_root"):
            request = self.item_module.enroll_root(self, request)
            return provision.encoded(request)
        return raw

    def root_launch_input(self, path):
        return provision.read_protected(path)

    def reconcile_canary_spend(self):
        """Seed only the fake-key canary via the installed operator entry."""
        if self.api_key_canary is None:
            return
        self.current = "admin.publication"
        row = self.rows[self.current]
        require(row["result"] == "pass" and self.admin_inputs is not None,
                "canary spend enrollment requires completed publication")
        previous = copy.deepcopy(row["observed"])
        row["result"] = "fail"
        profiles = self.decode_document(
            self.publication_blob(self.initial["profiles"]))
        selected = [profile for profile in profiles.get("profiles", [])
                    if profile.get("driver") == "claudock-cli"]
        require(len(selected) == 1 and selected[0].get("profile_id"),
                "canary spend profile is missing or ambiguous")
        request = provision.canary_balance(
            self.admin_inputs, self.root, selected[0]["profile_id"])
        declaration = {
            "schema": "laneboss.canary-spend.v1", "fake_reading": True,
            "authenticated_service": False,
            "credential_id": request["credential_id"],
            "profile_ids": request["profile_ids"], "selector": request["selector"],
            "reading_micros": 10000000, "floor_micros": request["floor_micros"],
            "tool_source": "canary-balance.input.sh",
        }
        self.keep_json("canary-spend.fixture.json", declaration)
        balance = self.admin_call("spend-reconcile", request)
        self.keep_json("canary-spend.balance.json", balance)
        amounts = {"seed_micros": declaration["reading_micros"], "spent_micros": 0,
                   "reading_micros": declaration["reading_micros"],
                   "remaining_micros": declaration["reading_micros"],
                   "floor_micros": declaration["floor_micros"]}
        require(balance.get("credential_id") == request["credential_id"] and
                all(type(balance.get(name)) is int and balance[name] == value
                    for name, value in amounts.items()) and
                type(balance.get("generation")) is int and balance["generation"] > 0 and
                balance.get("needs_reading") is False and
                balance.get("accounting_error") is None,
                "installed canary spend receipt differs from the fake tool reading")
        try:
            observed = datetime.fromisoformat(balance.get("observed_at", "").replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError):
            raise Failed("installed canary spend receipt lacks its observation time") from None
        require(observed.utcoffset() is not None and
                abs((datetime.now(timezone.utc) - observed).total_seconds()) <= 60,
                "installed canary spend receipt has no fresh tool observation")
        self.passed(dict(previous, canary_spend={
            "fake_reading": True, "balance": balance, "command": self.last,
            "purpose": "credential setup only; does not prove the agent ran",
            "fixture": "canary-spend.fixture.json",
            "tool_sha256": digest(Path(request["command"])),
        }))

    def installation_validation(self, output):
        """Read the installer's actual native validator result without its argv or key."""
        status_file = output / "initial-validation.exit.json"
        if not status_file.exists():
            return {"retained": False}
        status = self.decode_document(provision.read_protected(status_file, mode=0o600))
        provision.fields(status, ("exit_code",))
        require(type(status["exit_code"]) is int, "native validation exit evidence differs")
        observed = {"retained": True, "exit_code": status["exit_code"]}
        if status["exit_code"] == 0:
            value = self.decode_document(provision.read_protected(output / "initial-validation.stdout", mode=0o600))
            provision.fields(value, ("valid", "manifest", "id"))
            observed["matches_inputs"] = (value["valid"] is True and self.initial is not None and
                value["manifest"] == self.initial_ref and value["id"] == self.initial["id"])
        else:
            raw = provision.read_protected(output / "initial-validation.stderr", mode=0o600, allow_empty=True)
            try:
                refusal = self.decode_document(raw)
            except ValueError:
                observed["typed_refusal"] = False
            else:
                require(refusal.get("code") and refusal.get("owner"), "native validator error lacks its typed owner")
                observed["refusal"] = refusal
        return observed

    def bind_root_launch(self, launch, grants, *, evidence_round=None):
        """Bind proposal selectors only to IDs returned by real grants.root."""
        if not self.generated_launches:
            return
        collections = ("resources", "data", "secrets", "profiles", "network", "channels")
        require(type(grants.get("policy_generation")) is int and
                grants["policy_generation"] == self.initial_receipt["generation"] and
                all(isinstance(grants.get(name), list) for name in collections),
                "issued root grants lost their actual policy or collections")
        approved = getattr(self, "grants_enrolled_manifest", None)
        if approved is None:
            approved = self.decode_document((self.root / "initial-inputs" / self.initial["profiles"]["id"]).read_bytes())
        require(len(grants["profiles"]) == len(approved["profiles"]) and len(grants["data"]) == len(approved["data"]) and
                len(grants["network"]) == len(approved["network"]) and
                all(len(grants[name]) == len(approved[name]) for name in ("resources", "secrets", "channels")),
                "issued fixture root grants exceed or omit the approved inventory")
        require(len(approved["network"]) == int(self.egress_anthropic),
                "approved network inventory differs from the explicit egress option")
        for expected_net in approved["network"]:
            require(expected_net["endpoint_id"] == "anthropic-api" and expected_net["mode"] == "internet",
                    "approved network grant exceeds the enrolled API scope")
            candidates = [row for row in grants["network"] if all(row.get(name) == expected_net[name] for name in
                          ("endpoint_id", "mode", "delegate", "expires_at"))]
            require(len(candidates) == 1, "issued root network grant differs from approved scope")
        ids = set()
        for expected_profile in approved["profiles"]:
            matches = [row for row in grants["profiles"] if row.get("profile_id") == expected_profile["profile_id"]]
            require(len(matches) == 1 and all(matches[0].get(name) == expected_profile[name] for name in
                    ("driver", "provider", "paid", "delegate", "expires_at")),
                    "returned root profile differs from the approved fixture scope")
        for row in [row for family in collections for row in grants[family]]:
            identifier = row.get("id")
            require(isinstance(identifier, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identifier) and
                    identifier not in ids and not row.get("parent_grant_id"), "returned root member identity differs")
            ids.add(identifier)
        selectors = getattr(self, "fixture_profile_selectors", {})
        require(isinstance(selectors, dict), "fixture profile selectors must name profiles by driver")
        selector = selectors.get(launch["driver"])
        require(selector is None or isinstance(selector, str) and bool(selector), "fixture profile selector is invalid")
        selected = [row for row in approved["profiles"] if row["driver"] == launch["driver"]
                    and (selector is None or row["profile_id"] == selector)]
        require(len(selected) == 1, "fixture profile selection is ambiguous" if selector is None else
                "fixture profile selector is not approved for this driver")
        expected = selected[0]
        profiles = [row for row in grants["profiles"] if row.get("profile_id") == expected["profile_id"] and
                    row.get("driver") == expected["driver"]]
        require(len(profiles) == 1 and profiles[0].get("id") and
                all(profiles[0].get(name) == expected[name] for name in
                    ("provider", "paid", "delegate", "expires_at")),
                "returned root profile differs from its approved fixture selector")
        profile = profiles[0]
        data = []
        for expected_data in approved["data"]:
            candidates = [row for row in grants["data"] if all(row.get(name) == expected_data[name] for name in
                ("source_object_id", "source_sha256", "relative_path", "access", "delivery", "destination",
                 "delegate", "expires_at", "history_scope")) and
                row.get("publication_id") == expected_data.get("publication_id")]
            require(len(candidates) == 1 and candidates[0].get("id"), "returned root data differs from approved fixture bytes")
            issued = candidates[0]
            data.append({"parent_grant_id": issued["id"], **{name: issued[name] for name in
                ("relative_path", "access", "delivery", "destination", "delegate", "expires_at")}})
        require(not launch.get("profile_grant_id") and all(not launch["grants"][name] for name in launch["grants"]),
                "fixture proposal already contains invented issued selectors")
        launch["profile_grant_id"] = profile["id"]
        launch["grants"]["data"] = data
        launch["grants"]["profiles"] = [{"parent_grant_id": profile["id"], "profile_id": profile["profile_id"],
                                        "delegate": profile["delegate"], "expires_at": profile["expires_at"]}]
        if self.egress_anthropic and launch["driver"] == "claudock-cli":
            require(len(grants["network"]) == 1, "Anthropic API network grant was not issued")
            network = grants["network"][0]
            launch["grants"]["network"] = [{"parent_grant_id": network["id"], "endpoint_id": network["endpoint_id"],
                                          "delegate": network["delegate"], "expires_at": network["expires_at"]}]
        for family, fields in (
                ("resources", ("regions", "image_ids", "machine_types", "max_active",
                 "max_hourly_micros", "total_budget_micros", "delegate", "expires_at")),
                ("secrets", ("name", "version", "delivery", "target", "delegate", "expires_at")),
                ("channels", ("channel_id", "delegate", "expires_at"))):
            selected = []
            for expected_row in approved[family]:
                matches = [row for row in grants[family] if all(
                    row.get(key) == value for key, value in expected_row.items()
                    if key not in ("id", "parent_grant_id"))]
                require(len(matches) == 1, "issued case member differs from approved scope")
                member = matches[0]
                selected.append({"parent_grant_id": member["id"],
                                 **{key: member[key] for key in fields}})
            launch["grants"][family] = selected
        suffix = ".%02d" % evidence_round if evidence_round is not None else ""
        self.keep_json("launch-" + self.human_prefix + "-" + launch["driver"] + suffix + ".input", launch)

    def validate_initial_launch(self, request):
        require(self.initial is not None and self.initial_receipt is not None and
                request.get("level") == self.initial["l5"]["level"] == 5 and
                request.get("role") == self.initial["l5"]["role"] and
                request.get("task") == self.initial["task"] and
                request.get("expected_policy_generation") == self.initial_receipt["generation"],
                "launch differs from the actual published L5 role, task or policy")
        launch = self.decode_document((self.root / "launch-enrollment.json.input").read_bytes())
        require(any(row["project_id"] == request.get("project_id") for row in launch["projects"]) and
                any(row["driver"] == request.get("driver") for row in launch["runtimes"]),
                "launch project or driver is absent from protected enrollment")

    def uid_direct_open(self):
        targets = [Path(self.installed["state_directory"]) / name for name in
                   ("state.sqlite", "state.sqlite-wal")]
        identities = []
        for path in targets:
            before = path.lstat()
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                    "direct-open target is not real")
            identities.append((before.st_dev, before.st_ino))
        harness = Path(__file__).resolve().with_name("open.py")
        canary = self.stage / "serve-open.py"
        shutil.copyfile(harness, canary)
        canary.chmod(0o444)
        provision.protected(canary)
        control = self.stage / "serve-open.control"
        control.write_bytes(os.urandom(32))
        control.chmod(0o444)
        lane = self.admin["lanes"][0]
        argv = ["setpriv", "--reuid=" + str(lane["uid"]),
                "--regid=" + str(lane["gid"]), "--clear-groups",
                "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all",
                "--no-new-privs", "/usr/bin/python3", "-I", "-B", str(canary),
                "--uid", str(lane["uid"]), "--control", str(control),
                "--sha256", digest(control), *map(str, targets)]
        observed = json.loads(self.command("direct-open", argv, clean=True))
        require(observed.get("uid") == lane["uid"] and observed.get("control") is True,
                "direct-open control failed")
        require(len(observed["targets"]) == len(targets) and
                all(row["denied"] and row["errno"] in (1, 13) for row in observed["targets"]),
                "direct-open did not observe denial")
        for path, identity in zip(targets, identities):
            after = path.lstat()
            require((after.st_dev, after.st_ino) == identity, "direct-open target disappeared")
        self.passed(dict(observed, scope=["database", "WAL"]))

    def launch(self):
        self.current = "state.launch"
        if self.launch_request is not None:
            data = self.root_launch_input(self.launch_request)
            request = agent_evidence.document(data)
            self.keep("launch-request.input.json", data)
        else:
            self.rows[self.current]["observed"].update({"executed": False,
                "owner_request": ["lb-v2-serve", "lb-v2-grants"],
                "reason": "protected launch request selecting the published L5 inputs was not supplied"})
            raise Blocked("state scope requires --launch-request with actual published L5 selectors")
        require(not request.get("root_ticket_id"), "launch input cannot supply a copied root ticket")
        self.validate_initial_launch(request)
        ticket = self.human.ticket(request, self.root_grants)
        request["root_ticket_id"] = ticket["id"]
        self.current = "state.launch"
        options = {}
        # lane.start is a mutation: the installed CLI requires a retained idempotency key
        options["idempotency_key"] = "serve-start-" + uuid.uuid4().hex
        session_proof = self.human.proof("read", "human.session", {}, self.human.public["principal_id"], 0)
        self.current = "state.launch"
        options["session_proof"] = str(session_proof)
        operation = self.cli("lane-start", ["lane", "start"], request, expected=None, **options)
        if self.last["exit_code"] != 0:
            refusal = agent_evidence.document((self.root / self.last["stderr"]).read_bytes())
            self.rows[self.current]["observed"] = {
                "executed": True, "request_kind": "provided" if self.launch_request else "proposal",
                "exit_code": self.last["exit_code"], "refusal": refusal,
                "owner": refusal.get("owner"),
                "lifecycle_reached": refusal.get("owner") == "lb-v2-lifecycle",
                "durable_context_gate": refusal.get("owner") == "lb-v2-lifecycle" and
                    refusal.get("code") == "not_implemented" and
                    "durable launch and private workspace context" in refusal.get("message", ""),
                "command": self.last}
            raise Failed("installed lane.start refused")
        require(operation.get("id") and operation.get("life_id") and type(operation.get("run")) is int and
                operation["run"] > 0 and operation.get("status") in ("pending", "running", "succeeded"),
                "lane.start did not return a real reservation")
        self.passed(dict(operation, scope="reservation; process execution not yet credited"))
        return operation

    def await_plan(self, operation):
        self.current = "state.plan"
        deadline = time.monotonic() + 120
        events, cursor = [], ""
        while True:
            actual = self.human.read("launch-operation", ["operation", "get"], {"operation_id": operation["id"]})
            require(actual.get("id") == operation["id"] and actual.get("life_id") == operation["life_id"] and
                    actual.get("run") == operation["run"], "launch operation identity changed")
            if actual.get("error"):
                refusal = actual["error"]
                self.rows[self.current]["observed"] = {"executed": True, "refusal": refusal,
                    "owner": refusal.get("owner"), "operation": actual, "command": self.last}
                raise Failed("real PlanLaunch operation failed")
            page = self.human.read("launch-events", ["event", "tail"], {
                "life_id": "", "run": 0, "since": 0,
                "cursor": cursor, "follow": False, "until": "", "deadline_ms": 1000})
            require(isinstance(page.get("events"), list), "launch event page absent")
            events = launch_evidence.merge(events, page["events"])
            cursor = page.get("cursor", "")
            if any(event.get("operation_id") == operation["id"] and event.get("kind") == "launch.planned" for event in events):
                result = launch_evidence.observe(events, operation, self.config, {
                    "supervisor": digest(self.binary), "agent": self.agent["sha256"],
                    "runtime": self.installed["runtime_manifest"]["sha256"]})
                self.passed({"planned_seq": result["planned_seq"], "plan": result["plan"]})
                self.current = "state.capture"
                capture = result["capture"]
                if capture["status"] == "refused":
                    self.rows[self.current]["observed"] = {"executed": True, "owner": capture["refusal"]["owner"],
                        "refusal": capture["refusal"], "binding": capture, "seq": result["capture_seq"]}
                    raise Failed("real capture registration refused")
                self.capture = capture
                self.passed({"binding": capture, "seq": result["capture_seq"]})
                return
            require(actual.get("status") not in ("failed", "cancelled"), "launch operation ended without a plan")
            require(time.monotonic() < deadline, "PlanLaunch observation deadline")
            time.sleep(0.2)

    def collect_agent(self, operation):
        self.current = "state.collect"
        target = {"life_id": operation["life_id"], "run": operation["run"]}
        deadline = time.monotonic() + 120
        while True:
            lane = self.human.read("launched-lane", ["lane", "status"], target)
            require(lane.get("life_id") == target["life_id"] and lane.get("run") == target["run"] and
                    lane.get("launch_id") == self.capture["launch_id"], "lane differs from captured run")
            if lane.get("session", {}).get("vendor_id"):
                require(lane["session"].get("driver") == "codex" and
                        lane["session"].get("vendor_version") == self.agent["version"],
                        "launched lane is not the enrolled fixture")
                # lane.check is a control mutation, not a human-session read.
                proof = self.human.proof("check", "lane.check", target, target["life_id"], lane["generation"])
                self.current = "state.collect"
                observed = self.human.rpc("lane-quiescence", ["lane", "check"], target, proof)
                require(observed.get("handle", {}).get("target") == target, "check observed another run")
                if observed.get("state") == "exited":
                    require(observed.get("survivors") == 0 and observed.get("exit_code") == 0,
                            "fixture did not exit normally with zero survivors")
                    break
                require(observed.get("state") == "running" and observed.get("survivors", 0) > 0,
                        "fixture containment is unknown")
            require(lane.get("state") not in ("lost", "failed", "cleaned", "abandoned"), "fixture lane failed before collection")
            require(time.monotonic() < deadline, "fixture quiescence deadline")
            time.sleep(1)
        if self.agent_output is not None:
            self.keep_json("agent-output.proposal.json", {"path": str(self.agent_output),
                           "authority": False, "reason": "no attested launch/workspace mapping"})
        # A lane-pool UID or caller-supplied path cannot identify this run's
        # workspace or attest that these bytes came from its pinned process.
        # Fix 9's protected outside-capture/workspace port must supply both
        # the output root and expected identity before collect_outputs runs.
        raise Blocked("lb-v2-lifecycle/admin: attested workspace and capture mapping absent")

    def collect_outputs(self, output, expected):
        """Prepared reader; callable only after the real mapping is implemented."""
        result = agent_evidence.audit(output, expected)
        retained = self.root / "agent-output"
        retained.mkdir(mode=0o700)
        for path in output.iterdir():
            data = agent_evidence.read(output, path.name)
            (retained / path.name).write_bytes(data)
            require(digest(retained / path.name) == hashlib.sha256(data).hexdigest(), "agent collection differs")
        self.passed({"life": expected["life"], "run": expected["run"], "calls": result["calls"]})
        for check, value in (("state.authorized", result["identity"]), ("state.append", result["record"]),
                             ("state.read", {"sha256": result["content_sha256"]}),
                             ("state.exact-retry", result["ordinary_retry"]),
                             ("state.changed-bytes", result["changed"]), ("unready.owner", result["unready"])):
            self.current = check
            self.passed(value)

    def build_artifact(self):
        """Build the exact artifact later pinned as the confined bootstrap."""
        binary = self.stage / "laneboss.input"
        tags = ("laneboss_partial", "laneboss_e2e_authenticator")
        self.command("build", ["go", "build", "-trimpath", "-mod=vendor", "-tags", ",".join(tags),
                               "-o", str(binary), "./cmd/laneboss"], seconds=900,
                     environment=dict(os.environ, CGO_ENABLED="0"))
        binary.chmod(0o555)
        return binary, tags

    def build_fixture(self, package):
        """Use the same static release policy for the confined agent fixture."""
        binary = self.stage / "serve-fixture"
        self.command("fixture-build", ["go", "build", "-trimpath", "-mod=vendor", "-tags", "laneboss_e2e_authenticator",
                     "-o", str(binary), package], seconds=600,
                     environment=dict(os.environ, CGO_ENABLED="0"))
        binary.chmod(0o555)
        return binary

    def build_authenticator(self):
        source = provision.authenticator_source(self.root)
        binary = source / "serve-authenticator"
        self.command("auth-build", ["go", "build", "-tags", "laneboss_e2e_authenticator", "-trimpath", "-o", str(binary),
                     "./cmd/laneboss/serve-authenticator"], seconds=600, cwd=source,
                     environment=dict(os.environ, CGO_ENABLED="0"))
        binary.chmod(0o555)
        return binary

    def build_bundle(self):
        binary = self.stage / "serve-bundle.input"
        self.command("bundle-build", ["go", "build", "-trimpath", "-mod=vendor", "-o", str(binary),
                     "./scripts/v2-serve/bundle"], seconds=600,
                     environment=dict(os.environ, CGO_ENABLED="0"))
        binary.chmod(0o555)
        return binary

    def install(self):
        require(platform.system() == "Linux" and os.getuid() == 0 and os.geteuid() == 0,
                "requires authorized Linux root")
        facts = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines()
                     if "=" in line)
        require(facts.get("ID", "").strip('"') == "ubuntu" and
                facts.get("VERSION_ID", "").strip('"') == "24.04", "requires Ubuntu 24.04")
        self.passed({"os": platform.system(), "release": "24.04", "uid": os.geteuid()})
        self.current = "source"
        owner = self.source.stat()
        # Read repository metadata as its owner. Root does not override Git's
        # ownership guard or change safe.directory to inspect a user tree.
        if self.source_snapshot:
            require(not os.path.lexists(self.source / ".git"),
                    "snapshot mode requires a source tree without Git metadata")
            self.keep_json("source-kind.json", {"kind": "snapshot", "git_revision": None})
        else:
            revision = self.command("revision", ["setpriv", "--reuid=" + str(owner.st_uid),
                "--regid=" + str(owner.st_gid), "--clear-groups", "--inh-caps=-all",
                "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs",
                "git", "--no-optional-locks", "rev-parse", "HEAD"], clean=True)
            self.keep("source-revision.txt", revision)
        archive = self.archive()
        self.passed({"sha256": digest(archive), "archive": archive.name})
        self.current = "build"
        self.command("toolchain", ["go", "version"])
        self.command("vendor", ["go", "mod", "vendor"], seconds=900)
        with tarfile.open(self.root / "dependencies.tar", "w") as dependencies:
            dependencies.add(self.stage / "vendor", arcname="vendor", recursive=True)
        self.keep("vendor-manifest.input", (self.stage / "vendor/modules.txt").read_bytes())
        binary, tags = self.build_artifact()
        version = json.loads(self.command("version", [str(binary), "--version"]))
        require(isinstance(version, dict) and version.get("program") == "laneboss" and
                version.get("api_protocol") == "laneboss.rpc.v2" and
                version.get("contract_revision") == "v2.0-draft.4", "wrong built contract")
        require(re.fullmatch(r"[0-9][A-Za-z0-9._-]{0,31}", version.get("version", "")),
                "invalid release version")
        shutil.copyfile(binary, self.root / "laneboss.input")
        require(digest(self.root / "laneboss.input") == digest(binary), "retained artifact differs")
        self.passed({"sha256": digest(binary), "tags": list(tags)})
        self.current = "fixture.build"
        fixture_package = (getattr(self.item_module, "AGENT_PACKAGE", None) or
                           "./cmd/laneboss/serve-fixture")
        fixture_packages = self.command("fixture-inputs", ["go", "list", "-mod=vendor", "-tags",
            "laneboss_e2e_authenticator", "-deps", "-json", fixture_package], seconds=600,
            environment=dict(os.environ, CGO_ENABLED="0"))
        provision.fixture_source(self.stage, self.root, fixture_packages,
                                 fixture_package.removeprefix("./") + "/main.go")
        # The fixture and its CLI client use this exact staged module and vendor
        # tree. No isolated module or substitute go.mod is recorded as an input.
        agent_binary = self.build_fixture(fixture_package)
        agent = json.loads(self.command("fixture-version", [str(agent_binary), "--version"]))
        require(agent.get("program") == "laneboss-serve-fixture" and agent.get("vendor_stood_in") is True,
                "fixture declaration is absent")
        self.agent = dict(agent, path=str(agent_binary), sha256=digest(agent_binary))
        shutil.copyfile(agent_binary, self.root / "serve-fixture.input")
        require(digest(self.root / "serve-fixture.input") == self.agent["sha256"], "retained fixture differs")
        self.passed({"program": agent["program"], "version": agent["version"],
                     "package": fixture_package, "fixture_kind": agent.get("fixture_kind"),
                     "sha256": self.agent["sha256"], "vendor_stood_in": True})
        if self.real_claudock:
            # The real binaries are fetched and built only on this disposable
            # box. Their isolated HOME contains no credential or owner profile.
            self.current = "boot.inputs"
            self.real_vendor = provision.real_claudock(self.root, self.command)
        self.current = "authenticator.build"
        self.authenticator = self.build_authenticator()
        auth = json.loads(self.command("auth-version", [str(self.authenticator), "--version"]))
        self.auth_info = auth
        require(auth.get("program") == "laneboss-serve-authenticator" and auth.get("hardware_stood_in") is True and
                auth.get("presence") == "simulated",
                "software authenticator declaration absent")
        retained_auth = self.root / "serve-authenticator.input"
        shutil.copyfile(self.authenticator, retained_auth)
        require(digest(retained_auth) == digest(self.authenticator), "retained authenticator differs")
        self.passed(dict(auth, sha256=digest(self.authenticator)))
        if self.item_module is not None:
            self.current = "item." + self.item_case + ".boot"
            self.item_inputs = self.item_module.boot(self)
            self.passed({"declared_runtime": True, "item_case": self.item_case})
        self.current = "root.stage"
        provision.protected(self.stage / "scripts/v2-admin/boot.py")
        provision.protected(binary)
        self.passed({"root_owned": True, "binary_sha256": digest(binary)})
        self.current = "boot.inputs"
        arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
        require(arch is not None, "unsupported release architecture")
        bundle_tool = None
        if self.boot_input is None:
            bundle_tool = self.build_bundle()
            self.keep("serve-bundle.input", bundle_tool.read_bytes())
            require(digest(self.root / "serve-bundle.input") == digest(bundle_tool), "retained bundle assembler differs")
        boot, manifest, self.reservation = provision.boot(binary, version, arch, self.root, self.agent,
            self.config, self.challenge, self.suite, self.boot_input, self.stage, bundle_tool, self.command,
            egress_anthropic=self.egress_anthropic, real_vendor=self.real_vendor,
            item_inputs=self.item_inputs, canary_api_key=self.api_key_canary is not None,
            real_api_key=self.real_api_key)
        if self.boot_input is None:
            self.root_grants = self.root_grants or boot.parent / "root-grants.json"
            self.lane_inputs = self.lane_inputs or boot.parent / "lane-inputs.json"
            self.launch_request = self.launch_request or boot.parent / "state-launch.json"
        self.enrollment = json.loads((self.root / "fixture-enrollment.input.json").read_bytes())
        boot_data = provision.document(provision.read_protected(boot))
        if "initial_publication" in boot_data:
            self.initial_ref = boot_data["initial_publication"]
            self.initial = self.decode_document((self.root / "initial-inputs/initial.json").read_bytes())
            self.challenge = self.enrollment["challenge"]
        runtime_file = Path(boot_data["runtime_file"])
        key_bytes = Path(boot_data["secret_key_file"]).stat().st_size
        require(key_bytes == 32 and digest(runtime_file) == boot_data["runtime_manifest"]["sha256"] and
                runtime_file.stat().st_size == boot_data["runtime_manifest"]["bytes"], "boot pins differ")
        self.passed({"runtime_sha256": digest(runtime_file), "key_bytes": key_bytes,
                     "publication": self.initial_ref,
                     "input": "supplied protected bundle" if self.boot_input else "owned harness fixture bundle",
                     "judge": "supplied enrollment" if self.boot_input else "inert fixture; no model request"})
        namespace = provision.evidence_root("lb-v2-serve-ns-")
        self.receipts.append((namespace, "namespace"))
        for mode in ("install", "check"):
            self.current = "namespace." + mode
            stdout = self.command("namespace-" + mode,
                ["bash", str(self.stage / "scripts/v2-admin/namespace.sh"), "--" + mode,
                 "--evidence", str(namespace)], seconds=900, clean=True)
            marker = b"PASS: unprivileged bwrap " + b"namespace prerequisites"
            require(any(line.startswith(marker) for line in stdout.splitlines()),
                    "missing namespace pass marker")
            receipts = sorted(namespace.glob("*/result.json"), key=lambda path: path.stat().st_mtime_ns)
            require(len(receipts) == (1 if mode == "install" else 2), "namespace receipt count differs")
            observed = json.loads(receipts[-1].read_bytes())
            require(observed.get("ready") is True and observed.get("exit_code") == 0 and
                    observed.get("switches_unchanged") is True and observed.get("mode") == mode,
                    "namespace receipt failed")
            self.passed(observed)
        self.current = "admin.install"
        if self.egress_anthropic:
            for tool in ("ip", "nft"):
                require(shutil.which(tool) is not None, "egress requires installed iproute2 and nftables")
            forwarding = Path("/proc/sys/net/ipv4/ip_forward")
            self.egress_forward = forwarding.read_bytes()
            if self.egress_forward.strip() != b"1":
                forwarding.write_bytes(b"1\n")
            require(forwarding.read_bytes().strip() == b"1", "IPv4 forwarding prerequisite did not hold")
        # admin boot.py refuses any shared-writable ancestor of its evidence, sticky /var/tmp included
        install_root = provision.evidence_root("lb-v2-serve-install-", "/opt")
        install = install_root / "run"
        self.receipts.append((install_root, "admin-install"))
        raw_result = self.command("admin-install",
            ["bash", str(self.stage / "scripts/v2-admin/install.sh"), "--install",
             "--config", self.config, "--binary", str(binary), "--manifest", str(manifest),
             "--boot", str(boot), "--evidence", str(install)], seconds=180, clean=True, expected=None)
        validation = self.installation_validation(install)
        self.rows[self.current]["observed"].update({"executed": True, "exit_code": self.last["exit_code"],
                                                    "initial_validation": validation})
        require(self.last["exit_code"] == 0, "administrator installation failed; retain exact installer and native validation evidence")
        result = self.decode_document(raw_result)
        require(result.get("verified") is True and
                result.get("publication") == ("pending" if self.initial is not None else "absent"),
                "admin installation or publication staging is not verified")
        require(self.initial is None or (validation.get("retained") is True and
                validation.get("exit_code") == 0 and validation.get("matches_inputs") is True),
                "administrator installation lacks its actual matching native initial validation")
        self.passed(dict(result, initial_validation=validation))
        self.current = "admin.check"
        result = json.loads(self.command("admin-check",
            ["bash", str(self.stage / "scripts/v2-admin/install.sh"), "--check",
             "--config", self.config], clean=True))
        require(result.get("verified") is True and result.get("changed") is False,
                "read-only admin check failed")
        self.passed(result)
        self.current = "installation"
        installation = Path(result["installation"])
        self.installation_file = installation
        self.installed = json.loads(installation.read_bytes())
        self.binary = Path("/usr/lib/laneboss-v2") / version["version"] / "laneboss"
        require(digest(self.binary) == digest(binary), "installed artifact differs")
        self.socket = Path(self.installed["socket"])
        require(self.socket == provision.installed_socket_path(self.config) and not self.socket.exists() and
                not self.socket.is_symlink(), "socket path is not fresh")
        self.admin = json.loads((Path("/etc/laneboss-v2/admin") / (self.config + ".json")).read_bytes())
        require(self.installed["service_uid"] == self.admin["service"]["uid"], "service UID differs")
        if self.initial is not None:
            runtime_root = self.binary.parent / "runtime" / self.config
            require(self.installed.get("runtime_manifest") == self.initial["runtime"] and
                    self.installed.get("launch_enrollment") == self.initial["launch_enrollment"] and
                    self.installed.get("admin_enrollment", {}).get("origin") == boot_data["admin_enrollment"]["origin"] and
                    self.installed["admin_enrollment"].get("rp_id") == boot_data["admin_enrollment"]["rp_id"] and
                    provision.read_protected(runtime_root / "initial.json", mode=0o444) ==
                    (self.root / "initial-inputs/initial.json").read_bytes(),
                    "installed publication or enrollment differs from supplied boot inputs")
        unit = Path("/etc/systemd/system") / ("laneboss-service@" + self.config + ".service")
        unit_bytes = unit.read_bytes()
        require(("--installation " + str(installation)).encode() in unit_bytes,
                "unit does not consume installed boot")
        self.keep("service-unit.input", unit_bytes)
        self.keep("installation.input.json", installation.read_bytes())
        self.passed({"binary_sha256": digest(self.binary), "service_uid": self.admin["service"]["uid"]})
        self.current = "fixture.enrollment"
        runtime_root = self.binary.parent / "runtime" / self.config
        enrolled = json.loads((runtime_root / "manifest.json").read_bytes())
        roots = {row["id"]: Path(row["path"]) for row in json.loads((runtime_root / "roots.json").read_bytes())}
        agent_objects = [obj for obj in enrolled["objects"] if obj["role"] == "serve-fixture-agent"]
        require(len(agent_objects) == 1, "fixture was not installed through admin")
        obj = agent_objects[0]
        provision.protected(roots[obj["root_id"]])
        actual = roots[obj["root_id"]] / obj["relative_path"]
        require(digest(actual) == self.agent["sha256"] == obj["content"]["sha256"] and
                actual.stat().st_size == obj["content"]["bytes"] and
                stat.S_IMODE(actual.stat().st_mode) == 0o555, "installed fixture bytes differ")
        self.passed({"runtime_manifest": digest(runtime_root / "manifest.json"),
                     "agent_sha256": digest(actual), "vendor_stood_in": True})
        self.current = "serve"
        if self.api_key_canary is not None:
            self.api_key_canary.start(self.config, self.admin["service"]["uid"], self.binary)
        helper_unit = "laneboss-helper@" + self.config + ".service"
        helper_fragment = provision.read_protected(Path("/etc/systemd/system") / helper_unit, 65536, mode=0o644)
        self.keep("helper-unit.input", helper_fragment)
        template = (self.stage / "packaging/v2/linux/laneboss-helper.service.in").read_bytes()
        expected_helper = template.replace(b"@BINARY@", str(self.binary).encode()).replace(
            b"@SERVICE@", self.admin["service"]["name"].encode()).replace(b"@INSTALLATION@", str(self.installation_file).encode())
        helper_sources = self.command("helper-unit-sources", ["systemctl", "cat", helper_unit], clean=True)
        helper_sources_file = self.last["stdout"]
        helper_version = self.command("helper-systemd-version", ["systemctl", "--version"], clean=True)
        helper_version_file = self.last["stdout"]
        helper_shown = self.command("helper-unit-policy", ["systemctl", "show", helper_unit,
            "--all", "--property=" + ",".join(provision.HELPER_PROPERTIES)], clean=True)
        helper_policy_file = self.last["stdout"]
        helper_policy = {"facts": provision.helper_policy_facts(expected_helper, helper_fragment, helper_shown),
                         "sources": helper_sources_file, "sources_sha256": provision.sha(helper_sources),
                         "systemd_version": helper_version_file, "systemd_version_sha256": provision.sha(helper_version),
                         "properties": helper_policy_file, "properties_sha256": provision.sha(helper_shown)}
        self.rows[self.current]["observed"]["helper_policy"] = helper_policy
        for role in ("helper", "service"):
            unit = "laneboss-" + role + "@" + self.config + ".service"
            self.units.append(unit)
            self.command("start-" + role, ["systemctl", "start", unit], clean=True)
            self.command("active-" + role, ["systemctl", "is-active", "--quiet", unit], clean=True)
        deadline = time.monotonic() + 30
        while not self.socket.exists():
            require(time.monotonic() < deadline, "installed socket startup deadline")
            time.sleep(0.1)
        require(stat.S_ISSOCK(self.socket.stat().st_mode), "installed socket absent")
        pid = int(self.command("service-pid",
            ["systemctl", "show", "--value", "-p", "MainPID", self.units[-1]], clean=True).strip())
        require(pid > 1 and digest(Path("/proc") / str(pid) / "exe") == digest(self.binary),
                "unit is not running installed bytes")
        status = (Path("/proc") / str(pid) / "status").read_text().splitlines()
        uids = [line.split()[1:] for line in status if line.startswith("Uid:")]
        require(len(uids) == 1 and all(int(uid) == self.admin["service"]["uid"] for uid in uids[0]),
                "service does not use dedicated UID")
        self.passed({"pid": pid, "installed_binary": True, "dedicated_uid": True, "helper_policy": helper_policy})
        self.current = "health"
        health = self.checked_cli("health", ["health"])
        require(health.get("protocol") == version["api_protocol"] and
                health.get("artifact_sha256") == digest(self.binary), "socket health identity differs")
        capabilities = {row["name"]: row["available"] for row in health["capabilities"]}
        require(capabilities.get("installed-transport") is True and
                capabilities.get("registered-methods") is True, "health lacks observed host capability")
        self.passed(health)
        # The existing UID-only canary remains supporting evidence. It does
        # not credit the required direct-open row for a real launched lane.
        self.current = "uid.direct-open"
        self.uid_direct_open()

    def run(self):
        self.install()
        self.prepare_human()
        self.human.enroll()
        self.publish_initial()
        self.reconcile_canary_spend()
        if self.suite == "lifecycle":
            flow.run(self, require, Failed, Blocked)
            if self.item_module is not None:
                self.current = "item." + self.item_case + ".prepare"
                prepared = self.item_module.prepare(self, require, Failed, Blocked)
                self.passed({"prepared": True, "binding_file": str(prepared["binding_file"])})
                self.current = "item." + self.item_case + ".run"
                self.item_result = items.run(self, self.item_case, prepared)
                self.current = "item." + self.item_case + ".run"
                self.passed(self.item_result)
                self.current = "item." + self.item_case + ".collection"
                self.passed(dict(self.item_result["collection"], entry=self.item_result["entry_collection"]))
            return
        operation = self.launch()
        self.await_plan(operation)
        self.collect_agent(operation)
        self.current = "state.drop-reply"
        raise Blocked("lost socket reply control absent")

    def capture_journal(self, unit):
        role = "helper" if unit.startswith("laneboss-helper@") else "service"
        target = self.failed_step or "cleanup"
        record = {"role": role, "result": "failed", "exit_code": None, "lines": None,
                  "bytes": None, "stdout": None, "stderr": None}
        self.rows[target]["observed"].setdefault("unit_journals", []).append(record)
        try:
            journal = self.command("journal-" + role, ["journalctl", "--no-pager", "--output", "cat",
                "_SYSTEMD_UNIT=" + unit, "+", "UNIT=" + unit], clean=True, expected=None)
        finally:
            if self.last and self.last["label"] == "journal-" + role:
                record.update({name: self.last[name] for name in ("exit_code", "stdout", "stderr", "elapsed_ms")})
        record.update({"bytes": len(journal), "lines": len(journal.splitlines()), "sha256": provision.sha(journal),
            "result": "failed" if self.last["exit_code"] != 0 else "captured" if journal else "empty"})
        require(self.last["exit_code"] == 0, "journal capture failed; retain its stdout, stderr and exit")
        require((self.root / self.last["stdout"]).read_bytes() == journal,
                "retained unit journal differs from captured bytes")
        refusals, unparsed, timings, invalid_timings, helper_caps = [], [], [], [], []
        for number, line in enumerate(journal.splitlines(), 1):
            if line.lstrip().startswith(b"{"):
                try:
                    value = agent_evidence.document(line)
                except ValueError:
                    unparsed.append(number)
                else:
                    if value.get("stage") in ("helper.before_accounts", "helper.after_accounts"):
                        require(role == "helper", "helper capability observation came from another unit")
                        try:
                            helper_caps.append({"line": number, **provision.helper_capability_record(value)})
                        except ValueError:
                            raise Failed("helper capability observation has an invalid field or verdict") from None
                    if isinstance(value.get("stage"), str) and value["stage"].startswith("initial_publish."):
                        if (set(value) != {"stage", "elapsed_ms"} or value["stage"] not in summary.INITIAL_STAGES or
                                type(value["elapsed_ms"]) is not int or value["elapsed_ms"] < 0 or role != "service"):
                            invalid_timings.append(number)
                        else:
                            timings.append({"line": number, **value})
                    if value.get("code") and value.get("owner"):
                        refusals.append({"line": number, "error": value})
        if refusals:
            self.rows[target]["observed"].setdefault("journal_refusals", []).append({
                "unit": unit, "role": role, "refusals": refusals, "command": self.last})
        if helper_caps:
            self.rows[target]["observed"].setdefault("helper_capability_observations", []).extend(helper_caps)
        if unparsed:
            self.rows[target]["observed"].setdefault("unparsed_journal_json", []).append({
                "unit": unit, "lines": unparsed, "command": self.last})
        if timings or invalid_timings:
            self.rows[target]["observed"].setdefault("initial_publish_timings", []).append({
                "role": role, "stdout": self.last["stdout"], "sha256": provision.sha(journal),
                "records": timings, "invalid_lines": invalid_timings})
        require(not invalid_timings, "initial publication timing has an invalid stage, value or extra field")
        publication = self.rows["admin.publish"]
        attempted = publication["result"] == "pass" or "publication_input" in publication["observed"]
        if role == "service" and attempted:
            stages = {row["stage"] for row in timings}
            require({"initial_publish.native_context", "initial_publish.total"} <= stages,
                    "initial publication stage timing is missing from retained service journal")
            if publication["result"] == "pass":
                require({"initial_publish." + stage for stage in (
                    "protected_read", "load_validate", "bundle_validate", "object_hashes", "policy_validate", "template_validate", "revalidate",
                    "plan", "seal", "commit", "read_object", "read_back")} <= stages,
                    "successful initial publication lacks retained stage timing")

    def cleanup(self):
        problems = []
        if self.item_module is not None:
            try:
                problems.extend(self.item_module.abort(self, require, Failed))
            except (OSError, ValueError, KeyError, Failed) as error:
                problems.append({"item_cleanup_error": str(error)})
        if self.suite == "lifecycle":
            try:
                problems.extend(flow.stop_owned(self, require, Failed))
            except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError, Failed) as error:
                problems.append({"lane_cleanup_error": str(error), "step": self.current})
        if self.active is not None and self.active.poll() is None:
            self.active.terminate()
            try:
                self.active.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.cleanup_ok = False
                self.active.kill()
                self.active.wait(timeout=10)
        for unit in reversed(self.units):
            try:
                self.capture_journal(unit)
            except (Failed, OSError, subprocess.SubprocessError) as error:
                problems.append(str(error))
        # Capture both journals before either unit is stopped. Collection is
        # required even if a journal query failed; that failure stays recorded.
        for unit in reversed(self.units):
            try:
                self.command("stop-unit", ["systemctl", "stop", unit], clean=True)
                pid = self.command("stopped-pid",
                    ["systemctl", "show", "--value", "-p", "MainPID", unit], clean=True)
                require(int(pid.strip()) == 0, "unit retained its main process")
                if unit.startswith("laneboss-service@"):
                    status = self.command("stopped-status",
                        ["systemctl", "show", "--value", "-p", "ExecMainStatus", unit], clean=True)
                    require(int(status.strip()) == 0, "requested service stop did not exit successfully")
            except (Failed, OSError, ValueError, subprocess.SubprocessError) as error:
                problems.append(str(error))
        if self.reservation is not None:
            self.reservation.close()
        if self.egress_forward is not None:
            try:
                forwarding = Path("/proc/sys/net/ipv4/ip_forward")
                forwarding.write_bytes(self.egress_forward)
                require(forwarding.read_bytes() == self.egress_forward, "forwarding restoration differs")
                self.egress_forward = None
            except (OSError, Failed) as error:
                problems.append(str(error))
        for source, name in self.receipts:
            target = self.root / name
            target.mkdir(mode=0o700)
            for path in source.rglob("*"):
                require(not path.is_symlink(), "linked root evidence")
                if path.is_file():
                    require(self.api_key_canary is None or path.name != "key-store.json",
                            "private credential store cannot be harvested")
                    destination = target / path.relative_to(source)
                    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    data = path.read_bytes()
                    retained = self.api_key_canary.retainable(data) if self.api_key_canary is not None else data
                    destination.write_bytes(retained)
                    require(destination.read_bytes() == retained, "receipt collection differs")
        if self.api_key_canary is not None:
            observation = self.api_key_canary.finish(self)
            if self.reply_mode == "fake-key":
                proofs = [record.get("vendor_proof", {}) for record in self.lane_records
                          if record["driver"] == "claudock-cli"]
                observation["vendor_proofs"] = proofs
                if len(proofs) != 1 or not all(flow.vendor_result_proven(proof) for proof in proofs):
                    problems.append(flow.AGENT_NOT_STARTED)
            self.rows["cleanup"]["observed"]["api_key_canary"] = observation
            if observation["source_error"] or observation["source_transfers"] == 0 or observation["lane_scans"] == 0:
                problems.append("API key canary source or stopped-lane measurement is incomplete")
            if any(row.get("unreadable") or row.get("key") or row.get("last8") for row in observation["places"]) or observation["evidence_withheld"]:
                problems.append("API key canary found exposure or an incomplete scan; inspect value-free observations")
        require(self.socket is None or not self.socket.exists(), "host retained its socket")
        self.current = "cleanup"
        if problems:
            self.rows["cleanup"]["observed"].update({"executed": True, "problems": problems})
            if flow.AGENT_NOT_STARTED in problems:
                raise Failed(flow.AGENT_NOT_STARTED)
            raise Failed("cleanup failed; retain its evidence")
        if self.cleanup_ok:
            observed = {"owned_units_stopped": True, "socket_collected": True,
                        "installation_retained": True, "collection": "dispose authorized test box"}
            for key in ("unit_journals", "journal_refusals", "unparsed_journal_json", "initial_publish_timings",
                        "helper_capability_observations", "api_key_canary"):
                if key in self.rows["cleanup"]["observed"]:
                    observed[key] = self.rows["cleanup"]["observed"][key]
            self.passed(observed)

    def report(self, failure):
        if self.api_key_canary is not None:
            failure = self.api_key_canary.redact(failure)
            self.rows = self.api_key_canary.redact(self.rows)
            self.item_result = self.api_key_canary.redact(self.item_result)
            # This is the complete harvested tree, including top-level report
            # inputs. Subsequent report writes use the same value-free guards.
            harvest = self.api_key_canary.scan("harvest", self.evidence)
            self.rows["cleanup"]["observed"]["harvest_scan"] = harvest
            if (harvest["key"] or harvest["last8"] or harvest["unreadable"] or
                    harvest["credential_file"] or self.api_key_canary.withheld):
                reason = "API key harvest contains credential material or an unreadable input"
                self.rows["cleanup"]["result"] = "fail"
                self.rows["cleanup"]["observed"]["harvest_error"] = reason
                failure = dict(failure, harvest_error=reason) if failure else {"check": "cleanup", "reason": reason}
        if failure is not None:
            # Cleanup cannot erase a failed step by reusing its observation row.
            self.rows[failure["check"]]["result"] = "fail"
            if failure.get("observed") is not None:
                retained = self.rows[failure["check"]]["observed"]
                restored = copy.deepcopy(failure["observed"])
                for key in ("journal_refusals", "unparsed_journal_json", "unit_journals", "initial_publish_timings",
                            "helper_capability_observations"):
                    if key in retained:
                        restored[key] = retained[key]
                self.rows[failure["check"]]["observed"] = restored
                failure["observed"] = copy.deepcopy(restored)
            observed = self.rows[failure["check"]]["observed"]
            actual = summary.errors(failure.get("observed", {}), journals=False) or summary.errors(observed, journals=False)
            if actual:
                failure["owner"], failure["code"] = actual[-1].get("owner"), actual[-1].get("code")
            else:
                failure["owner_request"] = observed.get("owner_request", summary.owners(failure["check"]))
        if failure is not None:
            for row in self.rows.values():
                if not row["observed"].get("executed", True):
                    row["observed"]["stopped_after"] = failure["check"]
                    if row["observed"].get("reason") == "prerequisite pending":
                        row["observed"]["reason"] = "stopped after " + failure["check"]
        references = []
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and not path.is_symlink():
                references.append({"path": str(path.relative_to(self.root)),
                                   "sha256": digest(path), "bytes": path.stat().st_size})
        # summary.txt is generated from this same object and added to the final
        # evidence manifest after writing it; no report-produced PASS is input.
        value = {"schema": "laneboss.serve-report.v2", "config": self.config,
                 "scope": self.scope, "required_checks": list(self.checks),
                 "reply_mode": self.reply_mode,
                 "presence": "simulated", "human_approval": "not_proven",
                 "authenticator_tag": "laneboss_e2e_authenticator",
                 "failure": failure, "checks": list(self.rows.values()),
                 "item_case": self.item_case, "item_result": self.item_result,
                 "manifest": str((self.root / "manifest.json").relative_to(self.evidence))}
        if self.api_key_canary is not None:
            value = self.api_key_canary.redact(value)
        temporary = self.evidence / "report.pending"
        temporary.write_bytes(encoded(value))
        temporary.replace(self.evidence / "report.json")
        passed, message = summary.describe(value)
        self.keep("summary.txt", (message + "\n").encode())
        references.append({"path": "summary.txt", "sha256": digest(self.root / "summary.txt"),
                           "bytes": (self.root / "summary.txt").stat().st_size})
        self.keep_json("manifest.json", references)
        print(message, file=sys.stdout if passed else sys.stderr)
        return passed


def interrupted(number, _frame):
    raise Failed("interrupted by signal " + str(number))


def record_failure(case, error, check=None):
    """A broken row must not prevent reporting the original harness fault."""
    check = case.current if check is None else check
    reason = str(error) if isinstance(error, (Blocked, Failed)) else "harness exception: " + type(error).__name__
    row = case.rows.setdefault(check, {"check": check, "result": "fail", "presence": presence(check),
                                       "observed": {"executed": False}})
    row["result"] = "fail"
    observed = row.setdefault("observed", {})
    rpc_check = check.startswith(("human.", "lane.", "state.")) and check != "human.enroll.attestation"
    executed = not isinstance(error, Blocked) and not (case.last and case.last.get("started") is False) and (
        not rpc_check or observed.get("rpc_executed", observed.get("executed", False)))
    # Unexpected exception arguments may contain private read bytes. Keep only
    # the class; typed gate failures retain their original refusal detail.
    observed.update({"executed": executed, "error": reason, "command": case.last})
    if case.failed_step is None:
        case.failed_step = check
    return {"check": check, "reason": reason, "command": case.last,
            "observed": copy.deepcopy(observed), "driver": case.human_prefix or None}


def arguments(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--source-snapshot", action="store_true",
                        help="consume an explicit source snapshot without Git metadata; retain its exact byte inventory")
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--launch-request", type=Path)
    parser.add_argument("--agent-output", type=Path)
    parser.add_argument("--root-grants", type=Path)
    parser.add_argument("--suite", choices=("lifecycle", "state"), default="lifecycle")
    parser.add_argument("--lane-inputs", type=Path)
    parser.add_argument("--config")
    parser.add_argument("--item-case", choices=("grants", "linux", "secrets", "lifecycle", "policy",
                        "messaging", "dashboard", "watchdog", "judge", "dirty"))
    parser.add_argument("--boot", type=Path)
    parser.add_argument("--real-claudock", action="store_true",
                        help="enroll real pinned Claudock/Claude for the Claudock lane; no credentials")
    key_source = parser.add_mutually_exclusive_group()
    key_source.add_argument("--canary-api-key", action="store_true",
                        help="with --real-claudock --egress-anthropic, enroll an ephemeral fake API key and measure persistence")
    key_source.add_argument("--real-api-key-file", type=Path,
                        help="consume and unlink a root-owned 0400 key file; requires --real-claudock --egress-anthropic")
    parser.add_argument("--cleanup-native-control", action="store_true",
                        help="build the disposable missing-native-port control")
    parser.add_argument("--egress-anthropic", action="store_true",
                        help="enroll api.anthropic.com:443 and grant it only to the Claudock lane")
    args = parser.parse_args(argv)
    require(args.source.is_absolute() and args.evidence.is_absolute(),
            "absolute paths required")
    require((args.boot is None) == (args.config is None) and
            (args.config is None or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", args.config)),
            "--boot and its explicit --config must be supplied together")
    require(args.boot is None or args.boot.is_absolute(), "--boot requires an absolute protected file")
    require(not args.real_claudock or (args.suite == "lifecycle" and args.boot is None),
            "--real-claudock requires the generated lifecycle bundle")
    live_linux = args.item_case == "linux" and args.real_api_key_file is not None
    require(not args.item_case or (args.suite == "lifecycle" and args.boot is None and
            (live_linux or not args.real_claudock and not args.egress_anthropic) and not args.cleanup_native_control),
            "item cases require their generated credential-free lifecycle bundle")
    require(not args.canary_api_key or (args.real_claudock and args.egress_anthropic),
            "--canary-api-key requires --real-claudock and --egress-anthropic")
    require(args.real_api_key_file is None or (args.real_api_key_file.is_absolute() and
            args.real_claudock and args.egress_anthropic),
            "--real-api-key-file requires an absolute file, --real-claudock and --egress-anthropic")
    return args


def main():
    args = arguments()
    require(not args.evidence.exists(), "preserve existing evidence")
    os.umask(0o077)
    args.evidence.mkdir(mode=0o700, parents=True)
    case = Case(args.source.resolve(strict=True), args.evidence.resolve(strict=True),
                args.launch_request, args.agent_output, args.root_grants, args.suite, args.lane_inputs,
                args.config, args.boot, args.cleanup_native_control,
                egress_anthropic=args.egress_anthropic, real_claudock=args.real_claudock,
                item_case=args.item_case, canary_api_key=args.canary_api_key,
                real_api_key_file=args.real_api_key_file, source_snapshot=args.source_snapshot)
    failure = None
    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, interrupted)
    try:
        case.run()
    except Exception as error:
        failure = record_failure(case, error)
    finally:
        try:
            case.current = "cleanup"
            case.cleanup()
        except Exception as error:
            cleanup_failure = record_failure(case, error, "cleanup")
            failure = dict(failure, cleanup_error=cleanup_failure["reason"]) if failure else cleanup_failure
    passed = case.report(failure)
    return 0 if passed and failure is None else 1


if __name__ == "__main__":
    sys.exit(main())
