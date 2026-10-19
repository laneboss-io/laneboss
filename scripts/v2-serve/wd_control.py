"""Protected fixed-action controller; never an RPC on a product endpoint.

The serve owner binds read_blob and native_probe from its installed checkpoint.
native_probe must start the pinned probe through the real helper and return its
PID, UID, cgroup, job_id, primary bytes and measured wait(). No command, unit,
PID, path, executable or claimed survivor count comes from a case request.
"""

import os
from pathlib import Path
import re
import select
import socket
import stat
import struct
import subprocess
import time

from wd_usage import Gate, closed, digest, need, parse, private, read_frame, save, send_frame, wire


def process(pid):
    need(type(pid) is int and pid > 1, "controller target has no process identity")
    root = Path("/proc") / str(pid)
    raw = (root / "stat").read_bytes()
    fields = raw[raw.rfind(b")") + 2:].split()
    status = (root / "status").read_text().splitlines()
    uids = [line.split()[1:] for line in status if line.startswith("Uid:")]
    need(len(fields) >= 20 and len(uids) == 1 and len(set(uids[0])) == 1, "controller process identity is ambiguous")
    return {"pid": pid, "generation": int(fields[19]), "uid": int(uids[0][0]),
            "mount_ns": (root / "ns/mnt").stat().st_ino, "pid_ns": (root / "ns/pid").stat().st_ino}


class Evidence:
    def __init__(self, root, case_uid):
        self.root, self.case_uid, self.serial = Path(root), case_uid, 0
        info = self.root.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == case_uid and stat.S_IMODE(info.st_mode) == 0o700,
             "controller evidence root is not the enrolled private case directory")

    def keep(self, name, data):
        self.serial += 1
        path = self.root / (f"control-{self.serial:05d}-" + name)
        save(path, data)
        if os.getuid() == 0:
            os.chown(path, self.case_uid, -1)
        need(private(path, {0, self.case_uid, os.getuid()}, allow_empty=True) == data, "controller evidence readback differs")
        return {"path": path.name, "sha256": digest(data), "bytes": len(data)}


class FixedController:
    def __init__(self, context, enrollment, *, read_blob, native_probe, evidence, file_observer=None):
        closed(enrollment, "schema service_id unit canary_id file signal_pid service_uid")
        need(enrollment["schema"] == "laneboss.wd-controller.v1" and context["case_id"] == "watchdog"
             and enrollment["unit"] == "laneboss-service@" + context["config"] + ".service"
             and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", enrollment["service_id"])
             and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", enrollment["canary_id"]), "controller enrollment differs from its fixed configuration")
        need(os.getuid() == 0, "fixed service controller requires its disposable root installation")
        self.context, self.enrollment = context, enrollment
        self.read_blob, self.native_probe, self.evidence = read_blob, native_probe, evidence
        self.file_observer = file_observer
        self.used = set()

    def command(self, args):
        result = subprocess.run(["/usr/bin/systemctl", *args], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=45, check=False)
        refs = [self.evidence.keep("systemctl.stdout", result.stdout),
                self.evidence.keep("systemctl.stderr", result.stderr),
                self.evidence.keep("systemctl.exit", wire({"exit_code": result.returncode}))]
        need(result.returncode == 0, "fixed systemd action failed; retain its actual output")
        return result.stdout, refs

    def service(self):
        data, refs = self.command(["show", "--property=MainPID", "--value", self.enrollment["unit"]])
        need(re.fullmatch(rb"[1-9][0-9]*\n?", data), "service has no measured main process")
        identity = process(int(data))
        need(identity["uid"] == self.enrollment["service_uid"], "service PID belongs to another principal")
        refs.append(self.evidence.keep("service-process.json", wire(identity)))
        return identity, refs

    def restart(self, params):
        closed(params, "service_id expected_generation")
        need(params["service_id"] == self.enrollment["service_id"] and type(params["expected_generation"]) is int,
             "restart selector is not enrolled")
        old, refs = self.service()
        need(old["generation"] == params["expected_generation"], "restart selection is stale")
        fd = os.pidfd_open(old["pid"], 0)
        try:
            need(process(old["pid"]) == old, "old service process changed before restart")
            _, outputs = self.command(["restart", self.enrollment["unit"]])
            refs.extend(outputs)
            poller = select.poll()
            poller.register(fd, select.POLLIN)
            exited = bool(poller.poll(45000))
            need(exited, "old service process did not actually exit")
        finally:
            os.close(fd)
        current, outputs = self.service()
        refs.extend(outputs)
        need(current["generation"] > old["generation"] and current != old, "restart has no newer kernel service generation")
        return {"service_id": params["service_id"], "previous_generation": old["generation"],
                "current_generation": current["generation"], "old_pid": old["pid"], "new_pid": current["pid"],
                "old_exited": exited, "evidence": refs}

    def canary(self, params):
        closed(params, "target canary_id input")
        closed(params["target"], "life_id run")
        closed(params["input"], "id sha256 bytes class")
        need(params["canary_id"] == self.enrollment["canary_id"] and params["input"]["class"] == "task",
             "canary selector or committed input class differs")
        if not callable(self.read_blob) or not callable(self.native_probe):
            raise Gate("fixed confined probe requires its installed native launcher and exact blob reader", "lb-v2-admin")
        source = self.read_blob(params["input"])
        need(len(source) == params["input"]["bytes"] and digest(source) == params["input"]["sha256"], "canary input bytes differ")
        task = parse(source)
        closed(task, "schema target nonce")
        need(task["schema"] == "laneboss.watchdog-probe.v2" and task["target"] == params["target"]
             and re.fullmatch(r"[a-f0-9]{32}", task["nonce"]), "canary task does not select its actual target")
        target_file = Path(self.file_observer or self.enrollment["file"])
        before = private(target_file, {0})
        inode = target_file.lstat().st_ino
        target_process = process(self.enrollment["signal_pid"])
        refs = [self.evidence.keep("probe-input.json", source),
                self.evidence.keep("targets-before.json", wire({"file_sha256": digest(before), "file_inode": inode, "process": target_process}))]
        handle = self.native_probe(params["target"], source, params["canary_id"])
        measured = process(handle.pid)
        host = process(os.getpid())
        need(measured["uid"] == handle.uid and measured["uid"] not in {0, self.evidence.case_uid}
             and measured["mount_ns"] != host["mount_ns"] and measured["pid_ns"] != host["pid_ns"],
             "probe did not run in its separately confined kernel identity")
        group = Path(handle.cgroup)
        need(group.is_absolute() and group.resolve(strict=True).is_relative_to(Path("/sys/fs/cgroup"))
             and handle.pid in [int(pid) for pid in (group / "cgroup.procs").read_text().split()],
             "probe process is not in its native enrolled containment")
        refs.append(self.evidence.keep("probe-process.json", wire(measured)))
        descriptor = os.pidfd_open(handle.pid, 0)
        try:
            need(process(handle.pid) == measured, "confined probe changed before its observed wait")
            code = handle.wait(timeout=30)
            poller = select.poll()
            poller.register(descriptor, select.POLLIN)
            need(bool(poller.poll(30000)), "confined probe's original kernel lifetime did not exit")
        finally:
            os.close(descriptor)
        members = []
        if group.exists():
            for path in (group / "cgroup.procs", *group.rglob("*/cgroup.procs")):
                members.extend(int(pid) for pid in path.read_text().split())
        refs.append(self.evidence.keep("probe-cgroup.json", wire({"present": group.exists(), "members": members})))
        need(code == 0 and not members, "confined probe did not exit or left actual survivors")
        data = handle.primary()
        refs.append(self.evidence.keep("probe-primary.jsonl", data))
        records = [parse(line) for line in data.splitlines() if line.strip()]
        reports = [r for r in records if r.get("schema") == "laneboss.watchdog-probe-result.v1"]
        need(len(reports) == 1, "confined probe lacks one measured result")
        report, = reports
        closed(report, "schema target nonce probes")
        need(report["target"] == params["target"] and report["nonce"] == task["nonce"], "confined report belongs to another input")
        unchanged_file = target_file.lstat().st_ino == inode and private(target_file, {0}) == before
        unchanged_process = process(target_process["pid"]) == target_process
        probes = report["probes"]
        need(len(probes) == 3 and {p["probe"] for p in probes} == {"forge", "file", "signal"}, "probe result inventory differs")
        checks = []
        for probe in probes:
            kind = probe["probe"]
            closed(probe, "probe attempted errno code target" + (" sha256" if kind == "file" else ""))
            target = self.enrollment["file"] if kind == "file" else self.enrollment["signal_pid"] if kind == "signal" else "watchdog.swapped"
            denied = probe["code"] in {"forbidden", "invalid_request", "unauthenticated"} if kind == "forge" else probe["errno"] in ({1, 13, 30} if kind == "file" else {1, 3, 13})
            need(probe["attempted"] is True and probe["target"] == target and denied,
                 "probe was not denied against its exact existing target")
            if kind == "file":
                need(probe["sha256"] == digest(before), "probe did not read its independently enrolled existing target")
            unchanged = unchanged_file if kind == "file" else unchanged_process if kind == "signal" else unchanged_file and unchanged_process
            checks.append({"probe": kind, "attempted": probe["attempted"], "confined": measured["uid"] == handle.uid,
                           "target_present": inode > 0 if kind == "file" else target_process["pid"] > 1,
                           "denied": denied, "unchanged": unchanged})
        need(all(c["unchanged"] for c in checks), "canary changed a protected target")
        refs.append(self.evidence.keep("canary-report.json", wire({"schema": "laneboss.watchdog-canary.v2",
                    "target": params["target"], "nonce": task["nonce"], "checks": checks})))
        return {"job_id": handle.job_id, "target": params["target"], "observed_exit": code,
                "containment_state": "exited", "survivors": len(members), "input_sha256": digest(source), "evidence": refs}

    def dispatch(self, peer_uid, request):
        closed(request, "schema case_id phase mutation_id binary_sha256 request_id nonce action params")
        need(peer_uid == self.evidence.case_uid and request["schema"] == "laneboss.e2e-control.v2"
             and all(request[key] == self.context[key] for key in ("case_id", "phase", "mutation_id", "binary_sha256")),
             "controller request differs from its enrolled case or kernel principal")
        need(re.fullmatch(r"[a-f0-9]{32}", request["request_id"]) and re.fullmatch(r"[a-f0-9]{32}", request["nonce"])
             and request["request_id"] not in self.used, "controller correlation is missing or replayed")
        self.used.add(request["request_id"])
        self.evidence.keep("request.json", wire(request))
        reply = {"schema": "laneboss.e2e-control-reply.v2", **{k: request[k] for k in ("case_id", "request_id", "nonce", "binary_sha256")}}
        try:
            need(request["action"] in {"restart_service", "run_confined_canary"}, "controller action is not fixed and enrolled")
            result = self.restart(request["params"]) if request["action"] == "restart_service" else self.canary(request["params"])
            reply.update(action=request["action"], result=result)
        except (Gate, OSError, ValueError, KeyError, subprocess.SubprocessError) as failure:
            ref = self.evidence.keep("action-failure.json", wire({"owner": getattr(failure, "owner", "lb-v2-serve"),
                "code": getattr(failure, "code", "integrity"), "message": str(failure)}))
            reply["error"] = {"code": getattr(failure, "code", "integrity"), "message": str(failure),
                              "instead": "Retain the exact controller evidence and repair the named native prerequisite.", "evidence": [ref]}
        self.evidence.keep("reply.json", wire(reply))
        return reply

    def serve_one(self, listener):
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(60)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            peer = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            send_frame(connection, self.dispatch(peer[1], read_frame(connection, peer)))
