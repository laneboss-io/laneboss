"""S1-S6: real Unix peers and separate OS accounts on a disposable Linux box.

This root-owned fixture is a named test-kit step. It creates a configuration
group and two credential-free accounts with groupadd/useradd. The daemon itself
always runs unprivileged as the service account. No fixture is a ticket verifier:
root seeds a protected journal to stand in for part 2's already verified session.
All accounts and evidence remain on the disposable box for collection.
"""

import datetime
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import uuid


UNKNOWN = "refused: the caller has no recorded identity"
SESSION_ROUTE = ("Instead: run laneboss start --role ROLE from the persistent "
                 "session that will issue these commands.")
START_ROUTE = ("Instead: register with laneboss start --role ROLE from the persistent "
               "session that will issue these commands, or run this command "
               "from a terminal as the human.")
MUTANTS = {
    "identityd-trust-pid": ("test_s1_kernel_peer", "caller-sent pid replaced kernel peer identity"),
    "identityd-public-store": ("test_s2_separate_account", "caller read the service-owned record"),
    "identityd-append-actor": ("test_s3_lane_actor", "caller-sent actor replaced the identified lane"),
    "identityd-allow-unknown": ("test_s4_unknown_refused", "an unidentified peer appended a record"),
    "identityd-no-start": ("test_s5_start_time", "a wrong process start time was accepted"),
    "identityd-ignore-version": ("test_s6_protocol_status", "an unsupported protocol version was accepted"),
    "identityd-lane-owner": ("test_s7_owner", "an L4 lane recorded its own next run"),
    "identityd-live-run": ("test_s7_live", "a live lane run was replaced"),
    "identityd-forget-runs": ("test_s7_history", "an older live run became its supervisor"),
    "identityd-overlap-root": ("test_s7_roots", "a live session anchor was relabelled"),
    "identityd-no-detach": ("test_s7_detach", "the launcher left the lane in its session tree"),
    "identityd-field-case": ("test_s8_case", "a case alias changed the operation"),
    "identityd-foreign-lane": ("test_s9_scope", "a lane recorded another lane's report"),
    "identityd-any-event": ("test_s10_events", "an unlisted event kind was accepted"),
    "identityd-peer-slots": ("test_s11_slots", "one peer exceeded its connection cap"),
    "identityd-large-payload": ("test_s12_size", "an oversized encoded payload was accepted"),
    "identityd-wide-detach": ("test_s13_above_anchor", "an above-anchor subreaper refused an ordinary launch"),
    "identityd-uid-setting": ("test_s14_uid_setting", "the configured UID connection limit was ignored"),
    "identityd-short-detach": ("test_s15_outer_session", "an orphan inherited an enclosing recorded session"),
}


def kernel_process(pid):
    prefix = Path("/proc") / str(pid)
    data = (prefix / "stat").read_text(encoding="utf-8")
    fields = data[data.rindex(")") + 1:].split()
    if fields[0] in ("Z", "X"):
        raise ProcessLookupError("the fixture process is no longer live")
    values = {}
    for line in (prefix / "status").read_text(encoding="utf-8").splitlines():
        columns = line.split()
        if columns and columns[0] in ("Uid:", "Gid:"):
            values[columns[0]] = int(columns[2])
    boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    return {"pid": pid, "uid": values["Uid:"], "gid": values["Gid:"],
            "start": boot + ":" + fields[19]}


def kernel_ancestry(pid):
    result = []
    seen = set()
    while pid > 1:
        if pid in seen or len(result) >= 128:
            raise RuntimeError("invalid fixture ancestry")
        seen.add(pid)
        result.append(kernel_process(pid))
        data = (Path("/proc") / str(pid) / "stat").read_text()
        pid = int(data[data.rindex(")") + 1:].split()[1])
    return result


def subreaper(enabled):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, int(enabled), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER failed")
    observed = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(observed), 0, 0, 0) != 0 or bool(observed.value) != enabled:
        raise RuntimeError("the kernel did not retain the requested subreaper setting")
    return bool(observed.value)


def publish_json(path, value):
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex[:8])
    with temporary.open("x", encoding="utf-8") as output:
        output.write(json.dumps(value) + "\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def orphan_main(descriptor, parent_fd, directory, path):
    parent = kernel_process(os.getppid())
    before = {"process": kernel_process(os.getpid()), "parent": parent,
              "who": exchange(path, {"laneboss_service": 1, "config": "identity", "op": "whoami"}),
              "append": exchange(path, {"laneboss_service": 1, "config": "identity", "op": "append",
                                        "type": "report", "payload": {"text": "live child canary"}})}
    publish_json(directory / "orphan-ready.json", before)
    print(json.dumps(before), flush=True)
    ready, _, _ = select.select([descriptor], [], [], 30)
    if not ready or os.read(descriptor, 1) != b"":
        raise RuntimeError("the lane root did not close the orphan gate")
    os.close(descriptor)
    # EOF alone is not an exit proof: Python may close a pipe before its
    # process teardown. Bind to the parent's real kernel lifetime as well.
    poller = select.poll()
    poller.register(parent_fd, select.POLLIN)
    exited = poller.poll(30000)
    if (len(exited) != 1 or exited[0][0] != parent_fd or not exited[0][1] & select.POLLIN
            or exited[0][1] & (select.POLLERR | select.POLLNVAL)):
        raise RuntimeError("the orphan's parent pidfd did not prove exit")
    os.close(parent_fd)
    deadline = time.monotonic() + 15
    while os.getppid() == parent["pid"]:
        if time.monotonic() >= deadline:
            raise RuntimeError("the orphan was not reparented after its parent's exit")
        time.sleep(0.01)
    process = kernel_process(os.getpid())
    ancestry = kernel_ancestry(os.getpid())
    if parent in ancestry:
        raise RuntimeError("the orphan still has its exited parent in kernel ancestry")
    who = exchange(path, {"laneboss_service": 1, "config": "identity", "op": "whoami"})
    append = exchange(path, {"laneboss_service": 1, "config": "identity", "op": "append",
                             "type": "report", "payload": {"text": "orphan canary"}})
    publish_json(directory / "orphan.json", {"process": process, "parent": parent,
                                             "parent_pid": os.getppid(), "ancestry": ancestry,
                                             "parent_exit_events": [event for _, event in exited],
                                             "who": who, "append": append})


def detached_main(directory, path):
    read_gate, write_gate = os.pipe()
    parent_fd = os.pidfd_open(os.getpid())
    try:
        child = subprocess.Popen([sys.executable, "-I", __file__, "--orphan", str(read_gate), str(parent_fd),
                                  str(directory), path], pass_fds=(read_gate, parent_fd),
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=sys.stderr, text=True)
    finally:
        os.close(parent_fd)
    os.close(read_gate)
    orphan_ready = read_pipe(child.stdout)
    child.stdout.close()
    who = exchange(path, {"laneboss_service": 1, "config": "identity", "op": "whoami"})
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    build = subprocess.run([sys.executable, "-I", __file__, "--build", path],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True,
                           check=True, timeout=15)
    publish_json(directory / "detached.json", {"process": kernel_process(os.getpid()),
                                               "ancestry": kernel_ancestry(os.getpid()),
                                               "child_pid": child.pid, "who": who,
                                               "orphan_ready": orphan_ready, "build": json.loads(build.stdout)})
    # Keep the gate open until the kernel closes it at actual process exit.
    # The child also polls our pidfd before resolving its adopted ancestry.
    signal.pause()


def build_main(path, leaf=False):
    if not leaf:
        subreaper(True)
    who = exchange(path, {"laneboss_service": 1, "config": "identity", "op": "whoami"})
    report = exchange(path, {"laneboss_service": 1, "config": "identity", "op": "append",
                             "type": "report", "payload": {"text": uuid.uuid4().hex}})
    result = {"process": kernel_process(os.getpid()), "who": who, "report": report}
    if not leaf:
        child = subprocess.run([sys.executable, "-I", __file__, "--build-leaf", path],
                               stdin=subprocess.DEVNULL, capture_output=True, text=True,
                               check=True, timeout=10)
        result["child"] = json.loads(child.stdout)
    print(json.dumps(result), flush=True)


def send_and_read(connection, stream, data, half_close=False):
    # A cap refusal may already be queued, or may close the peer between this
    # readiness check and sendall. Both orders lead to the same bounded read.
    unsent = bool(data) and bool(select.select([connection], [], [], 0)[0])
    if data and not unsent:
        try:
            connection.sendall(data)
        except (BrokenPipeError, ConnectionResetError):
            unsent = True
    if half_close and not unsent:
        connection.shutdown(socket.SHUT_WR)
    line = stream.readline(128 * 1024 + 1)
    if not line.endswith(b"\n") or len(line) > 128 * 1024:
        raise RuntimeError("the service did not return one bounded JSON line")
    response = json.loads(line)
    if unsent and response["ok"]:
        raise RuntimeError("the service returned success without a complete request")
    return response


def exchange(path, request=None, raw=None, half_close=False):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(10)
        connection.connect(path)
        data = raw.encode("utf-8") if raw is not None else (json.dumps(request) + "\n").encode("utf-8")
        with connection.makefile("rb") as stream:
            return send_and_read(connection, stream, data, half_close)


def read_pipe(stream):
    ready, _, _ = select.select([stream], [], [], 15)
    if not ready:
        raise RuntimeError("the fixture process did not answer within its deadline")
    line = stream.readline()
    if not line:
        raise RuntimeError("the fixture process ended before answering")
    return json.loads(line)


def record_permissions(path):
    result = {}
    for action in ("read", "write", "create"):
        try:
            if action == "read":
                result[action] = Path(path).read_text(encoding="utf-8")
            elif action == "write":
                with open(path, "w", encoding="utf-8") as output:
                    output.write("caller wrote the canary\n")
                result[action] = "wrote"
            else:
                with open(str(Path(path).parent / "caller-forged.json"), "x", encoding="utf-8") as output:
                    output.write(json.dumps({"principal": "supervisor:impostor"}) + "\n")
                result[action] = "created"
        except PermissionError as error:
            if error.errno != errno.EACCES:
                raise
            result[action] = "permission-denied"
    return result


def controller_main():
    children = []
    launchers = []
    held = []
    print(json.dumps({"ready": True, "process": kernel_process(os.getpid())}), flush=True)
    try:
        for line in sys.stdin:
            command = json.loads(line)
            if command["op"] == "quit":
                return
            if command["op"] == "spawn":
                child = subprocess.Popen([sys.executable, "-I", __file__, "--controller"],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, text=True, start_new_session=True)
                children.append(child)
                result = read_pipe(child.stdout)
                result["child"] = len(children) - 1
            elif command["op"] == "stop":
                child = children[command["child"]]
                child.stdin.write('{"op":"quit"}\n')
                child.stdin.flush()
                output, error = child.communicate(timeout=10)
                if child.returncode != 0:
                    raise RuntimeError("a child controller failed: " + error)
                result = {"exit": child.returncode, "output": output}
            elif command["op"] == "child":
                child = children[command["child"]]
                child.stdin.write(json.dumps(command["command"]) + "\n")
                child.stdin.flush()
                result = read_pipe(child.stdout)
            elif command["op"] == "permissions":
                result = record_permissions(command["path"])
            elif command["op"] == "forge":
                path = Path(command["path"])
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("x", encoding="utf-8") as output:
                    output.write(json.dumps(command["record"]) + "\n")
                result = {"uid": path.stat().st_uid, "record": json.loads(path.read_text())}
            elif command["op"] == "subreaper":
                result = {"enabled": subreaper(command["enabled"])}
            elif command["op"] == "reap":
                pid, status = os.waitpid(command["pid"], 0)
                result = {"pid": pid, "exit": os.waitstatus_to_exitcode(status)}
            elif command["op"] == "launch":
                environment = {"PATH": os.defpath, "LANEBOSS_CONFIG": "identity"}
                if command.get("fault"):
                    environment["LANEBOSS_FAULTS"] = json.dumps(command["fault"])
                process = subprocess.Popen([command["driver"], "__test", "identityd-launch"],
                                           env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True)
                process.stdin.write(json.dumps(command["input"]) + "\n")
                process.stdin.flush()
                readable, _, _ = select.select([process.stdout], [], [], 35)
                if not readable:
                    os.kill(process.pid, signal.SIGKILL)
                    process.communicate(timeout=10)
                    raise RuntimeError("the launch handoff missed its deadline")
                line = process.stdout.readline()
                if line:
                    result = {"result": json.loads(line), "running": process.poll() is None,
                              "caller": kernel_process(process.pid), "launcher": len(launchers)}
                    launchers.append(process)
                else:
                    output, error = process.communicate(timeout=10)
                    result = {"exit": process.returncode, "output": output, "error": error}
            elif command["op"] == "release-launch":
                process = launchers[command["launcher"]]
                process.stdin.write("q")
                process.stdin.flush()
                output, error = process.communicate(timeout=10)
                if process.returncode != 0:
                    raise RuntimeError("the launch caller failed: " + error)
                result = {"exit": process.returncode, "output": output}
            elif command["op"] == "hold":
                connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                connection.settimeout(10)
                connection.connect(command["socket"])
                stream = connection.makefile("rb")
                data = (json.dumps({"laneboss_service": 1, "config": "identity", "op": "whoami"}) + "\n").encode()
                try:
                    response = send_and_read(connection, stream, data)
                except BaseException:
                    stream.close()
                    connection.close()
                    raise
                if response["ok"]:
                    held.append((connection, stream))
                else:
                    stream.close()
                    connection.close()
                result = response
            elif command["op"] == "refresh-slot":
                connection, stream = held[command["slot"]]
                data = (json.dumps({"laneboss_service": 1, "config": "identity", "op": "whoami"}) + "\n").encode()
                result = send_and_read(connection, stream, data)
            elif command["op"] == "release-slots":
                for connection, stream in held:
                    stream.close()
                    connection.close()
                held.clear()
                result = {"remaining": len(held)}
            elif command["op"] == "slot-status":
                result = {"held": len(held)}
            elif command["op"] == "request":
                result = {"self": kernel_process(os.getpid()),
                          "response": exchange(command["socket"], command.get("request"),
                                               command.get("raw"), command.get("half_close", False))}
            else:
                raise RuntimeError("invalid fixture operation")
            print(json.dumps(result), flush=True)
    finally:
        for connection, stream in held:
            stream.close()
            connection.close()
        for process in launchers:
            if process.poll() is None:
                process.stdin.write("q")
                process.stdin.flush()
                output, error = process.communicate(timeout=10)
                if process.returncode != 0:
                    raise RuntimeError("a launch caller failed: " + error)
        for child in children:
            if child.poll() is None:
                child.stdin.write('{"op":"quit"}\n')
                child.stdin.flush()
                _, error = child.communicate(timeout=10)
            else:
                error = ""
            if child.returncode != 0:
                raise RuntimeError("the child controller failed: " + error)


class IdentityServiceRows(unittest.TestCase):
    def setUp(self):
        self.assertEqual(sys.platform, "linux", "these rows require the disposable Linux box")
        self.assertEqual(os.geteuid(), 0, "invoke the sealed test kit's identityd rows step")
        binary = Path(os.environ.get("LANEBOSS_BIN", ""))
        self.assertTrue(binary.is_absolute() and binary.is_file() and os.access(binary, os.X_OK),
                        "LANEBOSS_BIN must name an already built binary")
        self.mutant = os.environ.get("LANEBOSS_IDENTITYD_MUTANT", "")
        self.assertTrue(not self.mutant or self.mutant in MUTANTS, "unknown identity service mutant")
        evidence = Path(os.environ["LANEBOSS_IDENTITYD_EVIDENCE"])
        self.assertTrue(evidence.is_absolute() and evidence.is_dir(), "the evidence directory must exist")
        self.directory = Path(tempfile.mkdtemp(prefix="lb-svc-core-row-", dir=evidence))
        self.directory.chmod(0o755)
        token = uuid.uuid4().hex[:8]
        group_name = "lb-svc-core-g-" + token
        service_name = "lb-svc-core-s-" + token
        caller_name = "lb-svc-core-c-" + token
        subprocess.run(["groupadd", "--system", group_name], check=True, capture_output=True, text=True)
        for name in (service_name, caller_name):
            subprocess.run(["useradd", "--system", "--no-create-home", "--gid", group_name,
                            "--shell", "/usr/sbin/nologin", name],
                           check=True, capture_output=True, text=True)
        import grp
        import pwd
        self.gid = grp.getgrnam(group_name).gr_gid
        self.service_uid = pwd.getpwnam(service_name).pw_uid
        self.caller_uid = pwd.getpwnam(caller_name).pw_uid
        self.assertNotEqual(self.service_uid, self.caller_uid)
        mutation_directory = self.directory / "mutation"
        mutation_directory.mkdir(mode=0o700)
        os.chown(mutation_directory, self.service_uid, self.gid)
        self.marker = mutation_directory / "reached"
        client_mutation = self.directory / "client-mutation"
        client_mutation.mkdir(mode=0o700)
        os.chown(client_mutation, self.caller_uid, self.gid)
        self.client_marker = client_mutation / "reached"
        self.binary = self.directory / "laneboss"
        shutil.copyfile(binary, self.binary)
        self.binary.chmod(0o755)
        self.helper = self.directory / "row-helper.py"
        shutil.copyfile(__file__, self.helper)
        self.helper.chmod(0o644)
        self.state = self.directory / "state"
        # Unix socket paths are bounded by sockaddr_un; evidence paths need
        # not fit that bound. Keep only the runtime root in a short scratch path.
        self.runtime = Path(tempfile.mkdtemp(prefix="lb-svc-core-runtime-", dir="/var/tmp"))
        self.runtime.chmod(0o755)
        self.caller_state = self.directory / "caller-state"
        for path in (self.state, self.caller_state):
            path.mkdir(mode=0o755)
        os.chown(self.state, self.service_uid, self.gid)
        os.chown(self.caller_state, self.caller_uid, self.gid)
        self.socket = self.runtime / "identity" / "service.sock"
        self.environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANEBOSS_CONFIG": "identity"}
        self.controllers = []
        self.service = None
        self.uid_limit = None
        self.detached = []
        self.addCleanup(self.collect_processes)
        self.controller, ready = self.new_controller()
        self.anchor = ready["process"]
        self.principal = {"id": "supervisor:top", "level": 5}
        private = self.state / "identity"
        # The baseline is created by the root-owned fixture, never by the
        # caller account. Production has no registration bypass or seed flag.
        seed = {"laneboss_service": 1, "config": "identity", "seq": 1,
                "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "op": "register", "actor": self.principal["id"], "peer": self.anchor,
                "principal": self.principal, "process": self.anchor}
        self.journal = private / "records.jsonl"
        socket_directory = self.runtime / "identity"
        socket_directory.mkdir(mode=0o750)
        os.chown(socket_directory, self.service_uid, self.gid)
        manifest = {"service_uid": self.service_uid, "caller_uid": self.caller_uid,
                    "configuration_gid": self.gid, "group": group_name,
                    "accounts": [service_name, caller_name], "seed": seed,
                    "binary_sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                    "mutant": self.mutant, "runtime_root": str(self.runtime)}
        (self.directory / "fixture.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        # The service creates its directory, journal and modes. The root-owned
        # fixture then appends the baseline without changing ownership/modes.
        self.start_service()
        self.assertEqual(self.ready["service"]["last_seq"], 0)
        self.stop_service()
        self.assertEqual(self.journal.stat().st_uid, self.service_uid)
        with self.journal.open("ab") as output:
            output.write((json.dumps(seed) + "\n").encode())
            output.flush()
            os.fsync(output.fileno())
        self.canary = self.journal
        self.canary_bytes = self.journal.read_bytes()
        self.start_service()

    def demote(self, uid, gid=None):
        def change_user():
            os.setgroups([])
            os.setgid(self.gid if gid is None else gid)
            os.setuid(uid)
            os.umask(0o007)
        return change_user

    def new_controller(self, environment=None):
        process = subprocess.Popen([sys.executable, "-I", str(self.helper), "--controller"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, start_new_session=True,
                                   env=environment or self.environment,
                                   preexec_fn=self.demote(self.caller_uid))
        self.controllers.append(process)
        ready = read_pipe(process.stdout)
        self.assertTrue(ready["ready"])
        self.assertEqual(ready["process"], kernel_process(process.pid))
        return process, ready

    def command(self, process, command):
        process.stdin.write(json.dumps(command) + "\n")
        process.stdin.flush()
        return read_pipe(process.stdout)

    def request(self, request, process=None, **options):
        value = {"laneboss_service": 1, "config": "identity", **request}
        result = self.command(process or self.controller,
                              {"op": "request", "socket": str(self.socket), "request": value, **options})
        with (self.directory / "requests.jsonl").open("a", encoding="utf-8") as output:
            output.write(json.dumps({"request": value, "options": options, "result": result}) + "\n")
        return result

    def start_service(self):
        environment = dict(self.environment)
        point = self.mutant or os.environ.get("LANEBOSS_IDENTITYD_INERT", "")
        if point:
            environment["LANEBOSS_FAULTS"] = json.dumps({"point": point, "marker": str(self.marker)})
        arguments = [str(self.binary), "service", "run", "--config", "identity",
                     "--state-root", str(self.state), "--runtime-root", str(self.runtime)]
        if self.uid_limit is not None:
            arguments.extend(["--uid-connection-limit", str(self.uid_limit)])
        self.service = subprocess.Popen(arguments,
                                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, env=environment,
                                        preexec_fn=self.demote(self.service_uid))
        ready = read_pipe(self.service.stdout)
        self.assertTrue(ready["ok"], "the real service did not become ready")
        self.assertEqual(ready["service"]["process"], kernel_process(self.service.pid))
        self.assertEqual(ready["socket"], str(self.socket))
        self.ready = ready
        with (self.directory / "service-ready.jsonl").open("a", encoding="utf-8") as output:
            output.write(json.dumps(ready) + "\n")

    def stop_service(self):
        if self.service is None:
            return
        process = self.service
        self.service = None
        if process.poll() is None:
            os.kill(process.pid, signal.SIGTERM)
        output, error = process.communicate(timeout=15)
        with (self.directory / "service-output.log").open("a", encoding="utf-8") as log:
            log.write(output + error)
        self.assertEqual(process.returncode, 0, "the service failed during PID-specific collection: " + error)
        self.assertFalse(self.socket.exists(), "the service did not collect its own socket")

    def collect_processes(self):
        for peer in self.detached:
            try:
                current = kernel_process(peer["pid"])
            except (FileNotFoundError, ProcessLookupError):
                continue
            if current["start"] != peer["start"]:
                raise RuntimeError("a detached fixture PID was reused before collection")
            os.kill(peer["pid"], signal.SIGTERM)
        self.stop_service()
        for process in reversed(self.controllers):
            if process.poll() is None:
                process.stdin.write('{"op":"quit"}\n')
                process.stdin.flush()
            output, error = process.communicate(timeout=15)
            with (self.directory / "controller-output.log").open("a", encoding="utf-8") as log:
                log.write(output + error)
            self.assertEqual(process.returncode, 0, "a fixture process failed during collection: " + error)

    def mutation_reached(self):
        if self.mutant:
            self.assertTrue(self.marker.is_file() or self.client_marker.is_file(),
                            "the selected mutation was never reached")

    def child_command(self, child, command, process=None):
        return self.command(process or self.controller,
                            {"op": "child", "child": child["child"], "command": command})

    def child_request(self, child, request, process=None):
        value = {"laneboss_service": 1, "config": "identity", **request}
        return self.child_command(child, {"op": "request", "socket": str(self.socket), "request": value}, process)["response"]

    def lane_start(self, child, name, run=1, process=None, level=4):
        return self.request({"op": "lane-started", "lane": name, "run": run, "level": level,
                             "process": {key: child["process"][key] for key in ("pid", "start")}},
                            process)["response"]

    def legacy_run(self, child, name, run, level=4):
        return {"op": "lane-started", "actor": self.principal["id"], "peer": self.anchor,
                "principal": {"id": "lane:" + name, "level": level, "starter": self.principal["id"]},
                "process": child["process"], "lane": name, "run": run}

    def seed_more(self, *records):
        # Root-owned historical inputs model journals the earlier core could
        # write. They retain real observed PIDs/start times; no product bypass.
        self.stop_service()
        existing = [json.loads(line) for line in self.journal.read_text().splitlines()]
        with self.journal.open("ab") as output:
            for record in records:
                value = {"laneboss_service": 1, "config": "identity", "seq": len(existing) + 1,
                         "time": datetime.datetime.now(datetime.timezone.utc).isoformat(), **record}
                output.write((json.dumps(value) + "\n").encode())
                existing.append(value)
            output.flush()
            os.fsync(output.fileno())
        self.start_service()

    def wait_json(self, path):
        deadline = time.monotonic() + 15
        while not path.exists():
            if time.monotonic() >= deadline:
                self.fail("the real detached fixture did not produce its evidence")
            time.sleep(0.05)
        # Writers publish a completed file by atomic rename.
        return json.loads(path.read_text())

    def launch_fixture(self, name, process=None, child=None, grandchild=None):
        driver = Path(os.environ["LANEBOSS_FAULTS_BIN"])
        self.assertTrue(driver.is_absolute() and driver.is_file(), "the launch probe needs the fault binary")
        copied = self.directory / "launch-driver"
        if not copied.exists():
            shutil.copyfile(driver, copied)
            copied.chmod(0o755)
        directory = self.caller_state / name
        directory.mkdir(mode=0o700)
        os.chown(directory, self.caller_uid, self.gid)
        streams = {key: directory / key for key in ("input", "output", "error")}
        for path in streams.values():
            path.touch(mode=0o600)
            os.chown(path, self.caller_uid, self.gid)
        command = {"op": "launch", "driver": str(copied),
                   "input": {"spec": {"launcher": str(self.binary), "config": "identity",
                                      "runtime_root": str(self.runtime), "lane": name, "run": 1,
                                      "command": [sys.executable, "-I", str(self.helper), "--detached",
                                                  str(directory), str(self.socket)]},
                             **{key: str(path) for key, path in streams.items()}}}
        if self.mutant:
            command["fault"] = {"point": self.mutant, "marker": str(self.client_marker)}
        (self.directory / (name + "-launch-input.json")).write_text(json.dumps(command) + "\n")
        if child is None:
            result = self.command(process or self.controller, command)
        else:
            if grandchild is not None:
                command = {"op": "child", "child": grandchild["child"], "command": command}
            result = self.child_command(child, command, process)
        if "result" in result:
            self.detached.append(result["result"]["root"])
        return result, directory

    def assert_live_orphan_child(self, evidence, name):
        ready = evidence["orphan_ready"]
        self.assertEqual(ready["parent"], evidence["process"])
        self.assertEqual(ready["process"]["pid"], evidence["child_pid"])
        self.assertTrue(ready["who"]["ok"])
        self.assertEqual(ready["who"]["peer"], ready["process"])
        self.assertEqual(ready["who"]["principal"]["id"], "lane:" + name,
                         "an ordinary live lane child lost its lane identity")
        self.assertEqual(ready["who"]["identity_root"],
                         {key: evidence["process"][key] for key in ("pid", "start")})
        self.assertTrue(ready["append"]["ok"], "an ordinary live lane child could not report")
        self.assertEqual(ready["append"]["record"]["actor"], "lane:" + name)

    def assert_orphan(self, evidence, orphan, message):
        self.assertEqual(orphan["process"], evidence["orphan_ready"]["process"])
        self.assertEqual(orphan["parent"], evidence["process"])
        self.assertNotEqual(orphan["parent_pid"], orphan["parent"]["pid"],
                            "the orphan queried before kernel reparenting")
        self.assertNotIn(orphan["parent"], orphan["ancestry"],
                         "the orphan queried while its lane parent was still in ancestry")
        self.assertEqual(len(orphan["parent_exit_events"]), 1)
        self.assertTrue(orphan["parent_exit_events"][0] & select.POLLIN,
                        "the orphan queried without its parent's pidfd exit proof")
        self.assertTrue(orphan["who"]["ok"])
        self.assertEqual(orphan["who"]["peer"], orphan["process"])
        self.assertFalse(orphan["who"]["identified"], message + "; observed " + json.dumps(orphan["who"]))
        self.assertNotIn("principal", orphan["who"])
        self.assertNotIn("identity_root", orphan["who"])
        self.assertNotIn("detachment_root", orphan["who"])
        self.assertFalse(orphan["append"]["ok"], "an unidentified orphan appended as its starter")
        self.assertEqual(orphan["append"]["error"], UNKNOWN + "\n" + SESSION_ROUTE)

    def test_s1_kernel_peer(self):
        stranger, ready = self.new_controller({**self.environment, "LANEBOSS_ROLE": "top",
                                               "LANEBOSS_SESSION": str(self.anchor["pid"]),
                                               "LANEBOSS_LANE": "impostor",
                                               "LANEBOSS_PROCESSES": "portable"})
        claimed = {"pid": self.anchor["pid"], "uid": self.service_uid,
                   "gid": 0, "start": "invented", "actor": self.principal["id"]}
        result = self.request({"op": "whoami", "claim": claimed}, stranger)
        self.mutation_reached()
        response = result["response"]
        self.assertTrue(response["ok"])
        self.assertEqual(response["peer"], ready["process"],
                         "caller-sent pid replaced kernel peer identity")
        self.assertFalse(response["identified"], "labels identified an unrelated process")
        self.assertNotIn("principal", response)
        control = self.request({"op": "whoami", "claim": {"pid": stranger.pid}})["response"]
        self.assertTrue(control["identified"])
        self.assertEqual(control["principal"], self.principal)
        self.assertEqual(control["peer"], self.anchor)

    def test_s2_separate_account(self):
        before = self.journal.read_bytes()
        result = self.command(self.controller, {"op": "permissions", "path": str(self.canary)})
        self.mutation_reached()
        (self.directory / "file-access.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        self.assertEqual(result["read"], "permission-denied", "caller read the service-owned record")
        self.assertEqual(result["write"], "permission-denied", "caller wrote the service-owned record")
        self.assertEqual(result["create"], "permission-denied", "caller created a forged service record")
        self.assertEqual(self.canary.read_bytes(), self.canary_bytes)
        self.assertEqual(stat.S_IMODE(self.journal.parent.stat().st_mode), 0o700)
        self.assertEqual(self.journal.stat().st_uid, self.service_uid)
        self.assertEqual(stat.S_IMODE(self.socket.stat().st_mode), 0o660)
        self.assertEqual(self.socket.stat().st_gid, self.gid)
        forged = self.caller_state / "sessions"
        stranger, ready = self.new_controller({**self.environment, "LANEBOSS_STATE_HOME": str(self.caller_state),
                                               "LANEBOSS_ROLE": "top"})
        record = forged / (str(stranger.pid) + ".json")
        fake = {"config": "identity", "principal": self.principal["id"],
                "pid": stranger.pid, "start": ready["process"]["start"]}
        written = self.command(stranger, {"op": "forge", "path": str(record), "record": fake})
        self.assertEqual(written, {"uid": self.caller_uid, "record": fake})
        self.assertEqual(record.stat().st_uid, self.caller_uid)
        response = self.request({"op": "whoami"}, stranger)["response"]
        self.assertFalse(response["identified"], "a caller-owned record became service authority")
        self.assertEqual(self.journal.read_bytes(), before)
        control = self.request({"op": "whoami"})["response"]
        self.assertEqual(control["principal"], self.principal)
        # Independently present public storage to an unmodified binary. It
        # must refuse; accepting only the fixture's private input is insufficient.
        self.stop_service()
        self.journal.parent.chmod(0o750)
        self.journal.chmod(0o660)
        rejected = subprocess.run([str(self.binary), "service", "run", "--config", "identity",
                                   "--state-root", str(self.state), "--runtime-root", str(self.runtime)],
                                  env=self.environment, stdin=subprocess.DEVNULL,
                                  capture_output=True, text=True, timeout=15,
                                  preexec_fn=self.demote(self.service_uid))
        (self.directory / "public-store.stderr").write_text(rejected.stderr)
        self.assertEqual(rejected.returncode, 2, "the release policy admitted public storage")
        self.assertIn("the service directory has unsafe type or permissions", rejected.stderr)
        self.journal.parent.chmod(0o700)
        self.journal.chmod(0o600)
        self.start_service()

    def test_s3_lane_actor(self):
        child = self.command(self.controller, {"op": "spawn"})
        lane = "work-" + uuid.uuid4().hex[:8]
        target = {key: child["process"][key] for key in ("pid", "start")}
        started = self.request({"op": "lane-started", "lane": lane, "run": 1,
                                "process": target})["response"]
        self.assertTrue(started["ok"], started.get("error"))
        self.assertEqual(started["record"]["actor"], self.principal["id"])
        self.assertEqual(started["record"]["process"], child["process"])
        payload = {"text": uuid.uuid4().hex, "claimed_actor": "human"}
        request = {"laneboss_service": 1, "config": "identity", "op": "append", "type": "event",
                   "kind": "agent.observed", "lane": lane, "payload": payload,
                   "claim": {"actor": "supervisor:impostor", "pid": self.anchor["pid"]}}
        result = self.command(self.controller, {"op": "child", "child": child["child"],
                                               "command": {"op": "request", "socket": str(self.socket),
                                                           "request": request}})
        self.mutation_reached()
        response = result["response"]
        self.assertTrue(response["ok"], response.get("error"))
        self.assertEqual(response["record"]["actor"], "lane:" + lane,
                         "caller-sent actor replaced the identified lane")
        self.assertEqual(response["record"]["peer"], child["process"])
        self.assertEqual(response["record"]["payload"], payload)
        for kind in ("report", "send"):
            message = {**request, "type": kind, "kind": "", "to": self.principal["id"]}
            result = self.command(self.controller, {"op": "child", "child": child["child"],
                                                   "command": {"op": "request", "socket": str(self.socket),
                                                               "request": message}})["response"]
            self.assertTrue(result["ok"], result.get("error"))
            self.assertEqual(result["record"]["actor"], "lane:" + lane)
        records = [json.loads(line) for line in self.journal.read_text().splitlines()]
        self.assertEqual([record["seq"] for record in records], list(range(1, 6)))
        self.assertEqual(records[2], response["record"], "the reply differs from the service-written bytes")
        self.stop_service()
        self.start_service()
        result = self.command(self.controller, {"op": "child", "child": child["child"],
                                               "command": {"op": "request", "socket": str(self.socket),
                                                           "request": {"laneboss_service": 1, "config": "identity",
                                                                       "op": "whoami"}}})["response"]
        self.assertEqual(result["principal"], {"id": "lane:" + lane, "level": 3,
                                               "starter": self.principal["id"]})
        self.assertEqual(result["service"]["last_seq"], 5)

    def test_s4_unknown_refused(self):
        stranger, _ = self.new_controller()
        before = self.journal.read_bytes()
        append = self.request({"op": "append", "type": "report", "payload": {"text": "canary"}},
                              stranger)["response"]
        self.mutation_reached()
        self.assertFalse(append["ok"], "an unidentified peer appended a record")
        self.assertEqual(append["code"], 2)
        self.assertEqual(append["error"], UNKNOWN + "\n" + SESSION_ROUTE)
        start = self.request({"op": "lane-started", "lane": "unidentified", "run": 1,
                             "process": {key: self.anchor[key] for key in ("pid", "start")}},
                             stranger)["response"]
        self.assertFalse(start["ok"])
        self.assertEqual(start["error"], UNKNOWN + "\n" + START_ROUTE)
        for process in (stranger, self.controller):
            registration = self.request({"op": "register", "ticket": {"role": "top", "signature": "invented"}},
                                        process)["response"]
            self.assertFalse(registration["ok"], "the stub verifier admitted a ticket")
            self.assertEqual(registration["error"].splitlines()[0],
                             "refused: the bootstrap ticket verifier is not installed")
            self.assertIn("Instead:", registration["error"])
        self.assertEqual(self.journal.read_bytes(), before, "a refused state change wrote service bytes")
        who = self.request({"op": "whoami"}, stranger)["response"]
        self.assertTrue(who["ok"])
        self.assertFalse(who["identified"])
        control = self.request({"op": "append", "type": "report", "payload": {"text": "control"}})["response"]
        self.assertTrue(control["ok"], control.get("error"))
        self.assertEqual(control["record"]["actor"], self.principal["id"])

    def test_s5_start_time(self):
        child = self.command(self.controller, {"op": "spawn"})
        before = self.journal.read_bytes()
        target = {"pid": child["process"]["pid"], "start": child["process"]["start"] + "-reused"}
        bad = self.request({"op": "lane-started", "lane": "start-canary", "run": 1,
                            "process": target})["response"]
        self.mutation_reached()
        self.assertFalse(bad["ok"], "a wrong process start time was accepted")
        self.assertEqual(bad["error"].splitlines()[0],
                         "refused: the recorded process start time disagrees with the kernel")
        self.assertEqual(self.journal.read_bytes(), before)
        target["start"] = child["process"]["start"]
        control = self.request({"op": "lane-started", "lane": "start-canary", "run": 1,
                                "process": target})["response"]
        self.assertTrue(control["ok"], control.get("error"))
        self.assertEqual(control["record"]["process"], child["process"])

    def test_s6_protocol_status(self):
        before = self.journal.read_bytes()
        bad = self.request({"op": "whoami", "laneboss_service": 999})["response"]
        self.mutation_reached()
        self.assertFalse(bad["ok"], "an unsupported protocol version was accepted")
        self.assertEqual(bad["code"], 2)
        wrong_scope = self.request({"op": "whoami", "config": "other"})["response"]
        self.assertFalse(wrong_scope["ok"], "the socket admitted another configuration")
        duplicate = self.request({}, raw='{"laneboss_service":1,"config":"identity","op":"whoami","op":"append"}\n')["response"]
        self.assertFalse(duplicate["ok"], "duplicate JSON fields were accepted")
        oversized = self.request({}, raw=json.dumps({"laneboss_service": 1, "config": "identity", "op": "whoami",
                                                     "claim": {"text": "x" * (64 * 1024)}}) + "\n")["response"]
        self.assertFalse(oversized["ok"], "an oversized frame was accepted")
        incomplete = self.request({}, raw='{"laneboss_service":1', half_close=True)["response"]
        self.assertFalse(incomplete["ok"], "an unterminated frame was accepted")
        timed_out = self.request({}, raw="")["response"]
        self.assertFalse(timed_out["ok"], "an idle connection did not time out")
        self.assertEqual(self.journal.read_bytes(), before)
        status = subprocess.run([str(self.binary), "service", "status", "--config", "identity",
                                 "--runtime-root", str(self.runtime)], env=self.environment,
                                capture_output=True, text=True, timeout=15,
                                preexec_fn=self.demote(self.caller_uid))
        (self.directory / "status.json").write_text(status.stdout, encoding="utf-8")
        (self.directory / "status.stderr").write_text(status.stderr, encoding="utf-8")
        self.assertEqual(status.returncode, 0, status.stderr)
        observed = json.loads(status.stdout)
        self.assertTrue(observed["ok"])
        self.assertEqual(observed["service"], self.ready["service"])
        self.assertFalse(observed["identified"], "an unrelated status command acquired a supervisor identity")

    def test_s7_owner(self):
        name = "owner-" + uuid.uuid4().hex[:8]
        old = self.command(self.controller, {"op": "spawn"})
        ended = self.command(self.controller, {"op": "spawn"})
        self.assertEqual(self.command(self.controller, {"op": "stop", "child": ended["child"]})["exit"], 0)
        self.seed_more(self.legacy_run(old, name, 1), self.legacy_run(ended, name, 2))
        child = self.child_command(old, {"op": "spawn"})
        before = self.journal.read_bytes()
        refused = self.child_request(old, {"op": "lane-started", "lane": name, "run": 3, "level": 3,
                                          "process": {key: child["process"][key] for key in ("pid", "start")}})
        self.mutation_reached()
        self.assertFalse(refused["ok"], "an L4 lane recorded its own next run")
        self.assertIn("a lane cannot record a run of itself", refused["error"])
        self.assertEqual(self.journal.read_bytes(), before)
        self.assertEqual(self.child_request(old, {"op": "whoami"})["principal"],
                         {"id": "lane:" + name, "level": 4, "starter": self.principal["id"]})
        other, ready = self.new_controller()
        principal = {"id": "supervisor:other", "level": 5}
        self.seed_more({"op": "register", "actor": principal["id"], "peer": ready["process"],
                        "principal": principal, "process": ready["process"]})
        replacement = self.command(other, {"op": "spawn"})
        before = self.journal.read_bytes()
        refused = self.lane_start(replacement, name, 3, other)
        self.assertFalse(refused["ok"], "another starter took over the lane")
        self.assertIn("another recorded starter", refused["error"])
        self.assertEqual(self.journal.read_bytes(), before)
        legitimate = self.command(self.controller, {"op": "spawn"})
        control = self.lane_start(legitimate, name, 3)
        self.assertTrue(control["ok"], control.get("error"))
        self.assertEqual(control["record"]["principal"]["starter"], self.principal["id"])

    def test_s7_live(self):
        name = "live-" + uuid.uuid4().hex[:8]
        old = self.command(self.controller, {"op": "spawn"})
        self.assertTrue(self.lane_start(old, name)["ok"])
        replacement = self.command(self.controller, {"op": "spawn"})
        before = self.journal.read_bytes()
        refused = self.lane_start(replacement, name, 2)
        self.mutation_reached()
        self.assertFalse(refused["ok"], "a live lane run was replaced")
        self.assertIn("previous run is still live", refused["error"])
        self.assertEqual(self.journal.read_bytes(), before)
        who = self.child_request(old, {"op": "whoami"})
        self.assertEqual(who["principal"]["id"], "lane:" + name,
                         "run 1 became the supervisor after a refused resume")
        self.assertEqual(self.command(self.controller, {"op": "stop", "child": old["child"]})["exit"], 0)
        control = self.lane_start(replacement, name, 2)
        self.assertTrue(control["ok"], control.get("error"))

    def test_s7_history(self):
        name = "history-" + uuid.uuid4().hex[:8]
        old = self.command(self.controller, {"op": "spawn"})
        latest = self.command(self.controller, {"op": "spawn"})
        self.seed_more(self.legacy_run(old, name, 1), self.legacy_run(latest, name, 2))
        who = self.child_request(old, {"op": "whoami"})
        self.mutation_reached()
        self.assertEqual(who["principal"]["id"], "lane:" + name,
                         "an older live run became its supervisor")
        report = self.child_request(old, {"op": "append", "type": "report", "payload": {"text": "old run canary"}})
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["record"]["actor"], "lane:" + name)
        self.assertEqual(report["record"]["lane"], name)
        self.assertEqual(self.child_request(latest, {"op": "whoami"})["principal"]["id"], "lane:" + name)
        self.stop_service()
        self.start_service()
        self.assertEqual(self.child_request(old, {"op": "whoami"})["principal"]["id"], "lane:" + name)

    def test_s7_roots(self):
        session = self.command(self.controller, {"op": "spawn"})
        principal = {"id": "supervisor:nested", "level": 5}
        self.seed_more({"op": "register", "actor": principal["id"], "peer": session["process"],
                        "principal": principal, "process": session["process"]})
        before = self.journal.read_bytes()
        refused = self.lane_start(session, "session-overlay")
        self.mutation_reached()
        self.assertFalse(refused["ok"], "a live session anchor was relabelled")
        self.assertIn("contains a live recorded session or lane root", refused["error"])
        self.assertEqual(self.child_request(session, {"op": "whoami"})["principal"], principal)
        self.assertEqual(self.journal.read_bytes(), before)
        carrier = self.command(self.controller, {"op": "spawn"})
        grandchild = self.child_command(carrier, {"op": "spawn"})
        nested = {"id": "supervisor:deep", "level": 5}
        self.seed_more({"op": "register", "actor": nested["id"], "peer": grandchild["process"],
                        "principal": nested, "process": grandchild["process"]})
        refused = self.lane_start(carrier, "ancestor-overlay")
        self.assertFalse(refused["ok"], "an ancestor swallowed a recorded session")
        lane = self.command(self.controller, {"op": "spawn"})
        self.assertTrue(self.lane_start(lane, "first-root")["ok"])
        before = self.journal.read_bytes()
        refused = self.lane_start(lane, "second-root")
        self.assertFalse(refused["ok"], "one live root became two lane identities")
        self.assertEqual(self.journal.read_bytes(), before)
        separate = self.command(self.controller, {"op": "spawn"})
        self.assertTrue(self.lane_start(separate, "separate-root")["ok"])

    def test_s7_detach(self):
        name = "detach-" + uuid.uuid4().hex[:8]
        launched, directory = self.launch_fixture(name)
        self.assertTrue(launched.get("running"), launched)
        evidence = self.wait_json(directory / "detached.json")
        self.detached.append(kernel_process(evidence["child_pid"]))
        self.mutation_reached()
        self.assertNotIn(self.anchor, evidence["ancestry"],
                         "the launcher left the lane in its session tree")
        self.assertNotIn(launched["caller"], evidence["ancestry"],
                         "the launcher left the lane in its session tree")
        self.assertEqual(evidence["who"]["principal"]["id"], "lane:" + name)
        self.assertEqual(evidence["process"], launched["result"]["root"])
        self.assert_live_orphan_child(evidence, name)
        for build in (evidence["build"], evidence["build"]["child"]):
            self.assertTrue(build["who"]["ok"], "an ordinary forking build tool was refused")
            self.assertEqual(build["who"]["principal"]["id"], "lane:" + name)
            self.assertTrue(build["report"]["ok"], "an ordinary lane child could not report")
            self.assertEqual(build["report"]["record"]["actor"], "lane:" + name)
        before = self.journal.read_bytes()
        os.kill(evidence["process"]["pid"], signal.SIGTERM)
        orphan = self.wait_json(directory / "orphan.json")
        self.assert_orphan(evidence, orphan, "an orphan inherited its starter's supervisor identity")
        self.assertEqual(self.journal.read_bytes(), before, "the orphan changed the service journal")
        self.command(self.controller, {"op": "release-launch", "launcher": launched["launcher"]})
        # A real subreaper at the persistent session anchor retains the orphan.
        # The production launcher must detect that and keep the command gated.
        self.assertTrue(self.command(self.controller, {"op": "subreaper", "enabled": True})["enabled"])
        blocked, blocked_directory = self.launch_fixture("subreaper-" + uuid.uuid4().hex[:8])
        self.assertEqual(blocked.get("exit"), 2, "a session subreaper admitted the lane command")
        self.assertIn("subreaper retained the lane", blocked["error"])
        self.assertFalse((blocked_directory / "detached.json").exists(), "the command ran before detachment was proven")
        latest = json.loads(self.journal.read_text().splitlines()[-1])["process"]
        reaped = self.command(self.controller, {"op": "reap", "pid": latest["pid"]})
        self.assertEqual(reaped["exit"], 2, "the unexecuted gated child did not fail closed")
        self.assertFalse(self.command(self.controller, {"op": "subreaper", "enabled": False})["enabled"])

    def test_s8_case(self):
        before = self.journal.read_bytes()
        refused = self.request({"op": "whoami", "OP": "append", "type": "report",
                                "payload": {"text": "case alias canary"}})["response"]
        self.mutation_reached()
        self.assertFalse(refused["ok"], "a case alias changed the operation")
        self.assertEqual(self.journal.read_bytes(), before)
        nested = self.request({"op": "lane-started", "lane": "case-root", "run": 1,
                               "process": {"PID": self.anchor["pid"], "start": self.anchor["start"]}})["response"]
        self.assertFalse(nested["ok"], "a nested PID alias was accepted")
        self.assertEqual(self.journal.read_bytes(), before)
        self.assertTrue(self.request({"op": "whoami"})["response"]["ok"])

    def test_s9_scope(self):
        name = "scope-" + uuid.uuid4().hex[:8]
        child = self.command(self.controller, {"op": "spawn"})
        self.assertTrue(self.lane_start(child, name, level=3)["ok"])
        before = self.journal.read_bytes()
        request = {"op": "append", "type": "report", "lane": "another-lane", "payload": {"text": "scope canary"}}
        refused = self.child_request(child, request)
        self.mutation_reached()
        self.assertFalse(refused["ok"], "a lane recorded another lane's report")
        self.assertEqual(self.journal.read_bytes(), before)
        for kind in ("report", "send", "event"):
            request = {"op": "append", "type": kind, "to": self.principal["id"],
                       "payload": {"text": uuid.uuid4().hex}}
            if kind == "event":
                request["kind"] = "agent.observed"
            control = self.child_request(child, request)
            self.assertTrue(control["ok"], control.get("error"))
            self.assertEqual(control["record"]["lane"], name)
            self.assertEqual(control["record"]["actor"], "lane:" + name)

    def test_s10_events(self):
        before = self.journal.read_bytes()
        refused = self.request({"op": "append", "type": "event", "kind": "example.unlisted",
                                "payload": {"text": "event kind canary"}})["response"]
        self.mutation_reached()
        self.assertFalse(refused["ok"], "an unlisted event kind was accepted")
        self.assertEqual(self.journal.read_bytes(), before)
        malformed = self.request({"op": "append", "type": "event", "kind": "lane.refusal",
                                  "lane": "event-root", "payload": {"text": "invalid schema"}})["response"]
        self.assertFalse(malformed["ok"], "an allowed kind bypassed its CLI payload validator")
        self.assertEqual(self.journal.read_bytes(), before)
        control = self.request({"op": "append", "type": "event", "kind": "agent.observed",
                                "payload": {"text": uuid.uuid4().hex}})["response"]
        self.assertTrue(control["ok"], control.get("error"))

    def test_s11_slots(self):
        command = {"op": "hold", "socket": str(self.socket)}
        self.assertTrue(self.command(self.controller, command)["ok"])
        self.assertTrue(self.command(self.controller, command)["ok"])
        refused = self.command(self.controller, command)
        self.mutation_reached()
        self.assertFalse(refused["ok"], "one peer exceeded its connection cap")
        self.assertEqual(refused["code"], 2)
        self.assertIn("per-peer connection limit of 2", refused["error"])
        stranger, _ = self.new_controller()
        self.assertTrue(self.request({"op": "whoami"}, stranger)["response"]["ok"],
                        "the capped peer denied an independent caller")
        self.assertEqual(self.command(self.controller, {"op": "release-slots"})["remaining"], 0)

    def test_s12_size(self):
        before = self.journal.read_bytes()
        refused = self.request({"op": "append", "type": "report", "payload": {"text": "<" * 10000}})["response"]
        self.mutation_reached()
        self.assertFalse(refused["ok"], "an oversized encoded payload was accepted")
        self.assertEqual(self.journal.read_bytes(), before)
        control = self.request({"op": "append", "type": "report", "payload": {"text": "<" * 1000}})["response"]
        self.assertTrue(control["ok"], control.get("error"))
        self.assertEqual(control["record"]["payload"]["text"], "<" * 1000)

    def test_s13_above_anchor(self):
        above, _ = self.new_controller()
        self.assertTrue(self.command(above, {"op": "subreaper", "enabled": True})["enabled"])
        anchor = self.command(above, {"op": "spawn"})
        principal = {"id": "supervisor:below-reaper", "level": 5}
        self.seed_more({"op": "register", "actor": principal["id"], "peer": anchor["process"],
                        "principal": principal, "process": anchor["process"]})
        who = self.child_request(anchor, {"op": "whoami"}, above)
        self.assertEqual(who["principal"], principal)
        self.assertEqual(who["identity_root"], {key: anchor["process"][key] for key in ("pid", "start")})
        self.assertEqual(who["detachment_root"], who["identity_root"])
        name = "above-" + uuid.uuid4().hex[:8]
        launched, directory = self.launch_fixture(name, above, anchor)
        self.mutation_reached()
        self.assertTrue(launched.get("running"), "an above-anchor subreaper refused an ordinary launch")
        evidence = self.wait_json(directory / "detached.json")
        self.detached.append(kernel_process(evidence["child_pid"]))
        self.assertNotIn(anchor["process"], evidence["ancestry"])
        self.assertNotIn(launched["caller"], evidence["ancestry"])
        self.assertIn(kernel_process(above.pid), evidence["ancestry"], "the real above-anchor subreaper was not exercised")
        self.assertEqual(evidence["who"]["principal"]["id"], "lane:" + name)
        self.assert_live_orphan_child(evidence, name)
        for build in (evidence["build"], evidence["build"]["child"]):
            self.assertTrue(build["who"]["ok"], "an ordinary forking build tool was refused")
            self.assertEqual(build["who"]["principal"]["id"], "lane:" + name)
            self.assertTrue(build["report"]["ok"], "an ordinary lane child was refused")
            self.assertEqual(build["report"]["record"]["actor"], "lane:" + name)
        before = self.journal.read_bytes()
        os.kill(evidence["process"]["pid"], signal.SIGTERM)
        orphan = self.wait_json(directory / "orphan.json")
        self.assertEqual(orphan["parent_pid"], above.pid, "the orphan did not reach the above-anchor subreaper")
        self.assertNotIn(anchor["process"], orphan["ancestry"])
        self.assert_orphan(evidence, orphan, "an orphan inherited the below-reaper session")
        self.assertEqual(self.journal.read_bytes(), before, "the orphan changed the service journal")
        self.assertEqual(self.command(above, {"op": "reap", "pid": evidence["process"]["pid"]})["exit"], 0)
        self.assertEqual(self.command(above, {"op": "reap", "pid": orphan["process"]["pid"]})["exit"], 0)
        self.child_command(anchor, {"op": "release-launch", "launcher": launched["launcher"]}, above)
        self.assertFalse(self.command(above, {"op": "subreaper", "enabled": False})["enabled"])

    def test_s14_uid_setting(self):
        self.stop_service()
        self.uid_limit = 2
        self.start_service()
        command = {"op": "hold", "socket": str(self.socket)}
        peers = [self.new_controller()[0] for _ in range(3)]
        self.assertTrue(self.command(peers[0], command)["ok"])
        self.assertTrue(self.command(peers[1], command)["ok"])
        refused = self.command(peers[2], command)
        self.mutation_reached()
        self.assertFalse(refused["ok"], "the configured UID connection limit was ignored")
        self.assertIn("per-UID connection limit of 2", refused["error"])
        self.assertIn("--uid-connection-limit", refused["error"])
        for peer in peers:
            self.command(peer, {"op": "release-slots"})
        self.stop_service()
        self.uid_limit = 3
        self.start_service()
        for peer in peers:
            self.assertTrue(self.command(peer, command)["ok"], "the raised configured UID cap was not applied")
        for peer in peers:
            self.command(peer, {"op": "release-slots"})
        # The default is independently measured through distinct peer PIDs.
        self.stop_service()
        self.uid_limit = None
        self.start_service()
        default_peers = [self.new_controller()[0] for _ in range(9)]
        for peer in default_peers[:8]:
            self.assertTrue(self.command(peer, command)["ok"])
        refused = self.command(default_peers[8], command)
        self.assertFalse(refused["ok"], "the documented default UID cap was not enforced")
        self.assertIn("per-UID connection limit of 8", refused["error"])
        for peer in default_peers:
            self.command(peer, {"op": "release-slots"})

    def test_s15_outer_session(self):
        # A nearer recorded session cannot hide an enclosing recorded session
        # above a reaper. Allowing this launch would promote its orphan to top.
        reaper = self.command(self.controller, {"op": "spawn"})
        self.assertTrue(self.child_command(reaper, {"op": "subreaper", "enabled": True})["enabled"])
        inner = self.child_command(reaper, {"op": "spawn"})
        principal = {"id": "supervisor:inner", "level": 5}
        self.seed_more({"op": "register", "actor": principal["id"], "peer": inner["process"],
                        "principal": principal, "process": inner["process"]})
        who = self.child_command(reaper, {"op": "child", "child": inner["child"],
                                         "command": {"op": "request", "socket": str(self.socket),
                                                     "request": {"laneboss_service": 1, "config": "identity",
                                                                 "op": "whoami"}}})["response"]
        self.assertEqual(who["principal"], principal)
        self.assertEqual(who["identity_root"], {key: inner["process"][key] for key in ("pid", "start")})
        self.assertEqual(who["detachment_root"], {key: self.anchor[key] for key in ("pid", "start")})
        name = "outer-" + uuid.uuid4().hex[:8]
        launched, directory = self.launch_fixture(name, child=reaper, grandchild=inner)
        self.mutation_reached()
        if launched.get("running"):
            evidence = self.wait_json(directory / "detached.json")
            self.detached.append(kernel_process(evidence["child_pid"]))
            self.assert_live_orphan_child(evidence, name)
            os.kill(evidence["process"]["pid"], signal.SIGTERM)
            orphan = self.wait_json(directory / "orphan.json")
            self.assertEqual(orphan["parent_pid"], reaper["process"]["pid"])
            self.assertIn(self.anchor, orphan["ancestry"])
            for peer in (evidence["process"], orphan["process"]):
                self.assertEqual(self.child_command(reaper, {"op": "reap", "pid": peer["pid"]})["exit"], 0)
            self.child_command(reaper, {"op": "child", "child": inner["child"],
                                        "command": {"op": "release-launch", "launcher": launched["launcher"]}})
            self.assertFalse(self.child_command(reaper, {"op": "subreaper", "enabled": False})["enabled"])
            self.assert_orphan(evidence, orphan, "an orphan inherited an enclosing recorded session")
        self.assertEqual(launched.get("exit"), 2, "a recorded outer session retained the released lane")
        self.assertIn("subreaper retained the lane", launched["error"])
        self.assertFalse((directory / "detached.json").exists(), "the command ran before safe detachment")
        latest = json.loads(self.journal.read_text().splitlines()[-1])["process"]
        self.assertEqual(self.child_command(reaper, {"op": "reap", "pid": latest["pid"]})["exit"], 2)
        self.assertFalse(self.child_command(reaper, {"op": "subreaper", "enabled": False})["enabled"])
        control = self.child_command(reaper, {"op": "child", "child": inner["child"],
                                             "command": {"op": "request", "socket": str(self.socket),
                                                         "request": {"laneboss_service": 1, "config": "identity",
                                                                     "op": "append", "type": "report",
                                                                     "payload": {"text": uuid.uuid4().hex}}}})["response"]
        self.assertTrue(control["ok"], "the nested live session lost its reporting permission")
        self.assertEqual(control["record"]["actor"], principal["id"])

    def test_s16_cap_status(self):
        self.stop_service()
        self.uid_limit = 1
        self.start_service()
        self.assertTrue(self.command(self.controller, {"op": "hold", "socket": str(self.socket)})["ok"])
        before = self.journal.read_bytes()
        arguments = [str(self.binary), "service", "status", "--config", "identity",
                     "--runtime-root", str(self.runtime)]
        for attempt in range(50):
            # Keep the one admitted connection active without exceeding the
            # service's 64-request bound. Each status uses a different process.
            self.assertTrue(self.command(self.controller, {"op": "refresh-slot", "slot": 0})["ok"])
            status = subprocess.run(arguments, env=self.environment,
                                    preexec_fn=self.demote(self.caller_uid),
                                    capture_output=True, text=True, timeout=15)
            (self.directory / ("cap-status-" + str(attempt) + ".stdout")).write_text(status.stdout)
            (self.directory / ("cap-status-" + str(attempt) + ".stderr")).write_text(status.stderr)
            (self.directory / ("cap-status-" + str(attempt) + ".json")).write_text(
                json.dumps({"attempt": attempt, "argv": arguments, "exit": status.returncode}) + "\n")
            self.mutation_reached()
            self.assertEqual(status.returncode, 2, "a capped CLI status lost the UID refusal: " + status.stderr)
            self.assertIn("per-UID connection limit of 1", status.stderr)
            self.assertIn("--uid-connection-limit", status.stderr)
            self.assertNotIn("integrity problem", status.stdout + status.stderr)
            self.assertEqual(status.stdout, "")
            self.assertEqual(self.journal.read_bytes(), before, "a refused status changed the journal")
        self.assertEqual(self.command(self.controller, {"op": "release-slots"})["remaining"], 0)
        # Synchronize through the service before testing the uncapped control.
        self.stop_service()
        self.start_service()
        control = subprocess.run(arguments, env=self.environment,
                                 preexec_fn=self.demote(self.caller_uid),
                                 capture_output=True, text=True, timeout=15)
        (self.directory / "cap-status-control.stdout").write_text(control.stdout)
        (self.directory / "cap-status-control.stderr").write_text(control.stderr)
        (self.directory / "cap-status-control.json").write_text(json.dumps({"argv": arguments, "exit": control.returncode}) + "\n")
        self.assertEqual(control.returncode, 0, control.stderr)
        observed = json.loads(control.stdout)
        self.assertTrue(observed["ok"])
        self.assertFalse(observed["identified"])
        self.assertEqual(observed["service"], self.ready["service"])
        self.assertEqual(self.journal.read_bytes(), before)


if __name__ == "__main__":
    if sys.argv[1:] == ["--controller"]:
        controller_main()
    elif len(sys.argv) == 4 and sys.argv[1] == "--detached":
        detached_main(Path(sys.argv[2]), sys.argv[3])
    elif len(sys.argv) == 6 and sys.argv[1] == "--orphan":
        orphan_main(int(sys.argv[2]), int(sys.argv[3]), Path(sys.argv[4]), sys.argv[5])
    elif len(sys.argv) == 3 and sys.argv[1] in ("--build", "--build-leaf"):
        build_main(sys.argv[2], leaf=sys.argv[1] == "--build-leaf")
    else:
        unittest.main(verbosity=2)
