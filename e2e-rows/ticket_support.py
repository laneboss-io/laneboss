"""PTY and pipe-only process fixtures for the disposable Linux ticket rows."""

import errno
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from headless_support import HeadlessController, require_headless


def owner_command(binary, request, background):
    """Run actual human commands below the administrator-attested login root."""
    from reportsupport import request_environment
    if "stop" in request:
        exits = []
        for pid in request["stop"]:
            process = background.pop(pid)
            if process.poll() is None:
                os.kill(process.pid, signal.SIGTERM)
            process.communicate(timeout=20)
            exits.append(process.returncode)
        return {"exits": exits}
    environment = request_environment(request, os.environ)
    directory = request.get("cwd")
    command = [str(request.get("binary", binary)), *map(str, request["args"])]
    if request.get("serve") or request.get("background"):
        process = subprocess.Popen(command, cwd=directory, env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        background[process.pid] = process
        readable, _, _ = select.select([process.stdout], [], [], 30)
        if not readable:
            raise RuntimeError("the real human background command did not answer")
        line = process.stdout.readline()
        if not line:
            _, error = process.communicate(timeout=20)
            return {"code": process.returncode, "stdout": "", "stderr": error,
                    "exit": process.returncode}
        if process.poll() is not None:
            raise RuntimeError("the real human background command ended at readiness")
        return {"code": 0, "ready": line, "stdout": line.strip(), "stderr": "",
                "pid": process.pid, "exit": process.poll()}
    result = subprocess.run(command, cwd=directory, env=environment,
        input=request.get("stdin", request.get("input", "")), capture_output=True,
        text=True, timeout=90, start_new_session=request.get("detach", False))
    return {"code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def terminal_run(binary, arguments, environment):
    pid, descriptor = pty.fork()
    if pid == 0:
        terminal = os.open("/dev/tty", os.O_RDONLY | os.O_NOCTTY)
        os.close(terminal)
        fields = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()
        if int(fields[4]) == 0:
            raise RuntimeError("the PTY child has no controlling terminal")
        os.execve(str(binary), [str(binary), *map(str, arguments)], environment)
    output = bytearray()
    deadline = time.monotonic() + 60
    status = None
    try:
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            readable, _, _ = select.select([descriptor], [], [], max(0, remaining))
            if readable:
                try:
                    piece = os.read(descriptor, 65536)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    piece = b""
                if not piece:
                    break
                output.extend(piece)
                if len(output) > 2 ** 20:
                    raise RuntimeError("the terminal command exceeded its output bound")
        else:
            raise RuntimeError("the terminal command exceeded its deadline")
        while status is None:
            waited, observed = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                status = observed
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("the terminal child did not exit after closing its output")
            select.select([], [], [], min(0.05, remaining))
        return {"code": os.waitstatus_to_exitcode(status),
                "output": output.decode("utf-8").replace("\r\n", "\n")}
    finally:
        os.close(descriptor)
        if status is None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                status = os.waitpid(pid, 0)[1]
            else:
                status = os.waitpid(pid, 0)[1]


def controller_main(binary):
    require_headless()
    print(json.dumps({"ready": True, "pid": os.getpid()}), flush=True)
    for line in sys.stdin:
        request = json.loads(line)
        if request.get("quit"):
            return
        if request.get("terminal"):
            result = terminal_run(binary, request["args"], dict(os.environ))
        else:
            environment = {**os.environ, **request.get("environment", {})}
            command = ([request["program"], *map(str, request["args"])] if request.get("program") else
                       [sys.executable, "-I", str(Path(__file__).resolve()), "--invoke",
                        binary, *map(str, request["args"])])
            child = subprocess.run(
                command, env=environment,
                input="", capture_output=True, text=True, timeout=60,
                start_new_session=not bool(request.get("program")),
            )
            result = {"code": child.returncode, "stdout": child.stdout, "stderr": child.stderr}
        print(json.dumps(result), flush=True)


def login_main(binary):
    """An administrator attests this persistent PTY session before service start."""
    commands_read, commands_write = os.pipe()
    replies_read, replies_write = os.pipe()
    pid, terminal = pty.fork()
    if pid == 0:
        os.close(commands_write)
        os.close(replies_read)
        with os.fdopen(commands_read, "r") as commands, os.fdopen(replies_write, "w") as replies:
            background = {}
            replies.write(json.dumps({"pid": os.getpid()}) + "\n")
            replies.flush()
            for line in commands:
                request = json.loads(line)
                if request.get("quit"):
                    owner_command(binary, {"stop": list(background)}, background)
                    os._exit(0)
                if "write_file" in request:
                    # An actual unprivileged write canary, not a service grant.
                    count = Path(request["write_file"]).write_text(request["text"])
                    replies.write(json.dumps({"written": count}) + "\n")
                    replies.flush()
                    continue
                result = owner_command(binary, request, background)
                replies.write(json.dumps(result) + "\n")
                replies.flush()
        os._exit(0)
    os.close(commands_read)
    os.close(replies_write)
    try:
        with os.fdopen(commands_write, "w") as commands, os.fdopen(replies_read, "r") as replies:
            print(replies.readline().strip(), flush=True)
            for line in sys.stdin:
                request = json.loads(line)
                commands.write(line)
                commands.flush()
                if request.get("quit"):
                    break
                ready, _, _ = select.select([replies], [], [], 60)
                if not ready:
                    raise RuntimeError("the attested terminal missed its command deadline")
                answer = replies.readline()
                if not answer:
                    raise RuntimeError("the attested terminal stopped before responding")
                print(answer.strip(), flush=True)
        waited, status = os.waitpid(pid, 0)
        if waited != pid or os.waitstatus_to_exitcode(status) != 0:
            raise RuntimeError("the attested terminal did not exit cleanly")
    finally:
        os.close(terminal)


def runner_main(session):
    prompt = sys.stdin.buffer.read()
    directory = Path(".sessions")
    directory.mkdir(exist_ok=True)
    (directory / (session + ".jsonl")).write_text(json.dumps(
        {"type": "assistant", "timestamp": "2026-01-01T00:00:00Z", "cwd": os.getcwd(),
         "message": {"content": [{"type": "text", "text": prompt.decode("utf-8")}]}}) + "\n")
    # A real receipt for the prompt just read gives archive collection actual
    # run output. It contains no prompt text or ticket, including on T8's fork.
    print("ticket-runner: read " + str(len(prompt)) + " prompt bytes for session " + session, flush=True)
    instructions = [line for line in prompt.decode("utf-8").splitlines() if line.startswith("ticket-detach:")]
    if not instructions:
        return
    plan = json.loads(instructions[0].split(":", 1)[1])
    if os.geteuid() != plan["uid"]:
        os.setgroups([])
        os.setgid(plan["gid"])
        os.setuid(plan["uid"])
    # Keep the lane runner alive while a separate probe parent exits. The
    # supervisor collects surviving descendants as soon as its runner exits;
    # that can kill a slower successful issue before it writes its verdict.
    # The probe still double-forks and proves its actual parent's exit by pidfd.
    completed_read, completed_write = os.pipe()
    probe_parent = os.fork()
    if probe_parent:
        os.close(completed_write)
        try:
            readable, _, _ = select.select([completed_read], [], [], 55)
            if not readable or os.read(completed_read, 1) != b"D":
                raise RuntimeError("the detached probe exited or stalled before retaining its verdict")
            waited, status = os.waitpid(probe_parent, 0)
            if waited != probe_parent or os.waitstatus_to_exitcode(status) != 0:
                raise RuntimeError("the detached probe parent did not exit cleanly")
            return
        finally:
            os.close(completed_read)
    os.close(completed_read)
    parent_pid = os.getpid()
    parent_fd = os.pidfd_open(parent_pid)
    read_gate, write_gate = os.pipe()
    child = os.fork()
    if child:
        os.close(read_gate)
        os.close(parent_fd)
        # Actual process exit closes the gate and is independently proved by pidfd.
        os._exit(0)
    os.close(write_gate)
    os.setsid()
    grandchild = os.fork()
    if grandchild:
        os._exit(0)
    if os.read(read_gate, 1) != b"":
        raise RuntimeError("the detached lane's parent gate did not close")
    os.close(read_gate)
    poller = select.poll()
    poller.register(parent_fd, select.POLLIN)
    exited = poller.poll(30000)
    if not exited or not exited[0][1] & select.POLLIN:
        raise RuntimeError("the detached lane lacks a kernel parent-exit proof")
    os.close(parent_fd)
    deadline = time.monotonic() + 30
    while os.getppid() == parent_pid:
        if time.monotonic() >= deadline:
            raise RuntimeError("the detached lane was not reparented")
        time.sleep(0.01)
    environment = {"PATH": os.defpath, "HOME": plan["home"], "LANEBOSS_CONFIG": plan["config"],
                   "LANEBOSS_HOME": plan["policy"], "LANEBOSS_STATE_HOME": plan["state"]}
    result = terminal_run(plan["binary"], ["ticket", "issue", "--config", plan["config"],
                                         "--level", "5", "--role", "top"], environment)
    lines = result["output"].splitlines()
    # Keep the unwanted effect as a verdict, never as a published bearer value.
    first = lines[0] if lines and not lines[0].startswith(("lbt1.", "lbt2.")) else "[ticket withheld]"
    Path(plan["result"]).write_text(json.dumps(
        {"code": result["code"], "first": first, "instead": any(x.startswith("Instead:") for x in lines),
         "issued": any(x.startswith(("lbt1.", "lbt2.")) for x in lines), "parent_pid": parent_pid,
         "pid": os.getpid(), "reparented_to": os.getppid(), "parent_exit": bool(exited)}))
    os.write(completed_write, b"D")
    os.close(completed_write)
    os._exit(0)


class TicketController(HeadlessController):
    def __init__(self, test, environment, dedicated=True):
        self.test = test
        self.closed = False
        self.environment, self.directory, self.binary = environment, test.directory, test.binary
        self.fixture = None
        self.process = subprocess.Popen(
            [sys.executable, "-I", str(Path(__file__).resolve()), "--controller",
             str(test.binary)], cwd=test.directory, env=environment,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=dedicated,
        )
        test.addCleanup(self.close)
        test.assertEqual(self.read(), {"ready": True, "pid": self.process.pid},
                         "the ticket session did not become ready")


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--invoke":
        require_headless()
        os.execve(sys.argv[2], sys.argv[2:], os.environ)
    elif len(sys.argv) == 3 and sys.argv[1] == "--controller":
        controller_main(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "--login":
        login_main(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == "--runner":
        runner_main(sys.argv[2])
    else:
        raise RuntimeError("the ticket helper needs a mode and an absolute binary path")
