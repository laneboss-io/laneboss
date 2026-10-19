"""Shared black-box command, controlling-terminal, and mutation helpers.

These helpers run only on the disposable test box. They start the supplied
binary as a real child and never import a product package or build a binary.
"""

import fcntl
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import termios
import tty


POINT_ROWS = {
    "event-allow-started": "CurrentLaneRows." + "test_append_grants_no_legacy",
    "legacy-turn-strict-only": "LegacyLaneRows.test_legacy_turn_delivery",
    "legacy-relationship-disabled": "LegacyLaneRows.test_legacy_supervisor_delivery",
    "caller-any-lane-session": "DarwinCommunicationRows.test_d3_other_session_refused",
    "caller-no-lane-session": "DarwinCommunicationRows.test_d1_preserved_sessions",
    "caller-lane-session-no-start": "DarwinCommunicationRows.test_d5_kernel_start_mismatch",
    "lane-no-subreaper": "LaneCommunicationRows.test_c2_detached_native",
    "starter-level-minus-one": "ReportIdentityRows.test_r1_recorded_identity_and_parent",
    "actor-fixed-laneboss": "ReportIdentityRows.test_r8_lifecycle_records_actual_actor",
    "peers-allow-all": "ReportMessages.test_R2_cross_supervisor_refusal",
    "mail-actor-fixed-supervisor": "ReportMessages.test_R3_peer_delivery_has_lane_actor",
    "caller-trust-env": "ReportMessages.test_R4_message_bypass_refusals",
    "report-stop-at-failure": "ReportMessages.test_R5_discord_500",
    "report-drop-without-supervisor": "ReportMessages.test_R6_human_fallback_in_dashboard",
    "orghook-boundary-before-policy": "OrgHookBoundaryRows.test_installed_push_refusal",
    "orghook-boundary-repository-path": "OrgHookBoundaryRows.test_recorded_worktree_write_allowed",
}


def mutation_selection(directory):
    supplied = json.loads(os.environ.get("LANEBOSS_FAULTS") or "{}")
    if not isinstance(supplied, dict):
        raise RuntimeError("the mutation request must be an object")
    selected = os.environ.get("LANEBOSS_REPORT_MUTANT") or supplied.get("point", "")
    if selected and selected not in POINT_ROWS:
        raise RuntimeError("unknown report mutation point")
    if supplied.get("point") and supplied["point"] != selected:
        raise RuntimeError("the mutation selectors disagree")
    marker = (os.environ.get("LANEBOSS_REPORT_MARKER") or supplied.get("marker")
              or str(directory / "mutation-reached"))
    marker = Path(marker)
    if not marker.is_absolute():
        raise RuntimeError("the report mutation marker must be an absolute path")
    return selected, marker


def fault_environment(point, selected, marker):
    if not point or point != selected:
        return {}
    return {"LANEBOSS_FAULTS": json.dumps({"point": point, "marker": str(marker)})}


def request_environment(request, environment):
    selected = dict(environment)
    if "role" in request:
        if request["role"] is None:
            selected.pop("LANEBOSS_ROLE", None)
        else:
            selected["LANEBOSS_ROLE"] = request["role"]
    for name in request.get("unset", []):
        selected.pop(name, None)
    selected.update(request.get("environment", {}))
    return selected


def run_request(request, binary, environment, cwd):
    result = subprocess.run(
        [str(request.get("binary", binary)), *request["args"]], cwd=cwd,
        env=request_environment(request, environment),
        input=request.get("stdin", request.get("input", "")),
        capture_output=True, text=True, encoding="utf-8", timeout=90,
        start_new_session=request.get("detach", False),
    )
    return {"code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def controller_main(binary):
    # A real controlling terminal and a persistent session parent authenticate
    # the human and the role tickets minted by the actual start command.
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    environment = dict(os.environ)
    background = []
    print(json.dumps({"ready": True}), flush=True)
    try:
        for line in sys.stdin:
            request = json.loads(line)
            if request.get("quit"):
                break
            if request.get("background") or request.get("serve"):
                process = subprocess.Popen(
                    [str(request.get("binary", binary)), *request["args"]], cwd=os.getcwd(),
                    env=request_environment(request, environment),
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, encoding="utf-8",
                )
                background.append(process)
                readable, _, _ = select.select([process.stdout], [], [], 30)
                if not readable:
                    raise RuntimeError("background command did not advertise readiness")
                ready = process.stdout.readline()
                if not ready:
                    raise RuntimeError("background command exited before readiness")
                if process.poll() is not None:
                    raise RuntimeError("background command ended at readiness")
                response = {"code": 0, "ready": ready, "stdout": ready.strip(),
                            "stderr": "", "pid": process.pid, "exit": process.poll()}
            else:
                response = run_request(request, binary, environment, os.getcwd())
                if response["code"] == 0 and request.get("role"):
                    environment["LANEBOSS_ROLE"] = request["role"]
            print(json.dumps(response), flush=True)
    finally:
        for process in background:
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=15)


class TerminalController:
    def __init__(self, test, binary=None, environment=None, directory=None, _service_role=False):
        self.test = test
        self.environment = test.environment if environment is None else environment
        self.directory = test.directory if directory is None else directory
        self.binary = test.binary if binary is None else binary
        self.closed = False
        self.delegate = None
        self.fixture = None
        from ticket_fixture import fixture_for, service_rows
        if service_rows(test, self.environment):
            if not _service_role:
                from ticket_actors import ServiceActors
                self.delegate = ServiceActors(test, self.binary, self.environment, self.directory)
                test.addCleanup(self.close)
                return
            self.fixture = fixture_for(test)
            self.environment = self.fixture.actor_environment(self.environment["LANEBOSS_CONFIG"], self.environment)
            self.binary = self.fixture.actor_binary(self.binary)
        helper = self.fixture.directory / "reportsupport.py" if self.fixture is not None else Path(__file__).resolve()
        self.master, slave = pty.openpty()
        tty.setraw(slave)
        self.process = subprocess.Popen(
            [str(self.fixture.python) if self.fixture is not None else sys.executable, "-I", str(helper), "--controller", str(self.binary)],
            cwd=self.directory, env=self.environment,
            stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", start_new_session=True,
            preexec_fn=self.fixture.demote(self.fixture.human_uid) if self.fixture is not None else None,
        )
        os.close(slave)
        test.addCleanup(self.close)
        test.assertEqual(self.read(), {"ready": True}, "the terminal fixture did not become ready")

    def read(self):
        readable, _, _ = select.select([self.process.stdout], [], [], 100)
        self.test.assertTrue(readable, "the terminal fixture did not return a command result")
        line = self.process.stdout.readline()
        self.test.assertTrue(line, "the terminal fixture exited before returning a command result")
        return json.loads(line)

    def request(self, args, **options):
        if self.delegate is not None:
            result = self.delegate.request(args, **options)
            self.last_arguments = self.delegate.last_arguments
            self.last_binary = self.delegate.last_binary
            return result
        if self.fixture is not None:
            self.fixture.prepare_actor_files()
            if "binary" in options:
                options["binary"] = str(self.fixture.actor_binary(options["binary"]))
        from ticket_fixture import with_registration
        args = with_registration(self.test, args, self.environment)
        self.last_arguments = list(map(str, args))
        self.last_binary = str(options.get("binary", self.binary))
        request = {"args": list(map(str, args)), **options}
        if self.fixture is not None and args and args[0] == "start" and "--role" in args:
            # A requested role label is controller metadata until registration
            # succeeds. Explicit environment overrides remain actual CLI input.
            request["role"] = None
        os.write(self.master, (json.dumps(request) + "\n").encode("utf-8"))
        return self.read()

    def call(self, *args, role=None, code=0, detach=False, input_text="", serve=False):
        result = self.request(args, role=role, detach=detach, stdin=input_text, serve=serve)
        self.test.assertEqual(result["code"], code, result["stderr"])
        return result

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.delegate is not None:
            self.delegate.close()
            return
        try:
            if self.process.poll() is None:
                os.write(self.master, b'{"quit":true}\n')
            try:
                self.process.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate(timeout=5)
                self.test.fail("the terminal fixture did not shut down within its deadline")
            self.test.assertEqual(self.process.returncode, 0, "the terminal fixture failed during collection")
        finally:
            os.close(self.master)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--controller":
        raise RuntimeError("the helper requires --controller and an absolute binary path")
    controller_main(sys.argv[2])
