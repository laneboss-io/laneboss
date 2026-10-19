"""Real pipe-only sessions for headless rows; run only on the test box."""

import errno
import json
import os
from pathlib import Path
import select
import subprocess
import sys


def require_headless():
    # Check the controlling terminal, not merely whether stdin is redirected.
    try:
        descriptor = os.open("/dev/tty", os.O_RDONLY | os.O_NOCTTY)
    except OSError as error:
        if error.errno not in (errno.ENXIO, errno.ENODEV):
            raise
    else:
        os.close(descriptor)
        raise RuntimeError("the headless fixture acquired a controlling terminal")
    data = Path("/proc/self/stat").read_text(encoding="utf-8")
    fields = data[data.rindex(")") + 1:].split()
    if int(fields[4]) != 0:
        raise RuntimeError("the kernel reports a controlling terminal")


def controller_main(binary):
    require_headless()
    print(json.dumps({"ready": True, "pid": os.getpid()}), flush=True)
    for line in sys.stdin:
        request = json.loads(line)
        if request.get("quit"):
            return
        environment = dict(os.environ)
        environment.update(request.get("environment", {}))
        for key in request.get("unset", []):
            environment.pop(key, None)
        # setsid runs the short verifier; exec preserves that process and its
        # ancestry when replacing it with the real product. No PTY is allocated.
        result = subprocess.run(
            [sys.executable, "-I", str(Path(__file__).resolve()), "--invoke",
             binary, *request["args"]],
            env=environment, input=request.get("stdin", ""),
            capture_output=True, text=True, encoding="utf-8", timeout=90,
            start_new_session=True,
        )
        print(json.dumps({"code": result.returncode, "stdout": result.stdout,
                          "stderr": result.stderr}), flush=True)


class HeadlessController:
    def __init__(self, test, environment=None, directory=None, binary=None):
        self.test = test
        self.closed = False
        self.environment = test.environment if environment is None else environment
        self.directory = test.directory if directory is None else directory
        self.binary = test.binary if binary is None else binary
        from ticket_fixture import fixture_for, service_rows
        self.fixture = None
        if service_rows(test, self.environment):
            self.fixture = fixture_for(test)
            self.environment = self.fixture.actor_environment(self.environment["LANEBOSS_CONFIG"], self.environment)
            self.binary = self.fixture.actor_binary(self.binary)
        helper = self.fixture.directory / "headless_support.py" if self.fixture is not None else Path(__file__).resolve()
        self.process = subprocess.Popen(
            [str(self.fixture.python) if self.fixture is not None else sys.executable, "-I", str(helper), "--controller",
             str(self.binary)], cwd=self.directory, env=self.environment,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", start_new_session=True,
            preexec_fn=self.fixture.demote(self.fixture.human_uid) if self.fixture is not None else None,
        )
        test.addCleanup(self.close)
        test.assertEqual(self.read(), {"ready": True, "pid": self.process.pid},
                         "the pipe-only session did not become ready")

    def read(self):
        readable, _, _ = select.select([self.process.stdout], [], [], 100)
        self.test.assertTrue(readable, "the headless session did not answer")
        line = self.process.stdout.readline()
        self.test.assertTrue(line, "the headless session exited before answering")
        return json.loads(line)

    def request(self, args, **options):
        from ticket_fixture import with_registration
        if self.fixture is not None:
            self.fixture.prepare_actor_files()
        args = with_registration(self.test, args, self.environment)
        self.last_arguments = list(map(str, args))
        self.last_binary = str(self.binary)
        request = {"args": list(map(str, args)), **options}
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        return self.read()

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.process.poll() is None:
            self.process.stdin.write('{"quit":true}\n')
            self.process.stdin.flush()
        try:
            self.process.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.communicate(timeout=5)
            self.test.fail("the headless session missed its collection deadline")
        self.test.assertEqual(self.process.returncode, 0,
                              "the headless session failed during collection")


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--invoke":
        require_headless()
        os.execve(sys.argv[2], sys.argv[2:], os.environ)
    elif len(sys.argv) == 3 and sys.argv[1] == "--controller":
        controller_main(sys.argv[2])
    else:
        raise RuntimeError("the helper needs a mode and an absolute binary path")
