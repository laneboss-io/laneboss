"""J. `laneboss decisions <args>` behaves exactly like `python -m laneboss.decisions <args>`."""

import http.client
import json
import os
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile

from . import support
from ..decisions.support import GO_DECISIONS, decisions_go_binary

RECORD = {
    "id": "P-1", "kind": "decision", "asked_at": "2026-10-08T09:00:00Z", "answered_at": "2026-10-08T09:04:00Z",
    "project": "plain", "area": "plain", "topics": ["plain"],
    "question": {"text": "Should the launcher start the resident search?", "background": "plain"},
    "answer": {"verbatim": "Yes, the launcher starts the resident search.", "channel": "plain"},
    "scope": {"applies_to": "plain"}, "status": "in_force",
    "provenance": {"recorded_by": "plain", "recorded_at": "2026-10-08T09:05:00Z", "sources": []},
}


class UnixConnection(http.client.HTTPConnection):
    """An HTTP connection to a Unix socket."""

    def __init__(self, path):
        http.client.HTTPConnection.__init__(self, "localhost", timeout=30)
        self.unix_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.unix_path)


def setUpModule():
    support.install()


def tearDownModule():
    support.uninstall()


class DecisionsPassthroughTest(support.LauncherTest):
    def module(self, *arguments):
        environment = dict(self.environment, PYTHONPATH=str(support.ROOT / "src"), PYTHONDONTWRITEBYTECODE="1")
        program = [str(decisions_go_binary())]
        return subprocess.run(program + list(map(str, arguments)), cwd=str(self.directory),
                              env=environment, capture_output=True, text=True, encoding="utf-8", timeout=60)

    def same(self, *arguments, code=0):
        launcher = self.run_laneboss("decisions", *arguments, code=code)
        module = self.module(*arguments)
        self.assertEqual((launcher.returncode, launcher.stdout, launcher.stderr),
                         (module.returncode, module.stdout, module.stderr))
        return launcher

    def test_stats_matches_module(self):
        database = self.directory / "decisions.sqlite"
        initialized = self.module("init", "--db", database)
        self.assertEqual(initialized.returncode, 0, initialized.stderr)
        result = self.same("stats", "--db", database)
        self.assertEqual(json.loads(result.stdout)["records"], 0)
        other = self.directory / "other.sqlite"
        self.run_laneboss("decisions", "init", "--db", other)
        self.assertEqual(self.module("stats", "--db", other).stdout, result.stdout)
        self.same("verify", "--db", database)
        self.same("stats", "--db", self.directory / "absent.sqlite", code=2)
        self.same("frobnicate", code=2)
        self.same("--help")

    def test_serve_through_the_launcher(self):
        """`laneboss decisions serve`, started through the installed launcher, is the resident search: it makes its
        socket, prints its one ready line, answers a search over the socket with the bytes that `laneboss decisions
        search` prints, and on SIGTERM ends with exit 0 and removes its socket. Fails when the launcher's way in
        changes anything of it: a command that is not passed on, output that is held back, a signal that is lost."""
        database = self.directory / "decisions.sqlite"
        record = self.directory / "record.json"
        record.write_text(json.dumps(RECORD), encoding="utf-8")
        self.run_laneboss("decisions", "init", "--db", database)
        self.run_laneboss("decisions", "add", "--db", database, "--file", record)
        # A short directory of its own: the path of a Unix socket is limited to about 100 characters.
        short = tempfile.mkdtemp(prefix="lbs", dir="/tmp")
        self.addCleanup(shutil.rmtree, short, True)
        path = os.path.join(short, "run", "search.sock")
        process = subprocess.Popen(
            [str(self.command), "decisions", "serve", "--db", str(database), "--socket", path],
            cwd=str(self.directory), env=self.environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding="utf-8")

        def stop():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=30)
            process.stdout.close()
            process.stderr.close()

        self.addCleanup(stop)
        readable, _, _ = select.select([process.stdout], [], [], 60)
        self.assertTrue(readable, "the server printed no ready line in 60 seconds")
        ready = json.loads(process.stdout.readline())
        self.assertEqual((ready["ok"], ready["socket"], ready["pid"] > 0), (True, path, True))
        connection = UnixConnection(path)
        try:
            connection.request("GET", "/search?query=resident+search")
            reply = connection.getresponse()
            served = reply.read().decode("utf-8")
        finally:
            connection.close()
        expected = self.run_laneboss("decisions", "search", "resident search", "--db", database)
        self.assertEqual(reply.status, 200, served)
        self.assertEqual(served, expected.stdout)
        self.assertEqual([hit["record"]["id"] for hit in json.loads(served)], ["P-1"])
        process.send_signal(signal.SIGTERM)
        self.assertEqual(process.wait(timeout=30), 0, process.stderr.read())
        self.assertFalse(os.path.exists(path), "the socket was left behind")
