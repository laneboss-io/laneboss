"""Scalar capacity regressions; run with an already built LANEBOSS_BIN on Linux.

No service, credential, installation or Git operation is used. Every fixture,
request, command result and log is retained under LANEBOSS_JUDGE_CAPACITY_EVIDENCE
(or a printed temporary evidence directory). Test again with the release-base
binary: the exact-fit assertions must fail because its scalar reserve is 4096.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid


def setUpModule():
    if not sys.platform.startswith("linux"):
        raise RuntimeError("judge capacity rows require the disposable Linux test machine")


class JudgeCapacityRows(unittest.TestCase):
    def setUp(self):
        self.binary = Path(os.environ["LANEBOSS_BIN"]).resolve(strict=True)
        root = os.environ.get("LANEBOSS_JUDGE_CAPACITY_EVIDENCE")
        root = Path(root) if root else Path(tempfile.mkdtemp(prefix="lb-s0-judges-evidence-"))
        self.case = root / (self._testMethodName + "-" + uuid.uuid4().hex)
        self.case.mkdir(parents=True)
        print("Judge capacity evidence:", self.case, flush=True)
        self.records = self.case / "adapter-records"
        self.records.mkdir()
        self.release = self.case / "release"
        self.processes = []
        self.sequence = 0
        self.env = {"PATH": os.defpath, "HOME": str(self.case / "home"),
                    "LANEBOSS_HOME": str(self.case / "config"),
                    "LANEBOSS_STATE_HOME": str(self.case / "state"), "LANEBOSS_CONFIG": "capacity"}
        config = self.case / "config" / "configs" / "capacity"
        config.mkdir(parents=True)
        adapter = Path(__file__).resolve().parents[1] / "internal" / "judge" / "testdata" / "capacity_adapter.py"
        tables = []
        for name, mode in (("fast", "answer"), ("wait", "wait")):
            command = [sys.executable, str(adapter), str(self.records), str(self.release), mode]
            tables.append('[judges.' + name + ']\ncommand = ' + json.dumps(command) + '\ntimeout_seconds = 25\n')
        (config / "config.toml").write_text('schema_version = 1\nname = "capacity"\n'
                                           '[runners.unused]\ncommand = ["/bin/true", "{brief}"]\n' + "".join(tables))
        self.prompt = self.case / "prompt.txt"
        self.subject = self.case / "subject.txt"
        self.prompt.write_text("Is this a capacity check?")
        self.subject.write_text("actual subject text")
        self.log = self.case / "state/capacity/judges/egress.jsonl"

    def tearDown(self):
        self.release.write_text("release the adapter")
        for process in self.processes:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=10)
        self.wait_until(lambda: all(not self.provider_alive(p["pid"]) for p in self.calls()))

    @staticmethod
    def provider_alive(pid):
        status = Path("/proc") / str(pid) / "status"
        if not status.exists():
            return False
        return not any(line.startswith("State:") and "Z" in line for line in status.read_text().splitlines())

    def wait_until(self, predicate):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.02)
        self.fail("bounded wait did not reach its condition")

    def calls(self):
        return [json.loads(path.read_text()) for path in self.records.glob("*.json")]

    def ask_args(self, judge="fast"):
        return ["judge", "ask", "--config", "capacity", "--judge", judge,
                "--question", "capacity.check", "--prompt-file", str(self.prompt),
                "--subject", "text=" + str(self.subject)]

    def cli(self, args, limit=None, code=0):
        environment = dict(self.env)
        if limit is not None:
            environment["LANEBOSS_JUDGE_MAX_EGRESS_BYTES"] = str(limit)
        result = subprocess.run([str(self.binary), *args], env=environment, capture_output=True, timeout=35)
        self.sequence += 1
        (self.case / ("command-%02d.json" % self.sequence)).write_text(json.dumps({
            "argv": args, "limit": limit, "exit": result.returncode,
            "stdout": result.stdout.decode(), "stderr": result.stderr.decode()}))
        self.assertEqual(result.returncode, code, result.stderr.decode())
        return result

    def boundary(self, exact):
        before, calls = self.log.read_bytes(), len(self.calls())
        refused = self.cli(self.ask_args(), exact - 1, code=7)
        self.assertEqual(refused.stdout, b"")
        self.assertIn(b"nothing was asked", refused.stderr)
        self.assertIn(b"is full", refused.stderr)
        self.assertEqual((self.log.read_bytes(), len(self.calls())), (before, calls))
        self.assertEqual(self.cli(["judge", "egress", "--config", "capacity"], exact - 1).stdout, before)
        answer = json.loads(self.cli(self.ask_args(), exact).stdout)
        self.assertEqual((answer["outcome"], answer["probability"]),
                         ("answered", len(self.subject.read_text()) % 10 / 10))
        self.assertEqual(len(self.calls()), calls + 1)
        self.assertLessEqual(self.log.stat().st_size, exact)
        self.assertEqual(self.cli(["judge", "egress", "--config", "capacity"], exact).stdout, self.log.read_bytes())

    def test_scalar_exact_fit(self):
        self.cli(self.ask_args())
        lines = self.log.read_bytes().splitlines(keepends=True)
        self.assertEqual(len(lines), 2)
        self.assertNotIn("outcome_reserve", json.loads(lines[0]))
        self.assertLessEqual(len(lines[1]), 1024)
        self.boundary(sum(map(len, lines)) + len(lines[0]) + 1024)

    def outstanding(self, killed):
        self.cli(self.ask_args())
        sent_length = len(self.log.read_bytes().splitlines(keepends=True)[0])
        process = subprocess.Popen([str(self.binary), *self.ask_args("wait")], env=self.env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.processes.append(process)
        self.wait_until(lambda: len(self.calls()) == 2)
        pending = json.loads(self.log.read_bytes().splitlines()[-1])["ask"]
        if killed:
            process.kill()
            stdout, stderr = process.communicate(timeout=10)
            (self.case / "killed-launcher.json").write_text(json.dumps({
                "exit": process.returncode, "stdout": stdout.decode(), "stderr": stderr.decode()}))
            self.assertLess(process.returncode, 0)
        exact = self.log.stat().st_size + sent_length + 2 * 1024
        self.boundary(exact)
        self.release.write_text("finish the pending request")
        if killed:
            events = [json.loads(line) for line in self.log.read_bytes().splitlines()]
            self.assertEqual([e["event"] for e in events if e["ask"] == pending], ["sent"])
        else:
            stdout, stderr = process.communicate(timeout=10)
            (self.case / "completed-launcher.json").write_text(json.dumps({
                "exit": process.returncode, "stdout": stdout.decode(), "stderr": stderr.decode()}))
            self.assertEqual(process.returncode, 0, stderr.decode())
            self.assertEqual(json.loads(stdout)["outcome"], "answered")
        self.assertLessEqual(self.log.stat().st_size, exact)
        remaining = 2 if killed else 1
        self.boundary(self.log.stat().st_size + sent_length + remaining * 1024)

    def test_running_scalar_retains_reserve(self):
        self.outstanding(killed=False)

    def test_killed_scalar_retains_reserve(self):
        self.outstanding(killed=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
