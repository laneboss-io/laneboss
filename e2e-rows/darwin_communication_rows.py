"""Darwin-only rows authorized by the detached-communication follow-up.

Invoke this module explicitly on macOS with already built binaries. It is kept
outside Linux test discovery; attempting to run it on another OS fails.
"""

import json
import os
from pathlib import Path
import signal
import sys
import time
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_report_messages as messages
from commsupport import wait_file
from darwin_process_support import kernel_process
from reportsupport import run_request


class DarwinCommunicationRows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform != "darwin":
            raise RuntimeError("these rows are explicitly Darwin-only; run the Linux rows on the Linux box")

    def setUp(self):
        evidence = os.environ.get("LANEBOSS_COMMS_EVIDENCE", "")
        self.assertTrue(evidence and Path(evidence).is_absolute(),
                        "LANEBOSS_COMMS_EVIDENCE must name an absolute evidence directory")
        f = messages.ReportMessages(methodName="runTest")
        f.binary = messages.executable("LANEBOSS_BIN")
        f.fixture_prefix = "lb-comms-darwin-"
        f.evidence_directory = Path(evidence)
        f.evidence_directory.mkdir(parents=True, exist_ok=True)
        f.addCleanup = self.addCleanup
        self.fixture = f
        f.setUp()
        f.start_lane("reporter", supervisor="mini-a")
        started = f.lane_events("reporter", "lane.started")[-1]
        self.record_path = f.states / "rows" / "lanes" / "reporter" / "runs" / (
            started["payload"]["launch"] + ".json")
        record = f.await_value(self.session_record, "runner kernel session identity was not recorded")
        self.runner = record["runner_session"]
        actual = kernel_process(self.runner["pid"])
        self.assertIsNotNone(actual)
        self.assertTrue(actual["alive"])
        self.assertEqual((record["runner"]["pid"], self.runner["pid"], self.runner["sid"]),
                         (actual["pid"], actual["pid"], actual["sid"]))
        self.assertEqual(self.runner["start"], actual["start"], "the run must retain exact kernel microseconds")
        self.assertEqual(self.runner["sid"], self.runner["pid"])

    def session_record(self):
        record = json.loads(self.record_path.read_text(encoding="utf-8"))
        return record if record.get("runner_session") else None

    def request(self, name, unset=False):
        path = self.fixture.worktrees["reporter"] / (name + ".md")
        path.write_text("# " + name + "\n\n" + uuid.uuid4().hex + " — complete report\n", encoding="utf-8")
        request = {"args": ["report", "--config", "rows", "--file", str(path)],
                   "environment": self.fixture.faults(self.fixture.mutant)}
        if unset:
            request["unset"] = ["LANEBOSS_LANE", "LANEBOSS_ROLE", "LANEBOSS_INSTANCE", "LANEBOSS_SESSION"]
        return path, request

    def detached(self, mode, requests, **options):
        return self.fixture.lane_request("reporter", [], communication_detach=mode,
                                         requests=requests, **options)

    def assert_orphan(self, result, same_session):
        identity = result["identity"]
        self.assertEqual(result["launcher_exit"], 0)
        self.assertEqual(identity["ppid"], 1, "the command must run after reparenting to launchd")
        self.assertNotEqual(identity["ppid"], result["launcher_pid"])
        self.assertEqual(identity["pgid"], identity["pid"], "a group match must not stand in for a session match")
        self.assertFalse(identity["controlling_terminal"])
        if same_session:
            self.assertEqual(identity["sid"], self.runner["pid"])
        else:
            self.assertNotEqual(identity["sid"], self.runner["pid"])

    def assert_delivered(self, response, path):
        self.fixture.mutation_reached("caller-no-lane-session")
        self.assertEqual(response["code"], 0, "preserved session lost lane identity: " + response["stderr"])
        outcomes = {item["channel"]: item for item in map(json.loads, response["stdout"].splitlines())}
        self.assertEqual(outcomes["dashboard"]["status"], "delivered")
        report_id = outcomes["dashboard"]["report_id"]
        events = [event for event in self.fixture.events() if event["kind"] == "report.sent"
                  and event["payload"]["report_id"] == report_id]
        self.assertEqual(len(events), 1)
        self.assertEqual((events[0]["actor"], events[0]["payload"]["from"], events[0]["payload"]["to"]),
                         ("lane:reporter", "lane:reporter", "supervisor:mini-a"))
        self.assertEqual(events[0]["payload"]["text"], path.read_text(encoding="utf-8"))

    def assert_refused(self, response, before):
        self.assertEqual(response["code"], 2, "a caller without a valid live lane session was admitted")
        self.assertIn("refused:", response["stderr"])
        self.assertEqual(self.fixture.events(), before, "a refused caller changed stored events")

    def test_d1_preserved_sessions(self):
        for mode in ("background", "nohup", "double-fork"):
            with self.subTest(mode=mode):
                path, request = self.request(mode)
                unlabeled_path, unlabeled = self.request(mode + "-unlabeled", unset=True)
                result = self.detached(mode, [request, unlabeled])
                self.assert_orphan(result, same_session=True)
                if mode == "nohup":
                    self.assertTrue(result["identity"]["hup_ignored"])
                self.assert_delivered(result["responses"][0], path)
                self.assert_delivered(result["responses"][1], unlabeled_path)

    def test_d2_setsid_orphan_refused(self):
        path, request = self.request("new-session")
        before = self.fixture.events()
        result = self.detached("setsid", [request])
        self.assert_orphan(result, same_session=False)
        self.assertEqual(result["identity"]["sid"], result["identity"]["pid"])
        self.assert_refused(result["responses"][0], before)
        control = self.detached("background", [request])
        self.assert_orphan(control, same_session=True)
        self.assert_delivered(control["responses"][0], path)

    def test_d3_other_session_refused(self):
        f = self.fixture
        before = f.events()
        for labels in ({}, {"LANEBOSS_LANE": "reporter", "LANEBOSS_RUN": "1"}):
            with self.subTest(labels=bool(labels)):
                _path, request = self.request("cross-session")
                request["environment"].update(labels)
                request["detach"] = True
                result = run_request(request, f.binary, f.environment, f.worktrees["reporter"])
                f.mutation_reached("caller-any-lane-session")
                self.assert_refused(result, before)
        path, request = self.request("same-session-control", unset=True)
        control = self.detached("background", [request])
        self.assert_orphan(control, same_session=True)
        self.assert_delivered(control["responses"][0], path)

    def process_alive(self, recorded):
        current = kernel_process(recorded["pid"])
        return current is not None and current["alive"] and current["start"] == recorded["start"]

    def collect_child(self, recorded):
        if self.process_alive(recorded):
            os.kill(recorded["pid"], signal.SIGKILL)
        deadline = time.monotonic() + 10
        while self.process_alive(recorded):
            self.assertLess(time.monotonic(), deadline, "the parked fixture child did not exit")
            time.sleep(0.02)

    def park_uncached_child(self, requests):
        # A legitimate old sampler can remember a helper before reparenting.
        # Keep a genuinely leftover child for D4; never edit the product record
        # or suppress the product's cleanup to manufacture a survivor.
        for attempt in range(8):
            parked = self.detached("background", requests, communication_park=True)
            identity = parked["identity"]
            self.addCleanup(self.collect_child, identity)
            observed = self.record_path.stat().st_mtime_ns
            samples = 0
            deadline = time.monotonic() + 15
            while samples < 2:
                stamp = self.record_path.stat().st_mtime_ns
                if stamp != observed:
                    observed, samples = stamp, samples + 1
                self.assertLess(time.monotonic(), deadline, "the run record did not advance through two real samples")
                time.sleep(0.02)
            record = json.loads(self.record_path.read_text(encoding="utf-8"))
            remembered = any(item["pid"] == identity["pid"] for item in record["processes"])
            if not remembered:
                actual = kernel_process(identity["pid"])
                self.assertIsNotNone(actual)
                self.assertEqual((actual["ppid"], actual["sid"]), (1, self.runner["pid"]))
                return parked
            self.collect_child(identity)
        self.fail("could not retain an unsampled leftover child for the runner-exit canary")

    def test_d4_runner_exit_refuses_leftover(self):
        f = self.fixture
        _path, request = self.request("after-runner-exit")
        _unlabeled_path, unlabeled = self.request("after-exit-unlabeled", unset=True)
        parked = self.park_uncached_child([request, unlabeled])
        (f.worktrees["reporter"] / "fixture-finish").touch()
        f.await_value(lambda: f.idle_status("reporter"), "the runner did not finish before the leftover reported")
        self.assertFalse(self.process_alive(self.runner), "the recorded session leader must have exited")
        self.assertTrue(self.process_alive(parked["identity"]), "the exit canary child must actually remain alive")
        ended = f.lane_events("reporter", "lane.ended")[-1]["payload"]
        self.assertEqual((ended["reason"], ended["exit_code"]), ("exit", 0))
        before = f.events()
        job = Path(parked["job"])
        (job / "release").touch()
        wait_file(job / "result.json", time.monotonic() + 30)
        result = json.loads((job / "result.json").read_text(encoding="utf-8"))
        self.assertEqual(result["identity"]["sid"], self.runner["pid"])
        for response in result["responses"]:
            self.assert_refused(response, before)

    def test_d5_kernel_start_mismatch(self):
        f = self.fixture
        path, request = self.request("kernel-start-mismatch", unset=True)
        record = self.session_record()
        supervisor = kernel_process(record["supervisor"]["pid"])
        self.assertIsNotNone(supervisor)
        self.assertTrue(supervisor["alive"])
        # Freeze this fixture's sampler during the stale-record canary so it
        # cannot replace the poisoned bytes. Neither the runner nor caller is
        # stopped, and the actual PID/start proof is restored before collection.
        os.kill(supervisor["pid"], signal.SIGSTOP)
        try:
            f.await_value(lambda: kernel_process(supervisor["pid"])["state"] == 4,
                          "fixture supervisor did not stop for the stale-record canary")
            original = self.record_path.read_bytes()
            poisoned = json.loads(original)
            poisoned["runner_session"]["start"] += "0"
            payload = json.dumps(poisoned).encode("utf-8")
            (f.worktrees["reporter"] / "poisoned-run-record.json").write_bytes(payload)
            self.record_path.write_bytes(payload)
            try:
                before = f.events()
                result = self.detached("background", [request])
                self.assert_orphan(result, same_session=True)
                f.mutation_reached("caller-lane-session-no-start")
                self.assert_refused(result["responses"][0], before)
            finally:
                self.record_path.write_bytes(original)
        finally:
            self.assertTrue(self.process_alive(supervisor), "the paused fixture supervisor changed identity")
            os.kill(supervisor["pid"], signal.SIGCONT)
        control = self.detached("background", [request])
        self.assert_orphan(control, same_session=True)
        self.assert_delivered(control["responses"][0], path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
