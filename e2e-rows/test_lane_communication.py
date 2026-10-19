"""Communication from real running lanes and their detached descendants.

Only the agent runner is a stand-in. All product operations use LANEBOSS_BIN.
Run on the disposable Linux box; LANEBOSS_COMMS_EVIDENCE retains full fixtures.
"""

import hashlib
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
from orgsupport import ROLES
from reportsupport import TerminalController, run_request
from reportsupport import fault_environment
from commsupport import wait_file


class LaneCommunicationRows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The composed LB-235 fixture reads LANEBOSS_BIN in its own setUpClass; run it once here.
        messages.ReportMessages.setUpClass()

    def setUp(self):
        self.assertEqual(sys.platform, "linux", "communication runtime rows require the Linux box")
        evidence = os.environ.get("LANEBOSS_COMMS_EVIDENCE", "")
        self.assertTrue(evidence and Path(evidence).is_absolute(),
                        "LANEBOSS_COMMS_EVIDENCE must name an absolute evidence directory")
        self.evidence = Path(evidence)
        self.evidence.mkdir(parents=True, exist_ok=True)
        # Compose the existing LB-235 fixture without rediscovering its tests.
        self.fixture = messages.ReportMessages(methodName="runTest")
        selected_binary = "LANEBOSS_FAULTS_BIN" if self._testMethodName == "test_c8_linux_session_fallback" else "LANEBOSS_BIN"
        self.fixture.binary = messages.executable(selected_binary)
        self.fixture.evidence_directory = self.evidence
        self.fixture.addCleanup = self.addCleanup
        self.fixture.setUp()

    def prepare(self, portable=False, reporter_environment=None):
        f = self.fixture
        if portable:
            f.environment["LANEBOSS_PROCESSES"] = "portable"
        f.environment.update(f.faults(f.mutant))
        # This controller gets the same mode as every lane and state reader.
        f.human = TerminalController(f)
        # Cleanups run last-in first-out: stop the lanes through this controller before it closes, then
        # forget them so the fixture's own earlier stop_lanes cleanup has nothing left to do.
        def stop_and_forget():
            f.stop_lanes()
            f.started_lanes.clear()
        self.addCleanup(stop_and_forget)
        f.start_lane("boss", supervisor=None, level=4)
        for lane in ("reporter", "peer"):
            work = f.directory / "worktrees" / lane
            work.mkdir(parents=True)
            f.worktrees[lane] = work
            brief = work / "brief.md"
            brief.write_text("# Communication descendant fixture\n", encoding="utf-8")
            result = f.lane_request("boss", ["lane", "start", "--config", "rows", "--lane", lane,
                                             "--worktree", work, "--brief", brief,
                                             "--runner", "row-runner", "--model", "row-runner-model-1",
                                             "--turns", "--level", "3", "--role", ROLES[3]],
                                    environment=(reporter_environment or {}) if lane == "reporter" else {})
            self.assertEqual(result["code"], 0, result["stderr"])
            f.started_lanes.append(lane)
            f.await_value(lambda work=work: (work / "ready.json").is_file(), "nested runner never became ready")
            started = f.lane_events(lane, "lane.started")[-1]
            self.assertEqual((started["actor"], started["payload"]["starter"]), ("lane:boss", "lane:boss"))
        started = f.lane_events("reporter", "lane.started")[-1]
        record = f.states / "rows" / "lanes" / "reporter" / "runs" / (started["payload"]["launch"] + ".json")
        self.run_record_path = record
        self.run_record = json.loads(record.read_text(encoding="utf-8"))

    def document(self, name):
        path = self.fixture.worktrees["reporter"] / (name + ".md")
        path.write_text("# " + name + "\n\n" + uuid.uuid4().hex + " — complete message\n", encoding="utf-8")
        return path

    def assert_mail(self, lane, receipt, data):
        f = self.fixture
        events = [event for event in f.lane_events(lane, "lane.mailed")
                  if event["payload"]["sequence"] == receipt["sequence"]]
        self.assertEqual(len(events), 1, "mail must have exactly one real announcement")
        event = events[0]
        self.assertEqual((event["actor"], event["payload"]["sender"]), ("lane:reporter", "lane:reporter"))
        self.assertEqual((event["payload"]["sha256"], event["payload"]["bytes"]),
                         (hashlib.sha256(data).hexdigest(), len(data)))
        self.assertEqual(Path(receipt["file"]).read_bytes(), data)

    def assert_report(self, response, path):
        self.assertEqual(response["code"], 0, "detached report lost identity: " + response["stderr"])
        outcomes = {item["channel"]: item for item in map(json.loads, response["stdout"].splitlines())}
        self.assertEqual(outcomes["dashboard"]["status"], "delivered")
        self.assertEqual(outcomes["terminal"]["status"], "delivered")
        report_id = outcomes["dashboard"]["report_id"]
        sent = [event for event in self.fixture.events() if event["kind"] == "report.sent"
                and event["payload"]["report_id"] == report_id]
        self.assertEqual(len(sent), 1)
        self.assertEqual((sent[0]["actor"], sent[0]["payload"]["from"], sent[0]["payload"]["to"]),
                         ("lane:reporter", "lane:reporter", "lane:boss"))
        self.assertEqual(sent[0]["payload"]["text"], path.read_text(encoding="utf-8"))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        mailed = [event for event in self.fixture.lane_events("boss", "lane.mailed")
                  if event["payload"]["sha256"] == digest]
        self.assertEqual(len(mailed), 1)
        payload = mailed[0]["payload"]
        mail = self.fixture.states / "rows" / "lanes" / "boss" / "mail" / (
            "{:09d}-{}".format(payload["sequence"], digest))
        self.assert_mail("boss", {"sequence": payload["sequence"], "file": str(mail)}, path.read_bytes())

    def paths(self, name):
        report = self.document(name + "-report")
        send = self.document(name + "-send")
        return report, send, [
            {"args": ["report", "--config", "rows", "--file", str(report)]},
            {"args": ["lane", "send", "--config", "rows", "--lane", "peer", "--file", str(send)]},
        ]

    def consume_mail(self, lane, expected):
        f = self.fixture
        ready_file = f.worktrees[lane] / "ready.json"
        previous = json.loads(ready_file.read_text(encoding="utf-8"))
        result = f.human.request(["lane", "stop", "--config", "rows", "--lane", lane])
        self.assertEqual(result["code"], 0, result["stderr"])
        f.await_value(lambda: f.idle_status(lane), "recipient did not stop")
        (f.worktrees[lane] / "fixture-finish").touch()
        result = f.human.request(["lane", "turn", "--config", "rows", "--lane", lane])
        self.assertEqual(result["code"], 0, result["stderr"])
        f.await_value(lambda: f.lane_events(lane, "lane.delivered"), "recipient never delivered the actual mail")

        def next_prompt():
            current = json.loads(ready_file.read_text(encoding="utf-8"))
            return current if current["prompt_file"] != previous["prompt_file"] else None

        ready = f.await_value(next_prompt, "recipient runner never received the next turn's prompt")
        prompt = Path(ready["prompt_file"]).read_bytes()
        for data in expected:
            self.assertIn(data, prompt, "recipient runner did not receive the whole message")
        ended = [event for event in f.lane_events(lane, "lane.ended") if event["payload"]["run"] == 2]
        self.assertEqual(len(ended), 1)
        self.assertEqual((ended[0]["payload"]["reason"], ended[0]["payload"]["exit_code"],
                          ended[0]["payload"]["survivors"]), ("exit", 0, 0))

    def test_c1_running_lane_paths(self):
        self.prepare()
        f = self.fixture
        report, send, requests = self.paths("running")
        self.assert_report(f.lane_request("reporter", requests[0]["args"]), report)
        response = f.lane_request("reporter", requests[1]["args"])
        self.assertEqual(response["code"], 0, response["stderr"])
        self.assert_mail("peer", json.loads(response["stdout"]), send.read_bytes())
        upward = self.document("running-upward")
        response = f.lane_request("reporter", ["lane", "send", "--config", "rows", "--lane", "boss",
                                               "--file", upward], unset=["LANEBOSS_LANE"])
        self.assertEqual(response["code"], 0, response["stderr"])
        self.assert_mail("boss", json.loads(response["stdout"]), upward.read_bytes())
        note = self.fixture.worktrees["reporter"] / "event.json"
        note.write_text(json.dumps({"kind": "test.note", "lane": "reporter", "actor": "cli",
                                    "protocol_version": "1.3.0", "payload": {"text": send.read_text()}}),
                        encoding="utf-8")
        response = f.lane_request("reporter", ["event", "append", "--config", "rows", "--file", note])
        self.assertEqual(response["code"], 0, response["stderr"])
        self.assertEqual(f.lane_events("reporter", "test.note")[-1]["actor"], "lane:reporter")
        self.consume_mail("peer", [send.read_bytes()])
        self.consume_mail("boss", [report.read_bytes(), upward.read_bytes()])
        verified = f.cli("state", "verify", "--config", "rows")
        self.assertEqual(verified["code"], 0, verified["stderr"])
        self.assertTrue(json.loads(verified["stdout"])["ok"])

    def detached_rows(self, portable, turn=False):
        self.prepare(portable)
        f = self.fixture
        if turn:
            ready = f.worktrees["reporter"] / "ready.json"
            old_pid = json.loads(ready.read_text(encoding="utf-8"))["pid"]
            result = f.human.request(["lane", "stop", "--config", "rows", "--lane", "reporter"])
            self.assertEqual(result["code"], 0, result["stderr"])
            f.await_value(lambda: f.idle_status("reporter"), "reporter did not stop before turn")
            wake = f.worktrees["boss"] / "wake.md"
            wake.write_text("# Continue communication from the next turn\n", encoding="utf-8")
            result = f.lane_request("boss", ["lane", "send", "--config", "rows", "--lane", "reporter",
                                           "--file", wake])
            self.assertEqual(result["code"], 0, result["stderr"])
            result = f.human.request(["lane", "turn", "--config", "rows", "--lane", "reporter"])
            self.assertEqual(result["code"], 0, result["stderr"])
            self.assertEqual(json.loads(result["stdout"])["run"], 2)
            f.await_value(lambda: json.loads(ready.read_text(encoding="utf-8"))["pid"] != old_pid,
                          "turn runner never became ready")
            started = f.lane_events("reporter", "lane.started")[-1]
            self.assertEqual(started["payload"]["run"], 2)
            record = f.states / "rows" / "lanes" / "reporter" / "runs" / (started["payload"]["launch"] + ".json")
            self.run_record = json.loads(record.read_text(encoding="utf-8"))
        reports, sends = [], []
        for mode in ("background", "nohup", "setsid", "double-fork"):
            with self.subTest(mode=mode, portable=portable):
                report, send, requests = self.paths(mode)
                # Removing labels must leave kernel ancestry as the proof.
                for request in requests:
                    request["unset"] = ["LANEBOSS_LANE", "LANEBOSS_ROLE", "LANEBOSS_INSTANCE", "LANEBOSS_SESSION"]
                result = f.lane_request("reporter", [], communication_detach=mode, requests=requests)
                f.mutation_reached("lane-no-subreaper")
                self.assertEqual(result["launcher_exit"], 0)
                self.assert_report(result["responses"][0], report)
                response = result["responses"][1]
                self.assertEqual(response["code"], 0, "detached send lost identity: " + response["stderr"])
                self.assert_mail("peer", json.loads(response["stdout"]), send.read_bytes())
                identity = result["identity"]
                self.assertEqual(identity["ppid"], self.run_record["supervisor"]["pid"],
                                 "detached caller did not reparent to its recorded lane supervisor")
                self.assertEqual(identity["pgid"], identity["pid"])
                self.assertNotEqual(identity["ppid"], result["launcher_pid"])
                if mode == "setsid":
                    self.assertEqual(identity["sid"], identity["pid"])
                elif mode == "double-fork":
                    self.assertNotEqual(identity["sid"], identity["pid"])
                elif mode == "nohup":
                    self.assertTrue(identity["hup_ignored"], "nohup did not ignore SIGHUP")
                reports.append(report.read_bytes())
                sends.append(send.read_bytes())
        # Each queued message must reach a real recipient prompt as well.
        if len(reports) == 4:
            self.consume_mail("peer", sends)
            self.consume_mail("boss", reports)

    def test_c2_detached_native(self):
        self.detached_rows(portable=False)

    def test_c3_detached_portable(self):
        self.detached_rows(portable=True)

    def test_c6_detached_turn_native(self):
        self.detached_rows(portable=False, turn=True)

    def test_c7_detached_turn_portable(self):
        self.detached_rows(portable=True, turn=True)

    def test_c4_non_descendants_stay_refused(self):
        self.prepare()
        f = self.fixture
        report, send, requests = self.paths("unrelated")
        before = f.events()
        for labels in ({}, {"LANEBOSS_LANE": "reporter"},
                       {"LANEBOSS_LANE": "reporter", "LANEBOSS_RUN": "1"}):
            for request in requests:
                with self.subTest(labels=bool(labels), command=request["args"][0]):
                    result = run_request({**request, "detach": True, "environment": labels},
                                         f.binary, f.environment, f.worktrees["reporter"])
                    self.assertEqual(result["code"], 2, "an unrelated caller was admitted")
                    self.assertIn("refused:", result["stderr"])
                    self.assertEqual(f.events(), before, "an unrelated caller wrote events")
        control = f.lane_request("reporter", requests[1]["args"], unset=["LANEBOSS_LANE"])
        self.assertEqual(control["code"], 0, control["stderr"])
        self.assert_mail("peer", json.loads(control["stdout"]), send.read_bytes())

    def test_c5_required_ask_contract(self):
        """Acceptance gap: this release tree has no send --ask option.

        Keep the requested successful-delivery assertion visible. This row
        must fail on the current parser; no success or feature is fabricated.
        """
        self.require_cli_send_ask_support()
        self.prepare()
        path = self.document("required-ask")
        response = self.fixture.lane_request("reporter", ["lane", "send", "--config", "rows", "--lane", "peer",
                                                         "--ask", "--file", path])
        self.assertEqual(response["code"], 0, "required send --ask delivery is absent: " + response["stderr"])
        self.assert_mail("peer", json.loads(response["stdout"]), path.read_bytes())

    def test_c8_linux_session_fallback(self):
        """An unsampled orphan keeps its SID when tagged kernel adoption is disabled."""
        f = self.fixture
        marker = f.directory / "fallback-subreaper-marker"
        self.prepare(portable=True, reporter_environment=fault_environment(
            "lane-no-subreaper", "lane-no-subreaper", marker))
        self.assertTrue(marker.is_file(), "kernel subreaper disabling did not reach its tagged call site")
        report, send, requests = self.paths("linux-session-fallback")
        for request in requests:
            request["unset"] = ["LANEBOSS_LANE", "LANEBOSS_ROLE", "LANEBOSS_INSTANCE", "LANEBOSS_SESSION"]
        parked = None
        for attempt in range(8):
            candidate = f.lane_request("reporter", [], communication_detach="background",
                                       communication_park=True, requests=requests)
            identity = candidate["identity"]
            self.addCleanup(self.collect_linux_child, identity)
            stamp = self.run_record_path.stat().st_mtime_ns
            samples, deadline = 0, time.monotonic() + 15
            while samples < 2:
                current = self.run_record_path.stat().st_mtime_ns
                if current != stamp:
                    stamp, samples = current, samples + 1
                self.assertLess(time.monotonic(), deadline, "portable run record did not advance through two samples")
                time.sleep(0.02)
            record = json.loads(self.run_record_path.read_text(encoding="utf-8"))
            if not any(item["pid"] == identity["pid"] for item in record["processes"]):
                parked = candidate
                self.run_record = record
                break
            self.collect_linux_child(identity)
        self.assertIsNotNone(parked, "could not isolate an unsampled Linux session-fallback caller")
        job = Path(parked["job"])
        (job / "release").touch()
        wait_file(job / "result.json", time.monotonic() + 30)
        result = json.loads((job / "result.json").read_text(encoding="utf-8"))
        self.assertNotEqual(result["identity"]["ppid"], self.run_record["supervisor"]["pid"])
        self.assertEqual(result["identity"]["sid"], self.run_record["runner"]["pid"])
        self.assert_report(result["responses"][0], report)
        self.assertEqual(result["responses"][1]["code"], 0, result["responses"][1]["stderr"])
        self.assert_mail("peer", json.loads(result["responses"][1]["stdout"]), send.read_bytes())

    def collect_linux_child(self, identity):
        def alive():
            path = Path("/proc") / str(identity["pid"]) / "stat"
            try:
                data = path.read_text(encoding="utf-8")
            except FileNotFoundError:
                return False
            parts = data[data.rindex(")") + 1:].split()
            return parts[0] != "Z" and parts[19] == identity["start"]
        if alive():
            os.kill(identity["pid"], signal.SIGKILL)
        deadline = time.monotonic() + 10
        while alive():
            self.assertLess(time.monotonic(), deadline, "the isolated Linux fallback child did not exit")
            time.sleep(0.02)

    def require_cli_send_ask_support(self):
        """Fail visibly until the decision-guide integration supplies --ask."""
        response = self.fixture.cli("lane", "send", "--config", "rows", "--help")
        self.assertEqual(response["code"], 0, response["stderr"])
        flags = response["stdout"].replace("[", " ").replace("]", " ").split()
        self.assertIn("--ask", flags, "CLI_SEND_ASK_SUPPORTED: the built CLI lacks lane send --ask")


if __name__ == "__main__":
    unittest.main(verbosity=2)
