"""Both-driver flow and CLI reporting controls, on disposable Linux only.

The ports below supply fixture lanes, never an authenticated vendor session.
Bootstrap prerequisites stay unrun, so the component report cannot claim E2E
acceptance. The actual flow, capture reader, exception handler and reporter run.
"""

from contextlib import redirect_stderr, redirect_stdout
import copy
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

import reply_test as controls


serve, flow = controls.serve, controls.flow
Case = serve.Case


class FlowCases(unittest.TestCase):
    def invoke(self, fault=None):
        temporary = tempfile.TemporaryDirectory(prefix="lb-flow-rows-")
        self.addCleanup(temporary.cleanup)
        evidence = Path(temporary.name) / "evidence"
        source = Path(__file__).resolve().parents[2]
        args = SimpleNamespace(source=source, evidence=evidence, launch_request=None,
            agent_output=None, root_grants=None, suite="lifecycle", lane_inputs=None,
            config=None, boot=None, cleanup_native_control=False, egress_anthropic=True,
            real_claudock=True, item_case=None, canary_api_key=True,
            real_api_key_file=None, source_snapshot=False)
        built = []
        clock = controls.Clock()

        def factory(*values, **options):
            case = Case(*values, **options)
            # Exercise real-key routing on fixture data, without a key file.
            case.real_api_key, case.reply_mode = True, "real-key"
            case.checks = flow.checks(reply=True)
            case.rows = {name: {"check": name, "result": "fail", "presence": serve.presence(name),
                               "observed": {"executed": False, "reason": "component prerequisite unrun"}}
                         for name in case.checks}
            probes, requests, reads = {}, {}, []
            owner = uuid.uuid4().hex
            for name, driver in flow.DRIVERS:
                raw = None if name == "claudock" else lambda p: (p.result_id + " codex fixture reply\n").encode()
                probe = controls.Probe(self, clock, real=True, readable=True, raw=raw)
                probe.owner, probe.case = owner, case
                probe.lane.update(level=5, role="supervisor", root_life_id=probe.target["life_id"],
                    starter_chain=[], starter_event_seq=0, generation=1, containment="quiescent",
                    budget_remaining={"wall_ms": 60000})
                probe.lane["session"]["driver"] = driver
                for kind in ("lane.created", "lane.started", "identity.bound"):
                    probe.add_event(kind, {})
                probe.events = probe.bound + probe.events
                for sequence, event in enumerate(probe.events, 1):
                    event["seq"] = sequence
                for event in probe.events + probe.bound:
                    event["config"] = case.config
                probe.bound[0]["payload"]["config"] = case.config
                requests[driver] = {"level": 5, "role": "supervisor", "driver": driver,
                                    "project_id": name, "budget": {"wall_ms": 60000}}
                probes[name] = probe
            self.assertEqual(set(probes), {"claudock", "codex"})
            case.lane_inputs = Path("/fixture/input")
            case.root_launch_input = lambda path: serve.encoded(requests)
            case.validate_initial_launch = lambda request: self.assertEqual(request, requests[request["driver"]])
            case.component_reads, case.component_probes = reads, probes

            def scan_fixture(current, record):
                # There is no installed helper on this component-test host.
                # Scan the fixture bytes; report() still scans all evidence.
                self.assertTrue(record["quiescent"])
                for raw in probes[record["name"]].blobs.values():
                    self.assertFalse(any(current.api_key_canary.matches(raw).values()))
                found = current.api_key_canary.scan("fixture-lane", current.root)
                self.assertFalse(found["key"] or found["last8"] or found["unreadable"])

            case.api_key_canary.scan_lane = scan_fixture

            def selected(target):
                return next(probe for probe in probes.values() if target == probe.target)

            def read(label, words, request):
                reads.append((case.human_prefix, case.current, tuple(words)))
                if fault == "missing" and case.current == "lane.codex.reply":
                    case.rows.pop(case.current)
                case.rows[case.current]["observed"]["rpc_executed"] = True
                case.last = {"label": label, "started": True, "exit_code": 0}
                if fault == "read" and case.current == "lane.codex.reply" and words == ["event", "tail"]:
                    raise LookupError("fixture_read_private_note")
                probe = probes[case.human_prefix]
                return probe.read(label, words, request, clock.now + 90)

            def upload(label, kind, raw):
                self.assertEqual(kind, "task")
                return {"id": uuid.uuid4().hex, "class": kind, "bytes": len(raw), "sha256": controls.sha(raw)}

            def start(label, words, request, **options):
                self.assertEqual(words, ["lane", "start"])
                probe = probes[request["project_id"]]
                self.assertEqual(request["driver"], probe.lane["session"]["driver"])
                return dict(probe.target, id=uuid.uuid4().hex, status="succeeded", simulated_presence=True)

            def rpc(label, words, request, proof):
                self.assertEqual(words, ["lane", "stop"])
                probe = selected(request["target"])
                end = next(event for event in probe.events if event["kind"] == "lane.ended")
                return dict(probe.target, id=uuid.uuid4().hex, status="succeeded",
                    stop={"state": probe.lane["state"], "end_event_id": end["id"],
                          "end_sequence": end["seq"], "end": copy.deepcopy(end["payload"])})

            def observe(current, record, require, running=False):
                probe = selected(record["target"])
                if running:
                    record["launch_id"], record["handle"] = probe.launch, probe.terminal["handle"]
                    native = {"state": "running", "survivors": 1, "handle": probe.terminal["handle"],
                              "observed_at": probe.terminal["observed_at"]}
                    return copy.deepcopy(probe.lane), native
                return copy.deepcopy(probe.lane), copy.deepcopy(probe.terminal)

            def collect(current, record, lane, require, fail):
                self.assertTrue(record["quiescent"])
                self.assertEqual(lane["life_id"], record["target"]["life_id"])
                record["collected"] = True

            def run():
                with mock.patch.object(flow, "observe", side_effect=observe), \
                        mock.patch.object(flow, "archive_clean", side_effect=collect), \
                        mock.patch.object(flow.time, "monotonic", clock.monotonic), \
                        mock.patch.object(flow.time, "sleep", clock.sleep):
                    flow.run(case, serve.require, serve.Failed, serve.Blocked)

            def cleanup():
                self.assertTrue(all(record["quiescent"] for record in case.lane_records))
                case.passed({"component_resources": "fixture only"})

            case.human = SimpleNamespace(public={"principal_id": owner}, session=mock.Mock(),
                upload=upload, read=read, rpc=rpc, proof=lambda *_: Path("/fixture/proof"),
                ticket=lambda *_: {"id": uuid.uuid4().hex})
            case.checked_cli, case.run, case.cleanup = start, run, cleanup
            built.append(case)
            return case

        with mock.patch.object(serve, "arguments", return_value=args), \
                mock.patch.object(serve, "Case", side_effect=factory), \
                mock.patch.object(serve.signal, "signal"), \
                mock.patch.object(serve.os, "umask"), \
                redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = serve.main()
        report = evidence / "report.json"
        self.assertTrue(report.is_file(), "harness did not write its report")
        raw = report.read_bytes()
        self.assertFalse(any(built[0].api_key_canary.matches(raw).values()), "report exposed canary material")
        return code, json.loads(raw), built[0]

    def test_both_reply_rows(self):
        code, report, case = self.invoke()
        self.assertEqual(code, 1, "unrun bootstrap prerequisites became an E2E pass")
        self.assertIsNone(report["failure"], "whole flow raised an exception")
        self.assertEqual([record["name"] for record in case.lane_records], ["claudock", "codex"])
        rows = {row["check"]: row for row in report["checks"]}
        for name in ("claudock", "codex"):
            self.assertIn("lane." + name + ".reply", report["required_checks"])
            self.assertEqual(rows["lane." + name + ".reply"]["result"], "pass")
            self.assertIn((name, "lane." + name + ".reply", ("event", "tail")), case.component_reads)
            self.assertIn((name, "lane." + name + ".reply", ("blob", "read")), case.component_reads)
        self.assertTrue(rows["lane.claudock.reply"]["observed"]["readme_heading_verified"])
        expected = b"".join(case.component_probes["codex"].blobs.values()).decode()
        self.assertEqual(rows["lane.codex.reply"]["observed"]["stdout"], expected)
        self.assertTrue(all(record["collected"] for record in case.lane_records))

    def test_read_crash_report(self):
        for fault, kind in (("read", "LookupError"), ("missing", "KeyError")):
            with self.subTest(fault=fault):
                code, report, case = self.invoke(fault)
                self.assertEqual(code, 1, "read exception became a pass")
                failure = report["failure"]
                self.assertEqual(failure["check"], "lane.codex.reply")
                self.assertEqual(failure["reason"], "harness exception: " + kind)
                self.assertNotIn("fixture_read_private_note", json.dumps(report))
                rows = {row["check"]: row for row in report["checks"]}
                self.assertEqual(rows["lane.claudock.reply"]["result"], "pass")
                self.assertEqual(rows["lane.codex.reply"]["result"], "fail")
                self.assertEqual(case.failed_step, "lane.codex.reply")


if __name__ == "__main__":
    unittest.main(verbosity=2)
