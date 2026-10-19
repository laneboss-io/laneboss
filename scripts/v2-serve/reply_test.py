"""Credential-free harness controls, executed only on the disposable Linux box.

The synthetic events use the public EventPage, CaptureRecord and SpendRecorded
shapes. No credential, login, model request, object ACL or production guard is
changed by these doubles. Mutations affect in-memory harness copies only.
"""

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import FunctionType, SimpleNamespace
import unittest
from unittest import mock
import uuid


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


serve = module("reply_serve_controls", "run.py")
flow = serve.flow


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class Probe:
    """An installed-human RPC double; public object denial remains explicit."""
    def __init__(self, test, clock, *, real=True, spend=True, raw=None, readable=None):
        self.test, self.clock, self.real = test, clock, real
        self.readable = True if readable is None else readable
        self.session, self.result_id = str(uuid.uuid4()), str(uuid.uuid4())
        self.owner = uuid.uuid4().hex
        self.binding, self.launch = uuid.uuid4().hex, uuid.uuid4().hex
        self.target = {"life_id": uuid.uuid4().hex, "run": 1}
        self.record = {"name": "claudock", "target": self.target}
        self.result_text = uuid.uuid4().hex + " synthetic model output"
        if real:
            heading = (Path(__file__).with_name("fixtures") / "README.md").read_text().splitlines()[0]
            self.result_text += "\n" + heading
        self.vendor = {"type": "result", "subtype": "success", "session_id": self.session,
            "uuid": self.result_id, "is_error": not real, "num_turns": 1,
            "total_cost_usd": 0.012345 if real else 0, "duration_ms": 100,
            "result": self.result_text, "usage": {"input_tokens": 11, "output_tokens": 7 if real else 0,
            "cache_read_input_tokens": 2, "cache_creation_input_tokens": 3}}
        if not real:
            # The fake-key CLI result shape exercised by keycli_test.go.
            self.vendor["api_error_status"] = 401
        self.lane = dict(self.target, state="verifying", launch_id=self.launch,
            session={"vendor_id": self.session},
            credential_spend={"spent_micros": 12345 if real else 0})
        self.terminal = {"state": "exited", "exit_code": 0 if real else 1, "survivors": 0,
            "handle": {"id": uuid.uuid4().hex, "target": self.target,
                       "containment_id": uuid.uuid4().hex, "generation": uuid.uuid4().hex},
            "observed_at": "2030-01-02T03:04:05Z", "prompt_status": "completed"}
        self.record.update(quiescent=True, quiescent_observation=self.terminal,
                           handle=copy.deepcopy(self.terminal["handle"]))
        self.exit_at = 0.0
        self.events, self.blobs, self.calls, self.checks = [], {}, [], []
        self.blob_error, self.event_hook, self.event_reads = None, None, 0
        self.page_size = 200
        self.case = SimpleNamespace(config="reply-controls", real_api_key=real,
            reply_mode="real-key" if real else "fake-key",
            current="lane.claudock.reply",
            rows={"lane.claudock.reply": {"result": "fail", "observed": {}}})
        self.case.human = SimpleNamespace(public={"principal_id": self.owner})
        self.case.passed = lambda observed: serve.Case.passed(self.case, observed)
        self.case.reply_scope = lambda: serve.Case.reply_scope(self.case)
        self.case.capture_check, self.case.capture_read = self.check, self.read
        self.add_event("lane.ended", {"reason": "exit", "launch_id": self.launch,
                       "observation": copy.deepcopy(self.terminal)})
        body = (json.dumps(self.vendor) + "\n").encode() if raw is None else raw(self) if callable(raw) else raw
        stream_id = uuid.uuid4().hex
        for offset in range(0, len(body), 262144):
            part = body[offset:offset + 262144]
            ref = {"id": uuid.uuid4().hex, "class": "capture", "bytes": len(part), "sha256": sha(part)}
            capture_id = uuid.uuid4().hex
            self.blobs[ref["id"]] = part
            self.add_event("capture.appended", {"id": capture_id, "binding_id": self.binding,
                "target": dict(self.target), "stream": "stdout", "offset": offset, "data": ref,
                "primary": True, "coverage": "partial"})
        self.add_event("capture.closed", {"binding_id": self.binding, "stream_id": stream_id,
            "eof": True, "next_offset": len(body)})
        stderr_id = uuid.uuid4().hex
        self.add_event("capture.closed", {"binding_id": self.binding, "stream_id": stderr_id,
            "eof": True, "next_offset": 0})
        self.streams = [{"id": stream_id, "stream": "stdout"}, {"id": stderr_id, "stream": "stderr"}]
        if spend:
            self.add_spend()
        self.bound = [{"id": uuid.uuid4().hex, "kind": "capture.bound", "origin": "service",
            "config": self.case.config, **self.target,
            "payload": {"id": self.binding, "target": self.target, "launch_id": self.launch,
                        "status": "registered", "streams": self.streams}}]

    def add_event(self, kind, payload):
        identifier = payload["id"] if kind == "capture.appended" else uuid.uuid4().hex
        event = {"id": identifier, "seq": len(self.events) + 1, "kind": kind,
                 "origin": "service", "recorded_at": "2030-01-02T03:04:05Z",
                 "config": self.case.config, **self.target, "payload": payload}
        self.events.append(event)
        return event

    def add_spend(self):
        captures = [event["payload"]["id"] for event in self.events if event["kind"] == "capture.appended"]
        return self.add_event("spend.recorded", {"capture_id": captures[-1] if captures else uuid.uuid4().hex,
            "usage": {"session_id": self.session, "result_id": self.result_id,
                "cost_micros": round(self.vendor["total_cost_usd"] * 1000000),
                "input_tokens": self.vendor["usage"]["input_tokens"], "output_tokens": self.vendor["usage"]["output_tokens"],
                "cache_read_tokens": self.vendor["usage"]["cache_read_input_tokens"],
                "cache_creation_tokens": self.vendor["usage"]["cache_creation_input_tokens"]}})

    def refresh_small_capture(self, results=None):
        """Keep mutated valid vendor inputs consistent with their ledger event."""
        captures = [event["payload"] for event in self.events if event["kind"] == "capture.appended"]
        self.test.assertEqual(len(captures), 1, "small capture fixture changed shape")
        raw = b"".join((json.dumps(result) + "\n").encode() for result in (results or [self.vendor]))
        ref = captures[0]["data"]
        ref.update(bytes=len(raw), sha256=sha(raw))
        self.blobs[ref["id"]] = raw
        for event in self.events:
            if event["kind"] == "capture.closed" and event["payload"]["stream_id"] == self.streams[0]["id"]:
                event["payload"]["next_offset"] = len(raw)

    def check(self, record, deadline):
        self.checks.append((self.clock.now, deadline))
        process = copy.deepcopy(self.terminal) if self.clock.now >= self.exit_at else {"state": "running", "survivors": 1}
        lane = dict(self.lane, state="verifying" if process["state"] == "exited" else "running")
        return lane, process

    def read(self, label, words, request, deadline):
        self.calls.append((self.clock.now, label, list(words), dict(request), deadline))
        if words == ["identity", "self"]:
            return {"config": self.case.config, "actor": {"kind": "human", "id": self.owner}}
        if words == ["lane", "status"]:
            return copy.deepcopy(self.lane)
        if words == ["event", "tail"]:
            self.event_reads += 1
            if self.event_hook:
                self.event_hook(self)
            offset = int(request["cursor"]) if request["cursor"] else 0
            selected = self.events[offset:offset + self.page_size]
            end = offset + len(selected)
            result = {"events": copy.deepcopy(selected), "cursor": str(end), "complete": end == len(self.events)}
            self.test.assertLess(len(serve.encoded(result)) + 8192, 1048576, "event response exceeds one frame")
            return result
        self.test.assertEqual(words, ["blob", "read"])
        self.test.assertTrue(type(request["limit"]) is int and 0 < request["limit"] <= 262144,
                             "blob request exceeds public chunk/frame bound")
        if self.blob_error is not None:
            raise self.blob_error
        if self.readable:
            raw = self.blobs[request["object_id"]]
            part = raw[request["offset"]:request["offset"] + request["limit"]]
            return {"object_id": request["object_id"], "offset": request["offset"],
                    "data": base64.b64encode(part).decode(), "sha256": sha(part)}
        # The production drain gives these bytes a worker-owner ACL. The
        # human fixture must get the same denial; it never widens that ACL.
        raise flow.CaptureNotVisible(flow.CAPTURE_NOT_VISIBLE)

    def run(self):
        flow.reply(self.case, self.record, self.lane, self.bound, serve.require)
        return self.case.rows["lane.claudock.reply"]["observed"]


class ReplyControls(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.enterContext(mock.patch.object(flow.time, "monotonic", self.clock.monotonic))
        self.enterContext(mock.patch.object(flow.time, "sleep", self.clock.sleep))

    def probe(self, **options):
        self.clock.now = 0
        return Probe(self, self.clock, **options)

    def success(self, probe, message="valid public spend proof was rejected"):
        try:
            observed = probe.run()
        except serve.Failed:
            self.fail(message)
        self.assertEqual(probe.case.rows["lane.claudock.reply"]["result"], "pass")
        return observed

    def rejected(self, probe):
        with self.assertRaises(serve.Failed):
            probe.run()
        self.assertEqual(probe.case.rows["lane.claudock.reply"]["result"], "fail")

    def test_spend_ok(self):
        probe = self.probe()
        observed = self.success(probe)
        records = observed["spend"]["records"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0], {"session_id": probe.session, "result_id": probe.result_id,
            "cost_micros": 12345, "input_tokens": 11, "output_tokens": 7, "cache_read_tokens": 2,
            "cache_creation_tokens": 3,
            "capture_id": next(event["payload"]["capture_id"] for event in probe.events if event["kind"] == "spend.recorded"),
            "sealed_session": True})
        self.assertTrue(observed["result_present"])
        self.assertFalse(observed["is_error"])
        self.assertTrue(observed["readme_heading_verified"])
        self.assertEqual(observed["public_result_fields"],
            "is_error/subtype: not on the public path (api/spend.go:6-14, :44)")
        self.assertEqual(observed["capture_read"], {"status": "read"})
        self.assertEqual(observed["outcome"], "a real model turn completed and was billed")
        self.assertTrue(probe.result_text not in json.dumps(observed), "row retained model output text")

    def test_late_exit(self):
        probe = self.probe()
        # The existing quiescent row has completed before reply starts.
        self.clock.now = 225
        observed = self.success(probe, "late exit lost its guaranteed read window")
        self.assertEqual(probe.calls[0][0], 225)
        self.assertEqual(probe.calls[0][4] - probe.calls[0][0], 90)
        self.assertTrue(all(call[4] == 315 for call in probe.calls))
        self.assertEqual(probe.checks, [], "reply issued a process check")
        self.assertEqual(observed["windows"], {"read_seconds": 90, "command_seconds": 10, "total_seconds": 90})
        self.assertEqual(observed["diagnostics"]["process_source"], "lane.quiescent")
        self.assertEqual(observed["diagnostics"]["read_window_ms"], 90000)
        self.assertLessEqual(self.clock.now, 330)

    def test_bounds(self):
        running = self.probe()
        running.record["quiescent"] = False
        self.rejected(running)
        self.assertLessEqual(self.clock.now, 240)
        self.assertEqual(running.calls, [], "capture access started before exit")
        missing = self.probe(spend=False)
        self.rejected(missing)
        self.assertLessEqual(self.clock.now, 90)
        diagnostics = missing.case.rows["lane.claudock.reply"]["observed"]["diagnostics"]
        self.assertEqual(diagnostics["phase"], "read")
        self.assertTrue(diagnostics["deadline_hit"])
        self.assertEqual(diagnostics["read_window_ms"], 90000)
        self.assertEqual(sum(call[2] == ["blob", "read"] for call in missing.calls), 1,
                         "an expected object denial was retried")

    def test_windows(self):
        for real in (True, False):
            probe = self.probe(real=real)
            observed = self.success(probe)
            mode = "real-key" if real else "fake-key"
            for field in ("read_seconds", "command_seconds", "total_seconds"):
                with self.subTest(real=real, field=field):
                    changed = copy.deepcopy(observed)
                    changed["windows"][field] += 1
                    self.assertFalse(flow.reply_passed(changed, mode), "changed windows passed")
            for field, value in (("read_window_ms", 1000), ("read_elapsed_ms", 90000), ("phase", "wait")):
                changed = copy.deepcopy(observed)
                changed["diagnostics"][field] = value
                self.assertFalse(flow.reply_passed(changed, mode), "invalid timing facts passed")

    def test_zero_usage(self):
        for field in ("cost_micros", "output_tokens"):
            with self.subTest(field=field):
                probe = self.probe()
                event = next(event for event in probe.events if event["kind"] == "spend.recorded")
                event["payload"]["usage"][field] = 0
                if field == "cost_micros":
                    probe.vendor["total_cost_usd"] = 0
                else:
                    probe.vendor["usage"]["output_tokens"], probe.vendor["result"] = 0, ""
                probe.refresh_small_capture()
                self.rejected(probe)

    def test_no_spend(self):
        probe = self.probe(spend=False)
        probe.lane["credential_spend"]["spent_micros"] = 999999
        self.rejected(probe)

    def test_result_required(self):
        probe = self.probe(readable=False)
        self.rejected(probe)
        observed = probe.case.rows["lane.claudock.reply"]["observed"]
        self.assertFalse(observed["result_present"])
        self.assertEqual(observed["capture_read"]["status"], "not_visible")

    def test_scope(self):
        for field in ("config", "life_id", "run", "origin", "session"):
            with self.subTest(field=field):
                probe = self.probe()
                event = next(event for event in probe.events if event["kind"] == "spend.recorded")
                if field == "session":
                    event["payload"]["usage"]["session_id"] = str(uuid.uuid4())
                elif field == "run":
                    event["run"] = 2
                else:
                    event[field] = "foreign"
                self.rejected(probe)

    def test_two_results(self):
        probe = self.probe()
        second = copy.deepcopy(probe.vendor)
        second["uuid"] = str(uuid.uuid4())
        probe.add_spend()["payload"]["usage"]["result_id"] = second["uuid"]
        probe.refresh_small_capture([probe.vendor, second])
        self.rejected(probe)

    def test_real_exit(self):
        for field in ("code", "survivors", "signal", "reason"):
            with self.subTest(field=field):
                probe = self.probe()
                if field == "code":
                    probe.terminal["exit_code"] = 1
                elif field == "survivors":
                    probe.terminal["survivors"] = 1
                elif field == "signal":
                    probe.terminal.pop("exit_code")
                    probe.terminal["signal"] = 9
                else:
                    probe.events[0]["payload"]["reason"] = "stop"
                probe.events[0]["payload"]["observation"] = copy.deepcopy(probe.terminal)
                self.rejected(probe)

    def test_fake_exit(self):
        probe = self.probe(real=False)
        observed = self.success(probe)
        self.assertEqual(len(observed["spend"]["records"]), 1)
        self.assertEqual(observed["spend"]["records"][0]["cost_micros"], 0)
        self.assertEqual(observed["spend"]["records"][0]["output_tokens"], 0)
        self.assertTrue(observed["result_present"])
        self.assertEqual(observed["outcome"], "Claude Code reached the vendor with the fake key")
        self.assertTrue(flow.vendor_result_proven(probe.record["vendor_proof"]))
        self.assertFalse(flow.reply_passed(observed, "real-key"))

    def test_agent_missing(self):
        probe = self.probe(real=False, spend=False, raw=b"claude executable was not found\n")
        probe.lane["credential_spend"]["accounting_error"] = {"code": "accounting_error"}
        with self.assertRaisesRegex(serve.Failed, "the agent never started"):
            probe.run()
        observed = probe.case.rows["lane.claudock.reply"]["observed"]
        self.assertEqual(observed["diagnostics"]["capture_records"], 1)
        self.assertEqual(observed["diagnostics"]["process"]["exit_code"], 1)
        self.assertTrue(observed["spend"]["accounting_error"])
        self.assertEqual(observed["spend"]["records"], [])
        self.assertEqual(probe.case.rows["lane.claudock.reply"]["result"], "fail")

    def test_fake_no_record(self):
        probe = self.probe(real=False, spend=False, raw=b"")
        with self.assertRaisesRegex(serve.Failed, "the agent never started"):
            probe.run()
        observed = probe.case.rows["lane.claudock.reply"]["observed"]
        self.assertEqual(observed["error"], "the agent never started")
        self.assertTrue(observed["diagnostics"]["deadline_hit"])
        self.assertNotIn("vendor_proof", probe.record)

    def test_fake_scope(self):
        for field in ("config", "life_id", "run", "origin", "session_id"):
            with self.subTest(field=field):
                probe = self.probe(real=False, raw=b"")
                event = next(event for event in probe.events if event["kind"] == "spend.recorded")
                if field == "session_id":
                    event["payload"]["usage"][field] = str(uuid.uuid4())
                else:
                    event[field] = 2 if field == "run" else "foreign"
                with self.assertRaisesRegex(serve.Failed, "the agent never started"):
                    probe.run()

    def test_fake_capture_proof(self):
        probe = self.probe(real=False, spend=False)
        observed = self.success(probe)
        self.assertTrue(flow.fake_reply_passed(observed), "validated public capture result was rejected")
        for field, value in (("session_id", "foreign"), ("result_id", ""),
                             ("sealed_session", False), ("source", "stderr")):
            changed = copy.deepcopy(observed)
            changed["capture_result"][field] = value
            self.assertFalse(flow.fake_reply_passed(changed), "unsealed capture result passed")

    def test_auth_401(self):
        probe = self.probe(real=False)
        observed = self.success(probe)
        expected = {"is_error": True, "subtype": "success", "api_error_status": 401,
                    "num_turns": 1, "duration_ms": 100, "error_class": "authentication_error"}
        self.assertEqual({field: observed.get(field) for field in expected}, expected,
                         "authentication result lost its safe metadata")
        for change in ({"is_error": False}, {"error_class": "network_error"}, {"result_present": False}):
            changed = copy.deepcopy(observed)
            changed.update(change)
            self.assertFalse(flow.fake_reply_passed(changed), "non-authentication result passed")

    def test_auth_owner(self):
        probe = self.probe(real=False)
        probe.case.human.public["principal_id"] = "another-owner"
        with self.assertRaisesRegex(serve.Failed, "capture reader is another human"):
            probe.run()

    def test_auth_class(self):
        for source in ("subtype", "message"):
            with self.subTest(source=source):
                probe = self.probe(real=False, spend=False)
                probe.vendor.pop("api_error_status")
                if source == "subtype":
                    probe.vendor["subtype"] = "authentication_failed"
                    results = [probe.vendor]
                else:
                    results = [{"type": "assistant", "session_id": probe.session,
                                "error": "authentication_failed"}, probe.vendor]
                probe.refresh_small_capture(results)
                observed = self.success(probe)
                self.assertEqual(observed.get("error_class"), "authentication_error",
                                 "documented authentication class was lost")
                self.assertIsNone(observed["api_error_status"])

    def test_auth_network(self):
        for error in ("network_error", "unknown_private_class"):
            with self.subTest(error=error):
                probe = self.probe(real=False)
                probe.vendor.pop("api_error_status")
                probe.vendor.update(subtype="error_during_execution", error=error)
                probe.refresh_small_capture()
                kind = "network_error" if error == "network_error" else "vendor_error"
                with self.assertRaisesRegex(serve.Failed, "fake-key vendor result class: " + kind):
                    probe.run()
                observed = probe.case.rows["lane.claudock.reply"]["observed"]
                self.assertEqual(observed.get("error_class"), kind)
                self.assertEqual(probe.case.rows["lane.claudock.reply"]["result"], "fail")
                if error == "unknown_private_class":
                    self.assertNotIn(error, json.dumps(observed), "unknown vendor class entered diagnostics")

    def test_auth_success_rejected(self):
        probe = self.probe(real=False)
        probe.vendor["is_error"] = False
        probe.refresh_small_capture()
        with self.assertRaisesRegex(serve.Failed, "fake-key vendor result class: none"):
            probe.run()

    def test_auth_spend_only(self):
        probe = self.probe(real=False, raw=b"")
        with self.assertRaisesRegex(serve.Failed, "authentication refusal result is unavailable"):
            probe.run()
        self.assertNotIn("vendor_proof", probe.record)

    def test_auth_real_error(self):
        probe = self.probe(readable=True)
        probe.vendor.update(is_error=True, api_error_status=401)
        probe.refresh_small_capture()
        with self.assertRaisesRegex(serve.Failed, "public vendor result.*authentication_error"):
            probe.run()
        observed = probe.case.rows["lane.claudock.reply"]["observed"]
        self.assertEqual(observed.get("error_class"), "authentication_error")
        self.assertFalse(flow.reply_passed(observed, "real-key"))

    def test_auth_real_success(self):
        probe = self.probe(readable=True)
        observed = self.success(probe)
        self.assertFalse(observed["is_error"])
        self.assertEqual(observed.get("error_class"), "none", "successful result class was lost")
        self.assertGreater(observed["spend"]["records"][0]["cost_micros"], 0)
        self.assertGreater(observed["spend"]["records"][0]["output_tokens"], 0)

    def test_heading_required(self):
        probe = self.probe(readable=True)
        probe.vendor["result"] = uuid.uuid4().hex + " answer without the task heading"
        probe.refresh_small_capture()
        with self.assertRaisesRegex(serve.Failed, "reply lacks README heading"):
            probe.run()

    def test_auth_withheld(self):
        canary = serve.api_key_canary.Canary()
        probe = self.probe(real=False)
        probe.vendor["result"] = "Invalid API key: " + canary.key.decode()
        probe.refresh_small_capture()
        original = probe.read
        commands = []
        temporary = tempfile.TemporaryDirectory(prefix="lb-auth-private-")
        self.addCleanup(temporary.cleanup)
        case = serve.Case.__new__(serve.Case)
        case.root = case.stage = Path(temporary.name)
        case.api_key_canary, case.index, case.cleanup_ok = canary, 0, True
        case.config, case.real_api_key, case.reply_mode = probe.case.config, False, "fake-key"
        case.current, case.rows = probe.case.current, probe.case.rows
        case.capture_check = probe.check
        def read(label, words, request):
            value = original(label, words, request, self.clock.now + 90)
            process = mock.Mock(returncode=0)
            process.communicate.return_value = (serve.encoded(value), b"")
            with mock.patch.object(serve.subprocess, "Popen", return_value=process):
                raw = case.command(label, ["fixture-cli"])
            commands.append(dict(case.last))
            return json.loads(raw)
        case.human = SimpleNamespace(read=read, public=probe.case.human.public)
        probe.case = case
        observed = self.success(probe)
        self.assertEqual(observed.get("error_class"), "authentication_error")
        self.assertTrue(all(item.get("output_withheld") is True for item in commands),
                        "reply command stopped withholding vendor output")
        retained = b"".join(path.read_bytes() for path in case.root.iterdir()) + serve.encoded(observed)
        self.assertFalse(any(canary.matches(retained).values()), "private result entered evidence")
        self.assertFalse(canary.withheld, "private capture bytes reached the evidence keeper")

    def test_fake_unknown(self):
        observed = self.success(self.probe(real=False))
        for change in ({"state": "running"}, {"exited": False}, {"survivors": 1},
                       {"survivors": True}, {"exit_code": None}, {"signal": 9}):
            changed = copy.deepcopy(observed)
            changed["diagnostics"]["process"].update(change)
            self.assertFalse(flow.fake_reply_passed(changed), "unknown terminal outcome passed")

    def test_public_error(self):
        observed = self.success(self.probe())
        self.assertEqual(observed["public_is_error"], [{"source": "capture.result", "is_error": False}])
        # Exercise the defensive predicate without inventing a readable
        # worker blob or adding a field to a closed production RPC schema.
        changed = copy.deepcopy(observed)
        changed["public_is_error"] = [{"source": "already-observed public field", "is_error": True}]
        self.assertFalse(flow.reply_passed(changed, "real-key"))
        changed["public_is_error"][0]["is_error"] = False
        self.assertTrue(flow.reply_passed(changed, "real-key"))

    def test_blob_errors(self):
        probe = self.probe()
        probe.blob_error = serve.Failed("typed integrity refusal")
        with self.assertRaisesRegex(serve.Failed, "integrity refusal"):
            probe.run()
        self.assertEqual(probe.case.rows["lane.claudock.reply"]["result"], "fail")

    def test_large_capture(self):
        seed = uuid.uuid4().hex * 512
        def payload(probe):
            return ((json.dumps({"type": "assistant", "message": {"content": seed}}) + "\n").encode() * 70 +
                    (json.dumps(probe.vendor) + "\n").encode())
        probe = self.probe(raw=payload)
        raw = b"".join(probe.blobs.values())
        self.assertGreater(len(raw), 1048576, "capture fixture never exceeds one frame")
        probe.page_size = 2
        observed = self.success(probe)
        reads = [call[3] for call in probe.calls if call[2] == ["blob", "read"]]
        self.assertGreater(len(reads), 1, "large capture did not exercise bounded pages")
        self.assertTrue(all(0 < request["limit"] <= 32768 for request in reads))
        self.assertGreater(probe.event_reads, 1, "capture metadata did not exercise cursor pages")
        stdout = next(stream for stream in observed["diagnostics"]["streams"] if stream["stream"] == "stdout")
        self.assertEqual(stdout["bytes"], len(raw))
        self.assertEqual(stdout["read_bytes"], len(raw), "large capture was not fully verified")
        self.assertTrue(seed not in json.dumps(observed), "capture contents entered evidence")

    def test_cursor(self):
        probe = self.probe(spend=False)
        first_snapshot_size = len(probe.events)
        def append_after_first(snapshot):
            if snapshot.event_reads == 2:
                snapshot.add_spend()
        probe.event_hook = append_after_first
        self.success(probe)
        requests = [call[3] for call in probe.calls if call[2] == ["event", "tail"]]
        self.assertEqual([request["cursor"] for request in requests], ["", str(first_snapshot_size)])

    def test_summary(self):
        probe = self.probe()
        observed = self.success(probe)
        names = serve.summary.expected_checks("installed-lifecycle", reply=True)
        report = {"scope": "installed-lifecycle", "reply_mode": "real-key", "presence": "simulated",
            "human_approval": "not_proven", "required_checks": names,
            "checks": [{"check": name, "result": "pass", "presence": "simulated",
                       "observed": observed if name == "lane.claudock.reply" else {"executed": True}} for name in names]}
        passed, text = serve.summary.describe(report)
        self.assertTrue(passed)
        self.assertIn("a real model turn completed and was billed", text.splitlines())
        self.assertIn("is_error/subtype: not on the public path (api/spend.go:6-14, :44)", text.splitlines())
        self.assertNotIn(flow.CAPTURE_NOT_VISIBLE, text.splitlines())
        self.assertTrue("reply shown" not in text and "reply read" not in text and probe.result_text not in text,
                        "summary overstated or exposed the result")


class CommandControls(unittest.TestCase):
    def case(self):
        temporary = tempfile.TemporaryDirectory(prefix="lb-v2-reply-unit-")
        self.addCleanup(temporary.cleanup)
        case = serve.Case.__new__(serve.Case)
        case.root, case.stage = Path(temporary.name), Path(temporary.name)
        case.api_key_canary, case.index, case.cleanup_ok = None, 0, True
        case.current = "lane.claudock.reply"
        case.rows = {case.current: {"result": "fail", "observed": {"executed": True}}}
        return case

    def arm(self, case, label="read"):
        case.reply_read = {"deadline": 100, "row": case.current, "label": label}
        case.rows[case.current]["observed"]["diagnostics"] = {"phase": "read"}

    def order_fixture(self, *, real=False, stop_delay=0, quiet_delay=0, read_delay=0,
                      large=False, end_reason="exit", answer_at=0, budget_ms=60000):
        clock = Clock()
        def body(probe):
            prefix = (json.dumps({"type": "assistant", "message": {"content": "x" * 16000}}) + "\n").encode()
            return prefix * 32 + (json.dumps(probe.vendor) + "\n").encode()
        probe = Probe(self, clock, real=real, readable=True, raw=body if large else None)
        probe.events[0]["payload"]["reason"] = end_reason
        for kind in ("lane.created", "lane.started", "identity.bound"):
            probe.add_event(kind, {})
        case = self.case()
        case.config, case.reply_mode, case.real_api_key = probe.case.config, probe.case.reply_mode, real
        case.rows = {name: {"result": "fail", "observed": {}} for name in flow.checks(reply=True, fake=not real)}
        case.api_key_canary = SimpleNamespace(retainable=lambda raw: raw, scan_lane=mock.Mock())
        case.lane_inputs, case.root_grants, case.lane_records = Path("/fixture/input"), None, []
        case.challenge = uuid.uuid4().hex
        request = {"level": 5, "driver": "claudock-cli", "role": "supervisor", "project_id": "fixture",
                   "budget": {"wall_ms": budget_ms}}
        case.root_launch_input = lambda _: serve.encoded({"claudock-cli": request})
        case.validate_initial_launch = mock.Mock()
        probe.lane.update(level=5, role=request["role"], root_life_id=probe.target["life_id"],
                          starter_chain=[], starter_event_seq=0, generation=1,
                          budget_remaining={"wall_ms": budget_ms}, containment="quiescent")
        probe.lane["session"]["driver"] = request["driver"]
        operation = dict(probe.target, id="fixture-operation", status="succeeded", simulated_presence=True)
        refusal = {"code": "containment_unknown", "retryable": False, "owner": "lb-v2-service",
                   "message": "natural completion lacks the actual zero-survivor observation"}
        trace = []
        finished = copy.deepcopy(probe.events)
        model = {"committed": answer_at == 0, "noted": False, "cut": False}
        if answer_at:
            probe.events = [event for event in probe.events if event["kind"] in
                            ("lane.created", "lane.started", "identity.bound")]
            for index, event in enumerate(probe.events, 1):
                event["seq"] = index
            probe.lane.update(state="running", containment="running")

        def commit_answer(cut=False):
            if model["committed"]:
                return
            for event in finished:
                if event["kind"] not in ("lane.created", "lane.started", "identity.bound"):
                    probe.add_event(event["kind"], copy.deepcopy(event["payload"]))
            model.update(committed=True, cut=cut)
            probe.lane.update(state="verifying", containment="quiescent", generation=2)
            if cut:
                probe.terminal.pop("exit_code", None)
                probe.terminal["signal"] = 9
                for event in probe.events:
                    if event["kind"] == "lane.ended":
                        event["payload"].update(reason="stop", observation=copy.deepcopy(probe.terminal))
                probe.events = [event for event in probe.events if event["kind"] != "spend.recorded"]
                probe.refresh_small_capture([{"type": "assistant", "session_id": probe.session,
                                              "message": {"content": "unfinished answer"}}])

        def visible_events():
            if answer_at and clock.now >= answer_at and not model["committed"] and not model["noted"]:
                probe.add_event("run.observed", copy.deepcopy(probe.terminal))
                model["noted"] = True
            return probe.bound + probe.events

        def cli(label, words, selected, **options):
            if words == ["lane", "start"]:
                self.assertEqual(selected["driver"], request["driver"])
                case.last = {"exit_code": 0}
                return operation
            self.assertEqual(words, ["lane", "check"])
            self.assertEqual(selected, probe.target)
            process = mock.Mock(returncode=75)
            process.communicate.return_value = (b"", serve.encoded(refusal))
            with mock.patch.object(serve.subprocess, "Popen", return_value=process):
                case.command(label, ["fixture-cli", *words], expected=options["expected"])

        def observe(selected, record, require, running=False):
            trace.append(("observe", selected.current))
            if selected.current == "lane.claudock.reply":
                return selected.checked_cli("lane-check", ["lane", "check"], record["target"])
            if selected.current.endswith(".quiescent"):
                clock.sleep(quiet_delay)
            if answer_at and clock.now >= answer_at and not model["committed"]:
                commit_answer()
            if answer_at and not model["committed"]:
                running = {"state": "running", "survivors": 1,
                           "handle": probe.terminal["handle"], "observed_at": probe.terminal["observed_at"]}
                return copy.deepcopy(probe.lane), running
            return copy.deepcopy(probe.lane), copy.deepcopy(probe.terminal)

        def read(label, words, selected):
            trace.append(("read", case.current, tuple(words)))
            visible_events()
            scoped = getattr(case, "reply_read", None)
            deadline = scoped["deadline"] if isinstance(scoped, dict) else clock.now + 90
            value = probe.read(label, words, selected, deadline)
            if case.current != "lane.claudock.reply":
                return value
            process = mock.Mock(returncode=0)
            def communicate(timeout):
                self.assertEqual(timeout, flow.REPLY_COMMAND_SECONDS)
                trace.append(("reservation", label, clock.now, deadline, timeout))
                clock.sleep(read_delay)
                return serve.encoded(value), b""
            process.communicate.side_effect = communicate
            with mock.patch.object(serve.subprocess, "Popen", return_value=process):
                return json.loads(case.command(label, ["fixture-cli", *words]))

        def rpc(label, words, selected, proof):
            self.assertEqual(words, ["lane", "stop"])
            self.assertEqual(selected["target"], probe.target)
            trace.append(("stop", clock.now))
            if answer_at and not model["committed"]:
                commit_answer(cut=clock.now < answer_at)
            clock.sleep(stop_delay)
            if not model["cut"]:
                ended = next(event for event in probe.events if event["kind"] == "lane.ended")
                return dict(operation, stop={"state": probe.lane["state"], "end_event_id": ended["id"],
                                            "end_sequence": ended["seq"], "end": copy.deepcopy(ended["payload"])})
            return operation

        case.cli = cli
        case.capture_check = lambda record, deadline: flow.observe(case, record, serve.require)
        case.human = SimpleNamespace(session=mock.Mock(), read=read, rpc=rpc,
            upload=lambda *_: {"id": "fixture-task"}, ticket=lambda *_: {"id": "fixture-ticket"},
            proof=lambda *_: Path("/fixture/proof"), public={"principal_id": probe.owner})
        probe.case = case
        collect = mock.Mock()
        def run():
            with mock.patch.object(flow, "DRIVERS", (("claudock", "claudock-cli"),)), \
                    mock.patch.object(flow, "observe", side_effect=observe), \
                    mock.patch.object(flow, "events", side_effect=lambda *_: visible_events()), \
                    mock.patch.object(flow, "archive_clean", collect), \
                    mock.patch.object(flow.time, "monotonic", clock.monotonic), \
                    mock.patch.object(flow.time, "sleep", clock.sleep):
                flow.run(case, serve.require, serve.Failed, serve.Blocked)
        return case, probe, trace, run, collect

    def test_reply_read_order(self):
        case, probe, trace, run, collect = self.order_fixture()
        try:
            run()
        except serve.Failed:
            failed = case.rows[case.current]["observed"]
            self.assertEqual(failed.get("refusal", {}).get("code"), "containment_unknown")
            self.assertEqual(failed.get("exit_code"), 75)
            self.assertEqual(trace.count(("observe", "lane.claudock.reply")), 1)
            self.fail("reply issued lane.check before quiescent: exit 75 containment_unknown")
        self.assertNotIn(("observe", "lane.claudock.reply"), trace, "reply performed a control operation")
        quiescent = ("observe", "lane.claudock.lifecycle.quiescent")
        blob = ("read", "lane.claudock.reply", ("blob", "read"))
        self.assertLess(trace.index(quiescent), trace.index(blob), "reply read preceded quiescent")
        observed = case.rows["lane.claudock.reply"]["observed"]
        self.assertEqual(observed["api_error_status"], 401)
        self.assertEqual(observed["error_class"], "authentication_error")
        self.assertTrue(case.lane_records[0]["quiescent"])
        self.assertEqual(case.rows["lane.claudock.reply"]["result"], "pass")
        collect.assert_called_once()

    def test_late_read_phase(self):
        case, probe, trace, run, _ = self.order_fixture(real=True, stop_delay=230, quiet_delay=45)
        try:
            run()
        except serve.Failed:
            self.fail("late read phase lost its full window")
        reads = [item for item in trace if item[0] == "reservation"]
        self.assertTrue(reads, "no owner read command ran")
        self.assertEqual(reads[0][2], 275)
        self.assertTrue(all(item[3] == 365 and item[3] - item[2] >= 10 and item[4] == 10 for item in reads),
                        "late read phase lost its full window")
        observed = case.rows["lane.claudock.reply"]["observed"]
        self.assertEqual(observed["diagnostics"]["read_window_ms"], 90000)
        self.assertEqual(observed["capture_read"]["status"], "read")
        self.assertEqual(observed["result_sha256"], sha(probe.result_text.encode()))
        self.assertEqual(case.rows["lane.claudock.reply"]["result"], "pass")

    def test_slow_answer_before_stop(self):
        case, probe, trace, run, collect = self.order_fixture(real=True, answer_at=45)
        try:
            run()
        except serve.Failed:
            self.fail("slow real answer was stopped before completion")
        stops = [item[1] for item in trace if item[0] == "stop"]
        self.assertEqual(len(stops), 1, "stop proof was dropped")
        self.assertGreaterEqual(stops[0], 45)
        self.assertLess(stops[0], 60, "wait exceeded the existing run budget")
        observed = case.rows["lane.claudock.reply"]["observed"]
        self.assertTrue(observed["readme_heading_verified"])
        self.assertEqual(observed["result_sha256"], sha(probe.result_text.encode()))
        self.assertGreater(observed["spend"]["records"][0]["cost_micros"], 0)
        self.assertEqual(observed["diagnostics"]["end_reason"], "exit")
        self.assertEqual(case.rows["lane.claudock.stop"]["observed"]["proof"], "ended-run")
        self.assertEqual(case.rows["lane.claudock.reply"]["result"], "pass")
        collect.assert_called_once()

    def test_answer_budget(self):
        case, _, trace, run, collect = self.order_fixture(real=True, answer_at=45, budget_ms=30000)
        with self.assertRaisesRegex(serve.Failed, "run budget exhausted before vendor result"):
            run()
        self.assertFalse(any(item[0] == "stop" for item in trace), "wait timeout stopped an unfinished answer")
        self.assertEqual(case.lane_records[0]["request"]["budget"]["wall_ms"], 30000)
        collect.assert_not_called()

    def test_cut_answer_fast(self):
        clock = Clock()
        probe = self.row_probe(clock, readable=True, raw=lambda p: (
            json.dumps({"type": "assistant", "session_id": p.session,
                        "message": {"content": "unfinished answer"}}) + "\n").encode())
        probe.terminal.pop("exit_code")
        probe.terminal["signal"] = 9
        probe.events = [event for event in probe.events if event["kind"] != "spend.recorded"]
        ended = next(event for event in probe.events if event["kind"] == "lane.ended")
        ended["payload"].update(reason="stop", observation=copy.deepcopy(probe.terminal))
        process = mock.Mock(returncode=0)
        process.communicate.return_value = (b"metadata\n", b"")
        with mock.patch.object(serve.time, "monotonic", clock.monotonic), \
                mock.patch.object(flow.time, "sleep", clock.sleep), \
                mock.patch.object(serve.subprocess, "Popen", return_value=process):
            with self.assertRaisesRegex(serve.Failed, "run stopped before its vendor result"):
                probe.run()
        self.assertLess(clock.now, 1, "stopped answer polled through its read window")
        self.assertEqual(probe.case.rows["lane.claudock.reply"]["result"], "fail")

    def test_slow_read_phase(self):
        case, _, _, run, collect = self.order_fixture(real=True, stop_delay=230, quiet_delay=45,
                                                     read_delay=6, large=True)
        with self.assertRaisesRegex(serve.Failed, "reply command lacks its full reserved window"):
            run()
        observed = case.rows["lane.claudock.reply"]["observed"]
        self.assertGreaterEqual(observed["diagnostics"]["read_elapsed_ms"], 80000)
        self.assertLess(observed["diagnostics"]["read_elapsed_ms"], 90000)
        self.assertEqual(case.rows["lane.claudock.reply"]["result"], "fail")
        collect.assert_not_called()

    def test_ended_stop_receipt(self):
        case, _, _, run, collect = self.order_fixture(real=True)
        original = case.human.rpc
        def wrong_end(*args):
            result = copy.deepcopy(original(*args))
            result["stop"]["end_sequence"] += 1
            return result
        case.human.rpc = wrong_end
        with self.assertRaisesRegex(serve.Failed, "ended-run stop lacks its exact committed-end receipt"):
            run()
        collect.assert_not_called()

    def test_budget_commands(self):
        case = self.case()
        case.current = "lane.claudock.events"
        process = mock.Mock(returncode=0)
        process.communicate.return_value = (b"metadata\n", b"")
        with mock.patch.object(serve.time, "monotonic", return_value=25), \
                mock.patch.object(serve.subprocess, "Popen", return_value=process):
            with case.budget_scope(30):
                with case.budget_scope(40):
                    case.command("answer-events", ["fixture-cli"])
                self.assertEqual(case.command_deadline, 30)
        self.assertEqual(process.communicate.call_args.kwargs["timeout"], 5,
                         "natural wait command outlived its budget")
        self.assertFalse(hasattr(case, "command_deadline"), "wait budget leaked into reply")
        with self.assertRaises(KeyboardInterrupt):
            with case.budget_scope(30):
                raise KeyboardInterrupt()
        self.assertFalse(hasattr(case, "command_deadline"), "failed wait leaked its budget")

    def test_budget_keeps_reserve(self):
        case = self.case()
        self.arm(case)
        process = mock.Mock(returncode=0)
        process.communicate.return_value = (b"metadata\n", b"")
        with mock.patch.object(serve.time, "monotonic", return_value=25), \
                mock.patch.object(serve.subprocess, "Popen", return_value=process) as popen:
            with case.budget_scope(30):
                with self.assertRaisesRegex(serve.Failed, "reply command lacks its full reserved window"):
                    case.command("read", ["fixture-cli"])
            popen.assert_not_called()

    def test_fake_row_gate(self):
        for name in ("lane.claudock.running", "lane.claudock.events", "cleanup"):
            with self.subTest(row=name):
                case = self.case()
                case.reply_mode, case.current = "fake-key", name
                case.rows[name] = {"result": "fail", "observed": {}}
                with self.assertRaisesRegex(serve.Failed, "the agent never started"):
                    case.passed({"state": "exited", "exit_code": 1, "survivors": 0})
                self.assertEqual(case.rows[name]["result"], "fail")

    def proof(self):
        probe = Probe(self, Clock(), real=False)
        probe.run()
        return probe.record["vendor_proof"]

    def test_fake_row_proof(self):
        proof = self.proof()
        for name in ("lane.claudock.running", "lane.claudock.events", "cleanup"):
            with self.subTest(row=name):
                case = self.case()
                case.reply_mode, case.current = "fake-key", name
                case.rows[name] = {"result": "fail", "observed": {}}
                observed = ({"api_key_canary": {"vendor_proofs": [proof]}} if name == "cleanup"
                            else {"vendor_proof": proof})
                try:
                    case.passed(observed)
                except serve.Failed:
                    self.fail("valid fake row was rejected")
                self.assertEqual(case.rows[name]["result"], "pass")

    def test_lifecycle_labels(self):
        case = self.case()
        case.reply_mode = "fake-key"
        declared = flow.checks(reply=True, fake=True)
        for step in flow.LIFECYCLE_STEPS:
            flow.row(case, "claudock", step)
            self.assertEqual(case.current, "lane.claudock.lifecycle." + step,
                             "fake lifecycle row implies the agent ran")
            self.assertIn(case.current, declared)
            case.rows[case.current] = {"result": "fail", "observed": {}}
            case.passed({"state": "exited", "exit_code": 1, "survivors": 0})
            self.assertEqual(case.rows[case.current]["observed"]["purpose"],
                             "lifecycle only; does not prove the agent ran")

    def test_canary_cleanup(self):
        proof = self.proof()
        for valid in (False, True):
            with self.subTest(valid=valid):
                case = self.case()
                case.reply_mode, case.current = "fake-key", "cleanup"
                case.rows["cleanup"] = {"result": "fail", "observed": {}}
                case.item_module, case.suite, case.active = None, "state", None
                case.units, case.receipts = [], []
                case.reservation, case.egress_forward, case.socket = None, None, None
                case.lane_records = [{"driver": "claudock-cli", "quiescent": True,
                                      "collected": True, "vendor_proof": proof if valid else {}}]
                case.api_key_canary = SimpleNamespace(finish=lambda _: {
                    "source_error": False, "source_transfers": 1, "lane_scans": 1,
                    "places": [], "evidence_withheld": False})
                if valid:
                    case.cleanup()
                    self.assertEqual(case.rows["cleanup"]["result"], "pass")
                else:
                    with self.assertRaisesRegex(serve.Failed, "the agent never started"):
                        case.cleanup()
                    self.assertIn("problems", case.rows["cleanup"]["observed"],
                                  "canary exposure was credited without vendor proof")
                    self.assertIn("the agent never started", case.rows["cleanup"]["observed"]["problems"])
                    self.assertEqual(case.rows["cleanup"]["result"], "fail")

    def test_fake_dispatch(self):
        for valid in (False, True):
            with self.subTest(valid=valid):
                clock = Clock()
                probe = Probe(self, clock, real=False, spend=valid, raw=None if valid else b"")
                if not valid:
                    probe.lane["credential_spend"]["accounting_error"] = {"code": "accounting_error"}
                for kind in ("lane.created", "lane.started", "identity.bound"):
                    probe.add_event(kind, {})
                case = self.case()
                case.config, case.reply_mode, case.real_api_key = probe.case.config, "fake-key", False
                case.rows = {name: {"result": "fail", "observed": {}} for name in flow.checks(reply=True, fake=True)}
                case.api_key_canary = SimpleNamespace(retainable=lambda raw: raw, scan_lane=mock.Mock())
                case.lane_inputs, case.root_grants, case.lane_records = Path("/fixture/input"), None, []
                case.challenge = uuid.uuid4().hex
                request = {"level": 5, "driver": "claudock-cli", "role": "supervisor", "project_id": "fixture"}
                case.root_launch_input = lambda _: serve.encoded({"claudock-cli": request})
                case.validate_initial_launch = mock.Mock()
                case.human = SimpleNamespace(session=mock.Mock(), upload=lambda *_: {"id": "fixture-task"},
                    ticket=lambda *_: {"id": "fixture-ticket"}, proof=lambda *_: Path("/fixture/proof"),
                    public={"principal_id": probe.owner})
                operation = dict(probe.target, id="fixture-operation", status="succeeded", simulated_presence=True)
                case.checked_cli = lambda *_args, **_options: operation
                case.capture_check, case.capture_read = probe.check, probe.read
                probe.case = case
                def stopped(selected, record, require, fail):
                    self.assertEqual(probe.terminal["handle"]["target"], record["target"])
                    self.assertEqual(probe.terminal["survivors"], 0)
                    record.update(quiescent=True, quiescent_observation=copy.deepcopy(probe.terminal))
                    return probe.lane
                with mock.patch.object(flow, "DRIVERS", (("claudock", "claudock-cli"),)), \
                        mock.patch.object(flow, "observe", return_value=(probe.lane, probe.terminal)), \
                        mock.patch.object(flow, "events", return_value=probe.bound + probe.events), \
                        mock.patch.object(flow, "stop", side_effect=stopped) as stop, \
                        mock.patch.object(flow, "archive_clean") as collect, \
                        mock.patch.object(flow.time, "monotonic", clock.monotonic), \
                        mock.patch.object(flow.time, "sleep", clock.sleep):
                    if valid:
                        try:
                            flow.run(case, serve.require, serve.Failed, serve.Blocked)
                        except serve.Failed:
                            self.fail("vendor proof was required before its observation")
                        stop.assert_called_once()
                        collect.assert_called_once()
                    else:
                        with self.assertRaisesRegex(serve.Failed, "the agent never started"):
                            flow.run(case, serve.require, serve.Failed, serve.Blocked)
                        self.assertEqual(case.current, "lane.claudock.reply", "failed before the vendor observation")
                        stop.assert_called_once()
                        collect.assert_not_called()
                for step in ("running", "events", "reply"):
                    row = case.rows["lane.claudock." + step]
                    self.assertEqual(row["result"], "pass" if valid else "fail")
                self.assertEqual(case.api_key_canary.scan_lane.call_count, int(valid))

    def test_reserve(self):
        case = self.case()
        process = mock.Mock(returncode=0)
        process.communicate.return_value = (b"metadata\n", b"")
        self.arm(case)
        with mock.patch.object(serve.time, "monotonic", return_value=90), \
                mock.patch.object(serve.subprocess, "Popen", return_value=process):
            case.command("read", ["fixture-cli"])
        self.assertEqual(process.communicate.call_args.kwargs["timeout"], 10)
        with mock.patch.object(serve.time, "monotonic", return_value=90.001), \
                mock.patch.object(serve.subprocess, "Popen", return_value=process) as popen:
            with self.assertRaisesRegex(serve.Failed, "full reserved window",
                                       msg="a command started without its full reserved window"):
                case.command("read", ["fixture-cli"])
            popen.assert_not_called()

    def test_spawn_check(self):
        case = self.case()
        self.arm(case, "late-preparation")
        process = mock.Mock(returncode=0)
        process.communicate.return_value = (b"metadata\n", b"")
        with mock.patch.object(serve.time, "monotonic", side_effect=[90, 90.2, 90.2]), \
                mock.patch.object(serve.subprocess, "Popen", return_value=process) as popen:
            with self.assertRaisesRegex(serve.Failed, "full reserved window"):
                case.command("late-preparation", ["fixture-cli"])
            popen.assert_not_called()

    def test_scope_limits(self):
        for change in ("row", "phase", "label"):
            with self.subTest(change=change):
                case = self.case()
                self.arm(case)
                if change == "row":
                    case.current = "human.claudock.read.confirm"
                    case.rows[case.current] = {"observed": {}}
                elif change == "phase":
                    case.rows[case.current]["observed"]["diagnostics"]["phase"] = "wait"
                else:
                    case.reply_read["label"] = "another-read"
                process = mock.Mock(returncode=0)
                process.communicate.return_value = (b"metadata\n", b"")
                with mock.patch.object(serve.time, "monotonic", return_value=101), \
                        mock.patch.object(serve.subprocess, "Popen", return_value=process):
                    try:
                        case.command("read", ["fixture-cli"])
                    except serve.Failed:
                        self.fail("a command outside the read scope lost its normal timeout")
                self.assertEqual(process.communicate.call_args.kwargs["timeout"], 60)

    def row_probe(self, clock, **options):
        probe = Probe(self, clock, **options)
        case = self.case()
        case.config, case.real_api_key = probe.case.config, True
        case.capture_check = probe.check
        def read(label, words, request):
            saved = case.current
            case.current = "human.claudock.read.confirm"
            case.rows[case.current] = {"observed": {}}
            case.command("human-confirm", ["fixture-cli", "human", "confirm"])
            case.current = saved
            case.command(label, ["fixture-cli"])
            return probe.read(label, words, request, case.reply_read["deadline"])
        case.human = SimpleNamespace(read=read, public=probe.case.human.public)
        probe.case = case
        return probe

    def test_after_row(self):
        clock = Clock()
        probe = self.row_probe(clock)
        case = probe.case
        # Saved expired state must be harmless when the next human row runs.
        saved = {"deadline": 90, "row": case.current, "label": "human-confirm"}
        case.reply_read = saved
        process = mock.Mock(returncode=0)
        process.communicate.return_value = (b"metadata\n", b"")
        with mock.patch.object(serve.time, "monotonic", clock.monotonic), \
                mock.patch.object(flow.time, "sleep", clock.sleep), \
                mock.patch.object(serve.subprocess, "Popen", return_value=process):
            probe.run()
            self.assertEqual(case.rows["lane.claudock.reply"]["result"], "pass")
            calls = process.communicate.call_args_list
            self.assertEqual([call.kwargs["timeout"] for call in calls], [60, 10] * 4,
                             "human proof commands lost their normal timeout")
            clock.now = 101
            case.current = "human.claudock.read.confirm"
            try:
                case.command("human-confirm", ["fixture-cli", "human", "confirm"])
            except serve.Failed:
                self.fail("post-row confirmation lost its normal timeout")
        self.assertEqual(process.communicate.call_args.kwargs["timeout"], 60,
                         "post-row confirmation lost its normal timeout")
        self.assertIs(case.reply_read, saved)

    def test_row_restore(self):
        names = ("reply_read", "private_output", "private_label", "command_stderr")
        for failure in (None, serve.Failed("fixture"), OSError("fixture"), KeyboardInterrupt()):
            for present in (False, True):
                with self.subTest(failure=type(failure).__name__, present=present):
                    clock = Clock()
                    probe = self.row_probe(clock)
                    case = probe.case
                    saved = {name: object() for name in names} if present else {}
                    for name, value in saved.items():
                        setattr(case, name, value)
                    if failure is not None:
                        def broken(*args):
                            for name in names:
                                setattr(case, name, object())
                            raise failure
                        case.human.read = broken
                    process = mock.Mock(returncode=0)
                    process.communicate.return_value = (b"metadata\n", b"")
                    with mock.patch.object(serve.time, "monotonic", clock.monotonic), \
                            mock.patch.object(flow.time, "sleep", clock.sleep), \
                            mock.patch.object(serve.subprocess, "Popen", return_value=process):
                        if failure is None:
                            probe.run()
                            self.assertEqual(case.rows["lane.claudock.reply"]["result"], "pass")
                        else:
                            with self.assertRaises(type(failure)):
                                probe.run()
                    for name in names:
                        if present:
                            self.assertIs(getattr(case, name), saved[name], "row did not restore " + name)
                        else:
                            self.assertFalse(hasattr(case, name), "row leaked " + name)

    def refusal_case(self, *, code="not_found", owner="lb-v2-service", words=None):
        case = self.case()
        original = case.rows[case.current]["observed"]
        error = {"code": code, "owner": owner, "message": "fixture typed refusal",
                 "instead": "retain the typed refusal", "retryable": False}
        def cli(label, command, request=None, **options):
            case.command_stderr = serve.encoded(error)
            case.last = {"label": label, "exit_code": 2, "output_withheld": True, "stderr": "not-written"}
        case.cli = cli
        case.human = SimpleNamespace(read=lambda *args: case.checked_cli(*args))
        return case, original, error, words or ["blob", "read"]

    def test_not_found(self):
        case, original, error, words = self.refusal_case()
        try:
            case.capture_read("reply-blob", words, {}, serve.time.monotonic() + 90)
        except flow.CaptureNotVisible as failure:
            self.assertEqual(str(failure), flow.CAPTURE_NOT_VISIBLE)
        except serve.Failed:
            self.fail("the specifically authorized blob not_found was not recorded neutrally")
        else:
            self.fail("the blob denial was silently accepted as readable data")
        self.assertIs(case.rows[case.current]["observed"], original)
        self.assertIsNone(case.reply_read)
        self.assertIsNone(case.command_stderr)

    def test_other_errors(self):
        for code, owner, words in (("integrity", "lb-v2-service", ["blob", "read"]),
            ("forbidden", "lb-v2-service", ["blob", "read"]),
            ("unauthenticated", "lb-v2-service", ["blob", "read"]),
            ("not_found", "other-owner", ["blob", "read"]),
            ("not_found", "lb-v2-service", ["event", "tail"])):
            with self.subTest(code=code, owner=owner, words=words):
                case, original, error, selected = self.refusal_case(code=code, owner=owner, words=words)
                try:
                    case.capture_read("reply-blob", selected, {}, serve.time.monotonic() + 90)
                except flow.CaptureNotVisible:
                    self.fail("a non-authorized refusal was hidden by the blob branch")
                except serve.Failed:
                    self.assertEqual(case.rows[case.current]["observed"]["refusal"], error)
                else:
                    self.fail("a public refusal became success")

    def test_private_output(self):
        case = self.case()
        raw = (uuid.uuid4().hex + " synthetic vendor text").encode()
        process = mock.Mock(returncode=0)
        process.communicate.return_value = (raw, raw)
        def read(label, words, request):
            case.command("human-confirm", ["fixture-signer"])
            self.assertTrue((case.root / case.last["stdout"]).read_bytes() == raw,
                            "proof bytes were removed before the CLI could consume them")
            return case.command(label, ["fixture-cli"])
        case.human = SimpleNamespace(read=read)
        with mock.patch.object(serve.subprocess, "Popen", return_value=process):
            result = case.capture_read("reply-blob", ["blob", "read"], {}, serve.time.monotonic() + 90)
        self.assertTrue(result == raw)
        self.assertEqual((case.root / case.last["stdout"]).read_bytes(), b"")
        self.assertEqual((case.root / case.last["stderr"]).read_bytes(), b"")
        self.assertTrue(all(raw not in path.read_bytes() for path in case.root.glob("002-*")),
                        "private output entered retained command evidence")

    def test_timeout(self):
        case = self.case()
        raw = uuid.uuid4().hex.encode()
        process = mock.Mock(returncode=-9)
        process.communicate.side_effect = [subprocess.TimeoutExpired(["fixture-cli"], 0.1), (raw, raw)]
        case.private_output, case.private_label = True, "reply-blob"
        with mock.patch.object(serve.subprocess, "Popen", return_value=process):
            with self.assertRaisesRegex(serve.Failed, "timed out"):
                case.command("reply-blob", ["fixture-cli"], seconds=0.1)
        self.assertTrue(process.kill.called)
        self.assertTrue(all(raw not in path.read_bytes() for path in case.root.iterdir()),
                        "timeout retained vendor bytes")


class MutationControls(unittest.TestCase):
    def assert_red(self, cls, name, reason=None):
        result = unittest.TestResult()
        cls(name).run(result)
        errors = "\n".join(detail for _, detail in result.errors)
        self.assertEqual(len(result.errors), 0, "mutation caused an unrelated error: " + name + "\n" + errors)
        self.assertGreater(len(result.failures), 0, "mutation escaped its control: " + name)
        if reason:
            self.assertTrue(any(reason in detail for _, detail in result.failures),
                            "mutation failed for the wrong reason: " + name)

    def test_phase_controls(self):
        # Baseline timing already starts after quiescence. These explicit
        # faults prove that the new component checks detect each alternative;
        # they are not a claimed RED reproduction on the source revision.
        source = Path(flow.__file__).read_text()
        faults = [
            ("test_late_read_phase", "reply", "read_started = started",
             "read_started = started - REPLY_READ_SECONDS", "late read phase lost its full window"),
            ("test_slow_read_phase", "reply", "deadline = read_started + REPLY_READ_SECONDS",
             "deadline = read_started + REPLY_READ_SECONDS * 2", None),
        ]
        for name, attribute, before, after, reason in faults:
            with self.subTest(control=name):
                self.assertEqual(source.count(before), 1, "phase control anchor changed")
                namespace = {"__file__": flow.__file__, "__name__": "phase_control"}
                exec(compile(source.replace(before, after), flow.__file__, "exec"), namespace)
                with mock.patch.object(flow, attribute, namespace[attribute]):
                    self.assert_red(CommandControls, name, reason)

    def test_auth_guards(self):
        with mock.patch.object(flow, "vendor_error_class", return_value="authentication_error"):
            self.assert_red(ReplyControls, "test_auth_network", "Failed not raised")
        with mock.patch.object(flow, "fake_reply_passed", return_value=True):
            self.assert_red(ReplyControls, "test_auth_spend_only", "Failed not raised")
        original = serve.Case.command
        def retain_private(case, *args, **options):
            case.private_output = False
            return original(case, *args, **options)
        with mock.patch.object(serve.Case, "command", retain_private):
            self.assert_red(ReplyControls, "test_auth_withheld",
                            "reply command stopped withholding vendor output")

    def test_mutations(self):
        policies = [
            ("test_spend_ok", "reply_passed", lambda *_: False),
            ("test_zero_usage", "reply_passed", lambda *_: True),
            ("test_no_spend", "reply_passed", lambda *_: True),
            ("test_result_required", "reply_passed", lambda *_: True),
            ("test_scope", "reply_passed", lambda *_: True),
            ("test_two_results", "reply_passed", lambda *_: True),
            ("test_real_exit", "reply_passed", lambda *_: True),
            ("test_windows", "reply_windows_valid", lambda *_: True),
            ("test_public_error", "reply_passed", lambda *_: True),
            ("test_fake_exit", "fake_reply_passed", lambda *_: False),
            ("test_fake_unknown", "terminal_process", lambda *_: True),
            ("test_agent_missing", "vendor_result_proven", lambda *_: True),
            ("test_fake_no_record", "vendor_result_proven", lambda *_: True),
            ("test_fake_scope", "vendor_result_proven", lambda *_: True),
            ("test_bounds", "reply", lambda *_: None),
            ("test_blob_errors", "reply", lambda *_: None),
        ]
        for name, attribute, replacement in policies:
            with self.subTest(control=name), mock.patch.object(flow, attribute, replacement):
                self.assert_red(ReplyControls, name)
        with mock.patch.object(flow, "fake_row_passed", return_value=True):
            self.assert_red(CommandControls, "test_fake_row_gate")
        original = flow.fake_row_passed
        def reject_agent_rows(name, observed):
            return name not in ("lane.claudock.running", "lane.claudock.events", "cleanup") and original(name, observed)
        with mock.patch.object(flow, "fake_row_passed", reject_agent_rows):
            self.assert_red(CommandControls, "test_fake_row_proof", "valid fake row was rejected")
        reader_source = Path(flow.__file__).read_text()
        flow_mutations = [
            (ReplyControls, "test_fake_capture_proof", "vendor_result_proven",
             'capture.get("sealed_session") is True', 'True', "unsealed capture result passed"),
            (CommandControls, "test_lifecycle_labels", "check_name",
             'return "lane.%s.lifecycle.%s" % (name, step)',
             'return "lane.%s.%s" % (name, step)', "fake lifecycle row implies the agent ran"),
            (CommandControls, "test_fake_dispatch", "run",
             'if fake:\n            case.rows[case.current]["observed"] = running_observed',
             'if False:\n            case.rows[case.current]["observed"] = running_observed',
             "vendor proof was required before its observation"),
            (CommandControls, "test_answer_budget", "wait_answer",
             'min(budgets) / 1000', 'min(budgets) / 500', "Failed not raised"),
            (CommandControls, "test_ended_stop_receipt", "stop",
             'receipt.get("end_sequence") == natural["seq"]', 'True', "Failed not raised"),
            (CommandControls, "test_cut_answer_fast", "reply_run",
             'diagnostics["end_reason"] == "stop" and not observed["result_present"] and captured and all(',
             'False and captured and all(', "run stopped before its vendor result"),
            (ReplyControls, "test_heading_required", "project_heading",
             'return heading', 'return ""', "Failed not raised"),
        ]
        for cls, name, attribute, before, after, reason in flow_mutations:
            with self.subTest(control=name):
                self.assertEqual(reader_source.count(before), 1, "flow mutation anchor changed")
                namespace = {"__file__": flow.__file__, "__name__": "reply_flow_mutant"}
                exec(compile(reader_source.replace(before, after), flow.__file__, "exec"), namespace)
                function = namespace[attribute]
                mutant = FunctionType(function.__code__, vars(flow), attribute, function.__defaults__)
                with mock.patch.object(flow, attribute, mutant):
                    self.assert_red(cls, name, reason)
        reader_mutations = [
            ("test_late_exit",
             "deadline = read_started + REPLY_READ_SECONDS", "deadline = read_started",
             "late exit lost its guaranteed read window"),
            ("test_large_capture",
             '"limit": min(REPLY_READ_BYTES, ref["bytes"] - offset)',
             '"limit": sum(entry["data"]["bytes"] for entry in inventory.values())',
             "blob request exceeds public chunk/frame bound"),
            ("test_cursor", "event_cursor = cursor", 'event_cursor = ""', None),
        ]
        for name, before, after, reason in reader_mutations:
            with self.subTest(control=name):
                self.assertEqual(reader_source.count(before), 1, "reader mutation anchor changed")
                namespace = {"__file__": flow.__file__, "__name__": "reply_reader_mutant"}
                exec(compile(reader_source.replace(before, after), flow.__file__, "exec"), namespace)
                # Recompiled modules define fresh exception classes. Match
                # the public denial raised by the installed-human double.
                namespace["CaptureNotVisible"] = flow.CaptureNotVisible
                with mock.patch.object(flow, "reply", namespace["reply"]):
                    self.assert_red(ReplyControls, name, reason)
        command_source = Path(serve.__file__).read_text()
        command_mutations = [
            ("test_budget_commands", 'seconds = min(seconds, remaining)', 'seconds = seconds',
             "natural wait command outlived its budget"),
            ("test_canary_cleanup",
             'if len(proofs) != 1 or not all(flow.vendor_result_proven(proof) for proof in proofs):',
             'if False:', "canary exposure was credited without vendor proof"),
            ("test_reserve",
             'require(deadline - time.monotonic() >= seconds, "reply command lacks its full reserved window")',
             "None", "a command started without its full reserved window"),
            ("test_spawn_check",
             'started = time.monotonic()\n        if in_read:',
             'started = time.monotonic()\n        if False:', None),
            ("test_after_row",
             'self.current == scoped.get("row") == "lane.claudock.reply" and\n'
             '                   name == scoped.get("label") and\n'
             '                   self.rows.get(self.current, {}).get("observed", {}).get("diagnostics", {}).get("phase") == "read"',
             'name == scoped.get("label")', "post-row confirmation lost its normal timeout"),
            ("test_scope_limits", 'name == scoped.get("label") and', 'True and',
             "outside the read scope lost its normal timeout"),
            ("test_scope_limits", '.get("phase") == "read"', '.get("phase") in ("read", "wait")',
             "outside the read scope lost its normal timeout"),
            ("test_row_restore", 'for name, value in previous.items():', 'for name, value in ():', "row leaked"),
            ("test_other_errors",
             'refusal.get("code") == "not_found"', 'refusal.get("code") in ("not_found", "integrity")',
             "a non-authorized refusal was hidden"),
            ("test_not_found",
             'refusal.get("code") == "not_found"', 'refusal.get("code") == "never-match"',
             "the specifically authorized blob not_found was not recorded neutrally"),
            ("test_private_output",
             'b"" if private_output else stdout', "stdout", None),
            ("test_timeout", 'b"" if private_output else stderr', "stderr", None),
        ]
        for name, before, after, reason in command_mutations:
            with self.subTest(control=name):
                self.assertIn(before, command_source, "command mutation anchor changed")
                namespace = {"__file__": serve.__file__, "__name__": "reply_command_mutant"}
                exec(compile(command_source.replace(before, after), serve.__file__, "exec"), namespace)
                namespace.update(Failed=serve.Failed, require=serve.require, flow=flow)
                with mock.patch.object(serve, "Case", namespace["Case"]):
                    self.assert_red(CommandControls, name, reason)
        with mock.patch.object(serve.summary.steps, "REAL_TURN_PROOF", "unapproved claim"):
            self.assert_red(ReplyControls, "test_summary")


if __name__ == "__main__":
    unittest.main(verbosity=2)
