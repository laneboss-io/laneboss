#!/usr/bin/env python3
"""Unit controls for acceptance observers; these do not prove product E2E."""

import argparse
import copy
import json
from pathlib import Path
import secrets
import sys
import unittest
import tempfile

from run import Case

from observations import (
    CaseFailure, digest, verify_channel, verify_delivery, verify_human_mail,
    verify_human_raw, verify_mail_copy, verify_manual_actor,
    verify_partial_retry, verify_scheduler_actor,
)


def opaque():
    return secrets.token_hex(16)


def sample():
    content = ("Observed file bytes " + opaque() + "\n").encode()
    recipient = opaque()
    sender = {"kind": "lane", "id": opaque(), "life_id": opaque(), "level": 4, "role": "executor"}
    requester = {"kind": "lane", "id": opaque(), "life_id": opaque(), "level": 5, "role": "supervisor"}
    mail = {
        "generation": 1, "artifacts": [],
        "id": opaque(), "sender": sender, "recipient_life_id": recipient,
        "content": {"id": opaque(), "sha256": digest(content), "bytes": len(content), "class": "report"},
        "source": "cli", "queued_seq": 3, "status": "queued", "ask": False,
    }
    logical, observed = opaque(), "2026-10-01T12:00:00Z"
    target = {"life_id": recipient, "run": 2}

    def event(kind, seq, payload):
        return {"schema": 2, "id": opaque(), "config": "fixture", "seq": seq,
                "origin": "service", "kind": kind, "life_id": recipient, "run": 2,
                "logical_turn_id": logical, "actor": copy.deepcopy(requester),
                "requested_by": copy.deepcopy(requester), "payload": payload}

    events = [
        event("mail.queued", mail["queued_seq"], copy.deepcopy(mail)),
        event("lane.turn", 4, {"mail_ids": [mail["id"]], "trigger": {
            "kind": "manual", "mail_ids": [mail["id"]], "causing_seqs": [mail["queued_seq"]],
        }}),
        event("lane.ended", 5, {"reason": "exit", "profile_continuation": False, "observation": {
            "handle": {"target": copy.deepcopy(target)}, "state": "exited", "survivors": 0,
            "exit_code": 0, "prompt_status": "completed", "observed_at": observed,
        }}),
        event("mail.delivered", 6, {"mail_id": mail["id"], "target": copy.deepcopy(target),
                                   "logical_turn_id": logical, "status": "delivered",
                                   "prompt_status": "completed", "cause": "exit", "observed_at": observed}),
    ]
    return content, recipient, mail, requester, events


def sink_sample(mail, content):
    channels = [opaque(), opaque()]
    rows = [{"mail_id": mail["id"], "channel_id": channel, "delivery_key": opaque(),
             "receipt_id": opaque(), "content_sha256": digest(content)} for channel in channels]
    return channels, rows


class Observations(unittest.TestCase):
    def test_runner_reached(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-messaging-") as directory:
            root = Path(directory)
            case = Case({"test_root": str(root), "evidence_root": str(root / "evidence")}, root / "result.json")
            case.active = "HUMAN-SEND"
            with self.assertRaises(OSError):
                case.bridge(str(root / "missing.sock"), {"action": "dashboard-mail"})
            self.assertTrue(case.results["HUMAN-SEND"]["reached"])

    def test_runner_exit(self):
        with tempfile.TemporaryDirectory(prefix="lb-v2-messaging-") as directory:
            root = Path(directory)
            context = {"test_root": str(root), "evidence_root": str(root / "evidence"), "phase": "candidate", "mutation_id": "", "binary_sha256": digest(b"fixture artifact"), "source_sha256": digest(b"fixture source")}
            case = Case(context, root / "result.json")
            case.active, case.last_exit = "HUMAN-SEND", 0
            content, recipient, mail, _, _ = sample()
            with self.assertRaises(CaseFailure):
                verify_human_mail(mail, recipient, content)
            case.fail_active()
            case.finish()
            result = json.loads((root / "result.json").read_bytes())
            failed = next(item for item in result["assertions"] if item["id"] == "HUMAN-SEND")
            self.assertEqual(failed["verdict"], "fail")
            self.assertGreater(failed["observed_exit"], 0)

    def test_mail_provenance(self):
        content, recipient, mail, _, _ = sample()
        kept = copy.deepcopy(mail)
        kept["status"], kept["logical_turn_id"] = "delivered", opaque()
        verify_mail_copy(kept, mail, content, recipient)
        kept["sender"]["life_id"] = opaque()
        with self.assertRaisesRegex(CaseFailure, "immutable mail provenance"):
            verify_mail_copy(kept, mail, content, recipient)

    def test_human_sender(self):
        content, recipient, mail, _, _ = sample()
        lane = copy.deepcopy(mail["sender"])
        mail["sender"], mail["source"] = {"kind": "human", "id": opaque()}, "dashboard"
        verify_human_mail(mail, recipient, content)
        mail["sender"] = lane
        with self.assertRaisesRegex(CaseFailure, "human sender/source"):
            verify_human_mail(mail, recipient, content)

    def test_mail_generation(self):
        content, recipient, mail, _, _ = sample()
        kept = copy.deepcopy(mail)
        kept["generation"] += 1
        verify_mail_copy(kept, mail, content, recipient)
        kept["generation"] = 0
        with self.assertRaisesRegex(CaseFailure, "generation or artifact"):
            verify_mail_copy(kept, mail, content, recipient)

    def test_human_raw(self):
        _, _, mail, _, _ = sample()
        mail["sender"], mail["source"] = {"kind": "human", "id": opaque()}, "dashboard"
        raw = {"messages": [copy.deepcopy(mail)], "records": [], "gaps": [], "cursor": ""}
        verify_human_raw(raw, mail)
        raw["messages"][0]["content"]["sha256"] = digest(b"different actual bytes")
        with self.assertRaisesRegex(CaseFailure, "raw history changed"):
            verify_human_raw(raw, mail)

    def test_manual_actor(self):
        _, recipient, mail, requester, events = sample()
        self.assertNotEqual(requester, mail["sender"])
        verify_manual_actor(events, mail, requester, recipient)
        events[1]["actor"] = copy.deepcopy(mail["sender"])
        with self.assertRaisesRegex(CaseFailure, "manual turn actor"):
            verify_manual_actor(events, mail, requester, recipient)

    def test_scheduler_actor(self):
        _, recipient, mail, _, events = sample()
        events[1]["actor"] = {"kind": "scheduler", "id": opaque()}
        verify_scheduler_actor(events, mail, recipient)
        events[1]["actor"] = copy.deepcopy(mail["sender"])
        with self.assertRaisesRegex(CaseFailure, "automatic turn actor"):
            verify_scheduler_actor(events, mail, recipient)

    def test_delivery_target(self):
        _, recipient, mail, _, events = sample()
        verify_delivery(events, mail, recipient)
        events[-1]["life_id"] = opaque()
        with self.assertRaisesRegex(CaseFailure, "different life or run"):
            verify_delivery(events, mail, recipient)

    def test_delivery_completion(self):
        _, recipient, mail, _, events = sample()
        verify_delivery(events, mail, recipient)
        events[2]["payload"]["observation"]["survivors"] = 1
        with self.assertRaisesRegex(CaseFailure, "uncertain or limited process"):
            verify_delivery(events, mail, recipient)

    def test_delivery_origin(self):
        _, recipient, mail, _, events = sample()
        verify_delivery(events, mail, recipient)
        events[-1]["origin"] = "legacy_import"
        with self.assertRaisesRegex(CaseFailure, "exactly one completed"):
            verify_delivery(events, mail, recipient)

    def test_channel_delivery(self):
        content, _, mail, _, _ = sample()
        channels, rows = sink_sample(mail, content)
        verify_channel(rows, mail["id"], content, channels)
        with self.assertRaisesRegex(CaseFailure, "destinations are missing"):
            verify_channel([], mail["id"], content, channels)

    def test_partial_duplicate(self):
        content, _, mail, _, _ = sample()
        channels, rows = sink_sample(mail, content)
        before = copy.deepcopy(rows[:1])
        verify_partial_retry(before, rows, mail["id"], content, channels)
        duplicate = copy.deepcopy(rows[0])
        duplicate["delivery_key"], duplicate["receipt_id"] = opaque(), opaque()
        after = [duplicate, *rows]
        with self.assertRaisesRegex(CaseFailure, "duplicate confirmed"):
            verify_partial_retry(before, after, mail["id"], content, channels)

    def test_partial_missing(self):
        content, _, mail, _, _ = sample()
        channels, rows = sink_sample(mail, content)
        before = copy.deepcopy(rows[:1])
        verify_partial_retry(before, rows, mail["id"], content, channels)
        with self.assertRaisesRegex(CaseFailure, "destinations are missing"):
            verify_partial_retry(before, before, mail["id"], content, channels)

    def test_partial_stability(self):
        content, _, mail, _, _ = sample()
        channels, rows = sink_sample(mail, content)
        before = copy.deepcopy(rows[:1])
        verify_partial_retry(before, rows, mail["id"], content, channels)
        after = copy.deepcopy(rows)
        after[0]["receipt_id"] = opaque()
        with self.assertRaisesRegex(CaseFailure, "already confirmed"):
            verify_partial_retry(before, after, mail["id"], content, channels)

    def test_delivery_key(self):
        content, _, mail, _, _ = sample()
        channels, rows = sink_sample(mail, content)
        verify_channel(rows, mail["id"], content, channels)
        rows[1]["delivery_key"] = rows[0]["delivery_key"]
        with self.assertRaisesRegex(CaseFailure, "reused a delivery key"):
            verify_channel(rows, mail["id"], content, channels)


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.started = []

    def startTest(self, test):
        self.started.append(test.id().removeprefix("__main__."))
        super().startTest(test)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", help="One Observations.test_name, or omit to run all observers")
    parser.add_argument("--json", type=Path, required=True)
    options = parser.parse_args()
    if sys.platform != "linux":
        raise SystemExit("Observer tests run only on the authorized Linux box")
    loader = unittest.TestLoader()
    suite = (loader.loadTestsFromName(options.test, sys.modules[__name__]) if options.test
             else loader.loadTestsFromTestCase(Observations))
    runner = unittest.TextTestRunner(verbosity=2, resultclass=RecordingResult)
    result = runner.run(suite)
    identity = lambda test: test.id().removeprefix("__main__.")
    report = {
        "schema": "laneboss.msg-observer-tests.v1", "started": result.started,
        "tests_run": result.testsRun, "failed": [identity(test) for test, _ in result.failures],
        "errors": [identity(test) for test, _ in result.errors],
        "skipped": [identity(test) for test, _ in result.skipped],
        "expected_failures": [identity(test) for test, _ in result.expectedFailures],
        "unexpected_successes": [identity(test) for test in result.unexpectedSuccesses],
        "diagnostics": [detail for _, detail in result.failures + result.errors],
    }
    options.json.write_text(json.dumps(report, sort_keys=True) + "\n")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
