"""Harness ordering units; adapters are input models, not installed authority."""

import copy
import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("stop_flow", Path(__file__).with_name("lifecycle.py"))
flow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(flow)


class ExitReads:
    def __init__(self, test, commit=True, handled=True):
        self.test, self.commit, self.handled = test, commit, handled
        self.asked, self.durable = False, False
        self.reads, self.stops, self.clock = 0, [], 0
        self.saved, self.receipts = {}, []
        self.target = {"life_id": "life-a", "run": 1}
        self.handle = {"id": "launch-a", "target": self.target,
                       "containment_id": "containment-a", "generation": "boot:7"}
        self.record = {"name": "codex", "target": self.target, "handle": self.handle}
        self.observation = {"state": "exited", "exit_code": 0, "survivors": 0,
                            "handle": self.handle, "observed_at": "2030-01-02T03:04:05Z"}
        self.case = SimpleNamespace(config="stop-case", challenge="challenge", current="",
            item_module=SimpleNamespace(finish_lifecycle=self.finish),
            human=SimpleNamespace(upload=self.upload), keep_json=self.keep,
            passed=self.receipts.append)

    def finish(self, case, record, require, fail):
        self.test.assertIs(case, self.case)
        self.test.assertEqual(record["target"], self.target)
        self.asked = True
        return self.handled

    def upload(self, label, kind, raw):
        return {"id": label, "class": kind, "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest()}

    def keep(self, name, value):
        self.test.assertNotIn(name, self.saved)
        self.saved[name] = copy.deepcopy(value)

    def status(self, case, record, require):
        self.test.assertEqual(record["target"], self.target)
        return dict(self.target, state="verifying" if self.durable else "running",
                    containment="quiescent" if self.durable else "running",
                    generation=4 if self.durable else 2)

    def observe(self, case, record, require):
        return self.status(case, record, require), copy.deepcopy(self.observation)

    def events(self, case, record, require):
        self.test.assertTrue(self.asked, "read exit before requesting the fixture's normal exit")
        self.reads += 1
        if not self.commit or self.reads < 2:
            return []
        self.durable = True
        return [{"kind": "lane.ended", "config": case.config, **self.target,
                 "origin": "service", "seq": 17, "id": "end-a",
                 "recorded_at": "2030-01-02T03:04:06Z",
                 "payload": {"reason": "exit", "launch_id": self.handle["id"],
                             "observation": copy.deepcopy(self.observation)}}]

    def control(self, case, label, method, request, target, generation):
        self.test.assertEqual(method, "lane.stop")
        self.test.assertTrue(self.asked, "Stop preceded the fixture's natural exit request")
        if self.handled:
            self.test.assertTrue(self.durable, "Stop preceded the durable exit record")
        self.test.assertEqual(request["target"], self.target)
        self.test.assertEqual(target, self.target["life_id"])
        self.test.assertEqual(request["expected_generation"], generation)
        self.test.assertEqual(generation, self.status(case, self.record, None)["generation"])
        self.stops.append(copy.deepcopy(request))
        return {"id": "stop-" + str(len(self.stops)), "status": "succeeded", **self.target}

    def now(self):
        self.clock += 20
        return self.clock

    def execute(self):
        with mock.patch.object(flow, "status", self.status), \
             mock.patch.object(flow, "observe", self.observe), \
             mock.patch.object(flow, "events", self.events), \
             mock.patch.object(flow, "control", self.control), \
             mock.patch.object(flow.time, "monotonic", self.now), \
             mock.patch.object(flow.time, "sleep"):
            return flow.stop(self.case, self.record,
                lambda ok, message: self.test.assertTrue(ok, message), AssertionError)


class StopWait(unittest.TestCase):
    def test_record_precedes_stop(self):
        reads = ExitReads(self)
        result = reads.execute()
        self.assertEqual(len(reads.stops), 1)
        self.assertGreaterEqual(reads.reads, 2)
        self.assertEqual(result["state"], "verifying")
        proof = reads.saved["codex-exit-record.json"]
        self.assertEqual(proof["event"]["recorded_at"], "2030-01-02T03:04:06Z")
        self.assertEqual(proof["event"]["payload"]["observation"], reads.observation)

    def test_uncommitted_exit_refuses_stop(self):
        reads = ExitReads(self, commit=False)
        with self.assertRaisesRegex(AssertionError, "recorded natural exit deadline"):
            reads.execute()
        self.assertGreater(reads.reads, 0)
        self.assertEqual(reads.stops, [])
        self.assertEqual(reads.saved, {})

    def test_declined_hook_keeps_plain_stop(self):
        # A lane the item did not end itself (another driver) is stopped as
        # before: no exit wait, no exit record, one Stop at the live generation.
        for answer in (False, None):
            reads = ExitReads(self, handled=answer)
            result = reads.execute()
            self.assertEqual(reads.reads, 0)
            self.assertEqual(len(reads.stops), 1)
            self.assertEqual(reads.stops[0]["expected_generation"], 2)
            self.assertNotIn("codex-exit-record.json", reads.saved)
            self.assertEqual(result["state"], "running")


class GrantsHook(unittest.TestCase):
    def test_only_codex_lane_uses_relay(self):
        path = Path(__file__).with_name("case_grants.py")
        spec = importlib.util.spec_from_file_location("grants_hook", path)
        grants = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(grants)
        made = []
        with mock.patch.object(grants, "Relay", lambda *a: made.append(a)):
            refuse = lambda ok, message: self.assertTrue(ok, message)
            done = grants.finish_lifecycle(None, {"driver": "claudock-cli"}, refuse, None)
        self.assertIs(done, False)
        self.assertEqual(made, [])


if __name__ == "__main__":
    unittest.main()
