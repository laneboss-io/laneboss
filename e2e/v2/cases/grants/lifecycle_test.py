"""Actual installed stop hook and producer selectors, without invented reports.

The observation/control ports model the native boundary. The companion broker
regression measures actual canonical-seat quarantine and later item acquisition.
"""

import copy
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("prep", HERE / "prep_probe.py")
PREP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREP)
GRANTS, FLOW = PREP.GRANTS, PREP.GRANTS.flow


class Lifecycle(unittest.TestCase):
    def sequence(self, shared=False):
        area = tempfile.TemporaryDirectory(prefix="grants-stop-")
        self.addCleanup(area.cleanup)
        prepared = PREP.prefix(Path(area.name))
        self.assertEqual(GRANTS.AGENT_PACKAGE, "./scripts/v2-serve/grants_actor")
        case = PREP.BOOT.BootFixture(Path(area.name))
        case.grants_boot = {"profiles": copy.deepcopy(prepared["profile_ids"])}
        case.grants_enrolled_manifest = prepared["approved"]
        case.fixture_profile_selectors = {driver: "serve-profile-" + driver
                                         for driver in ("claudock-cli", "codex")}
        case.challenge = "component-challenge"
        request = {"driver": "codex", "grants": {name: [] for name in GRANTS.FAMILIES}}
        case.generated_launches = True
        case.human_prefix = "lifecycle"
        case.initial_receipt = {"generation": 1}
        case.egress_anthropic = False
        PREP.SERVER.Case.bind_root_launch(case, request, prepared["issued"])
        selected = next(row for row in prepared["issued"]["profiles"]
                        if row["id"] == request["profile_grant_id"])
        self.assertEqual(selected["profile_id"], "serve-profile-codex")
        self.assertEqual(prepared["parent"]["profile_id"], case.grants_boot["profiles"]["parent"])
        self.assertEqual(prepared["child"]["profile_id"], case.grants_boot["profiles"]["child"])
        if shared:
            case.grants_boot["profiles"]["parent"] = selected["profile_id"]
        target = {"life_id": "baseline-codex", "run": 1}
        record = {"name": "codex", "driver": "codex", "target": target, "request": request}
        stops, reads = [], []
        clock = iter(range(0, 1000, 30))
        case.config = "lifecycle-component"
        case.item_module = GRANTS
        case.passed = lambda receipt: self.assertTrue(receipt)
        case.human = SimpleNamespace(upload=lambda *args: {"id": "reason", "class": "task"})

        def status(*args):
            return dict(target, generation=3, state="running")

        def events(*args):
            reads.append("event.tail")
            return []  # No grants actor report is fabricated for this lane.

        def control(case, label, method, body, life, generation):
            self.assertEqual(method, "lane.stop")
            self.assertEqual(body["target"], target)
            self.assertEqual(body["expected_generation"], generation)
            self.assertEqual(life, target["life_id"])
            stops.append(copy.deepcopy(body))
            return dict(target, id="stop-operation", status="succeeded")

        def observe(*args):
            self.assertEqual(len(stops), 1, "observation preceded the real stop request")
            return status(), {"state": "exited", "signal": 15, "survivors": 0}

        with mock.patch.object(FLOW, "status", status), \
             mock.patch.object(FLOW, "events", events), \
             mock.patch.object(FLOW, "control", control), \
             mock.patch.object(FLOW, "observe", observe), \
             mock.patch.object(FLOW.time, "monotonic", lambda: next(clock)), \
             mock.patch.object(FLOW.time, "sleep"):
            if shared:
                with self.assertRaisesRegex(ValueError, "lifecycle stop would quarantine an item seat"):
                    FLOW.stop(case, record, GRANTS.io.require, ValueError)
                self.assertEqual(stops, [])
            else:
                FLOW.stop(case, record, GRANTS.io.require, ValueError)
                self.assertEqual(len(stops), 1)
                self.assertIs(record["quiescent"], True)
            self.assertEqual(reads, [], "baseline stop waited on an item relay report")

    def test_stop_then_item_seats(self):
        self.sequence()

    def test_shared_seat_refused(self):
        self.sequence(shared=True)


if __name__ == "__main__":
    unittest.main()
