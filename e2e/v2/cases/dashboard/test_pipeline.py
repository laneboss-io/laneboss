"""Producer path controls; doubles never establish installed authority."""

import json
import copy
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from fixture_io import FixtureError
from test_data import data_module as data
from test_producer import producer, SOURCE


class PipelineTests(unittest.TestCase):
    def test_fake_asset(self):
        owner = SimpleNamespace(stage=SOURCE, keep=Mock(), agent={"path": Path("/test/actor")})
        result = producer.boot(owner)
        asset = result["assets"][0]
        self.assertEqual(asset["role"], "dashboard-fake-judge", "scored source was not explicitly enrolled as a fake")
        spec = json.loads(Path(asset["file"]).read_bytes())
        self.assertIs(spec["fake"], True)
        self.assertEqual(spec["algorithm"], "sha256-question-v1")
        self.assertGreater(spec["max_cost_micros"], 0)
        tool = result["assets"][1]
        self.assertEqual((tool["role"], tool["file"], tool["mode"]), ("tool", "/test/actor", 0o555),
                         "candidate check executable is not enrolled from the measured actor")
        self.assertEqual(result["bundle"]["root_grants"]["data"], [], "dashboard fixture widened baseline materialization")
        project = result["bundle"]["projects"][0]
        self.assertEqual(project["object"], owner.dashboard_boot["project_tree"])
        self.assertEqual(len(owner.dashboard_boot["case_root"]["data"]), 1)

    def relay(self, chunks):
        target = {"life_id": "actual-life", "run": 2}
        relay = SimpleNamespace(seen=set(), offset=0, pending=bytearray(), values=[],
            record={"operation": {"id": "actual-operation"}, "target": target}, refusal=Mock(),
            capture_blob=lambda ref: chunks[ref["id"]], require=data.need)
        events, offset = [], 0
        for index, raw in enumerate(chunks.values(), 1):
            events.append({"seq": index, "kind": "capture.appended", "origin": "service", **target,
                "operation_id": "actual-operation", "payload": {"binding_id": "actual-binding", "target": target,
                    "primary": True, "coverage": "partial", "stream": "stdout", "offset": offset,
                    "data": {"id": str(index), "bytes": len(raw)}}})
            offset += len(raw)
        return relay, events

    def test_partial_relay(self):
        raw = (json.dumps({"type": "system", "subtype": "dashboard-fixture", "fixture": {
            "type": "grants.ready", "target": {"life_id": "actual-life", "run": 2}}}) + "\n").encode()
        relay, events = self.relay({"1": raw[:17], "2": raw[17:]})
        values = data.relay_values(relay, events[:1])
        self.assertEqual(values, [])
        values = data.relay_values(relay, events)
        self.assertEqual([row["type"] for row in values], ["grants.ready"], "partial capture was not reassembled into its actual relay value")
        self.assertEqual(relay.offset, len(raw))

    def test_relay_scope(self):
        relay, events = self.relay({"1": b"{}\n"})
        events[0]["operation_id"] = "foreign-operation"
        with self.assertRaises(ValueError, msg="foreign capture became relay authority"):
            data.relay_values(relay, events)

    def test_gap_binding(self):
        target = {"life_id": "capture-life", "run": 2}
        record = {"primary": True, "coverage": "partial", "binding_id": "binding", "target": target,
            "stream": "stdout", "offset": 17, "data": {"bytes": 29}}
        gap = {"target": target, "stream": "stdout", "start_offset": 46, "reason": "incomplete_coverage:partial"}
        value = {"records": [record], "gaps": [gap]}
        self.assertTrue(data.partial_gap_bound(value), "actual partial tail was rejected")
        gap["target"] = dict(target, run=1)
        self.assertFalse(data.partial_gap_bound(value), "unrelated gap passed as partial capture evidence")

    def prepared(self):
        target = {"life_id": "review-life", "run": 2}
        blob = lambda kind: {"id": kind + "-actual", "class": kind}
        result = {"subject": {"target": target}, "required_checks": ["actual-check"], "missing_checks": [],
            "request": {"target": target, "diff": blob("diff"), "checks": [blob("check")],
                        "record_inventory": blob("manifest"), "refusal_resolution": []}}
        owner = SimpleNamespace(keep_json=Mock())
        item = SimpleNamespace(case=owner, browser=SimpleNamespace(handoff=SimpleNamespace(review_prepare=Mock(return_value=result))))
        return item, target, result

    def test_review_producer(self):
        item, target, result = self.prepared()
        request = data.review_inputs(item, target)
        item.browser.handoff.review_prepare.assert_called_once_with(target)
        self.assertEqual(request, result["request"], "native producer candidate references were replaced")
        item.case.keep_json.assert_called_once_with("dash-review-prepared.json", result)

    def test_review_gate(self):
        item, target, result = self.prepared()
        result["missing_checks"] = ["actual-check"]
        with self.assertRaises(FixtureError, msg="missing measured test job passed review preparation") as caught:
            data.review_inputs(item, target)
        self.assertEqual(caught.exception.error["owner"], "lb-v2-grants")
        self.assertIn("TestChild", caught.exception.error["message"])

    def test_review_subject(self):
        item, target, result = self.prepared()
        result["subject"]["target"] = dict(target, run=1)
        with self.assertRaises(ValueError, msg="foreign frozen subject passed review preparation"):
            data.review_inputs(item, target)

    def test_test_child(self):
        item, target, missing = self.prepared()
        measured = copy.deepcopy(missing)
        missing["missing_checks"] = ["actual-check"]
        item.browser.handoff.review_prepare.side_effect = [missing, measured]
        request = {"child": target, "candidate": {"id": "child-candidate"}, "test_plan": {"id": "child-plan"}, "budget": {}}
        record = {"target": target, "test_child_request": request}
        item.records = {"merge": record}
        item.lane = Mock(return_value={"generation": 7})
        item.browser.proof = Mock(return_value={"id": "actual-test-proof"})
        operation = {"id": "actual-test-operation", "status": "succeeded", "last_seq": 19}
        item.browser.rpc = Mock(return_value=operation)
        def execute(params, submit, **options):
            self.assertEqual(options, {"subject": missing["subject"], "required": ["actual-check"]})
            return {"operation": submit(params)}
        item.case.item_test_child = SimpleNamespace(execute=Mock(side_effect=execute))
        self.assertEqual(data.review_inputs(item, target), measured["request"])
        self.assertEqual(item.browser.rpc.call_args.args, ("grants.test-child", request, {"id": "actual-test-proof"}),
                         "TestChild was not dispatched through the actual public service")
        item.case.item_test_child.execute.assert_called_once()
        self.assertEqual(record["test_operation"], operation)
        self.assertEqual(item.browser.handoff.review_prepare.call_count, 2)

    def test_test_child_subject(self):
        item, target, missing = self.prepared()
        measured = copy.deepcopy(missing)
        measured["subject"]["target"] = dict(target, run=1)
        missing["missing_checks"] = ["actual-check"]
        item.browser.handoff.review_prepare.side_effect = [missing, measured]
        item.records = {"merge": {"target": target, "test_child_request": {"child": target}}}
        item.lane = Mock(return_value={"generation": 7})
        item.browser.proof, item.browser.rpc, item.await_operation = Mock(), Mock(), Mock()
        item.case.item_test_child = SimpleNamespace(execute=Mock(return_value={"operation": {"id": "actual-test"}}))
        with self.assertRaises(ValueError, msg="completed test selected another frozen subject"):
            data.review_inputs(item, target)

    def root_fixture(self):
        expiry = "2030-01-01T00:00:00Z"
        tree = {"id": "actual-tree", "sha256": "a" * 64}
        member = {"id": "actual-data", "source_object_id": tree["id"], "source_sha256": tree["sha256"],
            "destination": "/work/main", "relative_path": ".", "history_scope": "tree", "access": "rw", "delivery": "copy",
            "delegate": False, "expires_at": expiry}
        profile = {"id": "actual-profile-grant", "profile_id": "actual-profile", "driver": "codex",
            "paid": False, "delegate": False, "expires_at": expiry}
        grants = {"id": "actual-root-grants", "generation": 1, "policy_generation": 7, "data": [member],
            "profiles": [profile], "expires_at": expiry}
        owner = SimpleNamespace(config="fixture", human_prefix="itemdashboard", dashboard_boot={"project_tree": tree},
            human=SimpleNamespace(public={"principal_id": "actual-human"}), passed=Mock())
        item = data.DashData(owner, {}, None, None, None)
        item.root_manifest_ref = {"id": "actual-root-manifest"}
        def rpc(method, params, proof):
            if method == "grants.root":
                return grants
            self.assertEqual(method, "ticket.issue")
            return dict(params, id="actual-ticket", config="fixture", principal_id="actual-human", redeemed=False)
        item.browser = SimpleNamespace(proof=Mock(return_value={"id": "actual-proof"}), rpc=Mock(side_effect=rpc))
        request = {"driver": "codex", "level": 5, "role": "supervisor", "expected_policy_generation": 7,
            "budget": {"wall_ms": 1000}, "grants": {"data": []}}
        return item, request, grants

    def test_root_binding(self):
        item, request, grants = self.root_fixture()
        ticket = item.root_ticket(request)
        self.assertEqual(ticket["grant_set_id"], grants["id"])
        self.assertEqual(request["grants"]["data"][0]["parent_grant_id"], "actual-data",
                         "case root selected a data grant other than the actual issued member")
        self.assertEqual(request["profile_grant_id"], "actual-profile-grant")
        self.assertEqual(len(request["grants"]["data"]), 1)

    def test_root_source(self):
        item, request, grants = self.root_fixture()
        grants["data"][0]["source_sha256"] = "b" * 64
        with self.assertRaises(ValueError, msg="case root accepted another project source digest"):
            item.root_ticket(request)
        self.assertEqual(item.browser.rpc.call_count, 1)

    def test_root_policy(self):
        item, request, grants = self.root_fixture()
        grants["policy_generation"] += 1
        with self.assertRaises(ValueError, msg="case root accepted another policy generation"):
            item.root_ticket(request)
        self.assertEqual(item.browser.rpc.call_count, 1)

    def test_requirements(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = SimpleNamespace(config="fixture", keep=Mock())
            document = data.review_requirements(owner, "actual-project", 7, Path(directory))
            path = Path(directory) / "fixture.json"
            self.assertEqual(json.loads(path.read_bytes()), document)
            self.assertEqual(document["policy_generation"], 7, "protected requirement generation was replaced")
            self.assertEqual(document["projects"][0]["project_id"], "actual-project")
            self.assertEqual(path.stat().st_mode & 0o777, 0o444)
            with self.assertRaises(FileExistsError):
                data.review_requirements(owner, "actual-project", 7, Path(directory))

    def accounting_fixture(self, *, model="dashboard-fake-sha256-question-v1", changed=False, audit=True):
        proposal = {"level": 5, "role": "supervisor", "driver": "codex", "task": {"id": "actual-task"}}
        bodies = {}
        owner = SimpleNamespace(config="fixture", human_prefix="itemdashboard", rows={}, lane_inputs=Path("/test/input"),
            root_launch_input=lambda path: json.dumps({"codex": proposal, "claudock-cli": dict(proposal, driver="claudock-cli")}).encode(),
            decode_document=json.loads, dashboard_boot={"budget": {"wall_ms": 300000, "spend_micros": 0}, "project_id": "actual-project"}, passed=Mock(),
            publication_blob=lambda ref: json.dumps(bodies[ref["id"]]).encode())
        item = data.from_checkpoint(owner, data.need, ValueError)
        item.records = {aid: {"target": {"life_id": aid, "run": 1}} for aid in ("DASH-L6", "DASH-POLICY", "DASH-MERGED")}
        item.lane = Mock(side_effect=lambda record: {"logical_turn_id": "actual-turn", "workspace": {"project_id": "actual-project"}})
        item.read = Mock(return_value={"policy_generation": 7})
        def evaluate(method, request):
            self.assertEqual(method, "policy.evaluate", "fixture did not dispatch the actual policy evaluator")
            scored = request["target"]["life_id"] == "DASH-POLICY"
            key = "actual-scored" if scored else "actual-unscored"
            retained = copy.deepcopy(request)
            if changed:
                retained["target"]["run"] += 1
            bodies[key] = {"request": retained, "batches": [{"reply": {"reported_model": model}}] if scored else []}
            rule = {"result": "refuse", "critical": True}
            if scored:
                rule["probability"] = .95
            return {"id": key, "audit_complete": audit, "input": {"id": key}, "rules": [rule]}
        item.browser = SimpleNamespace(rpc=Mock(side_effect=evaluate))
        return item

    def test_accounting(self):
        item = self.accounting_fixture()
        with patch.object(data, "review_requirements") as installed:
            item.prepare_accounting()
        self.assertEqual(item.browser.rpc.call_count, 2)
        installed.assert_called_once_with(item.case, "actual-project", 7)
        self.assertEqual(item.case.passed.call_count, 2)

    def test_accounting_source(self):
        item = self.accounting_fixture(model="another-source")
        with patch.object(data, "review_requirements"):
            with self.assertRaises(ValueError, msg="scored accounting accepted an unmarked source"):
                item.prepare_accounting()

    def test_accounting_input(self):
        item = self.accounting_fixture(changed=True)
        with patch.object(data, "review_requirements"):
            with self.assertRaises(ValueError, msg="accounting accepted unrelated retained request bytes"):
                item.prepare_accounting()

    def test_accounting_audit(self):
        item = self.accounting_fixture(audit=False)
        with patch.object(data, "review_requirements"):
            with self.assertRaises(ValueError, msg="accounting accepted a missing policy audit"):
                item.prepare_accounting()


if __name__ == "__main__":
    unittest.main()
