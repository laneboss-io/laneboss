"""Fix-10/11 and installed-row regressions; authorized Linux execution only."""

import copy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "e2e" / "v2"))

import draft4
import ladder
from ladder_fixtures import make_run
from ladder_live import CLI
from ladder_ready import PLAN, blockers, instance_rows, ready_plan
from ladder_transactions import mutation_receipt
from manifests import presence_value
from support import Failure, bytes_hash, save
from readsession import SessionReader
from prepare_ladder import prepare
from support import regular
import test_draft4


class CurrentRunControls(unittest.TestCase):
    def red(self, check, mutate):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, plan, _ = make_run(root)
            mutate(run)
            with self.assertRaises(ladder.LadderFailure) as caught:
                ladder.verify_run(run, plan, root)
            self.assertEqual(caught.exception.check_id, check)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, plan, _ = make_run(root)
            self.assertEqual(len(ladder.verify_run(run, plan, root)), 10)

    def test_missing_bound_run(self):
        self.red("launch-pins", lambda run: run["launch_audits"].pop())

    def test_reserved_role_and_driver(self):
        self.red("launch-pins", lambda run: run["launch_audits"][0]["reservation"].update(role="executor"))
        self.red("launch-pins", lambda run: run["launch_audits"][0]["reservation"].update(driver="codex"))

    def test_worker_cannot_bind_agent(self):
        self.red("launch-pins", lambda run: run["launch_audits"][0]["record"].update(kind="worker"))

    def test_prepared_binding_pins(self):
        self.red("launch-pins", lambda run: run["launch_audits"][0]["prepared"].update(containment_id="foreign"))
        self.red("launch-pins", lambda run: run["launch_audits"][0]["identity"].update(record_sha256=bytes_hash(b"foreign")))

    def test_original_spec_and_authority(self):
        self.red("launch-pins", lambda run: run["launch_audits"][0]["recovery"]["handoff"].update(
            spec_sha256=bytes_hash(b"foreign")))
        self.red("launch-authority", lambda run: run["launch_audits"][0]["reservation"]["authority"].update(id="foreign"))

    def test_policy_at_release(self):
        self.red("policy-generation", lambda run: run["launch_audits"][0].update(policy_at_release=2))

    def test_fresh_work_uses_current_policy(self):
        self.red("policy-generation", lambda run: run["mutations"][0]["policy_context"].update(current_generation=2))

    def test_replay_retains_approved_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, plan, _ = make_run(root)
            run["mutations"][-1]["policy_context"]["current_generation"] = 2
            self.assertEqual(len(ladder.verify_run(run, plan, root)), 10)
        self.red("policy-generation", lambda run: run["mutations"][-1]["receipt"].update(policy_generation=2))

    def test_projection_needs_lane_policy(self):
        self.red("policy-generation", lambda run: run["lanes"][0].update(policy_generation=2))

    def test_reservation_is_not_ready_write(self):
        self.red("write-matrix", lambda run: run["mutations"][0]["transaction"]["fields"].append("Lanes"))
        self.red("write-matrix", lambda run: run["mutations"][0]["transaction"]["guards"].append("Cancellation"))

    def mark_simulated(self, run):
        run["root_ticket"]["simulated_presence"] = True
        for event in run["events"]:
            if event["kind"] in ("ticket.issued", "ticket.redeemed", "human.session", "human.proof.used"):
                event["payload"]["simulated_presence"] = True
        for item in run["mutations"]:
            if item["actor"]["kind"] != "human":
                continue
            item["receipt"]["simulated_presence"] = True
            item["response"]["result"]["simulated_presence"] = True
            item["receipt"]["reply"]["result"]["simulated_presence"] = True
            if "proof" in item["request"]:
                item["request"]["proof"]["simulated_presence"] = True
        run["presence"] = {"simulated_presence": True, "presence": "simulated", "human_approval": "not_proven"}
        for read in run["reads"]:
            read["session"]["simulated_presence"] = True

    def test_simulated_is_not_human_approval(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, plan, _ = make_run(root)
            self.mark_simulated(run)
            self.assertEqual(len(ladder.verify_run(run, plan, root)), 10)
            run["presence"]["human_approval"] = "proven"
            with self.assertRaises(ladder.LadderFailure) as caught:
                ladder.verify_run(run, plan, root)
            self.assertEqual(caught.exception.check_id, "presence")

    def test_root_cannot_drop_presence_mark(self):
        def mutate(run):
            self.mark_simulated(run)
            run["mutations"][0]["receipt"]["simulated_presence"] = False
        self.red("presence", mutate)

    def test_declared_software_cannot_hide(self):
        def mutate(run):
            event = next(event for event in run["events"] if event["kind"] == "human.proof.used")
            event["payload"]["credential_id"] = "laneboss-e2e-software-auth"
        self.red("presence", mutate)

    def test_retained_guidance_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            run, _, _ = make_run(Path(temporary))
            source = next(item for item in run["mutations"] if item["actor"]["kind"] == "lane")
            item = copy.deepcopy(source)
            request, receipt = item["request"], item["receipt"]
            request.update(method="guidance.select", params={})
            request["request_sha256"] = draft4.intent_digest(run["config"], request["method"], {})
            receipt["key"] = {key: request[key] for key in ("method", "idempotency_key", "request_sha256")}
            lane = run["lanes"][0]
            result = {"target": {"life_id": lane["life_id"], "run": 2}, "task": lane["task"],
                      "policy_generation": 1, "candidate_snapshot_id": "snapshot", "reservation_id": "claim",
                      "judgment_ids": [], "id": "selection", "logical_turn_id": "turn-two",
                      "as_of": "2026-01-01T00:00:00Z", "items": [], "status": "empty", "notice": "no candidates"}
            item["response"]["result"], receipt["reply"] = result, {"result": result}
            item["transaction"] = {"fields": [], "events": [], "effects": [], "guards": [], "reply": True}
            item["policy_context"] = {"current_generation": 2, "use": "retained_selection"}
            self.assertIsInstance(mutation_receipt(item, run["config"]), tuple)
            item["policy_context"]["use"] = "fresh"
            with self.assertRaises(ladder.LadderFailure) as caught:
                mutation_receipt(item, run["config"])
            self.assertEqual(caught.exception.check_id, "policy-generation")

    def test_session_refresh_is_monotonic(self):
        def mutate(run):
            following = copy.deepcopy(run["reads"][0])
            following["request"]["request_id"] = os.urandom(16).hex()
            following["response"]["request_id"] = following["request"]["request_id"]
            following["session"]["generation"] = 1
            run["reads"].append(following)
        self.red("read-auth", mutate)

    def test_live_review_cannot_be_historical(self):
        self.red("cleanup", lambda run: next(event for event in run["events"] if
                 event["kind"] == "lane.reviewed")["payload"].pop("evidence"))

    def test_review_check_and_eof(self):
        def bad_check(run):
            review = next(event for event in run["events"] if event["kind"] == "lane.reviewed")
            review["payload"]["evidence"]["checks"][0]["exit_code"] = 1
        self.red("cleanup", bad_check)
        def missing_eof(run):
            review = next(event for event in run["events"] if event["kind"] == "lane.reviewed")
            review["payload"]["evidence"]["inventory"]["streams"][0]["eof"] = False
        self.red("cleanup", missing_eof)

    def test_review_handles_empty_stderr(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, plan, _ = make_run(root, empty_stderr=True)
            self.assertEqual(len(ladder.verify_run(run, plan, root)), 10)

    def test_review_end_matches_chunks(self):
        def mutate(run):
            review = next(event for event in run["events"] if event["kind"] == "lane.reviewed")
            fact = review["payload"]["evidence"]["inventory"]["streams"][0]
            fact["end_offset"] = 0
            for event in run["events"]:
                if event["kind"] == "capture.closed" and event["payload"]["stream_id"] == fact["stream_id"]:
                    event["payload"]["next_offset"] = 0
        self.red("cleanup", mutate)


class ReadyPlanControls(unittest.TestCase):
    def red(self, mutate, message):
        source = ready_plan()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "plan.json"
            changed = copy.deepcopy(source)
            mutate(changed)
            save(path, changed)
            with self.assertRaisesRegex(Failure, message):
                ready_plan(path)
            save(path, source)
            self.assertEqual(ready_plan(path), source)

    def test_every_row_has_a_named_port(self):
        self.red(lambda value: value["rows"][0].update(depends=[]), "owning port")
        self.red(lambda value: value["rows"][0]["depends"][0].update(port=""), "unnamed")
        self.red(lambda value: value["rows"][0]["depends"][0].update(evidence=[]), "source evidence")
        self.red(lambda value: value["rows"][0]["depends"][0]["evidence"][0].update(
            symbol="no-such-symbol"), "missing source symbol")
        self.red(lambda value: value["rows"][0]["depends"][0]["evidence"][0].update(
            symbol="func "), "ambiguous source symbol")
        self.red(lambda value: value["rows"][0]["depends"][0]["evidence"][0].update(
            file="internal/v2/service/stub.go"), "missing source symbol")
        self.red(lambda value: value["rows"][0]["depends"][0]["evidence"][0].update(
            line=1), "unknown JSON field")
        self.red(lambda value: value["rows"][0]["depends"][0]["evidence"][0].update(
            directory=7), "source evidence directory")
        self.red(lambda value: value["rows"][0]["depends"][0]["evidence"][0].update(
            directory="internal/v2/service", file="../server.go"), "source evidence directory")
        with tempfile.TemporaryDirectory() as temporary:
            source = ready_plan()
            ref = source["rows"][0]["depends"][0]["evidence"][0]
            ref["directory"], ref["file"] = ref["file"].rsplit("/", 1)
            path = Path(temporary) / "plan.json"
            save(path, source)
            self.assertEqual(ready_plan(path), source)

    def test_every_lane_has_landed_status(self):
        self.red(lambda value: value["lanes"].pop("lb-v2-service"), "unknown")
        self.red(lambda value: value["lanes"].update({"lb-v2-service": "unknown"}), "landed status")
        self.red(lambda value: value["rows"][0]["depends"][0].update(
            landed=not value["rows"][0]["depends"][0]["landed"]), "port landed")
        self.red(lambda value: value["rows"][0].update(
            landed=not value["rows"][0]["landed"]), "row landed")

    def test_ten_instances_and_d9(self):
        self.red(lambda value: value["instances"][1].update(level=6), "level, parent")
        self.red(lambda value: value["instances"].pop(), "ten distinct")
        self.red(lambda value: value["rows"].pop(), "missing or unknown rows")

    def test_phase_and_wall_clock(self):
        self.red(lambda value: value["rows"][0].update(phase="stub"), "phase")
        self.red(lambda value: value["rows"][0].update(seconds=[60, 30]), "wall-clock")

    def test_source_plan_is_not_runtime_pass(self):
        value = ready_plan()
        self.assertEqual(len(value["lanes"]), 18)
        # An owner may have real implementations and unfinished required ports.
        self.assertTrue(value["lanes"]["lb-v2-admin"])
        self.assertTrue(value["lanes"]["lb-v2-secrets"])
        self.assertTrue(value["lanes"]["lb-v2-dashboard"])
        self.assertTrue(value["lanes"]["lb-v2-service"])
        rows = {row["id"]: row for row in value["rows"]}
        self.assertTrue(rows["READY-HEALTH"]["landed"])
        self.assertTrue(rows["LADDER-COLLECT"]["landed"])
        self.assertFalse(rows["LADDER-REVIEW"]["landed"])
        pending = [item for row in value["rows"] for item in blockers(value, row)]
        self.assertTrue(pending)
        self.assertTrue(any("VerifyReview" in item["port"] for item in pending))
        self.assertTrue(any("parent-receive" in item["port"] for item in pending))
        self.assertGreaterEqual(sum(len(row["depends"]) for row in value["rows"]), 102)
        self.assertTrue(instance_rows(value, "l3d"))
        self.assertTrue(PLAN.is_file())

    def test_plan_bytes_are_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = root / "input-plan.json"
            # Whitespace is deliberate: re-encoding this JSON must fail the
            # deciding byte assertion even when its decoded value is identical.
            raw = PLAN.read_bytes() + b"\n \n"
            plan.write_bytes(raw)
            with patch("prepare_ladder.PLAN", plan):
                prepared = prepare(root / "prepared", ["tree-a", "tree-b"], 123)
            saved = root / "prepared/row-plan.json"
            self.assertNotEqual(saved.read_bytes(), raw.rstrip() + b"\n")
            self.assertEqual(saved.read_bytes(), raw)
            self.assertEqual(prepared["row_plan_sha256"], bytes_hash(raw))


class SharedReaderControls(unittest.TestCase):
    def test_cli_reuses_configured_reader(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cli = test_draft4.Draft4CLIControls().cli(root, {})
            reader = Mock(proof_id="one-session-proof")
            result = {"config": "tree-a", "actor": {"kind": "human", "id": "test-human"},
                      "endpoint_generation": 1, "policy_generation": 1}
            def reply(request):
                self.assertNotIn("proof", request)
                return {"request_id": request["request_id"], "result": result}
            reader.call.side_effect = reply
            cli.reader = reader
            for _ in range(10):
                self.assertEqual(cli.call(["identity", "self"], {}), result)
            self.assertEqual(reader.call.call_count, 10)
            self.assertEqual({item["session_proof_id"] for item in cli.invocations}, {"one-session-proof"})
            cli.recorder.run.assert_not_called()

    def test_presence_flag_is_not_truthiness(self):
        with self.assertRaises(ladder.LadderFailure) as caught:
            draft4.presence({"simulated_presence": 1})
        self.assertEqual(caught.exception.check_id, "presence")
        self.assertTrue(draft4.presence({"simulated_presence": True}))
        self.assertFalse(draft4.presence({}))

    def test_aggregate_preserves_marked_tree(self):
        marked = {"simulated_presence": True, "presence": "simulated", "human_approval": "not_proven"}
        aggregate = {"simulated_presence": False, "presence": "not_measured", "human_approval": "not_measured",
                     "trees": [marked]}
        with self.assertRaisesRegex(Failure, "dropped"):
            presence_value(aggregate)
        aggregate.update(simulated_presence=True, presence="simulated", human_approval="not_proven")
        self.assertEqual(presence_value(aggregate), aggregate)

    def test_one_process_per_session_window(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable, binding, proof = root / "reader", root / "binding", root / "proof"
            executable.write_bytes(os.urandom(16))
            binding.write_bytes(os.urandom(16))
            test_draft4.Draft4CLIControls().proof(proof)
            expiry = (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat()
            child = Mock(pid=4321)
            child.wait.return_value = 0
            session = {"result": {"id": "session", "config": "tree-a", "expires_at": expiry,
                                   "idle_expires_at": expiry}}
            with patch("readsession.immutable", side_effect=regular), patch("draft4.immutable", side_effect=regular):
                reader = SessionReader(executable, "tree-a", binding, proof, root / "session", {})
                with patch("readsession.subprocess.Popen", return_value=child) as opened:
                    with patch("readsession.process_identity", return_value={"pid": 4321}):
                        with patch.object(reader, "receive", return_value=session):
                            for _ in range(100):
                                reader.ensure_open()
                            self.assertEqual(opened.call_count, 1)
                            self.assertEqual(len(reader.used_proofs), 1)
                            reader.session["expires_at"] = datetime.now(timezone.utc).isoformat()
                            with self.assertRaises(Failure) as caught:
                                reader.ensure_open()
                            self.assertEqual(caught.exception.code, "unauthenticated")
                            self.assertEqual(opened.call_count, 1)
                            test_draft4.Draft4CLIControls().proof(proof)
                            session["result"]["expires_at"] = expiry
                            reader.ensure_open()
                            self.assertEqual(opened.call_count, 2)
                            self.assertEqual(len(reader.used_proofs), 2)
                            reader.close()
