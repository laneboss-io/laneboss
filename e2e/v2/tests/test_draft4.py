"""Draft.4 red controls over the same full verifier and CLI adapter."""

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

from draft4 import canonical, intent_digest
from ladder import LadderFailure, verify_run
from ladder_fixtures import make_run
from ladder_live import CLI
from ladder_transactions import continuation_swap, write_shape
from support import Command, Failure, bytes_hash, regular, save


class Draft4RunControls(unittest.TestCase):
    def red(self, name, mutate):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, plan, _ = make_run(root)
            mutate(run)
            with self.assertRaises(LadderFailure) as caught:
                verify_run(run, plan, root)
            self.assertEqual(caught.exception.check_id, name)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, plan, _ = make_run(root)
            self.assertEqual(len(verify_run(run, plan, root)), 10)

    def test_missing_mutation_key(self):
        self.red("mutation-key", lambda run: run["mutations"][0]["request"].update(idempotency_key=""))

    def test_foreign_receipt_config(self):
        self.red("receipt-config", lambda run: run["mutations"][0]["receipt"].update(config="tree-b"))

    def test_foreign_receipt_actor(self):
        def mutate(run):
            run["mutations"][0]["receipt"]["actor"] = {"kind": "human", "id": "another-human"}
        self.red("receipt-config", mutate)

    def test_foreign_receipt_key(self):
        self.red("receipt-config", lambda run: run["mutations"][0]["receipt"]["key"].update(
            idempotency_key=os.urandom(16).hex()))

    def test_missing_typed_reply(self):
        self.red("typed-reply", lambda run: run["mutations"][0]["receipt"].update(reply=None))

    def test_mutation_without_reply(self):
        self.red("write-matrix", lambda run: run["mutations"][0]["transaction"].update(reply=False))

    def test_policy_write_in_spawn(self):
        self.red("write-matrix", lambda run: run["mutations"][0]["transaction"]["fields"].append("Policy"))

    def test_missing_cancellation_guard(self):
        self.red("write-matrix", lambda run: next(item for item in run["mutations"] if
                 item["request"]["method"] == "lane.turn")["transaction"]["guards"].remove("Cancellation"))

    def test_missing_root_ticket_guard(self):
        self.red("write-matrix", lambda run: run["mutations"][0]["transaction"]["guards"].remove("Ticket"))

    def test_wrong_ticket_principal(self):
        self.red("ticket", lambda run: run["root_ticket"].update(principal_id="another-human"))

    def test_wrong_ticket_config(self):
        self.red("ticket", lambda run: run["root_ticket"].update(config="tree-b"))

    def test_wrong_ticket_endpoint(self):
        self.red("ticket", lambda run: run["root_ticket"].update(endpoint_generation=2))

    def test_replay_without_original(self):
        self.red("mutation-replay", lambda run: run["mutations"][0].update(replayed=True))

    def test_missing_observed_mutation(self):
        def mutate(run):
            item = next(item for item in run["mutations"] if item["request"]["method"] == "lane.start" and
                        item["actor"]["kind"] == "lane")
            run["mutations"].remove(item)
        self.red("mutation-key", mutate)

    def release_red(self, key, value):
        def mutate(run):
            event = next(item for item in run["events"] if item["kind"] == "helper.released")
            event["payload"][key] = value
        self.red("release", mutate)

    def test_release_live_connection(self):
        self.release_red("live_connections", 1)

    def test_release_queued_job(self):
        self.release_red("queued_jobs", 1)

    def test_release_writable_export(self):
        self.release_red("writable_exports", 1)

    def test_release_wrong_containment(self):
        self.release_red("containment_id", "another-containment")

    def test_clean_keeps_old_epoch(self):
        self.red("cancellation", lambda run: run["lanes"][1].update(cancellation_epoch=1))

    def test_completion_keeps_requester(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, plan, _ = make_run(root)
            for event in run["events"]:
                if event["kind"] in ("archive.verified", "lane.cleaned"):
                    event["actor"] = {"kind": "worker", "id": "archive-worker"}
            self.assertEqual(len(verify_run(run, plan, root)), 10)

    def test_read_observation_missing(self):
        self.red("read-auth", lambda run: run["reads"].clear())

    def test_read_changes_state(self):
        self.red("write-matrix", lambda run: run["reads"][0]["transaction"]["fields"].append("ReadSessions"))

    def test_read_different_socket(self):
        self.red("read-auth", lambda run: run["reads"][0]["session"].update(connection_id="another-socket"))

    def test_read_ambient_proof(self):
        self.red("read-auth", lambda run: run["reads"][0]["request"].update(proof={"id": "borrowed"}))

    def test_read_reuses_session_proof(self):
        def mutate(run):
            item = copy.deepcopy(run["reads"][0])
            item["request"]["request_id"] = os.urandom(16).hex()
            item["response"]["request_id"] = item["request"]["request_id"]
            item["connection_id"] = item["session"]["connection_id"] = "another-connection"
            run["reads"].append(item)
        self.red("read-auth", mutate)

    def test_replay_changed_reply(self):
        def mutate(run):
            item = copy.deepcopy(run["mutations"][-1])
            item["request"]["request_id"] = os.urandom(16).hex()
            item["response"]["request_id"] = item["request"]["request_id"]
            item["replayed"] = True
            item["response"]["result"]["status"] = "running"
            item["receipt"]["reply"]["result"]["status"] = "running"
            run["mutations"].append(item)
        self.red("mutation-replay", mutate)

    def test_exact_retained_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run, plan, _ = make_run(root)
            item = copy.deepcopy(run["mutations"][-1])
            item["request"]["request_id"] = os.urandom(16).hex()
            item["response"]["request_id"] = item["request"]["request_id"]
            item["replayed"] = True
            run["mutations"].append(item)
            run["client_intents"].append({**run["client_intents"][0],
                                          "request_id": item["request"]["request_id"]})
            self.assertEqual(len(verify_run(run, plan, root)), 10)


class Draft4ShapeControls(unittest.TestCase):
    def shape(self):
        return {"fields": ["WorkerLeases"], "events": [], "effects": ["Worker"],
                "guards": ["Cancellation"], "reply": True}

    def test_four_worker_lease_rows(self):
        actor = {"kind": "lane", "id": "parent", "life_id": "parent-life"}
        for method in ("lane.start", "lane.adopt", "lane.resume", "lane.turn"):
            shape = self.shape()
            shape["fields"].append("Policy")
            with self.assertRaises(LadderFailure) as caught:
                write_shape(method, actor, shape)
            self.assertEqual(caught.exception.check_id, "write-matrix")
            shape["fields"].remove("Policy")
            self.assertIsNone(write_shape(method, actor, shape))

    def test_state_changing_read(self):
        shape = self.shape()
        with self.assertRaises(LadderFailure):
            write_shape("lane.list", {"kind": "human"}, shape)
        for key in ("fields", "events", "effects", "guards"):
            shape[key] = []
        self.assertIsNone(write_shape("lane.list", {"kind": "human"}, shape))

    def test_no_org_deferred_guess(self):
        with self.assertRaises(Failure) as caught:
            write_shape("org.change.apply", {"kind": "lane"}, self.shape())
        self.assertEqual((caught.exception.code, caught.exception.owner),
                         ("not_implemented", "lb-v2-e2e"))

    def test_jcs_input_and_utf16_keys(self):
        value = {"\ue000": 1, "\U00010000": 2}
        self.assertEqual(list(value), ["\ue000", "\U00010000"])
        self.assertLess(canonical(value).index("\U00010000"), canonical(value).index("\ue000"))
        with self.assertRaises(Failure):
            canonical({"fraction": 0.5})
        self.assertNotEqual(intent_digest("tree-a", "human.session", {}),
                            intent_digest("tree-b", "human.session", {}))

    def test_continuation_swap_fence(self):
        previous = {"life_id": "child", "run": 2, "logical_turn_id": "turn-two",
                    "payload": {"lane": {"cancellation_epoch": 4}}}
        following = {"life_id": "child", "run": 3, "logical_turn_id": "turn-two", "payload": {
            "lane": {"cancellation_epoch": 4, "profile_grant_id": "next-grant"}, "profile_swap": {
                "profile_grant_id": "next-grant", "eligibility_id": "eligibility", "expected_generation": 7,
                "cancellation_epoch": 4, "from_profile_id": "previous-profile", "to_profile_id": "next-profile",
                "causing_run": 2, "continuation_run": 3, "logical_turn_id": "turn-two",
                "limit": {"target": {"life_id": "child", "run": 2}, "profile_id": "previous-profile",
                          "kind": "quota", "provider": "unit-provider", "capture_id": "unit-capture",
                          "capture_sha256": bytes_hash(os.urandom(8)), "adapter_version": "unit-version",
                          "observed_at": "2026-01-01T00:00:00Z"},
                "room": {"profile_id": "next-profile", "available": True,
                         "checked_at": "2026-01-01T00:00:00Z", "expires_at": "2026-01-01T00:01:00Z",
                         "evidence": {"id": "room-evidence", "sha256": bytes_hash(b"unit-room"),
                                      "bytes": len(b"unit-room"), "class": "record"},
                         "reason": "unit-room"}, "operation_id": "continuation-op"}}}
        wrong = copy.deepcopy(following)
        wrong["payload"]["profile_swap"]["cancellation_epoch"] = 5
        with self.assertRaises(LadderFailure) as caught:
            continuation_swap(previous, wrong)
        self.assertEqual(caught.exception.check_id, "runtime")
        stale = copy.deepcopy(previous)
        stale["payload"]["lane"]["cancellation_epoch"] = 3
        with self.assertRaises(LadderFailure) as caught:
            continuation_swap(stale, following)
        self.assertEqual(caught.exception.check_id, "runtime")
        same = copy.deepcopy(following)
        swap = same["payload"]["profile_swap"]
        swap["from_profile_id"] = swap["to_profile_id"]
        swap["limit"]["profile_id"] = swap["from_profile_id"]
        with self.assertRaises(LadderFailure) as caught:
            continuation_swap(previous, same)
        self.assertEqual(caught.exception.check_id, "runtime")
        incomplete = copy.deepcopy(following)
        incomplete["payload"]["profile_swap"]["limit"].pop("capture_id")
        with self.assertRaises(LadderFailure) as caught:
            continuation_swap(previous, incomplete)
        self.assertEqual(caught.exception.check_id, "runtime")
        self.assertIsNone(continuation_swap(previous, following))
        claudock = copy.deepcopy(previous)
        claudock["payload"]["lane"]["session"] = {"driver": "claudock-cli"}
        with self.assertRaises(LadderFailure) as caught:
            continuation_swap(claudock, following)
        self.assertEqual(caught.exception.check_id, "runtime")
        codex = copy.deepcopy(previous)
        codex["payload"]["lane"]["session"] = {"driver": "codex"}
        self.assertIsNone(continuation_swap(codex, following))


class Draft4CLIControls(unittest.TestCase):
    def cli(self, root, reply):
        cli = object.__new__(CLI)
        cli.binary, cli.binding, cli.config = "installed-cli", "installed-binding", "tree-a"
        cli.root, cli.index = root, 0
        cli.bound = {"class": "human"}
        cli.used_read_proofs, cli.used_operation_proofs, cli.invocations = set(), set(), []
        out, err = root / "out", root / "err"
        save(out, reply)
        save(err, {})
        cli.recorder = Mock()
        cli.recorder.run.return_value = Command(0, out, err, root / "command")
        return cli

    def proof(self, path, method="human.session", params=None):
        save(path, {"id": os.urandom(16).hex(), "request_sha256": intent_digest(
            "tree-a", method, {} if params is None else params), "expires_at": (
                datetime.now(timezone.utc) + timedelta(seconds=90)).isoformat()})

    def test_missing_key_does_not_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            cli = self.cli(Path(temporary), {})
            with self.assertRaises(Failure):
                cli.call(["lane", "start"], {})
            cli.recorder.run.assert_not_called()

    def test_read_needs_session_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            cli = self.cli(Path(temporary), {})
            with self.assertRaises(Failure) as caught:
                cli.call(["lane", "list"], {"cursor": "", "limit": 128})
            self.assertEqual((caught.exception.code, caught.exception.owner),
                             ("prerequisite_missing", "lb-v2-identity"))
            cli.recorder.run.assert_not_called()

    def test_read_proof_is_one_connection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = {"config": "tree-a", "actor": {"kind": "human", "id": "unit-human"},
                      "endpoint_generation": 1, "policy_generation": 1}
            cli = self.cli(root, result)
            path = root / "session-proof.json"
            self.proof(path)
            with patch("draft4.immutable", side_effect=regular):
                self.assertEqual(cli.call(["identity", "self"], {}, proof=path), result)
                with self.assertRaises(Failure) as caught:
                    cli.call(["identity", "self"], {}, proof=path)
            self.assertEqual(caught.exception.code, "unauthenticated")
            argv = cli.recorder.run.call_args.args[0]
            self.assertEqual(argv[argv.index("--proof") + 1], str(path))
            self.assertEqual(cli.recorder.run.call_count, 1)

    def test_lane_never_borrows_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            cli = self.cli(Path(temporary), {})
            cli.bound["class"] = "lane"
            with self.assertRaises(Failure) as caught:
                cli.call(["lane", "list"], {}, proof="human-proof")
            self.assertEqual(caught.exception.code, "forbidden")
            cli.recorder.run.assert_not_called()

    def test_committed_content_ref(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = os.urandom(16).hex().encode("ascii")
            reference = {"id": "report-object", "sha256": bytes_hash(data), "bytes": len(data), "class": "report"}
            result = {"id": "record-id", "collection": "reports", "content": reference,
                      "actor": {"kind": "human", "id": "unit-human"}, "origin": "observation",
                      "recorded_at": datetime.now(timezone.utc).isoformat(), "generation": 1}
            cli = self.cli(root, result)
            path = root / "content-ref.json"
            save(path, reference)
            body = {"collection": "reports", "content": reference, "related_ids": []}
            proof = root / "operation-proof.json"
            self.proof(proof, "records.append", body)
            with patch("ladder_live.immutable", side_effect=regular), patch("draft4.immutable", side_effect=regular):
                self.assertEqual(cli.call(["records", "append"], body, content_ref=path,
                                          proof=proof, key=os.urandom(16).hex()), result)
            argv = cli.recorder.run.call_args.args[0]
            self.assertIn("--content-ref", argv)
            self.assertNotIn("--file", argv)
            self.assertNotIn("--request", argv)
            self.assertEqual(cli.recorder.run.call_count, 1)
