"""Converged-tree harness controls, never live-service acceptance."""

import copy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "e2e/v2"))

from draft4 import operation_proof
from installed_ladder import launch_context
import ladder_case
from ladder_case import fixture
from ladder_live import CLI
import ladder_live
from readsession import SessionReader
from prepare_ladder import prepare
from support import Failure, bytes_hash, load, regular, save


class SelectedEvents(unittest.TestCase):
    def cli(self, lanes):
        cli = object.__new__(CLI)
        cli.config, cli.cursor, cli.seq, cli.events = "tree-a", "", 0, []
        cli.event_positions = {}
        cli.authority_events = {}
        cli.lanes = Mock(return_value=lanes)
        return cli

    def event(self, seq, life="life-a", run=1, config="tree-a"):
        return {"schema": 2, "config": config, "id": "event-" + str(seq),
                "seq": seq, "life_id": life, "run": run}

    def test_fresh_config_no_empty_select(self):
        cli = self.cli([])
        cli.call = Mock(side_effect=AssertionError("unselected public event.tail"))
        self.assertTrue(cli.events_page())
        cli.call.assert_not_called()

    def test_life_run_exclusive_cursor(self):
        cli = self.cli([{"life_id": "life-a", "run": 2}, {"life_id": "life-b", "run": 1}])
        cli.call = Mock(side_effect=[
            {"events": [self.event(2)], "cursor": "a1", "complete": True},
            {"events": [self.event(9, run=2)], "cursor": "a2", "complete": True},
            {"events": [self.event(4, life="life-b")], "cursor": "b1", "complete": True}])
        self.assertTrue(cli.events_page())
        self.assertEqual([event["seq"] for event in cli.events], [2, 4, 9])
        queries = [call.args[1] for call in cli.call.call_args_list]
        self.assertEqual([(q["life_id"], q["run"]) for q in queries],
                         [("life-a", 1), ("life-a", 2), ("life-b", 1)])
        cli.call.reset_mock()
        cli.call.side_effect = [
            {"events": [], "cursor": cursor, "complete": True}
            for cursor in ("a1", "a2", "b1")]
        self.assertTrue(cli.events_page())
        self.assertEqual([call.args[1]["cursor"] for call in cli.call.call_args_list], ["a1", "a2", "b1"])
        self.assertTrue(all(call.args[1]["since"] == 0 for call in cli.call.call_args_list))

    def test_foreign_stale_replay_refuse(self):
        for field, value in (("config", "tree-b"), ("life_id", "foreign"), ("run", 2), ("seq", 0)):
            with self.subTest(field=field):
                cli = self.cli([{"life_id": "life-a", "run": 1}])
                event = self.event(1)
                event[field] = value
                cli.call = Mock(return_value={"events": [event], "cursor": "next", "complete": True})
                with self.assertRaises(Failure):
                    cli.events_page()
        cli = self.cli([{"life_id": "life-a", "run": 1}])
        cli.call = Mock(return_value={"events": [self.event(1)], "cursor": "next", "complete": True})
        self.assertTrue(cli.events_page())
        with self.assertRaises(Failure):
            cli.events_page()

    def test_protected_not_replace_public(self):
        cli = self.cli([])
        event = {**self.event(1), "life_id": "", "run": 0, "origin": "service", "kind": "human.session"}
        cli.configuration_events([event])
        self.assertEqual(cli.events, [event])
        cli.configuration_events([event])
        self.assertEqual(cli.events, [event])
        for changed in ({**event, "config": "tree-b"}, {**event, "origin": "observation"},
                        {**event, "life_id": "other-life"}, {**event, "kind": "ticket.issued"}):
            with self.assertRaises(Failure):
                cli.configuration_events([changed])
        with self.assertRaises(Failure):
            cli.configuration_events([])


class InstallationPreflight(unittest.TestCase):
    def inputs(self, root):
        inputs = root / "inputs"
        inputs.mkdir()
        prepared = root / "prepared"
        prepare(prepared, ["tree-a", "tree-b"], 701)
        binary = root / "candidate"
        binary.write_bytes(os.urandom(32))
        digest = bytes_hash(binary.read_bytes())
        trees = []
        for index, config in enumerate(("tree-a", "tree-b")):
            path = root / (config + ".json")
            allocation = {"store_id": "store-" + config, "socket": str(root / (config + ".sock")),
                          "service_uid": 62000 + index * 100,
                          "workspace_ids": [config + "-workspace-" + str(i) for i in range(10)],
                          "lane_uids": list(range(62001 + index * 100, 62011 + index * 100))}
            save(path, {"config": config, "contract_revision": "v2.0-draft.4",
                        "artifact_sha256": digest, "service_uid": allocation["service_uid"],
                        "socket": allocation["socket"]})
            trees.append({"config": config, "binding_file": str(path), "start_file": str(root / (config + "-start")),
                          "ticket_file": str(root / (config + "-ticket")), "request_id": os.urandom(16).hex(),
                          "idempotency_key": os.urandom(16).hex(), "binding": allocation})
        value = {"schema": "laneboss.ladder-live.v2", "contract_revision": "v2.0-draft.4",
                 "plan_directory": str(prepared), "observer_binding": str(root / "observer"),
                 "trees": trees, "artifacts": {"binary": str(binary)}}
        save(inputs / "ladder.json", value)
        case = SimpleNamespace(inputs=inputs, context={"config": "tree-a", "binary": str(binary),
                               "binding_file": trees[0]["binding_file"], "binary_sha256": digest})
        return case, value

    def test_overlap_refuses_pre_dispatch(self):
        for key in ("store_id", "socket", "service_uid", "workspace_ids", "lane_uids"):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                case, value = self.inputs(Path(temporary))
                with patch("ladder_case.immutable", side_effect=regular):
                    self.assertEqual(len(fixture(case)[0]["trees"]), 2)
                    original = copy.deepcopy(value)
                    value["trees"][1]["binding"][key] = copy.deepcopy(value["trees"][0]["binding"][key])
                    if key in ("socket", "service_uid"):
                        path = Path(value["trees"][1]["binding_file"])
                        bound = load(path)
                        bound[key] = value["trees"][1]["binding"][key]
                        save(path, bound)
                    save(case.inputs / "ladder.json", value)
                    with self.assertRaisesRegex(Failure, "overlap"):
                        fixture(case)
                    self.assertNotEqual(value, original)


class OwnerWaits(unittest.TestCase):
    def test_second_tree_wait_kept(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            clis, trees = [], []
            for config in ("tree-a", "tree-b"):
                principal, ticket_id = os.urandom(16).hex(), os.urandom(16).hex()
                reader = Mock(spec=SessionReader, used_proofs=set())
                cli = Mock(config=config, reader=reader, events=[])
                cli.call.return_value = {"config": config, "actor": {"kind": "human", "id": principal},
                                         "endpoint_generation": 1, "policy_generation": 1}
                start, proof = root / (config + "-start"), root / (config + "-ticket")
                save(start, {"lane": "l6", "level": 6, "role": "supervisor", "driver": "claudock-cli",
                             "root_ticket_id": ticket_id})
                if config == "tree-a":
                    save(proof, {"principal_id": principal, "config": config, "endpoint_generation": 1,
                         "id": ticket_id, "level": 6, "role": "supervisor", "grant_set_id": os.urandom(16).hex(),
                         "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=90)).isoformat(), "redeemed": False})
                trees.append({"config": config, "start_file": str(start), "ticket_file": str(proof),
                              "request_id": os.urandom(16).hex(), "idempotency_key": os.urandom(16).hex()})
                clis.append(cli)
            coverage = {"durable-waits", "privacy", "kernel", "overlap", "source", "actor", "collection",
                        "read-auth", "root-turn", "barrier", "archives", "draft4-mutations", "draft4-releases",
                        "draft4-reads", "draft4-launch-pins", "draft4-policy", "draft4-presence", "draft4-review",
                        "configuration-events"}
            observer = Mock()
            observer.call.return_value = {"ready": True, "coverage": sorted(coverage)}
            with patch.object(ladder_live, "immutable", side_effect=regular), patch.object(
                    ladder_live, "keep_artifacts", return_value=({}, {})):
                with self.assertRaises(Failure) as caught:
                    ladder_live.run_pair(clis, trees, observer, {}, root, {})
            self.assertEqual(caught.exception.code, "prerequisite_missing")
            self.assertIn("tree-b", str(caught.exception))
            self.assertTrue(all(call.args[0] == ["identity", "self"] for cli in clis for call in cli.call.call_args_list))

    def test_missing_confirm_explicit_wait(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fresh-proof.json"
            with self.assertRaises(Failure) as caught:
                operation_proof(path, "tree-a", "human.session", {}, set())
            self.assertEqual(caught.exception.code, "prerequisite_missing")
            self.assertIn("owner", caught.exception.wire()["instead"].lower())

    def test_bad_proofs_not_renewals(self):
        from draft4 import intent_digest
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "proof.json"
            value = {"id": os.urandom(16).hex(), "request_sha256": intent_digest("tree-a", "human.session", {}),
                     "expires_at": (datetime.now(timezone.utc) + timedelta(seconds=90)).isoformat()}
            save(path, value)
            used = set()
            with patch("draft4.immutable", side_effect=regular):
                self.assertEqual(operation_proof(path, "tree-a", "human.session", {}, used), value)
                for config, previous in (("tree-a", used), ("tree-b", set())):
                    with self.assertRaises(Failure):
                        operation_proof(path, config, "human.session", {}, previous)
                value["expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
                save(path, value)
                with self.assertRaises(Failure):
                    operation_proof(path, "tree-a", "human.session", {}, set())


class SupportingAcceptance(unittest.TestCase):
    def test_direct_case_no_bypass(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, output = root / "inputs", root / "evidence"
            inputs.mkdir()
            output.mkdir()
            case = Mock(inputs=inputs, root=output, context={"test_root": str(inputs),
                        "binary": "candidate", "config": "tree-a", "binding_file": "binding",
                        "binary_sha256": bytes_hash(os.urandom(32))})
            case.finish.return_value = 69
            with patch.object(ladder_case, "require_linux"), patch.object(ladder_case, "Case", return_value=case), patch.object(
                    ladder_case, "CLI") as cli:
                cli.return_value.reader = None
                cli.return_value.last_exit = 0
                self.assertEqual(ladder_case.main(), 69)
                self.assertEqual(cli.call_count, 0, "readiness failure must precede CLI construction")
            call = case.finish.call_args
            self.assertFalse(call.kwargs["reached"])
            self.assertEqual(call.args[0].code, "prerequisite_missing")

    def test_ports_not_replace_support(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary, source = root / "candidate", root / "source.tar"
            binary.write_bytes(os.urandom(50))
            source.write_bytes(os.urandom(60))
            context = {"case_id": "e2e", "phase": "candidate", "config": "tree-a", "test_root": str(root),
                       "binary": str(binary), "binary_sha256": bytes_hash(binary.read_bytes()),
                       "source_sha256": bytes_hash(source.read_bytes())}
            retained = Mock(report={"scope": "installed-lifecycle"})
            retained.path.side_effect = lambda name: binary if name == "laneboss.input" else source
            with patch("installed_ladder.context_file", return_value=context), patch(
                    "installed_ladder.ready_plan", return_value={"rows": []}):
                with self.assertRaisesRegex(Failure, "8F") as caught:
                    launch_context(root / "context.json", retained)
            self.assertEqual(caught.exception.code, "prerequisite_missing")
